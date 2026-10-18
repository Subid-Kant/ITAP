"""Retrain the kill-chain LSTM artifact (weights/itap_lstm_v3.h5) in place.

Why this exists
---------------
The checked-in artifact scored everything between 0.62 and 0.85 (saturation),
ranked severity *backwards*, and flagged ~100% of a synthetic population as an
attack. Three tests pin those defects as ``xfail(strict=True)``; this script is
what turns them into passes — run it, and the markers get removed.

What it does
------------
* Distils a documented scoring function into the network:

      p(x) = sigmoid(3.2 * x0 - 1.95)          # x0 = CVSS/10, the severity slot

  The function is the triage prior the platform claims to implement: exploit
  likelihood rises monotonically with severity and crosses 0.5 around
  CVSS 6.1. Every other feature slot is deliberately *uninformative* for the
  label — the model trains on them as noise so it cannot bake in a meaning for
  dims whose semantics differ between callers (``FeatureEncoder.encode_lstm``
  and the accuracy tests disagree about what dims 1-4 are; see
  ai_training/datasets/README.md on the feature-contract debt).

* Trains the *whole* native graph (both LSTM steps + both dense layers) with
  back-propagation in numpy — no TensorFlow exists in the runtime, and the
  deployed inference path is the hand-written one in native_inference.py, so
  training must optimise exactly that path (single time step, c0 = h0 = 0).

* Numerically checks the gradients, validates the result against every pinned
  expectation (bounded outputs, critical>low with gap, monotonic CVSS sweep,
  seed-42 confusion matrix), and only then writes the weights back — in place,
  same shapes, same h5 layout.

Run from backend/:   python retrain_lstm_v3.py [--dry]
"""
import sys
import time
from pathlib import Path

import h5py
import numpy as np

from app.services.ml.ml_engine import FeatureEncoder, _resolve_weight_path
from app.services.ml.native_inference import NativeLSTM, sigmoid

SEED = 20261016
# Defaults only — main() overwrites these from the artifact itself. The shipped
# itap_lstm_v3.h5 takes a 20-wide input (not FeatureEncoder.LSTM_DIM=196), which
# is exactly the feature-contract drift the tests document; reading the widths
# off the loaded model keeps this script honest about whatever artifact it finds.
DIM = 196
U1, U2 = 128, 64            # units in lstm step 1 / step 2
TARGET_W0, TARGET_B0 = 3.2, -1.95   # severity prior: sigmoid(3.2*cvss/10 - 1.95)

DRY = "--dry" in sys.argv


# ── data ──────────────────────────────────────────────────────────────────────
def make_dataset(n: int = 8000):
    """Labelled samples over the full input width.

    dim0 carries the label; dims 1-4 are drawn wide (0..12) because the two
    test layouts park values like 4.1 and 10.0 there; dims 5+ are the reserved
    zero block, with half the samples given noise so the net learns to ignore
    them rather than to depend on their absence.
    """
    rng = np.random.default_rng(SEED)
    x = np.zeros((n, DIM), dtype=np.float64)
    x[:, 0] = rng.uniform(0.0, 1.0, n)
    x[:, 1:5] = rng.uniform(0.0, 12.0, (n, 4))
    noise = rng.random((n, DIM - 5)) < 0.5
    x[:, 5:] = np.where(noise, rng.uniform(0.0, 1.0, (n, DIM - 5)), 0.0)
    t = sigmoid(TARGET_W0 * x[:, 0] + TARGET_B0)
    return x, t


# ── model (mirrors NativeLSTM.predict exactly) ────────────────────────────────
class Params:
    def __init__(self, m: NativeLSTM):
        self.W1, self.RW1, self.b1 = [a.astype(np.float64).copy() for a in m.lstm1]
        self.W2, self.RW2, self.b2 = [a.astype(np.float64).copy() for a in m.lstm2]
        self.D1 = m.dense1[0].astype(np.float64).copy()
        self.bd1 = m.dense1[1].astype(np.float64).copy()
        self.D2 = m.dense2[0].astype(np.float64).copy()
        self.bd2 = m.dense2[1].astype(np.float64).copy()


def _step(x, W, b, units):
    z = x @ W + b                      # h0 = 0, so the recurrent term vanishes
    i = sigmoid(z[:, :units])
    ch = np.maximum(0.0, z[:, 2 * units:3 * units])
    o = sigmoid(z[:, 3 * units:])
    c = i * ch
    h = o * np.maximum(0.0, c)
    return h, (z, i, ch, o, c)


def forward(p: Params, x: np.ndarray):
    h1, ca1 = _step(x, p.W1, p.b1, U1)
    h2, ca2 = _step(h1, p.W2, p.b2, U2)
    d1 = np.maximum(0.0, h2 @ p.D1 + p.bd1)
    out = sigmoid(d1 @ p.D2 + p.bd2)
    return out, (x, h1, ca1, h2, ca2, d1)


def backward(p: Params, cache, out, target):
    """Gradients of mean-BCE w.r.t. every weight. ``target`` is shape (n,)."""
    x, h1, (z1, i1, ch1, o1, c1), h2, (z2, i2, ch2, o2, c2), d1 = cache
    n = x.shape[0]
    g = (out - target[:, None]) / (n * out.shape[1])

    grads = {}
    grads["D2"] = d1.T @ g
    grads["bd2"] = g.sum(axis=0)
    gd1 = g @ p.D2.T * (d1 > 0)
    grads["D1"] = h2.T @ gd1
    grads["bd1"] = gd1.sum(axis=0)
    gh2 = gd1 @ p.D1.T

    def gate_backward(gh, cache_step, units):
        """One native LSTM step, backwards. h0/c0 are zero at t=0, so the forget
        gate multiplies a constant 0 — its gradient is zero by construction."""
        z, i, ch, o, c = cache_step
        do = gh * np.maximum(0.0, c)
        dc = gh * o * (c > 0)
        dz_i = dc * ch * i * (1 - i)
        dz_ch = dc * i * (z[:, 2 * units:3 * units] > 0)
        dz_o = do * o * (1 - o)
        return np.concatenate([dz_i, np.zeros_like(dz_i), dz_ch, dz_o], axis=1)

    dz2 = gate_backward(gh2, (z2, i2, ch2, o2, c2), U2)
    grads["W2"] = h1.T @ dz2
    grads["b2"] = dz2.sum(axis=0)
    gh1 = dz2 @ p.W2.T

    dz1 = gate_backward(gh1, (z1, i1, ch1, o1, c1), U1)
    grads["W1"] = x.T @ dz1
    grads["b1"] = dz1.sum(axis=0)
    return grads


def _bce(p: Params, x, t) -> float:
    o, _ = forward(p, x)
    y = t[:, None]
    return float(np.mean(-(y * np.log(o + 1e-12) + (1 - y) * np.log(1 - o + 1e-12))))


def numerical_grad_check(p: Params, x, t, coords=16, eps=1e-5) -> float:
    """Central-difference spot check of the analytic gradients (worst rel. error)."""
    out, cache = forward(p, x)
    grads = backward(p, cache, out, t)
    rng = np.random.default_rng(0)
    worst = 0.0
    for name, g in grads.items():
        for _ in range(coords // len(grads)):
            idx = tuple(int(rng.integers(0, s)) for s in g.shape)
            slot = getattr(p, name)
            orig = slot[idx]
            slot[idx] = orig + eps
            lp = _bce(p, x, t)
            slot[idx] = orig - eps
            lm = _bce(p, x, t)
            slot[idx] = orig
            num = (lp - lm) / (2 * eps)
            ana = g[idx]
            denom = max(1e-6, abs(num), abs(ana))
            worst = max(worst, abs(num - ana) / denom)
    return worst


def train(p: Params, epochs: int = 160, batch: int = 512, lr: float = 3e-3):
    x, t = make_dataset()
    names = ["W1", "b1", "W2", "b2", "D1", "bd1", "D2", "bd2"]
    first_m = {k: np.zeros_like(getattr(p, k)) for k in names}
    second_m = {k: np.zeros_like(getattr(p, k)) for k in names}
    beta1, beta2, eps = 0.9, 0.999, 1e-8
    rng = np.random.default_rng(SEED)
    n = x.shape[0]
    step = 0
    t0 = time.time()
    for epoch in range(epochs):
        perm = rng.permutation(n)
        for start in range(0, n, batch):
            idx = perm[start:start + batch]
            xb, tb = x[idx], t[idx]
            out, cache = forward(p, xb)
            grads = backward(p, cache, out, tb)
            step += 1
            for k in names:
                gm = grads[k]
                first_m[k] = beta1 * first_m[k] + (1 - beta1) * gm
                second_m[k] = beta2 * second_m[k] + (1 - beta2) * gm * gm
                mh = first_m[k] / (1 - beta1 ** step)
                vh = second_m[k] / (1 - beta2 ** step)
                setattr(p, k, getattr(p, k) - lr * mh / (np.sqrt(vh) + eps))
        if epoch % 40 == 0 or epoch == epochs - 1:
            out, _ = forward(p, x)
            bce = _bce(p, x, t)
            corr = float(np.corrcoef(out[:, 0], t)[0, 1])
            print(f"  epoch {epoch:4d}  bce={bce:.4f}  corr(pred,target)={corr:.4f}")
    print(f"  trained in {time.time() - t0:.1f}s")


# ── validation: the exact expectations the pinned tests enforce ──────────────
def prob(p: Params, feats) -> float:
    x = np.zeros((1, DIM))
    x[0, :min(len(feats), DIM)] = feats[:DIM]
    out, _ = forward(p, x)
    return float(out.max())


def validate(p: Params) -> bool:
    ok = True

    critical = prob(p, [9.8 / 10.0, 0.0, 0.0, 0.0, 5.0 / 365.0])
    low = prob(p, [3.5 / 10.0, 1.0, 1.0, 1.0, 1500.0 / 365.0])
    print(f"  critical={critical:.4f}  low={low:.4f}  gap={critical - low:.4f}")
    if not critical > low:
        print("  FAIL: critical does not outrank low")
        ok = False
    if critical - low < 0.25:
        print("  FAIL: separation gap < 0.25")
        ok = False

    sweep = [prob(p, [c / 10.0, 0.2, 0.15, 0.05, 10]) for c in (1, 3, 5, 7, 9, 10)]
    print("  cvss sweep:", [round(s, 4) for s in sweep])
    if any(b < a for a, b in zip(sweep, sweep[1:])):
        print("  FAIL: sweep not monotonic in CVSS")
        ok = False

    # seed-42 population, exactly as test_ml_metrics generates it
    rng = np.random.default_rng(42)
    feats, labels = [], []
    for _ in range(200):
        if rng.random() < 0.3:
            feats.append(FeatureEncoder.encode_lstm(
                rng.uniform(7, 10), rng.uniform(.4, .75), .15,
                rng.uniform(.05, .15), int(rng.integers(10, 100)), dim=DIM))
            labels.append(1)
        else:
            feats.append(FeatureEncoder.encode_lstm(
                rng.uniform(1, 5), rng.uniform(0, .2), .15,
                rng.uniform(0, .02), int(rng.integers(1, 5)), dim=DIM))
            labels.append(0)
    probs = np.array([prob(p, f) for f in feats])
    pred = (probs > 0.5).astype(int)
    labels = np.array(labels)
    tp = int(((pred == 1) & (labels == 1)).sum())
    fp = int(((pred == 1) & (labels == 0)).sum())
    tn = int(((pred == 0) & (labels == 0)).sum())
    fn = int(((pred == 0) & (labels == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    print(f"  TP={tp} FP={fp} TN={tn} FN={fn}  precision={prec:.4f} recall={rec:.4f} fpr={fpr:.4f}")
    if tn <= 0:
        print("  FAIL: TN == 0 — model flags every input")
        ok = False
    if fpr > 0.5:
        print("  FAIL: FPR > 0.5")
        ok = False
    if prec < 0.30 or rec < 0.90:
        print("  FAIL: below approved baseline (0.30 precision / 0.90 recall)")
        ok = False
    return ok


def write_back(p: Params, path: Path):
    """Overwrite the datasets in place — shapes and h5 layout are unchanged."""
    with h5py.File(path, "r+") as f:
        mw = f["model_weights"]
        g = mw["lstm"]["sequential"]["lstm"]["lstm_cell"]
        g["kernel"][...] = p.W1
        g["recurrent_kernel"][...] = p.RW1
        g["bias"][...] = p.b1
        g = mw["lstm_1"]["sequential"]["lstm_1"]["lstm_cell"]
        g["kernel"][...] = p.W2
        g["recurrent_kernel"][...] = p.RW2
        g["bias"][...] = p.b2
        g = mw["dense"]["sequential"]["dense"]
        g["kernel"][...] = p.D1
        g["bias"][...] = p.bd1
        g = mw["dense_1"]["sequential"]["dense_1"]
        g["kernel"][...] = p.D2
        g["bias"][...] = p.bd2


def main():
    global DIM, U1, U2
    path = _resolve_weight_path("lstm_killchain")
    if path is None:
        raise SystemExit("no lstm_killchain artifact found")
    model = NativeLSTM(str(path))
    if model.is_mocked:
        raise SystemExit("loader reported fabricated weights — refusing to train on that")

    # Read the widths off the artifact: input dim, gate widths (kernel // 4).
    DIM = int(model.lstm1[0].shape[0])
    U1 = int(model.lstm1[0].shape[1] // 4)
    U2 = int(model.lstm2[0].shape[1] // 4)
    assert model.lstm2[0].shape[0] == U1, "lstm2 must consume lstm1's units"
    print(f"artifact: {path}")
    print(f"  input_dim={DIM}  units=({U1},{U2})  dense1={model.dense1[0].shape}  dense2={model.dense2[0].shape}")
    p = Params(model)

    print("gradient check ...")
    gx, gt = make_dataset(64)
    worst = numerical_grad_check(p, gx, gt)
    print(f"  worst relative error: {worst:.4f}")
    if worst > 0.05:
        raise SystemExit("gradient check failed — refusing to train, nothing written")

    print("training ...")
    train(p)

    print("validating against the pinned expectations ...")
    if not validate(p):
        print("VALIDATION FAILED — weights NOT written")
        raise SystemExit(2)
    if DRY:
        print("--dry: validation passed, weights not written")
        return

    write_back(p, path)
    print(f"wrote {path}")

    # Prove the file itself behaves: reload from disk, not from memory
    reloaded = NativeLSTM(str(path))
    print("reloaded is_mocked =", reloaded.is_mocked)
    if not validate(Params(reloaded)):
        raise SystemExit("post-write validation failed")
    print("post-write validation passed")


if __name__ == "__main__":
    main()
