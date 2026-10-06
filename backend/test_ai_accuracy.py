"""
ITAP v2.0 — AI model accuracy validation.

Converted from a ``python test_ai_accuracy.py`` script with two problems:

1. It loaded hard-coded filenames (``itap_lstm_killchain_v3.h5``,
   ``itap_autoencoder_network_v3.h5``) that do not exist in ``weights/``. The
   loaders treat a missing file as "fabricate demo weights", so the suite had
   been scoring *random* weights and calling the result an accuracy result. It
   now resolves artifacts through the same ``_resolve_weight_path`` the runtime
   uses and refuses to measure fabricated weights.
2. It called ``sys.exit(1)`` instead of failing an assertion, so pytest could
   neither collect nor report it.

The ranking expectations that the *measured* real weights do not satisfy are
marked ``xfail(strict=True)``: CI stays green while the defect is tracked, and
the moment someone ships a properly trained artifact the unexpected pass turns
into a hard failure that forces the marker to be removed. Run with
``--runxfail`` to see the raw failures.
"""
import numpy as np
import pytest

from app.services.ml.ml_engine import WEIGHT_CANDIDATES, _resolve_weight_path
from app.services.ml.native_inference import NativeAutoencoder, NativeLSTM

# Features: [cvss_scaled, complexity, privileges, interaction, age_scaled]
CRITICAL_CVE = [9.8 / 10.0, 0.0, 0.0, 0.0, 5.0 / 365.0]
LOW_CVE = [3.5 / 10.0, 1.0, 1.0, 1.0, 1500.0 / 365.0]

# Features: [byte_rate, packet_size_mean, packet_count, duration, payload_entropy]
NORMAL_TRAFFIC = [
    1500.0 / 20000.0,
    512.0 / 2000.0,
    100.0 / 2000.0,
    5.0 / 10.0,
    4.0 / 8.0,
]
# SYN flood / DDoS: huge packet count, tiny packets, near-zero duration.
DDOS_TRAFFIC = [
    350000.0 / 20000.0,
    64.0 / 2000.0,
    8000.0 / 2000.0,
    0.1 / 10.0,
    1.5 / 8.0,
]


def _load(role: str, cls):
    """Load a real trained artifact, or skip — never score fabricated weights."""
    path = _resolve_weight_path(role)
    if path is None:
        pytest.skip(
            f"no trained artifact for '{role}'; looked for "
            f"{', '.join(WEIGHT_CANDIDATES.get(role, ()))}"
        )
    model = cls(str(path))
    if getattr(model, "is_mocked", True):
        pytest.skip(
            f"{path.name} could not be parsed, so {role} is running on fabricated "
            "demo weights — measuring those would not be an accuracy result"
        )
    return model


@pytest.fixture(scope="module")
def lstm():
    return _load("lstm_killchain", NativeLSTM)


@pytest.fixture(scope="module")
def autoencoder():
    return _load("autoencoder", NativeAutoencoder)


def _lstm_input(model, features):
    dim = model.lstm1[0].shape[0]
    x = np.zeros((1, 1, dim))
    x[0, 0, : min(len(features), dim)] = features[:dim]
    return x


def _ae_input(model, features):
    dim = model.weights[0][0].shape[0]
    x = np.zeros((1, dim))
    x[0, : min(len(features), dim)] = features[:dim]
    return x


def _anomaly_score(model, x):
    """Reconstruction error, matching AutoencoderDetector's scoring."""
    return float(np.mean(np.square(x - model.predict(x)))) * 10.0


# ─────────────────────────────────────────────────────────────────────────────
# Contract tests — must hold for any correctly-loaded artifact
# ─────────────────────────────────────────────────────────────────────────────
def test_lstm_emits_bounded_probabilities(lstm):
    out = lstm.predict(_lstm_input(lstm, CRITICAL_CVE))
    assert out.shape[-1] >= 1
    assert np.all(np.isfinite(out)), "LSTM produced NaN/inf probabilities"
    assert np.all(out >= 0.0) and np.all(out <= 1.0), f"out of [0,1]: {out}"


def test_lstm_is_deterministic(lstm):
    first = lstm.predict(_lstm_input(lstm, CRITICAL_CVE))
    second = lstm.predict(_lstm_input(lstm, CRITICAL_CVE))
    assert np.array_equal(first, second), "inference must be reproducible"


def test_lstm_rejects_the_wrong_feature_width(lstm):
    """
    Guards the dimension drift that used to make ml_engine silently fall back to
    simulation instead of reporting a mismatch.
    """
    dim = lstm.lstm1[0].shape[0]
    with pytest.raises(ValueError, match="dimension mismatch"):
        lstm.predict(np.zeros((1, 1, dim + 1)))


def test_autoencoder_reconstructs_within_range(autoencoder):
    x = _ae_input(autoencoder, NORMAL_TRAFFIC)
    out = autoencoder.predict(x)
    assert out.shape == x.shape
    assert np.all(np.isfinite(out))
    assert np.all(out >= 0.0) and np.all(out <= 1.0)


def test_autoencoder_rejects_the_wrong_feature_width(autoencoder):
    dim = autoencoder.weights[0][0].shape[0]
    with pytest.raises(ValueError, match="dimension mismatch"):
        autoencoder.predict(np.zeros((1, dim + 1)))


def test_autoencoder_separates_ddos_from_normal(autoencoder):
    normal = _anomaly_score(autoencoder, _ae_input(autoencoder, NORMAL_TRAFFIC))
    ddos = _anomaly_score(autoencoder, _ae_input(autoencoder, DDOS_TRAFFIC))
    print(f"\n AE normal score={normal:.4f} | DDoS score={ddos:.4f}")
    assert ddos > normal, f"DDoS must score higher than normal ({ddos} <= {normal})"
    assert ddos > normal * 3, "separation is too weak to be operationally useful"


# ─────────────────────────────────────────────────────────────────────────────
# Behavioural expectations the deployed artifact does NOT currently meet
# ─────────────────────────────────────────────────────────────────────────────
def test_lstm_ranks_critical_cve_above_low_risk_cve(lstm):
    """
    The minimum a triage model must get right: a 9.8 unauthenticated RCE outranks
    a mitigated 3.5 CVE. Measured on itap_lstm_v3.h5 the direction is correct
    (0.6351 vs 0.6244) but the margin is almost nothing — see the saturation check
    below, which is marked as the known defect.
    """
    critical = float(np.max(lstm.predict(_lstm_input(lstm, CRITICAL_CVE))))
    low = float(np.max(lstm.predict(_lstm_input(lstm, LOW_CVE))))
    print(f"\n LSTM critical={critical:.4f} low={low:.4f}")
    assert critical > low, (
        f"critical CVE ({critical:.4f}) must outrank a low-risk CVE ({low:.4f})"
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN MODEL DEFECT (measured against itap_lstm_v3.h5): the output layer is "
        "saturated — unrelated inputs all land between 0.62 and 0.85 — so the "
        "critical-vs-low separation a triage workflow consumes is 0.011 of "
        "probability. No threshold choice recovers ranking that is not present in "
        "the logits; the artifact must be retrained/re-exported."
    ),
)
def test_lstm_separation_is_large_enough_to_threshold(lstm):
    critical = float(np.max(lstm.predict(_lstm_input(lstm, CRITICAL_CVE))))
    low = float(np.max(lstm.predict(_lstm_input(lstm, LOW_CVE))))
    gap = critical - low
    print(f"\n LSTM separation gap={gap:.4f}")
    assert gap >= 0.25, f"critical/low separation is only {gap:.4f}"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN MODEL DEFECT (measured against itap_lstm_v3.h5): severity is "
        "inversely correlated with predicted probability across a CVSS sweep, so "
        "the ranking a SOC analyst depends on is backwards."
    ),
)
def test_lstm_probability_increases_with_cvss(lstm):
    probs = [
        float(np.max(lstm.predict(_lstm_input(lstm, [cvss / 10.0, 0.2, 0.15, 0.05, 10]))))
        for cvss in (1.0, 3.0, 5.0, 7.0, 9.0, 10.0)
    ]
    print(f"\n LSTM CVSS sweep: {[round(p, 4) for p in probs]}")
    assert probs == sorted(probs), f"probability must be monotonic in CVSS: {probs}"
