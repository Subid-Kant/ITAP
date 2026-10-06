"""
ITAP v2.0 — synthetic regression metrics for the deployed kill-chain LSTM.

Two integrity problems fixed here:

* The module loaded ``itap_lstm_killchain_v3.h5``, which is not an artifact this
  checkout ships (``weights/`` holds ``itap_lstm_v3.h5``). The missing file made
  ``NativeLSTM`` fabricate demo weights, and the test then reported precision /
  recall numbers for random weights as if they described the product.
* It fed ``FeatureEncoder.encode_lstm(...)`` a vector of ``LSTM_DIM`` (196)
  features while the loaded artifact wants 20, so the dimension guard raised on
  every sample — the loop only "worked" because the failure happened outside it.

Features are now built at the width of the model that actually loaded, and the
baseline thresholds are the ones measured from the real artifact, so a future
drop is a genuine regression signal rather than a coin flip.
"""
import numpy as np
import pytest

from app.services.ml.ml_engine import (
    WEIGHT_CANDIDATES,
    FeatureEncoder,
    _resolve_weight_path,
)
from app.services.ml.native_inference import NativeLSTM

# Approved baseline — measured from itap_lstm_v3.h5 with this exact synthetic
# population (seed=42, 200 samples). Tighten only alongside a retrained artifact.
BASELINE_PRECISION = 0.30
BASELINE_RECALL = 0.90


def _load_lstm() -> NativeLSTM:
    path = _resolve_weight_path("lstm_killchain")
    if path is None:
        pytest.skip(
            "no trained LSTM artifact; looked for "
            f"{', '.join(WEIGHT_CANDIDATES['lstm_killchain'])}"
        )
    model = NativeLSTM(str(path))
    if getattr(model, "is_mocked", True):
        pytest.skip(
            f"{path.name} could not be parsed — refusing to report metrics for "
            "fabricated demo weights"
        )
    return model


@pytest.fixture(scope="module")
def lstm() -> NativeLSTM:
    return _load_lstm()


def generate_synthetic_lstm_data(dim: int, seed: int = 42, num_samples: int = 200):
    """Deterministic attack/benign population spanning the feature schema."""
    rng = np.random.default_rng(seed)
    features, labels = [], []
    for _ in range(num_samples):
        is_attack = rng.random() < 0.3
        if is_attack:
            cvss = rng.uniform(7.0, 10.0)
            env_risk = rng.uniform(0.4, 0.75)
            ti_factor = rng.uniform(0.05, 0.15)
            open_ports = int(rng.integers(10, 100))
            label = 1
        else:
            cvss = rng.uniform(1.0, 5.0)
            env_risk = rng.uniform(0.0, 0.2)
            ti_factor = rng.uniform(0.0, 0.02)
            open_ports = int(rng.integers(1, 5))
            label = 0
        features.append(
            FeatureEncoder.encode_lstm(
                cvss, env_risk, 0.15, ti_factor, open_ports, dim=dim
            )
        )
        labels.append(label)
    return np.array(features), np.array(labels)


def confusion_matrix(y_pred: np.ndarray, y_true: np.ndarray) -> dict:
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
    }


@pytest.fixture(scope="module")
def metrics(lstm: NativeLSTM) -> dict:
    dim = lstm.lstm1[0].shape[0]
    X, y_true = generate_synthetic_lstm_data(dim)

    y_pred = np.array(
        [
            1 if float(np.max(lstm.predict(np.array([[row]])))) > 0.5 else 0
            for row in X
        ]
    )
    result = confusion_matrix(y_pred, y_true)
    result["samples"] = int(len(X))
    result["positive_rate"] = float(np.mean(y_true))
    result["predicted_positive_rate"] = float(np.mean(y_pred))
    return result


def test_population_actually_contains_both_classes(metrics):
    """
    A regression suite over a single-class population proves nothing, so pin it.
    """
    assert metrics["samples"] == 200
    assert 0.1 < metrics["positive_rate"] < 0.9, (
        f"synthetic population is degenerate: {metrics['positive_rate']:.2f} positive"
    )


def test_metrics_meet_the_approved_baseline(metrics):
    print(
        "\n--- Synthetic Regression Metrics (LSTM) ---\n"
        f"TP={metrics['tp']} FP={metrics['fp']} TN={metrics['tn']} FN={metrics['fn']}\n"
        f"Precision: {metrics['precision']:.4f}\n"
        f"Recall:    {metrics['recall']:.4f}\n"
        f"F1 Score:  {metrics['f1']:.4f}\n"
        f"FPR:       {metrics['fpr']:.4f}\n"
        "-------------------------------------------"
    )
    assert metrics["precision"] >= BASELINE_PRECISION, (
        f"Regression: precision dropped to {metrics['precision']:.4f} "
        f"(baseline {BASELINE_PRECISION})"
    )
    assert metrics["recall"] >= BASELINE_RECALL, (
        f"Regression: recall dropped to {metrics['recall']:.4f} "
        f"(baseline {BASELINE_RECALL})"
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN MODEL DEFECT (measured against itap_lstm_v3.h5): the artifact "
        "emits P(attack) >= 0.5 for essentially every input, so the confusion "
        "matrix is TP=65 FP=135 TN=0 FN=0 — a 100% false-positive rate. Alert "
        "fatigue guaranteed; retrain before this is production-relied upon."
    ),
)
def test_model_does_not_flag_every_input_as_an_attack(metrics):
    assert metrics["tn"] > 0, "model never predicts 'benign' for benign traffic"
    assert metrics["fpr"] <= 0.5, f"false-positive rate too high: {metrics['fpr']:.2f}"
