# ITAP — Kaggle ML Training Setup Guide

## Overview

The ITAP ML training pipeline uses Kaggle's free cloud GPU to train a real LSTM model and Autoencoder on 5 years of NVD CVE data. Training runs **entirely on Kaggle's servers** — your laptop can be closed at any time.

---

## Step 1 — Install Kaggle CLI

```bash
pip install kaggle
```

---

## Step 2 — Get Your API Token

1. Go to [kaggle.com](https://www.kaggle.com) → **Account** → **API** → **Create New Token**
2. A `kaggle.json` file will download containing your credentials
3. Place it in the correct location:

**Windows:**
```
C:\Users\<YourUsername>\.kaggle\kaggle.json
```

**Linux/Mac:**
```bash
mkdir -p ~/.kaggle
mv ~/Downloads/kaggle.json ~/.kaggle/
chmod 600 ~/.kaggle/kaggle.json
```

---

## Step 3 — Push the Notebook to Kaggle

From the project root directory:

```bash
# Push notebook + dataset (no auto-run)
python ai_training/push_to_kaggle.py

# Push AND trigger training immediately on Kaggle's cloud GPU
python ai_training/push_to_kaggle.py --run
```

✅ Your laptop can now be closed — training continues on Kaggle's T4 GPU.

---

## Step 4 — Monitor Training

Visit your notebook on Kaggle:
```
https://www.kaggle.com/code/<your-username>/itap-threat-prediction-training
```

Or check status via CLI:
```bash
python ai_training/push_to_kaggle.py --status
```

---

## Step 5 — Download Trained Weights

Once training completes (usually 2–4 hours):

```bash
python ai_training/push_to_kaggle.py --download
```

Weights are saved to:
```
backend/app/services/ml/weights/
├── itap_lstm_v2.h5          ← Exploit probability predictor
└── itap_autoencoder_v2.h5   ← Anomaly detection model
```

---

## What the Notebook Trains

| Model | Architecture | Dataset | Output |
|---|---|---|---|
| **LSTM** | 128→64 units + Dropout | 5yr NVD CVE feed | P(exploit in 72h) |
| **Autoencoder** | Dense 64→32→8→32→64 | Synthetic benign traffic | Anomaly score (MSE) |

---

## Troubleshooting

| Error | Solution |
|---|---|
| `403 Forbidden` | Accept Kaggle's terms of service at kaggle.com |
| `kaggle: command not found` | Run `pip install kaggle` |
| `~/.kaggle/kaggle.json not found` | Download API token from Kaggle Account page |
| Kernel push fails | Check if notebook name conflicts — try deleting old version on Kaggle |
| No .h5 files after download | Training still running — check status and wait |

---

## Notes

- Kaggle provides **30 GPU hours/week** for free on T4 GPU
- Internet is enabled in the notebook to download NVD feeds from NIST
- Training data (`itap_training_data.jsonl`) is uploaded as a private Kaggle dataset
- The notebook is set to **private** — only you can see it
