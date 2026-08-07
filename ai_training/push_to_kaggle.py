#!/usr/bin/env python3
"""
ITAP Kaggle Auto-Push Script
Automatically pushes the ITAP training notebook and dataset to Kaggle for cloud GPU training.
Training continues even when your laptop is closed.

Usage:
    python ai_training/push_to_kaggle.py             # Push notebook only
    python ai_training/push_to_kaggle.py --run       # Push and trigger training immediately
    python ai_training/push_to_kaggle.py --status    # Check current training status
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ─── Configuration ────────────────────────────────────────────
KAGGLE_USERNAME = None   # Auto-detected from ~/.kaggle/kaggle.json
NOTEBOOK_PATH   = Path(__file__).parent / "Kaggle_ITAP_LLM_Training.ipynb"
DATASET_PATH    = Path(__file__).parent / "itap_training_data.jsonl"
KERNEL_SLUG     = "itap-lstm-autoencoder-threat-training"
DATASET_SLUG    = "itap-training-dataset"


def check_kaggle_installed():
    """Verify Kaggle CLI is installed."""
    if shutil.which("kaggle") is None and subprocess.run([sys.executable, "-m", "kaggle", "--version"], capture_output=True).returncode != 0:
        print("❌ Kaggle CLI not found. Install it with:\n   pip install kaggle")
        sys.exit(1)
    print("✅ Kaggle CLI found")


def get_kaggle_credentials() -> dict:
    """Load Kaggle credentials from ~/.kaggle/kaggle.json."""
    cred_path = Path.home() / ".kaggle" / "kaggle.json"
    if not cred_path.exists():
        print(f"❌ Kaggle credentials not found at {cred_path}")
        print("   1. Go to https://www.kaggle.com → Account → API → Create New Token")
        print("   2. Save the downloaded kaggle.json to ~/.kaggle/kaggle.json")
        print("   3. Run: chmod 600 ~/.kaggle/kaggle.json  (on Linux/Mac)")
        sys.exit(1)
    with open(cred_path) as f:
        creds = json.load(f)
    print(f"✅ Kaggle credentials loaded for user: {creds['username']}")
    return creds


def push_dataset(username: str):
    """Push the training dataset to Kaggle."""
    print("\n📦 Pushing training dataset to Kaggle...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy dataset to temp dir
        shutil.copy(DATASET_PATH, tmpdir)
        
        # Create dataset metadata
        metadata = {
            "title": "ITAP Threat Prediction Training Data",
            "id": f"{username}/{DATASET_SLUG}",
            "licenses": [{"name": "CC0-1.0"}],
        }
        with open(os.path.join(tmpdir, "dataset-metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)
        
        # Push to Kaggle
        result = subprocess.run(
            [sys.executable, "-m", "kaggle", "datasets", "create", "-p", tmpdir, "--dir-mode", "zip"],
            capture_output=True, text=True, encoding="utf-8"
        )
        
        if result.returncode == 0:
            print(f"✅ Dataset pushed: https://www.kaggle.com/datasets/{username}/{DATASET_SLUG}")
        else:
            # Try updating if it already exists
            result2 = subprocess.run(
                [sys.executable, "-m", "kaggle", "datasets", "version", "-p", tmpdir, "-m", "Updated training data"],
                capture_output=True, text=True, encoding="utf-8"
            )
            if result2.returncode == 0:
                print(f"✅ Dataset updated: https://www.kaggle.com/datasets/{username}/{DATASET_SLUG}")
            else:
                print(f"⚠️  Dataset push note: {result.stderr.strip()}")


def push_notebook(username: str, run_immediately: bool = False):
    """Push the training notebook to Kaggle as a kernel."""
    print("\n📓 Pushing training notebook to Kaggle...")
    
    if not NOTEBOOK_PATH.exists():
        print(f"❌ Notebook not found at {NOTEBOOK_PATH}")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy notebook
        shutil.copy(NOTEBOOK_PATH, tmpdir)
        
        # Create kernel metadata
        kernel_meta = {
            "id": f"{username}/{KERNEL_SLUG}",
            "title": "ITAP — LSTM & Autoencoder Threat Training",
            "code_file": NOTEBOOK_PATH.name,
            "language": "python",
            "kernel_type": "notebook",
            "is_private": True,
            "enable_gpu": True,
            "enable_internet": True,
            "dataset_sources": [f"{username}/{DATASET_SLUG}"],
            "competition_sources": [],
            "kernel_sources": [],
        }
        with open(os.path.join(tmpdir, "kernel-metadata.json"), "w") as f:
            json.dump(kernel_meta, f, indent=2)
        
        # Push kernel
        result = subprocess.run(
            [sys.executable, "-m", "kaggle", "kernels", "push", "-p", tmpdir],
            capture_output=True, text=True, encoding="utf-8"
        )
        
        if result.returncode == 0:
            kernel_url = f"https://www.kaggle.com/code/{username}/{KERNEL_SLUG}"
            print(f"✅ Notebook pushed: {kernel_url}")
            print(f"   GPU Training: {'ENABLED ✅' if kernel_meta['enable_gpu'] else 'DISABLED'}")
            print(f"   Internet: {'ENABLED ✅' if kernel_meta['enable_internet'] else 'DISABLED'}")
            if run_immediately:
                print("\n🚀 Training started on Kaggle cloud GPU!")
                print("   You can close your laptop — training continues on Kaggle's servers.")
                print(f"   Monitor at: {kernel_url}")
        else:
            print(f"❌ Notebook push failed: {result.stderr.strip()}")
            sys.exit(1)


def check_training_status(username: str):
    """Check the current status of the training kernel."""
    print(f"\n📊 Checking training status for kernel: {KERNEL_SLUG}")
    result = subprocess.run(
        [sys.executable, "-m", "kaggle", "kernels", "status", f"{username}/{KERNEL_SLUG}"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"Status:\n{result.stdout}")
        kernel_url = f"https://www.kaggle.com/code/{username}/{KERNEL_SLUG}"
        print(f"\n🔗 Full output: {kernel_url}")
    else:
        print(f"❌ Could not fetch status: {result.stderr.strip()}")


def download_weights(username: str):
    """Download trained model weights from the Kaggle kernel output."""
    print("\n⬇️  Downloading trained model weights...")
    weights_dir = Path(__file__).parent.parent / "backend" / "app" / "services" / "ml" / "weights"
    weights_dir.mkdir(parents=True, exist_ok=True)
    
    result = subprocess.run(
        [sys.executable, "-m", "kaggle", "kernels", "output", f"{username}/{KERNEL_SLUG}", "-p", str(weights_dir)],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"✅ Weights downloaded to: {weights_dir}")
        h5_files = list(weights_dir.glob("*.h5"))
        if h5_files:
            print(f"   Found model files: {[f.name for f in h5_files]}")
        else:
            print("   ⚠️  No .h5 files found yet — training may still be in progress")
    else:
        print(f"❌ Download failed: {result.stderr.strip()}")


def main():
    parser = argparse.ArgumentParser(
        description="ITAP — Push training notebook to Kaggle for cloud GPU training"
    )
    parser.add_argument("--run", action="store_true", help="Trigger notebook run immediately after push")
    parser.add_argument("--status", action="store_true", help="Check current training status")
    parser.add_argument("--download", action="store_true", help="Download trained model weights")
    args = parser.parse_args()

    print("=" * 60)
    print("  ITAP — Kaggle Training Pipeline Auto-Push")
    print("=" * 60)

    check_kaggle_installed()
    creds = get_kaggle_credentials()
    username = creds["username"]

    if args.status:
        check_training_status(username)
        return

    if args.download:
        download_weights(username)
        return

    # Push dataset first (contains training data)
    push_dataset(username)
    
    # Then push notebook
    push_notebook(username, run_immediately=args.run)

    print("\n" + "=" * 60)
    print("  Next Steps:")
    print(f"  1. Monitor training: https://www.kaggle.com/code/{username}/{KERNEL_SLUG}")
    print("  2. Once complete, download weights:")
    print("     python ai_training/push_to_kaggle.py --download")
    print("  3. Weights go to: backend/app/services/ml/weights/")
    print("=" * 60)


if __name__ == "__main__":
    main()
