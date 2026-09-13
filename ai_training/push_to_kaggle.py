#!/usr/bin/env python3
"""
ITAP Kaggle Auto-Push Script (Distributed Architecture)
Pushes 3 specialized ITAP training notebooks to Kaggle for parallel cloud GPU training.
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

NOTEBOOKS = [
    {
        "file": "Kaggle_Autoencoder_Network.ipynb",
        "slug": "itap-autoencoder-network-training",
        "title": "ITAP Autoencoder Network Training",
        "datasets": [
            "cicdataset/cicids2017",
            "hassan06/nslkdd"
        ]
    },
    {
        "file": "Kaggle_LSTM_KillChain.ipynb",
        "slug": "itap-lstm-killchain-training",
        "title": "ITAP LSTM Kill Chain Training",
        "datasets": [
            "teamincognito/cyber-security-attacks",
            "mrwellsdavid/unsw-nb15"
        ]
    },
    {
        "file": "Kaggle_LSTM_WAF_Payloads.ipynb",
        "slug": "itap-lstm-waf-payloads-training",
        "title": "ITAP LSTM WAF Payloads Training",
        "datasets": [
            "simiotic/waf-payloads"
        ]
    }
]

def check_kaggle_installed():
    if shutil.which("kaggle") is None and subprocess.run([sys.executable, "-m", "kaggle", "--version"], capture_output=True).returncode != 0:
        print("[ERROR] Kaggle CLI not found. Install it with:\n   pip install kaggle")
        sys.exit(1)
    print("[OK] Kaggle CLI found")


def get_kaggle_credentials() -> dict:
    cred_path = Path.home() / ".kaggle" / "kaggle.json"
    if not cred_path.exists():
        print(f"[ERROR] Kaggle credentials not found at {cred_path}")
        sys.exit(1)
    with open(cred_path) as f:
        creds = json.load(f)
    print(f"[OK] Kaggle credentials loaded for user: {creds['username']}")
    return creds


def push_notebook(username: str, nb_config: dict, run_immediately: bool = False):
    nb_path = Path(__file__).parent / nb_config["file"]
    print(f"\n[PUSH] Pushing {nb_config['file']} to Kaggle...")
    
    if not nb_path.exists():
        print(f"[ERROR] Notebook not found at {nb_path}")
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        shutil.copy(nb_path, tmpdir)
        
        kernel_meta = {
            "id": f"{username}/{nb_config['slug']}",
            "title": nb_config["title"],
            "code_file": nb_path.name,
            "language": "python",
            "kernel_type": "notebook",
            "is_private": True,
            "enable_gpu": True,
            "enable_internet": True,
            "dataset_sources": nb_config["datasets"]
        }
        with open(os.path.join(tmpdir, "kernel-metadata.json"), "w") as f:
            json.dump(kernel_meta, f, indent=2)
        
        result = subprocess.run(
            [sys.executable, "-m", "kaggle", "kernels", "push", "-p", tmpdir],
            capture_output=True, text=True, encoding="utf-8"
        )
        
        if result.returncode == 0:
            kernel_url = f"https://www.kaggle.com/code/{username}/{nb_config['slug']}"
            print(f"[OK] Notebook pushed: {kernel_url}")
            if run_immediately:
                print(f"[START] Parallel Training started for {nb_config['slug']}!")
        else:
            print(f"[ERROR] Notebook push failed: {result.stderr.strip()}")


def check_training_status(username: str):
    for nb in NOTEBOOKS:
        slug = nb["slug"]
        print(f"\n[STATUS] Checking training status for kernel: {slug}")
        result = subprocess.run(
            [sys.executable, "-m", "kaggle", "kernels", "status", f"{username}/{slug}"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"Status:\n{result.stdout}")
        else:
            print(f"[ERROR] Could not fetch status: {result.stderr.strip()}")


def download_weights(username: str):
    weights_dir = Path(__file__).parent.parent / "backend" / "app" / "services" / "ml" / "weights"
    weights_dir.mkdir(parents=True, exist_ok=True)
    
    for nb in NOTEBOOKS:
        slug = nb["slug"]
        print(f"\n[DOWNLOAD] Downloading weights from {slug}...")
        result = subprocess.run(
            [sys.executable, "-m", "kaggle", "kernels", "output", f"{username}/{slug}", "-p", str(weights_dir)],
            capture_output=True, text=True, encoding="utf-8"
        )
        if result.returncode == 0:
            print(f"[OK] Output downloaded for {slug}")
        else:
            print(f"[WARN] Download failed or no output for {slug}: {result.stderr.strip()}")
            
    h5_files = list(weights_dir.glob("*.h5"))
    if h5_files:
        print(f"\n[SUCCESS] Total model files found in weights directory: {[f.name for f in h5_files]}")


def main():
    parser = argparse.ArgumentParser(description="ITAP - Distributed Kaggle Training Auto-Push")
    parser.add_argument("--run", action="store_true", help="Trigger notebook runs immediately after push")
    parser.add_argument("--status", action="store_true", help="Check current training status for all notebooks")
    parser.add_argument("--download", action="store_true", help="Download trained model weights")
    args = parser.parse_args()

    print("=" * 60)
    print("  ITAP - Kaggle DISTRIBUTED Training Pipeline")
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

    for nb_config in NOTEBOOKS:
        push_notebook(username, nb_config, run_immediately=args.run)

    print("\n" + "=" * 60)
    print("  Next Steps:")
    print("  1. Monitor parallel training on Kaggle Dashboard.")
    print("  2. Once complete, download weights:")
    print("     python ai_training/push_to_kaggle.py --download")
    print("=" * 60)


if __name__ == "__main__":
    main()
