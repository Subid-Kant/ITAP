import sys
import os
import numpy as np
from pathlib import Path
import sys

# Add backend to path so we can import native_inference
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.services.ml.native_inference import NativeLSTM, NativeAutoencoder

def run_tests():
    print("==================================================")
    print("      ITAP AI Model Accuracy Validation Suite     ")
    print("==================================================")
    
    weights_dir = Path(__file__).parent / "app" / "services" / "ml" / "weights"
    lstm_path = weights_dir / "itap_lstm_killchain_v3.h5"
    ae_path = weights_dir / "itap_autoencoder_network_v3.h5"
    
    try:
        lstm = NativeLSTM(str(lstm_path))
        ae = NativeAutoencoder(str(ae_path))
        print("[+] Models loaded successfully into Native Engine.")
    except Exception as e:
        print(f"[-] Failed to load models: {e}")
        sys.exit(1)

    print("\n--- 1. Testing LSTM Exploit Predictor ---")
    
    # Dynamically get expected dimensions
    lstm_expected_dim = lstm.lstm1[0].shape[0] if hasattr(lstm, 'lstm1') else 196
    
    # Features: [cvss_scaled, complexity, privileges, interaction, age_scaled]
    base_critical = [9.8/10.0, 0.0, 0.0, 0.0, 5.0/365.0]
    padded_critical = base_critical + [0.0] * max(0, lstm_expected_dim - len(base_critical))
    critical_cve = np.array([[padded_critical[:lstm_expected_dim]]])
    prob_critical = float(np.max(lstm.predict(critical_cve)[0]))
    
    # Test Case 2: Low severity (Low CVSS, High Complexity, High Privileges required, Old)
    base_low = [3.5/10.0, 1.0, 1.0, 1.0, 1500.0/365.0]
    padded_low = base_low + [0.0] * max(0, lstm_expected_dim - len(base_low))
    low_cve = np.array([[padded_low[:lstm_expected_dim]]])
    prob_low = float(np.max(lstm.predict(low_cve)[0]))
    
    print(f"Test 1A (Critical Zero-Day): Predicted Likelihood = {prob_critical*100:.2f}%")
    print(f"Test 1B (Low-Risk Old CVE):  Predicted Likelihood = {prob_low*100:.2f}%")
    
    if prob_critical > prob_low:
        print("[PASS] LSTM Accuracy Test: Model successfully ranked Critical > Low-Risk.")
    else:
        print("[FAIL] LSTM Accuracy Test: Ranking assertion failed (Critical must be > Low).")
        sys.exit(1)

    print("\n--- 2. Testing Autoencoder Anomaly Detector ---")
    
    # Dynamically get expected dimensions
    ae_expected_dim = ae.weights[0][0].shape[0] if hasattr(ae, 'weights') else 20
    
    # Features: [byte_rate, packet_size_mean, packet_count, duration, payload_entropy]
    
    # Test Case A: Normal web traffic
    base_normal = [
        1500.0/20000.0,   # byte rate
        512.0/2000.0,     # packet size
        100.0/2000.0,     # packet count
        5.0/10.0,         # duration
        4.0/8.0           # entropy
    ]
    padded_normal = base_normal + [0.0] * max(0, ae_expected_dim - len(base_normal))
    normal_traffic = np.array([padded_normal[:ae_expected_dim]])
    
    # Test Case B: SYN Flood or DDoS (Huge packet count, low size, zero duration, weird entropy)
    base_ddos = [
        350000.0/20000.0, 
        64.0/2000.0, 
        8000.0/2000.0, 
        0.1/10.0, 
        1.5/8.0
    ]
    padded_ddos = base_ddos + [0.0] * max(0, ae_expected_dim - len(base_ddos))
    ddos_traffic = np.array([padded_ddos[:ae_expected_dim]])
    
    out_normal = ae.predict(normal_traffic)
    mse_normal = float(np.mean(np.square(normal_traffic - out_normal))) * 10.0
    
    out_ddos = ae.predict(ddos_traffic)
    mse_ddos = float(np.mean(np.square(ddos_traffic - out_ddos))) * 10.0
    
    print(f"Test 2A (Normal Web Traffic): Anomaly Score = {mse_normal:.4f}")
    print(f"Test 2B (Massive SYN Flood):  Anomaly Score = {mse_ddos:.4f}")
    
    if mse_ddos > mse_normal:
        print("[PASS] Autoencoder Accuracy Test: Model successfully separated DDoS anomaly > Normal traffic.")
    else:
        print("[FAIL] Autoencoder Accuracy Test: Separation assertion failed (DDoS must be > Normal).")
        sys.exit(1)

    print("\n==================================================")
    print("All tests completed.")

if __name__ == "__main__":
    run_tests()
