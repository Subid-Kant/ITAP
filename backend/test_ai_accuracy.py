import sys
import os
import numpy as np
from pathlib import Path

# Add backend to path so we can import native_inference
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.services.ml.native_inference import NativeLSTM, NativeAutoencoder

def run_tests():
    print("==================================================")
    print("      ITAP AI Model Accuracy Validation Suite     ")
    print("==================================================")
    
    weights_dir = Path(__file__).parent / "app" / "services" / "ml" / "weights"
    lstm_path = weights_dir / "itap_lstm_v2.h5"
    ae_path = weights_dir / "itap_autoencoder_v2.h5"
    
    try:
        lstm = NativeLSTM(str(lstm_path))
        ae = NativeAutoencoder(str(ae_path))
        print("[+] Models loaded successfully into Native Engine.")
    except Exception as e:
        print(f"[-] Failed to load models: {e}")
        return

    print("\n--- 1. Testing LSTM Exploit Predictor ---")
    
    # Test Case 1: Critical zero-day (High CVSS, Low Complexity, No Privileges, Recent)
    # Features: [cvss_scaled, complexity, privileges, interaction, age_scaled]
    critical_cve = np.array([[[9.8/10.0, 0.0, 0.0, 0.0, 5.0/365.0]]])
    prob_critical = lstm.predict(critical_cve)[0][0]
    
    # Test Case 2: Low severity (Low CVSS, High Complexity, High Privileges required, Old)
    low_cve = np.array([[[3.5/10.0, 1.0, 1.0, 1.0, 1500.0/365.0]]])
    prob_low = lstm.predict(low_cve)[0][0]
    
    print(f"Test 1A (Critical Zero-Day): Predicted Likelihood = {prob_critical*100:.2f}%")
    print(f"Test 1B (Low-Risk Old CVE):  Predicted Likelihood = {prob_low*100:.2f}%")
    
    if prob_critical > 0.70 and prob_low < 0.30:
        print("[PASS] LSTM Accuracy Test: The model successfully distinguishes between critical and low-risk threats.")
    else:
        print("[FAIL] LSTM Accuracy Test: The mathematical separation is not strict enough.")

    print("\n--- 2. Testing Autoencoder Anomaly Detector ---")
    
    # Features: [byte_rate, packet_size_mean, packet_count, duration, payload_entropy]
    
    # Test Case A: Normal web traffic
    normal_traffic = np.array([[
        1500.0/20000.0,   # byte rate
        512.0/2000.0,     # packet size
        100.0/2000.0,     # packet count
        5.0/10.0,         # duration
        4.0/8.0           # entropy
    ]])
    
    # Test Case B: SYN Flood or DDoS (Huge packet count, low size, zero duration, weird entropy)
    ddos_traffic = np.array([[
        350000.0/20000.0, 
        64.0/2000.0, 
        8000.0/2000.0, 
        0.1/10.0, 
        1.5/8.0
    ]])
    
    out_normal = ae.predict(normal_traffic)
    mse_normal = float(np.mean(np.square(normal_traffic - out_normal))) * 10.0
    
    out_ddos = ae.predict(ddos_traffic)
    mse_ddos = float(np.mean(np.square(ddos_traffic - out_ddos))) * 10.0
    
    print(f"Test 2A (Normal Web Traffic): Anomaly Score = {min(mse_normal, 0.99):.4f} (Closer to 0 is better)")
    print(f"Test 2B (Massive SYN Flood):  Anomaly Score = {min(mse_ddos, 0.99):.4f} (Closer to 1 is better)")
    
    if mse_normal < 0.4 and mse_ddos > 0.7:
        print("[PASS] Autoencoder Accuracy Test: The model successfully flags malicious anomalies.")
    else:
        print("[FAIL] Autoencoder Accuracy Test: Anomaly detection lacks sensitivity.")

    print("\n==================================================")
    print("All tests completed.")

if __name__ == "__main__":
    run_tests()
