"""Create deterministic, synthetic, privacy-safe training datasets for ITAP.

The generated records mirror ITAP's backend contracts. They are seed data and
must be supplemented with reviewed, de-identified production telemetry before
use in a security decision pipeline.
"""
import argparse
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20260916
OUT = Path(__file__).parent / "datasets"
LSTM_FEATURES = ["cvss_scaled", "attack_complexity_high", "privileges_required", "user_interaction_required", "age_scaled"]
AE_FEATURES = ["byte_rate", "packet_size_mean", "packet_count", "duration", "payload_entropy"]

PLAYBOOKS = {
    "sql_injection": ("Initial Access", "T1190", "Exploit Public-Facing Application", "critical", "SQL injection attempts against an internet-facing application", ["Enable a narrowly scoped WAF detection/block rule after validation.", "Preserve reverse-proxy and database audit evidence.", "Replace string-built queries with parameterized queries and add regression tests."]),
    "rdp_bruteforce": ("Credential Access", "T1110", "Brute Force", "high", "repeated failed remote desktop authentications", ["Rate-limit or block the responsible source at the approved perimeter control.", "Review successful logons and reset affected credentials if compromise is verified.", "Require MFA and VPN or zero-trust access for remote administration."]),
    "port_scan": ("Discovery", "T1046", "Network Service Discovery", "medium", "high-rate connection attempts across many destination ports", ["Apply a time-bounded rate limit or block after analyst review.", "Search for related authentication attempts from the same pseudonymous source.", "Reduce externally exposed services and document justified exceptions."]),
    "c2_beacon": ("Command and Control", "T1071", "Application Layer Protocol", "high", "periodic encrypted outbound traffic with an unusual interval", ["Preserve endpoint and proxy telemetry before containment.", "Restrict the destination through the approved egress control after validation.", "Hunt for the same process, certificate fingerprint, and interval on peer hosts."]),
    "data_exfiltration": ("Exfiltration", "T1041", "Exfiltration Over C2 Channel", "critical", "unusual sustained outbound volume to an untrusted destination", ["Escalate to incident response and preserve network evidence.", "Contain the affected asset using the approved change procedure.", "Determine affected data, legal obligations, and the initial access path."]),
    "syn_flood": ("Impact", "T1498", "Network Denial of Service", "high", "a high SYN ratio and packet rate consistent with service exhaustion", ["Engage the network/DDoS response owner and enable approved mitigation.", "Validate service availability and retain flow telemetry.", "Tune capacity, upstream filtering, and alert thresholds after the incident."]),
    "exposed_service": ("Initial Access", "T1133", "External Remote Services", "high", "an unnecessary externally reachable administrative service", ["Confirm business ownership before changing exposure.", "Restrict access to approved management networks and require MFA.", "Remove the service from the public attack surface if no justified use exists."]),
    "malicious_domain": ("Command and Control", "T1071", "Application Layer Protocol", "medium", "a domain with adverse reputation signals from multiple sources", ["Validate the indicator against source confidence and time observed.", "Block or sinkhole through the approved DNS/security workflow.", "Search historical DNS, proxy, and endpoint telemetry for related activity."]),
}

def dump(path, rows):
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")

def ip(token, private=False):
    n = int(hashlib.sha256(token.encode()).hexdigest()[:8], 16)
    return f"10.{(n>>16)%250+1}.{(n>>8)%250+1}.{n%250+1}" if private else f"198.51.100.{n%250+1}"

def llm_rows(rng, count):
    rows, keys = [], list(PLAYBOOKS)
    for i in range(count):
        kind = keys[i % len(keys)]
        tactic, technique_id, technique, severity, finding, actions = PLAYBOOKS[kind]
        asset = f"asset-{i % 48:02d}"
        evidence = {
            "event_id": f"itap-synth-{i:05d}", "asset_id": asset,
            "observed_at": (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=i * 5)).isoformat(),
            "source_ip_token": f"src-{i % 73:03d}", "destination_ip_token": asset,
            "confidence": round(rng.uniform(.72, .98), 2), "data_origin": "synthetic_seed"
        }
        if kind == "rdp_bruteforce": evidence.update({"service": "rdp", "destination_port": 3389, "failed_auth_count_10m": rng.randint(80, 500)})
        elif kind == "port_scan": evidence.update({"service": "network", "unique_destination_ports_5m": rng.randint(30, 180), "syn_ratio": round(rng.uniform(.65, .96), 2)})
        elif kind == "c2_beacon": evidence.update({"service": "https", "beacon_interval_seconds": rng.choice([30, 60, 300]), "payload_entropy": round(rng.uniform(7.1, 7.9), 2)})
        elif kind == "data_exfiltration": evidence.update({"service": "https", "outbound_bytes_10m": rng.randint(80_000_000, 900_000_000), "destination_reputation": "untrusted"})
        elif kind == "syn_flood": evidence.update({"service": "https", "packet_count_1m": rng.randint(10_000, 90_000), "syn_ratio": round(rng.uniform(.82, .99), 2)})
        elif kind == "sql_injection": evidence.update({"service": "https", "waf_rule_family": "sqli", "blocked_request_count_5m": rng.randint(20, 500)})
        elif kind == "exposed_service": evidence.update({"service": "remote_admin", "destination_port": rng.choice([22, 3389, 5900]), "internet_exposed": True})
        else: evidence.update({"service": "dns", "reputation_sources": 2, "domain_token": f"domain-{i%29:02d}.invalid"})
        response = [{"predicted_attack_type": finding, "predicted_cve": None, "probability": evidence["confidence"], "severity": severity.upper(), "confidence": "high" if evidence["confidence"] >= .85 else "medium", "root_cause": "The ITAP evidence indicates an exposure or behavioural pattern requiring analyst validation; no unobserved root cause is asserted.", "attack_vector_detail": "The observed telemetry is consistent with the stated ATT&CK technique. Preserve evidence and validate scope before any containment action.", "affected_components": [evidence["asset_id"], evidence.get("service", "unknown_service")], "remediation": [{"step": n + 1, "action": action, "priority": "immediate" if n == 0 else "short-term" if n == 1 else "long-term", "detail": "Execute through the approved ITAP incident-response and change-management workflow."} for n, action in enumerate(actions)]}]
        rows.append({"messages": [{"role":"system","content":"You are ITAP-AI, a defensive cybersecurity analyst. Return one valid JSON array only, using ITAP prediction fields. Do not invent evidence, credentials, victims, CVEs, or exploit instructions. Recommend proportionate, approved defensive actions."}, {"role":"user","content":"Analyze this ITAP telemetry event and provide a human-readable structured triage result.\n" + json.dumps(evidence)}, {"role":"assistant","content":json.dumps(response)}], "metadata": {"dataset":"itap_llama3_qlora", "task":"triage_and_response", "scenario":kind, "split":"train" if i % 10 < 8 else "validation" if i % 10 == 8 else "test", "synthetic":True, "response_contract":"backend.app.services.ml.llm_service.generate_prediction"}})
    return rows

def lstm_rows(rng, count):
    rows = []
    for i in range(count):
        high = i % 2 == 0
        cvss = rng.uniform(7.5, 10.0) if high else rng.uniform(0.1, 6.5)
        age = rng.uniform(0, 45) if high else rng.uniform(180, 1800)
        seq = []
        for step in range(6):
            drift = step / 200
            seq.append([round(min(1, cvss / 10 + drift), 5), 0.0 if high else 1.0, 0.0 if high else rng.choice([0.0, 1.0]), 0.0 if high else rng.choice([0.0, 1.0]), round(min(1, (age + step) / 3650), 5)])
        probability = round(min(.99, max(.01, .18 + .075 * cvss + (.12 if high else -.10) - age / 12000)), 4)
        rows.append({"event_id":f"lstm-synth-{i:05d}","sequence_id":f"cve-{i:05d}","window_steps":6,"feature_order":LSTM_FEATURES,"sequence":seq,"label":{"exploit_observed_within_72h":int(probability >= .65),"exploit_probability_72h":probability,"label_source":"synthetic_rule"},"metadata":{"split":"train" if i%10<8 else "validation" if i%10==8 else "test","synthetic":True}})
    return rows

def ae_rows(rng, count):
    rows = []
    attack_kinds = [("syn_flood", [320000,64,5000,1,1.2]), ("exfiltration", [1120000,1400,800,45,7.8]), ("port_scan", [96000,64,1500,3,.5]), ("c2_beacon", [8192,256,40,1200,7.9]), ("brute_force", [256000,128,2000,6,3.2])]
    for i in range(count):
        anomalous = i % 5 == 0
        if anomalous:
            family, base = attack_kinds[i % len(attack_kinds)]
            raw = [max(0, x * rng.uniform(.93, 1.07)) for x in base]
        else:
            family = "benign_baseline"
            raw = [max(0, rng.gauss(mu, sd)) for mu, sd in [(10000,3000),(512,150),(150,80),(5,4),(4.5,.8)]]
        norm = [min(1.0, raw[0]/20000), min(1.0, raw[1]/2000), min(1.0, raw[2]/2000), min(1.0, raw[3]/10), min(1.0, raw[4]/8)]
        rows.append({"flow_id":f"ae-synth-{i:05d}","observed_at":(datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(seconds=i*30)).isoformat(),"feature_order":AE_FEATURES,"raw_features":dict(zip(AE_FEATURES,[round(x,4) for x in raw])),"normalized_features":[round(x,6) for x in norm],"label":{"is_anomalous":anomalous,"attack_family":family,"label_source":"synthetic_rule"},"metadata":{"split":"train" if i%10<8 else "validation" if i%10==8 else "test","synthetic":True}})
    return rows

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--llm", type=int, default=960)
    parser.add_argument("--lstm", type=int, default=2400)
    parser.add_argument("--autoencoder", type=int, default=4000)
    args = parser.parse_args()
    OUT.mkdir(exist_ok=True)
    rng = random.Random(SEED)
    dump(OUT / "itap_llama3_qlora.jsonl", llm_rows(rng, args.llm))
    dump(OUT / "itap_lstm_exploit_sequences.jsonl", lstm_rows(rng, args.lstm))
    dump(OUT / "itap_autoencoder_network_flows.jsonl", ae_rows(rng, args.autoencoder))
    manifest = {"generated_at":datetime.now(timezone.utc).isoformat(),"seed":SEED,"files":{"itap_llama3_qlora.jsonl":args.llm,"itap_lstm_exploit_sequences.jsonl":args.lstm,"itap_autoencoder_network_flows.jsonl":args.autoencoder},"warning":"All records are synthetic seed data, not evidence of real attacks or model-quality labels."}
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

if __name__ == "__main__": main()
