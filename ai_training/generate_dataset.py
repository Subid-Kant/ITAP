import json
import random
import hashlib
from datetime import datetime

# Harsh, realistic scenarios to train the model to be rigorous
SCENARIOS = [
    {
        "context": "A web application endpoint /api/v2/users?id=1' OR '1'='1 is receiving thousands of requests from a distributed botnet.",
        "tasks": [
            {
                "instruction": "Classify the primary threat tactic and technique.",
                "response": '{"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "sub_technique": "SQL Injection", "confidence": "high", "reasoning": "The payload \\"1\' OR \'1\'=\'1\\" is a classic SQL injection signature aimed at bypassing authentication or extracting data via a public-facing API."}'
            },
            {
                "instruction": "Generate a harsh, zero-tolerance incident response playbook for this active SQLi attack.",
                "response": '{"priority": "CRITICAL", "actions": ["IMMEDIATE ACTION: Deploy WAF rule to block signature \\"OR \'1\'=\'1\\"", "IMMEDIATE ACTION: Temporarily sinkhole traffic from identified botnet ASNs", "INVESTIGATION: Query database audit logs for unauthorized SELECT/DROP statements in the last 24 hours", "REMEDIATION: Force password reset for all users if data exfiltration is confirmed", "CODE FIX: Demand immediate deployment of parameterized queries for the /api/v2/users endpoint. No exceptions."]}'
            }
        ]
    },
    {
        "context": "Internal network monitoring detects an anomalous PowerShell command: `powershell.exe -nop -w hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA...` executing on a finance department workstation.",
        "tasks": [
            {
                "instruction": "Analyse this anomaly and classify the threat.",
                "response": '{"classification": "Execution / Defense Evasion", "severity": "CRITICAL", "threat_type": "Obfuscated PowerShell Execution (Likely C2/Stager)", "reasoning": "The use of \'-nop\' (NoProfile), \'-w hidden\' (WindowStyle Hidden), and \'-EncodedCommand\' with a base64 string is a highly suspicious, adversarial technique used to execute malicious payloads in memory while evading basic logging and AV."}'
            }
        ]
    },
    {
        "context": "A Linux server in the DMZ suddenly initiates outbound connections on port 4444 to an unknown IP in a high-risk ASN, transferring 500MB of data in 5 minutes.",
        "tasks": [
            {
                "instruction": "Evaluate the risk and predict the kill chain progression.",
                "response": '{"current_phase": "Exfiltration", "risk_score": 98, "predicted_next": ["Impact (Data Destruction/Ransomware)"], "reasoning": "Outbound traffic on non-standard ports (4444 is a default Metasploit handler port) combined with high data transfer volume from a DMZ asset strongly indicates a successful compromise and active data exfiltration. The attacker has already achieved C2 and is stealing data."}'
            }
        ]
    },
    {
        "context": "OSINT data reveals the target domain has 5 open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3389 (RDP), and 9200 (Elasticsearch). The RDP port has been hit with 50,000 failed login attempts in the last hour.",
        "tasks": [
            {
                "instruction": "Assess the security posture and provide strict remediation steps.",
                "response": '{"posture": "UNACCEPTABLE", "critical_findings": ["RDP (3389) exposed to public internet", "Elasticsearch (9200) potentially exposed", "Active Brute Force campaign against RDP"], "remediation": ["MANDATORY: Close port 3389 at the perimeter firewall immediately. Require VPN for RDP access.", "MANDATORY: Block source IPs of the brute force attack.", "MANDATORY: Verify Elasticsearch (9200) requires authentication and is not bound to 0.0.0.0.", "INVESTIGATION: Check event logs for ANY successful RDP logins during the attack window."]}'
            }
        ]
    },
    # Add more harsh/realistic scenarios here...
]

def generate_dataset(num_samples=1500):
    dataset = []
    
    # Generate variations of the base scenarios to create a robust dataset
    for _ in range(num_samples):
        base = random.choice(SCENARIOS)
        
        # Add slight permutations to context to prevent memorization
        context = base["context"]
        if "botnet" in context:
            context = context.replace("botnet", random.choice(["botnet", "APT group", "proxy network"]))
        if "4444" in context:
            context = context.replace("4444", random.choice(["4444", "8080", "1337", "53"]))
            
        task = random.choice(base["tasks"])
        
        # Llama 3 Instruct Format
        prompt = f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\nYou are ITAP-AI, a ruthless, highly-skilled cybersecurity analyst. Analyze threats with zero tolerance for poor security practices. Output strict JSON only.<|eot_id|><|start_header_id|>user<|end_header_id|>\n\nContext: {context}\nInstruction: {task['instruction']}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n{task['response']}<|eot_id|>"
        
        dataset.append({"text": prompt})
        
    return dataset

if __name__ == "__main__":
    print("Generating rigorous cybersecurity training dataset...")
    data = generate_dataset(2000)
    
    with open("itap_training_data.jsonl", "w") as f:
        for item in data:
            f.write(json.dumps(item) + "\n")
            
    print(f"Dataset generated: itap_training_data.jsonl ({len(data)} samples)")
