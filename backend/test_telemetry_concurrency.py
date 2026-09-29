import asyncio
import os
import json
import uuid
import pytest
from app.services.telemetry_service import TelemetryCollector

@pytest.mark.asyncio
async def test_telemetry_concurrency():
    """
    Test that launching multiple simultaneous identical scans 
    results in exactly ONE training_eligible record.
    """
    # Use a unique domain to avoid colliding with other tests
    test_domain = f"concurrent-test-{uuid.uuid4().hex}.example.com"
    osint_data = {
        "summary": {"open_ports": [80, 443]},
        "vulnerabilities_by_service": [
            {"service": "nginx", "port": 443, "version": "1.18", "cves": [{"cve_id": "CVE-2021-1234"}]}
        ]
    }
    lstm_results = {"prediction": "exploit"}
    ae_results = {"anomaly_score": 0.5}
    llm_output = {"triage": "critical"}
    model_metadata = {"test": True}

    # Launch 5 identical scans concurrently
    tasks = []
    for _ in range(5):
        tasks.append(
            TelemetryCollector.log_scan(
                domain=test_domain,
                osint_data=osint_data,
                lstm_results=lstm_results,
                autoencoder_results=ae_results,
                llm_output=llm_output,
                model_metadata=model_metadata
            )
        )
    
    await asyncio.gather(*tasks)

    # Verify results in JSONL
    dataset_path = TelemetryCollector.DATASET_PATH
    eligible_count = 0
    duplicate_count = 0
    
    if os.path.exists(dataset_path):
        with open(dataset_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("domain") == test_domain:
                    if record.get("training_eligible"):
                        eligible_count += 1
                    else:
                        duplicate_count += 1

    assert eligible_count == 1, f"Expected exactly 1 eligible record, got {eligible_count}"
    assert duplicate_count == 4, f"Expected exactly 4 duplicates, got {duplicate_count}"
