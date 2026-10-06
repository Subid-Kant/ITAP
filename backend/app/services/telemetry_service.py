import json
import hashlib
import os
import threading
import uuid
import datetime
import logging
from typing import Dict, Any

logger = logging.getLogger("itap.telemetry")

class TelemetryCollector:
    DATASET_PATH = os.path.join(os.path.dirname(__file__), "../../../data/telemetry_dataset.jsonl")
    HISTORY_PATH = os.path.join(os.path.dirname(__file__), "../../../data/telemetry_history.json")

    # In-process mutual exclusion for the read-compare-write cycle below.
    #
    # threading, not asyncio: writers reach log_scan from more than one event loop —
    # the API loop, background monitors, worker threads that call asyncio.run, and the
    # dataset scripts in ai_training/. An asyncio.Lock only serialises tasks inside the
    # one loop that first contended it, and once contended it *raises* RuntimeError for
    # every other loop. It therefore neither serialised nor protected cross-loop
    # writers. A threading lock covers every thread and loop in the process, and since
    # the critical section below performs no await, holding it can never stall the
    # event loop for longer than one small file write.
    #
    # INVARIANT: do not await inside this lock.
    #
    # Limitation: this is per-process. Multiple uvicorn workers sharing one dataset
    # file still need OS-level file locking (portalocker/fcntl) to be fully safe.
    _write_lock = threading.RLock()

    @classmethod
    def ensure_directories(cls):
        os.makedirs(os.path.dirname(cls.DATASET_PATH), exist_ok=True)
        if not os.path.exists(cls.HISTORY_PATH):
            with open(cls.HISTORY_PATH, "w", encoding="utf-8") as f:
                json.dump({}, f)

    @classmethod
    def generate_fingerprint(cls, domain: str, osint_data: Dict[str, Any]) -> str:
        """
        Generate a stable SHA-256 fingerprint based on the immutable characteristics of a scan.
        This ignores volatile fields like timestamps and risk_score.
        """
        # Extract open_ports which is an integer count, or default to 0
        open_ports = osint_data.get("summary", {}).get("open_ports", 0)
        
        fingerprint_data = {
            "domain": domain,
            "open_ports": open_ports,
            "vulnerabilities": []
        }
        
        for svc in osint_data.get("vulnerabilities_by_service", []):
            cve_list = sorted([c.get("cve_id") for c in svc.get("cves", []) if c.get("cve_id")])
            fingerprint_data["vulnerabilities"].append({
                "service": svc.get("service"),
                "port": svc.get("port"),
                "version": svc.get("version"),
                "cves": cve_list
            })
            
        fingerprint_data["vulnerabilities"] = sorted(fingerprint_data["vulnerabilities"], key=lambda x: str(x))
        
        raw_string = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(raw_string.encode('utf-8')).hexdigest()

    @classmethod
    def _get_last_fingerprint_unlocked(cls, domain: str) -> str:
        """Fetch the last known fingerprint for a domain from the local history."""
        try:
            with open(cls.HISTORY_PATH, "r", encoding="utf-8") as f:
                history = json.load(f)
                return history.get(domain, {}).get("fingerprint")
        except Exception:
            return None

    @classmethod
    def _update_last_fingerprint_unlocked(cls, domain: str, fingerprint: str, event_id: str):
        """Update the local history with the new fingerprint."""
        cls.ensure_directories()
        try:
            with open(cls.HISTORY_PATH, "r", encoding="utf-8") as f:
                history = json.load(f)
                
            history[domain] = {
                "fingerprint": fingerprint,
                "last_event_id": event_id,
                "timestamp": datetime.datetime.utcnow().isoformat()
            }
            
            with open(cls.HISTORY_PATH, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to update telemetry history: {e}")

    @classmethod
    async def log_scan(
        cls, 
        domain: str, 
        osint_data: Dict[str, Any], 
        lstm_results: Any, 
        autoencoder_results: Any, 
        llm_output: Any,
        model_metadata: Dict[str, Any] = None
    ):
        """
        Deduplicates scans via fingerprinting and logs meaningful changes into the training dataset.
        Appends all scans, but marks duplicates as training_eligible: false.
        Uses a single transaction lock to prevent concurrent scan race conditions.
        """
        cls.ensure_directories()
        
        fingerprint = cls.generate_fingerprint(domain, osint_data)
        # uuid4 entropy: datetime.utcnow() only advances in coarse ticks on
        # Windows, so bursts of scans inside one tick used to mint identical
        # event_ids — duplicate keys in the very dataset models train on.
        event_id = f"evt-{hashlib.md5((domain + str(datetime.datetime.utcnow()) + uuid.uuid4().hex).encode()).hexdigest()[:8]}"
        
        # Serialise the whole read-compare-write cycle: two scans that both read
        # "no previous fingerprint" before either writes would each claim to be new.
        with cls._write_lock:
            last_fingerprint = cls._get_last_fingerprint_unlocked(domain)
            
            training_eligible = True
            duplicate_of = None
            reason = "new_or_changed_scan_state"
            
            if last_fingerprint and fingerprint == last_fingerprint:
                training_eligible = False
                duplicate_of = last_fingerprint
                reason = "unchanged_scan_state"

            # Construct the telemetry record
            record = {
                "event_id": event_id,
                "domain": domain,
                "observed_at": datetime.datetime.utcnow().isoformat() + "Z",
                "fingerprint": fingerprint,
                "duplicate_of": duplicate_of,
                "training_eligible": training_eligible,
                "reason": reason,
                
                # Label Quality (Weak by default)
                "label_source": "osint_rule",
                "label_confidence": 0.45,
                "analyst_reviewed": False,
                
                # Metadata
                "schema_version": "v3.0",
                "model_metadata": model_metadata or {},
                
                
                # Inputs (The Ensemble Data)
                "inputs": {
                    "osint_summary": osint_data.get("summary", {}),
                    "lstm_predictions": lstm_results,
                    "autoencoder_anomalies": autoencoder_results
                },
                
                # Output (The LLM Target)
                "output_triage": llm_output
            }

            # Write to the JSONL dataset (append all scans)
            try:
                with open(cls.DATASET_PATH, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
                if training_eligible:
                    logger.info(f"Telemetry logged candidate for {domain} (Event: {event_id})")
                else:
                    logger.info(f"Telemetry logged duplicate for {domain} (Fingerprint matched)")
            except Exception as e:
                logger.error(f"Failed to write to telemetry dataset: {e}")
                
            # Update history reference regardless
            cls._update_last_fingerprint_unlocked(domain, fingerprint, event_id)
