import aiohttp
import json
import logging
from typing import Dict, Any, List

from app.services.ml.output_validation import UNTRUSTED_EVIDENCE_RULE, wrap_untrusted

logger = logging.getLogger("itap.llm")

# Default to Ollama local API
OLLAMA_API_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3" # Or custom trained model name like 'itap_llama3_lora'

class LocalLLMService:
    @staticmethod
    async def is_ollama_available() -> bool:
        """Check if the local Ollama LLM is running and reachable."""
        try:
            async with aiohttp.ClientSession() as session:
                # We can just check the root endpoint for a 200 OK
                async with session.get("http://localhost:11434/", timeout=2) as response:
                    return response.status == 200
        except Exception:
            return False

    @staticmethod
    async def generate_prediction(domain: str, osint_data: dict, lstm_results: Any = None, autoencoder_results: Any = None) -> List[Dict[str, Any]]:
        """
        Prompt the local Llama 3 model to predict threats based on OSINT data.
        Integrates math outputs from the LSTM and Autoencoder ensemble models.
        Falls back to Statistical ML Engine (lstm_results) if LLM is unreachable or fails.
        """
        import re

        if not await LocalLLMService.is_ollama_available():
            logger.warning("Ollama LLM unreachable. Falling back to Statistical ML Engine (LSTMPredictor).")
            if lstm_results:
                return lstm_results
            from app.services.ml.ml_engine import LSTMPredictor
            return await LSTMPredictor.predict_threats(domain, osint_data)

        prompt = f"""
        You are an elite Incident Responder and Forensics Analyst. Review the following evidence for the target: {domain}.

        {UNTRUSTED_EVIDENCE_RULE}
        {wrap_untrusted({
            "osint_summary": osint_data.get('summary', {}),
            "lstm_time_series_predictions": lstm_results,
            "autoencoder_anomaly_detection": autoencoder_results,
        })}

        Based on ALL of this numeric and textual evidence, generate the final JSON triage and predict the top 3 most likely cyber attacks.
        For each threat, your analysis MUST be hyper-specific and technical:
        1. The exact attack type and CVE if applicable.
        2. ROOT CAUSE: Describe the precise memory flaw, architectural weakness, or misconfiguration (e.g., "Use-after-free in nf_tables", "Unsanitized input to eval()").
        3. ATTACK VECTOR: Provide the step-by-step kill chain. Include technical details like HTTP payloads, exact commands (e.g., curl, nmap), or exploitation techniques.
        4. AFFECTED COMPONENTS: Identify specific services, daemons, or frameworks based on the OSINT data.
        5. REMEDIATION: Provide actionable, code-level remediation (e.g., exact iptables/ufw block rules, nginx.conf snippets, patch commands, or registry edits).

        Output MUST be in strict JSON array format. DO NOT use markdown code blocks (```json) in your response, just the raw JSON:
        [
          {{
            "predicted_attack_type": "string",
            "predicted_cve": "string or null",
            "probability": float (0.0 to 1.0),
            "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
            "confidence": "high" | "medium" | "low",
            "root_cause": "string — Hyper-specific technical flaw",
            "attack_vector_detail": "string — Step-by-step kill chain with technical payloads",
            "affected_components": ["string", "..."],
            "remediation": [
              {{"step": 1, "action": "string", "priority": "immediate", "detail": "string with exact commands/snippets"}},
              {{"step": 2, "action": "string", "priority": "short-term", "detail": "string"}},
              {{"step": 3, "action": "string", "priority": "long-term", "detail": "string"}}
            ]
          }}
        ]
        """

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(OLLAMA_API_URL, json={
                    "model": MODEL_NAME,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json"
                }, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        response_text = data.get("response", "[]")
                        
                        # Robust JSON parsing: strip Markdown wrappers
                        cleaned_json = re.sub(r"```json\s*|\s*```", "", response_text.strip())

                        try:
                            predictions = json.loads(cleaned_json)
                            # Backfill any missing enrichment fields from the KB
                            from app.services.ml.ml_engine import LSTMPredictor
                            for p in predictions:
                                p['time_window_hours'] = 72
                                attack_type = p.get("predicted_attack_type", "Exploitation Attempt")
                                # Fill in any fields the LLM skipped
                                if not p.get("root_cause") or not p.get("remediation"):
                                    rca = LSTMPredictor._get_root_cause_info(
                                        attack_type, p.get("cve_description", ""),
                                        target_domain=domain, osint_data=osint_data
                                    )
                                    p.setdefault("root_cause", rca["root_cause"])
                                    p.setdefault("attack_vector_detail", rca["attack_vector_detail"])
                                    p.setdefault("affected_components", rca["affected_components"])
                                    p.setdefault("remediation", rca["remediation"])
                            return predictions
                        except json.JSONDecodeError:
                            logger.error(f"Failed to parse LLM JSON. Falling back to ML Engine. Cleaned text: {cleaned_json[:200]}")
                            if lstm_results: return lstm_results
                            from app.services.ml.ml_engine import LSTMPredictor
                            return await LSTMPredictor.predict_threats(domain, osint_data)
                    else:
                        if lstm_results: return lstm_results
                        from app.services.ml.ml_engine import LSTMPredictor
                        return await LSTMPredictor.predict_threats(domain, osint_data)
        except Exception as e:
            logger.error(f"Error connecting to local LLM: {e}. Falling back to ML Engine.")
            if lstm_results: return lstm_results
            from app.services.ml.ml_engine import LSTMPredictor
            return await LSTMPredictor.predict_threats(domain, osint_data)

    @staticmethod
    async def generate_remediation_for_active_threat(domain: str, threat_title: str, threat_desc: str) -> Dict[str, Any]:
        """
        Prompt the local Llama 3 model to generate root cause and remediation for a specific active threat (e.g. from Nmap).
        Falls back to Statistical ML Engine if LLM is unreachable.
        """
        import re

        if not await LocalLLMService.is_ollama_available():
            from app.services.ml.ml_engine import LSTMPredictor
            # Fallback to ML Engine's knowledge base
            return LSTMPredictor._get_root_cause_info(threat_title, threat_desc, domain, {})

        prompt = f"""
        You are an elite Incident Responder. Provide a precise, highly technical root cause and remediation plan for the following confirmed vulnerability on {domain}:

        {UNTRUSTED_EVIDENCE_RULE}
        {wrap_untrusted({
            "vulnerability_title": threat_title,
            "vulnerability_details": threat_desc,
        }, label="vulnerability")}

        Output MUST be in strict JSON object format. DO NOT use markdown code blocks (```json) in your response, just the raw JSON:
        {{
          "root_cause": "string — Hyper-specific technical flaw causing this issue.",
          "attack_vector_detail": "string — Step-by-step kill chain an attacker would use to exploit this.",
          "remediation": [
            {{"step": 1, "action": "string", "priority": "immediate", "detail": "string with exact commands/snippets"}},
            {{"step": 2, "action": "string", "priority": "short-term", "detail": "string"}},
            {{"step": 3, "action": "string", "priority": "long-term", "detail": "string"}}
          ]
        }}
        """

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(OLLAMA_API_URL, json={
                    "model": MODEL_NAME,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json"
                }, timeout=15) as response:
                    if response.status == 200:
                        data = await response.json()
                        response_text = data.get("response", "{}")
                        cleaned_json = re.sub(r"```json\s*|\s*```", "", response_text.strip())
                        
                        try:
                            result = json.loads(cleaned_json)
                            return result
                        except json.JSONDecodeError:
                            logger.error(f"Failed to parse LLM JSON for active threat. Falling back. Cleaned text: {cleaned_json[:200]}")
        except Exception as e:
            logger.error(f"Error calling LLM for active threat enrichment: {e}. Falling back to ML Engine.")

        # Fallback if LLM failed
        from app.services.ml.ml_engine import LSTMPredictor
        return LSTMPredictor._get_root_cause_info(threat_title, threat_desc, domain, {})

    @staticmethod
    async def detect_anomalies() -> Dict[str, Any]:
        """
        Prompt the local Llama 3 model to analyze recent network traffic logs for anomalies.
        Falls back to Statistical ML Engine (AutoencoderDetector) if LLM is unreachable.
        """
        if not await LocalLLMService.is_ollama_available():
            logger.warning("Ollama LLM unreachable. Falling back to Statistical ML Engine (AutoencoderDetector).")
            from app.services.ml.ml_engine import AutoencoderDetector
            anomalies = await AutoencoderDetector.detect_anomalies(threshold=0.82)
            return {
                "anomalies_detected": len(anomalies),
                "anomalies": anomalies
            }

        prompt = """
        You are an advanced cybersecurity AI analyzing recent network traffic. 
        Generate 3 realistic anomalies based on common attack patterns (e.g., brute force, port scan, data exfiltration).
        These are ILLUSTRATIVE EXAMPLES, not observations: state nothing as a confirmed
        finding, and do not imply any real host or address is involved.
        Output MUST be in strict JSON array format:
        [
          {{
            "source_ip": "IP Address",
            "anomaly_score": float (0.8 to 1.0),
            "classification": "string",
            "pattern_fingerprint": "hex string"
          }}
        ]
        Respond with ONLY the JSON array. Do not include any markdown formatting.
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(OLLAMA_API_URL, json={
                    "model": MODEL_NAME,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json"
                }, timeout=15) as response:
                    if response.status == 200:
                        data = await response.json()
                        response_text = data.get("response", "[]")
                        try:
                            anomalies = json.loads(response_text)
                            if not isinstance(anomalies, list):
                                return {"anomalies_detected": 0, "anomalies": []}
                            # The prompt asks the model to *generate* plausible
                            # anomalies, and it is given no real traffic data — so
                            # every field (including the attacker IPs) is invented.
                            # Tag it, because the API endpoint downstream used to file
                            # CRITICAL incidents against these fabricated addresses.
                            flagged = []
                            for item in anomalies:
                                if not isinstance(item, dict):
                                    continue
                                item.setdefault("is_anomalous", True)
                                item["is_simulated"] = True
                                item["synthetic_flow_inventory"] = True
                                item["evidence_source"] = "llm_generated"
                                flagged.append(item)
                            return {
                                "anomalies_detected": len(flagged),
                                "anomalies": flagged,
                            }
                        except json.JSONDecodeError:
                            return {"anomalies_detected": 0, "anomalies": []}
                    else:
                        from app.services.ml.ml_engine import AutoencoderDetector
                        anomalies = await AutoencoderDetector.detect_anomalies(threshold=0.82)
                        return {"anomalies_detected": len(anomalies), "anomalies": anomalies}
        except Exception:
            from app.services.ml.ml_engine import AutoencoderDetector
            anomalies = await AutoencoderDetector.detect_anomalies(threshold=0.82)
            return {"anomalies_detected": len(anomalies), "anomalies": anomalies}

llm_service = LocalLLMService()
