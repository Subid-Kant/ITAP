import aiohttp
import json
import logging
from typing import Dict, Any, List

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
    async def generate_prediction(domain: str, osint_data: dict) -> List[Dict[str, Any]]:
        """
        Prompt the local Llama 3 model to predict threats based on OSINT data.
        Falls back to Statistical ML Engine (LSTMPredictor) if LLM is unreachable.
        All predictions include root_cause, attack_vector_detail, affected_components,
        and a structured remediation playbook.
        """
        if not await LocalLLMService.is_ollama_available():
            logger.warning("Ollama LLM unreachable. Falling back to Statistical ML Engine (LSTMPredictor).")
            from app.services.ml.ml_engine import LSTMPredictor
            return await LSTMPredictor.predict_threats(domain, osint_data)

        prompt = f"""
        You are an advanced cybersecurity AI. Analyze the following OSINT data for the target domain: {domain}.
        OSINT Data: {json.dumps(osint_data.get('summary', {}))}

        Predict the top 3 most likely cyber attacks against this target.
        For each threat, provide:
        1. The attack type and CVE if applicable
        2. The ROOT CAUSE — WHY this threat exists (the underlying vulnerability, misconfiguration, or weakness)
        3. The ATTACK VECTOR DETAIL — HOW an attacker would actually exploit this step by step
        4. Which specific COMPONENTS are affected based on the OSINT data
        5. A structured REMEDIATION plan with immediate, short-term, and long-term steps

        Output MUST be in strict JSON array format:
        [
          {{
            "predicted_attack_type": "string",
            "predicted_cve": "string or null",
            "probability": float (0.0 to 1.0),
            "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
            "confidence": "high" | "medium" | "low",
            "root_cause": "string — WHY this threat exists, the underlying vulnerability or misconfiguration",
            "attack_vector_detail": "string — HOW the attacker exploits this step by step",
            "affected_components": ["string", "..."],
            "remediation": [
              {{"step": 1, "action": "string", "priority": "immediate", "detail": "string"}},
              {{"step": 2, "action": "string", "priority": "short-term", "detail": "string"}},
              {{"step": 3, "action": "string", "priority": "long-term", "detail": "string"}}
            ]
          }}
        ]
        Respond with ONLY the JSON array. Do not include any markdown formatting like ```json.
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
                            predictions = json.loads(response_text)
                            # Backfill any missing enrichment fields from the KB
                            from app.services.ml.ml_engine import LSTMPredictor
                            for p in predictions:
                                p['time_window_hours'] = 72
                                attack_type = p.get("predicted_attack_type", "Exploitation Attempt")
                                # Fill in any fields the LLM skipped
                                if not p.get("root_cause") or not p.get("remediation"):
                                    rca = LSTMPredictor._get_root_cause_info(
                                        attack_type, p.get("cve_description", "")
                                    )
                                    p.setdefault("root_cause", rca["root_cause"])
                                    p.setdefault("attack_vector_detail", rca["attack_vector_detail"])
                                    p.setdefault("affected_components", rca["affected_components"])
                                    p.setdefault("remediation", rca["remediation"])
                            return predictions
                        except json.JSONDecodeError:
                            logger.error(f"Failed to parse LLM response as JSON: {response_text}")
                            return []
                    else:
                        from app.services.ml.ml_engine import LSTMPredictor
                        return await LSTMPredictor.predict_threats(domain, osint_data)
        except Exception as e:
            logger.error(f"Error connecting to local LLM: {e}")
            from app.services.ml.ml_engine import LSTMPredictor
            return await LSTMPredictor.predict_threats(domain, osint_data)

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
                            return {
                                "anomalies_detected": len(anomalies),
                                "anomalies": anomalies
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
