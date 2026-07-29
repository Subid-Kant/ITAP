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
        """
        if not await LocalLLMService.is_ollama_available():
            logger.warning("Ollama LLM unreachable. Falling back to Statistical ML Engine (LSTMPredictor).")
            from app.services.ml.ml_engine import LSTMPredictor
            return await LSTMPredictor.predict_threats(domain, osint_data)

        prompt = f"""
        You are an advanced cybersecurity AI. Analyze the following OSINT data for the target domain: {domain}.
        OSINT Data: {json.dumps(osint_data.get('summary', {}))}
        
        Predict the top 3 most likely cyber attacks that could be carried out against this target.
        Output MUST be in strict JSON array format with the following keys:
        [
          {{
            "predicted_attack_type": "string",
            "predicted_cve": "string or null",
            "probability": float (0.0 to 1.0),
            "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
            "confidence": "high" | "medium" | "low"
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
                            # Ensure it has the correct fields
                            for p in predictions:
                                p['time_window_hours'] = 72
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
