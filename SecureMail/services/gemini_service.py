import os
import json
import logging
import time
from typing import Dict, Any
from django.conf import settings
from google import genai
from google.genai import types

logger = logging.getLogger(__name__)

class GeminiService:
    _instance = None
    _client_initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GeminiService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._client_initialized:
            api_key = getattr(settings, 'GEMINI_API_KEY', os.getenv('GEMINI_API_KEY'))
            if api_key:
                self.client = genai.Client(api_key=api_key)
                self.model_name = 'gemini-flash-latest'
                self._client_initialized = True
                logger.info("GeminiService initialized successfully.")
            else:
                self.client = None
                logger.warning("GEMINI_API_KEY is missing. Gemini explainability is disabled.")

    def explain_analysis(self, email_data: Dict[str, Any], max_retries=2) -> Dict[str, Any]:
        """
        Explain the security decisions made by the local ML engine.
        Does NOT make security decisions. Only explains them.
        """
        logger.info("[GEMINI] explain_analysis() entered")
        if not self.client:
            logger.error("[GEMINI] self.client is None. Returning fallback.")
            return self._get_fallback_explanation(email_data)

        prompt = self._build_prompt(email_data)
        logger.info("[GEMINI] Prompt generated")
        logger.info(f"[GEMINI] Prompt length: {len(prompt)}")
        
        for attempt in range(max_retries):
            try:
                start_time = time.time()
                

                
                logger.info("[GEMINI] Sending request...")
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.2,
                    )
                )
                

                
                logger.info("[GEMINI] Response received")
                if hasattr(response, 'candidates') and response.candidates:
                    logger.info(f"[GEMINI] Candidate count: {len(response.candidates)}")
                    logger.info(f"[GEMINI] Finish reason: {response.candidates[0].finish_reason}")
                if hasattr(response, 'usage_metadata'):
                    logger.info(f"[GEMINI] Token usage: {response.usage_metadata}")
                if hasattr(response, 'text'):
                    logger.info(f"[GEMINI] Response length: {len(response.text)}")
                    
                latency = time.time() - start_time
                if latency > 10.0:
                    logger.warning(f"Gemini execution took {latency:.2f}s, which exceeds the 10s budget.")
                
                logger.info("[GEMINI] Parsing completed")
                result = json.loads(response.text)
                self._validate_schema(result)
                result['latency_ms'] = int(latency * 1000)
                
                # Add cache metadata
                import datetime
                result['generated_at'] = datetime.datetime.now().isoformat()
                result['model_version'] = self.model_name
                result['prompt_version'] = "1.0"
                if hasattr(response, 'usage_metadata'):
                    try:
                        result['token_usage'] = {
                            'prompt_tokens': getattr(response.usage_metadata, 'prompt_token_count', 0),
                            'completion_tokens': getattr(response.usage_metadata, 'candidates_token_count', 0),
                            'total_tokens': getattr(response.usage_metadata, 'total_token_count', 0)
                        }
                    except Exception:
                        result['token_usage'] = {}
                else:
                    result['token_usage'] = {}
                
                logger.info("[GEMINI] Saved to database")
                return result
                
            except json.JSONDecodeError as e:
                logger.error(f"Gemini returned invalid JSON (Attempt {attempt+1}/{max_retries}): {e}")
            except Exception as e:
                import traceback
                logger.error(f"Gemini API Error (Attempt {attempt+1}/{max_retries}): {e}\nTraceback: {traceback.format_exc()}")
                
        logger.error("Gemini failed after max retries. Using fallback.")
        return self._get_fallback_explanation(email_data)

    def _build_prompt(self, email_data: Dict[str, Any]) -> str:
        return f"""You are an expert cybersecurity forensic analyst for SecureMail.
Your task is to EXPLAIN the security decision made by the SecureMail engines.
You MUST NOT change the prediction, confidence, or threat score. The engines have already decided.
You MUST explain why the engine made this decision to a non-technical end user, based on the provided signals.

--- Data Provided by Engines ---
Header Analysis: {email_data.get('header_analysis', {})}
Sender Email: {email_data.get('sender', '')}
Sender Reputation: {email_data.get('sender_reputation', 0)}
URL Analysis: {email_data.get('url_analysis', [])}
ML Engine Prediction: {email_data.get('machine_learning', {}).get('prediction', 'UNKNOWN')} (Confidence: {email_data.get('machine_learning', {}).get('confidence', 0)}%)
ML Features Triggered: {email_data.get('machine_learning', {}).get('features', {})}
Attachment Findings: {email_data.get('attachment_findings', [])}

--- Overall Email Verdict (FINAL & NON-NEGOTIABLE) ---
Threat Score: {email_data.get('overall_risk_score', 0)}/100

Respond strictly in valid JSON format matching this schema:
{{
  "summary": "1-2 sentence high-level summary of what this email is.",
  "attack_type": "The specific type of attack (e.g. Credential Harvesting, Spear Phishing, Safe Marketing) or 'None'.",
  "risk_reason": "A user-friendly explanation of why the threat score is what it is.",
  "recommended_action": "What the user should do next (e.g. 'Delete immediately', 'Safe to open').",
  "user_explanation": "A paragraph explaining the ML engine's decision in plain English.",
  "technical_analysis": "A paragraph explaining the technical red flags (SPF, DKIM, Malicious links).",
  "confidence_comment": "A short comment on why the ML engine has the given confidence level.",
  "red_flags": ["list", "of", "specific", "red", "flags", "found"]
}}
"""

    def _validate_schema(self, data: Dict[str, Any]):
        required_keys = ['summary', 'attack_type', 'risk_reason', 'recommended_action', 
                         'user_explanation', 'technical_analysis', 'confidence_comment', 'red_flags']
        for k in required_keys:
            if k not in data:
                raise ValueError(f"Missing required key in Gemini JSON response: {k}")

    def _get_fallback_explanation(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Deterministic fallback if Gemini fails or is disabled."""
        return {
            "summary": "Automated explanation generation is currently unavailable.",
            "attack_type": email_data.get('prediction', 'Unknown'),
            "risk_reason": f"The ML engine assigned a threat score of {email_data.get('threat_score', 0)}.",
            "recommended_action": "Review the email carefully.",
            "user_explanation": "Gemini explainability is currently offline. The ML Engine's verdict is shown.",
            "technical_analysis": "Deterministic fallback applied. Check raw signals.",
            "confidence_comment": "Based on historical accuracy model.",
            "red_flags": ["Automated system offline - manual review suggested."]
        }
