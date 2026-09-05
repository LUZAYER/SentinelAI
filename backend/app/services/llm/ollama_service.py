"""
Ollama LLM Service

Handles integration with local Ollama instance for generating explanations.
"""

import json
import logging
import time

import httpx

from backend.app.core.config import settings
from backend.app.services.llm.prompts import SYSTEM_PROMPT, EXPLANATION_PROMPT_TEMPLATE

logger = logging.getLogger(__name__)


class OllamaService:
    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL
        self.model = settings.OLLAMA_MODEL
        self.timeout = 120.0  # Allow up to 2 minutes for LLM generation

    def explain_analysis(self, analysis_type: str, detection_result: dict, risk_data: dict) -> dict:
        """Generate structured explanation using Ollama."""
        start_time = time.time()

        # Format evidence as JSON string for the prompt
        indicators_str = json.dumps(detection_result.get("indicators", {}), indent=2)
        evidence_str = json.dumps(detection_result.get("evidence", {}), indent=2)
        
        # Limit technical details to prevent context overflow
        tech_details = detection_result.get("technical_details", {})
        # Remove potentially huge fields if they exist
        if "frame_analysis" in tech_details and len(tech_details["frame_analysis"]) > 5:
            tech_details["frame_analysis"] = tech_details["frame_analysis"][:5]
            tech_details["frame_analysis_note"] = "... (truncated)"
        tech_details_str = json.dumps(tech_details, indent=2)

        prompt = EXPLANATION_PROMPT_TEMPLATE.format(
            analysis_type=analysis_type,
            risk_score=risk_data.get("overall_score", 0),
            severity=risk_data.get("severity", "UNKNOWN"),
            confidence=risk_data.get("confidence", 0),
            status=detection_result.get("status", "unknown"),
            detector_score=detection_result.get("risk_score", 0),
            indicators=indicators_str,
            evidence=evidence_str,
            technical_details=tech_details_str,
        )

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.1,  # Low temperature for more deterministic/factual output
                "top_p": 0.9,
            }
        }

        try:
            # We must use synchronous httpx because this is called from Celery worker (sync)
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(f"{self.base_url}/api/chat", json=payload)
                response.raise_for_status()
                
                data = response.json()
                content = data.get("message", {}).get("content", "{}")
                
                try:
                    parsed_content = json.loads(content)
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse LLM JSON response: {content}")
                    # Try to salvage if it returned markdown json
                    if "```json" in content:
                        clean_content = content.split("```json")[1].split("```")[0].strip()
                        parsed_content = json.loads(clean_content)
                    else:
                        parsed_content = self._get_fallback_response(analysis_type, risk_data)
                
                parsed_content["model"] = self.model
                parsed_content["raw_response"] = content
                parsed_content["processing_time"] = round(time.time() - start_time, 2)
                
                return parsed_content
                
        except Exception as e:
            logger.error(f"Ollama API request failed: {e}", exc_info=True)
            fallback = self._get_fallback_response(analysis_type, risk_data)
            fallback["processing_time"] = round(time.time() - start_time, 2)
            return fallback

    def _get_fallback_response(self, analysis_type: str, risk_data: dict) -> dict:
        """Provide a fallback response if LLM generation fails."""
        severity = risk_data.get("severity", "UNKNOWN")
        score = risk_data.get("overall_score", 0)
        
        return {
            "model": "fallback_generator",
            "summary": f"{analysis_type.capitalize()} analysis completed with {severity} severity.",
            "explanation": (
                f"This {analysis_type} analysis has been completed with an overall risk score of "
                f"{score}/100 ({severity} severity). The detection pipeline identified the indicators "
                f"listed in the evidence section. LLM generation failed or timed out."
            ),
            "risk_explanation": f"The risk score of {score}/100 indicates {severity.lower()} risk level.",
            "recommendations": [
                "Review the detailed evidence and indicators provided by the detection pipeline.",
                "Cross-reference findings with other sources if available."
            ],
            "raw_response": None
        }
