"""
Base Detector Interface

All detection modules must implement this interface.
This ensures a consistent analysis interface across all detectors
and allows new detectors to be added without redesigning the system.

Every detector's analyze() method returns a standardized DetectionResult dict:
{
    "analysis_type": str,       # e.g., "deepfake", "phishing"
    "status": str,              # "clean", "suspicious", "malicious", "unknown"
    "risk_score": float,        # 0-100
    "confidence": float,        # 0.0 - 1.0
    "indicators": dict,         # Detector-specific indicators
    "evidence": dict,           # Structured evidence
    "technical_details": dict,  # Technical analysis data
    "limitations": list[str],   # Known limitations of this analysis
}
"""

from abc import ABC, abstractmethod
from typing import Any


class BaseDetector(ABC):
    """Abstract base class for all SentinelAI detectors."""

    @abstractmethod
    def analyze(self, **kwargs) -> dict:
        """Run detection analysis on the provided input.

        Args:
            **kwargs: Input data (file_path, url, text_content, etc.)

        Returns:
            Standardized detection result dictionary.
        """
        pass

    @abstractmethod
    def supported_input_types(self) -> list[str]:
        """Return list of supported input types (e.g., ['image', 'video'])."""
        pass

    @property
    def detector_name(self) -> str:
        """Human-readable detector name."""
        return self.__class__.__name__

    def _empty_result(self, analysis_type: str, limitations: list[str] | None = None) -> dict:
        """Return an empty/baseline result template."""
        return {
            "analysis_type": analysis_type,
            "status": "unknown",
            "risk_score": 0,
            "confidence": 0,
            "indicators": {},
            "evidence": {},
            "technical_details": {},
            "limitations": limitations or [],
        }
