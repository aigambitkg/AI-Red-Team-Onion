"""
AI Red Team Onion — Validation & Anti-Hallucination Layer
==========================================================
Ensures the swarm reports only verified, evidence-based findings.

Components:
  - PayloadValidator:      Pre-execution syntax + structure checks
  - ResultVerifier:        Post-execution ground-truth verification
  - ConfidenceCalibrator:  Empirical confidence replacing LLM guesses
  - ConsensusValidator:    Multi-agent quorum before final findings
"""

from swarm.validation.payload_validator import PayloadValidator
from swarm.validation.result_verifier import ResultVerifier
from swarm.validation.confidence_calibrator import ConfidenceCalibrator
from swarm.validation.consensus import ConsensusValidator

__all__ = [
    "PayloadValidator",
    "ResultVerifier",
    "ConfidenceCalibrator",
    "ConsensusValidator",
]
