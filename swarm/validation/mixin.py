"""
AI Red Team Onion — ValidationMixin
======================================
Mixin class that adds validation capabilities to any SwarmAgent.

Usage in agents:
    class ExploitAgent(SwarmAgent, CognitiveMixin, ValidationMixin):
        ...

Provides:
    self.payload_validator   — Pre-execution payload validation
    self.result_verifier     — Post-execution ground-truth verification
    self.confidence_calibrator — Empirical confidence calibration
    self.consensus_validator — Multi-agent consensus tracking

    # High-level methods:
    self.validate_payloads(payloads, tech_stack) → valid payloads only
    self.verify_result(vector, payload, target, response) → VerifiedFinding
    self.calibrate_confidence(llm_conf, vector, tech_stack) → float
    self.register_for_consensus(finding_id, vector, target, severity)
    self.confirm_finding(finding_id, summary)
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ValidationMixin:
    """
    Mixin that provides anti-hallucination validation to swarm agents.
    Designed to be mixed in alongside SwarmAgent and CognitiveMixin.
    """

    # Lazy-initialized validation components
    _payload_validator = None
    _result_verifier = None
    _confidence_calibrator = None
    _consensus_validator = None

    @property
    def payload_validator(self):
        """Lazy-init PayloadValidator."""
        if self._payload_validator is None:
            from swarm.validation.payload_validator import PayloadValidator
            config = None
            if hasattr(self, 'config') and hasattr(self.config, 'validation'):
                config = self.config.validation
            self._payload_validator = PayloadValidator(config)
        return self._payload_validator

    @property
    def result_verifier(self):
        """Lazy-init ResultVerifier."""
        if self._result_verifier is None:
            from swarm.validation.result_verifier import ResultVerifier
            config = None
            if hasattr(self, 'config') and hasattr(self.config, 'validation'):
                config = self.config.validation
            self._result_verifier = ResultVerifier(config)
        return self._result_verifier

    @property
    def confidence_calibrator(self):
        """Lazy-init ConfidenceCalibrator."""
        if self._confidence_calibrator is None:
            from swarm.validation.confidence_calibrator import ConfidenceCalibrator
            config = None
            if hasattr(self, 'config') and hasattr(self.config, 'validation'):
                config = self.config.validation
            self._confidence_calibrator = ConfidenceCalibrator(config)
        return self._confidence_calibrator

    @property
    def consensus_validator(self):
        """Lazy-init ConsensusValidator."""
        if self._consensus_validator is None:
            from swarm.validation.consensus import ConsensusValidator
            config = None
            if hasattr(self, 'config') and hasattr(self.config, 'validation'):
                config = self.config.validation
            self._consensus_validator = ConsensusValidator(config)
        return self._consensus_validator

    # ── High-Level Convenience Methods ──────────────────────────

    def validate_payloads(
        self,
        payloads: List[Dict],
        tech_stack: Optional[List[str]] = None,
        vector: str = "",
    ) -> List[Dict]:
        """
        Validate and filter a list of payloads before execution.
        Returns only valid payloads with calibrated confidence.

        Integrates:
          - PayloadValidator (syntax, structure, tech-relevance)
          - ConfidenceCalibrator (replaces LLM confidence)
        """
        try:
            # Step 1: PayloadValidator filters
            valid = self.payload_validator.filter_valid(payloads, tech_stack)

            # Step 2: Calibrate confidence on remaining payloads
            for p in valid:
                p["confidence"] = self.confidence_calibrator.calibrate(
                    llm_confidence=p.get("confidence", 0.5),
                    vector=vector or p.get("vector", p.get("category", "")),
                    tech_stack=tech_stack,
                    payload_source=p.get("source", ""),
                )

            rejected_count = len(payloads) - len(valid)
            if rejected_count > 0:
                agent_name = getattr(self, 'agent_id', 'unknown')
                logger.info(
                    f"[{agent_name}] PayloadValidator: "
                    f"{len(valid)}/{len(payloads)} Payloads akzeptiert, "
                    f"{rejected_count} abgelehnt"
                )

            return valid
        except Exception as e:
            logger.warning(f"Payload-Validierung fehlgeschlagen, alle Payloads durchgelassen: {e}")
            return payloads

    def verify_result(
        self,
        vector: str,
        payload: str,
        target: str,
        response: str,
        finding_id: str = "",
    ) -> "VerifiedFinding":
        """
        Verify an execution result against ground truth.
        Creates a finding, collects response evidence, and returns
        the verified finding with its verification level.
        """
        from swarm.validation.result_verifier import VerifiedFinding, VerificationLevel

        try:
            finding = self.result_verifier.create_finding(
                vector=vector,
                payload=payload,
                target=target,
                raw_response=response,
                finding_id=finding_id,
            )
            self.result_verifier.analyze_response(finding)

            # Record outcome in calibrator
            is_success = finding.verification_level in (
                VerificationLevel.CONFIRMED,
                VerificationLevel.PROBABLE,
            )
            self.confidence_calibrator.record_outcome(
                vector=vector,
                success=is_success,
                tech_stack=None,  # Can be enriched by caller
                payload_source=finding.payload[:20] if finding.payload else "",
            )

            return finding
        except Exception as e:
            logger.warning(f"Ergebnis-Verifizierung fehlgeschlagen: {e}")
            # Return an unverified finding
            from swarm.validation.result_verifier import VerifiedFinding
            return VerifiedFinding(
                finding_id=finding_id or "F-error",
                vector=vector,
                payload=payload,
                target=target,
                raw_response=response,
            )

    def calibrate_confidence(
        self,
        llm_confidence: float,
        vector: str,
        tech_stack: Optional[List[str]] = None,
        payload_source: str = "",
    ) -> float:
        """Calibrate an LLM-generated confidence score."""
        try:
            return self.confidence_calibrator.calibrate(
                llm_confidence=llm_confidence,
                vector=vector,
                tech_stack=tech_stack,
                payload_source=payload_source,
            )
        except Exception as e:
            logger.warning(f"Confidence-Kalibrierung fehlgeschlagen: {e}")
            return min(llm_confidence, 0.5)  # Cap at 0.5 as safety fallback

    def register_for_consensus(
        self,
        finding_id: str,
        vector: str,
        target: str,
        severity: str = "medium",
    ):
        """Register a finding for consensus tracking."""
        try:
            self.consensus_validator.register_finding(
                finding_id=finding_id,
                vector=vector,
                target=target,
                severity=severity,
            )
        except Exception as e:
            logger.warning(f"Konsens-Registrierung fehlgeschlagen: {e}")

    def confirm_finding(
        self, finding_id: str, summary: str, confidence: float = 0.7
    ):
        """Confirm another agent's finding."""
        from swarm.validation.consensus import Confirmation
        try:
            agent_id = getattr(self, 'agent_id', 'unknown')
            self.consensus_validator.add_confirmation(
                finding_id=finding_id,
                confirmation=Confirmation(
                    source_agent=agent_id,
                    confirmation_type="detection",
                    summary=summary,
                    confidence=confidence,
                ),
            )
        except Exception as e:
            logger.warning(f"Finding-Bestätigung fehlgeschlagen: {e}")

    def get_validation_stats(self) -> Dict:
        """Aggregate validation statistics from all components."""
        stats = {}
        try:
            stats["payload_validator"] = self.payload_validator.get_stats()
        except Exception:
            pass
        try:
            stats["result_verifier"] = self.result_verifier.get_stats()
        except Exception:
            pass
        try:
            stats["confidence_calibrator"] = self.confidence_calibrator.get_stats()
        except Exception:
            pass
        try:
            stats["consensus_validator"] = self.consensus_validator.get_stats()
        except Exception:
            pass
        return stats
