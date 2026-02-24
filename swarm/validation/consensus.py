"""
AI Red Team Onion — ConsensusValidator
========================================
Multi-agent quorum validation for findings.

Before a finding enters the final report, it must be independently confirmed
by multiple agents or verification methods. This prevents any single agent
(or a single hallucinating LLM call) from producing false findings.

Quorum Rules:
  - LOW severity  → 1 agent confirmation sufficient
  - MEDIUM severity → 2 independent confirmations required
  - HIGH/CRITICAL  → 2 confirmations + 1 re-test required

Consensus Sources:
  - ExploitAgent reports a vulnerability
  - ExecutionAgent successfully exploits it
  - ReconAgent independently detects the same issue
  - Re-test reproduces the result
  - ResponseValidator confirms (not a false positive)
"""

import time
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ConsensusSeverity(Enum):
    """Severity levels that determine quorum requirements."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Quorum requirements per severity
QUORUM_REQUIREMENTS = {
    ConsensusSeverity.INFO: {"min_confirmations": 1, "require_retest": False},
    ConsensusSeverity.LOW: {"min_confirmations": 1, "require_retest": False},
    ConsensusSeverity.MEDIUM: {"min_confirmations": 2, "require_retest": False},
    ConsensusSeverity.HIGH: {"min_confirmations": 2, "require_retest": True},
    ConsensusSeverity.CRITICAL: {"min_confirmations": 2, "require_retest": True},
}


@dataclass
class Confirmation:
    """A single confirmation from an agent or verification method."""
    source_agent: str  # "exploit", "execution", "recon", "c4", "retest", "validator"
    confirmation_type: str  # "detection", "exploitation", "retest", "analysis"
    summary: str
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class ConsensusEntry:
    """Tracks consensus state for a single finding."""
    finding_id: str
    vector: str
    target: str
    severity: ConsensusSeverity
    confirmations: List[Confirmation] = field(default_factory=list)
    retested: bool = False
    retest_passed: bool = False
    consensus_reached: bool = False
    consensus_reached_at: float = 0.0
    created_at: float = field(default_factory=time.time)

    @property
    def unique_agents(self) -> Set[str]:
        return {c.source_agent for c in self.confirmations}

    @property
    def confirmation_count(self) -> int:
        return len(self.unique_agents)


class ConsensusValidator:
    """
    Multi-agent consensus validator.

    Usage:
        consensus = ConsensusValidator(config)

        # Agent reports a finding
        entry = consensus.register_finding("F-abc123", "sql_injection", "target.com", "high")

        # Different agents confirm
        consensus.add_confirmation("F-abc123", Confirmation(
            source_agent="exploit",
            confirmation_type="detection",
            summary="SQLi union-based detected in /api/search",
            confidence=0.8,
        ))

        consensus.add_confirmation("F-abc123", Confirmation(
            source_agent="execution",
            confirmation_type="exploitation",
            summary="SQLi successfully exploited, data extracted",
            confidence=0.9,
        ))

        # Check if consensus is reached
        if consensus.has_consensus("F-abc123"):
            include_in_report(entry)
    """

    def __init__(self, config=None):
        self._config = config
        self._entries: Dict[str, ConsensusEntry] = {}
        self._custom_quorum = None
        if config and hasattr(config, "consensus_quorum"):
            self._custom_quorum = config.consensus_quorum
        self._min_severity = ConsensusSeverity.MEDIUM
        if config and hasattr(config, "consensus_min_severity"):
            sev_str = config.consensus_min_severity.lower()
            for s in ConsensusSeverity:
                if s.value == sev_str:
                    self._min_severity = s

    # ── Public API ──────────────────────────────────────────────

    def register_finding(
        self,
        finding_id: str,
        vector: str,
        target: str,
        severity: str = "medium",
    ) -> ConsensusEntry:
        """Register a new finding for consensus tracking."""
        sev = self._parse_severity(severity)
        entry = ConsensusEntry(
            finding_id=finding_id,
            vector=vector,
            target=target,
            severity=sev,
        )
        self._entries[finding_id] = entry
        logger.debug(f"Finding {finding_id} registriert für Konsens (Severity: {sev.value})")
        return entry

    def add_confirmation(
        self,
        finding_id: str,
        confirmation: Confirmation,
    ) -> Optional[ConsensusEntry]:
        """
        Add a confirmation from an agent.
        Returns the entry if found, None otherwise.
        Automatically checks if consensus is now reached.
        """
        entry = self._entries.get(finding_id)
        if not entry:
            logger.warning(f"Finding {finding_id} nicht registriert — Bestätigung ignoriert")
            return None

        # Check for duplicate confirmation from same agent
        if confirmation.source_agent in entry.unique_agents:
            logger.debug(
                f"Agent '{confirmation.source_agent}' hat {finding_id} bereits bestätigt — "
                f"Update statt Duplikat"
            )
            # Update existing confirmation instead of adding duplicate
            for i, c in enumerate(entry.confirmations):
                if c.source_agent == confirmation.source_agent:
                    entry.confirmations[i] = confirmation
                    break
        else:
            entry.confirmations.append(confirmation)

        # Handle re-test confirmations specially
        if confirmation.confirmation_type == "retest":
            entry.retested = True
            entry.retest_passed = confirmation.confidence > 0.5

        # Check consensus
        self._check_consensus(entry)
        return entry

    def record_retest(
        self,
        finding_id: str,
        passed: bool,
        summary: str = "",
    ) -> Optional[ConsensusEntry]:
        """Convenience: record a re-test result."""
        return self.add_confirmation(finding_id, Confirmation(
            source_agent="retest",
            confirmation_type="retest",
            summary=summary or f"Re-Test {'bestanden' if passed else 'fehlgeschlagen'}",
            confidence=0.9 if passed else 0.1,
        ))

    def has_consensus(self, finding_id: str) -> bool:
        """Check if a finding has reached consensus."""
        entry = self._entries.get(finding_id)
        if not entry:
            return False
        return entry.consensus_reached

    def requires_consensus(self, severity: str) -> bool:
        """Check if a severity level requires consensus."""
        sev = self._parse_severity(severity)
        return self._severity_rank(sev) >= self._severity_rank(self._min_severity)

    def get_pending_findings(self) -> List[ConsensusEntry]:
        """Get findings that haven't reached consensus yet."""
        return [
            e for e in self._entries.values()
            if not e.consensus_reached
        ]

    def get_consensus_findings(self) -> List[ConsensusEntry]:
        """Get findings that have reached consensus."""
        return [
            e for e in self._entries.values()
            if e.consensus_reached
        ]

    def get_finding_status(self, finding_id: str) -> Dict:
        """Get detailed status of a finding's consensus progress."""
        entry = self._entries.get(finding_id)
        if not entry:
            return {"error": f"Finding {finding_id} nicht gefunden"}

        requirements = self._get_requirements(entry.severity)
        return {
            "finding_id": finding_id,
            "vector": entry.vector,
            "severity": entry.severity.value,
            "consensus_reached": entry.consensus_reached,
            "confirmations": entry.confirmation_count,
            "required_confirmations": requirements["min_confirmations"],
            "confirming_agents": sorted(entry.unique_agents),
            "retested": entry.retested,
            "retest_required": requirements["require_retest"],
            "retest_passed": entry.retest_passed,
        }

    def get_stats(self) -> Dict:
        """Overall consensus statistics."""
        total = len(self._entries)
        reached = sum(1 for e in self._entries.values() if e.consensus_reached)
        pending = total - reached
        return {
            "total_findings_tracked": total,
            "consensus_reached": reached,
            "pending_consensus": pending,
            "consensus_rate": round(reached / total, 4) if total > 0 else 0.0,
        }

    # ── Private helpers ─────────────────────────────────────────

    def _check_consensus(self, entry: ConsensusEntry):
        """Check if consensus requirements are met."""
        if entry.consensus_reached:
            return  # Already done

        # Low-severity findings below min_severity don't need consensus
        if self._severity_rank(entry.severity) < self._severity_rank(self._min_severity):
            entry.consensus_reached = True
            entry.consensus_reached_at = time.time()
            logger.info(
                f"Finding {entry.finding_id} automatisch akzeptiert "
                f"(Severity {entry.severity.value} < Schwelle {self._min_severity.value})"
            )
            return

        requirements = self._get_requirements(entry.severity)
        min_conf = self._custom_quorum or requirements["min_confirmations"]

        # Check confirmation count
        if entry.confirmation_count < min_conf:
            return

        # Check re-test requirement
        if requirements["require_retest"] and not entry.retest_passed:
            return

        # Consensus reached!
        entry.consensus_reached = True
        entry.consensus_reached_at = time.time()
        logger.info(
            f"KONSENS ERREICHT für {entry.finding_id}: "
            f"{entry.confirmation_count} Bestätigungen von {sorted(entry.unique_agents)}"
            f"{', Re-Test bestanden' if entry.retested else ''}"
        )

    def _get_requirements(self, severity: ConsensusSeverity) -> Dict:
        """Get quorum requirements for a severity level."""
        return QUORUM_REQUIREMENTS.get(severity, QUORUM_REQUIREMENTS[ConsensusSeverity.MEDIUM])

    def _parse_severity(self, severity: str) -> ConsensusSeverity:
        """Parse severity string to enum."""
        if isinstance(severity, ConsensusSeverity):
            return severity
        for s in ConsensusSeverity:
            if s.value == severity.lower():
                return s
        return ConsensusSeverity.MEDIUM

    def _severity_rank(self, severity: ConsensusSeverity) -> int:
        """Numeric rank for comparison."""
        ranks = {
            ConsensusSeverity.INFO: 0,
            ConsensusSeverity.LOW: 1,
            ConsensusSeverity.MEDIUM: 2,
            ConsensusSeverity.HIGH: 3,
            ConsensusSeverity.CRITICAL: 4,
        }
        return ranks.get(severity, 2)
