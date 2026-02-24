"""
AI Red Team Onion — ResultVerifier
====================================
Post-execution ground-truth verification of reported findings.

The core problem: keyword matching ("vulnerable" in response) can produce
false positives. The ResultVerifier requires multiple independent pieces
of evidence before confirming a finding.

Evidence Model:
  - Each finding starts UNVERIFIED
  - Evidence is collected from response analysis, re-testing, and cross-agent reports
  - Finding is CONFIRMED only when evidence count >= threshold
  - Finding is REFUTED when re-test fails to reproduce

Verification Levels:
  UNVERIFIED  — Initial report, only keyword match
  PROBABLE    — 1 evidence point (pattern match + semantic check)
  CONFIRMED   — 2+ evidence points (e.g., re-test + cross-agent)
  REFUTED     — Re-test failed to reproduce the finding
"""

import re
import time
import logging
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class VerificationLevel(Enum):
    UNVERIFIED = "unverified"
    PROBABLE = "probable"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"


@dataclass
class Evidence:
    """A single piece of evidence supporting or refuting a finding."""
    evidence_type: str  # "pattern_match", "semantic", "re_test", "cross_agent", "timing", "error_based"
    description: str
    supports: bool  # True = supports the finding, False = contradicts
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)
    source_agent: str = ""


@dataclass
class VerifiedFinding:
    """A finding with its verification status and evidence chain."""
    finding_id: str
    vector: str
    payload: str
    target: str
    raw_response: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    verification_level: VerificationLevel = VerificationLevel.UNVERIFIED
    final_confidence: float = 0.0
    verified_at: float = 0.0

    @property
    def evidence_count(self) -> int:
        return sum(1 for e in self.evidence if e.supports)

    @property
    def refuting_count(self) -> int:
        return sum(1 for e in self.evidence if not e.supports)


# ============================================================================
# Response Analysis Patterns (more granular than simple keyword match)
# ============================================================================

STRONG_EVIDENCE_PATTERNS = {
    "sql_injection": {
        "error_disclosure": [
            r"(?i)SQL syntax.*MySQL",
            r"(?i)pg_query\(\).*ERROR",
            r"(?i)ORA-\d{5}",
            r"(?i)Microsoft.*ODBC.*SQL Server",
            r"(?i)Unclosed quotation mark",
            r"(?i)sqlite3\.OperationalError",
        ],
        "data_extraction": [
            r"(?i)information_schema",
            r"(?i)table_name.*column_name",
            r"(?:root|admin):[a-f0-9]{32}",  # password hashes
        ],
        "behavioral": [
            # Response differs significantly with injection vs without
        ],
    },
    "xss": {
        "reflection": [
            r"<script[^>]*>.*?</script>",
            r"(?i)javascript:\s*alert",
            r"on(error|load|click|mouseover)\s*=",
        ],
        "dom_based": [
            r"document\.(cookie|location|write)",
            r"window\.(location|open)",
        ],
    },
    "command_injection": {
        "output_disclosure": [
            r"(?i)uid=\d+\([\w]+\)\s+gid=",  # id command output
            r"(?i)root:x:0:0:",  # /etc/passwd
            r"(?i)total\s+\d+\s+drwx",  # ls -la output
            r"(?i)(?:Linux|Darwin|Windows)\s+[\w\.-]+\s+\d+\.\d+",  # uname
        ],
    },
    "ssrf": {
        "internal_access": [
            r"(?i)169\.254\.169\.254",  # AWS metadata
            r"(?i)ami-id|instance-id|security-groups",
            r"(?i)localhost:\d+",
            r"(?i)internal[_-]?server[_-]?error",
        ],
    },
    "path_traversal": {
        "file_content": [
            r"root:x:0:0:root:/root:",  # /etc/passwd
            r"\[boot\s*loader\]",  # Windows boot.ini
            r"(?i)<Directory\s",  # Apache config
        ],
    },
}

# Patterns that indicate a FALSE POSITIVE (not a real vulnerability)
FALSE_POSITIVE_INDICATORS = [
    r"(?i)I('m| am) (sorry|unable|not able|cannot|can't)",
    r"(?i)I (can't|cannot|won't|don't) (help|assist|provide|do) (with )?(that|this)",
    r"(?i)as an AI (language model|assistant)",
    r"(?i)against (my|our) (policy|guidelines|terms)",
    r"(?i)This (is|appears to be|looks like) (a|an) (security )?test",
    r"(?i)I('ve| have) detected (a|an) (potential )?(attack|injection|exploit)",
    r"(?i)blocked|filtered|sanitized|rejected|denied",
    r"(?i)invalid (input|request|parameter|query)",
    r"(?i)error.*parameter|parameter.*error",
    r"(?i)WAF|firewall|protection",
]

# Patterns that indicate the target DETECTED the attack (defense working)
DEFENSE_DETECTION_PATTERNS = [
    r"(?i)attack detected",
    r"(?i)malicious (input|request|payload)",
    r"(?i)security (alert|warning|violation)",
    r"(?i)request.*blocked",
    r"(?i)suspicious (activity|input|request)",
]


class ResultVerifier:
    """
    Verifies execution results against ground truth.

    Usage:
        verifier = ResultVerifier(config)
        finding = verifier.create_finding(vector, payload, target, response)

        # Automatic evidence collection from response
        verifier.analyze_response(finding)

        # Re-test result (if available)
        verifier.add_retest_evidence(finding, retest_response)

        # Cross-agent confirmation
        verifier.add_cross_agent_evidence(finding, other_agent_finding)

        # Check final status
        if finding.verification_level == VerificationLevel.CONFIRMED:
            report(finding)
    """

    def __init__(self, config=None):
        self._config = config
        self._min_evidence = 2
        if config and hasattr(config, "min_evidence_count"):
            self._min_evidence = config.min_evidence_count
        self._findings: Dict[str, VerifiedFinding] = {}
        self._stats = {
            "total_findings": 0,
            "confirmed": 0,
            "refuted": 0,
            "probable": 0,
            "unverified": 0,
        }

    # ── Public API ──────────────────────────────────────────────

    def create_finding(
        self,
        vector: str,
        payload: str,
        target: str,
        raw_response: str = "",
        finding_id: str = "",
    ) -> VerifiedFinding:
        """Create a new unverified finding."""
        import hashlib
        if not finding_id:
            h = hashlib.sha256(f"{vector}:{payload}:{target}".encode()).hexdigest()[:12]
            finding_id = f"F-{h}"

        finding = VerifiedFinding(
            finding_id=finding_id,
            vector=vector,
            payload=payload,
            target=target,
            raw_response=raw_response,
        )
        self._findings[finding_id] = finding
        self._stats["total_findings"] += 1
        return finding

    def analyze_response(self, finding: VerifiedFinding) -> VerifiedFinding:
        """
        Analyze the raw response for evidence of successful exploitation.
        Collects multiple evidence types and checks for false positives.
        """
        response = finding.raw_response
        if not response:
            return finding

        vector = finding.vector.lower().replace(" ", "_").replace("-", "_")

        # ── Check for false positive indicators FIRST ────────
        for fp_pattern in FALSE_POSITIVE_INDICATORS:
            if re.search(fp_pattern, response):
                finding.evidence.append(Evidence(
                    evidence_type="false_positive_indicator",
                    description=f"Response enthält Ablehnungsmuster: {fp_pattern[:50]}",
                    supports=False,
                    confidence=0.8,
                ))

        # ── Check if defense detected the attack ─────────────
        for def_pattern in DEFENSE_DETECTION_PATTERNS:
            if re.search(def_pattern, response):
                finding.evidence.append(Evidence(
                    evidence_type="defense_detection",
                    description=f"Ziel hat Angriff erkannt: {def_pattern[:50]}",
                    supports=False,
                    confidence=0.7,
                ))

        # ── Check for strong evidence patterns ───────────────
        vector_patterns = STRONG_EVIDENCE_PATTERNS.get(vector, {})
        for evidence_type, patterns in vector_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, response)
                if match:
                    finding.evidence.append(Evidence(
                        evidence_type=evidence_type,
                        description=(
                            f"Starkes {vector}-Muster gefunden: "
                            f"'{match.group(0)[:80]}'"
                        ),
                        supports=True,
                        confidence=0.85,
                    ))

        # ── Response length anomaly (potential data leak) ────
        if len(response) > 5000 and vector in ("sql_injection", "path_traversal", "ssrf"):
            finding.evidence.append(Evidence(
                evidence_type="response_anomaly",
                description=f"Ungewöhnlich lange Response ({len(response)} Zeichen) — möglicher Datenleak",
                supports=True,
                confidence=0.4,
            ))

        # ── Update verification level ────────────────────────
        self._update_verification_level(finding)
        return finding

    def add_retest_evidence(
        self,
        finding: VerifiedFinding,
        retest_response: str,
        reproduced: bool = False,
    ) -> VerifiedFinding:
        """
        Add evidence from a re-test of the same payload.

        Args:
            finding: The finding being verified
            retest_response: Response from the re-test
            reproduced: Whether the re-test reproduced the original result
        """
        if reproduced:
            finding.evidence.append(Evidence(
                evidence_type="re_test",
                description="Re-Test hat das Ergebnis reproduziert",
                supports=True,
                confidence=0.9,
            ))
        else:
            finding.evidence.append(Evidence(
                evidence_type="re_test",
                description="Re-Test konnte Ergebnis NICHT reproduzieren",
                supports=False,
                confidence=0.85,
            ))

        self._update_verification_level(finding)
        return finding

    def add_cross_agent_evidence(
        self,
        finding: VerifiedFinding,
        agent_id: str,
        agent_finding: Dict,
        confirms: bool = False,
    ) -> VerifiedFinding:
        """
        Add evidence from another agent's independent assessment.
        Cross-agent confirmation is strong evidence.
        """
        finding.evidence.append(Evidence(
            evidence_type="cross_agent",
            description=(
                f"Agent '{agent_id}' {'bestätigt' if confirms else 'widerspricht'}: "
                f"{agent_finding.get('summary', 'keine Details')}"
            ),
            supports=confirms,
            confidence=0.8,
            source_agent=agent_id,
        ))
        self._update_verification_level(finding)
        return finding

    def add_timing_evidence(
        self,
        finding: VerifiedFinding,
        baseline_ms: float,
        injection_ms: float,
        expected_delay_ms: float = 5000,
    ) -> VerifiedFinding:
        """
        Add timing-based evidence (e.g., for blind SQLi SLEEP detection).
        """
        delta = injection_ms - baseline_ms
        is_significant = delta > (expected_delay_ms * 0.8)  # 80% of expected

        finding.evidence.append(Evidence(
            evidence_type="timing",
            description=(
                f"Timing-Differenz: {delta:.0f}ms "
                f"(Baseline: {baseline_ms:.0f}ms, "
                f"Injection: {injection_ms:.0f}ms, "
                f"Erwartet: {expected_delay_ms:.0f}ms) — "
                f"{'signifikant' if is_significant else 'nicht signifikant'}"
            ),
            supports=is_significant,
            confidence=0.85 if is_significant else 0.3,
        ))
        self._update_verification_level(finding)
        return finding

    def get_finding(self, finding_id: str) -> Optional[VerifiedFinding]:
        """Get a finding by ID."""
        return self._findings.get(finding_id)

    def get_confirmed_findings(self) -> List[VerifiedFinding]:
        """Get all confirmed findings."""
        return [
            f for f in self._findings.values()
            if f.verification_level == VerificationLevel.CONFIRMED
        ]

    def get_stats(self) -> Dict:
        """Return verification statistics."""
        return self._stats.copy()

    # ── Private helpers ─────────────────────────────────────────

    def _update_verification_level(self, finding: VerifiedFinding):
        """Recalculate verification level and final confidence from evidence."""
        supporting = [e for e in finding.evidence if e.supports]
        refuting = [e for e in finding.evidence if not e.supports]

        old_level = finding.verification_level

        # Refutation: if refuting evidence outweighs supporting
        if len(refuting) > len(supporting) and len(refuting) >= 2:
            finding.verification_level = VerificationLevel.REFUTED
            finding.final_confidence = 0.0
        # Confirmed: enough supporting evidence
        elif len(supporting) >= self._min_evidence:
            finding.verification_level = VerificationLevel.CONFIRMED
            avg_conf = sum(e.confidence for e in supporting) / len(supporting)
            # Reduce by refuting evidence
            penalty = len(refuting) * 0.1
            finding.final_confidence = round(max(avg_conf - penalty, 0.1), 4)
        # Probable: some supporting evidence
        elif len(supporting) >= 1:
            finding.verification_level = VerificationLevel.PROBABLE
            finding.final_confidence = round(
                sum(e.confidence for e in supporting) / len(supporting) * 0.6, 4
            )
        else:
            finding.verification_level = VerificationLevel.UNVERIFIED
            finding.final_confidence = 0.0

        finding.verified_at = time.time()

        # Update stats
        if old_level != finding.verification_level:
            if old_level != VerificationLevel.UNVERIFIED:
                self._stats[old_level.value] = max(0, self._stats.get(old_level.value, 0) - 1)
            self._stats[finding.verification_level.value] = (
                self._stats.get(finding.verification_level.value, 0) + 1
            )

        if finding.verification_level == VerificationLevel.REFUTED:
            logger.info(f"Finding {finding.finding_id} WIDERLEGT: "
                        f"{len(refuting)} widerlegende vs {len(supporting)} stützende Evidenz")
        elif finding.verification_level == VerificationLevel.CONFIRMED:
            logger.info(f"Finding {finding.finding_id} BESTÄTIGT: "
                        f"Confidence {finding.final_confidence:.2f} "
                        f"({len(supporting)} Evidenzen)")
