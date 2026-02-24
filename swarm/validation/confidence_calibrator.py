"""
AI Red Team Onion — ConfidenceCalibrator
==========================================
Replaces LLM-hallucinated confidence scores with empirically grounded values.

Problem: When the CognitiveEngine generates a payload and says "confidence: 0.95",
that number is fabricated. The LLM has no empirical basis for claiming 95% success.

Solution: Track actual outcomes per (vector, tech_stack) combination and use
Bayesian updating to produce calibrated confidence scores.

Confidence Sources (ordered by reliability):
  1. Empirical success rate   — actual test results (highest weight)
  2. Knowledge Base rate      — historical success from KB (medium weight)
  3. Category base rate       — known base rates per vector type (low weight)
  4. LLM estimate (capped)   — LLM guess, hard-capped at 0.5 (lowest weight)

Decay: Confidence decays over time without re-verification.
"""

import time
import logging
import math
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


# Base rates per attack vector (from published security research)
# These are conservative starting points before any empirical data
VECTOR_BASE_RATES = {
    "sql_injection": 0.15,
    "xss": 0.20,
    "command_injection": 0.08,
    "ssrf": 0.10,
    "path_traversal": 0.12,
    "template_injection": 0.07,
    "prompt_injection": 0.25,
    "jailbreak": 0.15,
    "system_prompt_extraction": 0.20,
    "data_exfiltration": 0.10,
    "tool_abuse": 0.08,
    "social_engineering": 0.12,
}

# LLM confidence is ALWAYS capped at this value
LLM_CONFIDENCE_CAP = 0.5


@dataclass
class OutcomeRecord:
    """Records a single test outcome for calibration."""
    vector: str
    tech_stack: Tuple[str, ...] = ()
    success: bool = False
    timestamp: float = field(default_factory=time.time)
    payload_source: str = ""  # "tier1", "tier2_llm", "tier3_orchestrated"


@dataclass
class CalibrationState:
    """Bayesian calibration state for a (vector, tech_key) pair."""
    # Beta distribution parameters (Bayesian conjugate prior)
    alpha: float = 1.0   # pseudo-successes (prior)
    beta: float = 4.0    # pseudo-failures (prior) → starts pessimistic
    total_trials: int = 0
    last_success_at: float = 0.0
    last_updated_at: float = field(default_factory=time.time)

    @property
    def mean(self) -> float:
        """Bayesian mean = alpha / (alpha + beta)"""
        return self.alpha / (self.alpha + self.beta)

    @property
    def variance(self) -> float:
        """Bayesian variance for the Beta distribution."""
        ab = self.alpha + self.beta
        return (self.alpha * self.beta) / (ab * ab * (ab + 1))

    @property
    def uncertainty(self) -> float:
        """Standard deviation as a measure of uncertainty."""
        return math.sqrt(self.variance)


class ConfidenceCalibrator:
    """
    Produces empirically calibrated confidence scores.

    Usage:
        calibrator = ConfidenceCalibrator(config)

        # Before execution: get calibrated confidence for a payload
        calibrated = calibrator.calibrate(
            llm_confidence=0.95,
            vector="sql_injection",
            tech_stack=["mysql", "php"],
            payload_source="tier2_llm"
        )
        # calibrated ≈ 0.15-0.30 (NOT 0.95!)

        # After execution: record the actual outcome
        calibrator.record_outcome(
            vector="sql_injection",
            tech_stack=["mysql", "php"],
            success=False
        )

        # Next time: calibrated confidence adjusts based on empirical data
    """

    def __init__(self, config=None):
        self._config = config
        self._decay_rate = 0.1
        self._min_threshold = 0.3
        if config:
            if hasattr(config, "confidence_decay_rate"):
                self._decay_rate = config.confidence_decay_rate
            if hasattr(config, "min_confidence_threshold"):
                self._min_threshold = config.min_confidence_threshold

        # Calibration state per (vector, tech_key)
        self._states: Dict[str, CalibrationState] = defaultdict(CalibrationState)
        self._outcomes: List[OutcomeRecord] = []

    # ── Public API ──────────────────────────────────────────────

    def calibrate(
        self,
        llm_confidence: float,
        vector: str,
        tech_stack: Optional[List[str]] = None,
        payload_source: str = "",
    ) -> float:
        """
        Produce a calibrated confidence score.

        Combines:
          1. Empirical Bayesian estimate (if we have data)
          2. Category base rate
          3. Capped LLM estimate (lowest priority)
          4. Time decay

        Args:
            llm_confidence: The LLM's claimed confidence (will be capped)
            vector: Attack vector type
            tech_stack: Detected target technologies
            payload_source: "tier1", "tier2_llm", "tier3_orchestrated"

        Returns:
            Calibrated confidence ∈ [0.01, 1.0]
        """
        vector = self._normalize_vector(vector)
        tech_key = self._make_tech_key(vector, tech_stack)
        state = self._states[tech_key]

        # ── Source weights ────────────────────────────────────
        # 1. Empirical (Bayesian mean) — highest trust
        empirical = state.mean if state.total_trials > 0 else None

        # 2. Base rate for vector category
        base_rate = VECTOR_BASE_RATES.get(vector, 0.10)

        # 3. LLM confidence — hard capped, lowest trust
        capped_llm = min(llm_confidence, LLM_CONFIDENCE_CAP)

        # ── Weighted combination ──────────────────────────────
        if empirical is not None and state.total_trials >= 3:
            # Enough data: heavily weight empirical
            # Weight increases with more trials
            emp_weight = min(0.8, 0.4 + state.total_trials * 0.05)
            base_weight = 0.15
            llm_weight = 1.0 - emp_weight - base_weight
            calibrated = (
                empirical * emp_weight
                + base_rate * base_weight
                + capped_llm * llm_weight
            )
        elif empirical is not None:
            # Some data but not enough for high confidence
            calibrated = (
                empirical * 0.3
                + base_rate * 0.4
                + capped_llm * 0.3
            )
        else:
            # No empirical data: base rate + capped LLM
            calibrated = base_rate * 0.6 + capped_llm * 0.4

        # ── Source penalty ────────────────────────────────────
        # Tier-2 LLM-generated payloads get a reliability discount
        if payload_source == "tier2_llm":
            calibrated *= 0.85
        elif payload_source == "tier3_orchestrated":
            calibrated *= 0.90  # Orchestrated plans are slightly more reliable

        # ── Time decay ────────────────────────────────────────
        if state.last_success_at > 0:
            hours_since_success = (time.time() - state.last_success_at) / 3600
            decay = math.exp(-self._decay_rate * hours_since_success)
            calibrated *= max(decay, 0.3)  # Don't decay below 30% of value

        return round(max(min(calibrated, 1.0), 0.01), 4)

    def record_outcome(
        self,
        vector: str,
        success: bool,
        tech_stack: Optional[List[str]] = None,
        payload_source: str = "",
    ):
        """
        Record an actual test outcome. Updates the Bayesian estimate.

        Args:
            vector: Attack vector type
            success: Whether the attack actually succeeded (verified!)
            tech_stack: Target technologies
            payload_source: Source of the payload
        """
        vector = self._normalize_vector(vector)
        tech_key = self._make_tech_key(vector, tech_stack)
        state = self._states[tech_key]

        # Bayesian update (conjugate prior for Bernoulli likelihood)
        if success:
            state.alpha += 1.0
            state.last_success_at = time.time()
        else:
            state.beta += 1.0

        state.total_trials += 1
        state.last_updated_at = time.time()

        # Record for audit trail
        self._outcomes.append(OutcomeRecord(
            vector=vector,
            tech_stack=tuple(sorted(tech_stack or [])),
            success=success,
            payload_source=payload_source,
        ))

        logger.debug(
            f"Outcome recorded: {vector} {'SUCCESS' if success else 'FAIL'} "
            f"→ P(success)={state.mean:.3f} "
            f"(α={state.alpha:.1f}, β={state.beta:.1f}, n={state.total_trials})"
        )

    def get_calibration_state(
        self, vector: str, tech_stack: Optional[List[str]] = None
    ) -> Dict:
        """Get current calibration state for a vector/tech combination."""
        vector = self._normalize_vector(vector)
        tech_key = self._make_tech_key(vector, tech_stack)
        state = self._states[tech_key]
        return {
            "vector": vector,
            "tech_key": tech_key,
            "bayesian_mean": round(state.mean, 4),
            "uncertainty": round(state.uncertainty, 4),
            "total_trials": state.total_trials,
            "alpha": state.alpha,
            "beta": state.beta,
            "base_rate": VECTOR_BASE_RATES.get(vector, 0.10),
        }

    def get_stats(self) -> Dict:
        """Overall calibration statistics."""
        total = len(self._outcomes)
        successes = sum(1 for o in self._outcomes if o.success)
        return {
            "total_outcomes_recorded": total,
            "overall_success_rate": round(successes / total, 4) if total > 0 else 0.0,
            "unique_vector_tech_combos": len(self._states),
            "calibration_states": {
                k: round(v.mean, 4)
                for k, v in self._states.items()
                if v.total_trials > 0
            },
        }

    # ── Private helpers ─────────────────────────────────────────

    def _normalize_vector(self, vector: str) -> str:
        v = vector.lower().strip().replace(" ", "_").replace("-", "_")
        aliases = {
            "sqli": "sql_injection", "sql": "sql_injection",
            "cross_site_scripting": "xss", "rce": "command_injection",
            "ssti": "template_injection", "lfi": "path_traversal",
        }
        return aliases.get(v, v)

    def _make_tech_key(self, vector: str, tech_stack: Optional[List[str]]) -> str:
        """Create a lookup key from vector + tech stack."""
        if tech_stack:
            techs = "_".join(sorted(t.lower() for t in tech_stack[:3]))
            return f"{vector}:{techs}"
        return vector
