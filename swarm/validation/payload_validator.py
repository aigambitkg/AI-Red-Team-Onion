"""
AI Red Team Onion — PayloadValidator
=====================================
Pre-execution validation of payloads, especially LLM-generated Tier-2 payloads.

Validates:
  1. Structural integrity   — JSON schema, required fields present
  2. Syntax correctness     — Payload string is well-formed for its vector
  3. Tech-stack relevance   — Payload targets the right technology
  4. Safety boundaries      — Payload stays within authorized scope
  5. Deduplication          — No repeated identical payloads

Prevents:
  - LLM-hallucinated payloads with syntax errors
  - Payloads targeting wrong technology (e.g., MySQL SQLi against PostgreSQL)
  - Overly long / malformed payloads crashing execution
  - Duplicate payloads wasting execution time
"""

import re
import logging
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ============================================================================
# Validation Result
# ============================================================================

@dataclass
class PayloadValidationResult:
    """Result of a single payload validation."""
    valid: bool
    payload: Dict
    issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    adjusted_confidence: float = 0.0

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0


# ============================================================================
# Vector-specific syntax validators
# ============================================================================

VECTOR_SYNTAX_RULES = {
    "sql_injection": {
        "required_chars": ["'", '"', "-", "=", " "],
        "min_patterns": [
            r"(?i)(SELECT|UNION|OR\s+\d|AND\s+\d|INSERT|UPDATE|DELETE|DROP|--|;|SLEEP|BENCHMARK|WAITFOR)",
        ],
        "max_length": 2000,
        "forbidden_patterns": [],  # Nothing categorically forbidden for SQLi
    },
    "xss": {
        "required_chars": [],
        "min_patterns": [
            r"(?i)(<script|<img|<svg|<iframe|javascript:|on\w+=|<body|<input|<link|<style|alert\(|prompt\(|confirm\(|document\.|window\.)",
        ],
        "max_length": 5000,
        "forbidden_patterns": [],
    },
    "command_injection": {
        "required_chars": [],
        "min_patterns": [
            r"(?i)(;|\||&&|`|\$\(|%0a|%0d|\bcat\b|\bls\b|\bwhoami\b|\bid\b|\bping\b|\bcurl\b|\bwget\b|\bnc\b|\bbash\b|\bsh\b|\bpowershell\b|\bcmd\b)",
        ],
        "max_length": 1000,
        "forbidden_patterns": [
            r"(?i)(rm\s+-rf\s+/\s*$|mkfs|dd\s+if=|:\(\)\{)",  # Destructive commands
        ],
    },
    "ssrf": {
        "required_chars": [],
        "min_patterns": [
            r"(?i)(https?://|file://|gopher://|dict://|ftp://|127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.|metadata|internal|10\.\d|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)",
        ],
        "max_length": 2000,
        "forbidden_patterns": [],
    },
    "path_traversal": {
        "required_chars": [],
        "min_patterns": [
            r"(\.\./|\.\.\\|%2e%2e|%252e|/etc/passwd|/windows/|\\windows\\|file://)",
        ],
        "max_length": 1000,
        "forbidden_patterns": [],
    },
    "template_injection": {
        "required_chars": [],
        "min_patterns": [
            r"(\{\{|\$\{|<%|#\{|\{%|#set|#foreach|<#assign|T\(java|__class__|__globals__|__builtins__)",
        ],
        "max_length": 2000,
        "forbidden_patterns": [],
    },
    "prompt_injection": {
        "required_chars": [],
        "min_patterns": [
            r"(?i)(ignore|forget|disregard|override|new instruction|system prompt|you are now|act as|pretend|roleplay|DAN|jailbreak|bypass)",
        ],
        "max_length": 8000,
        "forbidden_patterns": [],
    },
}

# Tech stack → compatible vectors
TECH_VECTOR_COMPATIBILITY = {
    "mysql": ["sql_injection"],
    "postgresql": ["sql_injection"],
    "mssql": ["sql_injection"],
    "sqlite": ["sql_injection"],
    "oracle": ["sql_injection"],
    "mongodb": ["nosql_injection"],
    "nginx": ["ssrf", "path_traversal", "command_injection"],
    "apache": ["ssrf", "path_traversal", "command_injection"],
    "django": ["template_injection", "sql_injection", "xss", "ssrf"],
    "flask": ["template_injection", "sql_injection", "xss", "ssrf"],
    "express": ["xss", "command_injection", "ssrf", "path_traversal"],
    "react": ["xss"],
    "angular": ["xss"],
    "wordpress": ["sql_injection", "xss", "path_traversal"],
    "php": ["sql_injection", "xss", "command_injection", "path_traversal", "template_injection"],
    "java": ["template_injection", "command_injection", "sql_injection", "ssrf"],
    "spring": ["template_injection", "sql_injection", "ssrf"],
    "node": ["command_injection", "xss", "ssrf", "path_traversal"],
    "jinja2": ["template_injection"],
    "twig": ["template_injection"],
    "freemarker": ["template_injection"],
}


class PayloadValidator:
    """
    Validates payloads before execution.

    Usage:
        validator = PayloadValidator(config)
        result = validator.validate(payload_dict)
        if result.valid:
            execute(payload_dict)
        else:
            log(result.issues)

    Batch:
        results = validator.validate_batch(payload_list)
        valid_payloads = [r.payload for r in results if r.valid]
    """

    def __init__(self, config=None):
        """
        Args:
            config: Optional ValidationConfig from config.py
        """
        self._config = config
        self._seen_hashes: set = set()
        self._stats = {
            "total_validated": 0,
            "passed": 0,
            "rejected": 0,
            "deduplicated": 0,
        }

    # ── Public API ──────────────────────────────────────────────

    def validate(
        self,
        payload: Dict,
        tech_stack: Optional[List[str]] = None,
        strict: bool = False,
    ) -> PayloadValidationResult:
        """
        Validate a single payload dict.

        Args:
            payload: Dict with at least 'payload' key (the attack string)
                     Optional: 'vector', 'category', 'confidence', 'source'
            tech_stack: Known target technologies (for relevance check)
            strict: If True, warnings become errors

        Returns:
            PayloadValidationResult
        """
        self._stats["total_validated"] += 1
        issues = []
        warnings = []

        # ── 1. Structural validation ──────────────────────────
        struct_ok, struct_issues = self._validate_structure(payload)
        issues.extend(struct_issues)

        if not struct_ok:
            self._stats["rejected"] += 1
            return PayloadValidationResult(
                valid=False, payload=payload, issues=issues
            )

        payload_str = str(payload.get("payload", ""))
        vector = self._normalize_vector(payload.get("vector", payload.get("category", "")))

        # ── 2. Length check ───────────────────────────────────
        max_len = self._get_max_length(vector)
        if len(payload_str) > max_len:
            issues.append(f"Payload zu lang: {len(payload_str)} > {max_len} Zeichen")

        # ── 3. Empty / trivial check ─────────────────────────
        if len(payload_str.strip()) < 3:
            issues.append("Payload ist leer oder trivial (< 3 Zeichen)")

        # ── 4. Syntax validation (vector-specific) ───────────
        if vector and vector in VECTOR_SYNTAX_RULES:
            syntax_issues, syntax_warnings = self._validate_syntax(payload_str, vector)
            issues.extend(syntax_issues)
            warnings.extend(syntax_warnings)

        # ── 5. Forbidden patterns (safety) ───────────────────
        safety_issues = self._check_safety(payload_str, vector)
        issues.extend(safety_issues)

        # ── 6. Tech-stack relevance ──────────────────────────
        if tech_stack and vector:
            relevance_warnings = self._check_tech_relevance(vector, tech_stack)
            warnings.extend(relevance_warnings)

        # ── 7. Deduplication ─────────────────────────────────
        if self._is_duplicate(payload_str):
            warnings.append("Duplikat: identischer Payload bereits validiert")
            self._stats["deduplicated"] += 1
            if strict:
                issues.append("Duplikat im Strict-Modus nicht erlaubt")

        # ── 8. Confidence adjustment ─────────────────────────
        original_conf = float(payload.get("confidence", payload.get("success_rate", 0.5)))
        adjusted_conf = self._adjust_confidence(original_conf, issues, warnings)

        # ── Strict mode: warnings → errors ───────────────────
        if strict and warnings:
            issues.extend([f"[strict] {w}" for w in warnings])
            warnings = []

        valid = len(issues) == 0
        if valid:
            self._stats["passed"] += 1
        else:
            self._stats["rejected"] += 1

        return PayloadValidationResult(
            valid=valid,
            payload=payload,
            issues=issues,
            warnings=warnings,
            adjusted_confidence=adjusted_conf,
        )

    def validate_batch(
        self,
        payloads: List[Dict],
        tech_stack: Optional[List[str]] = None,
        strict: bool = False,
    ) -> List[PayloadValidationResult]:
        """Validate a list of payloads. Returns list of results."""
        return [self.validate(p, tech_stack, strict) for p in payloads]

    def filter_valid(
        self,
        payloads: List[Dict],
        tech_stack: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Convenience: returns only valid payloads with adjusted confidence."""
        results = self.validate_batch(payloads, tech_stack)
        valid = []
        for r in results:
            if r.valid:
                p = r.payload.copy()
                p["confidence"] = r.adjusted_confidence
                p["validated"] = True
                valid.append(p)
        return valid

    def get_stats(self) -> Dict:
        """Return validation statistics."""
        return self._stats.copy()

    def reset(self):
        """Reset dedup cache and stats."""
        self._seen_hashes.clear()
        self._stats = {k: 0 for k in self._stats}

    # ── Private helpers ─────────────────────────────────────────

    def _validate_structure(self, payload: Dict) -> Tuple[bool, List[str]]:
        """Check that payload dict has required fields."""
        issues = []
        if not isinstance(payload, dict):
            return False, ["Payload ist kein Dictionary"]

        if "payload" not in payload and "payloads" not in payload:
            issues.append("Feld 'payload' fehlt im Payload-Dict")

        payload_val = payload.get("payload", "")
        if payload_val is None:
            issues.append("Payload-Wert ist None")
        elif not isinstance(payload_val, str):
            # Allow but warn if payload is not a string
            if not isinstance(payload_val, (list, dict)):
                issues.append(f"Payload hat unerwarteten Typ: {type(payload_val).__name__}")

        return len(issues) == 0, issues

    def _normalize_vector(self, vector: str) -> str:
        """Normalize vector name to match VECTOR_SYNTAX_RULES keys."""
        if not vector:
            return ""
        v = vector.lower().strip().replace(" ", "_").replace("-", "_")
        # Common aliases
        aliases = {
            "sqli": "sql_injection",
            "sql": "sql_injection",
            "cross_site_scripting": "xss",
            "rce": "command_injection",
            "cmd_injection": "command_injection",
            "lfi": "path_traversal",
            "rfi": "path_traversal",
            "directory_traversal": "path_traversal",
            "ssti": "template_injection",
            "server_side_template_injection": "template_injection",
        }
        return aliases.get(v, v)

    def _get_max_length(self, vector: str) -> int:
        """Get max payload length for vector."""
        if self._config and hasattr(self._config, "max_payload_length"):
            return self._config.max_payload_length
        rules = VECTOR_SYNTAX_RULES.get(vector, {})
        return rules.get("max_length", 10000)

    def _validate_syntax(self, payload_str: str, vector: str) -> Tuple[List[str], List[str]]:
        """Vector-specific syntax validation."""
        issues = []
        warnings = []
        rules = VECTOR_SYNTAX_RULES.get(vector, {})

        # Check minimum patterns — at least one should match
        min_patterns = rules.get("min_patterns", [])
        if min_patterns:
            matched = any(re.search(p, payload_str) for p in min_patterns)
            if not matched:
                warnings.append(
                    f"Payload enthält keine typischen {vector}-Muster — "
                    f"möglicherweise unwirksam"
                )

        return issues, warnings

    def _check_safety(self, payload_str: str, vector: str) -> List[str]:
        """Check for forbidden/dangerous patterns."""
        issues = []
        rules = VECTOR_SYNTAX_RULES.get(vector, {})
        forbidden = rules.get("forbidden_patterns", [])
        for pattern in forbidden:
            if re.search(pattern, payload_str):
                issues.append(
                    f"Sicherheitsverstoß: Payload enthält verbotenes Muster "
                    f"({pattern[:40]}...)"
                )
        return issues

    def _check_tech_relevance(self, vector: str, tech_stack: List[str]) -> List[str]:
        """Check if the payload vector is relevant for the detected tech stack."""
        warnings = []
        if not tech_stack:
            return warnings

        # Collect all compatible vectors for the tech stack
        compatible_vectors = set()
        for tech in tech_stack:
            tech_lower = tech.lower()
            for tech_key, vectors in TECH_VECTOR_COMPATIBILITY.items():
                if tech_key in tech_lower or tech_lower in tech_key:
                    compatible_vectors.update(vectors)

        # If we have compatibility data and vector is not in it
        if compatible_vectors and vector and vector not in compatible_vectors:
            warnings.append(
                f"Vektor '{vector}' ist möglicherweise nicht relevant für "
                f"Tech-Stack {tech_stack} (kompatibel: {sorted(compatible_vectors)})"
            )

        return warnings

    def _is_duplicate(self, payload_str: str) -> bool:
        """Check if we've seen this exact payload before."""
        h = hashlib.sha256(payload_str.encode("utf-8", errors="replace")).hexdigest()[:16]
        if h in self._seen_hashes:
            return True
        self._seen_hashes.add(h)
        return False

    def _adjust_confidence(
        self, original: float, issues: List[str], warnings: List[str]
    ) -> float:
        """
        Adjust confidence based on validation results.
        - Each issue → confidence halved
        - Each warning → 10% reduction
        - Cap LLM-sourced confidence at 0.7 (can't claim >70% without evidence)
        """
        conf = min(original, 0.7)  # Cap LLM hallucinated confidence
        for _ in issues:
            conf *= 0.5
        for _ in warnings:
            conf *= 0.9
        return round(max(conf, 0.01), 4)
