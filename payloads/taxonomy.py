"""
AI Red Team Onion — Payload Taxonomy Registry
===============================================
Zentrale Registry aller 3 Payload-Tiers.
Bietet einheitlichen Zugriff auf Tier-1 (statisch), Tier-2 (adaptiv)
und Tier-3 (strategisch) Payloads.

Funktionen:
  - get_tier(n): Alle Payloads eines Tiers
  - get_category(tier, category): Payloads einer Kategorie
  - search(query): Suche über alle Tiers
  - select_tier(context): Wählt automatisch den besten Tier
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("RedTeam.Taxonomy")


# ─────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────

@dataclass
class TaxonomyEntry:
    """Ein Eintrag in der Taxonomy Registry."""
    tier: int                    # 1, 2 oder 3
    category: str                # z.B. "sql_injection", "adaptive_generator"
    subcategory: str = ""        # z.B. "union_based", "polymorphic"
    name: str = ""               # Menschenlesbarer Name
    description: str = ""        # Beschreibung
    module_path: str = ""        # Python-Modul-Pfad
    payload_count: int = 0       # Anzahl verfügbarer Payloads
    requires_context: bool = False  # Braucht Runtime-Kontext?
    requires_cognitive: bool = False  # Braucht CognitiveEngine?


# ─────────────────────────────────────────────
# TAXONOMY REGISTRY
# ─────────────────────────────────────────────

class TaxonomyRegistry:
    """
    Zentrale Registry aller Payload-Tiers.
    Singleton — wird beim Import initialisiert.
    """

    def __init__(self):
        self._entries: list[TaxonomyEntry] = []
        self._initialized = False

    def initialize(self):
        """Registriert alle bekannten Tier-Einträge."""
        if self._initialized:
            return
        self._register_tier1()
        self._register_tier2()
        self._register_tier3()
        self._initialized = True
        logger.info(f"Taxonomy Registry: {len(self._entries)} Einträge registriert")

    def _register_tier1(self):
        """Tier-1: Statische Payloads"""
        tier1_categories = [
            # Reconnaissance
            ("network_recon", "Network Reconnaissance", "payloads.tier1_reconnaissance", "NETWORK_RECON"),
            ("dns_enumeration", "DNS Enumeration", "payloads.tier1_reconnaissance", "DNS_ENUMERATION"),
            ("subdomain_bruteforce", "Subdomain Bruteforce", "payloads.tier1_reconnaissance", "SUBDOMAIN_WORDLIST"),
            ("web_fingerprinting", "Web Fingerprinting", "payloads.tier1_reconnaissance", "WEB_FINGERPRINTING"),
            ("service_detection", "Service Detection", "payloads.tier1_reconnaissance", "SERVICE_DETECTION"),
            # Web Attacks
            ("sql_injection", "SQL Injection", "payloads.tier1_web_attacks", "SQL_INJECTION"),
            ("xss", "Cross-Site Scripting", "payloads.tier1_web_attacks", "CROSS_SITE_SCRIPTING"),
            ("command_injection", "Command Injection", "payloads.tier1_web_attacks", "COMMAND_INJECTION"),
            ("ssrf", "Server-Side Request Forgery", "payloads.tier1_web_attacks", "SSRF"),
            ("path_traversal", "Path Traversal", "payloads.tier1_web_attacks", "PATH_TRAVERSAL"),
            ("template_injection", "Template Injection", "payloads.tier1_web_attacks", "TEMPLATE_INJECTION"),
            # Credentials
            ("default_credentials", "Default Credentials", "payloads.tier1_credentials", "DEFAULT_CREDENTIALS"),
            ("common_passwords", "Common Passwords", "payloads.tier1_credentials", "COMMON_PASSWORDS"),
            ("api_key_patterns", "API Key Patterns", "payloads.tier1_credentials", "API_KEY_PATTERNS"),
            ("unsecured_endpoints", "Unsecured Endpoints", "payloads.tier1_credentials", "UNSECURED_ENDPOINTS"),
            # CVE
            ("cve_database", "CVE Database", "payloads.tier1_cve_database", "CVE_REGISTRY"),
            # LLM (bestehend)
            ("prompt_injection", "Prompt Injection", "payloads.attack_payloads", "PAYLOADS"),
            ("jailbreak", "Jailbreak", "payloads.attack_payloads", "PAYLOADS"),
            ("system_prompt_extraction", "System Prompt Extraction", "payloads.attack_payloads", "SYSTEM_PROMPT_EXTRACTION"),
            ("data_exfiltration", "Data Exfiltration", "payloads.attack_payloads", "PAYLOADS"),
            ("social_engineering", "Social Engineering", "payloads.attack_payloads", "PAYLOADS"),
            ("tool_abuse", "Tool Abuse", "payloads.attack_payloads", "PAYLOADS"),
        ]

        for cat, name, module, _ in tier1_categories:
            self._entries.append(TaxonomyEntry(
                tier=1, category=cat, name=name,
                description=f"Tier-1 statische {name} Payloads",
                module_path=module,
                requires_context=False,
                requires_cognitive=False,
            ))

    def _register_tier2(self):
        """Tier-2: Adaptive Payloads"""
        tier2_categories = [
            ("adaptive_generator", "Adaptive Payload Generator",
             "payloads.tier2_adaptive", "Kontextsensitive Payload-Generierung basierend auf Tech-Stack"),
            ("polymorphic_evasion", "Polymorphic Evasion Engine",
             "payloads.tier2_evasion", "Payload-Mutation und WAF-Bypass via Encoding/Obfuscation"),
            ("exploit_chain", "Exploit Chain Builder",
             "payloads.tier2_chain_builder", "Mehrstufige Exploit-Chains aus korrelierten Findings"),
            ("api_fuzzer", "API Fuzzer",
             "payloads.tier2_fuzzer", "Fuzzing von API-Endpunkten (JSON, Query, Header, Form)"),
        ]

        for cat, name, module, desc in tier2_categories:
            self._entries.append(TaxonomyEntry(
                tier=2, category=cat, name=name,
                description=desc,
                module_path=module,
                requires_context=True,
                requires_cognitive=cat == "adaptive_generator",
            ))

    def _register_tier3(self):
        """Tier-3: Strategische Payloads"""
        tier3_categories = [
            ("swarm_orchestrator", "Swarm Operation Orchestrator",
             "payloads.tier3_orchestrator", "Koordinierte Multi-Agent Schwarm-Operationen"),
            ("business_logic", "Business Logic Analyzer",
             "payloads.tier3_business_logic", "Race Conditions, State Machine Bypasses, TOCTOU"),
            ("covert_channels", "Covert Channel Builder",
             "payloads.tier3_covert_channels", "DNS-Tunnel, Timing-Kanäle, Steganographie"),
            ("resource_exhaustion", "Coordinated Resource Exhaustion",
             "payloads.tier3_resource_exhaustion", "Koordinierte Slowloris, ReDoS, API-Quota-Erschöpfung"),
            ("adaptive_persistence", "Adaptive Persistence Manager",
             "payloads.tier3_adaptive_persistence", "Persistenz mit automatischer Rotation bei Erkennung"),
        ]

        for cat, name, module, desc in tier3_categories:
            self._entries.append(TaxonomyEntry(
                tier=3, category=cat, name=name,
                description=desc,
                module_path=module,
                requires_context=True,
                requires_cognitive=True,
            ))

    # ─── PUBLIC API ───────────────────────────────

    def get_tier(self, tier: int) -> list[TaxonomyEntry]:
        """Alle Einträge eines bestimmten Tiers."""
        self.initialize()
        return [e for e in self._entries if e.tier == tier]

    def get_category(self, tier: int, category: str) -> Optional[TaxonomyEntry]:
        """Einzelnen Eintrag nach Tier + Kategorie."""
        self.initialize()
        for e in self._entries:
            if e.tier == tier and e.category == category:
                return e
        return None

    def search(self, query: str) -> list[TaxonomyEntry]:
        """Suche über Name, Kategorie und Beschreibung."""
        self.initialize()
        q = query.lower()
        return [
            e for e in self._entries
            if q in e.name.lower()
            or q in e.category.lower()
            or q in e.description.lower()
        ]

    def get_all(self) -> list[TaxonomyEntry]:
        """Alle Einträge."""
        self.initialize()
        return list(self._entries)

    def get_stats(self) -> dict:
        """Statistiken über die Registry."""
        self.initialize()
        return {
            "total_entries": len(self._entries),
            "tier1": len(self.get_tier(1)),
            "tier2": len(self.get_tier(2)),
            "tier3": len(self.get_tier(3)),
            "requires_cognitive": sum(1 for e in self._entries if e.requires_cognitive),
            "requires_context": sum(1 for e in self._entries if e.requires_context),
        }


# ─────────────────────────────────────────────
# PAYLOAD SELECTOR
# ─────────────────────────────────────────────

class PayloadSelector:
    """
    Wählt automatisch den optimalen Tier basierend auf verfügbarem Kontext.

    Entscheidungslogik:
      - Kein Kontext → Tier 1 (statische Payloads)
      - Tech-Stack bekannt → Tier 2 (adaptive Generierung)
      - Mehrere korrelierte Findings + Schwarm-Koordination → Tier 3
    """

    def __init__(self, registry: Optional[TaxonomyRegistry] = None):
        self.registry = registry or TaxonomyRegistry()
        self.registry.initialize()

    def select_tier(
        self,
        tech_stack: list[str] = None,
        findings: list[dict] = None,
        cognitive_enabled: bool = False,
        agent_count: int = 1,
    ) -> int:
        """
        Wählt den optimalen Tier.

        Args:
            tech_stack: Erkannte Technologien
            findings: Bisherige Schwachstellen-Findings
            cognitive_enabled: Ist die CognitiveEngine verfügbar?
            agent_count: Anzahl aktiver Agenten

        Returns:
            Empfohlener Tier (1, 2 oder 3)
        """
        # Tier 3: Mehrere korrelierte Findings + Schwarm
        if (findings and len(findings) >= 3
                and cognitive_enabled
                and agent_count >= 2):
            unique_vectors = set(f.get("vector", "") for f in findings if f.get("vector"))
            if len(unique_vectors) >= 2:
                return 3

        # Tier 2: Tech-Stack bekannt oder Findings vorhanden
        if tech_stack or (findings and cognitive_enabled):
            return 2

        # Tier 1: Default
        return 1

    def get_recommended_categories(
        self,
        tier: int,
        vector: str = "",
    ) -> list[TaxonomyEntry]:
        """
        Empfiehlt Kategorien für den gewählten Tier.

        Args:
            tier: Gewählter Tier
            vector: Optionaler Angriffsvektor-Filter

        Returns:
            Liste empfohlener TaxonomyEntries
        """
        entries = self.registry.get_tier(tier)
        if vector:
            # Exakte Matches zuerst, dann verwandte
            exact = [e for e in entries if e.category == vector]
            related = [e for e in entries if vector in e.description.lower() and e not in exact]
            return exact + related

        return entries


# ─────────────────────────────────────────────
# MODULE-LEVEL SINGLETON
# ─────────────────────────────────────────────

_registry = TaxonomyRegistry()


def get_registry() -> TaxonomyRegistry:
    """Zugriff auf die globale Taxonomy Registry."""
    _registry.initialize()
    return _registry


def get_selector() -> PayloadSelector:
    """Zugriff auf den globalen Payload Selector."""
    return PayloadSelector(_registry)
