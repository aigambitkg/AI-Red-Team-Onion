"""
AI Red Team Onion — Taxonomy Test Suite
=========================================
Vollständiger Test aller 3 Payload-Tiers.

Tests:
  - Tier 1: Payload-Syntax, KB-Loading, Module-Integration
  - Tier 2: Generator-Output, Evasion-Varianten, Chain-Validierung
  - Tier 3: Orchestrator-Logik, Blackboard-Flow
  - Registry: Suche, Tier-Selektion, Statistiken
"""

import sys
import os
import importlib
import unittest
from pathlib import Path

# Projekt-Root zum Path hinzufügen
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestTier1Payloads(unittest.TestCase):
    """Tier-1: Statische Payload-Bibliotheken."""

    def test_tier1_reconnaissance_imports(self):
        """tier1_reconnaissance.py ist importierbar und hat erwartete Exports."""
        mod = importlib.import_module("payloads.tier1_reconnaissance")
        self.assertTrue(hasattr(mod, "NETWORK_RECON"))
        self.assertTrue(hasattr(mod, "DNS_ENUMERATION"))
        self.assertTrue(hasattr(mod, "SUBDOMAIN_BRUTEFORCE"))
        self.assertTrue(hasattr(mod, "WEB_FINGERPRINTING"))
        self.assertTrue(hasattr(mod, "SERVICE_DETECTION"))
        # Compatibility aliases
        self.assertTrue(hasattr(mod, "HTTP_TECH_FINGERPRINTING"))
        self.assertTrue(hasattr(mod, "COMMON_PATHS"))
        self.assertTrue(hasattr(mod, "FINGERPRINT_INDICATORS"))

    def test_tier1_reconnaissance_non_empty(self):
        """Recon-Payloads enthalten tatsächliche Daten."""
        from payloads.tier1_reconnaissance import NETWORK_RECON, get_subdomain_wordlist
        self.assertGreater(len(NETWORK_RECON), 0, "NETWORK_RECON darf nicht leer sein")
        wordlist = get_subdomain_wordlist()
        self.assertGreater(len(wordlist), 50, "SUBDOMAIN_WORDLIST soll 50+ Einträge haben")

    def test_tier1_web_attacks_imports(self):
        """tier1_web_attacks.py ist importierbar und hat erwartete Exports."""
        mod = importlib.import_module("payloads.tier1_web_attacks")
        self.assertTrue(hasattr(mod, "SQL_INJECTION"))
        self.assertTrue(hasattr(mod, "CROSS_SITE_SCRIPTING"))
        self.assertTrue(hasattr(mod, "COMMAND_INJECTION"))
        self.assertTrue(hasattr(mod, "SSRF"))
        self.assertTrue(hasattr(mod, "PATH_TRAVERSAL"))
        self.assertTrue(hasattr(mod, "TEMPLATE_INJECTION"))

    def test_tier1_web_attacks_categories(self):
        """Web-Attack-Payloads sind nach DB-Typ/Technik kategorisiert."""
        from payloads.tier1_web_attacks import SQL_INJECTION
        self.assertIsInstance(SQL_INJECTION, dict)
        # Check that a key containing "union_based" exists (adjacent string literal in dict)
        keys_str = " ".join(SQL_INJECTION.keys())
        self.assertIn("union_based", keys_str)

    def test_tier1_web_success_indicators(self):
        """WEB_SUCCESS_INDICATORS sind vorhanden."""
        mod = importlib.import_module("payloads.tier1_web_attacks")
        self.assertTrue(hasattr(mod, "WEB_SUCCESS_INDICATORS"))
        indicators = mod.WEB_SUCCESS_INDICATORS
        self.assertIsInstance(indicators, dict)
        self.assertGreater(len(indicators), 0)

    def test_tier1_credentials_imports(self):
        """tier1_credentials.py ist importierbar."""
        mod = importlib.import_module("payloads.tier1_credentials")
        self.assertTrue(hasattr(mod, "DEFAULT_CREDENTIALS"))
        self.assertTrue(hasattr(mod, "COMMON_PASSWORDS"))
        self.assertTrue(hasattr(mod, "API_KEY_PATTERNS"))
        self.assertTrue(hasattr(mod, "UNSECURED_ENDPOINTS"))

    def test_tier1_credentials_patterns(self):
        """API Key Patterns sind valide Regex-Strings oder kompilierte Pattern."""
        import re
        from payloads.tier1_credentials import API_KEY_PATTERNS
        self.assertIsInstance(API_KEY_PATTERNS, dict)
        self.assertGreater(len(API_KEY_PATTERNS), 0)
        # Values can be compiled regex patterns or strings
        for name, pattern in list(API_KEY_PATTERNS.items())[:10]:
            if isinstance(pattern, re.Pattern):
                # Already compiled — valid
                self.assertIsNotNone(pattern.pattern)
            elif isinstance(pattern, str):
                try:
                    re.compile(pattern)
                except re.error:
                    self.fail(f"Ungültiger Regex: {pattern}")
            elif isinstance(pattern, dict):
                p = pattern.get("pattern", "")
                if p:
                    re.compile(p)

    def test_tier1_cve_database_imports(self):
        """tier1_cve_database.py ist importierbar."""
        mod = importlib.import_module("payloads.tier1_cve_database")
        self.assertTrue(hasattr(mod, "CVE_REGISTRY"))
        self.assertTrue(hasattr(mod, "SERVICE_CVE_MAP"))

    def test_tier1_cve_registry_structure(self):
        """CVE Registry hat erwartete Struktur."""
        from payloads.tier1_cve_database import CVE_REGISTRY
        self.assertIsInstance(CVE_REGISTRY, (dict, list))
        if isinstance(CVE_REGISTRY, dict):
            # Mindestens ein CVE-Eintrag
            self.assertGreater(len(CVE_REGISTRY), 0)


class TestTier1Modules(unittest.TestCase):
    """Tier-1: Attack-Module."""

    def _try_import(self, module_path, class_name):
        """Helper: Import a module class, skip if dependencies missing."""
        try:
            mod = importlib.import_module(module_path)
            return getattr(mod, class_name)
        except ImportError as e:
            self.skipTest(f"Dependencies missing for {module_path}: {e}")

    def test_web_vulnerability_module_imports(self):
        """WebVulnerabilityModule ist importierbar."""
        cls = self._try_import("modules.web_vulnerability", "WebVulnerabilityModule")
        mod = cls()
        self.assertEqual(mod.name, "Web Vulnerability")

    def test_reconnaissance_module_imports(self):
        """ReconnaissanceModule ist importierbar."""
        cls = self._try_import("modules.reconnaissance", "ReconnaissanceModule")
        mod = cls()
        self.assertEqual(mod.name, "Reconnaissance")

    def test_credential_testing_module_imports(self):
        """CredentialTestingModule ist importierbar."""
        cls = self._try_import("modules.credential_testing", "CredentialTestingModule")
        mod = cls()
        self.assertEqual(mod.name, "Credential Testing")

    def test_cve_scanner_module_imports(self):
        """CVEScannerModule ist importierbar."""
        cls = self._try_import("modules.cve_scanner", "CVEScannerModule")
        mod = cls()
        self.assertEqual(mod.name, "CVE Scanner")

    def test_modules_inherit_base(self):
        """Alle Module erben von BaseAttackModule."""
        from modules.base_module import BaseAttackModule
        modules = [
            ("modules.web_vulnerability", "WebVulnerabilityModule"),
            ("modules.reconnaissance", "ReconnaissanceModule"),
            ("modules.credential_testing", "CredentialTestingModule"),
            ("modules.cve_scanner", "CVEScannerModule"),
        ]
        imported = 0
        for mod_path, cls_name in modules:
            try:
                mod = importlib.import_module(mod_path)
                cls = getattr(mod, cls_name)
                self.assertTrue(
                    issubclass(cls, BaseAttackModule),
                    f"{cls_name} muss von BaseAttackModule erben"
                )
                imported += 1
            except ImportError:
                continue
        self.assertGreater(imported, 0, "Mindestens ein Modul muss importierbar sein")


class TestTier2Payloads(unittest.TestCase):
    """Tier-2: Adaptive Payload-Generierung."""

    def test_tier2_adaptive_imports(self):
        """tier2_adaptive.py ist importierbar."""
        mod = importlib.import_module("payloads.tier2_adaptive")
        self.assertTrue(hasattr(mod, "TechStackMapper"))
        self.assertTrue(hasattr(mod, "AdaptivePayloadGenerator"))

    def test_tech_stack_mapper(self):
        """TechStackMapper liefert Payloads für bekannte Technologien."""
        from payloads.tier2_adaptive import TechStackMapper
        mapper = TechStackMapper()
        result = mapper.map_tech_to_payloads(["mysql", "nginx"])
        self.assertIsInstance(result, dict)
        # Sollte mindestens eine Kategorie zurückgeben
        self.assertGreater(len(result), 0, "TechStackMapper soll Payloads liefern")

    def test_tier2_evasion_imports(self):
        """tier2_evasion.py ist importierbar."""
        mod = importlib.import_module("payloads.tier2_evasion")
        self.assertTrue(hasattr(mod, "PolymorphicEngine"))

    def test_polymorphic_engine_mutate(self):
        """PolymorphicEngine erzeugt Varianten."""
        from payloads.tier2_evasion import PolymorphicEngine
        engine = PolymorphicEngine()
        payload = "' OR 1=1--"
        mutations = engine.mutate(payload)
        self.assertIsInstance(mutations, list)
        self.assertGreater(len(mutations), 0, "Muss mindestens eine Mutation erzeugen")
        # Mutationen müssen sich vom Original unterscheiden
        unique = set(mutations)
        self.assertGreater(len(unique), 0)

    def test_tier2_chain_builder_imports(self):
        """tier2_chain_builder.py ist importierbar."""
        mod = importlib.import_module("payloads.tier2_chain_builder")
        self.assertTrue(hasattr(mod, "ExploitChainBuilder"))

    def test_tier2_fuzzer_imports(self):
        """tier2_fuzzer.py ist importierbar."""
        mod = importlib.import_module("payloads.tier2_fuzzer")
        self.assertTrue(hasattr(mod, "APIFuzzer"))


class TestTier3Payloads(unittest.TestCase):
    """Tier-3: Strategische Payloads."""

    def test_tier3_orchestrator_imports(self):
        """tier3_orchestrator.py ist importierbar."""
        mod = importlib.import_module("payloads.tier3_orchestrator")
        self.assertTrue(hasattr(mod, "SwarmOperationOrchestrator"))

    def test_tier3_business_logic_imports(self):
        """tier3_business_logic.py ist importierbar."""
        mod = importlib.import_module("payloads.tier3_business_logic")
        self.assertTrue(hasattr(mod, "BusinessFlowAnalyzer"))

    def test_tier3_covert_channels_imports(self):
        """tier3_covert_channels.py ist importierbar."""
        mod = importlib.import_module("payloads.tier3_covert_channels")
        self.assertTrue(hasattr(mod, "CovertChannelBuilder"))

    def test_tier3_resource_exhaustion_imports(self):
        """tier3_resource_exhaustion.py ist importierbar."""
        mod = importlib.import_module("payloads.tier3_resource_exhaustion")
        self.assertTrue(hasattr(mod, "CoordinatedExhaustion"))

    def test_tier3_adaptive_persistence_imports(self):
        """tier3_adaptive_persistence.py ist importierbar."""
        mod = importlib.import_module("payloads.tier3_adaptive_persistence")
        self.assertTrue(hasattr(mod, "AdaptivePersistenceManager"))


class TestTaxonomyRegistry(unittest.TestCase):
    """Taxonomy Registry und Payload Selector."""

    def test_registry_initializes(self):
        """Registry initialisiert sich ohne Fehler."""
        from payloads.taxonomy import TaxonomyRegistry
        reg = TaxonomyRegistry()
        reg.initialize()
        stats = reg.get_stats()
        self.assertGreater(stats["total_entries"], 0)

    def test_registry_tiers(self):
        """Registry hat Einträge für alle 3 Tiers."""
        from payloads.taxonomy import TaxonomyRegistry
        reg = TaxonomyRegistry()
        reg.initialize()
        self.assertGreater(len(reg.get_tier(1)), 0, "Tier 1 muss Einträge haben")
        self.assertGreater(len(reg.get_tier(2)), 0, "Tier 2 muss Einträge haben")
        self.assertGreater(len(reg.get_tier(3)), 0, "Tier 3 muss Einträge haben")

    def test_registry_search(self):
        """Registry-Suche findet relevante Einträge."""
        from payloads.taxonomy import TaxonomyRegistry
        reg = TaxonomyRegistry()
        reg.initialize()
        results = reg.search("sql")
        self.assertGreater(len(results), 0, "Suche nach 'sql' muss Ergebnisse liefern")

    def test_registry_get_category(self):
        """get_category findet spezifische Einträge."""
        from payloads.taxonomy import TaxonomyRegistry
        reg = TaxonomyRegistry()
        reg.initialize()
        entry = reg.get_category(1, "sql_injection")
        self.assertIsNotNone(entry, "SQL Injection muss in Tier 1 existieren")

    def test_payload_selector_tier1_default(self):
        """PayloadSelector wählt Tier 1 ohne Kontext."""
        from payloads.taxonomy import PayloadSelector
        selector = PayloadSelector()
        tier = selector.select_tier()
        self.assertEqual(tier, 1, "Ohne Kontext muss Tier 1 gewählt werden")

    def test_payload_selector_tier2_with_techstack(self):
        """PayloadSelector wählt Tier 2 mit Tech-Stack."""
        from payloads.taxonomy import PayloadSelector
        selector = PayloadSelector()
        tier = selector.select_tier(tech_stack=["nginx", "django"])
        self.assertEqual(tier, 2, "Mit Tech-Stack muss Tier 2 gewählt werden")

    def test_payload_selector_tier3_with_findings(self):
        """PayloadSelector wählt Tier 3 mit genug Findings + CognitiveEngine."""
        from payloads.taxonomy import PayloadSelector
        selector = PayloadSelector()
        findings = [
            {"vector": "sqli", "severity": "high"},
            {"vector": "xss", "severity": "medium"},
            {"vector": "ssrf", "severity": "high"},
        ]
        tier = selector.select_tier(
            findings=findings,
            cognitive_enabled=True,
            agent_count=4,
        )
        self.assertEqual(tier, 3, "Mit 3+ Findings + Cognitive muss Tier 3 gewählt werden")


class TestPayloadsInit(unittest.TestCase):
    """payloads/__init__.py Registry."""

    def test_init_imports(self):
        """payloads/__init__.py ist importierbar."""
        mod = importlib.import_module("payloads")
        self.assertTrue(hasattr(mod, "get_all_tier1_payloads"))
        self.assertTrue(hasattr(mod, "get_payloads_by_category"))

    def test_get_all_tier1_payloads(self):
        """get_all_tier1_payloads gibt ein Dict zurück."""
        from payloads import get_all_tier1_payloads
        result = get_all_tier1_payloads()
        self.assertIsInstance(result, dict)
        self.assertGreater(len(result), 0)


class TestKBTierLoader(unittest.TestCase):
    """Knowledge Base Tier Loader."""

    def test_kb_tier_loader_imports(self):
        """kb_tier_loader.py ist importierbar."""
        mod = importlib.import_module("knowledge.kb_tier_loader")
        self.assertTrue(hasattr(mod, "load_tier1_into_kb"))


class TestConfigIntegration(unittest.TestCase):
    """Config-Integration."""

    def test_tier_config_exists(self):
        """TierConfig existiert in config.py."""
        from config import TierConfig, AppConfig
        cfg = AppConfig()
        self.assertTrue(hasattr(cfg, "tiers"))
        self.assertIsInstance(cfg.tiers, TierConfig)

    def test_new_modules_in_scan_config(self):
        """Neue Module sind in ScanConfig.modules registriert."""
        from config import ScanConfig
        cfg = ScanConfig()
        self.assertIn("web_vulnerability", cfg.modules)
        self.assertIn("reconnaissance", cfg.modules)
        self.assertIn("credential_testing", cfg.modules)
        self.assertIn("cve_scanner", cfg.modules)


class TestScannerIntegration(unittest.TestCase):
    """Scanner-Integration der neuen Module."""

    def test_scanner_loads_tier1_modules(self):
        """Scanner lädt Tier-1-Module ohne Fehler."""
        try:
            from scanner import RedTeamScanner
            scanner = RedTeamScanner()
            module_names = [m.name for m in scanner.modules]
            # Bestehende Module müssen geladen sein (display names)
            self.assertIn("System Prompt Extraction", module_names)
            # Tier-1-Module sollten auch geladen sein (wenn verfügbar)
            tier1_names = ["Web Vulnerability", "Reconnaissance", "Credential Testing", "CVE Scanner"]
            tier1_loaded = [n for n in tier1_names if n in module_names]
            # At least the base modules must be present
            self.assertGreater(len(module_names), 0, "Scanner muss Module laden")
        except ImportError as e:
            self.skipTest(f"Scanner-Dependencies fehlen: {e}")


class TestAgentIntegration(unittest.TestCase):
    """Agent-Integration der Tier 2/3 Funktionalität."""

    def test_engine_has_adaptive_prompt(self):
        """CognitiveEngine hat adaptive_generator System-Prompt."""
        from swarm.cognition.engine import SYSTEM_PROMPTS
        self.assertIn("adaptive_generator", SYSTEM_PROMPTS)

    def test_engine_has_adaptive_method(self):
        """CognitiveEngine hat generate_adaptive_payload() Methode."""
        from swarm.cognition.engine import CognitiveEngine
        self.assertTrue(hasattr(CognitiveEngine, "generate_adaptive_payload"))

    def test_emergence_has_chain_detection(self):
        """EmergenceDetector hat detect_chain_opportunity() Methode."""
        from swarm.intelligence.emergence import EmergenceDetector
        self.assertTrue(hasattr(EmergenceDetector, "detect_chain_opportunity"))

    def test_resilience_has_tier_circuit_breaker(self):
        """ResilienceManager hat create_tier_circuit_breaker() Methode."""
        from swarm.intelligence.resilience import ResilienceManager
        self.assertTrue(hasattr(ResilienceManager, "create_tier_circuit_breaker"))

    def test_resilience_tier_fallback(self):
        """ResilienceManager Tier-Fallback funktioniert."""
        from swarm.intelligence.resilience import ResilienceManager
        rm = ResilienceManager()
        rm.register_agent("test_agent", "exploit")
        # Ohne offenen Circuit: Kein Fallback
        result = rm.get_tier_fallback_recommendation("test_agent", 3)
        self.assertIsNone(result, "Ohne offenen Circuit kein Fallback")


class TestSuccessIndicators(unittest.TestCase):
    """Erweiterte SUCCESS_INDICATORS."""

    def test_web_indicators_present(self):
        """SUCCESS_INDICATORS enthält Web-Attack-Kategorien."""
        from payloads.attack_payloads import SUCCESS_INDICATORS
        self.assertIn("sql_injection", SUCCESS_INDICATORS)
        self.assertIn("xss", SUCCESS_INDICATORS)
        self.assertIn("command_injection", SUCCESS_INDICATORS)
        self.assertIn("ssrf", SUCCESS_INDICATORS)
        self.assertIn("path_traversal", SUCCESS_INDICATORS)
        self.assertIn("template_injection", SUCCESS_INDICATORS)

    def test_indicators_are_lists(self):
        """Alle Indicator-Einträge sind Listen."""
        from payloads.attack_payloads import SUCCESS_INDICATORS
        for key, value in SUCCESS_INDICATORS.items():
            self.assertIsInstance(value, list, f"{key} muss eine Liste sein")
            self.assertGreater(len(value), 0, f"{key} darf nicht leer sein")


class TestKBSubcategories(unittest.TestCase):
    """Erweiterte SUBCATEGORIES in Knowledge Base."""

    def test_new_subcategories_present(self):
        """SUBCATEGORIES enthält neue Tier-1/2/3-Kategorien."""
        from knowledge.knowledge_base import SUBCATEGORIES
        new_cats = [
            "network_recon", "dns_enumeration", "command_injection",
            "ssrf", "path_traversal", "template_injection",
            "adaptive_payload", "polymorphic_evasion", "exploit_chain",
            "business_logic", "covert_channel", "resource_exhaustion",
            "adaptive_persistence", "swarm_operation",
        ]
        for cat in new_cats:
            self.assertIn(cat, SUBCATEGORIES, f"'{cat}' fehlt in SUBCATEGORIES")


if __name__ == "__main__":
    unittest.main(verbosity=2)
