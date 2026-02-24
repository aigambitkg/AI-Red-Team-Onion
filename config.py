"""
AI Red Team Scanner - Configuration
====================================
Konfiguration für den AI Red Team Security Scanner.
"""

import os
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class NotionConfig:
    """Notion API Konfiguration"""
    api_key: str = os.getenv("NOTION_API_KEY", "")
    database_id: str = os.getenv("NOTION_DATABASE_ID", "")
    poll_interval_seconds: int = 30

@dataclass
class BrowserConfig:
    """Playwright Browser Konfiguration — nutzt Google Chrome (nicht Chromium)"""
    headless: bool = True
    timeout_ms: int = 30000
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    viewport_width: int = 1280
    viewport_height: int = 720
    browser_engine: str = "chrome"  # "chrome" = Google Chrome, "chromium" = Playwright Chromium
    chrome_path: str = ""  # Optional: Pfad zur Chrome-Binary, leer = auto-detect

@dataclass
class ScanConfig:
    """Scan-Parameter"""
    max_retries: int = 3
    delay_between_tests_sec: float = 2.0
    max_response_wait_sec: float = 15.0
    enable_browser_tests: bool = True
    enable_api_tests: bool = True

    # Welche Module aktiviert sind
    modules: list = field(default_factory=lambda: [
        "system_prompt_extraction",
        "prompt_injection",
        "jailbreak",
        "tool_abuse",
        "data_exfiltration",
        "social_engineering",
        # Tier-1 Module (benötigen keinen LLM-API-Key)
        "web_vulnerability",
        "reconnaissance",
        "credential_testing",
        "cve_scanner",
    ])

@dataclass
class APITargetConfig:
    """Konfiguration für API-basierte Ziele"""
    api_url: str = ""
    api_key: Optional[str] = None
    model: str = ""
    headers: dict = field(default_factory=dict)

@dataclass
class CognitiveConfig:
    """Konfiguration für das kognitive System (LLM-Reasoning, Memory, etc.)"""
    enabled: bool = os.getenv("REDSWARM_COGNITIVE_ENABLED", "true").lower() == "true"
    llm_provider: str = os.getenv("REDSWARM_LLM_PROVIDER", "anthropic")
    llm_model: str = os.getenv("REDSWARM_LLM_MODEL", "")
    llm_temperature: float = float(os.getenv("REDSWARM_LLM_TEMPERATURE", "0.7"))
    llm_max_tokens: int = int(os.getenv("REDSWARM_LLM_MAX_TOKENS", "2000"))
    memory_data_dir: str = os.getenv("REDSWARM_DATA_DIR", "./data")
    reflector_max_retries: int = 3

@dataclass
class SwarmIntelligenceConfig:
    """Konfiguration für Schwarm-Intelligenz (Stigmergy, Emergence, Resilience)"""
    stigmergy_enabled: bool = True
    pheromone_decay_rate: float = float(os.getenv("REDSWARM_PHEROMONE_DECAY", "0.05"))
    emergence_min_correlation: float = 0.6
    resilience_heartbeat_timeout: float = float(os.getenv("REDSWARM_HEARTBEAT_TIMEOUT", "30.0"))
    resilience_degradation_threshold: float = 0.5

@dataclass
class TierConfig:
    """Konfiguration für das 3-Tier Payload-System"""
    tier1_enabled: bool = os.getenv("REDSWARM_TIER1_ENABLED", "true").lower() == "true"
    tier2_enabled: bool = os.getenv("REDSWARM_TIER2_ENABLED", "true").lower() == "true"
    tier3_enabled: bool = os.getenv("REDSWARM_TIER3_ENABLED", "true").lower() == "true"
    auto_select_tier: bool = os.getenv("REDSWARM_TIER_AUTO_SELECT", "true").lower() == "true"
    load_tier1_into_kb: bool = os.getenv("REDSWARM_LOAD_TIER1_INTO_KB", "true").lower() == "true"
    max_tier2_mutations: int = int(os.getenv("REDSWARM_MAX_TIER2_MUTATIONS", "10"))
    tier3_min_findings: int = int(os.getenv("REDSWARM_TIER3_MIN_FINDINGS", "3"))

@dataclass
class ValidationConfig:
    """Konfiguration für das Anti-Halluzinations- und Validierungssystem"""
    enabled: bool = os.getenv("REDSWARM_VALIDATION_ENABLED", "true").lower() == "true"
    # PayloadValidator: Syntax-Check vor Ausführung
    validate_payloads_before_exec: bool = True
    max_payload_length: int = int(os.getenv("REDSWARM_MAX_PAYLOAD_LENGTH", "10000"))
    # ResultVerifier: Ground-Truth nach Ausführung
    verify_results: bool = True
    min_evidence_count: int = int(os.getenv("REDSWARM_MIN_EVIDENCE_COUNT", "2"))
    re_test_on_success: bool = True  # Erfolge nochmal testen
    # ConfidenceCalibrator: Empirische Confidence
    use_empirical_confidence: bool = True
    confidence_decay_rate: float = float(os.getenv("REDSWARM_CONFIDENCE_DECAY", "0.1"))
    min_confidence_threshold: float = float(os.getenv("REDSWARM_MIN_CONFIDENCE", "0.3"))
    # ConsensusValidator: Multi-Agent-Quorum
    require_consensus: bool = os.getenv("REDSWARM_REQUIRE_CONSENSUS", "true").lower() == "true"
    consensus_quorum: int = int(os.getenv("REDSWARM_CONSENSUS_QUORUM", "2"))
    # Welche Severity braucht Konsens (alles >= diesem Level)
    consensus_min_severity: str = os.getenv("REDSWARM_CONSENSUS_MIN_SEVERITY", "medium")

@dataclass
class AppConfig:
    notion: NotionConfig = field(default_factory=NotionConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    cognitive: CognitiveConfig = field(default_factory=CognitiveConfig)
    swarm_intelligence: SwarmIntelligenceConfig = field(default_factory=SwarmIntelligenceConfig)
    tiers: TierConfig = field(default_factory=TierConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)

    # Logging
    log_level: str = "INFO"
    log_file: str = "red_team_scan.log"
