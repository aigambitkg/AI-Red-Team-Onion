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
    ])

@dataclass
class APITargetConfig:
    """Konfiguration für API-basierte Ziele"""
    api_url: str = ""
    api_key: Optional[str] = None
    model: str = ""
    headers: dict = field(default_factory=dict)

@dataclass
class AppConfig:
    notion: NotionConfig = field(default_factory=NotionConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)

    # Logging
    log_level: str = "INFO"
    log_file: str = "red_team_scan.log"
