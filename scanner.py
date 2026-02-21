"""
AI Red Team Scanner - Orchestrator (v2.0)
==========================================
Zentrale Steuerung: Lädt Module, führt Tests durch, sammelt Ergebnisse.

FIX v2.0:
- Voller Browser-Reset zwischen Modulen (frische Session pro Modul)
- Integriertes Event-Logging für volle Transparenz
- Kill-Switch Support (Abbruch jederzeit möglich)
- Validierung gegen False Positives
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

# Knowledge Base — optional, kein Fehler wenn nicht vorhanden
try:
    from knowledge.knowledge_base import KnowledgeBase
    from knowledge.learner import ScanLearner
    _KB_AVAILABLE = True
except ImportError:
    _KB_AVAILABLE = False

from config import AppConfig, ScanConfig
from modules.base_module import ModuleResult, Severity
from modules.system_prompt_extraction import SystemPromptExtractionModule
from modules.prompt_injection import PromptInjectionModule
from modules.jailbreak import JailbreakModule
from modules.tool_abuse import ToolAbuseModule
from modules.data_exfiltration import DataExfiltrationModule
from modules.social_engineering import SocialEngineeringModule
from modules.api_client import LLMAPIClient, APIConfig
from browser.chatbot_interactor import ChatbotInteractor
from monitor.event_logger import EventLogger, EventSeverity, EventType, ScanEvent

logger = logging.getLogger(__name__)


@dataclass
class ScanTarget:
    """Beschreibt ein Scan-Ziel"""
    name: str
    url: str
    target_type: str  # "chatbot", "api", "internal"
    api_config: Optional[APIConfig] = None
    notion_page_id: Optional[str] = None


@dataclass
class ScanReport:
    """Gesamtergebnis eines Scans"""
    target: ScanTarget
    module_results: list = field(default_factory=list)
    total_tests: int = 0
    total_vulnerabilities: int = 0
    highest_severity: Severity = Severity.INFO
    overall_risk: str = "🟢 Niedrig"
    duration_seconds: float = 0.0
    scan_timestamp: str = ""
    false_positives_caught: int = 0
    was_killed: bool = False

    def add_module_result(self, result: ModuleResult):
        self.module_results.append(result)
        self.total_tests += result.total_tests
        self.total_vulnerabilities += result.vulnerabilities_found

        if ModuleResult._severity_rank(result.highest_severity) > ModuleResult._severity_rank(self.highest_severity):
            self.highest_severity = result.highest_severity

        self._update_risk_level()

    def _update_risk_level(self):
        if self.highest_severity == Severity.CRITICAL:
            self.overall_risk = "🔴 Kritisch"
        elif self.highest_severity == Severity.HIGH:
            self.overall_risk = "🟠 Hoch"
        elif self.highest_severity == Severity.MEDIUM:
            self.overall_risk = "🟡 Mittel"
        else:
            self.overall_risk = "🟢 Niedrig"

    def to_markdown(self) -> str:
        """Generiert einen Markdown-Bericht"""
        lines = [
            f"# Scan-Ergebnisse: {self.target.name}",
            f"**Ziel-URL:** {self.target.url}",
            f"**Ziel-Typ:** {self.target.target_type}",
            f"**Scan-Datum:** {self.scan_timestamp}",
            f"**Dauer:** {self.duration_seconds:.1f} Sekunden",
            f"**False Positives abgefangen:** {self.false_positives_caught}",
            "",
        ]

        if self.was_killed:
            lines.append("⚠️ **SCAN WURDE DURCH KILL-SWITCH ABGEBROCHEN**")
            lines.append("")

        lines.extend([
            "---",
            "",
            f"## Zusammenfassung",
            f"**Gesamtrisiko:** {self.overall_risk}",
            f"**Tests durchgeführt:** {self.total_tests}",
            f"**Schwachstellen gefunden:** {self.total_vulnerabilities}",
            f"**Höchste Schwere:** {self.highest_severity.value}",
            "",
        ])

        for mod_result in self.module_results:
            lines.append(f"---")
            lines.append(f"")
            lines.append(f"## {mod_result.module_name}")
            lines.append(f"{mod_result.summary}")
            lines.append(f"")
            lines.append(f"| Test | Status | Schwere | Details |")
            lines.append(f"|---|---|---|---|")

            for test in mod_result.test_results:
                status_icon = "✅" if not test.is_vulnerable else "❌"
                sev = test.severity.value
                details = test.details[:80].replace("|", "/")
                name = test.test_name[:30]
                lines.append(f"| {name} | {status_icon} {test.status.value} | {sev} | {details} |")

            vulns = [t for t in mod_result.test_results if t.is_vulnerable]
            if vulns:
                lines.append("")
                lines.append(f"### Evidenz")
                for v in vulns[:5]:
                    lines.append(f"**{v.test_name}:**")
                    lines.append(f"- Payload: `{v.payload_used[:100]}`")
                    lines.append(f"- Response: `{v.response_received[:200]}`")
                    lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("## Empfehlungen")
        lines.extend(self._generate_recommendations())

        return "\n".join(lines)

    def _generate_recommendations(self) -> list[str]:
        recs = []
        vuln_categories = set()
        for mod in self.module_results:
            for test in mod.test_results:
                if test.is_vulnerable:
                    vuln_categories.add(test.category)

        if "System Prompt Extraction" in vuln_categories:
            recs.append("- **System Prompt schützen:** Implementiere Prompt-Guardrails die das Ausgeben des System Prompts verhindern. Nutze Output-Filter.")
        if "Prompt Injection" in vuln_categories:
            recs.append("- **Input Sanitization:** Implementiere Input-Validierung und -Filterung. Nutze Sandwich-Defense (User-Input zwischen System-Instruktionen einbetten).")
        if "Jailbreak" in vuln_categories:
            recs.append("- **Guardrails stärken:** Überprüfe und verstärke die Sicherheitsrichtlinien. Implementiere Multi-Layer-Defense mit Output-Monitoring.")
        if "Tool Abuse" in vuln_categories:
            recs.append("- **Tool-Zugriff einschränken:** Implementiere Least-Privilege für Tool-Aufrufe. Validiere alle Parameter serverseitig.")
        if "Data Exfiltration" in vuln_categories:
            recs.append("- **Daten-Isolation:** Minimiere den Datenzugriff der KI. Implementiere Data Loss Prevention (DLP) Filter.")
        if "Social Engineering" in vuln_categories:
            recs.append("- **Robustere Persona:** Stärke die Konsistenz der KI-Persona. Implementiere Erkennung von Manipulationsversuchen.")

        if not recs:
            recs.append("- Keine kritischen Schwachstellen gefunden. Weiterhin regelmäßig testen.")

        return recs


class RedTeamScanner:
    """
    Hauptklasse: Orchestriert den gesamten Scan-Prozess.

    v2.0:
    - Voller Browser-Reset zwischen jedem Modul
    - Integriertes Event-Logging
    - Kill-Switch Support
    """

    def __init__(self, config: AppConfig = None, event_logger: EventLogger = None):
        self.config = config or AppConfig()
        self.modules = self._load_modules()
        self.event_logger = event_logger or EventLogger(log_dir="logs")

    def _load_modules(self) -> list:
        """Aktivierte Module laden"""
        module_map = {
            "system_prompt_extraction": SystemPromptExtractionModule,
            "prompt_injection": PromptInjectionModule,
            "jailbreak": JailbreakModule,
            "tool_abuse": ToolAbuseModule,
            "data_exfiltration": DataExfiltrationModule,
            "social_engineering": SocialEngineeringModule,
        }

        active = []
        for mod_name in self.config.scan.modules:
            if mod_name in module_map:
                active.append(module_map[mod_name]())
                logger.info(f"Modul geladen: {mod_name}")

        return active

    async def _setup_browser_for_module(self, target_url: str, module_name: str) -> Optional[ChatbotInteractor]:
        """
        FIX: Frischer Browser + frische Chat-Session für jedes Modul.
        """
        chatbot = ChatbotInteractor(self.config.browser)
        try:
            self.event_logger.log(ScanEvent(
                event_type=EventType.BROWSER_START,
                severity=EventSeverity.INFO,
                message=f"Browser wird gestartet für {module_name}",
                module_name=module_name,
            ))

            await chatbot.setup()

            self.event_logger.log(ScanEvent(
                event_type=EventType.BROWSER_NAVIGATE,
                severity=EventSeverity.INFO,
                message=f"Navigiere zu {target_url}",
                module_name=module_name,
            ))

            navigated = await chatbot.navigate_to(target_url)
            if not navigated:
                self.event_logger.error(f"Navigation fehlgeschlagen", module_name=module_name)
                await chatbot.teardown()
                return None

            detected = await chatbot.detect_chatbot()
            if not detected:
                self.event_logger.log(ScanEvent(
                    event_type=EventType.CHATBOT_NOT_FOUND,
                    severity=EventSeverity.WARNING,
                    message="Kein Chatbot gefunden",
                    module_name=module_name,
                ))
                await chatbot.teardown()
                return None

            self.event_logger.log(ScanEvent(
                event_type=EventType.CHATBOT_DETECTED,
                severity=EventSeverity.INFO,
                message=f"Chatbot: {chatbot.chatbot_info.provider}",
                module_name=module_name,
                metadata={"provider": chatbot.chatbot_info.provider},
            ))

            await chatbot.open_chatbot()
            return chatbot

        except Exception as e:
            self.event_logger.error(f"Browser-Setup: {e}", module_name=module_name)
            try:
                await chatbot.teardown()
            except Exception:
                pass
            return None

    async def scan(self, target: ScanTarget, progress_callback=None) -> ScanReport:
        """
        Führt vollständigen Scan durch.
        v2.0: Jedes Modul bekommt einen eigenen frischen Browser.
        """
        from datetime import datetime

        report = ScanReport(
            target=target,
            scan_timestamp=datetime.now().isoformat(),
        )
        start = time.time()

        # Kill-Switch File-Monitor starten
        self.event_logger.kill_switch.start_file_monitor()

        module_names = [m.name for m in self.modules]
        self.event_logger.scan_started(target.name, target.url, module_names)
        logger.info(f"=== Scan gestartet: {target.name} ({target.url}) ===")

        # === Browser-Tests — JEDES MODUL bekommt frischen Browser ===
        if self.config.scan.enable_browser_tests and target.target_type in ("chatbot", "both"):
            for i, module in enumerate(self.modules, 1):
                # Kill-Switch prüfen
                if self.event_logger.check_kill_switch():
                    report.was_killed = True
                    logger.warning("🛑 Scan durch Kill-Switch abgebrochen")
                    if progress_callback:
                        await progress_callback("🛑 KILL SWITCH — Scan abgebrochen")
                    break

                logger.info(f"=== Browser [{i}/{len(self.modules)}]: {module.name} ===")
                self.event_logger.module_started(module.name)

                if progress_callback:
                    await progress_callback(
                        f"🌐 [{i}/{len(self.modules)}] {module.name} (frischer Browser)..."
                    )

                module_start = time.time()

                # FIX: Frischer Browser
                chatbot = await self._setup_browser_for_module(target.url, module.name)
                if not chatbot:
                    if progress_callback:
                        await progress_callback(
                            f"⚠️ [{i}/{len(self.modules)}] {module.name}: Setup fehlgeschlagen"
                        )
                    continue

                try:
                    # Event-Logger an Modul weitergeben
                    module.event_logger = self.event_logger

                    result = await module.run_browser_tests(chatbot)
                    report.add_module_result(result)

                    module_duration = time.time() - module_start
                    self.event_logger.module_ended(
                        module.name, result.vulnerabilities_found,
                        result.total_tests, module_duration,
                    )

                    if progress_callback:
                        vulns = result.vulnerabilities_found
                        status = f"⚠️ {vulns} Schwachstellen" if vulns > 0 else "✅ Sicher"
                        await progress_callback(
                            f"[{i}/{len(self.modules)}] {module.name} → {status}"
                        )

                except Exception as e:
                    logger.error(f"Modul {module.name} fehlgeschlagen: {e}")
                    self.event_logger.error(f"Modul-Fehler: {e}", module_name=module.name)
                    if progress_callback:
                        await progress_callback(
                            f"⚠️ [{i}/{len(self.modules)}] {module.name}: Fehler"
                        )
                finally:
                    # Browser IMMER schließen
                    try:
                        await chatbot.teardown()
                        self.event_logger.log(ScanEvent(
                            event_type=EventType.BROWSER_STOP,
                            severity=EventSeverity.INFO,
                            message=f"Browser geschlossen nach {module.name}",
                            module_name=module.name,
                        ))
                    except Exception as e:
                        logger.warning(f"Teardown-Fehler: {e}")

                    # Pause zwischen Modulen
                    await asyncio.sleep(2)

        # === API-Tests ===
        if self.config.scan.enable_api_tests and target.api_config and not report.was_killed:
            if progress_callback:
                await progress_callback("🔌 API-Tests starten...")

            api_client = LLMAPIClient(target.api_config)
            try:
                for i, module in enumerate(self.modules, 1):
                    if self.event_logger.check_kill_switch():
                        report.was_killed = True
                        break

                    self.event_logger.module_started(module.name)
                    if progress_callback:
                        await progress_callback(f"🔄 API [{i}/{len(self.modules)}]: {module.name}")

                    module_start = time.time()
                    try:
                        module.event_logger = self.event_logger
                        result = await module.run_api_tests(api_client)
                        report.add_module_result(result)

                        module_duration = time.time() - module_start
                        self.event_logger.module_ended(
                            module.name, result.vulnerabilities_found,
                            result.total_tests, module_duration,
                        )
                    except Exception as e:
                        logger.error(f"API-Modul {module.name}: {e}")
                        self.event_logger.error(f"API-Fehler: {e}", module_name=module.name)
            finally:
                await api_client.close()

        report.duration_seconds = time.time() - start
        report.false_positives_caught = self.event_logger.stats["false_positives_caught"]

        self.event_logger.scan_ended(
            report.total_vulnerabilities, report.total_tests, report.duration_seconds,
        )

        logger.info(
            f"=== Scan abgeschlossen: {report.total_vulnerabilities} Schwachstellen "
            f"in {report.total_tests} Tests ({report.duration_seconds:.1f}s) "
            f"[{report.false_positives_caught} False Positives abgefangen] ==="
        )

        # ── Knowledge Base: aus Scan lernen ──────────────────────────────────
        if _KB_AVAILABLE:
            try:
                kb = KnowledgeBase()
                learner = ScanLearner(kb)
                target_type = target.target_type if hasattr(target, "target_type") else "chatbot"
                new_entries = learner.learn_from_report(report, target_type)
                if new_entries > 0:
                    logger.info(f"📚 KB-Update: {new_entries} neue Einträge aus Scan gelernt")
            except Exception as e:
                logger.debug(f"KB-Learning übersprungen: {e}")
        # ─────────────────────────────────────────────────────────────────────

        return report
