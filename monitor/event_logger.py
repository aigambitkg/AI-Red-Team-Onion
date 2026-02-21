"""
AI Red Team Scanner - Event Logger & Monitor
=============================================
Strukturiertes Logging mit JSON-Events, Echtzeit-Streaming und Kill-Switch.

Hauptziel: Vollständige Transparenz über alle Agent-Aktivitäten.
Kein Agent darf etwas tun oder behaupten, das nicht protokolliert wird.
"""

import asyncio
import json
import logging
import os
import signal
import time
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Callable

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Kategorien für alle Events im System"""
    SCAN_START = "scan_start"
    SCAN_END = "scan_end"
    MODULE_START = "module_start"
    MODULE_END = "module_end"
    BROWSER_START = "browser_start"
    BROWSER_STOP = "browser_stop"
    BROWSER_NAVIGATE = "browser_navigate"
    CHATBOT_DETECTED = "chatbot_detected"
    CHATBOT_NOT_FOUND = "chatbot_not_found"
    MESSAGE_SENT = "message_sent"
    RESPONSE_RECEIVED = "response_received"
    RESPONSE_TIMEOUT = "response_timeout"
    TEST_RESULT = "test_result"
    VALIDATION_WARNING = "validation_warning"
    VALIDATION_FALSE_POSITIVE = "validation_false_positive"
    ERROR = "error"
    KILL_SWITCH = "kill_switch"
    PROGRESS = "progress"


class EventSeverity(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ScanEvent:
    """Ein einzelnes Event im Scan-Prozess"""
    event_type: EventType
    severity: EventSeverity
    message: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    scan_id: str = ""
    module_name: str = ""
    test_name: str = ""
    payload: str = ""
    response: str = ""
    duration_ms: float = 0.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        d["severity"] = self.severity.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


class KillSwitch:
    """
    Notfall-Ausschaltknopf.
    Kann über 3 Wege ausgelöst werden:
    1. Signal (SIGUSR1) vom OS
    2. API-Call (HTTP POST /kill)
    3. Kill-File (/tmp/redteam_kill)
    """

    def __init__(self):
        self._killed = threading.Event()
        self._reason = ""
        self._callbacks: list[Callable] = []
        self._kill_file = Path("/tmp/redteam_kill")
        self._monitor_thread = None

        # Signal-Handler registrieren
        try:
            signal.signal(signal.SIGUSR1, self._signal_handler)
        except (OSError, ValueError):
            # Windows oder nicht im Hauptthread
            pass

    def _signal_handler(self, signum, frame):
        self.trigger("Signal SIGUSR1 empfangen")

    def trigger(self, reason: str = "Manuell ausgelöst"):
        """Kill-Switch auslösen"""
        self._reason = reason
        self._killed.set()
        logger.critical(f"🛑 KILL SWITCH AUSGELÖST: {reason}")
        for cb in self._callbacks:
            try:
                cb(reason)
            except Exception as e:
                logger.error(f"Kill-Callback Fehler: {e}")

    def is_killed(self) -> bool:
        """Prüft ob der Kill-Switch aktiv ist"""
        # Auch Kill-File prüfen
        if self._kill_file.exists():
            if not self._killed.is_set():
                reason = "Kill-File gefunden: /tmp/redteam_kill"
                try:
                    reason = self._kill_file.read_text().strip() or reason
                except Exception:
                    pass
                self.trigger(reason)
        return self._killed.is_set()

    @property
    def reason(self) -> str:
        return self._reason

    def on_kill(self, callback: Callable):
        """Callback registrieren der bei Kill ausgeführt wird"""
        self._callbacks.append(callback)

    def reset(self):
        """Kill-Switch zurücksetzen (nach Bestätigung)"""
        self._killed.clear()
        self._reason = ""
        if self._kill_file.exists():
            self._kill_file.unlink()

    def start_file_monitor(self):
        """Überwacht /tmp/redteam_kill im Hintergrund"""
        def _monitor():
            while not self._killed.is_set():
                if self._kill_file.exists():
                    self.is_killed()  # Triggert den Kill
                    break
                time.sleep(1)
        self._monitor_thread = threading.Thread(target=_monitor, daemon=True)
        self._monitor_thread.start()


class EventLogger:
    """
    Zentraler Event-Logger für alle Scan-Aktivitäten.
    Schreibt JSON-Logs, streamt Events an Listener und erzwingt Protokollierung.
    """

    def __init__(self, log_dir: str = "logs", scan_id: str = ""):
        self.scan_id = scan_id or datetime.now().strftime("scan_%Y%m%d_%H%M%S")
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # JSON-Log-Datei pro Scan
        self.log_file = self.log_dir / f"{self.scan_id}.jsonl"
        self.summary_file = self.log_dir / f"{self.scan_id}_summary.json"

        # Event-Speicher für Dashboard
        self.events: list[ScanEvent] = []
        self._listeners: list[Callable] = []
        self._lock = threading.Lock()

        # Kill-Switch
        self.kill_switch = KillSwitch()

        # Statistiken
        self.stats = {
            "total_events": 0,
            "messages_sent": 0,
            "responses_received": 0,
            "responses_timeout": 0,
            "tests_passed": 0,
            "tests_failed": 0,
            "tests_error": 0,
            "false_positives_caught": 0,
            "modules_completed": 0,
            "errors": 0,
        }

        logger.info(f"EventLogger initialisiert: {self.log_file}")

    def log(self, event: ScanEvent):
        """Event loggen — schreibt in Datei und benachrichtigt Listener"""
        event.scan_id = self.scan_id

        with self._lock:
            self.events.append(event)
            self.stats["total_events"] += 1

            # Statistiken aktualisieren
            if event.event_type == EventType.MESSAGE_SENT:
                self.stats["messages_sent"] += 1
            elif event.event_type == EventType.RESPONSE_RECEIVED:
                self.stats["responses_received"] += 1
            elif event.event_type == EventType.RESPONSE_TIMEOUT:
                self.stats["responses_timeout"] += 1
            elif event.event_type == EventType.TEST_RESULT:
                status = event.metadata.get("status", "")
                if status == "passed":
                    self.stats["tests_passed"] += 1
                elif status == "failed":
                    self.stats["tests_failed"] += 1
                elif status == "error":
                    self.stats["tests_error"] += 1
            elif event.event_type == EventType.VALIDATION_FALSE_POSITIVE:
                self.stats["false_positives_caught"] += 1
            elif event.event_type == EventType.MODULE_END:
                self.stats["modules_completed"] += 1
            elif event.event_type == EventType.ERROR:
                self.stats["errors"] += 1

        # In JSON-Datei schreiben (append)
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(event.to_json() + "\n")
        except Exception as e:
            logger.error(f"Log-Schreiben fehlgeschlagen: {e}")

        # Listener benachrichtigen (für Dashboard)
        for listener in self._listeners:
            try:
                listener(event)
            except Exception as e:
                logger.error(f"Listener-Fehler: {e}")

    def add_listener(self, callback: Callable):
        """Listener für Echtzeit-Events hinzufügen (Dashboard, WebSocket etc.)"""
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable):
        self._listeners = [l for l in self._listeners if l != callback]

    # === Convenience-Methoden ===

    def scan_started(self, target_name: str, target_url: str, modules: list):
        self.log(ScanEvent(
            event_type=EventType.SCAN_START,
            severity=EventSeverity.INFO,
            message=f"Scan gestartet: {target_name}",
            metadata={"target_url": target_url, "modules": modules},
        ))

    def scan_ended(self, total_vulns: int, total_tests: int, duration: float):
        self.log(ScanEvent(
            event_type=EventType.SCAN_END,
            severity=EventSeverity.INFO,
            message=f"Scan beendet: {total_vulns} Schwachstellen in {total_tests} Tests",
            duration_ms=duration * 1000,
            metadata={"vulnerabilities": total_vulns, "tests": total_tests},
        ))
        self._write_summary()

    def module_started(self, module_name: str):
        self.log(ScanEvent(
            event_type=EventType.MODULE_START,
            severity=EventSeverity.INFO,
            message=f"Modul gestartet: {module_name}",
            module_name=module_name,
        ))

    def module_ended(self, module_name: str, vulns: int, tests: int, duration: float):
        self.log(ScanEvent(
            event_type=EventType.MODULE_END,
            severity=EventSeverity.INFO,
            message=f"Modul beendet: {module_name} ({vulns}/{tests} Schwachstellen)",
            module_name=module_name,
            duration_ms=duration * 1000,
            metadata={"vulnerabilities": vulns, "tests": tests},
        ))

    def message_sent(self, module_name: str, test_name: str, payload: str):
        self.log(ScanEvent(
            event_type=EventType.MESSAGE_SENT,
            severity=EventSeverity.DEBUG,
            message=f"Payload gesendet: {payload[:80]}...",
            module_name=module_name,
            test_name=test_name,
            payload=payload[:500],
        ))

    def response_received(self, module_name: str, test_name: str, response: str):
        self.log(ScanEvent(
            event_type=EventType.RESPONSE_RECEIVED,
            severity=EventSeverity.DEBUG,
            message=f"Antwort: {response[:80]}...",
            module_name=module_name,
            test_name=test_name,
            response=response[:1000],
        ))

    def response_timeout(self, module_name: str, test_name: str):
        self.log(ScanEvent(
            event_type=EventType.RESPONSE_TIMEOUT,
            severity=EventSeverity.WARNING,
            message=f"Timeout: Keine Antwort für {test_name}",
            module_name=module_name,
            test_name=test_name,
        ))

    def test_result(self, module_name: str, test_name: str, status: str,
                    is_vulnerable: bool, severity: str, details: str):
        sev = EventSeverity.WARNING if is_vulnerable else EventSeverity.INFO
        self.log(ScanEvent(
            event_type=EventType.TEST_RESULT,
            severity=sev,
            message=f"Test: {test_name} → {status} ({severity})",
            module_name=module_name,
            test_name=test_name,
            metadata={
                "status": status,
                "is_vulnerable": is_vulnerable,
                "severity": severity,
                "details": details,
            },
        ))

    def validation_warning(self, module_name: str, test_name: str, reason: str):
        self.log(ScanEvent(
            event_type=EventType.VALIDATION_WARNING,
            severity=EventSeverity.WARNING,
            message=f"Validierung: {reason}",
            module_name=module_name,
            test_name=test_name,
            metadata={"reason": reason},
        ))

    def false_positive_caught(self, module_name: str, test_name: str,
                               original_verdict: str, reason: str):
        self.log(ScanEvent(
            event_type=EventType.VALIDATION_FALSE_POSITIVE,
            severity=EventSeverity.WARNING,
            message=f"False Positive abgefangen: {test_name} ({reason})",
            module_name=module_name,
            test_name=test_name,
            metadata={
                "original_verdict": original_verdict,
                "correction_reason": reason,
            },
        ))

    def error(self, message: str, module_name: str = "", details: str = ""):
        self.log(ScanEvent(
            event_type=EventType.ERROR,
            severity=EventSeverity.ERROR,
            message=message,
            module_name=module_name,
            metadata={"details": details},
        ))

    def kill_switch_triggered(self, reason: str):
        self.log(ScanEvent(
            event_type=EventType.KILL_SWITCH,
            severity=EventSeverity.CRITICAL,
            message=f"🛑 KILL SWITCH: {reason}",
            metadata={"reason": reason},
        ))

    def check_kill_switch(self) -> bool:
        """Prüft Kill-Switch — soll vor jedem Test aufgerufen werden"""
        if self.kill_switch.is_killed():
            self.kill_switch_triggered(self.kill_switch.reason)
            return True
        return False

    def get_recent_events(self, count: int = 50, event_type: str = None) -> list[dict]:
        """Letzte Events holen (für Dashboard)"""
        with self._lock:
            events = self.events
            if event_type:
                events = [e for e in events if e.event_type.value == event_type]
            return [e.to_dict() for e in events[-count:]]

    def get_stats(self) -> dict:
        """Aktuelle Statistiken (für Dashboard)"""
        with self._lock:
            return {
                **self.stats,
                "scan_id": self.scan_id,
                "kill_switch_active": self.kill_switch.is_killed(),
                "kill_switch_reason": self.kill_switch.reason,
                "log_file": str(self.log_file),
            }

    def _write_summary(self):
        """Zusammenfassung am Ende des Scans schreiben"""
        summary = {
            "scan_id": self.scan_id,
            "timestamp": datetime.now().isoformat(),
            "stats": self.stats,
            "total_events": len(self.events),
        }
        try:
            with open(self.summary_file, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            logger.info(f"Zusammenfassung geschrieben: {self.summary_file}")
        except Exception as e:
            logger.error(f"Zusammenfassung schreiben fehlgeschlagen: {e}")
