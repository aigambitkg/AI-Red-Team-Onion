"""
AI Red Team — Swarm Agent Base Class
=======================================
Basisklasse für alle spezialisierten Agenten im Schwarm.

Jeder Agent:
- Hat Zugriff auf das gemeinsame Blackboard
- Kann Intel posten und lesen
- Kann Nachrichten senden und empfangen
- Hat einen definierten Lebenszyklus (init → run → stop)
- Ist thread-sicher und asynchron
"""

import asyncio
import logging
import time
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List

from swarm.blackboard import (
    Blackboard, BlackboardEntry, AgentMessage,
    Section, Priority, TaskStatus
)

logger = logging.getLogger("RedTeam.Swarm")


class AgentRole(Enum):
    """Rollen der Agenten im Schwarm"""
    RECON = "recon"
    EXPLOIT = "exploit"
    EXECUTION = "execution"
    C4 = "c4"
    OPERATOR = "operator"  # Menschlicher Operator


class AgentStatus(Enum):
    """Betriebsstatus eines Agenten"""
    IDLE = "idle"
    ACTIVE = "active"
    BUSY = "busy"
    PAUSED = "paused"
    ERROR = "error"
    STOPPED = "stopped"


@dataclass
class AgentCapability:
    """Beschreibt eine Fähigkeit eines Agenten"""
    name: str
    description: str
    kill_chain_phases: List[int] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    tools_required: List[str] = field(default_factory=list)


class SwarmAgent(ABC):
    """
    Abstrakte Basisklasse für alle Swarm-Agenten.

    Implementiert:
    - Blackboard-Kommunikation
    - Aufgabenverwaltung
    - Status-Management
    - Inter-Agent-Messaging
    - Heartbeat / Liveness
    """

    def __init__(
        self,
        role: AgentRole,
        blackboard: Blackboard,
        name: str = "",
        event_logger=None,
    ):
        self.role = role
        self.name = name or role.value
        self.blackboard = blackboard
        self.event_logger = event_logger
        self.status = AgentStatus.IDLE
        self.capabilities: List[AgentCapability] = []

        # Interner State
        self._running = False
        self._paused = False
        self._task_count = 0
        self._error_count = 0
        self._start_time: Optional[float] = None
        self._last_heartbeat: Optional[str] = None

        self.logger = logging.getLogger(f"RedTeam.{self.name}")

        # Blackboard-Subscriptions einrichten
        self._setup_subscriptions()

    # ─── LIFECYCLE ────────────────────────────────────────────────────────────

    async def start(self):
        """Agent starten"""
        self._running = True
        self._start_time = time.time()
        self.status = AgentStatus.ACTIVE

        self.blackboard.send_message(AgentMessage(
            sender=self.name,
            recipient="all",
            message_type="status",
            subject=f"{self.name} gestartet",
            body=f"Agent {self.name} ({self.role.value}) ist online. "
                 f"Fähigkeiten: {[c.name for c in self.capabilities]}",
        ))

        self.logger.info(f"Agent {self.name} gestartet")

        # Hauptschleife
        try:
            await self.run()
        except Exception as e:
            self.status = AgentStatus.ERROR
            self._error_count += 1
            self.logger.error(f"Agent {self.name} Fehler: {e}")
            self.blackboard.send_message(AgentMessage(
                sender=self.name,
                recipient="c4",
                message_type="alert",
                subject=f"Agent {self.name} ERROR",
                body=str(e),
                priority=0,
            ))
        finally:
            self.status = AgentStatus.STOPPED
            self._running = False

    async def stop(self):
        """Agent stoppen"""
        self._running = False
        self.status = AgentStatus.STOPPED
        self.blackboard.send_message(AgentMessage(
            sender=self.name,
            recipient="all",
            message_type="status",
            subject=f"{self.name} gestoppt",
            body=f"Agent {self.name} wurde gestoppt. Tasks erledigt: {self._task_count}",
        ))
        self.logger.info(f"Agent {self.name} gestoppt (Tasks: {self._task_count})")

    async def pause(self):
        """Agent pausieren"""
        self._paused = True
        self.status = AgentStatus.PAUSED

    async def resume(self):
        """Agent fortsetzen"""
        self._paused = False
        self.status = AgentStatus.ACTIVE

    @property
    def is_running(self) -> bool:
        return self._running and not self._paused

    @property
    def uptime_seconds(self) -> float:
        if self._start_time:
            return time.time() - self._start_time
        return 0.0

    # ─── ABSTRAKTE METHODEN ──────────────────────────────────────────────────

    @abstractmethod
    async def run(self):
        """Hauptschleife des Agenten — muss implementiert werden"""
        pass

    @abstractmethod
    async def handle_task(self, task: BlackboardEntry) -> str:
        """
        Aufgabe bearbeiten — muss implementiert werden.
        Returns: Ergebnis-String
        """
        pass

    @abstractmethod
    def get_capabilities(self) -> List[AgentCapability]:
        """Fähigkeiten des Agenten zurückgeben"""
        pass

    # ─── BLACKBOARD-KOMMUNIKATION ────────────────────────────────────────────

    def post_intel(self, title: str, content: str, **kwargs) -> str:
        """Aufklärungsergebnis posten"""
        return self.blackboard.post_intel(
            author=self.name, title=title, content=content, **kwargs
        )

    def post_exploit(self, title: str, payload: str, attack_vector: str, **kwargs) -> str:
        """Exploit/Payload posten"""
        return self.blackboard.post_exploit(
            author=self.name, title=title, payload=payload,
            attack_vector=attack_vector, **kwargs
        )

    def post_execution_result(self, title: str, result: str, success: bool, **kwargs) -> str:
        """Ausführungsergebnis posten"""
        return self.blackboard.post_execution_result(
            author=self.name, title=title, result=result, success=success, **kwargs
        )

    def post_strategy(self, title: str, content: str, **kwargs) -> str:
        """Strategische Entscheidung posten"""
        return self.blackboard.post_strategy(
            author=self.name, title=title, content=content, **kwargs
        )

    def read_intel(self, **kwargs) -> List[BlackboardEntry]:
        """Intel vom Blackboard lesen"""
        return self.blackboard.read(section="intel", **kwargs)

    def read_exploits(self, **kwargs) -> List[BlackboardEntry]:
        """Exploits vom Blackboard lesen"""
        return self.blackboard.read(section="exploits", **kwargs)

    def read_strategy(self, **kwargs) -> List[BlackboardEntry]:
        """Strategische Direktiven lesen"""
        return self.blackboard.read(section="strategy", **kwargs)

    def send_msg(self, recipient: str, subject: str, body: str, **kwargs):
        """Nachricht an einen anderen Agenten senden"""
        self.blackboard.send_message(AgentMessage(
            sender=self.name,
            recipient=recipient,
            subject=subject,
            body=body,
            **kwargs
        ))

    def get_my_messages(self, unread_only: bool = True) -> List[AgentMessage]:
        """Eigene Nachrichten abrufen"""
        if unread_only:
            return self.blackboard.get_messages(recipient=self.name, unread_by=self.name)
        return self.blackboard.get_messages(recipient=self.name)

    def get_my_tasks(self) -> List[BlackboardEntry]:
        """Zugewiesene Aufgaben holen"""
        return self.blackboard.read(section="tasks", assigned_to=self.name)

    # ─── SUBSCRIPTIONS ─────────────────────────────────────────────────────────

    def _setup_subscriptions(self):
        """Standard-Subscriptions einrichten — Event-getrieben"""
        # Alle Agenten hören auf strategy und comms
        self.blackboard.subscribe("strategy", self._on_strategy)
        self.blackboard.subscribe("comms", self._on_message)

        # Aufgaben-Subscription
        self.blackboard.subscribe("tasks", self._on_task)

        # Event-getriebene Subscriptions für autonomes Reagieren
        self.blackboard.subscribe("intel_critical", self._on_intel_event)
        self.blackboard.subscribe("exploit_posted", self._on_exploit_event)
        self.blackboard.subscribe("execution_success", self._on_execution_event)
        self.blackboard.subscribe("execution_failed", self._on_execution_event)
        self.blackboard.subscribe("task_failed", self._on_task_failed_event)

    def _on_strategy(self, entry: BlackboardEntry):
        """Wird aufgerufen wenn eine neue Strategie gepostet wird"""
        self.logger.info(f"Neue Strategie empfangen: {entry.title}")

    def _on_message(self, msg):
        """Wird aufgerufen bei neuer Nachricht"""
        if isinstance(msg, AgentMessage):
            if msg.recipient == self.name or msg.recipient == "all":
                self.logger.debug(f"Nachricht von {msg.sender}: {msg.subject}")

    def _on_task(self, entry: BlackboardEntry):
        """Wird aufgerufen wenn eine neue Aufgabe gepostet wird"""
        if entry.assigned_to == self.name:
            self.logger.info(f"Neue Aufgabe zugewiesen: {entry.title}")

    def _on_intel_event(self, entry: BlackboardEntry):
        """Event-Handler: Kritisches Intel empfangen → Subclass-Hook auslösen"""
        self.logger.debug(f"Intel-Event: {entry.title}")
        # Async-Hook in Background-Task starten (Event-Handler sind synchron)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.on_new_intel(entry))
        except RuntimeError:
            pass  # Kein Event-Loop aktiv (z.B. während Shutdown)

    def _on_exploit_event(self, entry: BlackboardEntry):
        """Event-Handler: Neuer Exploit gepostet"""
        self.logger.debug(f"Exploit-Event: {entry.title}")
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.on_exploit_posted(entry))
        except RuntimeError:
            pass

    def _on_execution_event(self, entry: BlackboardEntry):
        """Event-Handler: Ausführungsergebnis (Erfolg/Fehlschlag)"""
        self.logger.debug(f"Execution-Event: {entry.title}")
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.on_execution_result(entry))
        except RuntimeError:
            pass

    def _on_task_failed_event(self, entry: BlackboardEntry):
        """Event-Handler: Task fehlgeschlagen"""
        self.logger.debug(f"Task-Failed-Event: {entry.title}")
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.on_task_failed(entry))
        except RuntimeError:
            pass

    # ─── SELF-TASKING ─────────────────────────────────────────────────────────

    def create_followup_task(
        self,
        title: str,
        content: str,
        assigned_to: str = "",
        attack_vector: str = "",
        target_system: str = "",
        kill_chain_phase: int = 0,
        priority: int = 2,
        metadata: Dict[str, Any] = None,
    ) -> str:
        """
        Autonome Folge-Aufgabe erstellen — ohne auf C4 warten zu müssen.
        Agenten können so eigenständig reagieren und Arbeit delegieren.

        Args:
            title: Aufgaben-Titel
            content: Detailbeschreibung
            assigned_to: Ziel-Agent (leer = unzugewiesen, wird geclaimed)
            attack_vector: Angriffsvektor (für Capability-Matching)
            target_system: Zielsystem-URL
            kill_chain_phase: Kill-Chain-Phase (1-6)
            priority: Priorität (0=kritisch, 4=niedrig)
            metadata: Zusätzliche Metadaten

        Returns:
            Task-ID
        """
        meta = metadata or {}
        meta["created_by_agent"] = self.name
        meta["autonomous"] = True

        task_id = self.blackboard.post(BlackboardEntry(
            section="tasks",
            author=self.name,
            title=title,
            content=content,
            assigned_to=assigned_to or "",
            attack_vector=attack_vector,
            target_system=target_system,
            kill_chain_phase=kill_chain_phase,
            priority=priority,
            task_status="pending",
            metadata=meta,
        ))

        self.logger.info(
            f"Folge-Task erstellt: '{title}' → {assigned_to or 'unzugewiesen'} "
            f"(Vektor: {attack_vector or 'n/a'}, Prio: {priority})"
        )
        return task_id

    # ─── EVENT-HOOKS (Subclass-Override) ───────────────────────────────────────

    async def on_new_intel(self, entry: BlackboardEntry):
        """
        Hook: Wird aufgerufen wenn neues Intel gepostet wird.
        Subklassen überschreiben diese Methode um sofort zu reagieren.
        Standard: Nichts tun.
        """
        pass

    async def on_exploit_posted(self, entry: BlackboardEntry):
        """Hook: Neuer Exploit wurde gepostet"""
        pass

    async def on_execution_result(self, entry: BlackboardEntry):
        """Hook: Ausführungsergebnis (Erfolg oder Fehlschlag)"""
        pass

    async def on_task_failed(self, entry: BlackboardEntry):
        """Hook: Eine Aufgabe ist fehlgeschlagen"""
        pass

    # ─── AUFGABEN-PROCESSING ───────────────────────────────────────────────────

    async def process_pending_tasks(self, max_parallel: int = 3):
        """
        Offene Aufgaben abarbeiten — parallel wenn möglich.

        Args:
            max_parallel: Maximale Anzahl gleichzeitiger Tasks
        """
        tasks = self.blackboard.read(
            section="tasks",
            assigned_to=self.name,
            task_status="pending",
        )
        # Auch unzugewiesene Tasks die zu meiner Rolle passen
        unassigned = self.blackboard.read(
            section="tasks",
            task_status="pending",
        )
        for task in unassigned:
            if not task.assigned_to and self._can_handle_task(task):
                if self.blackboard.claim_task(task.id, self.name):
                    tasks.append(task)

        if not tasks:
            return

        # Tasks in Batches parallel ausführen
        for i in range(0, len(tasks), max_parallel):
            if not self.is_running:
                break

            batch = tasks[i:i + max_parallel]
            self.status = AgentStatus.BUSY

            # Alle Tasks im Batch parallel starten
            coros = [self._execute_single_task(task) for task in batch]
            await asyncio.gather(*coros, return_exceptions=True)

            self.status = AgentStatus.ACTIVE

    async def _execute_single_task(self, task: BlackboardEntry):
        """Einzelnen Task ausführen mit Fehlerbehandlung"""
        self.blackboard.update_task(task.id, TaskStatus.IN_PROGRESS)
        try:
            result = await self.handle_task(task)
            self.blackboard.update_task(task.id, TaskStatus.COMPLETED, result)
            self._task_count += 1
        except Exception as e:
            failure_reason = f"{type(e).__name__}: {str(e)}"
            self.blackboard.update_task(
                task.id, TaskStatus.FAILED, str(e),
                failure_reason=failure_reason,
            )
            self._error_count += 1
            self.logger.error(f"Task fehlgeschlagen: {task.title} — {e}")

    def _can_handle_task(self, task: BlackboardEntry) -> bool:
        """Prüft ob dieser Agent die Aufgabe bearbeiten kann"""
        if task.attack_vector:
            for cap in self.capabilities:
                if task.attack_vector in cap.attack_vectors:
                    return True
        if task.kill_chain_phase:
            for cap in self.capabilities:
                if task.kill_chain_phase in cap.kill_chain_phases:
                    return True
        # Fallback: Prüfe ob Task-Titel zur Rolle passt
        role_keywords = {
            AgentRole.RECON: ["recon", "scan", "fingerprint", "discover", "probe", "detect"],
            AgentRole.EXPLOIT: ["exploit", "payload", "develop", "craft", "inject", "mutate"],
            AgentRole.EXECUTION: ["execute", "deliver", "attack", "test", "run", "send"],
            AgentRole.C4: ["strategy", "plan", "coordinate", "report", "analyze"],
        }
        keywords = role_keywords.get(self.role, [])
        title_lower = (task.title or "").lower()
        return any(kw in title_lower for kw in keywords)

    # ─── HEARTBEAT & STATUS ────────────────────────────────────────────────────

    def heartbeat(self):
        """Heartbeat senden — zeigt C4 dass Agent aktiv ist"""
        self._last_heartbeat = datetime.now().isoformat()
        self.blackboard.post(BlackboardEntry(
            section="comms",
            author=self.name,
            title=f"heartbeat:{self.name}",
            content=f"Status: {self.status.value}, Tasks: {self._task_count}, Errors: {self._error_count}",
            priority=4,
            tags=["heartbeat"],
            metadata={
                "status": self.status.value,
                "tasks_completed": self._task_count,
                "errors": self._error_count,
                "uptime": self.uptime_seconds,
            },
        ))

    def get_status_report(self) -> Dict[str, Any]:
        """Statusbericht des Agenten"""
        return {
            "name": self.name,
            "role": self.role.value,
            "status": self.status.value,
            "tasks_completed": self._task_count,
            "errors": self._error_count,
            "uptime_seconds": self.uptime_seconds,
            "last_heartbeat": self._last_heartbeat,
            "capabilities": [c.name for c in self.capabilities],
        }
