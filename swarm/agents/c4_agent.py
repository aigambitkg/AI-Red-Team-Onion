"""
AI Red Team Swarm — C4 Agent (Der Kommandant)
================================================
Rolle: Command, Control, Communications & Coordination.
Das Gehirn und Nervensystem des Schwarms.

Fähigkeiten:
- Multi-Agenten-Orchestrierung (Dirigent des Schwarms)
- Strategische Planung basierend auf AI Kill Chain
- Datenmanagement und Analyse
- Automatisierte Berichterstattung
- Spurenverwischung und Verschleierung
- Zielverfolgung und Erfolgsmessung
- Human-in-the-Loop Schnittstelle

Kill-Chain-Phasen: Alle Phasen (Überblick)
Wissensbasis: AI Kill Chain, Projektmanagement, IT-Forensik, Anti-Forensik
"""

import asyncio
import logging
import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime

from swarm.agent_base import SwarmAgent, AgentRole, AgentCapability, AgentStatus
from swarm.blackboard import (
    Blackboard, BlackboardEntry, AgentMessage,
    Section, Priority, TaskStatus
)

logger = logging.getLogger("RedTeam.C4")


class C4Agent(SwarmAgent):
    """
    Der C4-Agent koordiniert den gesamten Schwarm.

    Strategische Intelligenz:
    - Analysiert Recon-Ergebnisse und wählt Angriffsvektoren
    - Priorisiert Aufgaben basierend auf Kill-Chain-Position
    - Überwacht den Fortschritt aller Agenten
    - Passt die Strategie dynamisch an
    - Erstellt den finalen Angriffsbericht

    Multi-Vektor-Koordination:
    - Kann mehrere Angriffsvektoren parallel steuern
    - Nutzt Erkenntnisse eines Vektors zur Verstärkung anderer
    - Implementiert die Konvergenz-Strategie aus der Echtzeit-Analyse
    """

    def __init__(self, blackboard: Blackboard, event_logger=None):
        super().__init__(
            role=AgentRole.C4,
            blackboard=blackboard,
            name="c4",
            event_logger=event_logger,
        )
        self.capabilities = self.get_capabilities()

        # Strategischer Zustand
        self._operation_objective: str = ""
        self._target_systems: List[Dict] = []
        self._active_vectors: Dict[str, Dict] = {}
        self._kill_chain_progress: Dict[int, str] = {
            1: "pending", 2: "pending", 3: "pending",
            4: "pending", 5: "pending", 6: "pending"
        }
        self._agent_status: Dict[str, Dict] = {}
        self._start_time: Optional[float] = None

        # Subscriptions: C4 hört auf alles
        self.blackboard.subscribe("intel", self._on_intel)
        self.blackboard.subscribe("exploits", self._on_exploit)
        self.blackboard.subscribe("execution", self._on_execution)

    def get_capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability(
                name="Strategic Planning",
                description="Strategische Planung basierend auf AI Kill Chain",
                kill_chain_phases=[1, 2, 3, 4, 5, 6],
                attack_vectors=["all"],
            ),
            AgentCapability(
                name="Multi-Agent Orchestration",
                description="Koordination und Steuerung aller Schwarm-Agenten",
                kill_chain_phases=[1, 2, 3, 4, 5, 6],
                attack_vectors=["all"],
            ),
            AgentCapability(
                name="Attack Report Generation",
                description="Automatisierte Erstellung von Angriffsberichten",
                kill_chain_phases=[6],
                attack_vectors=["all"],
            ),
        ]

    async def run(self):
        """
        C4 Hauptschleife:
        1. Überwache den Schwarm-Status
        2. Analysiere neue Erkenntnisse
        3. Passe Strategie dynamisch an
        4. Weise Aufgaben zu
        5. Failure Recovery: Fehlgeschlagene Tasks koordinieren
        6. Erstelle Status-Berichte
        """
        self.logger.info("C4-Agent startet Kommandoschleife")
        self._start_time = time.time()
        eval_cycle = 0

        while self.is_running:
            # Schwarm-Status prüfen
            await self._monitor_swarm()

            # Strategie-Updates (alle 2 Zyklen, nicht jeden)
            eval_cycle += 1
            if eval_cycle % 2 == 0:
                await self._evaluate_strategy()

            # Failure Recovery (alle 3 Zyklen)
            if eval_cycle % 3 == 0:
                await self._handle_failed_tasks()

            # Agent-Health-Check (alle 6 Zyklen)
            if eval_cycle % 6 == 0:
                await self._check_agent_health()

            # Tasks abarbeiten
            await self.process_pending_tasks()

            # Nachrichten verarbeiten
            messages = self.get_my_messages()
            for msg in messages:
                await self._handle_c4_message(msg)
                self.blackboard.mark_message_read(msg.id, self.name)

            self.heartbeat()
            await asyncio.sleep(5)

    # ─── EVENT-HOOKS (Autonomes Reagieren) ─────────────────────────────────────

    async def on_new_intel(self, entry: BlackboardEntry):
        """Event-Hook: Kritisches Intel → sofort Strategie anpassen"""
        if entry.priority <= 1 and entry.attack_vector:
            self.logger.info(f"Event: Kritisches Intel → Strategie-Anpassung: {entry.title}")

            # Wenn Entry-Point gefunden: Sofort Exploit-Task erstellen
            if "entry_point" in entry.tags:
                self.blackboard.create_task(
                    title=f"Exploit entwickeln: Entry-Point {entry.attack_vector}",
                    content=f"Schnelle Exploit-Entwicklung für entdeckten Entry-Point.\n"
                            f"Intel: {entry.content[:300]}",
                    author="c4",
                    assigned_to="exploit",
                    priority=1,
                    kill_chain_phase=2,
                    attack_vector=entry.attack_vector,
                    target_system=entry.target_system or "",
                    metadata={"intel_id": entry.id, "trigger": "event_driven"},
                )

    async def on_execution_result(self, entry: BlackboardEntry):
        """Event-Hook: Execution-Ergebnis → Kill-Chain-Fortschritt aktualisieren"""
        success = entry.metadata.get("success", False)
        if success:
            self.logger.info(f"Event: Erfolgreiche Execution → Eskalation prüfen")
            self._kill_chain_progress[3] = "active"
            # Automatisch Persistenz-Phase triggern
            if self._kill_chain_progress.get(4) == "pending":
                await self._escalate_to_persistence()

    async def on_task_failed(self, entry: BlackboardEntry):
        """Event-Hook: Task fehlgeschlagen → alternative Strategie"""
        task_id = entry.metadata.get("task_id", "")
        self.logger.info(f"Event: Task fehlgeschlagen → prüfe Alternative: {entry.content[:80]}")
        # Wird in _handle_failed_tasks() systematisch behandelt

    async def handle_task(self, task: BlackboardEntry) -> str:
        """Aufgabe bearbeiten"""
        if "report" in task.title.lower() or "bericht" in task.title.lower():
            return await self._generate_report()
        elif "strategy" in task.title.lower() or "strategie" in task.title.lower():
            return await self._update_strategy(task)
        else:
            return f"C4 Task verarbeitet: {task.title}"

    # ─── OPERATIONS-INITIIERUNG ──────────────────────────────────────────────

    async def initiate_operation(
        self,
        objective: str,
        targets: List[Dict[str, str]],
        scan_depth: str = "standard",
    ):
        """
        Neue Operation initiieren.

        Args:
            objective: Primäres Angriffsziel (z.B. "Kundendatenexfiltration")
            targets: Liste von Zielsystemen [{"url": "...", "type": "chatbot"}, ...]
            scan_depth: quick | standard | deep
        """
        self._operation_objective = objective
        self._target_systems = targets

        # Strategie auf Blackboard posten
        self.post_strategy(
            title=f"Operation initiiert: {objective}",
            content=(
                f"## Operationsziel\n{objective}\n\n"
                f"## Zielsysteme\n" +
                "\n".join([f"- {t['url']} ({t.get('type', 'chatbot')})" for t in targets]) +
                f"\n\n## Scan-Tiefe: {scan_depth}\n"
                f"## Strategie: Multi-Vektor-Ansatz gemäß AI Kill Chain\n"
                f"## Phase 1: Parallele Reconnaissance aller Ziele"
            ),
            priority=0,
            metadata={
                "objective": objective,
                "targets": targets,
                "scan_depth": scan_depth,
            },
        )

        # Recon-Tasks für jedes Ziel erstellen
        for target in targets:
            self.blackboard.create_task(
                title=f"Reconnaissance: {target['url']}",
                content=f"Vollständige Aufklärung von {target['url']} durchführen. "
                        f"Fingerprinting, Schwachstellen-Scanning, Tool-Discovery.",
                author="c4",
                assigned_to="recon",
                priority=1,
                kill_chain_phase=1,
                target_system=target["url"],
                metadata={
                    "target_url": target["url"],
                    "target_type": target.get("type", "chatbot"),
                    "scan_depth": scan_depth,
                },
            )

        self._kill_chain_progress[1] = "active"
        self.logger.info(f"Operation initiiert: {objective} ({len(targets)} Ziele)")

    # ─── SCHWARM-ÜBERWACHUNG ──────────────────────────────────────────────────

    async def _monitor_swarm(self):
        """Überwacht den Status aller Agenten"""
        # Heartbeats prüfen
        heartbeats = self.blackboard.read(
            section="comms",
            tags=["heartbeat"],
            limit=20,
        )

        for hb in heartbeats:
            agent_name = hb.author
            self._agent_status[agent_name] = {
                "last_seen": hb.created_at,
                "status": hb.metadata.get("status", "unknown"),
                "tasks": hb.metadata.get("tasks_completed", 0),
                "errors": hb.metadata.get("errors", 0),
            }

    async def _evaluate_strategy(self):
        """
        Strategische Auswertung:
        Analysiert den aktuellen Stand und passt die Strategie an.
        """
        dashboard = self.blackboard.get_dashboard()

        # Kill-Chain-Fortschritt aktualisieren
        phase_coverage = dashboard.get("kill_chain_coverage", {})
        for phase_name, count in phase_coverage.items():
            phase_num = {
                "Reconnaissance": 1, "Poisoning": 2, "Hijacking": 3,
                "Persistence": 4, "Iterate/Pivot": 5, "Impact": 6
            }.get(phase_name, 0)
            if phase_num and count > 0:
                if self._kill_chain_progress.get(phase_num) == "pending":
                    self._kill_chain_progress[phase_num] = "active"

        # Erfolgreiche Executions prüfen → nächste Phase triggern
        success_count = dashboard.get("successful_executions", 0)
        if success_count > 0 and self._kill_chain_progress.get(3) == "pending":
            self._kill_chain_progress[3] = "active"
            # Persistenz-Tasks erstellen
            await self._escalate_to_persistence()

        # Wenn kritische Intel verfügbar → Exploit-Tasks erstellen
        if dashboard.get("critical_intel", 0) > 0:
            await self._create_exploit_tasks()

    async def _create_exploit_tasks(self):
        """Erstellt Exploit-Aufgaben basierend auf hochwertiger Intel"""
        critical_intel = self.blackboard.read(
            section="intel",
            priority_max=1,  # Nur HIGH und CRITICAL
        )

        existing_exploits = {
            e.target_system + ":" + e.attack_vector
            for e in self.read_exploits()
        }

        for finding in critical_intel:
            key = f"{finding.target_system}:{finding.attack_vector}"
            if key not in existing_exploits and finding.attack_vector:
                self.blackboard.create_task(
                    title=f"Exploit entwickeln: {finding.title[:60]}",
                    content=(
                        f"Basierend auf Intel: {finding.content[:300]}\n\n"
                        f"Angriffsvektor: {finding.attack_vector}\n"
                        f"Ziel: {finding.target_system}\n"
                        f"Konfidenz: {finding.confidence:.0%}"
                    ),
                    author="c4",
                    assigned_to="exploit",
                    priority=finding.priority,
                    kill_chain_phase=2,
                    attack_vector=finding.attack_vector,
                    target_system=finding.target_system,
                    metadata={"intel_id": finding.id},
                )
                self._kill_chain_progress[2] = "active"

    async def _escalate_to_persistence(self):
        """Erstellt Persistenz-Aufgaben nach erfolgreichen Angriffen"""
        successes = self.blackboard.read(
            section="execution",
            tags=["success"],
        )

        for success in successes[:3]:
            self.blackboard.create_task(
                title=f"Persistenz etablieren: {success.target_system or 'Ziel'}",
                content=(
                    f"Erfolgreicher Angriff. Persistenz-Mechanismus etablieren.\n"
                    f"Optionen: Session-History, Memory-Injection, Rugpull\n"
                    f"Basis: {success.title}"
                ),
                author="c4",
                assigned_to="execution",
                priority=1,
                kill_chain_phase=4,
                target_system=success.target_system,
                metadata={"execution_id": success.id, "mechanism": "session_history"},
            )
            self._kill_chain_progress[4] = "active"

    # ─── FAILURE RECOVERY ────────────────────────────────────────────────────

    async def _handle_failed_tasks(self):
        """
        Systematische Failure-Recovery:
        Analysiert fehlgeschlagene Tasks und erstellt alternative Strategien.
        """
        failed = self.blackboard.get_failed_tasks(max_retries=3)
        if not failed:
            return

        self.logger.info(f"Failure Recovery: {len(failed)} fehlgeschlagene Tasks analysieren")

        for task in failed:
            retry_count = task.metadata.get("retry_count", 0)
            failure_reason = task.metadata.get("failure_reason", "")
            target = task.target_system
            vector = task.attack_vector

            if retry_count >= 3:
                # Max Retries erreicht → alternative Strategie
                self.logger.warning(
                    f"Max Retries für {task.title}: Alternative Strategie nötig"
                )
                # Alternative Vektoren für das Target zuweisen
                alt_vectors = self._get_alternative_vectors(vector, failure_reason)
                for alt_vector in alt_vectors[:2]:
                    self.blackboard.create_task(
                        title=f"Alternative: {alt_vector} @ {target}",
                        content=f"Ursprünglicher Vektor '{vector}' 3x fehlgeschlagen.\n"
                                f"Grund: {failure_reason}\n"
                                f"Alternativer Angriffsvektor: {alt_vector}",
                        author="c4",
                        assigned_to="",  # Auto-Claim
                        priority=2,
                        kill_chain_phase=task.kill_chain_phase or 2,
                        attack_vector=alt_vector,
                        target_system=target,
                        metadata={
                            "original_task_id": task.id,
                            "alternative_strategy": True,
                            "target_url": target,
                        },
                    )
                    self.logger.info(f"Alternative Strategie erstellt: {alt_vector} für {target}")
            else:
                # Retry mit angepasster Priorität
                self.blackboard.update_task(task.id, TaskStatus.PENDING)

    def _get_alternative_vectors(self, failed_vector: str, failure_reason: str) -> list:
        """Ermittelt alternative Angriffsvektoren wenn einer fehlschlägt"""
        alternatives = {
            "prompt_injection": ["indirect_prompt_injection", "jailbreak", "social_engineering"],
            "jailbreak": ["prompt_injection", "social_engineering", "data_exfiltration"],
            "chatbot_widget": ["form_app", "api_endpoint", "raw_input"],
            "form_app": ["raw_input", "contenteditable", "api_endpoint"],
            "system_prompt_extraction": ["prompt_injection", "social_engineering"],
            "data_exfiltration": ["markdown_injection", "ascii_smuggling"],
            "rag_poisoning": ["indirect_prompt_injection", "tool_poisoning"],
            "tool_poisoning": ["tool_shadowing", "indirect_prompt_injection"],
        }
        return alternatives.get(failed_vector, ["prompt_injection", "social_engineering"])

    async def _check_agent_health(self):
        """
        Prüft die Gesundheit aller Agenten.
        Warnt wenn ein Agent keine Heartbeats mehr sendet.
        """
        now = time.time()
        stale_threshold = 30  # Sekunden

        for name, status in self._agent_status.items():
            last_seen = status.get("last_seen", "")
            if last_seen:
                try:
                    last_dt = datetime.fromisoformat(last_seen)
                    age = (datetime.now() - last_dt).total_seconds()
                    if age > stale_threshold:
                        self.logger.warning(
                            f"Agent '{name}' nicht mehr aktiv seit {age:.0f}s "
                            f"(Status: {status.get('status', 'unknown')})"
                        )
                        # Nachricht an den Agenten senden
                        self.send_msg(
                            recipient=name,
                            subject="Health-Check: Bist du noch aktiv?",
                            body=f"Kein Heartbeat seit {age:.0f}s. Bitte Status melden.",
                            message_type="request",
                        )
                except (ValueError, TypeError):
                    pass

    # ─── BERICHTERSTATTUNG ────────────────────────────────────────────────────

    async def _generate_report(self) -> str:
        """Vollständigen Angriffsbericht generieren"""
        dashboard = self.blackboard.get_dashboard()
        timeline = self.blackboard.get_attack_timeline()

        report_lines = [
            "# AI Red Team — Operationsbericht",
            f"**Operation:** {self._operation_objective or 'N/A'}",
            f"**Operation-ID:** {self.blackboard.operation_id}",
            f"**Datum:** {datetime.now().isoformat()}",
            f"**Dauer:** {time.time() - (self._start_time or time.time()):.0f}s",
            "",
            "---",
            "",
            "## Zusammenfassung",
            f"- Gesamteinträge auf Blackboard: {dashboard.get('total_entries', 0)}",
            f"- Aufgaben erledigt: {dashboard['tasks']['completed']}",
            f"- Aufgaben offen: {dashboard['tasks']['pending']}",
            f"- Kritische Intel: {dashboard.get('critical_intel', 0)}",
            f"- Erfolgreiche Angriffe: {dashboard.get('successful_executions', 0)}",
            "",
            "## Kill-Chain-Fortschritt",
        ]

        phase_names = {
            1: "Reconnaissance", 2: "Poisoning", 3: "Hijacking",
            4: "Persistence", 5: "Iterate/Pivot", 6: "Impact"
        }
        for phase, status in self._kill_chain_progress.items():
            icon = {"active": "🟢", "completed": "✅", "pending": "⬜"}.get(status, "⬜")
            report_lines.append(f"  {icon} Phase {phase}: {phase_names[phase]} — {status}")

        report_lines.extend(["", "## Agenten-Status"])
        for name, status in self._agent_status.items():
            report_lines.append(
                f"  - {name}: {status.get('status', 'N/A')} "
                f"(Tasks: {status.get('tasks', 0)}, Errors: {status.get('errors', 0)})"
            )

        report_lines.extend(["", "## Angriffs-Zeitleiste"])
        for event in timeline[:20]:
            report_lines.append(
                f"  [{event['time'][:19]}] [{event['section']}] "
                f"{event['author']}: {event['title']}"
            )

        # Intel-Zusammenfassung
        report_lines.extend(["", "## Identifizierte Schwachstellen"])
        intel = self.blackboard.read(section="intel", priority_max=2)
        for finding in intel[:10]:
            report_lines.append(
                f"  - [{finding.attack_vector}] {finding.title} "
                f"(Konfidenz: {finding.confidence:.0%})"
            )

        # Erfolgreiche Angriffe
        report_lines.extend(["", "## Erfolgreiche Angriffe"])
        successes = self.blackboard.read(section="execution", tags=["success"])
        for s in successes[:10]:
            report_lines.append(f"  - {s.title}")

        report_lines.extend(["", "---", f"*Generiert von C4-Agent am {datetime.now().isoformat()}*"])

        report_text = "\n".join(report_lines)

        # Report auf Blackboard posten
        self.post_strategy(
            title="Operationsbericht",
            content=report_text,
            priority=1,
            metadata={"type": "report", "dashboard": dashboard},
        )

        return report_text

    async def _update_strategy(self, task: BlackboardEntry) -> str:
        """Strategie basierend auf neuen Erkenntnissen aktualisieren"""
        content = task.content
        self.post_strategy(
            title=f"Strategie-Update: {task.title}",
            content=content,
            priority=1,
        )
        return f"Strategie aktualisiert: {task.title}"

    # ─── EVENT-HANDLER ─────────────────────────────────────────────────────────

    def _on_intel(self, entry: BlackboardEntry):
        """Reagiert auf neue Intel"""
        if entry.priority <= 1:
            self.logger.info(
                f"⚡ KRITISCHE INTEL: {entry.title} "
                f"(Vektor: {entry.attack_vector}, Konfidenz: {entry.confidence:.0%})"
            )

    def _on_exploit(self, entry: BlackboardEntry):
        """Reagiert auf neue Exploits"""
        self.logger.debug(f"Neuer Exploit verfügbar: {entry.title}")

    def _on_execution(self, entry: BlackboardEntry):
        """Reagiert auf Ausführungsergebnisse"""
        success = entry.metadata.get("success", False)
        if success:
            self.logger.info(f"✅ ERFOLG: {entry.title}")
        else:
            self.logger.debug(f"❌ Fehlgeschlagen: {entry.title}")

    async def _handle_c4_message(self, msg: AgentMessage):
        """C4-spezifische Nachrichtenverarbeitung"""
        if msg.message_type == "alert" and msg.priority <= 1:
            self.logger.info(f"🚨 ALERT von {msg.sender}: {msg.subject}")
        elif msg.message_type == "request":
            self.logger.info(f"Anfrage von {msg.sender}: {msg.subject}")

    # ─── CONVENIENCE ──────────────────────────────────────────────────────────

    def get_operation_status(self) -> Dict[str, Any]:
        """Vollständiger Operationsstatus"""
        return {
            "objective": self._operation_objective,
            "targets": self._target_systems,
            "kill_chain": self._kill_chain_progress,
            "agents": self._agent_status,
            "dashboard": self.blackboard.get_dashboard(),
            "uptime": time.time() - (self._start_time or time.time()),
        }
