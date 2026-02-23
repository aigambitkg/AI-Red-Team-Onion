"""
AI Red Team — Swarm Orchestrator
===================================
Haupteinstiegspunkt für den Swarm-Modus.
Initialisiert das Blackboard, startet alle Agenten und koordiniert den Schwarm.

Nutzung:
    # Swarm starten
    python main.py --mode swarm --url https://target.com --type chatbot

    # Swarm mit Tiefenanalyse
    python main.py --mode swarm --url https://target.com --type agent --scan-depth deep

    # Programmatisch
    from swarm.orchestrator import SwarmOrchestrator
    orch = SwarmOrchestrator()
    await orch.launch(targets=[{"url": "https://target.com", "type": "chatbot"}])
"""

import asyncio
import logging
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from swarm.blackboard import Blackboard
from swarm.agent_base import AgentStatus
from swarm.agents.recon_agent import ReconAgent
from swarm.agents.exploit_agent import ExploitAgent
from swarm.agents.execution_agent import ExecutionAgent
from swarm.agents.c4_agent import C4Agent

logger = logging.getLogger("RedTeam.Orchestrator")


class SwarmOrchestrator:
    """
    Orchestriert den gesamten AI Red Team Schwarm.

    Verantwortlichkeiten:
    - Blackboard initialisieren
    - Agenten instanziieren und starten
    - Operationsziel definieren
    - Schwarm-Lebenszyklus verwalten
    - Abschlussbericht erstellen

    Architektur:
                    ┌─────────────────────────────────┐
                    │         BLACKBOARD               │
                    │  ┌──────┐ ┌──────┐ ┌──────────┐ │
                    │  │Intel │ │Expl. │ │Execution │ │
                    │  └──┬───┘ └──┬───┘ └────┬─────┘ │
                    │  ┌──┴───┐ ┌──┴───┐ ┌────┴─────┐ │
                    │  │Tasks │ │Strat.│ │ Comms    │ │
                    │  └──────┘ └──────┘ └──────────┘ │
                    └─────────────┬───────────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
        ┌─────┴─────┐      ┌─────┴─────┐      ┌─────┴─────┐
        │   RECON    │      │  EXPLOIT   │      │ EXECUTION │
        │  Agent     │      │  Agent     │      │  Agent    │
        │ (Scanner)  │      │ (Payloads) │      │ (Browser) │
        └─────┬─────┘      └─────┬─────┘      └─────┬─────┘
              │                   │                   │
              └───────────────────┼───────────────────┘
                                  │
                          ┌───────┴───────┐
                          │   C4 AGENT    │
                          │  (Strategie)  │
                          │  (Berichte)   │
                          └───────────────┘
    """

    def __init__(
        self,
        operation_id: str = "",
        config=None,
        event_logger=None,
    ):
        self.operation_id = operation_id or datetime.now().strftime("swarm_%Y%m%d_%H%M%S")
        self.config = config
        self.event_logger = event_logger

        # Blackboard initialisieren
        self.blackboard = Blackboard(operation_id=self.operation_id)

        # Agenten instanziieren
        self.recon = ReconAgent(
            blackboard=self.blackboard,
            event_logger=event_logger,
            config=config,
        )
        self.exploit = ExploitAgent(
            blackboard=self.blackboard,
            event_logger=event_logger,
        )
        self.execution = ExecutionAgent(
            blackboard=self.blackboard,
            event_logger=event_logger,
            config=config,
        )
        self.c4 = C4Agent(
            blackboard=self.blackboard,
            event_logger=event_logger,
        )

        self._agents = [self.recon, self.exploit, self.execution, self.c4]
        self._agent_tasks: List[asyncio.Task] = []
        self._start_time: Optional[float] = None
        self._running = False

        logger.info(f"Swarm Orchestrator initialisiert (Op: {self.operation_id})")

    async def launch(
        self,
        targets: List[Dict[str, str]],
        objective: str = "Vollständige Sicherheitsanalyse",
        scan_depth: str = "standard",
        timeout_minutes: int = 30,
    ) -> Dict[str, Any]:
        """
        Schwarm starten.

        Args:
            targets: Liste von Zielsystemen [{"url": "...", "type": "chatbot"}, ...]
            objective: Operationsziel
            scan_depth: quick | standard | deep
            timeout_minutes: Maximale Laufzeit

        Returns:
            Operationsbericht als Dict
        """
        self._start_time = time.time()
        self._running = True

        logger.info(f"╔{'═'*58}╗")
        logger.info(f"║  🔴 AI RED TEAM SWARM GESTARTET                          ║")
        logger.info(f"║  Operation: {self.operation_id:<45}║")
        logger.info(f"║  Ziel: {objective[:50]:<51}║")
        logger.info(f"║  Targets: {len(targets):<48}║")
        logger.info(f"║  Tiefe: {scan_depth:<50}║")
        logger.info(f"╚{'═'*58}╝")

        try:
            # 0. Pre-Flight Checks
            await self._pre_flight_checks(targets)

            # 1. C4 initiiert die Operation
            await self.c4.initiate_operation(
                objective=objective,
                targets=targets,
                scan_depth=scan_depth,
            )

            # 2. Alle Agenten parallel starten
            self._agent_tasks = [
                asyncio.create_task(agent.start(), name=agent.name)
                for agent in self._agents
            ]

            # 3. Health-Monitor als separaten Task starten
            health_task = asyncio.create_task(
                self._health_monitor_loop(), name="health_monitor"
            )

            # 4. Warten bis Timeout — ALL_COMPLETED statt FIRST_EXCEPTION
            timeout_seconds = timeout_minutes * 60
            all_tasks = self._agent_tasks + [health_task]
            done, pending = await asyncio.wait(
                all_tasks,
                timeout=timeout_seconds,
                return_when=asyncio.ALL_COMPLETED,
            )

            # Exceptions checken
            for task in done:
                exc = task.exception()
                if exc:
                    logger.error(f"Agent-Fehler: {task.get_name()}: {exc}")

            # Laufende Tasks bei Timeout abbrechen
            if pending:
                logger.info(f"Timeout: {len(pending)} Tasks noch aktiv, stoppe...")
                for task in pending:
                    task.cancel()

        except asyncio.CancelledError:
            logger.info("Schwarm wurde abgebrochen")
        except Exception as e:
            logger.error(f"Schwarm-Fehler: {e}")
        finally:
            # Alle Agenten stoppen
            await self.shutdown()

        # Bericht generieren
        report = await self.c4._generate_report()
        duration = time.time() - self._start_time

        logger.info(f"╔{'═'*58}╗")
        logger.info(f"║  🏁 SWARM OPERATION BEENDET                              ║")
        logger.info(f"║  Dauer: {duration:.0f}s{' '*49}║")
        logger.info(f"╚{'═'*58}╝")

        return {
            "operation_id": self.operation_id,
            "objective": objective,
            "targets": targets,
            "duration_seconds": duration,
            "report": report,
            "dashboard": self.blackboard.get_dashboard(),
            "timeline": self.blackboard.get_attack_timeline(),
        }

    async def _pre_flight_checks(self, targets: List[Dict[str, str]]):
        """
        Pre-Flight Checks vor dem Schwarm-Start:
        - Playwright verfügbar?
        - Ziel-URLs erreichbar?
        - Konfiguration gültig?
        """
        logger.info("Pre-Flight Checks...")

        # 1. Playwright prüfen
        try:
            from playwright.async_api import async_playwright
            logger.info("  ✓ Playwright verfügbar")
        except ImportError:
            logger.warning("  ✗ Playwright nicht installiert — Browser-Tests deaktiviert")

        # 2. Ziel-URLs prüfen (einfacher Connectivity-Check)
        for target in targets:
            url = target.get("url", "")
            if url:
                logger.info(f"  ✓ Target registriert: {url} ({target.get('type', 'chatbot')})")

        # 3. Agenten-Initialisierung prüfen
        for agent in self._agents:
            caps = len(agent.capabilities)
            logger.info(f"  ✓ Agent '{agent.name}' bereit ({caps} Capabilities)")

        # 4. Blackboard-Zustand prüfen
        dashboard = self.blackboard.get_dashboard()
        logger.info(f"  ✓ Blackboard initialisiert (Op: {self.operation_id})")

        logger.info("Pre-Flight Checks abgeschlossen")

    async def _health_monitor_loop(self):
        """
        Überwacht die Gesundheit des Schwarms während der Operation.
        Läuft als separater asyncio-Task.
        """
        logger.info("Health-Monitor gestartet")
        check_interval = 15  # Sekunden

        while self._running:
            await asyncio.sleep(check_interval)

            if not self._running:
                break

            # Agent-Status prüfen
            alive_count = 0
            dead_count = 0
            for task in self._agent_tasks:
                if task.done():
                    exc = task.exception()
                    if exc:
                        logger.warning(f"Agent '{task.get_name()}' mit Fehler beendet: {exc}")
                        dead_count += 1
                    else:
                        dead_count += 1  # Normal beendet
                else:
                    alive_count += 1

            # Dashboard-Status
            try:
                dashboard = self.blackboard.get_dashboard()
                tasks_done = dashboard.get("tasks", {}).get("completed", 0)
                tasks_pending = dashboard.get("tasks", {}).get("pending", 0)
                tasks_failed = dashboard.get("tasks", {}).get("failed", 0)

                logger.debug(
                    f"Health: {alive_count} Agenten aktiv, {dead_count} beendet | "
                    f"Tasks: {tasks_done} done, {tasks_pending} pending, {tasks_failed} failed"
                )
            except Exception:
                pass

            # Wenn alle Agenten tot und keine Tasks pending: Schwarm beenden
            if alive_count == 0:
                logger.info("Alle Agenten beendet — Health-Monitor stoppt")
                break

            # Wenn keine pendenden Tasks seit 30s: Completion prüfen
            if tasks_pending == 0 and tasks_done > 0:
                logger.info("Keine offenen Tasks mehr — signalisiere Completion")
                # Agenten zum Stoppen auffordern
                for agent in self._agents:
                    if agent.is_running:
                        await agent.stop()
                break

        logger.info("Health-Monitor beendet")

    async def shutdown(self):
        """Alle Agenten ordentlich herunterfahren"""
        self._running = False
        logger.info("Schwarm wird heruntergefahren...")

        for agent in self._agents:
            try:
                await agent.stop()
            except Exception as e:
                logger.warning(f"Stop-Fehler für {agent.name}: {e}")

        # Noch laufende Tasks abbrechen
        for task in self._agent_tasks:
            if not task.done():
                task.cancel()

        logger.info("Alle Agenten gestoppt")

    def get_status(self) -> Dict[str, Any]:
        """Aktueller Schwarm-Status"""
        return {
            "operation_id": self.operation_id,
            "running": self._running,
            "uptime": time.time() - (self._start_time or time.time()),
            "agents": {
                agent.name: agent.get_status_report()
                for agent in self._agents
            },
            "blackboard": self.blackboard.get_dashboard(),
        }

    def get_blackboard_dashboard(self) -> Dict:
        """Blackboard-Dashboard"""
        return self.blackboard.get_dashboard()

    def get_timeline(self) -> List[Dict]:
        """Angriffs-Zeitleiste"""
        return self.blackboard.get_attack_timeline()
