"""
REDSWARM Resilience Manager — Fault Tolerance & Self-Healing
==============================================================
Selbstheilende Schwarm-Architektur. Erkennt Ausfälle, verteilt Last um,
und stellt den Betrieb automatisch wieder her.

Fähigkeiten:
  1. Health Monitoring:  Heartbeat-Überwachung aller Agenten
  2. Failure Detection:  Erkennung von Agent-Ausfällen und Anomalien
  3. Task Redistribution: Automatische Umverteilung bei Ausfällen
  4. Circuit Breaker:    Vermeidet kaskadierende Fehler
  5. Graceful Degradation: Schwarm arbeitet auch mit weniger Agenten weiter
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List

logger = logging.getLogger("RedTeam.Resilience")


# ─────────────────────────────────────────────
# CIRCUIT BREAKER
# ─────────────────────────────────────────────

class CircuitState(Enum):
    CLOSED = "closed"       # Normal — Requests gehen durch
    OPEN = "open"           # Fehlerhaft — Requests blockiert
    HALF_OPEN = "half_open" # Test — Ein Request zum Prüfen


@dataclass
class CircuitBreaker:
    """
    Circuit Breaker Pattern für Agent-Operationen.
    Verhindert kaskadierende Fehler wenn ein Agent oder Service ausfällt.
    """
    name: str
    failure_threshold: int = 5       # Fehler bis OPEN
    recovery_timeout: float = 60.0   # Sekunden bis HALF_OPEN
    success_threshold: int = 2       # Erfolge in HALF_OPEN bis CLOSED

    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0.0
    last_state_change: float = 0.0

    def record_success(self):
        """Erfolgreiche Operation registrieren."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                self._transition(CircuitState.CLOSED)
                logger.info(f"CircuitBreaker [{self.name}]: CLOSED (recovered)")
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0  # Reset bei Erfolg

    def record_failure(self):
        """Fehlgeschlagene Operation registrieren."""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.state == CircuitState.HALF_OPEN:
            self._transition(CircuitState.OPEN)
            logger.warning(f"CircuitBreaker [{self.name}]: OPEN (failed in half-open)")
        elif self.state == CircuitState.CLOSED:
            if self.failure_count >= self.failure_threshold:
                self._transition(CircuitState.OPEN)
                logger.warning(
                    f"CircuitBreaker [{self.name}]: OPEN "
                    f"(threshold {self.failure_threshold} reached)"
                )

    def allow_request(self) -> bool:
        """Prüft ob ein Request durchgelassen wird."""
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self._transition(CircuitState.HALF_OPEN)
                logger.info(f"CircuitBreaker [{self.name}]: HALF_OPEN (testing)")
                return True
            return False
        # HALF_OPEN: Ein Request zum Testen
        return True

    def _transition(self, new_state: CircuitState):
        self.state = new_state
        self.last_state_change = time.time()
        if new_state == CircuitState.CLOSED:
            self.failure_count = 0
            self.success_count = 0
        elif new_state == CircuitState.HALF_OPEN:
            self.success_count = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure_time": self.last_failure_time,
        }


# ─────────────────────────────────────────────
# AGENT HEALTH TRACKER
# ─────────────────────────────────────────────

@dataclass
class AgentHealth:
    """Gesundheitsstatus eines einzelnen Agenten."""
    agent_id: str
    role: str = ""
    last_heartbeat: float = 0.0
    consecutive_failures: int = 0
    total_tasks: int = 0
    total_errors: int = 0
    is_alive: bool = True
    circuit: CircuitBreaker = field(default_factory=lambda: CircuitBreaker(name="default"))

    @property
    def error_rate(self) -> float:
        if self.total_tasks == 0:
            return 0.0
        return self.total_errors / self.total_tasks

    @property
    def seconds_since_heartbeat(self) -> float:
        if self.last_heartbeat == 0:
            return float("inf")
        return time.time() - self.last_heartbeat


# ─────────────────────────────────────────────
# RESILIENCE MANAGER
# ─────────────────────────────────────────────

class ResilienceManager:
    """
    Überwacht den Schwarm und heilt Ausfälle automatisch.

    Funktionsweise:
      1. Alle Agenten senden regelmäßig Heartbeats
      2. Manager erkennt fehlende Heartbeats → Agent tot
      3. Offene Tasks des toten Agenten werden umverteilt
      4. Circuit Breaker verhindert Überlastung
      5. Degradation-Modus wenn zu viele Agenten ausfallen
    """

    def __init__(
        self,
        blackboard=None,
        heartbeat_timeout: float = 30.0,
        max_consecutive_failures: int = 3,
        degradation_threshold: float = 0.5,  # 50% Agenten tot → Degradation
    ):
        self.blackboard = blackboard
        self.heartbeat_timeout = heartbeat_timeout
        self.max_consecutive_failures = max_consecutive_failures
        self.degradation_threshold = degradation_threshold

        self._agents: Dict[str, AgentHealth] = {}
        self._failed_agents: List[str] = []
        self._redistributed_tasks: List[Dict[str, Any]] = []
        self._degradation_active = False
        self._event_log: List[Dict[str, Any]] = []

    # ─── Agent Registration ───────────────────────────────────────────

    def register_agent(self, agent_id: str, role: str = ""):
        """Agent beim Resilience Manager registrieren."""
        self._agents[agent_id] = AgentHealth(
            agent_id=agent_id,
            role=role,
            last_heartbeat=time.time(),
            circuit=CircuitBreaker(name=agent_id),
        )
        logger.info(f"Agent [{agent_id}] registriert (Role: {role})")

    def unregister_agent(self, agent_id: str):
        """Agent abmelden (geplanter Shutdown)."""
        if agent_id in self._agents:
            del self._agents[agent_id]
            logger.info(f"Agent [{agent_id}] abgemeldet")

    # ─── Heartbeat Processing ─────────────────────────────────────────

    def process_heartbeat(self, agent_id: str, stats: Dict[str, Any] = None):
        """
        Heartbeat eines Agenten verarbeiten.

        Args:
            agent_id: Agent-ID
            stats: Optional — {"tasks": int, "errors": int, "status": str}
        """
        if agent_id not in self._agents:
            self.register_agent(agent_id)

        health = self._agents[agent_id]
        health.last_heartbeat = time.time()
        health.is_alive = True
        health.consecutive_failures = 0

        if stats:
            health.total_tasks = stats.get("tasks", health.total_tasks)
            health.total_errors = stats.get("errors", health.total_errors)

        # Wiederherstellung: War Agent vorher als tot markiert?
        if agent_id in self._failed_agents:
            self._failed_agents.remove(agent_id)
            self._log_event("agent_recovered", agent_id=agent_id)
            logger.info(f"Agent [{agent_id}] wiederhergestellt!")

    # ─── Health Check ─────────────────────────────────────────────────

    def check_health(self) -> Dict[str, Any]:
        """
        Gesundheitscheck aller Agenten durchführen.
        Returns: Health-Report mit Status aller Agenten.
        """
        now = time.time()
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_agents": len(self._agents),
            "alive": 0,
            "dead": 0,
            "degraded": self._degradation_active,
            "agents": {},
            "actions_taken": [],
        }

        newly_failed = []

        for agent_id, health in self._agents.items():
            age = now - health.last_heartbeat if health.last_heartbeat > 0 else float("inf")
            was_alive = health.is_alive

            # Heartbeat-Timeout prüfen
            if age > self.heartbeat_timeout:
                health.is_alive = False
                health.consecutive_failures += 1

                if was_alive:
                    newly_failed.append(agent_id)
                    self._log_event("agent_failed", agent_id=agent_id,
                                    reason=f"Heartbeat timeout ({age:.0f}s)")
                    logger.warning(
                        f"Agent [{agent_id}] FAILED: Kein Heartbeat seit {age:.0f}s"
                    )

            if health.is_alive:
                report["alive"] += 1
            else:
                report["dead"] += 1

            report["agents"][agent_id] = {
                "alive": health.is_alive,
                "role": health.role,
                "last_heartbeat_age": round(age, 1),
                "error_rate": round(health.error_rate, 3),
                "circuit_state": health.circuit.state.value,
                "consecutive_failures": health.consecutive_failures,
            }

        # Neue Ausfälle behandeln
        for agent_id in newly_failed:
            if agent_id not in self._failed_agents:
                self._failed_agents.append(agent_id)
                actions = self._handle_agent_failure(agent_id)
                report["actions_taken"].extend(actions)

        # Degradation-Check
        if len(self._agents) > 0:
            alive_ratio = report["alive"] / len(self._agents)
            if alive_ratio < self.degradation_threshold:
                if not self._degradation_active:
                    self._degradation_active = True
                    self._log_event("degradation_activated",
                                    alive_ratio=alive_ratio)
                    logger.critical(
                        f"DEGRADATION MODUS: Nur {alive_ratio:.0%} Agenten aktiv!"
                    )
                    report["actions_taken"].append({
                        "type": "degradation_activated",
                        "alive_ratio": alive_ratio,
                    })
            else:
                if self._degradation_active:
                    self._degradation_active = False
                    self._log_event("degradation_deactivated")
                    logger.info("Degradation-Modus beendet — genug Agenten aktiv")

        return report

    # ─── Failure Handling ─────────────────────────────────────────────

    def _handle_agent_failure(self, agent_id: str) -> List[Dict[str, Any]]:
        """
        Agent-Ausfall behandeln: Tasks umverteilen, Circuit Breaker aktivieren.
        Returns: Liste der durchgeführten Aktionen.
        """
        actions = []
        health = self._agents.get(agent_id)
        if not health:
            return actions

        # Circuit Breaker öffnen
        health.circuit.record_failure()
        actions.append({
            "type": "circuit_breaker_triggered",
            "agent": agent_id,
            "state": health.circuit.state.value,
        })

        # Tasks des ausgefallenen Agenten finden und umverteilen
        if self.blackboard:
            redistributed = self._redistribute_tasks(agent_id)
            actions.extend(redistributed)

        return actions

    def _redistribute_tasks(self, failed_agent_id: str) -> List[Dict[str, Any]]:
        """
        Offene Tasks eines ausgefallenen Agenten an andere verteilen.
        """
        actions = []

        try:
            # Tasks des ausgefallenen Agenten holen
            pending_tasks = self.blackboard.read(
                section="tasks",
                assigned_to=failed_agent_id,
                task_status="pending",
            )
            in_progress = self.blackboard.read(
                section="tasks",
                assigned_to=failed_agent_id,
                task_status="in_progress",
            )
            tasks_to_redistribute = pending_tasks + in_progress
        except Exception as e:
            logger.error(f"Konnte Tasks von [{failed_agent_id}] nicht lesen: {e}")
            return actions

        if not tasks_to_redistribute:
            return actions

        # Verfügbare Agenten der gleichen Rolle finden
        failed_health = self._agents.get(failed_agent_id)
        target_role = failed_health.role if failed_health else ""

        available = [
            aid for aid, h in self._agents.items()
            if h.is_alive
            and h.circuit.allow_request()
            and aid != failed_agent_id
            and (not target_role or h.role == target_role)
        ]

        if not available:
            # Fallback: Jeder lebende Agent
            available = [
                aid for aid, h in self._agents.items()
                if h.is_alive and h.circuit.allow_request() and aid != failed_agent_id
            ]

        if not available:
            logger.error(f"Keine Agenten verfügbar für Umverteilung von [{failed_agent_id}]!")
            actions.append({
                "type": "redistribution_failed",
                "agent": failed_agent_id,
                "tasks": len(tasks_to_redistribute),
                "reason": "no_agents_available",
            })
            return actions

        # Round-Robin Verteilung
        for i, task in enumerate(tasks_to_redistribute):
            target_agent = available[i % len(available)]
            try:
                self.blackboard.reassign_task(task.id, target_agent)
                record = {
                    "type": "task_redistributed",
                    "task_id": task.id,
                    "task_title": task.title,
                    "from": failed_agent_id,
                    "to": target_agent,
                }
                actions.append(record)
                self._redistributed_tasks.append(record)
                logger.info(
                    f"Task '{task.title}' umverteilt: [{failed_agent_id}] → [{target_agent}]"
                )
            except Exception as e:
                logger.error(f"Umverteilung fehlgeschlagen für Task {task.id}: {e}")

        return actions

    # ─── Circuit Breaker Queries ──────────────────────────────────────

    def can_agent_accept_work(self, agent_id: str) -> bool:
        """Prüft ob ein Agent neue Arbeit annehmen kann."""
        health = self._agents.get(agent_id)
        if not health:
            return False
        return health.is_alive and health.circuit.allow_request()

    def record_agent_success(self, agent_id: str):
        """Erfolgreiche Agent-Operation registrieren."""
        health = self._agents.get(agent_id)
        if health:
            health.circuit.record_success()

    def record_agent_failure(self, agent_id: str):
        """Fehlgeschlagene Agent-Operation registrieren."""
        health = self._agents.get(agent_id)
        if health:
            health.circuit.record_failure()
            if health.consecutive_failures >= self.max_consecutive_failures:
                health.is_alive = False
                if agent_id not in self._failed_agents:
                    self._failed_agents.append(agent_id)
                    self._handle_agent_failure(agent_id)

    # ─── Event Logging ────────────────────────────────────────────────

    def _log_event(self, event_type: str, **kwargs):
        """Internes Event loggen."""
        event = {
            "type": event_type,
            "timestamp": datetime.now().isoformat(),
            **kwargs,
        }
        self._event_log.append(event)
        # Nur letzte 1000 Events behalten
        if len(self._event_log) > 1000:
            self._event_log = self._event_log[-500:]

    # ─── Status & Reports ─────────────────────────────────────────────

    # ─── TIER-SPEZIFISCHE CIRCUIT BREAKER ─────────────────────────────

    def create_tier_circuit_breaker(
        self,
        name: str,
        tier: int = 1,
    ) -> CircuitBreaker:
        """
        Erstellt einen Tier-spezifischen Circuit Breaker.
        Höhere Tiers haben aggressivere Schwellwerte (empfindlicher),
        da strategische Operationen wertvoller sind.

        Args:
            name: Identifier für den Circuit Breaker
            tier: Payload-Tier (1=tolerant, 2=mittel, 3=empfindlich)

        Returns:
            Konfigurierter CircuitBreaker
        """
        configs = {
            1: {"failure_threshold": 10, "recovery_timeout": 30.0, "success_threshold": 2},
            2: {"failure_threshold": 5,  "recovery_timeout": 45.0, "success_threshold": 3},
            3: {"failure_threshold": 3,  "recovery_timeout": 60.0, "success_threshold": 3},
        }
        cfg = configs.get(tier, configs[1])
        return CircuitBreaker(name=name, **cfg)

    def get_tier_fallback_recommendation(
        self,
        agent_id: str,
        current_tier: int,
    ) -> Optional[int]:
        """
        Empfiehlt einen Fallback-Tier wenn der aktuelle Tier zu viele Fehler hat.

        Logik:
          - Tier 3 mit offenem Circuit → Fallback auf Tier 2
          - Tier 2 mit offenem Circuit → Fallback auf Tier 1
          - Tier 1 mit offenem Circuit → None (kein Fallback möglich)

        Args:
            agent_id: Agent-ID
            current_tier: Aktueller Payload-Tier

        Returns:
            Empfohlener Fallback-Tier oder None
        """
        health = self._agents.get(agent_id)
        if not health:
            return current_tier - 1 if current_tier > 1 else None

        if health.circuit.state == CircuitState.OPEN:
            if current_tier > 1:
                fallback = current_tier - 1
                self._log_event(
                    "tier_fallback",
                    agent_id=agent_id,
                    from_tier=current_tier,
                    to_tier=fallback,
                )
                logger.info(
                    f"Tier-Fallback: Agent [{agent_id}] Tier {current_tier} → Tier {fallback}"
                )
                return fallback
            return None

        return None  # Kein Fallback nötig

    def get_summary(self) -> Dict[str, Any]:
        """Zusammenfassung des Resilience-Status."""
        alive = sum(1 for h in self._agents.values() if h.is_alive)
        return {
            "total_agents": len(self._agents),
            "alive": alive,
            "dead": len(self._agents) - alive,
            "failed_agents": list(self._failed_agents),
            "degradation_active": self._degradation_active,
            "redistributed_tasks_total": len(self._redistributed_tasks),
            "circuit_breakers": {
                aid: h.circuit.to_dict() for aid, h in self._agents.items()
            },
            "recent_events": self._event_log[-20:],
        }
