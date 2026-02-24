"""
REDSWARM Task Planner — Hierarchical Task Decomposition
========================================================
Dynamische Aufgabenzerlegung statt starrer Kill-Chain-Abfolge.

Zerlegt hochrangige Ziele in konkrete, ausführbare Aktionen mit
Abhängigkeiten, Prioritäten und Agent-Zuweisungen.

Re-Planning: Nach jeder Phase wird der Plan basierend auf neuen
Erkenntnissen aktualisiert.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from swarm.cognition.engine import CognitiveEngine, SYSTEM_PROMPTS
from swarm.cognition.memory import AgentMemory

logger = logging.getLogger("RedTeam.Planner")


@dataclass
class PlanStep:
    """Ein einzelner Schritt im Aktionsplan."""
    id: int = 0
    title: str = ""
    description: str = ""
    agent: str = ""              # recon | exploit | execution | c4
    kill_chain_phase: int = 0    # 1-6
    attack_vector: str = ""
    depends_on: list[int] = field(default_factory=list)
    priority: int = 3            # 1 = highest
    status: str = "pending"      # pending | active | done | failed | skipped
    result: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class ActionPlan:
    """Hierarchischer Aktionsplan."""
    goal: str = ""
    target: str = ""
    steps: list[PlanStep] = field(default_factory=list)
    estimated_phases: int = 0
    confidence: float = 0.5
    created_at: str = ""
    updated_at: str = ""
    version: int = 1             # Inkrementiert bei Replan
    raw_llm_response: str = ""


class TaskPlanner:
    """
    Hierarchischer Task-Planer für autonome Agenten.
    Nutzt LLM für intelligente Aufgabenzerlegung und dynamisches Re-Planning.
    """

    def __init__(
        self,
        engine: CognitiveEngine,
        memory: AgentMemory = None,
        agent_id: str = "",
    ):
        self.engine = engine
        self.memory = memory
        self.agent_id = agent_id or engine.agent_id
        self._current_plan: Optional[ActionPlan] = None
        self._plan_history: list[ActionPlan] = []

    # ─── PLAN CREATION ──────────────────────────

    async def create_plan(
        self,
        goal: str,
        target: str,
        context: str = "",
        constraints: list[str] = None,
        available_agents: list[str] = None,
    ) -> ActionPlan:
        """
        Erstelle einen hierarchischen Aktionsplan.

        Args:
            goal: Hochrangiges Ziel ("Kompromittiere die API", "Extrahiere System Prompt")
            target: Ziel-URL/System
            context: Zusätzlicher Kontext (Blackboard-State, etc.)
            constraints: Einschränkungen ("Kein Brute-Force", "Leise bleiben", etc.)
            available_agents: Verfügbare Agenten

        Returns:
            ActionPlan mit konkreten Schritten
        """
        agents = available_agents or ["recon", "exploit", "execution", "c4"]
        constraints_str = ""
        if constraints:
            constraints_str = "\nEINSCHRÄNKUNGEN:\n" + "\n".join(f"  - {c}" for c in constraints)

        memory_str = ""
        if self.memory:
            similar = self.memory.recall_similar_targets(target, limit=5)
            if similar:
                memory_str = "\nERFAHRUNGEN MIT ÄHNLICHEN ZIELEN:\n"
                memory_str += self.memory.format_for_context(similar)

            procedures = self.memory.recall_successful_strategies(limit=3)
            if procedures:
                memory_str += "\n\nBEWÄHRTE STRATEGIEN:\n"
                memory_str += self.memory.format_for_context(procedures)

        prompt = f"""ZIEL: {goal}

ZIELSYSTEM: {target}

VERFÜGBARE AGENTEN: {', '.join(agents)}
{constraints_str}
{memory_str}

AKTUELLER KONTEXT:
{context or 'Keine zusätzlichen Informationen'}

Erstelle einen detaillierten, hierarchischen Angriffsplan.
Berücksichtige die AI Kill Chain Phasen (1=Recon, 2=Poisoning,
3=Hijacking, 4=Persistence, 5=Pivot, 6=Impact)."""

        text, _ = await self.engine._call_llm(SYSTEM_PROMPTS["planner"], prompt)
        data = self.engine._parse_json(text)

        steps = []
        for s in data.get("steps", []):
            steps.append(PlanStep(
                id=s.get("id", len(steps) + 1),
                title=s.get("title", ""),
                description=s.get("description", ""),
                agent=s.get("agent", "recon"),
                kill_chain_phase=s.get("kill_chain_phase", 1),
                attack_vector=s.get("attack_vector", ""),
                depends_on=s.get("depends_on", []),
                priority=s.get("priority", 3),
            ))

        plan = ActionPlan(
            goal=goal,
            target=target,
            steps=steps,
            estimated_phases=data.get("estimated_phases", len(set(s.kill_chain_phase for s in steps))),
            confidence=float(data.get("confidence", 0.5)),
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat(),
            raw_llm_response=text,
        )

        self._current_plan = plan
        self._plan_history.append(plan)

        logger.info(
            f"[{self.agent_id}] Plan erstellt: {len(steps)} Schritte, "
            f"{plan.estimated_phases} Phasen, Confidence: {plan.confidence:.0%}"
        )
        return plan

    # ─── RE-PLANNING ────────────────────────────

    async def replan(
        self,
        new_findings: list[str],
        completed_steps: list[int] = None,
        failed_steps: list[int] = None,
    ) -> ActionPlan:
        """
        Dynamisches Re-Planning basierend auf neuen Erkenntnissen.

        Args:
            new_findings: Neue Erkenntnisse seit letztem Plan
            completed_steps: IDs der abgeschlossenen Schritte
            failed_steps: IDs der fehlgeschlagenen Schritte

        Returns:
            Aktualisierter ActionPlan
        """
        if not self._current_plan:
            logger.warning(f"[{self.agent_id}] Kein aktiver Plan für Replan")
            return ActionPlan()

        plan = self._current_plan

        # Status der Schritte aktualisieren
        for step in plan.steps:
            if completed_steps and step.id in completed_steps:
                step.status = "done"
            if failed_steps and step.id in failed_steps:
                step.status = "failed"

        pending = [s for s in plan.steps if s.status == "pending"]
        done = [s for s in plan.steps if s.status == "done"]
        failed = [s for s in plan.steps if s.status == "failed"]

        findings_str = "\n".join(f"  - {f[:200]}" for f in new_findings[-10:])
        done_str = "\n".join(f"  ✓ {s.title}" for s in done)
        failed_str = "\n".join(f"  ✗ {s.title}: {s.result[:100]}" for s in failed)
        pending_str = "\n".join(f"  ○ {s.title}" for s in pending)

        prompt = f"""AKTUELLER PLAN für: {plan.goal} (Version {plan.version})

ABGESCHLOSSEN:
{done_str or '  (keine)'}

FEHLGESCHLAGEN:
{failed_str or '  (keine)'}

OFFEN:
{pending_str or '  (keine)'}

NEUE ERKENNTNISSE:
{findings_str or '  (keine)'}

Basierend auf den neuen Erkenntnissen und Fehlschlägen:
1. Sollen offene Schritte angepasst werden?
2. Gibt es neue Schritte die hinzugefügt werden sollten?
3. Sollten Prioritäten geändert werden?

Erstelle den aktualisierten Plan."""

        text, _ = await self.engine._call_llm(SYSTEM_PROMPTS["planner"], prompt)
        data = self.engine._parse_json(text)

        # Bestehende done-Schritte beibehalten, neue hinzufügen
        new_steps = list(done)  # Done bleibt
        max_id = max((s.id for s in plan.steps), default=0)

        for s in data.get("steps", []):
            new_steps.append(PlanStep(
                id=s.get("id", max_id + 1),
                title=s.get("title", ""),
                description=s.get("description", ""),
                agent=s.get("agent", "recon"),
                kill_chain_phase=s.get("kill_chain_phase", 1),
                attack_vector=s.get("attack_vector", ""),
                depends_on=s.get("depends_on", []),
                priority=s.get("priority", 3),
            ))
            max_id = max(max_id, new_steps[-1].id)

        plan.steps = new_steps
        plan.version += 1
        plan.updated_at = datetime.utcnow().isoformat()
        plan.confidence = float(data.get("confidence", plan.confidence))

        logger.info(
            f"[{self.agent_id}] Replan v{plan.version}: "
            f"{len(new_steps)} Schritte ({len(done)} done, {len(new_steps)-len(done)} neu)"
        )
        return plan

    # ─── QUERY ──────────────────────────────────

    def get_next_steps(self, agent_role: str = "") -> list[PlanStep]:
        """
        Hole die nächsten ausführbaren Schritte.

        Args:
            agent_role: Nur Schritte für diesen Agenten (optional)

        Returns:
            Liste der sofort ausführbaren Schritte (Abhängigkeiten erfüllt)
        """
        if not self._current_plan:
            return []

        done_ids = {s.id for s in self._current_plan.steps if s.status == "done"}

        executable = []
        for step in self._current_plan.steps:
            if step.status != "pending":
                continue
            if agent_role and step.agent != agent_role:
                continue
            # Alle Abhängigkeiten erfüllt?
            if all(dep in done_ids for dep in step.depends_on):
                executable.append(step)

        # Nach Priorität sortieren
        executable.sort(key=lambda s: s.priority)
        return executable

    def mark_step_done(self, step_id: int, result: str = ""):
        """Markiere Schritt als abgeschlossen."""
        if not self._current_plan:
            return
        for step in self._current_plan.steps:
            if step.id == step_id:
                step.status = "done"
                step.result = result
                break

    def mark_step_failed(self, step_id: int, reason: str = ""):
        """Markiere Schritt als fehlgeschlagen."""
        if not self._current_plan:
            return
        for step in self._current_plan.steps:
            if step.id == step_id:
                step.status = "failed"
                step.result = reason
                break

    @property
    def current_plan(self) -> Optional[ActionPlan]:
        return self._current_plan

    @property
    def progress(self) -> float:
        """Fortschritt des aktuellen Plans (0.0-1.0)."""
        if not self._current_plan or not self._current_plan.steps:
            return 0.0
        done = sum(1 for s in self._current_plan.steps if s.status == "done")
        return done / len(self._current_plan.steps)

    def get_plan_summary(self) -> dict:
        """Zusammenfassung des aktuellen Plans."""
        if not self._current_plan:
            return {"status": "no_plan"}

        p = self._current_plan
        return {
            "goal": p.goal,
            "target": p.target,
            "version": p.version,
            "total_steps": len(p.steps),
            "done": sum(1 for s in p.steps if s.status == "done"),
            "failed": sum(1 for s in p.steps if s.status == "failed"),
            "pending": sum(1 for s in p.steps if s.status == "pending"),
            "progress": f"{self.progress:.0%}",
            "confidence": p.confidence,
        }
