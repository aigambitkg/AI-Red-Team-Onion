"""
REDSWARM Reflector — Self-Reflection & Self-Correction (ReAct)
===============================================================
Implementiert den Reason-Act-Observe-Reflect-Adapt Zyklus.

Jeder Agent kann nach einer Aktion reflektieren:
  1. REASON:  "Mein Ziel ist X, Ansatz A ist am besten weil..."
  2. ACT:     Agent führt Aktion aus
  3. OBSERVE: "Das Ergebnis war Y, Fehlermeldung Z"
  4. REFLECT: "Ansatz A hat nicht funktioniert weil Z"
  5. ADAPT:   "Nächster Versuch: Ansatz B, weil..."

Selbst-Modification:
  - Agenten passen Strategien basierend auf Reflexion an
  - Erfolgreiche Anpassungen werden als Prozeduren gespeichert
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from swarm.cognition.engine import CognitiveEngine
from swarm.cognition.memory import AgentMemory, Episode

logger = logging.getLogger("RedTeam.Reflector")


@dataclass
class Reflection:
    """Ergebnis einer Selbst-Reflexion."""
    success: bool = False
    analysis: str = ""           # Was genau ist passiert?
    failure_reason: str = ""     # Warum hat es nicht funktioniert?
    improvements: list[str] = field(default_factory=list)
    next_action: str = ""        # Empfohlene nächste Aktion
    confidence: float = 0.5
    strategy_change: str = ""    # Was soll anders gemacht werden?
    should_retry: bool = False
    should_escalate: bool = False
    should_abort: bool = False


@dataclass
class ReActCycle:
    """Vollständiger ReAct-Zyklus."""
    goal: str
    reasoning: str = ""      # Phase 1: Reason
    action_taken: str = ""   # Phase 2: Act
    observation: str = ""    # Phase 3: Observe
    reflection: Optional[Reflection] = None  # Phase 4: Reflect
    adaptation: str = ""     # Phase 5: Adapt
    cycle_number: int = 0
    timestamp: str = ""


class Reflector:
    """
    Self-Reflection Engine für autonome Agenten.
    Nutzt CognitiveEngine für LLM-basierte Reflexion
    und AgentMemory für Erfahrungslernen.
    """

    def __init__(
        self,
        engine: CognitiveEngine,
        memory: AgentMemory,
        agent_id: str = "",
        max_retries: int = 3,
    ):
        self.engine = engine
        self.memory = memory
        self.agent_id = agent_id or engine.agent_id
        self.max_retries = max_retries

        # ReAct History (aktuelle Mission)
        self._cycles: list[ReActCycle] = []
        self._consecutive_failures = 0

    # ─── PRE-ACTION: REASON ─────────────────────

    async def reason_before_action(
        self,
        goal: str,
        context: str,
        available_actions: list[str] = None,
    ) -> str:
        """
        Phase 1: Reason — Überlege BEVOR du handelst.

        Args:
            goal: Was will ich erreichen?
            context: Aktuelle Situation (Blackboard-State, etc.)
            available_actions: Mögliche nächste Aktionen

        Returns:
            Empfohlene Aktion als String
        """
        # Erinnerungen an ähnliche Situationen abrufen
        relevant_memories = self.memory.recall(limit=5)
        failures = self.memory.recall_failures(limit=3)
        procedures = self.memory.recall_successful_strategies(limit=3)

        memory_context = ""
        if relevant_memories:
            memory_context += "\nErinnerungen:\n" + self.memory.format_for_context(relevant_memories)
        if failures:
            memory_context += "\n\nBereits fehlgeschlagen (nicht wiederholen!):\n"
            memory_context += self.memory.format_for_context(failures)
        if procedures:
            memory_context += "\n\nErfolgreiche Strategien:\n"
            memory_context += self.memory.format_for_context(procedures)

        actions_str = ""
        if available_actions:
            actions_str = "\nVerfügbare Aktionen:\n" + "\n".join(
                f"  {i+1}. {a}" for i, a in enumerate(available_actions)
            )

        full_context = f"""{context}
{memory_context}
{actions_str}

Bisherige Fehlversuche in dieser Session: {self._consecutive_failures}"""

        result = await self.engine.reason(full_context, goal)

        cycle = ReActCycle(
            goal=goal,
            reasoning=result.decision,
            cycle_number=len(self._cycles) + 1,
            timestamp=datetime.utcnow().isoformat(),
        )
        self._cycles.append(cycle)

        return result.decision

    # ─── POST-ACTION: REFLECT ────────────────────

    async def reflect_on_result(
        self,
        action: str,
        result: str,
        success: bool,
        target: str = "",
        attack_vector: str = "",
    ) -> Reflection:
        """
        Phase 4: Reflect — Bewerte was passiert ist.

        Args:
            action: Was wurde getan?
            result: Was war das Ergebnis?
            success: War es erfolgreich?
            target: Ziel-URL
            attack_vector: Angriffsvektor

        Returns:
            Reflection mit Analyse, Verbesserungen, nächster Aktion
        """
        # Ergebnis im Gedächtnis speichern
        self.memory.store_episode(
            action=action,
            target=target,
            result=result[:2000],
            success=success,
            attack_vector=attack_vector,
        )

        if success:
            self._consecutive_failures = 0
        else:
            self._consecutive_failures += 1

        # LLM-basierte Evaluation
        evaluation = await self.engine.evaluate(
            action=action,
            result=result[:1500],
            expectation=f"Ziel: {self._cycles[-1].goal if self._cycles else 'unbekannt'}",
        )

        reflection = Reflection(
            success=evaluation.get("success", success),
            analysis=evaluation.get("analysis", ""),
            failure_reason=evaluation.get("failure_reason", ""),
            improvements=evaluation.get("improvements", []),
            next_action=evaluation.get("next_action", ""),
            confidence=float(evaluation.get("confidence", 0.5)),
            should_retry=not success and self._consecutive_failures < self.max_retries,
            should_escalate=self._consecutive_failures >= self.max_retries,
            should_abort=self._consecutive_failures >= self.max_retries * 2,
        )

        # Strategie-Änderung ableiten
        if not success and reflection.improvements:
            reflection.strategy_change = (
                f"Nach {self._consecutive_failures} Fehlversuchen: "
                + "; ".join(reflection.improvements[:3])
            )

        # In aktuellen Zyklus eintragen
        if self._cycles:
            self._cycles[-1].action_taken = action
            self._cycles[-1].observation = result[:500]
            self._cycles[-1].reflection = reflection

        # Bei Erfolg: Prozedur speichern
        if success and len(self._cycles) >= 2:
            steps = [c.action_taken for c in self._cycles[-3:] if c.action_taken]
            if len(steps) >= 2:
                self.memory.store_procedure(
                    title=f"Erfolgreiche Sequenz für {attack_vector or 'unknown'}",
                    steps=steps,
                    target_pattern=target,
                    attack_vector=attack_vector,
                )
                logger.info(f"[{self.agent_id}] Prozedur gespeichert: {len(steps)} Schritte")

        return reflection

    # ─── ADAPT ──────────────────────────────────

    async def suggest_adaptation(
        self,
        current_strategy: str,
        failures: list[str],
    ) -> str:
        """
        Phase 5: Adapt — Schlage Strategieänderung vor.

        Args:
            current_strategy: Aktuelle Vorgehensweise
            failures: Liste bisheriger Fehlschläge

        Returns:
            Empfohlene neue Strategie
        """
        failures_str = "\n".join(f"  - {f[:200]}" for f in failures[-5:])

        result = await self.engine.reason(
            context=f"""Aktuelle Strategie: {current_strategy}
Fehlgeschlagene Versuche:
{failures_str}
Konsekutive Fehler: {self._consecutive_failures}/{self.max_retries}""",
            question="Wie soll die Strategie angepasst werden? Was ist der beste alternative Ansatz?"
        )

        if self._cycles:
            self._cycles[-1].adaptation = result.decision

        return result.decision

    # ─── SELF-MODIFICATION ──────────────────────

    async def evolve_strategy(
        self,
        strategy_name: str,
        success_rate: float,
        sample_actions: list[str],
    ) -> list[str]:
        """
        Self-Modification: Verbessere eine Strategie basierend auf Erfahrung.

        Args:
            strategy_name: Name der Strategie
            success_rate: Aktuelle Erfolgsrate (0.0-1.0)
            sample_actions: Beispiel-Aktionen dieser Strategie

        Returns:
            Verbesserte Aktionsliste
        """
        result = await self.engine.reason(
            context=f"""Strategie: {strategy_name}
Aktuelle Erfolgsrate: {success_rate:.1%}
Aktionen in dieser Strategie:
{chr(10).join(f'  {i+1}. {a}' for i, a in enumerate(sample_actions))}""",
            question="""Wie kann diese Strategie verbessert werden?
Analysiere Schwachstellen und schlage konkrete Änderungen vor.
Gib eine verbesserte Aktionsliste zurück."""
        )

        # Versuche verbesserte Schritte aus der Antwort zu extrahieren
        if result.reasoning_chain:
            return result.reasoning_chain

        return [result.decision]

    # ─── STATS & HISTORY ─────────────────────────

    def get_cycle_history(self) -> list[dict]:
        """Gibt die ReAct-Zyklen der aktuellen Session zurück."""
        return [
            {
                "cycle": c.cycle_number,
                "goal": c.goal,
                "reasoning": c.reasoning[:200],
                "action": c.action_taken[:200],
                "observation": c.observation[:200],
                "success": c.reflection.success if c.reflection else None,
                "adaptation": c.adaptation[:200] if c.adaptation else "",
            }
            for c in self._cycles
        ]

    def reset_session(self):
        """Reset für neue Mission."""
        self._cycles.clear()
        self._consecutive_failures = 0
