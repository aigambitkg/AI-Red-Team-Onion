"""
REDSWARM Cognitive Layer
========================
LLM-powered autonomous reasoning, memory, reflection, and planning
for all swarm agents.

Components:
- engine.py    — Provider-agnostic LLM reasoning (CoT, ToT, payload generation)
- memory.py    — Episodic, semantic, procedural agent memory
- reflector.py — Self-reflection and self-correction (ReAct pattern)
- planner.py   — Hierarchical task decomposition and dynamic replanning
"""

from swarm.cognition.engine import CognitiveEngine, ReasoningResult
from swarm.cognition.memory import AgentMemory, Episode, MemoryType
from swarm.cognition.reflector import Reflector, Reflection
from swarm.cognition.planner import TaskPlanner, ActionPlan, PlanStep
