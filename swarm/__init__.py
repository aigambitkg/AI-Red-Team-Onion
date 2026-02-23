"""
AI Red Team — Swarm Hacking Module
====================================
Multi-Agent Swarm Architecture für koordinierte AI Red Team Operationen.

Architektur:
- Blackboard: Gemeinsames Schwarzes Brett für Inter-Agent-Kommunikation
- 4 spezialisierte Agenten: Recon, Exploit, Execution, C4
- Orchestrator: Koordiniert den gesamten Schwarm
- Strategies: Wissensbasis aus AI Kill Chain & Angriffsszenarien

Version: 1.0 — Februar 2026
"""

from swarm.blackboard import Blackboard
from swarm.agent_base import SwarmAgent, AgentRole, AgentStatus
from swarm.orchestrator import SwarmOrchestrator
