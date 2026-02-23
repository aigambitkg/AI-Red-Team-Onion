"""
AI Red Team Swarm — Spezialisierte Agenten
============================================
4 Agenten mit klar definierten Rollen:
- ReconAgent: Aufklärung und Schwachstellen-Scanning
- ExploitAgent: Payload-Entwicklung und Angriffsvorbereitung
- ExecutionAgent: Angriffsausführung und Datenexfiltration
- C4Agent: Kommando, Kontrolle, Kommunikation, Koordination
"""

from swarm.agents.recon_agent import ReconAgent
from swarm.agents.exploit_agent import ExploitAgent
from swarm.agents.execution_agent import ExecutionAgent
from swarm.agents.c4_agent import C4Agent
