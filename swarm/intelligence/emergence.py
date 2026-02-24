"""
REDSWARM Emergence Detector — Cross-Agent Strategy Correlation
================================================================
Erkennt Muster und Strategien die aus den kombinierten Findings
mehrerer Agenten emergieren — Angriffspfade die kein einzelner
Agent hätte sehen können.

Funktionsweise:
  1. Sammelt alle Findings/Intel/Exploits vom Blackboard
  2. LLM-basierte Korrelationsanalyse
  3. Erkennt kombinierte Angriffspfade
  4. Postet emergente Strategien zurück aufs Blackboard
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from swarm.cognition.engine import CognitiveEngine

logger = logging.getLogger("RedTeam.Emergence")


@dataclass
class EmergentStrategy:
    """Eine emergente Strategie die aus Agent-Korrelation entsteht."""
    title: str = ""
    description: str = ""
    contributing_agents: list[str] = field(default_factory=list)
    contributing_findings: list[str] = field(default_factory=list)
    combined_attack_path: list[str] = field(default_factory=list)
    novel_insight: str = ""         # Was ist neu daran?
    estimated_impact: str = "medium"  # low | medium | high | critical
    confidence: float = 0.5
    recommended_actions: list[str] = field(default_factory=list)


CORRELATION_PROMPT = """Du bist der Emergenz-Detektor eines AI Red Team Schwarms.
Analysiere die Findings ALLER Agenten und finde Muster die KEIN einzelner
Agent hätte erkennen können.

AUFGABE: Suche nach kombinierten Angriffspfaden.
Beispiel: Agent A findet schwache Auth. Agent B findet offene Admin-API.
→ Kombiniert: Auth-Bypass + Admin-API = vollständiger Zugang.

ANTWORT-FORMAT (exakt dieses JSON):
{
  "emergent_strategies": [
    {
      "title": "Kombinierter Angriffspfad",
      "description": "Detaillierte Beschreibung",
      "contributing_agents": ["recon", "exploit"],
      "contributing_findings": ["finding_id_1", "finding_id_2"],
      "combined_attack_path": ["Schritt 1", "Schritt 2", "Schritt 3"],
      "novel_insight": "Was ist neu? Was hätte ein einzelner Agent nicht gesehen?",
      "estimated_impact": "critical",
      "confidence": 0.8,
      "recommended_actions": ["Aktion 1", "Aktion 2"]
    }
  ],
  "cross_agent_patterns": ["Muster 1", "Muster 2"],
  "blind_spots": ["Was fehlt noch?", "Welche Informationen braucht der Schwarm?"]
}"""


class EmergenceDetector:
    """
    Erkennt emergente Strategien aus Cross-Agent-Findings.
    Wird periodisch vom C4-Agenten aufgerufen.
    """

    def __init__(self, engine: CognitiveEngine):
        self.engine = engine
        self._detected_strategies: list[EmergentStrategy] = []
        self._analysis_count = 0

    async def analyze_findings(
        self,
        findings_by_agent: dict[str, list[dict]],
        target_info: str = "",
        previous_strategies: list[str] = None,
    ) -> list[EmergentStrategy]:
        """
        Analysiere Findings aller Agenten und erkenne emergente Strategien.

        Args:
            findings_by_agent: {"recon": [finding1, ...], "exploit": [...], ...}
            target_info: Informationen über das Ziel
            previous_strategies: Bereits erkannte Strategien (nicht wiederholen)

        Returns:
            Liste neu erkannter emergenter Strategien
        """
        if not self.engine.enabled:
            return []

        # Findings formatieren
        findings_text = ""
        for agent, findings in findings_by_agent.items():
            if not findings:
                continue
            findings_text += f"\n═══ {agent.upper()} FINDINGS ═══\n"
            for f in findings[-10:]:  # Max 10 pro Agent
                title = f.get("title", "")
                severity = f.get("severity", "info")
                vector = f.get("attack_vector", "")
                detail = f.get("details", f.get("content", ""))[:200]
                findings_text += f"  [{severity}] {title}"
                if vector:
                    findings_text += f" (Vektor: {vector})"
                if detail:
                    findings_text += f"\n    {detail}"
                findings_text += "\n"

        if not findings_text.strip():
            return []

        previous_str = ""
        if previous_strategies:
            previous_str = "\n\nBEREITS ERKANNTE STRATEGIEN (NICHT wiederholen):\n"
            previous_str += "\n".join(f"  - {s}" for s in previous_strategies[-5:])

        prompt = f"""ZIEL: {target_info or 'Unbekannt'}

FINDINGS ALLER AGENTEN:
{findings_text}
{previous_str}

Analysiere die Findings ALLER Agenten und finde emergente Angriffspfade
die kein einzelner Agent hätte erkennen können."""

        text, _ = await self.engine._call_llm(CORRELATION_PROMPT, prompt)
        data = self.engine._parse_json(text)

        strategies = []
        for s in data.get("emergent_strategies", []):
            strategy = EmergentStrategy(
                title=s.get("title", ""),
                description=s.get("description", ""),
                contributing_agents=s.get("contributing_agents", []),
                contributing_findings=s.get("contributing_findings", []),
                combined_attack_path=s.get("combined_attack_path", []),
                novel_insight=s.get("novel_insight", ""),
                estimated_impact=s.get("estimated_impact", "medium"),
                confidence=float(s.get("confidence", 0.5)),
                recommended_actions=s.get("recommended_actions", []),
            )
            strategies.append(strategy)
            self._detected_strategies.append(strategy)

        self._analysis_count += 1

        if strategies:
            logger.info(
                f"Emergenz-Analyse #{self._analysis_count}: "
                f"{len(strategies)} neue Strategien erkannt"
            )

        return strategies

    async def detect_chain_opportunity(
        self,
        findings: list[dict],
        target: str = "",
    ) -> list[dict]:
        """
        Tier-3 Integration: Erkennt Exploit-Chain-Opportunities aus
        korrelierenden Findings mehrerer Agenten.

        Args:
            findings: Liste von Finding-Dicts mit vulnerability, severity, target
            target: Optionaler Target-Filter

        Returns:
            Liste von Chain-Opportunities mit Schritten und Impact
        """
        if not findings or len(findings) < 2:
            return []

        # Findings nach Target gruppieren
        by_target: dict[str, list[dict]] = {}
        for f in findings:
            t = f.get("target", target or "unknown")
            by_target.setdefault(t, []).append(f)

        opportunities = []

        for t, target_findings in by_target.items():
            if len(target_findings) < 2:
                continue

            vuln_types = list(set(
                f.get("vulnerability", "") for f in target_findings if f.get("vulnerability")
            ))

            if len(vuln_types) < 2:
                continue

            # Bekannte Chain-Muster
            chain_patterns = [
                ({"ssrf", "lfi"}, "SSRF → LFI → Credential Access"),
                ({"sqli", "file_upload"}, "SQLi → File Upload → RCE"),
                ({"xss", "csrf"}, "XSS → CSRF → Account Takeover"),
                ({"prompt_injection", "data_exfiltration"}, "Prompt Injection → Data Exfiltration"),
                ({"system_prompt_extraction", "jailbreak"}, "Prompt Leak → Targeted Jailbreak"),
                ({"tool_abuse", "data_exfiltration"}, "Tool Abuse → Data Exfiltration"),
                ({"path_traversal", "command_injection"}, "LFI → Command Injection → RCE"),
            ]

            type_set = set(vuln_types)
            matched = [name for pat, name in chain_patterns if pat.issubset(type_set)]

            if matched:
                opportunities.append({
                    "target": t,
                    "chain_patterns": matched,
                    "vulnerabilities": vuln_types,
                    "finding_count": len(target_findings),
                    "estimated_impact": "critical" if len(matched) > 1 else "high",
                    "confidence": min(
                        0.9,
                        sum(f.get("confidence", 0.5) for f in target_findings) / len(target_findings)
                    ),
                })
            elif len(vuln_types) >= 3:
                opportunities.append({
                    "target": t,
                    "chain_patterns": [f"Multi-Vector: {' → '.join(vuln_types[:4])}"],
                    "vulnerabilities": vuln_types,
                    "finding_count": len(target_findings),
                    "estimated_impact": "high",
                    "confidence": 0.5,
                })

        if opportunities:
            logger.info(f"Chain-Opportunities: {len(opportunities)} erkannt")

        return opportunities

    def get_blind_spots(self) -> list[str]:
        """Was fehlt dem Schwarm noch? Welche Informationen werden gebraucht?"""
        blind = set()
        for s in self._detected_strategies:
            if s.confidence < 0.5:
                blind.add(f"Niedrige Confidence bei: {s.title}")
        return list(blind)

    def get_stats(self) -> dict:
        return {
            "total_analyses": self._analysis_count,
            "total_strategies": len(self._detected_strategies),
            "high_impact": sum(
                1 for s in self._detected_strategies
                if s.estimated_impact in ("high", "critical")
            ),
        }
