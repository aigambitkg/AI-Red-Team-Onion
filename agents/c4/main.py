"""
REDSWARM — C4 (Command & Control) Agent Wrapper
==================================================
HTTP-Service der den bestehenden C4Agent wrapped.
Strategische Koordination, Kill-Chain-Tracking, Report-Generierung.
"""

import os
import sys
import asyncio
import logging

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "agents"))

from base_wrapper import create_agent_app, MissionPayload, send_update, get_mission_findings

logger = logging.getLogger("RedSwarm.C4")

AGENT_ID   = "c4-v1"
AGENT_PORT = int(os.getenv("AGENT_PORT", "8103"))

os.environ.setdefault("AGENT_BASE_URL", f"http://agent-c4:{AGENT_PORT}")


async def run_c4_agent(blackboard, payload: MissionPayload, bridge):
    """
    Startet den C4 Agent. Koordiniert den Schwarm und generiert den Report.
    Im Dashboard-Modus: Überwacht die Mission und sendet strategische Updates.
    """
    from swarm.agents.c4_agent import C4Agent
    from swarm.strategies.kill_chain import get_phase, recommend_strategy
    from config import AppConfig

    config = AppConfig()
    agent = C4Agent(
        name="c4",
        blackboard=blackboard,
        config=config,
    )

    await send_update(
        payload.update_url, payload.api_key, AGENT_ID,
        "progress", {"percent": 5, "current_task": "Strategie wird festgelegt..."}
    )

    # Kill Chain Strategie definieren
    scan_depth = payload.scan_depth

    # Phasen basierend auf Scan-Tiefe
    phases_to_execute = {
        "quick":    [1],           # Nur Reconnaissance
        "standard": [1, 2, 3],     # Recon + Poisoning + Hijacking
        "deep":     [1, 2, 3, 4, 5, 6],  # Alles
    }.get(scan_depth, [1, 2, 3])

    # Überschreibe mit expliziten Phasen falls angegeben
    if payload.kill_chain_phases:
        phases_to_execute = payload.kill_chain_phases

    # Strategie ins Blackboard posten
    blackboard.post_strategy(
        author="c4",
        title=f"Operationsplan: {payload.objective or 'Sicherheitsanalyse'}",
        content=(
            f"Ziel: {payload.target_url}\n"
            f"Typ: {payload.target_type}\n"
            f"Tiefe: {scan_depth}\n"
            f"Phasen: {phases_to_execute}\n"
            f"Intensität: {payload.intensity}\n"
            f"Objective: {payload.objective or 'Vollständige Sicherheitsanalyse'}"
        ),
        priority=0,
        metadata={
            "target_url": payload.target_url,
            "target_type": payload.target_type,
            "scan_depth": scan_depth,
            "phases": phases_to_execute,
            "intensity": payload.intensity,
        },
    )

    await send_update(
        payload.update_url, payload.api_key, AGENT_ID,
        "log", {
            "level": "info",
            "message": f"Strategie festgelegt: {len(phases_to_execute)} Kill-Chain-Phasen, "
                       f"Tiefe: {scan_depth}, Ziel: {payload.target_url}"
        }
    )

    await send_update(
        payload.update_url, payload.api_key, AGENT_ID,
        "progress", {"percent": 10, "current_task": "Überwache Swarm-Operationen..."}
    )

    # C4 Agent starten
    agent_task = asyncio.create_task(agent.start())

    timeout = {"low": 300, "medium": 900, "high": 1800, "critical": 3600}.get(payload.intensity, 900)

    try:
        # C4 überwacht und wartet bis alle anderen Agents fertig sind
        for elapsed in range(0, timeout, 10):
            await asyncio.sleep(10)

            # Blackboard-Dashboard abrufen
            dashboard = blackboard.get_dashboard()
            total_entries = dashboard.get("total_entries", 0)

            # Findings vom Backend holen (Inter-Agent)
            if payload.findings_url:
                backend_findings = await get_mission_findings(payload.findings_url)
                critical_count = sum(1 for f in backend_findings
                                    if f.get("severity") in ("CRITICAL", "KRITISCH"))
                high_count = sum(1 for f in backend_findings
                               if f.get("severity") in ("HIGH", "HOCH"))
            else:
                backend_findings = []
                critical_count = 0
                high_count = 0

            # Progress Update basierend auf Phase
            phase_progress = min(90, 10 + (elapsed * 80 // timeout))
            await send_update(
                payload.update_url, payload.api_key, AGENT_ID,
                "progress", {
                    "percent": phase_progress,
                    "current_task": f"Monitoring: {total_entries} Einträge, "
                                   f"{critical_count} kritisch, {high_count} hoch"
                }
            )

            # Strategische Findings posten
            if critical_count > 3 and elapsed > 60:
                await send_update(
                    payload.update_url, payload.api_key, AGENT_ID,
                    "finding", {
                        "severity": "CRITICAL",
                        "title": "Schwerwiegende Sicherheitslücken erkannt",
                        "description": (
                            f"Der Schwarm hat {critical_count} kritische und {high_count} hohe "
                            f"Sicherheitslücken identifiziert. Sofortige Gegenmaßnahmen empfohlen."
                        ),
                        "source_section": "strategy",
                    }
                )

    except asyncio.CancelledError:
        pass
    finally:
        # Report generieren
        await send_update(
            payload.update_url, payload.api_key, AGENT_ID,
            "progress", {"percent": 95, "current_task": "Report wird generiert..."}
        )

        # Finalen Report als Finding senden
        all_findings = await get_mission_findings(payload.findings_url) if payload.findings_url else []
        report = _generate_report(payload, all_findings, phases_to_execute)

        await send_update(
            payload.update_url, payload.api_key, AGENT_ID,
            "finding", {
                "severity": "INFO",
                "title": "📋 Abschlussbericht",
                "description": report[:2000],
                "source_section": "strategy",
            }
        )

        await agent.stop()
        agent_task.cancel()


def _generate_report(payload: MissionPayload, findings: list[dict], phases: list[int]) -> str:
    """Generiert einen Markdown-Report aus den gesammelten Findings."""
    critical = [f for f in findings if f.get("severity") in ("CRITICAL", "KRITISCH")]
    high = [f for f in findings if f.get("severity") in ("HIGH", "HOCH")]
    medium = [f for f in findings if f.get("severity") in ("MEDIUM", "MITTEL")]
    low = [f for f in findings if f.get("severity") in ("LOW", "INFO")]

    lines = [
        f"# REDSWARM Abschlussbericht",
        f"",
        f"**Ziel:** {payload.target_url}",
        f"**Typ:** {payload.target_type}",
        f"**Intensität:** {payload.intensity}",
        f"**Scan-Tiefe:** {payload.scan_depth}",
        f"**Kill-Chain-Phasen:** {phases}",
        f"**Objective:** {payload.objective or 'Sicherheitsanalyse'}",
        f"",
        f"## Zusammenfassung",
        f"",
        f"- **{len(critical)} Kritisch** — Sofortiger Handlungsbedarf",
        f"- **{len(high)} Hoch** — Zeitnah beheben",
        f"- **{len(medium)} Mittel** — In nächstem Sprint beheben",
        f"- **{len(low)} Info/Niedrig** — Zur Kenntnis",
        f"",
        f"## Kritische Findings",
        f"",
    ]

    for f in critical[:10]:
        lines.append(f"### {f.get('title', 'Unbenannt')}")
        lines.append(f"{f.get('description', '')}")
        if f.get("evidence"):
            lines.append(f"**Evidence:** `{f['evidence'][:200]}`")
        lines.append("")

    if high:
        lines.append("## Hohe Findings")
        lines.append("")
        for f in high[:10]:
            lines.append(f"- **{f.get('title', '')}**: {f.get('description', '')[:150]}")
        lines.append("")

    return "\n".join(lines)


app = create_agent_app(
    agent_id=AGENT_ID,
    agent_name="C4 — Command & Control",
    agent_desc="Strategische Koordination: Kill-Chain-Planung, Swarm-Überwachung, Report-Generierung",
    agent_icon="🎯",
    capabilities=[
        "strategy-planning",
        "kill-chain-tracking",
        "swarm-coordination",
        "report-generation",
        "risk-assessment",
    ],
    target_types=["chatbot", "api", "agent", "rag", "webapp"],
    agent_factory=run_c4_agent,
    port=AGENT_PORT,
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=AGENT_PORT)
