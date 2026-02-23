"""
REDSWARM — Recon Agent Wrapper
================================
HTTP-Service der den bestehenden ReconAgent wrapped.
Registriert sich automatisch beim Backend und
übersetzt Blackboard-Updates → HTTP-Events.
"""

import os
import sys
import asyncio
import logging

# Pfade
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "agents"))

from base_wrapper import create_agent_app, MissionPayload, send_update

logger = logging.getLogger("RedSwarm.Recon")

AGENT_ID     = "recon-v1"
AGENT_PORT   = int(os.getenv("AGENT_PORT", "8100"))

os.environ.setdefault("AGENT_BASE_URL", f"http://agent-recon:{AGENT_PORT}")


async def run_recon_agent(blackboard, payload: MissionPayload, bridge):
    """
    Startet den ReconAgent mit dem lokalen Blackboard.
    Der Agent schreibt auf das Blackboard, die Bridge übersetzt → Backend.
    """
    from swarm.agents.recon_agent import ReconAgent
    from config import AppConfig

    config = AppConfig()

    # Intensity → Scan Config
    if payload.intensity == "low":
        config.scan.delay_between_tests_sec = 3.0
    elif payload.intensity == "critical":
        config.scan.delay_between_tests_sec = 1.0

    # Agent erstellen
    agent = ReconAgent(
        name="recon",
        blackboard=blackboard,
        config=config,
    )

    # Initiale Tasks für den Agent erstellen
    targets = [{"url": payload.target_url, "type": payload.target_type}]
    for target in targets:
        blackboard.create_task(
            title=f"scan: {target['url']}",
            content=f"Vollständige Reconnaissance für {target['url']} (Typ: {target['type']})",
            author="c4",
            assigned_to="recon",
            priority=1,
            kill_chain_phase=1,
            target_system=target["url"],
            metadata={"target_type": target["type"], "scan_depth": payload.scan_depth},
        )

    # Progress: Gestartet
    await send_update(
        payload.update_url, payload.api_key, AGENT_ID,
        "progress", {"percent": 5, "current_task": "Reconnaissance wird initialisiert..."}
    )

    # Agent starten (läuft bis stop() oder Tasks fertig)
    agent_task = asyncio.create_task(agent.start())

    # Warten bis Agent fertig oder Timeout
    timeout = {"low": 300, "medium": 600, "high": 900, "critical": 1800}.get(payload.intensity, 600)

    try:
        # Periodisch prüfen ob der Agent noch arbeitet
        for elapsed in range(0, timeout, 5):
            await asyncio.sleep(5)

            # Prüfen ob noch Tasks offen sind
            pending = blackboard.get_pending_tasks()
            in_progress_tasks = blackboard.read(section="tasks", task_status="in_progress")

            if not pending and not in_progress_tasks and elapsed > 30:
                logger.info(f"[{AGENT_ID}] Keine offenen Tasks mehr nach {elapsed}s")
                break

            # Progress Update (geschätzt)
            total_tasks = len(blackboard.read(section="tasks", limit=500))
            done_tasks = len([t for t in blackboard.read(section="tasks", limit=500)
                            if getattr(t, 'task_status', '') in ('completed', 'failed')])
            if total_tasks > 0:
                pct = min(95, int((done_tasks / total_tasks) * 100))
                await send_update(
                    payload.update_url, payload.api_key, AGENT_ID,
                    "progress", {"percent": pct, "current_task": f"Tasks: {done_tasks}/{total_tasks}"}
                )

    except asyncio.CancelledError:
        pass
    finally:
        await agent.stop()
        agent_task.cancel()


# App erstellen
app = create_agent_app(
    agent_id=AGENT_ID,
    agent_name="Recon Agent",
    agent_desc="Kartiert die Angriffsfläche: Entry-Points, Fingerprinting, Vulnerability-Scanning, OSINT",
    agent_icon="🔭",
    capabilities=[
        "entry-point-discovery",
        "vulnerability-scan",
        "system-fingerprinting",
        "osint",
        "api-discovery",
        "js-analysis",
    ],
    target_types=["chatbot", "api", "agent", "rag", "webapp"],
    agent_factory=run_recon_agent,
    port=AGENT_PORT,
)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=AGENT_PORT)
