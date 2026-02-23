"""
REDSWARM — Execution Agent Wrapper
=====================================
HTTP-Service der den bestehenden ExecutionAgent wrapped.
Liefert Exploits ans Ziel: Browser-Interaktion, API-Angriffe, Content Poisoning.
"""

import os
import sys
import asyncio
import logging

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "agents"))

from base_wrapper import create_agent_app, MissionPayload, send_update, get_mission_findings

logger = logging.getLogger("RedSwarm.Execution")

AGENT_ID   = "execution-v1"
AGENT_PORT = int(os.getenv("AGENT_PORT", "8102"))

os.environ.setdefault("AGENT_BASE_URL", f"http://agent-execution:{AGENT_PORT}")


async def run_execution_agent(blackboard, payload: MissionPayload, bridge):
    """
    Startet den ExecutionAgent. Holt Exploits vom Backend und führt sie aus.
    """
    from swarm.agents.execution_agent import ExecutionAgent
    from config import AppConfig

    config = AppConfig()

    # Headless Browser für Docker
    config.browser.headless = True
    config.browser.browser_type = "chromium"

    agent = ExecutionAgent(
        name="execution",
        blackboard=blackboard,
        config=config,
    )

    await send_update(
        payload.update_url, payload.api_key, AGENT_ID,
        "progress", {"percent": 5, "current_task": "Lade Exploits vom Backend..."}
    )

    # Exploit-Findings vom Backend holen und ins Blackboard einspeisen
    if payload.findings_url:
        findings = await get_mission_findings(payload.findings_url)
        exploit_count = 0
        for f in findings:
            if f.get("source_section") == "exploits" or "Exploit:" in f.get("title", ""):
                blackboard.post_exploit(
                    author="exploit",
                    title=f.get("title", "Imported Exploit"),
                    payload=f.get("evidence", f.get("description", "")),
                    attack_vector=f.get("attack_vector", "prompt_injection"),
                    target_system=payload.target_url,
                    confidence=f.get("confidence", 0.5),
                    priority={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                        f.get("severity", "MEDIUM"), 2
                    ),
                    metadata=f,
                )
                exploit_count += 1

        await send_update(
            payload.update_url, payload.api_key, AGENT_ID,
            "log", {"level": "info", "message": f"{exploit_count} Exploits importiert"}
        )

    # Falls keine Exploits vorhanden: Standard-Payloads als Tasks erstellen
    if not blackboard.read(section="exploits", limit=1):
        from payloads.attack_payloads import (
            PROMPT_INJECTION, JAILBREAK, SYSTEM_PROMPT_EXTRACTION
        )

        vectors = payload.attack_vectors or ["prompt_injection", "jailbreak"]
        for vector in vectors:
            payload_lib = {
                "prompt_injection": PROMPT_INJECTION,
                "jailbreak": JAILBREAK,
                "system_prompt_extraction": SYSTEM_PROMPT_EXTRACTION,
            }.get(vector, {})

            # Nur die ersten Payloads pro Kategorie
            for category, payloads_list in payload_lib.items():
                for p in payloads_list[:3]:
                    blackboard.post_exploit(
                        author="exploit",
                        title=f"Payload: {vector}/{category}",
                        payload=p,
                        attack_vector=vector,
                        target_system=payload.target_url,
                        confidence=0.4,
                        priority=2,
                    )

    await send_update(
        payload.update_url, payload.api_key, AGENT_ID,
        "progress", {"percent": 15, "current_task": "Exploitation gestartet"}
    )

    agent_task = asyncio.create_task(agent.start())

    timeout = {"low": 300, "medium": 600, "high": 1200, "critical": 2400}.get(payload.intensity, 600)

    try:
        for elapsed in range(0, timeout, 5):
            await asyncio.sleep(5)

            pending = blackboard.get_pending_tasks("execution")
            unexecuted_exploits = [e for e in blackboard.read(section="exploits", limit=500)
                                   if not any(r.references and e.id in r.references
                                            for r in blackboard.read(section="execution", limit=500))]

            if not pending and not unexecuted_exploits and elapsed > 30:
                logger.info(f"[{AGENT_ID}] Execution abgeschlossen nach {elapsed}s")
                break
    except asyncio.CancelledError:
        pass
    finally:
        await agent.stop()
        agent_task.cancel()


app = create_agent_app(
    agent_id=AGENT_ID,
    agent_name="Execution Agent",
    agent_desc="Liefert Angriffe ans Ziel: Browser-Interaktion, API-Attacks, Content Poisoning, Persistence",
    agent_icon="⚔️",
    capabilities=[
        "browser-exploitation",
        "api-attacks",
        "content-poisoning",
        "persistence-establishment",
        "multi-entry-point-testing",
    ],
    target_types=["chatbot", "api", "agent", "rag", "webapp"],
    agent_factory=run_execution_agent,
    port=AGENT_PORT,
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=AGENT_PORT)
