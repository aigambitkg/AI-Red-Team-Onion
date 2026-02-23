"""
REDSWARM — Base Agent Wrapper
==============================
Gemeinsamer Code für alle Agent-Wrapper.
Jeder Agent-Service erbt von diesem Modul.

Aufgaben:
  1. FastAPI-App mit /run, /health, /relay Endpoints
  2. Startup: Registrierung beim REDSWARM-Backend
  3. /run: Erstellt Blackboard + Bridge, startet den Agent
  4. send_update() Helper für direkte Updates (ohne Bridge)

Jeder spezifische Agent-Wrapper importiert dieses Modul und
setzt nur: AGENT_ID, AGENT_NAME, AGENT_DESC, AGENT_ICON,
CAPABILITIES, TARGET_TYPES und die create_agent() Factory.
"""

import os
import sys
import asyncio
import logging
from typing import Any, Optional, Callable, Awaitable
from datetime import datetime

import httpx
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel

# Pfad zum Hauptprojekt hinzufügen (für swarm/, modules/, etc.)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

logger = logging.getLogger("RedSwarm.AgentWrapper")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)


# ─────────────────────────────────────────────
# ENVIRONMENT
# ─────────────────────────────────────────────
BACKEND_URL    = os.getenv("BACKEND_URL", "http://backend:8000")
AGENT_BASE_URL = os.getenv("AGENT_BASE_URL", "http://localhost:8100")
REDSWARM_KEY   = os.getenv("REDSWARM_API_KEY", "change-me-in-production")


# ─────────────────────────────────────────────
# SCHEMAS
# ─────────────────────────────────────────────

class MissionPayload(BaseModel):
    """Payload den das Backend an /run sendet."""
    mission_id:        str
    target_url:        str
    target_type:       str
    intensity:         str
    options:           dict[str, Any] = {}
    scan_depth:        str = "standard"
    kill_chain_phases: list[int] = []
    attack_vectors:    list[str] = []
    objective:         str = ""
    update_url:        str = ""
    findings_url:      str = ""
    relay_url:         str = ""
    api_key:           str = ""


class RelayEvent(BaseModel):
    """Inter-Agent Nachricht vom Backend."""
    event:      str
    from_agent: str
    to_agent:   str
    payload:    dict[str, Any]
    timestamp:  str = ""


# ─────────────────────────────────────────────
# HELPER: Updates ans Backend senden
# ─────────────────────────────────────────────

async def send_update(update_url: str, api_key: str, agent_id: str,
                      event_type: str, payload: dict) -> dict:
    """
    Sendet ein Update direkt an das Backend (ohne Bridge).

    event_type:
      "progress" → {"percent": 0-100, "current_task": "..."}
      "finding"  → {"severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "title": "...", ...}
      "log"      → {"level": "info|warn|error", "message": "..."}
      "complete" → {"summary": "..."}
      "error"    → {"message": "..."}
    """
    body = {
        "api_key": api_key,
        "update": {
            "agent_id":   agent_id,
            "event_type": event_type,
            "payload":    payload,
        }
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(update_url, json=body)
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        logger.debug(f"[{agent_id}] Update fehlgeschlagen: {e}")
    return {}


async def get_mission_findings(findings_url: str) -> list[dict]:
    """Holt die bisherigen Findings einer Mission (Inter-Agent Austausch)."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(findings_url)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return []


# ─────────────────────────────────────────────
# AGENT WRAPPER FACTORY
# ─────────────────────────────────────────────

def create_agent_app(
    agent_id: str,
    agent_name: str,
    agent_desc: str,
    agent_icon: str,
    capabilities: list[str],
    target_types: list[str],
    agent_factory: Callable,
    version: str = "1.0.0",
    port: int = 8100,
) -> FastAPI:
    """
    Erstellt eine vollständige FastAPI-App für einen Agent-Wrapper.

    agent_factory: async def(blackboard, payload, bridge) → Awaitable
        Funktion die den eigentlichen Agent startet.
        Bekommt: Blackboard-Instanz, MissionPayload, BlackboardBridge
    """

    app = FastAPI(title=agent_name)

    # Track laufende Missionen
    _active_missions: dict[str, dict] = {}

    @app.post("/run")
    async def handle_run(payload: MissionPayload, background_tasks: BackgroundTasks):
        """Backend ruft diesen Endpoint auf wenn eine Mission startet."""
        if payload.mission_id in _active_missions:
            return {"status": "already_running", "agent_id": agent_id}

        _active_missions[payload.mission_id] = {"status": "starting"}

        async def _run_agent():
            try:
                _active_missions[payload.mission_id]["status"] = "running"

                # Log: Agent gestartet
                await send_update(
                    payload.update_url, payload.api_key, agent_id,
                    "log", {"level": "info", "message": f"{agent_name} gestartet für {payload.target_url}"}
                )

                # Blackboard + Bridge erstellen
                from swarm.blackboard import Blackboard
                from backend.adapters.blackboard_bridge import BlackboardBridge

                bb = Blackboard(operation_id=payload.mission_id)

                bridge = BlackboardBridge(
                    blackboard=bb,
                    agent_id=agent_id,
                    update_url=payload.update_url,
                    api_key=payload.api_key,
                )

                # Bridge als parallelen Task starten
                bridge_task = asyncio.create_task(bridge.start())

                try:
                    # Agent starten (blockiert bis fertig oder gestoppt)
                    await agent_factory(bb, payload, bridge)
                except Exception as e:
                    logger.error(f"[{agent_id}] Agent-Fehler: {e}")
                    await bridge.send_error(str(e))
                finally:
                    # Bridge stoppen
                    bridge.stop()
                    await asyncio.sleep(1)  # Letzte Updates senden lassen
                    bridge_task.cancel()

                    # Complete senden
                    await bridge.send_complete()
                    _active_missions[payload.mission_id]["status"] = "done"

            except Exception as e:
                logger.error(f"[{agent_id}] Kritischer Fehler: {e}")
                _active_missions[payload.mission_id]["status"] = "error"
                try:
                    await send_update(
                        payload.update_url, payload.api_key, agent_id,
                        "error", {"message": str(e)}
                    )
                except Exception:
                    pass
            finally:
                # Aufräumen nach 60s
                await asyncio.sleep(60)
                _active_missions.pop(payload.mission_id, None)

        background_tasks.add_task(_run_agent)
        return {"status": "started", "agent_id": agent_id}

    @app.post("/relay")
    async def handle_relay(event: RelayEvent):
        """Inter-Agent Nachricht empfangen."""
        logger.info(f"[{agent_id}] Relay von {event.from_agent}: {event.payload.get('subject', '?')}")
        return {"status": "received"}

    @app.get("/health")
    async def health():
        active = sum(1 for m in _active_missions.values() if m["status"] == "running")
        return {
            "agent_id": agent_id,
            "status": "ready",
            "active_missions": active,
        }

    @app.on_event("startup")
    async def startup():
        """Beim Start beim Backend registrieren."""
        registration = {
            "agent_id":     agent_id,
            "name":         agent_name,
            "description":  agent_desc,
            "icon":         agent_icon,
            "capabilities": capabilities,
            "target_types": target_types,
            "version":      version,
            "callback_url": AGENT_BASE_URL,
        }
        for attempt in range(20):
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    r = await client.post(
                        f"{BACKEND_URL}/agents/register",
                        json=registration
                    )
                    if r.status_code == 200:
                        logger.info(f"[{agent_id}] ✓ Registriert beim Backend ({BACKEND_URL})")
                        return
            except Exception:
                pass
            logger.info(f"[{agent_id}] Backend nicht erreichbar, Retry {attempt+1}/20...")
            await asyncio.sleep(3)
        logger.error(f"[{agent_id}] ✗ Konnte sich nicht registrieren nach 20 Versuchen")

    return app
