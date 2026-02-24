"""
REDSWARM Backend — FastAPI
==========================
Vollständig dynamisches Backend. Keine hardcodierten Agents oder Zieltypen.
Agents registrieren sich selbst. Die UI rendert nur was hier verfügbar ist.

Persistenz: SQLite (zero-config, überlebt Neustarts)
Live-Updates: WebSocket + optionales Redis

Kommunikationsfluss:
  1. Agents registrieren sich via POST /agents/register
  2. UI holt verfügbare Agents via GET /agents
  3. UI startet Mission via POST /missions
  4. Backend startet Agents als async Tasks
  5. Agents pushen Updates via POST /missions/{id}/update
  6. UI empfängt Live-Updates via WebSocket ws://.../missions/{id}/ws
"""

import asyncio
import json
import uuid
import subprocess
import sys
from datetime import datetime
from typing import Any, Optional
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from db import (
    async_init_db,
    async_save_agent, async_get_all_agents, async_get_agent,
    async_delete_agent, async_update_agent_status,
    async_save_mission, async_get_all_missions, async_get_mission,
)


# ─────────────────────────────────────────────
# CONFIG (via Env-Variablen in Produktion)
# ─────────────────────────────────────────────
import os
REDIS_URL   = os.getenv("REDIS_URL",   "redis://redis:6379")
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
API_KEY     = os.getenv("REDSWARM_API_KEY", "change-me-in-production")


# ─────────────────────────────────────────────
# STARTUP / SHUTDOWN
# ─────────────────────────────────────────────
redis_client: aioredis.Redis = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client

    # SQLite initialisieren (erstellt DB + Tabellen automatisch)
    await async_init_db()

    # Redis (optional — nur für Event-Replay)
    try:
        redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True)
        await redis_client.ping()
    except Exception:
        redis_client = None

    # Agents aus DB in Memory-Cache laden (für schnellen Zugriff während Missions)
    agents = await async_get_all_agents()
    for a in agents:
        _agent_cache[a["agent_id"]] = a

    # Missionen aus DB laden (nur laufende)
    missions = await async_get_all_missions()
    for m in missions:
        if m["status"] == "running":
            m["status"] = "interrupted"  # War noch "running" → Backend wurde neu gestartet
            await async_save_mission(m)
        active_missions[m["id"]] = m

    yield

    if redis_client:
        await redis_client.aclose()

app = FastAPI(title="AI Red Team Onion API", version="1.2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # In Produktion: nur eigene Domain
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# IN-MEMORY CACHES (backed by SQLite)
# ─────────────────────────────────────────────
_agent_cache:     dict[str, dict] = {}   # agent_id → AgentData (synced with DB)
active_missions:  dict[str, dict] = {}   # mission_id → MissionState
ws_connections:   dict[str, list[WebSocket]] = {}  # mission_id → [ws, ...]


# ─────────────────────────────────────────────
# SCHEMAS
# ─────────────────────────────────────────────

class AgentRegistration(BaseModel):
    """
    Jeder Agent registriert sich selbst mit diesen Daten.
    Die UI rendert daraus dynamisch die Agent-Auswahl.
    """
    agent_id:     str
    name:         str
    description:  str
    icon:         str
    capabilities: list[str]
    target_types: list[str]
    version:      str = "1.0.0"
    callback_url: Optional[str] = None


class MissionConfig(BaseModel):
    """
    Vollständig dynamisch — kein Feld ist auf spezifische Agents festgelegt.
    """
    name:         str
    target_url:   str
    target_type:  str
    intensity:    str
    agent_ids:    list[str]
    options:      dict[str, Any] = {}
    # Erweiterte Felder für Kill Chain
    scan_depth:       str = "standard"        # quick | standard | deep
    kill_chain_phases: list[int] = []         # [1,2,3,...] leer = auto
    attack_vectors:   list[str] = []          # [] = alle
    objective:        str = ""                # Freier Text für C4


class AgentUpdate(BaseModel):
    """
    Agents senden Live-Updates an das Backend.
    Das Backend broadcastet sie an alle WebSocket-Verbindungen der Mission.
    """
    agent_id:   str
    event_type: str   # "progress" | "finding" | "log" | "complete" | "error"
    payload:    dict[str, Any]


class UpdateAuth(BaseModel):
    api_key: str
    update:  AgentUpdate


class RelayMessage(BaseModel):
    """Inter-Agent Kommunikation über das Backend."""
    api_key:    str
    from_agent: str
    to_agent:   str
    subject:    str
    body:       str
    metadata:   dict[str, Any] = {}


# ─────────────────────────────────────────────
# WEBSOCKET BROADCAST HELPER
# ─────────────────────────────────────────────

async def broadcast(mission_id: str, event: dict):
    """Sendet ein Event an alle aktiven WS-Verbindungen dieser Mission."""
    dead = []
    for ws in ws_connections.get(mission_id, []):
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)
    for ws in dead:
        ws_connections[mission_id].remove(ws)

    # Auch in Redis pushen (für Replay bei neuer WS-Verbindung)
    if redis_client:
        try:
            await redis_client.rpush(
                f"mission:{mission_id}:events",
                json.dumps(event, default=str)
            )
            await redis_client.expire(f"mission:{mission_id}:events", 86400)
        except Exception:
            pass


# ─────────────────────────────────────────────
# AGENT REGISTRY ENDPOINTS
# ─────────────────────────────────────────────

@app.post("/agents/register", tags=["Agents"])
async def register_agent(reg: AgentRegistration):
    """
    Agents rufen diesen Endpoint beim Start auf.
    Danach erscheinen sie automatisch in der UI.
    Daten werden in SQLite persistiert (überlebt Neustarts).
    """
    data = reg.model_dump()
    data["registered_at"] = datetime.utcnow().isoformat()

    # In DB + Cache speichern
    await async_save_agent(data)
    _agent_cache[reg.agent_id] = data

    return {"status": "registered", "agent_id": reg.agent_id}


@app.get("/agents", tags=["Agents"])
async def list_agents():
    """UI holt diese Liste um die Agent-Auswahl dynamisch zu rendern."""
    return list(_agent_cache.values())


@app.delete("/agents/{agent_id}", tags=["Agents"])
async def unregister_agent(agent_id: str):
    if agent_id not in _agent_cache:
        raise HTTPException(404, "Agent nicht gefunden")

    # Aus DB + Cache löschen
    await async_delete_agent(agent_id)
    del _agent_cache[agent_id]

    return {"status": "unregistered"}


# ─────────────────────────────────────────────
# MISSION ENDPOINTS
# ─────────────────────────────────────────────

@app.post("/missions", tags=["Missions"])
async def create_mission(config: MissionConfig, background_tasks: BackgroundTasks):
    """Erstellt und startet eine Mission."""
    unknown = [aid for aid in config.agent_ids if aid not in _agent_cache]
    if unknown:
        raise HTTPException(400, f"Unbekannte Agents: {unknown}")

    mission_id = str(uuid.uuid4())
    mission = {
        "id":         mission_id,
        "config":     config.model_dump(),
        "status":     "running",
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
        "findings":   [],
        "logs":       [],
        "agent_states": {
            aid: {"progress": 0, "status": "pending", "current_task": ""}
            for aid in config.agent_ids
        },
    }
    active_missions[mission_id] = mission
    ws_connections[mission_id] = []

    # In DB persistieren
    await async_save_mission(mission)

    background_tasks.add_task(dispatch_agents, mission_id, config)

    return {"mission_id": mission_id, "status": "running"}


@app.get("/missions/{mission_id}", tags=["Missions"])
async def get_mission_endpoint(mission_id: str):
    if mission_id not in active_missions:
        raise HTTPException(404, "Mission nicht gefunden")
    return active_missions[mission_id]


@app.get("/missions", tags=["Missions"])
async def list_missions():
    return list(active_missions.values())


@app.post("/missions/{mission_id}/stop", tags=["Missions"])
async def stop_mission(mission_id: str):
    if mission_id not in active_missions:
        raise HTTPException(404, "Mission nicht gefunden")
    active_missions[mission_id]["status"] = "stopped"
    await async_save_mission(active_missions[mission_id])
    await broadcast(mission_id, {
        "event": "mission_stopped",
        "timestamp": datetime.utcnow().isoformat()
    })
    return {"status": "stopped"}


@app.get("/missions/{mission_id}/findings", tags=["Missions"])
async def get_mission_findings(mission_id: str):
    """Agents können die bisherigen Findings einer Mission abfragen (Inter-Agent Austausch)."""
    if mission_id not in active_missions:
        raise HTTPException(404, "Mission nicht gefunden")
    return active_missions[mission_id].get("findings", [])


@app.get("/missions/{mission_id}/agent-states", tags=["Missions"])
async def get_agent_states(mission_id: str):
    """Agents können den Status anderer Agents abfragen."""
    if mission_id not in active_missions:
        raise HTTPException(404, "Mission nicht gefunden")
    return active_missions[mission_id].get("agent_states", {})


# ─────────────────────────────────────────────
# AGENT UPDATE ENDPOINT (Agents → Backend)
# ─────────────────────────────────────────────

@app.post("/missions/{mission_id}/update", tags=["Missions"])
async def receive_agent_update(mission_id: str, body: UpdateAuth):
    """
    Agents rufen diesen Endpoint auf um Updates zu senden.
    Das Backend broadcastet sie an die UI via WebSocket.
    """
    if body.api_key != API_KEY:
        raise HTTPException(403, "Ungültiger API-Key")
    if mission_id not in active_missions:
        raise HTTPException(404, "Mission nicht gefunden")

    update = body.update
    mission = active_missions[mission_id]

    # Prüfen ob Mission gestoppt wurde
    if mission["status"] == "stopped":
        return {"status": "mission_stopped", "should_stop": True}

    event = {
        "event":      update.event_type,
        "agent_id":   update.agent_id,
        "payload":    update.payload,
        "timestamp":  datetime.utcnow().isoformat(),
    }

    # Mission-State aktualisieren
    if update.event_type == "progress":
        if update.agent_id in mission["agent_states"]:
            mission["agent_states"][update.agent_id].update({
                "progress":     update.payload.get("percent", 0),
                "status":       "running",
                "current_task": update.payload.get("current_task", ""),
            })

    elif update.event_type == "finding":
        finding = {
            "id":          str(uuid.uuid4()),
            "agent_id":    update.agent_id,
            "found_at":    datetime.utcnow().isoformat(),
            **update.payload,
        }
        mission["findings"].append(finding)

    elif update.event_type == "log":
        log_entry = {
            "agent_id": update.agent_id,
            "timestamp": datetime.utcnow().isoformat(),
            **update.payload,
        }
        mission["logs"].append(log_entry)
        # Nur letzte 500 Logs behalten
        if len(mission["logs"]) > 500:
            mission["logs"] = mission["logs"][-500:]

    elif update.event_type == "complete":
        if update.agent_id in mission["agent_states"]:
            mission["agent_states"][update.agent_id]["status"] = "done"
            mission["agent_states"][update.agent_id]["progress"] = 100
        # Alle done? → Mission complete
        all_done = all(
            s["status"] in ("done", "error")
            for s in mission["agent_states"].values()
        )
        if all_done:
            mission["status"] = "complete"
            mission["finished_at"] = datetime.utcnow().isoformat()
            await broadcast(mission_id, {
                "event": "mission_complete",
                "timestamp": datetime.utcnow().isoformat(),
                "payload": {
                    "total_findings": len(mission["findings"]),
                    "duration_seconds": (
                        datetime.fromisoformat(mission["finished_at"]) -
                        datetime.fromisoformat(mission["started_at"])
                    ).total_seconds()
                }
            })

    elif update.event_type == "error":
        if update.agent_id in mission["agent_states"]:
            mission["agent_states"][update.agent_id]["status"] = "error"

    # Mission in DB persistieren (nach jedem Update)
    await async_save_mission(mission)

    await broadcast(mission_id, event)
    return {"status": "ok", "should_stop": mission["status"] == "stopped"}


# ─────────────────────────────────────────────
# INTER-AGENT RELAY (Agent → Backend → Agent)
# ─────────────────────────────────────────────

@app.post("/missions/{mission_id}/relay", tags=["Missions"])
async def relay_message(mission_id: str, msg: RelayMessage):
    """
    Inter-Agent Kommunikation. Agent A sendet Nachricht an Agent B.
    Wird als spezielle log-Event an alle WS-Clients gebroadcastet
    und per HTTP an den Ziel-Agent weitergeleitet (falls callback_url vorhanden).
    """
    if msg.api_key != API_KEY:
        raise HTTPException(403, "Ungültiger API-Key")
    if mission_id not in active_missions:
        raise HTTPException(404, "Mission nicht gefunden")

    event = {
        "event": "relay",
        "from_agent": msg.from_agent,
        "to_agent": msg.to_agent,
        "payload": {
            "subject": msg.subject,
            "body": msg.body,
            "metadata": msg.metadata,
        },
        "timestamp": datetime.utcnow().isoformat(),
    }
    await broadcast(mission_id, event)

    # Optionales HTTP-Forward an Ziel-Agent
    target_agent = _agent_cache.get(msg.to_agent)
    if target_agent and target_agent.get("callback_url"):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    f"{target_agent['callback_url']}/relay",
                    json=event
                )
        except Exception:
            pass

    return {"status": "relayed"}


# ─────────────────────────────────────────────
# WEBSOCKET (Backend → UI Live-Stream)
# ─────────────────────────────────────────────

@app.websocket("/missions/{mission_id}/ws")
async def mission_websocket(ws: WebSocket, mission_id: str):
    await ws.accept()

    if mission_id not in active_missions:
        await ws.send_json({"event": "error", "message": "Mission nicht gefunden"})
        await ws.close()
        return

    # Alle bisherigen Events aus Redis replay-en (für späten Connect)
    if redis_client:
        try:
            past_events = await redis_client.lrange(f"mission:{mission_id}:events", 0, -1)
            for raw in past_events:
                await ws.send_json(json.loads(raw))
        except Exception:
            pass

    # Aktuellen State senden
    await ws.send_json({
        "event":   "state_sync",
        "payload": active_missions[mission_id],
        "timestamp": datetime.utcnow().isoformat(),
    })

    ws_connections[mission_id].append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        if ws in ws_connections.get(mission_id, []):
            ws_connections[mission_id].remove(ws)


# ─────────────────────────────────────────────
# AGENT DISPATCH (startet Agents via HTTP)
# ─────────────────────────────────────────────

async def dispatch_agents(mission_id: str, config: MissionConfig):
    """
    Ruft den callback_url jedes Agents auf um die Mission zu starten.
    Agents bekommen: mission_id, target, options, callback_url für Updates.
    """
    await broadcast(mission_id, {
        "event":     "mission_started",
        "payload":   {"agent_count": len(config.agent_ids)},
        "timestamp": datetime.utcnow().isoformat(),
    })

    async with httpx.AsyncClient(timeout=30.0) as client:
        tasks = []
        for agent_id in config.agent_ids:
            agent = _agent_cache.get(agent_id)
            if not agent or not agent.get("callback_url"):
                await broadcast(mission_id, {
                    "event": "log",
                    "agent_id": agent_id,
                    "payload": {"level": "warn", "message": f"Agent {agent_id} hat keine callback_url"},
                    "timestamp": datetime.utcnow().isoformat(),
                })
                continue

            payload = {
                "mission_id":       mission_id,
                "target_url":       config.target_url,
                "target_type":      config.target_type,
                "intensity":        config.intensity,
                "options":          config.options,
                "scan_depth":       config.scan_depth,
                "kill_chain_phases": config.kill_chain_phases,
                "attack_vectors":   config.attack_vectors,
                "objective":        config.objective,
                "update_url":       f"{BACKEND_URL}/missions/{mission_id}/update",
                "findings_url":     f"{BACKEND_URL}/missions/{mission_id}/findings",
                "relay_url":        f"{BACKEND_URL}/missions/{mission_id}/relay",
                "api_key":          API_KEY,
            }
            tasks.append(
                _dispatch_single_agent(client, agent_id, agent, payload, mission_id)
            )

        await asyncio.gather(*tasks, return_exceptions=True)


async def _dispatch_single_agent(client, agent_id, agent, payload, mission_id):
    """Einzelnen Agent starten mit Error-Handling."""
    try:
        resp = await client.post(f"{agent['callback_url']}/run", json=payload)
        if resp.status_code == 200:
            await broadcast(mission_id, {
                "event": "log",
                "agent_id": agent_id,
                "payload": {"level": "info", "message": f"Agent {agent_id} gestartet"},
                "timestamp": datetime.utcnow().isoformat(),
            })
        else:
            await broadcast(mission_id, {
                "event": "log",
                "agent_id": agent_id,
                "payload": {"level": "error", "message": f"Agent {agent_id} Start fehlgeschlagen: HTTP {resp.status_code}"},
                "timestamp": datetime.utcnow().isoformat(),
            })
    except Exception as e:
        await broadcast(mission_id, {
            "event": "log",
            "agent_id": agent_id,
            "payload": {"level": "error", "message": f"Agent {agent_id} nicht erreichbar: {str(e)[:100]}"},
            "timestamp": datetime.utcnow().isoformat(),
        })


# ─────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────

@app.get("/health")
async def health():
    redis_ok = False
    if redis_client:
        try:
            await redis_client.ping()
            redis_ok = True
        except Exception:
            pass
    return {
        "status": "ok",
        "redis": "connected" if redis_ok else "unavailable",
        "persistence": "sqlite",
        "agents": len(_agent_cache),
        "missions": len(active_missions),
        "active_missions": sum(1 for m in active_missions.values() if m["status"] == "running"),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
