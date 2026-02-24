"""
REDSWARM Persistence Layer — SQLite
====================================
Zero-Config Persistenz. Erstellt sich automatisch beim ersten Start.
Keine extra Dependencies (sqlite3 ist in Python eingebaut).

Nutzt asyncio.to_thread() für non-blocking DB-Zugriffe in FastAPI.
DB-Datei: ./data/redswarm.db (via Env-Variable konfigurierbar)
"""

import json
import os
import sqlite3
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
DB_DIR  = os.getenv("REDSWARM_DATA_DIR", "/app/data")
DB_FILE = os.path.join(DB_DIR, "redswarm.db")


# ─────────────────────────────────────────────
# SCHEMA (auto-created on init)
# ─────────────────────────────────────────────
_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id      TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    icon          TEXT NOT NULL DEFAULT '🤖',
    capabilities  TEXT NOT NULL DEFAULT '[]',
    target_types  TEXT NOT NULL DEFAULT '[]',
    version       TEXT NOT NULL DEFAULT '1.0.0',
    callback_url  TEXT,
    status        TEXT NOT NULL DEFAULT 'idle',
    base_url      TEXT,
    registered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS missions (
    id            TEXT PRIMARY KEY,
    config        TEXT NOT NULL DEFAULT '{}',
    status        TEXT NOT NULL DEFAULT 'running',
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    findings      TEXT NOT NULL DEFAULT '[]',
    logs          TEXT NOT NULL DEFAULT '[]',
    agent_states  TEXT NOT NULL DEFAULT '{}'
);
"""


def _get_conn() -> sqlite3.Connection:
    """Thread-lokale Connection. SQLite ist thread-safe mit check_same_thread=False."""
    Path(DB_DIR).mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # Bessere Concurrency
    conn.execute("PRAGMA busy_timeout=5000")  # 5s warten bei Lock
    # Tabellen immer sicherstellen (CREATE IF NOT EXISTS ist idempotent)
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


# Singleton connection (reused across calls)
_conn: Optional[sqlite3.Connection] = None


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = _get_conn()
    return _conn


# ─────────────────────────────────────────────
# INIT
# ─────────────────────────────────────────────

def init_db():
    """Erstellt DB-Verzeichnis und Tabellen. Idempotent."""
    _db()  # Connection erzeugen + Tabellen anlegen


async def async_init_db():
    await asyncio.to_thread(init_db)


# ─────────────────────────────────────────────
# AGENTS — CRUD
# ─────────────────────────────────────────────

def _agent_row_to_dict(row: sqlite3.Row) -> dict:
    """Konvertiert DB-Row → API-kompatibles Dict."""
    d = dict(row)
    d["capabilities"] = json.loads(d["capabilities"])
    d["target_types"] = json.loads(d["target_types"])
    return d


def save_agent(data: dict) -> None:
    conn = _db()
    conn.execute("""
        INSERT OR REPLACE INTO agents
            (agent_id, name, description, icon, capabilities, target_types,
             version, callback_url, status, base_url, registered_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["agent_id"],
        data["name"],
        data.get("description", ""),
        data.get("icon", "🤖"),
        json.dumps(data.get("capabilities", [])),
        json.dumps(data.get("target_types", [])),
        data.get("version", "1.0.0"),
        data.get("callback_url"),
        data.get("status", "idle"),
        data.get("base_url"),
        data.get("registered_at", datetime.utcnow().isoformat()),
    ))
    conn.commit()


def get_all_agents() -> list[dict]:
    rows = _db().execute("SELECT * FROM agents ORDER BY registered_at DESC").fetchall()
    return [_agent_row_to_dict(r) for r in rows]


def get_agent(agent_id: str) -> Optional[dict]:
    row = _db().execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    return _agent_row_to_dict(row) if row else None


def delete_agent(agent_id: str) -> bool:
    conn = _db()
    cursor = conn.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
    conn.commit()
    return cursor.rowcount > 0


def update_agent_status(agent_id: str, status: str) -> None:
    conn = _db()
    conn.execute("UPDATE agents SET status = ? WHERE agent_id = ?", (status, agent_id))
    conn.commit()


# Async wrappers
async def async_save_agent(data: dict):
    await asyncio.to_thread(save_agent, data)

async def async_get_all_agents() -> list[dict]:
    return await asyncio.to_thread(get_all_agents)

async def async_get_agent(agent_id: str) -> Optional[dict]:
    return await asyncio.to_thread(get_agent, agent_id)

async def async_delete_agent(agent_id: str) -> bool:
    return await asyncio.to_thread(delete_agent, agent_id)

async def async_update_agent_status(agent_id: str, status: str):
    await asyncio.to_thread(update_agent_status, agent_id, status)


# ─────────────────────────────────────────────
# MISSIONS — CRUD
# ─────────────────────────────────────────────

def _mission_row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["config"]       = json.loads(d["config"])
    d["findings"]     = json.loads(d["findings"])
    d["logs"]         = json.loads(d["logs"])
    d["agent_states"] = json.loads(d["agent_states"])
    return d


def save_mission(data: dict) -> None:
    conn = _db()
    conn.execute("""
        INSERT OR REPLACE INTO missions
            (id, config, status, started_at, finished_at,
             findings, logs, agent_states)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["id"],
        json.dumps(data.get("config", {})),
        data.get("status", "running"),
        data.get("started_at", datetime.utcnow().isoformat()),
        data.get("finished_at"),
        json.dumps(data.get("findings", [])),
        json.dumps(data.get("logs", [])[-500:]),  # Max 500 Logs
        json.dumps(data.get("agent_states", {})),
    ))
    conn.commit()


def get_all_missions() -> list[dict]:
    rows = _db().execute("SELECT * FROM missions ORDER BY started_at DESC").fetchall()
    return [_mission_row_to_dict(r) for r in rows]


def get_mission(mission_id: str) -> Optional[dict]:
    row = _db().execute("SELECT * FROM missions WHERE id = ?", (mission_id,)).fetchone()
    return _mission_row_to_dict(row) if row else None


def delete_mission(mission_id: str) -> bool:
    conn = _db()
    cursor = conn.execute("DELETE FROM missions WHERE id = ?", (mission_id,))
    conn.commit()
    return cursor.rowcount > 0


# Async wrappers
async def async_save_mission(data: dict):
    await asyncio.to_thread(save_mission, data)

async def async_get_all_missions() -> list[dict]:
    return await asyncio.to_thread(get_all_missions)

async def async_get_mission(mission_id: str) -> Optional[dict]:
    return await asyncio.to_thread(get_mission, mission_id)
