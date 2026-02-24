"""
REDSWARM Agent Memory — Episodisch, Semantisch, Prozedural
============================================================
Drei Gedächtnistypen die über die existierende Knowledge Base hinausgehen.

1. Episodisch: "Was ist passiert?" — Jede Aktion als Episode gespeichert
2. Semantisch: "Was weiß ich?" — Fakten über Ziele, Technologien, Muster
3. Prozedural: "Wie mache ich es?" — Erfolgreiche Aktionssequenzen

Persistenz: SQLite (überlebt Neustarts, cross-mission)
"""

import json
import sqlite3
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("RedTeam.Memory")


class MemoryType(Enum):
    EPISODIC   = "episodic"    # Was ist passiert?
    SEMANTIC   = "semantic"    # Was weiß ich?
    PROCEDURAL = "procedural"  # Wie mache ich es?


@dataclass
class Episode:
    """Eine einzelne Erinnerung / Episode."""
    id: str = ""
    memory_type: str = "episodic"
    agent_id: str = ""
    mission_id: str = ""

    # Was ist passiert?
    action: str = ""           # "Payload X gegen Ziel Y gesendet"
    target: str = ""           # Ziel-URL/System
    result: str = ""           # Ergebnis
    success: bool = False      # Erfolgreich?

    # Kontext
    attack_vector: str = ""    # prompt_injection, jailbreak, etc.
    kill_chain_phase: int = 0  # 1-6
    confidence: float = 0.5    # Wie sicher?
    tags: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    # Zeit
    timestamp: str = ""
    relevance_score: float = 1.0  # Sinkt über Zeit (Decay)


# ─────────────────────────────────────────────
# SCHEMA
# ─────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
    id              TEXT PRIMARY KEY,
    memory_type     TEXT NOT NULL DEFAULT 'episodic',
    agent_id        TEXT NOT NULL,
    mission_id      TEXT DEFAULT '',

    action          TEXT NOT NULL DEFAULT '',
    target          TEXT DEFAULT '',
    result          TEXT DEFAULT '',
    success         INTEGER DEFAULT 0,

    attack_vector   TEXT DEFAULT '',
    kill_chain_phase INTEGER DEFAULT 0,
    confidence      REAL DEFAULT 0.5,
    tags            TEXT DEFAULT '[]',
    metadata        TEXT DEFAULT '{}',

    timestamp       TEXT NOT NULL,
    relevance_score REAL DEFAULT 1.0,

    -- Für Prozedural: Sequenz von Aktionen
    procedure_steps TEXT DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_mem_agent ON memories(agent_id);
CREATE INDEX IF NOT EXISTS idx_mem_type ON memories(memory_type);
CREATE INDEX IF NOT EXISTS idx_mem_target ON memories(target);
CREATE INDEX IF NOT EXISTS idx_mem_vector ON memories(attack_vector);
CREATE INDEX IF NOT EXISTS idx_mem_success ON memories(success);
"""


class AgentMemory:
    """
    Persistentes Gedächtnis für einen Agenten.
    SQLite-basiert, überlebt Neustarts und Missions.
    """

    def __init__(self, agent_id: str, data_dir: str = ""):
        self.agent_id = agent_id
        self._data_dir = data_dir or str(
            Path(__file__).parent.parent.parent / "data"
        )
        Path(self._data_dir).mkdir(parents=True, exist_ok=True)
        self._db_path = str(Path(self._data_dir) / f"memory_{agent_id}.db")
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self):
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ─── STORE ───────────────────────────────────

    def remember(self, episode: Episode) -> str:
        """Speichere eine Erinnerung."""
        import uuid
        if not episode.id:
            episode.id = str(uuid.uuid4())
        if not episode.timestamp:
            episode.timestamp = datetime.utcnow().isoformat()
        if not episode.agent_id:
            episode.agent_id = self.agent_id

        self._conn.execute("""
            INSERT OR REPLACE INTO memories
                (id, memory_type, agent_id, mission_id, action, target, result,
                 success, attack_vector, kill_chain_phase, confidence, tags,
                 metadata, timestamp, relevance_score, procedure_steps)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            episode.id, episode.memory_type, episode.agent_id, episode.mission_id,
            episode.action, episode.target, episode.result,
            1 if episode.success else 0,
            episode.attack_vector, episode.kill_chain_phase, episode.confidence,
            json.dumps(episode.tags), json.dumps(episode.metadata),
            episode.timestamp, episode.relevance_score,
            json.dumps(episode.metadata.get("procedure_steps", [])),
        ))
        self._conn.commit()
        return episode.id

    def store_episode(
        self,
        action: str,
        target: str,
        result: str,
        success: bool,
        attack_vector: str = "",
        kill_chain_phase: int = 0,
        mission_id: str = "",
        metadata: dict = None,
    ) -> str:
        """Convenience: Episodische Erinnerung speichern."""
        return self.remember(Episode(
            memory_type="episodic",
            agent_id=self.agent_id,
            mission_id=mission_id,
            action=action,
            target=target,
            result=result[:2000],
            success=success,
            attack_vector=attack_vector,
            kill_chain_phase=kill_chain_phase,
            confidence=0.9 if success else 0.4,
            metadata=metadata or {},
        ))

    def store_knowledge(
        self,
        fact: str,
        target: str = "",
        tags: list[str] = None,
        confidence: float = 0.7,
    ) -> str:
        """Convenience: Semantisches Wissen speichern."""
        return self.remember(Episode(
            memory_type="semantic",
            agent_id=self.agent_id,
            action=fact,
            target=target,
            confidence=confidence,
            tags=tags or [],
        ))

    def store_procedure(
        self,
        title: str,
        steps: list[str],
        target_pattern: str = "",
        attack_vector: str = "",
        success_rate: float = 1.0,
    ) -> str:
        """Convenience: Prozedurales Wissen speichern."""
        return self.remember(Episode(
            memory_type="procedural",
            agent_id=self.agent_id,
            action=title,
            target=target_pattern,
            result=f"{len(steps)} Schritte",
            success=True,
            attack_vector=attack_vector,
            confidence=success_rate,
            metadata={"procedure_steps": steps},
        ))

    # ─── RECALL ──────────────────────────────────

    def _row_to_episode(self, row: sqlite3.Row) -> Episode:
        d = dict(row)
        return Episode(
            id=d["id"],
            memory_type=d["memory_type"],
            agent_id=d["agent_id"],
            mission_id=d.get("mission_id", ""),
            action=d["action"],
            target=d.get("target", ""),
            result=d.get("result", ""),
            success=bool(d.get("success", 0)),
            attack_vector=d.get("attack_vector", ""),
            kill_chain_phase=d.get("kill_chain_phase", 0),
            confidence=d.get("confidence", 0.5),
            tags=json.loads(d.get("tags", "[]")),
            metadata=json.loads(d.get("metadata", "{}")),
            timestamp=d.get("timestamp", ""),
            relevance_score=d.get("relevance_score", 1.0),
        )

    def recall(
        self,
        memory_type: str = "",
        target: str = "",
        attack_vector: str = "",
        success_only: bool = False,
        limit: int = 20,
        min_confidence: float = 0.0,
    ) -> list[Episode]:
        """
        Erinnere dich an relevante Episoden.

        Args:
            memory_type: Nur bestimmter Typ (episodic/semantic/procedural)
            target: Nur für bestimmtes Ziel
            attack_vector: Nur für bestimmten Angriffsvektor
            success_only: Nur erfolgreiche Aktionen
            limit: Max Ergebnisse
            min_confidence: Min Confidence-Score
        """
        conditions = ["agent_id = ?"]
        params: list = [self.agent_id]

        if memory_type:
            conditions.append("memory_type = ?")
            params.append(memory_type)
        if target:
            conditions.append("target LIKE ?")
            params.append(f"%{target}%")
        if attack_vector:
            conditions.append("attack_vector = ?")
            params.append(attack_vector)
        if success_only:
            conditions.append("success = 1")
        if min_confidence > 0:
            conditions.append("confidence >= ?")
            params.append(min_confidence)

        where = " AND ".join(conditions)
        rows = self._conn.execute(
            f"SELECT * FROM memories WHERE {where} "
            f"ORDER BY relevance_score DESC, timestamp DESC LIMIT ?",
            params + [limit]
        ).fetchall()
        return [self._row_to_episode(r) for r in rows]

    def recall_similar_targets(self, target: str, limit: int = 10) -> list[Episode]:
        """Erinnere an Erfahrungen mit ähnlichen Zielen."""
        from urllib.parse import urlparse
        domain = urlparse(target).netloc if "://" in target else target
        return self.recall(target=domain, limit=limit)

    def recall_successful_strategies(
        self, attack_vector: str = "", limit: int = 10
    ) -> list[Episode]:
        """Erinnere nur erfolgreiche Strategien."""
        return self.recall(
            memory_type="procedural",
            attack_vector=attack_vector,
            success_only=True,
            limit=limit,
        )

    def recall_failures(
        self, target: str = "", attack_vector: str = "", limit: int = 10
    ) -> list[Episode]:
        """Erinnere Fehlschläge (um sie nicht zu wiederholen)."""
        conditions = ["agent_id = ?", "success = 0", "memory_type = 'episodic'"]
        params: list = [self.agent_id]
        if target:
            conditions.append("target LIKE ?")
            params.append(f"%{target}%")
        if attack_vector:
            conditions.append("attack_vector = ?")
            params.append(attack_vector)

        rows = self._conn.execute(
            f"SELECT * FROM memories WHERE {' AND '.join(conditions)} "
            f"ORDER BY timestamp DESC LIMIT ?",
            params + [limit]
        ).fetchall()
        return [self._row_to_episode(r) for r in rows]

    # ─── DECAY & MAINTENANCE ────────────────────

    def decay_relevance(self, half_life_hours: float = 24.0):
        """
        Reduziere Relevanz älterer Erinnerungen (Vergessens-Kurve).
        Wird periodisch aufgerufen.
        """
        decay_factor = 0.5 ** (1.0 / max(half_life_hours, 1.0))
        self._conn.execute("""
            UPDATE memories
            SET relevance_score = MAX(relevance_score * ?, 0.01)
            WHERE agent_id = ? AND memory_type = 'episodic'
        """, (decay_factor, self.agent_id))
        self._conn.commit()

    def consolidate(self, max_episodes: int = 1000):
        """
        Konsolidiere alte episodische Erinnerungen.
        Behalte die relevantesten, lösche den Rest.
        """
        count = self._conn.execute(
            "SELECT COUNT(*) FROM memories WHERE agent_id = ? AND memory_type = 'episodic'",
            (self.agent_id,)
        ).fetchone()[0]

        if count > max_episodes:
            # Behalte Top-N nach Relevanz
            self._conn.execute("""
                DELETE FROM memories
                WHERE agent_id = ? AND memory_type = 'episodic'
                AND id NOT IN (
                    SELECT id FROM memories
                    WHERE agent_id = ? AND memory_type = 'episodic'
                    ORDER BY relevance_score DESC, timestamp DESC
                    LIMIT ?
                )
            """, (self.agent_id, self.agent_id, max_episodes))
            self._conn.commit()
            deleted = count - max_episodes
            logger.info(f"[{self.agent_id}] Memory konsolidiert: {deleted} Episoden gelöscht")

    # ─── STATS ──────────────────────────────────

    def get_stats(self) -> dict:
        row = self._conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN memory_type='episodic' THEN 1 ELSE 0 END) as episodic,
                SUM(CASE WHEN memory_type='semantic' THEN 1 ELSE 0 END) as semantic,
                SUM(CASE WHEN memory_type='procedural' THEN 1 ELSE 0 END) as procedural,
                SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) as successes,
                AVG(confidence) as avg_confidence
            FROM memories WHERE agent_id = ?
        """, (self.agent_id,)).fetchone()

        return {
            "agent_id": self.agent_id,
            "total_memories": row["total"],
            "episodic": row["episodic"],
            "semantic": row["semantic"],
            "procedural": row["procedural"],
            "successes": row["successes"],
            "avg_confidence": round(row["avg_confidence"] or 0, 3),
        }

    def format_for_context(self, memories: list[Episode], max_chars: int = 2000) -> str:
        """Formatiere Erinnerungen als LLM-Kontext-String."""
        lines = []
        chars = 0
        for m in memories:
            line = f"- [{m.memory_type}] {m.action}"
            if m.target:
                line += f" (Ziel: {m.target})"
            if m.result:
                line += f" → {m.result[:100]}"
            if m.success:
                line += " ✓"
            else:
                line += " ✗"

            if chars + len(line) > max_chars:
                break
            lines.append(line)
            chars += len(line) + 1

        return "\n".join(lines)
