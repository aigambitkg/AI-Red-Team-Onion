"""
REDSWARM Stigmergy — Digital Pheromone System
===============================================
Indirekte Kommunikation zwischen Agenten über "digitale Pheromone"
auf dem Blackboard — wie Ameisen die Pheromonspuren hinterlassen.

Pheromone-Typen:
  - interest:  "Hier ist etwas Vielversprechendes" → zieht Exploit-Agenten an
  - danger:    "Hier wurde ich erkannt/blockiert" → stößt Agenten ab
  - success:   "Dieser Vektor funktioniert" → verstärkt ähnliche Ansätze
  - explored:  "Hier war ich schon" → verhindert Doppelarbeit
  - priority:  "Das hier ist wichtig" → erhöht Bearbeitungs-Priorität

Mechanik:
  - Pheromone sind gewichtete Tags auf Blackboard-Entries
  - Decay: Pheromone verlieren über Zeit an Stärke
  - Agenten checken Pheromone-Scores bei Task-Auswahl
"""

import json
import sqlite3
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger("RedTeam.Stigmergy")


class PheromoneType(Enum):
    INTEREST = "interest"    # Vielversprechend
    DANGER   = "danger"      # Gefahr (erkannt/blockiert)
    SUCCESS  = "success"     # Erfolgreich
    EXPLORED = "explored"    # Bereits untersucht
    PRIORITY = "priority"    # Hohe Wichtigkeit


@dataclass
class Pheromone:
    """Ein einzelnes Pheromon."""
    id: str = ""
    pheromone_type: str = "interest"
    target: str = ""             # Ziel-URL/System/Vektor
    deposited_by: str = ""       # Agent der es hinterlassen hat
    strength: float = 1.0        # 0.0–1.0 (sinkt über Zeit)
    context: str = ""            # Warum wurde es hinterlassen?
    attack_vector: str = ""
    kill_chain_phase: int = 0
    metadata: dict = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS pheromones (
    id              TEXT PRIMARY KEY,
    pheromone_type  TEXT NOT NULL,
    target          TEXT NOT NULL,
    deposited_by    TEXT NOT NULL,
    strength        REAL NOT NULL DEFAULT 1.0,
    context         TEXT DEFAULT '',
    attack_vector   TEXT DEFAULT '',
    kill_chain_phase INTEGER DEFAULT 0,
    metadata        TEXT DEFAULT '{}',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pher_target ON pheromones(target);
CREATE INDEX IF NOT EXISTS idx_pher_type ON pheromones(pheromone_type);
CREATE INDEX IF NOT EXISTS idx_pher_strength ON pheromones(strength);
"""


class StigmergyEngine:
    """
    Digital Pheromone System für den Schwarm.
    Persistiert in SQLite (data/pheromones.db).
    """

    def __init__(self, data_dir: str = ""):
        self._data_dir = data_dir or str(Path(__file__).parent.parent.parent / "data")
        Path(self._data_dir).mkdir(parents=True, exist_ok=True)
        self._db_path = str(Path(self._data_dir) / "pheromones.db")
        self._conn: Optional[sqlite3.Connection] = None
        self._half_life_seconds = 3600  # 1 Stunde Halbwertszeit
        self._init_db()

    def _init_db(self):
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ─── DEPOSIT ────────────────────────────────

    def deposit(
        self,
        pheromone_type: PheromoneType,
        target: str,
        agent_id: str,
        strength: float = 1.0,
        context: str = "",
        attack_vector: str = "",
        kill_chain_phase: int = 0,
        metadata: dict = None,
    ) -> str:
        """
        Hinterlasse ein Pheromon.

        Args:
            pheromone_type: Art des Pheromons
            target: Ziel (URL, Vektor, System)
            agent_id: Wer hinterlässt es?
            strength: Stärke (0.0-1.0)
            context: Warum?

        Returns:
            Pheromon-ID
        """
        import uuid
        pid = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()

        # Check ob gleicher Agent schon ein Pheromon gleichen Typs für gleiches Ziel hat
        existing = self._conn.execute(
            "SELECT id, strength FROM pheromones WHERE pheromone_type=? AND target=? AND deposited_by=?",
            (pheromone_type.value, target, agent_id)
        ).fetchone()

        if existing:
            # Verstärke existierendes Pheromon
            new_strength = min(existing["strength"] + strength * 0.5, 1.0)
            self._conn.execute(
                "UPDATE pheromones SET strength=?, context=?, updated_at=? WHERE id=?",
                (new_strength, context, now, existing["id"])
            )
            self._conn.commit()
            return existing["id"]

        self._conn.execute("""
            INSERT INTO pheromones
                (id, pheromone_type, target, deposited_by, strength, context,
                 attack_vector, kill_chain_phase, metadata, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pid, pheromone_type.value, target, agent_id,
            min(strength, 1.0), context, attack_vector, kill_chain_phase,
            json.dumps(metadata or {}), now, now,
        ))
        self._conn.commit()

        logger.debug(f"[{agent_id}] Pheromon hinterlassen: {pheromone_type.value} → {target} ({strength:.2f})")
        return pid

    # ─── SENSE ──────────────────────────────────

    def sense(
        self,
        target: str = "",
        pheromone_type: PheromoneType = None,
        min_strength: float = 0.1,
        limit: int = 20,
    ) -> list[Pheromone]:
        """
        Nimm Pheromone in der Umgebung wahr.

        Args:
            target: Ziel filtern (Substring-Match)
            pheromone_type: Nur bestimmter Typ
            min_strength: Mindest-Stärke
            limit: Max Ergebnisse
        """
        conditions = ["strength >= ?"]
        params: list = [min_strength]

        if target:
            conditions.append("target LIKE ?")
            params.append(f"%{target}%")
        if pheromone_type:
            conditions.append("pheromone_type = ?")
            params.append(pheromone_type.value)

        where = " AND ".join(conditions)
        rows = self._conn.execute(
            f"SELECT * FROM pheromones WHERE {where} ORDER BY strength DESC LIMIT ?",
            params + [limit]
        ).fetchall()

        return [Pheromone(
            id=r["id"],
            pheromone_type=r["pheromone_type"],
            target=r["target"],
            deposited_by=r["deposited_by"],
            strength=r["strength"],
            context=r["context"],
            attack_vector=r["attack_vector"] if r["attack_vector"] else "",
            kill_chain_phase=r["kill_chain_phase"] if r["kill_chain_phase"] else 0,
            metadata=json.loads(r["metadata"]) if r["metadata"] else {},
            created_at=r["created_at"],
            updated_at=r["updated_at"],
        ) for r in rows]

    def get_attraction_score(self, target: str) -> float:
        """
        Berechne den Attraktions-Score eines Ziels.
        Hoher Score = Agent sollte sich auf dieses Ziel konzentrieren.

        Score = Σ(interest + success + priority) - Σ(danger + explored)
        """
        pheromones = self.sense(target=target, min_strength=0.01)

        positive = 0.0
        negative = 0.0

        for p in pheromones:
            if p.pheromone_type in ("interest", "success", "priority"):
                positive += p.strength
            elif p.pheromone_type in ("danger", "explored"):
                negative += p.strength * 0.7  # Danger/explored wiegen weniger

        return max(positive - negative, 0.0)

    # ─── DECAY ──────────────────────────────────

    def decay(self):
        """
        Reduziere alle Pheromone-Stärken (Vergessens-Effekt).
        Sollte periodisch aufgerufen werden (z.B. alle 60 Sekunden).
        """
        decay_factor = 0.95  # 5% Decay pro Aufruf
        self._conn.execute(
            "UPDATE pheromones SET strength = strength * ?, updated_at = ?",
            (decay_factor, datetime.utcnow().isoformat())
        )
        # Lösche schwache Pheromone
        self._conn.execute("DELETE FROM pheromones WHERE strength < 0.01")
        self._conn.commit()

    # ─── CONVENIENCE ────────────────────────────

    def mark_interesting(self, target: str, agent_id: str, context: str = "", **kwargs):
        """Markiere etwas als interessant (zieht andere Agenten an)."""
        self.deposit(PheromoneType.INTEREST, target, agent_id, 0.8, context, **kwargs)

    def mark_dangerous(self, target: str, agent_id: str, context: str = "", **kwargs):
        """Markiere als gefährlich (stößt Agenten ab)."""
        self.deposit(PheromoneType.DANGER, target, agent_id, 0.9, context, **kwargs)

    def mark_success(self, target: str, agent_id: str, context: str = "", **kwargs):
        """Markiere als erfolgreich (verstärkt ähnliche Ansätze)."""
        self.deposit(PheromoneType.SUCCESS, target, agent_id, 1.0, context, **kwargs)

    def mark_explored(self, target: str, agent_id: str, context: str = "", **kwargs):
        """Markiere als erkundet (verhindert Doppelarbeit)."""
        self.deposit(PheromoneType.EXPLORED, target, agent_id, 0.6, context, **kwargs)

    # ─── STATS ──────────────────────────────────

    def get_heatmap(self) -> list[dict]:
        """Liefert eine Heatmap aller aktiven Pheromone (für Dashboard)."""
        rows = self._conn.execute("""
            SELECT target,
                   SUM(CASE WHEN pheromone_type='interest' THEN strength ELSE 0 END) as interest,
                   SUM(CASE WHEN pheromone_type='danger' THEN strength ELSE 0 END) as danger,
                   SUM(CASE WHEN pheromone_type='success' THEN strength ELSE 0 END) as success,
                   SUM(CASE WHEN pheromone_type='explored' THEN strength ELSE 0 END) as explored,
                   COUNT(*) as total_pheromones
            FROM pheromones
            WHERE strength >= 0.05
            GROUP BY target
            ORDER BY (interest + success - danger - explored * 0.5) DESC
            LIMIT 50
        """).fetchall()

        return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        row = self._conn.execute("""
            SELECT COUNT(*) as total,
                   SUM(strength) as total_strength,
                   AVG(strength) as avg_strength
            FROM pheromones WHERE strength >= 0.01
        """).fetchone()

        return {
            "total_active": row["total"],
            "total_strength": round(row["total_strength"] or 0, 2),
            "avg_strength": round(row["avg_strength"] or 0, 3),
        }
