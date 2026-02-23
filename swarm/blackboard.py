"""
AI Red Team — Blackboard (Schwarzes Brett)
============================================
Gemeinsamer, thread-sicherer Informationsraum für alle Swarm-Agenten.

Das Blackboard ist das zentrale Nervensystem des Schwarms:
- Agenten schreiben Erkenntnisse, Aufgaben und Status
- Agenten lesen Erkenntnisse anderer Agenten
- Prioritäts-basierte Aufgabenwarteschlange
- Echtzeit-Benachrichtigungen bei neuen Einträgen
- Vollständige Protokollierung aller Aktivitäten

Sektionen des Blackboards:
- intel:        Aufklärungsergebnisse (Recon → alle)
- exploits:     Entwickelte Payloads (Exploit → Execution)
- execution:    Ausführungsprotokolle (Execution → C4)
- strategy:     Strategische Entscheidungen (C4 → alle)
- tasks:        Aufgabenwarteschlange (C4 → Agenten)
- comms:        Inter-Agent-Nachrichten (alle → alle)

Basiert auf dem Blackboard-Architekturmuster aus der KI-Forschung,
adaptiert für offensive Security-Operationen.
"""

import json
import sqlite3
import threading
import time
import uuid
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable

logger = logging.getLogger("RedTeam.Blackboard")


# ─── Enums ────────────────────────────────────────────────────────────────────

class Section(Enum):
    """Sektionen des Blackboards"""
    INTEL = "intel"
    EXPLOITS = "exploits"
    EXECUTION = "execution"
    STRATEGY = "strategy"
    TASKS = "tasks"
    COMMS = "comms"


class Priority(Enum):
    """Prioritätsstufen für Einträge"""
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4


class TaskStatus(Enum):
    """Status einer Aufgabe"""
    PENDING = "pending"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ─── Datenmodelle ─────────────────────────────────────────────────────────────

@dataclass
class BlackboardEntry:
    """Ein einzelner Eintrag auf dem Schwarzen Brett"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    section: str = ""                    # intel | exploits | execution | strategy | tasks | comms
    author: str = ""                     # Agent-Name (recon, exploit, execution, c4, operator)
    title: str = ""
    content: str = ""
    priority: int = 2                    # 0=CRITICAL ... 4=INFO
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)  # IDs anderer Einträge
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    # Task-spezifisch
    task_status: str = ""                # pending | assigned | in_progress | completed | failed
    assigned_to: str = ""                # Agent dem die Aufgabe zugewiesen ist
    # Angriffs-spezifisch
    kill_chain_phase: int = 0            # 1-6 (AI Kill Chain Phase)
    attack_vector: str = ""              # z.B. "prompt_injection", "tool_poisoning"
    target_system: str = ""              # Zielsystem-Identifikator
    confidence: float = 0.0              # 0.0 - 1.0 Konfidenz der Erkenntnis


@dataclass
class AgentMessage:
    """Nachricht zwischen Agenten"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sender: str = ""
    recipient: str = ""        # Agent-Name oder "all" für Broadcast
    message_type: str = ""     # request | response | alert | status | directive
    subject: str = ""
    body: str = ""
    priority: int = 2
    requires_response: bool = False
    in_reply_to: str = ""      # ID der Original-Nachricht
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


# ─── Blackboard ───────────────────────────────────────────────────────────────

class Blackboard:
    """
    Zentrales Schwarzes Brett für den AI Red Team Swarm.

    Thread-sicher, persistent (SQLite), mit Echtzeit-Benachrichtigungen.

    Verwendung:
        bb = Blackboard()
        bb.post(BlackboardEntry(section="intel", author="recon", title="Schwachstelle gefunden", ...))
        findings = bb.read(section="intel", kill_chain_phase=1)
        bb.subscribe("intel", callback_function)
    """

    def __init__(self, db_path: Optional[Path] = None, operation_id: str = ""):
        self.operation_id = operation_id or datetime.now().strftime("op_%Y%m%d_%H%M%S")
        self.db_path = db_path or Path(__file__).parent.parent / "knowledge_db" / "blackboard.sqlite3"
        self.db_path.parent.mkdir(exist_ok=True)
        self._lock = threading.RLock()
        self._subscribers: Dict[str, List[Callable]] = {}
        self._init_db()
        logger.info(f"Blackboard initialisiert: {self.db_path} (Operation: {self.operation_id})")

    def _init_db(self):
        """Datenbank-Schema erstellen"""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS entries (
                    id TEXT PRIMARY KEY,
                    operation_id TEXT,
                    section TEXT NOT NULL,
                    author TEXT NOT NULL,
                    title TEXT,
                    content TEXT,
                    priority INTEGER DEFAULT 2,
                    tags TEXT DEFAULT '[]',
                    "references" TEXT DEFAULT '[]',
                    metadata TEXT DEFAULT '{}',
                    created_at TEXT,
                    updated_at TEXT,
                    task_status TEXT DEFAULT '',
                    assigned_to TEXT DEFAULT '',
                    kill_chain_phase INTEGER DEFAULT 0,
                    attack_vector TEXT DEFAULT '',
                    target_system TEXT DEFAULT '',
                    confidence REAL DEFAULT 0.0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    operation_id TEXT,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    message_type TEXT,
                    subject TEXT,
                    body TEXT,
                    priority INTEGER DEFAULT 2,
                    requires_response INTEGER DEFAULT 0,
                    in_reply_to TEXT DEFAULT '',
                    timestamp TEXT,
                    metadata TEXT DEFAULT '{}',
                    read_by TEXT DEFAULT '[]'
                )
            """)
            # Indices für schnelle Abfragen
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_section ON entries(section)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_author ON entries(author)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_phase ON entries(kill_chain_phase)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_priority ON entries(priority)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_task ON entries(task_status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_op ON entries(operation_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipient)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_msg_op ON messages(operation_id)")
            conn.commit()

    # ─── SCHREIBEN ─────────────────────────────────────────────────────────────

    def post(self, entry: BlackboardEntry) -> str:
        """
        Eintrag auf das Schwarze Brett schreiben.
        Benachrichtigt alle Subscriber der betreffenden Sektion.
        """
        with self._lock:
            entry.updated_at = datetime.now().isoformat()
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO entries VALUES
                    (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    entry.id, self.operation_id, entry.section, entry.author,
                    entry.title, entry.content, entry.priority,
                    json.dumps(entry.tags), json.dumps(entry.references),
                    json.dumps(entry.metadata), entry.created_at, entry.updated_at,
                    entry.task_status, entry.assigned_to,
                    entry.kill_chain_phase, entry.attack_vector,
                    entry.target_system, entry.confidence
                ))

        # Subscriber benachrichtigen (Sektions-basiert)
        self._notify(entry.section, entry)

        # Event-basierte Benachrichtigungen (cross-section)
        if entry.section == "intel" and entry.priority <= 1:
            self._notify("intel_critical", entry)
        if entry.section == "exploits":
            self._notify("exploit_posted", entry)
        if entry.section == "execution" and entry.metadata.get("success"):
            self._notify("execution_success", entry)
        if entry.section == "execution" and not entry.metadata.get("success"):
            self._notify("execution_failed", entry)

        logger.debug(f"BB POST [{entry.section}] von {entry.author}: {entry.title}")
        return entry.id

    def send_message(self, msg: AgentMessage) -> str:
        """Nachricht zwischen Agenten senden"""
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    msg.id, self.operation_id, msg.sender, msg.recipient,
                    msg.message_type, msg.subject, msg.body,
                    msg.priority, int(msg.requires_response),
                    msg.in_reply_to, msg.timestamp,
                    json.dumps(msg.metadata), "[]"
                ))

        self._notify("comms", msg)
        logger.debug(f"BB MSG {msg.sender} → {msg.recipient}: {msg.subject}")
        return msg.id

    # ─── LESEN ──────────────────────────────────────────────────────────────────

    def read(
        self,
        section: str = None,
        author: str = None,
        kill_chain_phase: int = None,
        attack_vector: str = None,
        task_status: str = None,
        assigned_to: str = None,
        priority_max: int = None,
        tags: List[str] = None,
        limit: int = 50,
        since: str = None,
    ) -> List[BlackboardEntry]:
        """
        Einträge vom Schwarzen Brett lesen mit flexiblen Filtern.

        Args:
            section: Sektion filtern (intel, exploits, execution, strategy, tasks)
            author: Nach Autor filtern
            kill_chain_phase: Nach Kill-Chain-Phase filtern (1-6)
            attack_vector: Nach Angriffsvektor filtern
            task_status: Nach Aufgabenstatus filtern
            assigned_to: Nach zugewiesenem Agent filtern
            priority_max: Maximale Priorität (0=nur CRITICAL, 4=alle)
            tags: Nach Tags filtern (mindestens ein Tag muss matchen)
            limit: Maximale Anzahl Ergebnisse
            since: Nur Einträge nach diesem Zeitstempel
        """
        conditions = ["operation_id = ?"]
        params: list = [self.operation_id]

        if section:
            conditions.append("section = ?")
            params.append(section)
        if author:
            conditions.append("author = ?")
            params.append(author)
        if kill_chain_phase is not None:
            conditions.append("kill_chain_phase = ?")
            params.append(kill_chain_phase)
        if attack_vector:
            conditions.append("attack_vector = ?")
            params.append(attack_vector)
        if task_status:
            conditions.append("task_status = ?")
            params.append(task_status)
        if assigned_to:
            conditions.append("assigned_to = ?")
            params.append(assigned_to)
        if priority_max is not None:
            conditions.append("priority <= ?")
            params.append(priority_max)
        if since:
            conditions.append("created_at > ?")
            params.append(since)
        if tags:
            tag_conditions = " OR ".join(["tags LIKE ?" for _ in tags])
            conditions.append(f"({tag_conditions})")
            params.extend([f'%{t}%' for t in tags])

        where = " AND ".join(conditions)
        params.append(limit)

        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute(
                f"SELECT * FROM entries WHERE {where} ORDER BY priority ASC, created_at DESC LIMIT ?",
                params
            ).fetchall()

        return [self._row_to_entry(r) for r in rows]

    def get_messages(
        self,
        recipient: str = None,
        sender: str = None,
        unread_by: str = None,
        limit: int = 50,
    ) -> List[AgentMessage]:
        """Nachrichten lesen"""
        conditions = ["operation_id = ?"]
        params: list = [self.operation_id]

        if recipient:
            conditions.append("(recipient = ? OR recipient = 'all')")
            params.append(recipient)
        if sender:
            conditions.append("sender = ?")
            params.append(sender)
        if unread_by:
            conditions.append("read_by NOT LIKE ?")
            params.append(f'%{unread_by}%')

        where = " AND ".join(conditions)
        params.append(limit)

        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute(
                f"SELECT * FROM messages WHERE {where} ORDER BY priority ASC, timestamp DESC LIMIT ?",
                params
            ).fetchall()

        return [self._row_to_message(r) for r in rows]

    def mark_message_read(self, message_id: str, reader: str):
        """Nachricht als gelesen markieren"""
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute("SELECT read_by FROM messages WHERE id = ?", (message_id,)).fetchone()
            if row:
                readers = json.loads(row[0])
                if reader not in readers:
                    readers.append(reader)
                    conn.execute("UPDATE messages SET read_by = ? WHERE id = ?",
                                 (json.dumps(readers), message_id))

    # ─── AUFGABEN-MANAGEMENT ──────────────────────────────────────────────────

    def create_task(
        self,
        title: str,
        content: str,
        author: str = "c4",
        assigned_to: str = "",
        priority: int = 2,
        kill_chain_phase: int = 0,
        attack_vector: str = "",
        target_system: str = "",
        metadata: Dict = None,
    ) -> str:
        """Neue Aufgabe erstellen und auf dem Blackboard posten"""
        entry = BlackboardEntry(
            section="tasks",
            author=author,
            title=title,
            content=content,
            priority=priority,
            task_status=TaskStatus.PENDING.value,
            assigned_to=assigned_to,
            kill_chain_phase=kill_chain_phase,
            attack_vector=attack_vector,
            target_system=target_system,
            metadata=metadata or {},
            tags=["task", attack_vector] if attack_vector else ["task"],
        )
        return self.post(entry)

    def claim_task(self, task_id: str, agent_name: str) -> bool:
        """Agent beansprucht eine Aufgabe (atomare Operation)"""
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                row = conn.execute(
                    "SELECT task_status FROM entries WHERE id = ? AND section = 'tasks'",
                    (task_id,)
                ).fetchone()
                if row and row[0] == TaskStatus.PENDING.value:
                    conn.execute(
                        "UPDATE entries SET task_status = ?, assigned_to = ?, updated_at = ? WHERE id = ?",
                        (TaskStatus.ASSIGNED.value, agent_name, datetime.now().isoformat(), task_id)
                    )
                    return True
        return False

    def update_task(self, task_id: str, status: TaskStatus, result: str = "",
                    failure_reason: str = ""):
        """Aufgabenstatus aktualisieren (mit Failure-Tracking für Retries)"""
        with self._lock:
            now = datetime.now().isoformat()
            with sqlite3.connect(str(self.db_path)) as conn:
                # Retry-Count und Failure-Reason in metadata tracken
                row = conn.execute(
                    "SELECT metadata FROM entries WHERE id = ?", (task_id,)
                ).fetchone()
                if row:
                    meta = json.loads(row[0] or "{}")
                    if status == TaskStatus.FAILED:
                        meta["retry_count"] = meta.get("retry_count", 0) + 1
                        if failure_reason:
                            meta["failure_reason"] = failure_reason
                        meta.setdefault("failure_history", []).append({
                            "time": now, "reason": failure_reason or result[:200]
                        })
                    conn.execute(
                        "UPDATE entries SET task_status = ?, metadata = ?, "
                        "content = content || ?, updated_at = ? WHERE id = ?",
                        (status.value, json.dumps(meta),
                         f"\n\n--- {'RESULT' if status != TaskStatus.FAILED else 'FAILED'} ---\n{result}" if result else "",
                         now, task_id)
                    )
                else:
                    conn.execute(
                        "UPDATE entries SET task_status = ?, updated_at = ? WHERE id = ?",
                        (status.value, now, task_id)
                    )

        # Bei Failure: Event-Subscriber benachrichtigen
        if status == TaskStatus.FAILED:
            self._notify("task_failed", BlackboardEntry(
                id=task_id, section="tasks", task_status="failed",
                content=failure_reason or result, metadata={"task_id": task_id}
            ))

    def get_pending_tasks(self, agent_name: str = None) -> List[BlackboardEntry]:
        """Offene Aufgaben holen (optional: für einen bestimmten Agenten)"""
        if agent_name:
            return self.read(section="tasks", assigned_to=agent_name, task_status="pending")
        return self.read(section="tasks", task_status="pending")

    def get_failed_tasks(
        self, target_system: str = None, attack_vector: str = None, max_retries: int = 3
    ) -> List[BlackboardEntry]:
        """Fehlgeschlagene Tasks holen — für C4 Retry-Logik"""
        conditions = ["operation_id = ?", "section = 'tasks'", "task_status = 'failed'"]
        params: list = [self.operation_id]
        if target_system:
            conditions.append("target_system = ?")
            params.append(target_system)
        if attack_vector:
            conditions.append("attack_vector = ?")
            params.append(attack_vector)
        where = " AND ".join(conditions)
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute(
                f"SELECT * FROM entries WHERE {where} ORDER BY updated_at DESC LIMIT 50", params
            ).fetchall()
        entries = [self._row_to_entry(r) for r in rows]
        # Nur Tasks mit weniger als max_retries zurückgeben
        return [e for e in entries if e.metadata.get("retry_count", 0) < max_retries]

    # ─── INTEL & STRATEGIE ─────────────────────────────────────────────────────

    def post_intel(
        self,
        author: str,
        title: str,
        content: str,
        kill_chain_phase: int = 1,
        attack_vector: str = "",
        confidence: float = 0.5,
        priority: int = 2,
        target_system: str = "",
        tags: List[str] = None,
        metadata: Dict = None,
    ) -> str:
        """Aufklärungsergebnis posten (Convenience-Methode)"""
        entry = BlackboardEntry(
            section="intel",
            author=author,
            title=title,
            content=content,
            priority=priority,
            kill_chain_phase=kill_chain_phase,
            attack_vector=attack_vector,
            confidence=confidence,
            target_system=target_system,
            tags=tags or ["intel", attack_vector],
            metadata=metadata or {},
        )
        return self.post(entry)

    def post_exploit(
        self,
        author: str,
        title: str,
        payload: str,
        attack_vector: str,
        target_system: str = "",
        confidence: float = 0.5,
        priority: int = 2,
        based_on_intel: List[str] = None,
        metadata: Dict = None,
    ) -> str:
        """Entwickelten Exploit/Payload posten"""
        entry = BlackboardEntry(
            section="exploits",
            author=author,
            title=title,
            content=payload,
            priority=priority,
            attack_vector=attack_vector,
            target_system=target_system,
            confidence=confidence,
            references=based_on_intel or [],
            tags=["exploit", attack_vector],
            metadata=metadata or {},
        )
        return self.post(entry)

    def post_execution_result(
        self,
        author: str,
        title: str,
        result: str,
        success: bool,
        exploit_id: str = "",
        kill_chain_phase: int = 3,
        metadata: Dict = None,
    ) -> str:
        """Ausführungsergebnis posten"""
        entry = BlackboardEntry(
            section="execution",
            author=author,
            title=title,
            content=result,
            priority=0 if success else 2,
            kill_chain_phase=kill_chain_phase,
            references=[exploit_id] if exploit_id else [],
            tags=["execution", "success" if success else "failed"],
            confidence=1.0 if success else 0.0,
            metadata={**(metadata or {}), "success": success},
        )
        return self.post(entry)

    def post_strategy(
        self,
        author: str,
        title: str,
        content: str,
        priority: int = 1,
        metadata: Dict = None,
    ) -> str:
        """Strategische Entscheidung oder Direktive posten"""
        entry = BlackboardEntry(
            section="strategy",
            author=author,
            title=title,
            content=content,
            priority=priority,
            tags=["strategy", "directive"],
            metadata=metadata or {},
        )
        return self.post(entry)

    # ─── SUBSCRIBE / NOTIFY ────────────────────────────────────────────────────

    def subscribe(self, section: str, callback: Callable):
        """
        Auf neue Einträge in einer Sektion subscriben.
        Callback wird mit dem neuen Entry aufgerufen.
        """
        if section not in self._subscribers:
            self._subscribers[section] = []
        self._subscribers[section].append(callback)

    def unsubscribe(self, section: str, callback: Callable):
        if section in self._subscribers:
            self._subscribers[section] = [
                cb for cb in self._subscribers[section] if cb != callback
            ]

    def _notify(self, section: str, entry):
        """Subscriber benachrichtigen"""
        for callback in self._subscribers.get(section, []):
            try:
                callback(entry)
            except Exception as e:
                logger.error(f"Subscriber-Fehler in {section}: {e}")

    # ─── DASHBOARD / STATISTIK ─────────────────────────────────────────────────

    def get_dashboard(self) -> Dict[str, Any]:
        """
        Gibt eine Übersicht über den aktuellen Stand des Blackboards zurück.
        Perfekt für das Dashboard oder den C4-Agenten.
        """
        with sqlite3.connect(str(self.db_path)) as conn:
            op = self.operation_id

            total = conn.execute(
                "SELECT COUNT(*) FROM entries WHERE operation_id = ?", (op,)
            ).fetchone()[0]

            by_section = dict(conn.execute(
                "SELECT section, COUNT(*) FROM entries WHERE operation_id = ? GROUP BY section", (op,)
            ).fetchall())

            by_author = dict(conn.execute(
                "SELECT author, COUNT(*) FROM entries WHERE operation_id = ? GROUP BY author", (op,)
            ).fetchall())

            by_phase = dict(conn.execute(
                "SELECT kill_chain_phase, COUNT(*) FROM entries WHERE operation_id = ? AND kill_chain_phase > 0 GROUP BY kill_chain_phase",
                (op,)
            ).fetchall())

            pending_tasks = conn.execute(
                "SELECT COUNT(*) FROM entries WHERE operation_id = ? AND section = 'tasks' AND task_status = 'pending'",
                (op,)
            ).fetchone()[0]

            completed_tasks = conn.execute(
                "SELECT COUNT(*) FROM entries WHERE operation_id = ? AND section = 'tasks' AND task_status = 'completed'",
                (op,)
            ).fetchone()[0]

            critical_intel = conn.execute(
                "SELECT COUNT(*) FROM entries WHERE operation_id = ? AND section = 'intel' AND priority <= 1",
                (op,)
            ).fetchone()[0]

            successful_executions = conn.execute(
                "SELECT COUNT(*) FROM entries WHERE operation_id = ? AND section = 'execution' AND tags LIKE '%success%'",
                (op,)
            ).fetchone()[0]

            unread_messages = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE operation_id = ?", (op,)
            ).fetchone()[0]

        kill_chain_names = {
            1: "Reconnaissance", 2: "Poisoning", 3: "Hijacking",
            4: "Persistence", 5: "Iterate/Pivot", 6: "Impact"
        }

        return {
            "operation_id": self.operation_id,
            "total_entries": total,
            "by_section": by_section,
            "by_author": by_author,
            "kill_chain_coverage": {
                kill_chain_names.get(k, f"Phase {k}"): v
                for k, v in by_phase.items()
            },
            "tasks": {
                "pending": pending_tasks,
                "completed": completed_tasks,
            },
            "critical_intel": critical_intel,
            "successful_executions": successful_executions,
            "total_messages": unread_messages,
        }

    def get_attack_timeline(self, limit: int = 100) -> List[Dict]:
        """Chronologische Zeitleiste aller Aktionen"""
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute("""
                SELECT section, author, title, priority, kill_chain_phase,
                       attack_vector, confidence, created_at, tags
                FROM entries
                WHERE operation_id = ?
                ORDER BY created_at ASC
                LIMIT ?
            """, (self.operation_id, limit)).fetchall()

        return [
            {
                "section": r[0], "author": r[1], "title": r[2],
                "priority": r[3], "phase": r[4], "vector": r[5],
                "confidence": r[6], "time": r[7],
                "tags": json.loads(r[8] or "[]"),
            }
            for r in rows
        ]

    # ─── RESET & CLEANUP ──────────────────────────────────────────────────────

    def clear_operation(self):
        """Alle Daten der aktuellen Operation löschen"""
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("DELETE FROM entries WHERE operation_id = ?", (self.operation_id,))
                conn.execute("DELETE FROM messages WHERE operation_id = ?", (self.operation_id,))
                conn.commit()
        logger.info(f"Operation {self.operation_id} vom Blackboard gelöscht")

    # ─── INTERNES ──────────────────────────────────────────────────────────────

    def _row_to_entry(self, row) -> BlackboardEntry:
        return BlackboardEntry(
            id=row[0],
            # operation_id = row[1] (nicht im Entry)
            section=row[2], author=row[3], title=row[4], content=row[5],
            priority=row[6],
            tags=json.loads(row[7] or "[]"),
            references=json.loads(row[8] or "[]"),
            metadata=json.loads(row[9] or "{}"),
            created_at=row[10], updated_at=row[11],
            task_status=row[12], assigned_to=row[13],
            kill_chain_phase=row[14], attack_vector=row[15],
            target_system=row[16], confidence=row[17],
        )

    def _row_to_message(self, row) -> AgentMessage:
        return AgentMessage(
            id=row[0],
            # operation_id = row[1]
            sender=row[2], recipient=row[3],
            message_type=row[4], subject=row[5], body=row[6],
            priority=row[7], requires_response=bool(row[8]),
            in_reply_to=row[9], timestamp=row[10],
            metadata=json.loads(row[11] or "{}"),
        )
