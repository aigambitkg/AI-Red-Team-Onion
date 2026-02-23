"""
Blackboard → HTTP Bridge
=========================
Übersetzt Blackboard-Einträge in HTTP-Updates für das REDSWARM-Backend.

Jeder Agent-Wrapper instanziiert eine BlackboardBridge.
Die Bridge pollt das lokale Blackboard alle 500ms und sendet
neue Einträge als Events an das Backend.

Mapping:
  - intel (Blackboard) → finding (Backend)
  - exploits → finding mit attack_vector
  - execution → finding mit success-Flag
  - tasks → log Events
  - comms (heartbeat) → progress Events
"""

import asyncio
import logging
from typing import Optional
from datetime import datetime

import httpx

logger = logging.getLogger("RedSwarm.Bridge")


# Blackboard-Priority → Severity Mapping
PRIORITY_TO_SEVERITY = {
    0: "CRITICAL",
    1: "HIGH",
    2: "MEDIUM",
    3: "LOW",
    4: "INFO",
}


class BlackboardBridge:
    """
    Pollt ein lokales Blackboard und sendet Updates an das REDSWARM-Backend.
    Hält Track welche Einträge bereits gesendet wurden (seen_ids).
    """

    def __init__(
        self,
        blackboard,
        agent_id: str,
        update_url: str,
        api_key: str,
        poll_interval: float = 0.5,
    ):
        self.bb = blackboard
        self.agent_id = agent_id
        self.update_url = update_url
        self.api_key = api_key
        self.poll_interval = poll_interval

        self._seen_ids: set[str] = set()
        self._running = False
        self._task_total = 0
        self._task_done = 0
        self._last_progress = -1

    async def start(self):
        """Startet den Polling-Loop als async Task."""
        self._running = True
        logger.info(f"[{self.agent_id}] Bridge gestartet → {self.update_url}")
        while self._running:
            try:
                await self._poll_cycle()
            except Exception as e:
                logger.warning(f"[{self.agent_id}] Bridge Poll-Fehler: {e}")
            await asyncio.sleep(self.poll_interval)

    def stop(self):
        """Stoppt den Polling-Loop."""
        self._running = False
        logger.info(f"[{self.agent_id}] Bridge gestoppt")

    async def _poll_cycle(self):
        """Ein einzelner Poll-Zyklus: liest alle Sections und sendet Neues."""
        # Intel → Findings
        await self._poll_section("intel", self._translate_intel)

        # Exploits → Findings
        await self._poll_section("exploits", self._translate_exploit)

        # Execution → Findings
        await self._poll_section("execution", self._translate_execution)

        # Tasks → Progress berechnen
        await self._poll_tasks()

        # Comms → Logs (nur relevante)
        await self._poll_section("comms", self._translate_comms)

    async def _poll_section(self, section: str, translator):
        """Liest eine Blackboard-Section und sendet neue Einträge."""
        try:
            entries = self.bb.read(section=section, limit=100)
        except Exception:
            return

        for entry in entries:
            if entry.id in self._seen_ids:
                continue
            self._seen_ids.add(entry.id)

            event_type, payload = translator(entry)
            if event_type and payload:
                await self._send_update(event_type, payload)

    def _translate_intel(self, entry) -> tuple[Optional[str], Optional[dict]]:
        """Blackboard Intel → Backend Finding."""
        severity = PRIORITY_TO_SEVERITY.get(entry.priority, "INFO")
        return "finding", {
            "severity":       severity,
            "title":          entry.title,
            "description":    entry.content[:500],
            "evidence":       str(entry.metadata.get("entry_point", ""))[:300] if entry.metadata else "",
            "attack_vector":  entry.attack_vector or "",
            "confidence":     entry.confidence,
            "kill_chain_phase": entry.kill_chain_phase,
            "tags":           entry.tags,
            "source_section": "intel",
        }

    def _translate_exploit(self, entry) -> tuple[Optional[str], Optional[dict]]:
        """Blackboard Exploit → Backend Finding."""
        severity = PRIORITY_TO_SEVERITY.get(entry.priority, "MEDIUM")
        return "finding", {
            "severity":       severity,
            "title":          f"Exploit: {entry.title}",
            "description":    f"Payload entwickelt: {entry.content[:300]}",
            "evidence":       entry.content[:200],
            "attack_vector":  entry.attack_vector or "",
            "confidence":     entry.confidence,
            "kill_chain_phase": entry.kill_chain_phase or 2,
            "source_section": "exploits",
        }

    def _translate_execution(self, entry) -> tuple[Optional[str], Optional[dict]]:
        """Blackboard Execution Result → Backend Finding."""
        success = entry.metadata.get("success", False) if entry.metadata else False
        severity = "CRITICAL" if success else "INFO"

        return "finding", {
            "severity":       severity,
            "title":          entry.title,
            "description":    entry.content[:500],
            "evidence":       entry.metadata.get("response_received", "")[:300] if entry.metadata else "",
            "attack_vector":  entry.attack_vector or "",
            "success":        success,
            "kill_chain_phase": entry.kill_chain_phase or 3,
            "source_section": "execution",
        }

    def _translate_comms(self, entry) -> tuple[Optional[str], Optional[dict]]:
        """Blackboard Comms → Backend Log (nur nicht-heartbeat)."""
        # Heartbeats ignorieren — Progress wird separat berechnet
        if entry.title and "heartbeat" in entry.title.lower():
            return None, None

        return "log", {
            "level":   "info",
            "message": f"[{entry.author}] {entry.title}: {entry.content[:200]}",
        }

    async def _poll_tasks(self):
        """Berechnet Fortschritt aus Task-Status und sendet Progress-Update."""
        try:
            all_tasks = self.bb.read(section="tasks", limit=500)
        except Exception:
            return

        if not all_tasks:
            return

        total = len(all_tasks)
        done = sum(1 for t in all_tasks
                    if getattr(t, 'task_status', '') in ('completed', 'failed'))

        self._task_total = total
        self._task_done = done

        # Fortschritt als Prozent
        if total > 0:
            pct = int((done / total) * 100)
        else:
            pct = 0

        # Nur senden wenn sich was geändert hat
        if pct != self._last_progress:
            self._last_progress = pct

            # Aktuelle Task finden
            in_progress = [t for t in all_tasks
                          if getattr(t, 'task_status', '') == 'in_progress']
            current_task = in_progress[0].title if in_progress else f"{done}/{total} Tasks"

            await self._send_update("progress", {
                "percent":      pct,
                "current_task": current_task,
            })

    async def _send_update(self, event_type: str, payload: dict):
        """Sendet ein Update an das REDSWARM-Backend."""
        body = {
            "api_key": self.api_key,
            "update": {
                "agent_id":   self.agent_id,
                "event_type": event_type,
                "payload":    payload,
            }
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(self.update_url, json=body)
                if resp.status_code == 200:
                    data = resp.json()
                    # Backend sagt uns ob Mission gestoppt wurde
                    if data.get("should_stop"):
                        logger.info(f"[{self.agent_id}] Mission gestoppt — Bridge wird beendet")
                        self._running = False
        except Exception as e:
            logger.debug(f"[{self.agent_id}] Update fehlgeschlagen: {e}")

    async def send_complete(self, summary: str = ""):
        """Sendet das Complete-Event an das Backend."""
        await self._send_update("complete", {
            "summary":        summary or f"{self._task_done} Tasks abgeschlossen",
            "total_findings": len(self._seen_ids),
            "total_tasks":    self._task_total,
        })

    async def send_error(self, message: str):
        """Sendet ein Error-Event an das Backend."""
        await self._send_update("error", {"message": message})
