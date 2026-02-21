"""
AI Red Team Scanner - Notion Reporter
=======================================
Schreibt Scan-Ergebnisse zurück in die Notion-Datenbank.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


class NotionReporter:
    """
    Schreibt Scan-Ergebnisse in die Notion-Datenbank zurück.
    Aktualisiert sowohl die DB-Properties als auch den Seiteninhalt.
    """

    def __init__(self, api_key: str, database_id: str = ""):
        if not HAS_HTTPX:
            raise ImportError("httpx benötigt: pip install httpx")

        self.api_key = api_key
        self.database_id = database_id
        self.base_url = "https://api.notion.com/v1"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Notion-Version": "2022-06-28",
        }
        self.client = httpx.Client(headers=self.headers, timeout=30.0)

    def update_scan_status(self, page_id: str, status: str, detail: str = ""):
        """Status eines Scan-Eintrags aktualisieren mit optionalem Detail-Text"""
        properties = {
            "Status": {"select": {"name": status}},
        }

        # Live-Fortschritt in "Notizen"-Feld schreiben
        if detail:
            properties["Notizen"] = {
                "rich_text": [{
                    "text": {"content": detail[:2000]}
                }]
            }

        payload = {"properties": properties}
        response = self.client.patch(
            f"{self.base_url}/pages/{page_id}",
            json=payload,
        )
        response.raise_for_status()
        logger.info(f"Status aktualisiert: {status} | {detail}")

    def update_scan_results(self, page_id: str, report):
        """Vollständige Scan-Ergebnisse in Notion schreiben"""
        from datetime import datetime

        # Properties aktualisieren
        tested_vectors = []
        for mod in report.module_results:
            if mod.vulnerabilities_found > 0:
                # Modul-Name zu Multi-Select Wert mappen
                name_map = {
                    "System Prompt Extraction": "System Prompt Leak",
                    "Prompt Injection": "Prompt Injection",
                    "Jailbreak": "Jailbreak",
                    "Tool Abuse & Privilege Escalation": "Tool Abuse",
                    "Data Exfiltration": "Data Exfiltration",
                    "Social Engineering": "Social Engineering",
                }
                mapped = name_map.get(mod.module_name, mod.module_name)
                tested_vectors.append({"name": mapped})

        properties = {
            "Status": {"select": {"name": "✅ Abgeschlossen"}},
            "Risiko-Level": {"select": {"name": report.overall_risk}},
            "Schwachstellen gefunden": {"number": report.total_vulnerabilities},
            "Scan Datum": {
                "date": {"start": datetime.now().strftime("%Y-%m-%d")}
            },
            "Getestete Vektoren": {"multi_select": tested_vectors},
            "Notizen": {
                "rich_text": [{
                    "text": {
                        "content": (
                            f"{report.total_tests} Tests | "
                            f"{report.total_vulnerabilities} Schwachstellen | "
                            f"Risiko: {report.overall_risk} | "
                            f"Dauer: {report.duration_seconds:.0f}s"
                        )[:2000]
                    }
                }]
            },
        }

        response = self.client.patch(
            f"{self.base_url}/pages/{page_id}",
            json={"properties": properties},
        )
        response.raise_for_status()
        logger.info("Properties aktualisiert")

        # Seiteninhalt mit Markdown-Bericht aktualisieren
        self._update_page_content(page_id, report.to_markdown())

    def _update_page_content(self, page_id: str, markdown_content: str):
        """Seiteninhalt mit dem Scan-Bericht aktualisieren"""
        # Erst bestehende Blöcke löschen
        existing = self.client.get(
            f"{self.base_url}/blocks/{page_id}/children?page_size=100"
        )
        if existing.status_code == 200:
            for block in existing.json().get("results", []):
                try:
                    self.client.delete(f"{self.base_url}/blocks/{block['id']}")
                except Exception:
                    pass

        # Markdown in Notion-Blöcke konvertieren
        blocks = self._markdown_to_blocks(markdown_content)

        # In Batches von 100 hinzufügen (Notion API Limit)
        for i in range(0, len(blocks), 100):
            batch = blocks[i:i + 100]
            response = self.client.patch(
                f"{self.base_url}/blocks/{page_id}/children",
                json={"children": batch},
            )
            if response.status_code != 200:
                logger.error(f"Block-Update fehlgeschlagen: {response.text}")

        logger.info(f"Seiteninhalt aktualisiert ({len(blocks)} Blöcke)")

    def _markdown_to_blocks(self, markdown: str) -> list:
        """Einfacher Markdown-zu-Notion-Block Konverter"""
        blocks = []
        lines = markdown.split("\n")
        i = 0

        while i < len(lines):
            line = lines[i]

            # Überschriften
            if line.startswith("# "):
                blocks.append({
                    "object": "block",
                    "type": "heading_1",
                    "heading_1": {
                        "rich_text": [{"type": "text", "text": {"content": line[2:]}}]
                    }
                })
            elif line.startswith("## "):
                blocks.append({
                    "object": "block",
                    "type": "heading_2",
                    "heading_2": {
                        "rich_text": [{"type": "text", "text": {"content": line[3:]}}]
                    }
                })
            elif line.startswith("### "):
                blocks.append({
                    "object": "block",
                    "type": "heading_3",
                    "heading_3": {
                        "rich_text": [{"type": "text", "text": {"content": line[4:]}}]
                    }
                })
            elif line.startswith("---"):
                blocks.append({
                    "object": "block",
                    "type": "divider",
                    "divider": {}
                })
            elif line.startswith("- "):
                blocks.append({
                    "object": "block",
                    "type": "bulleted_list_item",
                    "bulleted_list_item": {
                        "rich_text": [{"type": "text", "text": {"content": line[2:][:2000]}}]
                    }
                })
            elif line.startswith("|") and "---|" not in line:
                # Tabelle als Code-Block (Notion unterstützt keine nativen Tabellen via API)
                table_lines = [line]
                while i + 1 < len(lines) and lines[i + 1].startswith("|"):
                    i += 1
                    if "---|" not in lines[i]:
                        table_lines.append(lines[i])
                content = "\n".join(table_lines)[:2000]
                blocks.append({
                    "object": "block",
                    "type": "code",
                    "code": {
                        "rich_text": [{"type": "text", "text": {"content": content}}],
                        "language": "plain text"
                    }
                })
            elif line.strip().startswith("**") and line.strip().endswith("**"):
                # Fettgedruckter Text als callout
                text = line.strip().strip("*")
                blocks.append({
                    "object": "block",
                    "type": "callout",
                    "callout": {
                        "rich_text": [{"type": "text", "text": {"content": text}}],
                        "icon": {"emoji": "⚡"}
                    }
                })
            elif line.strip():
                # Normaler Paragraph
                blocks.append({
                    "object": "block",
                    "type": "paragraph",
                    "paragraph": {
                        "rich_text": [{"type": "text", "text": {"content": line[:2000]}}]
                    }
                })
            i += 1

        return blocks

    def create_scan_page(self, name: str, url: str, target_type: str = "chatbot") -> str:
        """
        Erstellt eine neue Scan-Seite in der Notion-Datenbank.
        Gibt die neue Page-ID zurück.
        """
        # Typ mappen
        type_map = {
            "chatbot": "Website Chatbot",
            "api": "API Endpoint",
            "both": "Interner Agent",
        }
        notion_type = type_map.get(target_type, "Website Chatbot")

        payload = {
            "parent": {"database_id": self.database_id},
            "properties": {
                "Name": {
                    "title": [{"text": {"content": name}}]
                },
                "Target URL": {"url": url},
                "Status": {"select": {"name": "🔄 Läuft"}},
                "Typ": {"select": {"name": notion_type}},
                "Notizen": {
                    "rich_text": [{"text": {"content": "Scan gestartet..."}}]
                },
            },
        }

        response = self.client.post(
            f"{self.base_url}/pages",
            json=payload,
        )
        response.raise_for_status()
        page_id = response.json()["id"]
        logger.info(f"Neue Scan-Seite erstellt: {name} (ID: {page_id})")
        return page_id

    def get_pending_scans(self) -> list:
        """
        Holt alle Einträge aus der DB bei denen 'Start Scan' = true ist.
        Wird vom n8n Workflow oder dem Polling-Mechanismus aufgerufen.
        """
        payload = {
            "filter": {
                "property": "🔴 Start Scan",
                "checkbox": {"equals": True}
            }
        }

        response = self.client.post(
            f"{self.base_url}/databases/{self.database_id}/query",
            json=payload,
        )
        response.raise_for_status()

        results = []
        for page in response.json().get("results", []):
            props = page["properties"]
            name = ""
            url = ""
            target_type = ""

            # Title extrahieren
            title_prop = props.get("Name", {})
            if title_prop.get("title"):
                name = title_prop["title"][0]["plain_text"]

            # URL extrahieren
            url_prop = props.get("Target URL", {})
            url = url_prop.get("url", "")

            # Typ extrahieren
            type_prop = props.get("Typ", {})
            if type_prop.get("select"):
                target_type = type_prop["select"]["name"]

            results.append({
                "page_id": page["id"],
                "name": name,
                "url": url,
                "type": target_type,
            })

        logger.info(f"Gefunden: {len(results)} ausstehende Scans")
        return results

    def reset_checkbox(self, page_id: str):
        """Checkbox nach dem Scan zurücksetzen"""
        payload = {
            "properties": {
                "🔴 Start Scan": {"checkbox": False},
            }
        }
        self.client.patch(
            f"{self.base_url}/pages/{page_id}",
            json=payload,
        )

    def close(self):
        self.client.close()
