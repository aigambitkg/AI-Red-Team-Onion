#!/usr/bin/env python3
"""
AI Red Team Scanner - Webhook Server
======================================
Ersetzt n8n komplett. Empfängt Webhooks von Notion Automations
und triggert Scans event-basiert.

Starten:
  uvicorn webhook_server:app --host 0.0.0.0 --port 8000

Oder:
  python webhook_server.py
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

# Projekt-Root zum Path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse

from config import AppConfig
from scanner import RedTeamScanner, ScanTarget
from reporting.notion_reporter import NotionReporter
from modules.api_client import APIConfig

# ─── Logging ────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("webhook_server.log"),
    ],
)
logger = logging.getLogger("RedTeam.Webhook")

# ─── Globals ────────────────────────────────────────────────
config = AppConfig()
active_scans: dict[str, dict] = {}  # page_id -> scan info


# ─── Lifespan ───────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/Shutdown-Logik"""
    logger.info("=" * 50)
    logger.info("🔴 AI Red Team Scanner - Webhook Server")
    logger.info("   Powered by AI-Gambit")
    logger.info("=" * 50)

    notion_key = os.getenv("NOTION_API_KEY")
    db_id = os.getenv("NOTION_DATABASE_ID")
    webhook_secret = os.getenv("WEBHOOK_SECRET", "")

    if not notion_key:
        logger.error("❌ NOTION_API_KEY nicht gesetzt!")
    if not db_id:
        logger.warning("⚠️  NOTION_DATABASE_ID nicht gesetzt (optional für Webhook-Modus)")
    if not webhook_secret:
        logger.warning("⚠️  WEBHOOK_SECRET nicht gesetzt — Webhook-Verifizierung deaktiviert")

    logger.info(f"✅ Server bereit. Warte auf Webhooks...")
    yield
    logger.info("Server wird gestoppt...")


# ─── App ────────────────────────────────────────────────────
app = FastAPI(
    title="AI Red Team Scanner",
    description="Webhook-Endpoint für Notion Automations",
    version="2.0",
    lifespan=lifespan,
)


# ─── Hilfsfunktionen ────────────────────────────────────────

def verify_webhook_signature(body: bytes, signature: str) -> bool:
    """Webhook-Signatur prüfen (optional, wenn WEBHOOK_SECRET gesetzt)"""
    secret = os.getenv("WEBHOOK_SECRET", "")
    if not secret:
        return True  # Keine Verifizierung wenn kein Secret

    expected = hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


def extract_page_id_from_payload(payload: dict) -> Optional[str]:
    """
    Page ID aus verschiedenen Webhook-Payload-Formaten extrahieren.

    Unterstützt:
    - Notion Automation Webhook: {"data": {"page_id": "..."}}
    - Einfacher Aufruf:         {"page_id": "..."}
    - Notion-Stil:              {"id": "..."}
    """
    # Direkt angegeben
    if "page_id" in payload:
        return payload["page_id"]

    # Notion Automation Format
    if "data" in payload:
        data = payload["data"]
        if isinstance(data, dict):
            return data.get("page_id") or data.get("id")

    # Fallback
    return payload.get("id")


async def run_scan_for_page(page_id: str) -> None:
    """
    Hauptlogik: Liest Notion-Seite, führt Scan durch, schreibt Ergebnisse zurück.
    Aktualisiert Notion in Echtzeit bei jedem Schritt.
    """
    notion_key = os.getenv("NOTION_API_KEY")
    db_id = os.getenv("NOTION_DATABASE_ID", "")

    if not notion_key:
        logger.error("NOTION_API_KEY nicht gesetzt")
        return

    reporter = NotionReporter(api_key=notion_key, database_id=db_id)

    # ─── Echtzeit-Fortschritt nach Notion pushen ─────────
    module_names = {
        "system_prompt_extraction": "System Prompt Extraction",
        "prompt_injection": "Prompt Injection",
        "jailbreak": "Jailbreak",
        "tool_abuse": "Tool Abuse",
        "data_exfiltration": "Data Exfiltration",
        "social_engineering": "Social Engineering",
    }
    total_modules = len(config.scan.modules)
    completed_modules = 0

    def update_notion_progress(status: str, detail: str):
        """Synchroner Helfer: Status + Detail in Notion schreiben"""
        try:
            reporter.update_scan_status(page_id, status, detail)
        except Exception as e:
            logger.warning(f"Notion-Update fehlgeschlagen: {e}")

    async def on_module_progress(progress_msg: str):
        """Callback für den Scanner — wird bei jedem Modul aufgerufen"""
        nonlocal completed_modules
        completed_modules += 1
        pct = int((completed_modules / total_modules) * 100) if total_modules else 0
        detail = f"[{completed_modules}/{total_modules}] {progress_msg} ({pct}%)"
        update_notion_progress("🔄 Läuft", detail)

    try:
        # Scan als aktiv markieren
        active_scans[page_id] = {
            "status": "running",
            "started_at": datetime.now().isoformat(),
            "current_step": "Initialisierung",
        }

        # ─── Phase 1: Initialisierung ───────────────────────
        update_notion_progress("🔄 Gestartet", "Lese Notion-Seite...")
        logger.info(f"📍 Scan gestartet für Page: {page_id}")

        # Seite aus Notion lesen
        import httpx
        async with httpx.AsyncClient(
            headers=reporter.headers, timeout=30.0
        ) as client:
            resp = await client.get(
                f"https://api.notion.com/v1/pages/{page_id}"
            )
            resp.raise_for_status()
            page = resp.json()

        props = page.get("properties", {})

        # URL extrahieren
        url = props.get("Target URL", {}).get("url", "")
        if not url:
            logger.error(f"Keine URL gefunden für Page {page_id}")
            update_notion_progress("❌ Fehler", "Keine Target URL in der Notion-Seite gefunden")
            reporter.reset_checkbox(page_id)
            return

        # Name extrahieren
        name_data = props.get("Name", {}).get("title", [])
        name = name_data[0]["plain_text"] if name_data else "Unknown Target"

        # Typ extrahieren
        type_data = props.get("Typ", {}).get("select", {})
        target_type = type_data.get("name", "chatbot") if type_data else "chatbot"

        type_map = {
            "Website Chatbot": "chatbot",
            "API Endpoint": "api",
            "Interner Agent": "both",
            "RAG System": "api",
            "Custom GPT": "chatbot",
        }
        mapped_type = type_map.get(target_type, "chatbot")

        # ─── Phase 2: Ziel erkannt ──────────────────────────
        update_notion_progress(
            "🔄 Läuft",
            f"Ziel: {name} | URL: {url} | Typ: {mapped_type} | Starte {total_modules} Module..."
        )
        active_scans[page_id]["current_step"] = f"Scanne {name}"

        # API-Config wenn nötig
        api_config = None
        api_url_prop = props.get("API URL", {})
        api_key_prop = props.get("API Key", {})

        if mapped_type in ("api", "both") or api_url_prop.get("url"):
            api_url = api_url_prop.get("url", url)
            api_key_text = ""
            if api_key_prop.get("rich_text"):
                api_key_text = api_key_prop["rich_text"][0].get("plain_text", "")

            model_prop = props.get("Model", {})
            model_text = ""
            if model_prop.get("rich_text"):
                model_text = model_prop["rich_text"][0].get("plain_text", "")

            api_type_prop = props.get("API Typ", {}).get("select", {})
            api_type = api_type_prop.get("name", "openai") if api_type_prop else "openai"

            api_config = APIConfig(
                base_url=api_url,
                api_key=api_key_text,
                model=model_text,
                api_type=api_type,
            )

        # ─── Phase 3: Scan durchführen ───────────────────────
        target = ScanTarget(
            name=name,
            url=url,
            target_type=mapped_type,
            api_config=api_config,
            notion_page_id=page_id,
        )

        logger.info(f"🎯 Scanne: {name} ({url}) [{mapped_type}]")

        scanner = RedTeamScanner(config)
        report = await scanner.scan(target, progress_callback=on_module_progress)

        # ─── Phase 4: Ergebnisse schreiben ───────────────────
        update_notion_progress(
            "📝 Schreibe Ergebnisse",
            f"Scan fertig: {report.total_vulnerabilities} Schwachstellen in {report.total_tests} Tests. Schreibe Bericht..."
        )

        reporter.update_scan_results(page_id, report)
        reporter.reset_checkbox(page_id)

        active_scans[page_id] = {
            "status": "completed",
            "finished_at": datetime.now().isoformat(),
            "vulnerabilities": report.total_vulnerabilities,
            "risk": report.overall_risk,
        }

        logger.info(
            f"✅ Scan abgeschlossen: {name} — "
            f"{report.total_vulnerabilities} Schwachstellen, "
            f"Risiko: {report.overall_risk}"
        )

    except Exception as e:
        logger.error(f"❌ Scan fehlgeschlagen für {page_id}: {e}", exc_info=True)
        try:
            update_notion_progress("❌ Fehlgeschlagen", f"Fehler: {str(e)[:500]}")
            reporter.reset_checkbox(page_id)
        except Exception:
            pass
        active_scans[page_id] = {
            "status": "failed",
            "error": str(e),
            "finished_at": datetime.now().isoformat(),
        }
    finally:
        reporter.close()


# ─── Endpoints ──────────────────────────────────────────────

@app.get("/")
async def root():
    """Root-Endpoint — zeigt an dass der Server läuft"""
    return {
        "service": "🔴 AI Red Team Scanner",
        "status": "running",
        "version": "2.0",
        "endpoints": {
            "webhook_notion": "POST /webhook/notion",
            "webhook_manual": "POST /webhook/scan",
            "status": "GET /status",
            "health": "GET /health",
        },
        "info": "Notion Automation Webhook → POST /webhook/notion",
    }


@app.post("/webhook/notion")
async def notion_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Haupt-Endpoint: Empfängt Webhook von Notion Automation.

    Notion Automation Setup:
    1. Datenbank öffnen → Automations (⚡ Icon)
    2. Trigger: "When property '🔴 Start Scan' changes to checked"
    3. Action: "Send webhook" → URL: https://dein-server:8000/webhook/notion
    """
    body = await request.body()

    # Optionale Signatur-Prüfung
    signature = request.headers.get("x-webhook-signature", "")
    if os.getenv("WEBHOOK_SECRET") and not verify_webhook_signature(body, signature):
        logger.warning("⚠️  Ungültige Webhook-Signatur")
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Payload parsen
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    logger.info(f"📨 Webhook empfangen: {json.dumps(payload, indent=2)[:500]}")

    # Page ID extrahieren
    page_id = extract_page_id_from_payload(payload)
    if not page_id:
        raise HTTPException(
            status_code=400,
            detail="Keine page_id im Payload gefunden"
        )

    # Prüfen ob bereits ein Scan läuft
    if page_id in active_scans and active_scans[page_id].get("status") == "running":
        return JSONResponse(
            status_code=409,
            content={
                "status": "already_running",
                "message": f"Scan für {page_id} läuft bereits",
            },
        )

    # Scan als Background Task starten
    background_tasks.add_task(run_scan_for_page, page_id)

    return {
        "status": "accepted",
        "page_id": page_id,
        "message": "Scan wird gestartet...",
    }


@app.post("/webhook/scan")
async def manual_scan(request: Request, background_tasks: BackgroundTasks):
    """
    Manueller Scan-Trigger via API.

    Beispiel:
      curl -X POST http://localhost:8000/webhook/scan \
        -H "Content-Type: application/json" \
        -d '{"page_id": "abc123..."}'
    """
    payload = await request.json()
    page_id = payload.get("page_id")

    if not page_id:
        raise HTTPException(status_code=400, detail="page_id erforderlich")

    background_tasks.add_task(run_scan_for_page, page_id)
    return {"status": "accepted", "page_id": page_id}


@app.get("/status")
async def get_status():
    """Server-Status und aktive Scans anzeigen"""
    return {
        "server": "running",
        "active_scans": len(
            [s for s in active_scans.values() if s.get("status") == "running"]
        ),
        "total_scans": len(active_scans),
        "scans": active_scans,
    }


@app.get("/status/{page_id}")
async def get_scan_status(page_id: str):
    """Status eines bestimmten Scans abfragen"""
    if page_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan nicht gefunden")
    return active_scans[page_id]


@app.get("/health")
async def health_check():
    """Health-Check für Monitoring"""
    notion_key = os.getenv("NOTION_API_KEY")
    return {
        "status": "healthy",
        "notion_configured": bool(notion_key),
        "timestamp": datetime.now().isoformat(),
    }


# ─── Direkt starten ────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")

    uvicorn.run(
        "webhook_server:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )
