#!/usr/bin/env python3
"""
AI Red Team Scanner - Main Entry Point (v3.0)
===============================================
v3.0: Swarm-Modus mit Multi-Agent-Architektur, Blackboard, AI Kill Chain.
v2.0: Monitor-Dashboard, Kill-Switch, Browser-Reset, Validierung.

Nutzung:
  # Standalone mit Dashboard
  python main.py --mode scan --url https://example.com --type chatbot

  # SWARM-Modus (Multi-Agent Red Team)
  python main.py --mode swarm --url https://target.com --type chatbot
  python main.py --mode swarm --url https://target.com --type agent --scan-depth deep
  python main.py --mode swarm --url https://t1.com --url https://t2.com --type chatbot

  # Polling-Modus
  python main.py --mode poll

  # Über n8n
  python main.py --mode n8n --page-id <notion-page-id>

  # Dashboard deaktivieren
  python main.py --mode scan --url ... --no-dashboard

Kill-Switch:
  - Dashboard: NOTFALL STOP Button auf http://localhost:8080
  - Signal: kill -SIGUSR1 <PID>
  - File: echo "Grund" > /tmp/redteam_kill
"""

import argparse
import asyncio
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import AppConfig
from scanner import RedTeamScanner, ScanTarget
from reporting.notion_reporter import NotionReporter
from modules.api_client import APIConfig
from monitor.event_logger import EventLogger

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("red_team_scan.log"),
    ]
)
logger = logging.getLogger("RedTeam.Main")


def parse_args():
    parser = argparse.ArgumentParser(description="AI Red Team Scanner v2.0")
    parser.add_argument(
        "--mode", choices=["poll", "scan", "n8n", "swarm"],
        default="poll",
        help="Betriebsmodus (swarm = Multi-Agent Red Team)"
    )
    parser.add_argument("--url", action="append", help="Ziel-URL(s) — mehrfach angeben für Multi-Target")
    parser.add_argument("--type", choices=["chatbot", "api", "both", "agent", "rag"], default="chatbot")
    parser.add_argument("--page-id", help="Notion Page ID (n8n-Modus)")
    parser.add_argument("--scan-depth", choices=["quick", "standard", "deep"],
                        default="standard", help="Scan-Tiefe (Swarm-Modus)")
    parser.add_argument("--objective", default="Vollständige Sicherheitsanalyse",
                        help="Operationsziel (Swarm-Modus)")
    parser.add_argument("--swarm-timeout", type=int, default=30,
                        help="Swarm-Timeout in Minuten (Standard: 30)")
    parser.add_argument("--api-url", help="API-Endpoint URL")
    parser.add_argument("--api-key", help="API Key des Ziel-Systems")
    parser.add_argument("--api-type", choices=["openai", "anthropic", "custom"],
                        default="openai")
    parser.add_argument("--model", help="Model Name")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--no-api", action="store_true")
    parser.add_argument("--no-dashboard", action="store_true",
                        help="Dashboard deaktivieren")
    parser.add_argument("--dashboard-port", type=int, default=8080,
                        help="Dashboard Port (Standard: 8080)")

    # ── Knowledge Base CLI ────────────────────────────────────────────────────
    parser.add_argument("--kb-stats", action="store_true",
                        help="Knowledge Base Statistiken anzeigen")
    parser.add_argument("--kb-import", metavar="FILE",
                        help="JSON-Wissensdatenbank importieren (eigene KB / Community-Payloads)")
    parser.add_argument("--kb-export", metavar="FILE",
                        help="Knowledge Base als JSON exportieren")
    parser.add_argument("--kb-search", metavar="QUERY",
                        help="Knowledge Base durchsuchen (semantisch oder Text)")
    parser.add_argument("--kb-rebuild", action="store_true",
                        help="RAG-Vektorindex neu aufbauen")
    # ─────────────────────────────────────────────────────────────────────────
    return parser.parse_args()


def start_monitor(event_logger, args):
    """Dashboard starten wenn nicht deaktiviert"""
    if args.no_dashboard:
        logger.info("Dashboard deaktiviert")
        return None, None

    try:
        from monitor.dashboard import start_dashboard
        thread, server = start_dashboard(event_logger, port=args.dashboard_port)
        logger.info(f"📊 Dashboard: http://localhost:{args.dashboard_port}")
        return thread, server
    except Exception as e:
        logger.warning(f"Dashboard konnte nicht gestartet werden: {e}")
        return None, None


async def run_single_scan(args, config: AppConfig, event_logger: EventLogger) -> None:
    """Einzelnen Scan durchführen — erstellt automatisch Notion-Eintrag"""
    if not args.url:
        logger.error("--url ist erforderlich im scan-Modus")
        sys.exit(1)

    # --url ist jetzt eine Liste (action=append), erstes Element nehmen
    scan_url = args.url[0] if isinstance(args.url, list) else args.url

    notion_key = os.getenv("NOTION_API_KEY")
    db_id = os.getenv("NOTION_DATABASE_ID")
    reporter = None
    page_id = args.page_id  # Kann None sein

    # --- Notion: Seite erstellen oder existierende nutzen ---
    if notion_key and db_id:
        reporter = NotionReporter(api_key=notion_key, database_id=db_id)

        if not page_id:
            # Automatisch neue Seite in Notion erstellen
            scan_name = scan_url.replace("https://", "").replace("http://", "").rstrip("/")
            page_id = reporter.create_scan_page(
                name=scan_name,
                url=scan_url,
                target_type=args.type,
            )
            logger.info(f"📝 Notion-Seite erstellt: {scan_name} (ID: {page_id})")
        else:
            reporter.update_scan_status(page_id, "🔄 Läuft")

    api_config = None
    if args.api_url:
        api_config = APIConfig(
            base_url=args.api_url,
            api_key=args.api_key or "",
            model=args.model or "",
            api_type=args.api_type,
        )

    target = ScanTarget(
        name=f"CLI Scan: {scan_url}",
        url=scan_url,
        target_type=args.type,
        api_config=api_config,
        notion_page_id=page_id,
    )

    config.scan.enable_browser_tests = not args.no_browser
    config.scan.enable_api_tests = not args.no_api

    # --- Fortschritt an Notion senden ---
    async def progress_to_notion(msg):
        if reporter and page_id:
            try:
                reporter.update_scan_status(page_id, "🔄 Läuft", detail=msg)
            except Exception as e:
                logger.debug(f"Notion-Fortschritt fehlgeschlagen: {e}")

    scanner = RedTeamScanner(config, event_logger=event_logger)

    try:
        report = await scanner.scan(target, progress_callback=progress_to_notion)

        # Ergebnisse ausgeben
        print("\n" + "=" * 60)
        print(report.to_markdown())
        print("=" * 60)

        # Ergebnisse in Notion speichern
        if reporter and page_id:
            reporter.update_scan_results(page_id, report)
            logger.info(f"✅ Ergebnisse in Notion gespeichert (Page: {page_id})")

    except Exception as e:
        logger.error(f"Scan fehlgeschlagen: {e}")
        if reporter and page_id:
            try:
                reporter.update_scan_status(page_id, "❌ Fehlgeschlagen", detail=str(e))
            except Exception:
                pass
        raise
    finally:
        if reporter:
            reporter.close()


async def run_n8n_mode(args, config: AppConfig, event_logger: EventLogger) -> None:
    """Von n8n Workflow aufgerufen"""
    notion_key = os.getenv("NOTION_API_KEY")
    db_id = os.getenv("NOTION_DATABASE_ID")

    if not notion_key:
        logger.error("NOTION_API_KEY nicht gesetzt")
        sys.exit(1)
    if not args.page_id:
        logger.error("--page-id erforderlich")
        sys.exit(1)

    reporter = NotionReporter(api_key=notion_key, database_id=db_id or "")

    try:
        reporter.update_scan_status(args.page_id, "🔄 Läuft")

        import httpx
        resp = httpx.get(
            f"https://api.notion.com/v1/pages/{args.page_id}",
            headers=reporter.headers,
        )
        page = resp.json()
        props = page.get("properties", {})

        url = props.get("Target URL", {}).get("url", "")
        name_data = props.get("Name", {}).get("title", [])
        name = name_data[0]["plain_text"] if name_data else "Unknown"

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

        api_config = None
        if args.api_url or mapped_type in ("api", "both"):
            api_config = APIConfig(
                base_url=args.api_url or url,
                api_key=args.api_key or "",
                model=args.model or "",
                api_type=args.api_type or "openai",
            )

        target = ScanTarget(
            name=name, url=url, target_type=mapped_type,
            api_config=api_config, notion_page_id=args.page_id,
        )

        # Fortschritt an Notion senden
        async def progress_to_notion(msg):
            try:
                reporter.update_scan_status(args.page_id, "🔄 Läuft", detail=msg)
            except Exception:
                pass

        scanner = RedTeamScanner(config, event_logger=event_logger)
        report = await scanner.scan(target, progress_callback=progress_to_notion)

        reporter.update_scan_results(args.page_id, report)
        reporter.reset_checkbox(args.page_id)

        logger.info(f"✅ Scan abgeschlossen: {name}")
        print(f"Scan abgeschlossen: {report.total_vulnerabilities} Schwachstellen")

    except Exception as e:
        logger.error(f"Scan fehlgeschlagen: {e}")
        try:
            reporter.update_scan_status(args.page_id, "❌ Fehlgeschlagen")
        except Exception:
            pass
        raise
    finally:
        reporter.close()


async def run_polling_mode(config: AppConfig, event_logger: EventLogger) -> None:
    """Notion-Datenbank auf neue Scans überwachen"""
    notion_key = os.getenv("NOTION_API_KEY")
    db_id = os.getenv("NOTION_DATABASE_ID")

    if not notion_key or not db_id:
        logger.error("NOTION_API_KEY und NOTION_DATABASE_ID müssen gesetzt sein")
        sys.exit(1)

    reporter = NotionReporter(api_key=notion_key, database_id=db_id)

    logger.info(f"🔍 Polling-Modus gestartet (Intervall: {config.notion.poll_interval_seconds}s)")

    try:
        while True:
            try:
                pending = reporter.get_pending_scans()

                for scan_info in pending:
                    # Kill-Switch prüfen
                    if event_logger.check_kill_switch():
                        logger.warning("🛑 Kill-Switch aktiv — Polling gestoppt")
                        return

                    page_id = scan_info["page_id"]
                    url = scan_info["url"]
                    name = scan_info["name"]
                    target_type = scan_info["type"]

                    if not url:
                        continue

                    logger.info(f"📍 Neuer Scan: {name} ({url})")
                    reporter.update_scan_status(page_id, "🔄 Läuft")

                    type_map = {
                        "Website Chatbot": "chatbot",
                        "API Endpoint": "api",
                        "Interner Agent": "both",
                        "RAG System": "api",
                        "Custom GPT": "chatbot",
                    }

                    target = ScanTarget(
                        name=name, url=url,
                        target_type=type_map.get(target_type, "chatbot"),
                        notion_page_id=page_id,
                    )

                    # Neuer EventLogger pro Scan
                    scan_logger = EventLogger(log_dir="logs")

                    # Dashboard-Listener übertragen
                    for listener in event_logger._listeners:
                        scan_logger.add_listener(listener)
                    scan_logger.kill_switch = event_logger.kill_switch

                    async def progress_to_notion(msg):
                        try:
                            reporter.update_scan_status(page_id, "🔄 Läuft", detail=msg)
                        except Exception:
                            pass

                    try:
                        scanner = RedTeamScanner(config, event_logger=scan_logger)
                        report = await scanner.scan(target, progress_callback=progress_to_notion)
                        reporter.update_scan_results(page_id, report)
                        reporter.reset_checkbox(page_id)
                        logger.info(f"✅ {name}: {report.total_vulnerabilities} Schwachstellen")
                    except Exception as e:
                        logger.error(f"Scan fehlgeschlagen für {name}: {e}")
                        reporter.update_scan_status(page_id, "❌ Fehlgeschlagen")
                        reporter.reset_checkbox(page_id)

            except Exception as e:
                logger.error(f"Polling-Fehler: {e}")

            await asyncio.sleep(config.notion.poll_interval_seconds)

    except KeyboardInterrupt:
        logger.info("Polling gestoppt")
    finally:
        reporter.close()


async def run_swarm_mode(args, config: AppConfig, event_logger: EventLogger) -> None:
    """
    Swarm-Modus: Multi-Agent Red Team mit Blackboard-Architektur.
    Startet den vollständigen AI Kill Chain Schwarm.
    """
    from swarm.orchestrator import SwarmOrchestrator

    urls = args.url
    if not urls:
        logger.error("--url ist erforderlich im swarm-Modus")
        sys.exit(1)

    # Targets aus URLs bauen
    targets = [{"url": u, "type": args.type} for u in urls]

    logger.info(f"🐝 Swarm-Modus: {len(targets)} Ziel(e), Tiefe: {args.scan_depth}")

    orchestrator = SwarmOrchestrator(
        config=config,
        event_logger=event_logger,
    )

    try:
        result = await orchestrator.launch(
            targets=targets,
            objective=args.objective,
            scan_depth=args.scan_depth,
            timeout_minutes=args.swarm_timeout,
        )

        # Report ausgeben
        report_text = result.get("report", "Kein Bericht generiert")
        print("\n" + "=" * 60)
        print(report_text)
        print("=" * 60)

        # Dashboard-Daten
        dashboard = result.get("dashboard", {})
        timeline = result.get("timeline", [])

        print(f"\n📊 Dashboard: {dashboard.get('total_entries', 0)} Einträge")
        print(f"⏱️  Dauer: {result.get('duration_seconds', 0):.0f}s")
        print(f"🎯 Ziele: {len(targets)}")

        # Report als Datei speichern
        report_path = Path("logs") / f"swarm_report_{result['operation_id']}.md"
        report_path.parent.mkdir(exist_ok=True)
        report_path.write_text(report_text)
        logger.info(f"📄 Report gespeichert: {report_path}")

        # Notion-Integration (falls konfiguriert)
        notion_key = os.getenv("NOTION_API_KEY")
        db_id = os.getenv("NOTION_DATABASE_ID")
        if notion_key and db_id:
            try:
                reporter = NotionReporter(api_key=notion_key, database_id=db_id)
                for target in targets:
                    scan_name = f"SWARM: {target['url'].replace('https://', '').replace('http://', '').rstrip('/')}"
                    page_id = reporter.create_scan_page(
                        name=scan_name,
                        url=target["url"],
                        target_type=target["type"],
                    )
                    reporter.update_scan_status(page_id, "✅ Abgeschlossen",
                                                detail=f"Swarm Op: {result['operation_id']}")
                reporter.close()
                logger.info("📝 Swarm-Ergebnisse in Notion gespeichert")
            except Exception as e:
                logger.warning(f"Notion-Export fehlgeschlagen: {e}")

    except Exception as e:
        logger.error(f"Swarm-Fehler: {e}")
        raise


async def main():
    args = parse_args()
    config = AppConfig()

    if args.no_browser:
        config.scan.enable_browser_tests = False
    if args.no_api:
        config.scan.enable_api_tests = False

    # Banner je nach Modus
    if args.mode == "swarm":
        print(r"""
    ╔══════════════════════════════════════════════╗
    ║     🔴 AI RED TEAM SWARM v3.0                ║
    ║     Multi-Agent AI Security Framework        ║
    ║     ─────────────────────────────             ║
    ║     🐝 Recon · Exploit · Execution · C4      ║
    ║     📋 Blackboard-Architektur                ║
    ║     ⛓️  AI Kill Chain (6 Phasen)              ║
    ║     ─────────────────────────────             ║
    ║     Powered by AI-Gambit                     ║
    ╚══════════════════════════════════════════════╝
        """)
    else:
        print(r"""
    ╔══════════════════════════════════════════════╗
    ║     🔴 AI RED TEAM SCANNER v3.0              ║
    ║     AI Security Testing Framework            ║
    ║     ─────────────────────────────             ║
    ║     + Monitor Dashboard + Kill-Switch         ║
    ║     + False-Positive Validierung              ║
    ║     + Frischer Browser pro Modul              ║
    ║     + Swarm-Modus (--mode swarm)              ║
    ║     ─────────────────────────────             ║
    ║     Powered by AI-Gambit                     ║
    ╚══════════════════════════════════════════════╝
        """)

    # EventLogger + Dashboard starten
    event_logger = EventLogger(log_dir="logs")
    dashboard_thread, dashboard_server = start_monitor(event_logger, args)

    if dashboard_thread:
        print(f"    📊 Dashboard: http://localhost:{args.dashboard_port}")
        print(f"    🛑 Kill-Switch: Dashboard Button oder 'echo stop > /tmp/redteam_kill'")
        print()

    # ── Knowledge Base Befehle (ohne Scan) ───────────────────────────────────
    if args.kb_stats or args.kb_import or args.kb_export or args.kb_search or args.kb_rebuild:
        try:
            from knowledge.knowledge_base import KnowledgeBase
            kb = KnowledgeBase()

            if args.kb_stats:
                kb.print_stats()

            if args.kb_import:
                from pathlib import Path
                path = Path(args.kb_import)
                if not path.exists():
                    print(f"❌ Datei nicht gefunden: {path}")
                else:
                    count = kb.import_json(path)
                    print(f"✅ {count} Einträge importiert aus {path}")

            if args.kb_export:
                from pathlib import Path
                path = Path(args.kb_export)
                count = kb.export_json(path)
                print(f"✅ {count} Einträge exportiert nach {path}")

            if args.kb_search:
                results = kb.semantic_search(args.kb_search, limit=5)
                print(f"\n🔍 Suchergebnisse für '{args.kb_search}':")
                print("─" * 60)
                for r in results:
                    rate = f"{r.success_rate*100:.0f}%" if (r.success_count + r.fail_count) > 0 else "neu"
                    print(f"  [{r.severity}] [{rate}] {r.title[:60]}")
                    print(f"    Kategorie: {r.category}/{r.subcategory}")
                    print(f"    Zieltypen: {', '.join(r.target_types)}")
                    print(f"    {r.content[:150]}...")
                    print()
                if not results:
                    print("  Keine Treffer gefunden.")

            if args.kb_rebuild:
                count = kb.rebuild_rag_index()
                print(f"✅ RAG-Index neu aufgebaut: {count} Einträge indexiert")

        except ImportError:
            print("⚠️  Knowledge Base Modul nicht verfügbar.")
        return
    # ─────────────────────────────────────────────────────────────────────────

    if args.mode == "swarm":
        await run_swarm_mode(args, config, event_logger)
    elif args.mode == "scan":
        await run_single_scan(args, config, event_logger)
    elif args.mode == "n8n":
        await run_n8n_mode(args, config, event_logger)
    elif args.mode == "poll":
        await run_polling_mode(config, event_logger)


if __name__ == "__main__":
    asyncio.run(main())
