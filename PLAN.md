# PRIO 1: Dashboard-Integration — Implementierungsplan

## Hauptziel
Die zwei getrennten Welten (CLI/Swarm-System + Dashboard-System) zu einer integrierten Lösung zusammenführen, sodass ein Non-Coder nach `docker compose up -d` ein funktionierendes Dashboard mit echten Agents hat.

## Architektur-Entscheidungen
- **Wrapper-Approach**: Jeder bestehende Swarm-Agent bekommt einen HTTP-Wrapper-Service
- **Frontend**: Eigenständiger Vite/React-Build
- **Bestehender Code bleibt erhalten** — keine Rewrites der Agent-Logik

---

## Ziel-Projektstruktur

```
ai_red_team/
├── docker-compose.yml              ← NEU (ersetzt alten, multi-service)
├── .env.example                    ← ERWEITERT (+ REDSWARM_API_KEY etc.)
│
├── backend/                        ← NEU
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                     ← aus Dashboard/files.zip (erweitert)
│   └── adapters/
│       └── blackboard_bridge.py    ← NEU: Blackboard → HTTP Übersetzer
│
├── frontend/                       ← NEU
│   ├── Dockerfile
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       └── App.jsx                 ← aus Dashboard/files.zip (erweitert)
│
├── nginx/                          ← NEU
│   └── nginx.conf
│
├── agents/                         ← NEU (HTTP-Wrapper für jeden Agent)
│   ├── base_wrapper.py             ← Gemeinsamer Wrapper-Code
│   ├── recon/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── main.py                 ← HTTP-Wrapper um ReconAgent
│   ├── exploit/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── main.py
│   ├── execution/
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── main.py
│   └── c4/
│       ├── Dockerfile
│       ├── requirements.txt
│       └── main.py
│
├── swarm/                          ← UNVERÄNDERT (bestehende Logik)
├── modules/                        ← UNVERÄNDERT
├── browser/                        ← UNVERÄNDERT
├── knowledge/                      ← UNVERÄNDERT
├── payloads/                       ← UNVERÄNDERT
├── monitor/                        ← UNVERÄNDERT (altes Dashboard bleibt als Fallback)
├── scanner.py                      ← UNVERÄNDERT
├── main.py                         ← UNVERÄNDERT (CLI bleibt funktionsfähig)
└── config.py                       ← UNVERÄNDERT
```

---

## Implementierungsschritte

### Schritt 1: Backend-Service erstellen
**Dateien**: `backend/main.py`, `backend/Dockerfile`, `backend/requirements.txt`

- `main.py` aus Dashboard/files.zip extrahieren und erweitern:
  - Mission-Options erweitern um `scan_depth`, `kill_chain_phases`, `attack_vectors`
  - Endpoint `GET /missions/{id}/findings` für Agent-zu-Agent Findings-Austausch
  - Endpoint `POST /missions/{id}/relay` für Inter-Agent-Kommunikation (ersetzt Blackboard-Messaging)
  - Health-Check erweitern mit Redis-Status
- Dockerfile: Python 3.12-slim + FastAPI + Redis + httpx
- requirements.txt: fastapi, uvicorn, redis, httpx, pydantic

### Schritt 2: Blackboard-Bridge Adapter
**Datei**: `backend/adapters/blackboard_bridge.py`

- Klasse `BlackboardBridge` die:
  - Ein lokales Blackboard instanziiert (pro Mission)
  - Alle 500ms das Blackboard pollt auf neue Einträge
  - Neue Einträge in HTTP-Updates übersetzt:
    - `intel` → `finding` (severity aus priority gemappt)
    - `exploits` → `finding` mit attack_vector + payload
    - `execution` → `finding` mit success-Flag
    - `tasks` → `log` Events
    - `comms` → `log` Events
  - Fortschritt berechnet aus Tasks (done/total) → `progress` Events
  - An das Backend sendet via `POST /missions/{id}/update`

### Schritt 3: Agent-Wrapper erstellen (4 Wrapper)
**Dateien**: `agents/base_wrapper.py`, `agents/recon/main.py`, etc.

`base_wrapper.py` — Gemeinsamer Code:
- FastAPI-App mit `/run` und `/health` Endpoints
- Startup-Hook: Registrierung beim Backend (`POST /agents/register`)
- `send_update()` Helper (identisch mit agent_template.py)
- `BlackboardBridge`-Integration: Startet Bridge als Background-Task

Jeder Agent-Wrapper (`agents/recon/main.py` etc.):
- Importiert den bestehenden Swarm-Agent (z.B. `from swarm.agents.recon_agent import ReconAgent`)
- Beim `/run` Call:
  1. Erstellt ein isoliertes Blackboard für diese Mission
  2. Instanziiert den Agent mit diesem Blackboard + Konfiguration
  3. Startet `BlackboardBridge` als Background-Task (pollt → sendet Updates)
  4. Startet `agent.start()` als Background-Task
  5. Gibt sofort `{"status": "started"}` zurück
- Agent-spezifische Registrierungsdaten:
  - Recon: icon=🔭, capabilities=[entry-point-discovery, vulnerability-scan, fingerprinting, osint]
  - Exploit: icon=💉, capabilities=[payload-development, rag-poisoning, tool-shadowing, kb-optimization]
  - Execution: icon=⚔️, capabilities=[browser-exploitation, api-attacks, content-poisoning, persistence]
  - C4: icon=🎯, capabilities=[strategy-planning, kill-chain-tracking, report-generation, swarm-coordination]

### Schritt 4: Frontend-Service erstellen
**Dateien**: `frontend/package.json`, `frontend/vite.config.js`, `frontend/index.html`, `frontend/src/App.jsx`, `frontend/Dockerfile`

- `App.jsx` aus Dashboard/files.zip extrahieren
- Erweiterungen:
  - Module-Verwaltungs-Tab (zeigt verfügbare Attack-Module)
  - Kill-Chain-Visualisierung (6 Phasen als Fortschritts-Tracker)
  - Knowledge-Base Stats-Widget (Payloads, Success-Rates)
  - Export-Button für Reports (Markdown-Download)
- Vite-Config: Proxy zu Backend für Entwicklung
- Dockerfile: Node 20 → `npm run build` → nginx:alpine für statische Files

### Schritt 5: Nginx Reverse Proxy
**Datei**: `nginx/nginx.conf`

- `/` → Frontend (React)
- `/api/` → Backend (FastAPI)
- `/ws/` → Backend WebSocket
- SSL-ready (Cert-Pfade vorbereitet)

### Schritt 6: Docker Compose (Multi-Service)
**Datei**: `docker-compose.yml` (Projekt-Root, ersetzt alten)

Services:
1. `redis` — Message Broker (redis:7-alpine)
2. `backend` — FastAPI (build: ./backend)
3. `frontend` — React/Vite (build: ./frontend)
4. `nginx` — Reverse Proxy (nginx:alpine, ports 80/443)
5. `agent-recon` — Recon Wrapper (build: ./agents/recon, depends: backend)
6. `agent-exploit` — Exploit Wrapper (build: ./agents/exploit, depends: backend)
7. `agent-execution` — Execution Wrapper (build: ./agents/execution, depends: backend)
8. `agent-c4` — C4 Wrapper (build: ./agents/c4, depends: backend)

Networks: `internal` (UI↔Backend↔Redis), `agents` (Backend↔Agents)
Volumes: `redis_data`, `knowledge_db`, `logs`

### Schritt 7: .env.example erweitern
- `REDSWARM_API_KEY` — API-Key für Agent↔Backend Kommunikation
- `BACKEND_PUBLIC_URL` — Öffentliche URL des Backends
- Bestehende Notion-Keys bleiben

### Schritt 8: Verifikation & Test
- `docker compose up -d` starten
- Prüfen: Alle 4 Agents registrieren sich erfolgreich
- Frontend erreichbar unter localhost
- Test-Mission starten über UI
- Live-Monitor zeigt Echtzeit-Updates
- Findings erscheinen im Report-Tab

---

## Nicht im Scope (bewusst ausgeklammert)
- Modul-Aktivierung/Deaktivierung über UI (→ Prio 4)
- Setup-Wizard / One-Click-Install (→ Prio 2)
- Notion-Template Duplikation (→ Prio 5)
- SSL-Zertifikate / Let's Encrypt Integration
- Persistente Datenbank (Postgres statt In-Memory)

## Geschätzte Dateien: ~20 neue Dateien, 0 bestehende geändert
## Geschätzter Umfang: ~1500-2000 Zeilen neuer Code
