# AI Red Team Scanner — Webhook Setup (ohne n8n)

## Architektur

```
Notion Checkbox ──→ Notion Automation ──→ Webhook POST ──→ webhook_server.py ──→ Scan ──→ Ergebnis zurück in Notion
```

**Kein n8n, kein Zapier, kein externer Service nötig.**

---

## 1. Server starten

### Option A: Direkt (Entwicklung)

```bash
cd ai_red_team
pip install -r requirements.txt
cp .env.example .env   # Dann .env mit echten Werten befüllen
python webhook_server.py
```

### Option B: Docker (Produktion)

```bash
cd ai_red_team
docker build -t red-team-scanner .
docker run -d \
  --name red-team-scanner \
  --env-file .env \
  -p 8000:8000 \
  --restart unless-stopped \
  red-team-scanner
```

### Option C: Docker Compose

```yaml
# docker-compose.yml
services:
  scanner:
    build: .
    env_file: .env
    ports:
      - "8000:8000"
    restart: unless-stopped
```

---

## 2. Server öffentlich erreichbar machen

Notion muss deinen Webhook-Endpoint erreichen können. Optionen:

### Für Entwicklung: ngrok / Cloudflare Tunnel

```bash
# ngrok
ngrok http 8000
# → Gibt dir z.B. https://abc123.ngrok-free.app

# Cloudflare Tunnel (kostenlos, stabiler)
cloudflared tunnel --url http://localhost:8000
# → Gibt dir z.B. https://xyz.trycloudflare.com
```

### Für Produktion: VPS / Cloud

Auf einem VPS (Hetzner, DigitalOcean, etc.):

1. Server mit Docker starten (Option B oben)
2. Reverse Proxy mit nginx + Let's Encrypt
3. Domain auf den VPS zeigen lassen

---

## 3. Notion Automation einrichten

1. **Notion-Datenbank öffnen** (deine Red Team Scanner DB)
2. **Klicke auf das ⚡ Icon** (Automations) oben rechts
3. **Neue Automation erstellen:**
   - **Trigger:** "When property changes"
     - Property: `🔴 Start Scan`
     - Condition: `is checked`
   - **Action:** "Send webhook request"
     - URL: `https://dein-server.de/webhook/notion`
     - Method: POST
     - Body: Notion sendet automatisch die Page-ID
4. **Automation aktivieren** (Toggle on)

---

## 4. Testen

### Health Check

```bash
curl http://localhost:8000/health
```

### Manueller Scan auslösen

```bash
curl -X POST http://localhost:8000/webhook/scan \
  -H "Content-Type: application/json" \
  -d '{"page_id": "deine-notion-page-id"}'
```

### Status abfragen

```bash
# Alle Scans
curl http://localhost:8000/status

# Bestimmter Scan
curl http://localhost:8000/status/deine-page-id
```

### Notion-Test

1. Gehe zur Notion-Datenbank
2. Setze die Checkbox `🔴 Start Scan` bei einem Eintrag
3. Der Webhook feuert → Server startet Scan → Ergebnisse erscheinen in Notion

---

## API-Endpoints

| Endpoint              | Method | Beschreibung                          |
|----------------------|--------|---------------------------------------|
| `/webhook/notion`    | POST   | Notion Automation Webhook             |
| `/webhook/scan`      | POST   | Manueller Scan (mit `page_id`)        |
| `/status`            | GET    | Alle aktiven/abgeschlossenen Scans    |
| `/status/{page_id}`  | GET    | Status eines bestimmten Scans         |
| `/health`            | GET    | Health Check                          |

---

## Sicherheit (Optional)

### Webhook-Secret

In `.env` ein `WEBHOOK_SECRET` setzen. Dann muss der Webhook-Sender
einen `x-webhook-signature` Header mit `sha256=HMAC(body, secret)` mitsenden.

### Firewall

Nur Port 8000 (oder deinen Proxy-Port) öffnen.
Idealerweise Notion-IPs whitelisten.

---

## Vergleich: Vorher (n8n) vs. Nachher (Webhook)

| Aspekt          | n8n                        | Webhook Server              |
|----------------|----------------------------|-----------------------------|
| Trigger        | Polling alle 30s           | Echtzeit Event-basiert      |
| Latenz         | Bis zu 30s Verzögerung     | < 1 Sekunde                 |
| Dependencies   | n8n Server + Node.js       | Nur Python + FastAPI         |
| Ressourcen     | ~500MB RAM für n8n         | ~50MB RAM                    |
| Wartung        | n8n Updates + Workflows    | Ein Python-File              |
| Kosten         | n8n Cloud oder Self-Host   | Kostenlos                    |
