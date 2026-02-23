# Webhook Setup — AI Red Team Scanner

Trigger scans directly from Notion by checking a checkbox. No n8n, no Zapier, no external services required.

## Architecture

```
Notion Checkbox → Notion Automation → POST /webhook/notion → webhook_server.py → Scan → Results → Notion
```

---

## 1. Start the Server

### Option A: Direct (development)

```bash
cd ai_red_team
pip install -r requirements.txt
cp .env.example .env   # Then fill in real values
python webhook_server.py
```

### Option B: Docker (production)

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
      - "8080:8080"   # Live dashboard
    shm_size: "256m"
    restart: unless-stopped
    volumes:
      - ./knowledge_db:/app/knowledge_db
      - ./logs:/app/logs
```

```bash
docker compose up -d
docker compose logs -f
```

---

## 2. Make the Server Publicly Accessible

Notion needs to reach your webhook endpoint. Options:

### Development: ngrok / Cloudflare Tunnel

```bash
# ngrok
ngrok http 8000
# → https://abc123.ngrok-free.app

# Cloudflare Tunnel (free, more stable)
cloudflared tunnel --url http://localhost:8000
# → https://xyz.trycloudflare.com
```

### Production: VPS / Cloud

1. Start the server with Docker (Option B above)
2. Set up a reverse proxy with nginx + Let's Encrypt
3. Point your domain at the VPS

---

## 3. Set Up Notion Automation

1. Open your Notion database (your Red Team Scanner DB)
2. Click the ⚡ **Automations** icon (top right)
3. Click **"New automation"**
4. Configure the automation:
   - **Trigger:** "When property changes"
     - Property: `🔴 Start Scan`
     - Condition: `is checked`
   - **Action:** "Send webhook request"
     - URL: `https://your-server.com/webhook/notion`
     - Method: POST
     - Body: Notion sends the page ID automatically
5. Toggle the automation **ON**

---

## 4. Test It

### Health check

```bash
curl http://localhost:8000/health
```

### Trigger a scan manually (without Notion)

```bash
curl -X POST http://localhost:8000/webhook/scan \
  -H "Content-Type: application/json" \
  -d '{"page_id": "your-notion-page-id"}'
```

### Query scan status

```bash
# All scans
curl http://localhost:8000/status

# Specific scan
curl http://localhost:8000/status/your-page-id
```

### End-to-end Notion test

1. Go to your Notion database
2. Check the `🔴 Start Scan` checkbox on any entry
3. The automation fires → webhook triggers → scan starts → results appear in Notion

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/webhook/notion` | POST | Notion Automation webhook receiver |
| `/webhook/scan` | POST | Manual trigger with `page_id` in body |
| `/status` | GET | All active and completed scans |
| `/status/{page_id}` | GET | Status of a specific scan |
| `/health` | GET | Health check |

---

## Security (Optional)

### Webhook Secret

Set `WEBHOOK_SECRET` in `.env`. The sender must then include an `x-webhook-signature` header with the value `sha256=HMAC(body, secret)`.

```env
WEBHOOK_SECRET=your-random-secret-here
```

### Firewall

Only expose port 8000 (or your proxy port) to the internet. Ideally whitelist Notion's IP ranges.

---

## Comparison: Polling vs. Webhook

| Aspect | Polling Mode | Webhook Mode |
|---|---|---|
| Trigger | Checks Notion every 30s | Real-time, event-driven |
| Latency | Up to 30s delay | < 1 second |
| External dependencies | None | Public URL required |
| Setup complexity | None | ngrok or VPS needed |
| Reliability | Always works locally | Depends on tunnel/server uptime |
| Best for | Local dev, quick tests | Production, daily use |
