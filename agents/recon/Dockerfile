FROM python:3.12-slim

# System-Dependencies für Playwright/Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget gnupg ca-certificates fonts-liberation libnss3 libatk-bridge2.0-0 \
    libdrm2 libxkbcommon0 libgbm1 libasound2 libatspi2.0-0 libgtk-3-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Requirements installieren
COPY agents/recon/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
RUN playwright install chromium && playwright install-deps chromium

# Projektcode kopieren (alles was der Agent braucht)
COPY swarm/ /app/swarm/
COPY modules/ /app/modules/
COPY browser/ /app/browser/
COPY knowledge/ /app/knowledge/
COPY payloads/ /app/payloads/
COPY monitor/ /app/monitor/
COPY config.py /app/config.py
COPY scanner.py /app/scanner.py
COPY agents/base_wrapper.py /app/agents/base_wrapper.py
COPY agents/recon/main.py /app/agents/recon/main.py
COPY backend/adapters/ /app/backend/adapters/

EXPOSE 8100

CMD ["python", "-m", "uvicorn", "agents.recon.main:app", "--host", "0.0.0.0", "--port", "8100"]
