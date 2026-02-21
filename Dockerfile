FROM python:3.12-slim

WORKDIR /app

# System deps für Playwright + Chrome
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl fonts-liberation libasound2 libatk-bridge2.0-0 libatk1.0-0 \
    libcups2 libdbus-1-3 libdrm2 libgbm1 libgtk-3-0 libnspr4 libnss3 \
    libx11-xcb1 libxcomposite1 libxdamage1 libxrandr2 xdg-utils \
    libxshmfence1 libxss1 libxtst6 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright Browser installieren (Chrome + Chromium + System-Deps)
RUN playwright install chrome && playwright install chromium && playwright install-deps

COPY . .

EXPOSE 8000

# Chromium/Chrome braucht mehr shared memory als Docker default (64MB)
# → docker run mit --shm-size=256m starten
CMD ["uvicorn", "webhook_server:app", "--host", "0.0.0.0", "--port", "8000"]
