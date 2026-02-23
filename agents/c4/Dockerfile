FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY agents/c4/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY swarm/ /app/swarm/
COPY modules/ /app/modules/
COPY knowledge/ /app/knowledge/
COPY payloads/ /app/payloads/
COPY monitor/ /app/monitor/
COPY config.py /app/config.py
COPY agents/base_wrapper.py /app/agents/base_wrapper.py
COPY agents/c4/main.py /app/agents/c4/main.py
COPY backend/adapters/ /app/backend/adapters/

EXPOSE 8103

CMD ["python", "-m", "uvicorn", "agents.c4.main:app", "--host", "0.0.0.0", "--port", "8103"]
