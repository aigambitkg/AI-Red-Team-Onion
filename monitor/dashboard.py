"""
AI Red Team Scanner - Web Dashboard
=====================================
Live-Dashboard auf localhost:8080 mit:
- Echtzeit-Events (SSE)
- Scan-Statistiken
- Aktivitäts-Log
- Kill-Switch Button
- JSON-Log Viewer

Nutzt nur stdlib + threading (kein Flask nötig).
"""

import http.server
import json
import logging
import os
import queue
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# SSE Event Queue für alle verbundenen Clients
_event_queues: list[queue.Queue] = []
_event_lock = threading.Lock()
_event_logger_ref = None  # Wird beim Start gesetzt


def _broadcast_event(event):
    """Sendet Event an alle verbundenen SSE-Clients"""
    data = event.to_json() if hasattr(event, 'to_json') else json.dumps(event)
    with _event_lock:
        dead = []
        for q in _event_queues:
            try:
                q.put_nowait(data)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _event_queues.remove(q)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Red Team Scanner - Monitor</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0e17; color: #e0e0e0; }

        .header {
            background: linear-gradient(135deg, #1a1f2e, #2a1a2e);
            padding: 20px 30px;
            border-bottom: 2px solid #ff4444;
            display: flex; justify-content: space-between; align-items: center;
        }
        .header h1 { color: #ff4444; font-size: 24px; }
        .header .subtitle { color: #888; font-size: 14px; }

        .kill-btn {
            background: #ff0000; color: white; border: none;
            padding: 12px 30px; font-size: 18px; font-weight: bold;
            cursor: pointer; border-radius: 8px;
            box-shadow: 0 0 20px rgba(255,0,0,0.3);
            transition: all 0.3s;
        }
        .kill-btn:hover { background: #cc0000; box-shadow: 0 0 40px rgba(255,0,0,0.6); }
        .kill-btn.killed { background: #444; cursor: not-allowed; }

        .stats-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px; padding: 20px 30px;
        }
        .stat-card {
            background: #1a1f2e; border-radius: 10px; padding: 15px;
            border: 1px solid #2a2f3e; text-align: center;
        }
        .stat-card .value { font-size: 32px; font-weight: bold; color: #4fc3f7; }
        .stat-card .label { font-size: 12px; color: #888; margin-top: 5px; }
        .stat-card.danger .value { color: #ff4444; }
        .stat-card.success .value { color: #66bb6a; }
        .stat-card.warning .value { color: #ffa726; }

        .main { display: grid; grid-template-columns: 1fr 400px; gap: 20px; padding: 0 30px 30px; }

        .events-panel {
            background: #1a1f2e; border-radius: 10px; padding: 15px;
            border: 1px solid #2a2f3e; max-height: 600px; overflow-y: auto;
        }
        .events-panel h3 { color: #4fc3f7; margin-bottom: 10px; }

        .event {
            padding: 8px 12px; margin: 4px 0; border-radius: 6px;
            font-size: 13px; border-left: 3px solid #333;
            background: #0f1320;
        }
        .event .time { color: #666; font-size: 11px; }
        .event .module { color: #4fc3f7; font-weight: bold; }
        .event .msg { color: #ccc; }

        .event.info { border-left-color: #4fc3f7; }
        .event.warning { border-left-color: #ffa726; background: #1a1810; }
        .event.error { border-left-color: #ff4444; background: #1a1015; }
        .event.critical { border-left-color: #ff0000; background: #2a0015; }
        .event.debug { border-left-color: #666; }

        .activity-panel {
            background: #1a1f2e; border-radius: 10px; padding: 15px;
            border: 1px solid #2a2f3e; max-height: 600px; overflow-y: auto;
        }
        .activity-panel h3 { color: #ffa726; margin-bottom: 10px; }

        .activity {
            padding: 6px 10px; margin: 3px 0; border-radius: 4px;
            font-size: 12px; background: #0f1320;
        }
        .activity .type { font-weight: bold; }
        .activity.test-pass { color: #66bb6a; }
        .activity.test-fail { color: #ff4444; }
        .activity.test-error { color: #ffa726; }
        .activity.false-pos { color: #ce93d8; }

        .status-bar {
            background: #1a1f2e; padding: 10px 30px; margin: 0 30px 20px;
            border-radius: 10px; border: 1px solid #2a2f3e;
            display: flex; align-items: center; gap: 15px;
        }
        .status-dot { width: 12px; height: 12px; border-radius: 50%; }
        .status-dot.active { background: #66bb6a; animation: pulse 2s infinite; }
        .status-dot.killed { background: #ff0000; }
        .status-dot.idle { background: #666; }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }

        .progress-text { font-size: 14px; }

        #connectionStatus {
            position: fixed; bottom: 10px; right: 10px;
            padding: 5px 10px; border-radius: 4px;
            font-size: 11px; z-index: 1000;
        }
        #connectionStatus.connected { background: #1b5e20; color: #66bb6a; }
        #connectionStatus.disconnected { background: #b71c1c; color: #ff8a80; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>AI Red Team Scanner — Monitor</h1>
            <div class="subtitle">Powered by AI-Gambit</div>
        </div>
        <button class="kill-btn" id="killBtn" onclick="triggerKill()">
            NOTFALL STOP
        </button>
    </div>

    <div class="status-bar">
        <div class="status-dot" id="statusDot"></div>
        <span class="progress-text" id="progressText">Warte auf Verbindung...</span>
    </div>

    <div class="stats-grid">
        <div class="stat-card"><div class="value" id="totalEvents">0</div><div class="label">Events</div></div>
        <div class="stat-card"><div class="value" id="messagesSent">0</div><div class="label">Nachrichten</div></div>
        <div class="stat-card success"><div class="value" id="testsPassed">0</div><div class="label">Tests OK</div></div>
        <div class="stat-card danger"><div class="value" id="testsFailed">0</div><div class="label">Vulnerabilities</div></div>
        <div class="stat-card warning"><div class="value" id="testsError">0</div><div class="label">Fehler</div></div>
        <div class="stat-card" style="border-color: #ce93d8"><div class="value" id="falsePos" style="color:#ce93d8">0</div><div class="label">False Positives</div></div>
        <div class="stat-card"><div class="value" id="modulesCompleted">0</div><div class="label">Module fertig</div></div>
        <div class="stat-card"><div class="value" id="responsesTimeout">0</div><div class="label">Timeouts</div></div>
    </div>

    <div class="main">
        <div class="events-panel" id="eventsPanel">
            <h3>Echtzeit-Events</h3>
        </div>
        <div class="activity-panel" id="activityPanel">
            <h3>Test-Ergebnisse</h3>
        </div>
    </div>

    <div id="connectionStatus" class="disconnected">Nicht verbunden</div>

    <script>
        let evtSource = null;
        let stats = {};

        function connect() {
            evtSource = new EventSource('/events');
            evtSource.onopen = () => {
                document.getElementById('connectionStatus').className = 'connected';
                document.getElementById('connectionStatus').textContent = 'Verbunden';
                document.getElementById('statusDot').className = 'status-dot active';
                document.getElementById('progressText').textContent = 'Scan läuft...';
            };
            evtSource.onmessage = (e) => {
                try {
                    const event = JSON.parse(e.data);
                    handleEvent(event);
                } catch(err) {}
            };
            evtSource.onerror = () => {
                document.getElementById('connectionStatus').className = 'disconnected';
                document.getElementById('connectionStatus').textContent = 'Verbindung verloren';
                setTimeout(connect, 3000);
            };
        }

        function handleEvent(evt) {
            addEventToPanel(evt);

            if (evt.event_type === 'test_result') {
                addTestResult(evt);
            }

            if (evt.event_type === 'kill_switch') {
                document.getElementById('statusDot').className = 'status-dot killed';
                document.getElementById('progressText').textContent = 'KILL SWITCH AKTIV: ' + evt.message;
                document.getElementById('killBtn').className = 'kill-btn killed';
                document.getElementById('killBtn').textContent = 'GESTOPPT';
            }

            if (evt.event_type === 'scan_end') {
                document.getElementById('statusDot').className = 'status-dot idle';
                document.getElementById('progressText').textContent = 'Scan abgeschlossen: ' + evt.message;
            }

            if (evt.event_type === 'module_start') {
                document.getElementById('progressText').textContent = 'Modul: ' + evt.module_name;
            }

            // Stats aktualisieren via Polling
            fetchStats();
        }

        function addEventToPanel(evt) {
            const panel = document.getElementById('eventsPanel');
            const div = document.createElement('div');
            div.className = 'event ' + evt.severity;
            const time = evt.timestamp ? evt.timestamp.split('T')[1].split('.')[0] : '';
            const mod = evt.module_name ? `<span class="module">[${evt.module_name}]</span> ` : '';
            div.innerHTML = `<span class="time">${time}</span> ${mod}<span class="msg">${evt.message}</span>`;
            panel.insertBefore(div, panel.children[1]);

            // Max 200 Events im DOM
            while (panel.children.length > 201) {
                panel.removeChild(panel.lastChild);
            }
        }

        function addTestResult(evt) {
            const panel = document.getElementById('activityPanel');
            const div = document.createElement('div');
            const meta = evt.metadata || {};
            let cls = 'activity ';
            if (meta.status === 'passed') cls += 'test-pass';
            else if (meta.status === 'failed') cls += 'test-fail';
            else cls += 'test-error';

            const icon = meta.is_vulnerable ? '❌' : (meta.status === 'error' ? '⚠️' : '✅');
            div.className = cls;
            div.innerHTML = `<span class="type">${icon} ${evt.test_name || meta.status}</span> — ${meta.severity || ''} — ${(meta.details || '').substring(0, 80)}`;
            panel.insertBefore(div, panel.children[1]);
        }

        async function fetchStats() {
            try {
                const resp = await fetch('/api/stats');
                const data = await resp.json();
                document.getElementById('totalEvents').textContent = data.total_events || 0;
                document.getElementById('messagesSent').textContent = data.messages_sent || 0;
                document.getElementById('testsPassed').textContent = data.tests_passed || 0;
                document.getElementById('testsFailed').textContent = data.tests_failed || 0;
                document.getElementById('testsError').textContent = data.tests_error || 0;
                document.getElementById('falsePos').textContent = data.false_positives_caught || 0;
                document.getElementById('modulesCompleted').textContent = data.modules_completed || 0;
                document.getElementById('responsesTimeout').textContent = data.responses_timeout || 0;
            } catch(e) {}
        }

        async function triggerKill() {
            if (confirm('WIRKLICH den Scan sofort abbrechen?')) {
                try {
                    await fetch('/api/kill', { method: 'POST' });
                } catch(e) {}
            }
        }

        // Initial
        connect();
        setInterval(fetchStats, 2000);
    </script>
</body>
</html>"""


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Request Handler für das Dashboard"""

    def log_message(self, format, *args):
        pass  # Stille HTTP-Logs

    def do_GET(self):
        if self.path == '/' or self.path == '/dashboard':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode('utf-8'))

        elif self.path == '/events':
            # Server-Sent Events
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            q = queue.Queue(maxsize=500)
            with _event_lock:
                _event_queues.append(q)

            try:
                while True:
                    try:
                        data = q.get(timeout=15)
                        self.wfile.write(f"data: {data}\n\n".encode('utf-8'))
                        self.wfile.flush()
                    except queue.Empty:
                        # Keep-alive
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with _event_lock:
                    if q in _event_queues:
                        _event_queues.remove(q)

        elif self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            stats = {}
            if _event_logger_ref:
                stats = _event_logger_ref.get_stats()
            self.wfile.write(json.dumps(stats).encode('utf-8'))

        elif self.path.startswith('/api/events'):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            events = []
            if _event_logger_ref:
                events = _event_logger_ref.get_recent_events(100)
            self.wfile.write(json.dumps(events).encode('utf-8'))

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/api/kill':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            if _event_logger_ref:
                _event_logger_ref.kill_switch.trigger("Dashboard Kill-Button")
                self.wfile.write(json.dumps({"status": "killed"}).encode('utf-8'))
            else:
                # Fallback: Kill-File erstellen
                Path("/tmp/redteam_kill").write_text("Dashboard Kill-Button")
                self.wfile.write(json.dumps({"status": "kill_file_created"}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()


def start_dashboard(event_logger, host: str = "0.0.0.0", port: int = 8080):
    """
    Startet das Dashboard als Hintergrund-Thread.
    Returns: threading.Thread
    """
    global _event_logger_ref
    _event_logger_ref = event_logger

    # Event-Logger Listener registrieren (streamt Events an Dashboard)
    event_logger.add_listener(_broadcast_event)

    server = http.server.HTTPServer((host, port), DashboardHandler)

    def _run():
        logger.info(f"Dashboard gestartet: http://{host}:{port}")
        server.serve_forever()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return thread, server
