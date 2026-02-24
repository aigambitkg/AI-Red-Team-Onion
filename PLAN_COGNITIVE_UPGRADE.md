# REDSWARM Cognitive Upgrade — Implementierungsplan

## Hauptziel
Die 4 AI-Agenten und den Schwarm von regelbasierter Automation zu echten
autonomen Systemen mit LLM-gestütztem Reasoning, Gedächtnis, Selbst-Reflexion
und emergenter Schwarm-Intelligenz transformieren.

## Architektur-Übersicht

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    NEUE KOGNITIVE SCHICHT                               │
│                                                                         │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐  │
│  │  Cognitive    │ │   Agent      │ │  Reflector   │ │   Planner    │  │
│  │  Engine       │ │   Memory     │ │  (ReAct)     │ │  (HTN)       │  │
│  │              │ │              │ │              │ │              │  │
│  │ - CoT/ToT    │ │ - Episodisch │ │ - Evaluate   │ │ - Decompose  │  │
│  │ - Provider-  │ │ - Semantisch │ │ - Correct    │ │ - Prioritize │  │
│  │   agnostic   │ │ - Prozedural │ │ - Adapt      │ │ - Replan     │  │
│  │ - OpenAI +   │ │ - Cross-Op   │ │ - Log Why    │ │ - Delegate   │  │
│  │   Anthropic  │ │              │ │              │ │              │  │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘  │
│         │                │                │                │          │
│  ┌──────┴────────────────┴────────────────┴────────────────┴───────┐  │
│  │                    CognitiveMixin (in agent_base.py)             │  │
│  │  think() → reason() → plan() → act() → reflect() → adapt()     │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                   │
│  │  Stigmergy   │ │  Emergence   │ │  Resilience  │                   │
│  │  Engine      │ │  Detector    │ │  Manager     │                   │
│  │              │ │              │ │              │                   │
│  │ - Pheromone  │ │ - Cross-     │ │ - Health     │                   │
│  │   scores     │ │   agent      │ │   monitor    │                   │
│  │ - Decay      │ │   correlation│ │ - Auto-heal  │                   │
│  │ - Attraction │ │ - Novel path │ │ - Task       │                   │
│  │              │ │   detection  │ │   takeover   │                   │
│  └──────────────┘ └──────────────┘ └──────────────┘                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Cognitive Engine (Fundament)

### 1.1 `swarm/cognition/__init__.py`
Paket-Init.

### 1.2 `swarm/cognition/engine.py` — LLM Reasoning Engine
Provider-agnostische LLM-Schnittstelle für Agenten-Kognition.

**Kern-Funktionen:**
- `reason(context, question) → ReasoningResult`
  Chain-of-Thought Reasoning: Agent beschreibt Situation, Engine liefert
  strukturierte Analyse + Entscheidung
- `plan(goal, context, constraints) → Plan`
  Hierarchische Aufgabenzerlegung (HTN): Ziel → Teilziele → konkrete Aktionen
- `evaluate(action, result, expectation) → Evaluation`
  Selbst-Bewertung: War die Aktion erfolgreich? Was lief schief? Was ändern?
- `generate_payload(vuln_info, target_context) → Payload`
  Autonome Exploit-Generierung basierend auf Schwachstellen-Analyse

**Provider-Config über ENV:**
```
REDSWARM_LLM_PROVIDER=anthropic|openai  (default: anthropic)
REDSWARM_LLM_MODEL=claude-sonnet-4-20250514|gpt-4o  (default: auto)
```

**Implementierung:**
- Nutzt bestehenden `modules/api_client.py` als Transport-Layer
- Eigene System-Prompts pro Reasoning-Typ (planner, evaluator, generator)
- Strukturierte JSON-Outputs via Prompt-Engineering
- Token-Budget-Management (max_tokens konfigurierbar)
- Retry mit Exponential Backoff
- Fallback: OpenAI → Anthropic (oder umgekehrt)

### 1.3 `swarm/cognition/memory.py` — Agent Memory System
Drei Gedächtnis-Typen, die über die bestehende KB hinausgehen.

**Episodisches Gedächtnis** (Was ist passiert?):
- Speichert: "Ich habe Payload X gegen Ziel Y verwendet → Resultat Z"
- Jede Aktion wird als Episode gespeichert (agent_id, action, target, result,
  timestamp)
- Abfrage: "Was habe ich bei ähnlichen Zielen gemacht?"

**Semantisches Gedächtnis** (Was weiß ich?):
- Erweitert bestehende KnowledgeBase um semantische Suche
- Speichert: "Django-Apps sind anfällig für X wenn Y konfiguriert ist"
- Nutzt bestehenden `knowledge/rag_engine.py` für Embeddings

**Prozedurales Gedächtnis** (Wie mache ich es?):
- Speichert: Erfolgreiche Aktionssequenzen als Prozeduren
- "Wenn WAF erkannt → erst Y testen, dann Z mutieren"
- Wird aus episodischem Gedächtnis durch Generalisierung erstellt

**Integration:**
- SQLite-Storage unter `data/memory_{agent_id}.db`
- Automatische Verdichtung (nach 1000 Episoden → zusammenfassen)
- Cross-Operation: Gedächtnis bleibt zwischen Missions erhalten

### 1.4 `swarm/cognition/reflector.py` — Self-Reflection (ReAct)
Implementiert den Reason-Act-Observe-Reflect Loop.

**ReAct-Zyklus:**
```
1. REASON: "Mein Ziel ist X. Basierend auf meinem Wissen ist Ansatz A am besten."
2. ACT:    Agent führt Aktion aus
3. OBSERVE: "Das Ergebnis war Y. Fehlermeldung: Z."
4. REFLECT: "Ansatz A hat nicht funktioniert weil Z.
             Nächster Versuch: Ansatz B, weil..."
5. ADAPT:   Agent passt Strategie an
```

**Integration mit Blackboard:**
- Jede Reflexion wird als Strategie-Eintrag gepostet
- Andere Agenten können von den Reflexionen lernen
- C4 nutzt aggregierte Reflexionen für Strategieanpassung

### 1.5 `swarm/cognition/planner.py` — Hierarchical Task Decomposition
Dynamische Aufgabenzerlegung statt starrer Kill-Chain-Abfolge.

**Input:** Hochrangiges Ziel + aktuelle Blackboard-Daten
**Output:** Hierarchischer Aktionsplan mit Abhängigkeiten

**Beispiel:**
```
Ziel: "Kompromittiere https://target.com/api"
├── 1. Fingerprint (Recon)
│   ├── 1.1 Technologie identifizieren
│   ├── 1.2 API-Endpunkte enumerieren
│   └── 1.3 Auth-Mechanismus analysieren
├── 2. Schwachstellen suchen (Recon → Exploit)
│   ├── 2.1 Prompt Injection testen
│   ├── 2.2 Auth-Bypass prüfen
│   └── 2.3 Rate-Limiting testen
├── 3. Exploits entwickeln (Exploit) [abhängig von 2]
│   ├── 3.1 Top-Schwachstelle ausnutzen
│   └── 3.2 Backup-Vektor vorbereiten
└── 4. Ausführen + Persistenz (Execution) [abhängig von 3]
```

**Replan:** Nach jeder Phase re-evaluiert der Planner den Plan basierend auf
neuen Erkenntnissen.

---

## Phase 2: Agent-Integration

### 2.1 `swarm/agent_base.py` — CognitiveMixin hinzufügen
Erweitert die bestehende `SwarmAgent`-Klasse um kognitive Methoden.

**Neue Methoden (alle optional nutzbar):**
```python
async def think(self, situation: str) -> ThoughtResult:
    """LLM-basiertes Reasoning über aktuelle Situation"""

async def plan_next_action(self) -> ActionPlan:
    """Dynamisch nächste Aktion planen basierend auf Blackboard-State"""

async def reflect_on_result(self, action, result) -> Reflection:
    """Selbst-Reflexion nach jeder Aktion"""

async def remember(self, key: str, context: str) -> list[Memory]:
    """Relevante Erinnerungen abrufen"""

async def perceive(self, raw_output: str) -> Perception:
    """Semantische Wahrnehmung: Tool-Output interpretieren"""
```

**Kein Breaking Change:** Bestehende Agenten funktionieren unverändert.
Die kognitiven Methoden sind opt-in — nur Agenten die sie aufrufen nutzen sie.

### 2.2 Agent-spezifische Upgrades

**Recon Agent** — Perception + Adaptive Scanning:
- `perceive()` analysiert Scan-Ergebnisse semantisch
- `think()` entscheidet: "Soll ich tiefer scannen oder zum nächsten Ziel?"
- `remember()` ruft ab: "Was weiß ich über Django-Apps?"
- Ergebnis: Recon priorisiert vielversprechende Angriffsflächen

**Exploit Agent** — Autonomous Payload Generation + Self-Modification:
- `generate_payload()` erstellt NEUE Payloads basierend auf Schwachstellen-Kontext
- `reflect_on_result()` analysiert warum ein Payload gescheitert ist
- `think()` entscheidet: "Welche Mutation hat die höchste Erfolgswahrscheinlichkeit?"
- Ergebnis: Exploit generiert neuartige Payloads statt nur Templates

**Execution Agent** — Perception + Theory of Mind:
- `perceive()` analysiert Server-Antworten semantisch
- `think()` erkennt: "Das ist eine WAF-Fehlermeldung, nicht eine App-Antwort"
- ToM für Social Engineering: "Der Nutzer ist gestresst → kurze, dringend klingende Nachricht"
- Ergebnis: Execution passt Strategie an Verteidigungsverhalten an

**C4 Agent** — Strategic Planning + Emergent Strategy:
- `plan_next_action()` erstellt dynamischen Angriffsplan
- `reflect_on_result()` bewertet Schwarm-Fortschritt
- Korreliert Findings über alle Agenten hinweg
- Ergebnis: C4 erkennt neuartige Angriffspfade aus kombinierten Findings

---

## Phase 3: Schwarm-Intelligenz

### 3.1 `swarm/intelligence/__init__.py`
Paket-Init.

### 3.2 `swarm/intelligence/stigmergy.py` — Digital Pheromone System
Indirekte Kommunikation über gewichtete Markierungen im Blackboard.

**Pheromone-Typen:**
- `interest`: "Hier ist etwas Vielversprechendes" (zieht Exploit-Agenten an)
- `danger`: "Hier wurde ich erkannt/blockiert" (stößt Agenten ab)
- `success`: "Dieser Vektor funktioniert" (verstärkt ähnliche Ansätze)
- `explored`: "Hier war ich schon" (verhindert Doppelarbeit)

**Mechanik:**
- Pheromone werden als Tags + Scores auf Blackboard-Entries gespeichert
- Decay: Pheromone verlieren über Zeit an Stärke (configurable half-life)
- Agenten checken Pheromone-Scores bei Task-Auswahl
- Hoher `interest`-Score + niedriger `explored`-Score = höchste Priorität

### 3.3 `swarm/intelligence/emergence.py` — Emergent Strategy Detection
Erkennt Muster über mehrere Agent-Findings hinweg.

**Funktionsweise:**
1. Sammelt alle Findings/Intel/Exploits
2. LLM-basierte Korrelationsanalyse:
   "Agent A fand schwache Auth. Agent B fand offene API.
    → Kombinierter Angriff: Auth-Bypass + API-Zugriff = vollständiger Zugang"
3. Erstellt neue Strategie-Einträge auf dem Blackboard
4. C4 nutzt diese für Angriffsplan-Updates

### 3.4 `swarm/intelligence/resilience.py` — Fault Tolerance
Selbstheilung des Schwarms bei Agenten-Ausfällen.

**Mechanik:**
- Überwacht Agent-Heartbeats (bereits vorhanden)
- Bei Ausfall: Offene Tasks des ausgefallenen Agenten werden reassigned
- Bei wiederholtem Ausfall: Warnung an C4 + Taktikänderung
- Schwarm funktioniert weiter auch wenn einzelne Agenten offline sind

---

## Phase 4: Konfiguration + Docker

### 4.1 `.env.example` erweitern
```
# Cognitive Engine
REDSWARM_LLM_PROVIDER=anthropic     # anthropic | openai
REDSWARM_LLM_MODEL=                  # leer = auto (best available)
REDSWARM_LLM_TEMPERATURE=0.7
REDSWARM_LLM_MAX_TOKENS=2000
REDSWARM_COGNITIVE_ENABLED=true      # false = legacy mode (kein LLM-Reasoning)
```

### 4.2 Docker Compose
- Memory-Volumes für jeden Agent: `agent_*_memory:/data/memory`
- Cognitive Engine als shared-Modul (in jedem Agent-Container)

---

## Dateistruktur (neue Dateien)

```
swarm/
├── cognition/
│   ├── __init__.py
│   ├── engine.py          # LLM Reasoning (CoT, ToT, Generator)
│   ├── memory.py          # Episodisch/Semantisch/Prozedural
│   ├── reflector.py       # Self-Reflection (ReAct)
│   └── planner.py         # Hierarchical Task Decomposition
├── intelligence/
│   ├── __init__.py
│   ├── stigmergy.py       # Digital Pheromones
│   ├── emergence.py       # Cross-Agent Correlation
│   └── resilience.py      # Fault Tolerance
├── agent_base.py          # MODIFIZIERT: + CognitiveMixin
└── ...
```

**Geschätzte neue Dateien:** 9
**Geschätzte modifizierte Dateien:** 6 (agent_base + 4 agents + orchestrator)

---

## Abhängigkeiten

**Keine neuen pip-Dependencies nötig!**
- LLM-Calls: Bestehender `httpx` + `api_client.py`
- Memory: Bestehender `sqlite3` (Python built-in)
- Embeddings: Bestehendes `knowledge/rag_engine.py` (optional ChromaDB)

---

## Implementierungs-Reihenfolge

1. `swarm/cognition/engine.py` (Fundament — alles andere baut darauf auf)
2. `swarm/cognition/memory.py` (Agenten brauchen Gedächtnis für Reasoning)
3. `swarm/cognition/reflector.py` (Self-Correction braucht Engine + Memory)
4. `swarm/cognition/planner.py` (Planning braucht Engine + Memory)
5. `swarm/agent_base.py` — CognitiveMixin integrieren
6. `swarm/intelligence/stigmergy.py` (Schwarm-Primitive)
7. `swarm/intelligence/emergence.py` (braucht Engine für LLM-Korrelation)
8. `swarm/intelligence/resilience.py` (unabhängig, kann parallel)
9. Agent-spezifische Upgrades (alle 4 Agenten)
10. Config + Docker + Tests
