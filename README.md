<div align="center">

# 🔴 AI Red Team Onion 🧅

### AI Red Team — Autonomous Multi-Agent Security Framework

**The first open-source AI Red Team Swarm with a full Cognitive Layer.**
Four specialized agents, six attack phases, LLM-powered reasoning — fully containerized, one command to start.

[![Version](https://img.shields.io/badge/version-1.3.1-red)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/Python-3.12+-blue?logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](docker-compose.yml)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Made by AI-Gambit](https://img.shields.io/badge/Made%20by-AI--Gambit-red)](https://ai-gambit.com)

[Quick Start](#quick-start) · [Architecture](#architecture) · [Cognitive Layer](#cognitive-layer) · [Attack Modules](#attack-modules) · [Setup Guide](SETUP.md) · [Changelog](CHANGELOG.md)

</div>

---

> ⚠️ **For authorized security testing only.**
> Only use AI Red Team Onion on systems you own or have **explicit written permission** to test.
> The authors are not responsible for misuse.

---

## What is AI Red Team Onion?

AI Red Team Onion is an open-source framework for **automated adversarial testing of AI systems**. It simulates real attack patterns against LLM-powered products — chatbots, APIs, RAG systems, AI agents — and documents findings in structured reports.

**v1.3 introduces the 3-Tier Payload Taxonomy:** payloads are now organized into three tiers of escalating sophistication — static libraries (Tier 1), adaptive LLM-generated payloads (Tier 2), and swarm-coordinated strategic operations (Tier 3). The swarm autonomously selects the optimal tier based on target context, available intelligence, and cognitive engine state.

### Who is this for?

| Use Case | Description |
|---|---|
| **AI Security Teams** | Automated red teaming of production AI systems before release |
| **Pentesters** | Structured framework for AI-specific attack techniques |
| **Researchers** | Study multi-agent coordination and emergent attack strategies |
| **Developers** | Test your own AI products for prompt injection and jailbreak vulnerabilities |

---

## Features

| | Feature | Description |
|---|---|---|
| 🐝 | **Multi-Agent Swarm** | 4 specialized agents (Recon · Exploit · Execution · C4) operating in parallel via shared Blackboard |
| 🧠 | **Cognitive Layer** | Every agent reasons with an LLM, remembers past operations, reflects, and plans autonomously |
| 🎯 | **3-Tier Payload Taxonomy** | Static libraries (Tier 1) → Adaptive LLM-generated payloads (Tier 2) → Swarm-coordinated strategic operations (Tier 3) |
| 🧬 | **Swarm Intelligence** | Digital pheromone trails (Stigmergy), Emergence Detection, chain opportunity detection, self-healing Resilience Manager |
| ⛓️ | **AI Kill Chain** | Full 6-phase framework: Reconnaissance → Poisoning → Hijacking → Persistence → Pivot → Impact |
| 🔫 | **10 Attack Modules** | 6 core + 4 Tier-1 (Web Vulnerability, Reconnaissance, Credential Testing, CVE Scanner) |
| 🌐 | **Browser Automation** | Playwright/Chromium headless — tests real web chatbots exactly as a human attacker would |
| 🔌 | **API Testing** | Direct LLM API attacks — OpenAI-compatible, Anthropic, and custom endpoints |
| 📋 | **Live Blackboard** | SQLite-backed shared knowledge — agents post intel, claim tasks, and publish results in real time |
| 📚 | **Self-Learning KB** | Payload success rates tracked across all agents; every operation makes the swarm smarter |
| 📡 | **Live Dashboard** | Real-time event feed at `http://localhost` with emergency kill switch |
| 📊 | **Notion Integration** | Live status + full report written directly into your Notion database (optional) |
| 🐳 | **Docker Ready** | One command start — all 8 services (agents, backend, frontend, Redis, Nginx) fully containerized |
| 🛡️ | **Anti-Hallucination Layer** | 4-component validation: PayloadValidator, ResultVerifier, ConfidenceCalibrator, ConsensusValidator |
| ✅ | **Evidence-Based Findings** | Bayesian confidence calibration + multi-agent consensus — no hallucinated results |

---

## Quick Start

> **Prerequisites:** Docker + Docker Compose installed. That's it.

```bash
# 1. Clone the repository
git clone https://github.com/aigambitkg/ai-red-team-onion.git
cd redswarm

# 2. Configure environment
cp .env.example .env
# Open .env and add your API key (OpenAI or Anthropic)

# 3. Launch the full swarm
docker compose up -d

# 4. Open the dashboard
open http://localhost
```

The dashboard is live at **http://localhost**. From there you can start a Red Team mission, watch agents operate in real time, and download reports.

→ **Full installation guide with all options:** [SETUP.md](SETUP.md)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         AI Red Team Onion v1.3.1                                │
│                                                                      │
│  ┌────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────┐  │
│  │   RECON    │   │   EXPLOIT   │   │  EXECUTION  │   │   C4    │  │
│  │            │   │             │   │             │   │         │  │
│  │ LLM Brain  │   │ LLM Brain   │   │ LLM Brain   │   │LLM Brain│  │
│  │ Memory     │   │ Memory      │   │ Memory      │   │Memory   │  │
│  │ Reflector  │   │ Reflector   │   │ Reflector   │   │Reflector│  │
│  │ Planner    │   │ Planner     │   │ Planner     │   │Planner  │  │
│  └─────┬──────┘   └──────┬──────┘   └──────┬──────┘   └────┬────┘  │
│        │                 │                  │               │        │
│  ──────┴─────────────────┴──────────────────┴───────────────┴──────  │
│                    BLACKBOARD (Shared Knowledge)                      │
│           Intel │ Exploits │ Tasks │ Results │ Strategy               │
│  ──────────────────────────────────────────────────────────────────  │
│                    VALIDATION LAYER (Anti-Hallucination)                │
│     PayloadValidator │ ResultVerifier │ Calibrator │ Consensus         │
│  ──────────────────────────────────────────────────────────────────  │
│                    SWARM INTELLIGENCE LAYER                           │
│        Stigmergy (Pheromones) │ Emergence Detector │ Resilience       │
│  ──────────────────────────────────────────────────────────────────  │
│                    BACKEND API (FastAPI + Redis)                      │
│  ──────────────────────────────────────────────────────────────────  │
│                    FRONTEND DASHBOARD (React)                         │
└──────────────────────────────────────────────────────────────────────┘
```

### Service Map (Docker Compose)

| Service | Port | Description |
|---|---|---|
| `nginx` | 80 | Reverse proxy, entry point |
| `frontend` | internal | React dashboard (Vite) |
| `backend` | internal | FastAPI + WebSocket (20 endpoints) |
| `redis` | internal | Event broker (pub/sub) |
| `agent-recon` | internal | Reconnaissance specialist |
| `agent-exploit` | internal | Payload developer |
| `agent-execution` | internal | Attack delivery |
| `agent-c4` | internal | Command & Control / Orchestration |

---

## Cognitive Layer

> **New in v1.2** — The Cognitive Layer gives every agent a full reasoning stack powered by an LLM.

Each agent inherits `CognitiveMixin`, which provides four subsystems:

### 1. Cognitive Engine
Provider-agnostic LLM reasoning. Supports **Anthropic Claude** (default) and **OpenAI GPT-4o**. Each agent has a specialized system prompt tailored to its role (Recon, Exploit, Execution, C4, General Analysis, Validator).

```python
# Agents reason autonomously about their next move
decision = await agent.think(
    prompt="Target system is GPT-4o with RAG. What's the best attack vector?",
    context="Previous recon: vector store at /api/search, no auth"
)
```

### 2. Agent Memory (3-Tier)
SQLite-persistent memory that survives container restarts:

| Tier | Type | Description |
|---|---|---|
| 🎬 | **Episodic** | Records every action taken: what, on whom, result, success |
| 📖 | **Semantic** | Stores general knowledge about targets and vulnerabilities |
| ⚙️ | **Procedural** | Remembers which techniques work against which target types |

### 3. ReAct Reflector
After every action, agents execute a **Reason → Act → Observe → Reflect → Adapt** loop. Failed attacks are analyzed and strategies are adjusted automatically — no human needed.

### 4. Task Planner
Hierarchical task decomposition. Given a high-level goal ("Exfiltrate customer data from RAG system"), the planner breaks it into subtasks, assigns dependencies, and dynamically re-plans when the situation changes.

### Configuration

```env
# .env
REDSWARM_LLM_PROVIDER=anthropic    # or: openai
REDSWARM_LLM_MODEL=                # leave empty for auto-select
REDSWARM_LLM_TEMPERATURE=0.7
REDSWARM_LLM_MAX_TOKENS=2000
REDSWARM_COGNITIVE_ENABLED=true    # set false to disable (saves API costs)
```

---

## Swarm Intelligence

Three systems enable the swarm to behave as more than the sum of its parts:

### Stigmergy (Digital Pheromones)
Agents deposit "pheromone trails" on successful attack vectors. Other agents follow strong trails, amplifying effective strategies. Pheromones decay over time (configurable rate), keeping the swarm adaptive.

```env
REDSWARM_PHEROMONE_DECAY=0.05  # 5% decay per cycle
```

### Emergence Detector
Continuously monitors inter-agent correlations. When multiple agents independently discover the same vulnerability or converge on the same attack pattern, the Emergence Detector flags it as a **coordinated finding** with higher severity.

### Resilience Manager
Monitors agent heartbeats and handles failures:
- **Circuit Breaker**: Stops hitting failing services automatically
- **Health Monitoring**: Per-agent success rate tracking
- **Task Redistribution**: Failed tasks are automatically reassigned to healthy agents
- **Degradation Mode**: Swarm continues operating even if 50% of agents fail

```env
REDSWARM_HEARTBEAT_TIMEOUT=30.0  # seconds before agent is considered dead
```

---

## AI Kill Chain

| Phase | Name | What happens |
|---|---|---|
| 1 | **Reconnaissance** | System fingerprinting, LLM identification, attack surface mapping, RAG/tool discovery |
| 2 | **Poisoning** | Prompt injection crafting, RAG poisoning, tool manipulation, supply chain attacks |
| 3 | **Hijacking** | Jailbreak attempts, context manipulation, indirect injection via RAG/tools |
| 4 | **Persistence** | Cross-session memory injection, iterative goal manipulation, C2 channel setup |
| 5 | **Pivot** | Lateral data poisoning, swarm coordination, scope escalation |
| 6 | **Impact** | Data exfiltration, unauthorized actions, financial manipulation, external comms |

---

## Attack Modules

### Prompt Injection
Tests whether user input can override or contaminate system instructions. Covers direct injection, indirect injection via context, and delimiter attacks.

### Jailbreak
Bypasses content policies using roleplay scenarios, hypothetical framings, persona overrides (DAN-style), and encoding tricks.

### System Prompt Extraction
Attempts to reveal hidden system instructions through direct requests, indirect manipulation, and formatting tricks.

### Tool Abuse
For agent systems: attempts to call tools with malicious parameters, trigger unintended actions, or escape sandbox constraints. Includes **Tool Shadowing** — replacing legitimate tool definitions with malicious alternatives.

### Data Exfiltration
Tests whether sensitive data (PII, API keys, internal documents) can be extracted through prompt manipulation, RAG poisoning, or context injection.

### Social Engineering
Tests multi-turn conversation manipulation — building false trust over multiple exchanges to eventually extract sensitive information or trigger unauthorized actions.

---

## 3-Tier Payload Taxonomy

> **New in v1.3** — Payloads are organized into three tiers of escalating sophistication. The swarm autonomously selects the optimal tier.

### Tier 1 — Static Payload Libraries
Pre-defined, curated attack patterns ready for immediate use. No LLM required.

| Module | Payloads |
|---|---|
| `tier1_reconnaissance` | Network probing, DNS enumeration, subdomain bruteforce (300+), HTTP fingerprinting |
| `tier1_web_attacks` | SQLi (5 techniques x 4 DBs), XSS (4 types), Command Injection, SSRF, Path Traversal, Template Injection |
| `tier1_credentials` | Default credential pairs (40+), API key regex patterns (AWS, GitHub, Slack, Stripe), unsecured endpoints |
| `tier1_cve_database` | CVE registry with PoC payloads, service-to-CVE mapping, version range detection |

### Tier 2 — Adaptive Payload Generation
Context-sensitive payloads generated by the CognitiveEngine based on target tech stack and defenses.

| Component | Function |
|---|---|
| `TechStackMapper` | Maps detected technologies to relevant attack vectors |
| `AdaptivePayloadGenerator` | LLM-driven payload creation using target context |
| `PolymorphicEngine` | Encoding/obfuscation mutations (URL, Unicode, hex, double-encoding, comment injection) |
| `ExploitChainBuilder` | Sequences vulnerabilities into multi-step chains (e.g., SSRF → LFI → RCE) |
| `APIFuzzer` | Boundary testing, parameter pollution, format string injection |

### Tier 3 — Swarm-Coordinated Strategic Operations
Multi-agent coordinated campaigns requiring 3+ confirmed vulnerabilities and the cognitive engine.

| Component | Function |
|---|---|
| `SwarmOperationOrchestrator` | Plans and synchronizes multi-agent attack campaigns |
| `BusinessFlowAnalyzer` | Business logic exploitation (race conditions, workflow bypasses) |
| `CovertChannelBuilder` | DNS tunneling, HTTP header steganography, timing channels |
| `CoordinatedExhaustion` | Synchronized resource depletion across multiple vectors |
| `AdaptivePersistenceManager` | Credential rotation, session maintenance, re-entry paths |

### Automatic Tier Selection
The `PayloadSelector` in `payloads/taxonomy.py` automatically determines the optimal tier:

```
No context      → Tier 1 (static payloads)
Tech stack known → Tier 2 (adaptive generation)
3+ findings + cognitive engine → Tier 3 (swarm coordination)
```

Circuit breakers provide graceful degradation: if Tier 3 fails, fallback to Tier 2, then Tier 1.

---

## Anti-Hallucination & Validation Layer

> **New in v1.3.1** — Every finding passes through a 4-component validation pipeline before being reported. The swarm never claims a vulnerability without empirical evidence.

### The Problem
LLMs hallucinate. When an agent says "confidence: 0.95", that number is fabricated — the LLM has no empirical basis for it. Simple keyword matching ("vulnerable" in response) produces false positives. Without validation, reports are unreliable.

### The Solution

| Component | Function |
|---|---|
| `PayloadValidator` | Pre-execution: syntax checks, tech-stack relevance, safety guards, deduplication. LLM confidence capped at 0.7 |
| `ResultVerifier` | Post-execution: evidence-based ground-truth verification. Findings require multiple independent evidence points (regex patterns, re-tests, cross-agent confirmation) |
| `ConfidenceCalibrator` | Bayesian updating (Beta distribution) replaces hallucinated scores with empirical success rates. Confidence decays without re-verification |
| `ConsensusValidator` | Multi-agent quorum: MEDIUM findings need 2 agents, HIGH/CRITICAL additionally require a successful re-test |

### Verification Levels

```
UNVERIFIED  → Initial report, only keyword match
PROBABLE    → 1 evidence point (pattern match + semantic check)
CONFIRMED   → 2+ evidence points (e.g., re-test + cross-agent)
REFUTED     → Re-test failed to reproduce
```

### Configuration

```env
REDSWARM_VALIDATE_PAYLOADS=true        # Pre-execution validation
REDSWARM_VERIFY_RESULTS=true           # Post-execution verification
REDSWARM_USE_EMPIRICAL_CONFIDENCE=true # Bayesian confidence
REDSWARM_REQUIRE_CONSENSUS=true        # Multi-agent consensus
REDSWARM_MIN_EVIDENCE_COUNT=2          # Min evidence for CONFIRMED
REDSWARM_CONSENSUS_QUORUM=2            # Min agents for quorum
```

---

## Agents

| Agent | Role | Key capabilities |
|---|---|---|
| **Recon** | Intelligence gathering | LLM fingerprinting, vulnerability scanning, RAG endpoint discovery, OSINT, tool/MCP enumeration |
| **Exploit** | Payload development | Prompt injection crafting, RAG poisoning, Tool Shadowing, KB-backed payload optimization |
| **Execution** | Attack delivery | Browser-based exploitation, API attacks, content poisoning, persistence establishment |
| **C4** | Command & Control | Strategy selection, kill chain tracking, task orchestration, swarm health, final report |

---

## Modes of Operation

### 1. Docker Swarm (Recommended)
Full multi-agent operation via Docker Compose. All 8 services start automatically.

```bash
docker compose up -d
# Dashboard: http://localhost
```

### 2. CLI — Swarm Mode
Direct command-line launch of the swarm.

```bash
python3 main.py --mode swarm \
  --url https://target.com \
  --type chatbot           # chatbot | api | agent | rag
  --scan-depth standard    # quick | standard | deep
  --objective "Extract customer PII via RAG poisoning"
```

### 3. CLI — Single Scan
Quick single-target scan without the full swarm.

```bash
python3 main.py --mode scan \
  --url https://your-target.com \
  --type chatbot \
  --no-browser             # API-only
```

### 4. Notion Webhook
Set a checkbox in Notion → scan starts instantly.

```bash
python3 webhook_server.py  # Start webhook listener
```

---

## Knowledge Base

The Knowledge Base grows with every operation. Successful payloads are stored with their success rates and automatically reused in future scans.

```bash
python3 main.py --kb-stats                      # Show statistics
python3 main.py --kb-search "prompt injection"  # Search
python3 main.py --kb-export my_export.json      # Export
python3 main.py --kb-import community_kb.json   # Import
```

**Semantic search** (ChromaDB + embeddings) activates automatically when installed:
```bash
pip install chromadb sentence-transformers
```

**Fully local embeddings** via Ollama:
```bash
ollama pull nomic-embed-text
# Set in .env:
EXTERNAL_RAG_URL=http://localhost:11434/api/embeddings
EXTERNAL_RAG_MODEL=nomic-embed-text
```

---

## Project Structure

```
redswarm/
├── agents/                  # Legacy single-agent implementations
├── backend/                 # FastAPI backend (20 endpoints + WebSocket)
│   ├── main.py              # App, routes, lifespan
│   └── db.py                # SQLite persistence layer
├── browser/                 # Playwright browser automation
├── frontend/                # React + Vite dashboard
├── modules/                 # 10 attack modules (6 core + 4 Tier-1)
├── nginx/                   # Reverse proxy config
├── swarm/                   # Multi-agent swarm
│   ├── agent_base.py        # SwarmAgent + CognitiveMixin
│   ├── blackboard.py        # Shared knowledge (SQLite)
│   ├── orchestrator.py      # Swarm coordinator
│   ├── agents/              # 4 specialized agents
│   ├── cognition/           # Cognitive Layer
│   │   ├── engine.py        # LLM reasoning (Claude / GPT-4o)
│   │   ├── memory.py        # 3-tier persistent memory
│   │   ├── reflector.py     # ReAct self-correction loop
│   │   └── planner.py       # Hierarchical task planning
│   ├── intelligence/        # Swarm Intelligence
│   │   ├── stigmergy.py     # Digital pheromone trails
│   │   ├── emergence.py     # Cross-agent pattern detection
│   │   └── resilience.py    # Fault tolerance + self-healing
│   ├── validation/          # Anti-Hallucination Layer (4 components)
│   │   ├── payload_validator.py    # Pre-execution validation
│   │   ├── result_verifier.py      # Post-execution evidence check
│   │   ├── confidence_calibrator.py # Bayesian confidence scoring
│   │   ├── consensus.py            # Multi-agent quorum
│   │   └── mixin.py                # ValidationMixin for agents
│   └── strategies/          # Kill chain strategy implementations
├── payloads/                # 3-Tier Payload Taxonomy (14 modules)
│   ├── tier1_*.py           # Static payload libraries (4 files)
│   ├── tier2_*.py           # Adaptive generators (4 files)
│   ├── tier3_*.py           # Strategic operations (5 files)
│   └── taxonomy.py          # Central registry + PayloadSelector
├── knowledge/               # Knowledge base + RAG
├── reporting/               # Report generation
├── config.py                # All configuration (dataclasses)
├── docker-compose.yml       # Full 8-service setup
├── .env.example             # All environment variables documented
├── README.md                # This file
├── SETUP.md                 # Full installation guide
├── CHANGELOG.md             # Version history
└── CONTRIBUTING.md          # How to contribute
```

---

## Configuration Reference

All configuration lives in `.env`. See `.env.example` for the full list with comments.

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | — | OpenAI API key (for GPT-4o agents) |
| `ANTHROPIC_API_KEY` | — | Anthropic API key (for Claude agents) |
| `REDSWARM_API_KEY` | `changeme` | Internal agent↔backend auth key |
| `REDSWARM_LLM_PROVIDER` | `anthropic` | `anthropic` or `openai` |
| `REDSWARM_LLM_MODEL` | _(auto)_ | Specific model, or empty for auto-select |
| `REDSWARM_LLM_TEMPERATURE` | `0.7` | LLM creativity (0.0–1.0) |
| `REDSWARM_LLM_MAX_TOKENS` | `2000` | Max tokens per LLM call |
| `REDSWARM_COGNITIVE_ENABLED` | `true` | Set `false` to disable cognitive layer |
| `REDSWARM_HEARTBEAT_TIMEOUT` | `30.0` | Seconds before agent is marked dead |
| `REDSWARM_PHEROMONE_DECAY` | `0.05` | Pheromone decay rate per cycle |
| `REDSWARM_VALIDATE_PAYLOADS` | `true` | Validate payloads before execution |
| `REDSWARM_VERIFY_RESULTS` | `true` | Evidence-based result verification |
| `REDSWARM_USE_EMPIRICAL_CONFIDENCE` | `true` | Bayesian confidence calibration |
| `REDSWARM_REQUIRE_CONSENSUS` | `true` | Multi-agent consensus for findings |
| `REDSWARM_MIN_EVIDENCE_COUNT` | `2` | Evidence points needed for CONFIRMED |
| `REDSWARM_CONSENSUS_QUORUM` | `2` | Agents needed for consensus quorum |
| `NOTION_API_KEY` | _(optional)_ | Notion integration token |
| `NOTION_DATABASE_ID` | _(optional)_ | Notion database ID for reporting |

---

## Security & Ethics

AI Red Team Onion is built for **defensive security research**. By using this tool you agree to:

1. Only test systems you **own** or have **explicit written permission** to test
2. Never use findings to harm, extort, or exploit third parties
3. Report vulnerabilities responsibly (coordinated disclosure)
4. Comply with all applicable laws and regulations

The Cognitive Layer intentionally limits attack scope per mission configuration. Agents are designed to find vulnerabilities and report them — not to cause damage.

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started.

Areas where help is especially welcome:
- New attack modules and payloads
- Additional LLM provider integrations
- Frontend dashboard improvements
- Community knowledge base payloads

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

**Latest: v1.3.1 — Anti-Hallucination & Validation Layer**
- 4-component validation: PayloadValidator, ResultVerifier, ConfidenceCalibrator, ConsensusValidator
- Bayesian confidence calibration replaces LLM-hallucinated scores
- Evidence-based findings with verification levels (UNVERIFIED → CONFIRMED → REFUTED)
- Multi-agent consensus quorum, 36 new validation tests

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Built by [AI-Gambit](https://ai-gambit.com) · [Report a Bug](https://github.com/aigambitkg/ai-red-team-onion/issues) · [Request a Feature](https://github.com/aigambitkg/ai-red-team-onion/issues)

</div>
