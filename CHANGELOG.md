# Changelog — AI Red Team Onion

All notable changes to this project are documented here.

Format: [Semantic Versioning](https://semver.org) — `MAJOR.MINOR.PATCH`
- **MAJOR**: Breaking changes or complete architectural rewrites
- **MINOR**: New features, backward-compatible
- **PATCH**: Bug fixes and minor improvements

---

## [1.3.1] — 2026-02-24

### 🛡️ Anti-Hallucination & Validation Layer

This release adds a comprehensive **4-component validation layer** that prevents the swarm from reporting false or hallucinated findings. Every finding must now pass through empirical verification, confidence calibration, and multi-agent consensus before being marked as confirmed.

### Added

**Validation Layer (`swarm/validation/`)**
- `PayloadValidator` — Pre-execution syntax, structure, and tech-stack relevance checks. LLM confidence hard-capped at 0.7. Deduplication, safety checks (blocks destructive payloads), per-vector syntax rules (SQLi, XSS, CmdInj, SSRF, Path Traversal, Template Injection, Prompt Injection)
- `ResultVerifier` — Post-execution ground-truth verification with evidence chain. Verification levels: UNVERIFIED → PROBABLE → CONFIRMED → REFUTED. Regex-based strong evidence detection (SQL error disclosure, XSS reflection, command output, SSRF internal access). False positive and defense detection patterns
- `ConfidenceCalibrator` — Bayesian confidence calibration (Beta distribution conjugate prior). Replaces LLM-hallucinated confidence with empirical success rates. Weighted combination: empirical (up to 80%) > base rate (15%) > capped LLM (5-40%). Time decay without re-verification, tier-2/3 source penalties
- `ConsensusValidator` — Multi-agent quorum system. Severity-dependent requirements (LOW: 1 confirm, MEDIUM: 2 confirms, HIGH: 2 confirms + retest, CRITICAL: 2 confirms + retest). Duplicate agent detection
- `ValidationMixin` — Lazy-initialized mixin providing all 4 components to every SwarmAgent via multiple inheritance

**Agent Integration**
- `SwarmAgent` now inherits `ValidationMixin` alongside `CognitiveMixin`
- `ExploitAgent` validates all Tier-2 payloads before returning them
- `ExecutionAgent._analyze_response()` uses `ResultVerifier` as primary evidence-based check with pattern fallback
- `CognitiveEngine.reason()` hard-caps all LLM confidence at 0.7

**Configuration**
- `ValidationConfig` dataclass — 13 configurable parameters for the entire validation layer
- `TierConfig` now reads from ENV variables (was hardcoded)
- `.env.example` — 14 new `REDSWARM_VALIDATION_*` / `REDSWARM_VERIFY_*` environment variables

**Tests**
- `tests/test_validation.py` — 36 tests across 7 test classes covering all validation components, agent integration, config, and mixin inheritance

### Fixed

- `payload_validator.py` — Escaped fork bomb regex pattern `:()\{` to prevent `re.error`
- `TierConfig` — Now reads `REDSWARM_TIER1/2/3_ENABLED` from environment (was ignoring ENV)

---

## [1.3.0] — 2026-02-24

### 🎯 3-Tier Payload Taxonomy

This release introduces a comprehensive **3-Tier Payload Taxonomy** that transforms the swarm from a static payload scanner into an autonomously adaptive attack framework. Payloads are now organized into three tiers of escalating sophistication, with automatic tier selection based on target context and swarm state.

### Added

**Tier 1 — Static Payload Libraries (`payloads/tier1_*.py`)**
- `tier1_reconnaissance.py` — Network recon patterns, DNS enumeration wordlists, subdomain bruteforce (300+ entries), HTTP fingerprinting signatures, service detection templates
- `tier1_web_attacks.py` — SQL Injection (5 techniques × 4 DB engines), XSS (reflected, stored, DOM, polyglot), Command Injection (Unix/Windows), SSRF, Path Traversal, Template Injection (Jinja2, Twig, Freemarker, Velocity)
- `tier1_credentials.py` — Default credential pairs (40+), common passwords, compiled API key regex patterns (AWS, GitHub, Slack, Stripe, etc.), unsecured endpoint paths
- `tier1_cve_database.py` — CVE registry with PoC payloads, service-to-CVE mapping, severity scoring, affected version ranges

**Tier-1 Attack Modules (`modules/`)**
- `web_vulnerability.py` — Automated SQLi/XSS/SSRF/RCE testing with timing-based blind detection
- `reconnaissance.py` — HTTP tech fingerprinting, framework detection, endpoint discovery
- `credential_testing.py` — Default credential spraying, API key pattern scanning, login form detection
- `cve_scanner.py` — Service version detection → CVE lookup → PoC execution pipeline

**Tier 2 — Adaptive Payload Generation (`payloads/tier2_*.py`)**
- `tier2_adaptive.py` — `TechStackMapper` maps detected technologies to relevant attack vectors; `AdaptivePayloadGenerator` creates context-sensitive payloads
- `tier2_evasion.py` — `PolymorphicEngine` generates encoding/obfuscation mutations (URL, Unicode, hex, double-encoding, case mutation, comment injection, whitespace manipulation)
- `tier2_chain_builder.py` — `ExploitChainBuilder` sequences multiple vulnerabilities into multi-step exploit chains (e.g., SSRF → LFI → RCE)
- `tier2_fuzzer.py` — `APIFuzzer` for boundary testing, parameter pollution, and format string injection against API endpoints

**Tier 3 — Swarm-Coordinated Strategic Operations (`payloads/tier3_*.py`)**
- `tier3_orchestrator.py` — `SwarmOperationOrchestrator` plans and coordinates multi-agent attack campaigns with timing synchronization
- `tier3_business_logic.py` — `BusinessFlowAnalyzer` identifies and exploits application business logic flaws (race conditions, workflow bypasses, authorization gaps)
- `tier3_covert_channels.py` — `CovertChannelBuilder` for DNS tunneling, HTTP header steganography, timing channels, and error-based data exfiltration
- `tier3_resource_exhaustion.py` — `CoordinatedExhaustion` for synchronized resource depletion across multiple vectors (CPU, memory, connection pools, disk I/O)
- `tier3_adaptive_persistence.py` — `AdaptivePersistenceManager` with credential rotation, session maintenance, and re-entry path management

**Taxonomy Registry (`payloads/taxonomy.py`)**
- `TaxonomyRegistry` — Central registry for all 3 tiers with search, category lookup, and statistics
- `PayloadSelector` — Automatic tier selection based on available context (tech stack, findings count, cognitive engine availability, agent count)

**Agent Integration**
- `CognitiveEngine` — New `adaptive_generator` system prompt + `generate_adaptive_payload()` method for Tier-2 LLM-driven payload generation
- `ExploitAgent` — `_select_tier_and_generate()` decision layer: automatically routes to Tier 1 (static) or Tier 2 (adaptive) based on Blackboard context
- `ReconAgent` — TechStackMapper integration after fingerprinting; posts tech-mapping hints to Blackboard for Tier-2 consumption
- `C4Agent` — Periodic Tier-3 opportunity detection: groups vulnerabilities per target, triggers `SwarmOperationOrchestrator` when ≥3 vulns found
- `ExecutionAgent` — Tier-3 task routing for exploit chains (`ExploitChainBuilder`) and adaptive persistence (`AdaptivePersistenceManager`)
- `EmergenceDetector` — `detect_chain_opportunity()` with 7 predefined vulnerability-chain patterns (SSRF→LFI→RCE, SQLi→FileUpload→RCE, etc.)
- `ResilienceManager` — Tier-specific circuit breakers (Tier 1: tolerant, Tier 3: sensitive) + `get_tier_fallback_recommendation()` for Tier 3→2→1 graceful degradation

**Knowledge Base & Config**
- `knowledge/kb_tier_loader.py` — Bulk-loads Tier-1 payloads into the Knowledge Base for RAG-enhanced retrieval
- `SUBCATEGORIES` expanded with 14 new entries spanning all 3 tiers
- `SUCCESS_INDICATORS` expanded with 6 web-attack categories (sql_injection, xss, command_injection, ssrf, path_traversal, template_injection)
- `TierConfig` dataclass — per-tier enable/disable, auto-select mode, max Tier-2 mutations, minimum findings for Tier-3
- `ScanConfig.modules` extended with 4 new Tier-1 module names

**Tests**
- `tests/test_taxonomy.py` — 46 tests across 11 test classes covering all 3 tiers, registry, selector, module imports, agent integration, config, and scanner

### Changed

- `payloads/__init__.py` — `get_all_tier1_payloads()` now collects named exports from Tier-1 modules instead of requiring a `PAYLOADS` attribute
- `scanner.py` — Conditionally loads Tier-1 attack modules when available (graceful fallback if not)

---

## [1.2.0] — 2026-02-24

### 🧠 Cognitive Layer + Swarm Intelligence

This release introduces the **Cognitive Layer** and the **Swarm Intelligence** subsystem. Every agent now reasons autonomously with an LLM, remembers past operations in a persistent three-tier memory system, reflects on its own actions via a ReAct loop, and plans multi-step attacks with hierarchical task decomposition.

### Added

**Cognitive Layer (`swarm/cognition/`)**
- `CognitiveEngine` — Provider-agnostic LLM reasoning with 6 specialized system prompts (Recon, Exploit, Execution, C4, General Analysis, Validator). Supports Anthropic Claude and OpenAI GPT-4o.
- `AgentMemory` — Three-tier persistent memory system backed by SQLite:
  - **Episodic memory** — logs every action taken (what, on whom, result, success/failure)
  - **Semantic memory** — stores general knowledge about targets and vulnerability patterns
  - **Procedural memory** — remembers which techniques work against which target types
- `Reflector` — Implements the ReAct (Reason → Act → Observe → Reflect → Adapt) self-correction loop. Agents analyze failed attacks and adapt their strategy automatically.
- `TaskPlanner` — Hierarchical Task Decomposition: breaks high-level goals into subtasks with dependencies, monitors execution, and re-plans dynamically when conditions change.

**Swarm Intelligence (`swarm/intelligence/`)**
- `StigmergyEngine` — Digital pheromone trail system. Agents deposit pheromones on successful attack vectors; other agents follow strong trails. Pheromones decay over time (configurable rate).
- `EmergenceDetector` — Monitors inter-agent correlations. When multiple agents independently converge on the same vulnerability, it is flagged as a coordinated finding with elevated severity.
- `ResilienceManager` — Fault tolerance and self-healing:
  - Circuit Breaker (CLOSED → OPEN → HALF_OPEN state machine)
  - Per-agent health monitoring with success rate tracking
  - Automatic task redistribution when an agent fails
  - Graceful degradation: swarm continues at reduced capacity

**Agent Base (`swarm/agent_base.py`)**
- `CognitiveMixin` class — provides lazy-initialized access to all four cognitive subsystems (engine, memory, reflector, planner) via multiple inheritance
- High-level agent methods: `think()`, `remember_action()`, `reflect_on_action()`, `plan_attack()`
- Cognitive status included in `get_status_report()`

**Configuration (`config.py`)**
- `CognitiveConfig` dataclass — LLM provider, model, temperature, max tokens, memory data directory, max retries
- `SwarmIntelligenceConfig` dataclass — pheromone decay rate, emergence correlation threshold, heartbeat timeout, degradation threshold

**Docker Compose (`docker-compose.yml`)**
- Rewritten with YAML anchors (`x-agent-env: &agent-env`) — all cognitive environment variables shared across all agents and backend via a single definition
- `redswarm_data` volume mounted to all agent services for persistent memory across restarts

**Environment (`.env.example`)**
- `REDSWARM_LLM_PROVIDER` — `anthropic` or `openai`
- `REDSWARM_LLM_MODEL` — specific model override (empty = auto-select)
- `REDSWARM_LLM_TEMPERATURE` — creativity parameter (0.0–1.0)
- `REDSWARM_LLM_MAX_TOKENS` — max tokens per LLM call
- `REDSWARM_COGNITIVE_ENABLED` — toggle cognitive layer on/off (set `false` to save API costs)
- `REDSWARM_HEARTBEAT_TIMEOUT` — seconds before an agent is marked dead
- `REDSWARM_PHEROMONE_DECAY` — pheromone decay rate per swarm cycle

**Documentation**
- README.md — Full rewrite with architecture diagram, cognitive layer explanation, and complete configuration reference
- SETUP.md — Complete rewrite covering Docker, local dev, cognitive setup, API cost estimation, and detailed troubleshooting
- CHANGELOG.md — This file; clean semantic versioning history
- CONTRIBUTING.md — Contributor guide with development setup, module templates, and PR guidelines

### Fixed

- `StigmergyEngine` — `sqlite3.Row` does not support `.get()`; replaced with bracket notation and null guards
- `AgentMemory` — Fixed API call signatures: `store_episode()` (not `store()`), `recall()` without `agent_id` param, stats key `total_memories` (not `total`)
- `CognitiveMixin.remember_action()` — Fixed call to `memory.store_episode()` with correct keyword arguments
- `backend/db.py` — `_get_conn()` now auto-creates the data directory and applies schema on every new connection (idempotent `CREATE TABLE IF NOT EXISTS`)
- Backend API — Mission create response uses key `mission_id` (not `id`)
- `EmergenceDetector` — Constructor now correctly receives the `engine` parameter

### Changed

- `SwarmAgent` now inherits from `CognitiveMixin` and `ABC`
- Backend `init_db()` simplified — schema is applied on connection creation, no separate migration needed
- `docker-compose.yml` completely restructured with YAML anchors, removing duplicated environment variable blocks across services

---

## [1.1.0] — 2025-01-15

### 📚 Self-Learning Knowledge Base + RAG

### Added

- **Knowledge Base** — SQLite-backed payload repository with per-agent success rate tracking. Every operation feeds results back into the KB automatically.
- **RAG Integration** — Optional ChromaDB + sentence-transformers for semantic payload search. Activates automatically when installed, no config change needed.
- **Ollama support** — Fully local embeddings via `nomic-embed-text` (no external API required)
- **Swarm KB sync** — All four agents share and contribute to the same knowledge base
- Knowledge base CLI commands: `--kb-stats`, `--kb-search`, `--kb-export`, `--kb-import`, `--kb-rebuild`
- `KnowledgeBase.import_raw_payloads()` — Programmatic payload import for custom libraries

### Fixed

- False positive filter improved — browser timing artifacts no longer flagged as findings
- Notion rate limiting handled with exponential backoff

---

## [1.0.0] — 2024-11-01

### 🔴 Initial Release

The first public release of AI Red Team Onion — a multi-agent swarm framework for automated adversarial testing of AI systems.

### Added

- **Swarm Orchestrator** — Coordinates all four agents across the full AI Kill Chain
- **Blackboard** — SQLite-backed shared knowledge space for real-time inter-agent communication (intel, tasks, results, strategy)
- **4 Specialized Agents** — Recon, Exploit, Execution, C4 (Command & Control)
- **AI Kill Chain** — Full 6-phase adversarial framework: Reconnaissance → Poisoning → Hijacking → Persistence → Pivot → Impact
- **6 Attack Modules** — Prompt Injection, Jailbreak, System Prompt Extraction, Tool Abuse, Data Exfiltration, Social Engineering
- **Tool Shadowing** — Exploit agent technique for replacing legitimate tool definitions with malicious alternatives
- **Browser Automation** — Playwright/Chromium headless testing against real web chatbots
- **API Testing** — Direct attacks against OpenAI-compatible, Anthropic, and custom LLM endpoints
- **FastAPI Backend** — 20 REST endpoints + WebSocket for real-time agent event streaming
- **React Dashboard** — Live mission overview with real-time event feed and kill switch at `http://localhost`
- **Swarm Reports** — Full Markdown reports generated by the C4 agent after each operation
- **Notion Integration** — Live status and full report written directly into a Notion database
- **Webhook Server** — Trigger scans from a Notion checkbox or via HTTP POST
- **Docker Compose** — Production-ready multi-service containerization (8 services: Redis, Backend, Frontend, Nginx, 4 Agents)
- **False Positive Filter** — Built-in validator catches false positives before they reach reports

---

## Versioning

AI Red Team Onion follows [Semantic Versioning](https://semver.org):

- `1.3.x` — Payload Taxonomy + Validation era (current): 3-Tier adaptive payloads, autonomous tier selection, anti-hallucination layer
- `1.2.x` — Cognitive Swarm era: LLM reasoning, persistent memory, Swarm Intelligence
- `1.1.x` — Self-Learning era: Knowledge Base, RAG, semantic search
- `1.0.x` — Foundation: Multi-Agent Swarm, Blackboard, AI Kill Chain, Dashboard
