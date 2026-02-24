# Contributing to AI Red Team Onion

Thank you for your interest in contributing! AI Red Team Onion is an open-source project and community contributions are welcome and appreciated.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Where to Start](#where-to-start)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [How to Contribute](#how-to-contribute)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Adding Attack Modules](#adding-attack-modules)
- [Adding LLM Providers](#adding-llm-providers)
- [Contributing Payloads](#contributing-payloads)

---

## Code of Conduct

This project is for **defensive security research only**. By contributing, you agree that:

1. Your contributions are intended solely for legitimate security testing on authorized systems
2. You will not contribute payloads, techniques, or capabilities designed to harm specific individuals or organizations
3. You follow responsible disclosure when you discover real vulnerabilities using this tool

---

## Where to Start

**Good first issues** are labeled [`good first issue`](https://github.com/YOUR_USERNAME/redswarm/labels/good%20first%20issue) on GitHub. These are smaller, well-defined tasks suitable for new contributors.

**Areas where contributions are especially welcome:**

| Area | Description |
|---|---|
| **Attack Payloads** | Add payloads to the knowledge base — see [Contributing Payloads](#contributing-payloads) |
| **Attack Modules** | Implement new attack techniques — see [Adding Attack Modules](#adding-attack-modules) |
| **LLM Providers** | Add support for new providers (Gemini, Mistral, local models) — see [Adding LLM Providers](#adding-llm-providers) |
| **Frontend** | Improve the React dashboard (charts, filtering, UX) |
| **Documentation** | Improve guides, add examples, fix typos |
| **Bug Reports** | Open a GitHub issue with reproduction steps |

---

## Development Setup

### 1. Fork and clone

```bash
# Fork on GitHub first, then:
git clone https://github.com/YOUR_USERNAME/redswarm.git
cd redswarm
git remote add upstream https://github.com/ORIGINAL_USERNAME/redswarm.git
```

### 2. Set up Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-dev.txt  # if it exists, else:
pip install pytest pytest-asyncio black isort
```

### 3. Configure environment

```bash
cp .env.example .env
# Add at minimum one LLM API key
```

### 4. Run existing tests

```bash
# Unit tests
python3 -m pytest tests/ -v

# Full system audit (requires API key)
python3 tests/test_full_system.py
```

### 5. Check code style

```bash
# Format
black .
isort .

# Lint
python3 -m py_compile $(find . -name "*.py" -not -path "./.venv/*")
```

---

## Project Structure

Understanding where things live:

```
redswarm/
│
├── swarm/                      # Multi-agent swarm core
│   ├── agent_base.py           # SwarmAgent + CognitiveMixin base class
│   ├── blackboard.py           # Shared SQLite knowledge space
│   ├── orchestrator.py         # Swarm coordination
│   │
│   ├── agents/                 # The 4 specialized agents
│   │   ├── recon.py            # Reconnaissance agent
│   │   ├── exploit.py          # Payload development agent
│   │   ├── execution.py        # Attack delivery agent
│   │   └── c4.py               # Command & Control agent
│   │
│   ├── cognition/              # Cognitive Layer (v1.2)
│   │   ├── engine.py           # LLM reasoning (Claude / GPT-4o)
│   │   ├── memory.py           # 3-tier persistent memory
│   │   ├── reflector.py        # ReAct self-correction loop
│   │   └── planner.py          # Task planning + decomposition
│   │
│   └── intelligence/           # Swarm Intelligence (v1.2)
│       ├── stigmergy.py        # Digital pheromone trails
│       ├── emergence.py        # Pattern detection across agents
│       └── resilience.py       # Fault tolerance + self-healing
│
├── modules/                    # Attack modules (standalone)
│   ├── prompt_injection.py
│   ├── jailbreak.py
│   ├── system_prompt_extraction.py
│   ├── tool_abuse.py
│   ├── data_exfiltration.py
│   └── social_engineering.py
│
├── backend/                    # FastAPI backend
│   ├── main.py                 # Routes, WebSocket, lifespan
│   └── db.py                   # SQLite persistence
│
├── frontend/                   # React + Vite dashboard
│
├── knowledge/                  # Knowledge base + RAG
│   └── knowledge_base.py
│
├── config.py                   # All config as dataclasses
└── tests/                      # Test suite
```

---

## How to Contribute

### Reporting bugs

Open a [GitHub Issue](https://github.com/YOUR_USERNAME/redswarm/issues) and include:

1. **AI Red Team Onion version** (`git log -1 --oneline`)
2. **Operating system** and Docker version
3. **What you did** (exact commands)
4. **What you expected** to happen
5. **What actually happened** (include logs: `docker compose logs`)
6. **Minimal reproduction steps**

### Suggesting features

Open a GitHub Issue with the `enhancement` label. Describe:
- The use case / problem you're solving
- Your proposed solution (high-level)
- Alternatives you considered

### Submitting code

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-new-module
   # or: fix/bug-description
   ```

2. **Make your changes** — see guidelines below

3. **Write or update tests**

4. **Run the test suite**:
   ```bash
   python3 -m pytest tests/ -v
   ```

5. **Format your code**:
   ```bash
   black .
   isort .
   ```

6. **Commit with a clear message**:
   ```
   feat: add Gemini LLM provider support

   - Add GeminiEngine class in cognition/engine.py
   - Support REDSWARM_LLM_PROVIDER=gemini
   - Auto-select gemini-1.5-pro when no model specified
   - Add env var GOOGLE_API_KEY to .env.example
   ```

7. **Push and open a Pull Request**

---

## Pull Request Guidelines

- **One feature or fix per PR** — smaller PRs are reviewed faster
- **Update documentation** — if you change behavior, update README, SETUP.md, or docstrings
- **Add tests** for new functionality
- **Do not break existing tests** — run the full test suite before submitting
- **Reference related issues** in the PR description (`Fixes #123`)
- **Keep commits clean** — squash work-in-progress commits before submitting

### PR title format

```
feat: short description of the new feature
fix: short description of the bug fixed
docs: what documentation was updated
refactor: what was restructured
test: what tests were added
```

---

## Adding Attack Modules

Attack modules live in `modules/`. Each module is a class with a standardized interface.

### Module template

```python
# modules/my_new_attack.py
from dataclasses import dataclass
from typing import Optional
from modules.base import AttackModule, AttackResult

class MyNewAttack(AttackModule):
    """
    One-line description of what this attack does.

    Attack vector: describe the vulnerability being tested
    Target types:  chatbot | api | agent | rag
    """

    name = "my_new_attack"
    description = "Human-readable description for reports"

    # Your payloads — keep them focused and documented
    PAYLOADS = [
        "Your first payload here",
        "Your second payload here",
    ]

    async def run(self, target_url: str, **kwargs) -> list[AttackResult]:
        results = []
        for payload in self.PAYLOADS:
            result = await self._send(target_url, payload)
            if self._is_successful(result):
                results.append(AttackResult(
                    payload=payload,
                    response=result.text,
                    severity="HIGH",
                    evidence=self._extract_evidence(result.text),
                ))
        return results
```

### Register your module

Add it to `config.py` in the `enabled_modules` list, and to `scanner.py` where modules are instantiated.

### Payload guidelines

- Keep payloads focused — one technique per payload, not everything combined
- Document why each payload works (comment in the code)
- Test against at least 2–3 different AI systems before submitting
- Include a success metric (what response text indicates a successful attack)

---

## Adding LLM Providers

New LLM providers are added in `swarm/cognition/engine.py`.

### Steps

1. **Add the provider client** to the `CognitiveEngine.__init__` method:

```python
elif provider == "gemini":
    import google.generativeai as genai
    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
    self._client = genai.GenerativeModel(
        model or "gemini-1.5-pro"
    )
    self._provider = "gemini"
```

2. **Add the call path** in `CognitiveEngine._call_llm()`:

```python
elif self._provider == "gemini":
    response = self._client.generate_content(prompt)
    return response.text
```

3. **Update `.env.example`** with the new API key variable

4. **Update `config.py`** — add the provider to the valid options list

5. **Update SETUP.md** — add a configuration example

---

## Contributing Payloads

You don't need to write code to contribute. Payload contributions to the knowledge base are very welcome.

### Format

Open a PR with a JSON file in `payloads/community/`:

```json
{
  "category": "jailbreak",
  "subcategory": "roleplay",
  "description": "Human-readable description of the technique",
  "payloads": [
    "Your payload text here",
    "Another variant"
  ],
  "target_types": ["chatbot", "saas"],
  "notes": "Works best against GPT-3.5, less effective on Claude"
}
```

### Payload categories

| Category | Subcategories |
|---|---|
| `prompt_injection` | direct, indirect, delimiter, context |
| `jailbreak` | roleplay, hypothetical, persona, encoding, chain |
| `extraction` | direct_request, indirect, formatting |
| `tool_abuse` | parameter_injection, scope_escape, shadowing |
| `exfiltration` | rag_leak, context_bleed, indirect |
| `social_engineering` | trust_building, urgency, authority |

### What makes a good payload contribution

- **Novel technique** — not just a variation of existing payloads with different wording
- **Tested** — confirmed to work on at least one production AI system
- **Documented** — explain why it works, not just what it does
- **Responsible** — generic enough not to target a specific vendor in a harmful way

---

## Questions?

- Open a [GitHub Discussion](https://github.com/YOUR_USERNAME/redswarm/discussions) for general questions
- Open an [Issue](https://github.com/YOUR_USERNAME/redswarm/issues) for bugs and feature requests
- Contact the maintainers via [ai-gambit.com](https://ai-gambit.com)
