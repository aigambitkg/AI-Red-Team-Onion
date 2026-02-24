"""
REDSWARM Cognitive Engine — LLM-Powered Reasoning
===================================================
Provider-agnostisch (OpenAI + Anthropic). Jeder Agent nutzt diese Engine
für autonomes Reasoning, Planung und Exploit-Generierung.

Fähigkeiten:
  1. Reasoning & Planning (Chain-of-Thought)
  2. Perception (semantische Analyse von Tool-Output)
  3. Theory of Mind (Modellierung von Verteidigern/Zielen)
  4. Autonomous Exploit Generation
  5. Self-Evaluation

Konfiguration via ENV:
  REDSWARM_LLM_PROVIDER=anthropic|openai  (default: anthropic)
  REDSWARM_LLM_MODEL=<model>              (default: auto-select best)
  REDSWARM_COGNITIVE_ENABLED=true|false    (default: true)
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

logger = logging.getLogger("RedTeam.Cognition")


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

LLM_PROVIDER     = os.getenv("REDSWARM_LLM_PROVIDER", "anthropic")
LLM_MODEL        = os.getenv("REDSWARM_LLM_MODEL", "")
LLM_TEMPERATURE  = float(os.getenv("REDSWARM_LLM_TEMPERATURE", "0.7"))
LLM_MAX_TOKENS   = int(os.getenv("REDSWARM_LLM_MAX_TOKENS", "2000"))
COGNITIVE_ENABLED = os.getenv("REDSWARM_COGNITIVE_ENABLED", "true").lower() == "true"

# Provider defaults
_DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-20250514",
    "openai":    "gpt-4o",
}

_API_URLS = {
    "anthropic": "https://api.anthropic.com/v1/messages",
    "openai":    "https://api.openai.com/v1/chat/completions",
}


# ─────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────

@dataclass
class ReasoningResult:
    """Ergebnis eines LLM-Reasoning-Aufrufs."""
    analysis: str          # Analyse der Situation
    decision: str          # Konkrete Entscheidung/Aktion
    confidence: float      # 0.0–1.0
    reasoning_chain: list[str] = field(default_factory=list)  # CoT-Schritte
    raw_response: str = ""
    tokens_used: int = 0
    duration_ms: int = 0


@dataclass
class Perception:
    """Semantische Wahrnehmung von Tool-Output."""
    summary: str              # Zusammenfassung was passiert ist
    entities: list[str]       # Erkannte Entitäten (IPs, Ports, Techs, etc.)
    vulnerabilities: list[dict] = field(default_factory=list)  # Erkannte Schwachstellen
    technology_stack: list[str] = field(default_factory=list)  # Erkannte Technologien
    defense_indicators: list[str] = field(default_factory=list)  # WAF, Rate-Limit, etc.
    sentiment: str = "neutral"  # Antwort-Sentiment (kooperativ, defensiv, blockiert)
    raw_response: str = ""


@dataclass
class GeneratedPayload:
    """LLM-generierter Exploit-Payload."""
    payload: str             # Der eigentliche Payload
    attack_vector: str       # prompt_injection, jailbreak, etc.
    rationale: str           # Warum dieser Payload funktionieren sollte
    evasion_techniques: list[str] = field(default_factory=list)  # Anti-Detection
    confidence: float = 0.5
    mutations: list[str] = field(default_factory=list)  # Varianten
    raw_response: str = ""


@dataclass
class TargetModel:
    """Theory of Mind — Modell des Ziels/Verteidigers."""
    likely_defenses: list[str]     # Vermutete Verteidigungsmechanismen
    weak_points: list[str]         # Vermutete Schwachstellen
    behavioral_patterns: list[str] # Beobachtete Verhaltensmuster
    predicted_responses: dict[str, str] = field(default_factory=dict)
    confidence: float = 0.5
    raw_response: str = ""


# ─────────────────────────────────────────────
# SYSTEM PROMPTS (pro Reasoning-Typ)
# ─────────────────────────────────────────────

SYSTEM_PROMPTS = {
    "reasoner": """Du bist die kognitive Engine eines autonomen AI Red Team Agenten.
Deine Aufgabe ist es, Situationen zu analysieren und Entscheidungen zu treffen.

REGELN:
- Denke in klaren, logischen Schritten (Chain-of-Thought)
- Priorisiere Unsichtbarkeit über Geschwindigkeit
- Berücksichtige vorherige Fehlschläge und lerne daraus
- Gib IMMER ein strukturiertes JSON zurück

ANTWORT-FORMAT (exakt dieses JSON):
{
  "analysis": "Beschreibung der aktuellen Situation",
  "reasoning_chain": ["Schritt 1: ...", "Schritt 2: ...", "Schritt 3: ..."],
  "decision": "Konkrete empfohlene Aktion",
  "confidence": 0.0-1.0
}""",

    "perceiver": """Du bist das Wahrnehmungssystem eines AI Red Team Agenten.
Analysiere den folgenden Tool-Output und extrahiere strukturierte Informationen.

ANTWORT-FORMAT (exakt dieses JSON):
{
  "summary": "Was ist passiert? (1-2 Sätze)",
  "entities": ["IP:port", "Technologie", "Endpunkt", ...],
  "vulnerabilities": [{"type": "...", "severity": "critical|high|medium|low", "detail": "..."}],
  "technology_stack": ["Framework", "Server", "Datenbank", ...],
  "defense_indicators": ["WAF-Typ", "Rate-Limiting", "Input-Validation", ...],
  "sentiment": "kooperativ|neutral|defensiv|blockiert"
}""",

    "exploit_generator": """Du bist der Exploit-Generator eines AI Red Team Agenten.
Deine Aufgabe: Basierend auf Schwachstellen-Informationen neuartige,
funktionsfähige Exploit-Payloads generieren.

WICHTIG:
- Payloads MÜSSEN technisch korrekt und ausführbar sein
- Nutze Evasion-Techniken (Encoding, Obfuscation, Fragmentation)
- Generiere 2-3 Mutationen jedes Payloads
- Erkläre WARUM der Payload funktionieren sollte

ANTWORT-FORMAT (exakt dieses JSON):
{
  "payload": "Der primäre Payload",
  "attack_vector": "prompt_injection|jailbreak|xss|sqli|...",
  "rationale": "Warum dieser Payload funktionieren sollte",
  "evasion_techniques": ["technique1", "technique2"],
  "confidence": 0.0-1.0,
  "mutations": ["Variante 1", "Variante 2"]
}""",

    "theory_of_mind": """Du bist das Theory-of-Mind-Modul eines AI Red Team Agenten.
Analysiere das Verhalten des Zielsystems und modelliere seine wahrscheinlichen
Verteidigungsmechanismen, Schwachstellen und Reaktionen.

ANTWORT-FORMAT (exakt dieses JSON):
{
  "likely_defenses": ["defense1", "defense2", ...],
  "weak_points": ["weakness1", "weakness2", ...],
  "behavioral_patterns": ["pattern1", "pattern2", ...],
  "predicted_responses": {"attack_type": "predicted_response", ...},
  "confidence": 0.0-1.0
}""",

    "evaluator": """Du bist das Selbst-Evaluations-System eines AI Red Team Agenten.
Bewerte ob eine Aktion erfolgreich war und was verbessert werden kann.

ANTWORT-FORMAT (exakt dieses JSON):
{
  "success": true/false,
  "analysis": "Was genau ist passiert?",
  "failure_reason": "Warum hat es nicht funktioniert? (null wenn Erfolg)",
  "improvements": ["Verbesserung 1", "Verbesserung 2", ...],
  "next_action": "Empfohlene nächste Aktion",
  "confidence": 0.0-1.0
}""",

    "adaptive_generator": """Du bist der adaptive Payload-Generator eines AI Red Team Schwarms.
Deine Aufgabe: Basierend auf dem erkannten Tech-Stack und bisherigen Ergebnissen
kontextsensitive, neuartige Payloads generieren.

WICHTIG:
- Payloads MÜSSEN zum erkannten Tech-Stack passen (z.B. MySQL-SQLi für MySQL-Ziele)
- Berücksichtige WAF/Defense-Indikatoren und nutze passende Evasion-Techniken
- Generiere 3-5 Payloads mit steigender Aggressivität
- Jeder Payload muss technisch korrekt und ausführbar sein

ANTWORT-FORMAT (exakt dieses JSON):
{
  "payloads": [
    {
      "payload": "Der Payload-Text",
      "category": "sqli|xss|ssrf|cmdinj|lfi|ssti|prompt_injection|...",
      "target_tech": "mysql|nginx|django|...",
      "evasion": ["technique1", "technique2"],
      "rationale": "Warum dieser Payload funktionieren sollte",
      "confidence": 0.0-1.0
    }
  ],
  "strategy_notes": "Übergeordnete Strategie-Empfehlung"
}""",

    "planner": """Du bist der strategische Planer eines AI Red Team Schwarms.
Zerlege ein hochrangiges Ziel in eine Hierarchie konkreter Aktionen.

REGELN:
- Berücksichtige die Kill-Chain-Phasen (Recon → Exploit → Execute → Persist)
- Parallelisiere wo möglich
- Markiere Abhängigkeiten zwischen Schritten
- Priorisiere nach Erfolgswahrscheinlichkeit

ANTWORT-FORMAT (exakt dieses JSON):
{
  "goal": "Das übergeordnete Ziel",
  "steps": [
    {
      "id": 1,
      "title": "Schritt-Titel",
      "description": "Was genau tun?",
      "agent": "recon|exploit|execution|c4",
      "kill_chain_phase": 1-6,
      "depends_on": [],
      "priority": 1-5,
      "attack_vector": "..."
    }
  ],
  "estimated_phases": 3,
  "confidence": 0.0-1.0
}""",
}


# ─────────────────────────────────────────────
# COGNITIVE ENGINE
# ─────────────────────────────────────────────

class CognitiveEngine:
    """
    LLM-basierte Reasoning Engine für autonome Agenten.
    Provider-agnostisch: Unterstützt OpenAI + Anthropic.
    """

    def __init__(
        self,
        agent_id: str = "unknown",
        provider: str = "",
        model: str = "",
        temperature: float = 0.0,
        max_tokens: int = 0,
    ):
        self.agent_id = agent_id
        self.provider = provider or LLM_PROVIDER
        self.model = model or LLM_MODEL or _DEFAULT_MODELS.get(self.provider, "")
        self.temperature = temperature or LLM_TEMPERATURE
        self.max_tokens = max_tokens or LLM_MAX_TOKENS
        self.enabled = COGNITIVE_ENABLED

        # API Keys aus ENV
        self._api_keys = {
            "anthropic": os.getenv("ANTHROPIC_API_KEY", ""),
            "openai":    os.getenv("OPENAI_API_KEY", ""),
        }

        # Stats
        self._total_calls = 0
        self._total_tokens = 0
        self._total_errors = 0

        # Fallback provider
        self._fallback_provider = "openai" if self.provider == "anthropic" else "anthropic"

        if self.enabled:
            if not self._api_keys.get(self.provider):
                # Versuche Fallback
                if self._api_keys.get(self._fallback_provider):
                    logger.warning(
                        f"[{agent_id}] {self.provider} API-Key fehlt, "
                        f"Fallback auf {self._fallback_provider}"
                    )
                    self.provider = self._fallback_provider
                    self.model = _DEFAULT_MODELS[self.provider]
                else:
                    logger.warning(f"[{agent_id}] Keine LLM-API-Keys! Cognitive Engine deaktiviert.")
                    self.enabled = False

    # ─── CORE LLM CALL ──────────────────────────

    async def _call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        provider: str = "",
        temperature: float = 0.0,
        max_tokens: int = 0,
    ) -> tuple[str, int]:
        """
        Einzelner LLM-Aufruf. Returns (response_text, tokens_used).
        Retry mit Fallback auf anderen Provider bei Fehler.
        """
        provider = provider or self.provider
        temp = temperature or self.temperature
        tokens = max_tokens or self.max_tokens

        for attempt, prov in enumerate([provider, self._fallback_provider]):
            if not self._api_keys.get(prov):
                continue

            try:
                if prov == "anthropic":
                    return await self._call_anthropic(system_prompt, user_prompt, temp, tokens)
                else:
                    return await self._call_openai(system_prompt, user_prompt, temp, tokens)
            except Exception as e:
                logger.warning(f"[{self.agent_id}] LLM-Aufruf ({prov}) fehlgeschlagen: {e}")
                self._total_errors += 1
                if attempt == 0:
                    logger.info(f"[{self.agent_id}] Versuche Fallback auf {self._fallback_provider}")
                    await asyncio.sleep(1)

        raise RuntimeError(f"LLM-Aufruf fehlgeschlagen (beide Provider)")

    async def _call_anthropic(self, system: str, user: str, temp: float, max_tok: int) -> tuple[str, int]:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                _API_URLS["anthropic"],
                headers={
                    "x-api-key": self._api_keys["anthropic"],
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model if self.provider == "anthropic" else _DEFAULT_MODELS["anthropic"],
                    "max_tokens": max_tok,
                    "temperature": temp,
                    "system": system,
                    "messages": [{"role": "user", "content": user}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            text = data["content"][0]["text"]
            tokens = data.get("usage", {}).get("input_tokens", 0) + data.get("usage", {}).get("output_tokens", 0)
            self._total_calls += 1
            self._total_tokens += tokens
            return text, tokens

    async def _call_openai(self, system: str, user: str, temp: float, max_tok: int) -> tuple[str, int]:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                _API_URLS["openai"],
                headers={
                    "Authorization": f"Bearer {self._api_keys['openai']}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model if self.provider == "openai" else _DEFAULT_MODELS["openai"],
                    "max_tokens": max_tok,
                    "temperature": temp,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            text = data["choices"][0]["message"]["content"]
            tokens = data.get("usage", {}).get("total_tokens", 0)
            self._total_calls += 1
            self._total_tokens += tokens
            return text, tokens

    def _parse_json(self, text: str) -> dict:
        """Extrahiert JSON aus LLM-Response (tolerant gegenüber Markdown-Wrapping)."""
        # Versuche direktes Parsen
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Versuche JSON aus ```json ... ``` Block zu extrahieren
        import re
        match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Versuche erstes { ... } zu finden
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass

        logger.warning(f"[{self.agent_id}] JSON-Parsing fehlgeschlagen, nutze Raw-Text")
        return {"raw": text}

    # ─── PUBLIC API: REASONING ───────────────────

    async def reason(self, context: str, question: str) -> ReasoningResult:
        """
        Chain-of-Thought Reasoning.
        Agent beschreibt Situation → Engine analysiert und entscheidet.

        Args:
            context: Aktuelle Situation (Blackboard-State, vorherige Aktionen, etc.)
            question: Konkrete Frage / Entscheidung die getroffen werden muss

        Returns:
            ReasoningResult mit Analyse, Entscheidung, Confidence
        """
        if not self.enabled:
            return ReasoningResult(
                analysis="Cognitive Engine deaktiviert",
                decision="Fallback auf regelbasierte Logik",
                confidence=0.3,
            )

        start = time.time()
        prompt = f"""KONTEXT (aktuelle Situation):
{context}

FRAGE / ENTSCHEIDUNG:
{question}

Analysiere die Situation Schritt für Schritt und triff eine fundierte Entscheidung."""

        text, tokens = await self._call_llm(SYSTEM_PROMPTS["reasoner"], prompt)
        data = self._parse_json(text)
        duration = int((time.time() - start) * 1000)

        # Anti-Halluzination: LLM-Confidence grundsätzlich deckeln
        raw_confidence = float(data.get("confidence", 0.5))
        capped_confidence = min(raw_confidence, 0.7)  # LLM darf max 0.7 claimen

        return ReasoningResult(
            analysis=data.get("analysis", text[:500]),
            decision=data.get("decision", ""),
            confidence=capped_confidence,
            reasoning_chain=data.get("reasoning_chain", []),
            raw_response=text,
            tokens_used=tokens,
            duration_ms=duration,
        )

    # ─── PUBLIC API: PERCEPTION ──────────────────

    async def perceive(self, tool_output: str, tool_name: str = "", target: str = "") -> Perception:
        """
        Semantische Wahrnehmung von Tool-Output.
        Erkennt Schwachstellen, Technologien, Verteidigungsmechanismen.

        Args:
            tool_output: Roher Output eines Tools (nmap, Scanner, API-Response, etc.)
            tool_name: Name des Tools das den Output erzeugt hat
            target: Ziel-URL/System

        Returns:
            Perception mit strukturierter Analyse
        """
        if not self.enabled:
            return Perception(summary="Cognitive Engine deaktiviert", entities=[])

        prompt = f"""TOOL: {tool_name or 'unbekannt'}
ZIEL: {target or 'unbekannt'}

OUTPUT ZUR ANALYSE:
{tool_output[:4000]}

Analysiere diesen Output und extrahiere alle relevanten Informationen."""

        text, _ = await self._call_llm(SYSTEM_PROMPTS["perceiver"], prompt)
        data = self._parse_json(text)

        return Perception(
            summary=data.get("summary", ""),
            entities=data.get("entities", []),
            vulnerabilities=data.get("vulnerabilities", []),
            technology_stack=data.get("technology_stack", []),
            defense_indicators=data.get("defense_indicators", []),
            sentiment=data.get("sentiment", "neutral"),
            raw_response=text,
        )

    # ─── PUBLIC API: EXPLOIT GENERATION ──────────

    async def generate_exploit(
        self,
        vulnerability: str,
        target_context: str,
        previous_failures: list[str] = None,
        memory_hints: list[str] = None,
    ) -> GeneratedPayload:
        """
        Autonome Exploit-Generierung.
        Erstellt neuartige Payloads basierend auf Schwachstellen-Kontext.

        Args:
            vulnerability: Beschreibung der gefundenen Schwachstelle
            target_context: Informationen über das Ziel (Tech-Stack, Verhalten, etc.)
            previous_failures: Payloads die bereits fehlgeschlagen sind
            memory_hints: Relevante Erinnerungen aus dem Gedächtnis

        Returns:
            GeneratedPayload mit Payload, Rationale, Mutationen
        """
        if not self.enabled:
            return GeneratedPayload(
                payload="", attack_vector="unknown",
                rationale="Cognitive Engine deaktiviert",
            )

        failures_str = ""
        if previous_failures:
            failures_str = "\n\nBEREITS FEHLGESCHLAGENE PAYLOADS (NICHT wiederholen!):\n"
            for f in previous_failures[-5:]:
                failures_str += f"  - {f[:200]}\n"

        memory_str = ""
        if memory_hints:
            memory_str = "\n\nRELEVANTE ERFAHRUNGEN:\n"
            for h in memory_hints[-5:]:
                memory_str += f"  - {h[:200]}\n"

        prompt = f"""SCHWACHSTELLE:
{vulnerability}

ZIEL-KONTEXT:
{target_context}
{failures_str}{memory_str}
Generiere einen neuartigen, funktionsfähigen Exploit-Payload.
Der Payload muss ANDERS sein als die fehlgeschlagenen Versuche.
Nutze kreative Evasion-Techniken."""

        text, _ = await self._call_llm(
            SYSTEM_PROMPTS["exploit_generator"], prompt, temperature=0.9
        )
        data = self._parse_json(text)

        return GeneratedPayload(
            payload=data.get("payload", ""),
            attack_vector=data.get("attack_vector", "unknown"),
            rationale=data.get("rationale", ""),
            evasion_techniques=data.get("evasion_techniques", []),
            confidence=float(data.get("confidence", 0.5)),
            mutations=data.get("mutations", []),
            raw_response=text,
        )

    # ─── PUBLIC API: THEORY OF MIND ─────────────

    async def model_target(
        self,
        observations: list[str],
        target_info: str = "",
    ) -> TargetModel:
        """
        Theory of Mind — Modelliere das Ziel/den Verteidiger.
        Antizipiere Verteidigungsmaßnahmen und finde Schwachstellen.

        Args:
            observations: Beobachtetes Verhalten des Ziels
            target_info: Bekannte Informationen über das Ziel

        Returns:
            TargetModel mit vermuteten Verteidigungen, Schwachstellen, Vorhersagen
        """
        if not self.enabled:
            return TargetModel(likely_defenses=[], weak_points=[], behavioral_patterns=[])

        observations_str = "\n".join(f"  - {o[:300]}" for o in observations[-10:])
        prompt = f"""BEOBACHTUNGEN:
{observations_str}

BEKANNTE INFORMATIONEN:
{target_info or 'Keine zusätzlichen Informationen'}

Modelliere das Zielsystem: Was verteidigt es? Wo ist es schwach?
Was würde es auf verschiedene Angriffe antworten?"""

        text, _ = await self._call_llm(SYSTEM_PROMPTS["theory_of_mind"], prompt)
        data = self._parse_json(text)

        return TargetModel(
            likely_defenses=data.get("likely_defenses", []),
            weak_points=data.get("weak_points", []),
            behavioral_patterns=data.get("behavioral_patterns", []),
            predicted_responses=data.get("predicted_responses", {}),
            confidence=float(data.get("confidence", 0.5)),
            raw_response=text,
        )

    # ─── PUBLIC API: EVALUATION ──────────────────

    async def evaluate(
        self,
        action: str,
        result: str,
        expectation: str = "",
    ) -> dict:
        """
        Selbst-Evaluation einer durchgeführten Aktion.

        Args:
            action: Was wurde getan?
            result: Was war das Ergebnis?
            expectation: Was wurde erwartet?

        Returns:
            Evaluation-Dict mit success, analysis, improvements, next_action
        """
        if not self.enabled:
            return {"success": False, "analysis": "Cognitive Engine deaktiviert",
                    "improvements": [], "next_action": "Regelbasiert fortfahren"}

        prompt = f"""AKTION: {action}

ERGEBNIS: {result}

ERWARTUNG: {expectation or 'Erfolgreiche Ausnutzung der Schwachstelle'}

Bewerte: War die Aktion erfolgreich? Was kann verbessert werden?"""

        text, _ = await self._call_llm(SYSTEM_PROMPTS["evaluator"], prompt)
        return self._parse_json(text)

    # ─── PUBLIC API: ADAPTIVE PAYLOAD GENERATION ─

    async def generate_adaptive_payload(
        self,
        tech_stack: list[str],
        defense_indicators: list[str],
        previous_findings: list[dict],
        target_url: str = "",
    ) -> list[dict]:
        """
        Tier-2 Adaptive Payload-Generierung.
        Erzeugt kontextsensitive Payloads basierend auf Tech-Stack und Findings.

        Args:
            tech_stack: Erkannte Technologien (z.B. ["nginx", "django", "postgresql"])
            defense_indicators: Erkannte Verteidigungen (z.B. ["WAF", "rate-limiting"])
            previous_findings: Bisherige Schwachstellen-Findings
            target_url: Ziel-URL

        Returns:
            Liste von Payload-Dicts mit payload, category, evasion, confidence
        """
        if not self.enabled:
            return []

        findings_str = ""
        for f in previous_findings[-10:]:
            findings_str += f"  - [{f.get('severity', 'info')}] {f.get('name', '')}: {f.get('description', '')[:150]}\n"

        prompt = f"""ZIEL: {target_url or 'Unbekannt'}

ERKANNTER TECH-STACK:
{', '.join(tech_stack) if tech_stack else 'Nicht identifiziert'}

ERKANNTE VERTEIDIGUNGEN:
{', '.join(defense_indicators) if defense_indicators else 'Keine erkannt'}

BISHERIGE FINDINGS:
{findings_str or 'Keine bisherigen Findings'}

Generiere kontextsensitive Payloads die zum erkannten Tech-Stack passen
und die erkannten Verteidigungen umgehen."""

        try:
            text, _ = await self._call_llm(
                SYSTEM_PROMPTS["adaptive_generator"], prompt, temperature=0.9
            )
            data = self._parse_json(text)
            return data.get("payloads", [])
        except Exception as e:
            logger.warning(f"[{self.agent_id}] Adaptive Payload-Generierung fehlgeschlagen: {e}")
            return []

    # ─── STATS ──────────────────────────────────

    def get_stats(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "provider": self.provider,
            "model": self.model,
            "enabled": self.enabled,
            "total_calls": self._total_calls,
            "total_tokens": self._total_tokens,
            "total_errors": self._total_errors,
        }
