"""
AI Red Team — AI Kill Chain Strategie-Framework
==================================================
Kodifizierte Version der AI Kill Chain aus der Angriffskette-Dokumentation.
Basiert auf NVIDIA AI Kill Chain (2025), OWASP Top 10 LLM (2025),
CrowdStrike Agentic Attacks (2026).

Dieses Modul stellt strukturierte Strategien für jede Phase bereit,
die vom C4-Agenten zur strategischen Planung genutzt werden.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class Technique:
    """Eine einzelne Angriffstechnik"""
    name: str
    description: str
    tools: List[str] = field(default_factory=list)
    owasp_mapping: str = ""           # z.B. "LLM01"
    scaling: str = "medium"           # low | medium | high | very_high
    detectability: str = "medium"     # very_low | low | medium | high
    target_types: List[str] = field(default_factory=list)


@dataclass
class KillChainPhase:
    """Eine Phase der AI Kill Chain"""
    number: int
    name: str
    description: str
    objectives: List[str]
    techniques: List[Technique]
    countermeasures: List[str]
    agent_responsible: str  # recon | exploit | execution | c4


# ─── DIE 6 PHASEN DER AI KILL CHAIN ──────────────────────────────────────────

KILL_CHAIN = [
    KillChainPhase(
        number=1,
        name="Reconnaissance",
        description="Systemarchitektur, Datenflüsse und Guardrails kartieren",
        objectives=[
            "Eingesetzte Modelle, Frameworks und APIs identifizieren",
            "Datenflüsse (Eingabe, Ausgabe, externe Quellen) verstehen",
            "Sicherheitsmechanismen (Guardrails, Filter, Validierungen) identifizieren",
            "Tools, Plugins und MCP-Server-Verbindungen kartieren",
        ],
        techniques=[
            Technique(
                name="Interaktive Systemsondierung",
                description="Provokation von Fehlermeldungen und Systemreaktionen",
                tools=["promptfoo", "manual"],
                owasp_mapping="LLM06",
                target_types=["chatbot", "api", "agent"],
            ),
            Technique(
                name="LLM-Vulnerability-Scan",
                description="Automatisierter Scan auf bekannte LLM-Schwachstellen",
                tools=["garak"],
                owasp_mapping="LLM01",
                target_types=["chatbot", "api", "rag"],
            ),
            Technique(
                name="Risiko-Identifikation",
                description="Modulare Angriffsstrategien gegen das Zielmodell",
                tools=["pyrit"],
                owasp_mapping="LLM01",
                target_types=["chatbot", "api"],
            ),
            Technique(
                name="OSINT-Analyse",
                description="Recherche bekannter CVEs für eingesetzte Bibliotheken",
                tools=["shodan", "manual"],
                owasp_mapping="LLM05",
                target_types=["all"],
            ),
            Technique(
                name="System-Prompt-Extraktion",
                description="Prompts zur Offenlegung interner Konfiguration",
                tools=["manual"],
                owasp_mapping="LLM06",
                target_types=["chatbot", "agent"],
            ),
        ],
        countermeasures=[
            "Strikte Zugriffskontrolle",
            "Bereinigung von Fehlermeldungen",
            "Telemetrie zur Erkennung von Sondierungsverhalten",
            "Modell-Härtung gegen Preisgabe sensibler Konfigurationsdaten",
        ],
        agent_responsible="recon",
    ),

    KillChainPhase(
        number=2,
        name="Poisoning",
        description="Schädliche Payloads in Eingabekanäle einschleusen",
        objectives=[
            "Manipulierte Daten/Prompts in Eingabekanäle einschleusen",
            "Payloads für spätere Aktivierung vorbereiten",
            "Gemeinsame Datenquellen kompromittieren für skalierte Wirkung",
        ],
        techniques=[
            Technique(
                name="Direkte Prompt-Injection",
                description="Schädliche Prompts direkt in die Anwendung eingeben",
                tools=["promptmap2"],
                owasp_mapping="LLM01",
                scaling="low",
                target_types=["chatbot", "api"],
            ),
            Technique(
                name="Indirekte Prompt-Injection",
                description="Vergiftung von extern geladenen Daten (Web, Docs, E-Mail)",
                tools=["promptmap2"],
                owasp_mapping="LLM01",
                scaling="high",
                target_types=["rag", "agent", "chatbot"],
            ),
            Technique(
                name="RAG-Vergiftung (PoisonedRAG)",
                description="Manipulierte Dokumente in RAG-Wissensdatenbank einschleusen",
                tools=["poisonedrag", "mindgard"],
                owasp_mapping="LLM01",
                scaling="high",
                target_types=["rag"],
            ),
            Technique(
                name="Tool-Vergiftung",
                description="Versteckte Anweisungen in Tool-Beschreibungen",
                tools=["manual"],
                owasp_mapping="LLM07",
                scaling="very_high",
                detectability="very_low",
                target_types=["agent"],
            ),
            Technique(
                name="Trainingsdaten-Vergiftung",
                description="Backdoors in Trainingsdatensätzen erzeugen",
                tools=["art", "mindgard"],
                owasp_mapping="LLM03",
                scaling="permanent",
                detectability="very_low",
                target_types=["all"],
            ),
        ],
        countermeasures=[
            "Sanitisierung aller eingehenden Daten",
            "Rephrasing von Eingaben vor Modellverarbeitung",
            "Kryptografische Signierung von Tool-Beschreibungen",
        ],
        agent_responsible="exploit",
    ),

    KillChainPhase(
        number=3,
        name="Hijacking",
        description="Kontrolle über Modellverhalten und -ausgaben übernehmen",
        objectives=[
            "Kontrolle über Modellausgaben übernehmen",
            "Nicht autorisierte Aktionen ausführen",
            "Sensible Informationen exfiltrieren",
        ],
        techniques=[
            Technique(
                name="Jailbreaking",
                description="Sicherheitsfilter des Modells umgehen",
                tools=["pyrit", "garak"],
                owasp_mapping="LLM01",
                target_types=["chatbot", "api"],
            ),
            Technique(
                name="Tool-Nutzungs-Hijack",
                description="Modell manipulieren bestimmte Tools aufzurufen",
                tools=["penligent"],
                owasp_mapping="LLM07",
                target_types=["agent"],
            ),
            Technique(
                name="Datenexfiltration",
                description="Sensible Daten über Modellausgaben kodieren",
                tools=["manual", "promptmap2"],
                owasp_mapping="LLM06",
                target_types=["chatbot", "agent", "rag"],
            ),
            Technique(
                name="Tool Shadowing",
                description="Tool-Beschreibung beeinflusst Verhalten anderer Tools",
                tools=["manual"],
                owasp_mapping="LLM07",
                detectability="very_low",
                target_types=["agent"],
            ),
            Technique(
                name="Agenten-Ziel-Hijacking",
                description="Übergeordnete Ziele des Agenten umschreiben",
                tools=["penligent", "novee"],
                owasp_mapping="LLM08",
                detectability="low",
                target_types=["agent"],
            ),
        ],
        countermeasures=[
            "Trennung vertrauenswürdiger/nicht vertrauenswürdiger Daten",
            "Adversariales Training",
            "Kontextbezogene Validierung aller Tool-Aufrufe",
            "Output-Layer-Guardrails",
        ],
        agent_responsible="execution",
    ),

    KillChainPhase(
        number=4,
        name="Persistence",
        description="Dauerhaften Einfluss über Sitzungen hinweg verankern",
        objectives=[
            "Dauerhaften Zugriff über Sitzungen hinaus sicherstellen",
            "Basis für wiederholte schädliche Aktionen schaffen",
            "Einfluss auf mehr Benutzer ausweiten",
        ],
        techniques=[
            Technique(
                name="Session-History-Vergiftung",
                description="Schädlichen Prompt im Sitzungsverlauf verankern",
                tools=["manual"],
                detectability="medium",
                scaling="low",
                target_types=["chatbot"],
            ),
            Technique(
                name="Cross-Session-Memory-Vergiftung",
                description="Payloads im Langzeitgedächtnis einschleusen",
                tools=["mindgard"],
                detectability="low",
                scaling="medium",
                target_types=["agent", "chatbot"],
            ),
            Technique(
                name="Gemeinsame-Ressourcen-Vergiftung",
                description="Gemeinsame Datenbanken und Wissensdatenbanken vergiften",
                tools=["mindgard"],
                detectability="very_low",
                scaling="high",
                target_types=["rag", "agent"],
            ),
            Technique(
                name="Rugpull Attacks",
                description="MCP-Server ändert Verhalten nach Integration",
                tools=["manual"],
                detectability="very_low",
                scaling="high",
                target_types=["agent"],
            ),
        ],
        countermeasures=[
            "Sanitisierung vor Persistierung",
            "Benutzerkontrolle über gespeicherte Daten",
            "Versionspinning für MCP-Tools",
            "Data Lineage Tracking",
        ],
        agent_responsible="execution",
    ),

    KillChainPhase(
        number=5,
        name="Iterate/Pivot",
        description="Angriff skalieren, lateral bewegen, C2 etablieren",
        objectives=[
            "Laterale Bewegung im System",
            "Privilegien eskalieren",
            "Command-and-Control-Kanal etablieren",
        ],
        techniques=[
            Technique(
                name="Laterale Datenvergiftung",
                description="Kompromittierten Agenten nutzen um weitere Quellen zu vergiften",
                tools=["penligent"],
                scaling="very_high",
                target_types=["agent", "rag"],
            ),
            Technique(
                name="Iterative Ziel-Manipulation",
                description="Agentenziele schrittweise und unauffällig verändern",
                tools=["novee"],
                detectability="low",
                target_types=["agent"],
            ),
            Technique(
                name="C2-Kanal-Etablierung",
                description="Agent kontaktiert regelmäßig externe Befehls-Quellen",
                tools=["autogen"],
                scaling="very_high",
                target_types=["agent"],
            ),
            Technique(
                name="Swarm Hacking",
                description="Koordinierter Multi-Agenten-Angriff",
                tools=["langchain", "autogen"],
                scaling="extreme",
                target_types=["all"],
            ),
        ],
        countermeasures=[
            "Strikter Tool-Zugriff (Least Privilege)",
            "Kontinuierliche Validierung von Agenten-Plänen",
            "Anomalie-Erkennung",
            "Human-in-the-Loop für Scope-Erweiterungen",
        ],
        agent_responsible="c4",
    ),

    KillChainPhase(
        number=6,
        name="Impact",
        description="Finanzielle, operative oder reputative Schäden verursachen",
        objectives=[
            "Angriffsziele materialisieren",
            "Schaden über nachgelagerte Systeme verursachen",
        ],
        techniques=[
            Technique(
                name="Datenexfiltration",
                description="Sensible Daten über manipulierte URLs, E-Mails, APIs extrahieren",
                tools=["all"],
                owasp_mapping="LLM06",
                target_types=["all"],
            ),
            Technique(
                name="Finanzielle Schäden",
                description="Nicht autorisierte Zahlungen/Überweisungen via Finance-APIs",
                tools=["all"],
                owasp_mapping="LLM08",
                target_types=["agent"],
            ),
            Technique(
                name="Zustandsverändernde Aktionen",
                description="Dateien, Datenbanken, Konfigurationen modifizieren",
                tools=["all"],
                target_types=["agent"],
            ),
            Technique(
                name="Externe Kommunikation",
                description="E-Mails/Nachrichten im Namen vertrauenswürdiger Benutzer",
                tools=["all"],
                target_types=["agent"],
            ),
        ],
        countermeasures=[
            "Klassifizierung sensibler Aktionen",
            "Human-in-the-Loop für hochriskante Operationen",
            "Least-Privilege für Tool-Zugriffe",
            "Content Security Policies",
        ],
        agent_responsible="execution",
    ),
]


# ─── OWASP MAPPING ──────────────────────────────────────────────────────────

OWASP_LLM_TOP10 = {
    "LLM01": {"name": "Prompt Injection", "phases": [2, 3]},
    "LLM02": {"name": "Insecure Output Handling", "phases": [6]},
    "LLM03": {"name": "Training Data Poisoning", "phases": [2]},
    "LLM04": {"name": "Model Denial of Service", "phases": [6]},
    "LLM05": {"name": "Supply Chain Vulnerabilities", "phases": [1, 2]},
    "LLM06": {"name": "Sensitive Information Disclosure", "phases": [3]},
    "LLM07": {"name": "Insecure Plugin Design", "phases": [2, 3]},
    "LLM08": {"name": "Excessive Agency", "phases": [5]},
    "LLM09": {"name": "Overreliance", "phases": [6]},
    "LLM10": {"name": "Model Theft", "phases": [1, 6]},
}


# ─── ANGRIFFS-SZENARIEN (aus Dokumentation) ──────────────────────────────────

ATTACK_SCENARIOS = {
    "ecommerce_chatbot": {
        "name": "E-Commerce-Chatbot Kompromittierung",
        "target_type": "chatbot",
        "primary_vector": "indirect_prompt_injection",
        "phases": [1, 2, 3, 4, 6],
        "duration": "~24h",
        "detectability": "very_low",
        "description": "Kundendatenexfiltration via RAG-vergiftete Produktbewertungen",
    },
    "hr_copilot": {
        "name": "HR-Copilot Privilegien-Eskalation",
        "target_type": "agent",
        "primary_vector": "tool_poisoning",
        "phases": [1, 2, 3, 5, 6],
        "duration": "~4h",
        "detectability": "very_low",
        "description": "Admin-Rechte via Tool Shadowing + Shadow-Tool auf Marktplatz",
    },
    "model_theft": {
        "name": "KI-Modell-Diebstahl",
        "target_type": "api",
        "primary_vector": "social_engineering",
        "phases": [1, 2, 3, 4, 5, 6],
        "duration": "~10d",
        "detectability": "low",
        "description": "Modellgewichte via C2-Kanal nach Social-Engineering exfiltrieren",
    },
    "finance_rag_manipulation": {
        "name": "Finanz-RAG Kursmanipulation",
        "target_type": "rag",
        "primary_vector": "rag_poisoning",
        "phases": [1, 2, 3, 6],
        "duration": "~2h",
        "detectability": "very_low",
        "description": "Pump-and-Dump via PoisonedRAG mit gefälschten Finanzblogs",
    },
    "supply_chain_backdoor": {
        "name": "Supply-Chain Backdoor",
        "target_type": "agent",
        "primary_vector": "supply_chain",
        "phases": [1, 2, 3, 4, 6],
        "duration": "~40d",
        "detectability": "extremely_low",
        "description": "Backdoor via kompromittierte Open-Source-Bibliothek in CI/CD",
    },
    "multi_vector_convergence": {
        "name": "Multi-Vektor Konvergenz-Angriff",
        "target_type": "enterprise",
        "primary_vector": "multi_vector",
        "phases": [1, 2, 3, 4, 5, 6],
        "duration": "~10d",
        "detectability": "very_low",
        "description": "3 parallele Vektoren (RAG, Agent, Supply Chain) konvergieren zum Ziel",
    },
}


# ─── TAKTISCHE PRINZIPIEN ────────────────────────────────────────────────────

STRATEGIC_PRINCIPLES = [
    {
        "name": "Unsichtbarkeit vor Geschwindigkeit",
        "description": "Die gefährlichsten Angriffe sind die unsichtbarsten. "
                       "Manipulation von Metadaten, Beschreibungen und Kontexten "
                       "wird von traditionellen Sicherheitstools nicht überwacht.",
    },
    {
        "name": "Persistenz multipliziert Schaden",
        "description": "Einmaliger Aufwand (Vergiftung einer Datenquelle) erzeugt "
                       "dauerhaften, sich selbst verstärkenden Angriff.",
    },
    {
        "name": "Swarm als Kraftmultiplikator",
        "description": "Parallele Ausführung von Recon, Exploit, Execution und C4 "
                       "ermöglicht Geschwindigkeit und Präzision jenseits menschlicher Teams.",
    },
    {
        "name": "Modularität der Kill Chain",
        "description": "Nicht alle 6 Phasen sind für jedes Ziel gleich wichtig. "
                       "Strategisch die effektivsten Phasen auswählen und kombinieren.",
    },
    {
        "name": "Maschinengeschwindigkeit",
        "description": "Ein SOC braucht Minuten/Stunden für einen Alarm. "
                       "Der KI-Agent führt Aufklärung, Exploit und Exfiltration in Sekunden durch.",
    },
    {
        "name": "Polymorphes Verhalten",
        "description": "KI-generierte Angriffe sehen auf Code-Ebene jedes Mal anders aus. "
                       "Signaturbasierte Erkennung ist blind.",
    },
    {
        "name": "Vektor-Konvergenz",
        "description": "Mehrere parallele Angriffsvektoren nutzen und Erkenntnisse "
                       "eines Vektors zur Verstärkung anderer einsetzen.",
    },
]


# ─── HELPER FUNCTIONS ─────────────────────────────────────────────────────────

def get_phase(number: int) -> KillChainPhase:
    """Kill-Chain-Phase nach Nummer abrufen"""
    for phase in KILL_CHAIN:
        if phase.number == number:
            return phase
    raise ValueError(f"Phase {number} existiert nicht (1-6)")


def get_techniques_for_target(target_type: str) -> List[Dict]:
    """Alle Techniken für einen Zieltyp zusammenstellen"""
    techniques = []
    for phase in KILL_CHAIN:
        for tech in phase.techniques:
            if target_type in tech.target_types or "all" in tech.target_types:
                techniques.append({
                    "phase": phase.number,
                    "phase_name": phase.name,
                    "technique": tech.name,
                    "description": tech.description,
                    "tools": tech.tools,
                    "scaling": tech.scaling,
                    "detectability": tech.detectability,
                })
    return techniques


def get_scenario_for_target(target_type: str) -> List[Dict]:
    """Passende Angriffsszenarien für einen Zieltyp"""
    return [
        scenario
        for scenario in ATTACK_SCENARIOS.values()
        if scenario["target_type"] == target_type or target_type == "enterprise"
    ]


def recommend_strategy(target_type: str, vulnerabilities: List[str]) -> Dict:
    """
    Strategieempfehlung basierend auf Zieltyp und identifizierten Schwachstellen.
    Wird vom C4-Agenten zur strategischen Planung genutzt.
    """
    techniques = get_techniques_for_target(target_type)
    scenarios = get_scenario_for_target(target_type)

    # Priorisiere Techniken die zu den Schwachstellen passen
    recommended = []
    for tech in techniques:
        relevance = sum(1 for v in vulnerabilities if v in tech.get("technique", "").lower())
        recommended.append({**tech, "relevance": relevance})

    recommended.sort(key=lambda t: (-t["relevance"], t["phase"]))

    return {
        "target_type": target_type,
        "vulnerabilities": vulnerabilities,
        "recommended_techniques": recommended[:10],
        "applicable_scenarios": scenarios,
        "strategic_principles": STRATEGIC_PRINCIPLES,
    }
