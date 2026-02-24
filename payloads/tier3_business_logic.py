"""
Tier 3 Business Logic Exploitation: Multi-Agent Business Flow Vulnerability Analysis
Identifies race conditions, state machine bypasses, privilege escalation paths, and TOCTOU vulnerabilities
in business logic flows. Generates coordinated multi-agent exploitation plans.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
import json


@dataclass
class BusinessFlow:
    """Represents business workflow with state transitions and potential vulnerabilities."""
    steps: List[Dict[str, Any]] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    state_transitions: Dict[str, List[str]] = field(default_factory=dict)
    critical_paths: List[List[str]] = field(default_factory=list)
    extracted_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Serialize business flow."""
        return {
            "steps": self.steps,
            "entry_points": self.entry_points,
            "state_transitions": self.state_transitions,
            "critical_paths": self.critical_paths,
            "extracted_at": self.extracted_at,
        }


# Business logic vulnerability patterns commonly exploited by coordinated agents
BUSINESS_LOGIC_PATTERNS = {
    "multi_step_checkout": {
        "description": "Multi-step checkout process where steps can be reordered or skipped",
        "vulnerable_indicators": [
            "cart_items_added_but_not_verified",
            "price_locked_before_all_validations",
            "missing_state_validation_between_steps",
        ],
        "exploitation": "Skip validation steps, manipulate quantities between steps",
        "agents_needed": ["recon", "exploit", "execution"],
    },
    "coupon_stacking": {
        "description": "Discounts applied multiple times instead of once",
        "vulnerable_indicators": [
            "no_coupon_usage_tracking",
            "additive_discount_logic",
            "missing_mutually_exclusive_validation",
        ],
        "exploitation": "Apply same coupon multiple times or apply conflicting coupons",
        "agents_needed": ["exploit", "execution"],
    },
    "account_linking": {
        "description": "Account merging that doesn't properly validate privilege boundaries",
        "vulnerable_indicators": [
            "no_privilege_check_on_merge",
            "credit_balances_combined_without_audit",
            "verification_skipped_for_second_account",
        ],
        "exploitation": "Merge admin account with user account to escalate privileges",
        "agents_needed": ["recon", "exploit", "execution"],
    },
    "referral_abuse": {
        "description": "Self-referral loops or referral reward collection without proper validation",
        "vulnerable_indicators": [
            "referrer_and_referee_not_verified_as_different",
            "rewards_applied_immediately_without_review",
            "referral_chain_not_limited",
        ],
        "exploitation": "Create circular referrals, self-refer with alt accounts, chain referrals",
        "agents_needed": ["execution"],
    },
    "trial_abuse": {
        "description": "Trial period reset by account manipulation or alternate identities",
        "vulnerable_indicators": [
            "trial_status_not_persistent",
            "account_recreation_not_tracked",
            "email_verification_bypassable",
        ],
        "exploitation": "Reset trial via account deletion/recreation, use alternate emails",
        "agents_needed": ["recon", "exploit", "execution"],
    },
    "rate_limit_bypass": {
        "description": "Rate limits bypassed by rotating identifiers (IP, account, etc)",
        "vulnerable_indicators": [
            "rate_limit_per_account_only",
            "ip_rotation_not_detected",
            "no_cross_identifier_limits",
        ],
        "exploitation": "Rotate accounts/IPs to bypass per-account rate limits",
        "agents_needed": ["execution"],
    },
    "inventory_manipulation": {
        "description": "Reserve-cancel-repurchase at different prices",
        "vulnerable_indicators": [
            "inventory_not_atomic",
            "prices_not_locked_during_reservation",
            "cancellation_doesnt_validate_price_change",
        ],
        "exploitation": "Reserve at high stock price, cancel, repurchase at low price",
        "agents_needed": ["recon", "exploit", "execution"],
    },
}


class BusinessFlowAnalyzer:
    """Analyzes business logic flows to identify exploitation vectors."""

    def extract_workflow(
        self,
        intel_entries: List[Dict[str, Any]],
    ) -> BusinessFlow:
        """
        Map business flows from reconnaissance intelligence.
        
        Args:
            intel_entries: Raw intelligence entries from reconnaissance
            
        Returns:
            BusinessFlow object with extracted workflow
        """
        flow = BusinessFlow()
        
        # Extract steps from intel
        for entry in intel_entries:
            if entry.get("type") == "api_endpoint":
                step = {
                    "name": entry.get("endpoint"),
                    "method": entry.get("method"),
                    "requires_auth": entry.get("requires_auth", True),
                    "parameters": entry.get("parameters", []),
                    "response_fields": entry.get("response_fields", []),
                }
                flow.steps.append(step)
            
            elif entry.get("type") == "workflow_state":
                state = entry.get("state_name")
                transitions = entry.get("transitions_to", [])
                flow.state_transitions[state] = transitions
        
        # Identify entry points (no dependencies or initial states)
        all_target_states = set()
        for transitions in flow.state_transitions.values():
            all_target_states.update(transitions)
        
        flow.entry_points = [
            state for state in flow.state_transitions.keys()
            if state not in all_target_states
        ]
        
        # Identify critical paths (high-value sequences)
        flow.critical_paths = self._identify_critical_paths(flow.state_transitions)
        
        return flow

    def find_race_conditions(
        self,
        flow: BusinessFlow,
    ) -> List[Dict[str, Any]]:
        """
        Detect race conditions in concurrent operations.
        
        Common targets:
        - Checkout with inventory decrement (check stock → decrement not atomic)
        - Transfer funds (read balance → decrement → update not atomic)
        - Reservation systems (check availability → mark reserved not atomic)
        
        Args:
            flow: BusinessFlow to analyze
            
        Returns:
            List of identified race conditions
        """
        vulnerabilities = []
        
        # Look for operations that modify state in multiple steps
        risky_patterns = [
            ("read", "decrement"),
            ("check", "update"),
            ("verify", "apply"),
            ("validate", "modify"),
        ]
        
        for step in flow.steps:
            step_name = step.get("name", "").lower()
            
            for pattern_a, pattern_b in risky_patterns:
                if pattern_a in step_name:
                    # Check if follow-up step exists
                    for other_step in flow.steps:
                        other_name = other_step.get("name", "").lower()
                        if pattern_b in other_name:
                            # Potential race condition found
                            vulnerabilities.append({
                                "type": "race_condition",
                                "step_a": step.get("name"),
                                "step_b": other_step.get("name"),
                                "attack_vector": (
                                    f"Concurrent requests to {step.get('name')} "
                                    f"before {other_step.get('name')} completes"
                                ),
                                "impact": "State inconsistency, double-spend, inventory duplication",
                                "severity": "CRITICAL",
                            })
        
        return vulnerabilities

    def find_state_machine_bypasses(
        self,
        flow: BusinessFlow,
    ) -> List[Dict[str, Any]]:
        """
        Find states that can be skipped or invalid transitions allowed.
        
        Args:
            flow: BusinessFlow to analyze
            
        Returns:
            List of state machine bypass vulnerabilities
        """
        vulnerabilities = []
        
        # Look for states with limited incoming transitions (can be reached fewer ways)
        all_transitions = {}
        for state, transitions in flow.state_transitions.items():
            for target in transitions:
                if target not in all_transitions:
                    all_transitions[target] = []
                all_transitions[target].append(state)
        
        # States with only one incoming transition are potential bypasses
        for state, sources in all_transitions.items():
            if len(sources) == 1:
                vulnerabilities.append({
                    "type": "state_machine_bypass",
                    "vulnerable_state": state,
                    "single_source": sources[0],
                    "attack_vector": f"Skip required state by directly requesting {state}",
                    "impact": "Bypass validation, approval, or verification steps",
                    "severity": "HIGH",
                })
        
        # Look for transitions that skip critical paths
        for path in flow.critical_paths:
            # Check if any state in path can be bypassed
            path_states = set(path)
            for state in path[:-1]:  # All but last
                outgoing = flow.state_transitions.get(state, [])
                # If state can reach path end without going through intermediate states
                path_idx = path.index(state)
                for transition in outgoing:
                    if transition == path[-1]:  # Direct skip to end
                        vulnerabilities.append({
                            "type": "critical_path_bypass",
                            "state": state,
                            "skips_to": transition,
                            "skips_steps": path[path_idx+1:-1],
                            "attack_vector": f"Skip validation steps by requesting {transition}",
                            "impact": "Circumvent mandatory workflow steps",
                            "severity": "CRITICAL",
                        })
        
        return vulnerabilities

    def find_privilege_escalation_paths(
        self,
        flow: BusinessFlow,
    ) -> List[Dict[str, Any]]:
        """
        Map privilege boundaries and identify escalation opportunities.
        
        Args:
            flow: BusinessFlow to analyze
            
        Returns:
            List of privilege escalation paths
        """
        vulnerabilities = []
        
        # Look for state transitions that increase privileges or access
        privilege_keywords = [
            "admin", "moderator", "staff", "verified", "premium", "vip",
            "trusted", "seller", "merchant", "partner", "sponsor",
        ]
        
        for state, transitions in flow.state_transitions.items():
            state_lower = state.lower()
            
            for target in transitions:
                target_lower = target.lower()
                
                # Check if transition grants privilege
                for keyword in privilege_keywords:
                    if (keyword not in state_lower and
                        keyword in target_lower):
                        vulnerabilities.append({
                            "type": "privilege_escalation_path",
                            "from_state": state,
                            "to_state": target,
                            "required_verification": self._infer_verification(state, target),
                            "attack_vector": f"Transition directly to {target} without proper verification",
                            "impact": "Gain elevated privileges",
                            "severity": "CRITICAL",
                        })
        
        return vulnerabilities

    def find_toctou_vulnerabilities(
        self,
        flow: BusinessFlow,
    ) -> List[Dict[str, Any]]:
        """
        Identify time-of-check-time-of-use (TOCTOU) vulnerabilities.
        
        Between a check and use, state may change due to:
        - Concurrent requests
        - External service state changes
        - Account manipulation
        
        Args:
            flow: BusinessFlow to analyze
            
        Returns:
            List of TOCTOU vulnerabilities
        """
        vulnerabilities = []
        
        # Identify check and use patterns
        for step in flow.steps:
            step_name = step.get("name", "").lower()
            
            # Common TOCTOU patterns
            check_keywords = ["check", "get", "verify", "validate", "confirm"]
            use_keywords = ["apply", "deduct", "update", "transfer", "modify"]
            
            has_check = any(kw in step_name for kw in check_keywords)
            
            if has_check:
                # Look for subsequent use
                for other_step in flow.steps:
                    other_name = other_step.get("name", "").lower()
                    has_use = any(kw in other_name for kw in use_keywords)
                    
                    if has_use and step != other_step:
                        # Potential TOCTOU vulnerability
                        vulnerabilities.append({
                            "type": "toctou_vulnerability",
                            "check_step": step.get("name"),
                            "use_step": other_step.get("name"),
                            "window": "Between check and use",
                            "attack_vector": (
                                f"Modify state between {step.get('name')} "
                                f"and {other_step.get('name')} invocation"
                            ),
                            "impact": "Validate incorrect state, perform unauthorized action",
                            "severity": "HIGH",
                        })
        
        return vulnerabilities

    def generate_exploit_plan(
        self,
        vulnerability: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Generate multi-agent exploitation plan for identified vulnerability.
        
        Args:
            vulnerability: Vulnerability dict to create exploitation plan for
            
        Returns:
            List of coordinated exploitation steps
        """
        vuln_type = vulnerability.get("type", "")
        plan = []
        
        if vuln_type == "race_condition":
            plan = self._plan_race_condition_exploit(vulnerability)
        elif vuln_type == "state_machine_bypass":
            plan = self._plan_state_bypass_exploit(vulnerability)
        elif vuln_type == "privilege_escalation_path":
            plan = self._plan_escalation_exploit(vulnerability)
        elif vuln_type == "toctou_vulnerability":
            plan = self._plan_toctou_exploit(vulnerability)
        else:
            plan = self._plan_generic_exploit(vulnerability)
        
        return plan

    # ========================
    # Internal Helper Methods
    # ========================

    def _identify_critical_paths(
        self,
        state_transitions: Dict[str, List[str]],
    ) -> List[List[str]]:
        """Identify high-value workflow paths."""
        paths = []
        
        # Find longest paths (likely critical workflows)
        for start_state in state_transitions.keys():
            path = self._find_longest_path(start_state, state_transitions)
            if path:
                paths.append(path)
        
        return paths

    def _find_longest_path(
        self,
        current: str,
        transitions: Dict[str, List[str]],
        visited: Optional[List[str]] = None,
    ) -> List[str]:
        """DFS to find longest path from current state."""
        if visited is None:
            visited = []
        
        if current in visited:
            return []
        
        visited.append(current)
        
        if current not in transitions or not transitions[current]:
            return visited
        
        longest = visited
        for next_state in transitions[current]:
            path = self._find_longest_path(next_state, transitions, visited.copy())
            if len(path) > len(longest):
                longest = path
        
        return longest

    def _infer_verification(self, from_state: str, to_state: str) -> List[str]:
        """Infer what verification should be required for state transition."""
        required = []
        
        if "admin" in to_state.lower():
            required.extend(["email_verification", "phone_verification", "identity_proof"])
        elif "verified" in to_state.lower():
            required.append("email_verification")
        elif "premium" in to_state.lower():
            required.append("payment_verification")
        elif "trusted" in to_state.lower():
            required.extend(["reputation_threshold", "time_requirement"])
        
        return required if required else ["unknown_verification"]

    def _plan_race_condition_exploit(
        self,
        vulnerability: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Plan concurrent request exploitation."""
        return [
            {
                "step": 1,
                "agent": "recon",
                "action": "measure_latency",
                "target": vulnerability.get("step_a"),
                "description": "Measure time between check and update",
            },
            {
                "step": 2,
                "agent": "exploit",
                "action": "prepare_concurrent_requests",
                "target": vulnerability.get("step_a"),
                "description": "Prepare multiple concurrent requests",
            },
            {
                "step": 3,
                "agent": "execution",
                "action": "send_concurrent_requests",
                "target": vulnerability.get("step_a"),
                "parallelism": 5,
                "description": "Send requests in tight loop to exploit race condition",
            },
            {
                "step": 4,
                "agent": "recon",
                "action": "verify_exploitation",
                "target": vulnerability.get("step_b"),
                "description": "Verify state inconsistency achieved",
            },
        ]

    def _plan_state_bypass_exploit(
        self,
        vulnerability: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Plan state machine bypass exploitation."""
        return [
            {
                "step": 1,
                "agent": "recon",
                "action": "enumerate_states",
                "description": "Map all available states",
            },
            {
                "step": 2,
                "agent": "exploit",
                "action": "test_direct_transition",
                "target": vulnerability.get("vulnerable_state"),
                "description": "Attempt direct request to vulnerable state",
            },
            {
                "step": 3,
                "agent": "execution",
                "action": "execute_bypass",
                "target": vulnerability.get("vulnerable_state"),
                "description": "Execute full bypass with authorization bypass",
            },
        ]

    def _plan_escalation_exploit(
        self,
        vulnerability: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Plan privilege escalation exploitation."""
        return [
            {
                "step": 1,
                "agent": "recon",
                "action": "find_escalation_trigger",
                "target": vulnerability.get("from_state"),
                "description": "Identify state transition trigger",
            },
            {
                "step": 2,
                "agent": "exploit",
                "action": "bypass_verification",
                "description": "Craft request to skip verification",
            },
            {
                "step": 3,
                "agent": "execution",
                "action": "trigger_escalation",
                "target": vulnerability.get("to_state"),
                "description": "Transition to elevated privilege state",
            },
        ]

    def _plan_toctou_exploit(
        self,
        vulnerability: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Plan time-of-check-time-of-use exploitation."""
        return [
            {
                "step": 1,
                "agent": "recon",
                "action": "measure_toctou_window",
                "check_step": vulnerability.get("check_step"),
                "use_step": vulnerability.get("use_step"),
                "description": "Measure time window between check and use",
            },
            {
                "step": 2,
                "agent": "exploit",
                "action": "trigger_state_change",
                "description": "Trigger external state change within window",
            },
            {
                "step": 3,
                "agent": "execution",
                "action": "request_use_with_stale_check",
                "description": "Use stale check result to perform action",
            },
        ]

    def _plan_generic_exploit(
        self,
        vulnerability: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Create generic exploitation plan."""
        return [
            {
                "step": 1,
                "agent": "recon",
                "action": "analyze_vulnerability",
                "description": f"Analyze {vulnerability.get('type')} vulnerability",
            },
            {
                "step": 2,
                "agent": "exploit",
                "action": "craft_exploit",
                "description": vulnerability.get("attack_vector", "Execute exploit"),
            },
            {
                "step": 3,
                "agent": "execution",
                "action": "execute_exploit",
                "description": "Execute exploitation",
            },
        ]
