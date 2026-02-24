"""
Tier 3 Orchestrator: Swarm-Coordinated Multi-Agent Operation Orchestration
Coordinates reconnaissance, exploitation, execution, and persistence across distributed agent swarms.
Manages operation planning, task decomposition, dependency resolution, and escalation logic.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
import json


class OperationPhase(Enum):
    """Defines stages of a coordinated multi-agent operation."""
    PLANNING = "planning"
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    CLEANUP = "cleanup"


@dataclass
class AgentTask:
    """Individual task assigned to an agent in the swarm."""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_type: str = ""  # "recon"|"exploit"|"execution"|"c4"
    action: str = ""
    payload: str = ""
    target: str = ""
    dependencies: List[str] = field(default_factory=list)
    phase: OperationPhase = OperationPhase.PLANNING
    priority: int = 3  # 1-5, 5 is highest
    status: str = "pending"  # "pending"|"assigned"|"in_progress"|"completed"|"failed"
    result: Optional[Dict[str, Any]] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary for serialization."""
        return {
            "task_id": self.task_id,
            "agent_type": self.agent_type,
            "action": self.action,
            "payload": self.payload,
            "target": self.target,
            "dependencies": self.dependencies,
            "phase": self.phase.value,
            "priority": self.priority,
            "status": self.status,
            "result": self.result,
            "created_at": self.created_at,
        }


@dataclass
class OperationPlan:
    """Comprehensive plan for coordinated multi-agent operation."""
    operation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    goal: str = ""
    tasks: List[AgentTask] = field(default_factory=list)
    current_phase: OperationPhase = OperationPhase.PLANNING
    status: str = "initialized"  # "initialized"|"executing"|"escalating"|"completed"|"failed"
    findings: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def get_ready_tasks(self) -> List[AgentTask]:
        """Return tasks with all dependencies met and not yet executed."""
        completed_task_ids = {
            task.task_id for task in self.tasks
            if task.status == "completed"
        }
        
        ready_tasks = []
        for task in self.tasks:
            if task.status not in ["pending", "assigned"]:
                continue
            
            # Check if all dependencies are completed
            if all(dep_id in completed_task_ids for dep_id in task.dependencies):
                ready_tasks.append(task)
        
        # Sort by priority (higher priority first)
        return sorted(ready_tasks, key=lambda t: t.priority, reverse=True)

    def get_phase_progress(self) -> Dict[str, Any]:
        """Calculate progress metrics for current phase."""
        phase_tasks = [t for t in self.tasks if t.phase == self.current_phase]
        if not phase_tasks:
            return {"total": 0, "completed": 0, "failed": 0, "progress": 0}
        
        completed = sum(1 for t in phase_tasks if t.status == "completed")
        failed = sum(1 for t in phase_tasks if t.status == "failed")
        total = len(phase_tasks)
        
        return {
            "total": total,
            "completed": completed,
            "failed": failed,
            "progress": (completed / total * 100) if total > 0 else 0,
        }

    def advance_phase(self) -> bool:
        """Advance to next phase if current phase is complete."""
        progress = self.get_phase_progress()
        
        # Require 80% completion to advance
        if progress["progress"] < 80:
            return False
        
        phase_order = [
            OperationPhase.PLANNING,
            OperationPhase.RECONNAISSANCE,
            OperationPhase.EXPLOITATION,
            OperationPhase.EXECUTION,
            OperationPhase.PERSISTENCE,
            OperationPhase.CLEANUP,
        ]
        
        current_index = phase_order.index(self.current_phase)
        if current_index < len(phase_order) - 1:
            self.current_phase = phase_order[current_index + 1]
            return True
        
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert operation plan to dictionary."""
        return {
            "operation_id": self.operation_id,
            "goal": self.goal,
            "tasks": [t.to_dict() for t in self.tasks],
            "current_phase": self.current_phase.value,
            "status": self.status,
            "findings": self.findings,
            "created_at": self.created_at,
        }


class SwarmOperationOrchestrator:
    """Orchestrates multi-agent reconnaissance, exploitation, and execution campaigns."""

    def __init__(self):
        self.operations: Dict[str, OperationPlan] = {}
        self.task_results: Dict[str, Dict[str, Any]] = {}

    def plan_operation(
        self,
        goal: str,
        findings: List[Dict[str, Any]],
        available_agents: List[str],
    ) -> OperationPlan:
        """
        Create comprehensive operation plan from goal and reconnaissance findings.
        
        Args:
            goal: High-level objective (e.g., "Compromise admin account")
            findings: Intelligence from reconnaissance phase
            available_agents: List of available agent identifiers
            
        Returns:
            OperationPlan with decomposed tasks and dependencies
        """
        plan = OperationPlan(goal=goal, findings=findings)
        
        # Decompose goal into sub-objectives
        sub_objectives = self._decompose_goal(goal, findings)
        
        # Generate tasks for each sub-objective
        task_map = {}
        for idx, objective in enumerate(sub_objectives):
            tasks = self._create_tasks_for_objective(
                objective, idx, plan.operation_id
            )
            for task in tasks:
                plan.tasks.append(task)
                task_map[task.task_id] = task
        
        # Assign agents to tasks
        self._assign_agents(plan.tasks, available_agents)
        
        # Calculate dependencies between tasks
        self._calculate_dependencies(plan.tasks, sub_objectives)
        
        plan.status = "planning_complete"
        self.operations[plan.operation_id] = plan
        
        return plan

    def get_next_tasks(self, plan: OperationPlan) -> List[AgentTask]:
        """
        Retrieve next executable tasks based on dependencies and phase.
        
        Args:
            plan: OperationPlan to query
            
        Returns:
            List of ready tasks sorted by priority
        """
        return plan.get_ready_tasks()

    def update_task_result(
        self,
        plan: OperationPlan,
        task_id: str,
        result: Dict[str, Any],
    ) -> None:
        """
        Update task with execution result and check for escalation triggers.
        
        Args:
            plan: OperationPlan containing the task
            task_id: ID of completed task
            result: Execution result data
        """
        for task in plan.tasks:
            if task.task_id == task_id:
                task.status = "completed"
                task.result = result
                
                # Check if result indicates escalation opportunity
                if result.get("escalation_indicator"):
                    plan.findings.append({
                        "type": "escalation_opportunity",
                        "source_task": task_id,
                        "data": result.get("escalation_data"),
                    })
                
                # Update operation status based on findings
                if self.should_escalate(plan):
                    plan.status = "escalating"
                
                self.task_results[task_id] = result
                return

    def should_escalate(self, plan: OperationPlan) -> bool:
        """
        Determine if operation should escalate to higher tier based on findings.
        
        Escalation triggers:
        - Critical system access discovered
        - Persistent backdoor installation successful
        - Administrative privilege escalation achieved
        - High-value data access confirmed
        
        Args:
            plan: OperationPlan to evaluate
            
        Returns:
            True if escalation is warranted
        """
        escalation_keywords = [
            "root_access",
            "admin_credentials",
            "persistence_established",
            "privilege_escalation",
            "sensitive_data_access",
            "supply_chain_entry",
            "lateral_movement",
        ]
        
        for finding in plan.findings:
            finding_str = json.dumps(finding).lower()
            if any(keyword in finding_str for keyword in escalation_keywords):
                return True
        
        # Escalate if multiple exploitation successes
        exploitation_successes = sum(
            1 for f in plan.findings
            if f.get("type") == "escalation_opportunity"
        )
        if exploitation_successes >= 3:
            return True
        
        return False

    def to_blackboard_entries(self, plan: OperationPlan) -> List[Dict[str, Any]]:
        """
        Convert operation plan to Blackboard system compatible entries.
        Allows information sharing across agent swarms.
        
        Args:
            plan: OperationPlan to convert
            
        Returns:
            List of blackboard-compatible entries
        """
        entries = []
        
        # Operation metadata entry
        entries.append({
            "type": "operation_metadata",
            "operation_id": plan.operation_id,
            "goal": plan.goal,
            "current_phase": plan.current_phase.value,
            "status": plan.status,
            "timestamp": datetime.utcnow().isoformat(),
        })
        
        # Task entries for agent discovery
        for task in plan.tasks:
            entries.append({
                "type": "task",
                "task_id": task.task_id,
                "agent_type": task.agent_type,
                "action": task.action,
                "target": task.target,
                "phase": task.phase.value,
                "status": task.status,
                "priority": task.priority,
            })
        
        # Findings entries
        for finding in plan.findings:
            entries.append({
                "type": "finding",
                "operation_id": plan.operation_id,
                "data": finding,
                "timestamp": datetime.utcnow().isoformat(),
            })
        
        return entries

    def create_rollback_plan(self, plan: OperationPlan) -> List[AgentTask]:
        """
        Generate cleanup and rollback tasks to remove evidence of operation.
        
        Args:
            plan: OperationPlan to create cleanup for
            
        Returns:
            List of cleanup tasks
        """
        cleanup_tasks = []
        
        # Create cleanup task for each executed task in reverse order
        completed_tasks = [t for t in plan.tasks if t.status == "completed"]
        
        for task in reversed(completed_tasks):
            cleanup_task = AgentTask(
                agent_type="c4",  # Cleanup, Cover, Cover-up, C&C
                action=f"cleanup_{task.action}",
                payload=f"rollback_{task.payload}" if task.payload else "",
                target=task.target,
                phase=OperationPhase.CLEANUP,
                priority=5,
            )
            
            # Cleanup task depends on main task being identified as rollback
            cleanup_task.dependencies = [task.task_id]
            cleanup_tasks.append(cleanup_task)
        
        return cleanup_tasks

    # ========================
    # Internal Methods
    # ========================

    def _decompose_goal(
        self,
        goal: str,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Break down high-level goal into sub-objectives."""
        objectives = []
        
        # Map goal keywords to reconnaissance requirements
        goal_lower = goal.lower()
        
        if "admin" in goal_lower or "privilege" in goal_lower:
            objectives.extend([
                {
                    "type": "enumerate_users",
                    "priority": 1,
                    "phase": OperationPhase.RECONNAISSANCE,
                },
                {
                    "type": "identify_admin",
                    "priority": 1,
                    "phase": OperationPhase.RECONNAISSANCE,
                },
                {
                    "type": "escalate_privileges",
                    "priority": 2,
                    "phase": OperationPhase.EXPLOITATION,
                },
            ])
        
        if "credential" in goal_lower:
            objectives.extend([
                {
                    "type": "find_credentials",
                    "priority": 2,
                    "phase": OperationPhase.RECONNAISSANCE,
                },
                {
                    "type": "test_credentials",
                    "priority": 2,
                    "phase": OperationPhase.EXPLOITATION,
                },
            ])
        
        if "persistence" in goal_lower or "backdoor" in goal_lower:
            objectives.extend([
                {
                    "type": "install_persistence",
                    "priority": 3,
                    "phase": OperationPhase.PERSISTENCE,
                },
                {
                    "type": "verify_persistence",
                    "priority": 3,
                    "phase": OperationPhase.PERSISTENCE,
                },
            ])
        
        # Default objectives if no matches
        if not objectives:
            objectives = [
                {
                    "type": "initial_reconnaissance",
                    "priority": 1,
                    "phase": OperationPhase.RECONNAISSANCE,
                },
                {
                    "type": "exploit",
                    "priority": 2,
                    "phase": OperationPhase.EXPLOITATION,
                },
                {
                    "type": "execute",
                    "priority": 2,
                    "phase": OperationPhase.EXECUTION,
                },
            ]
        
        return objectives

    def _create_tasks_for_objective(
        self,
        objective: Dict[str, Any],
        index: int,
        operation_id: str,
    ) -> List[AgentTask]:
        """Create tasks for a given objective."""
        tasks = []
        
        obj_type = objective.get("type", "")
        phase = objective.get("phase", OperationPhase.PLANNING)
        priority = objective.get("priority", 3)
        
        # Map objective types to agent types and actions
        action_map = {
            "enumerate_users": ("recon", "enumerate_domain_users"),
            "identify_admin": ("recon", "find_admin_accounts"),
            "escalate_privileges": ("exploit", "privilege_escalation_attempt"),
            "find_credentials": ("recon", "search_for_credentials"),
            "test_credentials": ("exploit", "credential_validation"),
            "install_persistence": ("execution", "install_backdoor"),
            "verify_persistence": ("recon", "verify_c2_connection"),
            "initial_reconnaissance": ("recon", "initial_scan"),
            "exploit": ("exploit", "execute_exploit"),
            "execute": ("execution", "command_execution"),
        }
        
        agent_type, action = action_map.get(obj_type, ("recon", obj_type))
        
        task = AgentTask(
            agent_type=agent_type,
            action=action,
            payload="",
            target="",
            phase=phase,
            priority=priority,
            status="pending",
        )
        
        tasks.append(task)
        return tasks

    def _assign_agents(
        self,
        tasks: List[AgentTask],
        available_agents: List[str],
    ) -> None:
        """Assign available agents to tasks."""
        agent_idx = 0
        
        for task in sorted(tasks, key=lambda t: t.priority, reverse=True):
            if available_agents and agent_idx < len(available_agents):
                task.target = available_agents[agent_idx % len(available_agents)]
                task.status = "assigned"
                agent_idx += 1

    def _calculate_dependencies(
        self,
        tasks: List[AgentTask],
        objectives: List[Dict[str, Any]],
    ) -> None:
        """Calculate task dependencies based on phases and objectives."""
        phase_order = [
            OperationPhase.PLANNING,
            OperationPhase.RECONNAISSANCE,
            OperationPhase.EXPLOITATION,
            OperationPhase.EXECUTION,
            OperationPhase.PERSISTENCE,
            OperationPhase.CLEANUP,
        ]
        
        for task in tasks:
            for other_task in tasks:
                if task == other_task:
                    continue
                
                # Tasks in earlier phases must complete first
                if (phase_order.index(other_task.phase) <
                        phase_order.index(task.phase)):
                    if other_task.task_id not in task.dependencies:
                        task.dependencies.append(other_task.task_id)
