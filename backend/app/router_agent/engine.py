import structlog
from enum import Enum
from typing import Any

logger = structlog.get_logger()


class WorkflowState(str, Enum):
    IDLE = "idle"
    DISCOVERY = "discovery"
    FINGERPRINTING = "fingerprinting"
    THREAT_MODELING = "threat_modeling"
    VULN_SCANNING = "vuln_scanning"
    EXPLOIT_ANALYSIS = "exploit_analysis"
    MITRE_MAPPING = "mitre_mapping"
    RISK_ANALYSIS = "risk_analysis"
    REPORTING = "reporting"
    BASELINE = "baseline"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


WORKFLOW_TRANSITIONS = {
    WorkflowState.IDLE: [WorkflowState.DISCOVERY],
    WorkflowState.DISCOVERY: [WorkflowState.FINGERPRINTING, WorkflowState.FAILED, WorkflowState.PAUSED],
    WorkflowState.FINGERPRINTING: [WorkflowState.THREAT_MODELING, WorkflowState.VULN_SCANNING, WorkflowState.FAILED, WorkflowState.PAUSED],
    WorkflowState.THREAT_MODELING: [WorkflowState.VULN_SCANNING, WorkflowState.FAILED, WorkflowState.PAUSED],
    WorkflowState.VULN_SCANNING: [WorkflowState.EXPLOIT_ANALYSIS, WorkflowState.FAILED, WorkflowState.PAUSED],
    WorkflowState.EXPLOIT_ANALYSIS: [WorkflowState.MITRE_MAPPING, WorkflowState.FAILED, WorkflowState.PAUSED],
    WorkflowState.MITRE_MAPPING: [WorkflowState.RISK_ANALYSIS, WorkflowState.FAILED, WorkflowState.PAUSED],
    WorkflowState.RISK_ANALYSIS: [WorkflowState.REPORTING, WorkflowState.BASELINE, WorkflowState.FAILED, WorkflowState.PAUSED],
    WorkflowState.REPORTING: [WorkflowState.BASELINE, WorkflowState.COMPLETED, WorkflowState.FAILED],
    WorkflowState.BASELINE: [WorkflowState.COMPLETED, WorkflowState.FAILED],
    WorkflowState.PAUSED: list(WorkflowState),
}


class RouterEngine:
    def __init__(self):
        self.state = WorkflowState.IDLE
        self.history: list[dict] = []

    def can_transition(self, target: WorkflowState) -> bool:
        allowed = WORKFLOW_TRANSITIONS.get(self.state, [])
        return target in allowed

    def transition(self, target: WorkflowState, metadata: dict | None = None) -> bool:
        if not self.can_transition(target):
            logger.warning(
                "Invalid state transition",
                current=self.state.value,
                target=target.value,
            )
            return False

        prev = self.state
        self.state = target
        self.history.append({
            "from": prev.value,
            "to": target.value,
            "metadata": metadata or {},
        })
        logger.info("State transition", from_state=prev.value, to_state=target.value)
        return True

    def get_next_steps(self) -> list[str]:
        allowed = WORKFLOW_TRANSITIONS.get(self.state, [])
        return [s.value for s in allowed if s not in (WorkflowState.FAILED, WorkflowState.PAUSED)]

    def reset(self):
        self.state = WorkflowState.IDLE
        self.history = []
