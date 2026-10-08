from enum import StrEnum


class FindingState(StrEnum):
    OPEN = "OPEN"
    ANALYZING = "ANALYZING"
    REMEDIATION_PENDING = "REMEDIATION_PENDING"
    APPROVED = "APPROVED"
    REMEDIATING = "REMEDIATING"
    VERIFYING = "VERIFYING"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"


ALLOWED_TRANSITIONS = {
    FindingState.OPEN: {FindingState.ANALYZING},
    FindingState.ANALYZING: {FindingState.REMEDIATION_PENDING, FindingState.OPEN},
    FindingState.REMEDIATION_PENDING: {FindingState.APPROVED, FindingState.OPEN},
    FindingState.APPROVED: {FindingState.REMEDIATING},
    FindingState.REMEDIATING: {FindingState.VERIFYING, FindingState.FAILED},
    FindingState.VERIFYING: {FindingState.RESOLVED, FindingState.FAILED},
    FindingState.FAILED: {FindingState.OPEN, FindingState.REMEDIATION_PENDING},
    FindingState.RESOLVED: set(),
}


def transition(current: str, target: str) -> str:
    current_state = FindingState(current)
    target_state = FindingState(target)
    if target_state not in ALLOWED_TRANSITIONS[current_state]:
        raise ValueError(f"Invalid finding transition: {current_state} -> {target_state}")
    return target_state.value
