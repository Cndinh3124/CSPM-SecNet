
from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    allowed: bool
    approval_required: bool
    reason: str


DEFAULT_RULES = {
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": {
        "action": "restrict_public_ssh",
        "allowed_scopes": {"demo", "sandbox"},
        "approval_required": True,
        "production_allowed": False,
    }
}


def _labels_to_dict(labels):
    """Convert Prowler labels into a dictionary."""
    if isinstance(labels, dict):
        return labels

    result = {}

    if not isinstance(labels, list):
        return result

    for item in labels:
        if not isinstance(item, str) or ":" not in item:
            continue

        key, value = item.split(":", 1)
        result[key.strip()] = value.strip()

    return result


def evaluate(finding, ai_analysis=None):
    """
    Decide whether a remediation review plan may be created.

    AI provides recommendations only. It does not authorize AWS changes.
    Every plan produced by this policy requires explicit approval.
    """
    control_id = finding.get("control_id", "")
    rule = DEFAULT_RULES.get(control_id)

    if not rule:
        return PolicyDecision(
            action="none",
            allowed=False,
            approval_required=True,
            reason="No remediation rule exists for this control.",
        )

    labels = _labels_to_dict(finding.get("labels", []))

    scope = labels.get("CSPMScope", "").lower()
    target = labels.get("CSPMTarget", "").lower() == "true"
    environment = labels.get("Environment", "").lower()

    if not target:
        return PolicyDecision(
            action="none",
            allowed=False,
            approval_required=True,
            reason="Resource is not explicitly tagged as a CSPM target.",
        )

    if scope not in rule["allowed_scopes"]:
        return PolicyDecision(
            action="none",
            allowed=False,
            approval_required=True,
            reason="Resource scope is not allowed by policy.",
        )

    if (
        environment == "production"
        and not rule["production_allowed"]
    ):
        return PolicyDecision(
            action="none",
            allowed=False,
            approval_required=True,
            reason="Production remediation is not allowed by policy.",
        )

    ai_mode = str(
        (ai_analysis or {}).get("auto_remediation", "MANUAL")
    ).upper()

    if ai_mode not in {"SAFE", "REVIEW_REQUIRED", "MANUAL"}:
        return PolicyDecision(
            action="none",
            allowed=False,
            approval_required=True,
            reason="Unknown AI remediation classification.",
        )

    return PolicyDecision(
        action=rule["action"],
        allowed=True,
        approval_required=True,
        reason=(
            "Policy permits creating a remediation review plan. "
            f"AI classification: {ai_mode}. "
            "Explicit approval is required before execution."
        ),
    )


def build_plan(finding, ai_analysis, decision):
    """Build a reviewable remediation plan from a policy decision."""
    if not decision.allowed:
        raise ValueError(
            "Cannot build a remediation plan for a denied policy decision."
        )

    if not decision.approval_required:
        raise ValueError(
            "Remediation plans must require explicit approval."
        )

    return {
        "finding_fingerprint": finding.get("fingerprint"),
        "control_id": finding.get("control_id"),
        "resource_id": finding.get("resource_id"),
        "resource_arn": finding.get("resource_arn"),
        "region": finding.get("region"),
        "action": decision.action,
        "approval_required": True,
        "status": "PENDING_APPROVAL",
        "reason": decision.reason,
        "ai_recommendation": (
            ai_analysis.get("recommended_remediation")
            if isinstance(ai_analysis, dict)
            else None
        ),
        "remediation_plan": (
            ai_analysis.get("remediation_plan", {})
            if isinstance(ai_analysis, dict)
            else {}
        ),
        "confidence": (
            ai_analysis.get("confidence")
            if isinstance(ai_analysis, dict)
            else None
        ),
    }
