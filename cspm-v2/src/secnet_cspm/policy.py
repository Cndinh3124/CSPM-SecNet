from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PolicyDecision:
    """Immutable result of a remediation policy evaluation."""

    action: str
    allowed: bool
    approval_required: bool
    reason: str


DEFAULT_RULES: dict[str, dict[str, Any]] = {
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": {
        "action": "restrict_public_ssh",
        "allowed_scopes": {"demo", "sandbox"},
        "approval_required": True,
        "production_allowed": False,
    },
}


def _labels_to_dict(labels: Any) -> dict[str, str]:
    """Normalize labels from dictionaries or lists of dictionaries/strings.

    Supported examples:
        {"CSPMScope": "demo"}

        [
            {"CSPMScope": "demo"},
            {"CSPMTarget": "true"},
        ]

        ["CSPMScope:demo", "CSPMTarget:true"]

    Label keys are normalized case-insensitively.
    Invalid label entries are ignored.
    """
    if isinstance(labels, dict):
        items = labels.items()
    elif isinstance(labels, list):
        result: dict[str, str] = {}

        for item in labels:
            if isinstance(item, dict):
                for key, value in item.items():
                    if key is None or value is None:
                        continue

                    normalized_key = str(key).strip().lower()
                    normalized_value = str(value).strip()

                    if normalized_key:
                        result[normalized_key] = normalized_value

            elif isinstance(item, str) and ":" in item:
                key, value = item.split(":", 1)
                normalized_key = key.strip().lower()
                normalized_value = value.strip()

                if normalized_key:
                    result[normalized_key] = normalized_value

        return result
    else:
        return {}

    result: dict[str, str] = {}

    for key, value in items:
        if key is None or value is None:
            continue

        normalized_key = str(key).strip().lower()
        normalized_value = str(value).strip()

        if normalized_key:
            result[normalized_key] = normalized_value

    return result


def evaluate(
    finding: dict[str, Any],
    ai_analysis: dict[str, Any] | None = None,
) -> PolicyDecision:
    """Evaluate whether a finding is eligible for a review plan.

    This function never performs remediation.
    """
    if not isinstance(finding, dict):
        return PolicyDecision(
            action="none",
            allowed=False,
            approval_required=True,
            reason="Invalid finding input.",
        )

    control_id = str(finding.get("control_id") or "").strip()
    rule = DEFAULT_RULES.get(control_id)

    if rule is None:
        return PolicyDecision(
            action="none",
            allowed=False,
            approval_required=True,
            reason="No remediation rule exists for this control.",
        )

    labels = _labels_to_dict(finding.get("labels", []))

    scope = labels.get("cspmscope", "").lower()
    target = labels.get("cspmtarget", "").lower() == "true"
    environment = labels.get("environment", "").lower()

    if not target:
        return PolicyDecision(
            action=rule["action"],
            allowed=False,
            approval_required=True,
            reason="Resource is not explicitly tagged as a CSPM target.",
        )

    if scope not in rule["allowed_scopes"]:
        return PolicyDecision(
            action=rule["action"],
            allowed=False,
            approval_required=True,
            reason="Resource scope is not allowed by policy.",
        )

    if environment == "production" and not rule["production_allowed"]:
        return PolicyDecision(
            action=rule["action"],
            allowed=False,
            approval_required=True,
            reason="Production remediation is not allowed by policy.",
        )

    # Fail closed when environment metadata is missing.
    if not environment:
        return PolicyDecision(
            action=rule["action"],
            allowed=False,
            approval_required=True,
            reason="Resource environment is missing.",
        )

    if environment not in {"demo", "sandbox"}:
        return PolicyDecision(
            action=rule["action"],
            allowed=False,
            approval_required=True,
            reason=(
                "Resource environment is not an allowed "
                "demo/sandbox environment."
            ),
        )

    analysis = ai_analysis if isinstance(ai_analysis, dict) else {}
    ai_mode = (
        str(analysis.get("auto_remediation", "MANUAL"))
        .strip()
        .upper()
    )

    if ai_mode not in {"SAFE", "REVIEW_REQUIRED", "MANUAL"}:
        return PolicyDecision(
            action=rule["action"],
            allowed=False,
            approval_required=True,
            reason="Unknown AI remediation classification.",
        )

    # Even SAFE only permits creation of a review plan.
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


def build_remediation_plan(
    decision: PolicyDecision,
    finding: dict[str, Any],
    ai_analysis: dict[str, Any],
) -> dict[str, Any]:
    """Build a pending remediation review plan after policy approval."""
    if not isinstance(decision, PolicyDecision):
        raise TypeError("A valid policy decision is required.")

    if not decision.allowed:
        raise ValueError("Cannot build a plan for a denied policy decision.")

    if not decision.approval_required:
        raise ValueError("Remediation plans must require explicit approval.")

    if not isinstance(finding, dict):
        raise TypeError("Invalid finding input.")

    if not isinstance(ai_analysis, dict):
        raise TypeError("Invalid AI analysis input.")

    fingerprint = finding.get("fingerprint")
    control_id = finding.get("control_id")
    resource_id = finding.get("resource_id")
    region = finding.get("region")

    # Do not create incomplete plans that cannot be safely reviewed.
    required_fields = {
        "fingerprint": fingerprint,
        "control_id": control_id,
        "resource_id": resource_id,
        "region": region,
    }

    for field, value in required_fields.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                f"Finding is missing required field: {field}"
            )

    return {
        "finding_fingerprint": fingerprint,
        "control_id": control_id,
        "resource_id": resource_id,
        "resource_arn": finding.get("resource_arn"),
        "region": region,
        "action": decision.action,
        "approval_required": True,
        "status": "PENDING_APPROVAL",
        "reason": decision.reason,
        "ai_recommendation": ai_analysis.get(
            "recommended_remediation"
        ),
        "remediation_plan": ai_analysis.get("remediation_plan", {}),
        "confidence": ai_analysis.get("confidence"),
    }


def build_plan(
    finding: dict[str, Any],
    ai_analysis: dict[str, Any],
    decision: PolicyDecision,
) -> dict[str, Any]:
    """Backward-compatible wrapper for callers using the legacy API."""
    return build_remediation_plan(
        decision,
        finding,
        ai_analysis,
    )
