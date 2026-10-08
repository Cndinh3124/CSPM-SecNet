from dataclasses import dataclass
from typing import Any


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


def _labels_to_dict(labels: list[Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for label in labels:
        if not isinstance(label, str) or ":" not in label:
            continue
        key, value = label.split(":", 1)
        result[key] = value
    return result


def evaluate(finding: dict[str, Any], ai_analysis: dict[str, Any] | None = None) -> PolicyDecision:
    control_id = finding.get("control_id", "")
    rule = DEFAULT_RULES.get(control_id)
    if not rule:
        return PolicyDecision("none", False, False, "No deterministic remediation policy exists.")

    labels = _labels_to_dict(finding.get("labels", []))
    scope = labels.get("CSPMScope")
    target = labels.get("CSPMTarget", "").lower() == "true"
    environment = labels.get("Environment", "")

    if not target:
        return PolicyDecision("none", False, False, "Resource is not explicitly tagged CSPMTarget=true.")
    if scope not in rule["allowed_scopes"]:
        return PolicyDecision("none", False, False, f"Scope '{scope}' is not allowed.")
    if environment == "production" and not rule["production_allowed"]:
        return PolicyDecision("none", False, False, "Production remediation is disabled by policy.")

    ai_mode = str((ai_analysis or {}).get("auto_remediation", "MANUAL"))
    if ai_mode == "MANUAL":
        return PolicyDecision("none", False, False, "AI classified remediation as MANUAL.")
    if ai_mode not in {"SAFE", "REVIEW_REQUIRED"}:
        return PolicyDecision("none", False, False, f"Unsupported AI remediation class: {ai_mode}.")

    return PolicyDecision(
        action=rule["action"],
        allowed=True,
        approval_required=rule["approval_required"] or ai_mode == "REVIEW_REQUIRED",
        reason="Deterministic scope/control policy allows a remediation plan.",
    )


def build_plan(finding: dict[str, Any], ai_analysis: dict[str, Any], decision: PolicyDecision) -> dict[str, Any]:
    return {
        "finding_fingerprint": finding["fingerprint"],
        "control_id": finding["control_id"],
        "resource_id": finding["resource_id"],
        "resource_arn": finding.get("resource_arn", ""),
        "region": finding["region"],
        "action": decision.action,
        "approval_required": decision.approval_required,
        "status": "PENDING_APPROVAL" if decision.approval_required else "READY",
        "reason": decision.reason,
        "ai": {
            "recommended_remediation": ai_analysis.get("recommended_remediation", ""),
            "remediation_plan": ai_analysis.get("remediation_plan", {}),
            "confidence": ai_analysis.get("confidence"),
        },
    }
