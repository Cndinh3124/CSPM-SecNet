import json
import os
import subprocess
from pathlib import Path
from typing import Any


class RemediationError(RuntimeError):
    pass


ALLOWED_CONTROL = (
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
)
ALLOWED_ACTION = "restrict_public_ssh"
ALLOWED_RESOURCE_ID = "sg-0b18998e447203ad1"


def execute(plan: dict[str, Any], *, approve: bool = False, dry_run: bool = True) -> dict[str, Any]:
    if plan.get("status") not in {"READY", "PENDING_APPROVAL"}:
        raise RemediationError("Remediation plan is not executable.")

    if plan.get("action") != ALLOWED_ACTION:
        raise RemediationError(
            f"Unsupported remediation action: {plan.get('action')}"
        )

    if plan.get("control_id") != ALLOWED_CONTROL:
        raise RemediationError("Unsupported or missing control_id.")

    if plan.get("resource_id") != ALLOWED_RESOURCE_ID:
        raise RemediationError("Unsupported or missing resource_id.")

    for field in ("finding_fingerprint", "region"):
        value = plan.get(field)
        if not isinstance(value, str) or not value.strip():
            raise RemediationError(f"Missing required plan field: {field}")

    if plan.get("approval_required") is not True:
        raise RemediationError(
            "Remediation plan must require explicit approval."
        )

    if plan.get("approval_required") and not approve:
        return {
            "status": "BLOCKED",
            "reason": "Explicit approval is required.",
            "dry_run": dry_run,
        }

    if not dry_run:
        if os.getenv("CSPM_ALLOW_AWS_MUTATION", "false").lower() != "true":
            raise RemediationError(
                "AWS mutation is disabled. Set CSPM_ALLOW_AWS_MUTATION=true only in the controlled demo."
            )

    action = plan.get("action")
    if action != "restrict_public_ssh":
        raise RemediationError(f"Unsupported remediation action: {action}")

    policy = Path(__file__).resolve().parents[3] / "custodian" / "policies" / "ec2-public-ssh.yml"
    cmd = [
        os.getenv("CUSTODIAN_COMMAND", "custodian"),
        "run",
        "-s",
        str(Path("data/custodian")),
        "--region",
        plan["region"],
        str(policy),
    ]

    if dry_run:
        return {
            "status": "DRY_RUN",
            "command": cmd,
            "plan": plan,
        }

    result = subprocess.run(cmd, text=True, capture_output=True)
    output = {
        "status": "EXECUTED" if result.returncode == 0 else "FAILED",
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": cmd,
        "plan": plan,
    }
    if result.returncode != 0:
        raise RemediationError(json.dumps(output, ensure_ascii=False))
    return output
