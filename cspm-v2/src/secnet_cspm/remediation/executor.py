import json
import os
import subprocess
from pathlib import Path
from typing import Any


class RemediationError(RuntimeError):
    pass


def execute(plan: dict[str, Any], *, approve: bool = False, dry_run: bool = True) -> dict[str, Any]:
    if plan.get("status") not in {"READY", "PENDING_APPROVAL"}:
        raise RemediationError("Remediation plan is not executable.")

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

    policy = Path(__file__).resolve().parents[2] / "custodian" / "policies" / "ec2-public-ssh.yml"
    cmd = [
        os.getenv("CUSTODIAN_COMMAND", "custodian"),
        "run",
        "-s",
        str(Path("data/custodian")),
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
