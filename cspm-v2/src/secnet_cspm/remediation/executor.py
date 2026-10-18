import os
import re
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class RemediationError(RuntimeError):
    """Raised when a remediation plan is invalid or AWS rejects the action."""


ALLOWED_CONTROL = "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
ALLOWED_ACTION = "restrict_public_ssh"
_RESOURCE_ID_RE = re.compile(r"^sg-[0-9a-f]{8}(?:[0-9a-f]{9})?$")
_ALLOWED_SCOPES = {"demo", "sandbox"}
_PUBLIC_IPV4 = "0.0.0.0/0"
_PUBLIC_IPV6 = "::/0"


def _validate_plan(plan: dict[str, Any]) -> tuple[str, str]:
    if not isinstance(plan, dict):
        raise RemediationError("Remediation plan must be a JSON object.")

    if plan.get("status") not in {"READY", "PENDING_APPROVAL"}:
        raise RemediationError("Remediation plan is not executable.")
    if plan.get("action") != ALLOWED_ACTION:
        raise RemediationError(f"Unsupported remediation action: {plan.get('action')}")
    if plan.get("control_id") != ALLOWED_CONTROL:
        raise RemediationError("Unsupported or missing control_id.")
    if plan.get("approval_required") is not True:
        raise RemediationError("Remediation plan must require explicit approval.")

    resource_id = plan.get("resource_id")
    if not isinstance(resource_id, str) or not _RESOURCE_ID_RE.fullmatch(resource_id):
        raise RemediationError("Invalid or missing EC2 Security Group ID.")

    region = plan.get("region")
    if not isinstance(region, str) or not region.strip():
        raise RemediationError("Missing required plan field: region.")
    if not isinstance(plan.get("finding_fingerprint"), str) or not plan["finding_fingerprint"].strip():
        raise RemediationError("Missing required plan field: finding_fingerprint.")

    return resource_id, region.strip()


def _public_ssh_permissions(group: dict[str, Any]) -> list[dict[str, Any]]:
    """Return only public CIDR entries for exact TCP/22 ingress rules."""
    revoke: list[dict[str, Any]] = []
    for permission in group.get("IpPermissions", []):
        if (
            permission.get("IpProtocol") != "tcp"
            or permission.get("FromPort") != 22
            or permission.get("ToPort") != 22
        ):
            continue

        for entry in permission.get("IpRanges", []):
            if entry.get("CidrIp") == _PUBLIC_IPV4:
                revoke.append({
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": _PUBLIC_IPV4}],
                })
        for entry in permission.get("Ipv6Ranges", []):
            if entry.get("CidrIpv6") == _PUBLIC_IPV6:
                revoke.append({
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "Ipv6Ranges": [{"CidrIpv6": _PUBLIC_IPV6}],
                })
    return revoke


def execute(
    plan: dict[str, Any],
    *,
    approve: bool = False,
    dry_run: bool = True,
) -> dict[str, Any]:
    resource_id, region = _validate_plan(plan)

    if not approve:
        return {
            "status": "BLOCKED",
            "reason": "Explicit approval is required.",
            "dry_run": dry_run,
            "resource_id": resource_id,
            "region": region,
        }

    if not dry_run and os.getenv("CSPM_ALLOW_AWS_MUTATION", "false").lower() != "true":
        raise RemediationError(
            "AWS mutation is disabled. Set CSPM_ALLOW_AWS_MUTATION=true "
            "only for an explicitly approved demo/sandbox change."
        )

    try:
        ec2 = boto3.client("ec2", region_name=region)
        response = ec2.describe_security_groups(GroupIds=[resource_id])
    except (BotoCoreError, ClientError) as exc:
        raise RemediationError(f"Unable to inspect Security Group: {type(exc).__name__}") from exc

    groups = response.get("SecurityGroups", [])
    if len(groups) != 1 or groups[0].get("GroupId") != resource_id:
        raise RemediationError("AWS did not return exactly the requested Security Group.")

    group = groups[0]
    tags = {
        str(item.get("Key", "")).lower(): str(item.get("Value", ""))
        for item in group.get("Tags", [])
        if isinstance(item, dict)
    }
    scope = tags.get("cspmscope", "").lower()
    if tags.get("cspmtarget", "").lower() != "true" or scope not in _ALLOWED_SCOPES:
        raise RemediationError(
            "Security Group is not explicitly tagged as an allowed CSPM demo/sandbox target."
        )
    if tags.get("environment", "").lower() not in _ALLOWED_SCOPES:
        raise RemediationError("Security Group Environment tag must be demo or sandbox.")

    permissions = _public_ssh_permissions(group)
    if not permissions:
        return {
            "status": "NOOP",
            "reason": "No exact public TCP/22 ingress rule was found; no changes made.",
            "resource_id": resource_id,
            "region": region,
            "dry_run": dry_run,
        }

    if dry_run:
        return {
            "status": "DRY_RUN",
            "reason": "Would revoke only the public TCP/22 CIDR entries listed below.",
            "resource_id": resource_id,
            "region": region,
            "permissions": permissions,
            "dry_run": True,
        }

    try:
        result = ec2.revoke_security_group_ingress(
            GroupId=resource_id,
            IpPermissions=permissions,
        )
    except (BotoCoreError, ClientError) as exc:
        raise RemediationError(f"AWS rejected the remediation: {type(exc).__name__}") from exc

    return {
        "status": "EXECUTED",
        "resource_id": resource_id,
        "region": region,
        "permissions": permissions,
        "aws_response": result,
        "dry_run": False,
    }
