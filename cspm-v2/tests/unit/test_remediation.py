from pathlib import Path

import pytest

from secnet_cspm.remediation.executor import execute, RemediationError


def plan(**overrides):
    value = {
        "action": "restrict_public_ssh",
        "status": "PENDING_APPROVAL",
        "approval_required": True,
        "finding_fingerprint": "abc",
        "control_id": (
            "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
        ),
        "resource_id": "sg-0b18998e447203ad1",
        "region": "ap-southeast-1",
    }
    value.update(overrides)
    return value


def test_without_approval_is_blocked():
    result = execute(plan(), approve=False, dry_run=True)
    assert result["status"] == "BLOCKED"


def test_dry_run_does_not_mutate():
    result = execute(plan(), approve=True, dry_run=True)
    assert result["status"] == "DRY_RUN"


def test_unknown_action_is_rejected():
    with pytest.raises(RemediationError):
        execute(plan(action="delete_everything"), approve=True, dry_run=True)


def test_live_mutation_requires_explicit_env(monkeypatch):
    monkeypatch.delenv("CSPM_ALLOW_AWS_MUTATION", raising=False)
    with pytest.raises(RemediationError):
        execute(plan(), approve=True, dry_run=False)

def test_missing_control_id_is_rejected():
    value = plan()
    value.pop("control_id")
    with pytest.raises(RemediationError):
        execute(value, approve=True, dry_run=True)


def test_wrong_resource_id_is_rejected():
    with pytest.raises(RemediationError):
        execute(
            plan(resource_id="sg-12345678"),
            approve=True,
            dry_run=True,
        )


def test_missing_region_is_rejected():
    value = plan()
    value.pop("region")
    with pytest.raises(RemediationError):
        execute(value, approve=True, dry_run=True)


def test_dry_run_does_not_call_custodian(monkeypatch):
    import secnet_cspm.remediation.executor as executor

    def unexpected_call(*args, **kwargs):
        raise AssertionError("Custodian must not run during dry-run")

    monkeypatch.setattr(executor.subprocess, "run", unexpected_call)

    result = execute(plan(), approve=True, dry_run=True)
    assert result["status"] == "DRY_RUN"


def test_dry_run_command_contains_plan_region():
    result = execute(plan(), approve=True, dry_run=True)

    assert result["status"] == "DRY_RUN"
    assert "--region" in result["command"]

    region_index = result["command"].index("--region")
    assert result["command"][region_index + 1] == "ap-southeast-1"
