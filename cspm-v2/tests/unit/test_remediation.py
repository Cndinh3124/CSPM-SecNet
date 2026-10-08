from pathlib import Path

import pytest

from secnet_cspm.remediation.executor import execute, RemediationError


def plan(**overrides):
    value = {
        "action": "restrict_public_ssh",
        "status": "PENDING_APPROVAL",
        "approval_required": True,
        "finding_fingerprint": "abc",
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
