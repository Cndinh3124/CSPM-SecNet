import pytest
from secnet_cspm.lifecycle import transition


def test_valid_lifecycle():
    assert transition("OPEN", "ANALYZING") == "ANALYZING"
    assert transition("ANALYZING", "REMEDIATION_PENDING") == "REMEDIATION_PENDING"
    assert transition("REMEDIATION_PENDING", "APPROVED") == "APPROVED"
    assert transition("APPROVED", "REMEDIATING") == "REMEDIATING"
    assert transition("REMEDIATING", "VERIFYING") == "VERIFYING"
    assert transition("VERIFYING", "RESOLVED") == "RESOLVED"


def test_invalid_transition_is_rejected():
    with pytest.raises(ValueError):
        transition("OPEN", "RESOLVED")
