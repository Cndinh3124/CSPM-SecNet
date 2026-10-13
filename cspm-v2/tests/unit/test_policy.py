
import pytest

from secnet_cspm.policy import build_plan, evaluate


def finding(**overrides):
    value = {
        "control_id": (
            "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
        ),
        "resource_id": "sg-123",
        "resource_arn": (
            "arn:aws:ec2:ap-southeast-1:123:security-group/sg-123"
        ),
        "region": "ap-southeast-1",
        "fingerprint": "abc",
        "labels": [
            "CSPMScope:demo",
            "CSPMTarget:true",
            "Environment:demo",
        ],
    }
    value.update(overrides)
    return value


def test_safe_ai_creates_plan_requiring_approval():
    decision = evaluate(finding(), {"auto_remediation": "SAFE"})

    assert decision.allowed is True
    assert decision.approval_required is True
    assert decision.action == "restrict_public_ssh"


def test_review_required_ai_creates_plan_requiring_approval():
    decision = evaluate(finding(), {"auto_remediation": "REVIEW_REQUIRED"})

    assert decision.allowed is True
    assert decision.approval_required is True


def test_manual_ai_can_create_review_plan():
    decision = evaluate(finding(), {"auto_remediation": "MANUAL"})

    assert decision.allowed is True
    assert decision.approval_required is True
    assert decision.action == "restrict_public_ssh"


def test_missing_ai_analysis_defaults_to_manual():
    decision = evaluate(finding())

    assert decision.allowed is True
    assert decision.approval_required is True


def test_unknown_ai_classification_is_blocked():
    decision = evaluate(finding(), {"auto_remediation": "UNKNOWN"})

    assert decision.allowed is False


def test_unscoped_resource_is_blocked():
    decision = evaluate(
        finding(labels=["Environment:demo"]),
        {"auto_remediation": "SAFE"},
    )

    assert decision.allowed is False


def test_resource_without_target_tag_is_blocked():
    decision = evaluate(
        finding(
            labels=[
                "CSPMScope:demo",
                "Environment:demo",
            ]
        ),
        {"auto_remediation": "SAFE"},
    )

    assert decision.allowed is False


def test_production_is_blocked():
    decision = evaluate(
        finding(
            labels=[
                "CSPMScope:demo",
                "CSPMTarget:true",
                "Environment:production",
            ]
        ),
        {"auto_remediation": "SAFE"},
    )

    assert decision.allowed is False


def test_unsupported_control_is_blocked():
    decision = evaluate(
        finding(control_id="unsupported_control"),
        {"auto_remediation": "SAFE"},
    )

    assert decision.allowed is False


def test_build_plan_requires_approved_policy_decision():
    value = finding()
    analysis = {
        "auto_remediation": "MANUAL",
        "recommended_remediation": "Review SSH ingress.",
        "remediation_plan": {},
        "confidence": 0.95,
    }

    decision = evaluate(value, analysis)
    plan = build_plan(value, analysis, decision)

    assert plan["status"] == "PENDING_APPROVAL"
    assert plan["approval_required"] is True
    assert plan["action"] == "restrict_public_ssh"


def test_build_plan_rejects_denied_decision():
    value = finding(labels=["Environment:demo"])
    decision = evaluate(value, {"auto_remediation": "SAFE"})

    with pytest.raises(ValueError):
        build_plan(value, {}, decision)


def test_ocsf_dictionary_labels_are_supported():
    value = finding(
        labels=[
            {"Project": "SecNet-CSPM"},
            {"CSPMTest": "true"},
            {"CSPMScope": "demo"},
            {"CSPMTarget": "true"},
            {"Environment": "demo"},
        ]
    )

    decision = evaluate(value, {"auto_remediation": "SAFE"})

    assert decision.allowed is True
    assert decision.action == "restrict_public_ssh"
    assert decision.approval_required is True
