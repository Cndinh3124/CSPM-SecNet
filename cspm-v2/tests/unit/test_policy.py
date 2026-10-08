from secnet_cspm.policy import evaluate


def finding(**overrides):
    value = {
        "control_id": "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
        "resource_id": "sg-123",
        "resource_arn": "arn:aws:ec2:ap-southeast-1:123:security-group/sg-123",
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


def test_demo_public_ssh_requires_approval():
    decision = evaluate(finding(), {"auto_remediation": "SAFE"})
    assert decision.allowed is True
    assert decision.approval_required is True
    assert decision.action == "restrict_public_ssh"


def test_unscoped_resource_is_blocked():
    decision = evaluate(
        finding(labels=["Environment:demo"]),
        {"auto_remediation": "SAFE"},
    )
    assert decision.allowed is False


def test_production_is_blocked():
    decision = evaluate(
        finding(labels=[
            "CSPMScope:demo",
            "CSPMTarget:true",
            "Environment:production",
        ]),
        {"auto_remediation": "SAFE"},
    )
    assert decision.allowed is False


def test_manual_ai_cannot_create_plan():
    decision = evaluate(finding(), {"auto_remediation": "MANUAL"})
    assert decision.allowed is False
