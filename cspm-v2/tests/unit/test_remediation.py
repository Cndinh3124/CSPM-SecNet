import pytest

from secnet_cspm import remediation
from secnet_cspm.remediation import executor
from secnet_cspm.remediation.executor import RemediationError, execute


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


def security_group(**overrides):
    value = {
        "GroupId": "sg-0b18998e447203ad1",
        "Tags": [
            {"Key": "CSPMTarget", "Value": "true"},
            {"Key": "CSPMScope", "Value": "demo"},
            {"Key": "Environment", "Value": "demo"},
        ],
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [
                    {"CidrIp": "0.0.0.0/0"},
                    {"CidrIp": "10.0.0.0/8"},
                ],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
        ],
    }
    value.update(overrides)
    return value


class FakeEC2:
    def __init__(self, group=None):
        self.group = group or security_group()
        self.describe_calls = []
        self.revoke_calls = []

    def describe_security_groups(self, **kwargs):
        self.describe_calls.append(kwargs)
        return {"SecurityGroups": [self.group]}

    def revoke_security_group_ingress(self, **kwargs):
        self.revoke_calls.append(kwargs)
        return {"Return": True}


def mock_ec2(monkeypatch, client):
    monkeypatch.setattr(executor.boto3, "client", lambda service, **kwargs: client)


def test_without_approval_is_blocked_and_does_not_call_aws(monkeypatch):
    def unexpected_client(*args, **kwargs):
        raise AssertionError("AWS client must not be created without approval")

    monkeypatch.setattr(executor.boto3, "client", unexpected_client)
    result = execute(plan(), approve=False, dry_run=True)
    assert result["status"] == "BLOCKED"


def test_dry_run_lists_only_public_ssh_and_does_not_mutate(monkeypatch):
    client = FakeEC2()
    mock_ec2(monkeypatch, client)

    result = execute(plan(), approve=True, dry_run=True)

    assert result["status"] == "DRY_RUN"
    assert len(client.describe_calls) == 1
    assert client.revoke_calls == []
    assert result["permissions"] == [
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    ]


def test_unknown_action_is_rejected():
    with pytest.raises(RemediationError):
        execute(plan(action="delete_everything"), approve=True, dry_run=True)


def test_missing_control_id_is_rejected():
    value = plan()
    value.pop("control_id")
    with pytest.raises(RemediationError):
        execute(value, approve=True, dry_run=True)


def test_invalid_resource_id_is_rejected():
    with pytest.raises(RemediationError):
        execute(plan(resource_id="sg-12345678xyz"), approve=True, dry_run=True)


def test_missing_region_is_rejected():
    value = plan()
    value.pop("region")
    with pytest.raises(RemediationError):
        execute(value, approve=True, dry_run=True)


def test_missing_fingerprint_is_rejected():
    with pytest.raises(RemediationError):
        execute(plan(finding_fingerprint=""), approve=True, dry_run=True)


def test_live_mutation_requires_explicit_env(monkeypatch):
    monkeypatch.delenv("CSPM_ALLOW_AWS_MUTATION", raising=False)
    with pytest.raises(RemediationError, match="AWS mutation is disabled"):
        execute(plan(), approve=True, dry_run=False)


@pytest.mark.parametrize(
    "tags",
    [
        [{"Key": "CSPMScope", "Value": "demo"}, {"Key": "Environment", "Value": "demo"}],
        [
            {"Key": "CSPMTarget", "Value": "true"},
            {"Key": "CSPMScope", "Value": "production"},
            {"Key": "Environment", "Value": "production"},
        ],
        [
            {"Key": "CSPMTarget", "Value": "true"},
            {"Key": "CSPMScope", "Value": "demo"},
            {"Key": "Environment", "Value": "production"},
        ],
    ],
)
def test_unapproved_scope_or_missing_target_tag_is_blocked(monkeypatch, tags):
    client = FakeEC2(security_group(Tags=tags))
    mock_ec2(monkeypatch, client)

    with pytest.raises(RemediationError, match="tagged|Environment"):
        execute(plan(), approve=True, dry_run=True)

    assert client.revoke_calls == []


def test_no_public_ssh_rule_is_noop(monkeypatch):
    client = FakeEC2(security_group(IpPermissions=[
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
        }
    ]))
    mock_ec2(monkeypatch, client)

    result = execute(plan(), approve=True, dry_run=True)

    assert result["status"] == "NOOP"
    assert client.revoke_calls == []


def test_ipv6_public_ssh_is_detected(monkeypatch):
    client = FakeEC2(security_group(IpPermissions=[
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
    ]))
    mock_ec2(monkeypatch, client)

    result = execute(plan(), approve=True, dry_run=True)

    assert result["status"] == "DRY_RUN"
    assert result["permissions"][0]["Ipv6Ranges"] == [{"CidrIpv6": "::/0"}]


def test_live_execution_revokes_only_selected_public_ssh_entry(monkeypatch):
    monkeypatch.setenv("CSPM_ALLOW_AWS_MUTATION", "true")
    client = FakeEC2()
    mock_ec2(monkeypatch, client)

    result = execute(plan(), approve=True, dry_run=False)

    assert result["status"] == "EXECUTED"
    assert client.revoke_calls == [
        {
            "GroupId": "sg-0b18998e447203ad1",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        }
    ]


def test_aws_group_mismatch_is_blocked(monkeypatch):
    client = FakeEC2(security_group(GroupId="sg-11111111"))
    mock_ec2(monkeypatch, client)

    with pytest.raises(RemediationError, match="exactly the requested"):
        execute(plan(), approve=True, dry_run=True)


def test_broad_or_non_ssh_permissions_are_not_selected(monkeypatch):
    client = FakeEC2(security_group(IpPermissions=[
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        },
    ]))
    mock_ec2(monkeypatch, client)

    result = execute(plan(), approve=True, dry_run=True)

    assert result["status"] == "NOOP"
    assert client.revoke_calls == []
