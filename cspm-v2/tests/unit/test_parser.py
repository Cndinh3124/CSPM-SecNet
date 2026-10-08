import json
from pathlib import Path

from secnet_cspm.parser import normalize_ocsf, parse_file


FIXTURE = Path(__file__).parent / "fixtures" / "prowler" / "ec2_public_ssh.ocsf.json"


def test_parse_realistic_prowler_ocsf():
    findings = parse_file(FIXTURE, "scan-test", "ap-southeast-1")

    assert len(findings) == 1
    finding = findings[0]

    assert finding["control_id"] == "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
    assert finding["status"] == "FAIL"
    assert finding["severity"] == "HIGH"
    assert finding["title"].startswith("Security group does not allow ingress")
    assert finding["resource_id"] == "sg-06064219c4fe6e8a1"
    assert finding["resource_type"] == "AwsEc2SecurityGroup"
    assert finding["region"] == "ap-southeast-1"
    assert finding["service"] == "ec2"
    assert finding["account_id"] == "392024306192"
    assert finding["fingerprint"]


def test_fingerprint_is_stable():
    finding = json.loads(FIXTURE.read_text(encoding="utf-8"))
    a = normalize_ocsf(finding, "scan-a", "ap-southeast-1")
    b = normalize_ocsf(finding, "scan-b", "ap-southeast-1")

    assert a["fingerprint"] == b["fingerprint"]
