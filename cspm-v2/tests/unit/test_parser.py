import csv
import json
from pathlib import Path

from secnet_cspm.parser import normalize_ocsf, parse_directory, parse_file

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


def test_parse_prowler_semicolon_csv_maps_uid_status_and_remediation(tmp_path):
    path = tmp_path / "prowler-output.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            delimiter=";",
            fieldnames=[
                "FINDING_UID", "ACCOUNT_UID", "CHECK_ID", "CHECK_TITLE", "STATUS",
                "STATUS_EXTENDED", "SEVERITY", "RESOURCE_TYPE", "RESOURCE_UID",
                "RESOURCE_NAME", "SERVICE_NAME", "REGION",
                "REMEDIATION_RECOMMENDATION_TEXT",
            ],
        )
        writer.writeheader()
        writer.writerow({
            "FINDING_UID": "prowler-aws-accessanalyzer_enabled-account-region-resource",
            "ACCOUNT_UID": "392024306192",
            "CHECK_ID": "accessanalyzer_enabled",
            "CHECK_TITLE": "IAM Access Analyzer is enabled",
            "STATUS": "FAIL",
            "STATUS_EXTENDED": "IAM Access Analyzer is not enabled.",
            "SEVERITY": "Low",
            "RESOURCE_TYPE": "AwsIamAnalyzer",
            "RESOURCE_UID": "arn:aws:accessanalyzer:ap-southeast-1:392024306192:analyzer/unknown",
            "RESOURCE_NAME": "unknown",
            "SERVICE_NAME": "iam",
            "REGION": "ap-southeast-1",
            "REMEDIATION_RECOMMENDATION_TEXT": "Enable IAM Access Analyzer.",
        })

    findings = parse_file(path, "scan-test", "ap-southeast-1")

    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_uid"].startswith("prowler-aws-accessanalyzer_enabled")
    assert finding["control_id"] == "accessanalyzer_enabled"
    assert finding["resource_arn"].startswith("arn:aws:accessanalyzer:")
    assert finding["message"] == "IAM Access Analyzer is not enabled."
    assert finding["remediation"] == "Enable IAM Access Analyzer."


def test_non_fail_statuses_are_not_normalized_as_failed_findings(tmp_path):
    path = tmp_path / "manual.csv"
    path.write_text(
        "CHECK_ID;STATUS;REGION\nexample_check;MANUAL;ap-southeast-1\n",
        encoding="utf-8",
    )

    assert parse_file(path, "scan-test", "ap-southeast-1") == []


def test_parse_directory_deduplicates_csv_and_ocsf_and_ignores_compliance_subdir(tmp_path):
    ocsf = json.loads(FIXTURE.read_text(encoding="utf-8"))
    ocsf["metadata"] = {"event_code": ocsf["finding_info"]["uid"]}
    (tmp_path / "findings.ocsf.json").write_text(
        json.dumps([ocsf]), encoding="utf-8"
    )

    csv_path = tmp_path / "findings.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            delimiter=";",
            fieldnames=[
                "FINDING_UID", "ACCOUNT_UID", "CHECK_ID", "CHECK_TITLE", "STATUS",
                "SEVERITY", "RESOURCE_TYPE", "RESOURCE_UID", "RESOURCE_NAME",
                "SERVICE_NAME", "REGION",
            ],
        )
        writer.writeheader()
        writer.writerow({
            "FINDING_UID": "same-finding",
            "ACCOUNT_UID": "392024306192",
            "CHECK_ID": ocsf["metadata"]["event_code"],
            "CHECK_TITLE": "Security group does not allow ingress from internet to TCP port 22",
            "STATUS": "FAIL",
            "SEVERITY": "High",
            "RESOURCE_TYPE": "AwsEc2SecurityGroup",
            "RESOURCE_UID": "sg-06064219c4fe6e8a1",
            "RESOURCE_NAME": "test-security-group",
            "SERVICE_NAME": "ec2",
            "REGION": "ap-southeast-1",
        })

    compliance_dir = tmp_path / "compliance"
    compliance_dir.mkdir()
    (compliance_dir / "duplicate.csv").write_text(
        csv_path.read_text(encoding="utf-8"), encoding="utf-8"
    )

    findings = parse_directory(tmp_path, "scan-test", "ap-southeast-1")

    assert len(findings) == 1
    assert findings[0]["control_id"] == "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
    assert findings[0]["resource_id"] == "sg-06064219c4fe6e8a1"
