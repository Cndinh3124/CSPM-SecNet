import json
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


BASE_DIR = Path(__file__).resolve().parents[2]
REGISTRY_PATH = BASE_DIR / "docs" / "cspm-policy-registry.json"
OUTPUT_DIR = BASE_DIR / "tests" / "outputs"


def load_registry():
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def get_securityhub_client(region):
    return boto3.client(
        "securityhub",
        region_name=region,
    )


def get_ec2_client(region):
    return boto3.client(
        "ec2",
        region_name=region,
    )


def get_s3_client(region):
    return boto3.client(
        "s3",
        region_name=region,
    )


def get_cloudtrail_client(region):
    return boto3.client(
        "cloudtrail",
        region_name=region,
    )


def get_findings(client, control_id):
    findings = []
    next_token = None

    filters = {
        "ComplianceSecurityControlId": [
            {
                "Value": control_id,
                "Comparison": "EQUALS",
            }
        ]
    }

    while True:
        kwargs = {
            "Filters": filters,
            "MaxResults": 100,
        }

        if next_token:
            kwargs["NextToken"] = next_token

        response = client.get_findings(**kwargs)

        findings.extend(
            response.get("Findings", [])
        )

        next_token = response.get(
            "NextToken"
        )

        if not next_token:
            break

    return findings


def get_resource_id(finding):
    resources = finding.get(
        "Resources",
        [],
    )

    if not resources:
        return "UNKNOWN"

    return resources[0].get(
        "Id",
        "UNKNOWN",
    )


def get_resource_type(finding):
    resources = finding.get(
        "Resources",
        [],
    )

    if not resources:
        return "UNKNOWN"

    return resources[0].get(
        "Type",
        "UNKNOWN",
    )


def normalize_status(finding):
    compliance = finding.get(
        "Compliance",
        {}
    )

    return compliance.get(
        "Status",
        "UNKNOWN",
    )


def extract_resource_id(resource_id):
    """
    Convert an ARN/resource reference into
    the actual AWS resource identifier.

    Examples:

    arn:aws:ec2:...:security-group/sg-123
        -> sg-123

    arn:aws:ec2:...:vpc/vpc-123
        -> vpc-123

    arn:aws:s3:::bucket-name
        -> bucket-name
    """

    if not resource_id:
        return resource_id

    if resource_id.startswith(
        "arn:aws:s3:::"
    ):
        return resource_id.split(
            "arn:aws:s3:::",
            1
        )[1]

    if "/" in resource_id:
        return resource_id.rsplit(
            "/",
            1
        )[-1]

    return resource_id


def resource_exists(
    finding,
    region,
):
    """
    Determine whether the AWS resource
    referenced by a Security Hub finding
    still exists.

    Returns:

        True  -> resource exists
        False -> resource does not exist
        None  -> unable to determine
    """

    resource_id = get_resource_id(
        finding
    )

    resource_type = get_resource_type(
        finding
    )

    normalized_id = extract_resource_id(
        resource_id
    )

    try:

        # -------------------------------------------------
        # EC2 Security Group
        # -------------------------------------------------

        if resource_type == "AwsEc2SecurityGroup":

            ec2 = get_ec2_client(
                region
            )

            ec2.describe_security_groups(
                GroupIds=[normalized_id]
            )

            return True

        # -------------------------------------------------
        # EC2 VPC
        # -------------------------------------------------

        if resource_type == "AwsEc2Vpc":

            ec2 = get_ec2_client(
                region
            )

            response = ec2.describe_vpcs(
                VpcIds=[normalized_id]
            )

            return len(
                response.get(
                    "Vpcs",
                    []
                )
            ) > 0

        # -------------------------------------------------
        # S3 Bucket
        # -------------------------------------------------

        if resource_type == "AwsS3Bucket":

            s3 = get_s3_client(
                region
            )

            s3.head_bucket(
                Bucket=normalized_id
            )

            return True

        # -------------------------------------------------
        # CloudTrail
        # -------------------------------------------------

        if resource_type == "AwsCloudTrailTrail":

            cloudtrail = get_cloudtrail_client(
                region
            )

            response = cloudtrail.get_trail(
                Name=normalized_id
            )

            return (
                response.get(
                    "Trail",
                    None
                )
                is not None
            )

        # -------------------------------------------------
        # Unknown resource type
        # -------------------------------------------------

        return None

    except ClientError as exc:

        error_code = exc.response.get(
            "Error",
            {}
        ).get(
            "Code"
        )

        not_found_codes = {
            "InvalidGroup.NotFound",
            "InvalidVpcID.NotFound",
            "NoSuchBucket",
            "404",
            "ResourceNotFoundException",
        }

        if error_code in not_found_codes:
            return False

        return None

    except Exception:
        return None


def build_resource_item(
    finding,
    status,
):
    return {
        "resource_id": get_resource_id(
            finding
        ),
        "resource_type": get_resource_type(
            finding
        ),
        "status": status,
        "record_state": finding.get(
            "RecordState"
        ),
        "workflow_status": finding.get(
            "Workflow",
            {}
        ).get(
            "Status"
        ),
        "updated_at": finding.get(
            "UpdatedAt"
        ),
        "last_observed_at": finding.get(
            "LastObservedAt"
        ),
        "title": finding.get(
            "Title"
        ),
    }


def build_control_result(
    control,
    findings,
    region,
):
    control_id = control[
        "control_id"
    ]

    passed = []
    failed = []
    stale = []
    unknown = []

    for finding in findings:

        status = normalize_status(
            finding
        )

        resource_id = get_resource_id(
            finding
        )

        # -------------------------------------------------
        # First check whether resource still exists
        # -------------------------------------------------

        exists = resource_exists(
            finding,
            region
        )

        # -------------------------------------------------
        # Resource has been deleted
        # -------------------------------------------------

        if exists is False:

            stale.append(
                build_resource_item(
                    finding,
                    "STALE"
                )
            )

            continue

        # -------------------------------------------------
        # Resource still exists
        # -------------------------------------------------

        item = build_resource_item(
            finding,
            status
        )

        if status == "PASSED":

            passed.append(item)

        elif status == "FAILED":

            failed.append(item)

        else:

            unknown.append(item)

    # -----------------------------------------------------
    # Control-level status
    # -----------------------------------------------------

    if failed:

        control_status = "FAILED"

    elif unknown:

        control_status = "UNKNOWN"

    elif passed:

        control_status = "PASSED"

    else:

        control_status = "NO_DATA"

    # -----------------------------------------------------
    # Resource compliance
    #
    # STALE resources are intentionally excluded.
    # -----------------------------------------------------

    active_resources = (
        len(passed)
        + len(failed)
        + len(unknown)
    )

    resource_compliance = 0.0

    if active_resources > 0:

        resource_compliance = round(
            (
                len(passed)
                / active_resources
            )
            * 100,
            2
        )

    return {
        "control_id": control_id,
        "resource": control.get(
            "resource"
        ),
        "severity": control.get(
            "severity"
        ),

        "status": control_status,

        "passed_resources": len(
            passed
        ),

        "failed_resources": len(
            failed
        ),

        "stale_resources": len(
            stale
        ),

        "unknown_resources": len(
            unknown
        ),

        "total_active_resources":
            active_resources,

        "resource_compliance_percent":
            resource_compliance,

        "passed": passed,

        "failed": failed,

        "stale": stale,

        "unknown": unknown,
    }


def print_control_result(
    result
):
    control_id = result[
        "control_id"
    ]

    status = result[
        "status"
    ]

    print(
        f"[SCAN] {control_id:<14}"
        f"{status:<15}"
        f"Passed={result['passed_resources']} "
        f"Failed={result['failed_resources']}"
    )

    if result[
        "failed"
    ]:

        print(
            "       Failed resources:"
        )

        for item in result[
            "failed"
        ]:

            print(
                f"         - "
                f"{item['resource_id']}"
            )

    if result[
        "stale"
    ]:

        print(
            "       Stale resources:"
        )

        for item in result[
            "stale"
        ]:

            print(
                f"         - "
                f"{item['resource_id']}"
            )

    if result[
        "unknown"
    ]:

        print(
            "       Unknown resources:"
        )

        for item in result[
            "unknown"
        ]:

            print(
                f"         - "
                f"{item['resource_id']}"
            )

    print(
        "       Resource compliance: "
        f"{result['resource_compliance_percent']:.2f}%"
    )


def save_report(
    report
):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%dT%H%M%SZ"
    )

    output_path = (
        OUTPUT_DIR
        / f"cspm-scan-{timestamp}.json"
    )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            report,
            f,
            indent=2,
            ensure_ascii=False
        )

    return output_path


def main():

    registry = load_registry()

    provider = registry.get(
        "provider",
        "AWS"
    )

    region = registry.get(
        "region",
        "ap-southeast-1"
    )

    benchmark = registry.get(
        "benchmark",
        "CIS AWS Foundations Benchmark"
    )

    print("=" * 70)

    print(
        "CSPM ENGINE v3.1"
    )

    print("=" * 70)

    print(
        f"Provider : {provider}"
    )

    print(
        f"Region   : {region}"
    )

    print(
        f"Benchmark: {benchmark}"
    )

    print()

    securityhub = (
        get_securityhub_client(
            region
        )
    )

    controls = registry.get(
        "policies",
        []
    )

    results = []

    for control in controls:

        control_id = control[
            "control_id"
        ]

        findings = get_findings(
            securityhub,
            control_id
        )

        result = build_control_result(
            control,
            findings,
            region
        )

        results.append(
            result
        )

        print_control_result(
            result
        )

    # -----------------------------------------------------
    # Control-level summary
    # -----------------------------------------------------

    passed_controls = sum(
        1
        for result in results
        if result["status"]
        == "PASSED"
    )

    failed_controls = sum(
        1
        for result in results
        if result["status"]
        == "FAILED"
    )

    unknown_controls = sum(
        1
        for result in results
        if result["status"]
        == "UNKNOWN"
    )

    total_controls = len(
        results
    )

    compliance = (
        round(
            (
                passed_controls
                / total_controls
            )
            * 100,
            2
        )
        if total_controls
        else 0.0
    )

    # -----------------------------------------------------
    # Resource-level totals
    # -----------------------------------------------------

    total_passed_resources = sum(
        result[
            "passed_resources"
        ]
        for result in results
    )

    total_failed_resources = sum(
        result[
            "failed_resources"
        ]
        for result in results
    )

    total_stale_resources = sum(
        result[
            "stale_resources"
        ]
        for result in results
    )

    total_unknown_resources = sum(
        result[
            "unknown_resources"
        ]
        for result in results
    )

    total_active_resources = sum(
        result[
            "total_active_resources"
        ]
        for result in results
    )

    resource_compliance = (
        round(
            (
                total_passed_resources
                / total_active_resources
            )
            * 100,
            2
        )
        if total_active_resources
        else 0.0
    )

    # -----------------------------------------------------
    # Report
    # -----------------------------------------------------

    report = {

        "scan": {

            "engine_version":
                "3.1",

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "provider":
                provider,

            "region":
                region,

            "benchmark":
                benchmark,
        },

        "summary": {

            "total_controls":
                total_controls,

            "passed_controls":
                passed_controls,

            "failed_controls":
                failed_controls,

            "unknown_controls":
                unknown_controls,

            "control_compliance_percent":
                compliance,

            "total_active_resources":
                total_active_resources,

            "passed_resources":
                total_passed_resources,

            "failed_resources":
                total_failed_resources,

            "stale_resources":
                total_stale_resources,

            "unknown_resources":
                total_unknown_resources,

            "resource_compliance_percent":
                resource_compliance,
        },

        "controls":
            results,
    }

    # -----------------------------------------------------
    # Print summary
    # -----------------------------------------------------

    print()

    print("=" * 70)

    print(
        "SCAN SUMMARY"
    )

    print("=" * 70)

    print(
        f"Total controls : "
        f"{total_controls}"
    )

    print(
        f"Passed         : "
        f"{passed_controls}"
    )

    print(
        f"Failed         : "
        f"{failed_controls}"
    )

    print(
        f"Unknown        : "
        f"{unknown_controls}"
    )

    print(
        f"Compliance     : "
        f"{compliance}%"
    )

    print()

    print(
        "RESOURCE SUMMARY"
    )

    print(
        f"Active resources : "
        f"{total_active_resources}"
    )

    print(
        f"Passed resources: "
        f"{total_passed_resources}"
    )

    print(
        f"Failed resources: "
        f"{total_failed_resources}"
    )

    print(
        f"Stale resources : "
        f"{total_stale_resources}"
    )

    print(
        f"Unknown resources: "
        f"{total_unknown_resources}"
    )

    print(
        f"Resource compliance: "
        f"{resource_compliance}%"
    )

    output_path = save_report(
        report
    )

    print()

    print(
        f"Report: {output_path}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()