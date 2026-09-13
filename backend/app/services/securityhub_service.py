import logging
from typing import Any

import boto3


logger = logging.getLogger("secnet-securityhub")


class SecurityHubService:
    """
    Read-only service for collecting AWS Security Hub findings.

    This service does not modify AWS resources.
    """

    def __init__(self, region: str = "ap-southeast-1"):
        self.region = region

        self.client = boto3.client(
            "securityhub",
            region_name=region,
        )

    def get_findings(
        self,
        max_results: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Retrieve active Security Hub findings.

        READ-ONLY.
        """

        findings: list[dict[str, Any]] = []
        next_token = None

        while True:
            kwargs: dict[str, Any] = {
                "Filters": {
                    "RecordState": [
                        {
                            "Value": "ACTIVE",
                            "Comparison": "EQUALS",
                        }
                    ]
                },
                "MaxResults": min(max_results, 100),
            }

            if next_token:
                kwargs["NextToken"] = next_token

            response = self.client.get_findings(
                **kwargs
            )

            findings.extend(
                response.get("Findings", [])
            )

            next_token = response.get(
                "NextToken"
            )

            if not next_token:
                break

            if len(findings) >= max_results:
                break

        return findings[:max_results]

    def get_ec2_53_findings(
        self,
        max_results: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Retrieve active EC2.53 findings.

        READ-ONLY.
        """

        response = self.client.get_findings(
            Filters={
                "RecordState": [
                    {
                        "Value": "ACTIVE",
                        "Comparison": "EQUALS",
                    }
                ],
                "ComplianceSecurityControlId": [
                    {
                        "Value": "EC2.53",
                        "Comparison": "EQUALS",
                    }
                ],
            },
            MaxResults=min(max_results, 100),
        )

        return response.get(
            "Findings",
            [],
        )

    def finding_to_cspm(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Convert one AWS Security Hub finding into
        the normalized SecNet CSPM Finding structure.

        This method does NOT write to PostgreSQL
        and does NOT modify AWS resources.
        """

        compliance = (
            finding.get("Compliance") or {}
        )

        severity_data = (
            finding.get("Severity") or {}
        )

        workflow = (
            finding.get("Workflow") or {}
        )

        resources = (
            finding.get("Resources") or []
        )

        resource = (
            resources[0]
            if resources
            else {}
        )

        control_id = compliance.get(
            "SecurityControlId",
            "UNKNOWN",
        )

        severity = severity_data.get(
            "Label",
            "UNKNOWN",
        )

        workflow_status = workflow.get(
            "Status",
            "NEW",
        )

        record_state = finding.get(
            "RecordState",
            "ACTIVE",
        )

        # -----------------------------------------------------
        # CSPM status
        #
        # Security Hub Workflow and CSPM compliance status
        # are different concepts.
        #
        # NEW / NOTIFIED / IN_PROGRESS findings are treated
        # as FAILED for the normalized CSPM finding.
        #
        # RESOLVED is retained as RESOLVED.
        # -----------------------------------------------------

        if workflow_status == "RESOLVED":
            cspm_status = "RESOLVED"
        elif record_state == "ARCHIVED":
            cspm_status = "ARCHIVED"
        else:
            cspm_status = "FAILED"

        # -----------------------------------------------------
        # Risk mapping
        # -----------------------------------------------------

        risk_mapping = {
            "CRITICAL": (
                95,
                "CRITICAL",
            ),
            "HIGH": (
                80,
                "HIGH",
            ),
            "MEDIUM": (
                55,
                "MEDIUM",
            ),
            "LOW": (
                25,
                "LOW",
            ),
            "INFORMATIONAL": (
                0,
                "LOW",
            ),
        }

        risk_score, risk_level = risk_mapping.get(
            severity.upper(),
            (0, "LOW"),
        )

        return {
            "finding_id": finding.get(
                "Id",
                "UNKNOWN",
            ),
            "control_id": control_id,
            "title": finding.get(
                "Title",
                "Unknown Security Hub finding",
            ),
            "description": finding.get(
                "Description",
                "",
            ),
            "severity": severity,
            "status": cspm_status,
            "resource_id": resource.get(
                "Id"
            ),
            "resource_type": resource.get(
                "Type"
            ),
            "region": resource.get(
                "Region"
            ) or self.region,
            "source": "AWS Security Hub",
            "risk_score": risk_score,
            "risk_level": risk_level,

            # Preserve Security Hub-specific state
            # without changing the current database schema.
            "securityhub_workflow": workflow_status,
            "securityhub_record_state": record_state,
        }


def get_securityhub_service(
    region: str = "ap-southeast-1",
) -> SecurityHubService:
    """
    Create a Security Hub service instance.
    """

    return SecurityHubService(
        region=region
    )