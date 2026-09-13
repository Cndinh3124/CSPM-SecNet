import logging
import time
from datetime import datetime, timezone

from sqlalchemy import select

from app.db import SessionLocal
from app.models import Scan, Finding, Resource

from secnet_cspm.scanner import scan as run_cspm_scan
from app.services.securityhub_service import SecurityHubService


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("secnet-cspm-worker")


def utcnow():
    return datetime.now(timezone.utc)


def _finding_priority(item: dict) -> int:
    """
    Determine which finding representation should win when
    CSPM Scanner and Security Hub return the same finding_id.

    Priority:
        2 = AWS Security Hub
        1 = CSPM Scanner
        0 = unknown/other
    """

    source = str(
        item.get("source", "")
    ).strip().lower()

    if source == "aws security hub":
        return 2

    if source == "cspm scanner":
        return 1

    return 0


def _deduplicate_findings(
    findings: list[dict],
) -> list[dict]:
    """
    Deduplicate findings by finding_id.

    The same finding can be returned by both:
        - CSPM Scanner
        - AWS Security Hub

    Since findings.finding_id is UNIQUE in PostgreSQL, only one
    representation of each finding_id may be persisted.

    When duplicates exist, prefer the AWS Security Hub
    representation because it contains Security Hub-specific
    workflow and record-state metadata.
    """

    unique_findings: dict[str, dict] = {}
    duplicate_count = 0

    for item in findings:

        finding_id = item.get(
            "finding_id"
        )

        if not finding_id:
            continue

        existing = unique_findings.get(
            finding_id
        )

        if existing is None:
            unique_findings[
                finding_id
            ] = item
            continue

        duplicate_count += 1

        current_priority = _finding_priority(
            item
        )

        existing_priority = _finding_priority(
            existing
        )

        if current_priority > existing_priority:
            unique_findings[
                finding_id
            ] = item

    if duplicate_count:

        logger.info(
            "Deduplicated findings | input=%s | unique=%s | duplicates=%s",
            len(findings),
            len(unique_findings),
            duplicate_count,
        )

    else:

        logger.info(
            "No duplicate findings detected | total=%s",
            len(unique_findings),
        )

    return list(
        unique_findings.values()
    )


def process_scan(
    scan_id: int,
):
    db = SessionLocal()

    try:

        scan_record = db.get(
            Scan,
            scan_id,
        )

        if not scan_record:

            logger.error(
                "Scan %s not found",
                scan_id,
            )

            return

        if scan_record.status != "QUEUED":

            logger.info(
                "Scan %s skipped because status is %s",
                scan_id,
                scan_record.status,
            )

            return

        scan_record.status = "RUNNING"
        scan_record.started_at = utcnow()

        db.commit()

        logger.info(
            "Starting scan %s | region=%s | scope=%s",
            scan_id,
            scan_record.region,
            scan_record.scope,
        )

        # =====================================================
        # 1. Run CSPM Scanner
        # =====================================================

        result = run_cspm_scan(
            region=scan_record.region,
        )

        summary = result.get(
            "summary",
            {},
        )

        scan_record.total_controls = summary.get(
            "total_controls",
            0,
        )

        scan_record.passed_controls = summary.get(
            "passed_controls",
            0,
        )

        scan_record.failed_controls = summary.get(
            "failed_controls",
            0,
        )

        scan_record.compliance_percent = summary.get(
            "control_compliance_percent",
            0,
        )

        findings = result.get(
            "findings",
            [],
        )

        logger.info(
            "CSPM Scanner completed | scan=%s | controls=%s | findings=%s",
            scan_id,
            scan_record.total_controls,
            len(findings),
        )

        # =====================================================
        # 2. Collect AWS Security Hub Findings
        #
        # READ-ONLY.
        #
        # This operation only calls Security Hub GetFindings.
        # No AWS resource is modified.
        # =====================================================

        securityhub_findings = []

        try:

            securityhub_service = SecurityHubService(
                region=scan_record.region,
            )

            raw_securityhub_findings = (
                securityhub_service.get_findings(
                    max_results=100,
                )
            )

            logger.info(
                "Security Hub returned %s active findings",
                len(raw_securityhub_findings),
            )

            for raw_finding in raw_securityhub_findings:

                normalized = (
                    securityhub_service.finding_to_cspm(
                        raw_finding
                    )
                )

                securityhub_findings.append(
                    normalized
                )

        except Exception as exc:

            # Security Hub integration must not prevent
            # the existing CSPM Scanner from completing.

            logger.exception(
                "Security Hub collection failed: %s",
                exc,
            )

        # =====================================================
        # 3. Merge CSPM + Security Hub Findings
        # =====================================================

        raw_total_findings = (
            len(findings)
            + len(securityhub_findings)
        )

        all_findings = list(
            findings
        )

        all_findings.extend(
            securityhub_findings
        )

        logger.info(
            "Scan %s | CSPM findings=%s | Security Hub findings=%s | raw total=%s",
            scan_id,
            len(findings),
            len(securityhub_findings),
            raw_total_findings,
        )

        # =====================================================
        # 4. Deduplicate Findings
        # =====================================================

        all_findings = _deduplicate_findings(
            all_findings
        )

        logger.info(
            "Scan %s | unique findings=%s",
            scan_id,
            len(all_findings),
        )

        # =====================================================
        # 5. Build unique resource collection
        #
        # A single AWS resource can appear in multiple findings.
        # Keep one representation per resource_id.
        # =====================================================

        unique_resources = {}

        for item in all_findings:

            resource_arn = item.get(
                "resource"
            )

            if not resource_arn:

                resource_arn = item.get(
                    "resource_id"
                )

            if not resource_arn:
                continue

            existing = unique_resources.get(
                resource_arn
            )

            if existing is None:

                unique_resources[
                    resource_arn
                ] = item

                continue

            # Keep the highest-risk representation.

            current_risk = (
                item.get(
                    "risk_score",
                    0,
                )
                or 0
            )

            existing_risk = (
                existing.get(
                    "risk_score",
                    0,
                )
                or 0
            )

            if current_risk > existing_risk:

                unique_resources[
                    resource_arn
                ] = item

        logger.info(
            "Scan %s | unique resources=%s",
            scan_id,
            len(unique_resources),
        )

        # =====================================================
        # 6. UPSERT FINDINGS
        #
        # If finding_id does not exist:
        #     INSERT
        #
        # If finding_id already exists:
        #     UPDATE
        #
        # This prevents:
        #
        # duplicate key value violates unique constraint
        #
        # "ix_findings_finding_id"
        # =====================================================

        for item in all_findings:

            finding_id = item.get(
                "finding_id"
            )

            if not finding_id:
                continue

            # -------------------------------------------------
            # Support both CSPM Scanner and Security Hub
            # normalized structures.
            # -------------------------------------------------

            control_id = item.get(
                "control",
                item.get(
                    "control_id",
                    "UNKNOWN",
                ),
            )

            resource_arn = item.get(
                "resource",
                item.get(
                    "resource_id"
                ),
            )

            resource_type = item.get(
                "resource_type",
            )

            source = item.get(
                "source",
                "CSPM Scanner",
            )

            # -------------------------------------------------
            # Find existing record
            # -------------------------------------------------

            finding = db.scalar(
                select(Finding).where(
                    Finding.finding_id
                    == finding_id
                )
            )

            # -------------------------------------------------
            # INSERT
            # -------------------------------------------------

            if finding is None:

                finding = Finding(
                    finding_id=finding_id,

                    control_id=control_id,

                    title=item.get(
                        "title",
                        "Unknown finding",
                    ),

                    description=item.get(
                        "description",
                        "",
                    ),

                    severity=item.get(
                        "severity",
                        "MEDIUM",
                    ),

                    status=item.get(
                        "status",
                        "UNKNOWN",
                    ),

                    resource_id=resource_arn,

                    resource_type=resource_type,

                    region=item.get(
                        "region",
                        scan_record.region,
                    ),

                    source=source,

                    risk_score=item.get(
                        "risk_score",
                        0,
                    ),

                    risk_level=item.get(
                        "risk_level",
                        "LOW",
                    ),

                    securityhub_workflow=item.get(
                        "securityhub_workflow"
                    ),

                    securityhub_record_state=item.get(
                        "securityhub_record_state"
                    ),

                    first_seen=utcnow(),

                    last_seen=utcnow(),
                )

                db.add(
                    finding
                )

            # -------------------------------------------------
            # UPDATE
            # -------------------------------------------------

            else:

                finding.control_id = item.get(
                    "control",
                    item.get(
                        "control_id",
                        finding.control_id,
                    ),
                )

                finding.title = item.get(
                    "title",
                    finding.title,
                )

                finding.description = item.get(
                    "description",
                    finding.description,
                )

                finding.severity = item.get(
                    "severity",
                    finding.severity,
                )

                finding.status = item.get(
                    "status",
                    finding.status,
                )

                finding.resource_id = item.get(
                    "resource",
                    item.get(
                        "resource_id",
                        finding.resource_id,
                    ),
                )

                finding.resource_type = item.get(
                    "resource_type",
                    finding.resource_type,
                )

                finding.region = item.get(
                    "region",
                    finding.region,
                )

                finding.source = item.get(
                    "source",
                    finding.source,
                )

                finding.risk_score = item.get(
                    "risk_score",
                    finding.risk_score,
                )

                finding.risk_level = item.get(
                    "risk_level",
                    finding.risk_level,
                )

                # Security Hub metadata is updated only
                # when supplied by a Security Hub finding.

                if (
                    "securityhub_workflow"
                    in item
                ):

                    finding.securityhub_workflow = (
                        item.get(
                            "securityhub_workflow"
                        )
                    )

                if (
                    "securityhub_record_state"
                    in item
                ):

                    finding.securityhub_record_state = (
                        item.get(
                            "securityhub_record_state"
                        )
                    )

                finding.last_seen = utcnow()

        # =====================================================
        # 7. Flush Findings Before Resources
        #
        # This gives PostgreSQL an early consistency check
        # before the transaction is completed.
        # =====================================================

        db.flush()

        # =====================================================
        # 8. UPSERT UNIQUE RESOURCES
        # =====================================================

        for resource_arn, item in unique_resources.items():

            resource_type = item.get(
                "resource_type",
                "Unknown",
            )

            resource = db.scalar(
                select(Resource).where(
                    Resource.resource_id
                    == resource_arn
                )
            )

            # -------------------------------------------------
            # INSERT RESOURCE
            # -------------------------------------------------

            if resource is None:

                resource = Resource(
                    resource_id=resource_arn,

                    resource_type=resource_type,

                    service=_detect_service(
                        resource_type
                    ),

                    region=item.get(
                        "region",
                        scan_record.region,
                    ),

                    status=item.get(
                        "status",
                        "UNKNOWN",
                    ),

                    risk_score=item.get(
                        "risk_score",
                        0,
                    ),

                    first_seen=utcnow(),

                    last_seen=utcnow(),
                )

                db.add(
                    resource
                )

            # -------------------------------------------------
            # UPDATE RESOURCE
            # -------------------------------------------------

            else:

                resource.resource_type = item.get(
                    "resource_type",
                    resource.resource_type,
                )

                resource.service = _detect_service(
                    item.get(
                        "resource_type",
                        resource.resource_type,
                    )
                )

                resource.region = item.get(
                    "region",
                    resource.region,
                )

                resource.status = item.get(
                    "status",
                    resource.status,
                )

                resource.risk_score = item.get(
                    "risk_score",
                    resource.risk_score,
                )

                resource.last_seen = utcnow()

        # =====================================================
        # 9. Complete Scan
        # =====================================================

        scan_record.status = "COMPLETED"

        scan_record.finished_at = utcnow()

        db.commit()

        logger.info(
            "Scan %s persisted successfully | findings=%s | resources=%s",
            scan_id,
            len(all_findings),
            len(unique_resources),
        )

    except Exception as exc:

        db.rollback()

        logger.exception(
            "Scan %s failed: %s",
            scan_id,
            exc,
        )

        scan_record = db.get(
            Scan,
            scan_id,
        )

        if scan_record:

            scan_record.status = "FAILED"

            scan_record.error_message = str(
                exc
            )

            scan_record.finished_at = utcnow()

            db.commit()

    finally:

        db.close()


def _detect_service(
    resource_type: str | None,
) -> str:

    if not resource_type:
        return "UNKNOWN"

    mapping = {
        "AwsEc2SecurityGroup": "EC2",
        "AwsEc2Vpc": "VPC",
        "AwsS3Bucket": "S3",
        "AwsAccount": "AWS",
        "AwsCloudTrailTrail": "CloudTrail",
    }

    return mapping.get(
        resource_type,
        "AWS",
    )


def worker_loop():

    logger.info(
        "SecNet CSPM Worker started"
    )

    while True:

        db = SessionLocal()

        try:

            queued_scan = db.scalar(
                select(Scan)
                .where(
                    Scan.status == "QUEUED"
                )
                .order_by(
                    Scan.created_at.asc()
                )
                .limit(1)
            )

            if queued_scan:

                scan_id = queued_scan.id

            else:

                scan_id = None

        finally:

            db.close()

        if scan_id:

            process_scan(
                scan_id
            )

        else:

            time.sleep(5)


if __name__ == "__main__":
    worker_loop()