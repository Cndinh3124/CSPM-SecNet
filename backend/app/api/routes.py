from datetime import datetime
import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.auth import get_current_user, require_role
from app.db import get_db

from app.models import (
    User,
    Scan,
    Finding,
    Resource,
    RemediationRun,
)

from app.schemas import (
    ScanCreate,
    ScanResponse,
    FindingResponse,
    RemediationApprovalRequest,
    RemediationPlanResponse,
    RemediationExecutionResponse,
)

from app.services.remediation_service import (
    approve_remediation_run,
    build_candidates,
    create_remediation_run,
    execute_remediation_run,
    serialize_run,
    get_audit_logs,
    serialize_audit_log,
)


router = APIRouter()


# ============================================================
# CSPM POLICY REGISTRY
# ============================================================

POLICY_REGISTRY_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "cspm-policy-registry.json"
)


def load_cspm_control_ids() -> list[str]:
    """Return controls explicitly governed by SecNet CSPM."""
    try:
        data = json.loads(
            POLICY_REGISTRY_PATH.read_text(
                encoding="utf-8"
            )
        )
    except Exception:
        return []

    return [
        str(policy["control_id"])
        for policy in data.get("policies", [])
        if policy.get("control_id")
    ]


CSPM_CONTROL_IDS = load_cspm_control_ids()


# ============================================================
# AUTHORIZATION HELPERS
# ============================================================

def get_user_email(
    current_user: User,
) -> str:
    """
    Return the authenticated user's email.

    The email is taken from the authenticated database user,
    never from a client-supplied request field.
    """

    return current_user.email


# ============================================================
# HEALTH
# ============================================================

@router.get("/health/db")
def health_db(
    db: Session = Depends(get_db),
):
    """
    Database health check.

    This endpoint remains public because it is used by
    infrastructure health checks.
    """

    try:
        db.execute(func.now())

        return {
            "status": "ok",
            "database": "postgresql",
        }

    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Database unavailable: {exc}",
        )


# ============================================================
# SCANS
# ============================================================

@router.post(
    "/scans",
    response_model=ScanResponse,
)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("ADMIN")
    ),
):
    """
    Create a new CSPM scan.

    ADMIN only.

    requested_by is taken from the authenticated user.
    """

    scan = Scan(
        status="QUEUED",
        provider=payload.provider or "AWS",
        region=payload.region or "ap-southeast-1",
        scope=payload.scope or "LAB",
        requested_by=get_user_email(
            current_user
        ),
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


@router.get("/scans")
def list_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("ADMIN", "VIEWER")
    ),
):
    """
    Return scan history.

    ADMIN + VIEWER.
    """

    scans = (
        db.query(Scan)
        .order_by(
            desc(Scan.created_at)
        )
        .all()
    )

    return {
        "value": scans,
        "Count": len(scans),
    }


@router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("ADMIN", "VIEWER")
    ),
):
    """
    Return one scan.

    ADMIN + VIEWER.
    """

    scan = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id
        )
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found",
        )

    return scan


# ============================================================
# SCAN DETAIL
# ============================================================

@router.get(
    "/scans/{scan_id}/detail"
)
def get_scan_detail(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("ADMIN", "VIEWER")
    ),
):
    """
    Return aggregated scan information
    for the CSPM Dashboard.

    Includes:
      - Scan metadata
      - CIS control summary
      - Findings
      - Resource summary
      - Resource inventory

    ADMIN + VIEWER.
    """

    # --------------------------------------------------------
    # 1. Get scan
    # --------------------------------------------------------

    scan = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id
        )
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found",
        )

    # --------------------------------------------------------
    # 2. Findings
    # --------------------------------------------------------

    finding_query = (
        db.query(Finding)
        .filter(
            Finding.region == scan.region
        )
    )

    if scan.started_at is not None:
        finding_query = finding_query.filter(
            Finding.last_seen >= scan.started_at
        )

    if scan.finished_at is not None:
        finding_query = finding_query.filter(
            Finding.last_seen <= scan.finished_at
        )

    findings = (
        finding_query
        .order_by(
            Finding.control_id,
            Finding.id,
        )
        .all()
    )

    # --------------------------------------------------------
    # 3. CIS control summary
    # --------------------------------------------------------

    control_map = {
        control_id: {
            "control_id": control_id,
            "status": "UNKNOWN",
            "passed": [],
            "failed": [],
            "unknown": [],
        }
        for control_id in CSPM_CONTROL_IDS
    }

    for finding in findings:
        control_id = str(
            finding.control_id or "UNKNOWN"
        )

        if control_id not in control_map:
            continue

        item = {
            "finding_id": finding.finding_id,
            "resource_id": finding.resource_id,
            "resource_type": finding.resource_type,
            "severity": finding.severity,
            "status": finding.status,
            "risk_score": finding.risk_score,
            "risk_level": finding.risk_level,
            "reason": finding.description,
            "region": finding.region,
            "source": finding.source,
        }

        status = str(
            finding.status or ""
        ).upper()

        if status == "FAILED":
            control_map[control_id]["status"] = "FAILED"
            control_map[control_id]["failed"].append(item)

        elif status == "UNKNOWN":
            if (
                control_map[control_id]["status"]
                != "FAILED"
            ):
                control_map[control_id]["status"] = "UNKNOWN"

            control_map[control_id]["unknown"].append(item)

        else:
            if (
                control_map[control_id]["status"]
                != "FAILED"
            ):
                control_map[control_id]["status"] = "PASSED"

            control_map[control_id]["passed"].append(item)

    # --------------------------------------------------------
    # 4. Build control list
    # --------------------------------------------------------

    controls = []

    for control_id in CSPM_CONTROL_IDS:
        control = control_map[control_id]

        passed_count = len(
            control["passed"]
        )

        failed_count = len(
            control["failed"]
        )

        unknown_count = len(
            control["unknown"]
        )

        total = (
            passed_count
            + failed_count
            + unknown_count
        )

        compliance = (
            (passed_count / total) * 100
            if total > 0
            else 0
        )

        controls.append(
            {
                "control_id": control_id,
                "status": control["status"],
                "passed": control["passed"],
                "failed": control["failed"],
                "unknown": control["unknown"],
                "passed_count": passed_count,
                "failed_count": failed_count,
                "unknown_count": unknown_count,
                "total_findings": total,
                "compliance_percent": round(
                    compliance,
                    2,
                ),
            }
        )

    # --------------------------------------------------------
    # 5. Resource summary
    # --------------------------------------------------------

    resources = (
        db.query(Resource)
        .filter(
            Resource.region == scan.region
        )
        .order_by(
            Resource.resource_type,
            Resource.resource_id,
        )
        .all()
    )

    resource_total = len(
        resources
    )

    resource_passed = sum(
        1
        for resource in resources
        if str(
            resource.status or ""
        ).upper() == "PASSED"
    )

    resource_failed = sum(
        1
        for resource in resources
        if str(
            resource.status or ""
        ).upper() == "FAILED"
    )

    resource_resolved = sum(
        1
        for resource in resources
        if str(
            resource.status or ""
        ).upper() == "RESOLVED"
    )

    resource_unknown = sum(
        1
        for resource in resources
        if str(
            resource.status or ""
        ).upper() == "UNKNOWN"
    )

    # --------------------------------------------------------
    # 6. Resource service helper
    # --------------------------------------------------------

    def resource_service(
        resource_type: str | None,
    ) -> str:

        rtype = str(
            resource_type or ""
        ).lower()

        if "s3" in rtype:
            return "S3"

        if "cloudtrail" in rtype:
            return "CloudTrail"

        if "ec2" in rtype or "vpc" in rtype:
            return "EC2"

        if "rds" in rtype:
            return "RDS"

        if "iam" in rtype:
            return "IAM"

        if "kms" in rtype:
            return "KMS"

        if "account" in rtype:
            return "AWS"

        if rtype.startswith("aws"):
            parts = rtype[3:].split(
                "::",
                1,
            )

            return (
                parts[0]
                if parts and parts[0]
                else "AWS"
            )

        return "AWS"

    # --------------------------------------------------------
    # 7. Build resource inventory
    # --------------------------------------------------------

    resource_inventory = []

    for resource in resources:

        status = str(
            resource.status or "UNKNOWN"
        ).upper()

        try:
            risk_score = float(
                resource.risk_score or 0
            )
        except (
            TypeError,
            ValueError,
        ):
            risk_score = 0

        resource_inventory.append(
            {
                "resource_id": resource.resource_id,
                "resource_type": resource.resource_type,
                "service": (
                    resource.service
                    or resource_service(
                        resource.resource_type
                    )
                ),
                "region": resource.region,
                "status": status,
                "risk_score": risk_score,
                "first_seen": resource.first_seen,
                "last_seen": resource.last_seen,
            }
        )

    # --------------------------------------------------------
    # 8. Sort resource inventory
    # --------------------------------------------------------

    resource_inventory.sort(
        key=lambda item: (
            0
            if item["status"] == "FAILED"
            else 1
            if item["status"] == "UNKNOWN"
            else 2
            if item["status"] == "PASSED"
            else 3
            if item["status"] == "RESOLVED"
            else 4,
            -float(
                item["risk_score"] or 0
            ),
            item["resource_id"] or "",
        )
    )

    # --------------------------------------------------------
    # 9. Response
    # --------------------------------------------------------

    return {
        "scan": {
            "id": scan.id,
            "status": scan.status,
            "provider": scan.provider,
            "region": scan.region,
            "scope": scan.scope,
            "requested_by": scan.requested_by,
            "total_controls": scan.total_controls,
            "passed_controls": scan.passed_controls,
            "failed_controls": scan.failed_controls,
            "compliance_percent": scan.compliance_percent,
            "created_at": scan.created_at,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
            "error_message": scan.error_message,
        },

        "controls": controls,

        "resource_summary": {
            "active": resource_total,
            "total": resource_total,
            "passed": resource_passed,
            "failed": resource_failed,
            "resolved": resource_resolved,
            "unknown": resource_unknown,
        },

        "resources": resource_inventory,

        "findings": [
            {
                "id": finding.id,
                "finding_id": finding.finding_id,
                "control_id": finding.control_id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "status": finding.status,
                "resource_id": finding.resource_id,
                "resource_type": finding.resource_type,
                "region": finding.region,
                "source": finding.source,
                "risk_score": finding.risk_score,
                "risk_level": finding.risk_level,
                "first_seen": finding.first_seen,
                "last_seen": finding.last_seen,
            }
            for finding in findings
        ],

        "summary": {
            "total_controls": scan.total_controls,
            "passed_controls": scan.passed_controls,
            "failed_controls": scan.failed_controls,
            "compliance_percent": scan.compliance_percent,
            "total_findings": len(findings),
            "active_resources": resource_total,
            "passed_resources": resource_passed,
            "failed_resources": resource_failed,
            "resolved_resources": resource_resolved,
            "unknown_resources": resource_unknown,
        },
    }


# ============================================================
# FINDINGS
# ============================================================

@router.get("/findings")
def list_findings(
    status: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    control_id: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("ADMIN", "VIEWER")
    ),
):
    """
    Return findings with optional server-side filters.

    ADMIN + VIEWER.

    READ-ONLY.
    """

    query = db.query(Finding)

    if status:
        query = query.filter(
            func.upper(Finding.status)
            == status.strip().upper()
        )

    if severity:
        query = query.filter(
            func.upper(Finding.severity)
            == severity.strip().upper()
        )

    if source:
        query = query.filter(
            Finding.source == source.strip()
        )

    if control_id:
        query = query.filter(
            func.upper(Finding.control_id)
            == control_id.strip().upper()
        )

    findings = (
        query
        .order_by(
            desc(Finding.last_seen)
        )
        .all()
    )

    return {
        "value": findings,
        "Count": len(findings),
    }


# ============================================================
# OVERVIEW
# ============================================================

@router.get("/overview")
def overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("ADMIN", "VIEWER")
    ),
):
    """
    Dashboard overview.

    ADMIN + VIEWER.
    """

    total_findings = (
        db.query(
            func.count(Finding.id)
        )
        .scalar()
        or 0
    )

    critical_findings = (
        db.query(
            func.count(Finding.id)
        )
        .filter(
            func.upper(
                Finding.risk_level
            )
            == "CRITICAL"
        )
        .scalar()
        or 0
    )

    high_findings = (
        db.query(
            func.count(Finding.id)
        )
        .filter(
            func.upper(
                Finding.risk_level
            )
            == "HIGH"
        )
        .scalar()
        or 0
    )

    active_resources = (
        db.query(
            func.count(Resource.id)
        )
        .scalar()
        or 0
    )

    latest_scan = (
        db.query(Scan)
        .order_by(
            desc(Scan.created_at)
        )
        .first()
    )

    return {
        "findings": {
            "total": total_findings,
            "critical": critical_findings,
            "high": high_findings,
        },

        "resources": {
            "active": active_resources,
        },

        "latest_scan": latest_scan,
    }


# ============================================================
# REMEDIATION - CANDIDATES
# ============================================================

@router.get(
    "/remediation/candidates"
)
def get_remediation_candidates(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("ADMIN", "VIEWER")
    ),
):
    """
    Return current remediation candidates.

    ADMIN + VIEWER.

    READ-ONLY.
    """

    candidates = build_candidates(
        db
    )

    allowed = sum(
        1
        for item in candidates
        if item.get("action") == "ALLOW"
    )

    skipped = sum(
        1
        for item in candidates
        if item.get("action") == "SKIP"
    )

    return {
        "value": candidates,
        "count": len(candidates),
        "summary": {
            "total_candidates": len(candidates),
            "allowed": allowed,
            "skipped": skipped,
        },
    }


# ============================================================
# CREATE REMEDIATION PLAN
# ============================================================

@router.post(
    "/remediation/plan",
    response_model=RemediationPlanResponse,
)
def create_remediation_plan(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("ADMIN")
    ),
):
    """
    Create a remediation plan.

    ADMIN only.

    requested_by is taken from the authenticated user.

    IMPORTANT:
    This endpoint does NOT execute remediation.

    State:
        PLANNED
    """

    run, _candidates = create_remediation_run(
        db=db,
        requested_by=get_user_email(
            current_user
        ),
    )

    return serialize_run(run)


# ============================================================
# REMEDIATION HISTORY
# ============================================================

@router.get(
    "/remediation/runs"
)
def list_remediation_runs(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("ADMIN", "VIEWER")
    ),
):
    """
    Return remediation run history.

    ADMIN + VIEWER.
    """

    runs = (
        db.query(RemediationRun)
        .order_by(
            desc(
                RemediationRun.created_at
            )
        )
        .all()
    )

    return {
        "value": [
            serialize_run(run)
            for run in runs
        ],
        "count": len(runs),
    }


# ============================================================
# REMEDIATION DETAIL
# ============================================================

@router.get(
    "/remediation/runs/{run_id}"
)
def get_remediation_run(
    run_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("ADMIN", "VIEWER")
    ),
):
    """
    Return one remediation run.

    ADMIN + VIEWER.
    """

    run = (
        db.query(RemediationRun)
        .filter(
            RemediationRun.id == run_id
        )
        .first()
    )

    if not run:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Remediation run "
                f"{run_id} not found"
            ),
        )

    return serialize_run(run)


# ============================================================
# REMEDIATION AUDIT LOG
# ============================================================

@router.get(
    "/remediation/runs/{run_id}/audit"
)
def get_remediation_audit(
    run_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("ADMIN", "VIEWER")
    ),
):
    """
    Return audit history for a remediation run.

    ADMIN + VIEWER.

    READ-ONLY.
    """

    run = (
        db.query(RemediationRun)
        .filter(
            RemediationRun.id == run_id
        )
        .first()
    )

    if not run:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Remediation run "
                f"{run_id} not found"
            ),
        )

    audit_logs = get_audit_logs(
        db=db,
        run_id=run_id,
    )

    return {
        "run_id": run_id,
        "count": len(audit_logs),
        "value": [
            serialize_audit_log(
                audit
            )
            for audit in audit_logs
        ],
    }


# ============================================================
# APPROVE REMEDIATION
# ============================================================

@router.post(
    "/remediation/runs/{run_id}/approve",
    response_model=RemediationPlanResponse,
)
def approve_remediation(
    run_id: int,
    payload: RemediationApprovalRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("ADMIN")
    ),
):
    """
    Approve a remediation plan.

    ADMIN only.

    The authenticated user's email is used as
    approved_by. The client supplied approved_by
    field is intentionally ignored.

    IMPORTANT:
    Approval does NOT execute AWS remediation.

    PLANNED -> APPROVED
    """

    run = (
        db.query(RemediationRun)
        .filter(
            RemediationRun.id == run_id
        )
        .first()
    )

    if not run:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Remediation run "
                f"{run_id} not found"
            ),
        )

    try:
        run = approve_remediation_run(
            db=db,
            run=run,
            approved_by=get_user_email(
                current_user
            ),
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        )

    return serialize_run(run)


# ============================================================
# EXECUTE REMEDIATION
# ============================================================

@router.post(
    "/remediation/runs/{run_id}/execute",
    response_model=RemediationExecutionResponse,
)
def execute_remediation(
    run_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("ADMIN")
    ),
):
    """
    Execute an approved remediation run.

    ADMIN only.

    SAFETY:
    - Execution requires APPROVED status.
    - Only ALLOW candidates can be considered.
    - SKIP candidates are never executed.
    - Current executor is a SAFE NO-OP.
    - No AWS resource is modified by this endpoint yet.
    """

    run = (
        db.query(RemediationRun)
        .filter(
            RemediationRun.id == run_id
        )
        .first()
    )

    if not run:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Remediation run "
                f"{run_id} not found"
            ),
        )

    try:
        run, _candidates = execute_remediation_run(
            db=db,
            run=run,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        )

    return {
        "id": run.id,
        "status": run.status,
        "total_candidates": run.total_candidates,
        "allowed_candidates": run.allowed_candidates,
        "skipped_candidates": run.skipped_candidates,
        "success_count": run.success_count,
        "failed_count": run.failed_count,
        "executed_at": run.executed_at,
    }