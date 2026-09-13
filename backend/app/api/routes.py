from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.db import get_db

from app.models import (
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
# HEALTH
# ============================================================

@router.get("/health/db")
def health_db(
    db: Session = Depends(get_db),
):
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
):
    scan = Scan(
        status="QUEUED",
        provider=payload.provider or "AWS",
        region=payload.region or "ap-southeast-1",
        scope=payload.scope or "LAB",
        requested_by=payload.requested_by,
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


@router.get("/scans")
def list_scans(
    db: Session = Depends(get_db),
):
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
):
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
):
    """
    Return aggregated scan information
    for the CSPM Dashboard.

    Includes:
      - Scan metadata
      - CIS control summary
      - Findings
      - Resource summary
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

    control_map = {}

    for finding in findings:

        control_id = finding.control_id

        if control_id not in control_map:

            control_map[control_id] = {
                "control_id": control_id,
                "status": "PASSED",
                "passed": [],
                "failed": [],
                "unknown": [],
            }

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

            control_map[control_id]["failed"].append(
                item
            )

        elif status == "UNKNOWN":

            if (
                control_map[control_id]["status"]
                != "FAILED"
            ):
                control_map[control_id]["status"] = "UNKNOWN"

            control_map[control_id]["unknown"].append(
                item
            )

        else:

            control_map[control_id]["passed"].append(
                item
            )

    # --------------------------------------------------------
    # 4. Build control list
    # --------------------------------------------------------

    controls = []

    for control_id in sorted(
        control_map.keys()
    ):

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

        if total > 0:

            compliance = (
                passed_count / total
            ) * 100

        else:

            compliance = 0

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

    resource_query = (
        db.query(Resource)
        .filter(
            Resource.region == scan.region
        )
    )

    if scan.started_at is not None:

        resource_query = resource_query.filter(
            Resource.last_seen >= scan.started_at
        )

    if scan.finished_at is not None:

        resource_query = resource_query.filter(
            Resource.last_seen <= scan.finished_at
        )

    resources = resource_query.all()

    resource_total = len(
        resources
    )

    resource_passed = sum(
        1
        for resource in resources
        if str(
            resource.status
        ).upper() == "PASSED"
    )

    resource_failed = sum(
        1
        for resource in resources
        if str(
            resource.status
        ).upper() == "FAILED"
    )

    resource_unknown = sum(
        1
        for resource in resources
        if str(
            resource.status
        ).upper() == "UNKNOWN"
    )

    # --------------------------------------------------------
    # 6. Response
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
            "passed": resource_passed,
            "failed": resource_failed,
            "unknown": resource_unknown,
        },

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
            "unknown_resources": resource_unknown,
        },
    }


# ============================================================
# FINDINGS
# ============================================================

@router.get("/findings")
def list_findings(
    db: Session = Depends(get_db),
):
    findings = (
        db.query(Finding)
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
):
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
):
    """
    Return current remediation candidates.

    READ-ONLY.

    This endpoint does not modify AWS resources.
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
    requested_by: str | None = None,
    db: Session = Depends(get_db),
):
    """
    Create a remediation plan.

    IMPORTANT:
    This endpoint does NOT execute remediation.

    State:

        PLANNED
    """

    run, _candidates = create_remediation_run(
        db=db,
        requested_by=requested_by,
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
):
    """
    Return remediation run history.
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
):
    """
    Return one remediation run.
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
):
    """
    Return audit history for a remediation run.

    Audit events include:
      - PLAN_CREATED
      - PLAN_APPROVED
      - EXECUTION_REQUESTED
      - EXECUTION_BLOCKED
      - EXECUTION_COMPLETED

    READ-ONLY:
    This endpoint does not modify any AWS resource.
    """

    # --------------------------------------------------------
    # 1. Validate remediation run
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # 2. Get audit logs
    # --------------------------------------------------------

    audit_logs = get_audit_logs(
        db=db,
        run_id=run_id,
    )

    # --------------------------------------------------------
    # 3. Response
    # --------------------------------------------------------

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
):
    """
    Approve a remediation plan.

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
            approved_by=payload.approved_by,
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
):
    """
    Execute an approved remediation run.

    SAFETY:
    - Execution requires APPROVED status.
    - Only ALLOW candidates can be considered.
    - SKIP candidates are never executed.
    - Current executor is a SAFE NO-OP.
    - No AWS resource is modified by this endpoint yet.
    """

    # --------------------------------------------------------
    # 1. Find remediation run
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # 2. Execute through service
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # 3. Response
    # --------------------------------------------------------

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