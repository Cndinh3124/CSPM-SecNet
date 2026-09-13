from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json

from sqlalchemy.orm import Session

from app.models import (
    Finding,
    RemediationRun,
    RemediationAuditLog,
)

from cspm_engine.scope_validator import validate_resource


ROOT = Path(__file__).resolve().parents[2]

REGISTRY_PATH = (
    ROOT
    / "docs"
    / "cspm-policy-registry.json"
)


def utcnow():
    return datetime.now(timezone.utc)


# ============================================================
# AUDIT LOG
# ============================================================

def write_audit_log(
    db: Session,
    run_id: int,
    action: str,
    status: str,
    actor: str | None = None,
    message: str | None = None,
    metadata: dict | None = None,
):
    """
    Create an immutable audit event for a remediation run.

    This function only writes audit information to PostgreSQL.
    It does NOT modify any AWS resource.
    """

    audit = RemediationAuditLog(
        run_id=run_id,
        action=action,
        actor=actor,
        status=status,
        message=message,
        log_metadata=metadata,
        created_at=utcnow(),
    )

    db.add(audit)

    return audit


def get_audit_logs(
    db: Session,
    run_id: int,
):
    """
    Return audit logs for a remediation run
    in chronological order.
    """

    return (
        db.query(RemediationAuditLog)
        .filter(
            RemediationAuditLog.run_id == run_id
        )
        .order_by(
            RemediationAuditLog.created_at.asc(),
            RemediationAuditLog.id.asc(),
        )
        .all()
    )


# ============================================================
# POLICY REGISTRY
# ============================================================

def load_policy_registry() -> dict[str, Any]:
    """
    Load CSPM Policy Registry.

    Policy Registry is the single source of truth for:
    - remediation policy
    - scope
    - remediation type
    """

    if not REGISTRY_PATH.exists():
        raise FileNotFoundError(
            f"CSPM Policy Registry not found: {REGISTRY_PATH}"
        )

    return json.loads(
        REGISTRY_PATH.read_text(
            encoding="utf-8"
        )
    )


def get_control_policy(
    control_id: str,
) -> dict[str, Any]:
    """
    Return policy definition for a specific control.
    """

    registry = load_policy_registry()

    for policy in registry.get(
        "policies",
        [],
    ):
        if policy.get(
            "control_id"
        ) == control_id:
            return policy

    return {}


# ============================================================
# BUILD REMEDIATION CANDIDATES
# ============================================================

def build_candidates(
    db: Session,
) -> list[dict[str, Any]]:
    """
    Build remediation candidates from current FAILED findings.

    IMPORTANT:
    This function only plans remediation.

    It does NOT modify AWS resources.

    Scope validation is READ-ONLY and is performed
    through the CSPM Scope Validator.
    """

    findings = (
        db.query(Finding)
        .filter(
            Finding.status == "FAILED"
        )
        .order_by(
            Finding.control_id,
            Finding.id,
        )
        .all()
    )

    candidates = []

    for finding in findings:

        # ----------------------------------------------------
        # Load Policy
        # ----------------------------------------------------

        policy = get_control_policy(
            finding.control_id
        )

        # ----------------------------------------------------
        # Default Safety
        # ----------------------------------------------------

        action = "SKIP"

        reason = (
            "No remediation policy allows this resource"
        )

        # ----------------------------------------------------
        # Remediation Configuration
        # ----------------------------------------------------

        remediation = policy.get(
            "remediation",
            {},
        )

        remediation_type = remediation.get(
            "type"
        )

        # ----------------------------------------------------
        # Scope Configuration
        # ----------------------------------------------------

        scope = remediation.get(
            "scope",
            {},
        )

        scope_mode = scope.get(
            "mode",
            "explicit",
        )

        # ----------------------------------------------------
        # Scope Validation
        # ----------------------------------------------------

        if scope_mode == "tag":

            tag_key = scope.get(
                "key"
            )

            tag_value = str(
                scope.get(
                    "value",
                    "",
                )
            )

            # READ-ONLY validation.
            is_allowed, validation_reason = (
                validate_resource(
                    finding.resource_id,
                    finding.resource_type,
                )
            )

            if is_allowed:

                action = "ALLOW"

                reason = (
                    "Resource is within approved scope: "
                    f"{tag_key}={tag_value}"
                )

            else:

                action = "SKIP"

                reason = validation_reason

        elif scope_mode == "explicit":

            action = "SKIP"

            reason = (
                "Resource requires explicit "
                "remediation scope validation"
            )

        else:

            action = "SKIP"

            reason = (
                "Unsupported remediation "
                f"scope mode: {scope_mode}"
            )

        # ----------------------------------------------------
        # Candidate
        # ----------------------------------------------------

        candidates.append(
            {
                "control_id": finding.control_id,
                "resource_id": finding.resource_id,
                "resource_type": finding.resource_type,
                "remediation_type": remediation_type,
                "severity": finding.severity,
                "description": finding.description,
                "action": action,
                "scope": scope,
                "reason": reason,
            }
        )

    return candidates


# ============================================================
# CREATE REMEDIATION PLAN
# ============================================================

def create_remediation_run(
    db: Session,
    requested_by: str | None = None,
):
    """
    Create a remediation plan.

    This function ONLY creates a plan in PostgreSQL.

    It does NOT execute remediation.
    """

    candidates = build_candidates(
        db
    )

    allowed = sum(
        1
        for item in candidates
        if item["action"] == "ALLOW"
    )

    skipped = sum(
        1
        for item in candidates
        if item["action"] == "SKIP"
    )

    run = RemediationRun(
        status="PLANNED",
        requested_by=requested_by,
        total_candidates=len(
            candidates
        ),
        allowed_candidates=allowed,
        skipped_candidates=skipped,
        success_count=0,
        failed_count=0,
    )

    db.add(run)

    # Flush first so PostgreSQL generates run.id.
    db.flush()

    # --------------------------------------------------------
    # Audit: PLAN_CREATED
    # --------------------------------------------------------

    write_audit_log(
        db=db,
        run_id=run.id,
        action="PLAN_CREATED",
        actor=requested_by,
        status="SUCCESS",
        message=(
            "Remediation plan created successfully."
        ),
        metadata={
            "total_candidates": len(candidates),
            "allowed_candidates": allowed,
            "skipped_candidates": skipped,
        },
    )

    db.commit()

    db.refresh(run)

    return run, candidates


# ============================================================
# APPROVE REMEDIATION PLAN
# ============================================================

def approve_remediation_run(
    db: Session,
    run: RemediationRun,
    approved_by: str,
):
    """
    Approve an existing remediation plan.

    Approval does NOT execute remediation.
    """

    if run.status != "PLANNED":

        raise ValueError(
            "Remediation run cannot be approved "
            f"from status {run.status}"
        )

    run.status = "APPROVED"

    run.approved_by = approved_by

    run.approved_at = utcnow()

    # --------------------------------------------------------
    # Audit: PLAN_APPROVED
    # --------------------------------------------------------

    write_audit_log(
        db=db,
        run_id=run.id,
        action="PLAN_APPROVED",
        actor=approved_by,
        status="SUCCESS",
        message=(
            "Remediation plan approved. "
            "Execution requires the AWS executor safety gate."
        ),
        metadata={
            "total_candidates": run.total_candidates,
            "allowed_candidates": run.allowed_candidates,
            "skipped_candidates": run.skipped_candidates,
        },
    )

    db.commit()

    db.refresh(run)

    return run


# ============================================================
# EXECUTION STATE VALIDATION
# ============================================================

def validate_execution_state(
    run: RemediationRun,
):
    """
    Validate that a remediation run is approved
    before execution.
    """

    if run.status != "APPROVED":

        raise ValueError(
            "Remediation execution requires "
            "APPROVED status"
        )


# ============================================================
# EXECUTE REMEDIATION
# ============================================================

def execute_remediation_run(
    db: Session,
    run: RemediationRun,
):
    """
    Safe remediation execution gate.

    IMPORTANT:
    This implementation does NOT execute:
    - Cloud Custodian
    - AWS CLI
    - Lambda
    - boto3 mutation
    - any AWS modification

    It only:
    1. validates approval
    2. rebuilds candidates
    3. revalidates scope
    4. records execution state
    5. writes audit logs

    Execution behavior:

        APPROVED + 0 ALLOW
            -> NO_ACTION

        APPROVED + ALLOW
            -> BLOCKED_FOR_EXECUTOR
    """

    # --------------------------------------------------------
    # Execution Guard
    # --------------------------------------------------------

    validate_execution_state(
        run
    )

    # --------------------------------------------------------
    # Audit: EXECUTION_REQUESTED
    # --------------------------------------------------------

    write_audit_log(
        db=db,
        run_id=run.id,
        action="EXECUTION_REQUESTED",
        actor=run.approved_by,
        status="STARTED",
        message=(
            "Execution requested for approved remediation run."
        ),
        metadata={
            "previous_status": run.status,
        },
    )

    # --------------------------------------------------------
    # Rebuild candidates
    #
    # Scope is intentionally revalidated immediately
    # before any future remediation.
    # --------------------------------------------------------

    candidates = build_candidates(
        db
    )

    allowed_candidates = [
        item
        for item in candidates
        if item.get("action") == "ALLOW"
    ]

    skipped_candidates = [
        item
        for item in candidates
        if item.get("action") == "SKIP"
    ]

    # --------------------------------------------------------
    # Update execution statistics
    # --------------------------------------------------------

    run.total_candidates = len(
        candidates
    )

    run.allowed_candidates = len(
        allowed_candidates
    )

    run.skipped_candidates = len(
        skipped_candidates
    )

    run.success_count = 0

    run.failed_count = 0

    # --------------------------------------------------------
    # NO ACTION
    # --------------------------------------------------------

    if not allowed_candidates:

        run.status = "NO_ACTION"

        run.executed_at = utcnow()

        write_audit_log(
            db=db,
            run_id=run.id,
            action="EXECUTION_COMPLETED",
            actor=run.approved_by,
            status="NO_ACTION",
            message=(
                "Execution completed without AWS mutation "
                "because no candidate is within the approved scope."
            ),
            metadata={
                "total_candidates": len(candidates),
                "allowed_candidates": 0,
                "skipped_candidates": len(
                    skipped_candidates
                ),
            },
        )

        db.commit()

        db.refresh(run)

        return run, candidates

    # --------------------------------------------------------
    # SAFETY GATE
    # --------------------------------------------------------

    # ALLOW candidates exist.
    #
    # However, the real AWS executor is intentionally
    # disabled at this stage.
    #
    # Therefore NO AWS mutation occurs.

    run.status = "BLOCKED_FOR_EXECUTOR"

    run.executed_at = utcnow()

    write_audit_log(
        db=db,
        run_id=run.id,
        action="EXECUTION_BLOCKED",
        actor=run.approved_by,
        status="BLOCKED",
        message=(
            "Execution blocked because the AWS remediation "
            "executor is not enabled yet."
        ),
        metadata={
            "total_candidates": len(candidates),
            "allowed_candidates": len(
                allowed_candidates
            ),
            "skipped_candidates": len(
                skipped_candidates
            ),
            "aws_mutation": False,
        },
    )

    db.commit()

    db.refresh(run)

    return run, candidates


# ============================================================
# SERIALIZE RUN
# ============================================================

def serialize_run(
    run: RemediationRun,
):
    """
    Serialize remediation run for API responses.
    """

    return {
        "id": run.id,
        "status": run.status,
        "requested_by": run.requested_by,
        "approved_by": run.approved_by,
        "approved_at": run.approved_at,
        "total_candidates": run.total_candidates,
        "allowed_candidates": run.allowed_candidates,
        "skipped_candidates": run.skipped_candidates,
        "success_count": run.success_count,
        "failed_count": run.failed_count,
        "created_at": run.created_at,
        "executed_at": run.executed_at,
    }


# ============================================================
# SERIALIZE AUDIT LOG
# ============================================================

def serialize_audit_log(
    audit: RemediationAuditLog,
):
    """
    Serialize one audit log event for API responses.
    """

    return {
        "id": audit.id,
        "run_id": audit.run_id,
        "action": audit.action,
        "actor": audit.actor,
        "status": audit.status,
        "message": audit.message,
        "metadata": audit.log_metadata,
        "created_at": audit.created_at,
    }