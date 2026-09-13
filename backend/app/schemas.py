from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


# ============================================================
# SCAN
# ============================================================

class ScanCreate(BaseModel):
    provider: str = "AWS"
    region: str = "ap-southeast-1"
    scope: str = "LAB"
    requested_by: str | None = None


class ScanResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: int
    status: str
    provider: str
    region: str
    scope: str
    requested_by: str | None

    total_controls: int
    passed_controls: int
    failed_controls: int
    compliance_percent: float

    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None


# ============================================================
# FINDING
# ============================================================

class FindingResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: int

    finding_id: str
    control_id: str

    title: str
    description: str

    severity: str
    status: str

    resource_id: str | None
    resource_type: str | None

    region: str
    source: str

    risk_score: float
    risk_level: str

    first_seen: datetime
    last_seen: datetime


# ============================================================
# REMEDIATION CANDIDATE
# ============================================================

class RemediationCandidate(BaseModel):
    control_id: str

    resource_id: str | None = None

    resource_type: str | None = None

    remediation_type: str | None = None

    severity: str = "UNKNOWN"

    description: str = ""

    action: str = "SKIP"

    scope: dict = Field(
        default_factory=dict
    )

    reason: str = ""


# ============================================================
# REMEDIATION PLAN
# ============================================================

class RemediationPlanResponse(BaseModel):
    id: int

    status: str

    requested_by: str | None

    total_candidates: int
    allowed_candidates: int
    skipped_candidates: int

    success_count: int
    failed_count: int

    created_at: datetime

    approved_by: str | None
    approved_at: datetime | None

    executed_at: datetime | None


# ============================================================
# REMEDIATION APPROVAL
# ============================================================

class RemediationApprovalRequest(BaseModel):
    approved_by: str


# ============================================================
# REMEDIATION EXECUTION
# ============================================================

class RemediationExecutionResponse(BaseModel):
    id: int

    status: str

    total_candidates: int
    allowed_candidates: int
    skipped_candidates: int

    success_count: int
    failed_count: int

    executed_at: datetime | None


# ============================================================
# REMEDIATION AUDIT LOG
# ============================================================

class RemediationAuditLogResponse(BaseModel):
    """
    Response schema for remediation audit logs.

    Audit logs provide a traceable history of all
    remediation lifecycle events.
    """

    model_config = ConfigDict(
        from_attributes=True
    )

    id: int

    run_id: int

    action: str

    actor: str | None

    status: str

    message: str | None

    metadata: dict | None

    created_at: datetime


# ============================================================
# REMEDIATION AUDIT LOG LIST
# ============================================================

class RemediationAuditLogListResponse(BaseModel):
    """
    Response schema for the remediation audit endpoint.
    """

    run_id: int

    count: int

    value: list[RemediationAuditLogResponse]
# ============================================================
# AUTHENTICATION
# ============================================================

class LoginRequest(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    role: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse