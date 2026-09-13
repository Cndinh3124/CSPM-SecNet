from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow():
    return datetime.now(timezone.utc)


# ============================================================
# ROLE
# ============================================================

class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    name: Mapped[str] = mapped_column(
        String(32),
        unique=True,
        nullable=False,
        index=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )

    users: Mapped[list["User"]] = relationship(
        "User",
        back_populates="role",
    )


# ============================================================
# USER
# ============================================================

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    role_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("roles.id"),
        nullable=False,
        index=True,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )

    role: Mapped["Role"] = relationship(
        "Role",
        back_populates="users",
    )


# ============================================================
# SCAN
# ============================================================

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        default="QUEUED",
        index=True,
    )

    provider: Mapped[str] = mapped_column(
        String(32),
        default="AWS",
    )

    region: Mapped[str] = mapped_column(
        String(64),
        default="ap-southeast-1",
    )

    scope: Mapped[str] = mapped_column(
        String(128),
        default="LAB",
    )

    requested_by: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    total_controls: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    passed_controls: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    failed_controls: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    compliance_percent: Mapped[float] = mapped_column(
        Float,
        default=0,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )


# ============================================================
# FINDING
# ============================================================

class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    finding_id: Mapped[str] = mapped_column(
        String(512),
        unique=True,
        index=True,
    )

    control_id: Mapped[str] = mapped_column(
        String(64),
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(512),
    )

    description: Mapped[str] = mapped_column(
        Text,
        default="",
    )

    severity: Mapped[str] = mapped_column(
        String(32),
        default="MEDIUM",
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        default="FAILED",
        index=True,
    )

    resource_id: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
        index=True,
    )

    resource_type: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    region: Mapped[str] = mapped_column(
        String(64),
        default="ap-southeast-1",
    )

    source: Mapped[str] = mapped_column(
        String(128),
        default="AWS Security Hub",
    )

    risk_score: Mapped[float] = mapped_column(
        Float,
        default=0,
    )

    risk_level: Mapped[str] = mapped_column(
        String(32),
        default="MEDIUM",
    )

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    securityhub_workflow: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )

    securityhub_record_state: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )


# ============================================================
# RESOURCE
# ============================================================

class Resource(Base):
    __tablename__ = "resources"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    resource_id: Mapped[str] = mapped_column(
        String(512),
        unique=True,
        index=True,
    )

    resource_type: Mapped[str] = mapped_column(
        String(128),
    )

    service: Mapped[str] = mapped_column(
        String(64),
    )

    region: Mapped[str] = mapped_column(
        String(64),
        default="ap-southeast-1",
    )

    status: Mapped[str] = mapped_column(
        String(32),
        default="UNKNOWN",
    )

    risk_score: Mapped[float] = mapped_column(
        Float,
        default=0,
    )

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )


# ============================================================
# REMEDIATION RUN
# ============================================================

class RemediationRun(Base):
    __tablename__ = "remediation_runs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        default="PLANNED",
        index=True,
    )

    requested_by: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    approved_by: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    total_candidates: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    allowed_candidates: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    skipped_candidates: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    success_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    failed_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


# ============================================================
# REMEDIATION AUDIT LOG
# ============================================================

class RemediationAuditLog(Base):
    __tablename__ = "remediation_audit_logs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    run_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True,
    )

    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    actor: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Python attribute is log_metadata because "metadata"
    # is reserved by SQLAlchemy Declarative API.
    # PostgreSQL column remains "metadata".
    log_metadata: Mapped[dict | None] = mapped_column(
        "metadata",
        JSONB,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
    )