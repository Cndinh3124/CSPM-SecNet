from typing import List, Literal

from pydantic import BaseModel, Field


class RemediationStep(BaseModel):
    action: str = Field(
        description="Concrete remediation action."
    )

    rationale: str = Field(
        description="Why the action addresses the finding."
    )


class FindingAnalysis(BaseModel):
    summary: str

    technical_cause: str

    security_impact: str

    affected_resource: str

    evidence: List[str]

    recommended_priority: Literal[
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]

    remediation_steps: List[RemediationStep]

    validation_steps: List[str]

    confidence: Literal[
        "HIGH",
        "MEDIUM",
        "LOW",
    ]

    safety_note: str
