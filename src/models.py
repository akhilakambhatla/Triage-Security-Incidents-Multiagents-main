"""Data models for security alert triage."""

from __future__ import annotations

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertCategory(str, Enum):
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE = "malware"
    POLICY_VIOLATION = "policy_violation"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    CONFIGURATION_DRIFT = "configuration_drift"


class SecurityAlert(BaseModel):
    """Raw security alert from SIEM/CSPM."""

    alert_id: str
    source: str = Field(description="e.g., CloudTrail, GuardDuty, WAF")
    title: str
    description: str
    raw_indicators: list[str] = Field(default_factory=list)
    affected_resource: str = ""
    timestamp: str = ""


class Classification(BaseModel):
    """Output of the classifier agent."""

    severity: Severity
    category: AlertCategory
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str


class Investigation(BaseModel):
    """Output of the investigator agent."""

    findings: list[str]
    affected_scope: str
    attack_vector: str = ""
    ioc_matches: list[str] = Field(default_factory=list)
    requires_escalation: bool = False
    escalation_reason: str = ""


class Remediation(BaseModel):
    """Output of the remediation agent."""

    immediate_actions: list[str]
    long_term_fixes: list[str]
    playbook_reference: str = ""
    estimated_impact: str = ""
    requires_human_approval: bool = False
    approval_reason: str = ""


class TriageResult(BaseModel):
    """Final triage output combining all agent outputs."""

    alert: SecurityAlert
    classification: Classification
    investigation: Investigation
    remediation: Remediation
    human_decision: str = ""
    status: str = "pending"
