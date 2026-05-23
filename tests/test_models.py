"""Tests for data models."""

from src.models import (
    SecurityAlert,
    Classification,
    Investigation,
    Remediation,
    TriageResult,
    Severity,
    AlertCategory,
)


def test_security_alert_creation():
    alert = SecurityAlert(
        alert_id="TEST-001",
        source="GuardDuty",
        title="Test alert",
        description="Test description",
        raw_indicators=["1.2.3.4", "suspicious"],
        affected_resource="arn:aws:s3:::test-bucket",
        timestamp="2026-05-23T00:00:00Z",
    )
    assert alert.alert_id == "TEST-001"
    assert alert.source == "GuardDuty"
    assert len(alert.raw_indicators) == 2


def test_classification_model():
    c = Classification(
        severity=Severity.HIGH,
        category=AlertCategory.UNAUTHORIZED_ACCESS,
        confidence=0.92,
        reasoning="Tor exit node accessing PII bucket",
    )
    assert c.severity == Severity.HIGH
    assert c.confidence == 0.92


def test_investigation_model():
    inv = Investigation(
        findings=["Lateral movement detected", "3 buckets accessed"],
        affected_scope="Production AWS account",
        attack_vector="Compromised service account credentials",
        ioc_matches=["185.220.101.34"],
        requires_escalation=True,
        escalation_reason="Active data exfiltration from PII bucket",
    )
    assert inv.requires_escalation is True
    assert len(inv.findings) == 2


def test_remediation_model():
    rem = Remediation(
        immediate_actions=["Revoke credentials", "Block IP"],
        long_term_fixes=["Enable MFA", "Implement least-privilege"],
        playbook_reference="unauthorized_access",
        estimated_impact="Service account used by 3 pipelines",
        requires_human_approval=True,
        approval_reason="Revoking credentials will disrupt data pipelines",
    )
    assert rem.requires_human_approval is True
    assert len(rem.immediate_actions) == 2


def test_triage_result_composite():
    alert = SecurityAlert(
        alert_id="TEST-002",
        source="CloudTrail",
        title="Root login",
        description="Root account login detected",
    )
    classification = Classification(
        severity=Severity.CRITICAL,
        category=AlertCategory.UNAUTHORIZED_ACCESS,
        confidence=0.99,
        reasoning="Root login should never happen",
    )
    investigation = Investigation(
        findings=["First root login in 6 months"],
        affected_scope="Entire AWS account",
        requires_escalation=True,
        escalation_reason="Root access = full account compromise risk",
    )
    remediation = Remediation(
        immediate_actions=["Disable root access keys"],
        long_term_fixes=["Enable hardware MFA on root"],
    )
    result = TriageResult(
        alert=alert,
        classification=classification,
        investigation=investigation,
        remediation=remediation,
        status="awaiting_human_review",
    )
    assert result.status == "awaiting_human_review"
    assert result.classification.severity == Severity.CRITICAL
