"""Tests for graph construction and routing logic."""

from src.graph import (
    build_triage_graph,
    route_after_investigation,
    route_after_remediation,
    TriageState,
)
from src.models import (
    SecurityAlert,
    Classification,
    Investigation,
    Remediation,
    Severity,
    AlertCategory,
)


def _make_alert() -> SecurityAlert:
    return SecurityAlert(
        alert_id="TEST-001",
        source="GuardDuty",
        title="Test",
        description="Test alert",
    )


def _make_classification(severity: Severity) -> Classification:
    return Classification(
        severity=severity,
        category=AlertCategory.UNAUTHORIZED_ACCESS,
        confidence=0.9,
        reasoning="test",
    )


def test_graph_builds_without_error():
    graph = build_triage_graph()
    assert graph is not None


def test_graph_compiles():
    graph = build_triage_graph()
    app = graph.compile()
    assert app is not None


def test_route_investigation_escalates():
    state: TriageState = {
        "alert": _make_alert(),
        "classification": _make_classification(Severity.HIGH),
        "investigation": Investigation(
            findings=["breach confirmed"],
            affected_scope="production",
            requires_escalation=True,
            escalation_reason="Active breach",
        ),
        "remediation": None,
        "human_decision": "",
        "status": "pending",
    }
    assert route_after_investigation(state) == "human_review"


def test_route_investigation_continues():
    state: TriageState = {
        "alert": _make_alert(),
        "classification": _make_classification(Severity.MEDIUM),
        "investigation": Investigation(
            findings=["minor issue"],
            affected_scope="single instance",
            requires_escalation=False,
            escalation_reason="",
        ),
        "remediation": None,
        "human_decision": "",
        "status": "pending",
    }
    assert route_after_investigation(state) == "remediate"


def test_route_remediation_escalates_critical():
    state: TriageState = {
        "alert": _make_alert(),
        "classification": _make_classification(Severity.CRITICAL),
        "investigation": Investigation(
            findings=["test"], affected_scope="all", requires_escalation=False
        ),
        "remediation": Remediation(
            immediate_actions=["block"],
            long_term_fixes=["fix"],
            requires_human_approval=False,
        ),
        "human_decision": "",
        "status": "pending",
    }
    assert route_after_remediation(state) == "human_review"


def test_route_remediation_escalates_approval_needed():
    state: TriageState = {
        "alert": _make_alert(),
        "classification": _make_classification(Severity.MEDIUM),
        "investigation": Investigation(
            findings=["test"], affected_scope="limited", requires_escalation=False
        ),
        "remediation": Remediation(
            immediate_actions=["revoke creds"],
            long_term_fixes=["rotate keys"],
            requires_human_approval=True,
            approval_reason="Will disrupt pipeline",
        ),
        "human_decision": "",
        "status": "pending",
    }
    assert route_after_remediation(state) == "human_review"


def test_route_remediation_auto_resolves_low():
    state: TriageState = {
        "alert": _make_alert(),
        "classification": _make_classification(Severity.LOW),
        "investigation": Investigation(
            findings=["false positive"], affected_scope="none", requires_escalation=False
        ),
        "remediation": Remediation(
            immediate_actions=["log"],
            long_term_fixes=["tune threshold"],
            requires_human_approval=False,
        ),
        "human_decision": "",
        "status": "pending",
    }
    assert route_after_remediation(state) == "auto_resolve"
