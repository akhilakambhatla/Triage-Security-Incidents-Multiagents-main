"""Tests for graph construction and routing logic."""

from src.graph import (
    build_triage_graph,
    route_after_investigation,
    route_after_investigation_review,
    route_after_remediation,
    route_after_remediation_review,
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


# --- New node / routing coverage ---


def test_graph_contains_all_expected_nodes():
    graph = build_triage_graph()
    compiled = graph.compile()
    node_names = set(compiled.get_graph().nodes.keys())
    for expected in (
        "classify",
        "threat_intel",
        "investigate",
        "remediate",
        "investigation_human_review",
        "remediation_human_review",
        "rca",
        "auto_resolve",
    ):
        assert expected in node_names


def test_route_after_investigation_review_approved():
    state: TriageState = {
        "alert": _make_alert(),
        "classification": None,
        "threat_intel": None,
        "investigation": None,
        "remediation": None,
        "root_cause_analysis": None,
        "human_decision": "",
        "status": "investigation_approved",
    }
    assert route_after_investigation_review(state) == "remediate"


def test_route_after_investigation_review_rejected():
    state: TriageState = {
        "alert": _make_alert(),
        "classification": None,
        "threat_intel": None,
        "investigation": None,
        "remediation": None,
        "root_cause_analysis": None,
        "human_decision": "",
        "status": "closed_by_human",
    }
    assert route_after_investigation_review(state) == "end"


def test_route_after_remediation_review_approved():
    state: TriageState = {
        "alert": _make_alert(),
        "classification": None,
        "threat_intel": None,
        "investigation": None,
        "remediation": None,
        "root_cause_analysis": None,
        "human_decision": "",
        "status": "remediation_approved",
    }
    assert route_after_remediation_review(state) == "rca"


def test_route_after_remediation_review_rejected():
    state: TriageState = {
        "alert": _make_alert(),
        "classification": None,
        "threat_intel": None,
        "investigation": None,
        "remediation": None,
        "root_cause_analysis": None,
        "human_decision": "",
        "status": "remediation_rejected",
    }
    assert route_after_remediation_review(state) == "end"


# --- End-to-end interrupt/resume flow (agents mocked, no real LLM/API calls) ---


async def _fake_classify(alert):
    return _make_classification(Severity.CRITICAL)


async def _fake_threat_intel(alert):
    from src.models import ThreatIntelligence

    return ThreatIntelligence(matches=[], risk_elevated=False, summary="none")


async def _fake_investigate(alert, classification, threat_intel=None):
    return Investigation(
        findings=["breach confirmed"],
        affected_scope="prod",
        requires_escalation=True,
        escalation_reason="active breach",
    )


async def _fake_remediate(alert, classification, investigation):
    return Remediation(
        immediate_actions=["revoke creds"],
        long_term_fixes=["rotate keys"],
        requires_human_approval=False,
    )


async def _fake_rca(alert, classification, investigation, remediation):
    from src.models import RootCauseAnalysis

    return RootCauseAnalysis(root_cause="compromised credential", contributing_factors=[])


async def test_full_graph_pauses_and_resumes_on_approval(monkeypatch):
    import src.graph as graph_module
    from langgraph.types import Command
    from langgraph.checkpoint.memory import InMemorySaver

    monkeypatch.setattr(graph_module, "classify_alert", _fake_classify)
    monkeypatch.setattr(graph_module, "enrich_threat_intel", _fake_threat_intel)
    monkeypatch.setattr(graph_module, "investigate_alert", _fake_investigate)
    monkeypatch.setattr(graph_module, "recommend_remediation", _fake_remediate)
    monkeypatch.setattr(graph_module, "perform_root_cause_analysis", _fake_rca)

    app = graph_module.compile_triage_graph(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "test-thread-1"}}

    initial_state: TriageState = {
        "alert": _make_alert(),
        "classification": None,
        "threat_intel": None,
        "investigation": None,
        "remediation": None,
        "root_cause_analysis": None,
        "human_decision": "",
        "status": "pending",
    }

    result = await app.ainvoke(initial_state, config=config)
    assert "__interrupt__" in result  # paused for investigation review (critical severity)

    result = await app.ainvoke(
        Command(resume={"approved": True, "notes": "looks legit"}), config=config
    )
    # CRITICAL severity always escalates after remediation too.
    assert "__interrupt__" in result

    result = await app.ainvoke(
        Command(resume={"approved": True, "notes": "go ahead"}), config=config
    )

    assert result["status"] == "resolved_with_approval"
    assert result["root_cause_analysis"] is not None


async def test_full_graph_stops_when_investigation_review_rejected(monkeypatch):
    import src.graph as graph_module
    from langgraph.types import Command
    from langgraph.checkpoint.memory import InMemorySaver

    monkeypatch.setattr(graph_module, "classify_alert", _fake_classify)
    monkeypatch.setattr(graph_module, "enrich_threat_intel", _fake_threat_intel)
    monkeypatch.setattr(graph_module, "investigate_alert", _fake_investigate)
    monkeypatch.setattr(graph_module, "recommend_remediation", _fake_remediate)
    monkeypatch.setattr(graph_module, "perform_root_cause_analysis", _fake_rca)

    app = graph_module.compile_triage_graph(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "test-thread-2"}}

    initial_state: TriageState = {
        "alert": _make_alert(),
        "classification": None,
        "threat_intel": None,
        "investigation": None,
        "remediation": None,
        "root_cause_analysis": None,
        "human_decision": "",
        "status": "pending",
    }

    result = await app.ainvoke(initial_state, config=config)
    assert "__interrupt__" in result

    result = await app.ainvoke(
        Command(resume={"approved": False, "notes": "false positive"}), config=config
    )

    assert result["status"] == "closed_by_human"
    assert result.get("remediation") is None  # never reached remediate
