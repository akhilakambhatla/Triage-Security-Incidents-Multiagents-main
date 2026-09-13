"""LangGraph workflow for multi-agent security triage.

Flow::

    classify -> threat_intel -> investigate -> [escalate?] -> remediate -> [approve?] -> rca -> END
                                                    |                          |
                                                    v                          v
                                       investigation_human_review    remediation_human_review
                                                    |                          |
                                          [approved?]                [approved?]
                                             /      \\                   /      \\
                                     remediate    END (closed)        rca    END (rejected)

Both human-review nodes use LangGraph's ``interrupt()`` to genuinely pause
the graph (not just set a status string) until a human resumes it with a
decision via ``Command(resume=...)``. That requires a checkpointer, so
``compile_triage_graph`` always compiles with one (in-memory by default;
pass your own for persistence across process restarts).
"""

from __future__ import annotations

from typing import TypedDict, Literal

from langgraph.graph import StateGraph, END
from langgraph.types import interrupt
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.base import BaseCheckpointSaver

from .models import (
    SecurityAlert,
    Classification,
    Investigation,
    Remediation,
    ThreatIntelligence,
    RootCauseAnalysis,
    Severity,
)
from .agents import (
    classify_alert,
    enrich_threat_intel,
    investigate_alert,
    recommend_remediation,
    perform_root_cause_analysis,
)
from . import audit
from . import notifications


class TriageState(TypedDict):
    """State passed between nodes in the triage graph."""

    alert: SecurityAlert
    classification: Classification | None
    threat_intel: ThreatIntelligence | None
    investigation: Investigation | None
    remediation: Remediation | None
    root_cause_analysis: RootCauseAnalysis | None
    human_decision: str
    status: str


# --- Graph Nodes ---


async def classify_node(state: TriageState) -> dict:
    """Node: Classify the incoming alert."""
    classification = await classify_alert(state["alert"])
    audit.record(
        "classification_complete",
        state["alert"].alert_id,
        severity=classification.severity.value,
        category=classification.category.value,
        confidence=classification.confidence,
    )
    return {"classification": classification}


async def threat_intel_node(state: TriageState) -> dict:
    """Node: Enrich the alert with threat intelligence before investigation."""
    threat_intel = await enrich_threat_intel(state["alert"])
    audit.record(
        "threat_intel_complete",
        state["alert"].alert_id,
        matches=len(threat_intel.matches),
        risk_elevated=threat_intel.risk_elevated,
    )
    return {"threat_intel": threat_intel}


async def investigate_node(state: TriageState) -> dict:
    """Node: Investigate the classified alert."""
    investigation = await investigate_alert(
        state["alert"], state["classification"], state.get("threat_intel")
    )
    audit.record(
        "investigation_complete",
        state["alert"].alert_id,
        requires_escalation=investigation.requires_escalation,
        affected_scope=investigation.affected_scope,
    )
    return {"investigation": investigation}


async def remediate_node(state: TriageState) -> dict:
    """Node: Generate remediation recommendations."""
    remediation = await recommend_remediation(
        state["alert"], state["classification"], state["investigation"]
    )
    audit.record(
        "remediation_complete",
        state["alert"].alert_id,
        requires_human_approval=remediation.requires_human_approval,
        immediate_actions=remediation.immediate_actions,
    )
    return {"remediation": remediation}


async def investigation_human_review_node(state: TriageState) -> dict:
    """Node: Pause for human review after a concerning investigation.

    Genuinely interrupts graph execution (via ``interrupt()``) rather than
    just setting a status string. Resume with:
    ``Command(resume={"approved": bool, "notes": str})``.
    """
    alert = state["alert"]
    investigation = state["investigation"]
    reason = investigation.escalation_reason if investigation else "Escalation flagged."

    notifications.notify_escalation("investigation", alert.alert_id, alert.title, reason)
    audit.record("investigation_escalated", alert.alert_id, reason=reason)

    decision = interrupt(
        {
            "stage": "investigation",
            "alert_id": alert.alert_id,
            "title": alert.title,
            "reason": reason,
            "findings": investigation.findings if investigation else [],
            "prompt": "Approve continuing to remediation? (approved: bool, notes: str)",
        }
    )

    approved = bool(decision.get("approved", False)) if isinstance(decision, dict) else bool(decision)
    notes = decision.get("notes", "") if isinstance(decision, dict) else ""

    audit.record("investigation_review_decided", alert.alert_id, approved=approved, notes=notes)

    return {
        "human_decision": f"Investigation review: {'APPROVED' if approved else 'REJECTED'} - {notes}",
        "status": "investigation_approved" if approved else "closed_by_human",
    }


async def remediation_human_review_node(state: TriageState) -> dict:
    """Node: Pause for human review/approval of proposed remediation actions."""
    alert = state["alert"]
    remediation = state["remediation"]
    classification = state["classification"]

    if classification and classification.severity in (Severity.CRITICAL, Severity.HIGH):
        reason = f"{classification.severity.value.upper()} severity always requires approval."
    else:
        reason = remediation.approval_reason if remediation else "Approval flagged."

    notifications.notify_escalation("remediation", alert.alert_id, alert.title, reason)
    audit.record("remediation_escalated", alert.alert_id, reason=reason)

    decision = interrupt(
        {
            "stage": "remediation",
            "alert_id": alert.alert_id,
            "title": alert.title,
            "reason": reason,
            "immediate_actions": remediation.immediate_actions if remediation else [],
            "prompt": "Approve executing these remediation actions? (approved: bool, notes: str)",
        }
    )

    approved = bool(decision.get("approved", False)) if isinstance(decision, dict) else bool(decision)
    notes = decision.get("notes", "") if isinstance(decision, dict) else ""

    audit.record("remediation_review_decided", alert.alert_id, approved=approved, notes=notes)

    return {
        "human_decision": f"Remediation review: {'APPROVED' if approved else 'REJECTED'} - {notes}",
        "status": "remediation_approved" if approved else "remediation_rejected",
    }


async def rca_node(state: TriageState) -> dict:
    """Node: Post-incident root cause analysis, run once a path is resolved."""
    rca = await perform_root_cause_analysis(
        state["alert"], state["classification"], state["investigation"], state["remediation"]
    )
    audit.record("root_cause_analysis_complete", state["alert"].alert_id, root_cause=rca.root_cause)

    final_status = (
        "resolved_with_approval" if state["status"] == "remediation_approved" else "auto_resolved"
    )

    return {"root_cause_analysis": rca, "status": final_status}


async def auto_resolve_node(state: TriageState) -> dict:
    """Node: Mark low-risk alerts for auto-resolution (RCA still runs after)."""
    audit.record("auto_resolved", state["alert"].alert_id)
    return {
        "status": "auto_resolved",
        "human_decision": "Auto-resolved: low risk, no escalation needed",
    }


# --- Routing Logic ---


def route_after_investigation(
    state: TriageState,
) -> Literal["remediate", "human_review"]:
    """Route based on investigation results.

    Returns the same ``"human_review"`` literal as the original single-node
    design; ``build_triage_graph`` maps it to the ``investigation_human_review``
    node specifically (kept distinct from remediation's review node so each
    pause can route to a different place on resume).
    """
    if state["investigation"] and state["investigation"].requires_escalation:
        return "human_review"
    return "remediate"


def route_after_investigation_review(
    state: TriageState,
) -> Literal["remediate", "end"]:
    """Route based on the human's investigation-review decision."""
    if state["status"] == "investigation_approved":
        return "remediate"
    return "end"


def route_after_remediation(
    state: TriageState,
) -> Literal["human_review", "auto_resolve"]:
    """Route based on remediation risk and severity.

    Returns the original ``"human_review"`` literal; mapped to the
    ``remediation_human_review`` node in ``build_triage_graph``.
    """
    classification = state["classification"]
    remediation = state["remediation"]

    # Always escalate critical/high severity
    if classification and classification.severity in (Severity.CRITICAL, Severity.HIGH):
        return "human_review"

    # Escalate if remediation needs approval
    if remediation and remediation.requires_human_approval:
        return "human_review"

    return "auto_resolve"


def route_after_remediation_review(
    state: TriageState,
) -> Literal["rca", "end"]:
    """Route based on the human's remediation-approval decision."""
    if state["status"] == "remediation_approved":
        return "rca"
    return "end"


# --- Build Graph ---


def build_triage_graph() -> StateGraph:
    """Construct the LangGraph triage workflow."""
    graph = StateGraph(TriageState)

    # Add nodes
    graph.add_node("classify", classify_node)
    graph.add_node("threat_intel", threat_intel_node)
    graph.add_node("investigate", investigate_node)
    graph.add_node("remediate", remediate_node)
    graph.add_node("investigation_human_review", investigation_human_review_node)
    graph.add_node("remediation_human_review", remediation_human_review_node)
    graph.add_node("rca", rca_node)
    graph.add_node("auto_resolve", auto_resolve_node)

    # Set entry point
    graph.set_entry_point("classify")

    # Define edges
    graph.add_edge("classify", "threat_intel")
    graph.add_edge("threat_intel", "investigate")

    graph.add_conditional_edges(
        "investigate",
        route_after_investigation,
        {"remediate": "remediate", "human_review": "investigation_human_review"},
    )
    graph.add_conditional_edges(
        "investigation_human_review",
        route_after_investigation_review,
        {"remediate": "remediate", "end": END},
    )
    graph.add_conditional_edges(
        "remediate",
        route_after_remediation,
        {"human_review": "remediation_human_review", "auto_resolve": "auto_resolve"},
    )
    graph.add_conditional_edges(
        "remediation_human_review",
        route_after_remediation_review,
        {"rca": "rca", "end": END},
    )

    graph.add_edge("auto_resolve", "rca")
    graph.add_edge("rca", END)

    return graph


def compile_triage_graph(checkpointer: BaseCheckpointSaver | None = None):
    """Compile the triage graph for execution.

    A checkpointer is required because the human-review nodes use
    ``interrupt()`` to genuinely pause execution; state must be persisted
    somewhere for the graph to be resumable. Defaults to an in-memory
    checkpointer (fine for a single process/demo); pass e.g. a Postgres or
    SQLite checkpointer for durability across restarts in production.
    """
    graph = build_triage_graph()
    return graph.compile(checkpointer=checkpointer or InMemorySaver())
