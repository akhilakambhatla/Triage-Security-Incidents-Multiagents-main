"""LangGraph workflow for multi-agent security triage."""

from __future__ import annotations

from typing import TypedDict, Literal

from langgraph.graph import StateGraph, END

from .models import (
    SecurityAlert,
    Classification,
    Investigation,
    Remediation,
    TriageResult,
    Severity,
)
from .agents import classify_alert, investigate_alert, recommend_remediation


class TriageState(TypedDict):
    """State passed between nodes in the triage graph."""

    alert: SecurityAlert
    classification: Classification | None
    investigation: Investigation | None
    remediation: Remediation | None
    human_decision: str
    status: str


# --- Graph Nodes ---


async def classify_node(state: TriageState) -> dict:
    """Node: Classify the incoming alert."""
    classification = await classify_alert(state["alert"])
    return {"classification": classification}


async def investigate_node(state: TriageState) -> dict:
    """Node: Investigate the classified alert."""
    investigation = await investigate_alert(state["alert"], state["classification"])
    return {"investigation": investigation}


async def remediate_node(state: TriageState) -> dict:
    """Node: Generate remediation recommendations."""
    remediation = await recommend_remediation(
        state["alert"], state["classification"], state["investigation"]
    )
    return {"remediation": remediation}


async def human_review_node(state: TriageState) -> dict:
    """Node: Flag for human-in-the-loop review.

    In production, this would pause execution and await human input
    via a webhook, Slack notification, or approval queue.
    """
    reasons = []
    if state["investigation"] and state["investigation"].requires_escalation:
        reasons.append(f"Investigation: {state['investigation'].escalation_reason}")
    if state["remediation"] and state["remediation"].requires_human_approval:
        reasons.append(f"Remediation: {state['remediation'].approval_reason}")

    return {
        "status": "awaiting_human_review",
        "human_decision": f"ESCALATED - Reasons: {'; '.join(reasons)}",
    }


async def auto_resolve_node(state: TriageState) -> dict:
    """Node: Auto-resolve low-risk alerts."""
    return {
        "status": "auto_resolved",
        "human_decision": "Auto-resolved: low risk, no escalation needed",
    }


# --- Routing Logic ---


def route_after_investigation(
    state: TriageState,
) -> Literal["remediate", "human_review"]:
    """Route based on investigation results."""
    if state["investigation"] and state["investigation"].requires_escalation:
        return "human_review"
    return "remediate"


def route_after_remediation(
    state: TriageState,
) -> Literal["human_review", "auto_resolve"]:
    """Route based on remediation risk and severity."""
    classification = state["classification"]
    remediation = state["remediation"]

    # Always escalate critical/high severity
    if classification and classification.severity in (Severity.CRITICAL, Severity.HIGH):
        return "human_review"

    # Escalate if remediation needs approval
    if remediation and remediation.requires_human_approval:
        return "human_review"

    return "auto_resolve"


# --- Build Graph ---


def build_triage_graph() -> StateGraph:
    """Construct the LangGraph triage workflow.

    Flow:
        classify -> investigate -> [escalate?] -> remediate -> [approve?] -> resolve
                                       |                            |
                                       v                            v
                                  human_review                 human_review
    """
    graph = StateGraph(TriageState)

    # Add nodes
    graph.add_node("classify", classify_node)
    graph.add_node("investigate", investigate_node)
    graph.add_node("remediate", remediate_node)
    graph.add_node("human_review", human_review_node)
    graph.add_node("auto_resolve", auto_resolve_node)

    # Set entry point
    graph.set_entry_point("classify")

    # Define edges
    graph.add_edge("classify", "investigate")
    graph.add_conditional_edges(
        "investigate",
        route_after_investigation,
        {"remediate": "remediate", "human_review": "human_review"},
    )
    graph.add_conditional_edges(
        "remediate",
        route_after_remediation,
        {"human_review": "human_review", "auto_resolve": "auto_resolve"},
    )
    graph.add_edge("human_review", END)
    graph.add_edge("auto_resolve", END)

    return graph


def compile_triage_graph():
    """Compile the triage graph for execution."""
    graph = build_triage_graph()
    return graph.compile()
