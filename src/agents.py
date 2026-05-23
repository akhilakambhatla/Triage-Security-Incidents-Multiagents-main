"""Individual agent implementations for the triage pipeline."""

from __future__ import annotations

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage

from .models import (
    SecurityAlert,
    Classification,
    Investigation,
    Remediation,
    Severity,
    AlertCategory,
)
from .knowledge_base import get_playbook, search_playbooks


def get_llm(model: str = "gpt-4o-mini", temperature: float = 0.1) -> ChatOpenAI:
    """Get configured LLM instance."""
    return ChatOpenAI(model=model, temperature=temperature)


# --- Classifier Agent ---

CLASSIFIER_PROMPT = """You are a security alert classifier working in a SOC.
Given a raw security alert, classify it by severity and category.

Severity levels:
- critical: Active breach, data loss imminent, requires immediate response
- high: Confirmed malicious activity, significant risk if not addressed within 1 hour
- medium: Suspicious activity requiring investigation within 4 hours
- low: Minor policy violation or informational alert
- info: Noise, false positive, or expected behavior

Categories:
- unauthorized_access: Failed/successful auth from unusual source
- data_exfiltration: Unusual data transfer patterns
- malware: Known malicious signatures or C2 communication
- policy_violation: Security policy or compliance breach
- anomalous_behavior: Statistical deviation from baseline
- configuration_drift: Infrastructure config changed unexpectedly

Respond with JSON containing: severity, category, confidence (0-1), reasoning."""


async def classify_alert(alert: SecurityAlert) -> Classification:
    """Classify a security alert by severity and category."""
    llm = get_llm()
    structured_llm = llm.with_structured_output(Classification)

    result = await structured_llm.ainvoke([
        SystemMessage(content=CLASSIFIER_PROMPT),
        HumanMessage(content=f"""Alert ID: {alert.alert_id}
Source: {alert.source}
Title: {alert.title}
Description: {alert.description}
Indicators: {', '.join(alert.raw_indicators)}
Affected Resource: {alert.affected_resource}
Timestamp: {alert.timestamp}"""),
    ])
    return result


# --- Investigator Agent ---

INVESTIGATOR_PROMPT = """You are a security investigator. Given a classified alert,
conduct a deeper investigation to determine scope, attack vector, and whether
escalation is needed.

Consider:
1. What is the blast radius?
2. Is this part of a larger attack chain?
3. Are there indicators of compromise (IOCs) that need cross-referencing?
4. Does this require human escalation? (escalate if: critical severity,
   data loss confirmed, active attacker present, or compliance breach)

Respond with JSON: findings (list), affected_scope, attack_vector,
ioc_matches (list), requires_escalation (bool), escalation_reason."""


async def investigate_alert(
    alert: SecurityAlert, classification: Classification
) -> Investigation:
    """Investigate a classified alert for scope and escalation needs."""
    llm = get_llm()
    structured_llm = llm.with_structured_output(Investigation)

    result = await structured_llm.ainvoke([
        SystemMessage(content=INVESTIGATOR_PROMPT),
        HumanMessage(content=f"""Alert: {alert.title}
Description: {alert.description}
Classification: {classification.severity.value} / {classification.category.value}
Confidence: {classification.confidence}
Indicators: {', '.join(alert.raw_indicators)}
Resource: {alert.affected_resource}"""),
    ])
    return result


# --- Remediation Agent ---

REMEDIATION_PROMPT = """You are a security remediation specialist. Given an
investigated alert and relevant playbook context, recommend immediate and
long-term actions.

Rules:
- Immediate actions should be executable within minutes
- Long-term fixes should prevent recurrence
- Flag for human approval if: action could cause service disruption,
  affects production workloads, or involves credential revocation for
  service accounts

Playbook context:
{playbook_context}

Respond with JSON: immediate_actions (list), long_term_fixes (list),
playbook_reference, estimated_impact, requires_human_approval (bool),
approval_reason."""


async def recommend_remediation(
    alert: SecurityAlert,
    classification: Classification,
    investigation: Investigation,
) -> Remediation:
    """Generate remediation recommendations using playbook RAG."""
    # RAG: retrieve relevant playbook
    playbook = get_playbook(classification.category.value)
    related = search_playbooks(alert.description)

    playbook_context = f"""Primary playbook: {playbook['title']}
Immediate actions reference: {playbook['immediate']}
Long-term fixes reference: {playbook['long_term']}

Related playbooks found: {[r['playbook']['title'] for r in related]}"""

    llm = get_llm()
    structured_llm = llm.with_structured_output(Remediation)

    prompt = REMEDIATION_PROMPT.format(playbook_context=playbook_context)

    result = await structured_llm.ainvoke([
        SystemMessage(content=prompt),
        HumanMessage(content=f"""Alert: {alert.title}
Severity: {classification.severity.value}
Category: {classification.category.value}
Investigation findings: {investigation.findings}
Scope: {investigation.affected_scope}
Attack vector: {investigation.attack_vector}
Requires escalation: {investigation.requires_escalation}
Resource: {alert.affected_resource}"""),
    ])
    return result
