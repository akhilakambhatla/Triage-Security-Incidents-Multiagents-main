"""Individual agent implementations for the triage pipeline."""

from __future__ import annotations

from langchain_google_vertexai import ChatVertexAI
from langchain_core.messages import SystemMessage, HumanMessage

from .models import (
    SecurityAlert,
    Classification,
    Investigation,
    Remediation,
    Severity,
    AlertCategory,
    ThreatIntelligence,
    ThreatIntelMatch,
    RootCauseAnalysis,
)
from .knowledge_base import get_playbook
from .threat_intel import lookup_indicators
from .vector_store import retrieve_semantic_context


def get_llm(model: str = "gemini-2.0-flash", temperature: float = 0.1) -> ChatVertexAI:
    """Get configured LLM instance.

    Authenticates via Application Default Credentials (ADC) rather than an
    API key, since GCP org policy may disallow API key creation.
    """
    return ChatVertexAI(model=model, temperature=temperature)


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


# --- Threat Intel Agent ---

THREAT_INTEL_PROMPT = """You are a threat intelligence analyst. You are given a
security alert plus raw indicator-of-compromise (IOC) matches already looked up
against a threat feed. Summarize what these matches mean for this specific
alert, and decide whether they should elevate the perceived risk.

Rules:
- risk_elevated should be true if any match has confidence >= 0.7, or if
  multiple lower-confidence matches point at the same threat_type.
- If there are no matches, risk_elevated is false and matches is an empty list.
- summary should be 1-3 sentences a SOC analyst can read in passing.

You must return the matches list exactly as given to you (do not invent new
indicators), plus your risk_elevated decision and summary."""


async def enrich_threat_intel(alert: SecurityAlert) -> ThreatIntelligence:
    """Look up alert indicators against the threat feed and summarize risk.

    Runs between classification and investigation so the investigator has
    IOC context available. The IOC lookup itself is deterministic (see
    threat_intel.py); the LLM's job is only to summarize/decide risk framing,
    not to fabricate matches.
    """
    raw_matches = lookup_indicators(alert.raw_indicators)

    if not raw_matches:
        return ThreatIntelligence(matches=[], risk_elevated=False, summary="No known IOC matches.")

    llm = get_llm()
    structured_llm = llm.with_structured_output(ThreatIntelligence)

    matches_text = "\n".join(
        f"- {m['indicator']} ({m['indicator_type']}): {m['threat_type']}, "
        f"confidence={m['confidence']}, source={m['source']} — {m['description']}"
        for m in raw_matches
    )

    result = await structured_llm.ainvoke([
        SystemMessage(content=THREAT_INTEL_PROMPT),
        HumanMessage(content=f"""Alert: {alert.title}
Description: {alert.description}

Raw IOC matches from threat feed:
{matches_text}"""),
    ])

    # Guarantee the matches we actually looked up survive the LLM round-trip,
    # even if the model paraphrases or drops fields.
    result.matches = [ThreatIntelMatch(**m) for m in raw_matches]
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
    alert: SecurityAlert,
    classification: Classification,
    threat_intel: ThreatIntelligence | None = None,
) -> Investigation:
    """Investigate a classified alert for scope and escalation needs."""
    llm = get_llm()
    structured_llm = llm.with_structured_output(Investigation)

    threat_intel_context = "No threat intel matches." if threat_intel is None else (
        threat_intel.summary
        if threat_intel.matches
        else "No known IOC matches."
    )

    result = await structured_llm.ainvoke([
        SystemMessage(content=INVESTIGATOR_PROMPT),
        HumanMessage(content=f"""Alert: {alert.title}
Description: {alert.description}
Classification: {classification.severity.value} / {classification.category.value}
Confidence: {classification.confidence}
Indicators: {', '.join(alert.raw_indicators)}
Resource: {alert.affected_resource}
Threat intel: {threat_intel_context}"""),
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
    # RAG: category lookup gives the canonical playbook for this alert type...
    playbook = get_playbook(classification.category.value)

    # ...and semantic retrieval over ALL playbooks surfaces relevant steps
    # from *other* categories too (e.g. a data-exfil alert might also need
    # a config-drift step if a misconfigured bucket policy was the vector).
    semantic_query = f"{alert.title} {alert.description} {investigation.attack_vector}"
    retrieved = retrieve_semantic_context(semantic_query, k=5)
    retrieved_text = "\n".join(f"- [{d.metadata.get('category')}] {d.page_content}" for d in retrieved)

    playbook_context = f"""Primary playbook: {playbook['title']}
Immediate actions reference: {playbook['immediate']}
Long-term fixes reference: {playbook['long_term']}

Semantically retrieved relevant steps (may span multiple playbooks):
{retrieved_text or '(none retrieved)'}"""

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


# --- Root Cause Analysis Agent ---

RCA_PROMPT = """You are a security incident post-mortem analyst. Given the
full trail of an already-handled security alert (classification,
investigation, remediation), produce a blameless root cause analysis
suitable for a post-incident review.

Rules:
- root_cause should be one clear sentence naming the underlying cause
  (not just the symptom that triggered the alert).
- contributing_factors are secondary conditions that made the incident
  possible or worse (e.g. missing MFA, over-broad IAM policy).
- timeline is a short ordered list of what happened, inferred from the
  alert/investigation data (do not invent exact timestamps you don't have).
- lessons_learned and prevention_recommendations should be concrete and
  actionable, not generic ("enable MFA on the specific account", not
  "improve security posture").

Respond with JSON matching the RootCauseAnalysis schema."""


async def perform_root_cause_analysis(
    alert: SecurityAlert,
    classification: Classification,
    investigation: Investigation,
    remediation: Remediation,
) -> RootCauseAnalysis:
    """Produce a post-incident root cause analysis.

    Runs after a remediation path has been decided (auto-resolved or
    human-approved) so the RCA has the complete picture of what was found
    and what was done about it.
    """
    llm = get_llm()
    structured_llm = llm.with_structured_output(RootCauseAnalysis)

    result = await structured_llm.ainvoke([
        SystemMessage(content=RCA_PROMPT),
        HumanMessage(content=f"""Alert: {alert.title}
Description: {alert.description}
Severity/Category: {classification.severity.value} / {classification.category.value}

Investigation findings: {investigation.findings}
Affected scope: {investigation.affected_scope}
Attack vector: {investigation.attack_vector}
IOC matches: {investigation.ioc_matches}

Remediation immediate actions: {remediation.immediate_actions}
Remediation long-term fixes: {remediation.long_term_fixes}"""),
    ])
    return result
