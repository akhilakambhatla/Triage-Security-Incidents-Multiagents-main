# Triage Security Incidents (Multi-Agent)

A multi-agent security alert triage system built with **LangGraph**. It automates the SOC analyst workflow — classify → enrich → investigate → remediate → post-mortem — with genuine human-in-the-loop pauses for high-risk decisions.

## Architecture

```
                                          ┌──────────────┐
                              ┌──────────▶│ Investigation │
                              │           │ Human Review  │ (interrupt)
                              │           └──────┬────────┘
                              │ escalation?    approved?
┌───────────┐  ┌────────────┐│┌──────────────┐  │  ┌──────────────┐┌──────────────┐  ┌─────┐  ┌──────┐
│ Classifier│─▶│Threat Intel│┼▶│ Investigator │──┴─▶│  Remediator  │┼▶│Auto-Resolve│─▶│ RCA │─▶│ END  │
│   Agent   │  │   Agent    │ │    Agent     │      │    Agent     ││└──────────────┘  └──┬──┘  └──────┘
└───────────┘  └────────────┘ └──────────────┘      └──────┬───────┘│                     │
                                                             │approval needed?              │
                                                             ▼        │                     │
                                                     ┌──────────────┐ │                     │
                                                     │ Remediation  │─┘── approved ──────────┘
                                                     │ Human Review │ (interrupt)
                                                     └──────────────┘
```

### Agents

| Agent | Role | Output |
|-------|------|--------|
| **Classifier** | Determines severity (critical→info) and category (6 types) | Severity, category, confidence score |
| **Threat Intel** | Matches alert indicators (IPs, domains, patterns) against a local threat feed and summarizes risk | IOC matches, risk-elevated flag |
| **Investigator** | Assesses blast radius, attack vector, IOCs (now threat-intel aware) | Findings, scope, escalation decision |
| **Remediator** | Generates actions using real playbook RAG (Vertex AI embeddings) | Immediate + long-term fixes, approval flag |
| **Root Cause Analysis** | Post-incident blameless post-mortem, runs after a path resolves | Root cause, contributing factors, prevention recommendations |

Two cross-cutting pieces sit alongside the pipeline rather than as graph nodes of their own (see the docstrings in `audit.py` / `notifications.py` for why):

- **Audit logger** — every node records a structured entry (JSON lines to `audit_log.jsonl`, plus in-memory for the demo/tests) so every decision is traceable end to end.
- **Notifier** — fires at both human-review pauses. Uses `SLACK_WEBHOOK_URL` if set, otherwise falls back to console output; failures never crash the pipeline.

### Key Design Decisions

- **Conditional routing**: Critical/high severity alerts always escalate to human review. Medium/low can auto-resolve.
- **Real playbook RAG**: The remediation agent retrieves from an embedded vector store (Vertex AI `text-embedding-005` + LangChain's `InMemoryVectorStore`) built by chunking every playbook step individually, so retrieval can surface relevant steps across categories, not just the alert's own category. Falls back to the original keyword search if embeddings can't be built (no GCP credentials configured) — see `vector_store.py`.
- **Genuine human-in-the-loop**: Both escalation points use LangGraph's `interrupt()` to actually pause graph execution (not just set a status string), checkpointed so the graph can be resumed later with `Command(resume={"approved": bool, "notes": str})` — from a webhook handler, Slack action, or approval UI in production.
- **Structured outputs**: All agents return typed Pydantic models, enabling downstream automation.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Authenticate to GCP (for LLM agents) — see "Gemini via Vertex AI" below
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=your-gcp-project-id
export GOOGLE_CLOUD_LOCATION=us-central1

# Run tests (no GCP auth needed - agents/embeddings are mocked or have
# offline fallbacks; tests cover models, routing, agents, knowledge base,
# threat intel, audit, notifications, and vector store)
pytest -v

# Run demo (requires GCP auth) - auto-approves every human-review pause
python -m src.demo

# Run demo and actually be prompted at each human-review pause
python -m src.demo --interactive

# Run just one sample alert (0, 1, or 2)
python -m src.demo --alert 0
```

### Gemini via Vertex AI

This project calls Gemini through Vertex AI using Application Default Credentials (ADC) instead of an API key — some GCP orgs disable API key creation by policy, so this works everywhere. One-time setup:

1. Pick or create a GCP project, then enable the Vertex AI API:
   `gcloud services enable aiplatform.googleapis.com --project=your-gcp-project-id`
2. Authenticate your local machine for ADC:
   `gcloud auth application-default login`
3. Export the project and region the agents should use:
   `export GOOGLE_CLOUD_PROJECT=your-gcp-project-id`
   `export GOOGLE_CLOUD_LOCATION=us-central1`

No key ever touches the codebase or `.env` — `ChatVertexAI` and `VertexAIEmbeddings` both pick up ADC automatically.

### Optional: Slack notifications

```bash
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

Without this set, escalation notifications print to the console (and are always recorded to the audit trail either way).

## Project Structure

```
src/
├── models.py          # Pydantic models (Alert, Classification, Investigation, Remediation,
│                       #   ThreatIntelligence, RootCauseAnalysis)
├── agents.py           # Agent implementations: classify, threat intel, investigate,
│                        #   remediate, root cause analysis — all structured-output LLM calls
├── graph.py             # LangGraph StateGraph: nodes, conditional routing, real interrupts
├── knowledge_base.py     # Security playbook store (raw data + legacy keyword search)
├── vector_store.py        # Real RAG: chunks playbooks, embeds with Vertex AI, semantic search
├── threat_intel.py         # Local IOC feed + matching logic used by the Threat Intel agent
├── audit.py                 # Cross-cutting audit trail, called from every node
├── notifications.py          # Escalation notifications (Slack webhook / console fallback)
└── demo.py                    # Interactive demo, drives the interrupt/resume loop
tests/
├── test_models.py             # Data model validation
├── test_knowledge_base.py     # Playbook retrieval and legacy keyword search
├── test_vector_store.py       # Document chunking + semantic retrieval (mocked, no GCP call)
├── test_threat_intel.py       # IOC matching against the local feed
├── test_audit.py              # Audit trail recording/filtering
├── test_notifications.py      # Notification backends (console/Slack, mocked)
└── test_graph.py              # Graph construction, routing, and end-to-end interrupt/resume
```

## Sample Alerts

The demo includes three realistic enterprise scenarios:

1. **Data exfiltration via compromised service account** — Tor exit node accessing PII S3 bucket at 3 AM → CRITICAL, escalates to human
2. **Security group opened to internet** — Dev opens SSH to 0.0.0.0/0 outside change window → MEDIUM, policy violation
3. **WAF blocking SQL injection scan** — 1,247 blocked requests, no exploitation → LOW, auto-resolves

## Tech Stack

- **LangGraph** — Multi-agent orchestration, conditional routing, state management, and real interrupt/resume checkpointing
- **LangChain** — LLM integration with structured output parsing, `InMemoryVectorStore` for RAG
- **Pydantic** — Type-safe data models across the pipeline
- **Gemini via Vertex AI (gemini-2.5-flash)** — Agent reasoning, authenticated with ADC (swappable for any LangChain-compatible LLM)
- **Vertex AI Embeddings (text-embedding-005)** — Semantic retrieval over the playbook knowledge base
- **requests** — Slack webhook delivery for escalation notifications (optional)

## Why This Exists

Security operations teams handle hundreds of alerts daily. Most are noise. The critical ones need fast, accurate triage. This system demonstrates how a multi-agent architecture can automate the repetitive classification and investigation work while keeping humans in the loop for high-stakes decisions.
