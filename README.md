# Triage Security Incidents (Multi-Agent)

A multi-agent security alert triage system built with **LangGraph**. It automates the SOC analyst workflow — classify → investigate → remediate — with human-in-the-loop escalation for high-risk decisions.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Classifier │────▶│ Investigator │────▶│  Remediator  │────▶│ Auto-Resolve │
│    Agent    │     │    Agent     │     │    Agent     │     │              │
└─────────────┘     └──────┬───────┘     └──────┬───────┘     └──────────────┘
                           │                     │
                           │ escalation?         │ approval needed?
                           ▼                     ▼
                    ┌──────────────┐     ┌──────────────┐
                    │ Human Review │     │ Human Review │
                    │   (HITL)     │     │   (HITL)     │
                    └──────────────┘     └──────────────┘
```

### Agents

| Agent | Role | Output |
|-------|------|--------|
| **Classifier** | Determines severity (critical→info) and category (6 types) | Severity, category, confidence score |
| **Investigator** | Assesses blast radius, attack vector, IOCs | Findings, scope, escalation decision |
| **Remediator** | Generates actions using playbook RAG | Immediate + long-term fixes, approval flag |

### Key Design Decisions

- **Conditional routing**: Critical/high severity alerts always escalate to human review. Medium/low can auto-resolve.
- **Playbook RAG**: Remediation agent retrieves from a structured knowledge base of incident response playbooks, simulating retrieval-augmented generation over security runbooks.
- **Human-in-the-loop**: Two escalation points — after investigation (active breach?) and after remediation (disruptive action?). In production, these pause execution and await approval via webhook/Slack.
- **Structured outputs**: All agents return typed Pydantic models, enabling downstream automation.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Authenticate to GCP (for LLM agents) — see "Gemini via Vertex AI" below
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=your-gcp-project-id
export GOOGLE_CLOUD_LOCATION=us-central1

# Run tests (no GCP auth needed - tests cover models, routing, and knowledge base)
pytest -v

# Run demo (requires GCP auth)
python -m src.demo
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

No key ever touches the codebase or `.env` — `ChatVertexAI` picks up ADC automatically.

## Project Structure

```
src/
├── models.py          # Pydantic models (Alert, Classification, Investigation, Remediation)
├── agents.py          # Individual agent implementations with structured output
├── graph.py           # LangGraph StateGraph definition with conditional routing
├── knowledge_base.py  # Security playbook store (simulates RAG retrieval)
└── demo.py            # Interactive demo with sample enterprise alerts
tests/
├── test_models.py     # Data model validation
├── test_knowledge_base.py  # Playbook retrieval and search
└── test_graph.py      # Graph construction and routing logic
```

## Sample Alerts

The demo includes three realistic enterprise scenarios:

1. **Data exfiltration via compromised service account** — Tor exit node accessing PII S3 bucket at 3 AM → CRITICAL, escalates to human
2. **Security group opened to internet** — Dev opens SSH to 0.0.0.0/0 outside change window → MEDIUM, policy violation
3. **WAF blocking SQL injection scan** — 1,247 blocked requests, no exploitation → LOW, auto-resolves

## Tech Stack

- **LangGraph** — Multi-agent orchestration with conditional routing and state management
- **LangChain** — LLM integration with structured output parsing
- **Pydantic** — Type-safe data models across the pipeline
- **Gemini via Vertex AI (gemini-2.0-flash)** — Agent reasoning, authenticated with ADC (swappable for any LangChain-compatible LLM)

## Why This Exists

Security operations teams handle hundreds of alerts daily. Most are noise. The critical ones need fast, accurate triage. This system demonstrates how a multi-agent architecture can automate the repetitive classification and investigation work while keeping humans in the loop for high-stakes decisions.
