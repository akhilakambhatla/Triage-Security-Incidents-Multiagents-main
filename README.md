# Security Triage Agent

Multi-agent security alert triage system built with **LangGraph**. Automates the SOC analyst workflow: classify → investigate → remediate, with human-in-the-loop escalation for high-risk decisions.

Built from real-world experience deploying automated security remediation systems at AWS for Fortune 50 financial institutions.

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
                    │ Human Review │     │ Human Review  │
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

# Set OpenAI key (for LLM agents)
export OPENAI_API_KEY=sk-...

# Run tests (no API key needed - tests cover models, routing, and knowledge base)
pytest -v

# Run demo (requires API key)
python -m src.demo
```

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
- **OpenAI GPT-4o-mini** — Agent reasoning (swappable for any LangChain-compatible LLM)

## Why This Exists

Security operations teams handle hundreds of alerts daily. Most are noise. The critical ones need fast, accurate triage. This system demonstrates how a multi-agent architecture can automate the repetitive classification and investigation work while keeping humans in the loop for high-stakes decisions — the same pattern used in production at enterprise scale.
