"""Demo runner showing the triage system in action."""

from __future__ import annotations

import argparse
import asyncio

from langgraph.types import Command
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from .models import SecurityAlert
from .graph import compile_triage_graph, TriageState

console = Console()

# --- Sample Alerts (realistic enterprise scenarios) ---

SAMPLE_ALERTS = [
    SecurityAlert(
        alert_id="ALT-2026-0847",
        source="AWS GuardDuty",
        title="Unusual API calls from IAM user in production account",
        description=(
            "IAM user 'svc-data-pipeline' made 847 ListBuckets and GetObject calls "
            "to S3 buckets containing PII data from an IP address in a country where "
            "the organization has no operations. Activity occurred between 02:00-04:00 UTC, "
            "outside normal business hours."
        ),
        raw_indicators=["IP: 185.220.101.34", "Tor exit node", "847 API calls in 2 hours"],
        affected_resource="arn:aws:s3:::prod-customer-pii-data",
        timestamp="2026-05-23T03:15:00Z",
    ),
    SecurityAlert(
        alert_id="ALT-2026-0848",
        source="AWS Config",
        title="Security group modified to allow 0.0.0.0/0 on port 22",
        description=(
            "Production security group sg-0a1b2c3d was modified to allow inbound SSH "
            "from any IP address. Change was made by IAM user 'dev-john' outside of "
            "the approved change window."
        ),
        raw_indicators=["sg-0a1b2c3d", "0.0.0.0/0:22", "outside change window"],
        affected_resource="arn:aws:ec2:us-west-2:123456789:security-group/sg-0a1b2c3d",
        timestamp="2026-05-23T14:22:00Z",
    ),
    SecurityAlert(
        alert_id="ALT-2026-0849",
        source="AWS WAF",
        title="SQL injection attempts blocked - elevated volume",
        description=(
            "WAF rule 'SQLi-Detection' blocked 1,247 requests from distributed IPs "
            "targeting /api/v2/accounts endpoint. Pattern suggests automated scanning "
            "tool. All requests blocked, no successful exploitation detected."
        ),
        raw_indicators=["1247 blocked requests", "distributed IPs", "/api/v2/accounts"],
        affected_resource="arn:aws:elasticloadbalancing:us-east-1:123456789:app/prod-api",
        timestamp="2026-05-23T11:45:00Z",
    ),
]


def print_alert(alert: SecurityAlert) -> None:
    """Pretty-print an alert."""
    console.print(Panel(
        f"[bold]{alert.title}[/bold]\n\n"
        f"[dim]Source:[/dim] {alert.source}\n"
        f"[dim]Resource:[/dim] {alert.affected_resource}\n"
        f"[dim]Time:[/dim] {alert.timestamp}\n\n"
        f"{alert.description}\n\n"
        f"[dim]Indicators:[/dim] {', '.join(alert.raw_indicators)}",
        title=f"Alert {alert.alert_id}",
        border_style="red",
    ))


def print_result(state: dict) -> None:
    """Pretty-print triage results."""
    classification = state.get("classification")
    threat_intel = state.get("threat_intel")
    investigation = state.get("investigation")
    remediation = state.get("remediation")
    rca = state.get("root_cause_analysis")

    # Threat intel
    if threat_intel and threat_intel.matches:
        console.print(f"\n[bold]Threat Intel:[/bold] [yellow]{threat_intel.summary}[/yellow]")
        for m in threat_intel.matches:
            console.print(f"  - {m.indicator} ({m.threat_type}, confidence={m.confidence:.0%}, source={m.source})")

    # Classification
    if classification:
        severity_colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "green",
            "info": "dim",
        }
        color = severity_colors.get(classification.severity.value, "white")
        console.print(f"\n[bold]Classification:[/bold]")
        console.print(f"  Severity: [{color}]{classification.severity.value.upper()}[/{color}]")
        console.print(f"  Category: {classification.category.value}")
        console.print(f"  Confidence: {classification.confidence:.0%}")
        console.print(f"  Reasoning: {classification.reasoning}")

    # Investigation
    if investigation:
        console.print(f"\n[bold]Investigation:[/bold]")
        console.print(f"  Scope: {investigation.affected_scope}")
        console.print(f"  Vector: {investigation.attack_vector}")
        for finding in investigation.findings:
            console.print(f"  - {finding}")
        if investigation.requires_escalation:
            console.print(f"  [red bold]ESCALATION: {investigation.escalation_reason}[/red bold]")

    # Remediation
    if remediation:
        console.print(f"\n[bold]Remediation:[/bold]")
        console.print("  [underline]Immediate:[/underline]")
        for action in remediation.immediate_actions:
            console.print(f"    > {action}")
        console.print("  [underline]Long-term:[/underline]")
        for fix in remediation.long_term_fixes:
            console.print(f"    > {fix}")
        if remediation.requires_human_approval:
            console.print(f"  [yellow]Needs approval: {remediation.approval_reason}[/yellow]")

    # Root cause analysis
    if rca:
        console.print(f"\n[bold]Root Cause Analysis:[/bold]")
        console.print(f"  Root cause: {rca.root_cause}")
        for factor in rca.contributing_factors:
            console.print(f"  - Contributing: {factor}")
        for rec in rca.prevention_recommendations:
            console.print(f"  [cyan]Prevent:[/cyan] {rec}")

    # Final status
    status = state.get("status", "unknown")
    decision = state.get("human_decision", "")
    status_color = "red" if "reject" in status else ("yellow" if "approv" in status else "green")
    console.print(f"\n[bold]Status:[/bold] [{status_color}]{status}[/{status_color}]")
    if decision:
        console.print(f"  {decision}")
    console.print("=" * 60)


def _print_interrupt(payload: dict) -> None:
    console.print(Panel(
        f"[bold]{payload.get('prompt', 'Human decision needed')}[/bold]\n\n"
        f"[dim]Stage:[/dim] {payload.get('stage')}\n"
        f"[dim]Reason:[/dim] {payload.get('reason')}",
        title=f"⏸ PAUSED — Alert {payload.get('alert_id')}",
        border_style="magenta",
    ))


async def run_demo(alert_index: int | None = None, interactive: bool = False) -> None:
    """Run the triage demo on sample alerts.

    Args:
        alert_index: run only this sample alert (0-indexed), or all if None.
        interactive: if True, actually prompt for approve/reject at each
            human-review pause. If False (default), auto-approves every
            escalation so the demo can run end-to-end unattended.
    """
    app = compile_triage_graph()

    alerts = [SAMPLE_ALERTS[alert_index]] if alert_index is not None else SAMPLE_ALERTS

    console.print("\n[bold cyan]Triage Security Incidents - Multi-Agent Demo[/bold cyan]")
    console.print(f"Processing {len(alerts)} alert(s)...\n")

    for alert in alerts:
        print_alert(alert)

        initial_state: TriageState = {
            "alert": alert,
            "classification": None,
            "threat_intel": None,
            "investigation": None,
            "remediation": None,
            "root_cause_analysis": None,
            "human_decision": "",
            "status": "pending",
        }

        config = {"configurable": {"thread_id": alert.alert_id}}

        console.print(
            "[dim]Running triage pipeline: classify → threat_intel → investigate → remediate...[/dim]"
        )
        result = await app.ainvoke(initial_state, config=config)

        # Drain any human-review interrupts, resuming the graph each time.
        while "__interrupt__" in result:
            pending = result["__interrupt__"][0]
            _print_interrupt(pending.value)

            if interactive:
                approved = Confirm.ask("Approve?", default=True)
                notes = Prompt.ask("Notes", default="")
            else:
                approved, notes = True, "auto-approved by demo runner"
                console.print("[dim](non-interactive demo: auto-approving — pass --interactive to decide manually)[/dim]")

            result = await app.ainvoke(
                Command(resume={"approved": approved, "notes": notes}), config=config
            )

        print_result(result)


def main():
    """Entry point."""
    parser = argparse.ArgumentParser(description="Run the security triage multi-agent demo.")
    parser.add_argument(
        "--interactive", action="store_true",
        help="Prompt for approve/reject at each human-review pause instead of auto-approving.",
    )
    parser.add_argument(
        "--alert", type=int, default=None,
        help="Run only the sample alert at this index (0-based).",
    )
    args = parser.parse_args()
    asyncio.run(run_demo(alert_index=args.alert, interactive=args.interactive))


if __name__ == "__main__":
    main()
