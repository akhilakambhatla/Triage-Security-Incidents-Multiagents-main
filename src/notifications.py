"""Notification dispatch for human-in-the-loop escalation points.

Backends are chosen by environment configuration so the pipeline stays fully
offline/testable by default:

- ``SLACK_WEBHOOK_URL`` set -> POSTs a message to that Slack incoming webhook.
- ``NOTIFY_EMAIL`` set -> logs an email-send (wire up an actual SMTP/SES call
  where marked below; left as a stub since sending real email needs
  account-specific credentials this repo doesn't have).
- Neither set -> falls back to a console/audit-log-only notification, which
  is what tests and local demo runs use.

Any failure to reach an external service is caught and logged rather than
propagated, so a flaky webhook can never take down the triage graph.
"""

from __future__ import annotations

import os

from . import audit

_SENT_NOTIFICATIONS: list[dict] = []


def _dispatch_slack(webhook_url: str, text: str) -> bool:
    try:
        import requests

        resp = requests.post(webhook_url, json={"text": text}, timeout=5)
        return resp.ok
    except Exception:
        return False


def notify_escalation(stage: str, alert_id: str, title: str, reason: str) -> dict:
    """Notify humans that an alert needs review.

    Args:
        stage: "investigation" or "remediation" — which escalation point fired.
        alert_id: the alert being escalated.
        title: short alert title for the message.
        reason: why it escalated.
    """
    message = f"[SECURITY ESCALATION - {stage.upper()}] {alert_id}: {title}\nReason: {reason}"

    delivered_via = "console"
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    notify_email = os.environ.get("NOTIFY_EMAIL")

    if webhook_url:
        ok = _dispatch_slack(webhook_url, message)
        delivered_via = "slack" if ok else "slack_failed_fallback_console"
    elif notify_email:
        # Stub: wire up your SMTP/SES/SendGrid client here.
        delivered_via = f"email_stub:{notify_email}"

    if delivered_via.startswith("console") or "failed" in delivered_via:
        print(message)

    record = {
        "stage": stage,
        "alert_id": alert_id,
        "title": title,
        "reason": reason,
        "delivered_via": delivered_via,
    }
    _SENT_NOTIFICATIONS.append(record)
    audit.record(
        "notification_sent", alert_id, stage=stage, title=title,
        reason=reason, delivered_via=delivered_via,
    )
    return record


def get_sent_notifications() -> list[dict]:
    """Return notifications sent this process (used by tests/demo)."""
    return list(_SENT_NOTIFICATIONS)


def clear_sent_notifications() -> None:
    _SENT_NOTIFICATIONS.clear()
