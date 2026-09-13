"""Tests for escalation notifications."""

from src import notifications


def setup_function():
    notifications.clear_sent_notifications()


def test_notify_escalation_console_backend(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("NOTIFY_EMAIL", raising=False)

    record = notifications.notify_escalation("investigation", "ALT-1", "Test alert", "reason")

    assert record["delivered_via"] == "console"
    assert record["alert_id"] == "ALT-1"
    assert notifications.get_sent_notifications() == [record]


def test_notify_escalation_slack_backend(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example.com/x")
    monkeypatch.setattr(notifications, "_dispatch_slack", lambda url, text: True)

    record = notifications.notify_escalation("remediation", "ALT-2", "Test", "reason")
    assert record["delivered_via"] == "slack"


def test_notify_escalation_slack_failure_falls_back(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example.com/x")
    monkeypatch.setattr(notifications, "_dispatch_slack", lambda url, text: False)

    record = notifications.notify_escalation("remediation", "ALT-3", "Test", "reason")
    assert "failed" in record["delivered_via"]
