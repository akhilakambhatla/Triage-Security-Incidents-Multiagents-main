"""Tests for the audit trail."""

import os

from src import audit


def setup_function():
    audit.clear_audit_trail()


def test_record_appends_entry():
    entry = audit.record("test_event", "ALT-1", foo="bar")
    assert entry["event"] == "test_event"
    assert entry["alert_id"] == "ALT-1"
    assert entry["foo"] == "bar"
    assert "timestamp" in entry


def test_get_audit_trail_returns_all():
    audit.record("e1", "ALT-1")
    audit.record("e2", "ALT-2")
    trail = audit.get_audit_trail()
    assert len(trail) == 2


def test_get_audit_trail_filters_by_alert():
    audit.record("e1", "ALT-1")
    audit.record("e2", "ALT-2")
    trail = audit.get_audit_trail(alert_id="ALT-1")
    assert len(trail) == 1
    assert trail[0]["alert_id"] == "ALT-1"


def test_clear_audit_trail():
    audit.record("e1", "ALT-1")
    audit.clear_audit_trail()
    assert audit.get_audit_trail() == []


def test_record_survives_bad_log_path(monkeypatch):
    # Point the log file at an unwritable path; record() must not raise.
    monkeypatch.setattr(audit, "DEFAULT_LOG_PATH", "/nonexistent-dir/x/audit.jsonl")
    entry = audit.record("e1", "ALT-1")
    assert entry["event"] == "e1"
