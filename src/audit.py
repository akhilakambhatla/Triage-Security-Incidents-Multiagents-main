"""Audit trail for the triage pipeline.

Design note: rather than a dedicated LangGraph node (which would only see
whichever state happened to be current when it ran), auditing is a
cross-cutting concern invoked from *inside* every node. This is the same
pattern you'd use for structured logging in a real SOC pipeline — every
node calls ``record()`` right before returning, so the audit trail captures
one entry per state transition in execution order, including the alert ID,
the deciding agent, and the key fields that drove that decision.

Entries are kept in memory (``get_audit_trail`` / ``clear_audit_trail``, used
by tests and the demo) and also appended as JSON lines to a log file so they
survive process restarts. Set ``AUDIT_LOG_PATH`` to control the file location;
set it to the empty string to disable file writes entirely (useful in tests).
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone

_LOCK = threading.Lock()
_AUDIT_TRAIL: list[dict] = []

DEFAULT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "audit_log.jsonl")


def record(event: str, alert_id: str, **fields) -> dict:
    """Record one audit entry and return it.

    Args:
        event: short machine-readable event name, e.g. "classification_complete".
        alert_id: the alert this entry relates to.
        **fields: any additional structured context (severity, reasoning, etc.).
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "alert_id": alert_id,
        **fields,
    }

    with _LOCK:
        _AUDIT_TRAIL.append(entry)
        if DEFAULT_LOG_PATH:
            try:
                with open(DEFAULT_LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
            except OSError:
                # Never let audit-log I/O failures break the triage pipeline.
                pass

    return entry


def get_audit_trail(alert_id: str | None = None) -> list[dict]:
    """Return recorded entries, optionally filtered to a single alert."""
    with _LOCK:
        if alert_id is None:
            return list(_AUDIT_TRAIL)
        return [e for e in _AUDIT_TRAIL if e["alert_id"] == alert_id]


def clear_audit_trail() -> None:
    """Clear the in-memory trail (used by tests)."""
    with _LOCK:
        _AUDIT_TRAIL.clear()
