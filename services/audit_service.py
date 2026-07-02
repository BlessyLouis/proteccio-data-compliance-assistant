"""
audit_service.py
------------------
Structured audit trail for compliance-sensitive actions: uploads,
detections, risk assessments, chat queries, and redaction actions.

Logs are stored as JSON lines in logs/audit.log (append-only), which
keeps them simple to parse for the Audit Logs dashboard page while
still being human-readable.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Optional

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
AUDIT_LOG_PATH = os.path.join(LOG_DIR, "audit.log")

EVENT_TYPES = (
    "UPLOAD",
    "DETECTION",
    "RISK_ASSESSMENT",
    "CHAT_QUERY",
    "REDACTION",
    "REPORT_EXPORT",
)


def log_event(event_type: str, session_id: str, details: Optional[dict] = None) -> None:
    """Append a structured audit event as a JSON line."""
    if event_type not in EVENT_TYPES:
        event_type = "UNKNOWN"

    entry = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "event_type": event_type,
        "session_id": session_id,
        "details": details or {},
    }

    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_audit_log(limit: int = 200) -> list[dict]:
    """Return the most recent `limit` audit events, newest first."""
    if not os.path.exists(AUDIT_LOG_PATH):
        return []

    entries = []
    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    entries.reverse()
    return entries[:limit]


def clear_audit_log() -> None:
    """Clear the audit log file (used for demo/reset purposes)."""
    open(AUDIT_LOG_PATH, "w").close()
