"""Tests for the thin read-only HITL audit API (governance/lib/hitl_api.py)."""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest

from governance.lib import hitl_api


def _make_db(tmp_path: Path) -> Path:
    """Build a minimal audit_events DB with two gates (one resolved, one not)."""
    db = tmp_path / "audit.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE audit_events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, timestamp TEXT, "
        "event_type TEXT, agent_id TEXT, manifest_id TEXT, tool_name TEXT, "
        "trust_level INTEGER, data_classification TEXT, "
        "responsible_person TEXT, outcome TEXT, detail TEXT)"
    )

    def ins(event_type: str, detail: dict, outcome: str = "", **cols) -> None:
        conn.execute(
            "INSERT INTO audit_events "
            "(event_id, timestamp, event_type, agent_id, manifest_id, tool_name, "
            "trust_level, data_classification, responsible_person, outcome, detail) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                cols.get("timestamp", "2026-06-20T00:00:00+00:00"),
                event_type,
                cols.get("agent_id", "agentA"),
                cols.get("manifest_id", "m1"),
                cols.get("tool_name", "ToolSearch"),
                cols.get("trust_level", 5),
                cols.get("data_classification", "restricted"),
                cols.get("responsible_person"),
                outcome,
                json.dumps(detail),
            ),
        )

    resolved_gate = "gate-resolved-0001"
    pending_gate = "gate-pending-0002"
    ins("human_gate", {"gate_id": resolved_gate, "gate_reason": "major_tier",
                       "gate_kind": "scheduled", "conductor_tier": "MAJOR"},
        outcome="escalate")
    ins("human_gate_response", {"gate_id": resolved_gate,
                                "response_action": "approve", "latency_ms": 4200},
        outcome="approve", timestamp="2026-06-20T00:00:04+00:00")
    ins("human_gate", {"gate_id": pending_gate, "gate_reason": "data_exfil",
                       "gate_kind": "unscheduled", "conductor_tier": "STANDARD"},
        outcome="escalate")
    conn.commit()
    conn.close()
    return db


def test_token_match_constant_time_true_false():
    assert hitl_api._token_matches("s3cret-token", "s3cret-token") is True
    assert hitl_api._token_matches("s3cret-token", "wrong") is False
    # Differing lengths must not raise (digests are fixed length).
    assert hitl_api._token_matches("short", "a-much-longer-token-value") is False


def test_list_gates_pairs_resolved_and_pending(tmp_path):
    db = _make_db(tmp_path)
    gates = hitl_api.list_gates(db, limit=50)
    assert len(gates) == 2
    by_id = {g["gate_id"]: g for g in gates}

    resolved = by_id["gate-resolved-0001"]
    assert resolved["resolved"] is True
    assert resolved["response_action"] == "approve"
    assert resolved["latency_ms"] == 4200
    assert resolved["gate_reason"] == "major_tier"
    assert resolved["conductor_tier"] == "MAJOR"

    pending = by_id["gate-pending-0002"]
    assert pending["resolved"] is False
    assert pending["response_action"] is None
    assert pending["latency_ms"] is None


def test_list_pending_returns_only_unresolved(tmp_path):
    db = _make_db(tmp_path)
    pending = hitl_api.list_pending(db, limit=50)
    assert [g["gate_id"] for g in pending] == ["gate-pending-0002"]


def test_health_counts(tmp_path):
    db = _make_db(tmp_path)
    h = hitl_api.health(db)
    assert h["status"] == "ok"
    assert h["gate_count"] == 2
    assert h["pending_count"] == 1


def test_health_unavailable_on_missing_db(tmp_path):
    h = hitl_api.health(tmp_path / "nonexistent.db")
    assert h["status"] == "unavailable"


def test_connect_is_read_only(tmp_path):
    db = _make_db(tmp_path)
    conn = hitl_api._connect_ro(db)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("INSERT INTO audit_events (event_type) VALUES ('x')")
    conn.close()
