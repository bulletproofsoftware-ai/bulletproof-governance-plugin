"""Thin read-only HITL (human-in-the-loop) audit API.

Exposes the governance approval-gate audit trail (``human_gate`` /
``human_gate_response`` events in ``state/audit.db``) over a small HTTP
surface so an external console (e.g. AgentHR) can DISPLAY it.

This API is deliberately **read-only**. The governance gate has no external
control point: the actual approval is Claude Code's own in-session permission
prompt, and ``hooks/post_tool_metrics.py`` records the ``human_gate_response``
post-hoc (heuristically inferred) purely for latency/audit metrics. Nothing
blocks on or polls ``audit.db`` for an external decision, so a write-back
"approve/deny" endpoint would be a fake control. We therefore expose only
observability — gates, their resolution, and latency.

Endpoints (all require ``Authorization: Bearer <GOVERNANCE_HITL_TOKEN>``):
  GET /hitl/health        -> {status, db_path, gate_count, pending_count}
  GET /hitl/gates?limit=N -> recent gates, paired with their response + latency
  GET /hitl/pending       -> gates with no recorded response (unresolved)

Config (env):
  GOVERNANCE_HITL_TOKEN   shared bearer token. REQUIRED — when unset the API
                          fails closed (401 on every request).
  GOVERNANCE_HITL_PORT    listen port (default 8126).
  GOVERNANCE_HITL_HOST    bind host (default 127.0.0.1).
  GOVERNANCE_AUDIT_DB     audit.db path (default <plugin>/state/audit.db).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("hitl_api")

DEFAULT_PORT = 8126
DEFAULT_HOST = "127.0.0.1"
MAX_LIMIT = 500
DEFAULT_LIMIT = 100


def _plugin_root() -> Path:
    # governance/lib/hitl_api.py -> repo root is two parents up from lib.
    return Path(__file__).resolve().parents[2]


def _audit_db_path() -> Path:
    override = os.environ.get("GOVERNANCE_AUDIT_DB")
    if override:
        return Path(override)
    return _plugin_root() / "state" / "audit.db"


def _expected_token() -> str | None:
    tok = os.environ.get("GOVERNANCE_HITL_TOKEN")
    return tok if tok else None


def _token_matches(presented: str, expected: str) -> bool:
    """Constant-time comparison (SHA-256 digests -> fixed length)."""
    a = hashlib.sha256(presented.encode("utf-8")).digest()
    b = hashlib.sha256(expected.encode("utf-8")).digest()
    return hmac.compare_digest(a, b)


def _connect_ro(db_path: Path) -> sqlite3.Connection:
    """Open the audit DB strictly read-only."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _safe_detail(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _responses_by_gate(conn: sqlite3.Connection, limit: int) -> dict[str, dict]:
    """Map gate_id -> response info from human_gate_response events.

    Scans a bounded window (a multiple of the requested gate limit) so a recent
    gate's response is found even when responses interleave with other events.
    """
    rows = conn.execute(
        "SELECT timestamp, outcome, detail FROM audit_events "
        "WHERE event_type = 'human_gate_response' "
        "ORDER BY id DESC LIMIT ?",
        (min(limit * 4, MAX_LIMIT * 4),),
    ).fetchall()
    out: dict[str, dict] = {}
    for r in rows:
        detail = _safe_detail(r["detail"])
        gate_id = detail.get("gate_id")
        if not gate_id or gate_id in out:
            continue
        out[gate_id] = {
            "response_action": detail.get("response_action") or r["outcome"],
            "latency_ms": detail.get("latency_ms"),
            "responded_at": r["timestamp"],
        }
    return out


def _gate_row(r: sqlite3.Row, responses: dict[str, dict]) -> dict:
    detail = _safe_detail(r["detail"])
    gate_id = detail.get("gate_id")
    resp = responses.get(gate_id) if gate_id else None
    return {
        "gate_id": gate_id,
        "gate_reason": detail.get("gate_reason"),
        "gate_kind": detail.get("gate_kind"),
        "conductor_tier": detail.get("conductor_tier"),
        "agent_id": r["agent_id"],
        "manifest_id": r["manifest_id"],
        "tool_name": r["tool_name"],
        "trust_level": r["trust_level"],
        "data_classification": r["data_classification"],
        "opened_at": r["timestamp"],
        "resolved": resp is not None,
        "response_action": resp["response_action"] if resp else None,
        "latency_ms": resp["latency_ms"] if resp else None,
        "responded_at": resp["responded_at"] if resp else None,
        "responsible_person": r["responsible_person"],
    }


def list_gates(db_path: Path, limit: int) -> list[dict]:
    limit = max(1, min(limit, MAX_LIMIT))
    with _connect_ro(db_path) as conn:
        responses = _responses_by_gate(conn, limit)
        rows = conn.execute(
            "SELECT timestamp, agent_id, manifest_id, tool_name, trust_level, "
            "data_classification, responsible_person, detail FROM audit_events "
            "WHERE event_type = 'human_gate' ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [_gate_row(r, responses) for r in rows]


def list_pending(db_path: Path, limit: int) -> list[dict]:
    return [g for g in list_gates(db_path, limit) if not g["resolved"]]


def health(db_path: Path) -> dict:
    try:
        with _connect_ro(db_path) as conn:
            gate_count = conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE event_type='human_gate'"
            ).fetchone()[0]
        pending_count = len(list_pending(db_path, MAX_LIMIT))
        return {
            "status": "ok",
            "db_path": str(db_path),
            "gate_count": gate_count,
            "pending_count": pending_count,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
    except sqlite3.Error as exc:
        return {"status": "unavailable", "db_path": str(db_path), "error": str(exc)}


class HitlHandler(BaseHTTPRequestHandler):
    server_version = "GovernanceHITL/1.0"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003 - stdlib hook
        logger.info("%s - %s", self.address_string(), fmt % args)

    def _send(self, status: int, payload: dict | list) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        expected = _expected_token()
        if not expected:
            # Fail closed: no token configured -> reject everything.
            return False
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        return _token_matches(header[7:], expected)

    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return

        db_path = _audit_db_path()
        try:
            if path == "/hitl/health":
                self._send(200, health(db_path))
            elif path == "/hitl/gates":
                limit = self._limit(parse_qs(parsed.query))
                self._send(200, {"gates": list_gates(db_path, limit)})
            elif path == "/hitl/pending":
                limit = self._limit(parse_qs(parsed.query))
                self._send(200, {"pending": list_pending(db_path, limit)})
            else:
                self._send(404, {"error": "not found"})
        except sqlite3.Error as exc:
            self._send(503, {"error": "audit db unavailable", "detail": str(exc)})

    @staticmethod
    def _limit(query: dict) -> int:
        try:
            return int(query.get("limit", [DEFAULT_LIMIT])[0])
        except (ValueError, TypeError):
            return DEFAULT_LIMIT


def run(host: str | None = None, port: int | None = None) -> None:
    host = host or os.environ.get("GOVERNANCE_HITL_HOST", DEFAULT_HOST)
    port = port or int(os.environ.get("GOVERNANCE_HITL_PORT", str(DEFAULT_PORT)))
    if not _expected_token():
        logger.warning(
            "GOVERNANCE_HITL_TOKEN is not set — the HITL API will reject every "
            "request (fail-closed). Set it before relying on this service."
        )
    logging.basicConfig(level=logging.INFO)
    server = ThreadingHTTPServer((host, port), HitlHandler)
    logger.info("HITL read-only API listening on http://%s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


if __name__ == "__main__":
    run()
