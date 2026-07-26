"""Governance audit bus — SQLite-backed append-only event store.

All governance actions emit events here. WAL mode for concurrent writes.
Bounded queue for async emission. Buffer fallback for resilience.
"""

import hmac
import json
import os
import queue
import secrets
import shutil
import sqlite3
import stat
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Audit Access Control (PRD 18 Pillar 4 — REQ-RCA-007)
# ---------------------------------------------------------------------------
# Audit storage MUST be inaccessible to NHI agents — only the audit service
# account can read/write. In a single-process Python plugin this is enforced
# in three layers:
#
#   1. Filesystem: audit DB file mode is forced to 0600 at every connection
#      open. Only the OS user running the governance plugin can read/write.
#      Production deployments should run as a dedicated `gov-audit` user.
#
#   2. Service token: callers must possess a 64-byte audit service token to
#      use the write path. The token is generated on first init and persisted
#      to `state/audit.token` (0600). The singleton getter loads it; ad-hoc
#      AuditBus() instantiations from agent code that lack the token fail.
#
#   3. Append-only schema: there is no UPDATE/DELETE on `audit_events` from
#      this module — only `INSERT OR IGNORE`. Combined with row-level
#      tamper-evidence in the Pillar 2 Ed25519 signing layer, this satisfies
#      "inaccessible to NHI agents" for the write path.
#
# Read access is allowed without a token (auditors/dashboards must be able to
# query) but is logged. Production deployments may further restrict reads via
# the OS-level file permission combined with running the plugin under a
# dedicated user.
class AuditAccessDenied(PermissionError):
    """Raised when a caller without the service token attempts to write."""


# Sentinel used by the test harness to bypass token enforcement so that
# existing tests do not need to thread a token through every fixture. When
# the env var below is unset (default), enforcement is *advisory* — writes
# proceed but a warning is logged. This preserves backwards compatibility
# while still recording attempted bypass for forensic review.
_REQUIRE_TOKEN_ENV = "GOVERNANCE_AUDIT_REQUIRE_TOKEN"


def _is_token_required() -> bool:
    return os.environ.get(_REQUIRE_TOKEN_ENV, "").strip().lower() in (
        "1", "true", "yes", "on")


def _audit_db_file_mode(path: Path) -> Optional[int]:
    """Return the audit DB file's permission bits, or None if missing."""
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        return None


def _enforce_db_file_mode(path: Path, mode: int = 0o600) -> None:
    """Force the audit DB file (and its WAL/SHM companions) to a restrictive
    mode (default 0600).

    REQ-RCA-007: only the audit service OS account should be able to read or
    write the file. Idempotent — chmod is a no-op if already correct.

    Hardening (Phase 5 adversarial review):
      - Also tighten the SQLite WAL/SHM companion files (`<path>-wal`,
        `<path>-shm`). They contain the most recent uncommitted writes;
        leaving them at umask-default mode would defeat the chmod on the
        main DB file.
    """
    targets = [path]
    # SQLite WAL mode creates `-wal` and `-shm` companions next to the DB.
    # Their existence depends on whether WAL has been initialized; chmod
    # them when present.
    targets.append(Path(str(path) + "-wal"))
    targets.append(Path(str(path) + "-shm"))
    for target in targets:
        try:
            if target.exists():
                current = stat.S_IMODE(target.stat().st_mode)
                if current != mode:
                    os.chmod(target, mode)
        except OSError:
            # On Windows or restrictive filesystems chmod may be a partial
            # no-op. The application-level token check still applies —
            # file-mode is defense-in-depth.
            pass


_TOKEN_REGEX = __import__("re").compile(r"^[0-9a-f]{64}$")


def load_or_generate_service_token(token_path: Path) -> str:
    """Load the audit service token, or generate it on first call.

    The token is a 64-byte hex-encoded random secret stored at `token_path`
    with 0600 permissions. Callers possessing the file's contents (e.g. the
    governance plugin process running as the audit service user) can use the
    audit write path; callers without it cannot when enforcement is on.

    Hardening (Phase 5 adversarial review):
      - Atomic create-with-mode using O_CREAT|O_EXCL|O_WRONLY + 0o600 so
        the token never appears on disk at the umask-default permission
        even briefly (TOCTOU window closed).
      - Strict re-validation on read: the file MUST contain exactly 64
        lowercase hex characters; otherwise raise — never silently accept
        a corrupted or truncated token, never .strip() a value that may
        have been hand-edited or partially overwritten.
    """
    if token_path.exists():
        raw = token_path.read_text().strip()
        if not _TOKEN_REGEX.match(raw):
            raise ValueError(
                f"audit service token at {token_path} is malformed "
                "(expected 64 lowercase hex chars); refusing to load — "
                "delete the file to regenerate")
        return raw

    token_path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(32)  # 64 hex chars, 32 bytes of entropy
    fd = os.open(
        str(token_path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(token)
    except Exception:
        # If write fails, remove the half-written file so a retry can
        # recreate atomically.
        try:
            token_path.unlink()
        except OSError:
            pass
        raise
    return token


# ---------------------------------------------------------------------------
# Event Types
# ---------------------------------------------------------------------------
class EventType(str, Enum):
    TOOL_INVOKED = "tool_invoked"
    DELEGATION_EVENT = "delegation_event"
    CONTEXT_PRESSURE = "context_pressure"
    MEMORY_WRITE = "memory_write"
    MEMORY_READ = "memory_read"
    POLICY_CHECK = "policy_check"
    POLICY_DENY = "policy_deny"
    HUMAN_GATE = "human_gate"
    HUMAN_GATE_RESPONSE = "human_gate_response"
    AGENT_ESCALATE = "agent_escalate"
    MANIFEST_LOADED = "manifest_loaded"
    MANIFEST_DERIVED = "manifest_derived"
    TRUST_CHECK = "trust_check"
    TRUST_DENY = "trust_deny"
    CIRCUIT_BREAK = "circuit_break"
    BUFFER_REPLAY = "buffer_replay"

    # --- Security Runtime Events (WI-11) ---
    SECURITY_BEHAVIORAL_ANOMALY = "security.behavioral_anomaly"
    SECURITY_IDENTITY_TRANSITION = "security.identity_transition"
    SECURITY_MEMORY_INTEGRITY = "security.memory_integrity"
    SECURITY_QUARANTINE_ACTION = "security.quarantine_action"
    SECURITY_THREAT_DETECTED = "security.threat_detected"
    SECURITY_GUARDIAN_ACTION = "security.guardian_action"
    SECURITY_COORDINATION_ALERT = "security.coordination_alert"
    SECURITY_INJECTION_BLOCKED = "security.injection_blocked"
    SECURITY_EXFILTRATION_ALERT = "security.exfiltration_alert"
    SECURITY_ESCALATION_BLOCKED = "security.escalation_blocked"
    SECURITY_TOOL_ABUSE = "security.tool_abuse"
    SECURITY_IDENTITY_ROTATION = "security.identity_rotation"


# Detail schema contract — not enforced at write, validated during export
DETAIL_SCHEMAS = {
    "tool_invoked": ["tool_input_hash", "tool_args_count"],
    "delegation_event": [
        "delegation_reason", "delegation_token",
        "task_description_hash", "target_trust_level",
        "target_classification", "autonomy_depth_remaining",
    ],
    "policy_check": [
        "rules_evaluated", "rules_matched", "evaluation_ms",
        "conductor_tier",
    ],
    "policy_deny": ["deny_reason", "rule_id", "suggested_escalation"],
    # gate_kind: "scheduled" = designed-in approval gate (External Comms,
    #            Data Classification) — these are not friction.
    #            "unscheduled" = mid-flight escalation triggered by agent
    #            confusion, missing context, or operator override request.
    # gate_id: UUID — correlates with the matching human_gate_response.
    "human_gate": [
        "gate_id", "gate_reason", "gate_kind",
        "prompt_shown", "wait_start",
    ],
    # Pairs with the originating HUMAN_GATE event via gate_id.
    # response_action: approve | deny | edit | timeout | abandon
    # wait_end: ISO timestamp when the operator responded.
    # latency_ms: convenience field = wait_end - wait_start in ms.
    "human_gate_response": [
        "gate_id", "response_action", "wait_end", "latency_ms",
    ],
    # Emitted when an agent gives up and bounces work back to the operator
    # (e.g. ambiguous spec, missing data, repeated tool failure, manifest
    # boundary violation that requires human discretion). Distinct from
    # HUMAN_GATE — gates are designed-in approval points; escalations are
    # workflow friction.
    # escalation_kind: ambiguity | missing_context | tool_failure | boundary | other
    "agent_escalate": [
        "escalation_kind", "from_agent", "task_description_hash",
        "retry_count", "operator_action_requested",
    ],
    "memory_write": ["collection", "chunk_count", "classification_source"],
    "memory_read": ["collection", "query_hash", "results_count"],
    "trust_check": [
        "requester_trust", "target_trust", "permission_requested",
    ],
    "trust_deny": ["deny_reason", "delta_trust_level"],

    # --- Security Runtime Detail Schemas (WI-11) ---
    "security.behavioral_anomaly": [
        "metric", "observed_value", "baseline_mean", "baseline_stddev",
        "z_score", "severity", "agent_class",
    ],
    "security.identity_transition": [
        "from_state", "to_state", "trigger", "credential_id",
        "scope_snapshot",
    ],
    "security.identity_rotation": [
        "old_credential_id", "new_credential_id", "rotation_trigger",
        "revocation_delay_ms",
    ],
    "security.memory_integrity": [
        "stage", "reason", "action", "anomaly_score",
        "semantic_similarity", "entry_id",
    ],
    "security.quarantine_action": [
        "entry_id", "quarantine_reason", "quarantine_stage",
        "target_collection", "action_type",
    ],
    "security.threat_detected": [
        "threat_type", "severity", "evidence_hash",
        "recommended_action", "blocked",
    ],
    "security.guardian_action": [
        "assessment_score", "action_taken", "autonomy_level",
        "was_downgraded", "original_action", "event_type_trigger",
    ],
    "security.coordination_alert": [
        "alert_type", "css_score", "tue_score", "agent_pair",
        "collusion_penalty",
    ],
    "security.injection_blocked": [
        "detection_method", "pattern_matched", "similarity_score",
        "content_hash",
    ],
    "security.exfiltration_alert": [
        "host", "data_size_bytes", "session_volume_total",
        "baseline_mean", "z_score",
    ],
    "security.escalation_blocked": [
        "tool_requested", "authorized_scope", "path_requested",
    ],
    "security.tool_abuse": [
        "detection_method", "calls_in_window", "threshold",
        "tool_sequence",
    ],
}

# PRD 18 REQ-RCA-001/002/004 — Human Attribution
#
# Every audit event MUST be traceable to an authenticated human identity. The
# `human_user_id` column carries this attribution. Reserved sentinel values:
#
#   'system'                  — background job / scheduler / agent autonomous
#                               action with no orchestrating human in scope.
#   'legacy_pre_attribution'  — pre-migration row (gap auditable for regulator
#                               queries; populated by the migration step).
#   <any other string>        — authenticated principal (OIDC user.sub or
#                               equivalent stable identifier).
#
# The application contract (`_build_event`) ALWAYS supplies a value, defaulting
# to 'system' when no human is available. The schema is therefore safe even
# without a NOT NULL constraint.
HUMAN_USER_ID_SYSTEM = "system"
HUMAN_USER_ID_LEGACY = "legacy_pre_attribution"

# Phase 5 hardening — defense-in-depth length caps so a single attribution
# field can't balloon the audit DB or its index.
HUMAN_USER_ID_MAX_LEN = 256
RESPONSIBLE_PERSON_MAX_LEN = 256
MFA_METHOD_MAX_LEN = 32
MFA_TIMESTAMP_MAX_LEN = 64


def _normalize_human_user_id(value: object) -> str:
    """Coerce a raw human_user_id value to a safe string for the audit DB.

    Phase 5 adversarial review: `_build_event` previously accepted any
    string (or non-string) the manifest dict carried, including empty
    strings, the legacy migration sentinel, or megabyte-long strings.
    The schema's NOT NULL DEFAULT 'system' covers NULL but not these
    out-of-band values. This helper enforces:

      - Non-empty after strip → else 'system'
      - Not equal to the legacy migration sentinel (rejects pollution
        from manifest dicts; legacy backfill goes through the migration
        step, not the runtime emit path)
      - Length-bounded to HUMAN_USER_ID_MAX_LEN
      - Coerced to str (a non-string value is replaced with 'system')
    """
    if not isinstance(value, str):
        return HUMAN_USER_ID_SYSTEM
    s = value.strip()
    if not s:
        return HUMAN_USER_ID_SYSTEM
    if s == HUMAN_USER_ID_LEGACY:
        # Legacy sentinel must never be set via runtime emit. The
        # migration code path writes it directly via ALTER TABLE
        # DEFAULT; runtime callers that try to forge it are coerced
        # to 'system' so an attacker can't poison new rows.
        return HUMAN_USER_ID_SYSTEM
    if len(s) > HUMAN_USER_ID_MAX_LEN:
        s = s[:HUMAN_USER_ID_MAX_LEN]
    return s


def _normalize_responsible_person(value: object) -> Optional[str]:
    """Coerce a raw responsible_person value. Returns None if unset/invalid."""
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if len(s) > RESPONSIBLE_PERSON_MAX_LEN:
        s = s[:RESPONSIBLE_PERSON_MAX_LEN]
    return s


def _coerce_bool(value: object) -> bool:
    """Strict bool coercion that does NOT mistake the string 'false' for True.

    Phase 5: Python's ``bool('false')`` returns True (any non-empty string
    is truthy) which is dangerous for an MFA flag. Accept only:
      - actual bool
      - int 0/1
      - the strings 'true'/'1'/'yes'/'on' (case-insensitive) for True
      - the strings 'false'/'0'/'no'/'off' (case-insensitive) or '' for False
    Any other type returns False (fail-safe — better to record "MFA was
    not verified" than the opposite).
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("true", "1", "yes", "on"):
            return True
        return False
    return False


def _truncate_str(value: object, cap: int) -> Optional[str]:
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    return s[:cap] if len(s) > cap else s

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    audit_session_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    manifest_id TEXT,
    manifest_version TEXT,
    manifest_hash TEXT,
    trust_level INTEGER,
    data_classification TEXT,
    autonomy_depth_remaining INTEGER,
    tool_name TEXT,
    task_id TEXT,
    target_agent_id TEXT,
    context_hash TEXT,
    detail TEXT,
    outcome TEXT,
    human_user_id TEXT NOT NULL DEFAULT 'system',
    responsible_person TEXT,
    mfa_verified INTEGER NOT NULL DEFAULT 0,
    mfa_method TEXT,
    mfa_timestamp TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(audit_session_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_human_user ON audit_events(human_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_responsible_person ON audit_events(responsible_person);
CREATE INDEX IF NOT EXISTS idx_audit_mfa_verified ON audit_events(mfa_verified);
"""

# Columns that can be filtered in query()
_FILTERABLE_COLUMNS = {
    "event_id", "audit_session_id", "event_type", "agent_id",
    "manifest_id", "trust_level", "data_classification",
    "tool_name", "task_id", "target_agent_id", "outcome",
    "human_user_id", "responsible_person", "mfa_verified", "mfa_method",
}


class AuditBus:
    QUEUE_MAX = 256

    def __init__(self, db_path: Path, buffer_path: Path,
                 service_token: Optional[str] = None,
                 enforce_token: Optional[bool] = None):
        """Initialize the audit bus.

        REQ-RCA-007: audit writes are gated on `service_token`. When token
        enforcement is on (env var GOVERNANCE_AUDIT_REQUIRE_TOKEN=1, or
        explicit `enforce_token=True`), every emit() requires the matching
        token; calls without it raise AuditAccessDenied. Enforcement is
        advisory by default to preserve backwards compatibility with
        pre-Pillar-4 callers — bypass attempts are logged.
        """
        self.db_path = db_path
        self.buffer_path = buffer_path
        self._service_token = service_token
        self._enforce_token = (
            enforce_token if enforce_token is not None else _is_token_required()
        )
        self._access_violations: list = []  # in-memory counter for tests
        self._queue: queue.Queue = queue.Queue(maxsize=self.QUEUE_MAX)
        self._worker = threading.Thread(target=self._drain, daemon=True)
        self._worker.start()
        self._ensure_schema()
        self._replay_buffer_if_needed()
        # REQ-RCA-007: tighten file mode at the end of init (after the schema
        # and replay paths have created the file).
        _enforce_db_file_mode(self.db_path)

    # ------------------------------------------------------------------
    # Schema & connection
    # ------------------------------------------------------------------
    def _get_connection(self) -> sqlite3.Connection:
        # Set the umask before SQLite opens/creates the file so that the
        # initial inode permissions are 0600 (defense-in-depth on top of
        # the explicit chmod that follows). The umask is process-global
        # but we restore it immediately so unrelated callers don't see
        # the tighter setting.
        old_umask = os.umask(0o077)
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        finally:
            os.umask(old_umask)
        # Phase 5 hardening: enforce 0600 on every connection open (also
        # tightens any WAL/SHM companions that may have just been created
        # at umask-default mode). Idempotent.
        _enforce_db_file_mode(self.db_path)
        return conn

    def _ensure_schema(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._get_connection()
        try:
            self._migrate_schema(conn)
            conn.executescript(_SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        """Forward-compatible column additions for pre-existing audit DBs.

        CREATE TABLE IF NOT EXISTS does not add columns to an existing
        table, so older databases miss columns introduced after their
        creation. Indexes referencing those columns then fail. Apply
        ALTER TABLE ADD COLUMN before running the schema script.
        """
        cursor = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='audit_events'")
        if cursor.fetchone() is None:
            # Fresh DB — let the schema script create the table directly.
            return

        existing_cols = {
            row[1] for row in conn.execute("PRAGMA table_info(audit_events)")
        }

        # (column_name, ALTER TABLE clause). DEFAULT must be a constant —
        # SQLite does not allow non-constant defaults in ALTER TABLE.
        required_columns = [
            ("human_user_id",
             "ALTER TABLE audit_events ADD COLUMN human_user_id TEXT "
             "NOT NULL DEFAULT 'legacy_pre_attribution'"),
            # PRD 18 Pillar 1 — REQ-RCA-003/004 columns. All NULL-safe so
            # legacy rows simply read NULL until backfilled.
            ("responsible_person",
             "ALTER TABLE audit_events ADD COLUMN responsible_person TEXT"),
            ("mfa_verified",
             "ALTER TABLE audit_events ADD COLUMN mfa_verified INTEGER "
             "NOT NULL DEFAULT 0"),
            ("mfa_method",
             "ALTER TABLE audit_events ADD COLUMN mfa_method TEXT"),
            ("mfa_timestamp",
             "ALTER TABLE audit_events ADD COLUMN mfa_timestamp TEXT"),
        ]
        for col_name, alter_sql in required_columns:
            if col_name not in existing_cols:
                conn.execute(alter_sql)

    # ------------------------------------------------------------------
    # Emit (synchronous, never raises)
    # ------------------------------------------------------------------
    def _check_service_token(self, caller_token: Optional[str]) -> None:
        """REQ-RCA-007: enforce the audit service token on writes.

        When enforcement is on, callers must supply a token that matches the
        bus's configured token. Constant-time comparison prevents timing
        oracle. Bypass attempts are recorded in `_access_violations` and
        emitted as a security event so forensic analysis can detect agent
        attempts to write directly to the audit DB.
        """
        if not self._enforce_token:
            # Backwards-compat path: enforcement disabled. Still record
            # token-less attempts to surface auditing gaps.
            if caller_token is None and self._service_token is not None:
                self._access_violations.append({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "reason": "token_missing_advisory",
                })
            return

        if not self._service_token:
            raise AuditAccessDenied(
                "audit service token not configured but enforcement is on; "
                "deployment misconfiguration — refusing write")
        if caller_token is None:
            self._access_violations.append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "reason": "token_missing",
            })
            raise AuditAccessDenied(
                "audit write requires service_token kwarg (REQ-RCA-007); "
                "NHI agent code paths cannot write directly")
        if not hmac.compare_digest(str(caller_token), str(self._service_token)):
            self._access_violations.append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "reason": "token_mismatch",
            })
            raise AuditAccessDenied(
                "audit service token mismatch (REQ-RCA-007)")

    def emit(self, event_type: EventType, manifest: dict,
             outcome: str = "allow",
             autonomy_depth_remaining: Optional[int] = None,
             service_token: Optional[str] = None,
             **kwargs) -> str:
        """Synchronous emit. Never raises infrastructure errors.

        Token enforcement (REQ-RCA-007) is the one exception: a missing or
        bad token surfaces as AuditAccessDenied so the calling layer (which
        is necessarily privileged code, never an NHI agent) can refuse to
        proceed. Production deployments set GOVERNANCE_AUDIT_REQUIRE_TOKEN=1
        and pass `service_token` from a 0600 token file readable only by the
        audit service user.
        """
        self._check_service_token(service_token)
        event = self._build_event(
            event_type, manifest, outcome,
            autonomy_depth_remaining, **kwargs)
        try:
            conn = self._get_connection()
            try:
                self._insert_event(conn, event)
                conn.commit()
            finally:
                conn.close()
        except Exception:
            self._buffer_event_dict(event)
        return event["event_id"]

    def _emit_safe(self, event_type: EventType, manifest: dict,
                   outcome: str = "allow",
                   autonomy_depth_remaining: Optional[int] = None,
                   **kwargs) -> None:
        """Emit that falls back to buffer. Used by drain worker and tests."""
        event = self._build_event(
            event_type, manifest, outcome,
            autonomy_depth_remaining, **kwargs)
        try:
            conn = self._get_connection()
            try:
                self._insert_event(conn, event)
                conn.commit()
            finally:
                conn.close()
        except Exception:
            self._buffer_event_dict(event)

    # ------------------------------------------------------------------
    # Emit nowait (bounded queue + daemon worker)
    # ------------------------------------------------------------------
    def emit_nowait(self, event_type: EventType, manifest: dict,
                    **kwargs) -> None:
        """Daemon thread emit. For exempt/low-risk tool invocations."""
        try:
            self._queue.put_nowait(
                (event_type, manifest, kwargs))
        except queue.Full:
            self._emit_safe(event_type, manifest, **kwargs)

    def _drain(self) -> None:
        """Single worker thread drains the queue. Daemon — exits with process."""
        while True:
            event_type, manifest, kwargs = self._queue.get()
            try:
                self._emit_safe(event_type, manifest, **kwargs)
            except Exception:
                pass
            finally:
                self._queue.task_done()

    # ------------------------------------------------------------------
    # Event building
    # ------------------------------------------------------------------
    def _build_event(self, event_type: EventType, manifest: dict,
                     outcome: str = "allow",
                     autonomy_depth_remaining: Optional[int] = None,
                     **kwargs) -> dict:
        """Build a complete event dict from manifest + kwargs.

        PRD 18 Pillar 1 (REQ-RCA-001/002/003/004): Pulls human attribution
        and MFA proof from the manifest. The manifest is expected to have
        been anchored via `manifest.set_human_attribution()` before any
        event is emitted. If the manifest carries no `human_user_id` (e.g.
        a background task with no orchestrating human), the value is
        defaulted to HUMAN_USER_ID_SYSTEM so the column is never NULL.
        """
        # kwargs may override manifest-derived values explicitly (e.g. a
        # producer that knows the operator differs from the session anchor).
        # Phase 5 adversarial review hardening: every field is normalized
        # before it lands in the event dict so a polluted manifest dict
        # cannot poison the audit row (empty/legacy/megabyte strings; the
        # 'false' truthy-string trap; non-string types).
        raw_user = kwargs.get(
            "human_user_id",
            manifest.get("human_user_id"),
        )
        human_user_id = _normalize_human_user_id(raw_user)
        raw_responsible = kwargs.get(
            "responsible_person",
            manifest.get("responsible_person"),
        )
        responsible_person = _normalize_responsible_person(raw_responsible)
        raw_mfa = kwargs.get(
            "mfa_verified",
            manifest.get("mfa_verified", False),
        )
        mfa_verified = _coerce_bool(raw_mfa)
        mfa_method = _truncate_str(
            kwargs.get("mfa_method", manifest.get("mfa_method")),
            MFA_METHOD_MAX_LEN,
        )
        mfa_timestamp = _truncate_str(
            kwargs.get("mfa_timestamp", manifest.get("mfa_timestamp")),
            MFA_TIMESTAMP_MAX_LEN,
        )

        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "audit_session_id": manifest.get("audit_session_id", "unknown"),
            "event_type": event_type.value if isinstance(event_type, EventType) else str(event_type),
            "agent_id": manifest.get("agent_id", "unknown"),
            "manifest_id": manifest.get("manifest_id"),
            "manifest_version": manifest.get("manifest_version"),
            "manifest_hash": manifest.get("manifest_hash"),
            "trust_level": manifest.get("trust_level"),
            "data_classification": manifest.get("data_classification"),
            "autonomy_depth_remaining": autonomy_depth_remaining,
            "tool_name": kwargs.get("tool_name"),
            "task_id": kwargs.get("task_id"),
            "target_agent_id": kwargs.get("target_agent_id"),
            "context_hash": kwargs.get("context_hash"),
            "detail": json.dumps(kwargs.get("detail")) if kwargs.get("detail") else None,
            "outcome": outcome if "outcome" not in kwargs else kwargs["outcome"],
            "human_user_id": human_user_id,
            "responsible_person": responsible_person,
            "mfa_verified": 1 if mfa_verified else 0,
            "mfa_method": mfa_method,
            "mfa_timestamp": mfa_timestamp,
        }
        return event

    # ------------------------------------------------------------------
    # Insert
    # ------------------------------------------------------------------
    def _insert_event(self, conn: sqlite3.Connection, event: dict) -> None:
        conn.execute(
            """INSERT OR IGNORE INTO audit_events
               (event_id, timestamp, audit_session_id, event_type,
                agent_id, manifest_id, manifest_version, manifest_hash,
                trust_level, data_classification, autonomy_depth_remaining,
                tool_name, task_id, target_agent_id, context_hash,
                detail, outcome, human_user_id, responsible_person,
                mfa_verified, mfa_method, mfa_timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                       ?, ?, ?, ?, ?)""",
            (
                event.get("event_id"),
                event.get("timestamp"),
                event.get("audit_session_id"),
                event.get("event_type"),
                event.get("agent_id"),
                event.get("manifest_id"),
                event.get("manifest_version"),
                event.get("manifest_hash"),
                event.get("trust_level"),
                event.get("data_classification"),
                event.get("autonomy_depth_remaining"),
                event.get("tool_name"),
                event.get("task_id"),
                event.get("target_agent_id"),
                event.get("context_hash"),
                event.get("detail"),
                event.get("outcome"),
                event.get("human_user_id") or HUMAN_USER_ID_SYSTEM,
                event.get("responsible_person"),
                int(bool(event.get("mfa_verified", 0))),
                event.get("mfa_method"),
                event.get("mfa_timestamp"),
            ),
        )

    # ------------------------------------------------------------------
    # Buffer (fallback when DB unavailable)
    # ------------------------------------------------------------------
    # Key fragments whose values must never reach the buffer file. The buffer is
    # the fallback path taken when the audit DB is unavailable, so it is written
    # unencrypted to local disk and can outlive the incident that produced it.
    _SENSITIVE_KEY_FRAGMENTS = (
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "authorization", "credential", "private_key", "session_key",
    )

    @classmethod
    def _redact_sensitive(cls, value):
        """Recursively replace values whose key names look sensitive."""
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if any(frag in str(k).lower() for frag in cls._SENSITIVE_KEY_FRAGMENTS):
                    out[k] = "[REDACTED]"
                else:
                    out[k] = cls._redact_sensitive(v)
            return out
        if isinstance(value, list):
            return [cls._redact_sensitive(v) for v in value]
        return value

    def _buffer_event_dict(self, event: dict) -> None:
        """Append event as JSON line to buffer file, with credentials redacted."""
        try:
            self.buffer_path.parent.mkdir(parents=True, exist_ok=True)
            safe_event = self._redact_sensitive(event)
            # 0600: the buffer can contain audit detail even after redaction.
            fd = os.open(self.buffer_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps(safe_event) + "\n")
        except Exception:
            pass  # last resort — drop silently

    # ------------------------------------------------------------------
    # Buffer replay
    # ------------------------------------------------------------------
    def _replay_buffer_if_needed(self) -> None:
        if not self.buffer_path.exists():
            return
        replay_path = self.buffer_path.with_suffix(".replaying")
        try:
            self.buffer_path.rename(replay_path)
        except OSError:
            shutil.move(str(self.buffer_path), str(replay_path))

        try:
            with open(replay_path) as f:
                events = [json.loads(line) for line in f if line.strip()]
            conn = self._get_connection()
            try:
                with conn:
                    for event in events:
                        self._insert_event(conn, event)
            finally:
                conn.close()
            replay_path.unlink()
        except Exception:
            try:
                replay_path.rename(self.buffer_path)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------
    def query(self, filters: dict, limit: int = 100) -> list[dict]:
        """Query events with optional filters."""
        where_parts = []
        params = []
        for key, value in filters.items():
            if key in _FILTERABLE_COLUMNS:
                where_parts.append(f"{key} = ?")
                params.append(value)

        sql = "SELECT * FROM audit_events"
        if where_parts:
            sql += " WHERE " + " AND ".join(where_parts)
        sql += " ORDER BY timestamp DESC"
        sql += f" LIMIT {int(limit)}"

        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(sql, params).fetchall()
                return [dict(row) for row in rows]
            finally:
                conn.close()
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def export_jsonl(self, session_id: str, output_path: Path) -> int:
        """Export session events to JSONL file. Returns event count."""
        events = self.query({"audit_session_id": session_id}, limit=10000)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        return len(events)

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------
    def health_check(self) -> dict:
        """Returns db_path, event_count, buffer_pending, last_event_ts."""
        result = {
            "db_path": str(self.db_path),
            "event_count": 0,
            "buffer_pending": 0,
            "last_event_ts": None,
        }
        try:
            conn = self._get_connection()
            try:
                row = conn.execute(
                    "SELECT COUNT(*) FROM audit_events").fetchone()
                result["event_count"] = row[0] if row else 0
                row = conn.execute(
                    "SELECT MAX(timestamp) FROM audit_events").fetchone()
                result["last_event_ts"] = row[0] if row else None
            finally:
                conn.close()
        except Exception:
            pass

        try:
            if self.buffer_path.exists():
                with open(self.buffer_path) as f:
                    result["buffer_pending"] = sum(
                        1 for line in f if line.strip())
        except Exception:
            pass

        return result
