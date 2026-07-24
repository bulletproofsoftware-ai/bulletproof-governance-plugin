# tests/test_audit_bus.py
import json
import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def audit_paths(tmp_path):
    db = tmp_path / "audit.db"
    buf = tmp_path / "audit-buffer.json"
    return db, buf


@pytest.fixture
def sample_manifest():
    return {
        "agent_id": "conductor",
        "manifest_id": "gov-conductor",
        "manifest_version": "1.0.0",
        "manifest_hash": "abc123" * 10 + "abcd",
        "trust_level": 5,
        "data_classification": "internal",
        "audit_session_id": "sess-001",
    }


class TestAuditBusInit:
    def test_creates_db_with_schema(self, audit_paths):
        from governance.lib.audit_bus import AuditBus
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        assert db.exists()

    def test_wal_mode_enabled(self, audit_paths):
        import sqlite3
        from governance.lib.audit_bus import AuditBus
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        conn = sqlite3.connect(db)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        assert mode == "wal"


class TestEmit:
    def test_emit_returns_event_id(self, audit_paths, sample_manifest):
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        event_id = bus.emit(EventType.TOOL_INVOKED, sample_manifest,
                            tool_name="Read", outcome="allow")
        assert event_id is not None
        assert len(event_id) > 0

    def test_emit_stores_event(self, audit_paths, sample_manifest):
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        bus.emit(EventType.POLICY_DENY, sample_manifest,
                 tool_name="Bash", outcome="deny",
                 detail={"deny_reason": "tool_not_permitted"})
        events = bus.query({"audit_session_id": "sess-001"})
        assert len(events) == 1
        assert events[0]["event_type"] == "policy_deny"
        assert events[0]["outcome"] == "deny"

    def test_emit_decomposes_manifest(self, audit_paths, sample_manifest):
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        bus.emit(EventType.MANIFEST_LOADED, sample_manifest)
        events = bus.query({"audit_session_id": "sess-001"})
        e = events[0]
        assert e["agent_id"] == "conductor"
        assert e["manifest_id"] == "gov-conductor"
        assert e["trust_level"] == 5

    def test_emit_never_raises(self, sample_manifest):
        """Even with a bad db path, emit should not raise."""
        from governance.lib.audit_bus import AuditBus, EventType
        bad_path = Path("/nonexistent/dir/audit.db")
        buf = Path("/tmp/gov-test-buf.json")
        bus = AuditBus.__new__(AuditBus)
        bus.db_path = bad_path
        bus.buffer_path = buf
        bus._queue = None
        # Should not raise
        bus._emit_safe(EventType.TOOL_INVOKED, sample_manifest,
                       tool_name="Read", outcome="allow")
        # Should have buffered
        assert buf.exists()
        buf.unlink(missing_ok=True)


class TestQuery:
    def test_filter_by_event_type(self, audit_paths, sample_manifest):
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read")
        bus.emit(EventType.POLICY_DENY, sample_manifest, tool_name="Bash")
        bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Glob")
        results = bus.query({"event_type": "tool_invoked"})
        assert len(results) == 2

    def test_filter_by_agent_id(self, audit_paths, sample_manifest):
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read")
        other = sample_manifest.copy()
        other["agent_id"] = "builder"
        bus.emit(EventType.TOOL_INVOKED, other, tool_name="Write")
        results = bus.query({"agent_id": "conductor"})
        assert len(results) == 1

    def test_query_limit(self, audit_paths, sample_manifest):
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        for i in range(10):
            bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name=f"T{i}")
        results = bus.query({}, limit=3)
        assert len(results) == 3


class TestHealthCheck:
    def test_returns_stats(self, audit_paths, sample_manifest):
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read")
        health = bus.health_check()
        assert health["event_count"] == 1
        assert "db_path" in health
        assert health["buffer_pending"] == 0


class TestBufferReplay:
    def test_replay_on_init(self, audit_paths, sample_manifest):
        from governance.lib.audit_bus import AuditBus, EventType
        import uuid
        db, buf = audit_paths
        # Write a buffered event manually
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": "2026-03-04T12:00:00",
            "audit_session_id": "sess-001",
            "event_type": "tool_invoked",
            "agent_id": "conductor",
            "manifest_id": "gov-conductor",
            "manifest_version": "1.0.0",
            "manifest_hash": "abc",
            "trust_level": 5,
            "data_classification": "internal",
            "tool_name": "Read",
            "outcome": "allow",
        }
        buf.write_text(json.dumps(event) + "\n")
        # Init should replay
        bus = AuditBus(db_path=db, buffer_path=buf)
        events = bus.query({"audit_session_id": "sess-001"})
        assert len(events) == 1
        assert not buf.exists()  # buffer consumed


class TestExportJsonl:
    def test_export(self, audit_paths, sample_manifest, tmp_path):
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read")
        bus.emit(EventType.POLICY_DENY, sample_manifest, tool_name="Bash")
        out = tmp_path / "export.jsonl"
        count = bus.export_jsonl("sess-001", out)
        assert count == 2
        lines = out.read_text().strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "event_id" in parsed


class TestHumanAttribution:
    """PRD 18 Pillar 1 — REQ-RCA-001/002/003/004."""

    def test_default_human_user_id_is_system(self, audit_paths, sample_manifest):
        """REQ-RCA-002: every event has a non-NULL human_user_id."""
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read")
        events = bus.query({"audit_session_id": "sess-001"})
        assert len(events) == 1
        assert events[0]["human_user_id"] == "system"

    def test_attributed_manifest_writes_human_user_id(self, audit_paths,
                                                     sample_manifest):
        """REQ-RCA-001: human_user_id from manifest flows into audit row."""
        from governance.lib.audit_bus import AuditBus, EventType
        from governance.lib.manifest import set_human_attribution
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        attributed = set_human_attribution(sample_manifest,
                                           "alice@example.com",
                                           "alice@example.com")
        bus.emit(EventType.TOOL_INVOKED, attributed, tool_name="Read")
        events = bus.query({"audit_session_id": "sess-001"})
        assert events[0]["human_user_id"] == "alice@example.com"
        assert events[0]["responsible_person"] == "alice@example.com"

    def test_responsible_person_can_differ_from_user(self, audit_paths,
                                                    sample_manifest):
        """REQ-RCA-004: delegated execution — responsible_person != user."""
        from governance.lib.audit_bus import AuditBus, EventType
        from governance.lib.manifest import set_human_attribution
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        m = set_human_attribution(sample_manifest,
                                  human_user_id="oncall-operator-3",
                                  responsible_person="cto@company.com")
        bus.emit(EventType.TOOL_INVOKED, m, tool_name="Read")
        events = bus.query({"audit_session_id": "sess-001"})
        assert events[0]["human_user_id"] == "oncall-operator-3"
        assert events[0]["responsible_person"] == "cto@company.com"

    def test_mfa_attestation_flows_into_event(self, audit_paths,
                                              sample_manifest):
        """REQ-RCA-003: MFA proof recorded on confidential/restricted events."""
        from governance.lib.audit_bus import AuditBus, EventType
        from governance.lib.manifest import (set_human_attribution,
                                             set_mfa_attestation)
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        m = set_human_attribution(sample_manifest, "alice@example.com")
        m = set_mfa_attestation(m, method="webauthn",
                                timestamp="2026-05-02T13:00:00Z")
        bus.emit(EventType.TOOL_INVOKED, m, tool_name="Read")
        events = bus.query({"audit_session_id": "sess-001"})
        assert events[0]["mfa_verified"] == 1
        assert events[0]["mfa_method"] == "webauthn"
        assert events[0]["mfa_timestamp"] == "2026-05-02T13:00:00Z"

    def test_mfa_default_is_zero(self, audit_paths, sample_manifest):
        """Events without MFA attestation record mfa_verified=0."""
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read")
        events = bus.query({"audit_session_id": "sess-001"})
        assert events[0]["mfa_verified"] == 0
        assert events[0]["mfa_method"] is None
        assert events[0]["mfa_timestamp"] is None

    def test_filter_by_human_user_id(self, audit_paths, sample_manifest):
        """REQ-RCA-002: human_user_id is a queryable filter column."""
        from governance.lib.audit_bus import AuditBus, EventType
        from governance.lib.manifest import set_human_attribution
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        alice = set_human_attribution(sample_manifest, "alice@example.com")
        bob = set_human_attribution(sample_manifest, "bob@example.com")
        bus.emit(EventType.TOOL_INVOKED, alice, tool_name="Read")
        bus.emit(EventType.TOOL_INVOKED, bob, tool_name="Write")
        results = bus.query({"human_user_id": "alice@example.com"})
        assert len(results) == 1
        assert results[0]["tool_name"] == "Read"

    def test_filter_by_mfa_verified(self, audit_paths, sample_manifest):
        """REQ-RCA-003: mfa_verified is a queryable filter column."""
        from governance.lib.audit_bus import AuditBus, EventType
        from governance.lib.manifest import (set_human_attribution,
                                             set_mfa_attestation)
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        attributed = set_human_attribution(sample_manifest, "alice@example.com")
        bus.emit(EventType.TOOL_INVOKED, attributed, tool_name="Read")
        with_mfa = set_mfa_attestation(attributed, "totp",
                                       "2026-05-02T13:00:00Z")
        bus.emit(EventType.TOOL_INVOKED, with_mfa, tool_name="Bash")
        verified_only = bus.query({"mfa_verified": 1})
        assert len(verified_only) == 1
        assert verified_only[0]["tool_name"] == "Bash"

    def test_kwarg_override_takes_precedence(self, audit_paths,
                                             sample_manifest):
        """Producers may explicitly override per-emit attribution."""
        from governance.lib.audit_bus import AuditBus, EventType
        from governance.lib.manifest import set_human_attribution
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        attributed = set_human_attribution(sample_manifest, "alice@example.com")
        bus.emit(EventType.TOOL_INVOKED, attributed, tool_name="Read",
                 human_user_id="bob@example.com",
                 responsible_person="bob@example.com")
        events = bus.query({"audit_session_id": "sess-001"})
        assert events[0]["human_user_id"] == "bob@example.com"
        assert events[0]["responsible_person"] == "bob@example.com"

    def test_legacy_db_migrates_forward(self, tmp_path):
        """Old databases gain the new columns via ALTER TABLE on init."""
        import sqlite3
        # Build a legacy schema (pre-Pillar-1) with only the original columns.
        db = tmp_path / "legacy.db"
        buf = tmp_path / "buf.json"
        legacy = """
            CREATE TABLE audit_events (
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
                outcome TEXT
            );
        """
        conn = sqlite3.connect(db)
        conn.executescript(legacy)
        # Insert a pre-attribution row so we can verify it's preserved.
        conn.execute(
            "INSERT INTO audit_events (event_id, timestamp, audit_session_id, "
            "event_type, agent_id) VALUES (?, ?, ?, ?, ?)",
            ("legacy-1", "2025-01-01T00:00:00Z", "sess-legacy",
             "tool_invoked", "old-agent"))
        conn.commit()
        conn.close()

        from governance.lib.audit_bus import AuditBus
        bus = AuditBus(db_path=db, buffer_path=buf)
        cols = {row[1] for row in
                sqlite3.connect(db).execute("PRAGMA table_info(audit_events)")}
        assert "human_user_id" in cols
        assert "responsible_person" in cols
        assert "mfa_verified" in cols
        assert "mfa_method" in cols
        assert "mfa_timestamp" in cols
        # Legacy rows must read 'legacy_pre_attribution' so auditors can see
        # which rows pre-date Pillar 1.
        legacy_rows = bus.query({"audit_session_id": "sess-legacy"})
        assert len(legacy_rows) == 1
        assert legacy_rows[0]["human_user_id"] == "legacy_pre_attribution"
        assert legacy_rows[0]["mfa_verified"] == 0


class TestManifestHelpers:
    """Tests for manifest.set_human_attribution / set_mfa_attestation."""

    def test_set_human_attribution_defaults_responsible(self):
        from governance.lib.manifest import set_human_attribution
        m = {"agent_id": "x", "data_classification": "internal"}
        out = set_human_attribution(m, "alice@example.com")
        assert out["human_user_id"] == "alice@example.com"
        assert out["responsible_person"] == "alice@example.com"
        # original not mutated
        assert "human_user_id" not in m

    def test_set_human_attribution_rejects_legacy_sentinel(self):
        from governance.lib.manifest import set_human_attribution
        with pytest.raises(ValueError):
            set_human_attribution({"agent_id": "x"}, "legacy_pre_attribution")

    def test_set_human_attribution_rejects_empty(self):
        from governance.lib.manifest import set_human_attribution
        with pytest.raises(ValueError):
            set_human_attribution({"agent_id": "x"}, "")
        with pytest.raises(ValueError):
            set_human_attribution({"agent_id": "x"}, "   ")

    def test_set_mfa_attestation_validates_method(self):
        from governance.lib.manifest import set_mfa_attestation
        with pytest.raises(ValueError):
            set_mfa_attestation({"agent_id": "x"}, "magic_link",
                                "2026-05-02T13:00:00Z")

    def test_set_mfa_attestation_writes_fields(self):
        from governance.lib.manifest import set_mfa_attestation
        m = {"agent_id": "x"}
        out = set_mfa_attestation(m, "webauthn", "2026-05-02T13:00:00Z")
        assert out["mfa_verified"] is True
        assert out["mfa_method"] == "webauthn"
        assert out["mfa_timestamp"] == "2026-05-02T13:00:00Z"

    def test_is_mfa_required_for_classifications(self):
        from governance.lib.manifest import is_mfa_required
        assert is_mfa_required({"data_classification": "confidential"}) is True
        assert is_mfa_required({"data_classification": "restricted"}) is True
        assert is_mfa_required({"data_classification": "internal"}) is False
        assert is_mfa_required({"data_classification": "public"}) is False
        assert is_mfa_required({}) is False

    def test_propagation_through_enforce_parent_ceiling(self):
        from governance.lib.manifest import (enforce_parent_ceiling,
                                             set_human_attribution,
                                             set_mfa_attestation)
        parent = {
            "manifest_id": "parent", "audit_session_id": "sess-1",
            "trust_level": 4, "data_classification": "confidential",
            "max_autonomy_depth": 3, "human_required": True,
        }
        parent = set_human_attribution(parent, "alice@example.com",
                                       "cto@company.com")
        parent = set_mfa_attestation(parent, "webauthn",
                                     "2026-05-02T13:00:00Z")
        static = {
            "manifest_id": "child-static",
            "manifest_version": "1.0.0",
            "trust_level": 5, "data_classification": "restricted",
            "max_autonomy_depth": 2, "human_required": False,
            "permitted_tools": [], "permitted_delegations": [],
        }
        resolved = enforce_parent_ceiling(static, parent)
        assert resolved["human_user_id"] == "alice@example.com"
        assert resolved["responsible_person"] == "cto@company.com"
        assert resolved["mfa_verified"] is True
        assert resolved["mfa_method"] == "webauthn"

    def test_propagation_through_derive_child(self):
        from governance.lib.manifest import (derive_child_manifest,
                                             set_human_attribution)
        parent = {
            "manifest_id": "parent", "audit_session_id": "sess-1",
            "trust_level": 3, "data_classification": "internal",
            "max_autonomy_depth": 2, "human_required": True,
            "permitted_tools": [], "permitted_delegations": [],
        }
        parent = set_human_attribution(parent, "alice@example.com")
        child = derive_child_manifest(parent, "untrusted-child")
        assert child["human_user_id"] == "alice@example.com"
        assert child["responsible_person"] == "alice@example.com"

    def test_has_valid_human_attribution(self):
        from governance.lib.manifest import has_valid_human_attribution
        assert has_valid_human_attribution(
            {"human_user_id": "alice@example.com"}) is True
        assert has_valid_human_attribution(
            {"human_user_id": "system"}) is True
        assert has_valid_human_attribution(
            {"human_user_id": "legacy_pre_attribution"}) is False
        assert has_valid_human_attribution({}) is False
        assert has_valid_human_attribution({"human_user_id": ""}) is False
        assert has_valid_human_attribution({"human_user_id": "  "}) is False


class TestAuditAccessControl:
    """PRD 18 Pillar 4 — REQ-RCA-007: audit DB access control."""

    def test_db_file_mode_enforced_to_0600(self, audit_paths, sample_manifest):
        """File mode is forced to 0600 on init (Unix only)."""
        import platform
        import stat as _stat
        if platform.system() == "Windows":
            pytest.skip("file mode semantics differ on Windows")
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read")
        mode = _stat.S_IMODE(db.stat().st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_emit_rejected_when_token_required_and_missing(
            self, audit_paths, sample_manifest):
        """Token enforcement: emit() without token raises AuditAccessDenied."""
        from governance.lib.audit_bus import (AuditBus, AuditAccessDenied,
                                              EventType)
        db, buf = audit_paths
        bus = AuditBus(
            db_path=db, buffer_path=buf,
            service_token="secret-token-xyz", enforce_token=True)
        with pytest.raises(AuditAccessDenied):
            bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read")
        assert bus._access_violations[-1]["reason"] == "token_missing"

    def test_emit_rejected_when_token_mismatch(
            self, audit_paths, sample_manifest):
        """Token enforcement: emit() with wrong token raises."""
        from governance.lib.audit_bus import (AuditBus, AuditAccessDenied,
                                              EventType)
        db, buf = audit_paths
        bus = AuditBus(
            db_path=db, buffer_path=buf,
            service_token="secret-token-xyz", enforce_token=True)
        with pytest.raises(AuditAccessDenied):
            bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read",
                     service_token="wrong-token")
        assert bus._access_violations[-1]["reason"] == "token_mismatch"

    def test_emit_succeeds_with_correct_token(
            self, audit_paths, sample_manifest):
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(
            db_path=db, buffer_path=buf,
            service_token="secret-token-xyz", enforce_token=True)
        eid = bus.emit(EventType.TOOL_INVOKED, sample_manifest,
                       tool_name="Read", service_token="secret-token-xyz")
        assert eid is not None
        rows = bus.query({"audit_session_id": "sess-001"})
        assert len(rows) == 1

    def test_advisory_mode_allows_tokenless_emit(
            self, audit_paths, sample_manifest):
        """Backwards compat: enforcement off (default) lets tokenless emits through."""
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(
            db_path=db, buffer_path=buf,
            service_token="secret-token-xyz", enforce_token=False)
        # Token is configured but enforcement is off; emit should still work.
        bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read")
        rows = bus.query({"audit_session_id": "sess-001"})
        assert len(rows) == 1
        # The advisory bypass attempt is recorded for forensic review.
        assert bus._access_violations[-1]["reason"] == "token_missing_advisory"

    def test_advisory_mode_no_violation_recorded_without_token(
            self, audit_paths, sample_manifest):
        """If no token configured and enforcement off, no violation recorded."""
        from governance.lib.audit_bus import AuditBus, EventType
        db, buf = audit_paths
        bus = AuditBus(db_path=db, buffer_path=buf)
        bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read")
        # No service_token configured → no advisory violation triggered.
        assert bus._access_violations == []

    def test_enforcement_with_no_token_configured_raises(
            self, audit_paths, sample_manifest):
        """Misconfig: enforcement on but no service_token → refuse all writes."""
        from governance.lib.audit_bus import (AuditBus, AuditAccessDenied,
                                              EventType)
        db, buf = audit_paths
        bus = AuditBus(
            db_path=db, buffer_path=buf,
            service_token=None, enforce_token=True)
        with pytest.raises(AuditAccessDenied):
            bus.emit(EventType.TOOL_INVOKED, sample_manifest,
                     tool_name="Read", service_token="any-token")

    def test_env_var_toggles_enforcement(
            self, audit_paths, sample_manifest, monkeypatch):
        """GOVERNANCE_AUDIT_REQUIRE_TOKEN=1 enables enforcement globally."""
        from governance.lib.audit_bus import (AuditBus, AuditAccessDenied,
                                              EventType)
        monkeypatch.setenv("GOVERNANCE_AUDIT_REQUIRE_TOKEN", "1")
        db, buf = audit_paths
        bus = AuditBus(
            db_path=db, buffer_path=buf, service_token="t-1")
        with pytest.raises(AuditAccessDenied):
            bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read")
        # Same bus accepts a correct token.
        bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read",
                 service_token="t-1")

    def test_token_constant_time_comparison(
            self, audit_paths, sample_manifest):
        """Token comparison uses hmac.compare_digest (constant-time).

        We can't *prove* timing safety from outside, but we can prove the
        function is invoked by checking that two tokens differing only at
        the last byte both raise — this would be true for any comparison,
        but combined with code review of `_check_service_token` it confirms
        the invariant. The test exists primarily to lock in the call-site.
        """
        from governance.lib.audit_bus import (AuditBus, AuditAccessDenied,
                                              EventType)
        db, buf = audit_paths
        bus = AuditBus(
            db_path=db, buffer_path=buf,
            service_token="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
            enforce_token=True)
        # Differs at last char only.
        with pytest.raises(AuditAccessDenied):
            bus.emit(EventType.TOOL_INVOKED, sample_manifest, tool_name="Read",
                     service_token=
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    def test_load_or_generate_service_token_is_idempotent(self, tmp_path):
        from governance.lib.audit_bus import load_or_generate_service_token
        path = tmp_path / "audit.token"
        t1 = load_or_generate_service_token(path)
        assert path.exists()
        # Re-call returns the same token (no rotation).
        t2 = load_or_generate_service_token(path)
        assert t1 == t2
        assert len(t1) == 64  # 32 bytes of entropy hex-encoded

    def test_service_token_file_mode_0600(self, tmp_path):
        import platform
        import stat as _stat
        if platform.system() == "Windows":
            pytest.skip("file mode semantics differ on Windows")
        from governance.lib.audit_bus import load_or_generate_service_token
        path = tmp_path / "audit.token"
        load_or_generate_service_token(path)
        mode = _stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600
