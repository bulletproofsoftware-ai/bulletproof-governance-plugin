"""Tests for IdentityLifecycleManager — Phase 3 (REQ-059/060/061)."""

import hashlib
import pytest
from unittest.mock import MagicMock, patch

from governance.lib.security.identity_lifecycle import (
    IdentityLifecycleManager,
    SessionCredential,
    VALID_STATES,
    VALID_TRANSITIONS,
)
from governance.lib.security.security_config import SecurityConfig


@pytest.fixture
def mock_qdrant():
    q = MagicMock()
    q.get_identity_session.return_value = None
    q.upsert_identity_session.return_value = "ok"
    return q


@pytest.fixture
def mock_audit_bus():
    bus = MagicMock()
    bus.emit.return_value = "event-id"
    return bus


@pytest.fixture
def config():
    return SecurityConfig()


@pytest.fixture
def manifest():
    return {
        "agent_id": "test-agent",
        "manifest_id": "test-manifest",
        "manifest_version": "1.0",
        "manifest_hash": "abc123",
        "trust_level": 3,
        "data_classification": "internal",
        "permitted_tools": ["Read", "Write", "Grep"],
        "permitted_delegations": [],
        "human_required": False,
        "max_autonomy_depth": 3,
        "max_delegation_count": 5,
        "audit_session_id": "session-123",
    }


@pytest.fixture
def mgr(mock_qdrant, mock_audit_bus, config):
    return IdentityLifecycleManager(
        qdrant=mock_qdrant,
        audit_bus=mock_audit_bus,
        config=config,
        registry=MagicMock(),
        policy_engine=MagicMock(),
    )


class TestProvision:
    def test_provision_creates_credential(self, mgr, manifest):
        """Provision should create a new credential and return raw token."""
        credential, raw_token = mgr.provision(
            "test-agent", "session-123", manifest)
        assert credential.state == "PROVISION"
        assert credential.agent_id == "test-agent"
        assert credential.session_id == "session-123"
        assert len(raw_token) == 64  # 32 bytes hex
        assert credential.token_hash == hashlib.sha256(
            raw_token.encode()).hexdigest()

    def test_provision_stores_in_qdrant(self, mgr, manifest, mock_qdrant):
        """Provision should persist credential to Qdrant."""
        mgr.provision("test-agent", "session-123", manifest)
        mock_qdrant.upsert_identity_session.assert_called()

    def test_provision_emits_audit_event(self, mgr, manifest, mock_audit_bus):
        """Provision should emit identity_transition event."""
        mgr.provision("test-agent", "session-123", manifest)
        mock_audit_bus.emit.assert_called()


class TestAuthenticate:
    def test_authenticate_with_valid_token(self, mgr, manifest, mock_qdrant):
        """Valid token should authenticate successfully."""
        credential, raw_token = mgr.provision(
            "test-agent", "session-123", manifest)

        # Mock the Qdrant read to return the credential
        mock_qdrant.get_identity_session.return_value = {
            "credential_id": credential.credential_id,
            "session_id": "session-123",
            "agent_id": "test-agent",
            "token_hash": credential.token_hash,
            "scope": credential.scope,
            "state": "PROVISION",
            "issued_at": credential.issued_at,
            "expires_at": credential.expires_at,
            "rotation_interval": 3600,
            "manifest_hash": manifest["manifest_hash"],
            "state_history": [],
        }

        result = mgr.authenticate("session-123", raw_token, manifest)
        assert result.authorized is True

    def test_authenticate_with_invalid_token(self, mgr, manifest, mock_qdrant):
        """Invalid token should fail and revoke."""
        credential, _ = mgr.provision(
            "test-agent", "session-123", manifest)

        mock_qdrant.get_identity_session.return_value = {
            "credential_id": credential.credential_id,
            "session_id": "session-123",
            "agent_id": "test-agent",
            "token_hash": credential.token_hash,
            "scope": [],
            "state": "PROVISION",
            "manifest_hash": manifest["manifest_hash"],
            "state_history": [],
        }

        result = mgr.authenticate("session-123", "wrong-token", manifest)
        assert result.authorized is False
        assert "token_mismatch" in result.reason


class TestStateMachine:
    def test_valid_transitions(self):
        """All defined transitions should be valid."""
        assert "AUTHENTICATE" in VALID_TRANSITIONS["PROVISION"]
        assert "AUTHORIZE" in VALID_TRANSITIONS["AUTHENTICATE"]
        assert "MONITOR" in VALID_TRANSITIONS["AUTHORIZE"]
        assert "SUSPEND" in VALID_TRANSITIONS["MONITOR"]
        assert "REVOKE" in VALID_TRANSITIONS["MONITOR"]
        assert "MONITOR" in VALID_TRANSITIONS["SUSPEND"]
        assert "REVOKE" in VALID_TRANSITIONS["SUSPEND"]
        assert len(VALID_TRANSITIONS["REVOKE"]) == 0  # Terminal

    def test_all_6_states_defined(self):
        """Should have exactly 6 states."""
        assert len(VALID_STATES) == 6
        assert "PROVISION" in VALID_STATES
        assert "REVOKE" in VALID_STATES


class TestSuspendRevoke:
    def test_suspend_from_monitor(self, mgr, mock_qdrant):
        """Should be able to suspend from MONITOR state."""
        mock_qdrant.get_identity_session.return_value = {
            "credential_id": "cred-1",
            "session_id": "session-1",
            "agent_id": "agent-1",
            "token_hash": "hash",
            "scope": [],
            "state": "MONITOR",
            "state_history": [],
            "revocation_reason": "",
            "manifest_hash": "",
            "throttle_rate": 1.0,
        }
        result = mgr.suspend("session-1", "anomaly_detected")
        assert result is True

    def test_unsuspend_restores_monitor(self, mgr, mock_qdrant):
        """Unsuspend should move from SUSPEND back to MONITOR."""
        mock_qdrant.get_identity_session.return_value = {
            "credential_id": "cred-1",
            "session_id": "session-1",
            "agent_id": "agent-1",
            "token_hash": "hash",
            "scope": [],
            "state": "SUSPEND",
            "state_history": [],
            "revocation_reason": "test",
            "manifest_hash": "",
            "throttle_rate": 1.0,
        }
        result = mgr.unsuspend("session-1", "operator-1")
        assert result is True

    def test_revoke_is_terminal(self, mgr, mock_qdrant):
        """Revoke should be terminal — no further transitions."""
        mock_qdrant.get_identity_session.return_value = {
            "credential_id": "cred-1",
            "session_id": "session-1",
            "agent_id": "agent-1",
            "token_hash": "hash",
            "scope": [],
            "state": "REVOKE",
            "state_history": [],
            "revocation_reason": "expired",
            "manifest_hash": "",
            "throttle_rate": 1.0,
        }
        # Cannot revoke again
        result = mgr.revoke("session-1", "duplicate")
        assert result is False

    def test_cannot_suspend_from_revoke(self, mgr, mock_qdrant):
        """Cannot suspend from terminal REVOKE state."""
        mock_qdrant.get_identity_session.return_value = {
            "credential_id": "cred-1",
            "session_id": "session-1",
            "agent_id": "agent-1",
            "token_hash": "hash",
            "scope": [],
            "state": "REVOKE",
            "state_history": [],
            "revocation_reason": "",
            "manifest_hash": "",
            "throttle_rate": 1.0,
        }
        result = mgr.suspend("session-1", "test")
        assert result is False


class TestScopeValidation:
    def test_scope_allows_matching_tools(self, mgr, mock_qdrant):
        """Tools matching scope patterns should be allowed."""
        mock_qdrant.get_identity_session.return_value = {
            "credential_id": "cred-1",
            "session_id": "session-1",
            "agent_id": "agent-1",
            "token_hash": "hash",
            "scope": ["Read", "Write", "Grep"],
            "state": "MONITOR",
            "state_history": [],
            "revocation_reason": "",
            "manifest_hash": "",
            "throttle_rate": 1.0,
        }
        assert mgr.validate_scope("session-1", "Read") is True
        assert mgr.validate_scope("session-1", "Bash") is False


class TestThrottle:
    def test_throttle_updates_rate(self, mgr, mock_qdrant):
        """Throttle should update the rate limit."""
        mock_qdrant.get_identity_session.return_value = {
            "credential_id": "cred-1",
            "session_id": "session-1",
            "agent_id": "agent-1",
            "token_hash": "hash",
            "scope": [],
            "state": "MONITOR",
            "state_history": [],
            "revocation_reason": "",
            "manifest_hash": "",
            "throttle_rate": 1.0,
        }
        result = mgr.throttle("session-1", rate_limit=0.5)
        assert result is True
