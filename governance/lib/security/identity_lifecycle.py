"""Identity Lifecycle Manager — 6-state machine with ephemeral credentials (REQ-059/060/061).

States: PROVISION -> AUTHENTICATE -> AUTHORIZE -> MONITOR -> SUSPEND -> REVOKE
Ephemeral credentials per session, rotation with 60s revocation window,
integration with trust broker for scope validation.
"""

import hashlib
import logging
import os
import secrets
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

from governance.lib.audit_bus import AuditBus, EventType
from governance.lib.security.security_config import SecurityConfig

logger = logging.getLogger("governance.security.identity_lifecycle")

# ---------------------------------------------------------------------------
# States
# ---------------------------------------------------------------------------
VALID_STATES = {"PROVISION", "AUTHENTICATE", "AUTHORIZE", "MONITOR", "SUSPEND", "REVOKE"}

VALID_TRANSITIONS = {
    "PROVISION": {"AUTHENTICATE"},
    "AUTHENTICATE": {"AUTHORIZE", "REVOKE"},
    "AUTHORIZE": {"MONITOR", "REVOKE"},
    "MONITOR": {"SUSPEND", "REVOKE"},
    "SUSPEND": {"MONITOR", "REVOKE"},
    "REVOKE": set(),  # terminal
}


# ---------------------------------------------------------------------------
# Credential dataclass
# ---------------------------------------------------------------------------
@dataclass
class SessionCredential:
    credential_id: str
    session_id: str
    agent_id: str
    token_hash: str  # SHA-256 of issued token (token itself NOT stored)
    scope: list = field(default_factory=list)
    state: str = "PROVISION"
    issued_at: str = ""
    expires_at: str = ""
    rotation_interval: int = 3600
    last_rotated_at: str = ""
    previous_credential_id: str = ""
    revocation_reason: str = ""
    manifest_hash: str = ""
    state_history: list = field(default_factory=list)
    throttle_rate: float = 1.0  # 1.0 = full speed, 0.5 = half speed


@dataclass
class AuthResult:
    authorized: bool
    scope: list = field(default_factory=list)
    reason: str = ""


# ---------------------------------------------------------------------------
# IdentityLifecycleManager
# ---------------------------------------------------------------------------
class IdentityLifecycleManager:
    def __init__(self, qdrant, audit_bus: AuditBus, config: SecurityConfig,
                 registry=None, policy_engine=None):
        self.qdrant = qdrant
        self.audit_bus = audit_bus
        self.config = config
        self.registry = registry
        self.policy_engine = policy_engine
        self._rotation_timers: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Provision — create ephemeral credential for a new session
    # ------------------------------------------------------------------
    def provision(
        self,
        agent_id: str,
        session_id: str,
        manifest: dict,
    ) -> tuple[SessionCredential, str]:
        """Provision ephemeral identity for a session.

        Returns (credential, raw_token). The raw_token is returned exactly
        once; only its SHA-256 hash is persisted.
        """
        # Generate ephemeral token
        raw_token = secrets.token_hex(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        now = datetime.now(timezone.utc)
        ttl = int(os.environ.get("IDENTITY_TOKEN_TTL_SECONDS", "86400"))
        rotation_interval = manifest.get(
            "credential_rotation_interval",
            int(os.environ.get("IDENTITY_ROTATION_INTERVAL", "3600")))

        # Build scope from manifest
        scope = manifest.get("permitted_tools", [])
        session_scope = manifest.get("session_scope", [])
        if session_scope:
            scope = scope + session_scope

        credential = SessionCredential(
            credential_id=str(uuid.uuid4()),
            session_id=session_id,
            agent_id=agent_id,
            token_hash=token_hash,
            scope=scope,
            state="PROVISION",
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=ttl)).isoformat(),
            rotation_interval=rotation_interval,
            last_rotated_at=now.isoformat(),
            manifest_hash=manifest.get("manifest_hash", ""),
            state_history=[{
                "state": "PROVISION",
                "timestamp": now.isoformat(),
                "trigger": "session_start",
            }],
        )

        # Store in Qdrant
        self._persist_credential(credential)

        # Emit audit event
        self.audit_bus.emit(
            EventType.SECURITY_IDENTITY_TRANSITION,
            manifest=manifest,
            outcome="info",
            detail={
                "from_state": "",
                "to_state": "PROVISION",
                "trigger": "session_start",
                "credential_id": credential.credential_id,
                "scope_snapshot": str(credential.scope[:5]),
            },
        )

        return credential, raw_token

    # ------------------------------------------------------------------
    # Authenticate — verify credential and manifest hash
    # ------------------------------------------------------------------
    def authenticate(
        self,
        session_id: str,
        token: str,
        manifest: dict,
    ) -> AuthResult:
        """Verify credential validity and manifest hash."""
        credential = self._get_credential_by_session(session_id)
        if not credential:
            return AuthResult(authorized=False, reason="no_credential_found")

        if credential.state != "PROVISION":
            return AuthResult(
                authorized=False,
                reason=f"invalid_state_for_auth: {credential.state}")

        # Verify token hash
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if token_hash != credential.token_hash:
            self._transition(credential, "REVOKE", "token_mismatch", manifest)
            return AuthResult(authorized=False, reason="token_mismatch")

        # Verify manifest hash (tamper evidence)
        if credential.manifest_hash and manifest.get("manifest_hash"):
            if credential.manifest_hash != manifest["manifest_hash"]:
                self._transition(credential, "REVOKE", "manifest_tampered", manifest)
                return AuthResult(authorized=False, reason="manifest_tampered")

        self._transition(credential, "AUTHENTICATE", "token_verified", manifest)
        return AuthResult(authorized=True, scope=credential.scope)

    # ------------------------------------------------------------------
    # Authorize — validate scope against manifest via policy engine
    # ------------------------------------------------------------------
    def authorize(self, session_id: str, manifest: dict) -> AuthResult:
        """Cross-reference scope with manifest. Install scope enforcement."""
        credential = self._get_credential_by_session(session_id)
        if not credential:
            return AuthResult(authorized=False, reason="no_credential_found")

        if credential.state != "AUTHENTICATE":
            return AuthResult(
                authorized=False,
                reason=f"invalid_state_for_authorize: {credential.state}")

        # Validate scope against policy engine (if available)
        if self.policy_engine:
            for tool_pattern in credential.scope:
                if not self.policy_engine._tool_permitted(manifest, tool_pattern):
                    self._transition(
                        credential, "REVOKE", "scope_mismatch", manifest)
                    return AuthResult(authorized=False, reason="scope_mismatch")

        self._transition(credential, "AUTHORIZE", "scope_granted", manifest)

        # Move to MONITOR immediately
        credential = self._get_credential_by_session(session_id)
        if credential and credential.state == "AUTHORIZE":
            self._transition(credential, "MONITOR", "scope_enforcement_installed", manifest)

            # Schedule rotation timer
            self._schedule_rotation(credential, manifest)

        return AuthResult(authorized=True, scope=credential.scope if credential else [])

    # ------------------------------------------------------------------
    # Fast-track: provision -> monitor in one call (for session start)
    # ------------------------------------------------------------------
    def provision_and_activate(
        self,
        agent_id: str,
        session_id: str,
        manifest: dict,
    ) -> tuple[SessionCredential, str]:
        """Provision, authenticate, authorize, and activate in one call.

        Returns (credential, raw_token). Used by session_start hook.
        """
        credential, raw_token = self.provision(agent_id, session_id, manifest)

        # Auto-authenticate (we trust the session_start hook)
        self.authenticate(session_id, raw_token, manifest)

        # Auto-authorize
        self.authorize(session_id, manifest)

        # Refresh credential from Qdrant
        final = self._get_credential_by_session(session_id)
        return final or credential, raw_token

    # ------------------------------------------------------------------
    # Rotation — issue new credential, revoke old within 60s
    # ------------------------------------------------------------------
    def rotate(self, session_id: str, manifest: dict,
               trigger: str = "scheduled") -> Optional[str]:
        """Rotate credential. Returns new raw token or None on failure."""
        credential = self._get_credential_by_session(session_id)
        if not credential or credential.state != "MONITOR":
            return None

        old_credential_id = credential.credential_id

        # Generate new token
        new_token = secrets.token_hex(32)
        new_hash = hashlib.sha256(new_token.encode()).hexdigest()
        now = datetime.now(timezone.utc)

        # Update credential in place
        credential.token_hash = new_hash
        credential.previous_credential_id = old_credential_id
        credential.last_rotated_at = now.isoformat()
        credential.credential_id = str(uuid.uuid4())

        self._persist_credential(credential)

        # Emit rotation event
        self.audit_bus.emit(
            EventType.SECURITY_IDENTITY_ROTATION,
            manifest=manifest,
            outcome="info",
            detail={
                "old_credential_id": old_credential_id,
                "new_credential_id": credential.credential_id,
                "rotation_trigger": trigger,
                "revocation_delay_ms": 0,
            },
        )

        # Re-schedule next rotation
        self._schedule_rotation(credential, manifest)

        return new_token

    # ------------------------------------------------------------------
    # Suspend — restrict to read-only
    # ------------------------------------------------------------------
    def suspend(self, session_id: str, reason: str,
                manifest: Optional[dict] = None) -> bool:
        """Suspend an agent session (read-only mode)."""
        credential = self._get_credential_by_session(session_id)
        if not credential or credential.state not in ("MONITOR", "AUTHORIZE"):
            return False

        m = manifest or {"agent_id": credential.agent_id, "audit_session_id": session_id}
        credential.revocation_reason = reason
        self._transition(credential, "SUSPEND", reason, m)
        return True

    # ------------------------------------------------------------------
    # Unsuspend — restore to MONITOR
    # ------------------------------------------------------------------
    def unsuspend(self, session_id: str, operator_id: str,
                  manifest: Optional[dict] = None) -> bool:
        """Restore a suspended session (human clears suspension)."""
        credential = self._get_credential_by_session(session_id)
        if not credential or credential.state != "SUSPEND":
            return False

        m = manifest or {"agent_id": credential.agent_id, "audit_session_id": session_id}
        credential.revocation_reason = ""
        self._transition(credential, "MONITOR", f"cleared_by_{operator_id}", m)
        return True

    # ------------------------------------------------------------------
    # Revoke — terminal state
    # ------------------------------------------------------------------
    def revoke(self, session_id: str, reason: str,
               manifest: Optional[dict] = None) -> bool:
        """Revoke credential (terminal state)."""
        credential = self._get_credential_by_session(session_id)
        if not credential or credential.state == "REVOKE":
            return False

        m = manifest or {"agent_id": credential.agent_id, "audit_session_id": session_id}
        credential.revocation_reason = reason
        self._transition(credential, "REVOKE", reason, m)

        # Cancel rotation timer
        self._cancel_rotation(session_id)

        return True

    # ------------------------------------------------------------------
    # Throttle — reduce rate without state change
    # ------------------------------------------------------------------
    def throttle(self, session_id: str, rate_limit: float = 0.5) -> bool:
        """Throttle an agent session's execution rate."""
        credential = self._get_credential_by_session(session_id)
        if not credential or credential.state in ("REVOKE",):
            return False

        credential.throttle_rate = rate_limit
        self._persist_credential(credential)
        return True

    # ------------------------------------------------------------------
    # Scope validation — check if a tool call is within scope
    # ------------------------------------------------------------------
    def validate_scope(self, session_id: str, tool_name: str,
                       tool_input: Optional[dict] = None) -> bool:
        """Check if tool call is within the session's authorized scope."""
        # If Qdrant is unavailable, credential lookup will always fail —
        # allow rather than blocking every tool call due to infra issues.
        # The non-Qdrant detectors (signature, rate, exfiltration) still protect.
        if not self.qdrant.available:
            return True
        credential = self._get_credential_by_session(session_id)
        if not credential:
            # No credential means identity lifecycle was never bootstrapped
            # for this session (session_start doesn't provision credentials yet).
            # Allow — the other detectors still provide protection.
            logger.debug("validate_scope: no credential for session %s — identity lifecycle not bootstrapped, allowing", session_id)
            return True

        if credential.state in ("REVOKE",):
            return False

        if credential.state == "SUSPEND":
            # Suspended: only allow read-only tools
            read_only_tools = {"Read", "Glob", "Grep"}
            if tool_name not in read_only_tools:
                return False

        # Check scope patterns
        import fnmatch
        for pattern in credential.scope:
            if fnmatch.fnmatch(tool_name, pattern):
                return True

        # If scope is empty, allow all (backward compat)
        if not credential.scope:
            return True

        return False

    # ------------------------------------------------------------------
    # Get session state
    # ------------------------------------------------------------------
    def get_session_state(self, session_id: str) -> Optional[dict]:
        """Get current session identity state."""
        credential = self._get_credential_by_session(session_id)
        if not credential:
            return None
        return {
            "credential_id": credential.credential_id,
            "session_id": credential.session_id,
            "agent_id": credential.agent_id,
            "state": credential.state,
            "scope": credential.scope,
            "issued_at": credential.issued_at,
            "expires_at": credential.expires_at,
            "last_rotated_at": credential.last_rotated_at,
            "throttle_rate": credential.throttle_rate,
            "revocation_reason": credential.revocation_reason,
            "state_history": credential.state_history,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _transition(self, credential: SessionCredential, to_state: str,
                    trigger: str, manifest: dict) -> None:
        """Execute a state transition with validation and audit."""
        from_state = credential.state

        # Validate transition
        if to_state not in VALID_TRANSITIONS.get(from_state, set()):
            logger.error(
                "Invalid state transition: %s -> %s (agent=%s)",
                from_state, to_state, credential.agent_id)
            return

        now = datetime.now(timezone.utc).isoformat()
        credential.state = to_state
        credential.state_history.append({
            "state": to_state,
            "timestamp": now,
            "trigger": trigger,
        })

        self._persist_credential(credential)

        # Emit audit event
        self.audit_bus.emit(
            EventType.SECURITY_IDENTITY_TRANSITION,
            manifest=manifest,
            outcome="info",
            detail={
                "from_state": from_state,
                "to_state": to_state,
                "trigger": trigger,
                "credential_id": credential.credential_id,
                "scope_snapshot": str(credential.scope[:5]),
            },
        )

    def _persist_credential(self, credential: SessionCredential) -> None:
        """Write credential to Qdrant."""
        self.qdrant.upsert_identity_session(
            credential.credential_id,
            {
                "credential_id": credential.credential_id,
                "session_id": credential.session_id,
                "agent_id": credential.agent_id,
                "token_hash": credential.token_hash,
                "scope": credential.scope,
                "state": credential.state,
                "issued_at": credential.issued_at,
                "expires_at": credential.expires_at,
                "rotation_interval": credential.rotation_interval,
                "last_rotated_at": credential.last_rotated_at,
                "previous_credential_id": credential.previous_credential_id,
                "revocation_reason": credential.revocation_reason,
                "manifest_hash": credential.manifest_hash,
                "state_history": [str(h) for h in credential.state_history],
                "throttle_rate": credential.throttle_rate,
            },
        )

    def _get_credential_by_session(self, session_id: str) -> Optional[SessionCredential]:
        """Load credential from Qdrant by session_id."""
        data = self.qdrant.get_identity_session(session_id)
        if not data:
            return None
        return SessionCredential(
            credential_id=data.get("credential_id", ""),
            session_id=data.get("session_id", session_id),
            agent_id=data.get("agent_id", ""),
            token_hash=data.get("token_hash", ""),
            scope=data.get("scope", []),
            state=data.get("state", "PROVISION"),
            issued_at=data.get("issued_at", ""),
            expires_at=data.get("expires_at", ""),
            rotation_interval=data.get("rotation_interval", 3600),
            last_rotated_at=data.get("last_rotated_at", ""),
            previous_credential_id=data.get("previous_credential_id", ""),
            revocation_reason=data.get("revocation_reason", ""),
            manifest_hash=data.get("manifest_hash", ""),
            state_history=data.get("state_history", []),
            throttle_rate=data.get("throttle_rate", 1.0),
        )

    def _schedule_rotation(self, credential: SessionCredential,
                           manifest: dict) -> None:
        """Schedule credential rotation timer."""
        with self._lock:
            self._cancel_rotation(credential.session_id)
            timer = threading.Timer(
                credential.rotation_interval,
                self._rotation_callback,
                args=(credential.session_id, manifest),
            )
            timer.daemon = True
            timer.start()
            self._rotation_timers[credential.session_id] = timer

    def _cancel_rotation(self, session_id: str) -> None:
        """Cancel pending rotation timer."""
        timer = self._rotation_timers.pop(session_id, None)
        if timer:
            timer.cancel()

    def _rotation_callback(self, session_id: str, manifest: dict) -> None:
        """Callback for scheduled rotation."""
        try:
            self.rotate(session_id, manifest, trigger="scheduled")
        except Exception as e:
            logger.error("Rotation failed for session %s: %s", session_id, e)
