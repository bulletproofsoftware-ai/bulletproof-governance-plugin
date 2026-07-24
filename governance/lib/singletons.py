"""Governance singletons — lazy initialization for all core objects.

All four core objects share the same AuditBus instance. Initialized
lazily on first access. Imported by all hook scripts.

WI-11 extension: adds lazy getters for 8 security modules.
"""

import json
import os
from pathlib import Path
from typing import Optional

from governance.lib.audit_bus import AuditBus
from governance.lib.memory_governor import MemoryGovernor
from governance.lib.policy_engine import PolicyEngine, load_tool_tiers
from governance.lib.trust_broker import ManifestRegistry, TrustBroker

# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------
_audit_bus: Optional[AuditBus] = None
_policy_engine: Optional[PolicyEngine] = None
_trust_broker: Optional[TrustBroker] = None
_registry: Optional[ManifestRegistry] = None
_governor: Optional[MemoryGovernor] = None

# Security module singletons (WI-11)
_security_qdrant = None
_security_config = None
_behavioral_monitor = None
_identity_lifecycle = None
_memory_integrity = None
_coordination_scorer = None
_threat_detection = None
_guardian_agent = None


def _get_plugin_root() -> Path:
    env = os.environ.get("GOVERNANCE_PLUGIN_ROOT")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent.parent


def get_audit_bus() -> AuditBus:
    global _audit_bus
    if _audit_bus is None:
        root = _get_plugin_root()
        _audit_bus = AuditBus(
            db_path=root / "state" / "audit.db",
            buffer_path=root / "state" / "audit-buffer.json")
    return _audit_bus


def get_registry() -> ManifestRegistry:
    global _registry
    if _registry is None:
        root = _get_plugin_root()
        _registry = ManifestRegistry(
            registry_path=root / "state" / "active-manifests.json")
    return _registry


def get_policy_engine() -> PolicyEngine:
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine(
            audit_bus=get_audit_bus(),
            tool_tiers=load_tool_tiers())
    return _policy_engine


def get_trust_broker() -> TrustBroker:
    global _trust_broker
    if _trust_broker is None:
        _trust_broker = TrustBroker(
            audit_bus=get_audit_bus(),
            manifest_registry=get_registry())
    return _trust_broker


def get_governor() -> MemoryGovernor:
    global _governor
    if _governor is None:
        _governor = MemoryGovernor(audit_bus=get_audit_bus())
    return _governor


# ---------------------------------------------------------------------------
# Session state helpers
# ---------------------------------------------------------------------------
def load_session_state() -> dict:
    state_path = _get_plugin_root() / "state" / "session-state.json"
    if not state_path.exists():
        return {}
    try:
        return json.loads(state_path.read_text())
    except Exception:
        return {}


def write_session_state(state: dict) -> None:
    state_path = _get_plugin_root() / "state" / "session-state.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2))


# ---------------------------------------------------------------------------
# Pending human-gate tracking — bridges PreToolUse open and PostToolUse close
# so the outcome-collector can compute approval-gate latency.
# ---------------------------------------------------------------------------
def track_pending_gate(gate_id: str, tool_name: str,
                       gate_kind: str, started_iso: str) -> None:
    """Record an open human gate so the matching response can be paired later.

    gate_kind is "scheduled" (designed-in approval) or "unscheduled"
    (mid-flight friction). Stored in session-state.json so the next
    PostToolUse hook can detect the response and emit HUMAN_GATE_RESPONSE.
    """
    try:
        state = load_session_state()
        state["pending_gate"] = {
            "gate_id": gate_id,
            "tool_name": tool_name,
            "gate_kind": gate_kind,
            "started_iso": started_iso,
        }
        write_session_state(state)
    except Exception:
        # Tracking failure must not block the gate emission itself.
        pass


def consume_pending_gate() -> dict:
    """Pop the pending gate record (one-shot) — returns {} if none.

    Called by post_tool_metrics.py once the operator response is observed
    or the gate is judged abandoned.
    """
    try:
        state = load_session_state()
        pending = state.pop("pending_gate", None)
        if pending is not None:
            write_session_state(state)
            return pending
    except Exception:
        pass
    return {}


def peek_pending_gate() -> dict:
    """Read the pending gate without clearing it. Returns {} if none."""
    try:
        return load_session_state().get("pending_gate", {}) or {}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Security module getters (WI-11)
# ---------------------------------------------------------------------------
def get_security_config():
    """Lazy-load security configuration."""
    global _security_config
    if _security_config is None:
        from governance.lib.security.security_config import load_security_config
        _security_config = load_security_config()
    return _security_config


def get_security_qdrant():
    """Lazy-init shared Qdrant client for security collections."""
    global _security_qdrant
    if _security_qdrant is None:
        from governance.lib.security.qdrant_client import SecurityQdrantClient
        config = get_security_config()
        _security_qdrant = SecurityQdrantClient(url=config.qdrant_url)
    return _security_qdrant


def get_behavioral_monitor():
    """Lazy-init behavioral monitor."""
    global _behavioral_monitor
    if _behavioral_monitor is None:
        from governance.lib.security.behavioral_monitor import BehavioralMonitor
        _behavioral_monitor = BehavioralMonitor(
            qdrant=get_security_qdrant(),
            audit_bus=get_audit_bus(),
            config=get_security_config(),
        )
    return _behavioral_monitor


def get_identity_lifecycle():
    """Lazy-init identity lifecycle manager."""
    global _identity_lifecycle
    if _identity_lifecycle is None:
        from governance.lib.security.identity_lifecycle import IdentityLifecycleManager
        _identity_lifecycle = IdentityLifecycleManager(
            qdrant=get_security_qdrant(),
            audit_bus=get_audit_bus(),
            config=get_security_config(),
            registry=get_registry(),
            policy_engine=get_policy_engine(),
        )
    return _identity_lifecycle


def get_memory_integrity():
    """Lazy-init memory integrity verifier."""
    global _memory_integrity
    if _memory_integrity is None:
        from governance.lib.security.memory_integrity import MemoryIntegrityVerifier
        _memory_integrity = MemoryIntegrityVerifier(
            qdrant=get_security_qdrant(),
            audit_bus=get_audit_bus(),
            config=get_security_config(),
        )
    return _memory_integrity


def get_coordination_scorer():
    """Lazy-init coordination scorer."""
    global _coordination_scorer
    if _coordination_scorer is None:
        from governance.lib.security.coordination_scorer import CoordinationScorer
        _coordination_scorer = CoordinationScorer(
            qdrant=get_security_qdrant(),
            audit_bus=get_audit_bus(),
            config=get_security_config(),
        )
    return _coordination_scorer


def get_threat_detection():
    """Lazy-init threat detection engine."""
    global _threat_detection
    if _threat_detection is None:
        from governance.lib.security.threat_detection import ThreatDetectionEngine
        _threat_detection = ThreatDetectionEngine(
            qdrant=get_security_qdrant(),
            audit_bus=get_audit_bus(),
            config=get_security_config(),
        )
    return _threat_detection


def get_guardian_agent():
    """Lazy-init Guardian Agent."""
    global _guardian_agent
    if _guardian_agent is None:
        from governance.lib.security.guardian_agent import GuardianAgent
        _guardian_agent = GuardianAgent(
            qdrant=get_security_qdrant(),
            audit_bus=get_audit_bus(),
            config=get_security_config(),
            identity_mgr=get_identity_lifecycle(),
        )
    return _guardian_agent
