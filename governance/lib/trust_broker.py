"""Governance trust broker — delegation mediation.

Validates inter-agent delegation: breadth limits, depth budget,
classification boundaries, trust escalation, permitted targets.
ManifestRegistry provides session-scoped, TTL-purged manifest storage.
"""

import fcntl
import fnmatch
import hashlib
import json
import re
import secrets
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from governance.lib.audit_bus import AuditBus, EventType
from governance.lib.manifest import (
    CLASSIFICATION_ORDER,
    resolve_manifest,
)


# ---------------------------------------------------------------------------
# TrustDecision
# ---------------------------------------------------------------------------
@dataclass
class TrustDecision:
    action: str              # allow, deny, escalate
    reason: str = ""
    resolved_manifest: Optional[dict] = field(default=None)
    delegation_token: str = ""
    gate_type: str = ""      # depth_exhausted | classification_boundary |
                             # trust_escalation | target_not_permitted |
                             # breadth_exceeded | error


# ---------------------------------------------------------------------------
# Target agent extraction
# ---------------------------------------------------------------------------
def _extract_target_agent(tool_input: dict) -> Optional[str]:
    """Extract target agent ID from Task tool input."""
    # 1. Explicit subagent_type field (preferred)
    subagent_type = tool_input.get("subagent_type", "").strip()
    if subagent_type:
        return subagent_type

    # 2. Convention-based extraction from prompt (fallback)
    prompt = tool_input.get("description", tool_input.get("prompt", ""))
    agent_match = re.match(r"^AGENT:\s*([a-zA-Z0-9_-]+)", prompt)
    if agent_match:
        return agent_match.group(1)

    # 3. Unresolvable
    return None


# ---------------------------------------------------------------------------
# ManifestRegistry — session-scoped, TTL-purged, file-locked
# ---------------------------------------------------------------------------
class ManifestRegistry:
    TTL_SECONDS = 3600

    def __init__(self, registry_path: Path):
        self.path = registry_path
        self.lock_path = registry_path.with_suffix(".lock")

    @contextmanager
    def _file_lock(self):
        """Exclusive file lock for concurrent read-modify-write safety."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = open(self.lock_path, "w")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text())
        except Exception:
            return {}

    def _save(self, registry: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(registry, indent=2))
        try:
            tmp.rename(self.path)
        except OSError:
            import shutil
            shutil.move(str(tmp), str(self.path))

    def _purge_stale(self, registry: dict) -> dict:
        cutoff = datetime.now(timezone.utc).timestamp() - self.TTL_SECONDS
        result = {}
        for k, v in registry.items():
            try:
                ts = datetime.fromisoformat(v["registered_at"])
                if ts.timestamp() > cutoff:
                    result[k] = v
            except Exception:
                continue
        return result

    def register_active(self, agent_id: str, manifest: dict,
                        session_id: Optional[str] = None) -> None:
        sid = session_id or manifest.get("audit_session_id", "unknown")
        with self._file_lock():
            registry = self._load()
            key = f"{sid}:{agent_id}"
            registry[key] = {
                "manifest": manifest,
                "registered_at": datetime.now(timezone.utc).isoformat(),
            }
            self._save(self._purge_stale(registry))

    def get_active(self, agent_id: str,
                   session_id: Optional[str] = None) -> Optional[dict]:
        with self._file_lock():
            registry = self._load()
        if session_id:
            entry = registry.get(f"{session_id}:{agent_id}")
        else:
            matches = {k: v for k, v in registry.items()
                       if k.endswith(f":{agent_id}")}
            entry = (max(matches.values(),
                         key=lambda v: v["registered_at"])
                     if matches else None)
        return entry["manifest"] if entry else None

    def deregister(self, agent_id: str,
                   session_id: Optional[str] = None) -> None:
        with self._file_lock():
            registry = self._load()
            if session_id:
                registry.pop(f"{session_id}:{agent_id}", None)
            else:
                registry = {k: v for k, v in registry.items()
                            if not k.endswith(f":{agent_id}")}
            self._save(registry)

    def purge_stale(self) -> int:
        with self._file_lock():
            registry = self._load()
            purged = self._purge_stale(registry)
            removed = len(registry) - len(purged)
            self._save(purged)
        return removed


# ---------------------------------------------------------------------------
# TrustBroker
# ---------------------------------------------------------------------------
class TrustBroker:
    def __init__(self, audit_bus: AuditBus,
                 manifest_registry: ManifestRegistry):
        self.audit_bus = audit_bus
        self.registry = manifest_registry

    def evaluate_delegation(self, source_manifest: dict,
                            target_agent_id: str,
                            task_description: str) -> TrustDecision:
        """Evaluate whether source can delegate to target.

        Returns TrustDecision with allow/deny/escalate.
        """
        # 1. Resolve target with parent ceiling
        target_manifest = resolve_manifest(target_agent_id, source_manifest)

        # 2. Delegation breadth limit (session total)
        max_delegations = source_manifest.get("max_delegation_count", 0)
        session_id = source_manifest.get("audit_session_id")
        agent_id_src = source_manifest.get("agent_id")
        issued = self.audit_bus.query({
            "event_type": "delegation_event",
            "agent_id": agent_id_src,
            "audit_session_id": session_id,
            "outcome": "allow",
        }, limit=max_delegations + 1)
        current_count = len(issued)
        if current_count >= max_delegations:
            self.audit_bus.emit(
                EventType.TRUST_DENY, source_manifest,
                target_agent_id=target_agent_id, outcome="deny",
                detail={
                    "deny_reason": "delegation_count_exceeded",
                    "current": current_count,
                    "max": max_delegations,
                })
            return TrustDecision(
                "deny",
                f"Delegation breadth limit reached "
                f"({current_count}/{max_delegations})",
                gate_type="breadth_exceeded")

        # 3. Autonomy depth budget
        if source_manifest.get("max_autonomy_depth", 0) <= 0:
            self.audit_bus.emit(
                EventType.TRUST_DENY, source_manifest,
                target_agent_id=target_agent_id, outcome="deny",
                detail={"deny_reason": "autonomy_depth_exhausted"})
            return TrustDecision(
                "escalate",
                "Autonomy depth exhausted — human approval required",
                gate_type="depth_exhausted")

        # 4. Classification boundary
        source_class = source_manifest.get("data_classification", "public")
        target_class = target_manifest.get("data_classification", "public")
        if CLASSIFICATION_ORDER.index(target_class) > \
           CLASSIFICATION_ORDER.index(source_class):
            self.audit_bus.emit(
                EventType.TRUST_DENY, source_manifest,
                target_agent_id=target_agent_id, outcome="deny",
                detail={
                    "deny_reason": "classification_boundary_violation",
                    "source": source_class,
                    "target": target_class,
                })
            return TrustDecision(
                "deny",
                f"Target classification '{target_class}' exceeds "
                f"source ceiling '{source_class}'",
                gate_type="classification_boundary")

        # 5. Trust level (defense-in-depth)
        if target_manifest.get("trust_level", 0) > \
           source_manifest.get("trust_level", 0):
            self.audit_bus.emit(
                EventType.TRUST_DENY, source_manifest,
                target_agent_id=target_agent_id, outcome="deny",
                detail={"deny_reason": "trust_escalation_attempt"})
            return TrustDecision(
                "deny", "Trust level escalation denied",
                gate_type="trust_escalation")

        # 6. Permitted delegation targets
        if not self._check_permitted_delegations(
                source_manifest, target_agent_id):
            self.audit_bus.emit(
                EventType.TRUST_DENY, source_manifest,
                target_agent_id=target_agent_id, outcome="deny",
                detail={"deny_reason": "delegation_target_not_permitted"})
            return TrustDecision(
                "deny",
                f"Agent '{target_agent_id}' not in permitted delegations",
                gate_type="target_not_permitted")

        # 7. Register resolved manifest for downstream hooks
        self.registry.register_active(
            target_agent_id, target_manifest, session_id)

        # 8. Issue delegation token and emit event
        token = self._issue_delegation_token(
            source_manifest, target_manifest, task_description)
        self.audit_bus.emit(
            EventType.DELEGATION_EVENT, source_manifest,
            target_agent_id=target_agent_id, outcome="allow",
            detail={
                "delegation_token": token,
                "target_trust_level": target_manifest.get("trust_level"),
                "target_classification": target_manifest.get(
                    "data_classification"),
                "autonomy_depth_remaining": target_manifest.get(
                    "max_autonomy_depth"),
                "task_description_hash": hashlib.sha256(
                    task_description.encode()).hexdigest()[:16],
            })

        return TrustDecision(
            "allow", resolved_manifest=target_manifest,
            delegation_token=token)

    def _check_permitted_delegations(self, source_manifest: dict,
                                     target_agent_id: str) -> bool:
        """Check if target is in source's permitted_delegations."""
        permitted = source_manifest.get("permitted_delegations")
        if permitted is None:
            return False
        if not permitted:
            return False
        for pattern in permitted:
            if fnmatch.fnmatch(target_agent_id, pattern):
                return True
        return False

    def _issue_delegation_token(self, source: dict, target: dict,
                                task_description: str) -> str:
        """Generate unique delegation token for forensic linkage."""
        payload = (
            f"{source.get('audit_session_id', 'unknown')}:"
            f"{source.get('manifest_id', 'unknown')}:"
            f"{target.get('manifest_id', 'unknown')}:"
            f"{datetime.now(timezone.utc).isoformat()}:"
            f"{secrets.token_hex(8)}")
        return hashlib.sha256(payload.encode()).hexdigest()[:24]
