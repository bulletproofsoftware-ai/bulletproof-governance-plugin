"""Governance memory governor — content classification and approval gates.

Classifies memory write content, enforces agent ceiling,
tags provenance, gates restricted/confidential writes.
"""

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from governance.lib.audit_bus import AuditBus, EventType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CLASSIFICATION_ORDER = ["public", "internal", "confidential", "restricted"]


# ---------------------------------------------------------------------------
# GovernanceDecision
# ---------------------------------------------------------------------------
@dataclass
class GovernanceDecision:
    action: str              # allow, block, human_gate
    classification: str      # public, internal, confidential, restricted
    provenance: Optional[dict] = field(default=None)
    reason: str = ""
    gate_type: str = ""      # ceiling_exceeded | restricted_blocked | confidential_queued


# ---------------------------------------------------------------------------
# MemoryGovernor
# ---------------------------------------------------------------------------
class MemoryGovernor:
    def __init__(self, audit_bus: AuditBus):
        self.audit_bus = audit_bus
        self.classification_patterns = load_classification_patterns()

    def _classify_content(self, content: str) -> str:
        """Pattern-match content to classification level. Highest match wins."""
        for level in reversed(CLASSIFICATION_ORDER):  # restricted first
            if level == "public":
                continue
            patterns = self.classification_patterns.get(level, [])
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return level
        return "public"

    def classify_and_gate(self, manifest: dict, content: str,
                          tool_input: dict) -> GovernanceDecision:
        """Classify content and apply governance gates.

        Returns GovernanceDecision with action and optional provenance tags.
        """
        # 1. Classify content
        classification = self._classify_content(content)

        # 2. Ceiling check — agent can't write above its classification
        agent_ceiling = manifest.get("data_classification", "public")
        if CLASSIFICATION_ORDER.index(classification) > \
           CLASSIFICATION_ORDER.index(agent_ceiling):
            self.audit_bus.emit(
                EventType.POLICY_DENY, manifest,
                tool_name="mcp__claude-memory__memory_store",
                outcome="deny",
                detail={
                    "deny_reason": "classification_ceiling_exceeded",
                    "content_classification": classification,
                    "agent_ceiling": agent_ceiling})
            return GovernanceDecision(
                "block", classification,
                reason=f"Content classified '{classification}' exceeds "
                       f"agent ceiling '{agent_ceiling}'",
                gate_type="ceiling_exceeded")

        # 3. Restricted = block (never persist before approval)
        if classification == "restricted":
            self.audit_bus.emit(
                EventType.POLICY_DENY, manifest,
                tool_name="mcp__claude-memory__memory_store",
                outcome="deny",
                detail={
                    "deny_reason": "restricted_content_blocked",
                    "classification": classification})
            return GovernanceDecision(
                "block", classification,
                reason="Restricted content blocked — requires human "
                       "approval via /governance-review before storage",
                gate_type="restricted_blocked")

        # 4. Confidential = queue-and-proceed (persists with pending_review tag).
        # SCHEDULED gate — confidential classification is a designed-in policy,
        # not mid-flight friction. gate_id + gate_kind enable the
        # outcome-collector to pair this open with a HUMAN_GATE_RESPONSE later.
        if classification == "confidential":
            import uuid as _uuid
            from datetime import datetime as _dt, timezone as _tz
            from governance.lib.singletons import (
                track_pending_gate as _track_pending_gate)

            _gate_id = str(_uuid.uuid4())
            _started_iso = _dt.now(_tz.utc).isoformat()
            self.audit_bus.emit(
                EventType.HUMAN_GATE, manifest,
                tool_name="mcp__claude-memory__memory_store",
                outcome="escalate",
                detail={
                    "gate_id": _gate_id,
                    "gate_reason": "confidential_write_queued",
                    "gate_kind": "scheduled",
                    "prompt_shown": "Confidential memory write requires review",
                    "wait_start": _started_iso,
                    "classification": classification})
            _track_pending_gate(_gate_id,
                                "mcp__claude-memory__memory_store",
                                "scheduled", _started_iso)
            provenance = self._build_provenance(manifest)
            provenance["gov_approval_status"] = "pending_review"
            provenance["gov_gate_reason"] = (
                f"Classification '{classification}' requires review")
            return GovernanceDecision(
                "allow", classification, provenance,
                reason=f"Queued for review ('{classification}')",
                gate_type="confidential_queued")

        # 5. Public/internal — build provenance and allow
        provenance = self._build_provenance(manifest)
        self.audit_bus.emit(
            EventType.MEMORY_WRITE, manifest,
            tool_name="mcp__claude-memory__memory_store",
            outcome="allow",
            detail={
                "classification": classification,
                "collection": tool_input.get("collection", "claude_memories")})

        return GovernanceDecision("allow", classification, provenance)

    def _build_provenance(self, manifest: dict) -> dict:
        """Build provenance metadata tags for memory writes."""
        return {
            "gov_manifest_id": manifest.get("manifest_id", "unknown"),
            "gov_agent_id": manifest.get("agent_id",
                                         manifest.get("manifest_id", "unknown")),
            "gov_manifest_version": manifest.get("manifest_version"),
            "gov_manifest_hash": manifest.get("manifest_hash"),
            "gov_trust_level": manifest.get("trust_level"),
            "gov_classification": manifest.get("data_classification"),
            "gov_session_id": manifest.get("audit_session_id"),
            "gov_task_id": manifest.get("task_id"),
            "gov_timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------
def load_classification_patterns(path: Optional[Path] = None) -> dict:
    """Load content classification patterns from YAML."""
    if path is None:
        plugin_root = Path(os.environ.get(
            "GOVERNANCE_PLUGIN_ROOT",
            str(Path(__file__).resolve().parent.parent.parent)))
        path = plugin_root / "state" / "classification-patterns.yaml"
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}
