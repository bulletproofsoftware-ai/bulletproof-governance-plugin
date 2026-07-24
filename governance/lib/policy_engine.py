"""Governance policy engine — runtime tool risk evaluation.

Classifies tools into tiers (exempt/standard/elevated), checks manifest
permissions, applies conductor tier matrix for gate decisions.
"""

import fnmatch
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from governance.lib.audit_bus import AuditBus, EventType


def _emit_human_gate(audit_bus: AuditBus, manifest: dict, tool_name: str,
                     gate_reason: str, gate_kind: str,
                     extra_detail: Optional[dict] = None) -> None:
    """Emit HUMAN_GATE with gate_id + gate_kind, and stash a pending-gate
    record so post_tool_metrics can pair the response.

    gate_kind:
      "scheduled"   = designed-in approval (manifest, tier matrix, classification)
      "unscheduled" = mid-flight friction (depth exhausted, etc.)
    """
    # Late import to avoid a circular dep with singletons (which imports
    # this module via the policy engine getter).
    from governance.lib.singletons import track_pending_gate

    gate_id = str(uuid.uuid4())
    started_iso = datetime.now(timezone.utc).isoformat()
    detail = {
        "gate_id": gate_id,
        "gate_reason": gate_reason,
        "gate_kind": gate_kind,
        "prompt_shown": gate_reason,
        "wait_start": started_iso,
    }
    if extra_detail:
        detail.update(extra_detail)
    audit_bus.emit(EventType.HUMAN_GATE, manifest,
                   tool_name=tool_name, outcome="escalate",
                   detail=detail)
    track_pending_gate(gate_id, tool_name, gate_kind, started_iso)


# ---------------------------------------------------------------------------
# PolicyDecision
# ---------------------------------------------------------------------------
@dataclass
class PolicyDecision:
    action: str          # allow, deny, human_gate
    reason: str = ""
    gate_type: str = ""  # permitted_tools | depth_exhausted | manifest_required | tier_matrix


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------
class PolicyEngine:
    def __init__(self, audit_bus: AuditBus, tool_tiers: dict):
        self.audit_bus = audit_bus
        self.tool_tiers = tool_tiers

    def _classify_tool(self, tool_name: str) -> str:
        """Classify tool into exempt/standard/elevated tier."""
        if tool_name in self.tool_tiers.get("exempt", []):
            return "exempt"
        if tool_name in self.tool_tiers.get("elevated", []):
            return "elevated"
        for pattern in self.tool_tiers.get("elevated_patterns", []):
            if fnmatch.fnmatch(tool_name, pattern):
                return "elevated"
        if tool_name in self.tool_tiers.get("standard", []):
            return "standard"
        # Unknown tools default to elevated — fail toward scrutiny
        return "elevated"

    def _tool_permitted(self, manifest: dict, tool_name: str) -> bool:
        """Check if tool is in agent's permitted_tools (supports fnmatch)."""
        permitted = manifest.get("permitted_tools", [])
        if not permitted:
            return False
        for pattern in permitted:
            if fnmatch.fnmatch(tool_name, pattern):
                return True
        return False

    def evaluate(self, manifest: dict, tool_name: str,
                 tool_input: dict, conductor_tier: Optional[str]) -> PolicyDecision:
        """Evaluate whether an agent can use a tool.

        Returns PolicyDecision with action: allow, deny, or human_gate.
        """
        tier = self._classify_tool(tool_name)

        # Exempt tools — always allow, audit async
        if tier == "exempt":
            self.audit_bus.emit_nowait(EventType.TOOL_INVOKED, manifest,
                                       tool_name=tool_name, outcome="allow")
            return PolicyDecision("allow")

        # --- Manifest checks (all tiers above exempt) ---

        # 1. Tool in permitted_tools?
        if not self._tool_permitted(manifest, tool_name):
            self.audit_bus.emit(EventType.POLICY_DENY, manifest,
                               tool_name=tool_name, outcome="deny",
                               detail={"deny_reason": "tool_not_permitted"})
            return PolicyDecision("deny", "Tool not in agent's permitted_tools",
                                 gate_type="permitted_tools")

        # 2. Autonomy depth exhausted?
        # This is an UNSCHEDULED gate — agent ran out of autonomy budget,
        # not a designed-in approval point. Also emits AGENT_ESCALATE so
        # the outcome-collector counts it toward Escalation Rate.
        if manifest.get("max_autonomy_depth", 0) <= 0:
            self.audit_bus.emit(EventType.CIRCUIT_BREAK, manifest,
                               tool_name=tool_name, outcome="escalate")
            self.audit_bus.emit(
                EventType.AGENT_ESCALATE, manifest,
                tool_name=tool_name, outcome="escalate",
                detail={
                    "escalation_kind": "boundary",
                    "from_agent": manifest.get("agent_id", "unknown"),
                    "task_description_hash": "",
                    "retry_count": 0,
                    "operator_action_requested": "extend autonomy depth or take over",
                })
            _emit_human_gate(self.audit_bus, manifest, tool_name,
                             gate_reason="autonomy_depth_exhausted",
                             gate_kind="unscheduled")
            return PolicyDecision("human_gate", "Autonomy depth exhausted",
                                 gate_type="depth_exhausted")

        # 3. Human approval required by manifest?
        # SCHEDULED — manifest explicitly designed for human approval on this tool.
        if manifest.get("human_required", False):
            _emit_human_gate(self.audit_bus, manifest, tool_name,
                             gate_reason="manifest_required",
                             gate_kind="scheduled")
            return PolicyDecision("human_gate",
                                 "Agent manifest requires human approval",
                                 gate_type="manifest_required")

        # --- Conductor tier matrix ---
        effective_tier = conductor_tier or "STANDARD"

        # MAJOR + elevated = always human gate.
        # SCHEDULED — tier matrix is part of the conductor's designed gate policy.
        if tier == "elevated" and effective_tier == "MAJOR":
            _emit_human_gate(self.audit_bus, manifest, tool_name,
                             gate_reason="major_tier_elevated_tool",
                             gate_kind="scheduled",
                             extra_detail={"conductor_tier": effective_tier})
            return PolicyDecision("human_gate",
                                 "MAJOR task + elevated tool requires human approval",
                                 gate_type="tier_matrix")

        # Synchronous audit for elevated or STANDARD+
        if tier == "elevated" or effective_tier in ("STANDARD", "MAJOR"):
            self.audit_bus.emit(EventType.POLICY_CHECK, manifest,
                               tool_name=tool_name, outcome="allow",
                               detail={"conductor_tier": effective_tier})
        else:
            self.audit_bus.emit_nowait(EventType.TOOL_INVOKED, manifest,
                                       tool_name=tool_name, outcome="allow")

        return PolicyDecision("allow")


# ---------------------------------------------------------------------------
# Config loaders
# ---------------------------------------------------------------------------
def load_tool_tiers(path: Optional[Path] = None) -> dict:
    """Load tool tier configuration from YAML file."""
    if path is None:
        plugin_root = Path(os.environ.get(
            "GOVERNANCE_PLUGIN_ROOT",
            str(Path(__file__).resolve().parent.parent.parent)))
        path = plugin_root / "state" / "tool-tiers.yaml"
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def load_conductor_tier() -> Optional[str]:
    """Load current conductor tier from conductor-state.json."""
    state_path = Path(os.environ.get(
        "CONDUCTOR_STATE_PATH", "conductor-state.json"))
    try:
        if not state_path.exists():
            return None
        with open(state_path) as f:
            state = json.load(f)
        return state.get("governance", {}).get("conductor_tier")
    except Exception:
        return None
