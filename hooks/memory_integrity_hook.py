#!/usr/bin/env python3
"""Memory Integrity PreToolUse hook — 4-stage pipeline for memory writes.

Matches: mcp__claude-memory__memory_store
Runs BEFORE pre_tool_check.py. FAIL CLOSED on exception.

Pipeline: provenance -> semantic consistency -> fact verification -> anomaly scoring.
On failure: quarantine or reject, then block the write.
"""

import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Bootstrap import path
PLUGIN_ROOT = Path(os.environ.get(
    "CLAUDE_PLUGIN_ROOT",
    str(Path(__file__).resolve().parent.parent)))
sys.path.insert(0, str(PLUGIN_ROOT))

# ── Feature 1: provenance / use-policy gate (deterministic Stage 0) ──────────
# CISO Condition A — Trust boundary: the derivation defaults are server-side and
# never client-trusted; an EXPLICIT provenance_status is honored verbatim
# (explicit wins over derivation). This gate defends the *class of writer*
# (a low-trust automated extractor identified by `source` can never mint an
# instruction-grade memory for itself), NOT authentication of a human's intent.
#
# CISO Condition B — This _derive_prov MUST stay byte-for-byte equivalent in
# behavior to the TS deriveProvenance() in claude-memory-mcp/src/index.ts. A
# conformance test (governance-plugin pytest + the MCP repo's vitest, both fed
# tests/fixtures/provenance-derivation.json) asserts identical output for a shared
# vector of inputs and FAILS THE BUILD if the two ever diverge. If you edit this
# regex/enum, edit the TS one too.
_PROVENANCE_VALUES = (
    "observed", "inferred", "user_confirmed", "imported", "generated",
)
_DERIVE_AUTO_RE = re.compile(r"auto|analyz|extract|summari|generat|digest|consolidat")


def _derive_prov(src):
    """Mirror of TS deriveProvenance(). `src` is a lowercased string (or '')."""
    if not src:
        return "observed"
    if _DERIVE_AUTO_RE.search(src):
        return "generated"
    if src == "user":
        return "user_confirmed"
    if src in ("import", "imported"):
        return "imported"
    return "observed"


def _use_policy_block(tool_input):
    """Return True (and print a decision:block) iff the write must be rejected for
    a use-policy violation. No I/O — cannot raise on infrastructure."""
    prov = tool_input.get("provenance_status")
    source = (tool_input.get("source") or "").lower()
    effective_prov = prov if prov in _PROVENANCE_VALUES else _derive_prov(source)

    if tool_input.get("can_use_as_instruction") is True and \
       effective_prov not in ("user_confirmed", "imported"):
        print(json.dumps({
            "decision": "block",
            "reason": ("[Policy] can_use_as_instruction=true requires "
                       "provenance_status user_confirmed|imported "
                       f"(effective='{effective_prov}'). Memory write rejected."),
        }))
        return True
    return False


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            print(json.dumps({}))
            return

        input_data = json.loads(raw)
        tool_name = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input", {})

        # Only intercept memory_store calls
        if "memory_store" not in tool_name:
            print(json.dumps({}))
            return

        from governance.lib.singletons import (
            get_memory_integrity,
            get_guardian_agent,
            load_session_state,
            get_registry,
        )
        from governance.lib.manifest import resolve_manifest
        from governance.lib.security.memory_integrity import MemoryEntry

        # Session context
        raw_agent_id = os.environ.get("CLAUDE_AGENT_ID", "unknown")
        agent_id = raw_agent_id if raw_agent_id else "unknown"
        session_state = load_session_state()
        session_id = session_state.get("audit_session_id")

        # Build manifest
        manifest = None
        if session_id:
            registry = get_registry()
            manifest = registry.get_active(agent_id, session_id)
        if not manifest:
            manifest = resolve_manifest(agent_id)
        manifest["agent_id"] = agent_id
        if session_id:
            manifest["audit_session_id"] = session_id

        # Extract memory entry from tool input
        content = tool_input.get("content", "")
        if not content:
            # No content to verify
            print(json.dumps({}))
            return

        # ── Feature 1: deterministic use-policy gate (before the ML pipeline) ──
        # Defense-in-depth backstop to the server-side gate in the MCP server
        # (src/index.ts::resolveUsePolicy). A policy rejection is a deterministic
        # decision:block; it does no I/O so it cannot raise on infrastructure (an
        # infra exception still falls through to the FAIL-OPEN handler below).
        if _use_policy_block(tool_input):
            return

        entry = MemoryEntry(
            id=str(uuid.uuid4()),
            content=content,
            metadata={
                "agent_id": agent_id,
                "session_id": session_id or "",
                "timestamp": tool_input.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                "source_tool": tool_input.get("source_tool", tool_name),
            },
            target_collection=tool_input.get("collection", "claude_memories"),
        )

        # Run integrity pipeline
        integrity = get_memory_integrity()
        result = integrity.verify(entry, manifest)

        if result.blocked:
            # Notify Guardian if quarantined or rejected
            if result.quarantined or result.rejection_reason:
                try:
                    guardian = get_guardian_agent()
                    from governance.lib.security.threat_detection import ThreatEvent
                    from datetime import datetime, timezone
                    guardian.process_event(ThreatEvent(
                        threat_id=str(uuid.uuid4()),
                        type="MEMORY_QUARANTINE" if result.quarantined else "MEMORY_POISONING",
                        severity="HIGH",
                        agent_id=agent_id,
                        session_id=session_id or "",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        evidence={
                            "quarantine_id": result.quarantine_id,
                            "rejection_reason": result.rejection_reason,
                            "stages": [s.stage for s in result.stages if not s.passed],
                        },
                    ))
                except Exception:
                    pass

            reason = result.rejection_reason
            if result.quarantined:
                reason = f"Memory write quarantined (ID: {result.quarantine_id[:8]}...)"

            print(json.dumps({
                "decision": "block",
                "reason": f"[Security] {reason or 'Memory integrity check failed'}",
            }))
            return

        # All clear
        print(json.dumps({}))

    except Exception as e:
        # FAIL OPEN — governance integrity check is supplementary;
        # core dedup/redaction/validation is handled by pre_store.py.
        # Blocking all memory stores on infra errors breaks the system.
        import traceback
        log_dir = Path(os.environ.get(
            "CLAUDE_PLUGIN_ROOT",
            str(Path(__file__).resolve().parent.parent))) / "state"
        log_dir.mkdir(parents=True, exist_ok=True)
        try:
            with open(log_dir / "memory-integrity-errors.log", "a") as f:
                f.write(f"{datetime.now(timezone.utc).isoformat()} {type(e).__name__}: {e}\n")
                traceback.print_exc(file=f)
        except Exception:
            pass
        print(json.dumps({}))


if __name__ == "__main__":
    main()
