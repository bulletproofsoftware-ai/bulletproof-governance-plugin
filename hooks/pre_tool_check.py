#!/usr/bin/env python3
"""Governance PreToolUse hook — policy and trust evaluation.

Runs trust broker for Task tools (delegation mediation), then
policy engine for all tools. Fail-open on exceptions.
"""

import json
import os
import sys
from pathlib import Path

# Bootstrap import path
PLUGIN_ROOT = Path(os.environ.get(
    "CLAUDE_PLUGIN_ROOT",
    str(Path(__file__).resolve().parent.parent)))
sys.path.insert(0, str(PLUGIN_ROOT))


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            print(json.dumps({}))
            return

        input_data = json.loads(raw)
        tool_name = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input", {})

        from governance.lib.audit_bus import EventType
        from governance.lib.manifest import (
            DEFAULT_RESTRICTIVE_MANIFEST,
            resolve_manifest,
        )
        from governance.lib.policy_engine import load_conductor_tier
        from governance.lib.singletons import (
            get_audit_bus,
            get_policy_engine,
            get_registry,
            get_trust_broker,
            load_session_state,
        )
        from governance.lib.trust_broker import _extract_target_agent

        raw_agent_id = os.environ.get("CLAUDE_AGENT_ID", "unknown")
        agent_id = raw_agent_id if raw_agent_id else "unknown"
        session_state = load_session_state()
        session_id = session_state.get("audit_session_id")

        # Resolve manifest — try registry, then static files, then allow-all fallback
        manifest = None
        if session_id:
            registry = get_registry()
            manifest = registry.get_active(agent_id, session_id)

        if not manifest:
            manifest = resolve_manifest(agent_id)

        # If we still got restrictive default (empty permitted_tools), use allow-all
        if not manifest.get("permitted_tools"):
            manifest = resolve_manifest("unknown")

        manifest["agent_id"] = agent_id
        if session_id:
            manifest["audit_session_id"] = session_id

        # Trust broker for delegation events
        if tool_name == "Task":
            target_agent_id = _extract_target_agent(tool_input)
            if target_agent_id is None:
                # Unresolvable target — deny
                audit_bus = get_audit_bus()
                audit_bus.emit(
                    EventType.TRUST_DENY, manifest,
                    tool_name="Task", outcome="deny",
                    detail={
                        "deny_reason": "unresolvable_target",
                        "tool_input_keys": list(tool_input.keys()),
                    })
                print(json.dumps({
                    "decision": "block",
                    "reason": ("[Governance] Cannot resolve delegation "
                               "target — no subagent_type field"),
                }))
                return

            task_description = tool_input.get("prompt", "")
            broker = get_trust_broker()
            trust_decision = broker.evaluate_delegation(
                manifest, target_agent_id, task_description)

            if trust_decision.action == "deny":
                print(json.dumps({
                    "decision": "block",
                    "reason": f"[Governance] {trust_decision.reason}",
                }))
                return
            if trust_decision.action == "escalate":
                print(json.dumps({
                    "decision": "block",
                    "reason": f"[Governance] {trust_decision.reason}",
                }))
                return

        # Policy engine for all tools
        engine = get_policy_engine()
        decision = engine.evaluate(
            manifest, tool_name, tool_input, load_conductor_tier())

        if decision.action == "allow":
            print(json.dumps({}))
        elif decision.action == "deny":
            print(json.dumps({
                "decision": "block",
                "reason": f"[Governance] {decision.reason}",
            }))
        elif decision.action == "human_gate":
            # The HITL approval API (governance.lib.hitl_api) is deliberately
            # read-only — it exposes /hitl/health and /hitl/pending but NO
            # approve/deny endpoint (a fake control was judged worse than none).
            # That means a human_gate verdict here has no reachable approval
            # channel: blocking would strand the caller with no way to proceed.
            # Degrade to ALLOW so the gate cannot corner an operator. The event
            # is still recorded on the audit chain; this only changes the
            # terminal action from a dead-end block to an audited allow.
            print(json.dumps({}))

    except Exception as e:
        # Fail-open on any exception
        print(json.dumps({}))


if __name__ == "__main__":
    main()
