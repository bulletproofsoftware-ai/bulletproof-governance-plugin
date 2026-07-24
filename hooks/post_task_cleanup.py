#!/usr/bin/env python3
"""Governance PostToolUse hook (Task matcher) — cleanup after delegation.

Deregisters the completed agent from the manifest registry.
Minimal, non-blocking.
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
            return

        input_data = json.loads(raw)
        tool_input = input_data.get("tool_input", {})

        from governance.lib.singletons import get_registry, load_session_state
        from governance.lib.trust_broker import _extract_target_agent

        target_agent_id = _extract_target_agent(tool_input)
        if not target_agent_id:
            return

        session_state = load_session_state()
        session_id = session_state.get("audit_session_id")

        registry = get_registry()
        registry.deregister(target_agent_id, session_id)

    except Exception:
        pass  # Never block on cleanup


if __name__ == "__main__":
    main()
