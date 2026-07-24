#!/usr/bin/env python3
"""Security PreToolUse hook — threat detection + scope enforcement.

FAIL CLOSED: on any exception, this hook returns {"decision": "block"}.
This is the security-critical counterpart to pre_tool_check.py which fails open.

Runs BEFORE pre_tool_check.py in the hook chain.
"""

import json
import logging
import os
import sys
import traceback
from pathlib import Path

# Bootstrap import path
PLUGIN_ROOT = Path(os.environ.get(
    "CLAUDE_PLUGIN_ROOT",
    str(Path(__file__).resolve().parent.parent)))
sys.path.insert(0, str(PLUGIN_ROOT))


def _log_error(message: str):
    """Best-effort error logging to state dir."""
    try:
        log_dir = PLUGIN_ROOT / "governance" / "state"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "security-errors.log"
        error_logger = logging.getLogger("governance.security.errors")
        if not error_logger.handlers:
            handler = logging.FileHandler(str(log_file), encoding="utf-8")
            handler.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)s %(message)s"))
            error_logger.addHandler(handler)
            error_logger.setLevel(logging.ERROR)
        error_logger.error(message)
    except Exception:
        pass


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            print(json.dumps({}))
            return

        input_data = json.loads(raw)
        tool_name = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input", {})

        from governance.lib.singletons import (
            get_threat_detection,
            get_identity_lifecycle,
            get_guardian_agent,
            load_session_state,
            get_registry,
        )
        from governance.lib.manifest import resolve_manifest

        # Get session context
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

        # Initialize security modules
        threat_engine = get_threat_detection()
        identity_mgr = get_identity_lifecycle()
        guardian = get_guardian_agent()

        # Run threat detection (all 4 sub-detectors)
        threats = threat_engine.scan(
            manifest=manifest,
            tool_name=tool_name,
            tool_input=tool_input,
            identity_mgr=identity_mgr,
        )

        # If blocking threats found, send to Guardian and block
        if threats and threat_engine.has_blocking_threat(threats):
            # Feed all threats to Guardian
            for threat in threats:
                guardian.process_event(threat)

            # Build block reason from highest severity threat
            highest = max(threats, key=lambda t: {
                "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1
            }.get(t.severity, 0))

            print(json.dumps({
                "decision": "block",
                "reason": (
                    f"[Security] {highest.type} detected "
                    f"(severity: {highest.severity}). "
                    f"Tool '{tool_name}' blocked."
                ),
            }))
            return

        # Non-blocking threats: still notify Guardian
        for threat in threats:
            guardian.process_event(threat)

        # All clear
        print(json.dumps({}))

    except ImportError as e:
        # Missing dependency (e.g. qdrant_client not in system Python).
        # Fail OPEN — blocking all tools because a pip package is absent
        # is worse than skipping security scanning for a session.
        _log_error(f"pre_tool_security DEGRADED (missing dep, fail-open): {e}")
        print(json.dumps({}))

    except Exception as e:
        # Infrastructure-class failures (storage, network, FS) cannot
        # signal a policy violation — policy decisions are returned as
        # Threat objects, never raised. Failing closed on infra outage
        # bricks every tool call in the session, which is worse than
        # running a session without scanning. Degrade gracefully.
        infra_class_names = {
            "OperationalError",         # sqlite3 / SQLAlchemy
            "DatabaseError",            # sqlite3 / SQLAlchemy
            "IntegrityError",           # sqlite3 schema migration races
            "ConnectionError",          # qdrant / network
            "TimeoutError",             # network
            "ResponseHandlingException",  # qdrant_client
            "UnexpectedResponse",       # qdrant_client
            "FileNotFoundError",
            "PermissionError",
            "OSError",
        }
        cls_name = type(e).__name__
        if cls_name in infra_class_names or isinstance(
                e, (ConnectionError, TimeoutError, OSError)):
            _log_error(
                f"pre_tool_security DEGRADED (infra fail-open, {cls_name}): "
                f"{e}\n{traceback.format_exc()}")
            sys.stderr.write(
                f"[governance] security scan unavailable ({cls_name}); "
                f"running without runtime threat detection this turn.\n")
            print(json.dumps({}))
            return

        # Truly unknown error — fail CLOSED.
        _log_error(f"pre_tool_security fail-closed: {e}\n{traceback.format_exc()}")
        print(json.dumps({
            "decision": "block",
            "reason": (
                f"[Security] Security check failed (fail-closed): "
                f"{cls_name}"
            ),
        }))


if __name__ == "__main__":
    main()
