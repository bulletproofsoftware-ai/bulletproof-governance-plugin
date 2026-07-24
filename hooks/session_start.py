#!/usr/bin/env python3
"""Governance SessionStart hook — bootstrap governance for the session.

Initializes audit bus, registers conductor manifest, validates all
static manifests, writes session state. Never blocks session start.
"""

import json
import os
import sys
import uuid
from pathlib import Path

# Bootstrap import path
PLUGIN_ROOT = Path(os.environ.get(
    "CLAUDE_PLUGIN_ROOT",
    str(Path(__file__).resolve().parent.parent)))
sys.path.insert(0, str(PLUGIN_ROOT))


def main():
    try:
        # Read stdin (SessionStart sends empty or minimal input)
        sys.stdin.read()

        from governance.lib.audit_bus import EventType
        from governance.lib.manifest import (
            DEFAULT_RESTRICTIVE_MANIFEST,
            _hash_manifest,
            load_all_static_manifests,
            load_static_manifest,
            validate_manifest,
        )
        from governance.lib.singletons import (
            get_audit_bus,
            get_registry,
            write_session_state,
        )

        audit_bus = get_audit_bus()
        session_id = str(uuid.uuid4())

        # Stamp session into conductor manifest FIRST
        conductor_manifest = load_static_manifest("conductor")
        if conductor_manifest:
            conductor_manifest["audit_session_id"] = session_id
            conductor_manifest["manifest_hash"] = _hash_manifest(
                conductor_manifest)
        else:
            conductor_manifest = DEFAULT_RESTRICTIVE_MANIFEST.copy()
            conductor_manifest["agent_id"] = "conductor"
            conductor_manifest["audit_session_id"] = session_id

        # Register — downstream delegation chains inherit from this
        registry = get_registry()
        registry.purge_stale()
        registry.register_active("conductor", conductor_manifest, session_id)

        # Write session state
        write_session_state({
            "audit_session_id": session_id,
            "conductor_manifest_hash": conductor_manifest.get(
                "manifest_hash"),
        })

        # Validate all static manifests
        manifests = load_all_static_manifests()
        invalid = [m for m in manifests if not validate_manifest(m)]

        # Emit session start event
        audit_bus.emit(
            EventType.MANIFEST_LOADED, manifest=conductor_manifest,
            detail={
                "manifests_loaded": len(manifests),
                "manifests_invalid": len(invalid),
                "audit_db_health": audit_bus.health_check(),
            })

        msg = (f"[Governance] Session {session_id[:8]}... initialized. "
               f"{len(manifests)} manifests loaded.")
        if invalid:
            names = [m.get("agent_id", "?") for m in invalid]
            msg += (f" {len(invalid)} invalid "
                    f"(using restrictive defaults): {names}")

        # Output empty JSON — systemMessage stdout gets displayed to user
        print('{}')

    except Exception:
        # Never block session start
        print('{}')


if __name__ == "__main__":
    main()
