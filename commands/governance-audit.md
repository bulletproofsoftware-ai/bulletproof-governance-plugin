---
name: governance-audit
description: Forensic query and export of governance audit events
user_invocable: true
---

# /governance-audit — Forensic Event Query

Search and export governance audit events for forensic analysis.

## Usage

`/governance-audit [filters]`

### Filter examples:
- `/governance-audit` — show last 20 events from current session
- `/governance-audit agent=conductor-builder` — filter by agent
- `/governance-audit type=policy_deny` — filter by event type
- `/governance-audit outcome=deny` — filter by outcome
- `/governance-audit export` — export current session to JSONL

## Steps

1. **Load governance singletons:**
   ```python
   import os, sys
   sys.path.insert(0, os.environ.get("GOVERNANCE_PLUGIN_ROOT", os.path.expanduser("~/.claude/plugins/local/governance-plugin")))
   from governance.lib.singletons import get_audit_bus, load_session_state
   ```

2. **Parse filters from arguments** (if provided):
   - `agent=X` → `{"agent_id": X}`
   - `type=X` → `{"event_type": X}`
   - `outcome=X` → `{"outcome": X}`
   - `session=X` → `{"audit_session_id": X}`
   - No filters → use current session ID

3. **Query audit bus:**
   ```python
   bus = get_audit_bus()
   session = load_session_state()
   filters = parsed_filters or {"audit_session_id": session.get("audit_session_id")}
   events = bus.query(filters, limit=20)
   ```

4. **Display results** in table format:
   ```
   ID          Time                 Type            Agent              Tool       Outcome
   ─────────── ──────────────────── ─────────────── ────────────────── ────────── ────────
   abc12345    2026-03-04T12:00:00  delegation      conductor          Task       allow
   def67890    2026-03-04T12:00:01  policy_deny     conductor-builder  Bash       deny
   ```

5. **If `export` argument:**
   ```python
   from pathlib import Path
   out = Path(f"governance-audit-{session_id[:8]}.jsonl")
   count = bus.export_jsonl(session_id, out)
   ```
   Report: "Exported {count} events to {path}"

## Valid event_type values:
tool_invoked, delegation_event, context_pressure, memory_write, memory_read,
policy_check, policy_deny, human_gate, manifest_loaded, manifest_derived,
trust_check, trust_deny, circuit_break, buffer_replay

## Valid outcome values:
allow, deny, escalate, error
