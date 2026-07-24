---
name: governance-status
description: Display governance framework health and session status
user_invocable: true
---

# /governance-status — Governance Health Display

Read-only health and status display for the governance framework.

## Steps

1. **Load governance singletons:**
   ```python
   import os, sys
   sys.path.insert(0, os.environ.get("GOVERNANCE_PLUGIN_ROOT", os.path.expanduser("~/.claude/plugins/local/governance-plugin")))
   from governance.lib.singletons import get_audit_bus, get_registry, load_session_state
   ```

2. **Gather data:**

   **Audit Bus Health:**
   ```python
   bus = get_audit_bus()
   health = bus.health_check()
   ```
   Display: event_count, db_path, buffer_pending, last_event_ts, DB file size.

   **Session State:**
   ```python
   session = load_session_state()
   ```
   Display: audit_session_id (truncated), conductor_manifest_hash (truncated).

   **Manifest Registry:**
   ```python
   registry = get_registry()
   ```
   Display: active manifest count, session ID.

   **Pending Reviews:**
   ```python
   pending = bus.query({"event_type": "human_gate", "outcome": "escalate"}, limit=100)
   ```
   Display: count of pending review items.

   **Recent Denials (last 5):**
   ```python
   denials = bus.query({"outcome": "deny"}, limit=5)
   ```
   For each: event_type, agent_id, tool_name, detail (deny_reason), timestamp.

   **Session Totals:**
   ```python
   all_events = bus.query({"audit_session_id": session.get("audit_session_id")}, limit=10000)
   ```
   Count by event_type and outcome. Display delegation count, policy checks, gates.

3. **Format as a clean table/report** and display to the user.

## Output Format

```
Governance Status
═══════════════════════════════════════
Session:     {session_id[:8]}...
DB Events:   {count}
Buffer:      {pending} pending
Last Event:  {timestamp}

Manifest Registry: {active_count} active
Pending Reviews:   {review_count}

Recent Denials:
  [{timestamp}] {agent_id} → {tool_name}: {reason}
  ...

Session Totals:
  Delegations: {n} allowed, {m} denied
  Policy:      {n} checks, {m} denials
  Gates:       {n} human gates triggered
```
