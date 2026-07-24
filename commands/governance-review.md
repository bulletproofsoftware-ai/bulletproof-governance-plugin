---
name: governance-review
description: Review pending governance items — confidential memory writes awaiting approval
user_invocable: true
---

# /governance-review — Pending Approval Queue

You are reviewing memory writes that were classified as **confidential** and tagged with `gov_approval_status: "pending_review"`.

## Steps

1. **Load governance singletons:**
   ```python
   import os, sys
   sys.path.insert(0, os.environ.get("GOVERNANCE_PLUGIN_ROOT", os.path.expanduser("~/.claude/plugins/local/governance-plugin")))
   from governance.lib.singletons import get_audit_bus
   ```

2. **Query audit bus for pending items:**
   ```python
   bus = get_audit_bus()
   pending = bus.query({"event_type": "human_gate", "outcome": "escalate"}, limit=50)
   ```

3. **For each pending event, display:**
   - Agent ID and manifest ID
   - Content classification
   - Gate reason
   - Timestamp
   - Event detail (truncated to 200 chars)

4. **For each item, ask the user:**
   - **Approve**: Update the memory's metadata `gov_approval_status` to `"approved"` via `mcp__claude-memory__memory_store`
   - **Deny**: Remove the memory from Qdrant via the memory plugin's purge capability
   - **Skip**: Move to next item

5. **Concurrency guard:** Before processing each item, verify the event hasn't already been processed by checking for a subsequent `POLICY_CHECK` event with the same `event_id` reference.

6. **Summary:** After processing all items, display:
   - Items approved
   - Items denied
   - Items skipped
   - Remaining pending count

## If no pending items:
Report: "No pending governance reviews. All clear."
