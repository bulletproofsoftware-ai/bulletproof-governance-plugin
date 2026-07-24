# How to Use — bulletproof-governance-plugin

Once installed (see [INSTALL.md](INSTALL.md)), the governance layer runs
automatically through Claude Code hooks. You interact with it mainly through
three slash commands and by editing the policy YAMLs. This guide covers the
day-to-day flow.

## What happens automatically

Every Claude Code session and tool call is governed without any action on your
part:

1. **Session start.** `session_start.py` initializes the audit bus, registers the
   `conductor` manifest for the session, validates all static manifests, and
   writes `state/session-state.json`. Session start is never blocked.

2. **Before each tool call** (`PreToolUse`):
   - `pre_tool_security.py` runs threat detection (prompt injection, privilege
     escalation, exfiltration, tool abuse, memory poisoning). A blocking threat
     returns `{"decision": "block"}`. **Fails closed** on unknown errors,
     fail-open on missing deps / infra outages.
   - For `memory_store` calls, `memory_integrity_hook.py` runs the 4-stage
     integrity pipeline. **Fails closed.**
   - `pre_tool_check.py` runs the trust broker (for `Task` delegations) and the
     policy engine (for all tools), producing `allow` / `deny` / `human_gate`.
     **Fails open.**

3. **After each tool call** (`PostToolUse`):
   - `post_tool_metrics.py` records behavioral metrics and updates baselines.
   - `post_tool_security.py` scans the tool's *response* for secondary prompt
     injection and credential/PII leakage, and injects a warning into the next
     turn if it finds any.
   - After a `Task` completes, `post_task_cleanup.py` deregisters that agent.

## Tool tiers and permissions

A tool call is allowed only if the calling agent's manifest lists it in
`permitted_tools` (fnmatch patterns supported), *and* it passes the tier rules
in `state/tool-tiers.yaml`:

- **exempt** — always allowed, audited asynchronously (e.g. `Read`, `Glob`,
  `Grep`). Unknown tools are **not** exempt; they default to `elevated`
  ("fail toward scrutiny").
- **standard** — subject to manifest permission + tier-matrix checks
  (e.g. `Edit`, `Write`, `Bash`, `Task`).
- **elevated** — highest scrutiny (e.g. `mcp__claude-memory__memory_forget`,
  `NotebookEdit`, and anything matched by `elevated_patterns`). With a `MAJOR`
  conductor tier, an elevated tool always triggers a human gate.

## Delegation (Task) governance

When an agent uses `Task` to delegate, the trust broker evaluates the request in
order and can `allow`, `deny`, or `escalate`:

- **breadth** — the source may not exceed its `max_delegation_count` for the
  session;
- **depth** — `max_autonomy_depth` must be > 0 (else escalate for human
  approval);
- **classification boundary** — the target may not exceed the source's data
  classification;
- **trust escalation** — the target's `trust_level` may not exceed the source's;
- **permitted targets** — the target must match a pattern in the source's
  `permitted_delegations`.

On allow, the broker issues a delegation token, registers the resolved target
manifest, and emits a `delegation_event`.

## Memory-write governance

When an agent calls `mcp__claude-memory__memory_store`, the memory governor
classifies the content and gates it:

| Classification | Action |
|----------------|--------|
| `public` / `internal` | **allow**, tagged with provenance metadata. |
| `confidential` | **queue-and-proceed** — persists with `gov_approval_status: pending_review` and opens a scheduled human gate. Review with `/governance-review`. |
| `restricted` | **block** — never persisted before human approval. |
| above the agent's ceiling | **block** — an agent cannot write content classified higher than its own `data_classification`. |

## Slash commands

### `/governance-status`
Read-only health and session status: audit-DB event count, buffer backlog, last
event timestamp, active manifest count, pending-review count, recent denials, and
session totals by event type.

### `/governance-audit`
Forensic query and export of audit events. Examples:

```
/governance-audit                              # last 20 events, current session
/governance-audit agent=conductor-builder      # filter by agent
/governance-audit type=policy_deny             # filter by event type
/governance-audit outcome=deny                 # filter by outcome
/governance-audit export                        # export session to JSONL
```

Valid event types include: `tool_invoked`, `delegation_event`, `memory_write`,
`policy_check`, `policy_deny`, `human_gate`, `manifest_loaded`, `trust_deny`,
`circuit_break`, `buffer_replay`. Valid outcomes: `allow`, `deny`, `escalate`,
`error`.

### `/governance-review`
Reviews memory writes classified `confidential` and tagged
`gov_approval_status: pending_review`. For each item you can **approve** (updates
the metadata to `approved`), **deny** (removes it from Qdrant), or **skip**.

## Approvals are Claude Code's own prompts

There is **no external approve/deny endpoint**. When the policy engine returns a
`human_gate`, the actual approval is Claude Code's in-session permission prompt.
The HITL API (`governance/lib/hitl_api.py`) exposes gate *observability* only —
see [ADMINISTRATOR.md](ADMINISTRATOR.md).

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
