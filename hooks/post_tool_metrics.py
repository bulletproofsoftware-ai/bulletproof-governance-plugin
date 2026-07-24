#!/usr/bin/env python3
"""Security PostToolUse hook — behavioral metrics collection.

Records tool usage metrics, updates baselines, checks for anomalies.
Non-blocking: never returns a decision. Fail-open.
"""

import json
import os
import sys
import time
from pathlib import Path

# Bootstrap import path
PLUGIN_ROOT = Path(os.environ.get(
    "CLAUDE_PLUGIN_ROOT",
    str(Path(__file__).resolve().parent.parent)))
sys.path.insert(0, str(PLUGIN_ROOT))

# File-system tools for breadth tracking
FILE_TOOLS = {"Read", "Write", "Edit", "Glob", "Grep"}
EXTERNAL_TOOLS = {"WebFetch", "Bash"}


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return

        input_data = json.loads(raw)
        tool_name = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input", {})
        tool_output = input_data.get("tool_output", {})

        from governance.lib.singletons import (
            get_behavioral_monitor,
            get_guardian_agent,
            get_coordination_scorer,
            load_session_state,
            get_registry,
        )
        from governance.lib.manifest import (
            resolve_manifest,
            set_human_attribution,
            HUMAN_USER_SYSTEM,
        )
        from governance.lib.security.coordination_scorer import ToolCall

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

        # PRD 18 Pillar 1 (REQ-RCA-001/002/004) — anchor the manifest to the
        # authenticated human BEFORE any downstream emit so every audit row
        # this hook produces carries non-NULL human_user_id and a named
        # responsible_person. Resolution order:
        #   1. CLAUDE_USER env var (set by Claude Code if available)
        #   2. CLAUDE_USER_ID env var (alternate)
        #   3. GOVERNANCE_RESPONSIBLE_PERSON env var (deployment-time owner)
        #   4. USER env var (OS-level fallback for single-user dev systems)
        #   5. HUMAN_USER_SYSTEM sentinel (background/autonomous job)
        # Wrapped in try/except so a misconfigured environment never blocks
        # the post-tool hook (fail-open at the attribution layer; the
        # schema's NOT NULL DEFAULT 'system' is still the bottom safety net).
        try:
            human_user_id = (
                os.environ.get("CLAUDE_USER")
                or os.environ.get("CLAUDE_USER_ID")
                or os.environ.get("USER")
                or HUMAN_USER_SYSTEM
            )
            responsible_person = (
                os.environ.get("GOVERNANCE_RESPONSIBLE_PERSON")
                or human_user_id
            )
            manifest = set_human_attribution(
                manifest,
                human_user_id=human_user_id,
                responsible_person=responsible_person,
            )
        except Exception:
            # Attribution helper rejects empty values etc. — fall back to
            # 'system' so emit still has a valid value via _build_event's
            # _normalize_human_user_id helper.
            manifest["human_user_id"] = HUMAN_USER_SYSTEM

        agent_class = manifest.get("agent_class", "")
        monitor = get_behavioral_monitor()
        guardian = get_guardian_agent()

        # Determine if tool output indicates error
        is_error = False
        if isinstance(tool_output, dict):
            is_error = bool(tool_output.get("error") or tool_output.get("is_error"))
        elif isinstance(tool_output, str) and "error" in tool_output.lower()[:50]:
            is_error = True

        # Record file access frequency
        if tool_name in FILE_TOOLS:
            anomaly = monitor.record_metric(
                agent_id, "FILE_ACCESS_FREQUENCY", 1.0,
                agent_class, manifest)
            if anomaly:
                guardian.process_event(_anomaly_to_event(anomaly, session_id))

        # Record directory access breadth
        if tool_name in FILE_TOOLS:
            file_path = tool_input.get("file_path", tool_input.get("path", ""))
            if file_path:
                parts = str(file_path).split("/")
                depth = min(len(parts), 4)
                anomaly = monitor.record_metric(
                    agent_id, "DIRECTORY_ACCESS_BREADTH", float(depth),
                    agent_class, manifest)
                if anomaly:
                    guardian.process_event(_anomaly_to_event(anomaly, session_id))

        # Record external network calls
        if tool_name in EXTERNAL_TOOLS:
            anomaly = monitor.record_metric(
                agent_id, "EXTERNAL_NETWORK_CALLS", 1.0,
                agent_class, manifest)
            if anomaly:
                guardian.process_event(_anomaly_to_event(anomaly, session_id))

        # Record error rate
        if is_error:
            anomaly = monitor.record_metric(
                agent_id, "ERROR_RATE", 1.0,
                agent_class, manifest)
            if anomaly:
                guardian.process_event(_anomaly_to_event(anomaly, session_id))

        # Record tool call for TUE
        scorer = get_coordination_scorer()
        scorer.record_tool_call(agent_id, ToolCall(
            tool_name=tool_name,
            outcome_class="error" if is_error else "success",
            is_redundant=False,
            is_false_positive=False,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        ))

        # ---- Outcome-collector signals ----
        # 1. HUMAN_GATE_RESPONSE: pair an open gate with the operator's
        #    response. If the tool that just ran matches the pending gate,
        #    the user approved (the tool would have been blocked otherwise).
        #    If a different tool ran instead, treat as redirect/abandon.
        # 2. AGENT_ESCALATE: AskUserQuestion always represents an agent
        #    bouncing work back to the operator for clarification — a
        #    textbook unscheduled escalation.
        try:
            _emit_outcome_signals(tool_name, is_error, manifest)
        except Exception:
            # Outcome signals are observational; never block the metrics path.
            pass

    except Exception:
        pass  # Fail-open for metrics collection


def _emit_outcome_signals(tool_name: str, is_error: bool, manifest: dict):
    """Outcome-collector observational signals.

    1. HUMAN_GATE_RESPONSE — if a gate is pending in session-state, pair it
       with this tool call. Same-tool match = approve; different tool =
       redirect; gate older than 10 minutes = timeout.

    2. AGENT_ESCALATE — AskUserQuestion is always an agent giving up and
       requesting operator help, so emit unscheduled escalation.

    All emissions go through the audit bus singleton; failures are silent.
    """
    from datetime import datetime, timezone
    from governance.lib.singletons import (
        consume_pending_gate, peek_pending_gate, get_audit_bus)
    from governance.lib.audit_bus import EventType

    audit_bus = get_audit_bus()
    now = datetime.now(timezone.utc)

    # Pair open gate with response — only if a gate is actually pending.
    pending = peek_pending_gate()
    if pending:
        gate_id = pending.get("gate_id", "")
        gate_tool = pending.get("tool_name", "")
        started = pending.get("started_iso", "")
        latency_ms = 0
        try:
            started_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
            latency_ms = int((now - started_dt).total_seconds() * 1000)
        except Exception:
            latency_ms = 0

        # Decide response action.
        # - same tool fired now = the user approved, retried, and it ran
        # - different tool   = user redirected to other work
        # - >10min stale     = timeout heuristic; abandon
        if latency_ms > 10 * 60 * 1000:
            response_action = "timeout"
        elif tool_name == gate_tool:
            response_action = "approve" if not is_error else "approve_with_error"
        else:
            response_action = "redirect"

        # Always consume — paired or stale, the gate's resolution is observed.
        consume_pending_gate()

        audit_bus.emit(
            EventType.HUMAN_GATE_RESPONSE, manifest,
            tool_name=gate_tool,
            outcome=response_action,
            detail={
                "gate_id": gate_id,
                "response_action": response_action,
                "wait_end": now.isoformat(),
                "latency_ms": latency_ms,
            })

    # AskUserQuestion = agent escalating an ambiguity to the operator.
    if tool_name == "AskUserQuestion":
        audit_bus.emit(
            EventType.AGENT_ESCALATE, manifest,
            tool_name=tool_name,
            outcome="escalate",
            detail={
                "escalation_kind": "ambiguity",
                "from_agent": manifest.get("agent_id", "unknown"),
                "task_description_hash": "",
                "retry_count": 0,
                "operator_action_requested": "answer clarifying question",
            })


def _anomaly_to_event(anomaly, session_id):
    """Convert AnomalyResult to a ThreatEvent-like object for Guardian."""
    from governance.lib.security.threat_detection import ThreatEvent
    import uuid
    from datetime import datetime, timezone

    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }

    return ThreatEvent(
        threat_id=str(uuid.uuid4()),
        type="BEHAVIORAL_ANOMALY",
        severity=severity_map.get(anomaly.severity, "LOW"),
        agent_id=anomaly.agent_id,
        session_id=session_id or "",
        timestamp=datetime.now(timezone.utc).isoformat(),
        evidence={
            "metric": anomaly.metric,
            "z_score": anomaly.z_score,
            "observed": anomaly.observed,
            "baseline_mean": anomaly.baseline_mean,
        },
    )


if __name__ == "__main__":
    main()
