"""Forensic Replay — session timeline reconstruction (REQ-075).

Reconstructs complete session timelines from forensic_events (Qdrant)
and audit_events (SQLite). 90-day retention window.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from governance.lib.audit_bus import AuditBus

logger = logging.getLogger("governance.security.forensic_replay")

RETENTION_DAYS = 90


class ForensicReplay:
    """Reconstructs session timelines from multiple event sources."""

    def __init__(self, qdrant, audit_bus: AuditBus):
        self.qdrant = qdrant
        self.audit_bus = audit_bus

    def replay_session(
        self,
        session_id: str,
        time_range: Optional[tuple[str, str]] = None,
    ) -> dict:
        """Reconstruct session timeline from forensic_events and audit_events.

        Args:
            session_id: The session to replay.
            time_range: Optional (start_iso, end_iso) to limit the window.

        Returns:
            SessionTimeline dict with categorized events.
        """
        # Pull from forensic_events (Qdrant)
        qdrant_events = self._get_qdrant_events(session_id, time_range)

        # Pull from SQLite audit bus (governance events)
        audit_events = self._get_audit_events(session_id)

        # Merge and sort
        all_events = self._merge_events(qdrant_events, audit_events)

        # Filter by time range if specified
        if time_range:
            start, end = time_range
            all_events = [
                e for e in all_events
                if start <= e.get("timestamp", "") <= end
            ]

        # Compute duration
        duration = 0.0
        if all_events:
            try:
                first_ts = datetime.fromisoformat(
                    all_events[0].get("timestamp", ""))
                last_ts = datetime.fromisoformat(
                    all_events[-1].get("timestamp", ""))
                duration = (last_ts - first_ts).total_seconds()
            except (ValueError, TypeError):
                pass

        # Get agent_id from first event
        agent_id = ""
        for e in all_events:
            aid = e.get("agent_id", "")
            if aid and aid != "unknown":
                agent_id = aid
                break

        # Categorize events
        return {
            "session_id": session_id,
            "agent_id": agent_id,
            "duration_seconds": duration,
            "event_count": len(all_events),
            "events": all_events,
            "identity_transitions": [
                e for e in all_events
                if e.get("event_type", "").endswith("identity_transition")
            ],
            "anomaly_signals": [
                e for e in all_events
                if e.get("event_type", "").endswith("behavioral_anomaly")
            ],
            "guardian_interventions": [
                e for e in all_events
                if e.get("event_type", "").endswith("guardian_action")
            ],
            "memory_operations": [
                e for e in all_events
                if "memory" in e.get("event_type", "")
            ],
            "threat_events": [
                e for e in all_events
                if any(x in e.get("event_type", "") for x in [
                    "threat", "injection", "exfiltration",
                    "escalation", "tool_abuse",
                ])
            ],
            "tool_calls": [
                e for e in all_events
                if e.get("event_type", "") == "tool_invoked"
            ],
        }

    def replay_agent(self, agent_id: str, limit: int = 1000) -> list[dict]:
        """Get all forensic events for an agent (across sessions)."""
        results = self.qdrant.scroll_points(
            "forensic_events",
            filter_conditions={"agent_id": agent_id},
            limit=limit,
            order_by="timestamp",
        )
        return [r["payload"] for r in results]

    def get_correlation_chain(self, correlation_id: str) -> list[dict]:
        """Get all events in a correlation chain."""
        results = self.qdrant.scroll_points(
            "forensic_events",
            filter_conditions={"correlation_id": correlation_id},
            limit=500,
            order_by="sequence_number",
        )
        return [r["payload"] for r in results]

    def check_retention(self) -> dict:
        """Check retention status. Returns expired event count."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
        ).isoformat()

        # Get all events and check which are expired
        all_events = self.qdrant.scroll_points(
            "forensic_events",
            limit=10000,
        )

        expired = []
        active = []
        for e in all_events:
            retention_date = e["payload"].get("retention_expires_at", "")
            if retention_date and retention_date < datetime.now(timezone.utc).isoformat():
                expired.append(e["id"])
            else:
                active.append(e["id"])

        return {
            "total_events": len(all_events),
            "active_events": len(active),
            "expired_events": len(expired),
            "retention_days": RETENTION_DAYS,
            "cutoff_date": cutoff,
        }

    def purge_expired(self) -> int:
        """Delete expired forensic events. Returns count deleted."""
        now = datetime.now(timezone.utc).isoformat()
        all_events = self.qdrant.scroll_points(
            "forensic_events",
            limit=10000,
        )

        deleted = 0
        for e in all_events:
            retention_date = e["payload"].get("retention_expires_at", "")
            if retention_date and retention_date < now:
                if self.qdrant.delete_point("forensic_events", e["id"]):
                    deleted += 1

        return deleted

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _get_qdrant_events(
        self,
        session_id: str,
        time_range: Optional[tuple[str, str]] = None,
    ) -> list[dict]:
        """Get forensic events from Qdrant for a session."""
        results = self.qdrant.scroll_points(
            "forensic_events",
            filter_conditions={"session_id": session_id},
            limit=10000,
            order_by="sequence_number",
        )
        events = []
        for r in results:
            p = r["payload"]
            events.append({
                "event_id": p.get("event_id", r["id"]),
                "timestamp": p.get("timestamp", ""),
                "event_type": p.get("event_type", ""),
                "agent_id": p.get("agent_id", ""),
                "session_id": p.get("session_id", session_id),
                "sequence_number": p.get("sequence_number", 0),
                "payload": p.get("payload", ""),
                "correlation_id": p.get("correlation_id", ""),
                "source": "forensic_events",
            })
        return events

    def _get_audit_events(self, session_id: str) -> list[dict]:
        """Get audit events from SQLite for a session."""
        events = self.audit_bus.query(
            {"audit_session_id": session_id},
            limit=10000,
        )
        result = []
        for e in events:
            result.append({
                "event_id": e.get("event_id", ""),
                "timestamp": e.get("timestamp", ""),
                "event_type": e.get("event_type", ""),
                "agent_id": e.get("agent_id", ""),
                "session_id": session_id,
                "sequence_number": 0,
                "tool_name": e.get("tool_name", ""),
                "outcome": e.get("outcome", ""),
                "detail": e.get("detail", ""),
                "source": "audit_bus",
            })
        return result

    def _merge_events(
        self,
        qdrant_events: list[dict],
        audit_events: list[dict],
    ) -> list[dict]:
        """Merge and sort events from multiple sources by timestamp."""
        all_events = qdrant_events + audit_events

        # Deduplicate by event_id
        seen = set()
        unique = []
        for e in all_events:
            eid = e.get("event_id", "")
            if eid and eid in seen:
                continue
            if eid:
                seen.add(eid)
            unique.append(e)

        # Sort by timestamp
        unique.sort(key=lambda e: e.get("timestamp", ""))

        return unique
