"""Tests for ForensicReplay — Phase 10 (REQ-075)."""

import pytest
from unittest.mock import MagicMock

from governance.lib.security.forensic_replay import ForensicReplay, RETENTION_DAYS


@pytest.fixture
def mock_qdrant():
    q = MagicMock()
    q.scroll_points.return_value = []
    q.delete_point.return_value = True
    return q


@pytest.fixture
def mock_audit_bus():
    bus = MagicMock()
    bus.query.return_value = []
    return bus


@pytest.fixture
def replay(mock_qdrant, mock_audit_bus):
    return ForensicReplay(mock_qdrant, mock_audit_bus)


class TestTimelineReconstruction:
    def test_empty_session_returns_structure(self, replay):
        """Empty session should return valid timeline structure."""
        result = replay.replay_session("session-1")
        assert result["session_id"] == "session-1"
        assert result["event_count"] == 0
        assert result["events"] == []
        assert isinstance(result["identity_transitions"], list)
        assert isinstance(result["anomaly_signals"], list)
        assert isinstance(result["guardian_interventions"], list)

    def test_merges_qdrant_and_audit_events(self, replay, mock_qdrant, mock_audit_bus):
        """Should merge events from both sources."""
        mock_qdrant.scroll_points.return_value = [
            {"id": "q1", "payload": {
                "event_id": "e1", "timestamp": "2026-04-06T12:00:00Z",
                "event_type": "security.identity_transition",
                "agent_id": "agent-1", "session_id": "session-1",
                "sequence_number": 1,
            }},
        ]
        mock_audit_bus.query.return_value = [
            {"event_id": "e2", "timestamp": "2026-04-06T12:01:00Z",
             "event_type": "tool_invoked", "agent_id": "agent-1"},
        ]
        result = replay.replay_session("session-1")
        assert result["event_count"] == 2
        # Should be sorted by timestamp
        assert result["events"][0]["event_id"] == "e1"
        assert result["events"][1]["event_id"] == "e2"

    def test_deduplicates_events(self, replay, mock_qdrant, mock_audit_bus):
        """Should deduplicate events by event_id."""
        mock_qdrant.scroll_points.return_value = [
            {"id": "q1", "payload": {
                "event_id": "e1", "timestamp": "2026-04-06T12:00:00Z",
                "event_type": "test", "agent_id": "agent-1",
            }},
        ]
        mock_audit_bus.query.return_value = [
            {"event_id": "e1", "timestamp": "2026-04-06T12:00:00Z",
             "event_type": "test", "agent_id": "agent-1"},
        ]
        result = replay.replay_session("session-1")
        assert result["event_count"] == 1

    def test_categorizes_events(self, replay, mock_qdrant):
        """Should categorize events by type."""
        mock_qdrant.scroll_points.return_value = [
            {"id": "q1", "payload": {
                "event_id": "e1", "timestamp": "2026-04-06T12:00:00Z",
                "event_type": "security.identity_transition",
                "agent_id": "a1",
            }},
            {"id": "q2", "payload": {
                "event_id": "e2", "timestamp": "2026-04-06T12:01:00Z",
                "event_type": "security.behavioral_anomaly",
                "agent_id": "a1",
            }},
            {"id": "q3", "payload": {
                "event_id": "e3", "timestamp": "2026-04-06T12:02:00Z",
                "event_type": "security.guardian_action",
                "agent_id": "a1",
            }},
        ]
        result = replay.replay_session("session-1")
        assert len(result["identity_transitions"]) == 1
        assert len(result["anomaly_signals"]) == 1
        assert len(result["guardian_interventions"]) == 1


class TestRetention:
    def test_retention_is_90_days(self):
        """Default retention should be 90 days."""
        assert RETENTION_DAYS == 90

    def test_check_retention_structure(self, replay, mock_qdrant):
        """check_retention should return expected structure."""
        mock_qdrant.scroll_points.return_value = []
        result = replay.check_retention()
        assert "total_events" in result
        assert "active_events" in result
        assert "expired_events" in result
        assert result["retention_days"] == 90
