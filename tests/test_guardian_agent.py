"""Tests for GuardianAgent — Phase 7 (REQ-071/072)."""

import pytest
from unittest.mock import MagicMock

from governance.lib.security.guardian_agent import (
    GuardianAgent,
    GuardianDecision,
    BASE_SCORES,
    GUARDIAN_AGENT_ID,
    MASS_ACTION_LIMIT,
)
from governance.lib.security.security_config import SecurityConfig, GuardianConfig
from governance.lib.security.threat_detection import ThreatEvent


@pytest.fixture
def mock_qdrant():
    q = MagicMock()
    q.log_guardian_decision.return_value = "ok"
    q.scroll_points.return_value = []
    return q


@pytest.fixture
def mock_audit_bus():
    bus = MagicMock()
    bus.emit.return_value = "event-id"
    return bus


@pytest.fixture
def mock_identity_mgr():
    mgr = MagicMock()
    mgr.throttle.return_value = True
    mgr.suspend.return_value = True
    mgr.revoke.return_value = True
    return mgr


@pytest.fixture
def config():
    cfg = SecurityConfig()
    cfg.guardian = GuardianConfig(autonomy_level="SEMI_AUTONOMOUS")
    return cfg


@pytest.fixture
def guardian(mock_qdrant, mock_audit_bus, config, mock_identity_mgr):
    return GuardianAgent(mock_qdrant, mock_audit_bus, config, mock_identity_mgr)


class TestAssessmentScore:
    def test_prompt_injection_score(self, guardian):
        """Prompt injection should score high (9 base)."""
        event = ThreatEvent(type="PROMPT_INJECTION", severity="CRITICAL")
        score = guardian.compute_assessment_score(event)
        assert score >= 9

    def test_behavioral_anomaly_score(self, guardian):
        """Behavioral anomaly should score low (3 base)."""
        event = ThreatEvent(type="BEHAVIORAL_ANOMALY", severity="LOW")
        score = guardian.compute_assessment_score(event)
        assert 1 <= score <= 5

    def test_severity_modifier(self, guardian):
        """CRITICAL severity should add 2 to base score."""
        event = ThreatEvent(type="TOOL_ABUSE", severity="CRITICAL")
        score = guardian.compute_assessment_score(event)
        base = BASE_SCORES["TOOL_ABUSE"]
        assert score == min(base + 2, 10)

    def test_evidence_modifiers(self, guardian):
        """Repeated + corroborated evidence should increase score."""
        event = ThreatEvent(
            type="BEHAVIORAL_ANOMALY", severity="LOW",
            evidence={"repeated": True, "corroborated": True})
        score = guardian.compute_assessment_score(event)
        assert score > BASE_SCORES["BEHAVIORAL_ANOMALY"]

    def test_score_capped_at_10(self, guardian):
        """Score should never exceed 10."""
        event = ThreatEvent(
            type="PROMPT_INJECTION", severity="CRITICAL",
            evidence={"repeated": True, "corroborated": True})
        score = guardian.compute_assessment_score(event)
        assert score <= 10

    def test_score_minimum_1(self, guardian):
        """Score should never be below 1."""
        event = ThreatEvent(type="UNKNOWN", severity="LOW")
        score = guardian.compute_assessment_score(event)
        assert score >= 1


class TestScoreToAction:
    def test_log_only_for_low(self, guardian):
        assert guardian._score_to_action(1) == "LOG_ONLY"
        assert guardian._score_to_action(2) == "LOG_ONLY"

    def test_notify_for_medium(self, guardian):
        assert guardian._score_to_action(3) == "NOTIFY"
        assert guardian._score_to_action(4) == "NOTIFY"

    def test_throttle_for_high(self, guardian):
        assert guardian._score_to_action(5) == "THROTTLE"
        assert guardian._score_to_action(6) == "THROTTLE"

    def test_suspend_for_critical(self, guardian):
        assert guardian._score_to_action(7) == "SUSPEND"
        assert guardian._score_to_action(8) == "SUSPEND"

    def test_terminate_for_extreme(self, guardian):
        assert guardian._score_to_action(9) == "TERMINATE"
        assert guardian._score_to_action(10) == "TERMINATE"


class TestAutonomyLevels:
    def test_advisory_downgrades_to_notify(self, guardian):
        """ADVISORY level should downgrade THROTTLE/SUSPEND/TERMINATE to NOTIFY."""
        guardian.autonomy_level = "ADVISORY"
        event = ThreatEvent(
            type="PROMPT_INJECTION", severity="CRITICAL",
            session_id="session-1")
        decision = guardian.process_event(event)
        assert decision.action_taken == "NOTIFY"
        assert decision.action_was_downgraded is True

    def test_semi_auto_downgrades_terminate(self, guardian):
        """SEMI_AUTONOMOUS should downgrade TERMINATE to SUSPEND."""
        guardian.autonomy_level = "SEMI_AUTONOMOUS"
        event = ThreatEvent(
            type="PROMPT_INJECTION", severity="CRITICAL",
            session_id="session-1")
        decision = guardian.process_event(event)
        # Score >= 9 -> TERMINATE -> downgraded to SUSPEND
        assert decision.action_taken == "SUSPEND"
        assert decision.action_was_downgraded is True
        assert decision.human_confirmation_required is True

    def test_fully_autonomous_no_downgrade(self, guardian):
        """FULLY_AUTONOMOUS should not downgrade any action."""
        guardian.autonomy_level = "FULLY_AUTONOMOUS"
        event = ThreatEvent(
            type="PROMPT_INJECTION", severity="CRITICAL",
            session_id="session-1")
        decision = guardian.process_event(event)
        assert decision.action_taken == "TERMINATE"
        assert decision.action_was_downgraded is False


class TestSelfProtection:
    def test_cannot_target_self(self, guardian):
        """Guardian should not take action against itself."""
        event = ThreatEvent(
            type="PROMPT_INJECTION", severity="CRITICAL",
            agent_id=GUARDIAN_AGENT_ID, session_id="session-1")
        decision = guardian.process_event(event)
        assert decision.action_taken == "LOG_ONLY"

    def test_mass_action_rate_limit(self, guardian, mock_identity_mgr):
        """Should escalate to GLOBAL_LOCKDOWN when rate limit exceeded."""
        guardian.autonomy_level = "FULLY_AUTONOMOUS"

        # Exhaust the rate limit
        for i in range(MASS_ACTION_LIMIT + 2):
            event = ThreatEvent(
                type="PROMPT_INJECTION", severity="CRITICAL",
                agent_id=f"agent-{i}", session_id=f"session-{i}")
            decision = guardian.process_event(event)

        # After limit, should enter GLOBAL_LOCKDOWN and force SUSPEND
        assert guardian.is_locked_down is True
        event = ThreatEvent(
            type="PROMPT_INJECTION", severity="CRITICAL",
            agent_id="agent-last", session_id="session-last")
        decision = guardian.process_event(event)
        assert decision.action_taken == "SUSPEND"
        assert decision.action_was_downgraded is True
        assert decision.human_confirmation_required is True


class TestActionExecution:
    def test_throttle_calls_identity_mgr(self, guardian, mock_identity_mgr):
        """THROTTLE should call identity_mgr.throttle."""
        guardian.autonomy_level = "FULLY_AUTONOMOUS"
        event = ThreatEvent(
            type="TOOL_ABUSE", severity="HIGH",
            agent_id="agent-1", session_id="session-1")
        # Score ~6 -> THROTTLE
        guardian.process_event(event)
        # Identity mgr should have been called
        assert mock_identity_mgr.throttle.called or mock_identity_mgr.suspend.called

    def test_decision_logged_to_qdrant(self, guardian, mock_qdrant):
        """Every decision should be logged to Qdrant."""
        event = ThreatEvent(
            type="BEHAVIORAL_ANOMALY", severity="LOW",
            agent_id="agent-1", session_id="session-1")
        guardian.process_event(event)
        mock_qdrant.log_guardian_decision.assert_called()


class TestConfigChange:
    def test_change_requires_scope(self, guardian):
        """Autonomy level change should require security_admin scope."""
        manifest = {"permitted_tools": ["Read"]}  # No security_admin
        result = guardian.set_autonomy_level("ADVISORY", manifest)
        assert result is False

    def test_change_with_correct_scope(self, guardian):
        """Should allow change with security_admin scope."""
        manifest = {"permitted_tools": ["security_admin"],
                    "agent_id": "admin", "audit_session_id": "session-1"}
        result = guardian.set_autonomy_level("ADVISORY", manifest)
        assert result is True
        assert guardian.autonomy_level == "ADVISORY"

    def test_invalid_level_rejected(self, guardian):
        """Invalid autonomy level should be rejected."""
        manifest = {"permitted_tools": ["security_admin"]}
        result = guardian.set_autonomy_level("INVALID", manifest)
        assert result is False
