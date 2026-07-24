"""Tests for CoordinationScorer — Phase 6 (REQ-065/066)."""

import pytest
from unittest.mock import MagicMock

from governance.lib.security.coordination_scorer import (
    CoordinationScorer,
    Interaction,
    ToolCall,
)
from governance.lib.security.security_config import SecurityConfig


@pytest.fixture
def mock_qdrant():
    q = MagicMock()
    q.store_coordination_score.return_value = "ok"
    q.get_recent_scores.return_value = []
    return q


@pytest.fixture
def mock_audit_bus():
    bus = MagicMock()
    bus.emit.return_value = "event-id"
    return bus


@pytest.fixture
def config():
    return SecurityConfig()


@pytest.fixture
def scorer(mock_qdrant, mock_audit_bus, config):
    return CoordinationScorer(mock_qdrant, mock_audit_bus, config)


class TestCSSComputation:
    def test_no_interactions_returns_1(self, scorer):
        """No interactions should return CSS=1.0."""
        result = scorer.compute_css("agent-a", "agent-b")
        assert result.css == 1.0
        assert result.interaction_count == 0

    def test_perfect_interactions(self, scorer):
        """Perfect quality interactions should yield high CSS."""
        for i in range(5):
            scorer.record_interaction(Interaction(
                agent_a="agent-a",
                agent_b="agent-b",
                tool_name="Read",
                outcome_quality=1.0,
                max_outcome=1.0,
                weight=1.0,
            ))
        result = scorer.compute_css("agent-a", "agent-b")
        assert result.css == 1.0

    def test_low_quality_triggers_threshold(self, scorer):
        """Low quality interactions should trigger threshold breach."""
        guardian = MagicMock()
        scorer.set_guardian(guardian)

        for i in range(5):
            scorer.record_interaction(Interaction(
                agent_a="agent-a",
                agent_b="agent-b",
                tool_name="Read",
                outcome_quality=0.1,
                max_outcome=1.0,
                weight=1.0,
            ))
        result = scorer.compute_css("agent-a", "agent-b")
        assert result.css < 0.4
        assert result.breach_level in ("threshold", "critical")

    def test_collusion_penalty_applied(self, scorer):
        """CSS should apply 0.3 penalty when >60% output copying."""
        for i in range(10):
            scorer.record_interaction(Interaction(
                agent_a="agent-a",
                agent_b="agent-b",
                tool_name="Write",
                outcome_quality=1.0,
                max_outcome=1.0,
                weight=1.0,
                output_a="the quick brown fox jumps over the lazy dog " * 5,
                output_b="the quick brown fox jumps over the lazy dog " * 5,
            ))
        result = scorer.compute_css("agent-a", "agent-b")
        assert result.collusion_penalty == 0.3
        assert result.css == pytest.approx(0.7, abs=0.01)

    def test_pair_key_is_deterministic(self, scorer):
        """Pair key should be the same regardless of order."""
        key1 = scorer._pair_key("agent-a", "agent-b")
        key2 = scorer._pair_key("agent-b", "agent-a")
        assert key1 == key2

    def test_css_critical_breach_at_02(self, scorer):
        """CSS < 0.2 should be critical breach."""
        for i in range(5):
            scorer.record_interaction(Interaction(
                agent_a="agent-a",
                agent_b="agent-b",
                tool_name="Write",
                outcome_quality=0.05,
                max_outcome=1.0,
                weight=1.0,
            ))
        result = scorer.compute_css("agent-a", "agent-b")
        assert result.css < 0.2
        assert result.breach_level == "critical"


class TestTUEComputation:
    def test_empty_history_returns_1(self, scorer):
        """No tool calls should return TUE=1.0."""
        result = scorer.compute_tue("agent-1")
        assert result.tue == 1.0
        assert result.window_size == 0

    def test_all_success_returns_1(self, scorer):
        """All successful calls should return TUE=1.0."""
        for i in range(50):
            scorer.record_tool_call("agent-1", ToolCall(
                tool_name="Read",
                outcome_class="success",
            ))
        result = scorer.compute_tue("agent-1")
        assert result.tue == 1.0

    def test_high_redundancy_lowers_tue(self, scorer):
        """High redundancy should lower TUE."""
        for i in range(50):
            scorer.record_tool_call("agent-1", ToolCall(
                tool_name="Read",
                outcome_class="success",
                is_redundant=(i % 2 == 0),  # 50% redundant
            ))
        result = scorer.compute_tue("agent-1")
        assert result.tue < 0.6

    def test_false_positives_lower_tue(self, scorer):
        """False positives should lower TUE via precision weight."""
        for i in range(50):
            scorer.record_tool_call("agent-1", ToolCall(
                tool_name="Read",
                outcome_class="success",
                is_false_positive=(i % 5 == 0),  # 20% FP
            ))
        result = scorer.compute_tue("agent-1")
        assert result.tue < 0.85

    def test_rolling_window_is_50(self, scorer):
        """TUE should use a 50-call rolling window."""
        # Record 100 calls
        for i in range(100):
            scorer.record_tool_call("agent-1", ToolCall(
                tool_name="Read",
                outcome_class="error" if i < 50 else "success",
            ))
        result = scorer.compute_tue("agent-1")
        # Only last 50 (all success) should be in window
        assert result.tue == 1.0
        assert result.window_size == 50

    def test_consecutive_low_windows_flags_degraded(self, scorer, mock_qdrant):
        """3 consecutive windows below 0.35 should flag degradation."""
        mock_qdrant.get_recent_scores.return_value = [
            {"tue": 0.2}, {"tue": 0.3},
        ]
        # Add current window with low TUE
        for i in range(50):
            scorer.record_tool_call("agent-1", ToolCall(
                tool_name="Read",
                outcome_class="error",
            ))
        result = scorer.compute_tue("agent-1")
        assert result.degraded is True
        assert result.consecutive_low_windows >= 3


class TestOutputSimilarity:
    def test_identical_outputs(self, scorer):
        """Identical outputs should have similarity close to 1."""
        sim = scorer._output_similarity("hello world", "hello world")
        assert sim == 1.0

    def test_different_outputs(self, scorer):
        """Different outputs should have low similarity."""
        sim = scorer._output_similarity(
            "the cat sat on the mat",
            "python javascript rust golang")
        assert sim < 0.2

    def test_empty_outputs(self, scorer):
        """Empty outputs should return 0."""
        assert scorer._output_similarity("", "hello") == 0.0
        assert scorer._output_similarity("hello", "") == 0.0
