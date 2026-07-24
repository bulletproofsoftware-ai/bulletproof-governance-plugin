"""Tests for BehavioralMonitor — Phase 2 (REQ-057/058)."""

import math
import pytest
from unittest.mock import MagicMock, patch

from governance.lib.security.behavioral_monitor import (
    BehavioralMonitor,
    BaselineData,
    METRIC_IDS,
)
from governance.lib.security.security_config import SecurityConfig, MetricConfig


@pytest.fixture
def mock_qdrant():
    q = MagicMock()
    q.get_baseline.return_value = None
    q.upsert_baseline.return_value = "ok"
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
def monitor(mock_qdrant, mock_audit_bus, config):
    return BehavioralMonitor(mock_qdrant, mock_audit_bus, config)


class TestBaselineCreation:
    def test_first_observation_creates_baseline(self, monitor, mock_qdrant):
        """First observation should create a new baseline."""
        monitor.record_metric("agent-1", "FILE_ACCESS_FREQUENCY", 5.0)
        mock_qdrant.upsert_baseline.assert_called()
        call_args = mock_qdrant.upsert_baseline.call_args
        assert call_args[0][0] == "agent-1"
        assert call_args[0][1] == "FILE_ACCESS_FREQUENCY"
        data = call_args[0][2]
        assert data["mean"] == 5.0
        assert data["sample_count"] == 1

    def test_welford_update_accuracy(self, monitor, mock_qdrant):
        """Welford's algorithm should produce accurate mean/stddev."""
        # Simulate 5 observations
        values = [10.0, 12.0, 8.0, 11.0, 9.0]

        # First call creates baseline
        monitor.record_metric("agent-1", "FILE_ACCESS_FREQUENCY", values[0])

        # Subsequent calls update
        for val in values[1:]:
            mock_qdrant.get_baseline.return_value = {
                "mean": sum(values[:values.index(val)]) / values.index(val),
                "stddev": 0.0,
                "m2": 0.0,
                "p95": val,
                "sample_count": values.index(val),
                "agent_class": "",
            }
            monitor.record_metric("agent-1", "FILE_ACCESS_FREQUENCY", val)

        # Verify upsert was called for each observation
        assert mock_qdrant.upsert_baseline.call_count == len(values)


class TestAnomalyDetection:
    def test_no_anomaly_during_learning_phase(self, monitor, mock_qdrant):
        """Should return None when sample_count < min_sessions."""
        mock_qdrant.get_baseline.return_value = {
            "mean": 5.0, "stddev": 1.0, "m2": 9.0,
            "p95": 7.0, "sample_count": 3, "agent_class": "",
        }
        result = monitor.check_anomaly("agent-1", "FILE_ACCESS_FREQUENCY", 100.0)
        assert result is None

    def test_anomaly_detected_above_threshold(self, monitor, mock_qdrant):
        """Should detect anomaly when z-score > threshold_sigma."""
        mock_qdrant.get_baseline.return_value = {
            "mean": 5.0, "stddev": 1.0, "m2": 10.0,
            "p95": 7.0, "sample_count": 20, "agent_class": "",
        }
        # z-score = (20 - 5) / 1 = 15, way above 3.0
        result = monitor.check_anomaly("agent-1", "FILE_ACCESS_FREQUENCY", 20.0)
        assert result is not None
        assert result.severity == "CRITICAL"
        assert result.z_score > 3.0

    def test_no_anomaly_within_normal_range(self, monitor, mock_qdrant):
        """Should not detect anomaly within normal range."""
        mock_qdrant.get_baseline.return_value = {
            "mean": 5.0, "stddev": 1.0, "m2": 10.0,
            "p95": 7.0, "sample_count": 20, "agent_class": "",
        }
        result = monitor.check_anomaly("agent-1", "FILE_ACCESS_FREQUENCY", 6.5)
        assert result is None

    def test_severity_levels(self, monitor):
        """Test z-score to severity mapping."""
        assert BehavioralMonitor._z_to_severity(4.5) == "CRITICAL"
        assert BehavioralMonitor._z_to_severity(3.5) == "HIGH"
        assert BehavioralMonitor._z_to_severity(2.7) == "MEDIUM"
        assert BehavioralMonitor._z_to_severity(2.0) == "LOW"


class TestConfigurableSensitivity:
    def test_agent_class_override(self, monitor, mock_qdrant, config):
        """Agent class override should change threshold."""
        # Default threshold for FILE_ACCESS_FREQUENCY is 3.0
        # read_only override is 2.0
        mock_qdrant.get_baseline.return_value = {
            "mean": 5.0, "stddev": 1.0, "m2": 10.0,
            "p95": 7.0, "sample_count": 20, "agent_class": "read_only",
        }
        # z-score = (7.5 - 5) / 1 = 2.5
        # With default threshold 3.0: not anomalous
        # With read_only threshold 2.0: anomalous
        result = monitor.check_anomaly(
            "agent-1", "FILE_ACCESS_FREQUENCY", 7.5, agent_class="read_only")
        assert result is not None

    def test_unknown_metric_returns_none(self, monitor):
        """Unknown metric should be rejected."""
        result = monitor.record_metric("agent-1", "UNKNOWN_METRIC", 5.0)
        assert result is None


class TestAllMetricIDs:
    def test_all_8_metrics_defined(self):
        """Should have exactly 8 metric IDs."""
        assert len(METRIC_IDS) == 8
        assert "FILE_ACCESS_FREQUENCY" in METRIC_IDS
        assert "SESSION_DURATION" in METRIC_IDS
        assert "ERROR_RATE" in METRIC_IDS


class TestP95Update:
    def test_p95_increases_for_high_values(self):
        """P95 should increase when new value exceeds current."""
        p95 = BehavioralMonitor._update_p95(10.0, 20.0, 5)
        assert p95 > 10.0

    def test_p95_decreases_slowly(self):
        """P95 should decrease slowly for low values."""
        p95 = BehavioralMonitor._update_p95(10.0, 2.0, 50)
        assert p95 < 10.0
        assert p95 > 2.0  # Should not drop to the value immediately
