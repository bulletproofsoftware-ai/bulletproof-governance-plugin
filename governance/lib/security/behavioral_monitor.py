"""Behavioral Monitor — 8-metric baselines with z-score anomaly detection (REQ-057/058).

Establishes per-agent behavioral baselines using Welford's online algorithm.
Detects anomalies via z-score with configurable sensitivity per metric and
agent class. Minimum 10 sessions before anomaly detection activates.
"""

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from governance.lib.audit_bus import AuditBus, EventType
from governance.lib.security.security_config import (
    MetricConfig,
    SecurityConfig,
    get_metric_config,
)

logger = logging.getLogger("governance.security.behavioral_monitor")

# ---------------------------------------------------------------------------
# Metric IDs — the 8 tracked dimensions
# ---------------------------------------------------------------------------
METRIC_IDS = [
    "FILE_ACCESS_FREQUENCY",      # BM-001: files/minute
    "TOOL_USAGE_DISTRIBUTION",    # BM-002: % share per tool
    "TOKEN_CONSUMPTION_RATE",     # BM-003: tokens/task
    "API_CALL_PATTERNS",          # BM-004: calls/min + endpoint mix
    "DIRECTORY_ACCESS_BREADTH",   # BM-005: unique paths/session
    "EXTERNAL_NETWORK_CALLS",     # BM-006: calls/session to external hosts
    "SESSION_DURATION",           # BM-007: seconds
    "ERROR_RATE",                 # BM-008: errors/100 tool calls
]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
@dataclass
class AnomalyResult:
    agent_id: str
    metric: str
    observed: float
    baseline_mean: float
    baseline_stddev: float
    z_score: float
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    agent_class: str = ""


@dataclass
class BaselineData:
    mean: float = 0.0
    stddev: float = 0.0
    m2: float = 0.0
    p95: float = 0.0
    sample_count: int = 0
    last_updated: str = ""
    agent_class: str = ""


# ---------------------------------------------------------------------------
# BehavioralMonitor
# ---------------------------------------------------------------------------
class BehavioralMonitor:
    def __init__(self, qdrant, audit_bus: AuditBus, config: SecurityConfig):
        self.qdrant = qdrant
        self.audit_bus = audit_bus
        self.config = config

    def record_metric(
        self,
        agent_id: str,
        metric: str,
        value: float,
        agent_class: str = "",
        manifest: Optional[dict] = None,
    ) -> Optional[AnomalyResult]:
        """Record a metric observation, update baseline, check for anomaly.

        Returns AnomalyResult if anomaly detected, None otherwise.
        """
        if metric not in METRIC_IDS:
            logger.warning("Unknown metric: %s", metric)
            return None

        # Update baseline with Welford's algorithm
        self._update_baseline(agent_id, metric, value, agent_class)

        # Check for anomaly
        anomaly = self.check_anomaly(agent_id, metric, value, agent_class)

        if anomaly:
            # Emit to audit bus
            m = manifest or {"agent_id": agent_id, "audit_session_id": "unknown"}
            self.audit_bus.emit(
                EventType.SECURITY_BEHAVIORAL_ANOMALY,
                manifest=m,
                outcome="warn",
                detail={
                    "metric": anomaly.metric,
                    "observed_value": anomaly.observed,
                    "baseline_mean": anomaly.baseline_mean,
                    "baseline_stddev": anomaly.baseline_stddev,
                    "z_score": anomaly.z_score,
                    "severity": anomaly.severity,
                    "agent_class": anomaly.agent_class,
                },
            )
            logger.warning(
                "Behavioral anomaly: agent=%s metric=%s z=%.2f severity=%s",
                agent_id, metric, anomaly.z_score, anomaly.severity,
            )

        return anomaly

    def check_anomaly(
        self,
        agent_id: str,
        metric: str,
        value: float,
        agent_class: str = "",
    ) -> Optional[AnomalyResult]:
        """Check a value against the agent's baseline for anomalies."""
        metric_config = get_metric_config(self.config, metric, agent_class or None)
        baseline = self._get_baseline(agent_id, metric)

        if baseline is None or baseline.sample_count < metric_config.min_sessions:
            return None  # Learning phase — not enough data

        # Z-score calculation
        stddev = max(baseline.stddev, 1e-6)
        z_score = (value - baseline.mean) / stddev

        if abs(z_score) > metric_config.threshold_sigma:
            severity = self._z_to_severity(z_score)
            return AnomalyResult(
                agent_id=agent_id,
                metric=metric,
                observed=value,
                baseline_mean=baseline.mean,
                baseline_stddev=baseline.stddev,
                z_score=z_score,
                severity=severity,
                agent_class=agent_class,
            )

        return None

    def _update_baseline(
        self,
        agent_id: str,
        metric: str,
        value: float,
        agent_class: str = "",
    ) -> None:
        """Update baseline using Welford's online algorithm."""
        baseline = self._get_baseline(agent_id, metric)

        if baseline is None:
            # First observation
            self.qdrant.upsert_baseline(agent_id, metric, {
                "mean": value,
                "stddev": 0.0,
                "m2": 0.0,
                "p95": value,
                "sample_count": 1,
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "agent_class": agent_class,
            })
            return

        n = baseline.sample_count + 1
        delta = value - baseline.mean
        new_mean = baseline.mean + delta / n
        delta2 = value - new_mean
        new_m2 = baseline.m2 + delta * delta2
        new_stddev = math.sqrt(new_m2 / n) if n > 1 else 0.0

        # Approximate P95 update (exponential moving average approach)
        new_p95 = self._update_p95(baseline.p95, value, n)

        self.qdrant.upsert_baseline(agent_id, metric, {
            "mean": new_mean,
            "stddev": new_stddev,
            "m2": new_m2,
            "p95": new_p95,
            "sample_count": n,
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "agent_class": agent_class or baseline.agent_class,
        })

    def _get_baseline(self, agent_id: str, metric: str) -> Optional[BaselineData]:
        """Load baseline from Qdrant."""
        data = self.qdrant.get_baseline(agent_id, metric)
        if data is None:
            return None
        return BaselineData(
            mean=data.get("mean", 0.0),
            stddev=data.get("stddev", 0.0),
            m2=data.get("m2", 0.0),
            p95=data.get("p95", 0.0),
            sample_count=data.get("sample_count", 0),
            last_updated=data.get("last_updated", ""),
            agent_class=data.get("agent_class", ""),
        )

    def get_baseline_summary(self, agent_id: str) -> dict[str, dict]:
        """Get all baselines for an agent. Returns metric -> baseline dict."""
        result = {}
        for metric in METRIC_IDS:
            bl = self._get_baseline(agent_id, metric)
            if bl:
                result[metric] = {
                    "mean": bl.mean,
                    "stddev": bl.stddev,
                    "p95": bl.p95,
                    "sample_count": bl.sample_count,
                    "last_updated": bl.last_updated,
                }
        return result

    @staticmethod
    def _z_to_severity(z_score: float) -> str:
        """Map z-score to severity level."""
        abs_z = abs(z_score)
        if abs_z > 4.0:
            return "CRITICAL"
        if abs_z > 3.0:
            return "HIGH"
        if abs_z > 2.5:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _update_p95(current_p95: float, new_value: float, n: int) -> float:
        """Approximate P95 using exponential moving average.

        For small n, the EMA adapts quickly. For large n, it stabilizes.
        """
        alpha = max(0.02, 2.0 / (n + 1))
        if new_value > current_p95:
            # Pull up faster when exceeding current P95
            return current_p95 + alpha * 2 * (new_value - current_p95)
        return current_p95 + alpha * (new_value - current_p95)
