"""Security configuration loader (REQ-058).

Loads security-config.yaml with defaults for all configurable thresholds.
Supports per-metric, per-agent-class overrides. Config changes require
no code modifications — edit YAML and restart.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


# ---------------------------------------------------------------------------
# Metric configuration dataclass
# ---------------------------------------------------------------------------
@dataclass
class MetricConfig:
    min_sessions: int = 10
    threshold_sigma: float = 3.0
    threshold_kl_divergence: float = 0.4
    threshold_rate_spike: float = 10.0
    threshold_new_endpoint: bool = True
    threshold_new_host: bool = True
    threshold_new_prefix: bool = True
    threshold_spike_pct: float = 50.0
    agent_class_overrides: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Guardian configuration dataclass
# ---------------------------------------------------------------------------
@dataclass
class GuardianConfig:
    autonomy_level: str = "SEMI_AUTONOMOUS"
    webhook_url: Optional[str] = None
    webhook_timeout_ms: int = 5000
    max_notification_delay_seconds: int = 30
    required_scope: str = "security_admin"
    require_double_confirm_for_full_auto: bool = True


# ---------------------------------------------------------------------------
# Full security configuration
# ---------------------------------------------------------------------------
@dataclass
class SecurityConfig:
    metrics: dict[str, MetricConfig] = field(default_factory=dict)
    guardian: GuardianConfig = field(default_factory=GuardianConfig)
    memory_anomaly_threshold: float = 4.5
    injection_similarity_threshold: float = 0.85
    semantic_consistency_threshold: float = 0.35
    forensic_retention_days: int = 90
    host_allowlist: list[str] = field(default_factory=list)
    rate_limit_per_agent: int = 100  # max security checks/second
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "nomic-embed-text"
    qdrant_url: str = "http://localhost:6334"
    dashboard_port: int = 8101
    dashboard_jwt_secret: str = ""  # Must come from env


# ---------------------------------------------------------------------------
# Default metric configurations
# ---------------------------------------------------------------------------
DEFAULT_METRICS = {
    "FILE_ACCESS_FREQUENCY": MetricConfig(
        min_sessions=10, threshold_sigma=3.0,
        agent_class_overrides={
            "read_only": {"threshold_sigma": 2.0},
            "write_authorized": {"threshold_sigma": 3.5},
            "external_facing": {"threshold_sigma": 2.5},
        },
    ),
    "TOOL_USAGE_DISTRIBUTION": MetricConfig(
        min_sessions=10, threshold_kl_divergence=0.4,
    ),
    "TOKEN_CONSUMPTION_RATE": MetricConfig(
        min_sessions=20, threshold_sigma=2.5,
    ),
    "API_CALL_PATTERNS": MetricConfig(
        min_sessions=10, threshold_rate_spike=10.0, threshold_new_endpoint=True,
    ),
    "DIRECTORY_ACCESS_BREADTH": MetricConfig(
        min_sessions=10, threshold_sigma=2.0, threshold_new_prefix=True,
    ),
    "EXTERNAL_NETWORK_CALLS": MetricConfig(
        min_sessions=10, threshold_new_host=True,
    ),
    "SESSION_DURATION": MetricConfig(
        min_sessions=20, threshold_sigma=3.0,
    ),
    "ERROR_RATE": MetricConfig(
        min_sessions=20, threshold_sigma=2.0, threshold_spike_pct=50.0,
    ),
}


def _get_config_path() -> Path:
    """Resolve security config file path."""
    env_path = os.environ.get("SECURITY_CONFIG_PATH")
    if env_path:
        return Path(env_path)
    plugin_root = Path(os.environ.get(
        "GOVERNANCE_PLUGIN_ROOT",
        str(Path(__file__).resolve().parent.parent.parent.parent)))
    return plugin_root / "state" / "security-config.yaml"


def _merge_metric_config(raw: dict) -> MetricConfig:
    """Build MetricConfig from raw YAML dict."""
    config = MetricConfig()
    for key, value in raw.items():
        if key == "agent_class_overrides":
            config.agent_class_overrides = value or {}
        elif hasattr(config, key):
            setattr(config, key, value)
    return config


def load_security_config() -> SecurityConfig:
    """Load security configuration from YAML with env overrides.

    Precedence: environment variables > YAML file > defaults.
    """
    config = SecurityConfig()

    # Load YAML
    config_path = _get_config_path()
    raw: dict[str, Any] = {}
    if config_path.exists():
        try:
            with open(config_path) as f:
                raw = yaml.safe_load(f) or {}
        except Exception:
            pass

    # Parse behavioral_monitor metrics
    bm_raw = raw.get("behavioral_monitor", {}).get("metrics", {})
    for metric_name, default_config in DEFAULT_METRICS.items():
        if metric_name in bm_raw:
            config.metrics[metric_name] = _merge_metric_config(bm_raw[metric_name])
        else:
            config.metrics[metric_name] = default_config

    # Parse guardian config
    guardian_raw = raw.get("guardian", {})
    if guardian_raw:
        config.guardian = GuardianConfig(
            autonomy_level=guardian_raw.get(
                "autonomy_level",
                os.environ.get("GUARDIAN_AUTONOMY_LEVEL", "SEMI_AUTONOMOUS")),
            webhook_url=guardian_raw.get(
                "notification", {}).get("webhook_url"),
            webhook_timeout_ms=guardian_raw.get(
                "notification", {}).get("webhook_timeout_ms", 5000),
            max_notification_delay_seconds=guardian_raw.get(
                "notification", {}).get("max_notification_delay_seconds", 30),
            required_scope=guardian_raw.get(
                "configuration_change", {}).get("required_scope", "security_admin"),
            require_double_confirm_for_full_auto=guardian_raw.get(
                "configuration_change", {}).get(
                    "require_double_confirm_for_full_auto", True),
        )
    else:
        config.guardian.autonomy_level = os.environ.get(
            "GUARDIAN_AUTONOMY_LEVEL", "SEMI_AUTONOMOUS")

    # Environment variable overrides
    config.memory_anomaly_threshold = float(os.environ.get(
        "MEMORY_ANOMALY_THRESHOLD",
        raw.get("memory_anomaly_threshold", 4.5)))
    config.injection_similarity_threshold = float(os.environ.get(
        "INJECTION_SIMILARITY_THRESHOLD",
        raw.get("injection_similarity_threshold", 0.85)))
    config.forensic_retention_days = int(os.environ.get(
        "FORENSIC_RETENTION_DAYS",
        raw.get("forensic_retention_days", 90)))
    config.ollama_url = os.environ.get(
        "OLLAMA_URL",
        raw.get("ollama_url", "http://localhost:11434"))
    config.ollama_model = os.environ.get(
        "OLLAMA_MODEL",
        raw.get("ollama_model", "nomic-embed-text"))
    config.qdrant_url = os.environ.get(
        "QDRANT_URL",
        raw.get("qdrant_url", "http://localhost:6334"))
    config.dashboard_port = int(os.environ.get(
        "SECURITY_DASHBOARD_PORT",
        raw.get("dashboard_port", 8101)))

    # JWT secret from env only — never hardcoded
    config.dashboard_jwt_secret = os.environ.get(
        "SECURITY_JWT_SECRET", "")

    # Host allowlist
    allowlist_path = raw.get("host_allowlist_path")
    if allowlist_path:
        try:
            full_path = config_path.parent / allowlist_path
            if full_path.exists():
                with open(full_path) as f:
                    data = yaml.safe_load(f) or {}
                config.host_allowlist = data.get("allowed_hosts", [])
        except Exception:
            pass

    return config


def get_metric_config(
    config: SecurityConfig,
    metric_name: str,
    agent_class: Optional[str] = None,
) -> MetricConfig:
    """Get metric config with optional agent class override applied."""
    base = config.metrics.get(metric_name)
    if base is None:
        base = DEFAULT_METRICS.get(metric_name, MetricConfig())

    if agent_class and agent_class in base.agent_class_overrides:
        overrides = base.agent_class_overrides[agent_class]
        # Create copy with overrides applied
        merged = MetricConfig(
            min_sessions=overrides.get("min_sessions", base.min_sessions),
            threshold_sigma=overrides.get("threshold_sigma", base.threshold_sigma),
            threshold_kl_divergence=overrides.get(
                "threshold_kl_divergence", base.threshold_kl_divergence),
            threshold_rate_spike=overrides.get(
                "threshold_rate_spike", base.threshold_rate_spike),
            threshold_new_endpoint=overrides.get(
                "threshold_new_endpoint", base.threshold_new_endpoint),
            threshold_new_host=overrides.get(
                "threshold_new_host", base.threshold_new_host),
            threshold_new_prefix=overrides.get(
                "threshold_new_prefix", base.threshold_new_prefix),
            threshold_spike_pct=overrides.get(
                "threshold_spike_pct", base.threshold_spike_pct),
        )
        return merged

    return base
