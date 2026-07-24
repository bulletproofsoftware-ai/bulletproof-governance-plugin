"""Inter-Agent Coordination Scorer — CSS + TUE formulas (REQ-065/066).

CSS (Component Synergy Score) per agent pair: <0.4 Guardian review,
<0.2 isolation, >60% copy penalty.
TUE (Tool Utilization Efficacy) per agent: rolling 50-call windows,
<0.35 for 3 consecutive windows triggers re-evaluation.
"""

import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from governance.lib.audit_bus import AuditBus, EventType
from governance.lib.security.security_config import SecurityConfig

logger = logging.getLogger("governance.security.coordination_scorer")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------
@dataclass
class Interaction:
    agent_a: str
    agent_b: str
    tool_name: str
    outcome_quality: float = 1.0  # [0, 1]
    max_outcome: float = 1.0
    weight: float = 1.0
    output_a: str = ""
    output_b: str = ""
    timestamp: str = ""
    is_cross_domain: bool = False


@dataclass
class ToolCall:
    tool_name: str
    outcome_class: str = "success"  # success, error, redundant, false_positive
    is_redundant: bool = False
    is_false_positive: bool = False
    timestamp: str = ""


@dataclass
class CSSResult:
    agent_a: str
    agent_b: str
    css: float
    collusion_penalty: float
    interaction_count: int
    breach_level: str = ""  # "", "threshold" (<0.4), "critical" (<0.2)


@dataclass
class TUEResult:
    agent_id: str
    tue: float
    window_size: int
    correct: int
    redundant: int
    false_positive: int
    degraded: bool = False
    consecutive_low_windows: int = 0


# ---------------------------------------------------------------------------
# CoordinationScorer
# ---------------------------------------------------------------------------
class CoordinationScorer:
    TUE_WINDOW_SIZE = 50
    CSS_LOW_THRESHOLD = 0.4
    CSS_CRITICAL_THRESHOLD = 0.2
    TUE_LOW_THRESHOLD = 0.35
    TUE_CONSECUTIVE_WINDOWS = 3
    COLLUSION_COPY_THRESHOLD = 0.6  # 60% output copying
    COLLUSION_PENALTY = 0.3

    def __init__(self, qdrant, audit_bus: AuditBus, config: SecurityConfig):
        self.qdrant = qdrant
        self.audit_bus = audit_bus
        self.config = config
        self._interactions: dict[str, list[Interaction]] = defaultdict(list)
        self._tool_calls: dict[str, list[ToolCall]] = defaultdict(list)
        self._guardian = None  # Set post-init to break circular dependency

    def set_guardian(self, guardian):
        """Set guardian reference (breaks circular dependency)."""
        self._guardian = guardian

    # ------------------------------------------------------------------
    # CSS computation
    # ------------------------------------------------------------------
    def record_interaction(self, interaction: Interaction) -> None:
        """Record an inter-agent interaction."""
        pair_key = self._pair_key(interaction.agent_a, interaction.agent_b)
        self._interactions[pair_key].append(interaction)

    def compute_css(self, agent_a: str, agent_b: str,
                    session_id: str = "") -> CSSResult:
        """Compute Component Synergy Score for an agent pair.

        CSS = (1/n) * sum(w_i * outcome_i / max_outcome) * (1 - collusion_penalty)
        """
        pair_key = self._pair_key(agent_a, agent_b)
        interactions = self._interactions.get(pair_key, [])
        n = len(interactions)

        if n == 0:
            return CSSResult(
                agent_a=agent_a, agent_b=agent_b,
                css=1.0, collusion_penalty=0.0, interaction_count=0)

        weighted_sum = 0.0
        for interaction in interactions:
            w_i = interaction.weight
            if interaction.is_cross_domain:
                w_i *= 1.5  # Higher weight for cross-domain
            outcome_i = interaction.outcome_quality
            max_outcome = max(interaction.max_outcome, 1e-6)
            weighted_sum += w_i * (outcome_i / max_outcome)

        raw_css = weighted_sum / n

        # Collusion penalty
        collusion = self._compute_collusion_penalty(interactions)
        css = raw_css * (1 - collusion)
        css = max(0.0, min(1.0, css))

        # Determine breach level
        breach_level = ""
        if css < self.CSS_CRITICAL_THRESHOLD:
            breach_level = "critical"
        elif css < self.CSS_LOW_THRESHOLD:
            breach_level = "threshold"

        result = CSSResult(
            agent_a=agent_a,
            agent_b=agent_b,
            css=css,
            collusion_penalty=collusion,
            interaction_count=n,
            breach_level=breach_level,
        )

        # Store in Qdrant
        self.qdrant.store_coordination_score({
            "record_type": "css",
            "agent_pair": pair_key,
            "agent_id": "",
            "session_id": session_id,
            "css": css,
            "tue": 0.0,
            "collusion_penalty": collusion,
            "interaction_count": n,
            "window_size": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Threshold checks — notify Guardian
        if breach_level == "critical":
            self._alert_guardian("CSS_CRITICAL_BREACH", "HIGH", {
                "css": css, "agents": [agent_a, agent_b],
                "collusion_penalty": collusion,
            })
            self._emit_coordination_alert("css_critical", css, 0.0,
                                          pair_key, collusion)
        elif breach_level == "threshold":
            self._alert_guardian("CSS_THRESHOLD_BREACH", "MEDIUM", {
                "css": css, "agents": [agent_a, agent_b],
                "collusion_penalty": collusion,
            })
            self._emit_coordination_alert("css_threshold", css, 0.0,
                                          pair_key, collusion)

        return result

    def _compute_collusion_penalty(self, interactions: list[Interaction]) -> float:
        """If A copies B's output in >60% of interactions, penalty = 0.3."""
        if not interactions:
            return 0.0

        copy_count = 0
        for i in interactions:
            if i.output_a and i.output_b:
                similarity = self._output_similarity(i.output_a, i.output_b)
                if similarity > 0.85:
                    copy_count += 1

        if len(interactions) > 0 and copy_count / len(interactions) > self.COLLUSION_COPY_THRESHOLD:
            return self.COLLUSION_PENALTY

        return 0.0

    @staticmethod
    def _output_similarity(a: str, b: str) -> float:
        """Simple Jaccard similarity for output comparison."""
        if not a or not b:
            return 0.0
        tokens_a = set(a.lower().split())
        tokens_b = set(b.lower().split())
        if not tokens_a or not tokens_b:
            return 0.0
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union) if union else 0.0

    # ------------------------------------------------------------------
    # TUE computation
    # ------------------------------------------------------------------
    def record_tool_call(self, agent_id: str, call: ToolCall) -> None:
        """Record a tool call for TUE computation."""
        self._tool_calls[agent_id].append(call)
        # Keep only last 150 calls (3 windows)
        if len(self._tool_calls[agent_id]) > 150:
            self._tool_calls[agent_id] = self._tool_calls[agent_id][-150:]

    def compute_tue(self, agent_id: str) -> TUEResult:
        """Compute Tool Utilization Efficacy for an agent.

        TUE = (correct / total) * (1 - redundancy) * precision_weight
        Rolling 50-call window.
        """
        calls = self._tool_calls.get(agent_id, [])
        window = calls[-self.TUE_WINDOW_SIZE:]
        total = len(window)

        if total == 0:
            return TUEResult(agent_id=agent_id, tue=1.0, window_size=0,
                             correct=0, redundant=0, false_positive=0)

        correct = sum(1 for c in window if c.outcome_class == "success")
        redundant = sum(1 for c in window if c.is_redundant)
        false_positive = sum(1 for c in window if c.is_false_positive)

        redundancy_ratio = redundant / total
        precision_weight = 1 - (false_positive / total)

        tue = (correct / total) * (1 - redundancy_ratio) * precision_weight
        tue = max(0.0, min(1.0, tue))

        # Store in Qdrant
        self.qdrant.store_coordination_score({
            "record_type": "tue",
            "agent_pair": "",
            "agent_id": agent_id,
            "session_id": "",
            "css": 0.0,
            "tue": tue,
            "collusion_penalty": 0.0,
            "interaction_count": 0,
            "window_size": total,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Check consecutive windows below threshold
        consecutive = self._check_consecutive_low_tue(agent_id, tue)
        degraded = consecutive >= self.TUE_CONSECUTIVE_WINDOWS

        result = TUEResult(
            agent_id=agent_id,
            tue=tue,
            window_size=total,
            correct=correct,
            redundant=redundant,
            false_positive=false_positive,
            degraded=degraded,
            consecutive_low_windows=consecutive,
        )

        if degraded:
            self._alert_guardian("TUE_DEGRADED", "MEDIUM", {
                "agent_id": agent_id,
                "tue": tue,
                "consecutive_windows": consecutive,
            })
            self._emit_coordination_alert("tue_degraded", 0.0, tue,
                                          agent_id, 0.0)

        return result

    def _check_consecutive_low_tue(self, agent_id: str, current_tue: float) -> int:
        """Count consecutive TUE windows below threshold."""
        recent = self.qdrant.get_recent_scores("tue", agent_id, limit=5)
        # Add current
        values = [r.get("tue", 1.0) for r in recent] + [current_tue]
        # Count from end
        count = 0
        for val in reversed(values):
            if val < self.TUE_LOW_THRESHOLD:
                count += 1
            else:
                break
        return count

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _pair_key(agent_a: str, agent_b: str) -> str:
        """Deterministic pair key (sorted)."""
        return ":".join(sorted([agent_a, agent_b]))

    def _alert_guardian(self, event_type: str, severity: str,
                        evidence: dict) -> None:
        """Send alert to Guardian Agent if available."""
        if self._guardian:
            from governance.lib.security.threat_detection import ThreatEvent
            self._guardian.process_event(ThreatEvent(
                threat_id=str(uuid.uuid4()),
                type=event_type,
                severity=severity,
                agent_id=evidence.get("agent_id", ""),
                session_id=evidence.get("session_id", ""),
                timestamp=datetime.now(timezone.utc).isoformat(),
                evidence=evidence,
            ))

    def _emit_coordination_alert(self, alert_type: str, css_score: float,
                                 tue_score: float, agent_pair: str,
                                 collusion_penalty: float) -> None:
        """Emit coordination alert to audit bus."""
        self.audit_bus.emit(
            EventType.SECURITY_COORDINATION_ALERT,
            manifest={"agent_id": "coordination_scorer",
                      "audit_session_id": "system"},
            outcome="warn",
            detail={
                "alert_type": alert_type,
                "css_score": css_score,
                "tue_score": tue_score,
                "agent_pair": agent_pair,
                "collusion_penalty": collusion_penalty,
            },
        )
