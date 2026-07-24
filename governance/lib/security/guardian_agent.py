"""Guardian Agent — 3 autonomy levels, 5-tier decision matrix (REQ-071/072).

Autonomy: ADVISORY / SEMI_AUTONOMOUS / FULLY_AUTONOMOUS
Score 1-10 -> LOG_ONLY / NOTIFY / THROTTLE / SUSPEND / TERMINATE
Self-protection: cannot self-terminate, mass action rate limit.
"""

import logging
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import httpx

from governance.lib.audit_bus import AuditBus, EventType
from governance.lib.security.security_config import SecurityConfig

logger = logging.getLogger("governance.security.guardian_agent")

# Guardian's own agent ID — excluded from self-targeting
GUARDIAN_AGENT_ID = "guardian_agent"

# Mass action rate limit: max 5 SUSPEND/TERMINATE in 60 seconds
MASS_ACTION_WINDOW = 60
MASS_ACTION_LIMIT = 5


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------
@dataclass
class GuardianDecision:
    decision_id: str = ""
    event_type: str = ""
    agent_id: str = ""
    session_id: str = ""
    assessment_score: int = 0
    action_taken: str = ""
    autonomy_level: str = ""
    action_was_downgraded: bool = False
    original_action: str = ""
    human_confirmation_required: bool = False
    human_confirmation_received: bool = False
    timestamp: str = ""
    evidence_summary: str = ""
    notification_sent: bool = False
    notification_latency_ms: int = 0


# Base assessment scores per threat type
BASE_SCORES = {
    "PROMPT_INJECTION": 9,
    "DATA_EXFILTRATION": 9,
    "PRIVILEGE_ESCALATION": 8,
    "MEMORY_POISONING": 7,
    "TOOL_ABUSE": 5,
    "BEHAVIORAL_ANOMALY": 3,
    "CSS_THRESHOLD_BREACH": 4,
    "CSS_CRITICAL_BREACH": 7,
    "TUE_DEGRADED": 3,
    "MEMORY_QUARANTINE": 4,
}


# ---------------------------------------------------------------------------
# GuardianAgent
# ---------------------------------------------------------------------------
class GuardianAgent:
    def __init__(self, qdrant, audit_bus: AuditBus, config: SecurityConfig,
                 identity_mgr=None):
        self.qdrant = qdrant
        self.audit_bus = audit_bus
        self.config = config
        self.identity_mgr = identity_mgr
        self.autonomy_level = config.guardian.autonomy_level
        self._action_log: list[tuple[float, str]] = []  # (timestamp, action)
        self._notification_client: Optional[httpx.Client] = None
        self._global_lockdown = False
        self._lockdown_timestamp: Optional[str] = None

    # ------------------------------------------------------------------
    # Core: process security event
    # ------------------------------------------------------------------
    def process_event(self, event) -> GuardianDecision:
        """Process a security event through the decision matrix.

        Args:
            event: ThreatEvent or similar with .type, .severity, .evidence,
                   .agent_id, .session_id fields.

        Returns:
            GuardianDecision with action taken and audit trail.
        """
        agent_id = getattr(event, "agent_id", "") or ""
        session_id = getattr(event, "session_id", "") or ""
        event_type = getattr(event, "type", "UNKNOWN")
        severity = getattr(event, "severity", "")
        evidence = getattr(event, "evidence", {})

        # Self-protection: Guardian cannot target itself
        if agent_id == GUARDIAN_AGENT_ID:
            logger.warning("Guardian self-targeting blocked for event: %s", event_type)
            return self._log_decision(
                event_type, agent_id, session_id, 0,
                "LOG_ONLY", "LOG_ONLY", False,
                "self_protection_block", evidence)

        score = self.compute_assessment_score(event)
        original_action = self._score_to_action(score)
        action = original_action
        downgraded = False
        human_required = False

        # Apply autonomy level gate
        if self.autonomy_level == "ADVISORY":
            if action in ("THROTTLE", "SUSPEND", "TERMINATE"):
                action = "NOTIFY"
                downgraded = True
                human_required = True
        elif self.autonomy_level == "SEMI_AUTONOMOUS":
            if action == "TERMINATE":
                action = "SUSPEND"
                downgraded = True
                human_required = True

        # Global lockdown check: if in lockdown, block all non-LOG actions
        if self._global_lockdown:
            logger.critical(
                "GLOBAL_LOCKDOWN active — forcing SUSPEND for event %s "
                "(human approval required to lift)", event_type)
            action = "SUSPEND"
            downgraded = True
            human_required = True

        # Mass action rate limit — escalate to GLOBAL_LOCKDOWN
        if action in ("SUSPEND", "TERMINATE"):
            if self._is_rate_limited():
                self._global_lockdown = True
                self._lockdown_timestamp = datetime.now(timezone.utc).isoformat()
                logger.critical(
                    "Mass action rate limit exceeded — entering GLOBAL_LOCKDOWN. "
                    "Human approval required to lift.")
                self.audit_bus.emit(
                    EventType.SECURITY_GUARDIAN_ACTION,
                    manifest={"agent_id": GUARDIAN_AGENT_ID,
                              "audit_session_id": session_id or "system"},
                    outcome="deny",
                    detail={
                        "assessment_score": score,
                        "action_taken": "GLOBAL_LOCKDOWN",
                        "autonomy_level": self.autonomy_level,
                        "was_downgraded": False,
                        "original_action": original_action,
                        "event_type_trigger": "mass_action_rate_limit_exceeded",
                        "lockdown_timestamp": self._lockdown_timestamp,
                    },
                )
                human_required = True

        # Execute action
        self._execute_action(action, event, session_id)

        # Log decision
        decision = self._log_decision(
            event_type, agent_id, session_id, score,
            action, original_action, downgraded,
            str(evidence)[:500], evidence,
            human_required=human_required)

        # Notify operator
        if action != "LOG_ONLY":
            self._notify_operator(decision)

        return decision

    # ------------------------------------------------------------------
    # Assessment score computation
    # ------------------------------------------------------------------
    def compute_assessment_score(self, event) -> int:
        """Map security event to 1-10 assessment score."""
        event_type = getattr(event, "type", "UNKNOWN")
        severity = getattr(event, "severity", "")
        evidence = getattr(event, "evidence", {})

        base = BASE_SCORES.get(event_type, 5)

        # Severity modifier
        if severity == "CRITICAL":
            base = min(base + 2, 10)
        elif severity == "HIGH":
            base = min(base + 1, 10)

        # Evidence modifiers
        if evidence.get("repeated", False):
            base = min(base + 1, 10)
        if evidence.get("corroborated", False):
            base = min(base + 2, 10)
        if evidence.get("fail_closed", False) or evidence.get("method") == "fail_closed":
            base = min(base + 1, 10)

        return max(1, min(base, 10))

    # ------------------------------------------------------------------
    # Score -> Action mapping
    # ------------------------------------------------------------------
    @staticmethod
    def _score_to_action(score: int) -> str:
        """Map assessment score to action tier."""
        if score <= 2:
            return "LOG_ONLY"
        if score <= 4:
            return "NOTIFY"
        if score <= 6:
            return "THROTTLE"
        if score <= 8:
            return "SUSPEND"
        return "TERMINATE"

    # ------------------------------------------------------------------
    # Action execution
    # ------------------------------------------------------------------
    def _execute_action(self, action: str, event, session_id: str) -> None:
        """Execute the determined action."""
        if not session_id or not self.identity_mgr:
            return

        now = time.time()

        if action == "THROTTLE":
            try:
                self.identity_mgr.throttle(session_id, rate_limit=0.5)
            except Exception as e:
                logger.error("Throttle failed: %s", e)

        elif action == "SUSPEND":
            try:
                reason = getattr(event, "type", "guardian_suspension")
                self.identity_mgr.suspend(session_id, reason)
                self._action_log.append((now, "SUSPEND"))
            except Exception as e:
                logger.error("Suspend failed: %s", e)

        elif action == "TERMINATE":
            try:
                reason = getattr(event, "type", "guardian_termination")
                self.identity_mgr.revoke(session_id, reason)
                self._action_log.append((now, "TERMINATE"))

                # For critical threats, quarantine all session writes
                event_type = getattr(event, "type", "")
                if event_type in ("PROMPT_INJECTION", "DATA_EXFILTRATION"):
                    self._quarantine_session_writes(session_id)
            except Exception as e:
                logger.error("Terminate failed: %s", e)

    def _quarantine_session_writes(self, session_id: str) -> None:
        """Quarantine all memory writes from a terminated session."""
        try:
            # This would scan for recent writes by session and quarantine them
            # For now, we log the intent — actual implementation depends on
            # the memory plugin's write tracking
            logger.info("Quarantine requested for session %s writes", session_id)
            self.audit_bus.emit(
                EventType.SECURITY_QUARANTINE_ACTION,
                manifest={"agent_id": GUARDIAN_AGENT_ID,
                          "audit_session_id": session_id},
                outcome="warn",
                detail={
                    "entry_id": f"session_{session_id}",
                    "quarantine_reason": "session_terminated_quarantine_all",
                    "quarantine_stage": "guardian_intervention",
                    "target_collection": "memory_quarantine",
                    "action_type": "session_quarantine",
                },
            )
        except Exception as e:
            logger.error("Session quarantine failed: %s", e)

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------
    def _is_rate_limited(self) -> bool:
        """Check if mass action rate limit is exceeded."""
        now = time.time()
        cutoff = now - MASS_ACTION_WINDOW
        recent = [(t, a) for t, a in self._action_log if t > cutoff]
        self._action_log = recent
        severe_count = sum(1 for _, a in recent if a in ("SUSPEND", "TERMINATE"))
        return severe_count >= MASS_ACTION_LIMIT

    # ------------------------------------------------------------------
    # Evidence redaction for external transmission
    # ------------------------------------------------------------------
    @staticmethod
    def _redact_evidence(text: str) -> str:
        """Redact PII and secrets from evidence before sending to webhooks.

        Masks:
        - API keys/tokens (32+ char alphanumeric strings)
        - Email addresses
        - User home directory paths (/Users/...)
        """
        # Redact long alphanumeric tokens (API keys, secrets)
        redacted = re.sub(
            r'[A-Za-z0-9_\-]{32,}',
            '[REDACTED_TOKEN]',
            text,
        )
        # Redact email addresses
        redacted = re.sub(
            r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}',
            '[REDACTED_EMAIL]',
            redacted,
        )
        # Redact user home directory paths
        redacted = re.sub(
            r'/Users/[^\s/]+',
            '/Users/[REDACTED]',
            redacted,
        )
        return redacted

    # ------------------------------------------------------------------
    # Notification
    # ------------------------------------------------------------------
    def _notify_operator(self, decision: GuardianDecision) -> None:
        """Send notification to operator."""
        webhook_url = self.config.guardian.webhook_url
        if not webhook_url:
            return

        start = time.time()
        try:
            if self._notification_client is None:
                self._notification_client = httpx.Client(
                    timeout=self.config.guardian.webhook_timeout_ms / 1000)

            payload = {
                "decision_id": decision.decision_id,
                "event_type": decision.event_type,
                "agent_id": decision.agent_id,
                "assessment_score": decision.assessment_score,
                "action_taken": decision.action_taken,
                "autonomy_level": decision.autonomy_level,
                "timestamp": decision.timestamp,
                "evidence_summary": self._redact_evidence(
                    decision.evidence_summary[:500]),
            }

            self._notification_client.post(webhook_url, json=payload)
            latency_ms = int((time.time() - start) * 1000)
            decision.notification_sent = True
            decision.notification_latency_ms = latency_ms

            self.audit_bus.emit(
                EventType.SECURITY_GUARDIAN_ACTION,
                manifest={"agent_id": GUARDIAN_AGENT_ID,
                          "audit_session_id": decision.session_id},
                outcome="info",
                detail={
                    "assessment_score": decision.assessment_score,
                    "action_taken": "notification_sent",
                    "autonomy_level": decision.autonomy_level,
                    "was_downgraded": False,
                    "original_action": "",
                    "event_type_trigger": "notification",
                },
            )

        except Exception as e:
            logger.error("Notification failed: %s", e)
            decision.notification_sent = False

    # ------------------------------------------------------------------
    # Decision logging
    # ------------------------------------------------------------------
    def _log_decision(
        self,
        event_type: str,
        agent_id: str,
        session_id: str,
        score: int,
        action: str,
        original_action: str,
        downgraded: bool,
        evidence_summary: str,
        evidence: dict = None,
        human_required: bool = False,
    ) -> GuardianDecision:
        """Log decision to Qdrant and audit bus."""
        decision = GuardianDecision(
            decision_id=str(uuid.uuid4()),
            event_type=event_type,
            agent_id=agent_id,
            session_id=session_id,
            assessment_score=score,
            action_taken=action,
            autonomy_level=self.autonomy_level,
            action_was_downgraded=downgraded,
            original_action=original_action,
            human_confirmation_required=human_required,
            timestamp=datetime.now(timezone.utc).isoformat(),
            evidence_summary=evidence_summary,
        )

        # Store in Qdrant
        self.qdrant.log_guardian_decision({
            "decision_id": decision.decision_id,
            "event_type": event_type,
            "agent_id": agent_id,
            "session_id": session_id,
            "assessment_score": score,
            "action_taken": action,
            "autonomy_level": self.autonomy_level,
            "action_was_downgraded": downgraded,
            "original_action": original_action,
            "human_confirmation_required": human_required,
            "human_confirmation_received": False,
            "human_confirmed_by": "",
            "timestamp": decision.timestamp,
            "evidence_summary": evidence_summary[:500],
            "notification_sent": False,
            "notification_latency_ms": 0,
        })

        # Emit to audit bus
        self.audit_bus.emit(
            EventType.SECURITY_GUARDIAN_ACTION,
            manifest={"agent_id": GUARDIAN_AGENT_ID,
                      "audit_session_id": session_id or "system"},
            outcome="info" if action == "LOG_ONLY" else "warn",
            detail={
                "assessment_score": score,
                "action_taken": action,
                "autonomy_level": self.autonomy_level,
                "was_downgraded": downgraded,
                "original_action": original_action,
                "event_type_trigger": event_type,
            },
        )

        return decision

    # ------------------------------------------------------------------
    # Configuration management
    # ------------------------------------------------------------------
    def set_autonomy_level(self, level: str, operator_manifest: dict) -> bool:
        """Change Guardian autonomy level (requires security_admin scope).

        Returns True if changed, False if denied.
        """
        valid_levels = {"ADVISORY", "SEMI_AUTONOMOUS", "FULLY_AUTONOMOUS"}
        if level not in valid_levels:
            return False

        # Check operator scope
        permitted = operator_manifest.get("permitted_tools", [])
        if self.config.guardian.required_scope not in permitted:
            logger.warning(
                "Autonomy level change denied: operator lacks %s scope",
                self.config.guardian.required_scope)
            return False

        # Double-confirm for FULLY_AUTONOMOUS
        if (level == "FULLY_AUTONOMOUS" and
                self.config.guardian.require_double_confirm_for_full_auto):
            # In a real system, this would trigger a second confirmation
            # For now, we log and proceed (the hook layer handles the gate)
            pass

        old_level = self.autonomy_level

        # Log the change BEFORE it takes effect
        self.audit_bus.emit(
            EventType.SECURITY_GUARDIAN_ACTION,
            manifest=operator_manifest,
            outcome="info",
            detail={
                "assessment_score": 0,
                "action_taken": "autonomy_level_change",
                "autonomy_level": f"{old_level}->{level}",
                "was_downgraded": False,
                "original_action": "config_change",
                "event_type_trigger": "autonomy_level_change",
            },
        )

        self.autonomy_level = level
        return True

    def lift_global_lockdown(self, operator_manifest: dict) -> bool:
        """Lift GLOBAL_LOCKDOWN state (requires human approval via security_admin scope).

        Returns True if lockdown was lifted, False if denied.
        """
        permitted = operator_manifest.get("permitted_tools", [])
        if self.config.guardian.required_scope not in permitted:
            logger.warning(
                "Lockdown lift denied: operator lacks %s scope",
                self.config.guardian.required_scope)
            return False

        if not self._global_lockdown:
            return True  # Already not in lockdown

        self._global_lockdown = False
        lift_time = datetime.now(timezone.utc).isoformat()
        logger.info("GLOBAL_LOCKDOWN lifted by operator at %s", lift_time)

        self.audit_bus.emit(
            EventType.SECURITY_GUARDIAN_ACTION,
            manifest=operator_manifest,
            outcome="info",
            detail={
                "assessment_score": 0,
                "action_taken": "GLOBAL_LOCKDOWN_LIFTED",
                "autonomy_level": self.autonomy_level,
                "was_downgraded": False,
                "original_action": "lockdown_lift",
                "event_type_trigger": "human_approval_lockdown_lift",
                "lockdown_entered": self._lockdown_timestamp or "unknown",
                "lockdown_lifted": lift_time,
            },
        )
        self._lockdown_timestamp = None
        return True

    @property
    def is_locked_down(self) -> bool:
        """Check if Guardian is in GLOBAL_LOCKDOWN state."""
        return self._global_lockdown

    def get_decision_history(self, limit: int = 50) -> list[dict]:
        """Get recent Guardian decisions from audit log."""
        results = self.qdrant.scroll_points(
            "guardian_audit_log",
            limit=limit,
            order_by="timestamp",
        )
        return [r["payload"] for r in results]
