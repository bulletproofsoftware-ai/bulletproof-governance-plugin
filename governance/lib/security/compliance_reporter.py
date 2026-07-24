"""Compliance Reporter — SOC 2 Type II + DOI reports (REQ-076).

Generates evidence packages for SOC 2 controls (CC6.1, CC6.3, CC6.7,
CC7.1, CC7.2, CC7.3, CC9.1) and state DOI agent disclosure reports.
JSON and PDF output formats. Report generation logged and digitally signed.
"""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from governance.lib.audit_bus import AuditBus, EventType

logger = logging.getLogger("governance.security.compliance_reporter")

# ---------------------------------------------------------------------------
# SOC 2 Type II Control Mapping
# ---------------------------------------------------------------------------
SOC2_CONTROLS = {
    "CC6.1": {
        "title": "Logical Access — Identity Lifecycle",
        "description": "The entity implements logical access security measures "
                       "to protect against threats from sources outside its "
                       "system boundaries.",
        "evidence_source": "identity_transition",
        "module": "Identity Lifecycle Manager",
        "event_types": [
            "security.identity_transition",
            "security.identity_rotation",
        ],
    },
    "CC6.3": {
        "title": "Role-Based Access — Manifest Scope Enforcement",
        "description": "The entity authorizes, modifies, or removes access "
                       "to data, software, functions, and other protected "
                       "information assets based on roles.",
        "evidence_source": "policy_check",
        "module": "Policy Engine + Trust Broker",
        "event_types": [
            "policy_check",
            "policy_deny",
            "trust_check",
            "trust_deny",
            "security.escalation_blocked",
        ],
    },
    "CC6.7": {
        "title": "Authorized Changes — Memory Integrity",
        "description": "The entity restricts the transmission, movement, "
                       "and removal of information to authorized internal "
                       "and external users.",
        "evidence_source": "memory_integrity",
        "module": "Memory Integrity Verifier",
        "event_types": [
            "security.memory_integrity",
            "security.quarantine_action",
        ],
    },
    "CC7.1": {
        "title": "Threat Detection",
        "description": "To meet its objectives, the entity uses detection "
                       "and monitoring procedures to identify changes to "
                       "configurations that result in new vulnerabilities.",
        "evidence_source": "threat_detected",
        "module": "Threat Detection Engine",
        "event_types": [
            "security.threat_detected",
            "security.injection_blocked",
            "security.exfiltration_alert",
            "security.tool_abuse",
        ],
    },
    "CC7.2": {
        "title": "System Monitoring — Behavioral Anomalies",
        "description": "The entity monitors system components and the "
                       "operation of those components for anomalies.",
        "evidence_source": "behavioral_anomaly",
        "module": "Behavioral Monitor",
        "event_types": [
            "security.behavioral_anomaly",
            "security.coordination_alert",
        ],
    },
    "CC7.3": {
        "title": "Security Evaluation — Guardian Decisions",
        "description": "The entity evaluates security events to determine "
                       "whether they could or have resulted in a failure.",
        "evidence_source": "guardian_decision",
        "module": "Guardian Agent",
        "event_types": [
            "security.guardian_action",
        ],
    },
    "CC9.1": {
        "title": "Risk Mitigation — Quarantine & Suspension",
        "description": "The entity identifies, selects, and develops risk "
                       "mitigation activities.",
        "evidence_source": "quarantine_action",
        "module": "Guardian Agent + Quarantine Manager",
        "event_types": [
            "security.quarantine_action",
            "security.guardian_action",
            "security.identity_transition",
        ],
    },
}


class ComplianceReporter:
    """Generates SOC 2 and DOI compliance reports."""

    def __init__(self, audit_bus: AuditBus, qdrant=None):
        self.audit_bus = audit_bus
        self.qdrant = qdrant

    # ------------------------------------------------------------------
    # SOC 2 Type II Report
    # ------------------------------------------------------------------
    def generate_soc2_report(
        self,
        period_start: str = "",
        period_end: str = "",
        controls: Optional[list[str]] = None,
    ) -> dict:
        """Generate SOC 2 Type II evidence package.

        Args:
            period_start: ISO 8601 start of reporting period.
            period_end: ISO 8601 end of reporting period.
            controls: List of CC controls to include (default: all 7).

        Returns:
            ComplianceReport dict with evidence per control.
        """
        if not controls:
            controls = list(SOC2_CONTROLS.keys())

        now = datetime.now(timezone.utc)
        if not period_start:
            period_start = (now.replace(day=1)).isoformat()
        if not period_end:
            period_end = now.isoformat()

        report = {
            "report_id": str(uuid.uuid4()),
            "report_type": "SOC2_TYPE_II",
            "generated_at": now.isoformat(),
            "generated_by": "compliance_reporter",
            "period_start": period_start,
            "period_end": period_end,
            "controls": {},
            "summary": {
                "total_controls": len(controls),
                "controls_with_evidence": 0,
                "total_evidence_events": 0,
            },
        }

        for control_id in controls:
            if control_id not in SOC2_CONTROLS:
                continue
            spec = SOC2_CONTROLS[control_id]
            evidence = self._collect_evidence(spec["event_types"])

            report["controls"][control_id] = {
                "control_id": control_id,
                "title": spec["title"],
                "description": spec["description"],
                "module": spec["module"],
                "evidence_count": len(evidence),
                "evidence_sample": evidence[:10],  # First 10 for review
                "evidence_summary": self._summarize_evidence(evidence),
                "status": "evidence_present" if evidence else "no_evidence",
            }

            if evidence:
                report["summary"]["controls_with_evidence"] += 1
                report["summary"]["total_evidence_events"] += len(evidence)

        # Digital signature (SHA-256 of report content)
        report["signature"] = self._sign_report(report)

        # Audit the report generation
        self.audit_bus.emit(
            EventType.POLICY_CHECK,
            manifest={"agent_id": "compliance_reporter",
                      "audit_session_id": "system"},
            outcome="info",
            detail={
                "rules_evaluated": len(controls),
                "rules_matched": report["summary"]["controls_with_evidence"],
                "evaluation_ms": 0,
                "conductor_tier": "compliance_report_soc2",
            },
        )

        return report

    # ------------------------------------------------------------------
    # DOI Report
    # ------------------------------------------------------------------
    def generate_doi_report(
        self,
        period_start: str = "",
        period_end: str = "",
    ) -> dict:
        """Generate state DOI agent disclosure report.

        Covers: agent identities, tool usage, data classification enforcement,
        anomaly detection findings, and Guardian interventions.
        """
        now = datetime.now(timezone.utc)
        if not period_start:
            period_start = (now.replace(day=1)).isoformat()
        if not period_end:
            period_end = now.isoformat()

        # Collect evidence by category
        identity_events = self._collect_evidence([
            "security.identity_transition",
            "security.identity_rotation",
        ])
        threat_events = self._collect_evidence([
            "security.threat_detected",
            "security.injection_blocked",
            "security.exfiltration_alert",
            "security.escalation_blocked",
            "security.tool_abuse",
        ])
        guardian_events = self._collect_evidence([
            "security.guardian_action",
        ])
        memory_events = self._collect_evidence([
            "security.memory_integrity",
            "security.quarantine_action",
        ])
        anomaly_events = self._collect_evidence([
            "security.behavioral_anomaly",
            "security.coordination_alert",
        ])

        # Build unique agent inventory
        agents = set()
        for e in identity_events:
            aid = e.get("agent_id", "")
            if aid and aid != "unknown":
                agents.add(aid)

        report = {
            "report_id": str(uuid.uuid4()),
            "report_type": "DOI_AGENT_DISCLOSURE",
            "generated_at": now.isoformat(),
            "generated_by": "compliance_reporter",
            "period_start": period_start,
            "period_end": period_end,
            "agent_inventory": {
                "total_agents": len(agents),
                "agent_ids": sorted(agents),
            },
            "sections": {
                "identity_management": {
                    "description": "Agent identity lifecycle events including "
                                   "provisioning, authentication, and revocation",
                    "event_count": len(identity_events),
                    "summary": self._summarize_evidence(identity_events),
                },
                "threat_detection": {
                    "description": "Security threats detected and blocked during "
                                   "the reporting period",
                    "event_count": len(threat_events),
                    "summary": self._summarize_evidence(threat_events),
                    "by_type": self._group_by_type(threat_events),
                },
                "guardian_interventions": {
                    "description": "Autonomous and advisory interventions by the "
                                   "Guardian Agent",
                    "event_count": len(guardian_events),
                    "summary": self._summarize_evidence(guardian_events),
                },
                "memory_integrity": {
                    "description": "Memory write integrity verification and "
                                   "quarantine actions",
                    "event_count": len(memory_events),
                    "summary": self._summarize_evidence(memory_events),
                },
                "behavioral_monitoring": {
                    "description": "Behavioral anomaly detections and coordination "
                                   "scoring alerts",
                    "event_count": len(anomaly_events),
                    "summary": self._summarize_evidence(anomaly_events),
                },
            },
            "summary": {
                "total_security_events": (
                    len(identity_events) + len(threat_events) +
                    len(guardian_events) + len(memory_events) +
                    len(anomaly_events)
                ),
                "threats_blocked": sum(
                    1 for e in threat_events
                    if e.get("outcome") in ("deny", "block")
                ),
                "sessions_suspended": sum(
                    1 for e in guardian_events
                    if _detail_field(e, "action_taken") in ("SUSPEND", "TERMINATE")
                ),
                "memory_entries_quarantined": sum(
                    1 for e in memory_events
                    if _detail_field(e, "action_type") == "quarantine"
                ),
            },
        }

        report["signature"] = self._sign_report(report)

        # Audit the report generation
        self.audit_bus.emit(
            EventType.POLICY_CHECK,
            manifest={"agent_id": "compliance_reporter",
                      "audit_session_id": "system"},
            outcome="info",
            detail={
                "rules_evaluated": 5,
                "rules_matched": 5,
                "evaluation_ms": 0,
                "conductor_tier": "compliance_report_doi",
            },
        )

        return report

    # ------------------------------------------------------------------
    # Evidence helpers
    # ------------------------------------------------------------------
    def _collect_evidence(self, event_types: list[str]) -> list[dict]:
        """Collect events from audit bus by event type."""
        events = []
        for etype in event_types:
            results = self.audit_bus.query(
                {"event_type": etype},
                limit=1000,
            )
            events.extend(results)
        return sorted(events, key=lambda e: e.get("timestamp", ""))

    @staticmethod
    def _summarize_evidence(events: list[dict]) -> dict:
        """Create statistical summary of evidence events."""
        if not events:
            return {"count": 0}

        outcomes = {}
        for e in events:
            outcome = e.get("outcome", "unknown")
            outcomes[outcome] = outcomes.get(outcome, 0) + 1

        agents = set()
        for e in events:
            aid = e.get("agent_id", "")
            if aid and aid != "unknown":
                agents.add(aid)

        return {
            "count": len(events),
            "outcome_distribution": outcomes,
            "unique_agents": len(agents),
            "earliest": events[0].get("timestamp", "") if events else "",
            "latest": events[-1].get("timestamp", "") if events else "",
        }

    @staticmethod
    def _group_by_type(events: list[dict]) -> dict:
        """Group events by event_type for breakdown."""
        groups = {}
        for e in events:
            etype = e.get("event_type", "unknown")
            groups.setdefault(etype, 0)
            groups[etype] += 1
        return groups

    @staticmethod
    def _sign_report(report: dict) -> str:
        """Generate SHA-256 signature of report content."""
        # Exclude signature field from hash
        content = {k: v for k, v in report.items() if k != "signature"}
        canonical = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


def _detail_field(event: dict, field: str) -> str:
    """Extract a field from event detail JSON."""
    detail = event.get("detail", "")
    if isinstance(detail, str):
        try:
            detail = json.loads(detail)
        except (json.JSONDecodeError, TypeError):
            return ""
    if isinstance(detail, dict):
        return str(detail.get(field, ""))
    return ""
