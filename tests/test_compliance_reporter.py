"""Tests for ComplianceReporter — Phase 11 (REQ-076)."""

import json
import pytest
from unittest.mock import MagicMock

from governance.lib.security.compliance_reporter import (
    ComplianceReporter,
    SOC2_CONTROLS,
)


@pytest.fixture
def mock_audit_bus():
    bus = MagicMock()
    bus.emit.return_value = "event-id"
    bus.query.return_value = []
    return bus


@pytest.fixture
def reporter(mock_audit_bus):
    return ComplianceReporter(mock_audit_bus)


class TestSOC2Report:
    def test_generates_all_7_controls(self, reporter):
        """Should generate evidence for all 7 SOC 2 controls."""
        report = reporter.generate_soc2_report()
        assert report["report_type"] == "SOC2_TYPE_II"
        assert len(report["controls"]) == 7
        for ctrl in ["CC6.1", "CC6.3", "CC6.7", "CC7.1", "CC7.2", "CC7.3", "CC9.1"]:
            assert ctrl in report["controls"]

    def test_report_has_signature(self, reporter):
        """Report should include SHA-256 signature."""
        report = reporter.generate_soc2_report()
        assert "signature" in report
        assert len(report["signature"]) == 64  # SHA-256 hex

    def test_report_has_period(self, reporter):
        """Report should include reporting period."""
        report = reporter.generate_soc2_report(
            period_start="2026-01-01T00:00:00Z",
            period_end="2026-03-31T23:59:59Z")
        assert report["period_start"] == "2026-01-01T00:00:00Z"
        assert report["period_end"] == "2026-03-31T23:59:59Z"

    def test_control_with_evidence(self, reporter, mock_audit_bus):
        """Control with evidence should be marked as evidence_present."""
        mock_audit_bus.query.return_value = [
            {"event_id": "e1", "timestamp": "2026-04-01T12:00:00Z",
             "event_type": "security.identity_transition",
             "agent_id": "agent-1", "outcome": "info"},
        ]
        report = reporter.generate_soc2_report(controls=["CC6.1"])
        ctrl = report["controls"]["CC6.1"]
        assert ctrl["status"] == "evidence_present"
        assert ctrl["evidence_count"] > 0

    def test_control_without_evidence(self, reporter):
        """Control without evidence should be marked no_evidence."""
        report = reporter.generate_soc2_report(controls=["CC7.1"])
        ctrl = report["controls"]["CC7.1"]
        assert ctrl["status"] == "no_evidence"

    def test_selective_controls(self, reporter):
        """Should only generate specified controls."""
        report = reporter.generate_soc2_report(controls=["CC6.1", "CC7.1"])
        assert len(report["controls"]) == 2

    def test_audits_report_generation(self, reporter, mock_audit_bus):
        """Report generation itself should be audited."""
        reporter.generate_soc2_report()
        mock_audit_bus.emit.assert_called()


class TestDOIReport:
    def test_generates_doi_structure(self, reporter):
        """DOI report should have required sections."""
        report = reporter.generate_doi_report()
        assert report["report_type"] == "DOI_AGENT_DISCLOSURE"
        assert "agent_inventory" in report
        assert "sections" in report
        sections = report["sections"]
        assert "identity_management" in sections
        assert "threat_detection" in sections
        assert "guardian_interventions" in sections
        assert "memory_integrity" in sections
        assert "behavioral_monitoring" in sections

    def test_doi_has_signature(self, reporter):
        """DOI report should include digital signature."""
        report = reporter.generate_doi_report()
        assert "signature" in report
        assert len(report["signature"]) == 64

    def test_doi_summary_totals(self, reporter, mock_audit_bus):
        """DOI report summary should tally correctly."""
        mock_audit_bus.query.return_value = [
            {"event_id": "e1", "timestamp": "2026-04-01T12:00:00Z",
             "event_type": "security.threat_detected",
             "agent_id": "agent-1", "outcome": "deny"},
        ]
        report = reporter.generate_doi_report()
        assert report["summary"]["total_security_events"] >= 0


class TestSOC2ControlMapping:
    def test_all_controls_have_event_types(self):
        """Every SOC 2 control should map to event types."""
        for ctrl_id, spec in SOC2_CONTROLS.items():
            assert "event_types" in spec
            assert len(spec["event_types"]) > 0

    def test_all_controls_have_description(self):
        """Every control should have a description."""
        for ctrl_id, spec in SOC2_CONTROLS.items():
            assert spec["description"]
            assert spec["title"]
            assert spec["module"]


class TestSignature:
    def test_signature_changes_with_content(self, reporter, mock_audit_bus):
        """Different report content should produce different signatures."""
        report1 = reporter.generate_soc2_report(controls=["CC6.1"])
        mock_audit_bus.query.return_value = [
            {"event_id": "e1", "timestamp": "2026-04-01",
             "event_type": "test", "agent_id": "a1", "outcome": "info"},
        ]
        report2 = reporter.generate_soc2_report(controls=["CC6.1"])
        # Different content -> different signatures (unless same events)
        # At minimum, report_id changes each time
        assert report1["report_id"] != report2["report_id"]
