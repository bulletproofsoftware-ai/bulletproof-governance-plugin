# tests/test_memory_governor.py
import os
from pathlib import Path

import pytest


@pytest.fixture
def audit_bus(tmp_path):
    from governance.lib.audit_bus import AuditBus
    db = tmp_path / "audit.db"
    buf = tmp_path / "audit-buffer.json"
    return AuditBus(db_path=db, buffer_path=buf)


@pytest.fixture
def classification_patterns():
    return {
        "restricted": [
            r'\b(password|secret|api[_-]?key|private[_-]?key|token|credential)\s*[:=]\s*\S+',
            r'\b\d{3}-\d{2}-\d{4}\b',
            r'-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----',
            r'\b(bearer\s+[a-zA-Z0-9\-._~+/]+=*)\b',
        ],
        "confidential": [
            r'\b(internal[_-]?only|do[_-]?not[_-]?share|proprietary|confidential)\b',
            r'\bCVE-\d{4}-\d{4,7}\b',
            r'\b(salary|compensation|revenue|profit)\s*[:=$]',
            r'\b(ssn|social[_-]?security|tax[_-]?id)\b',
        ],
        "internal": [
            r'\b(prod(uction)?|staging)\s+\b(server|host|endpoint|cluster)\b',
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            r'\b[a-zA-Z0-9\-]+\.(internal|corp|local)\b',
        ],
    }


@pytest.fixture
def governor(audit_bus, classification_patterns):
    from governance.lib.memory_governor import MemoryGovernor
    gov = MemoryGovernor(audit_bus=audit_bus)
    gov.classification_patterns = classification_patterns
    return gov


@pytest.fixture
def conductor_manifest():
    return {
        "agent_id": "conductor",
        "manifest_id": "gov-conductor",
        "manifest_version": "1.0.0",
        "manifest_hash": "abc" * 20 + "abcd",
        "trust_level": 5,
        "data_classification": "internal",
        "audit_session_id": "sess-001",
    }


@pytest.fixture
def public_manifest():
    return {
        "agent_id": "researcher",
        "manifest_id": "gov-researcher",
        "manifest_version": "1.0.0",
        "manifest_hash": "def" * 20 + "defg",
        "trust_level": 2,
        "data_classification": "public",
        "audit_session_id": "sess-001",
    }


class TestClassifyContent:
    def test_restricted_password(self, governor):
        assert governor._classify_content("password = hunter2") == "restricted"

    def test_restricted_api_key(self, governor):
        assert governor._classify_content("api_key = sk-abc123xyz") == "restricted"

    def test_restricted_ssn_format(self, governor):
        assert governor._classify_content("SSN is 123-45-6789") == "restricted"

    def test_restricted_private_key(self, governor):
        assert governor._classify_content("-----BEGIN PRIVATE KEY-----") == "restricted"

    def test_restricted_bearer_token(self, governor):
        assert governor._classify_content("bearer eyJhbGciOiJIUzI1NiJ9") == "restricted"

    def test_confidential_cve(self, governor):
        assert governor._classify_content("Found CVE-2026-1234 in the scan") == "confidential"

    def test_confidential_internal_only(self, governor):
        assert governor._classify_content("This is internal_only information") == "confidential"

    def test_confidential_salary(self, governor):
        assert governor._classify_content("salary = 150000") == "confidential"

    def test_internal_ip_address(self, governor):
        assert governor._classify_content("Server at 198.51.100.1") == "internal"

    def test_internal_corp_domain(self, governor):
        assert governor._classify_content("Connect to api.corp") == "internal"

    def test_internal_production_server(self, governor):
        assert governor._classify_content("production server is down") == "internal"

    def test_public_benign_content(self, governor):
        assert governor._classify_content("hello world") == "public"

    def test_public_cybersecurity_terms_not_classified(self, governor):
        """Generic cybersecurity words should NOT trigger classification."""
        assert governor._classify_content("vulnerability assessment") == "public"
        assert governor._classify_content("exploit development") == "public"
        assert governor._classify_content("server architecture") == "public"


class TestClassifyAndGate:
    def test_restricted_blocked(self, governor, conductor_manifest):
        decision = governor.classify_and_gate(
            conductor_manifest, "password = hunter2", {})
        assert decision.action == "block"
        assert decision.classification == "restricted"
        assert "restricted" in decision.reason.lower() or "block" in decision.reason.lower()

    def test_confidential_queued(self, governor):
        """Agent with confidential ceiling writing confidential content -> queued."""
        ciso_manifest = {
            "agent_id": "ciso",
            "manifest_id": "gov-ciso",
            "manifest_version": "1.0.0",
            "manifest_hash": "ccc" * 20 + "cccd",
            "trust_level": 4,
            "data_classification": "confidential",
            "audit_session_id": "sess-001",
        }
        decision = governor.classify_and_gate(
            ciso_manifest, "Found CVE-2026-1234", {})
        assert decision.action == "allow"
        assert decision.classification == "confidential"
        assert decision.provenance is not None
        assert decision.provenance.get("gov_approval_status") == "pending_review"

    def test_internal_allowed_with_provenance(self, governor, conductor_manifest):
        decision = governor.classify_and_gate(
            conductor_manifest, "Server at 198.51.100.1", {})
        assert decision.action == "allow"
        assert decision.classification == "internal"
        assert decision.provenance is not None
        assert "gov_manifest_id" in decision.provenance

    def test_public_allowed_with_provenance(self, governor, conductor_manifest):
        decision = governor.classify_and_gate(
            conductor_manifest, "hello world", {})
        assert decision.action == "allow"
        assert decision.classification == "public"
        assert decision.provenance is not None

    def test_ceiling_exceeded_blocks(self, governor, public_manifest):
        """Agent with public ceiling writing confidential content -> block."""
        decision = governor.classify_and_gate(
            public_manifest, "Found CVE-2026-5678 in scan", {})
        assert decision.action == "block"
        assert decision.gate_type == "ceiling_exceeded"

    def test_provenance_fields(self, governor, conductor_manifest):
        decision = governor.classify_and_gate(
            conductor_manifest, "hello world", {})
        prov = decision.provenance
        assert prov["gov_manifest_id"] == "gov-conductor"
        assert prov["gov_agent_id"] == "conductor"
        assert prov["gov_trust_level"] == 5
        assert prov["gov_session_id"] == "sess-001"
        assert "gov_timestamp" in prov

    def test_audit_events_on_block(self, governor, conductor_manifest, audit_bus):
        governor.classify_and_gate(
            conductor_manifest, "password = secret123", {})
        events = audit_bus.query({"event_type": "policy_deny"})
        assert len(events) == 1

    def test_audit_events_on_allow(self, governor, conductor_manifest, audit_bus):
        governor.classify_and_gate(
            conductor_manifest, "hello world", {})
        events = audit_bus.query({"event_type": "memory_write"})
        assert len(events) == 1


class TestGovernanceDecision:
    def test_dataclass_defaults(self):
        from governance.lib.memory_governor import GovernanceDecision
        d = GovernanceDecision("allow", "public")
        assert d.action == "allow"
        assert d.classification == "public"
        assert d.provenance is None
        assert d.reason == ""
        assert d.gate_type == ""

    def test_with_provenance(self):
        from governance.lib.memory_governor import GovernanceDecision
        d = GovernanceDecision("allow", "internal", {"gov_manifest_id": "test"})
        assert d.provenance["gov_manifest_id"] == "test"
