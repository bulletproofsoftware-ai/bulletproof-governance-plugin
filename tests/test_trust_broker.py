# tests/test_trust_broker.py
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest


@pytest.fixture
def audit_bus(tmp_path):
    from governance.lib.audit_bus import AuditBus
    db = tmp_path / "audit.db"
    buf = tmp_path / "audit-buffer.json"
    return AuditBus(db_path=db, buffer_path=buf)


@pytest.fixture
def registry(tmp_path):
    from governance.lib.trust_broker import ManifestRegistry
    return ManifestRegistry(registry_path=tmp_path / "active-manifests.json")


@pytest.fixture
def broker(audit_bus, registry):
    from governance.lib.trust_broker import TrustBroker
    return TrustBroker(audit_bus=audit_bus, manifest_registry=registry)


@pytest.fixture(autouse=True)
def set_manifests_dir(tmp_path):
    manifests_dir = tmp_path / "manifests"
    manifests_dir.mkdir()
    os.environ["GOVERNANCE_MANIFESTS_DIR"] = str(manifests_dir)
    yield manifests_dir
    os.environ.pop("GOVERNANCE_MANIFESTS_DIR", None)


def _write_yaml(path: Path, data: dict):
    import yaml
    path.write_text(yaml.dump(data))


@pytest.fixture
def conductor_manifest():
    return {
        "agent_id": "conductor",
        "manifest_id": "gov-conductor",
        "manifest_version": "1.0.0",
        "manifest_hash": "abc" * 20 + "abcd",
        "trust_level": 5,
        "data_classification": "internal",
        "permitted_tools": ["Task", "Read", "Write"],
        "permitted_delegations": ["*"],
        "human_required": False,
        "max_autonomy_depth": 3,
        "max_delegation_count": 10,
        "audit_session_id": "sess-001",
    }


@pytest.fixture
def builder_manifest_yaml(set_manifests_dir):
    _write_yaml(set_manifests_dir / "builder.yaml", {
        "agent_id": "builder",
        "manifest_id": "gov-builder",
        "manifest_version": "1.0.0",
        "trust_level": 3,
        "data_classification": "internal",
        "permitted_tools": ["Write", "Edit"],
        "permitted_delegations": ["conductor-qa", "conductor-code-reviewer"],
        "human_required": False,
        "max_autonomy_depth": 2,
        "max_delegation_count": 5,
    })


# -----------------------------------------------------------------------
# ManifestRegistry tests
# -----------------------------------------------------------------------
class TestManifestRegistry:
    def test_register_and_get(self, registry, conductor_manifest):
        registry.register_active("conductor", conductor_manifest, "sess-001")
        result = registry.get_active("conductor", "sess-001")
        assert result is not None
        assert result["agent_id"] == "conductor"

    def test_get_missing_returns_none(self, registry):
        assert registry.get_active("nonexistent", "sess-001") is None

    def test_deregister(self, registry, conductor_manifest):
        registry.register_active("conductor", conductor_manifest, "sess-001")
        registry.deregister("conductor", "sess-001")
        assert registry.get_active("conductor", "sess-001") is None

    def test_session_isolation(self, registry, conductor_manifest):
        registry.register_active("conductor", conductor_manifest, "sess-001")
        assert registry.get_active("conductor", "sess-002") is None

    def test_purge_stale(self, registry, tmp_path):
        """Entries older than TTL should be purged."""
        from governance.lib.trust_broker import ManifestRegistry
        reg = ManifestRegistry(registry_path=tmp_path / "test-reg.json")
        # Register with normal TTL so it survives the register_active purge
        manifest = {"agent_id": "test", "manifest_id": "gov-test"}
        reg.register_active("test", manifest, "sess-001")
        assert reg.get_active("test", "sess-001") is not None
        # Now set TTL to 0 and wait, then purge
        reg.TTL_SECONDS = 0
        time.sleep(0.1)
        removed = reg.purge_stale()
        assert removed == 1
        assert reg.get_active("test", "sess-001") is None

    def test_file_locking_concurrent(self, registry, conductor_manifest):
        """Basic test that file locking doesn't deadlock."""
        registry.register_active("a", conductor_manifest, "sess-001")
        registry.register_active("b", conductor_manifest, "sess-001")
        assert registry.get_active("a", "sess-001") is not None
        assert registry.get_active("b", "sess-001") is not None


# -----------------------------------------------------------------------
# TrustBroker.evaluate_delegation tests
# -----------------------------------------------------------------------
class TestEvaluateDelegation:
    def test_allow_valid_delegation(self, broker, conductor_manifest,
                                    builder_manifest_yaml):
        decision = broker.evaluate_delegation(
            conductor_manifest, "builder", "Build the feature")
        assert decision.action == "allow"
        assert decision.delegation_token != ""
        assert decision.resolved_manifest is not None

    def test_breadth_limit_exceeded(self, broker, audit_bus, conductor_manifest,
                                    builder_manifest_yaml, set_manifests_dir):
        """Exceed max_delegation_count -> deny."""
        # Create a manifest with max_delegation_count=2
        limited = conductor_manifest.copy()
        limited["max_delegation_count"] = 2
        # Issue 2 delegations (fill the quota)
        for i in range(2):
            _write_yaml(set_manifests_dir / f"agent{i}.yaml", {
                "agent_id": f"agent{i}", "manifest_id": f"gov-agent{i}",
                "manifest_version": "1.0.0", "trust_level": 2,
                "data_classification": "public",
                "permitted_tools": [], "permitted_delegations": [],
                "human_required": False, "max_autonomy_depth": 1,
                "max_delegation_count": 0,
            })
            broker.evaluate_delegation(limited, f"agent{i}", f"Task {i}")
        # Third should be denied
        _write_yaml(set_manifests_dir / "agent2.yaml", {
            "agent_id": "agent2", "manifest_id": "gov-agent2",
            "manifest_version": "1.0.0", "trust_level": 2,
            "data_classification": "public",
            "permitted_tools": [], "permitted_delegations": [],
            "human_required": False, "max_autonomy_depth": 1,
            "max_delegation_count": 0,
        })
        decision = broker.evaluate_delegation(limited, "agent2", "Task 2")
        assert decision.action == "deny"
        assert decision.gate_type == "breadth_exceeded"

    def test_depth_exhaustion_escalates(self, broker, set_manifests_dir):
        """max_autonomy_depth 0 -> escalate."""
        source = {
            "agent_id": "shallow",
            "manifest_id": "gov-shallow",
            "manifest_version": "1.0.0",
            "manifest_hash": "s" * 64,
            "trust_level": 3,
            "data_classification": "internal",
            "permitted_tools": ["Task"],
            "permitted_delegations": ["*"],
            "human_required": False,
            "max_autonomy_depth": 0,
            "max_delegation_count": 5,
            "audit_session_id": "sess-001",
        }
        _write_yaml(set_manifests_dir / "target.yaml", {
            "agent_id": "target", "manifest_id": "gov-target",
            "manifest_version": "1.0.0", "trust_level": 2,
            "data_classification": "public",
            "permitted_tools": [], "permitted_delegations": [],
            "human_required": False, "max_autonomy_depth": 1,
            "max_delegation_count": 0,
        })
        decision = broker.evaluate_delegation(source, "target", "Do something")
        assert decision.action == "escalate"
        assert decision.gate_type == "depth_exhausted"

    def test_classification_boundary_ceiling_caps(self, broker, set_manifests_dir):
        """Target with higher static classification gets capped by ceiling -> allow."""
        source = {
            "agent_id": "lowclass",
            "manifest_id": "gov-lowclass",
            "manifest_version": "1.0.0",
            "manifest_hash": "l" * 64,
            "trust_level": 3,
            "data_classification": "public",
            "permitted_tools": ["Task"],
            "permitted_delegations": ["*"],
            "human_required": False,
            "max_autonomy_depth": 3,
            "max_delegation_count": 5,
            "audit_session_id": "sess-001",
        }
        _write_yaml(set_manifests_dir / "hightarget.yaml", {
            "agent_id": "hightarget", "manifest_id": "gov-hightarget",
            "manifest_version": "1.0.0", "trust_level": 2,
            "data_classification": "confidential",
            "permitted_tools": [], "permitted_delegations": [],
            "human_required": False, "max_autonomy_depth": 1,
            "max_delegation_count": 0,
        })
        # enforce_parent_ceiling caps target to source's "public" —
        # defense-in-depth classification check passes (equal, not exceeding)
        decision = broker.evaluate_delegation(
            source, "hightarget", "Handle confidential")
        assert decision.action == "allow"

    def test_classification_boundary_defense_in_depth(self, broker, audit_bus):
        """Direct test of classification boundary check (defense-in-depth)."""
        from unittest.mock import patch
        source = {
            "agent_id": "lowclass",
            "manifest_id": "gov-lowclass",
            "manifest_version": "1.0.0",
            "manifest_hash": "l" * 64,
            "trust_level": 3,
            "data_classification": "public",
            "permitted_tools": ["Task"],
            "permitted_delegations": ["*"],
            "human_required": False,
            "max_autonomy_depth": 3,
            "max_delegation_count": 5,
            "audit_session_id": "sess-001",
        }
        # Simulate a bug in ceiling enforcement: resolved manifest retains
        # higher classification than source
        bad_resolved = {
            "agent_id": "hightarget",
            "manifest_id": "gov-hightarget",
            "trust_level": 2,
            "data_classification": "confidential",
            "max_autonomy_depth": 1,
        }
        with patch("governance.lib.trust_broker.resolve_manifest",
                    return_value=bad_resolved):
            decision = broker.evaluate_delegation(
                source, "hightarget", "Handle confidential")
        assert decision.action == "deny"
        assert decision.gate_type == "classification_boundary"

    def test_delegation_target_not_permitted(self, broker, set_manifests_dir):
        """Agent not in permitted_delegations -> deny."""
        source = {
            "agent_id": "restricted-delegator",
            "manifest_id": "gov-restricted-delegator",
            "manifest_version": "1.0.0",
            "manifest_hash": "r" * 64,
            "trust_level": 3,
            "data_classification": "internal",
            "permitted_tools": ["Task"],
            "permitted_delegations": ["conductor-qa"],
            "human_required": False,
            "max_autonomy_depth": 2,
            "max_delegation_count": 5,
            "audit_session_id": "sess-001",
        }
        _write_yaml(set_manifests_dir / "unauthorized.yaml", {
            "agent_id": "unauthorized", "manifest_id": "gov-unauthorized",
            "manifest_version": "1.0.0", "trust_level": 2,
            "data_classification": "internal",
            "permitted_tools": [], "permitted_delegations": [],
            "human_required": False, "max_autonomy_depth": 1,
            "max_delegation_count": 0,
        })
        decision = broker.evaluate_delegation(
            source, "unauthorized", "Not allowed")
        assert decision.action == "deny"
        assert decision.gate_type == "target_not_permitted"


class TestCheckPermittedDelegations:
    def test_none_denies(self, broker):
        manifest = {"permitted_delegations": None}
        assert broker._check_permitted_delegations(manifest, "anything") is False

    def test_empty_list_denies(self, broker):
        manifest = {"permitted_delegations": []}
        assert broker._check_permitted_delegations(manifest, "anything") is False

    def test_wildcard_allows(self, broker):
        manifest = {"permitted_delegations": ["*"]}
        assert broker._check_permitted_delegations(manifest, "anything") is True

    def test_fnmatch_pattern(self, broker):
        manifest = {"permitted_delegations": ["conductor-*"]}
        assert broker._check_permitted_delegations(manifest, "conductor-qa") is True
        assert broker._check_permitted_delegations(manifest, "random-agent") is False

    def test_exact_match(self, broker):
        manifest = {"permitted_delegations": ["conductor-qa"]}
        assert broker._check_permitted_delegations(manifest, "conductor-qa") is True
        assert broker._check_permitted_delegations(manifest, "conductor-builder") is False

    def test_absent_field_denies(self, broker):
        manifest = {}
        assert broker._check_permitted_delegations(manifest, "anything") is False


class TestExtractTargetAgent:
    def test_subagent_type(self):
        from governance.lib.trust_broker import _extract_target_agent
        assert _extract_target_agent({"subagent_type": "builder"}) == "builder"

    def test_empty_subagent_type(self):
        from governance.lib.trust_broker import _extract_target_agent
        assert _extract_target_agent({"subagent_type": ""}) is None

    def test_no_fields_returns_none(self):
        from governance.lib.trust_broker import _extract_target_agent
        assert _extract_target_agent({}) is None

    def test_agent_prefix_in_prompt(self):
        from governance.lib.trust_broker import _extract_target_agent
        result = _extract_target_agent(
            {"description": "AGENT: conductor-qa do the thing"})
        assert result == "conductor-qa"


class TestTrustDecision:
    def test_defaults(self):
        from governance.lib.trust_broker import TrustDecision
        d = TrustDecision("allow")
        assert d.action == "allow"
        assert d.reason == ""
        assert d.resolved_manifest is None
        assert d.delegation_token == ""
        assert d.gate_type == ""

    def test_full_fields(self):
        from governance.lib.trust_broker import TrustDecision
        d = TrustDecision("deny", "reason here", gate_type="depth_exhausted")
        assert d.action == "deny"
        assert d.gate_type == "depth_exhausted"
