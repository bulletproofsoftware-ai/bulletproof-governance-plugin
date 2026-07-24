# tests/test_policy_engine.py
import json
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
def tool_tiers():
    return {
        "exempt": ["Read", "Glob", "Grep", "TaskList", "TaskGet", "AskUserQuestion"],
        "standard": ["Edit", "Write", "Task", "Bash", "WebFetch", "WebSearch"],
        "elevated": [
            "mcp__claude-memory__memory_store",
            "mcp__claude-memory__memory_forget",
            "NotebookEdit",
        ],
        "elevated_patterns": [
            "mcp__MCP_DOCKER__*",
            "mcp__hostinger-mcp__*",
        ],
    }


@pytest.fixture
def conductor_manifest():
    return {
        "agent_id": "conductor",
        "manifest_id": "gov-conductor",
        "manifest_version": "1.0.0",
        "manifest_hash": "abc" * 20 + "abcd",
        "trust_level": 5,
        "data_classification": "internal",
        "permitted_tools": ["Task", "Read", "Glob", "Grep", "Write", "Edit",
                            "Bash", "AskUserQuestion", "mcp__claude-memory__*"],
        "permitted_delegations": ["*"],
        "human_required": False,
        "max_autonomy_depth": 3,
        "max_delegation_count": 10,
        "audit_session_id": "sess-001",
    }


@pytest.fixture
def restrictive_manifest():
    return {
        "agent_id": "unknown-agent",
        "manifest_id": "default-restrictive",
        "manifest_version": "1.0.0",
        "manifest_hash": "xyz" * 20 + "xyzw",
        "trust_level": 1,
        "data_classification": "public",
        "permitted_tools": [],
        "permitted_delegations": [],
        "human_required": True,
        "max_autonomy_depth": 0,
        "max_delegation_count": 0,
        "audit_session_id": "sess-001",
    }


class TestClassifyTool:
    def test_exempt_tool(self, audit_bus, tool_tiers):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        assert engine._classify_tool("Read") == "exempt"
        assert engine._classify_tool("Glob") == "exempt"

    def test_standard_tool(self, audit_bus, tool_tiers):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        assert engine._classify_tool("Write") == "standard"
        assert engine._classify_tool("Bash") == "standard"

    def test_elevated_tool(self, audit_bus, tool_tiers):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        assert engine._classify_tool("mcp__claude-memory__memory_store") == "elevated"
        assert engine._classify_tool("NotebookEdit") == "elevated"

    def test_elevated_pattern_match(self, audit_bus, tool_tiers):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        assert engine._classify_tool("mcp__MCP_DOCKER__browser_click") == "elevated"
        assert engine._classify_tool("mcp__hostinger-mcp__VPS_startVirtualMachineV1") == "elevated"

    def test_unknown_tool_defaults_elevated(self, audit_bus, tool_tiers):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        assert engine._classify_tool("SomeNewTool") == "elevated"


class TestToolPermitted:
    def test_exact_match(self, audit_bus, tool_tiers):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        manifest = {"permitted_tools": ["Read", "Write"]}
        assert engine._tool_permitted(manifest, "Read") is True
        assert engine._tool_permitted(manifest, "Bash") is False

    def test_fnmatch_pattern(self, audit_bus, tool_tiers):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        manifest = {"permitted_tools": ["mcp__claude-memory__*"]}
        assert engine._tool_permitted(manifest, "mcp__claude-memory__memory_store") is True
        assert engine._tool_permitted(manifest, "mcp__MCP_DOCKER__foo") is False

    def test_empty_permitted_denies_all(self, audit_bus, tool_tiers):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        manifest = {"permitted_tools": []}
        assert engine._tool_permitted(manifest, "Read") is False


class TestEvaluate:
    def test_exempt_tool_always_allows(self, audit_bus, tool_tiers, conductor_manifest):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        decision = engine.evaluate(conductor_manifest, "Read", {}, "STANDARD")
        assert decision.action == "allow"

    def test_tool_not_permitted_denies(self, audit_bus, tool_tiers, restrictive_manifest):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        decision = engine.evaluate(restrictive_manifest, "Write", {}, "STANDARD")
        assert decision.action == "deny"
        assert decision.gate_type == "permitted_tools"

    def test_autonomy_depth_zero_escalates(self, audit_bus, tool_tiers):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        manifest = {
            "agent_id": "test", "manifest_id": "gov-test",
            "manifest_version": "1.0.0", "manifest_hash": "a" * 64,
            "trust_level": 3, "data_classification": "internal",
            "permitted_tools": ["Write", "Edit"],
            "permitted_delegations": [],
            "human_required": False,
            "max_autonomy_depth": 0,
            "max_delegation_count": 0,
            "audit_session_id": "sess-001",
        }
        decision = engine.evaluate(manifest, "Write", {}, "STANDARD")
        assert decision.action == "human_gate"
        assert decision.gate_type == "depth_exhausted"

    def test_human_required_escalates(self, audit_bus, tool_tiers):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        manifest = {
            "agent_id": "test", "manifest_id": "gov-test",
            "manifest_version": "1.0.0", "manifest_hash": "a" * 64,
            "trust_level": 3, "data_classification": "internal",
            "permitted_tools": ["Write"],
            "permitted_delegations": [],
            "human_required": True,
            "max_autonomy_depth": 2,
            "max_delegation_count": 0,
            "audit_session_id": "sess-001",
        }
        decision = engine.evaluate(manifest, "Write", {}, "STANDARD")
        assert decision.action == "human_gate"
        assert decision.gate_type == "manifest_required"

    def test_major_elevated_requires_human(self, audit_bus, tool_tiers, conductor_manifest):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        decision = engine.evaluate(
            conductor_manifest, "mcp__claude-memory__memory_store", {}, "MAJOR")
        assert decision.action == "human_gate"
        assert decision.gate_type == "tier_matrix"

    def test_standard_standard_tool_allows(self, audit_bus, tool_tiers, conductor_manifest):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        decision = engine.evaluate(conductor_manifest, "Write", {}, "STANDARD")
        assert decision.action == "allow"

    def test_trivial_exempt_allows(self, audit_bus, tool_tiers, conductor_manifest):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        decision = engine.evaluate(conductor_manifest, "Read", {}, "TRIVIAL")
        assert decision.action == "allow"

    def test_none_tier_defaults_to_standard(self, audit_bus, tool_tiers, conductor_manifest):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        decision = engine.evaluate(conductor_manifest, "Write", {}, None)
        assert decision.action == "allow"

    def test_audit_events_emitted(self, audit_bus, tool_tiers, conductor_manifest):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        engine.evaluate(conductor_manifest, "Write", {}, "STANDARD")
        events = audit_bus.query({"event_type": "policy_check"})
        assert len(events) == 1

    def test_deny_emits_policy_deny(self, audit_bus, tool_tiers, restrictive_manifest):
        from governance.lib.policy_engine import PolicyEngine
        engine = PolicyEngine(audit_bus=audit_bus, tool_tiers=tool_tiers)
        engine.evaluate(restrictive_manifest, "Write", {}, "STANDARD")
        events = audit_bus.query({"event_type": "policy_deny"})
        assert len(events) == 1


class TestPolicyDecision:
    def test_dataclass_fields(self):
        from governance.lib.policy_engine import PolicyDecision
        d = PolicyDecision("allow")
        assert d.action == "allow"
        assert d.reason == ""
        assert d.gate_type == ""

    def test_with_all_fields(self):
        from governance.lib.policy_engine import PolicyDecision
        d = PolicyDecision("deny", "not permitted", "permitted_tools")
        assert d.action == "deny"
        assert d.reason == "not permitted"
        assert d.gate_type == "permitted_tools"
