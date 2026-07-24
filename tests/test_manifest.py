# tests/test_manifest.py
import json
import os
import tempfile
from pathlib import Path

import pytest

# We'll set GOVERNANCE_MANIFESTS_DIR before importing
_tmpdir = None

@pytest.fixture(autouse=True)
def manifest_dir(tmp_path):
    """Point manifest loading at a temp directory."""
    global _tmpdir
    _tmpdir = tmp_path / "manifests"
    _tmpdir.mkdir()
    os.environ["GOVERNANCE_MANIFESTS_DIR"] = str(_tmpdir)
    yield
    os.environ.pop("GOVERNANCE_MANIFESTS_DIR", None)


def _write_yaml(path: Path, data: dict):
    import yaml
    path.write_text(yaml.dump(data))


class TestHashManifest:
    def test_deterministic(self):
        from governance.lib.manifest import _hash_manifest
        m = {"agent_id": "test", "trust_level": 3}
        assert _hash_manifest(m) == _hash_manifest(m)

    def test_full_sha256_length(self):
        from governance.lib.manifest import _hash_manifest
        h = _hash_manifest({"agent_id": "x"})
        assert len(h) == 64  # full SHA-256, not truncated

    def test_excludes_manifest_hash_field(self):
        from governance.lib.manifest import _hash_manifest
        m1 = {"agent_id": "test", "trust_level": 3}
        m2 = {"agent_id": "test", "trust_level": 3, "manifest_hash": "old"}
        assert _hash_manifest(m1) == _hash_manifest(m2)


class TestLoadStaticManifest:
    def test_load_existing(self):
        from governance.lib.manifest import load_static_manifest
        _write_yaml(_tmpdir / "conductor.yaml", {
            "agent_id": "conductor",
            "manifest_id": "gov-conductor",
            "manifest_version": "1.0.0",
            "trust_level": 5,
            "data_classification": "internal",
            "permitted_tools": ["Task", "Read"],
            "permitted_delegations": ["*"],
            "human_required": False,
            "max_autonomy_depth": 3,
            "max_delegation_count": 10,
        })
        m = load_static_manifest("conductor")
        assert m is not None
        assert m["trust_level"] == 5
        assert m["manifest_hash"]  # auto-computed on load
        assert len(m["manifest_hash"]) == 64

    def test_missing_returns_none(self):
        from governance.lib.manifest import load_static_manifest
        assert load_static_manifest("nonexistent") is None


class TestResolveManifest:
    def test_static_only(self):
        from governance.lib.manifest import resolve_manifest, load_static_manifest
        _write_yaml(_tmpdir / "qa.yaml", {
            "agent_id": "qa", "manifest_id": "gov-qa",
            "manifest_version": "1.0.0", "trust_level": 3,
            "data_classification": "internal",
            "permitted_tools": [], "permitted_delegations": [],
            "human_required": False, "max_autonomy_depth": 1,
            "max_delegation_count": 0,
        })
        m = resolve_manifest("qa")
        assert m["trust_level"] == 3

    def test_no_static_no_parent_returns_default(self):
        from governance.lib.manifest import resolve_manifest, DEFAULT_RESTRICTIVE_MANIFEST
        m = resolve_manifest("unknown-agent")
        assert m["trust_level"] == 1
        assert m["human_required"] is True
        assert m["permitted_tools"] == []

    def test_parent_ceiling_enforced(self):
        from governance.lib.manifest import resolve_manifest
        _write_yaml(_tmpdir / "builder.yaml", {
            "agent_id": "builder", "manifest_id": "gov-builder",
            "manifest_version": "1.0.0", "trust_level": 3,
            "data_classification": "internal",
            "permitted_tools": ["Write", "Edit"],
            "permitted_delegations": [],
            "human_required": False, "max_autonomy_depth": 2,
            "max_delegation_count": 5,
        })
        parent = {
            "manifest_id": "gov-conductor", "trust_level": 5,
            "data_classification": "internal",
            "max_autonomy_depth": 3, "human_required": False,
            "audit_session_id": "test-session-123",
        }
        m = resolve_manifest("builder", parent)
        assert m["trust_level"] == 3  # min(3, 5)
        assert m["max_autonomy_depth"] == 2  # min(2, 3-1)
        assert m["audit_session_id"] == "test-session-123"  # inherited

    def test_derived_child_for_unknown(self):
        from governance.lib.manifest import resolve_manifest
        parent = {
            "manifest_id": "gov-conductor", "trust_level": 5,
            "data_classification": "internal",
            "max_autonomy_depth": 3, "human_required": False,
            "audit_session_id": "sess-1",
        }
        m = resolve_manifest("totally-new-agent", parent)
        assert m["trust_level"] <= 2
        assert m["permitted_tools"] == []
        assert m["permitted_delegations"] == []
        assert m["audit_parent_id"] == "gov-conductor"

    def test_parent_ceiling_caps_static_trust(self):
        """Static agent with trust 4, parent has trust 2 -> resolved trust 2."""
        from governance.lib.manifest import resolve_manifest
        _write_yaml(_tmpdir / "ciso.yaml", {
            "agent_id": "ciso", "manifest_id": "gov-ciso",
            "manifest_version": "1.0.0", "trust_level": 4,
            "data_classification": "confidential",
            "permitted_tools": ["Read"], "permitted_delegations": [],
            "human_required": False, "max_autonomy_depth": 1,
            "max_delegation_count": 2,
        })
        low_parent = {
            "manifest_id": "gov-low", "trust_level": 2,
            "data_classification": "public",
            "max_autonomy_depth": 1, "human_required": True,
            "audit_session_id": "sess-2",
        }
        m = resolve_manifest("ciso", low_parent)
        assert m["trust_level"] == 2  # capped by parent
        assert m["human_required"] is True  # OR with parent


class TestClassificationOrdering:
    def test_min_classification(self):
        from governance.lib.manifest import _min_classification
        assert _min_classification("confidential", "internal") == "internal"
        assert _min_classification("public", "restricted") == "public"
        assert _min_classification("internal", "internal") == "internal"


class TestLoadAllManifests:
    def test_loads_multiple(self):
        from governance.lib.manifest import load_all_static_manifests
        for name in ["a", "b", "c"]:
            _write_yaml(_tmpdir / f"{name}.yaml", {
                "agent_id": name, "manifest_id": f"gov-{name}",
                "manifest_version": "1.0.0", "trust_level": 2,
                "data_classification": "public",
                "permitted_tools": [], "permitted_delegations": [],
                "human_required": True, "max_autonomy_depth": 0,
                "max_delegation_count": 0,
            })
        manifests = load_all_static_manifests()
        assert len(manifests) == 3


class TestValidateManifest:
    def test_valid(self):
        from governance.lib.manifest import validate_manifest
        m = {
            "agent_id": "test", "manifest_id": "gov-test",
            "manifest_version": "1.0.0", "trust_level": 3,
            "data_classification": "internal",
            "permitted_tools": ["Read"],
            "permitted_delegations": [],
            "human_required": False, "max_autonomy_depth": 1,
            "max_delegation_count": 0,
        }
        assert validate_manifest(m) is True

    def test_missing_required_field(self):
        from governance.lib.manifest import validate_manifest
        assert validate_manifest({"agent_id": "x"}) is False

    def test_invalid_trust_level(self):
        from governance.lib.manifest import validate_manifest
        m = {
            "agent_id": "x", "manifest_id": "y",
            "manifest_version": "1.0.0", "trust_level": 99,
            "data_classification": "internal",
            "permitted_tools": [], "permitted_delegations": [],
            "human_required": False, "max_autonomy_depth": 0,
            "max_delegation_count": 0,
        }
        assert validate_manifest(m) is False
