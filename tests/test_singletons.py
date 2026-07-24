# tests/test_singletons.py
import os
import pytest


@pytest.fixture(autouse=True)
def reset_singletons(tmp_path):
    """Reset module-level singletons between tests."""
    os.environ["GOVERNANCE_PLUGIN_ROOT"] = str(tmp_path)
    os.environ["GOVERNANCE_MANIFESTS_DIR"] = str(tmp_path / "manifests")
    (tmp_path / "manifests").mkdir()
    (tmp_path / "state").mkdir()
    yield
    # Reset singletons
    import governance.lib.singletons as s
    s._audit_bus = None
    s._policy_engine = None
    s._trust_broker = None
    s._registry = None
    s._governor = None
    os.environ.pop("GOVERNANCE_PLUGIN_ROOT", None)
    os.environ.pop("GOVERNANCE_MANIFESTS_DIR", None)


class TestSingletons:
    def test_get_audit_bus_returns_same_instance(self):
        from governance.lib.singletons import get_audit_bus
        a = get_audit_bus()
        b = get_audit_bus()
        assert a is b

    def test_get_registry_returns_same_instance(self):
        from governance.lib.singletons import get_registry
        a = get_registry()
        b = get_registry()
        assert a is b

    def test_get_policy_engine_returns_same_instance(self):
        from governance.lib.singletons import get_policy_engine
        a = get_policy_engine()
        b = get_policy_engine()
        assert a is b

    def test_get_trust_broker_returns_same_instance(self):
        from governance.lib.singletons import get_trust_broker
        a = get_trust_broker()
        b = get_trust_broker()
        assert a is b

    def test_get_governor_returns_same_instance(self):
        from governance.lib.singletons import get_governor
        a = get_governor()
        b = get_governor()
        assert a is b

    def test_all_share_same_audit_bus(self):
        from governance.lib.singletons import (
            get_audit_bus, get_policy_engine, get_trust_broker, get_governor)
        bus = get_audit_bus()
        engine = get_policy_engine()
        broker = get_trust_broker()
        governor = get_governor()
        assert engine.audit_bus is bus
        assert broker.audit_bus is bus
        assert governor.audit_bus is bus
