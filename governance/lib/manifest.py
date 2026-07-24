"""Governance manifest — agent identity documents.

Loads static YAML manifests, resolves inheritance chains, enforces
parent ceiling, derives child manifests, computes tamper-evidence hashes.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CLASSIFICATION_ORDER = ["public", "internal", "confidential", "restricted"]

REQUIRED_MANIFEST_FIELDS = [
    "agent_id", "manifest_id", "manifest_version", "trust_level",
    "data_classification", "permitted_tools", "permitted_delegations",
    "human_required", "max_autonomy_depth", "max_delegation_count",
]

# Optional security extension fields (WI-11)
SECURITY_MANIFEST_FIELDS = [
    "session_scope",                  # list[str]: directory/tool scope patterns
    "credential_rotation_interval",   # int: seconds between rotation (default 3600)
    "agent_class",                    # str: read_only|write_authorized|external_facing
]

# PRD 18 Pillar 1 — Human Attribution fields (REQ-RCA-001/002/003/004).
# All optional in the static manifest; populated at session-start time by
# `set_human_attribution()` and `set_mfa_attestation()` before agent spawn.
HUMAN_ATTRIBUTION_MANIFEST_FIELDS = [
    "human_user_id",         # str: authenticated principal (OIDC sub or stable id);
                             #      sentinel 'system' allowed for autonomous jobs;
                             #      sentinel 'legacy_pre_attribution' is reserved for
                             #      pre-migration rows and must not be set in code.
    "responsible_person",    # str: named human accountable for the deployment/session;
                             #      may equal human_user_id, or be a different person
                             #      for delegated execution (e.g. on-call operator).
    "mfa_verified",          # bool: True iff a fresh MFA proof was supplied for this
                             #       session and data classification.
    "mfa_method",            # str: 'webauthn'|'totp'|'u2f'|'sso_step_up' or None.
    "mfa_timestamp",         # str: ISO 8601 UTC timestamp of the MFA proof.
]

HUMAN_USER_SYSTEM = "system"
HUMAN_USER_LEGACY = "legacy_pre_attribution"

# REQ-RCA-003 — Data classifications that require an MFA proof on the session.
MFA_REQUIRED_CLASSIFICATIONS = {"confidential", "restricted"}

DEFAULT_RESTRICTIVE_MANIFEST = {
    "manifest_id": "default-restrictive",
    "manifest_version": "1.0.0",
    "trust_level": 1,
    "data_classification": "public",
    "permitted_tools": [],
    "permitted_delegations": [],
    "human_required": True,
    "max_autonomy_depth": 0,
    "max_delegation_count": 0,
    "audit_parent_id": None,
    "audit_session_id": None,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_manifests_dir() -> Path:
    env_dir = os.environ.get("GOVERNANCE_MANIFESTS_DIR")
    if env_dir:
        return Path(env_dir)
    # Default: plugin_root/state/manifests/
    return Path(__file__).resolve().parent.parent.parent / "state" / "manifests"


def _hash_manifest(manifest: dict) -> str:
    """Full SHA-256 of canonicalized manifest JSON (excludes manifest_hash field)."""
    canonical = json.dumps(
        {k: v for k, v in manifest.items() if k != "manifest_hash"},
        sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _min_classification(a: str, b: str) -> str:
    """Return the lower classification level."""
    idx_a = CLASSIFICATION_ORDER.index(a) if a in CLASSIFICATION_ORDER else 0
    idx_b = CLASSIFICATION_ORDER.index(b) if b in CLASSIFICATION_ORDER else 0
    return CLASSIFICATION_ORDER[min(idx_a, idx_b)]


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def load_static_manifest(agent_id: str) -> Optional[dict]:
    """Load a static YAML manifest for agent_id. Returns None if not found."""
    manifests_dir = _get_manifests_dir()
    path = manifests_dir / f"{agent_id}.yaml"
    if not path.exists():
        return None
    try:
        with open(path) as f:
            manifest = yaml.safe_load(f)
        if not isinstance(manifest, dict):
            return None
        manifest["manifest_hash"] = _hash_manifest(manifest)
        return manifest
    except Exception:
        return None


def load_all_static_manifests() -> list[dict]:
    """Load all .yaml manifest files from the manifests directory."""
    manifests_dir = _get_manifests_dir()
    if not manifests_dir.exists():
        return []
    result = []
    for path in sorted(manifests_dir.glob("*.yaml")):
        try:
            with open(path) as f:
                manifest = yaml.safe_load(f)
            if isinstance(manifest, dict):
                manifest["manifest_hash"] = _hash_manifest(manifest)
                result.append(manifest)
        except Exception:
            continue
    return result


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate_manifest(manifest: dict) -> bool:
    """Check that manifest has all required fields with valid values."""
    for field in REQUIRED_MANIFEST_FIELDS:
        if field not in manifest:
            return False
    trust = manifest.get("trust_level")
    if not isinstance(trust, int) or trust < 1 or trust > 5:
        return False
    classification = manifest.get("data_classification")
    if classification not in CLASSIFICATION_ORDER:
        return False
    if not isinstance(manifest.get("permitted_tools"), list):
        return False
    if not isinstance(manifest.get("permitted_delegations"), list):
        return False
    if not isinstance(manifest.get("max_autonomy_depth"), int):
        return False
    if not isinstance(manifest.get("max_delegation_count"), int):
        return False
    return True


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------
def _propagate_human_attribution(parent: dict, target: dict) -> None:
    """Copy human attribution + MFA fields from parent into target dict.

    REQ-RCA-001/002/003/004 — child sessions inherit the orchestrating
    human's identity, the named responsible person, and any MFA proof
    captured at the parent level. This guarantees attribution flows down
    the delegation chain so every audit row carries the same human_user_id.
    """
    for field in HUMAN_ATTRIBUTION_MANIFEST_FIELDS:
        if field in parent:
            target[field] = parent[field]


def enforce_parent_ceiling(static: dict, parent: dict) -> dict:
    """Intersect static manifest capabilities with parent constraints."""
    resolved = static.copy()
    resolved["trust_level"] = min(
        static["trust_level"], parent["trust_level"])
    resolved["data_classification"] = _min_classification(
        static["data_classification"], parent["data_classification"])
    resolved["max_autonomy_depth"] = min(
        static["max_autonomy_depth"],
        parent["max_autonomy_depth"] - 1)
    resolved["audit_parent_id"] = parent["manifest_id"]
    resolved["audit_session_id"] = parent["audit_session_id"]
    resolved["human_required"] = (
        static["human_required"] or parent.get("human_required", False))
    _propagate_human_attribution(parent, resolved)
    resolved["manifest_hash"] = _hash_manifest(resolved)
    return resolved


def derive_child_manifest(parent: dict, agent_id: str) -> dict:
    """Create a restrictive derived manifest for an unknown agent."""
    child = {
        "manifest_id": f"{agent_id}-derived",
        "agent_id": agent_id,
        "manifest_version": "derived",
        "manifest_hash": None,
        "trust_level": min(parent["trust_level"], 2),
        "data_classification": parent["data_classification"],
        "permitted_tools": [],
        "permitted_delegations": [],
        "human_required": parent["trust_level"] <= 2,
        "max_autonomy_depth": max(parent["max_autonomy_depth"] - 1, 0),
        "max_delegation_count": 0,
        "audit_parent_id": parent["manifest_id"],
        "audit_session_id": parent.get("audit_session_id"),
        "derived_from": parent["manifest_id"],
        "derived_at": datetime.now(timezone.utc).isoformat(),
    }
    _propagate_human_attribution(parent, child)
    child["manifest_hash"] = _hash_manifest(child)
    return child


# ---------------------------------------------------------------------------
# Human Attribution (PRD 18 Pillar 1 — REQ-RCA-001/002/003/004)
# ---------------------------------------------------------------------------
def set_human_attribution(manifest: dict,
                          human_user_id: str,
                          responsible_person: Optional[str] = None) -> dict:
    """Anchor a manifest to an authenticated human identity.

    REQ-RCA-001 (session anchor): MUST be called before any agent is spawned
    from this manifest. Refusing to call this is the canonical way to express
    "this session is autonomous" — pass HUMAN_USER_SYSTEM explicitly so that
    every audit row still receives a non-empty attribution.

    REQ-RCA-004 (named responsible person): if responsible_person is not
    supplied, it defaults to the human_user_id. For delegated execution
    (e.g. an on-call operator who fires a job for a manager) the two fields
    will differ.

    Returns a new manifest dict (does not mutate the input). The manifest
    hash is rebuilt so that downstream tamper-evidence checks still pass.
    """
    if not isinstance(human_user_id, str) or not human_user_id.strip():
        raise ValueError("human_user_id must be a non-empty string")
    if human_user_id == HUMAN_USER_LEGACY:
        # 'legacy_pre_attribution' is a migration sentinel; never set in code.
        raise ValueError(
            "human_user_id 'legacy_pre_attribution' is reserved for "
            "pre-migration backfill")
    rp = responsible_person if responsible_person else human_user_id
    if not isinstance(rp, str) or not rp.strip():
        raise ValueError("responsible_person must be a non-empty string")

    new = manifest.copy()
    new["human_user_id"] = human_user_id
    new["responsible_person"] = rp
    new["manifest_hash"] = _hash_manifest(new)
    return new


def set_mfa_attestation(manifest: dict,
                        method: str,
                        timestamp: str) -> dict:
    """Record that a multi-factor authentication proof was supplied.

    REQ-RCA-003: confidential/restricted sessions require a fresh MFA proof.
    The proof must be captured BEFORE any audit event is emitted so that the
    `mfa_verified` flag flows through `_build_event`.

    `method` is a free-form string; producers should choose from a controlled
    vocabulary (e.g. 'webauthn', 'totp', 'u2f', 'sso_step_up'). `timestamp`
    must be ISO 8601 UTC.

    Returns a new manifest dict. Manifest hash is rebuilt.
    """
    valid_methods = {"webauthn", "totp", "u2f", "sso_step_up"}
    if method not in valid_methods:
        raise ValueError(
            f"mfa method '{method}' not in valid set {sorted(valid_methods)}")
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise ValueError("mfa timestamp must be a non-empty ISO 8601 string")

    new = manifest.copy()
    new["mfa_verified"] = True
    new["mfa_method"] = method
    new["mfa_timestamp"] = timestamp
    new["manifest_hash"] = _hash_manifest(new)
    return new


def is_mfa_required(manifest: dict) -> bool:
    """Return True if this manifest's classification mandates an MFA proof.

    REQ-RCA-003: confidential and restricted classifications require MFA.
    """
    return manifest.get("data_classification") in MFA_REQUIRED_CLASSIFICATIONS


def has_valid_human_attribution(manifest: dict) -> bool:
    """Return True iff the manifest has a non-empty `human_user_id`.

    Sentinel values (`system`) count as valid attribution. The legacy
    sentinel does NOT count as valid for new code paths because it indicates
    a pre-migration row.
    """
    val = manifest.get("human_user_id")
    if not isinstance(val, str) or not val.strip():
        return False
    return val != HUMAN_USER_LEGACY


def resolve_manifest(agent_id: str,
                     parent_manifest: Optional[dict] = None) -> dict:
    """Resolve the effective manifest for an agent.

    Resolution order:
    1. Static + parent -> enforce_parent_ceiling
    2. Static alone -> authoritative
    3. Parent only -> derive_child_manifest (restrictive)
    4. Neither -> DEFAULT_RESTRICTIVE_MANIFEST
    """
    static = load_static_manifest(agent_id)

    if static and parent_manifest:
        return enforce_parent_ceiling(static, parent_manifest)

    if static:
        return static

    if parent_manifest:
        return derive_child_manifest(parent_manifest, agent_id)

    return DEFAULT_RESTRICTIVE_MANIFEST.copy()
