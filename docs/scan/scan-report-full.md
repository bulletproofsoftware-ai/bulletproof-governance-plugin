# Security Scan Report: bulletproof-governance-plugin

**Scan ID:** `ae9709d8-2f4f-454e-913b-69e96ae5d3e9`
**Date:** 2026-07-24T20:26:38.322Z
**Score:** 962/1000 (excellent)
**Branch:** main | **Commit:** `N/A`
**Profile:** standard

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 61 |
| Low | 8 |
| Info | 2 |
| **Total (open)** | **71** |

> **Note:** The counts above reflect _open_ findings only.
> 1 scanner(s) were skipped — see "Skipped Scanners" below.

## Scanners Executed

| Scanner | Status | Findings | Duration | Notes |
|---------|--------|----------|----------|-------|
| trivy | pass | 1 | 2.6s |  |
| gitleaks | pass | 0 | 0.6s |  |
| opengrep | pass | 3 | 6.9s |  |
| checkov | pass | 0 | 3.4s |  |
| grype | pass | 0 | 3.4s |  |
| syft | pass | 7 | 1.6s |  |
| package-validator | pass | 0 | 0.1s |  |
| oxlint | skipped | 0 | 0.0s | _skipped: no_matching_files_ |
| ruff | pass | 59 | 0.0s |  |
| actionlint | pass | 0 | 0.0s |  |
| jscpd | pass | 0 | 0.0s |  |
| typos | pass | 1 | 0.0s |  |
| _file_inventory | pass | 0 | 0.0s |  |

## Medium Findings (61)

### [MEDIUM] \`datetime.timezone\` imported but unused

- **File:** `tests/test_trust_broker.py:5`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `datetime.timezone` imported but unused

**How to fix:** Auto-fix available: Remove unused import (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`datetime.datetime\` imported but unused

- **File:** `tests/test_trust_broker.py:5`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `datetime.datetime` imported but unused

**How to fix:** Auto-fix available: Remove unused import (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`json\` imported but unused

- **File:** `tests/test_trust_broker.py:2`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `json` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `json` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`pathlib.Path\` imported but unused

- **File:** `tests/test_policy_engine.py:4`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `pathlib.Path` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `pathlib.Path` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`os\` imported but unused

- **File:** `tests/test_policy_engine.py:3`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `os` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `os` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`json\` imported but unused

- **File:** `tests/test_policy_engine.py:2`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `json` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `json` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`unittest.mock.patch\` imported but unused

- **File:** `tests/test_memory_integrity.py:4`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `unittest.mock.patch` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `unittest.mock.patch` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`pathlib.Path\` imported but unused

- **File:** `tests/test_memory_governor.py:3`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `pathlib.Path` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `pathlib.Path` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`os\` imported but unused

- **File:** `tests/test_memory_governor.py:2`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `os` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `os` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`governance.lib.manifest.DEFAULT_RESTRICTIVE_MANIFEST\` imported but unused

- **File:** `tests/test_manifest.py:87`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `governance.lib.manifest.DEFAULT_RESTRICTIVE_MANIFEST` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `governance.lib.manifest.DEFAULT_RESTRICTIVE_MANIFEST` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`governance.lib.manifest.load_static_manifest\` imported but unused

- **File:** `tests/test_manifest.py:74`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `governance.lib.manifest.load_static_manifest` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `governance.lib.manifest.load_static_manifest` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`tempfile\` imported but unused

- **File:** `tests/test_manifest.py:4`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `tempfile` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `tempfile` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`json\` imported but unused

- **File:** `tests/test_manifest.py:2`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `json` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `json` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Local variable \`monitor\` is assigned to but never used

- **File:** `tests/test_integration_security.py:203`
- **Scanner:** ruff
- **Rule:** `RUFF-F841`

**What's wrong:** Local variable `monitor` is assigned to but never used

**How to fix:** Auto-fix available: Remove assignment to unused variable `monitor` (applicability: unsafe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`governance.lib.security.coordination_scorer.ToolCall\` imported but unused

- **File:** `tests/test_integration_security.py:14`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `governance.lib.security.coordination_scorer.ToolCall` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `governance.lib.security.coordination_scorer.ToolCall` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`unittest.mock.patch\` imported but unused

- **File:** `tests/test_integration_security.py:8`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `unittest.mock.patch` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `unittest.mock.patch` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`governance.lib.security.identity_lifecycle.SessionCredential\` imported but unused

- **File:** `tests/test_identity_lifecycle.py:9`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `governance.lib.security.identity_lifecycle.SessionCredential` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `governance.lib.security.identity_lifecycle.SessionCredential` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`unittest.mock.patch\` imported but unused

- **File:** `tests/test_identity_lifecycle.py:5`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `unittest.mock.patch` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `unittest.mock.patch` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`governance.lib.security.guardian_agent.GuardianDecision\` imported but unused

- **File:** `tests/test_guardian_agent.py:8`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `governance.lib.security.guardian_agent.GuardianDecision` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `governance.lib.security.guardian_agent.GuardianDecision` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`json\` imported but unused

- **File:** `tests/test_compliance_reporter.py:3`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `json` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `json` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`governance.lib.security.security_config.MetricConfig\` imported but unused

- **File:** `tests/test_behavioral_monitor.py:12`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `governance.lib.security.security_config.MetricConfig` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `governance.lib.security.security_config.MetricConfig` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`governance.lib.security.behavioral_monitor.BaselineData\` imported but unused

- **File:** `tests/test_behavioral_monitor.py:9`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `governance.lib.security.behavioral_monitor.BaselineData` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `governance.lib.security.behavioral_monitor.BaselineData` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`unittest.mock.patch\` imported but unused

- **File:** `tests/test_behavioral_monitor.py:5`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `unittest.mock.patch` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `unittest.mock.patch` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`math\` imported but unused

- **File:** `tests/test_behavioral_monitor.py:3`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `math` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `math` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`governance.lib.audit_bus.EventType\` imported but unused

- **File:** `tests/test_audit_bus.py:144`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `governance.lib.audit_bus.EventType` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `governance.lib.audit_bus.EventType` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Local variable \`bus\` is assigned to but never used

- **File:** `tests/test_audit_bus.py:41`
- **Scanner:** ruff
- **Rule:** `RUFF-F841`

**What's wrong:** Local variable `bus` is assigned to but never used

**How to fix:** Auto-fix available: Remove assignment to unused variable `bus` (applicability: unsafe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Local variable \`bus\` is assigned to but never used

- **File:** `tests/test_audit_bus.py:34`
- **Scanner:** ruff
- **Rule:** `RUFF-F841`

**What's wrong:** Local variable `bus` is assigned to but never used

**How to fix:** Auto-fix available: Remove assignment to unused variable `bus` (applicability: unsafe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`tempfile\` imported but unused

- **File:** `tests/test_audit_bus.py:4`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `tempfile` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `tempfile` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`os\` imported but unused

- **File:** `tests/test_audit_bus.py:3`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `os` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `os` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Undefined name \`BPM_ENV_FILE\`

- **File:** `scripts/create_security_collections.py:52`
- **Scanner:** ruff
- **Rule:** `RUFF-F821`

**What's wrong:** Undefined name `BPM_ENV_FILE`

**How to fix:** See: https://docs.astral.sh/ruff/rules/undefined-name

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`json\` imported but unused

- **File:** `hooks/session_start.py:8`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `json` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `json` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Local variable \`e\` is assigned to but never used

- **File:** `hooks/pre_tool_check.py:129`
- **Scanner:** ruff
- **Rule:** `RUFF-F841`

**What's wrong:** Local variable `e` is assigned to but never used

**How to fix:** Auto-fix available: Remove assignment to unused variable `e` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`governance.lib.manifest.DEFAULT_RESTRICTIVE_MANIFEST\` imported but unused

- **File:** `hooks/pre_tool_check.py:33`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `governance.lib.manifest.DEFAULT_RESTRICTIVE_MANIFEST` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `governance.lib.manifest.DEFAULT_RESTRICTIVE_MANIFEST` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] f-string without any placeholders

- **File:** `hooks/post_tool_security.py:251`
- **Scanner:** ruff
- **Rule:** `RUFF-F541`

**What's wrong:** f-string without any placeholders

**How to fix:** Auto-fix available: Remove extraneous `f` prefix (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] f-string without any placeholders

- **File:** `hooks/post_tool_security.py:250`
- **Scanner:** ruff
- **Rule:** `RUFF-F541`

**What's wrong:** f-string without any placeholders

**How to fix:** Auto-fix available: Remove extraneous `f` prefix (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Local variable \`timezone\` referenced before assignment

- **File:** `hooks/memory_integrity_hook.py:139`
- **Scanner:** ruff
- **Rule:** `RUFF-F823`

**What's wrong:** Local variable `timezone` referenced before assignment

**How to fix:** See: https://docs.astral.sh/ruff/rules/undefined-local

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Local variable \`datetime\` referenced before assignment

- **File:** `hooks/memory_integrity_hook.py:139`
- **Scanner:** ruff
- **Rule:** `RUFF-F823`

**What's wrong:** Local variable `datetime` referenced before assignment

**How to fix:** See: https://docs.astral.sh/ruff/rules/undefined-local

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`os\` imported but unused

- **File:** `governance/lib/security/threat_detection.py:9`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `os` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `os` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Module level import not at top of file

- **File:** `governance/lib/security/qdrant_client.py:21`
- **Scanner:** ruff
- **Rule:** `RUFF-E402`

**What's wrong:** Module level import not at top of file

**How to fix:** See: https://docs.astral.sh/ruff/rules/module-import-not-at-top-of-file

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`qdrant_client.http.exceptions.UnexpectedResponse\` imported but unused

- **File:** `governance/lib/security/qdrant_client.py:20`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `qdrant_client.http.exceptions.UnexpectedResponse` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `qdrant_client.http.exceptions.UnexpectedResponse` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Module level import not at top of file

- **File:** `governance/lib/security/qdrant_client.py:20`
- **Scanner:** ruff
- **Rule:** `RUFF-E402`

**What's wrong:** Module level import not at top of file

**How to fix:** See: https://docs.astral.sh/ruff/rules/module-import-not-at-top-of-file

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Module level import not at top of file

- **File:** `governance/lib/security/qdrant_client.py:19`
- **Scanner:** ruff
- **Rule:** `RUFF-E402`

**What's wrong:** Module level import not at top of file

**How to fix:** See: https://docs.astral.sh/ruff/rules/module-import-not-at-top-of-file

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`numpy\` imported but unused

- **File:** `governance/lib/security/memory_integrity.py:18`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `numpy` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `numpy` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`os\` imported but unused

- **File:** `governance/lib/security/memory_integrity.py:11`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `os` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `os` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`json\` imported but unused

- **File:** `governance/lib/security/memory_integrity.py:9`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `json` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `json` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`hashlib\` imported but unused

- **File:** `governance/lib/security/memory_integrity.py:8`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `hashlib` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `hashlib` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] Local variable \`severity\` is assigned to but never used

- **File:** `governance/lib/security/guardian_agent.py:101`
- **Scanner:** ruff
- **Rule:** `RUFF-F841`

**What's wrong:** Local variable `severity` is assigned to but never used

**How to fix:** Auto-fix available: Remove assignment to unused variable `severity` (applicability: unsafe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`dataclasses.field\` imported but unused

- **File:** `governance/lib/security/guardian_agent.py:13`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `dataclasses.field` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `dataclasses.field` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`collections.defaultdict\` imported but unused

- **File:** `governance/lib/security/guardian_agent.py:12`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `collections.defaultdict` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `collections.defaultdict` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`fastapi.Response\` imported but unused

- **File:** `governance/lib/security/dashboard_api.py:19`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `fastapi.Response` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `fastapi.Response` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

> ... and 11 more medium findings

## Low Findings (8)

- **SBOM-LICENSE-UNKNOWN**: Unknown License: setuptools@83.0.0 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: pyyaml@6.0.2 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: ossf/scorecard-action@v2.4.0 (`/.github/workflows/scorecard.yml`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: github/codeql-action/upload-sarif@4187e74d05793876e9989daffde9c3e66b4acd07 (`/.github/workflows/scorecard.yml`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 (`/.github/workflows/ci.yml`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 (`/.github/workflows/scorecard.yml`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 (`/.github/workflows/ci.yml`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in  (`LICENSE`)

## Skipped Scanners (1)

Scanners that did not run on this scan, with the reason why and how to enable them.

| Scanner | Reason | How to enable |
|---------|--------|---------------|
| `oxlint` | no_matching_files | No .js/.ts files found — Oxlint requires a JavaScript/TypeScript project |

## Recommendations

1. Update 1 vulnerable dependency/dependencies -- run `npm audit fix` or equivalent

---
*Generated by Code Hardener v0.1.0 | 2026-07-24T20:29:56.068Z*