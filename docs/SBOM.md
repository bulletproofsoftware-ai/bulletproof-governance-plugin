# SBOM — bulletproof-governance-plugin

Software Bill of Materials for the `governance` package. This is a pure-Python
project; there is no compiled or vendored code. The direct dependencies are
declared in `pyproject.toml` (core) and `requirements.txt` (core +
runtime-security).

A machine-readable CycloneDX 1.5 document is committed alongside this file:
[`governance.cyclonedx.json`](governance.cyclonedx.json). It was hand-authored
from the dependency manifests because no CycloneDX generator was available for
this project; it lists direct dependencies only.

## Direct dependencies

| Component | Version | Scope | License | Declared in | Notes |
|-----------|---------|-------|---------|-------------|-------|
| `pyyaml` | 6.0.2 | required | MIT | `pyproject.toml` (`>=6.0`), `requirements.txt` (`==6.0.2`) | YAML parsing for manifests and config. |
| `setuptools` | 83.0.0 | required (build) | MIT | `requirements.txt` (`==83.0.0`), `pyproject.toml` build-system (`>=68.0`) | Build backend. Bumped from 75.8.0 to remediate **CVE-2025-47273** (HIGH) and **CVE-2026-59890** (MODERATE). |
| `httpx` | >=0.28.0 | optional | BSD-3-Clause | `requirements.txt` | HTTP client used by the runtime-security modules (Ollama/embedding calls). |
| `numpy` | >=1.26.0 | optional | BSD-3-Clause | `requirements.txt` | Vector math for memory-integrity anomaly scoring. |
| `qdrant-client` | >=1.12.0 | optional | Apache-2.0 | `requirements.txt` | Client for the security Qdrant collections. |

### Component count

- **5** direct dependencies (2 required, 3 optional).

### License distribution (direct dependencies)

| License | Count | Components |
|---------|-------|-----------|
| MIT | 2 | `pyyaml`, `setuptools` |
| BSD-3-Clause | 2 | `httpx`, `numpy` |
| Apache-2.0 | 1 | `qdrant-client` |

All direct-dependency licenses are OSI-approved and compatible with this
project's Apache-2.0 license.

## Optional / not in `requirements.txt`

The optional security dashboard (`governance/lib/security/dashboard_api.py`)
additionally imports **`fastapi`** (MIT) and **`PyJWT`** (`jwt`, MIT). These are
*not* declared in the core `requirements.txt`; install them separately only if
you run the dashboard API.

## Transitive dependencies

Transitive dependencies are resolved by `pip` from the direct dependencies above
and are not pinned in this repository. Run `pip freeze` in your installed
environment for a fully resolved lock, or generate a complete CycloneDX SBOM
against your installed environment with a tool such as `cyclonedx-py`.

## Base images

This project ships **no Dockerfile** and no container image. It runs as a Python
package inside the Claude Code host process; there is no base image to report.

## Standard library

The core governance layer (audit bus, manifest resolver, trust broker, policy
engine, HITL API) relies heavily on the Python standard library only —
`sqlite3`, `hashlib`, `hmac`, `secrets`, `fcntl`, `http.server`, `json`,
`pathlib` — which is why the required third-party footprint is minimal.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
