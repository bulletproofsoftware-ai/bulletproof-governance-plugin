# Overview — bulletproof-governance-plugin

`bulletproof-governance-plugin` is an **agent-governance framework for Claude Code**.
It installs as a Claude Code plugin and inserts a governance layer between the model
and its tools: every tool call and every memory write passes through identity,
trust, policy, and integrity checks, and every governance-relevant decision is
written to an append-only audit log.

The framework is pure Python (>= 3.11), depends only on `pyyaml` at its core
(with `httpx`, `numpy`, and `qdrant-client` for the runtime-security modules),
and self-registers its hooks through `hooks/hooks.json`.

## The problem it addresses

Multi-agent Claude Code workflows delegate work to sub-agents, write to shared
memory, and call tools that can touch the filesystem, the network, and external
services. Without a governance layer there is no consistent record of *which*
agent did *what*, no enforced ceiling on what a delegated agent may do, and no
classification gate on what gets persisted to memory. This plugin adds those
controls as hooks so they apply uniformly, without changing agent code.

## Core components

All core objects share a single `AuditBus` instance and are lazily initialized
by `governance/lib/singletons.py`.

| Component | Module | Responsibility |
|-----------|--------|----------------|
| **Identity manifests** | `governance/lib/manifest.py` | Load static YAML manifests, resolve inheritance chains, enforce the parent ceiling, derive restrictive child manifests, compute SHA-256 tamper-evidence hashes. Also anchors human attribution and MFA attestation onto a session. |
| **Trust broker** | `governance/lib/trust_broker.py` | Mediate inter-agent delegation: breadth limits, autonomy-depth budget, classification boundaries, trust-escalation checks, permitted targets. Issues delegation tokens. Includes a session-scoped, TTL-purged `ManifestRegistry`. |
| **Audit bus** | `governance/lib/audit_bus.py` | SQLite-backed, append-only (`INSERT OR IGNORE`) event store in WAL mode. Bounded async queue plus a JSON buffer fallback. File mode forced to `0600`; optional service-token write gate. |
| **Policy engine** | `governance/lib/policy_engine.py` | Classify tools into `exempt`/`standard`/`elevated` tiers, check the calling manifest's `permitted_tools`, and apply the conductor tier matrix to produce `allow` / `deny` / `human_gate` decisions. |
| **Memory governor** | `governance/lib/memory_governor.py` | Classify memory-write content (`public`/`internal`/`confidential`/`restricted`), enforce the agent's classification ceiling, tag provenance, block restricted writes, and queue confidential writes for review. |

## Runtime-security modules (`governance/lib/security/`)

An optional layer (requires `httpx`, `numpy`, `qdrant-client`) that adds
behavioral and threat monitoring. Each is lazily initialized via `singletons.py`
and degrades to fail-open if its dependencies or backends are unavailable.

| Module | Purpose |
|--------|---------|
| `behavioral_monitor.py` | 8-metric per-agent baselines (Welford's online algorithm) with z-score anomaly detection; minimum 10 sessions before activation. |
| `identity_lifecycle.py` | 6-state identity machine (PROVISION → AUTHENTICATE → AUTHORIZE → MONITOR → SUSPEND → REVOKE) with ephemeral per-session credentials and rotation. |
| `memory_integrity.py` | 4-stage pipeline (provenance → semantic consistency → fact verification → anomaly scoring) with a quarantine workflow; wraps the memory governor. |
| `threat_detection.py` | 5 sub-detectors: prompt injection, privilege escalation, data exfiltration, tool abuse, memory poisoning. Critical threats block execution. |
| `coordination_scorer.py` | Inter-agent Component Synergy Score (CSS) and Tool Utilization Efficacy (TUE) over rolling windows. |
| `guardian_agent.py` | 3 autonomy levels and a 5-tier decision matrix (LOG_ONLY → NOTIFY → THROTTLE → SUSPEND → TERMINATE); self-protection prevents self-termination. |
| `forensic_replay.py` | Session-timeline reconstruction from Qdrant `forensic_events` and SQLite `audit_events` (90-day retention). |
| `compliance_reporter.py` | SOC 2 Type II control evidence packages and state DOI disclosure reports (JSON/PDF). |
| `dashboard_api.py` | Optional FastAPI monitoring API (requires `fastapi` + `PyJWT`, not in the core `requirements.txt`). |
| `qdrant_client.py` | Shared wrapper for the 9 security Qdrant collections. |
| `security_config.py` | Loads `state/security-config.yaml`; all thresholds are operator-configurable without code changes. |

## Hooks

Registered by `hooks/hooks.json`:

- **SessionStart** → `session_start.py` — bootstraps the audit bus, registers the
  conductor manifest, validates static manifests, writes session state.
- **PreToolUse** → `pre_tool_security.py` (fail-closed threat scan),
  `memory_integrity_hook.py` (matcher: `memory_store`, fail-closed),
  `pre_tool_check.py` (trust + policy evaluation, fail-open).
- **PostToolUse** → `post_tool_metrics.py` (behavioral metrics, fail-open),
  `post_tool_security.py` (outbound response scanning, fail-open),
  `post_task_cleanup.py` (matcher: `Task`, deregisters the completed agent).

## Commands

- `/governance-status` — read-only health and session status.
- `/governance-audit` — forensic query and JSONL export of audit events.
- `/governance-review` — review confidential memory writes awaiting approval.

## What is NOT included

- **No external approval control point.** The HITL API (`governance/lib/hitl_api.py`)
  is deliberately **read-only** — it exposes gate observability, not an
  approve/deny endpoint. Approvals are Claude Code's own in-session permission
  prompts; the audit trail records responses post-hoc for latency metrics.
- **No bundled Qdrant/Ollama.** The security modules connect to a Qdrant
  instance (default `localhost:6334`) and, where used, Ollama
  (`localhost:11434`) that you run separately.
- **Per-agent runtime manifests are gitignored** (`state/manifests/`) — they are
  environment-specific and are written at runtime; they are not published in this
  repo. Only the shared configuration YAMLs under `state/` are tracked.

## See also

- [INSTALL.md](INSTALL.md) — installation and configuration
- [HOW-TO-USE.md](HOW-TO-USE.md) — day-to-day usage and commands
- [ADMINISTRATOR.md](ADMINISTRATOR.md) — operations, config, and the HITL API
- [SBOM.md](SBOM.md) — software bill of materials
- [scan/scan-report.md](scan/scan-report.md) — security scan results

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
