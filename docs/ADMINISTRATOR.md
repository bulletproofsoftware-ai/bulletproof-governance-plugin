# Administrator Guide — bulletproof-governance-plugin

Operational reference for running and tuning the governance plugin: the audit
store, the configuration YAMLs, the HITL observability API, and the
runtime-security backends.

## Runtime state (`state/`)

The following files are written at runtime and are **gitignored** — they are
per-environment and must not be committed:

| Path | Contents |
|------|----------|
| `state/audit.db` (+ `-wal`, `-shm`) | SQLite append-only audit event store (WAL mode). File mode forced to `0600`. |
| `state/audit-buffer.json` | Buffer fallback for audit events when the DB is momentarily unavailable; replayed on recovery. |
| `state/active-manifests.json` (+ `.lock`) | Session-scoped manifest registry (TTL 3600 s), file-locked. |
| `state/session-state.json` | Current `audit_session_id`, conductor manifest hash, and any pending human gate. |
| `state/manifests/` | Per-agent static manifests. Example manifests exist on disk but are gitignored; supply your own for your agents. |
| `state/audit.token` | 64-hex audit service token (`0600`), generated on first init. |

The tracked configuration files under `state/` (below) *are* committed.

## Audit bus

- **Append-only.** Only `INSERT OR IGNORE` — no `UPDATE`/`DELETE` from the
  module. Combined with `0600` file mode this satisfies "inaccessible to NHI
  agents" for the write path.
- **Service-token write gate.** Set `GOVERNANCE_AUDIT_REQUIRE_TOKEN=1` (or
  `true`/`yes`/`on`) to enforce that only callers holding the token in
  `state/audit.token` may write. When unset, enforcement is *advisory* (writes
  proceed, bypass attempts are logged) for backwards compatibility.
- **Read access** does not require the token (auditors/dashboards must be able to
  query) but is intended to be further restricted at the OS level by running the
  plugin under a dedicated `gov-audit` user.
- **Event types** are enumerated in `governance/lib/audit_bus.py` (`EventType`),
  including `human_gate`, `human_gate_response`, `policy_deny`, `trust_deny`,
  `delegation_event`, `memory_write`, `circuit_break`, and the `security.*`
  family emitted by the runtime-security modules.

## Configuration YAMLs (tracked, editable)

### `state/tool-tiers.yaml`
Maps tools to `exempt` / `standard` / `elevated` tiers, plus
`elevated_patterns` (fnmatch). Unknown tools default to `elevated`. Edit to add
your own MCP tools or adjust tiers.

### `state/host-allowlist.yaml`
Approved outbound hosts. Calls to hosts *not* listed here can trigger
exfiltration detection in the security layer. **Ships with example entries
(`example.com`, `bulletproofsoftware.ai`, common package registries and public
threat-intel feeds) — replace the examples with your own domains.**

### `state/classification-patterns.yaml`
Regexes that map memory-write content to `internal` / `confidential` /
`restricted` (highest match wins; anything unmatched is `public`). Covers secret
shapes (API keys, private keys, bearer/JWT tokens, cloud access-key IDs), PII
(SSN), CVEs, and internal host/IP patterns.

### `state/security-config.yaml`
Thresholds for the runtime-security layer — all operator-configurable without
code changes (edit YAML and restart):

- `behavioral_monitor.metrics` — per-metric `min_sessions`, `threshold_sigma`,
  KL-divergence / rate-spike thresholds, and per-`agent_class` overrides
  (`read_only`, `write_authorized`, `external_facing`).
- `guardian` — `autonomy_level` (`ADVISORY` / `SEMI_AUTONOMOUS` /
  `FULLY_AUTONOMOUS`), notification webhook, and configuration-change guards.
- Global thresholds — `memory_anomaly_threshold` (4.5),
  `injection_similarity_threshold` (0.85), `semantic_consistency_threshold`
  (0.35), `forensic_retention_days` (90), plus `ollama_url`, `ollama_model`,
  `qdrant_url`, and `dashboard_port`.

## HITL observability API

`governance/lib/hitl_api.py` is a **read-only** HTTP surface over the
approval-gate audit trail. It has **no approve/deny endpoint by design** — the
gate has no external control point (the approval is Claude Code's in-session
prompt), so a write-back endpoint would be a fake control.

Run it:

```bash
GOVERNANCE_HITL_TOKEN=<shared-token> scripts/run-hitl-api.sh
```

Endpoints (all require `Authorization: Bearer $GOVERNANCE_HITL_TOKEN`):

| Endpoint | Returns |
|----------|---------|
| `GET /hitl/health` | `{status, db_path, gate_count, pending_count}` |
| `GET /hitl/gates?limit=N` | Recent gates paired with their response + latency. |
| `GET /hitl/pending` | Gates with no recorded response (unresolved). |

Configuration (env): `GOVERNANCE_HITL_TOKEN` (**required** — fails closed with
401 on every request when unset), `GOVERNANCE_HITL_PORT` (default 8126),
`GOVERNANCE_HITL_HOST` (default `127.0.0.1`; set `0.0.0.0` to expose to a
container — the bearer token is the access control), `GOVERNANCE_AUDIT_DB`
(default `state/audit.db`). The DB is opened strictly read-only (`mode=ro`).

## Security Qdrant collections

`scripts/create_security_collections.py` provisions the nine collections the
security layer uses (768-dim vectors, cosine distance) against Qdrant
(default `http://localhost:6334`), reading `QDRANT_API_KEY` from the environment
or your `BPM_ENV_FILE`:

`agent_behavioral_baselines`, `agent_identity_sessions`, `memory_quarantine`,
`memory_rejected`, `knowledge_anchors`, `injection_signatures`,
`coordination_scores`, `guardian_audit_log`, `forensic_events`.

## Optional security dashboard

`governance/lib/security/dashboard_api.py` is a JWT-authenticated FastAPI service
(default port 8101) exposing sessions, threats, quarantine, Guardian actions,
CSS/TUE scores, identities, forensic replay, and compliance reports. It requires
`fastapi` and `PyJWT`, which are **not** in the core `requirements.txt`; install
them separately if you run the dashboard.

## Failure modes

| Hook | On error |
|------|----------|
| `session_start.py` | Never blocks session start. |
| `pre_tool_security.py` | Fail **closed** on unknown errors; fail **open** on missing deps or infra-class errors (DB/network/FS) so a package or backend outage does not brick every tool call. |
| `memory_integrity_hook.py` | Fail **closed** (blocks the memory write). |
| `pre_tool_check.py` | Fail **open**. A `human_gate` verdict degrades to *allow* because there is no reachable external approval channel (the event is still audited). |
| `post_tool_*` / cleanup | Fail **open** / non-blocking. |

## Testing

```bash
python -m pytest tests/
```

17 test modules cover the manifest resolver, trust broker, policy engine, memory
governor, audit bus, HITL API, singletons, integration security, and each
runtime-security module.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
