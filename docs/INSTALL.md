# Install — bulletproof-governance-plugin

`bulletproof-governance-plugin` is a Claude Code plugin plus a small Python
package (`governance`). This guide covers installing the plugin, installing the
Python package, and configuring the environment.

## Requirements

- **Python** >= 3.11 (the hooks import the `governance` package).
- **Claude Code** with plugin support (the hooks self-register via
  `hooks/hooks.json`).
- Core Python dependency: `pyyaml`.
- Runtime-security modules additionally require: `httpx`, `numpy`,
  `qdrant-client`, and (for a reachable backend) a **Qdrant** instance. The
  optional dashboard API also needs `fastapi` and `PyJWT`.

## 1. Install the Python package

```bash
git clone https://github.com/bulletproofsoftware-ai/bulletproof-governance-plugin.git
cd bulletproof-governance-plugin
pip install -e .
```

`pip install -e .` installs the core (`pyyaml`) dependency declared in
`pyproject.toml`. To pull in the runtime-security dependencies as well:

```bash
pip install -r requirements.txt
```

`requirements.txt` pins `pyyaml`, `setuptools`, `httpx`, `numpy`, and
`qdrant-client`.

## 2. Register the plugin with Claude Code

Point your Claude Code plugin configuration at this repository, or clone it into
your plugins directory. The hooks self-register through `hooks/hooks.json` for
three events:

- `SessionStart`
- `PreToolUse`
- `PostToolUse`

The plugin metadata lives in `.claude-plugin/plugin.json` and
`.claude-plugin/marketplace.json`.

## 3. Configure the environment

The hook commands and modules read the following environment variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `GOVERNANCE_PLUGIN_ROOT` | Root of the plugin on disk. Set this if the plugin is not at the default location. | `~/.claude/plugins/local/governance-plugin` |
| `CLAUDE_PLUGIN_ROOT` | Used by the hook scripts to bootstrap the import path. | Parent of the `hooks/` directory. |
| `GOVERNANCE_MANIFESTS_DIR` | Directory holding static agent manifests. | `<plugin_root>/state/manifests` |
| `BPM_ENV_FILE` | Env file the hooks source for `QDRANT_API_KEY` (for the security Qdrant collections). | `~/.bulletproof-memory/.env` |
| `CONDUCTOR_STATE_PATH` | Path to `conductor-state.json`, read to determine the current conductor tier. | `conductor-state.json` |
| `GOVERNANCE_AUDIT_REQUIRE_TOKEN` | When truthy (`1`/`true`/`yes`/`on`), enforce the audit service-token write gate. Advisory by default. | unset (advisory) |

> The hook definitions in `hooks/hooks.json` invoke Python via
> `${GOVERNANCE_PYTHON:-python3}` — by default the `python3` on your `PATH`.
> To use a dedicated interpreter (e.g. a virtualenv), set `GOVERNANCE_PYTHON`
> to its absolute path. Whatever interpreter resolves must be Python 3.11+
> with the plugin's requirements installed.

## 4. (Optional) Provision the security Qdrant collections

The runtime-security modules use nine Qdrant collections. Provision them with:

```bash
python scripts/create_security_collections.py
```

This connects to Qdrant (default `http://localhost:6334`) using `QDRANT_API_KEY`
from your environment or env file, and creates any missing collections
(768-dimension vectors, cosine distance):

`agent_behavioral_baselines`, `agent_identity_sessions`, `memory_quarantine`,
`memory_rejected`, `knowledge_anchors`, `injection_signatures`,
`coordination_scores`, `guardian_audit_log`, `forensic_events`.

If you do not run the security modules, this step is not required — the
security hooks fail open (skip) when their dependencies or backend are absent.

## 5. Configure policy inputs

Edit the tracked configuration YAMLs under `state/`:

- **`state/tool-tiers.yaml`** — which tools are `exempt` / `standard` /
  `elevated` (plus `elevated_patterns`).
- **`state/host-allowlist.yaml`** — approved outbound hosts. **Ships with
  example entries; replace with your own.**
- **`state/classification-patterns.yaml`** — content-classification regexes.
- **`state/security-config.yaml`** — behavioral-monitor and Guardian thresholds.

See [ADMINISTRATOR.md](ADMINISTRATOR.md) for details on each file.

## 6. Verify

```bash
python -m pytest tests/
```

The repository ships 17 test modules covering the manifest resolver, trust
broker, policy engine, memory governor, audit bus, HITL API, and each security
module.

## Uninstall

Remove the plugin from your Claude Code plugin configuration and
`pip uninstall governance`. Runtime state lives under `state/` (audit DB,
session state, active manifests) and is gitignored; delete it to reset.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
