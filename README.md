# bulletproof-governance-plugin

**An agent-governance framework for Claude Code: identity, trust, audit, policy, and memory governance.**

`bulletproof-governance-plugin` adds a governance layer to Claude Code — agent identity
manifests, a trust broker, an append-only audit bus, a policy engine, and a memory
governor that classifies and guards what gets written to memory. It installs as a
Claude Code plugin with pre/post-tool hooks.

## What it does

- **Identity manifests** — every agent has a declared manifest (generated under `state/` at runtime)
  defining its capabilities and permissions.
- **Trust broker** — validates agent identity and brokers cross-agent trust.
- **Audit bus** — append-only audit log of governance-relevant events.
- **Policy engine** — evaluates tool calls against policy (host allowlists, data
  classification, approval gates).
- **Memory governor** — classifies content (public/internal/…) and enforces rules
  before memory writes.
- **HITL API** — a human-in-the-loop review surface for gated actions.

## Install (as a Claude Code plugin)

Point your Claude Code plugin config at this repo, or clone it into your plugins
directory. The hooks self-register via `hooks/hooks.json`
(`SessionStart`, `PreToolUse`, `PostToolUse`).

Set `GOVERNANCE_PLUGIN_ROOT` if the plugin isn't at the default
`~/.claude/plugins/local/governance-plugin`, and `BPM_ENV_FILE` to point at an env
file holding `QDRANT_API_KEY` (the hooks read it for the security collections).

## Configuration

- **`state/host-allowlist.yaml`** — the network allowlist the policy engine enforces.
  Ships with example entries; **replace with your own** servers/domains.
- **`state/classification-patterns.yaml`** — data-classification patterns.
- Per-agent capability manifests are written under `state/` at runtime (gitignored).

## Security collections

`scripts/create_security_collections.py` provisions the Qdrant collections the
governance layer uses (reads `QDRANT_API_KEY` from your env / env file).

## Development

```bash
pip install -e .
python -m pytest tests/
```

## License

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
