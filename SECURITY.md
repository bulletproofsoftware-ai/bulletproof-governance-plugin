# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in `bulletproof-governance-plugin`,
please report it responsibly:

- Open a [private security advisory](https://github.com/bulletproofsoftware-ai/bulletproof-governance-plugin/security/advisories/new)
  on GitHub (preferred), or
- Open a regular issue **only** if the vulnerability is already public.

Please include:

- a description of the vulnerability and its impact,
- the affected component (e.g. audit bus, policy engine, memory governor, a hook,
  a runtime-security module),
- steps to reproduce, and
- any suggested remediation.

We aim to acknowledge reports within a few business days and to provide a
remediation timeline after triage.

## Supported versions

This project is at an early (`0.1.x`) stage. Security fixes are applied to the
`main` branch. Pin to a commit SHA if you need a stable reference.

## Scope

In scope:

- The governance enforcement logic (manifest resolution, trust brokering, policy
  evaluation, memory-write classification).
- The append-only audit store and its access controls.
- The hooks that run inside the Claude Code host process.
- The read-only HITL API and the optional security dashboard API.

Out of scope:

- Vulnerabilities in third-party dependencies (report those upstream; we track
  them via Dependabot and address them by version bump).
- The security of the separate Qdrant / Ollama backends you deploy.

## Dependency hygiene

Dependencies are monitored weekly via `.github/dependabot.yml`. Known-vulnerable
dependencies are remediated by bumping to the first patched version.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
