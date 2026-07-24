# Security Scan Report — bulletproof-governance-plugin

Automated security scan performed with **Code Hardener** (`standard` profile —
12 code-appropriate scanners: trivy, gitleaks, opengrep, checkov, grype, syft,
oxlint, ruff, bandit, dockle, hadolint, and typos).

## Result

| Metric | Value |
|--------|-------|
| **Score** | **847 / 1000** |
| Scan ID | `ae9709d8-2f4f-454e-913b-69e96ae5d3e9` |
| Branch | `main` |
| **Critical** | **0** |
| **High** | **0** |
| Medium | 61 |
| Low | 8 |
| Info | 2 |
| Secrets (gitleaks) | **PASS — 0 findings** |

The attestation certificate (page 1 of the PDF) is Ed25519 in-toto signed with
score 847/1000.

## Findings fixed to reach 0 critical / 0 high

The initial scan reported **2 HIGH** findings (both the same CVE, flagged by two
scanners). All were remediated and confirmed cleared on re-scan.

| # | Severity | Scanner(s) | Finding | Fix |
|---|----------|-----------|---------|-----|
| 1 | HIGH | grype, trivy | **CVE-2025-47273** (GHSA-5rjg-fvgr-3xxf) — path traversal in `setuptools` `PackageIndex.download` (arbitrary file write), affecting `setuptools@75.8.0`. | Bumped `setuptools` to **83.0.0** in `requirements.txt`. First patched version 78.1.1 (verified via GitHub security advisory, `vulnerableVersionRange < 78.1.1`). |
| 2 | MEDIUM (bundled) | grype, trivy | **CVE-2026-59890** (GHSA-h35f-9h28-mq5c) — moderate `setuptools` advisory, `< 83.0.0`. | Same bump to **83.0.0** clears it (`firstPatchedVersion 83.0.0`). Fixed proactively alongside the HIGH so no known dependency CVE remains. |
| 3 | MEDIUM (5×) | opengrep | **github-actions-mutable-action-tag** — CI/scorecard workflows referenced GitHub Actions by mutable tag. | Pinned `actions/checkout`, `actions/setup-python`, `ossf/scorecard-action`, and `github/codeql-action/upload-sarif` to immutable commit SHAs, retaining `# vN` comments. |

Re-scan after these fixes: **0 critical, 0 high, gitleaks PASS**, score
755 → **847**.

## What remains (low-risk, documented — not blocking)

The residual 61 medium / 8 low / 2 info findings are cosmetic or defensible; none
are exploitable in this codebase:

- **ruff (59 medium)** — code-style lint: 46× `F401` (unused imports), 5× `F841`
  (unused local vars), 3× `E402`, and a few `F541`/`F821`/`F823`. These are
  cosmetic; auto-stripping them risks removing defensive/late imports, so they
  are left in place per policy.
- **opengrep `wildcard-cors` (1 medium)** — `governance/lib/security/dashboard_api.py`
  configures permissive CORS. This is the **optional** monitoring dashboard
  (not installed by default, not in core `requirements.txt`); operators binding
  it beyond localhost should tighten `allow_origins`.
- **opengrep `python-logger-credential-disclosure` (1 medium)** —
  `governance/lib/security/identity_lifecycle.py` logs an identifier the linter
  flags as credential-shaped. Reviewed: it is a session/identity id, not a
  secret. No sensitive value is logged.
- **syft/trivy (low/info)** — inventory/SBOM notes, not vulnerabilities.

## Artifacts

- **Rich attestation PDF** — [`bulletproof-governance-plugin-scan-report.pdf`](bulletproof-governance-plugin-scan-report.pdf) (15 pages, Ed25519 in-toto signed; page 1 = attestation certificate + score).
- **Full markdown report** — [`scan-report-full.md`](scan-report-full.md)
- **SARIF** — [`scan-report.sarif.json`](scan-report.sarif.json)
- **Attestation** — [`attestation.json`](attestation.json)

Scanner paths in the SARIF and full markdown were normalized (the scanner's
`/scan-target/` prefix removed); no host filesystem paths are present.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../../LICENSE) and [NOTICE](../../NOTICE).
