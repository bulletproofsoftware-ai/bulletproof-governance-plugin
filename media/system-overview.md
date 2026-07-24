# bulletproof-governance-plugin

The `bulletproof-governance-plugin` is a comprehensive agent-governance framework designed specifically for Claude Code. It functions as a governance layer situated between the AI model and its tools, ensuring that every tool call and memory write undergoes rigorous identity, trust, policy, and integrity verification. By leveraging a hook-based architecture, the plugin enforces a uniform security posture across multi-agent workflows without requiring modifications to the underlying agent code.

## Executive Summary

As multi-agent workflows in Claude Code become increasingly complex—involving delegated tasks, shared memory access, and tool interactions with external services—the need for visibility and control becomes paramount. The `bulletproof-governance-plugin` addresses this by providing a consistent record of agent activities, enforcing behavioral ceilings for delegated agents, and implementing a classification gate for memory persistence.

The framework is built on a pure Python (>= 3.11) architecture with minimal core dependencies (`pyyaml`). It features an append-only, SQLite-backed audit bus for forensic transparency and a multi-tiered policy engine that manages tool permissions and network access. For organizations requiring advanced protection, the plugin includes optional runtime-security modules that utilize vector databases (Qdrant) for behavioral anomaly detection and threat monitoring.

## Detailed Analysis of Key Themes

### 1. Identity and Trust Brokerage
The foundation of the framework is the identity manifest system. Every agent is associated with a declared YAML manifest that defines its capabilities, permissions, and inheritance chains.
*   **Manifest Integrity:** The system computes SHA-256 hashes for tamper evidence and anchors human attribution onto every session.
*   **Delegation Management:** The Trust Broker mediates inter-agent delegation (via the `Task` tool) by evaluating "breadth" (maximum delegation counts), "depth" (autonomy budgets), and "trust escalation" (ensuring a target agent does not exceed the trust level of the source).

### 2. Multi-Tiered Policy Enforcement
The plugin classifies tools into three distinct tiers to determine the level of scrutiny required:
*   **Exempt:** Tools like `Read`, `Glob`, or `Grep` are allowed and audited asynchronously.
*   **Standard:** Subject to manifest permissions and tier-matrix checks (e.g., `Edit`, `Write`, `Bash`).
*   **Elevated:** Highest scrutiny (e.g., `memory_forget`). These often trigger mandatory human gates when a major conductor tier is active.

### 3. Memory Governance and Data Classification
The Memory Governor acts as a gatekeeper for the `mcp__claude-memory__memory_store` tool. It uses regex-based classification patterns to map content to specific sensitivity levels:
*   **Public/Internal:** Allowed and tagged with metadata.
*   **Confidential:** Placed in a "queue-and-proceed" state, requiring subsequent human review via `/governance-review`.
*   **Restricted:** Blocked from persistence until human approval is secured.
*   **Ceiling Enforcement:** Agents are strictly prohibited from writing content classified higher than their own assigned data classification level.

### 4. Runtime-Security and Behavioral Monitoring
For high-security environments, the plugin offers an optional suite of monitoring tools that integrate with Qdrant:
*   **Behavioral Monitor:** Uses Welford's online algorithm to track 8 metrics per agent, establishing baselines and triggering z-score anomaly detection after a 10-session training period.
*   **Threat Detection:** Includes five sub-detectors focused on prompt injection, privilege escalation, data exfiltration, tool abuse, and memory poisoning.
*   **Guardian Agent:** A self-protecting module with five response tiers: `LOG_ONLY`, `NOTIFY`, `THROTTLE`, `SUSPEND`, and `TERMINATE`.

## Operational Lifecycle and Hooks

The plugin integrates with Claude Code via three primary hook events defined in `hooks/hooks.json`.

| Hook Event | Executed Script | Logic and Failure Mode |
| :--- | :--- | :--- |
| **SessionStart** | `session_start.py` | Bootstraps audit bus and registers manifests; never blocks session start. |
| **PreToolUse** | `pre_tool_security.py` | Threat scan; **fails closed** on unknown errors. |
| | `memory_integrity_hook.py`| Integrity pipeline; **fails closed** on errors. |
| | `pre_tool_check.py` | Trust/Policy evaluation; **fails open** if approval channel is unreachable. |
| **PostToolUse** | `post_tool_metrics.py` | Records behavioral metrics; **fails open**. |
| | `post_tool_security.py` | Scans response for leakage/injection; **fails open**. |
| | `post_task_cleanup.py` | Deregisters agents after Task completion. |

## Configuration and Administration

### Core Configuration Files
The plugin's behavior is dictated by four primary YAML files located in the `state/` directory:
1.  **`tool-tiers.yaml`:** Maps tools to exempt, standard, or elevated tiers.
2.  **`host-allowlist.yaml`:** Defines approved outbound network domains.
3.  **`classification-patterns.yaml`:** Contains regexes for identifying secrets, PII, and internal data shapes.
4.  **`security-config.yaml`:** Sets thresholds for behavioral z-scores, autonomy levels, and retention periods.

### The HITL Observability API
The Human-in-the-Loop (HITL) API (`governance/lib/hitl_api.py`) provides a read-only surface for monitoring gate activity. 
*   **Design Philosophy:** It deliberately lacks an approve/deny endpoint. 
*   **Control Points:** Approvals are handled via Claude Code's native in-session prompts. The API exists solely for external observability, such as tracking gate latency and unresolved "pending" gates.
*   **Security:** Requires a 64-hex bearer token (`GOVERNANCE_HITL_TOKEN`) and defaults to localhost access.

## Key Insights and Important Quotes

### Security Philosophy
The plugin follows a "fail toward scrutiny" model for unknown entities while maintaining operational stability through selective "fail-open" logic for infrastructure.
*   **On Unknown Tools:** "Unknown tools default to elevated ('fail toward scrutiny')."
*   **On Infrastructure Failure:** The system is designed to "fail-open on missing deps or infra-class errors (DB/network/FS) so a package or backend outage does not brick every tool call."

### Data Integrity and Auditability
*   **Audit Bus:** The audit trail is "append-only. Only INSERT OR IGNORE—no UPDATE/DELETE from the module." This ensures that even "NHI [Non-Human Intelligence] agents" cannot modify the history of their actions.
*   **Access Control:** Read access to the audit store is restricted at the OS level by running under a dedicated `gov-audit` user with `0600` file permissions.

### Dependency Management
The framework maintains a minimal footprint to reduce the attack surface.
*   **Core Requirements:** "The core governance layer... relies heavily on the Python standard library only... which is why the required third-party footprint is minimal."
*   **Critical Vulnerability Mitigation:** The `SBOM` notes that `setuptools` was specifically updated to version `83.0.0` to remediate `CVE-2025-47273` (HIGH) and `CVE-2026-59890` (MODERATE).

## Actionable Insights

*   **Initial Setup Verification:** Upon installation, administrators must replace the example entries in `state/host-allowlist.yaml` with organization-specific domains to prevent false-positive exfiltration alerts.
*   **Security Provisioning:** If using the runtime-security modules, run `scripts/create_security_collections.py` to initialize the nine required Qdrant collections (e.g., `agent_behavioral_baselines`, `memory_quarantine`).
*   **Memory Management:** Use the `/governance-review` slash command regularly to process "confidential" memory writes that are queued for review; otherwise, they remain in a `pending_review` status.
*   **Environment Hardening:** To enforce strict audit security, set `GOVERNANCE_AUDIT_REQUIRE_TOKEN=1`. This ensures that only callers holding the generated service token in `state/audit.token` can write to the audit log.
*   **Monitoring Health:** Use `/governance-status` to monitor the `audit-buffer.json`. A growing buffer backlog indicates the SQLite database is momentarily unavailable or locked.