#!/usr/bin/env bash
#
# Launch the thin read-only HITL audit API (governance/lib/hitl_api.py).
#
# Exposes the approval-gate audit trail (human_gate / human_gate_response in
# state/audit.db) read-only over HTTP so an external console (e.g. AgentHR) can
# DISPLAY it. There is no write-back/approve endpoint by design — the gate has
# no external control point (see the module docstring).
#
# Required:
#   GOVERNANCE_HITL_TOKEN   shared bearer token (fail-closed: unset => 401 on all)
#
# Optional:
#   GOVERNANCE_HITL_PORT    listen port (default 8126)
#   GOVERNANCE_HITL_HOST    bind host. Default 127.0.0.1 (host-only). To let a
#                           Docker container reach it via localhost,
#                           set 0.0.0.0 — the bearer token is the access control.
#   GOVERNANCE_AUDIT_DB     audit.db path (default <plugin>/state/audit.db)
#
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${GOVERNANCE_HITL_TOKEN:-}" ]]; then
  echo "WARNING: GOVERNANCE_HITL_TOKEN is unset — the API will reject every request." >&2
fi

PY="./venv/bin/python"
[[ -x "$PY" ]] || PY="python3"

exec "$PY" -m governance.lib.hitl_api
