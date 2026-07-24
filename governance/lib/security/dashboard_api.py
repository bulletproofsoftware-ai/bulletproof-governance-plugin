"""Security Dashboard API — FastAPI on port 8101 (REQ-073).

JWT-authenticated REST API for security monitoring. 30-second poll refresh.
Endpoints: sessions, threats, quarantine, Guardian actions, CSS/TUE, identities,
forensic replay, compliance reports.
"""

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from typing import Optional

import jwt
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger("governance.security.dashboard_api")

# ---------------------------------------------------------------------------
# JWT configuration
# ---------------------------------------------------------------------------
JWT_SECRET = os.environ.get("SECURITY_JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 1
JWT_ISSUER = "governance-security-dashboard"

security_scheme = HTTPBearer(auto_error=False)


def _validate_jwt(token: str) -> dict:
    """Validate JWT token. Returns payload or raises."""
    if not JWT_SECRET:
        # No secret configured — reject all tokens
        raise HTTPException(401, "JWT secret not configured")
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> dict:
    """Dependency: extract and validate JWT from Authorization header."""
    if not credentials:
        raise HTTPException(401, "Missing authorization token")
    return _validate_jwt(credentials.credentials)


def create_token(subject: str, scope: list[str] = None) -> str:
    """Generate a JWT token for dashboard access."""
    if not JWT_SECRET:
        raise ValueError("SECURITY_JWT_SECRET not set")
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iss": JWT_ISSUER,
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
        "scope": scope or ["security_dashboard"],
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
def create_app(qdrant=None, audit_bus=None, config=None) -> FastAPI:
    """Create the security dashboard FastAPI application."""
    app = FastAPI(
        title="Agent Runtime Security Dashboard",
        version="1.0.0",
        description="WI-11 security monitoring API",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Store dependencies on app state
    app.state.qdrant = qdrant
    app.state.audit_bus = audit_bus
    app.state.config = config

    # ------------------------------------------------------------------
    # Health check (no auth required)
    # ------------------------------------------------------------------
    @app.get("/api/security/health")
    async def health():
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",
        }

    # ------------------------------------------------------------------
    # Token generation (for initial setup)
    # ------------------------------------------------------------------
    @app.post("/api/security/token")
    async def generate_token(request: Request):
        """Generate JWT token. Requires SECURITY_JWT_SECRET to be set."""
        body = await request.json()
        subject = body.get("subject", "operator")
        try:
            token = create_token(subject)
            return {"token": token, "expires_in": JWT_EXPIRY_HOURS * 3600}
        except ValueError as e:
            raise HTTPException(500, str(e))

    # ------------------------------------------------------------------
    # Sessions (REQ-073)
    # ------------------------------------------------------------------
    @app.get("/api/security/sessions")
    async def list_sessions(user: dict = Depends(get_current_user)):
        """Active sessions with risk scores."""
        q = app.state.qdrant
        if not q:
            return []
        results = q.scroll_points(
            "agent_identity_sessions",
            limit=100,
        )
        sessions = []
        for r in results:
            p = r["payload"]
            if p.get("state") == "REVOKE":
                continue
            sessions.append({
                "session_id": p.get("session_id", ""),
                "agent_id": p.get("agent_id", ""),
                "state": p.get("state", ""),
                "issued_at": p.get("issued_at", ""),
                "expires_at": p.get("expires_at", ""),
                "throttle_rate": p.get("throttle_rate", 1.0),
                "scope_count": len(p.get("scope", [])),
            })
        return sessions

    @app.get("/api/security/sessions/{session_id}")
    async def get_session(session_id: str, user: dict = Depends(get_current_user)):
        """Single session detail."""
        q = app.state.qdrant
        if not q:
            raise HTTPException(404, "Session not found")
        data = q.get_identity_session(session_id)
        if not data:
            raise HTTPException(404, "Session not found")
        return data

    # ------------------------------------------------------------------
    # Threats (REQ-073)
    # ------------------------------------------------------------------
    @app.get("/api/security/threats")
    async def list_threats(
        limit: int = 50,
        user: dict = Depends(get_current_user),
    ):
        """Recent threat events (24h)."""
        bus = app.state.audit_bus
        if not bus:
            return []
        events = bus.query(
            {"event_type": "security.threat_detected"},
            limit=limit,
        )
        # Also include injection blocked, escalation blocked, etc.
        for etype in [
            "security.injection_blocked",
            "security.exfiltration_alert",
            "security.escalation_blocked",
            "security.tool_abuse",
        ]:
            events.extend(bus.query({"event_type": etype}, limit=limit))

        # Sort by timestamp descending, deduplicate
        seen = set()
        unique = []
        for e in sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True):
            eid = e.get("event_id")
            if eid not in seen:
                seen.add(eid)
                unique.append(e)

        return unique[:limit]

    # ------------------------------------------------------------------
    # Quarantine (REQ-073)
    # ------------------------------------------------------------------
    @app.get("/api/security/quarantine")
    async def list_quarantine(
        limit: int = 50,
        user: dict = Depends(get_current_user),
    ):
        """Quarantine backlog."""
        q = app.state.qdrant
        if not q:
            return []
        results = q.scroll_points(
            "memory_quarantine",
            filter_conditions={"review_status": "pending"},
            limit=limit,
        )
        return [r["payload"] for r in results]

    @app.post("/api/security/quarantine/{entry_id}")
    async def review_quarantine(
        entry_id: str,
        request: Request,
        user: dict = Depends(get_current_user),
    ):
        """Promote or reject a quarantined entry."""
        body = await request.json()
        action = body.get("action", "")
        reason = body.get("reason", "")
        operator_id = user.get("sub", "unknown")

        q = app.state.qdrant
        bus = app.state.audit_bus
        if not q:
            raise HTTPException(500, "Qdrant not available")

        from governance.lib.security.memory_integrity import QuarantineManager
        mgr = QuarantineManager(q, bus)

        if action == "promote":
            success = mgr.promote(entry_id, operator_id)
        elif action == "reject":
            success = mgr.reject(entry_id, operator_id, reason)
        else:
            raise HTTPException(400, "Action must be 'promote' or 'reject'")

        if not success:
            raise HTTPException(404, "Entry not found")

        return {"status": "ok", "action": action, "entry_id": entry_id}

    # ------------------------------------------------------------------
    # Guardian actions (REQ-073)
    # ------------------------------------------------------------------
    @app.get("/api/security/guardian/actions")
    async def guardian_actions(
        limit: int = 50,
        user: dict = Depends(get_current_user),
    ):
        """Guardian action history."""
        q = app.state.qdrant
        if not q:
            return []
        results = q.scroll_points(
            "guardian_audit_log",
            limit=limit,
            order_by="timestamp",
        )
        return [r["payload"] for r in results]

    @app.get("/api/security/guardian/config")
    async def guardian_config(user: dict = Depends(get_current_user)):
        """Current Guardian configuration."""
        cfg = app.state.config
        if not cfg:
            return {}
        return {
            "autonomy_level": cfg.guardian.autonomy_level,
            "webhook_url": cfg.guardian.webhook_url or "",
            "max_notification_delay_seconds": cfg.guardian.max_notification_delay_seconds,
            "required_scope": cfg.guardian.required_scope,
        }

    @app.put("/api/security/guardian/config")
    async def update_guardian_config(
        request: Request,
        user: dict = Depends(get_current_user),
    ):
        """Update Guardian configuration (requires security_admin scope)."""
        scope = user.get("scope", [])
        cfg = app.state.config
        if not cfg:
            raise HTTPException(500, "Config not loaded")

        if cfg.guardian.required_scope not in scope:
            raise HTTPException(403, f"Requires {cfg.guardian.required_scope} scope")

        body = await request.json()
        new_level = body.get("autonomy_level")
        if new_level:
            valid = {"ADVISORY", "SEMI_AUTONOMOUS", "FULLY_AUTONOMOUS"}
            if new_level not in valid:
                raise HTTPException(400, f"Invalid autonomy level: {new_level}")
            cfg.guardian.autonomy_level = new_level

        return {"status": "ok", "autonomy_level": cfg.guardian.autonomy_level}

    # ------------------------------------------------------------------
    # CSS / TUE scores (REQ-073)
    # ------------------------------------------------------------------
    @app.get("/api/security/scores/{agent_id}")
    async def agent_scores(
        agent_id: str,
        limit: int = 20,
        user: dict = Depends(get_current_user),
    ):
        """CSS and TUE trends for an agent."""
        q = app.state.qdrant
        if not q:
            return {"css": [], "tue": []}

        tue_scores = q.get_recent_scores("tue", agent_id, limit=limit)
        # CSS uses pair keys, so we search for pairs containing this agent
        css_results = q.scroll_points(
            "coordination_scores",
            filter_conditions={"record_type": "css"},
            limit=100,
        )
        css_scores = [
            r["payload"] for r in css_results
            if agent_id in r["payload"].get("agent_pair", "")
        ][:limit]

        return {"css": css_scores, "tue": tue_scores}

    # ------------------------------------------------------------------
    # Identity lifecycle (REQ-073)
    # ------------------------------------------------------------------
    @app.get("/api/security/identities")
    async def list_identities(user: dict = Depends(get_current_user)):
        """Identity lifecycle status for all active sessions."""
        q = app.state.qdrant
        if not q:
            return []
        results = q.scroll_points(
            "agent_identity_sessions",
            limit=100,
        )
        return [
            {
                "credential_id": r["payload"].get("credential_id", ""),
                "session_id": r["payload"].get("session_id", ""),
                "agent_id": r["payload"].get("agent_id", ""),
                "state": r["payload"].get("state", ""),
                "issued_at": r["payload"].get("issued_at", ""),
                "last_rotated_at": r["payload"].get("last_rotated_at", ""),
                "throttle_rate": r["payload"].get("throttle_rate", 1.0),
            }
            for r in results
        ]

    # ------------------------------------------------------------------
    # Forensic replay (REQ-075)
    # ------------------------------------------------------------------
    @app.get("/api/security/forensic/{session_id}")
    async def forensic_timeline(
        session_id: str,
        user: dict = Depends(get_current_user),
    ):
        """Forensic timeline for a session."""
        q = app.state.qdrant
        bus = app.state.audit_bus
        if not q or not bus:
            raise HTTPException(500, "Backend not available")

        from governance.lib.security.forensic_replay import ForensicReplay
        replay = ForensicReplay(q, bus)
        timeline = replay.replay_session(session_id)
        return timeline

    # ------------------------------------------------------------------
    # Compliance reports (REQ-076)
    # ------------------------------------------------------------------
    @app.post("/api/security/compliance/soc2")
    async def generate_soc2(
        request: Request,
        user: dict = Depends(get_current_user),
    ):
        """Generate SOC 2 Type II report."""
        body = await request.json()
        period_start = body.get("period_start", "")
        period_end = body.get("period_end", "")
        controls = body.get("controls", [
            "CC6.1", "CC6.3", "CC6.7", "CC7.1", "CC7.2", "CC7.3", "CC9.1",
        ])

        bus = app.state.audit_bus
        if not bus:
            raise HTTPException(500, "Audit bus not available")

        from governance.lib.security.compliance_reporter import ComplianceReporter
        reporter = ComplianceReporter(bus, app.state.qdrant)
        report = reporter.generate_soc2_report(
            period_start=period_start,
            period_end=period_end,
            controls=controls,
        )
        return report

    @app.post("/api/security/compliance/doi")
    async def generate_doi(
        request: Request,
        user: dict = Depends(get_current_user),
    ):
        """Generate DOI disclosure report."""
        body = await request.json()
        period_start = body.get("period_start", "")
        period_end = body.get("period_end", "")

        bus = app.state.audit_bus
        if not bus:
            raise HTTPException(500, "Audit bus not available")

        from governance.lib.security.compliance_reporter import ComplianceReporter
        reporter = ComplianceReporter(bus, app.state.qdrant)
        report = reporter.generate_doi_report(
            period_start=period_start,
            period_end=period_end,
        )
        return report

    return app


# ---------------------------------------------------------------------------
# Server runner
# ---------------------------------------------------------------------------
def run_dashboard(port: int = 8101, host: str = "0.0.0.0"):
    """Start the dashboard API server."""
    import uvicorn
    from governance.lib.singletons import (
        get_audit_bus,
        get_security_qdrant,
        get_security_config,
    )

    app = create_app(
        qdrant=get_security_qdrant(),
        audit_bus=get_audit_bus(),
        config=get_security_config(),
    )

    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    port = int(os.environ.get("SECURITY_DASHBOARD_PORT", "8101"))
    run_dashboard(port=port)
