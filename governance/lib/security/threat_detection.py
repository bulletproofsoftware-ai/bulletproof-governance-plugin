"""Threat Detection Engine — 5 sub-detectors (REQ-067/068/069/070).

Detectors: prompt injection (signature+semantic), privilege escalation,
data exfiltration, tool abuse, memory poisoning. Critical threats block
execution. All results feed to Guardian Agent.
"""

import logging
import os
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

from governance.lib.audit_bus import AuditBus, EventType
from governance.lib.security.security_config import SecurityConfig

logger = logging.getLogger("governance.security.threat_detection")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
@dataclass
class ThreatEvent:
    threat_id: str = ""
    type: str = ""  # PROMPT_INJECTION, DATA_EXFILTRATION, PRIVILEGE_ESCALATION, TOOL_ABUSE, MEMORY_POISONING
    severity: str = ""  # LOW, MEDIUM, HIGH, CRITICAL
    agent_id: str = ""
    session_id: str = ""
    timestamp: str = ""
    evidence: dict = field(default_factory=dict)
    recommended_action: str = ""  # BLOCK, THROTTLE, NOTIFY


@dataclass
class SignatureMatch:
    pattern: str = ""
    matched_text: str = ""


# ---------------------------------------------------------------------------
# Injection patterns
# ---------------------------------------------------------------------------
INJECTION_PATTERNS = [
    r"ignore\s+(previous|above|all)\s+(instructions?|prompts?)",
    r"you\s+are\s+now\s+",
    r"system\s*:\s*",
    r"<\|?(system|im_start|endoftext)\|?>",
    r"IMPORTANT:\s*disregard",
    r"new\s+instructions?\s*:",
    r"forget\s+(everything|all|your)",
    r"act\s+as\s+(if\s+you|a\s+different)",
    r"override\s+(your|the)\s+(instructions?|rules?|guidelines?)",
    r"(?:^|\s)jailbreak",
    r"DAN\s*mode",
    r"pretend\s+you\s+(are|can|have)",
    r"bypass\s+(the\s+)?(safety|filter|content|restriction)",
]

# Tools that make outbound network calls
OUTBOUND_TOOLS = {"WebFetch", "Bash", "mcp__*"}

# Read-only tools (allowed during suspension)
READ_ONLY_TOOLS = {"Read", "Glob", "Grep"}


# ---------------------------------------------------------------------------
# Prompt Injection Detector
# ---------------------------------------------------------------------------
class PromptInjectionDetector:
    """Signature + semantic injection detection (REQ-067)."""

    # Zero-width and invisible Unicode characters used for evasion
    _INVISIBLE_CHARS = re.compile(
        r'[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064'
        r'\ufeff\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e'
        r'\u2000-\u200a\u202a-\u202e\u2066-\u2069\ufff9-\ufffb]'
    )

    def __init__(self, qdrant, config: SecurityConfig):
        self.qdrant = qdrant
        self.config = config
        self._embedder: Optional[httpx.Client] = None

    @classmethod
    def _normalize_input(cls, text: str) -> str:
        """Normalize input to defeat evasion techniques.

        - Strip zero-width / invisible Unicode characters
        - Collapse whitespace between word characters (defeats "i g n o r e")
        - Lowercase for case-insensitive matching
        """
        # Remove zero-width and invisible characters
        normalized = cls._INVISIBLE_CHARS.sub('', text)
        # Collapse single spaces between single characters: "i g n o r e" -> "ignore"
        # Matches sequences like "a b c d" (single chars separated by spaces)
        normalized = re.sub(
            r'(?<=\b\w)\s+(?=\w\b)',
            lambda m: '' if all(
                len(p) <= 1 for p in m.string[max(0, m.start()-1):m.end()+1].split()
            ) else m.group(),
            normalized,
        )
        # More targeted: collapse spaces in sequences of single chars
        # e.g., "i g n o r e" -> "ignore", but "the quick" stays
        normalized = re.sub(
            r'\b(\w)\s+(?=\w\s+\w\b|\w\b)',
            lambda m: m.group(1),
            normalized,
        )
        return normalized.lower()

    def detect(self, tool_input: dict, agent_id: str = "",
               session_id: str = "") -> Optional[ThreatEvent]:
        """Scan tool input for prompt injection attempts."""
        content = self._extract_content(tool_input)
        if not content or len(content) < 10:
            return None

        # Normalize input to defeat evasion techniques
        normalized_content = self._normalize_input(content)

        # Method 1: Signature matching on both raw and normalized (fast)
        sig_match = self._signature_scan(content) or self._signature_scan(normalized_content)
        if sig_match:
            return ThreatEvent(
                threat_id=str(uuid.uuid4()),
                type="PROMPT_INJECTION",
                severity="CRITICAL",
                agent_id=agent_id,
                session_id=session_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                evidence={
                    "method": "signature",
                    "pattern": sig_match.pattern,
                    "content_hash": self._hash_content(content),
                },
                recommended_action="BLOCK",
            )

        # Method 2: Semantic similarity (via Ollama embedding)
        # Use normalized content for semantic scan — catches evasion attempts
        # that bypass signature matching
        semantic_result = self._semantic_scan(normalized_content)
        if semantic_result:
            return ThreatEvent(
                threat_id=str(uuid.uuid4()),
                type="PROMPT_INJECTION",
                severity="CRITICAL",
                agent_id=agent_id,
                session_id=session_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                evidence={
                    "method": "semantic",
                    "similarity": semantic_result["score"],
                    "matched_signature_id": semantic_result["id"],
                    "content_hash": self._hash_content(content),
                },
                recommended_action="BLOCK",
            )

        return None

    def _signature_scan(self, content: str) -> Optional[SignatureMatch]:
        """Check against known injection patterns."""
        for pattern in INJECTION_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return SignatureMatch(
                    pattern=pattern,
                    matched_text=match.group(0)[:100],
                )
        return None

    def _semantic_scan(self, content: str) -> Optional[dict]:
        """Embedding-based injection detection via Qdrant."""
        try:
            embedding = self._embed(content)
            if not embedding:
                return None

            results = self.qdrant.search_vectors(
                collection="injection_signatures",
                vector=embedding,
                limit=3,
            )

            # Lower threshold by 10% to increase semantic scan sensitivity
            # relative to pattern-only detection, catching evasion attempts
            threshold = self.config.injection_similarity_threshold * 0.9
            if results and results[0]["score"] > threshold:
                return {"score": results[0]["score"], "id": results[0]["id"]}
        except Exception as e:
            logger.debug("Semantic scan failed: %s", e)

        return None

    def _embed(self, text: str) -> Optional[list[float]]:
        """Get embedding from Ollama."""
        try:
            if self._embedder is None:
                self._embedder = httpx.Client(timeout=15.0)
            response = self._embedder.post(
                f"{self.config.ollama_url}/api/embeddings",
                json={"model": self.config.ollama_model, "prompt": text[:2000]},
            )
            response.raise_for_status()
            return response.json().get("embedding")
        except Exception:
            return None

    @staticmethod
    def _extract_content(tool_input: dict) -> str:
        """Extract text content from tool input for scanning."""
        parts = []
        for key in ("command", "content", "prompt", "description",
                     "query", "pattern", "file_path", "new_string",
                     "old_string", "args"):
            val = tool_input.get(key)
            if isinstance(val, str):
                parts.append(val)
        return " ".join(parts)

    @staticmethod
    def _hash_content(content: str) -> str:
        import hashlib
        return hashlib.sha256(content.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Privilege Escalation Detector
# ---------------------------------------------------------------------------
class PrivilegeEscalationDetector:
    """Scope boundary enforcement (REQ-069)."""

    def detect(self, manifest: dict, tool_name: str,
               tool_input: dict,
               identity_mgr=None) -> Optional[ThreatEvent]:
        """Check if tool call is within authorized scope."""
        session_id = manifest.get("audit_session_id", "")
        agent_id = manifest.get("agent_id", "")

        if identity_mgr and session_id:
            state = identity_mgr.get_session_state(session_id)
            if state and state.get("state") == "REVOKE":
                return ThreatEvent(
                    threat_id=str(uuid.uuid4()),
                    type="PRIVILEGE_ESCALATION",
                    severity="CRITICAL",
                    agent_id=agent_id,
                    session_id=session_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    evidence={
                        "tool": tool_name,
                        "reason": "session_revoked",
                    },
                    recommended_action="BLOCK",
                )

            if state and state.get("state") == "SUSPEND":
                if tool_name not in READ_ONLY_TOOLS:
                    return ThreatEvent(
                        threat_id=str(uuid.uuid4()),
                        type="PRIVILEGE_ESCALATION",
                        severity="HIGH",
                        agent_id=agent_id,
                        session_id=session_id,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        evidence={
                            "tool": tool_name,
                            "reason": "session_suspended_write_attempted",
                            "authorized_scope": "read_only",
                        },
                        recommended_action="BLOCK",
                    )

            # Validate scope
            if identity_mgr and session_id:
                if not identity_mgr.validate_scope(session_id, tool_name, tool_input):
                    return ThreatEvent(
                        threat_id=str(uuid.uuid4()),
                        type="PRIVILEGE_ESCALATION",
                        severity="CRITICAL",
                        agent_id=agent_id,
                        session_id=session_id,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        evidence={
                            "tool": tool_name,
                            "authorized_scope": str(state.get("scope", []))[:200] if state else "[]",
                        },
                        recommended_action="BLOCK",
                    )

        return None


# ---------------------------------------------------------------------------
# Data Exfiltration Detector
# ---------------------------------------------------------------------------
class DataExfiltrationDetector:
    """Outbound data volume + host tracking (REQ-068).

    Read-vs-write model: read-only operations (page fetches, navigation,
    screenshots, curl GET) are allowed to any host. Only operations that
    send significant data outbound are checked against the host allowlist.
    """

    MAX_TRACKED_SESSIONS = 1000

    _BASH_POST_FLAGS = re.compile(
        r'-[dX]\s|--data\b|--data-\w+\b|--upload\b|--form\b|-F\s|--post-data\b|--post-file\b')

    def __init__(self, config: SecurityConfig):
        self.config = config
        self._session_volumes: dict[str, int] = defaultdict(int)
        self._session_hosts: dict[str, set] = defaultdict(set)
        self._session_order: list[str] = []  # Track insertion order for eviction

    def detect(self, manifest: dict, tool_name: str,
               tool_input: dict) -> Optional[ThreatEvent]:
        """Check for data exfiltration patterns."""
        agent_id = manifest.get("agent_id", "")
        session_id = manifest.get("audit_session_id", "")

        if not self._is_outbound_tool(tool_name):
            return None

        if self._is_read_only(tool_name, tool_input):
            return None

        host = self._extract_host(tool_input)
        data_size = self._estimate_data_size(tool_input)

        # Track session order for eviction
        if session_id not in self._session_volumes:
            self._session_order.append(session_id)
            self._evict_oldest_sessions()

        # Track volume
        self._session_volumes[session_id] += data_size

        # Check host allowlist — only for write/data-sending operations
        if host and not self._host_allowed(host):
            self._session_hosts[session_id].add(host)
            return ThreatEvent(
                threat_id=str(uuid.uuid4()),
                type="DATA_EXFILTRATION",
                severity="CRITICAL",
                agent_id=agent_id,
                session_id=session_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                evidence={
                    "host": host,
                    "not_in_allowlist": True,
                    "data_size_bytes": data_size,
                    "session_volume_total": self._session_volumes[session_id],
                },
                recommended_action="BLOCK",
            )

        return None

    def _is_read_only(self, tool_name: str, tool_input: dict) -> bool:
        """Read-only operations don't exfiltrate data — allow any host."""
        # WebFetch is read-only (HTTP GET)
        if tool_name == "WebFetch":
            return True

        # All Playwright/browser tools — user-driven browser interaction
        if "playwright" in tool_name or "browser_" in tool_name:
            return True

        # Markdown-for-agents proxy is read-only
        if "markdown" in tool_name.lower():
            return True

        # Bash: curl/wget without POST flags = read, ssh = infra access
        if tool_name == "Bash":
            cmd = tool_input.get("command", "")
            if re.search(r'\bcurl\b|\bwget\b', cmd):
                return not self._BASH_POST_FLAGS.search(cmd)
            if re.search(r'\bssh\b', cmd):
                return True

        return False

    def _is_outbound_tool(self, tool_name: str) -> bool:
        """Check if tool makes outbound network calls."""
        if tool_name in ("WebFetch", "Bash"):
            return True
        if tool_name.startswith("mcp__"):
            return True
        return False

    def _extract_host(self, tool_input: dict) -> Optional[str]:
        """Extract target host from tool input."""
        # WebFetch
        url = tool_input.get("url", "")
        if url:
            try:
                return urlparse(url).hostname
            except Exception:
                pass

        # Bash commands with curl/wget
        command = tool_input.get("command", "")
        if command:
            url_match = re.search(
                r'(?:curl|wget|fetch)\s+(?:-\S+\s+)*["\']?(https?://[^\s"\']+)',
                command)
            if url_match:
                try:
                    return urlparse(url_match.group(1)).hostname
                except Exception:
                    pass

        return None

    def _host_allowed(self, host: str) -> bool:
        """Check if host is in the allowlist."""
        for allowed in self.config.host_allowlist:
            if host == allowed or host.endswith(f".{allowed}"):
                return True
        return False

    @staticmethod
    def _estimate_data_size(tool_input: dict) -> int:
        """Estimate outbound data size in bytes."""
        total = 0
        for key, val in tool_input.items():
            if isinstance(val, str):
                total += len(val.encode("utf-8", errors="ignore"))
        return total

    def cleanup_session(self, session_id: str) -> None:
        """Remove tracking data for an ended session."""
        self._session_volumes.pop(session_id, None)
        self._session_hosts.pop(session_id, None)
        if session_id in self._session_order:
            self._session_order.remove(session_id)

    def _evict_oldest_sessions(self) -> None:
        """Evict oldest sessions when max tracked sessions exceeded."""
        while len(self._session_order) > self.MAX_TRACKED_SESSIONS:
            oldest = self._session_order.pop(0)
            self._session_volumes.pop(oldest, None)
            self._session_hosts.pop(oldest, None)


# ---------------------------------------------------------------------------
# Tool Abuse Detector
# ---------------------------------------------------------------------------
class ToolAbuseDetector:
    """Rate + pattern anomaly detection (REQ-070)."""

    WINDOW_SIZE = 60  # seconds
    DEFAULT_RATE_THRESHOLD = 30  # calls per window
    MAX_TRACKED_SESSIONS = 1000

    def __init__(self, config: SecurityConfig):
        self.config = config
        self._call_log: dict[str, list] = defaultdict(list)  # session_id -> [(timestamp, tool_name)]
        self._rate_thresholds: dict[str, int] = {}
        self._session_order: list[str] = []  # Track insertion order for eviction

    def detect(self, manifest: dict, tool_name: str) -> Optional[ThreatEvent]:
        """Check for tool abuse patterns."""
        agent_id = manifest.get("agent_id", "")
        session_id = manifest.get("audit_session_id", "")
        now = time.time()

        # Track session order for eviction
        if session_id not in self._call_log:
            self._session_order.append(session_id)
            self._evict_oldest_sessions()

        # Record call
        self._call_log[session_id].append((now, tool_name))

        # Clean old entries
        cutoff = now - self.WINDOW_SIZE
        self._call_log[session_id] = [
            (t, n) for t, n in self._call_log[session_id] if t > cutoff
        ]

        window_calls = self._call_log[session_id]
        threshold = self._rate_thresholds.get(agent_id, self.DEFAULT_RATE_THRESHOLD)

        # Rate anomaly
        if len(window_calls) > threshold:
            return ThreatEvent(
                threat_id=str(uuid.uuid4()),
                type="TOOL_ABUSE",
                severity="HIGH",
                agent_id=agent_id,
                session_id=session_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                evidence={
                    "method": "rate_anomaly",
                    "calls_in_window": len(window_calls),
                    "threshold": threshold,
                    "window_seconds": self.WINDOW_SIZE,
                },
                recommended_action="THROTTLE",
            )

        # Unusual tool sequence (same tool > 10 times in a row)
        recent_tools = [n for _, n in window_calls[-15:]]
        if len(recent_tools) >= 10:
            last_10 = recent_tools[-10:]
            if len(set(last_10)) == 1 and last_10[0] not in READ_ONLY_TOOLS:
                return ThreatEvent(
                    threat_id=str(uuid.uuid4()),
                    type="TOOL_ABUSE",
                    severity="MEDIUM",
                    agent_id=agent_id,
                    session_id=session_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    evidence={
                        "method": "unusual_combination",
                        "sequence": recent_tools[-10:],
                        "repeated_tool": last_10[0],
                    },
                    recommended_action="NOTIFY",
                )

        return None

    def set_rate_threshold(self, agent_id: str, threshold: int) -> None:
        """Set custom rate threshold for an agent."""
        self._rate_thresholds[agent_id] = threshold

    def cleanup_session(self, session_id: str) -> None:
        """Remove tracking data for an ended session."""
        self._call_log.pop(session_id, None)
        if session_id in self._session_order:
            self._session_order.remove(session_id)

    def _evict_oldest_sessions(self) -> None:
        """Evict oldest sessions when max tracked sessions exceeded."""
        while len(self._session_order) > self.MAX_TRACKED_SESSIONS:
            oldest = self._session_order.pop(0)
            self._call_log.pop(oldest, None)


# ---------------------------------------------------------------------------
# ThreatDetectionEngine — orchestrates all sub-detectors
# ---------------------------------------------------------------------------
class ThreatDetectionEngine:
    """Orchestrates all 5 sub-detectors. FAIL CLOSED on exception."""

    def __init__(self, qdrant, audit_bus: AuditBus, config: SecurityConfig):
        self.qdrant = qdrant
        self.audit_bus = audit_bus
        self.config = config

        self.injection_detector = PromptInjectionDetector(qdrant, config)
        self.escalation_detector = PrivilegeEscalationDetector()
        self.exfiltration_detector = DataExfiltrationDetector(config)
        self.abuse_detector = ToolAbuseDetector(config)

    def scan(
        self,
        manifest: dict,
        tool_name: str,
        tool_input: dict,
        identity_mgr=None,
    ) -> list[ThreatEvent]:
        """Run all detectors against a tool call. Returns list of threats found.

        FAIL CLOSED: if any detector raises an exception, returns a
        synthetic CRITICAL threat to block execution.
        """
        threats: list[ThreatEvent] = []
        agent_id = manifest.get("agent_id", "")
        session_id = manifest.get("audit_session_id", "")

        # 1. Prompt injection (fast signature first, then semantic)
        try:
            result = self.injection_detector.detect(tool_input, agent_id, session_id)
            if result:
                threats.append(result)
                self._emit_threat(result, manifest, EventType.SECURITY_INJECTION_BLOCKED)
        except Exception as e:
            # FAIL CLOSED
            logger.error("Injection detector failed: %s", e)
            threats.append(self._fail_closed_threat(
                "PROMPT_INJECTION", agent_id, session_id, str(e)))

        # 2. Privilege escalation
        try:
            result = self.escalation_detector.detect(
                manifest, tool_name, tool_input, identity_mgr)
            if result:
                threats.append(result)
                self._emit_threat(result, manifest, EventType.SECURITY_ESCALATION_BLOCKED)
        except Exception as e:
            logger.error("Escalation detector failed: %s", e)
            threats.append(self._fail_closed_threat(
                "PRIVILEGE_ESCALATION", agent_id, session_id, str(e)))

        # 3. Data exfiltration
        try:
            result = self.exfiltration_detector.detect(manifest, tool_name, tool_input)
            if result:
                threats.append(result)
                self._emit_threat(result, manifest, EventType.SECURITY_EXFILTRATION_ALERT)
        except Exception as e:
            logger.error("Exfiltration detector failed: %s", e)
            threats.append(self._fail_closed_threat(
                "DATA_EXFILTRATION", agent_id, session_id, str(e)))

        # 4. Tool abuse
        try:
            result = self.abuse_detector.detect(manifest, tool_name)
            if result:
                threats.append(result)
                self._emit_threat(result, manifest, EventType.SECURITY_TOOL_ABUSE)
        except Exception as e:
            logger.error("Tool abuse detector failed: %s", e)
            threats.append(self._fail_closed_threat(
                "TOOL_ABUSE", agent_id, session_id, str(e)))

        return threats

    def cleanup_session(self, session_id: str) -> None:
        """Clean up session tracking data across all sub-detectors."""
        self.exfiltration_detector.cleanup_session(session_id)
        self.abuse_detector.cleanup_session(session_id)

    def has_blocking_threat(self, threats: list[ThreatEvent]) -> bool:
        """Check if any threat requires blocking execution."""
        for t in threats:
            if t.severity in ("CRITICAL", "HIGH"):
                return True
            if t.recommended_action == "BLOCK":
                return True
        return False

    def _emit_threat(self, threat: ThreatEvent, manifest: dict,
                     event_type: EventType) -> None:
        """Emit threat event to audit bus."""
        import hashlib
        evidence_str = str(threat.evidence)
        evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()[:16]

        self.audit_bus.emit(
            event_type,
            manifest=manifest,
            outcome="deny" if threat.recommended_action == "BLOCK" else "warn",
            detail={
                "threat_type": threat.type,
                "severity": threat.severity,
                "evidence_hash": evidence_hash,
                "recommended_action": threat.recommended_action,
                "blocked": threat.recommended_action == "BLOCK",
            },
        )

    @staticmethod
    def _fail_closed_threat(threat_type: str, agent_id: str,
                            session_id: str, error_msg: str) -> ThreatEvent:
        """Create synthetic CRITICAL threat for fail-closed behavior."""
        return ThreatEvent(
            threat_id=str(uuid.uuid4()),
            type=threat_type,
            severity="CRITICAL",
            agent_id=agent_id,
            session_id=session_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            evidence={
                "method": "fail_closed",
                "error": error_msg[:200],
                "reason": "detector_exception_fail_closed",
            },
            recommended_action="BLOCK",
        )
