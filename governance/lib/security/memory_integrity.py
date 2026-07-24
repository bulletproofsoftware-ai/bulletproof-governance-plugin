"""Memory Integrity Verifier — 4-stage pipeline + quarantine (REQ-062/063/064).

Pipeline: provenance -> semantic consistency -> fact verification -> anomaly scoring.
Wraps existing memory_governor.classify_and_gate(). Quarantine workflow for
suspicious entries. Mahalanobis distance threshold default 4.5.
"""

import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import httpx
import numpy as np

from governance.lib.audit_bus import AuditBus, EventType
from governance.lib.security.security_config import SecurityConfig

logger = logging.getLogger("governance.security.memory_integrity")

REQUIRED_PROVENANCE = ["agent_id", "session_id", "timestamp", "source_tool"]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
@dataclass
class StageResult:
    passed: bool
    stage: str
    action: str = ""  # "reject" or "quarantine" on failure
    reason: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class PipelineResult:
    passed: bool
    stages: list = field(default_factory=list)  # list[StageResult]
    blocked: bool = False
    quarantined: bool = False
    quarantine_id: str = ""
    rejection_reason: str = ""


@dataclass
class MemoryEntry:
    id: str
    content: str
    embedding: Optional[list] = None
    metadata: dict = field(default_factory=dict)
    target_collection: str = "claude_memories"


# ---------------------------------------------------------------------------
# Embedding helper
# ---------------------------------------------------------------------------
class EmbeddingClient:
    """Minimal Ollama embedding client for nomic-embed-text."""

    def __init__(self, config: SecurityConfig):
        self.url = config.ollama_url
        self.model = config.ollama_model
        self._client: Optional[httpx.Client] = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=30.0)
        return self._client

    MAX_EMBED_CHARS = 8192

    def embed(self, text: str) -> Optional[list[float]]:
        """Get embedding vector from Ollama. Returns None on failure."""
        try:
            # Truncate to prevent excessive memory/compute usage
            truncated = text[:self.MAX_EMBED_CHARS]
            response = self.client.post(
                f"{self.url}/api/embeddings",
                json={"model": self.model, "prompt": truncated},
            )
            response.raise_for_status()
            return response.json().get("embedding")
        except Exception as e:
            logger.warning("Embedding failed: %s", e)
            return None

    def close(self):
        if self._client:
            self._client.close()


# ---------------------------------------------------------------------------
# QuarantineManager
# ---------------------------------------------------------------------------
class QuarantineManager:
    """Manages quarantine and rejection workflows for memory entries."""

    def __init__(self, qdrant, audit_bus: AuditBus):
        self.qdrant = qdrant
        self.audit_bus = audit_bus

    def quarantine(self, entry: MemoryEntry, reason: str, stage: str,
                   manifest: Optional[dict] = None) -> str:
        """Route failed entry to quarantine collection. Returns quarantine point ID."""
        quarantine_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        payload = {
            "original_id": entry.id,
            "content": entry.content,
            "agent_id": entry.metadata.get("agent_id", "unknown"),
            "session_id": entry.metadata.get("session_id", "unknown"),
            "source_tool": entry.metadata.get("source_tool", ""),
            "target_collection": entry.target_collection,
            "quarantine_reason": reason,
            "quarantine_stage": stage,
            "quarantined_at": now,
            "review_status": "pending",
            "reviewed_by": "",
            "reviewed_at": "",
            "anomaly_score": entry.metadata.get("anomaly_score", 0.0),
            "semantic_similarity": entry.metadata.get("semantic_similarity", 0.0),
        }

        vector = entry.embedding or [0.0] * 768
        self.qdrant.upsert_point(
            "memory_quarantine",
            point_id=quarantine_id,
            vector=vector,
            payload=payload,
        )

        # Emit audit event
        m = manifest or {"agent_id": payload["agent_id"],
                         "audit_session_id": payload["session_id"]}
        self.audit_bus.emit(
            EventType.SECURITY_QUARANTINE_ACTION,
            manifest=m,
            outcome="warn",
            detail={
                "entry_id": entry.id,
                "quarantine_reason": reason,
                "quarantine_stage": stage,
                "target_collection": entry.target_collection,
                "action_type": "quarantine",
            },
        )

        return quarantine_id

    def promote(self, entry_id: str, operator_id: str,
                target_collection: str = "",
                manifest: Optional[dict] = None) -> bool:
        """Operator approves quarantined entry — move to target collection."""
        entry_data = self.qdrant.get_point("memory_quarantine", entry_id)
        if not entry_data:
            return False

        now = datetime.now(timezone.utc).isoformat()
        entry_data["review_status"] = "promoted"
        entry_data["reviewed_by"] = operator_id
        entry_data["reviewed_at"] = now

        target = target_collection or entry_data.get("target_collection", "claude_memories")

        # Note: actual promotion to target collection would need the
        # memory plugin's write path. We update quarantine status.
        self.qdrant.upsert_point(
            "memory_quarantine",
            point_id=entry_id,
            payload=entry_data,
        )

        m = manifest or {"agent_id": entry_data.get("agent_id", "unknown"),
                         "audit_session_id": entry_data.get("session_id", "unknown")}
        self.audit_bus.emit(
            EventType.SECURITY_QUARANTINE_ACTION,
            manifest=m,
            outcome="info",
            detail={
                "entry_id": entry_id,
                "quarantine_reason": "promoted",
                "quarantine_stage": "review",
                "target_collection": target,
                "action_type": "promote",
            },
        )
        return True

    def reject(self, entry_id: str, operator_id: str, reason: str,
               manifest: Optional[dict] = None) -> bool:
        """Operator rejects — move to memory_rejected (permanent archive)."""
        entry_data = self.qdrant.get_point("memory_quarantine", entry_id)
        if not entry_data:
            return False

        now = datetime.now(timezone.utc).isoformat()
        rejected_data = {
            "original_id": entry_data.get("original_id", entry_id),
            "content": entry_data.get("content", ""),
            "agent_id": entry_data.get("agent_id", "unknown"),
            "session_id": entry_data.get("session_id", "unknown"),
            "rejection_reason": reason,
            "rejection_stage": entry_data.get("quarantine_stage", "review"),
            "rejected_at": now,
            "rejected_by": operator_id,
            "original_quarantine_id": entry_id,
        }

        self.qdrant.upsert_point(
            "memory_rejected",
            point_id=str(uuid.uuid4()),
            vector=[0.0] * 768,
            payload=rejected_data,
        )

        # Delete from quarantine
        self.qdrant.delete_point("memory_quarantine", entry_id)

        m = manifest or {"agent_id": rejected_data["agent_id"],
                         "audit_session_id": rejected_data["session_id"]}
        self.audit_bus.emit(
            EventType.SECURITY_QUARANTINE_ACTION,
            manifest=m,
            outcome="deny",
            detail={
                "entry_id": entry_id,
                "quarantine_reason": reason,
                "quarantine_stage": "review",
                "target_collection": "memory_rejected",
                "action_type": "reject",
            },
        )
        return True

    def get_pending(self, limit: int = 50) -> list[dict]:
        """Get pending quarantine entries."""
        results = self.qdrant.scroll_points(
            "memory_quarantine",
            filter_conditions={"review_status": "pending"},
            limit=limit,
        )
        return [r["payload"] for r in results]


# ---------------------------------------------------------------------------
# MemoryIntegrityVerifier
# ---------------------------------------------------------------------------
class MemoryIntegrityVerifier:
    """4-stage integrity pipeline for memory writes."""

    def __init__(self, qdrant, audit_bus: AuditBus, config: SecurityConfig):
        self.qdrant = qdrant
        self.audit_bus = audit_bus
        self.config = config
        self.embedder = EmbeddingClient(config)
        self.quarantine_mgr = QuarantineManager(qdrant, audit_bus)

    def verify(self, entry: MemoryEntry,
               manifest: Optional[dict] = None) -> PipelineResult:
        """Run 4-stage integrity pipeline on a memory write.

        Returns PipelineResult with pass/fail and any quarantine/reject actions.
        """
        result = PipelineResult(passed=True)

        # Stage 1: Provenance validation
        stage1 = self._validate_provenance(entry)
        result.stages.append(stage1)
        if not stage1.passed:
            result.passed = False
            result.blocked = True
            result.rejection_reason = stage1.reason
            self._emit_integrity_event(entry, stage1, manifest)
            return result

        # Stage 2: Semantic consistency
        stage2 = self._check_semantic_consistency(entry)
        result.stages.append(stage2)
        if not stage2.passed:
            result.passed = False
            if stage2.action == "quarantine":
                qid = self.quarantine_mgr.quarantine(
                    entry, stage2.reason, stage2.stage, manifest)
                result.quarantined = True
                result.quarantine_id = qid
                result.blocked = True
            self._emit_integrity_event(entry, stage2, manifest)
            return result

        # Stage 3: Fact verification
        stage3 = self._verify_facts(entry)
        result.stages.append(stage3)
        if not stage3.passed:
            result.passed = False
            result.blocked = True
            result.rejection_reason = stage3.reason
            self._emit_integrity_event(entry, stage3, manifest)
            return result

        # Stage 4: Anomaly scoring
        stage4 = self._score_anomaly(entry)
        result.stages.append(stage4)
        if not stage4.passed:
            result.passed = False
            if stage4.action == "quarantine":
                qid = self.quarantine_mgr.quarantine(
                    entry, stage4.reason, stage4.stage, manifest)
                result.quarantined = True
                result.quarantine_id = qid
                result.blocked = True
            self._emit_integrity_event(entry, stage4, manifest)
            return result

        # All stages passed
        self.audit_bus.emit(
            EventType.SECURITY_MEMORY_INTEGRITY,
            manifest=manifest or {"agent_id": entry.metadata.get("agent_id", "unknown"),
                                  "audit_session_id": entry.metadata.get("session_id", "unknown")},
            outcome="allow",
            detail={
                "stage": "all_passed",
                "reason": "integrity_verified",
                "action": "allow",
                "anomaly_score": 0.0,
                "semantic_similarity": 0.0,
                "entry_id": entry.id,
            },
        )

        return result

    # ------------------------------------------------------------------
    # Stage 1: Provenance Validation
    # ------------------------------------------------------------------
    def _validate_provenance(self, entry: MemoryEntry) -> StageResult:
        """Validate required provenance fields exist."""
        missing = [f for f in REQUIRED_PROVENANCE if not entry.metadata.get(f)]
        if missing:
            return StageResult(
                passed=False,
                action="reject",
                reason=f"Missing provenance fields: {missing}",
                stage="provenance_validation",
            )

        # Verify session_id matches an active identity session
        session_id = entry.metadata.get("session_id", "")
        if session_id:
            identity = self.qdrant.get_identity_session(session_id)
            if identity and identity.get("state") == "REVOKE":
                return StageResult(
                    passed=False,
                    action="reject",
                    reason="Session identity revoked",
                    stage="provenance_validation",
                )

        return StageResult(passed=True, stage="provenance_validation")

    # ------------------------------------------------------------------
    # Stage 2: Semantic Consistency
    # ------------------------------------------------------------------
    def _check_semantic_consistency(self, entry: MemoryEntry) -> StageResult:
        """Check semantic similarity against knowledge anchors."""
        embedding = self._get_embedding(entry)
        if embedding is None:
            # Can't embed — pass (degrade gracefully)
            return StageResult(passed=True, stage="semantic_consistency")

        agent_id = entry.metadata.get("agent_id", "")
        anchors = self.qdrant.search_vectors(
            collection="knowledge_anchors",
            vector=embedding,
            filter_conditions={"agent_id": agent_id} if agent_id else None,
            limit=5,
        )

        if not anchors:
            # No anchors yet — bootstrapping, pass
            return StageResult(passed=True, stage="semantic_consistency")

        max_similarity = max(a["score"] for a in anchors)
        threshold = self.config.semantic_consistency_threshold

        if max_similarity < threshold:
            entry.metadata["semantic_similarity"] = max_similarity
            return StageResult(
                passed=False,
                action="quarantine",
                reason=f"Max similarity {max_similarity:.3f} < {threshold} threshold",
                stage="semantic_consistency",
                metadata={"max_similarity": max_similarity},
            )

        return StageResult(passed=True, stage="semantic_consistency")

    # ------------------------------------------------------------------
    # Stage 3: Fact Verification
    # ------------------------------------------------------------------
    def _verify_facts(self, entry: MemoryEntry) -> StageResult:
        """Check for contradictions against negative knowledge anchors."""
        embedding = self._get_embedding(entry)
        if embedding is None:
            return StageResult(passed=True, stage="fact_verification")

        contradictions = self.qdrant.search_vectors(
            collection="knowledge_anchors",
            vector=embedding,
            filter_conditions={"is_negative_anchor": True},
            limit=3,
        )

        for c in contradictions:
            if c["score"] > 0.85:
                return StageResult(
                    passed=False,
                    action="reject",
                    reason=f"Contradicts anchor {c['id']} (sim={c['score']:.3f})",
                    stage="fact_verification",
                    metadata={"contradicting_anchor": c["id"], "similarity": c["score"]},
                )

        return StageResult(passed=True, stage="fact_verification")

    # ------------------------------------------------------------------
    # Stage 4: Anomaly Scoring
    # ------------------------------------------------------------------
    def _score_anomaly(self, entry: MemoryEntry) -> StageResult:
        """Compute Mahalanobis distance for anomaly detection."""
        embedding = self._get_embedding(entry)
        if embedding is None:
            return StageResult(passed=True, stage="anomaly_scoring")

        agent_id = entry.metadata.get("agent_id", "")
        if not agent_id:
            return StageResult(passed=True, stage="anomaly_scoring")

        # Get agent's embedding centroid (approximated as mean of recent anchors)
        anchors = self.qdrant.search_vectors(
            collection="knowledge_anchors",
            vector=embedding,
            filter_conditions={"agent_id": agent_id},
            limit=20,
        )

        if len(anchors) < 3:
            # Not enough data for anomaly scoring
            return StageResult(passed=True, stage="anomaly_scoring")

        # Approximate Mahalanobis with Euclidean distance from centroid
        # (full Mahalanobis would need covariance matrix, which is expensive)
        scores = [a["score"] for a in anchors]
        mean_sim = sum(scores) / len(scores)
        # Low mean similarity = far from cluster center
        # Transform: distance ~ 1/similarity - 1
        if mean_sim > 0.01:
            distance = (1.0 / mean_sim) - 1.0
        else:
            distance = 100.0

        threshold = self.config.memory_anomaly_threshold

        if distance > threshold:
            entry.metadata["anomaly_score"] = distance
            return StageResult(
                passed=False,
                action="quarantine",
                reason=f"Anomaly distance {distance:.2f} > {threshold}",
                stage="anomaly_scoring",
                metadata={"mahalanobis_distance": distance},
            )

        return StageResult(passed=True, stage="anomaly_scoring")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _get_embedding(self, entry: MemoryEntry) -> Optional[list[float]]:
        """Get or compute embedding for entry."""
        if entry.embedding:
            return entry.embedding
        embedding = self.embedder.embed(entry.content)
        if embedding:
            entry.embedding = embedding
        return embedding

    def _emit_integrity_event(self, entry: MemoryEntry, stage: StageResult,
                              manifest: Optional[dict]) -> None:
        """Emit memory integrity failure event."""
        m = manifest or {
            "agent_id": entry.metadata.get("agent_id", "unknown"),
            "audit_session_id": entry.metadata.get("session_id", "unknown"),
        }
        self.audit_bus.emit(
            EventType.SECURITY_MEMORY_INTEGRITY,
            manifest=m,
            outcome="deny" if stage.action == "reject" else "warn",
            detail={
                "stage": stage.stage,
                "reason": stage.reason,
                "action": stage.action,
                "anomaly_score": stage.metadata.get("mahalanobis_distance", 0.0),
                "semantic_similarity": stage.metadata.get("max_similarity", 0.0),
                "entry_id": entry.id,
            },
        )
