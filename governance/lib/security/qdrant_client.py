"""Shared Qdrant client wrapper for security collections (REQ-077).

Provides lazy-initialized Qdrant connection, collection creation/management,
and typed helpers for all 9 security collections. Uses qdrant-client SDK
against localhost:6334 (configurable via QDRANT_URL).
"""

import logging
import os
import uuid
import warnings
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

# Suppress "Api key is used with an insecure connection" warning —
# localhost connections don't need TLS.
warnings.filterwarnings("ignore", message="Api key is used with an insecure connection")

from qdrant_client import QdrantClient
from qdrant_client.http.exceptions import UnexpectedResponse
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchValue,
    PointStruct,
    VectorParams,
    PayloadSchemaType,
)

logger = logging.getLogger("governance.security.qdrant")

# ---------------------------------------------------------------------------
# Collection definitions — 9 security collections
# ---------------------------------------------------------------------------
SECURITY_COLLECTIONS = {
    "agent_behavioral_baselines": {
        "vector_size": 1,
        "distance": Distance.COSINE,
        "payload_indexes": {
            "agent_id": PayloadSchemaType.KEYWORD,
            "metric": PayloadSchemaType.KEYWORD,
        },
    },
    "agent_identity_sessions": {
        "vector_size": 1,
        "distance": Distance.COSINE,
        "payload_indexes": {
            "credential_id": PayloadSchemaType.KEYWORD,
            "session_id": PayloadSchemaType.KEYWORD,
            "agent_id": PayloadSchemaType.KEYWORD,
            "state": PayloadSchemaType.KEYWORD,
        },
    },
    "memory_quarantine": {
        "vector_size": 768,
        "distance": Distance.COSINE,
        "payload_indexes": {
            "agent_id": PayloadSchemaType.KEYWORD,
            "session_id": PayloadSchemaType.KEYWORD,
            "review_status": PayloadSchemaType.KEYWORD,
        },
    },
    "memory_rejected": {
        "vector_size": 768,
        "distance": Distance.COSINE,
        "payload_indexes": {
            "agent_id": PayloadSchemaType.KEYWORD,
        },
    },
    "knowledge_anchors": {
        "vector_size": 768,
        "distance": Distance.COSINE,
        "payload_indexes": {
            "anchor_id": PayloadSchemaType.KEYWORD,
            "agent_id": PayloadSchemaType.KEYWORD,
        },
    },
    "injection_signatures": {
        "vector_size": 768,
        "distance": Distance.COSINE,
        "payload_indexes": {
            "signature_id": PayloadSchemaType.KEYWORD,
            "severity": PayloadSchemaType.KEYWORD,
        },
    },
    "coordination_scores": {
        "vector_size": 1,
        "distance": Distance.COSINE,
        "payload_indexes": {
            "record_type": PayloadSchemaType.KEYWORD,
            "agent_pair": PayloadSchemaType.KEYWORD,
            "agent_id": PayloadSchemaType.KEYWORD,
            "timestamp": PayloadSchemaType.KEYWORD,
        },
    },
    "guardian_audit_log": {
        "vector_size": 1,
        "distance": Distance.COSINE,
        "payload_indexes": {
            "decision_id": PayloadSchemaType.KEYWORD,
            "event_type": PayloadSchemaType.KEYWORD,
            "agent_id": PayloadSchemaType.KEYWORD,
            "session_id": PayloadSchemaType.KEYWORD,
            "action_taken": PayloadSchemaType.KEYWORD,
        },
    },
    "forensic_events": {
        "vector_size": 1,
        "distance": Distance.COSINE,
        "payload_indexes": {
            "event_id": PayloadSchemaType.KEYWORD,
            "session_id": PayloadSchemaType.KEYWORD,
            "agent_id": PayloadSchemaType.KEYWORD,
            "event_type": PayloadSchemaType.KEYWORD,
            "timestamp": PayloadSchemaType.KEYWORD,
        },
    },
}

# Default retention for forensic events
FORENSIC_RETENTION_DAYS = int(os.environ.get("FORENSIC_RETENTION_DAYS", "90"))


class SecurityQdrantClient:
    """Wrapper around QdrantClient for security-specific operations.

    Degrades gracefully when Qdrant is unreachable or misconfigured —
    methods return empty results instead of raising, so callers that
    depend on Qdrant (semantic scan, guardian log) degrade without
    cascading to a full tool-call block.
    """

    def __init__(self, url: Optional[str] = None, api_key: Optional[str] = None):
        self._url = url or os.environ.get("QDRANT_URL", "http://localhost:6334")
        self._api_key = api_key or os.environ.get("QDRANT_API_KEY")
        self._client: Optional[QdrantClient] = None
        self._available: Optional[bool] = None  # tri-state: None=untested

    @property
    def available(self) -> bool:
        """Check if Qdrant is reachable. Cached after first probe."""
        if self._available is None:
            try:
                _ = self.client.get_collections()
                self._available = True
            except Exception:
                self._available = False
        return self._available

    @property
    def client(self) -> QdrantClient:
        """Lazy-init Qdrant connection."""
        if self._client is None:
            kwargs: dict[str, Any] = {"url": self._url, "timeout": 10}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            self._client = QdrantClient(**kwargs)
        return self._client

    # ------------------------------------------------------------------
    # Collection management
    # ------------------------------------------------------------------
    def ensure_collections(self) -> dict[str, bool]:
        """Create all 9 security collections if they don't exist.

        Returns dict of collection_name -> created (True if newly created).
        """
        if not self.available:
            return {name: False for name in SECURITY_COLLECTIONS}
        results: dict[str, bool] = {}
        existing = {c.name for c in self.client.get_collections().collections}

        for name, spec in SECURITY_COLLECTIONS.items():
            if name in existing:
                results[name] = False
                continue
            try:
                self.client.create_collection(
                    collection_name=name,
                    vectors_config=VectorParams(
                        size=spec["vector_size"],
                        distance=spec["distance"],
                    ),
                )
                # Create payload indexes
                for field, schema_type in spec.get("payload_indexes", {}).items():
                    try:
                        self.client.create_payload_index(
                            collection_name=name,
                            field_name=field,
                            field_schema=schema_type,
                        )
                    except Exception as e:
                        logger.warning(
                            "Failed to create index %s.%s: %s", name, field, e
                        )
                results[name] = True
                logger.info("Created security collection: %s", name)
            except Exception as e:
                logger.error("Failed to create collection %s: %s", name, e)
                results[name] = False

        return results

    # ------------------------------------------------------------------
    # Generic CRUD helpers
    # ------------------------------------------------------------------
    def upsert_point(
        self,
        collection: str,
        point_id: Optional[str] = None,
        vector: Optional[list[float]] = None,
        payload: Optional[dict] = None,
    ) -> str:
        """Upsert a single point. Returns point_id. No-ops if Qdrant unavailable."""
        pid = point_id or str(uuid.uuid4())
        if not self.available:
            return pid
        vec = vector or [0.0]  # dummy vector for metadata-only collections
        self.client.upsert(
            collection_name=collection,
            points=[
                PointStruct(id=pid, vector=vec, payload=payload or {}),
            ],
        )
        return pid

    def get_point(self, collection: str, point_id: str) -> Optional[dict]:
        """Get a single point by ID. Returns payload or None."""
        if not self.available:
            return None
        try:
            points = self.client.retrieve(
                collection_name=collection,
                ids=[point_id],
                with_payload=True,
                with_vectors=False,
            )
            if points:
                return points[0].payload
        except Exception:
            pass
        return None

    def delete_point(self, collection: str, point_id: str) -> bool:
        """Delete a single point by ID."""
        if not self.available:
            return False
        try:
            self.client.delete(
                collection_name=collection,
                points_selector=[point_id],
            )
            return True
        except Exception:
            return False

    def search_vectors(
        self,
        collection: str,
        vector: list[float],
        filter_conditions: Optional[dict] = None,
        limit: int = 5,
    ) -> list[dict]:
        """Semantic search by vector with optional payload filters."""
        if not self.available:
            return []
        qdrant_filter = None
        if filter_conditions:
            must = []
            for key, value in filter_conditions.items():
                must.append(FieldCondition(key=key, match=MatchValue(value=value)))
            qdrant_filter = Filter(must=must)

        results = self.client.search(
            collection_name=collection,
            query_vector=vector,
            query_filter=qdrant_filter,
            limit=limit,
            with_payload=True,
        )
        return [
            {
                "id": str(r.id),
                "score": r.score,
                "payload": r.payload,
            }
            for r in results
        ]

    def scroll_points(
        self,
        collection: str,
        filter_conditions: Optional[dict] = None,
        limit: int = 100,
        order_by: Optional[str] = None,
    ) -> list[dict]:
        """Scroll through points with optional filters."""
        if not self.available:
            return []
        qdrant_filter = None
        if filter_conditions:
            must = []
            for key, value in filter_conditions.items():
                must.append(FieldCondition(key=key, match=MatchValue(value=value)))
            qdrant_filter = Filter(must=must)

        points, _ = self.client.scroll(
            collection_name=collection,
            scroll_filter=qdrant_filter,
            limit=limit,
            with_payload=True,
            with_vectors=False,
        )

        results = [{"id": str(p.id), "payload": p.payload} for p in points]

        # Client-side sort if order_by specified
        if order_by and results:
            results.sort(key=lambda r: r["payload"].get(order_by, ""))

        return results

    # ------------------------------------------------------------------
    # Baseline-specific helpers
    # ------------------------------------------------------------------
    def get_baseline(self, agent_id: str, metric: str) -> Optional[dict]:
        """Get behavioral baseline for agent+metric."""
        results = self.scroll_points(
            "agent_behavioral_baselines",
            filter_conditions={"agent_id": agent_id, "metric": metric},
            limit=1,
        )
        return results[0]["payload"] if results else None

    def upsert_baseline(self, agent_id: str, metric: str, data: dict) -> str:
        """Upsert behavioral baseline. Uses deterministic ID."""
        point_id = f"baseline-{agent_id}-{metric}"
        payload = {"agent_id": agent_id, "metric": metric, **data}
        return self.upsert_point(
            "agent_behavioral_baselines",
            point_id=point_id,
            payload=payload,
        )

    # ------------------------------------------------------------------
    # Identity session helpers
    # ------------------------------------------------------------------
    def get_identity_session(self, session_id: str) -> Optional[dict]:
        """Get identity session by session_id."""
        results = self.scroll_points(
            "agent_identity_sessions",
            filter_conditions={"session_id": session_id},
            limit=1,
        )
        return results[0]["payload"] if results else None

    def upsert_identity_session(self, credential_id: str, data: dict) -> str:
        """Upsert identity session using credential_id as point ID."""
        return self.upsert_point(
            "agent_identity_sessions",
            point_id=credential_id,
            payload=data,
        )

    # ------------------------------------------------------------------
    # Forensic event helpers
    # ------------------------------------------------------------------
    def store_forensic_event(
        self,
        session_id: str,
        agent_id: str,
        event_type: str,
        payload: dict,
        sequence_number: int = 0,
        correlation_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
    ) -> str:
        """Store a forensic event with automatic retention date."""
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        retention = now + timedelta(days=FORENSIC_RETENTION_DAYS)

        data = {
            "event_id": event_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "event_type": event_type,
            "timestamp": now.isoformat(),
            "sequence_number": sequence_number,
            "payload": payload if isinstance(payload, str) else str(payload),
            "correlation_id": correlation_id or "",
            "parent_event_id": parent_event_id or "",
            "retention_expires_at": retention.isoformat(),
        }
        return self.upsert_point("forensic_events", point_id=event_id, payload=data)

    # ------------------------------------------------------------------
    # Guardian audit log helpers
    # ------------------------------------------------------------------
    def log_guardian_decision(self, decision_data: dict) -> str:
        """Store a Guardian Agent decision."""
        decision_id = decision_data.get("decision_id", str(uuid.uuid4()))
        decision_data["decision_id"] = decision_id
        return self.upsert_point(
            "guardian_audit_log",
            point_id=decision_id,
            payload=decision_data,
        )

    # ------------------------------------------------------------------
    # Coordination score helpers
    # ------------------------------------------------------------------
    def store_coordination_score(self, data: dict) -> str:
        """Store CSS or TUE score entry."""
        point_id = str(uuid.uuid4())
        return self.upsert_point(
            "coordination_scores",
            point_id=point_id,
            payload=data,
        )

    def get_recent_scores(
        self,
        record_type: str,
        identifier: str,
        limit: int = 10,
    ) -> list[dict]:
        """Get recent CSS/TUE scores for an agent or pair."""
        filter_key = "agent_pair" if record_type == "css" else "agent_id"
        results = self.scroll_points(
            "coordination_scores",
            filter_conditions={"record_type": record_type, filter_key: identifier},
            limit=limit,
            order_by="timestamp",
        )
        return [r["payload"] for r in results]
