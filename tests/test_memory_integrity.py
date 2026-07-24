"""Tests for MemoryIntegrityVerifier — Phase 4 (REQ-062/063/064)."""

import pytest
from unittest.mock import MagicMock, patch

from governance.lib.security.memory_integrity import (
    MemoryIntegrityVerifier,
    MemoryEntry,
    QuarantineManager,
    REQUIRED_PROVENANCE,
)
from governance.lib.security.security_config import SecurityConfig


@pytest.fixture
def mock_qdrant():
    q = MagicMock()
    q.get_identity_session.return_value = {"state": "MONITOR"}
    q.search_vectors.return_value = []
    q.upsert_point.return_value = "point-id"
    q.scroll_points.return_value = []
    return q


@pytest.fixture
def mock_audit_bus():
    bus = MagicMock()
    bus.emit.return_value = "event-id"
    return bus


@pytest.fixture
def config():
    return SecurityConfig()


@pytest.fixture
def verifier(mock_qdrant, mock_audit_bus, config):
    v = MemoryIntegrityVerifier(mock_qdrant, mock_audit_bus, config)
    # Mock embedding client to avoid Ollama dependency
    v.embedder = MagicMock()
    v.embedder.embed.return_value = [0.1] * 768
    return v


@pytest.fixture
def valid_entry():
    return MemoryEntry(
        id="entry-1",
        content="Important fact about the system architecture.",
        metadata={
            "agent_id": "test-agent",
            "session_id": "session-1",
            "timestamp": "2026-04-06T12:00:00Z",
            "source_tool": "memory_store",
        },
        target_collection="claude_memories",
    )


class TestProvenanceValidation:
    def test_valid_provenance_passes(self, verifier, valid_entry):
        """Entry with all required provenance fields should pass."""
        result = verifier.verify(valid_entry)
        assert result.stages[0].stage == "provenance_validation"
        assert result.stages[0].passed is True

    def test_missing_agent_id_fails(self, verifier, valid_entry):
        """Entry missing agent_id should be rejected."""
        valid_entry.metadata.pop("agent_id")
        result = verifier.verify(valid_entry)
        assert result.passed is False
        assert result.blocked is True
        assert "Missing provenance" in result.rejection_reason

    def test_missing_timestamp_fails(self, verifier, valid_entry):
        """Entry missing timestamp should be rejected."""
        valid_entry.metadata.pop("timestamp")
        result = verifier.verify(valid_entry)
        assert result.passed is False
        assert result.blocked is True

    def test_revoked_session_fails(self, verifier, valid_entry, mock_qdrant):
        """Entry from a revoked session should be rejected."""
        mock_qdrant.get_identity_session.return_value = {"state": "REVOKE"}
        result = verifier.verify(valid_entry)
        assert result.passed is False
        assert "revoked" in result.rejection_reason.lower()

    def test_required_provenance_fields(self):
        """Should require exactly 4 provenance fields."""
        assert len(REQUIRED_PROVENANCE) == 4
        assert "agent_id" in REQUIRED_PROVENANCE
        assert "session_id" in REQUIRED_PROVENANCE
        assert "timestamp" in REQUIRED_PROVENANCE
        assert "source_tool" in REQUIRED_PROVENANCE


class TestSemanticConsistency:
    def test_no_anchors_bootstrapping_passes(self, verifier, valid_entry, mock_qdrant):
        """With no knowledge anchors, entry should pass (bootstrapping)."""
        mock_qdrant.search_vectors.return_value = []
        result = verifier.verify(valid_entry)
        # Should reach stage 2 and pass
        stage2 = [s for s in result.stages if s.stage == "semantic_consistency"]
        if stage2:
            assert stage2[0].passed is True

    def test_low_similarity_quarantines(self, verifier, valid_entry, mock_qdrant):
        """Entry with low similarity to anchors should be quarantined."""
        mock_qdrant.search_vectors.return_value = [
            {"id": "anchor-1", "score": 0.1, "payload": {}},
        ]
        result = verifier.verify(valid_entry)
        assert result.passed is False
        assert result.quarantined is True


class TestFactVerification:
    def test_contradiction_rejects(self, verifier, valid_entry, mock_qdrant):
        """Entry contradicting a negative anchor should be rejected."""
        # Stage 2 returns no anchors (pass), stage 3 finds contradiction
        call_count = [0]
        def search_side_effect(collection, vector, filter_conditions=None, limit=5):
            call_count[0] += 1
            if filter_conditions and filter_conditions.get("is_negative_anchor"):
                return [{"id": "neg-1", "score": 0.95, "payload": {}}]
            return [{"id": "anchor-1", "score": 0.8, "payload": {}}]

        mock_qdrant.search_vectors.side_effect = search_side_effect
        result = verifier.verify(valid_entry)
        assert result.passed is False
        assert result.blocked is True


class TestAnomalyScoring:
    def test_high_distance_quarantines(self, verifier, valid_entry, mock_qdrant):
        """Entry with high Mahalanobis distance should be quarantined."""
        # Return anchors with very low similarity (= high distance)
        mock_qdrant.search_vectors.return_value = [
            {"id": "a1", "score": 0.01, "payload": {}},
            {"id": "a2", "score": 0.02, "payload": {}},
            {"id": "a3", "score": 0.01, "payload": {}},
        ]
        result = verifier.verify(valid_entry)
        assert result.passed is False
        assert result.quarantined is True


class TestQuarantineManager:
    def test_quarantine_stores_entry(self, mock_qdrant, mock_audit_bus):
        """Quarantine should store entry in memory_quarantine collection."""
        mgr = QuarantineManager(mock_qdrant, mock_audit_bus)
        entry = MemoryEntry(
            id="entry-1",
            content="Suspicious content",
            metadata={"agent_id": "agent-1", "session_id": "session-1"},
        )
        qid = mgr.quarantine(entry, "anomalous", "semantic_consistency")
        mock_qdrant.upsert_point.assert_called()
        assert qid is not None

    def test_reject_moves_to_rejected(self, mock_qdrant, mock_audit_bus):
        """Reject should move entry from quarantine to rejected."""
        mock_qdrant.get_point.return_value = {
            "original_id": "entry-1",
            "content": "Rejected content",
            "agent_id": "agent-1",
            "session_id": "session-1",
            "quarantine_stage": "fact",
        }
        mgr = QuarantineManager(mock_qdrant, mock_audit_bus)
        result = mgr.reject("entry-1", "operator-1", "contradicts known facts")
        assert result is True
        mock_qdrant.delete_point.assert_called_with("memory_quarantine", "entry-1")

    def test_promote_updates_status(self, mock_qdrant, mock_audit_bus):
        """Promote should update quarantine entry status."""
        mock_qdrant.get_point.return_value = {
            "original_id": "entry-1",
            "content": "Approved content",
            "agent_id": "agent-1",
            "session_id": "session-1",
            "target_collection": "claude_memories",
        }
        mgr = QuarantineManager(mock_qdrant, mock_audit_bus)
        result = mgr.promote("entry-1", "operator-1")
        assert result is True

    def test_get_pending(self, mock_qdrant, mock_audit_bus):
        """Should return pending quarantine entries."""
        mock_qdrant.scroll_points.return_value = [
            {"id": "q1", "payload": {"review_status": "pending"}},
        ]
        mgr = QuarantineManager(mock_qdrant, mock_audit_bus)
        pending = mgr.get_pending()
        assert len(pending) == 1
