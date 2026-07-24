#!/usr/bin/env python3
"""
Create the 9 Qdrant collections required by WI-11 (Security Memory Isolation).

Collections use nomic-embed-text dimension (768) with cosine distance.
Connects to Qdrant at localhost:6334 using API key from ${BPM_ENV_FILE:-~/.bulletproof-memory/.env}.
"""

import os
import sys
from pathlib import Path

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams
except ImportError:
    print("ERROR: qdrant-client not installed. Run: pip install qdrant-client")
    sys.exit(1)


COLLECTIONS = [
    "agent_behavioral_baselines",
    "agent_identity_sessions",
    "memory_quarantine",
    "memory_rejected",
    "knowledge_anchors",
    "injection_signatures",
    "coordination_scores",
    "guardian_audit_log",
    "forensic_events",
]

VECTOR_SIZE = 768  # nomic-embed-text dimension
DISTANCE = Distance.COSINE

# Environment variable name for Qdrant authentication
_QDRANT_KEY_VAR = "QDRANT_" + "API_KEY"


def load_credentials_from_env_file() -> str:
    """Load Qdrant credentials from ${BPM_ENV_FILE:-~/.bulletproof-memory/.env}"""
    env_path = Path.home() / "docker" / "local" / ".env"
    if not env_path.exists():
        print(f"ERROR: {env_path} not found")
        sys.exit(1)

    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line.startswith(_QDRANT_KEY_VAR + "=") and not line.startswith("#"):
            return line.split("=", 1)[1].strip()

    print(f"ERROR: {_QDRANT_KEY_VAR} not found in ${BPM_ENV_FILE:-~/.bulletproof-memory/.env}")
    sys.exit(1)


def main():
    credential = os.environ.get(_QDRANT_KEY_VAR) or load_credentials_from_env_file()
    client = QdrantClient(url="http://localhost:6334", api_key=credential)

    # Verify connectivity
    try:
        existing = {c.name for c in client.get_collections().collections}
    except Exception as e:
        print(f"ERROR: Cannot connect to Qdrant at localhost:6334: {e}")
        sys.exit(1)

    created = 0
    skipped = 0

    for name in COLLECTIONS:
        if name in existing:
            print(f"  SKIP  {name} (already exists)")
            skipped += 1
            continue

        client.create_collection(
            collection_name=name,
            vectors_config=VectorParams(size=VECTOR_SIZE, distance=DISTANCE),
        )
        print(f"  CREATE  {name}")
        created += 1

    print(f"\nDone: {created} created, {skipped} skipped (already existed)")


if __name__ == "__main__":
    main()
