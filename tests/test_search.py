"""Tests for search module."""

from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from elle_cloud.config import CloudConfig, set_config
from elle_cloud.models import (
    ActionSummary,
    AnonymizedIncidentReport,
    Fingerprint,
    SimilarityQuery,
)
from elle_cloud.search import (
    compute_surface_similarity,
    cosine_similarity,
    search_similar,
)
from elle_cloud.storage import ensure_schema, get_connection, store_incident


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = CloudConfig(
            data_dir=Path(tmpdir) / "data",
            cert_dir=Path(tmpdir) / "certs",
            require_client_cert=False,
        )
        set_config(config)
        conn = get_connection()
        ensure_schema(conn)
        yield conn
        conn.close()


def create_incident(
    incident_id: str,
    domain: str,
    disk_pressure: float = 0.5,
    mem_pressure: float = 0.5,
    outcome: str = "improved",
    entities: tuple[str, ...] = (),
) -> AnonymizedIncidentReport:
    """Create a test incident with specified parameters."""
    return AnonymizedIncidentReport(
        incident_id=incident_id,
        created_at_hour=datetime(2024, 1, 15, 14, 0, 0),
        domain=domain,
        severity="warning",
        status="resolved",
        outcome=outcome,
        fingerprint=Fingerprint(
            disk_pressure=disk_pressure,
            mem_pressure=mem_pressure,
            entities=entities,
        ),
        action_summary=ActionSummary(),
        original_hash=f"hash-{incident_id}",
    )


class TestCosineSimilarity:
    """Tests for cosine similarity calculation."""

    def test_identical_vectors(self):
        """Identical vectors should have similarity 1.0."""
        v = [0.5, 0.5, 0.5, 0.5]
        assert cosine_similarity(v, v) == pytest.approx(1.0)

    def test_orthogonal_vectors(self):
        """Orthogonal vectors should have similarity 0.0."""
        v1 = [1.0, 0.0, 0.0, 0.0]
        v2 = [0.0, 1.0, 0.0, 0.0]
        assert cosine_similarity(v1, v2) == pytest.approx(0.0)

    def test_opposite_vectors(self):
        """Opposite vectors should have similarity -1.0."""
        v1 = [1.0, 0.0, 0.0, 0.0]
        v2 = [-1.0, 0.0, 0.0, 0.0]
        assert cosine_similarity(v1, v2) == pytest.approx(-1.0)

    def test_zero_vector(self):
        """Zero vector should return 0.0."""
        v1 = [0.0, 0.0, 0.0, 0.0]
        v2 = [1.0, 2.0, 3.0, 4.0]
        assert cosine_similarity(v1, v2) == 0.0

    def test_different_length_vectors(self):
        """Different length vectors should return 0.0."""
        v1 = [1.0, 2.0, 3.0]
        v2 = [1.0, 2.0]
        assert cosine_similarity(v1, v2) == 0.0


class TestSurfaceSimilarity:
    """Tests for surface hash similarity calculation."""

    def test_identical_hashes(self):
        """Identical hashes should have high similarity."""
        query = {"config1": "hash1", "config2": "hash2"}
        incident_pre = {"config1": "hash1", "config2": "hash2"}

        sim = compute_surface_similarity(query, incident_pre, None)
        assert sim == pytest.approx(1.0)

    def test_no_overlap(self):
        """No overlapping keys should have 0.0 similarity."""
        query = {"config1": "hash1"}
        incident_pre = {"config2": "hash2"}

        sim = compute_surface_similarity(query, incident_pre, None)
        assert sim == pytest.approx(0.0)

    def test_partial_match(self):
        """Partial matches should have proportional similarity."""
        query = {"config1": "hash1", "config2": "hash2"}
        incident_pre = {"config1": "hash1", "config2": "different"}

        sim = compute_surface_similarity(query, incident_pre, None)
        assert 0.0 < sim < 1.0

    def test_empty_query(self):
        """Empty query should return 0.0."""
        sim = compute_surface_similarity(None, {"config1": "hash1"}, None)
        assert sim == 0.0


class TestSearchSimilar:
    """Tests for similarity search."""

    def test_search_empty_db(self, temp_db):
        """Search on empty database should return no matches."""
        query = SimilarityQuery(
            fingerprint=Fingerprint(disk_pressure=0.5),
            limit=10,
        )
        result = search_similar(query, conn=temp_db)

        assert len(result.matches) == 0
        assert result.total_searched == 0

    def test_search_finds_similar(self, temp_db):
        """Search should find similar incidents."""
        # Store some incidents
        store_incident(
            create_incident("inc1", "disk", disk_pressure=0.8, mem_pressure=0.2),
            conn=temp_db,
        )
        store_incident(
            create_incident("inc2", "disk", disk_pressure=0.7, mem_pressure=0.3),
            conn=temp_db,
        )
        store_incident(
            create_incident("inc3", "net", disk_pressure=0.1, mem_pressure=0.9),
            conn=temp_db,
        )

        # Search for high disk pressure
        query = SimilarityQuery(
            fingerprint=Fingerprint(disk_pressure=0.85, mem_pressure=0.2),
            limit=10,
            min_similarity=0.5,
        )
        result = search_similar(query, conn=temp_db)

        assert len(result.matches) >= 1
        # The disk incidents should score higher
        assert result.matches[0].incident.domain == "disk"

    def test_search_filters_by_domain(self, temp_db):
        """Search should filter by domain when specified."""
        store_incident(
            create_incident("inc1", "disk", disk_pressure=0.8),
            conn=temp_db,
        )
        store_incident(
            create_incident("inc2", "net", disk_pressure=0.8),
            conn=temp_db,
        )

        query = SimilarityQuery(
            fingerprint=Fingerprint(disk_pressure=0.8),
            domain="net",
            limit=10,
        )
        result = search_similar(query, conn=temp_db)

        for match in result.matches:
            assert match.incident.domain == "net"

    def test_search_respects_limit(self, temp_db):
        """Search should respect the limit parameter."""
        for i in range(10):
            store_incident(
                create_incident(f"inc{i}", "disk", disk_pressure=0.5),
                conn=temp_db,
            )

        query = SimilarityQuery(
            fingerprint=Fingerprint(disk_pressure=0.5),
            limit=3,
        )
        result = search_similar(query, conn=temp_db)

        assert len(result.matches) <= 3
