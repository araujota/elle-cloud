"""Tests for storage module."""

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
)
from elle_cloud.storage import (
    ensure_schema,
    fingerprint_to_vector,
    get_connection,
    get_incident,
    get_incident_count,
    pack_vector,
    store_incident,
    unpack_vector,
)


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


@pytest.fixture
def sample_incident() -> AnonymizedIncidentReport:
    """Create a sample anonymized incident."""
    return AnonymizedIncidentReport(
        incident_id="test-incident-123",
        created_at_hour=datetime(2024, 1, 15, 14, 0, 0),
        domain="disk",
        severity="warning",
        status="resolved",
        outcome="improved",
        fingerprint=Fingerprint(
            disk_pressure=0.85,
            mem_pressure=0.4,
            cpu_pressure=0.2,
            service_failures_1h=2,
            entities=("nginx", "/dev/sda1"),
        ),
        action_summary=ActionSummary(
            total_actions=5,
            successful_actions=4,
            failed_actions=1,
            shell_count=3,
            capability_count=2,
        ),
        confidence=0.85,
        time_to_resolve_sec=3600,
        original_hash="abc123def456",
    )


class TestVectorOperations:
    """Tests for fingerprint vector operations."""

    def test_fingerprint_to_vector_basic(self):
        """Test basic fingerprint to vector conversion."""
        fp = Fingerprint(
            disk_pressure=0.5,
            mem_pressure=0.3,
            swap_pressure=0.1,
            cpu_pressure=0.8,
        )
        vector = fingerprint_to_vector(fp)

        assert len(vector) == 15
        assert vector[0] == 0.5  # disk_pressure
        assert vector[1] == 0.3  # mem_pressure
        assert vector[2] == 0.1  # swap_pressure
        assert vector[3] == 0.8  # cpu_pressure (clamped)

    def test_fingerprint_to_vector_clamping(self):
        """Test that values are properly clamped."""
        fp = Fingerprint(
            cpu_pressure=5.0,  # Should be clamped to 1.0
            oom_count_1h=100,  # Should be normalized
        )
        vector = fingerprint_to_vector(fp)

        assert vector[3] == 1.0  # cpu_pressure clamped
        assert vector[4] == 1.0  # oom_count normalized to max

    def test_pack_unpack_vector(self):
        """Test vector packing and unpacking."""
        original = [0.1, 0.2, 0.3, 0.4, 0.5]
        packed = pack_vector(original)
        unpacked = unpack_vector(packed)

        assert len(unpacked) == len(original)
        for a, b in zip(original, unpacked, strict=False):
            assert abs(a - b) < 1e-6


class TestIncidentStorage:
    """Tests for incident storage operations."""

    def test_store_incident(self, temp_db, sample_incident):
        """Test storing an incident."""
        cloud_id, accepted, duplicate = store_incident(
            sample_incident, conn=temp_db
        )

        assert accepted is True
        assert duplicate is None
        assert cloud_id.startswith("cloud-")

    def test_store_duplicate_incident(self, temp_db, sample_incident):
        """Test that duplicate incidents are detected."""
        # Store first time
        cloud_id1, accepted1, _ = store_incident(sample_incident, conn=temp_db)
        assert accepted1 is True

        # Store second time - should be duplicate
        cloud_id2, accepted2, duplicate = store_incident(
            sample_incident, conn=temp_db
        )
        assert accepted2 is False
        assert duplicate == cloud_id1
        assert cloud_id2 == cloud_id1

    def test_get_incident(self, temp_db, sample_incident):
        """Test retrieving an incident."""
        cloud_id, _, _ = store_incident(sample_incident, conn=temp_db)

        retrieved = get_incident(cloud_id, conn=temp_db)

        assert retrieved is not None
        assert retrieved.incident_id == sample_incident.incident_id
        assert retrieved.domain == sample_incident.domain
        assert retrieved.outcome == sample_incident.outcome
        assert retrieved.fingerprint.disk_pressure == sample_incident.fingerprint.disk_pressure

    def test_get_incident_count(self, temp_db, sample_incident):
        """Test counting incidents."""
        assert get_incident_count(conn=temp_db) == 0

        store_incident(sample_incident, conn=temp_db)
        assert get_incident_count(conn=temp_db) == 1

        # Create a different incident
        incident2 = AnonymizedIncidentReport(
            incident_id="test-incident-456",
            created_at_hour=datetime(2024, 1, 15, 15, 0, 0),
            domain="net",
            severity="error",
            status="resolved",
            outcome="improved",
            fingerprint=Fingerprint(),
            action_summary=ActionSummary(),
            original_hash="xyz789",
        )
        store_incident(incident2, conn=temp_db)
        assert get_incident_count(conn=temp_db) == 2
