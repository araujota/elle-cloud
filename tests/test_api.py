"""Tests for API endpoints."""

from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from elle_cloud.config import CloudConfig, set_config
from elle_cloud.main import create_app
from elle_cloud.models import (
    ActionSummary,
    AnonymizedIncidentReport,
    Fingerprint,
)
from elle_cloud.storage import ensure_schema, get_connection


@pytest.fixture
def client():
    """Create a test client with no auth required."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = CloudConfig(
            data_dir=Path(tmpdir) / "data",
            cert_dir=Path(tmpdir) / "certs",
            require_client_cert=False,  # Disable auth for testing
        )
        set_config(config)

        # Initialize database
        config.data_dir.mkdir(parents=True, exist_ok=True)
        conn = get_connection()
        ensure_schema(conn)
        conn.close()

        app = create_app(config)
        yield TestClient(app)


@pytest.fixture
def sample_incident() -> dict:
    """Create a sample incident as a dict for API submission."""
    return {
        "incident_id": "test-incident-123",
        "created_at_hour": "2024-01-15T14:00:00",
        "domain": "disk",
        "severity": "warning",
        "status": "resolved",
        "outcome": "improved",
        "fingerprint": {
            "disk_pressure": 0.85,
            "mem_pressure": 0.4,
            "cpu_pressure": 0.2,
            "service_failures_1h": 2,
            "entities": ["nginx", "/dev/sda1"],
        },
        "action_summary": {
            "total_actions": 5,
            "successful_actions": 4,
            "failed_actions": 1,
        },
        "confidence": 0.85,
        "time_to_resolve_sec": 3600,
        "original_hash": "abc123def456",
    }


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_check(self, client):
        """Health endpoint should return OK."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_readiness_check(self, client):
        """Readiness endpoint should return status."""
        response = client.get("/ready")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "checks" in data
        assert data["checks"]["database"] == "ok"


class TestIncidentEndpoints:
    """Tests for incident submission and retrieval."""

    def test_submit_incident(self, client, sample_incident):
        """Should successfully submit an incident."""
        response = client.post("/v1/incidents", json=sample_incident)
        assert response.status_code == 200

        data = response.json()
        assert data["accepted"] is True
        assert data["cloud_id"].startswith("cloud-")
        assert data["duplicate_of"] is None

    def test_submit_duplicate_incident(self, client, sample_incident):
        """Should detect duplicate incidents."""
        # Submit first time
        response1 = client.post("/v1/incidents", json=sample_incident)
        assert response1.status_code == 200
        cloud_id = response1.json()["cloud_id"]

        # Submit second time
        response2 = client.post("/v1/incidents", json=sample_incident)
        assert response2.status_code == 200

        data = response2.json()
        assert data["accepted"] is False
        assert data["duplicate_of"] == cloud_id

    def test_get_incident(self, client, sample_incident):
        """Should retrieve a submitted incident."""
        # Submit
        submit_response = client.post("/v1/incidents", json=sample_incident)
        cloud_id = submit_response.json()["cloud_id"]

        # Retrieve
        response = client.get(f"/v1/incidents/{cloud_id}")
        assert response.status_code == 200

        data = response.json()
        assert data["incident_id"] == sample_incident["incident_id"]
        assert data["domain"] == sample_incident["domain"]

    def test_get_nonexistent_incident(self, client):
        """Should return 404 for nonexistent incident."""
        response = client.get("/v1/incidents/nonexistent-id")
        assert response.status_code == 404


class TestSimilaritySearch:
    """Tests for similarity search endpoints."""

    def test_search_similar_post(self, client, sample_incident):
        """Should search for similar incidents via POST."""
        # Submit an incident first
        client.post("/v1/incidents", json=sample_incident)

        # Search
        search_query = {
            "fingerprint": {
                "disk_pressure": 0.8,
                "mem_pressure": 0.4,
            },
            "limit": 10,
            "min_similarity": 0.3,
        }
        response = client.post("/v1/incidents/similar", json=search_query)
        assert response.status_code == 200

        data = response.json()
        assert "matches" in data
        assert "total_searched" in data
        assert "query_time_ms" in data

    def test_search_similar_get(self, client, sample_incident):
        """Should search for similar incidents via GET."""
        # Submit an incident first
        client.post("/v1/incidents", json=sample_incident)

        # Search with query params
        response = client.get(
            "/v1/incidents/similar",
            params={
                "disk_pressure": 0.8,
                "mem_pressure": 0.4,
                "limit": 10,
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert "matches" in data

    def test_search_filter_by_domain(self, client, sample_incident):
        """Should filter search by domain."""
        # Submit disk incident
        client.post("/v1/incidents", json=sample_incident)

        # Submit net incident
        net_incident = sample_incident.copy()
        net_incident["incident_id"] = "test-net-123"
        net_incident["domain"] = "net"
        net_incident["original_hash"] = "different-hash"
        client.post("/v1/incidents", json=net_incident)

        # Search only net domain
        search_query = {
            "fingerprint": {"disk_pressure": 0.5},
            "domain": "net",
            "limit": 10,
        }
        response = client.post("/v1/incidents/similar", json=search_query)
        assert response.status_code == 200

        data = response.json()
        for match in data["matches"]:
            assert match["incident"]["domain"] == "net"


class TestStatsEndpoints:
    """Tests for statistics endpoints."""

    def test_get_domain_stats(self, client, sample_incident):
        """Should return domain statistics."""
        # Submit an incident
        client.post("/v1/incidents", json=sample_incident)

        response = client.get("/v1/stats/disk")
        assert response.status_code == 200

        data = response.json()
        assert data["domain"] == "disk"
        assert data["total_incidents"] >= 1

    def test_get_all_stats(self, client, sample_incident):
        """Should return overall statistics."""
        # Submit an incident
        client.post("/v1/incidents", json=sample_incident)

        response = client.get("/v1/stats")
        assert response.status_code == 200

        data = response.json()
        assert "total_incidents" in data
        assert data["total_incidents"] >= 1
