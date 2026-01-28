"""Vector search for similar incidents.

Implements fingerprint-based similarity search using:
- Cosine similarity on 15-dimensional fingerprint vectors
- Surface hash matching for drift correlation
- Pre-filtering by domain/outcome for efficiency
"""

from __future__ import annotations

import sqlite3
import time
from typing import Any

import structlog

from elle_cloud.config import get_config
from elle_cloud.models import (
    AnonymizedIncidentReport,
    CloudIncidentMatch,
    CloudQueryResult,
    Fingerprint,
    IncidentDomain,
    SimilarityQuery,
)
from elle_cloud.storage import (
    _row_to_incident,
    ensure_schema,
    fingerprint_to_vector,
    get_connection,
    unpack_vector,
)

logger = structlog.get_logger()


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    if len(a) != len(b):
        return 0.0

    dot = sum(x * y for x, y in zip(a, b, strict=False))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return float(dot / (norm_a * norm_b))


def compute_surface_similarity(
    query_hashes: dict[str, str] | None,
    incident_hashes_pre: dict[str, str] | None,
    incident_hashes_post: dict[str, str] | None,
) -> float:
    """Compute similarity based on surface hash overlap.

    Returns the Jaccard similarity of matching surface hashes.
    """
    if not query_hashes:
        return 0.0

    # Combine incident hashes
    incident_hashes: dict[str, str] = {}
    if incident_hashes_pre:
        incident_hashes.update(incident_hashes_pre)
    if incident_hashes_post:
        incident_hashes.update(incident_hashes_post)

    if not incident_hashes:
        return 0.0

    # Compute overlap
    common_keys = set(query_hashes.keys()) & set(incident_hashes.keys())
    if not common_keys:
        return 0.0

    matches = sum(1 for k in common_keys if query_hashes[k] == incident_hashes[k])
    total = len(set(query_hashes.keys()) | set(incident_hashes.keys()))

    return matches / total if total > 0 else 0.0


def search_similar(
    query: SimilarityQuery,
    tenant_id: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> CloudQueryResult:
    """Search for similar incidents using fingerprint vectors.

    Uses a two-phase approach:
    1. Pre-filter by domain/outcome if specified
    2. Compute similarity for all candidates
    3. Rank by combined fingerprint + surface similarity
    """
    start_time = time.monotonic()

    own_conn = conn is None
    if own_conn:
        conn = get_connection()
        ensure_schema(conn)

    assert conn is not None

    try:
        cursor = conn.cursor()

        # Build query with filters
        sql = "SELECT * FROM anonymized_incidents WHERE 1=1"
        params: list[Any] = []

        if query.domain:
            sql += " AND domain = ?"
            params.append(query.domain)

        if query.outcome:
            sql += " AND outcome = ?"
            params.append(query.outcome)

        if tenant_id:
            sql += " AND tenant_id = ?"
            params.append(tenant_id)

        # Limit to reasonable search space
        config = get_config()
        sql += " ORDER BY submitted_at DESC LIMIT ?"
        params.append(config.search_limit * 10)

        cursor.execute(sql, params)
        rows = cursor.fetchall()

        total_searched = len(rows)
        if total_searched == 0:
            return CloudQueryResult(
                matches=[],
                total_searched=0,
                query_time_ms=int((time.monotonic() - start_time) * 1000),
            )

        # Convert query fingerprint to vector
        query_vector = fingerprint_to_vector(query.fingerprint)

        # Score all candidates
        scored: list[tuple[sqlite3.Row, float, float, float]] = []

        for row in rows:
            # Unpack stored vector
            incident_vector = unpack_vector(row["fingerprint_vector"])

            # Compute fingerprint similarity
            fp_sim = cosine_similarity(query_vector, incident_vector)

            # Compute surface similarity
            surface_pre = None
            surface_post = None
            if row["surface_hashes_pre_json"]:
                import json
                surface_pre = json.loads(row["surface_hashes_pre_json"])
            if row["surface_hashes_post_json"]:
                import json
                surface_post = json.loads(row["surface_hashes_post_json"])

            surface_sim = compute_surface_similarity(
                query.surface_hashes,
                surface_pre,
                surface_post,
            )

            # Combined score: equal weighting when both signals available
            # If query has no surface hashes, use fingerprint only
            # If incident has no surface hashes, use fingerprint only
            has_query_surface = bool(query.surface_hashes)
            has_incident_surface = bool(surface_pre or surface_post)

            if has_query_surface and has_incident_surface:
                # Both signals available: 50/50 weighting
                combined = 0.5 * fp_sim + 0.5 * surface_sim
            else:
                # Fallback to fingerprint only
                combined = fp_sim

            if combined >= query.min_similarity:
                scored.append((row, fp_sim, surface_sim, combined))

        # Sort by combined score
        scored.sort(key=lambda x: x[3], reverse=True)

        # Build results
        matches: list[CloudIncidentMatch] = []
        for row, fp_sim, surface_sim, combined in scored[: query.limit]:
            incident = _row_to_incident(row)
            matches.append(
                CloudIncidentMatch(
                    cloud_id=row["cloud_id"],
                    fingerprint_similarity=fp_sim,
                    surface_similarity=surface_sim,
                    combined_score=combined,
                    installation_count=1,  # TODO: aggregate by similar incidents
                    resolution_stats={
                        "outcome": incident.outcome,
                        "confidence": incident.confidence,
                        "time_to_resolve_sec": incident.time_to_resolve_sec,
                        "time_to_mitigate_sec": incident.time_to_mitigate_sec,
                    },
                    incident=incident,
                )
            )

        query_time_ms = int((time.monotonic() - start_time) * 1000)

        logger.info(
            "Similarity search completed",
            total_searched=total_searched,
            matches_found=len(matches),
            query_time_ms=query_time_ms,
        )

        return CloudQueryResult(
            matches=matches,
            total_searched=total_searched,
            query_time_ms=query_time_ms,
        )

    finally:
        if own_conn:
            conn.close()


def search_by_surface_hash(
    surface_key: str,
    surface_hash: str,
    snapshot_type: str | None = None,
    limit: int = 10,
    tenant_id: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> list[AnonymizedIncidentReport]:
    """Find incidents with matching surface hashes.

    Useful for drift correlation - finding incidents where a specific
    config/service had the same hash value.
    """
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
        ensure_schema(conn)

    assert conn is not None

    try:
        cursor = conn.cursor()

        sql = """
            SELECT DISTINCT i.*
            FROM anonymized_incidents i
            JOIN surface_hashes s ON i.cloud_id = s.cloud_id
            WHERE s.surface_key = ? AND s.surface_hash = ?
        """
        params: list[Any] = [surface_key, surface_hash]

        if snapshot_type:
            sql += " AND s.snapshot_type = ?"
            params.append(snapshot_type)

        if tenant_id:
            sql += " AND i.tenant_id = ?"
            params.append(tenant_id)

        sql += " ORDER BY i.submitted_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(sql, params)
        rows = cursor.fetchall()

        return [_row_to_incident(row) for row in rows]

    finally:
        if own_conn:
            conn.close()


def get_resolution_recommendations(
    fingerprint: Fingerprint,
    domain: IncidentDomain | None = None,
    tenant_id: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Get resolution recommendations based on similar past incidents.

    Aggregates outcomes from similar incidents to provide guidance.
    """
    # Search for similar incidents
    query = SimilarityQuery(
        fingerprint=fingerprint,
        domain=domain,
        outcome=None,
        limit=20,
        min_similarity=0.5,
    )

    result = search_similar(query, tenant_id=tenant_id, conn=conn)

    if not result.matches:
        return {
            "has_recommendations": False,
            "sample_size": 0,
            "message": "No similar incidents found",
        }

    # Aggregate outcomes
    outcome_counts: dict[str, int] = {}
    total_resolve_time = 0
    resolve_count = 0
    total_mitigate_time = 0
    mitigate_count = 0
    total_confidence = 0.0

    for match in result.matches:
        outcome = match.resolution_stats.get("outcome", "unknown")
        outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1

        if match.resolution_stats.get("time_to_resolve_sec"):
            total_resolve_time += match.resolution_stats["time_to_resolve_sec"]
            resolve_count += 1

        if match.resolution_stats.get("time_to_mitigate_sec"):
            total_mitigate_time += match.resolution_stats["time_to_mitigate_sec"]
            mitigate_count += 1

        if match.resolution_stats.get("confidence"):
            total_confidence += match.resolution_stats["confidence"]

    sample_size = len(result.matches)

    return {
        "has_recommendations": True,
        "sample_size": sample_size,
        "outcome_distribution": {
            k: v / sample_size for k, v in outcome_counts.items()
        },
        "avg_time_to_resolve_sec": total_resolve_time / resolve_count if resolve_count > 0 else None,
        "avg_time_to_mitigate_sec": total_mitigate_time / mitigate_count if mitigate_count > 0 else None,
        "avg_confidence": total_confidence / sample_size if sample_size > 0 else 0.0,
        "top_matches": [
            {
                "cloud_id": m.cloud_id,
                "similarity": m.combined_score,
                "outcome": m.resolution_stats.get("outcome"),
            }
            for m in result.matches[:5]
        ],
    }
