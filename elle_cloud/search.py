"""Vector search for similar incidents.

Implements fingerprint-based similarity search using:
- pgvector cosine distance on fingerprint vectors (31D)
- Surface hash matching for drift correlation
- Pre-filtering by domain/outcome for efficiency
"""

from __future__ import annotations

import time
from typing import Any

import psycopg
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
    fingerprint_to_vector,
    get_db,
)

logger = structlog.get_logger()


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
    conn: psycopg.Connection | None = None,
) -> CloudQueryResult:
    """Search for similar incidents using pgvector cosine distance.

    Uses a two-phase approach:
    1. Pre-filter by domain/outcome and rank by vector distance (HNSW index)
    2. Compute surface similarity for candidates (Python)
    3. Combine scores and rank by combined similarity
    """
    start_time = time.monotonic()

    if conn is not None:
        return _search_similar_impl(conn, query, tenant_id, start_time)
    with get_db() as db_conn:
        return _search_similar_impl(db_conn, query, tenant_id, start_time)


def _search_similar_impl(
    conn: psycopg.Connection,
    query: SimilarityQuery,
    tenant_id: str | None,
    start_time: float,
) -> CloudQueryResult:
    """Internal implementation of search_similar."""
    config = get_config()

    # Convert query fingerprint to vector
    query_vector = fingerprint_to_vector(query.fingerprint)

    # Build query with pgvector cosine distance
    # <=> returns cosine distance (0 = identical, 2 = opposite)
    # similarity = 1 - distance
    sql = """
        SELECT *,
            1 - (fingerprint_vector <=> %s::vector) as fp_similarity
        FROM anonymized_incidents
        WHERE 1=1
    """
    params: list[Any] = [query_vector]

    if query.domain:
        sql += " AND domain = %s"
        params.append(query.domain)

    if query.outcome:
        sql += " AND outcome = %s"
        params.append(query.outcome)

    if tenant_id:
        sql += " AND tenant_id = %s"
        params.append(tenant_id)

    # Order by vector distance (uses HNSW index) and fetch candidates
    sql += " ORDER BY fingerprint_vector <=> %s::vector LIMIT %s"
    params.append(query_vector)
    params.append(config.search_limit * 10)

    rows = conn.execute(sql, params).fetchall()

    total_searched = len(rows)
    if total_searched == 0:
        return CloudQueryResult(
            matches=[],
            total_searched=0,
            query_time_ms=int((time.monotonic() - start_time) * 1000),
        )

    # Score all candidates with combined fingerprint + surface similarity
    scored: list[tuple[dict[str, Any], float, float, float]] = []

    for row in rows:
        fp_sim = float(row["fp_similarity"])

        # Compute surface similarity (JSONB already deserialized)
        surface_sim = compute_surface_similarity(
            query.surface_hashes,
            row["surface_hashes_pre_json"],
            row["surface_hashes_post_json"],
        )

        # Combined score: equal weighting when both signals available
        has_query_surface = bool(query.surface_hashes)
        has_incident_surface = bool(
            row["surface_hashes_pre_json"] or row["surface_hashes_post_json"]
        )

        if has_query_surface and has_incident_surface:
            combined = 0.5 * fp_sim + 0.5 * surface_sim
        else:
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
                installation_count=1,
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


def search_by_surface_hash(
    surface_key: str,
    surface_hash: str,
    snapshot_type: str | None = None,
    limit: int = 10,
    tenant_id: str | None = None,
) -> list[AnonymizedIncidentReport]:
    """Find incidents with matching surface hashes.

    Useful for drift correlation - finding incidents where a specific
    config/service had the same hash value.
    """
    with get_db() as conn:
        sql = """
            SELECT DISTINCT i.*
            FROM anonymized_incidents i
            JOIN surface_hashes s ON i.cloud_id = s.cloud_id
            WHERE s.surface_key = %s AND s.surface_hash = %s
        """
        params: list[Any] = [surface_key, surface_hash]

        if snapshot_type:
            sql += " AND s.snapshot_type = %s"
            params.append(snapshot_type)

        if tenant_id:
            sql += " AND i.tenant_id = %s"
            params.append(tenant_id)

        sql += " ORDER BY i.submitted_at DESC LIMIT %s"
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()

        return [_row_to_incident(row) for row in rows]


def get_resolution_recommendations(
    fingerprint: Fingerprint,
    domain: IncidentDomain | None = None,
    tenant_id: str | None = None,
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

    result = search_similar(query, tenant_id=tenant_id)

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
