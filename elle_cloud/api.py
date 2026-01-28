"""FastAPI routes for ELLE Cloud.

Endpoints:
- POST /v1/incidents - Submit anonymized incident
- GET /v1/incidents/similar - Query similar incidents
- GET /v1/stats/{domain} - Get resolution statistics
- POST /v1/admin/certs - Register certificate (admin)
- DELETE /v1/admin/certs/{fp} - Revoke certificate (admin)
- GET /health - Liveness probe
- GET /ready - Readiness probe
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.status import HTTP_404_NOT_FOUND

from elle_cloud.auth import AuthContext, get_auth_context, require_admin
from elle_cloud.config import get_config
from elle_cloud.models import (
    AnonymizedIncidentReport,
    CloudQueryResult,
    CloudSubmissionResult,
    DomainStats,
    Fingerprint,
    IncidentDomain,
    IncidentOutcome,
    SimilarityQuery,
)
from elle_cloud.search import search_similar
from elle_cloud.storage import (
    get_domain_stats,
    get_incident,
    get_incident_count,
    list_certificates,
    log_audit,
    register_certificate,
    revoke_certificate,
    store_incident,
)

# Rate limiter instance - shared with main.py
limiter = Limiter(key_func=get_remote_address)

logger = structlog.get_logger()

# =============================================================================
# Routers
# =============================================================================

router = APIRouter()
admin_router = APIRouter(prefix="/admin", tags=["admin"])
health_router = APIRouter(tags=["health"])


# =============================================================================
# Health Endpoints
# =============================================================================


@health_router.get("/health")
async def health_check() -> dict[str, str]:
    """Liveness probe - always returns OK if service is running."""
    return {"status": "ok"}


@health_router.get("/ready")
async def readiness_check() -> dict[str, Any]:
    """Readiness probe - checks if service can handle requests."""
    config = get_config()

    # Check database
    try:
        count = get_incident_count()
        db_ok = True
    except Exception as e:
        logger.error("Database check failed", error=str(e))
        db_ok = False
        count = 0

    # Check certificates
    try:
        certs_ok = config.ca_cert_path.exists() and config.server_cert_path.exists()
    except Exception:
        certs_ok = False

    ready = db_ok and certs_ok

    return {
        "status": "ready" if ready else "not_ready",
        "checks": {
            "database": "ok" if db_ok else "error",
            "certificates": "ok" if certs_ok else "missing",
        },
        "incident_count": count,
        "mode": config.mode.value,
        "org_name": config.org_name,
    }


# =============================================================================
# Incident Endpoints
# =============================================================================


@router.post("/v1/incidents", response_model=CloudSubmissionResult)
@limiter.limit("30/minute")
async def submit_incident(
    request: Request,
    incident: AnonymizedIncidentReport,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> CloudSubmissionResult:
    """Submit an anonymized incident report.

    The incident is stored with tenant isolation based on the client certificate.
    Duplicate incidents (same original_hash) are rejected.
    """
    logger.info(
        "Incident submission",
        installation_id=auth.installation_id,
        incident_id=incident.incident_id,
        domain=incident.domain,
    )

    # Store incident
    cloud_id, accepted, duplicate_of = store_incident(
        incident=incident,
        tenant_id=auth.tenant_id,
        installation_fingerprint=auth.cert_fingerprint,
    )

    # Count similar incidents
    if accepted:
        query = SimilarityQuery(
            fingerprint=incident.fingerprint,
            domain=incident.domain,
            limit=100,
            min_similarity=0.7,
        )
        result = search_similar(query, tenant_id=auth.tenant_id)
        similar_count = len(result.matches)
    else:
        similar_count = 0

    return CloudSubmissionResult(
        cloud_id=cloud_id,
        accepted=accepted,
        duplicate_of=duplicate_of,
        similar_count=similar_count,
    )


# NOTE: /similar routes MUST come before /{cloud_id} to avoid path matching issues
@router.post("/v1/incidents/similar", response_model=CloudQueryResult)
@limiter.limit("60/minute")
async def query_similar_incidents(
    request: Request,
    query: SimilarityQuery,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> CloudQueryResult:
    """Query for similar incidents using fingerprint matching.

    Returns incidents ranked by combined fingerprint and surface hash similarity.
    """
    logger.info(
        "Similarity query",
        installation_id=auth.installation_id,
        domain=query.domain,
        limit=query.limit,
    )

    return search_similar(query, tenant_id=auth.tenant_id)


@router.get("/v1/incidents/similar", response_model=CloudQueryResult)
@limiter.limit("60/minute")
async def query_similar_get(
    request: Request,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    domain: IncidentDomain | None = Query(default=None),
    outcome: IncidentOutcome | None = Query(default=None),
    limit: int = Query(default=10, ge=1, le=100),
    min_similarity: float = Query(default=0.3, ge=0.0, le=1.0),
    # Fingerprint components as query params with upper bounds
    disk_pressure: float = Query(default=0.0, ge=0.0, le=1.0),
    mem_pressure: float = Query(default=0.0, ge=0.0, le=1.0),
    cpu_pressure: float = Query(default=0.0, ge=0.0, le=10.0),  # Clamped upper bound
    oom_count_1h: int = Query(default=0, ge=0, le=10000),  # Reasonable upper bound
    service_failures_1h: int = Query(default=0, ge=0, le=10000),  # Reasonable upper bound
) -> CloudQueryResult:
    """Query similar incidents via GET (for simple queries)."""
    fingerprint = Fingerprint(
        disk_pressure=disk_pressure,
        mem_pressure=mem_pressure,
        cpu_pressure=cpu_pressure,
        oom_count_1h=oom_count_1h,
        service_failures_1h=service_failures_1h,
    )

    query = SimilarityQuery(
        fingerprint=fingerprint,
        domain=domain,
        outcome=outcome,
        limit=limit,
        min_similarity=min_similarity,
    )

    return search_similar(query, tenant_id=auth.tenant_id)


@router.get("/v1/incidents/{cloud_id}")
async def get_incident_by_id(
    cloud_id: str,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> AnonymizedIncidentReport:
    """Get an incident by its cloud ID.

    Tenant isolation: Only returns incident if it belongs to the authenticated tenant.
    """
    incident = get_incident(cloud_id, tenant_id=auth.tenant_id)
    if not incident:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail=f"Incident {cloud_id} not found",
        )
    return incident


# =============================================================================
# Statistics Endpoints
# =============================================================================


@router.get("/v1/stats/{domain}", response_model=DomainStats)
async def get_stats_for_domain(
    domain: IncidentDomain,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> DomainStats:
    """Get aggregate statistics for a domain.

    Returns outcome distribution, average resolution times, and common entities.
    """
    logger.info(
        "Stats query",
        installation_id=auth.installation_id,
        domain=domain,
    )

    return get_domain_stats(domain, tenant_id=auth.tenant_id)


@router.get("/v1/stats")
async def get_all_stats(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> dict[str, Any]:
    """Get overall statistics across all domains."""
    config = get_config()
    total = get_incident_count(tenant_id=auth.tenant_id)

    return {
        "total_incidents": total,
        "tenant_id": auth.tenant_id,
        "mode": config.mode.value,
        "org_name": config.org_name,
    }


# =============================================================================
# Admin Endpoints
# =============================================================================


class CertificateRegistration(BaseModel):
    """Request to register a certificate."""

    cert_fingerprint: str = Field(description="SHA-256 fingerprint of certificate")
    organization: str = Field(description="Organization name")
    installation_id: str | None = Field(default=None, description="Installation ID")
    common_name: str | None = Field(default=None, description="Certificate CN")
    expires_at: datetime = Field(description="Certificate expiration time")


@admin_router.post("/certs")
async def register_cert(
    registration: CertificateRegistration,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> dict[str, Any]:
    """Register a trusted certificate (admin only)."""
    require_admin(auth)

    success = register_certificate(
        cert_fingerprint=registration.cert_fingerprint,
        organization=registration.organization,
        installation_id=registration.installation_id,
        common_name=registration.common_name,
        issued_at=datetime.now(timezone.utc),
        expires_at=registration.expires_at,
    )

    # Audit log the registration attempt
    log_audit(
        action="cert.register",
        actor=auth,
        resource_type="certificate",
        resource_id=registration.cert_fingerprint[:16],
        details=f"organization={registration.organization}, success={success}",
    )

    return {
        "registered": success,
        "fingerprint": registration.cert_fingerprint,
    }


@admin_router.delete("/certs/{fingerprint}")
async def revoke_cert(
    fingerprint: str,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    reason: str = Query(default="manual revocation"),
) -> dict[str, Any]:
    """Revoke a trusted certificate (admin only)."""
    require_admin(auth)

    success = revoke_certificate(fingerprint, reason=reason)

    # Audit log the revocation attempt
    log_audit(
        action="cert.revoke",
        actor=auth,
        resource_type="certificate",
        resource_id=fingerprint[:16] if len(fingerprint) >= 16 else fingerprint,
        details=f"reason={reason}, success={success}",
    )

    if not success:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail=f"Certificate {fingerprint} not found",
        )

    return {
        "revoked": True,
        "fingerprint": fingerprint,
        "reason": reason,
    }


@admin_router.get("/certs")
async def list_certs(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    include_revoked: bool = Query(default=False),
) -> list[dict[str, Any]]:
    """List all trusted certificates (admin only)."""
    require_admin(auth)

    return list_certificates(include_revoked=include_revoked)
