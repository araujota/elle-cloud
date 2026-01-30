"""PostgreSQL storage for ELLE Cloud.

Handles:
- Anonymized incident storage with pgvector fingerprints
- Surface hash indexing for drift correlation
- Certificate trust store for mTLS
- Deduplication via original_hash
- Audit logging for security events
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import psycopg
import structlog
from pgvector.psycopg import register_vector
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

if TYPE_CHECKING:
    from elle_cloud.auth import AuthContext

from elle_cloud.config import get_config
from elle_cloud.models import (
    ActionSummary,
    AnonymizedIncidentReport,
    DomainStats,
    Fingerprint,
    IncidentDomain,
)

logger = structlog.get_logger()

# =============================================================================
# Connection Pool Management
# =============================================================================

_pool: ConnectionPool | None = None


def configure_pool(conninfo: str | None = None) -> ConnectionPool:
    """Create and configure the connection pool.

    Auto-configures using ELLE_CLOUD_* env vars if no conninfo provided.
    Safe to call multiple times - returns existing pool if already configured.
    """
    global _pool
    if _pool is not None:
        return _pool

    if conninfo is None:
        conninfo = get_config().conninfo

    def on_connect(conn: psycopg.Connection) -> None:
        register_vector(conn)

    _pool = ConnectionPool(
        conninfo=conninfo,
        min_size=2,
        max_size=10,
        kwargs={"row_factory": dict_row, "autocommit": False},
        configure=on_connect,
    )
    return _pool


def get_pool() -> ConnectionPool:
    """Get the active connection pool. Auto-configures if needed."""
    if _pool is None:
        configure_pool()
    assert _pool is not None
    return _pool


def close_pool() -> None:
    """Close the connection pool."""
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


@contextmanager
def get_db() -> Generator[psycopg.Connection, None, None]:
    """Context manager for database connections from pool."""
    pool = get_pool()
    with pool.connection() as conn:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


# =============================================================================
# Schema
# =============================================================================

SCHEMA_VERSION = 4

_SCHEMA_STATEMENTS = [
    "CREATE EXTENSION IF NOT EXISTS vector",

    """CREATE TABLE IF NOT EXISTS anonymized_incidents (
        id SERIAL PRIMARY KEY,
        incident_id TEXT UNIQUE NOT NULL,
        cloud_id TEXT UNIQUE NOT NULL,
        domain TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        outcome TEXT NOT NULL,
        created_at_hour TIMESTAMPTZ NOT NULL,
        updated_at_hour TIMESTAMPTZ,
        fingerprint_vector vector(31) NOT NULL,
        fingerprint_json JSONB NOT NULL,
        action_summary_json JSONB NOT NULL,
        telemetry_pre_json JSONB,
        telemetry_post_json JSONB,
        surface_hashes_pre_json JSONB,
        surface_hashes_post_json JSONB,
        surface_drift_json JSONB,
        drift_explanations_json JSONB,
        control_surface_pre_json JSONB,
        control_surface_post_json JSONB,
        confidence REAL NOT NULL,
        time_to_mitigate_sec INTEGER,
        time_to_resolve_sec INTEGER,
        trigger_source TEXT NOT NULL DEFAULT 'manual',
        anonymization_version TEXT NOT NULL DEFAULT '1.0',
        detail_level TEXT NOT NULL DEFAULT 'hashes',
        original_hash TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL DEFAULT 'global',
        submitted_at TIMESTAMPTZ NOT NULL,
        installation_fingerprint TEXT
    )""",

    "CREATE INDEX IF NOT EXISTS idx_incidents_domain ON anonymized_incidents(domain)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_outcome ON anonymized_incidents(outcome)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_tenant ON anonymized_incidents(tenant_id)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_submitted ON anonymized_incidents(submitted_at)",

    """CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint_vector
        ON anonymized_incidents USING hnsw (fingerprint_vector vector_cosine_ops)""",

    """CREATE TABLE IF NOT EXISTS surface_hashes (
        id SERIAL PRIMARY KEY,
        cloud_id TEXT NOT NULL,
        snapshot_type TEXT NOT NULL CHECK (snapshot_type IN ('pre', 'post')),
        surface_key TEXT NOT NULL,
        surface_hash TEXT NOT NULL,
        FOREIGN KEY (cloud_id) REFERENCES anonymized_incidents(cloud_id) ON DELETE CASCADE
    )""",

    "CREATE INDEX IF NOT EXISTS idx_surface_cloud_id ON surface_hashes(cloud_id)",
    "CREATE INDEX IF NOT EXISTS idx_surface_key_hash ON surface_hashes(surface_key, surface_hash)",

    """CREATE TABLE IF NOT EXISTS trusted_certificates (
        id SERIAL PRIMARY KEY,
        cert_fingerprint TEXT UNIQUE NOT NULL,
        organization TEXT NOT NULL,
        installation_id TEXT,
        common_name TEXT,
        issued_at TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE,
        revoked_at TIMESTAMPTZ,
        revoked_reason TEXT,
        is_admin BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",

    "CREATE INDEX IF NOT EXISTS idx_certs_fingerprint ON trusted_certificates(cert_fingerprint)",
    "CREATE INDEX IF NOT EXISTS idx_certs_installation ON trusted_certificates(installation_id)",
    "CREATE INDEX IF NOT EXISTS idx_certs_revoked ON trusted_certificates(revoked)",
    "CREATE INDEX IF NOT EXISTS idx_certs_admin ON trusted_certificates(is_admin)",

    """CREATE TABLE IF NOT EXISTS audit_log (
        id BIGSERIAL PRIMARY KEY,
        timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
        action TEXT NOT NULL,
        actor_fingerprint TEXT,
        actor_installation_id TEXT,
        resource_type TEXT,
        resource_id TEXT,
        details TEXT
    )""",

    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)",
    "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_fingerprint)",

    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)",
]


def ensure_schema(conn: psycopg.Connection | None = None) -> None:
    """Ensure database schema is up to date."""
    if conn is not None:
        _ensure_schema_impl(conn)
    else:
        with get_db() as db_conn:
            _ensure_schema_impl(db_conn)


def _ensure_schema_impl(conn: psycopg.Connection) -> None:
    """Internal schema initialization."""
    row = conn.execute(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
        "WHERE table_name = 'schema_version')"
    ).fetchone()

    if not row or not row["exists"]:
        # Fresh database - create schema
        for stmt in _SCHEMA_STATEMENTS:
            conn.execute(stmt)
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (%s)",
            (SCHEMA_VERSION,),
        )
        logger.info("Created database schema", version=SCHEMA_VERSION)
        return

    # Check version and migrate if needed
    row = conn.execute("SELECT version FROM schema_version").fetchone()
    current_version = row["version"] if row else 0

    if current_version < SCHEMA_VERSION:
        conn.execute(
            "UPDATE schema_version SET version = %s",
            (SCHEMA_VERSION,),
        )
        logger.info(
            "Migrated schema",
            from_version=current_version,
            to_version=SCHEMA_VERSION,
        )


# =============================================================================
# Fingerprint Vector Operations
# =============================================================================


def fingerprint_to_vector(fp: Fingerprint) -> list[float]:
    """Convert Fingerprint to 31-dimensional vector for similarity search.

    Dimensions 0-14: Original fields (backward-compatible)
    Dimensions 15-30: Monitoring sprint expansion fields
    """
    return [
        # Original 15 dimensions (unchanged)
        fp.disk_pressure,                                    # 0
        fp.mem_pressure,                                     # 1
        fp.swap_pressure,                                    # 2
        min(fp.cpu_pressure, 1.0),                           # 3
        min(fp.oom_count_1h / 10.0, 1.0),                   # 4
        min(fp.net_flaps_1h / 10.0, 1.0),                   # 5
        min(fp.service_failures_1h / 10.0, 1.0),            # 6
        min(fp.auth_failures_1h / 10.0, 1.0),               # 7
        min(fp.smart_pct_used_max / 100.0, 1.0),            # 8
        min(fp.smart_media_errors / 10.0, 1.0),             # 9
        min(fp.temp_max_c / 100.0, 1.0),                    # 10
        min(fp.docker_exited_count / 10.0, 1.0),            # 11
        len(fp.entities) / 20.0 if fp.entities else 0.0,    # 12
        1.0 if fp.oom_count_1h > 0 else 0.0,                # 13
        1.0 if fp.service_failures_1h > 0 else 0.0,         # 14
        # New 16 dimensions (monitoring sprint)
        fp.inode_pressure,                                    # 15
        fp.io_latency_pressure,                               # 16
        fp.conntrack_pressure,                                # 17
        fp.tcp_retransmit_rate,                               # 18
        min(fp.zombie_count / 20.0, 1.0),                    # 19
        float(fp.pending_reboot),                             # 20
        1.0 - min(fp.cert_expiry_days_min / 365.0, 1.0),    # 21
        min(fp.dns_p95_ms / 1000.0, 1.0),                   # 22
        fp.cgroup_mem_pressure,                               # 23
        fp.psi_cpu_avg10,                                     # 24
        fp.psi_memory_avg10,                                  # 25
        min(fp.security_events_1h / 100.0, 1.0),            # 26
        fp.gpu_mem_pressure,                                  # 27
        fp.gpu_util_pressure,                                 # 28
        fp.gpu_thermal_pressure,                              # 29
        min(fp.gpu_ecc_errors_1h / 10.0, 1.0),              # 30
    ]


# =============================================================================
# Incident Storage
# =============================================================================


def store_incident(
    incident: AnonymizedIncidentReport,
    tenant_id: str = "global",
    installation_fingerprint: str | None = None,
    conn: psycopg.Connection | None = None,
) -> tuple[str, bool, str | None]:
    """Store an anonymized incident.

    Returns:
        Tuple of (cloud_id, accepted, duplicate_of)
        - cloud_id: The assigned cloud ID
        - accepted: True if newly stored, False if duplicate
        - duplicate_of: Cloud ID of existing incident if duplicate
    """
    if conn is not None:
        return _store_incident_impl(conn, incident, tenant_id, installation_fingerprint)
    with get_db() as db_conn:
        return _store_incident_impl(db_conn, incident, tenant_id, installation_fingerprint)


def _store_incident_impl(
    conn: psycopg.Connection,
    incident: AnonymizedIncidentReport,
    tenant_id: str,
    installation_fingerprint: str | None,
) -> tuple[str, bool, str | None]:
    """Internal implementation of store_incident."""
    # Check for duplicate by original_hash
    row = conn.execute(
        "SELECT cloud_id FROM anonymized_incidents WHERE original_hash = %s",
        (incident.original_hash,),
    ).fetchone()

    if row:
        logger.debug("Duplicate incident detected", original_hash=incident.original_hash)
        return row["cloud_id"], False, row["cloud_id"]

    # Generate cloud ID with full UUID
    cloud_id = f"cloud-{uuid.uuid4().hex}"

    # Convert fingerprint to vector (pgvector handles list -> vector)
    vector = fingerprint_to_vector(incident.fingerprint)

    # Prepare drift explanations
    drift_explanations = None
    if incident.drift_explanations:
        drift_explanations = [
            de.model_dump() if hasattr(de, "model_dump") else de
            for de in incident.drift_explanations
        ]

    # Insert incident
    conn.execute(
        """
        INSERT INTO anonymized_incidents (
            incident_id, cloud_id, domain, severity, status, outcome,
            created_at_hour, updated_at_hour, fingerprint_vector, fingerprint_json,
            action_summary_json, telemetry_pre_json, telemetry_post_json,
            surface_hashes_pre_json, surface_hashes_post_json, surface_drift_json,
            drift_explanations_json, control_surface_pre_json, control_surface_post_json,
            confidence, time_to_mitigate_sec, time_to_resolve_sec,
            trigger_source, anonymization_version, detail_level, original_hash,
            tenant_id, submitted_at, installation_fingerprint
        ) VALUES (
            %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s,
            %s, %s, %s,
            %s, %s, %s,
            %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s
        )
        """,
        (
            incident.incident_id,
            cloud_id,
            incident.domain,
            incident.severity,
            incident.status,
            incident.outcome,
            incident.created_at_hour,
            incident.updated_at_hour,
            vector,
            Jsonb(incident.fingerprint.model_dump()),
            Jsonb(incident.action_summary.model_dump()),
            Jsonb(incident.telemetry_pre) if incident.telemetry_pre else None,
            Jsonb(incident.telemetry_post) if incident.telemetry_post else None,
            Jsonb(incident.surface_hashes_pre) if incident.surface_hashes_pre else None,
            Jsonb(incident.surface_hashes_post) if incident.surface_hashes_post else None,
            Jsonb(incident.surface_drift) if incident.surface_drift else None,
            Jsonb(drift_explanations) if drift_explanations else None,
            Jsonb(incident.control_surface_pre) if incident.control_surface_pre else None,
            Jsonb(incident.control_surface_post) if incident.control_surface_post else None,
            incident.confidence,
            incident.time_to_mitigate_sec,
            incident.time_to_resolve_sec,
            incident.trigger_source,
            incident.anonymization_version,
            incident.detail_level,
            incident.original_hash,
            tenant_id,
            datetime.now(timezone.utc),
            installation_fingerprint,
        ),
    )

    # Store surface hashes for indexing
    if incident.surface_hashes_pre:
        _store_surface_hashes(conn, cloud_id, "pre", incident.surface_hashes_pre)
    if incident.surface_hashes_post:
        _store_surface_hashes(conn, cloud_id, "post", incident.surface_hashes_post)

    logger.info("Stored incident", cloud_id=cloud_id, domain=incident.domain)
    return cloud_id, True, None


def _store_surface_hashes(
    conn: psycopg.Connection,
    cloud_id: str,
    snapshot_type: str,
    hashes: dict[str, str],
) -> None:
    """Store surface hashes for an incident."""
    for key, hash_value in hashes.items():
        conn.execute(
            """
            INSERT INTO surface_hashes (cloud_id, snapshot_type, surface_key, surface_hash)
            VALUES (%s, %s, %s, %s)
            """,
            (cloud_id, snapshot_type, key, hash_value),
        )


def get_incident(
    cloud_id: str,
    tenant_id: str | None = None,
    conn: psycopg.Connection | None = None,
) -> AnonymizedIncidentReport | None:
    """Get an incident by cloud ID.

    Args:
        cloud_id: The cloud ID of the incident.
        tenant_id: Optional tenant ID for tenant isolation.
        conn: Optional database connection.

    Returns:
        The incident if found (and belongs to tenant if specified), None otherwise.
    """
    if conn is not None:
        return _get_incident_impl(conn, cloud_id, tenant_id)
    with get_db() as db_conn:
        return _get_incident_impl(db_conn, cloud_id, tenant_id)


def _get_incident_impl(
    conn: psycopg.Connection,
    cloud_id: str,
    tenant_id: str | None,
) -> AnonymizedIncidentReport | None:
    """Internal implementation of get_incident."""
    if tenant_id:
        row = conn.execute(
            "SELECT * FROM anonymized_incidents WHERE cloud_id = %s AND tenant_id = %s",
            (cloud_id, tenant_id),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM anonymized_incidents WHERE cloud_id = %s",
            (cloud_id,),
        ).fetchone()

    if not row:
        return None
    return _row_to_incident(row)


def _row_to_incident(row: dict[str, Any]) -> AnonymizedIncidentReport:
    """Convert a database row to an AnonymizedIncidentReport.

    With PostgreSQL + psycopg3:
    - JSONB columns are already deserialized as Python dicts/lists
    - TIMESTAMPTZ columns are already datetime objects
    - BOOLEAN columns are already Python bools
    """
    from elle_cloud.models import DriftExplanation

    # JSONB already deserialized by psycopg
    fingerprint = Fingerprint.model_validate(row["fingerprint_json"])
    action_summary = ActionSummary.model_validate(row["action_summary_json"])

    # Parse drift explanations (already deserialized from JSONB)
    drift_explanations: tuple[DriftExplanation, ...] = ()
    if row.get("drift_explanations_json"):
        drift_explanations = tuple(
            DriftExplanation.model_validate(de) for de in row["drift_explanations_json"]
        )

    return AnonymizedIncidentReport(
        incident_id=row["incident_id"],
        created_at_hour=row["created_at_hour"],
        updated_at_hour=row["updated_at_hour"],
        domain=row["domain"],
        severity=row["severity"],
        status=row["status"],
        outcome=row["outcome"],
        fingerprint=fingerprint,
        action_summary=action_summary,
        telemetry_pre=row["telemetry_pre_json"],
        telemetry_post=row["telemetry_post_json"],
        surface_hashes_pre=row["surface_hashes_pre_json"],
        surface_hashes_post=row["surface_hashes_post_json"],
        surface_drift=row["surface_drift_json"] or {},
        drift_explanations=drift_explanations,
        control_surface_pre=row.get("control_surface_pre_json"),
        control_surface_post=row.get("control_surface_post_json"),
        confidence=row["confidence"],
        time_to_mitigate_sec=row["time_to_mitigate_sec"],
        time_to_resolve_sec=row["time_to_resolve_sec"],
        trigger_source=row["trigger_source"],
        anonymization_version=row["anonymization_version"],
        detail_level=row.get("detail_level", "hashes"),
        original_hash=row["original_hash"],
    )


def get_incident_count(
    tenant_id: str | None = None,
) -> int:
    """Get total incident count."""
    with get_db() as conn:
        if tenant_id:
            row = conn.execute(
                "SELECT COUNT(*) as count FROM anonymized_incidents WHERE tenant_id = %s",
                (tenant_id,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) as count FROM anonymized_incidents"
            ).fetchone()
        assert row is not None
        return row["count"]


def get_domain_stats(
    domain: IncidentDomain,
    tenant_id: str | None = None,
) -> DomainStats:
    """Get aggregate statistics for a domain."""
    with get_db() as conn:
        tenant_filter = " AND tenant_id = %s" if tenant_id else ""
        params: list[Any] = [domain]
        if tenant_id:
            params.append(tenant_id)

        # Total count
        row = conn.execute(
            f"SELECT COUNT(*) as count FROM anonymized_incidents "
            f"WHERE domain = %s{tenant_filter}",
            params,
        ).fetchone()
        assert row is not None
        total = row["count"]

        if total == 0:
            return DomainStats(domain=domain)

        # Outcome distribution
        rows = conn.execute(
            f"""
            SELECT outcome, COUNT(*) as count
            FROM anonymized_incidents
            WHERE domain = %s{tenant_filter}
            GROUP BY outcome
            """,
            params,
        ).fetchall()
        outcome_distribution = {r["outcome"]: r["count"] / total for r in rows}

        # Average times
        row = conn.execute(
            f"""
            SELECT
                AVG(time_to_resolve_sec) as avg_resolve,
                AVG(time_to_mitigate_sec) as avg_mitigate,
                AVG(confidence) as avg_confidence
            FROM anonymized_incidents
            WHERE domain = %s{tenant_filter}
            """,
            params,
        ).fetchone()
        assert row is not None
        avg_resolve = row["avg_resolve"]
        avg_mitigate = row["avg_mitigate"]
        avg_confidence = float(row["avg_confidence"] or 0.0)

        # Common entities (sample recent incidents)
        entity_counts: dict[str, int] = {}
        rows = conn.execute(
            f"""
            SELECT fingerprint_json
            FROM anonymized_incidents
            WHERE domain = %s{tenant_filter}
            ORDER BY submitted_at DESC
            LIMIT 1000
            """,
            params,
        ).fetchall()
        for r in rows:
            fp = Fingerprint.model_validate(r["fingerprint_json"])
            for entity in fp.entities:
                entity_counts[entity] = entity_counts.get(entity, 0) + 1

        common_entities = sorted(
            entity_counts.keys(), key=lambda e: -entity_counts[e]
        )[:10]

        return DomainStats(
            domain=domain,
            total_incidents=total,
            outcome_distribution=outcome_distribution,
            avg_time_to_resolve_sec=float(avg_resolve) if avg_resolve else None,
            avg_time_to_mitigate_sec=float(avg_mitigate) if avg_mitigate else None,
            avg_confidence=avg_confidence,
            common_entities=common_entities,
        )


# =============================================================================
# Certificate Trust Store
# =============================================================================


def register_certificate(
    cert_fingerprint: str,
    organization: str,
    installation_id: str | None,
    common_name: str | None,
    issued_at: datetime,
    expires_at: datetime,
    is_admin: bool = False,
    conn: psycopg.Connection | None = None,
) -> bool:
    """Register a trusted certificate.

    Uses atomic upsert to avoid race conditions.

    Returns:
        True if newly registered, False if already exists.
    """
    if conn is not None:
        return _register_cert_impl(
            conn, cert_fingerprint, organization, installation_id,
            common_name, issued_at, expires_at, is_admin,
        )
    with get_db() as db_conn:
        return _register_cert_impl(
            db_conn, cert_fingerprint, organization, installation_id,
            common_name, issued_at, expires_at, is_admin,
        )


def _register_cert_impl(
    conn: psycopg.Connection,
    cert_fingerprint: str,
    organization: str,
    installation_id: str | None,
    common_name: str | None,
    issued_at: datetime,
    expires_at: datetime,
    is_admin: bool,
) -> bool:
    """Internal implementation of register_certificate."""
    cur = conn.execute(
        """
        INSERT INTO trusted_certificates (
            cert_fingerprint, organization, installation_id, common_name,
            issued_at, expires_at, is_admin
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (cert_fingerprint) DO NOTHING
        """,
        (
            cert_fingerprint, organization, installation_id, common_name,
            issued_at, expires_at, is_admin,
        ),
    )

    if cur.rowcount and cur.rowcount > 0:
        logger.info(
            "Registered certificate",
            fingerprint=cert_fingerprint[:16] + "...",
            organization=organization,
            is_admin=is_admin,
        )
        return True
    return False


def is_certificate_trusted(
    cert_fingerprint: str,
) -> tuple[bool, str | None]:
    """Check if a certificate is trusted.

    Returns:
        Tuple of (is_trusted, installation_id)
    """
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT installation_id, expires_at, revoked
            FROM trusted_certificates
            WHERE cert_fingerprint = %s
            """,
            (cert_fingerprint,),
        ).fetchone()

        if not row:
            return False, None

        if row["revoked"]:
            return False, None

        expires_at = row["expires_at"]
        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            return False, None

        return True, row["installation_id"]


def revoke_certificate(
    cert_fingerprint: str,
    reason: str = "manual revocation",
) -> bool:
    """Revoke a trusted certificate.

    Returns True if revoked, False if not found.
    """
    with get_db() as conn:
        cur = conn.execute(
            """
            UPDATE trusted_certificates
            SET revoked = TRUE, revoked_at = %s, revoked_reason = %s
            WHERE cert_fingerprint = %s
            """,
            (datetime.now(timezone.utc), reason, cert_fingerprint),
        )

        if cur.rowcount and cur.rowcount > 0:
            logger.warning(
                "Revoked certificate",
                fingerprint=cert_fingerprint[:16] + "...",
                reason=reason,
            )
            return True
        return False


def list_certificates(
    include_revoked: bool = False,
) -> list[dict[str, Any]]:
    """List all trusted certificates."""
    with get_db() as conn:
        if include_revoked:
            rows = conn.execute(
                "SELECT * FROM trusted_certificates ORDER BY created_at DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM trusted_certificates "
                "WHERE revoked = FALSE ORDER BY created_at DESC"
            ).fetchall()

        return [dict(row) for row in rows]


def is_admin_certificate(
    cert_fingerprint: str,
) -> bool:
    """Check if a certificate has admin privileges."""
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT is_admin, expires_at, revoked
            FROM trusted_certificates
            WHERE cert_fingerprint = %s
            """,
            (cert_fingerprint,),
        ).fetchone()

        if not row:
            return False

        if row["revoked"]:
            return False

        if not row["is_admin"]:
            return False

        # Check expiration
        expires_at = row["expires_at"]
        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            return False

        return True


# =============================================================================
# Audit Logging
# =============================================================================


def log_audit(
    action: str,
    actor: AuthContext | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: str = "",
) -> None:
    """Log an audit event."""
    try:
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (
                    action, actor_fingerprint, actor_installation_id,
                    resource_type, resource_id, details
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    action,
                    actor.cert_fingerprint[:16] if actor and actor.cert_fingerprint else None,
                    actor.installation_id if actor else None,
                    resource_type,
                    resource_id,
                    details,
                ),
            )

    except Exception as e:
        logger.warning("Failed to log audit event", error=str(e), action=action)
