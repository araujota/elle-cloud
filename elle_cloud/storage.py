"""SQLite storage for ELLE Cloud.

Handles:
- Anonymized incident storage with vector fingerprints
- Surface hash indexing for drift correlation
- Certificate trust store for mTLS
- Deduplication via original_hash
- Audit logging for security events
"""

from __future__ import annotations

import json
import sqlite3
import struct
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

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
# Schema
# =============================================================================

SCHEMA_VERSION = 3

SCHEMA_SQL = """
-- Core incident storage
CREATE TABLE IF NOT EXISTS anonymized_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT UNIQUE NOT NULL,
    cloud_id TEXT UNIQUE NOT NULL,
    domain TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    outcome TEXT NOT NULL,
    created_at_hour TEXT NOT NULL,
    updated_at_hour TEXT,
    fingerprint_vector BLOB NOT NULL,
    fingerprint_json TEXT NOT NULL,
    action_summary_json TEXT NOT NULL,
    telemetry_pre_json TEXT,
    telemetry_post_json TEXT,
    surface_hashes_pre_json TEXT,
    surface_hashes_post_json TEXT,
    surface_drift_json TEXT,
    drift_explanations_json TEXT,
    control_surface_pre_json TEXT,
    control_surface_post_json TEXT,
    confidence REAL NOT NULL,
    time_to_mitigate_sec INTEGER,
    time_to_resolve_sec INTEGER,
    trigger_source TEXT NOT NULL DEFAULT 'manual',
    anonymization_version TEXT NOT NULL DEFAULT '1.0',
    detail_level TEXT NOT NULL DEFAULT 'hashes',
    original_hash TEXT UNIQUE NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'global',
    submitted_at TEXT NOT NULL,
    installation_fingerprint TEXT
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_incidents_domain ON anonymized_incidents(domain);
CREATE INDEX IF NOT EXISTS idx_incidents_outcome ON anonymized_incidents(outcome);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant ON anonymized_incidents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_incidents_submitted ON anonymized_incidents(submitted_at);
CREATE INDEX IF NOT EXISTS idx_incidents_original_hash ON anonymized_incidents(original_hash);

-- Surface hashes for drift correlation
CREATE TABLE IF NOT EXISTS surface_hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cloud_id TEXT NOT NULL,
    snapshot_type TEXT NOT NULL CHECK (snapshot_type IN ('pre', 'post')),
    surface_key TEXT NOT NULL,
    surface_hash TEXT NOT NULL,
    FOREIGN KEY (cloud_id) REFERENCES anonymized_incidents(cloud_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_surface_cloud_id ON surface_hashes(cloud_id);
CREATE INDEX IF NOT EXISTS idx_surface_key_hash ON surface_hashes(surface_key, surface_hash);

-- Certificate trust store
CREATE TABLE IF NOT EXISTS trusted_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cert_fingerprint TEXT UNIQUE NOT NULL,
    organization TEXT NOT NULL,
    installation_id TEXT,
    common_name TEXT,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    revoked_at TEXT,
    revoked_reason TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_certs_fingerprint ON trusted_certificates(cert_fingerprint);
CREATE INDEX IF NOT EXISTS idx_certs_installation ON trusted_certificates(installation_id);
CREATE INDEX IF NOT EXISTS idx_certs_revoked ON trusted_certificates(revoked);
CREATE INDEX IF NOT EXISTS idx_certs_admin ON trusted_certificates(is_admin);

-- Audit log for security events
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    actor_fingerprint TEXT,
    actor_installation_id TEXT,
    resource_type TEXT,
    resource_id TEXT,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_fingerprint);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);
"""


# =============================================================================
# Connection Management
# =============================================================================


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    """Get a SQLite connection with proper settings."""
    if db_path is None:
        db_path = get_config().db_path

    # Ensure parent directory exists with restricted permissions
    db_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        db_path.parent.chmod(0o700)  # Restrict directory access
    except OSError:
        pass  # May fail on some filesystems

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")

    # Restrict database file permissions after creation
    if db_path.exists():
        try:
            db_path.chmod(0o600)  # Restrict file access
        except OSError:
            pass  # May fail on some filesystems

    return conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for database connections."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Ensure database schema is up to date."""
    cursor = conn.cursor()

    # Check current version
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    )
    if not cursor.fetchone():
        # Fresh database - create schema
        conn.executescript(SCHEMA_SQL)
        cursor.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
        conn.commit()
        logger.info("Created database schema", version=SCHEMA_VERSION)
        return

    # Check version and migrate if needed
    cursor.execute("SELECT version FROM schema_version")
    row = cursor.fetchone()
    current_version = row[0] if row else 0

    if current_version < SCHEMA_VERSION:
        # Run migrations
        _migrate_schema(conn, current_version, SCHEMA_VERSION)


def _migrate_schema(conn: sqlite3.Connection, from_version: int, to_version: int) -> None:
    """Run schema migrations."""
    logger.info("Migrating schema", from_version=from_version, to_version=to_version)
    cursor = conn.cursor()

    # Migration from v1 to v2: add is_admin column and audit_log table
    if from_version < 2:
        # Add is_admin column to trusted_certificates
        cursor.execute(
            "ALTER TABLE trusted_certificates ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0"
        )
        # Create audit_log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                action TEXT NOT NULL,
                actor_fingerprint TEXT,
                actor_installation_id TEXT,
                resource_type TEXT,
                resource_id TEXT,
                details TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_fingerprint)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_certs_admin ON trusted_certificates(is_admin)")
        logger.info("Migrated to schema v2: added is_admin column and audit_log table")

    # Migration from v2 to v3: add drift explanations and control surface columns
    if from_version < 3:
        cursor.execute(
            "ALTER TABLE anonymized_incidents ADD COLUMN drift_explanations_json TEXT"
        )
        cursor.execute(
            "ALTER TABLE anonymized_incidents ADD COLUMN control_surface_pre_json TEXT"
        )
        cursor.execute(
            "ALTER TABLE anonymized_incidents ADD COLUMN control_surface_post_json TEXT"
        )
        cursor.execute(
            "ALTER TABLE anonymized_incidents ADD COLUMN detail_level TEXT NOT NULL DEFAULT 'hashes'"
        )
        logger.info("Migrated to schema v3: added drift explanations and control surfaces")

    cursor.execute("UPDATE schema_version SET version = ?", (to_version,))
    conn.commit()


# =============================================================================
# Fingerprint Vector Operations
# =============================================================================


def fingerprint_to_vector(fp: Fingerprint) -> list[float]:
    """Convert Fingerprint to 15-dimensional vector for similarity search.

    Dimensions:
    0: disk_pressure (0-1)
    1: mem_pressure (0-1)
    2: swap_pressure (0-1)
    3: cpu_pressure (clamped to 0-1)
    4: oom_count_1h (normalized)
    5: net_flaps_1h (normalized)
    6: service_failures_1h (normalized)
    7: auth_failures_1h (normalized)
    8: smart_pct_used_max (normalized)
    9: smart_media_errors (normalized)
    10: temp_max_c (normalized)
    11: docker_exited_count (normalized)
    12: entity_count (normalized)
    13: has_oom (binary)
    14: has_service_failures (binary)
    """
    return [
        fp.disk_pressure,
        fp.mem_pressure,
        fp.swap_pressure,
        min(fp.cpu_pressure, 1.0),
        min(fp.oom_count_1h / 10.0, 1.0),
        min(fp.net_flaps_1h / 10.0, 1.0),
        min(fp.service_failures_1h / 10.0, 1.0),
        min(fp.auth_failures_1h / 10.0, 1.0),
        min(fp.smart_pct_used_max / 100.0, 1.0),
        min(fp.smart_media_errors / 10.0, 1.0),
        min(fp.temp_max_c / 100.0, 1.0),
        min(fp.docker_exited_count / 10.0, 1.0),
        len(fp.entities) / 20.0 if fp.entities else 0.0,
        1.0 if fp.oom_count_1h > 0 else 0.0,
        1.0 if fp.service_failures_1h > 0 else 0.0,
    ]


def pack_vector(vector: list[float]) -> bytes:
    """Pack a vector of floats into bytes for storage."""
    return struct.pack(f"{len(vector)}f", *vector)


def unpack_vector(data: bytes) -> list[float]:
    """Unpack bytes into a vector of floats."""
    count = len(data) // 4  # 4 bytes per float
    return list(struct.unpack(f"{count}f", data))


# =============================================================================
# Incident Storage
# =============================================================================


def store_incident(
    incident: AnonymizedIncidentReport,
    tenant_id: str = "global",
    installation_fingerprint: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> tuple[str, bool, str | None]:
    """Store an anonymized incident.

    Returns:
        Tuple of (cloud_id, accepted, duplicate_of)
        - cloud_id: The assigned cloud ID
        - accepted: True if newly stored, False if duplicate
        - duplicate_of: Cloud ID of existing incident if duplicate
    """
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
        ensure_schema(conn)

    assert conn is not None

    try:
        cursor = conn.cursor()

        # Check for duplicate by original_hash
        cursor.execute(
            "SELECT cloud_id FROM anonymized_incidents WHERE original_hash = ?",
            (incident.original_hash,),
        )
        existing = cursor.fetchone()
        if existing:
            logger.debug("Duplicate incident detected", original_hash=incident.original_hash)
            return existing["cloud_id"], False, existing["cloud_id"]

        # Generate cloud ID with full UUID for stronger entropy
        cloud_id = f"cloud-{uuid.uuid4().hex}"

        # Convert fingerprint to vector
        vector = fingerprint_to_vector(incident.fingerprint)
        vector_blob = pack_vector(vector)

        # Prepare JSON fields
        fingerprint_json = incident.fingerprint.model_dump_json()
        action_summary_json = incident.action_summary.model_dump_json()
        telemetry_pre_json = json.dumps(incident.telemetry_pre) if incident.telemetry_pre else None
        telemetry_post_json = json.dumps(incident.telemetry_post) if incident.telemetry_post else None
        surface_hashes_pre_json = json.dumps(incident.surface_hashes_pre) if incident.surface_hashes_pre else None
        surface_hashes_post_json = json.dumps(incident.surface_hashes_post) if incident.surface_hashes_post else None
        surface_drift_json = json.dumps(incident.surface_drift) if incident.surface_drift else None

        # New fields for v3 schema
        drift_explanations_json = None
        if incident.drift_explanations:
            drift_explanations_json = json.dumps([
                de.model_dump() if hasattr(de, "model_dump") else de
                for de in incident.drift_explanations
            ])
        control_surface_pre_json = json.dumps(incident.control_surface_pre) if incident.control_surface_pre else None
        control_surface_post_json = json.dumps(incident.control_surface_post) if incident.control_surface_post else None

        # Insert incident
        cursor.execute(
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
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident.incident_id,
                cloud_id,
                incident.domain,
                incident.severity,
                incident.status,
                incident.outcome,
                incident.created_at_hour.isoformat(),
                incident.updated_at_hour.isoformat() if incident.updated_at_hour else None,
                vector_blob,
                fingerprint_json,
                action_summary_json,
                telemetry_pre_json,
                telemetry_post_json,
                surface_hashes_pre_json,
                surface_hashes_post_json,
                surface_drift_json,
                drift_explanations_json,
                control_surface_pre_json,
                control_surface_post_json,
                incident.confidence,
                incident.time_to_mitigate_sec,
                incident.time_to_resolve_sec,
                incident.trigger_source,
                incident.anonymization_version,
                incident.detail_level,
                incident.original_hash,
                tenant_id,
                datetime.now(timezone.utc).isoformat(),
                installation_fingerprint,
            ),
        )

        # Store surface hashes for indexing
        if incident.surface_hashes_pre:
            _store_surface_hashes(cursor, cloud_id, "pre", incident.surface_hashes_pre)
        if incident.surface_hashes_post:
            _store_surface_hashes(cursor, cloud_id, "post", incident.surface_hashes_post)

        if own_conn:
            conn.commit()

        logger.info("Stored incident", cloud_id=cloud_id, domain=incident.domain)
        return cloud_id, True, None

    finally:
        if own_conn:
            conn.close()


def _store_surface_hashes(
    cursor: sqlite3.Cursor,
    cloud_id: str,
    snapshot_type: str,
    hashes: dict[str, str],
) -> None:
    """Store surface hashes for an incident."""
    for key, hash_value in hashes.items():
        cursor.execute(
            """
            INSERT INTO surface_hashes (cloud_id, snapshot_type, surface_key, surface_hash)
            VALUES (?, ?, ?, ?)
            """,
            (cloud_id, snapshot_type, key, hash_value),
        )


def get_incident(
    cloud_id: str,
    tenant_id: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> AnonymizedIncidentReport | None:
    """Get an incident by cloud ID.

    Args:
        cloud_id: The cloud ID of the incident.
        tenant_id: Optional tenant ID for tenant isolation. If provided,
                   only returns the incident if it belongs to this tenant.
        conn: Optional database connection.

    Returns:
        The incident if found (and belongs to tenant if specified), None otherwise.
    """
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
        ensure_schema(conn)

    assert conn is not None

    try:
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute(
                "SELECT * FROM anonymized_incidents WHERE cloud_id = ? AND tenant_id = ?",
                (cloud_id, tenant_id),
            )
        else:
            cursor.execute(
                "SELECT * FROM anonymized_incidents WHERE cloud_id = ?",
                (cloud_id,),
            )
        row = cursor.fetchone()
        if not row:
            return None
        return _row_to_incident(row)
    finally:
        if own_conn:
            conn.close()


def _row_to_incident(row: sqlite3.Row) -> AnonymizedIncidentReport:
    """Convert a database row to an AnonymizedIncidentReport."""
    from elle_cloud.models import DriftExplanation

    fingerprint = Fingerprint.model_validate_json(row["fingerprint_json"])
    action_summary = ActionSummary.model_validate_json(row["action_summary_json"])

    # Parse drift explanations (v3 schema)
    drift_explanations: tuple[DriftExplanation, ...] = ()
    drift_json = row["drift_explanations_json"] if "drift_explanations_json" in row.keys() else None
    if drift_json:
        drift_explanations = tuple(
            DriftExplanation.model_validate(de) for de in json.loads(drift_json)
        )

    # Parse control surfaces (v3 schema, detailed mode only)
    control_pre = None
    control_post = None
    if "control_surface_pre_json" in row.keys():
        control_pre = json.loads(row["control_surface_pre_json"]) if row["control_surface_pre_json"] else None
    if "control_surface_post_json" in row.keys():
        control_post = json.loads(row["control_surface_post_json"]) if row["control_surface_post_json"] else None

    # Parse detail level (v3 schema)
    detail_level = row["detail_level"] if "detail_level" in row.keys() else "hashes"

    return AnonymizedIncidentReport(
        incident_id=row["incident_id"],
        created_at_hour=datetime.fromisoformat(row["created_at_hour"]),
        updated_at_hour=datetime.fromisoformat(row["updated_at_hour"]) if row["updated_at_hour"] else None,
        domain=row["domain"],
        severity=row["severity"],
        status=row["status"],
        outcome=row["outcome"],
        fingerprint=fingerprint,
        action_summary=action_summary,
        telemetry_pre=json.loads(row["telemetry_pre_json"]) if row["telemetry_pre_json"] else None,
        telemetry_post=json.loads(row["telemetry_post_json"]) if row["telemetry_post_json"] else None,
        surface_hashes_pre=json.loads(row["surface_hashes_pre_json"]) if row["surface_hashes_pre_json"] else None,
        surface_hashes_post=json.loads(row["surface_hashes_post_json"]) if row["surface_hashes_post_json"] else None,
        surface_drift=json.loads(row["surface_drift_json"]) if row["surface_drift_json"] else {},
        drift_explanations=drift_explanations,
        control_surface_pre=control_pre,
        control_surface_post=control_post,
        confidence=row["confidence"],
        time_to_mitigate_sec=row["time_to_mitigate_sec"],
        time_to_resolve_sec=row["time_to_resolve_sec"],
        trigger_source=row["trigger_source"],
        anonymization_version=row["anonymization_version"],
        detail_level=detail_level,
        original_hash=row["original_hash"],
    )


def get_incident_count(
    tenant_id: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> int:
    """Get total incident count."""
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
        ensure_schema(conn)

    assert conn is not None

    try:
        cursor = conn.cursor()
        if tenant_id:
            cursor.execute(
                "SELECT COUNT(*) FROM anonymized_incidents WHERE tenant_id = ?",
                (tenant_id,),
            )
        else:
            cursor.execute("SELECT COUNT(*) FROM anonymized_incidents")
        return cursor.fetchone()[0]
    finally:
        if own_conn:
            conn.close()


def get_domain_stats(
    domain: IncidentDomain,
    tenant_id: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> DomainStats:
    """Get aggregate statistics for a domain."""
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
        ensure_schema(conn)

    assert conn is not None

    try:
        cursor = conn.cursor()

        # Base query
        tenant_filter = " AND tenant_id = ?" if tenant_id else ""
        params: list[Any] = [domain]
        if tenant_id:
            params.append(tenant_id)

        # Total count
        cursor.execute(
            f"SELECT COUNT(*) FROM anonymized_incidents WHERE domain = ?{tenant_filter}",
            params,
        )
        total = cursor.fetchone()[0]

        if total == 0:
            return DomainStats(domain=domain)

        # Outcome distribution
        cursor.execute(
            f"""
            SELECT outcome, COUNT(*) as count
            FROM anonymized_incidents
            WHERE domain = ?{tenant_filter}
            GROUP BY outcome
            """,
            params,
        )
        outcome_counts = {row["outcome"]: row["count"] for row in cursor.fetchall()}
        outcome_distribution = {
            outcome: count / total for outcome, count in outcome_counts.items()
        }

        # Average times
        cursor.execute(
            f"""
            SELECT
                AVG(time_to_resolve_sec) as avg_resolve,
                AVG(time_to_mitigate_sec) as avg_mitigate,
                AVG(confidence) as avg_confidence
            FROM anonymized_incidents
            WHERE domain = ?{tenant_filter}
            """,
            params,
        )
        row = cursor.fetchone()
        avg_resolve = row["avg_resolve"]
        avg_mitigate = row["avg_mitigate"]
        avg_confidence = row["avg_confidence"] or 0.0

        # Common entities (from fingerprint JSON)
        # This is expensive - sample if dataset is large
        entity_counts: dict[str, int] = {}
        cursor.execute(
            f"""
            SELECT fingerprint_json
            FROM anonymized_incidents
            WHERE domain = ?{tenant_filter}
            ORDER BY submitted_at DESC
            LIMIT 1000
            """,
            params,
        )
        for row in cursor.fetchall():
            fp = Fingerprint.model_validate_json(row["fingerprint_json"])
            for entity in fp.entities:
                entity_counts[entity] = entity_counts.get(entity, 0) + 1

        # Sort by frequency
        common_entities = sorted(entity_counts.keys(), key=lambda e: -entity_counts[e])[:10]

        return DomainStats(
            domain=domain,
            total_incidents=total,
            outcome_distribution=outcome_distribution,
            avg_time_to_resolve_sec=avg_resolve,
            avg_time_to_mitigate_sec=avg_mitigate,
            avg_confidence=avg_confidence,
            common_entities=common_entities,
        )

    finally:
        if own_conn:
            conn.close()


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
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Register a trusted certificate.

    Uses atomic upsert to avoid race conditions.

    Args:
        cert_fingerprint: SHA-256 fingerprint of the certificate.
        organization: Organization name.
        installation_id: Optional installation identifier.
        common_name: Certificate common name.
        issued_at: Certificate issue date.
        expires_at: Certificate expiration date.
        is_admin: Whether this certificate has admin privileges.
        conn: Optional database connection.

    Returns:
        True if newly registered, False if already exists.
    """
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
        ensure_schema(conn)

    assert conn is not None

    try:
        cursor = conn.cursor()

        # Atomic upsert to avoid race condition
        cursor.execute(
            """
            INSERT INTO trusted_certificates (
                cert_fingerprint, organization, installation_id, common_name,
                issued_at, expires_at, is_admin
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cert_fingerprint) DO NOTHING
            """,
            (
                cert_fingerprint,
                organization,
                installation_id,
                common_name,
                issued_at.isoformat(),
                expires_at.isoformat(),
                1 if is_admin else 0,
            ),
        )

        if own_conn:
            conn.commit()

        if cursor.rowcount > 0:
            logger.info(
                "Registered certificate",
                fingerprint=cert_fingerprint[:16] + "...",
                organization=organization,
                is_admin=is_admin,
            )
            return True
        return False

    finally:
        if own_conn:
            conn.close()


def is_certificate_trusted(
    cert_fingerprint: str,
    conn: sqlite3.Connection | None = None,
) -> tuple[bool, str | None]:
    """Check if a certificate is trusted.

    Returns:
        Tuple of (is_trusted, installation_id)
    """
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
        ensure_schema(conn)

    assert conn is not None

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT installation_id, expires_at, revoked
            FROM trusted_certificates
            WHERE cert_fingerprint = ?
            """,
            (cert_fingerprint,),
        )
        row = cursor.fetchone()

        if not row:
            return False, None

        if row["revoked"]:
            return False, None

        expires_at = datetime.fromisoformat(row["expires_at"])
        # Handle both naive and timezone-aware datetimes
        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            return False, None

        return True, row["installation_id"]

    finally:
        if own_conn:
            conn.close()


def revoke_certificate(
    cert_fingerprint: str,
    reason: str = "manual revocation",
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Revoke a trusted certificate.

    Returns True if revoked, False if not found.
    """
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
        ensure_schema(conn)

    assert conn is not None

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE trusted_certificates
            SET revoked = 1, revoked_at = ?, revoked_reason = ?
            WHERE cert_fingerprint = ?
            """,
            (datetime.now(timezone.utc).isoformat(), reason, cert_fingerprint),
        )

        if own_conn:
            conn.commit()

        if cursor.rowcount > 0:
            logger.warning(
                "Revoked certificate",
                fingerprint=cert_fingerprint[:16] + "...",
                reason=reason,
            )
            return True
        return False

    finally:
        if own_conn:
            conn.close()


def list_certificates(
    include_revoked: bool = False,
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    """List all trusted certificates."""
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
        ensure_schema(conn)

    assert conn is not None

    try:
        cursor = conn.cursor()
        if include_revoked:
            cursor.execute("SELECT * FROM trusted_certificates ORDER BY created_at DESC")
        else:
            cursor.execute(
                "SELECT * FROM trusted_certificates WHERE revoked = 0 ORDER BY created_at DESC"
            )

        return [dict(row) for row in cursor.fetchall()]

    finally:
        if own_conn:
            conn.close()


def is_admin_certificate(
    cert_fingerprint: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Check if a certificate has admin privileges.

    Args:
        cert_fingerprint: SHA-256 fingerprint of the certificate.
        conn: Optional database connection.

    Returns:
        True if the certificate is an admin certificate and is trusted.
    """
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
        ensure_schema(conn)

    assert conn is not None

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT is_admin, expires_at, revoked
            FROM trusted_certificates
            WHERE cert_fingerprint = ?
            """,
            (cert_fingerprint,),
        )
        row = cursor.fetchone()

        if not row:
            return False

        if row["revoked"]:
            return False

        if not row["is_admin"]:
            return False

        # Check expiration
        expires_at = datetime.fromisoformat(row["expires_at"])
        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            return False

        return True

    finally:
        if own_conn:
            conn.close()


def log_audit(
    action: str,
    actor: AuthContext | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: str = "",
    conn: sqlite3.Connection | None = None,
) -> None:
    """Log an audit event.

    Args:
        action: The action performed (e.g., "cert.register", "incident.submit").
        actor: The authentication context of the actor.
        resource_type: Type of resource affected (e.g., "certificate", "incident").
        resource_id: ID of the affected resource.
        details: Additional details about the action.
        conn: Optional database connection.
    """
    own_conn = conn is None
    if own_conn:
        conn = get_connection()
        ensure_schema(conn)

    assert conn is not None

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_log (
                action, actor_fingerprint, actor_installation_id,
                resource_type, resource_id, details
            ) VALUES (?, ?, ?, ?, ?, ?)
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

        if own_conn:
            conn.commit()

    except Exception as e:
        logger.warning("Failed to log audit event", error=str(e), action=action)

    finally:
        if own_conn:
            conn.close()
