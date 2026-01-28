"""Pydantic models for ELLE Cloud.

Standalone copies of models from ELLE to avoid runtime dependency.
These models define the data structures for:
- Anonymized incident reports
- Fingerprints for similarity matching
- Cloud API responses
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# =============================================================================
# Type Aliases
# =============================================================================

IncidentDomain = Literal[
    "net",
    "disk",
    "oom",
    "docker",
    "auth",
    "pkg",
    "fs",
    "service",
    "gui",
    "other",
]

IncidentSeverity = Literal["info", "warning", "error", "critical"]

IncidentStatus = Literal["open", "mitigated", "resolved", "false_positive"]

IncidentOutcome = Literal["unknown", "improved", "partial", "no_change", "worse"]


# =============================================================================
# Fingerprint Model
# =============================================================================


class Fingerprint(BaseModel):
    """Derived features for incident similarity matching.

    Computed from snapshots and events for fast filtering
    and precondition evaluation.
    """

    model_config = ConfigDict(frozen=True)

    # Resource pressure (0.0 - 1.0)
    disk_pressure: float = Field(
        ge=0.0,
        le=1.0,
        default=0.0,
        description="Max disk usage ratio across mounts",
    )
    mem_pressure: float = Field(
        ge=0.0,
        le=1.0,
        default=0.0,
        description="Memory pressure: 1 - (available / total)",
    )
    swap_pressure: float = Field(
        ge=0.0,
        le=1.0,
        default=0.0,
        description="Swap usage ratio",
    )
    cpu_pressure: float = Field(
        ge=0.0,
        default=0.0,
        description="CPU load (1min average)",
    )

    # Event counts (last hour)
    oom_count_1h: int = Field(ge=0, default=0, description="OOM kills in last hour")
    net_flaps_1h: int = Field(ge=0, default=0, description="Network state changes in last hour")
    service_failures_1h: int = Field(ge=0, default=0, description="Service failures in last hour")
    auth_failures_1h: int = Field(ge=0, default=0, description="Auth failures in last hour")

    # Entities involved (for matching)
    entities: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Involved entities: service names, devices, interfaces",
    )

    # SMART warnings
    smart_pct_used_max: int = Field(ge=0, le=100, default=0)
    smart_media_errors: int = Field(ge=0, default=0)

    # Temperatures
    temp_max_c: int = Field(default=0, description="Max temperature in Celsius")

    # Docker
    docker_exited_count: int = Field(ge=0, default=0)

    # Custom features (extensible)
    custom: dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Action Summary
# =============================================================================


class ActionSummary(BaseModel):
    """Summary of actions taken during incident resolution."""

    model_config = ConfigDict(frozen=True)

    total_actions: int = Field(ge=0, default=0, description="Total number of actions")
    successful_actions: int = Field(ge=0, default=0, description="Number of successful actions")
    failed_actions: int = Field(ge=0, default=0, description="Number of failed actions")

    # Counts by kind
    shell_count: int = Field(ge=0, default=0)
    capability_count: int = Field(ge=0, default=0)
    edit_count: int = Field(ge=0, default=0)
    verify_count: int = Field(ge=0, default=0)
    rollback_count: int = Field(ge=0, default=0)
    privileged_count: int = Field(ge=0, default=0)
    gui_count: int = Field(ge=0, default=0)

    # Timing
    total_duration_ms: int = Field(ge=0, default=0, description="Sum of action durations")
    avg_duration_ms: int = Field(ge=0, default=0, description="Average action duration")


# =============================================================================
# Anonymized Incident Report
# =============================================================================


class AnonymizedIncidentReport(BaseModel):
    """Cloud-safe anonymized version of IncidentReport.

    Contains enough information for pattern matching and aggregate analysis
    while protecting sensitive system and user information.
    """

    model_config = ConfigDict(frozen=True)

    # Identity (preserved - UUIDs are anonymous by design)
    incident_id: str = Field(description="Original incident UUID")

    # Timestamps (generalized to hour)
    created_at_hour: datetime = Field(description="Creation time rounded to hour")
    updated_at_hour: datetime | None = Field(default=None, description="Update time rounded to hour")

    # Classification (preserved - enum values are safe)
    domain: IncidentDomain = Field(default="other")
    severity: IncidentSeverity = Field(default="warning")
    status: IncidentStatus = Field(default="open")
    outcome: IncidentOutcome = Field(default="unknown")

    # Trigger source (preserved)
    trigger_source: str = Field(default="manual")

    # Similarity fingerprint (preserved - all metrics)
    fingerprint: Fingerprint = Field(default_factory=Fingerprint)

    # Surface hashes (preserved - already anonymous hashes)
    surface_hashes_pre: dict[str, str] | None = Field(default=None)
    surface_hashes_post: dict[str, str] | None = Field(default=None)
    surface_drift: dict[str, bool] = Field(default_factory=dict)

    # Anonymized telemetry (metrics only, no identifiers)
    telemetry_pre: dict[str, Any] | None = Field(default=None)
    telemetry_post: dict[str, Any] | None = Field(default=None)

    # Action summary (counts by kind, success rate)
    action_summary: ActionSummary = Field(default_factory=ActionSummary)

    # Confidence (preserved)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)

    # Resolution time metrics (preserved)
    time_to_mitigate_sec: int | None = Field(default=None)
    time_to_resolve_sec: int | None = Field(default=None)

    # Anonymization metadata
    anonymization_version: str = Field(default="1.0")
    original_hash: str = Field(default="", description="SHA256 of original for deduplication")


# =============================================================================
# Cloud API Response Models
# =============================================================================


class CloudIncidentMatch(BaseModel):
    """A matching incident from the cloud knowledge base."""

    model_config = ConfigDict(frozen=True)

    cloud_id: str = Field(description="Cloud-assigned incident ID")
    fingerprint_similarity: float = Field(
        ge=0.0,
        le=1.0,
        description="Similarity score based on fingerprint matching",
    )
    surface_similarity: float = Field(
        ge=0.0,
        le=1.0,
        description="Similarity score based on surface hash matching",
    )
    combined_score: float = Field(
        ge=0.0,
        le=1.0,
        default=0.0,
        description="Combined relevance score",
    )
    installation_count: int = Field(
        ge=0,
        default=1,
        description="Number of installations that reported similar incidents",
    )
    resolution_stats: dict[str, Any] = Field(
        default_factory=dict,
        description="Aggregate resolution statistics",
    )
    # Include the full anonymized incident for context
    incident: AnonymizedIncidentReport | None = Field(
        default=None,
        description="Full anonymized incident data",
    )


class CloudSubmissionResult(BaseModel):
    """Result of submitting an incident to the cloud."""

    model_config = ConfigDict(frozen=True)

    cloud_id: str = Field(description="Cloud-assigned ID for this submission")
    accepted: bool = Field(description="Whether the submission was accepted")
    duplicate_of: str | None = Field(
        default=None,
        description="If duplicate, the ID of the existing incident",
    )
    similar_count: int = Field(
        ge=0,
        default=0,
        description="Number of similar incidents in the cloud",
    )


class CloudQueryResult(BaseModel):
    """Result of querying the cloud for similar incidents."""

    model_config = ConfigDict(frozen=True)

    matches: list[CloudIncidentMatch] = Field(
        default_factory=list,
        description="Matching incidents from the cloud",
    )
    total_searched: int = Field(
        ge=0,
        default=0,
        description="Total incidents searched in the cloud",
    )
    query_time_ms: int = Field(
        ge=0,
        default=0,
        description="Query execution time in milliseconds",
    )


class DomainStats(BaseModel):
    """Aggregate statistics for a domain."""

    model_config = ConfigDict(frozen=True)

    domain: str = Field(description="Incident domain")
    total_incidents: int = Field(ge=0, default=0)
    outcome_distribution: dict[str, float] = Field(
        default_factory=dict,
        description="Outcome percentages",
    )
    avg_time_to_resolve_sec: float | None = Field(default=None)
    avg_time_to_mitigate_sec: float | None = Field(default=None)
    avg_confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    common_entities: list[str] = Field(
        default_factory=list,
        description="Most common entities in this domain",
    )


# =============================================================================
# API Request Models
# =============================================================================


class SimilarityQuery(BaseModel):
    """Query parameters for similarity search."""

    fingerprint: Fingerprint = Field(description="Fingerprint to match against")
    surface_hashes: dict[str, str] | None = Field(
        default=None,
        description="Surface hashes for drift matching",
    )
    domain: IncidentDomain | None = Field(
        default=None,
        description="Filter by domain",
    )
    outcome: IncidentOutcome | None = Field(
        default=None,
        description="Filter by outcome",
    )
    limit: int = Field(
        ge=1,
        le=100,
        default=10,
        description="Maximum number of results",
    )
    min_similarity: float = Field(
        ge=0.0,
        le=1.0,
        default=0.3,
        description="Minimum similarity threshold",
    )
