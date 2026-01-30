"""Configuration for ELLE Cloud.

Environment-based configuration for different deployment modes:
- Global: Anthropic-hosted cloud for all ELLE installations
- Org: Self-hosted organization vault
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings


class CloudMode(str, Enum):
    """Deployment mode for ELLE Cloud."""

    GLOBAL = "global"
    ORG = "org"


class CloudConfig(BaseSettings):
    """ELLE Cloud configuration from environment."""

    # Deployment mode
    mode: CloudMode = Field(
        default=CloudMode.ORG,
        description="Deployment mode: global or org",
    )

    # Organization name (for org mode)
    org_name: str = Field(
        default="default-org",
        description="Organization name for org vault",
    )

    # Server settings
    bind_host: str = Field(
        default="0.0.0.0",
        description="Host to bind to",
    )
    bind_port: int = Field(
        default=8443,
        description="HTTPS port for mTLS",
    )
    health_port: int = Field(
        default=8080,
        description="HTTP port for health checks",
    )

    # Database (PostgreSQL)
    db_host: str = Field(
        default="localhost",
        description="PostgreSQL host",
    )
    db_port: int = Field(
        default=5432,
        description="PostgreSQL port",
    )
    db_name: str = Field(
        default="elle_cloud",
        description="PostgreSQL database name",
    )
    db_user: str = Field(
        default="elle_cloud",
        description="PostgreSQL user",
    )
    db_password: str = Field(
        default="",
        description="PostgreSQL password",
    )

    # Data directory
    data_dir: Path = Field(
        default=Path("/data"),
        description="Directory for auxiliary data files",
    )

    # Certificate directory
    cert_dir: Path = Field(
        default=Path("/certs"),
        description="Directory for TLS certificates",
    )

    # Logging
    log_level: Literal["debug", "info", "warning", "error"] = Field(
        default="info",
        description="Log level",
    )
    log_format: Literal["json", "text"] = Field(
        default="json",
        description="Log format",
    )

    # Security
    require_client_cert: bool = Field(
        default=True,
        description="Require client certificate for mTLS",
    )

    # Performance
    max_incidents: int = Field(
        default=100000,
        description="Maximum incidents to store (oldest pruned)",
    )
    search_limit: int = Field(
        default=100,
        description="Maximum search results",
    )

    # Detail level for stored incidents
    # "hashes": Only surface hashes (default, most private)
    # "detailed": Full anonymized control surfaces (richer sharing)
    detail_level: Literal["hashes", "detailed"] = Field(
        default="hashes",
        description="Level of detail to accept/store: 'hashes' or 'detailed'",
    )

    class Config:
        env_prefix = "ELLE_CLOUD_"
        env_file = ".env"
        env_file_encoding = "utf-8"

    @property
    def conninfo(self) -> str:
        """PostgreSQL connection string."""
        parts = [f"dbname={self.db_name}", f"user={self.db_user}"]
        if self.db_host:
            parts.append(f"host={self.db_host}")
        if self.db_port != 5432:
            parts.append(f"port={self.db_port}")
        if self.db_password:
            parts.append(f"password={self.db_password}")
        return " ".join(parts)

    @property
    def ca_cert_path(self) -> Path:
        """Path to CA certificate."""
        return self.cert_dir / "ca.crt"

    @property
    def ca_key_path(self) -> Path:
        """Path to CA private key."""
        return self.cert_dir / "ca.key"

    @property
    def server_cert_path(self) -> Path:
        """Path to server certificate."""
        return self.cert_dir / "server.crt"

    @property
    def server_key_path(self) -> Path:
        """Path to server private key."""
        return self.cert_dir / "server.key"

    @property
    def clients_dir(self) -> Path:
        """Directory for client certificates."""
        return self.cert_dir / "clients"


# Global config instance
_config: CloudConfig | None = None


def get_config() -> CloudConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = CloudConfig()
    return _config


def set_config(config: CloudConfig) -> None:
    """Set the global configuration instance (for testing)."""
    global _config
    _config = config


def reset_config() -> None:
    """Reset the global configuration instance (for testing)."""
    global _config
    _config = None
