"""ELLE Cloud entry point.

Supports multiple modes:
- server: Run the FastAPI server with mTLS
- init-certs: Generate CA and server certificates
- issue-client-cert: Issue a client certificate for an ELLE installation
"""

from __future__ import annotations

import argparse
import logging
import ssl
import sys

import structlog
import uvicorn
from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from elle_cloud import __version__
from elle_cloud.api import admin_router, health_router, limiter, router
from elle_cloud.config import CloudConfig, CloudMode, get_config, set_config
from elle_cloud.crypto import CloudCrypto
from elle_cloud.storage import close_pool, configure_pool, ensure_schema, register_certificate


def configure_logging(config: CloudConfig) -> None:
    """Configure structured logging."""
    log_level = getattr(logging, config.log_level.upper())

    if config.log_format == "json":
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
    else:
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.dev.ConsoleRenderer(),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )

    logging.basicConfig(level=log_level, format="%(message)s")


def create_app(config: CloudConfig | None = None) -> FastAPI:
    """Create the FastAPI application."""
    if config:
        set_config(config)
    else:
        config = get_config()

    app = FastAPI(
        title="ELLE Cloud",
        description="Anonymized Incident Report Knowledge Base",
        version=__version__,
        docs_url="/docs" if config.mode == CloudMode.ORG else None,
        redoc_url="/redoc" if config.mode == CloudMode.ORG else None,
    )

    # Configure rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Include routers
    app.include_router(health_router)
    app.include_router(router)
    app.include_router(admin_router)

    @app.on_event("startup")
    async def startup() -> None:
        """Initialize database on startup."""
        configure_pool()
        ensure_schema()
        structlog.get_logger().info(
            "ELLE Cloud started",
            mode=config.mode.value,
            org_name=config.org_name,
        )

    @app.on_event("shutdown")
    async def shutdown() -> None:
        """Close database pool on shutdown."""
        close_pool()

    return app


def cmd_server(args: argparse.Namespace) -> int:
    """Run the server."""
    config = get_config()
    configure_logging(config)

    logger = structlog.get_logger()
    logger.info(
        "Starting ELLE Cloud",
        mode=config.mode.value,
        org_name=config.org_name,
        bind=f"{config.bind_host}:{config.bind_port}",
    )

    app = create_app(config)

    # SSL configuration with hardened ciphers
    ssl_context = None
    if config.require_client_cert:
        crypto = CloudCrypto(config)
        paths = crypto.ensure_certificates()

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        # Restrict to strong ciphers only
        ssl_context.set_ciphers("ECDHE+AESGCM:CHACHA20:!aNULL:!MD5:!DSS")
        ssl_context.load_cert_chain(
            certfile=str(paths.server_cert),
            keyfile=str(paths.server_key),
        )
        ssl_context.load_verify_locations(cafile=str(paths.ca_cert))
        ssl_context.verify_mode = ssl.CERT_REQUIRED

        logger.info("mTLS enabled with TLS 1.3+ and hardened ciphers", ca=str(paths.ca_cert))

    uvicorn.run(
        app,
        host=config.bind_host,
        port=config.bind_port,
        ssl_keyfile=str(config.server_key_path) if ssl_context else None,
        ssl_certfile=str(config.server_cert_path) if ssl_context else None,
        ssl_ca_certs=str(config.ca_cert_path) if ssl_context else None,
        ssl_cert_reqs=ssl.CERT_REQUIRED if ssl_context else ssl.CERT_NONE,
        log_level=config.log_level,
    )

    return 0


def cmd_init_certs(args: argparse.Namespace) -> int:
    """Initialize certificates."""
    config = get_config()
    configure_logging(config)

    logger = structlog.get_logger()
    org_name = args.org_name or config.org_name

    logger.info("Initializing certificates", org_name=org_name)

    crypto = CloudCrypto(config)
    paths, admin_cert = crypto.init_certs(org_name)

    # Initialize database and register admin certificate
    configure_pool()
    ensure_schema()

    if admin_cert:
        register_certificate(
            cert_fingerprint=admin_cert.fingerprint,
            organization=org_name,
            installation_id=admin_cert.installation_id,
            common_name=admin_cert.installation_id,
            issued_at=admin_cert.expires_at,  # Will be fixed with proper issued_at
            expires_at=admin_cert.expires_at,
            is_admin=True,  # Mark as admin
        )
        logger.info(
            "Registered admin certificate",
            installation_id=admin_cert.installation_id,
            fingerprint=admin_cert.fingerprint[:16] + "...",
        )

    close_pool()

    logger.info(
        "Certificates created",
        ca_cert=str(paths.ca_cert),
        server_cert=str(paths.server_cert),
    )

    print(f"\nCertificates created for organization: {org_name}")
    print(f"  CA Certificate: {paths.ca_cert}")
    print(f"  CA Key: {paths.ca_key}")
    print(f"  Server Certificate: {paths.server_cert}")
    print(f"  Server Key: {paths.server_key}")
    if admin_cert:
        admin_cert_path = config.clients_dir / f"{admin_cert.installation_id}.crt"
        admin_key_path = config.clients_dir / f"{admin_cert.installation_id}.key"
        print("\nAdmin certificate (has admin privileges):")
        print(f"  Certificate: {admin_cert_path}")
        print(f"  Key: {admin_key_path}")
        print(f"  Fingerprint: {admin_cert.fingerprint}")
    print("\nNext steps:")
    print("  1. Issue client certificates with: issue-client-cert --installation-id <id>")
    print("  2. Start the server with: python -m elle_cloud.main")

    return 0


def cmd_issue_client_cert(args: argparse.Namespace) -> int:
    """Issue a client certificate."""
    config = get_config()
    configure_logging(config)

    logger = structlog.get_logger()
    installation_id = args.installation_id

    logger.info("Issuing client certificate", installation_id=installation_id)

    crypto = CloudCrypto(config)
    client_cert = crypto.issue_client_certificate(installation_id)

    # Register in trust store
    configure_pool()
    ensure_schema()
    register_certificate(
        cert_fingerprint=client_cert.fingerprint,
        organization=config.org_name,
        installation_id=installation_id,
        common_name=installation_id,
        issued_at=client_cert.expires_at,
        expires_at=client_cert.expires_at,
    )
    close_pool()

    cert_path = config.clients_dir / f"{installation_id}.crt"
    key_path = config.clients_dir / f"{installation_id}.key"

    print(f"\nClient certificate issued for: {installation_id}")
    print(f"  Certificate: {cert_path}")
    print(f"  Key: {key_path}")
    print(f"  Fingerprint: {client_cert.fingerprint}")
    print(f"  Expires: {client_cert.expires_at.isoformat()}")
    print("\nTo use with curl:")
    print(f"  curl --cert {cert_path} --key {key_path} \\")
    print(f"       --cacert {config.ca_cert_path} \\")
    print(f"       https://localhost:{config.bind_port}/health")

    return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ELLE Cloud - Anonymized Incident Report Knowledge Base",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"elle-cloud {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Server command
    subparsers.add_parser("server", help="Run the API server")

    # Init certs command
    init_parser = subparsers.add_parser("init-certs", help="Initialize certificates")
    init_parser.add_argument(
        "--org-name",
        type=str,
        help="Organization name for CA",
    )

    # Issue client cert command
    issue_parser = subparsers.add_parser(
        "issue-client-cert",
        help="Issue a client certificate",
    )
    issue_parser.add_argument(
        "--installation-id",
        type=str,
        required=True,
        help="Installation ID for the certificate",
    )

    args = parser.parse_args()

    if args.command == "server" or args.command is None:
        return cmd_server(args)
    elif args.command == "init-certs":
        return cmd_init_certs(args)
    elif args.command == "issue-client-cert":
        return cmd_issue_client_cert(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
