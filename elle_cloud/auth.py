"""mTLS authentication for ELLE Cloud.

Handles:
- Client certificate verification
- Tenant isolation via certificate CN
- Auth context for requests
- Certificate trust store integration
"""

from __future__ import annotations

from dataclasses import dataclass

import structlog
from cryptography import x509
from cryptography.x509.oid import NameOID
from fastapi import HTTPException, Request
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from elle_cloud.config import get_config
from elle_cloud.crypto import CloudCrypto
from elle_cloud.storage import is_admin_certificate, is_certificate_trusted, register_certificate

logger = structlog.get_logger()


@dataclass
class AuthContext:
    """Authentication context for a request."""

    installation_id: str
    tenant_id: str
    cert_fingerprint: str
    organization: str
    authenticated: bool = True


def extract_client_cert(request: Request) -> bytes | None:
    """Extract client certificate from request.

    In production with nginx/traefik, the cert is usually passed via header.
    In direct TLS mode, it's available from the connection.

    Returns:
        PEM-encoded certificate bytes if valid, None otherwise.
    """
    import urllib.parse

    # Check for header (reverse proxy mode)
    cert_header = request.headers.get("X-Client-Cert")
    if cert_header:
        # URL-decode and convert to bytes
        cert_pem = urllib.parse.unquote(cert_header).encode()
        # Validate PEM format before returning
        try:
            x509.load_pem_x509_certificate(cert_pem)
        except Exception:
            logger.warning("Invalid PEM in X-Client-Cert header")
            return None
        return cert_pem

    # Check for direct SSL context (uvicorn with ssl)
    if hasattr(request, "scope"):
        transport = request.scope.get("transport")
        if transport and hasattr(transport, "get_extra_info"):
            ssl_object = transport.get_extra_info("ssl_object")
            if ssl_object:
                cert = ssl_object.getpeercert(binary_form=True)
                if cert:
                    # Convert DER to PEM
                    from cryptography.hazmat.primitives.serialization import Encoding
                    x509_cert = x509.load_der_x509_certificate(cert)
                    return x509_cert.public_bytes(Encoding.PEM)

    return None


def verify_client_certificate(cert_pem: bytes) -> AuthContext:
    """Verify client certificate and extract auth context.

    Raises HTTPException if verification fails.
    """
    config = get_config()
    crypto = CloudCrypto(config)

    # Verify against CA
    is_valid, installation_id, error = crypto.verify_client_cert(cert_pem)

    if not is_valid:
        # Log detailed error for debugging but return generic message
        logger.warning(
            "Certificate verification failed",
            error=error,
            fingerprint=crypto.compute_fingerprint(cert_pem)[:16] if cert_pem else None,
        )
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Certificate verification failed",
        )

    # Compute fingerprint
    fingerprint = crypto.compute_fingerprint(cert_pem)

    # Check trust store (for revocation)
    is_trusted, stored_installation = is_certificate_trusted(fingerprint)

    if not is_trusted:
        # Certificate not in trust store - auto-register for org mode
        # In global mode, this would require admin approval
        if config.mode.value == "org":
            # Parse cert for metadata
            cert = x509.load_pem_x509_certificate(cert_pem)
            org_attr = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
            organization = org_attr[0].value if org_attr else config.org_name

            register_certificate(
                cert_fingerprint=fingerprint,
                organization=organization,
                installation_id=installation_id,
                common_name=installation_id,
                issued_at=cert.not_valid_before_utc,
                expires_at=cert.not_valid_after_utc,
            )
            logger.info(
                "Auto-registered client certificate",
                installation_id=installation_id,
                fingerprint=fingerprint[:16] + "...",
            )
        else:
            logger.warning(
                "Certificate not in trust store",
                fingerprint=fingerprint[:16] + "...",
            )
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Certificate not registered in trust store",
            )

    # Extract organization from cert
    cert = x509.load_pem_x509_certificate(cert_pem)
    org_attr = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    organization = org_attr[0].value if org_attr else "unknown"

    # Determine tenant ID
    # In org mode, all clients share the org tenant
    # In global mode, each installation is its own tenant
    if config.mode.value == "org":
        tenant_id = config.org_name
    else:
        tenant_id = installation_id or "global"

    return AuthContext(
        installation_id=installation_id or "unknown",
        tenant_id=tenant_id,
        cert_fingerprint=fingerprint,
        organization=organization,
    )


async def get_auth_context(request: Request) -> AuthContext:
    """FastAPI dependency for extracting auth context.

    Verifies client certificate and returns AuthContext.
    """
    config = get_config()

    # Skip auth for health endpoints
    if request.url.path in ("/health", "/ready"):
        return AuthContext(
            installation_id="health-check",
            tenant_id="system",
            cert_fingerprint="",
            organization="system",
            authenticated=False,
        )

    # Extract and verify certificate
    if config.require_client_cert:
        cert_pem = extract_client_cert(request)
        if not cert_pem:
            logger.warning("No client certificate provided")
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Client certificate required",
            )
        return verify_client_certificate(cert_pem)

    # No auth required (testing mode)
    return AuthContext(
        installation_id="anonymous",
        tenant_id="global",
        cert_fingerprint="",
        organization="anonymous",
        authenticated=False,
    )


def require_admin(auth: AuthContext) -> None:
    """Verify the request is from an admin.

    Admin status is determined by the is_admin flag in the certificate trust store.
    """
    if not auth.authenticated:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    # Check admin status from database
    if not is_admin_certificate(auth.cert_fingerprint):
        logger.warning(
            "Admin access denied",
            installation_id=auth.installation_id,
            fingerprint=auth.cert_fingerprint[:16],
        )
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
