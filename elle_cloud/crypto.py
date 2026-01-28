"""Certificate management for ELLE Cloud.

Handles:
- CA certificate generation for org vaults
- Server certificate generation
- Client certificate issuance for ELLE installations
- Certificate fingerprint computation
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import NamedTuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from elle_cloud.config import CloudConfig, get_config

logger = logging.getLogger(__name__)

# Certificate validity periods
CA_VALIDITY_DAYS = 3650  # 10 years
SERVER_VALIDITY_DAYS = 365  # 1 year
CLIENT_VALIDITY_DAYS = 365  # 1 year

# Key size
RSA_KEY_SIZE = 4096


class CertificatePaths(NamedTuple):
    """Paths to certificate files."""

    ca_cert: Path
    ca_key: Path
    server_cert: Path
    server_key: Path


class ClientCertificate(NamedTuple):
    """Generated client certificate and key."""

    cert_pem: bytes
    key_pem: bytes
    fingerprint: str
    installation_id: str
    expires_at: datetime


class CloudCrypto:
    """Certificate management for ELLE Cloud."""

    def __init__(self, config: CloudConfig | None = None):
        """Initialize crypto manager.

        Args:
            config: Cloud configuration. Uses global config if None.
        """
        self.config = config or get_config()

    def init_certs(
        self, org_name: str | None = None, create_admin: bool = True
    ) -> tuple[CertificatePaths, ClientCertificate | None]:
        """Initialize CA and server certificates.

        Creates the certificate directory and generates:
        - CA certificate and key
        - Server certificate signed by CA
        - (Optional) First admin client certificate

        Args:
            org_name: Organization name for CA. Uses config if None.
            create_admin: Whether to create an initial admin certificate.

        Returns:
            Tuple of (certificate paths, admin client certificate or None).
        """
        org = org_name or self.config.org_name

        # Ensure directories exist
        self.config.cert_dir.mkdir(parents=True, exist_ok=True)
        self.config.clients_dir.mkdir(parents=True, exist_ok=True)

        paths = CertificatePaths(
            ca_cert=self.config.ca_cert_path,
            ca_key=self.config.ca_key_path,
            server_cert=self.config.server_cert_path,
            server_key=self.config.server_key_path,
        )

        # Generate CA
        logger.info("Generating CA certificate for %s", org)
        self._generate_ca(paths.ca_cert, paths.ca_key, org)

        # Generate server cert
        logger.info("Generating server certificate")
        self._generate_server_cert(
            paths.ca_cert,
            paths.ca_key,
            paths.server_cert,
            paths.server_key,
            org,
        )

        # Generate initial admin certificate
        admin_cert = None
        if create_admin:
            admin_id = f"admin-{org}"
            logger.info("Generating initial admin certificate for %s", admin_id)
            admin_cert = self.issue_client_certificate(admin_id)

        return paths, admin_cert

    def ensure_certificates(self) -> CertificatePaths:
        """Ensure all required certificates exist, generating if needed.

        Returns:
            Paths to all certificate files.
        """
        paths = CertificatePaths(
            ca_cert=self.config.ca_cert_path,
            ca_key=self.config.ca_key_path,
            server_cert=self.config.server_cert_path,
            server_key=self.config.server_key_path,
        )

        # Check if certs exist
        if not paths.ca_cert.exists() or not paths.ca_key.exists():
            raise RuntimeError(
                "CA certificate not found. Run 'init-certs' first to generate certificates."
            )

        if not paths.server_cert.exists() or not paths.server_key.exists():
            raise RuntimeError(
                "Server certificate not found. Run 'init-certs' first to generate certificates."
            )

        return paths

    def issue_client_certificate(self, installation_id: str) -> ClientCertificate:
        """Issue a client certificate for an ELLE installation.

        Args:
            installation_id: Unique identifier for the ELLE installation.

        Returns:
            ClientCertificate with PEM-encoded cert, key, and metadata.
        """
        paths = self.ensure_certificates()

        # Load CA
        ca_cert = self._load_cert(paths.ca_cert)
        ca_key = self._load_key(paths.ca_key)

        # Generate client key
        client_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
        )

        # Build client certificate
        org_name = self.config.org_name
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"ELLE Client - {org_name}"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_name[:64]),
                x509.NameAttribute(NameOID.COMMON_NAME, installation_id),
            ]
        )

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=CLIENT_VALIDITY_DAYS)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(expires_at)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        fingerprint = self.compute_fingerprint(cert_pem)

        # Save to clients directory
        client_cert_path = self.config.clients_dir / f"{installation_id}.crt"
        client_key_path = self.config.clients_dir / f"{installation_id}.key"

        client_cert_path.write_bytes(cert_pem)
        client_key_path.write_bytes(key_pem)
        client_key_path.chmod(0o600)

        logger.info(
            "Issued client certificate for %s (fingerprint: %s...)",
            installation_id,
            fingerprint[:16],
        )

        return ClientCertificate(
            cert_pem=cert_pem,
            key_pem=key_pem,
            fingerprint=fingerprint,
            installation_id=installation_id,
            expires_at=expires_at,
        )

    def compute_fingerprint(self, cert_pem: bytes) -> str:
        """Compute SHA-256 fingerprint of a PEM certificate.

        Args:
            cert_pem: PEM-encoded certificate.

        Returns:
            Hex-encoded SHA-256 fingerprint.
        """
        cert = x509.load_pem_x509_certificate(cert_pem)
        return cert.fingerprint(hashes.SHA256()).hex()

    def verify_client_cert(self, cert_pem: bytes) -> tuple[bool, str | None, str | None]:
        """Verify a client certificate against our CA.

        Args:
            cert_pem: PEM-encoded client certificate.

        Returns:
            Tuple of (is_valid, installation_id, error_message).
        """
        try:
            paths = self.ensure_certificates()
            ca_cert = self._load_cert(paths.ca_cert)
            client_cert = x509.load_pem_x509_certificate(cert_pem)

            # Check issuer matches our CA
            if client_cert.issuer != ca_cert.subject:
                return False, None, "Certificate not issued by our CA"

            # Check validity period
            now = datetime.now(timezone.utc)
            if client_cert.not_valid_before > now:
                return False, None, "Certificate not yet valid"
            if client_cert.not_valid_after < now:
                return False, None, "Certificate expired"

            # Verify signature
            try:
                ca_cert.public_key().verify(
                    client_cert.signature,
                    client_cert.tbs_certificate_bytes,
                    client_cert.signature_algorithm_parameters,
                )
            except Exception:
                return False, None, "Certificate signature invalid"

            # Extract installation_id from CN
            cn = client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not cn:
                return False, None, "Certificate missing CN"

            installation_id = cn[0].value
            return True, installation_id, None

        except Exception as e:
            logger.exception("Certificate verification failed")
            return False, None, str(e)

    def _generate_ca(self, cert_path: Path, key_path: Path, org_name: str) -> None:
        """Generate a self-signed CA certificate."""
        # Generate CA key
        ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
        )

        # Build CA certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"ELLE Cloud - {org_name}"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"ELLE Cloud CA - {org_name}"),
            ]
        )

        now = datetime.now(timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=CA_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        # Write certificate
        cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

        # Write key with restricted permissions
        key_path.write_bytes(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)

        logger.info("Generated CA certificate: %s", cert_path)

    def _generate_server_cert(
        self,
        ca_cert_path: Path,
        ca_key_path: Path,
        server_cert_path: Path,
        server_key_path: Path,
        org_name: str,
    ) -> None:
        """Generate server certificate signed by CA."""
        ca_cert = self._load_cert(ca_cert_path)
        ca_key = self._load_key(ca_key_path)

        # Generate server key
        server_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
        )

        # Build server certificate
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"ELLE Cloud - {org_name}"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"ELLE Cloud Server - {org_name}"),
            ]
        )

        # Build SAN extension
        san_names: list[x509.GeneralName] = [
            x509.DNSName("localhost"),
            x509.IPAddress(ip_address("127.0.0.1")),
            x509.IPAddress(ip_address("::1")),
        ]

        # Add bind host if it's a specific IP
        bind_host = self.config.bind_host
        if bind_host and bind_host not in ("0.0.0.0", "::"):
            try:
                san_names.append(x509.IPAddress(ip_address(bind_host)))
            except ValueError:
                san_names.append(x509.DNSName(bind_host))

        now = datetime.now(timezone.utc)
        server_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=SERVER_VALIDITY_DAYS))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName(san_names),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        # Write certificate
        server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))

        # Write key with restricted permissions
        server_key_path.write_bytes(
            server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        server_key_path.chmod(0o600)

        logger.info("Generated server certificate: %s", server_cert_path)

    def _load_cert(self, path: Path) -> x509.Certificate:
        """Load a PEM certificate from disk."""
        return x509.load_pem_x509_certificate(path.read_bytes())

    def _load_key(self, path: Path) -> rsa.RSAPrivateKey:
        """Load a PEM private key from disk."""
        key = serialization.load_pem_private_key(
            path.read_bytes(),
            password=None,
        )
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("Expected RSA private key")
        return key
