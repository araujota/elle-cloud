# ELLE Cloud

Lightweight, ultra-secure container for ELLE anonymized incident reports. Supports vector search via fingerprint similarity and mTLS authentication.

## Features

- **Vector Search**: 15-dimensional fingerprint vectors for incident similarity matching
- **mTLS Authentication**: Client certificate-based authentication for secure access
- **Tenant Isolation**: Org mode for private vaults, global mode for shared knowledge
- **Surface Hash Matching**: Drift correlation via control surface hashes
- **SQLite Storage**: Simple, efficient storage with upgrade path to PostgreSQL

## Quick Start (Org Vault)

```bash
# Clone the repository
git clone https://github.com/anthropics/elle-cloud.git
cd elle-cloud

# Generate certificates for your organization
docker compose run --rm elle-cloud init-certs --org-name "my-org"

# Start the vault
docker compose up -d

# Issue a client certificate for an ELLE installation
docker compose run --rm elle-cloud issue-client-cert --installation-id "workstation-01"

# View logs
docker compose logs -f
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              ELLE Cloud Container                    │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌─────────────────┐   │
│  │ FastAPI  │  │  SQLite  │  │ mTLS Termination │   │
│  │   API    │──│ Storage  │  │ (client certs)   │   │
│  └──────────┘  └──────────┘  └─────────────────┘   │
│       │             │                │              │
│       ▼             ▼                ▼              │
│  ┌──────────┐  ┌──────────┐  ┌─────────────────┐   │
│  │Fingerprint│  │ Surface  │  │  Certificate    │   │
│  │  Vector   │  │  Hash    │  │    Manager      │   │
│  │  Search   │  │  Index   │  │                 │   │
│  └──────────┘  └──────────┘  └─────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/incidents` | POST | Submit anonymized incident |
| `/v1/incidents/{cloud_id}` | GET | Get incident by ID |
| `/v1/incidents/similar` | POST | Query similar incidents |
| `/v1/incidents/similar` | GET | Query similar (simple params) |
| `/v1/stats/{domain}` | GET | Get domain statistics |
| `/v1/stats` | GET | Get overall statistics |
| `/v1/admin/certs` | POST | Register certificate (admin) |
| `/v1/admin/certs/{fp}` | DELETE | Revoke certificate (admin) |
| `/health` | GET | Liveness probe |
| `/ready` | GET | Readiness probe |

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ELLE_CLOUD_MODE` | `org` | `org` for self-hosted, `global` for Anthropic cloud |
| `ELLE_CLOUD_ORG_NAME` | `default-org` | Organization name |
| `ELLE_CLOUD_BIND_HOST` | `0.0.0.0` | Server bind address |
| `ELLE_CLOUD_BIND_PORT` | `8443` | mTLS port |
| `ELLE_CLOUD_HEALTH_PORT` | `8080` | Health check port |
| `ELLE_CLOUD_DATA_DIR` | `/data` | SQLite database directory |
| `ELLE_CLOUD_CERT_DIR` | `/certs` | Certificate directory |
| `ELLE_CLOUD_LOG_LEVEL` | `info` | Log level |
| `ELLE_CLOUD_LOG_FORMAT` | `json` | `json` or `text` |
| `ELLE_CLOUD_REQUIRE_CLIENT_CERT` | `true` | Require mTLS |

## Usage Examples

### Submit an Incident

```bash
curl -k --cert ./certs/clients/workstation-01.crt \
        --key ./certs/clients/workstation-01.key \
        --cacert ./certs/ca.crt \
        -X POST https://localhost:8443/v1/incidents \
        -H "Content-Type: application/json" \
        -d '{
          "incident_id": "abc-123",
          "created_at_hour": "2024-01-15T14:00:00",
          "domain": "disk",
          "severity": "warning",
          "status": "resolved",
          "outcome": "improved",
          "fingerprint": {
            "disk_pressure": 0.85,
            "mem_pressure": 0.4
          },
          "action_summary": {
            "total_actions": 5,
            "successful_actions": 4
          },
          "confidence": 0.85,
          "original_hash": "unique-hash-123"
        }'
```

### Query Similar Incidents

```bash
curl -k --cert ./certs/clients/workstation-01.crt \
        --key ./certs/clients/workstation-01.key \
        --cacert ./certs/ca.crt \
        -X POST https://localhost:8443/v1/incidents/similar \
        -H "Content-Type: application/json" \
        -d '{
          "fingerprint": {
            "disk_pressure": 0.8,
            "mem_pressure": 0.5
          },
          "domain": "disk",
          "limit": 10,
          "min_similarity": 0.5
        }'
```

### Get Domain Statistics

```bash
curl -k --cert ./certs/clients/workstation-01.crt \
        --key ./certs/clients/workstation-01.key \
        --cacert ./certs/ca.crt \
        https://localhost:8443/v1/stats/disk
```

## Fingerprint Vector

The similarity search uses a 15-dimensional vector derived from the incident fingerprint:

| Dimension | Source | Normalization |
|-----------|--------|---------------|
| 0 | disk_pressure | 0-1 |
| 1 | mem_pressure | 0-1 |
| 2 | swap_pressure | 0-1 |
| 3 | cpu_pressure | clamped 0-1 |
| 4 | oom_count_1h | /10, max 1 |
| 5 | net_flaps_1h | /10, max 1 |
| 6 | service_failures_1h | /10, max 1 |
| 7 | auth_failures_1h | /10, max 1 |
| 8 | smart_pct_used_max | /100 |
| 9 | smart_media_errors | /10, max 1 |
| 10 | temp_max_c | /100 |
| 11 | docker_exited_count | /10, max 1 |
| 12 | entity_count | /20 |
| 13 | has_oom | binary |
| 14 | has_service_failures | binary |

Similarity is computed using cosine similarity, combined with surface hash matching.

## Development

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Type checking
mypy elle_cloud/

# Run locally (no auth)
ELLE_CLOUD_REQUIRE_CLIENT_CERT=false python -m elle_cloud.main
```

## Security

- **TLS 1.3 only**: Modern TLS with strong ciphers
- **mTLS**: Client certificates required for all API access
- **Tenant isolation**: Certificates determine tenant, no cross-tenant access
- **Deduplication**: `original_hash` prevents replay attacks
- **Audit logging**: All requests logged with certificate fingerprint

## License

MIT
