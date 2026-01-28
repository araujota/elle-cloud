# ELLE Cloud Team Setup Guide

How to set up a shared incident vault for your team so all ELLE installations can learn from each other's resolved incidents.

## Overview

When multiple team members run ELLE on their workstations or servers, each installation learns from its own incident history. By connecting them to a shared ELLE Cloud vault, the entire team benefits from collective knowledge:

- **Workstation A** resolves a disk pressure issue
- **Workstation B** encounters the same pattern days later
- ELLE on B queries the vault and finds A's successful resolution
- B applies the same approach with high confidence

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  Alice's    │   │   Bob's     │   │  Prod       │
│ Workstation │   │ Workstation │   │  Server     │
│   (ELLE)    │   │   (ELLE)    │   │   (ELLE)    │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │
       │    mTLS (unique client certs)     │
       ▼                 ▼                 ▼
    ───────────────────────────────────────────
                        │
               ┌────────▼────────┐
               │   ELLE Cloud    │
               │  (team vault)   │
               │                 │
               │  Shared tenant: │
               │  "acme-corp"    │
               └─────────────────┘
```

## Prerequisites

- Docker and Docker Compose on the vault host
- Network access from all ELLE installations to the vault (port 8443)
- One team member designated as **vault admin**

## Step 1: Vault Admin Sets Up the Server

The vault admin runs these commands on the server that will host the shared vault.

### 1.1 Clone and Configure

```bash
# On the vault server
git clone https://github.com/anthropics/elle-cloud.git
cd elle-cloud

# Optional: customize settings in .env
cat > .env << 'EOF'
ELLE_CLOUD_ORG_NAME=acme-corp
ELLE_CLOUD_LOG_LEVEL=info
EOF
```

### 1.2 Initialize Certificates

```bash
docker compose run --rm elle-cloud init-certs --org-name "acme-corp"
```

This creates:
- **CA certificate** (`/certs/ca.crt`) - distributes to all team members
- **Server certificate** - used by the vault
- **Admin certificate** (`/certs/clients/admin-acme-corp.crt`) - for vault administration

Output:
```
Certificates created for organization: acme-corp
  CA Certificate: /certs/ca.crt
  Server Certificate: /certs/server.crt

Admin certificate (has admin privileges):
  Certificate: /certs/clients/admin-acme-corp.crt
  Key: /certs/clients/admin-acme-corp.key
```

### 1.3 Start the Vault

```bash
docker compose up -d

# Verify it's running
docker compose logs -f
```

The vault is now listening on port 8443 with mTLS enabled.

## Step 2: Issue Certificates for Team Members

The vault admin issues a unique certificate for each ELLE installation.

### 2.1 Issue Client Certificates

```bash
# For Alice's workstation
docker compose run --rm elle-cloud issue-client-cert \
  --installation-id "alice-workstation"

# For Bob's workstation
docker compose run --rm elle-cloud issue-client-cert \
  --installation-id "bob-workstation"

# For the production server
docker compose run --rm elle-cloud issue-client-cert \
  --installation-id "prod-server-01"

# For the staging server
docker compose run --rm elle-cloud issue-client-cert \
  --installation-id "staging-server-01"
```

Each command creates a certificate/key pair in `/certs/clients/`.

### 2.2 List Issued Certificates

```bash
ls -la certs/clients/
```

```
admin-acme-corp.crt
admin-acme-corp.key
alice-workstation.crt
alice-workstation.key
bob-workstation.crt
bob-workstation.key
prod-server-01.crt
prod-server-01.key
staging-server-01.crt
staging-server-01.key
```

## Step 3: Distribute Certificates Securely

Each team member needs three files:
1. `ca.crt` - the CA certificate (same for everyone)
2. `<installation-id>.crt` - their unique client certificate
3. `<installation-id>.key` - their unique private key

### Secure Distribution Methods

**Option A: Secure file transfer**
```bash
# Admin creates a bundle for Alice
tar -czf alice-certs.tar.gz \
  certs/ca.crt \
  certs/clients/alice-workstation.crt \
  certs/clients/alice-workstation.key

# Transfer via secure channel (scp, encrypted email, etc.)
scp alice-certs.tar.gz alice@alice-workstation:~/
```

**Option B: Internal secrets manager**
```bash
# Store in HashiCorp Vault, AWS Secrets Manager, etc.
vault kv put secret/elle/alice-workstation \
  ca_cert=@certs/ca.crt \
  client_cert=@certs/clients/alice-workstation.crt \
  client_key=@certs/clients/alice-workstation.key
```

**Option C: Ansible/Puppet deployment**
```yaml
# ansible playbook snippet
- name: Deploy ELLE certificates
  copy:
    src: "{{ item.src }}"
    dest: "/etc/elle/certs/{{ item.dest }}"
    mode: "{{ item.mode }}"
  loop:
    - { src: "ca.crt", dest: "ca.crt", mode: "0644" }
    - { src: "{{ inventory_hostname }}.crt", dest: "client.crt", mode: "0644" }
    - { src: "{{ inventory_hostname }}.key", dest: "client.key", mode: "0600" }
```

## Step 4: Configure Each ELLE Installation

Each team member configures their ELLE to connect to the shared vault.

### 4.1 Place Certificates

```bash
# On each team member's machine
mkdir -p ~/.config/elle/certs

# Extract the bundle (if using tar method)
tar -xzf ~/alice-certs.tar.gz -C ~/.config/elle/certs --strip-components=1

# Set permissions
chmod 600 ~/.config/elle/certs/*.key
chmod 644 ~/.config/elle/certs/*.crt
```

### 4.2 Configure ELLE

Add to ELLE's configuration (`~/.config/elle/config.toml` or environment):

```toml
[cloud]
enabled = true
endpoint = "https://vault.acme-corp.internal:8443"
ca_cert = "~/.config/elle/certs/ca.crt"
client_cert = "~/.config/elle/certs/alice-workstation.crt"
client_key = "~/.config/elle/certs/alice-workstation.key"
```

Or via environment variables:

```bash
export ELLE_CLOUD_ENABLED=true
export ELLE_CLOUD_ENDPOINT="https://vault.acme-corp.internal:8443"
export ELLE_CLOUD_CA_CERT="$HOME/.config/elle/certs/ca.crt"
export ELLE_CLOUD_CLIENT_CERT="$HOME/.config/elle/certs/alice-workstation.crt"
export ELLE_CLOUD_CLIENT_KEY="$HOME/.config/elle/certs/alice-workstation.key"
```

### 4.3 Verify Connection

```bash
# Test the connection
curl --cert ~/.config/elle/certs/alice-workstation.crt \
     --key ~/.config/elle/certs/alice-workstation.key \
     --cacert ~/.config/elle/certs/ca.crt \
     https://vault.acme-corp.internal:8443/health

# Expected: {"status":"ok"}
```

## Step 5: Verify Team Sharing Works

### 5.1 Submit a Test Incident

From Alice's workstation:
```bash
curl --cert ~/.config/elle/certs/alice-workstation.crt \
     --key ~/.config/elle/certs/alice-workstation.key \
     --cacert ~/.config/elle/certs/ca.crt \
     -X POST https://vault.acme-corp.internal:8443/v1/incidents \
     -H "Content-Type: application/json" \
     -d '{
       "incident_id": "test-001",
       "created_at_hour": "2024-01-15T14:00:00",
       "domain": "disk",
       "severity": "warning",
       "status": "resolved",
       "outcome": "improved",
       "fingerprint": {"disk_pressure": 0.85},
       "action_summary": {"total_actions": 3, "successful_actions": 3},
       "confidence": 0.9,
       "original_hash": "alice-test-001"
     }'
```

### 5.2 Query from Another Installation

From Bob's workstation:
```bash
curl --cert ~/.config/elle/certs/bob-workstation.crt \
     --key ~/.config/elle/certs/bob-workstation.key \
     --cacert ~/.config/elle/certs/ca.crt \
     -X POST https://vault.acme-corp.internal:8443/v1/incidents/similar \
     -H "Content-Type: application/json" \
     -d '{
       "fingerprint": {"disk_pressure": 0.80},
       "domain": "disk",
       "limit": 5,
       "min_similarity": 0.5
     }'
```

Bob should see Alice's incident in the results, confirming cross-installation sharing works.

## Network Configuration

### Firewall Rules

The vault server needs to accept connections on port 8443:

```bash
# UFW
sudo ufw allow 8443/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
```

### DNS or Hosts Entry

Each team member needs to resolve the vault hostname:

```bash
# Option A: Internal DNS
# Add A record: vault.acme-corp.internal -> 10.0.1.50

# Option B: /etc/hosts on each machine
echo "10.0.1.50 vault.acme-corp.internal" | sudo tee -a /etc/hosts
```

### TLS Certificate SANs

If the vault is accessed via IP or custom hostname, regenerate server certs:

```bash
# In docker-compose.yaml, add:
environment:
  - ELLE_CLOUD_BIND_HOST=vault.acme-corp.internal
```

## Ongoing Operations

### Adding New Team Members

```bash
# Vault admin issues new certificate
docker compose run --rm elle-cloud issue-client-cert \
  --installation-id "charlie-laptop"

# Distribute to Charlie via secure channel
```

### Revoking Access

When someone leaves the team:

```bash
# Using admin certificate
curl --cert certs/clients/admin-acme-corp.crt \
     --key certs/clients/admin-acme-corp.key \
     --cacert certs/ca.crt \
     -X DELETE "https://localhost:8443/admin/certs/<fingerprint>?reason=employee-departure"
```

### Viewing Statistics

```bash
# Team-wide stats
curl --cert ~/.config/elle/certs/alice-workstation.crt \
     --key ~/.config/elle/certs/alice-workstation.key \
     --cacert ~/.config/elle/certs/ca.crt \
     https://vault.acme-corp.internal:8443/v1/stats
```

### Backup

```bash
# Backup the data volume
docker compose stop
tar -czf elle-cloud-backup-$(date +%Y%m%d).tar.gz data/ certs/
docker compose start
```

## Troubleshooting

### "Certificate verification failed"

- Verify the CA cert matches: `openssl x509 -in ca.crt -noout -fingerprint`
- Check cert expiration: `openssl x509 -in client.crt -noout -dates`
- Ensure the client cert was issued by this CA

### "Connection refused"

- Verify vault is running: `docker compose ps`
- Check firewall allows 8443: `nc -zv vault.acme-corp.internal 8443`
- Verify DNS resolution: `dig vault.acme-corp.internal`

### "Admin access required"

- Only the certificate created during `init-certs` has admin privileges
- Regular client certificates cannot manage other certificates

### Rate Limited (429)

- Default limits: 30 submissions/min, 60 queries/min per IP
- If hitting limits, check for runaway ELLE processes

## Security Considerations

1. **Protect private keys**: Client `.key` files should be `chmod 600`
2. **Secure distribution**: Never send keys over unencrypted channels
3. **Network isolation**: Consider placing vault on internal network only
4. **Audit logs**: Check `docker compose logs` for suspicious access
5. **Certificate rotation**: Certificates expire after 1 year by default

## Quick Reference

| Role | Command |
|------|---------|
| Initialize vault | `docker compose run --rm elle-cloud init-certs --org-name "org"` |
| Start vault | `docker compose up -d` |
| Issue cert | `docker compose run --rm elle-cloud issue-client-cert --installation-id "name"` |
| Test connection | `curl --cert client.crt --key client.key --cacert ca.crt https://host:8443/health` |
| View logs | `docker compose logs -f` |
| Stop vault | `docker compose down` |
