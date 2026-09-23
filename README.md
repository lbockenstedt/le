# le — Let's Encrypt / ACME Certificate Spoke (Lab Manager Module)

TLS certificate lifecycle management spoke for the Lab Manager (LM) hub-and-spoke ecosystem (`module_type = "certificates"`). Manages real ACME (Let's Encrypt) certificate issuance, DNS-01 and HTTP-01 validations, certificate revocation, automated renewals, target distribution tracking, and hub-brokered certificate delivery.

---

## Architecture & Overview

The `le` spoke operates as a certificate **producer** within Lab Manager. The spoke connects to the hub via an outbound WebSocket connection (port 443) and executes ACME workflows using `certbot`.

```
 +-------------------------------------------------------+
 |                     Lab Manager Hub                   |
 +-------------------------------------------------------+
      | (Outbound WebSocket TLS:443)       ^
      v                                    | (LE_GET_CERT / LE_CERT_RENEWED)
 +-------------------------------------------------------+
 |                   LEControlPlane                      |
 |  (Registers module "certificates", routes LE commands)|
 +-------------------------------------------------------+
      |
      v
 +-------------------------------------------------------+
 |                 LESpoke (Coordinator)                 |
 |  - Command dispatch & background renew loop           |
 |  - Event emissions (LE_CERT_RENEWED / FAILED)         |
 +-------------------------------------------------------+
      |                   |                     |
      v                   v                     v
+-------------+  +------------------+  +------------------+
|   acme.py   |  |    he_dns.py     |  |    ledger.py     |
| - certbot   |  | - DNS-01 hook    |  | - Atomic JSON    |
|   wrapper   |  | - HE.net session |  | - Target tracking|
| - HTTP/DNS  |  | - Dynamic update |  | - Hash & expiry  |
+-------------+  +------------------+  +------------------+
      |
      v
 [Let's Encrypt / ACME Directory]
```

- **Spoke Coordinator (`LESpoke`):** Central coordinator handling hub commands, managing the daily background renewal loop, and emitting real-time renewal events (`LE_CERT_RENEWED`).
- **ACME Certbot Wrapper (`acme.py`):** Async subprocess client wrapping `certbot` for HTTP-01 standalone/webroot and DNS-01 challenges, reading issued PEM materials, inspecting x509 expiration, and verifying ACME profile capabilities.
- **Hurricane Electric DNS Provider (`he_dns.py`):** Dedicated DNS-01 authenticator hook that logs into Hurricane Electric (he.net) DNS management to add and remove `_acme-challenge` TXT records dynamically.
- **On-Disk Atomic Certificate Ledger (`ledger.py`):** Thread-safe, atomic JSON store (`certs.json`) tracking certificate fingerprints, renewal windows, expiration timestamps, and target deployment states.
- **Hub-Brokered Certificate Distribution (`LE_GET_CERT` -> `INSTALL_CERT`):** The hub queries `LE_GET_CERT` to pull full chains and private keys, and pushes them down to target spokes (`opnsense`, `pxmx`, `ldap`, `cppm`) via `INSTALL_CERT`.

---

## Features

- **Certificate Listing & Lifecycle Details:** Comprehensive reporting of managed domains, SAN lists, expiration dates (`not_after`), effective renewal windows, and SHA-256 material hashes.
- **DNS-01 ACME Issuance & Renewal:** Automated issuance for wildcards and internal systems using DNS validation via Hurricane Electric, Cloudflare, Route53, and extensible DNS providers.
- **Certificate Revocation:** Complete revocation against ACME directories with automatic cleanup of local disk certificates and ledger entries.
- **Target Distribution Tracking:** Manages distribution lists per certificate across both spoke modules and agent targets, recording per-target push hashes, timestamps, and deployment statuses (`LE_MARK_DISTRIBUTED`).
- **DNS Credentials Management:** Vault-backed and local multi-tenant DNS-01 credentials storage (`/etc/lm-le/`) with secure file permissions (0600) and automatic secret redaction.
- **Certbot Hooks & Automated Renewal Timers:** Daily background renewal sweeps that identify certificates within their renewal window (default 30 days or custom), invoke certbot renew, and trigger immediate distribution pushes upon change.

---

## Spoke Commands Reference

The following commands are handled by `LESpoke`:

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `LE_GET_STATUS` | *None* | Reports spoke status, version, `certbot_present` flag, and managed certificate count. |
| `LE_LIST_CERTS` | *None* | Lists all managed certificates in the ledger with their target distribution states. |
| `LE_GET_CERT` | `domain` | Retrieves full chain, private key, CA chain, material hash, and expiration for hub distribution. |
| `LE_ISSUE_CERT` | `domain`, `email`, `challenge`, `dns_provider`, `staging`, `targets` | Requests a new TLS certificate via ACME using HTTP-01, DNS-01, or TLS-ALPN. |
| `LE_SET_CLIENTAUTH` | `domain`, `client_auth` | Toggles client authentication (mTLS `clientAuth` EKU) flag for a certificate. |
| `LE_ACME_INFO` | *None* | Probes and returns local certbot version and ACME profile capabilities. |
| `LE_RENEW_CERT` | `domain` (optional), `force` | Triggers renewal for a specific domain or all eligible managed certificates. |
| `LE_SYNC_VAULT_DNS` | `he_username`, `he_password`, credentials payload | Syncs DNS-01 provider credentials from the hub's Credential Vault to local 0600 files. |
| `LE_REVOKE_CERT` | `domain`, `delete` | Revokes the active certificate with the ACME CA and purges local files. |
| `LE_ADD_TARGET` | `domain`, `module_type`, `identifier` | Registers a new deployment destination module or spoke for a certificate. |
| `LE_REMOVE_TARGET` | `domain`, `idx` | Removes a target destination by its index from the certificate's target list. |
| `LE_MARK_DISTRIBUTED`| `domain`, `module_type`, `identifier`, `hash`, `status` | Records the hub's per-target push result and updates distribution tracking state. |
| `LE_DEPLOY_TO_AGENT` | `agent_id`, `domain`, `helper_path` | Deploys certificate material directly to a target Agent host via file drop and helper script. |
| `LE_LIST_DNS_CREDS` | `tenant_id` | Lists stored DNS provider credentials for a tenant (with secrets masked). |
| `LE_SET_DNS_CRED` | `tenant_id`, `name`, `provider`, `fields` | Securely stores DNS API credentials for DNS-01 validation. |
| `LE_DELETE_DNS_CRED` | `tenant_id`, `name` | Deletes a stored DNS credential set. |
| `LE_SET_HE_LOGIN` | `he_username`, `he_password` | Saves persistent Hurricane Electric account login credentials for DNS-01 automation. |
| `LE_GET_HE_LOGIN` | *None* | Checks if Hurricane Electric login credentials are currently configured. |
| `UPDATE_CONFIG` | `renew_interval`, config dict | Reconfigures spoke settings and restarts the background renewal loop. |
| `GET_VERSION` | *None* | Returns the module semantic version from the `VERSION` file. |

---

<!-- INSTALLERS:START -->
## Installation

Every installer in this repo, with every flag and environment variable it accepts.
Installers are idempotent — re-running one updates code and preserves credentials.

### Certificate-management spoke — `install_le.sh`

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/le/main/install_le.sh \
  | sudo bash -s -- --hub lm-hub.lrbtechnologies.com
```

Runs as **root**: certbot binds port 80 for HTTP-01, writes `/etc/letsencrypt`, and the spoke stores root-only DNS credentials in `/etc/lm-le`. `HUB_URL` defaults to `auto` (discover on every connect).

| Flag | Purpose |
| :--- | :--- |
| `--hub URL` | Hub WebSocket URL. A bare host is fine — `lm-hub.example.com` becomes `wss://lm-hub.example.com:443`, `host:port` gets a `wss://` prefix, and an explicit `ws://`/`wss://` is left alone. Omit it to auto-discover the hub (DNS `lm-hub.<suffix>`, then mDNS `_lm-hub._tcp.local.`). |
| `--id`, `--name` | Pin the spoke id. Omitted, the id derives from the hostname, so a renamed clone reconnects under its new name. |
| `--secret` | Pre-shared spoke secret. |
| `--hub-secret` | Hub PSK for auto-approval. Without it the spoke lands in *pending approval* in the WebUI. |
| `--all-prereqs` | Accepted and ignored — kept so the hub's install-module call doesn't abort. |

**Environment overrides:** `HUB_URL` (same normalization as `--hub`), `SPOKE_ID`.
<!-- INSTALLERS:END -->