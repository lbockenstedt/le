# le — Certificate Management

Certificate producer spoke. Repo: `le`. `module_type = "certificates"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

A **producer** spoke that runs certbot ACME to issue/renew/revoke/list TLS certificates for the domains the hub manages. The hub **brokers** distribution: this spoke is the source of cert material (`LE_GET_CERT` pulls fullchain+key); target spokes apply it to their devices; `LE_MARK_DISTRIBUTED` is the hub's per-target ack recorded in the ledger. The lm-core `cert_distribution.py` runs the hub-side loop; this repo is the le spoke itself (ACME wrapper + ledger + control plane).

## Entrypoints

`python3 -m src.control_plane` (`LEControlPlane`), systemd `lm-le.service`, `User=root` (root because certbot binds :80 for HTTP-01 and writes `/etc/letsencrypt`). Installer `install_le.sh` (clones lm core to `/opt/lm/core`, le to `/opt/lm/le`, apt `certbot python3-certbot-dns-cloudflare python3-certbot-dns-route53`, `/etc/lm-le` DNS-creds dir, `lm-le.service`).

## Ports

No listener. Spoke dials hub on **443** (`/ws/spoke`, wss). certbot transiently binds **:80** for HTTP-01 `--standalone` (or `--webroot -w <path>`).

## Environment variables

- `.env`: `HUB_URL`, `SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`.
- `acme.py`: `LM_LE_LIVE_DIR` (`/etc/letsencrypt/live`), `LM_LE_CONFIG_DIR` (`/etc/letsencrypt`), `LM_LE_DNS_CREDS_DIR` (`/etc/lm-le`), `LM_LE_CERTBOT_BIN` (`certbot`).
- `le_spoke.py`: `LM_LE_LEDGER` (`/var/lib/lm/<spoke_id>/certs.json`), `renew_interval` via `UPDATE_CONFIG` (default 86400s).

## Install flags

`install_le.sh`: `--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--all-prereqs` (no-op). Default `SPOKE_ID=le-<hostname>`, `HUB_URL=wss://localhost:443/ws/spoke`. **No** `--tls-verify`/`--tls-ca-cert` (not wired in this installer).

## Key commands / handlers (`LESpoke.handle_command`, `src/le_spoke.py`)

`LE_GET_STATUS` (version, `certbot_present`, certs managed), `LE_LIST_CERTS`, `LE_GET_CERT` (returns `fullchain`/`privkey`/`chain`/`material_hash`/`not_after`; `privkey` masked in logs but returned for distribution), `LE_ISSUE_CERT` (`domain`, `email`, `challenge` http|dns, `webroot`, `dns_provider`, `dns_creds`/`dns_creds_ini`, `staging`, `key_type`, `targets[]`), `LE_RENEW_CERT` (one domain or all), `LE_REVOKE_CERT` (`domain`, `delete`), `LE_ADD_TARGET`/`LE_REMOVE_TARGET` (`domain`, `target.module_type`, `target.identifier`), `LE_MARK_DISTRIBUTED` (`domain`, `module_type`, `identifier`, `hash`, `status`, `message`), `UPDATE_CONFIG` (honors `renew_interval`), `GET_VERSION`, `SET_LOG_LEVEL`.

Background `_renew_loop`: daily reconcile of ledger vs `/etc/letsencrypt/live`, renews any cert within the 30-day window, refreshes `material_hash`/`not_after` so the hub re-pushes.

## HTTP-01 / DNS-01 (`src/acme.py`)

- `_normalize_challenge`: `http`/`http-01`/`http01` → `http`; `dns`/`dns-01`/`dns01` → `dns`; else `ValueError`.
- HTTP-01: `certbot certonly --standalone` (default) or `--webroot -w <webroot>`.
- DNS-01: `--dns-<provider> --dns-<provider>-credentials <ini>`; creds INI written atomically 0600 to `/etc/lm-le/dns-<provider>.ini` (`write_dns_creds`, never logged). Preinstalled apt plugins: cloudflare + route53; others installable on demand.
- Certs stored in certbot's native `/etc/letsencrypt/live/<name>/` layout so `certbot renew`/standard tooling still work; the LM ledger is the parallel index.

## Key files

`src/control_plane.py` (`LEControlPlane`, `run_hub_mode`), `src/le_spoke.py` (`LESpoke` + renewal loop), `src/acme.py` (certbot wrapper: `issue`/`renew`/`revoke`/`list_certs`/`read_material`/`expiring`), `src/ledger.py` (`Ledger` atomic JSON — `upsert_cert`/`add_target`/`remove_target`/`target_key`), `install_le.sh`, `tests/test_acme.py`, `tests/test_le_spoke.py`, `tests/test_ledger.py`, `requirements.txt`, `VERSION`.

## Notable behaviors & gotchas

- **README says "structured stubs" but current code wires real certbot** — the README is stale on that point.
- **Simplest spoke** — no listener port, no `--tls-verify` installer flag, no FastAPI dep. ACME producer + ledger.
- **Hub-side cert distribution** (`lm core cert_distribution.py`) is out of scope for the le repo; this spoke just produces + ledger-tracks cert material.

## Related pages

[architecture-topology.md](architecture-topology.md), [lm-hub.md](lm-hub.md), [opnsense.md](opnsense.md) (OPNsense `OPNSENSE_INSTALL_CERT` is a cert-distribution target), [install-flags.md](install-flags.md).