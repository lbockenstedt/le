# le — Lab Manager Certificate Management module

A Lab Manager spoke that manages TLS certificate lifecycle (Let's Encrypt /
ACME): list, issue, renew, and revoke certificates for the domains this hub
manages. Connects to an LM hub over WebSocket, advertises `module_type =
"certificates"`, and answers `LE_*` commands relayed by the hub.

le is a **producer** spoke: it runs the real `certbot` ACME client to
issue/renew/revoke certs and tracks them + their distribution targets in an
atomic on-disk ledger. The hub **brokers** distribution — it pulls cert
material from le via `LE_GET_CERT` and pushes it to target spokes (OPNsense
firewall, pxmx hypervisor, ldap directory) via a generic `INSTALL_CERT`
command. The hub-side distribution loop lives in `lm core`; this repo is the
le spoke itself.

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

## Install (on a spoke host)

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/le/main/install_le.sh | \
  bash -s -- --hub wss://hub-host:443 --id le-spoke-1
```

`--hub` accepts a bare IP/host (normalized to `wss://<host>:443`), a full
`ws://`/`wss://` URL, or `auto` (the default — auto-discovery via DNS
`lm-hub.<suffix>` then mDNS). Or, from the LM hub's `install_all.sh`, `le` is
installed automatically as one of the co-located spokes (clone `lm` core into
`/opt/lm/core`, `le` into `/opt/lm/le`, build the venv, enable the `lm-le`
systemd unit).

## Layout

```
le/
├── src/
│   ├── control_plane.py   # LEControlPlane(BaseControlPlane), module_type="certificates"
│   ├── le_spoke.py        # LESpoke(BaseSpoke) — LE_* command dispatch + renewal loop
│   ├── acme.py            # certbot wrapper: issue/renew/revoke/list_certs/read_material
│   └── ledger.py          # Ledger — atomic JSON index of managed certs + targets
├── tests/                 # pytest: dispatch contract + acme argv + ledger
├── install_le.sh          # clones core+le into /opt/lm, venv, lm-le.service
├── requirements.txt
└── VERSION
```

Service: `lm-le` (**User=root**, because certbot binds privileged port 80 for
HTTP-01 and writes `/etc/letsencrypt` + `/etc/lm-le`; log
`/var/log/lm/lm-le.log`). Spoke id prefix `le`; default id `le-<hostname>`.
Module type `certificates` (label "Certificate Management").

## Commands

| Hub command          | Action |
|----------------------|--------|
| `LE_GET_STATUS`      | Module status (version, `certbot_present`, count) |
| `LE_LIST_CERTS`      | List managed certificates |
| `LE_GET_CERT`        | Pull cert material (`fullchain`/`privkey`/`chain`/`material_hash`/`not_after`) for hub distribution |
| `LE_ISSUE_CERT`      | Issue a cert (`domain`, `email`, `challenge` http\|dns\|tls-alpn, `webroot`, `dns_provider`, `dns_creds`/`dns_creds_ini`, `staging`, `key_type`, `targets[]`) |
| `LE_RENEW_CERT`      | Renew one cert (`domain`) or all |
| `LE_REVOKE_CERT`     | Revoke + remove a cert (`domain`, `delete`) |
| `LE_ADD_TARGET`      | Add a distribution target (`domain`, `target.module_type`, `target.identifier`) |
| `LE_REMOVE_TARGET`   | Remove a distribution target (`domain`, `idx`) |
| `LE_MARK_DISTRIBUTED`| Hub's per-target push ack (`domain`, `module_type`, `identifier`, `hash`, `status`, `message`) |
| `UPDATE_CONFIG`      | Apply hub config push (honors `renew_interval`) |
| `GET_VERSION`        | Return spoke version |
| `SET_LOG_LEVEL`      | Runtime log-level toggle from the WebUI |

A background renewal loop reconciles the ledger against
`/etc/letsencrypt/live` daily (or every `renew_interval` seconds), renews any
cert within the 30-day window, and emits `LE_CERT_RENEWED` to the hub so
distribution re-pushes immediately instead of waiting for the hourly sweep.

## Tests

```bash
python3 -m pytest tests -q
```

## Docs

See [`docs/le.md`](docs/le.md) for the full feature reference (env vars,
install flags, HTTP-01/DNS-01/TLS-ALPN-01 details, gotchas) and
[`docs/architecture-topology.md`](docs/architecture-topology.md) for the
shared LM hub/spoke/agent topology. The canonical copies live in
`lm/docs/`.