# Agent-hosting topology — which spokes serve `/ws/agent`

The tiered Hub → Spoke → Agent model is "always-a-spoke": a dumb device-mode
**Agent** never talks to the hub. It dials a **spoke's** `/ws/agent` listener
(loopback `ws://127.0.0.1:<port>` when co-located, or `wss://<spoke>:<port>` when
split). The spoke holds the role's logic + cert custody and drives the Agent with
just two primitives — `WRITE_FILE` and `RUN_COMMAND`. The Agent is a thin
executor.

A spoke opts into hosting Agents by subclassing `AgentHostingControlPlane`
(core/src/messaging/agent_hosting.py) instead of `BaseControlPlane`. The
listener is **opt-in** (`AGENT_LISTENER_OPT_IN = True` + a `*_AGENT_LISTENER=1`
env), so a spoke that only brokers data through the hub is byte-identical to
today with the listener off.

## Which spokes host Agents

| Module      | Control plane base           | Hosts `/ws/agent`? | Why                                                                          |
|-------------|------------------------------|--------------------|------------------------------------------------------------------------------|
| `pxmx`      | `AgentHostingControlPlane`   | yes (default-on)   | Proxmox node agent — local exec (qm/pct/pvesh), VNC, PTY, telemetry.         |
| `cs`        | `AgentHostingControlPlane`   | yes (opt-in)       | Client-sim agent — local simulation runtime on the cert-target/sim box.      |
| `netbox`    | `AgentHostingControlPlane`   | yes (opt-in)       | NetBox-host agent — cert custodian; installs the NetBox nginx cert.          |
| `le`        | `AgentHostingControlPlane`   | yes (opt-in)       | Cert-target agent — installs certs on boxes that have no spoke module.       |
| `opnsense`  | `BaseControlPlane`            | **no** (API proxy) | The firewall IS the appliance; it can't run our agent. Spoke proxies its API. |
| `cppm`      | `BaseControlPlane`            | **no** (API proxy) | ClearPass is the appliance; it can't run our agent. Spoke proxies its API.    |
| `nw`        | `BaseControlPlane`            | **no** (API proxy) | Switches/gateways are appliances; SSH/REST/SNMP proxied by the spoke.        |
| `dns`/`dhcp`/`ldap`/`statuspage`/`console` | hub-hosting `GenericAgent` role | via the generic agent | In-repo roles with no standalone control plane — hosted as sub-spokes. |

`opnsense`/`cppm`/`nw` are **intentionally API-only** — a `/ws/agent` listener on
them would be dead code (the appliance can't run our agent). They broker their
appliance's API to the hub and never host an Agent.

## The le agent-host path (this module)

`le` brokers cert material to **spoke** targets through the hub (the existing
ledger `targets` flow — untouched). The `/ws/agent` listener adds an
**additional** target type for cert-target boxes that have no spoke module: a
dumb Agent on that box dials the le spoke, and the spoke drives it to install a
cert via `WRITE_FILE` + `RUN_COMMAND` (the same cert-custodian model netbox
uses).

### Ports + env (le)

| Knob                  | Default     | Notes                                                         |
|-----------------------|-------------|---------------------------------------------------------------|
| `LM_LE_AGENT_LISTENER`| unset (off) | Set `1` to bind the `/ws/agent` listener. Opt-in.              |
| `LM_LE_AGENT_PORT`    | `8445`      | Distinct from pxmx `8443` + netbox `8444` (co-located safe).   |
| `LM_LE_AGENT_LOOPBACK`| unset       | Force loopback-only (all-in-one topology).                    |
| Agent config path     | `/etc/lm-le-agent/config.json` | Shared `agent_secret` (mirrors netbox/pxmx).        |

### Deploy flow

1. **Make the le spoke an agent host** (on the le spoke box): set
   `LM_LE_AGENT_LISTENER=1` (+ `LM_LE_AGENT_PORT` if non-default) and restart
   `lm-le`. The listener binds; a cert for `/ws/agent` is ensured (reuses the
   spoke's cert if present, else self-signs — same as netbox/pxmx).
2. **Install the Agent on the cert-target box** (device mode), pointed at the
   le spoke:
   ```bash
   curl -fsSL <lm>/agent/install_agent.sh | sudo bash -s -- \
       --spoke-url wss://<le-spoke>:8445/ws/agent --secret <agent_secret>
   ```
   Omit `--secret` for zero-touch: the Agent appears pending in the WebUI
   (Setup → Spokes & Agents); approve it and the spoke pushes the secret.
3. **Provision the install helper** on the cert-target box (the Agent runs it):
   ```bash
   sudo install -m 0755 le/scripts/lm-le-install-cert /usr/local/bin/lm-le-install-cert
   # If the Agent doesn't run as root, grant least-privilege NOPASSWD:
   echo "lm-agent ALL=(ALL) NOPASSWD: /usr/local/bin/lm-le-install-cert" \
       | sudo tee /etc/sudoers.d/lm-le-install-cert
   ```
   The helper places the cert under `/etc/lm-le/certs/<domain>/` and reloads the
   configured service (`LM_LE_INSTALL_RELOAD_CMD`, default `systemctl reload
   nginx`). Override per-box for haproxy/apache/etc.
4. **Deploy** from the LE module: `LE_DEPLOY_TO_AGENT` (explicit, one cert → one
   Agent) or add an `agent` ledger target (`module_type: "agent"`,
   `identifier: <hostname>`; empty `identifier` = any Agent) and the spoke
   auto-deploys the cached cert when that Agent connects
   (`deploy_cached_cert_to_agent`, fired from `_on_agent_registered`).

The spoke validates the cert+key pair **in-process** (`ssl.load_cert_chain`
over 0600 temps — same guard the hub uses) before any material reaches a live
host, then `WRITE_FILE`s two 0600 temps + `RUN_COMMAND`s
`sudo -n /usr/local/bin/lm-le-install-cert <domain> <crt> <key>`, and cleans the
temps in `finally`. The helper prints `OK <msg>` on success / exits nonzero
with stderr on failure; the spoke maps that to `SUCCESS`/`ERROR` and records
the push in the ledger (same shape as `LE_MARK_DISTRIBUTED`).

### mTLS (optional, later)

Once the LE **wildcard** is distributed to the hub + spokes + this `/ws/agent`
listener, flip mutual TLS on (System → Active Sessions → Mutual TLS). If a cert
later expires, the Agent self-heals: it falls back to the PSK channel just long
enough for the spoke to re-deploy a fresh cert, then resumes mTLS. (Default-off,
permissive — `CERT_OPTIONAL`, not a gate.)

## See also

- `netbox/DEPLOY-AGENT-CERT.md` — the netbox cert-custodian pattern this mirrors.
- `lm/docs/architecture-topology.md` — the overall Hub → Spoke → Agent topology.
- `lm/docs/generic-agent.md` — the hub-hosting `GenericAgent` (the other shape).