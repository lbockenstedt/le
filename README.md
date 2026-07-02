# le — Lab Manager Certificate Management module

A Lab Manager spoke that manages TLS certificate lifecycle (Let's Encrypt /
ACME): list, issue, renew, and revoke certificates for the domains this hub
manages. Connects to an LM hub over WebSocket, advertises `module_type =
"certificates"`, and answers `LE_*` commands relayed by the hub.

This first release ships **structured stubs** — the command dispatch and the
SUCCESS/ERROR contract are real, but the certbot/acme.sh integration is not yet
wired (handlers return a placeholder body + a `certbot_present` probe). The
seams for the real implementation are the `LE_*` branches in
`src/le_spoke.py::handle_command`.

## Install (on a spoke host)

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/le/main/install_le.sh | \
  bash -s -- --hub ws://hub-host:8765 --id le-spoke-1
```

Or, from the LM hub's `install_all.sh`, `le` is installed automatically as one
of the co-located spokes (clone `le` into `/opt/lm/le`, build the venv, enable
the `lm-le` systemd unit).

## Layout

```
le/
├── src/
│   ├── control_plane.py   # LEControlPlane(BaseControlPlane), module_type="certificates"
│   └── le_spoke.py        # LESpoke(BaseSpoke) — LE_* command dispatch + get_status
├── tests/                 # pytest: dispatch contract + get_status shape
├── install_le.sh          # clones core+le into /opt/lm, venv, lm-le.service
├── requirements.txt
└── VERSION
```

Service: `lm-le` (User=svc_lm, log `/var/log/lm/lm-le.log`). Spoke id prefix
`le`; default id `le-spoke-1`. Module type `certificates` (label "Certificate
Management").

## Commands

| Hub command      | Action                                  |
|------------------|------------------------------------------|
| `LE_LIST_CERTS`  | List managed certificates               |
| `LE_ISSUE_CERT`  | Issue a cert (`domain`, `email`, `challenge?`, `staging?`) |
| `LE_RENEW_CERT`  | Renew one cert (`domain`) or all         |
| `LE_REVOKE_CERT` | Revoke + remove a cert (`domain`)        |
| `LE_GET_STATUS`  | Module status (version, certbot present, count) |

## Tests

```bash
python3 -m pytest tests -q
```