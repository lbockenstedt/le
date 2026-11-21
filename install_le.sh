#!/bin/bash

# Resolve the branch this checkout is deployed on so a dev/qa host is not
# hard-reset back onto main by an installer re-run. Detached HEAD (or any git
# failure) falls back to main.
_deployed_branch() {
  local b
  b=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)
  case "$b" in ""|HEAD) echo main ;; *) echo "$b" ;; esac
}

set -e

# Lab Manager — Certificate Management (le) spoke installer.
# Mirrors install_opnsense.sh: clones core + le into /opt/lm, builds the venv,
# writes .env, and installs the lm-le systemd service. Runs as ROOT because
# certbot binds port 80 (HTTP-01 standalone), writes /etc/letsencrypt, and the
# spoke writes root-only DNS credentials to /etc/lm-le.

# Default Configuration
# HUB_URL defaults to "auto": the spoke auto-discovers the hub (DNS
# lm-hub.<suffix> then mDNS) on each connect via BaseControlPlane — same as
# every other LM spoke. The old "ws://localhost:8765" default is BROKEN now that
# the hub's bare 8765 listener was retired by the unified-:443 merge (the hub
# serves only on :443); a co-located le dials a dead port and a remote le dials
# its own localhost. Pass --hub <url> to pin.
HUB_URL="${HUB_URL:-auto}"
SPOKE_ID="${SPOKE_ID:-le-$(hostname -s)}"
SPOKE_SECRET="lm-secret"
SECRET_GIVEN=0
HUB_SECRET_GIVEN=0
# TLS verification of the hub cert follows the core default ("auto") unless
# --tls-verify --tls-ca-cert <path> is passed; the hub CA cert must be
# supplied because it is not on this box (as pxmx).
TLS_VERIFY=false
TLS_CA_CERT=""

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_URL="$2"; shift ;;
        --id|--name) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; SECRET_GIVEN=1; shift ;;
        --hub-secret) HUB_SECRET="$2"; HUB_SECRET_GIVEN=1; shift ;;
        --tls-verify) TLS_VERIFY=true ;;
        --tls-ca-cert) TLS_CA_CERT="$2"; shift ;;
        --all-prereqs) ;;  # no-op; accepted for LM hub compat
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Accept a bare hub IP/host for --hub (e.g. `--hub 172.16.1.31` == `--hub
# wss://172.16.1.31:443`). A ws://|wss:// scheme or the "auto" sentinel is left
# as-is; host:port gets a scheme; a bare host defaults to the unified :443.
if [ -n "${HUB_URL:-}" ] && [ "$HUB_URL" != "auto" ]; then
    case "$HUB_URL" in
        ws://*|wss://*) : ;;
        *:[0-9]*)       HUB_URL="wss://${HUB_URL}" ;;
        *)              HUB_URL="wss://${HUB_URL}:443" ;;
    esac
fi

if [ -n "$TLS_CA_CERT" ] && ! $TLS_VERIFY; then
    echo "❌ --tls-ca-cert is used only with --tls-verify; pass both."
    exit 1
fi
if $TLS_VERIFY && [ -z "$TLS_CA_CERT" ]; then
    echo "❌ --tls-verify requires --tls-ca-cert <path> (the hub CA cert is not on this box)."
    exit 1
fi
if [ -n "$TLS_CA_CERT" ] && { [ ! -f "$TLS_CA_CERT" ] || [ ! -r "$TLS_CA_CERT" ]; }; then
    echo "❌ --tls-ca-cert $TLS_CA_CERT is not a readable file."
    exit 1
fi
# Store an absolute path: the service runs from its install directory, so a
# relative path (./hub-ca.pem) would no longer resolve at runtime.
case "$TLS_CA_CERT" in
    ""|/*) ;;
    *) TLS_CA_CERT="$(cd "$(dirname "$TLS_CA_CERT")" && pwd -P)/$(basename "$TLS_CA_CERT")" ;;
esac

if [ -z "$SPOKE_SECRET" ] || [ "$SPOKE_SECRET" == "lm-secret" ]; then
    # Keep the default PSK "lm-secret" so the =-attached ExecStart below
    # (--secret=$SPOKE_SECRET) resolves to "lm-secret" at runtime (zero-touch;
    # the hub auto-approves the default PSK or awaits admin approval in the LM
    # WebUI). Clearing to "" would pass an empty string (pending negotiation).
    SPOKE_SECRET="lm-secret"
    echo "ℹ️  No pre-shared secret — spoke will connect with the default PSK 'lm-secret'."
fi

echo "🚀 Installing Certificate Management (le) Module..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

apt-get update
apt-get install -y python3-pip python3-venv git curl openssl certbot \
    python3-certbot-dns-cloudflare python3-certbot-dns-route53
# Note: only cloudflare + route53 DNS plugins are preinstalled. Other certbot
# DNS plugins (e.g. python3-certbot-dns-google, -digitalocean) can be apt-apt
# installed on demand when a DNS-01 issue targets that provider. HTTP-01 needs
# no plugin. cryptography (cert parsing) is pip-installed into the venv below.

INSTALL_DIR="/opt/lm"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# ── Retire any legacy lm-generic-agent on this box ───────────────────────────
# Vendored from lm/agent/install_agent.sh:retire_legacy_agent — keep in sync.
# The legacy leaf (lm-generic-agent, /opt/lm/generic-agent/src/agent.py) is
# protocol-incompatible with the session-key-adopting hub: it has no
# SPOKE_UPDATE_SESSION_KEY / LOAD_ROLE handler, connects + passes mTLS but never
# adopts a session key, and the hub refuses to dispatch to it (every role on
# the box times out while the WS stays "online"). Purge it before the clone so
# even an aborted install can't leave the zombie connecting under this box's
# id. Idempotent + non-fatal if absent; never touches this installer's own unit
# ($SERVICE_NAME) — it's (re)written below.
SERVICE_NAME="lm-le"
retire_legacy_agent() {
    # Match the legacy leaf by BOTH its historical unit name AND — crucially —
    # by any unit whose definition ExecStarts the legacy path
    # (/opt/lm/generic-agent/src/agent.py). Older template-menu builders named
    # the unit variously (not always lm-generic-agent), so a name-only purge
    # silently misses it and the zombie keeps connecting. Never touch the
    # role-capable unit ($SERVICE_NAME) — the install (re)writes it below.
    local names="lm-generic-agent"
    local f
    # Scan ALL standard systemd unit dirs, not just /etc — older builders dropped
    # the unit under /lib or /usr/lib, so an /etc-only grep misses it entirely.
    for f in /etc/systemd/system/*.service /etc/systemd/system/*/*.service \
             /run/systemd/system/*.service \
             /lib/systemd/system/*.service /usr/lib/systemd/system/*.service; do
        [ -e "$f" ] || continue
        if grep -qE "/opt/lm/generic-agent" "$f" 2>/dev/null; then
            names="$names $(basename "$f" .service)"
        fi
    done
    # Also ask systemd directly which unit (if any) currently has a process whose
    # ExecStart is the legacy path — catches a unit in a non-standard location.
    local u
    for u in $(systemctl list-units --type=service --state=running,failed --no-legend --plain 2>/dev/null | awk '{print $1}'); do
        if systemctl show "$u" -p ExecStart 2>/dev/null | grep -q "/opt/lm/generic-agent"; then
            names="$names ${u%.service}"
        fi
    done
    local svc purged=0
    for svc in $(printf '%s\n' $names | sort -u); do
        [ -n "$svc" ] || continue
        [ "$svc" = "$SERVICE_NAME" ] && continue   # protect the new role-capable unit
        if [ -e "/etc/systemd/system/${svc}.service" ] \
           || systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -qE "^${svc}\.service"; then
            systemctl stop    "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            rm -f "/etc/systemd/system/${svc}.service"
            systemctl mask    "$svc" 2>/dev/null || true   # after rm → mask sticks (blocks manual restart)
            echo "🧹  Purged legacy leaf unit ${svc}.service."
            purged=1
        fi
    done
    # Also stop any live process still exec'ing the legacy path (belt-and-
    # suspenders if it was launched outside systemd), then remove the dir.
    if [ -d /opt/lm/generic-agent ]; then
        pkill -f "/opt/lm/generic-agent/src/agent.py" 2>/dev/null || true
        rm -rf /opt/lm/generic-agent
        echo "🧹  Removed legacy leaf dir /opt/lm/generic-agent."
        purged=1
    fi
    if [ "$purged" = 1 ]; then
        systemctl daemon-reload 2>/dev/null || true
        echo "    The role-capable ${SERVICE_NAME} now owns this box's spoke connection."
    fi
}
retire_legacy_agent

# Hub core is required (BaseControlPlane / BaseSpoke live in lm/core/src).
if [ ! -d "core/.git" ]; then
    echo "🌐 Cloning required Hub repository..."
    git clone https://github.com/lbockenstedt/lm.git core
fi

if [ -d "le/.git" ]; then
    echo "📂 le repository already exists. Updating..."
    cd le && BR=$(_deployed_branch) && git fetch origin -q "$BR" && git reset --hard "origin/$BR" && cd ..   # hard-sync (soft `git pull` no-ops on a diverged/detached clone)
else
    echo "🌐 Cloning Certificate Management (le) repository..."
    git clone --branch "${LE_BRANCH:-main}" https://github.com/lbockenstedt/le.git
fi

SPOKE_PATH="$INSTALL_DIR/le"
echo "🛠️ Setting up Certificate Management (le)..."
cd "$SPOKE_PATH"

# Always reset the venv for a clean local environment.
echo "♻️ Resetting virtual environment..."
rm -rf venv

python3 -m venv venv
if [ ! -f "venv/bin/python3" ]; then
    echo "❌ Critical Error: venv creation failed."
    exit 1
fi

echo "Installing requirements..."
./venv/bin/python3 -m pip install --upgrade pip -q
if [ -f "requirements.txt" ]; then
    ./venv/bin/python3 -m pip install -r requirements.txt -q
fi

# --- Persistence Configuration ---
echo "⚙️ Configuring Spoke Identity..."
# The installer owns only these keys. Every other line is kept as it is:
# INSTALL_UUID and INSTALL_UUID_MACHINE (hub fingerprint and clone
# detection), LM_RECOVERY_PSK and LM_MTLS_* that core persisted at runtime,
# and the TLS settings unless --tls-verify replaces them.
OWNED_KEYS="HUB_URL SPOKE_ID SPOKE_SECRET HUB_SECRET"
if $TLS_VERIFY; then
    OWNED_KEYS="$OWNED_KEYS LM_HUB_TLS_VERIFY LM_HUB_CA_CERT"
fi
# The spoke may be running and persisting a key into .env right now, so
# hold core's sidecar lock (BaseControlPlane._env_file_flock) from the read
# to the atomic rename. Without flock(1) this proceeds unlocked, as core
# does when it cannot lock. .env holds the spoke and hub secrets, so the
# new file is owner-only.
(
    umask 077
    if command -v flock >/dev/null 2>&1; then
        exec 9>>.env.lock
        flock 9 || true
    fi
    # A re-run without --secret/--hub-secret keeps the secrets .env already
    # holds, instead of resetting the PSK to the default "lm-secret" (or the
    # hub secret to blank). A key that is present but empty is kept too:
    # core writes SPOKE_SECRET= after the hub rejects the secret, so the
    # spoke re-onboards zero-touch.
    _env_has() { [ -f .env ] && grep -q "^$1=" .env; }
    _env_value() { [ -f .env ] && grep "^$1=" .env | tail -1 | cut -d= -f2- || true; }
    if [ "$SECRET_GIVEN" = 0 ] && _env_has SPOKE_SECRET; then
        SPOKE_SECRET="$(_env_value SPOKE_SECRET)"
        echo "Keeping the existing spoke secret (pass --secret to change it)."
    fi
    if [ "$HUB_SECRET_GIVEN" = 0 ] && _env_has HUB_SECRET; then
        HUB_SECRET="$(_env_value HUB_SECRET)"
    fi
    # Copy every line the installer does not own, then write its own keys.
    tmp="$(mktemp .env.XXXXXX)"
    {
        if [ -f .env ]; then
            awk -v keys="$OWNED_KEYS" 'BEGIN { n = split(keys, k, " "); for (i = 1; i <= n; i++) own[k[i]] = 1 }
                { split($0, kv, "=") } !(kv[1] in own)' .env
        fi
        printf 'HUB_URL=%s\nSPOKE_ID=%s\nSPOKE_SECRET=%s\nHUB_SECRET=%s\n' \
            "$HUB_URL" "$SPOKE_ID" "$SPOKE_SECRET" "$HUB_SECRET"
        if $TLS_VERIFY; then
            printf 'LM_HUB_TLS_VERIFY=1\nLM_HUB_CA_CERT=%s\n' "$TLS_CA_CERT"
        fi
    } > "$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" .env
)

# Shared log dir; the service logs to stderr and systemd captures it to
# /var/log/lm/lm-le.log (root-owned append file). Root service owns the dir.
mkdir -p /var/log/lm

# Circular logging: cap /var/log/lm/*.log so it can't fill the disk (copytruncate
# keeps the inode → the running spoke's O_APPEND FileHandler + systemd stderr
# keep appending). Belt-and-suspenders alongside logging_setup's RotatingFileHandler.
cat > /etc/logrotate.d/lm <<'LOGROTATE'
/var/log/lm/*.log /var/log/client-sim-*.log {
    su root root
    size 50M
    rotate 5
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
LOGROTATE

# DNS-provider credentials dir (DNS-01). Root-only; the spoke writes
# dns-<provider>.ini here at 0600. Secrets — never logged, never committed.
mkdir -p /etc/lm-le
chmod 700 /etc/lm-le

# Per-spoke state dir for the cert ledger (/var/lib/lm/<spoke_id>/certs.json).
# The spoke creates its own subdir at runtime; ensure the parent exists.
mkdir -p /var/lib/lm

# --- Systemd Service ---
echo "⚙️ Creating systemd service for auto-start..."
cat <<EOF > /etc/systemd/system/lm-le.service
[Unit]
Description=Lab Manager Spoke - Certificate Management (le)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/le
EnvironmentFile=$INSTALL_DIR/le/.env
Environment="PYTHONPATH=$INSTALL_DIR:$INSTALL_DIR/core/src:$INSTALL_DIR/le/src"
ExecStart=$INSTALL_DIR/le/venv/bin/python3 -m src.control_plane --id "\$SPOKE_ID" --secret=\$SPOKE_SECRET --hub "\$HUB_URL" --hub-secret="\$HUB_SECRET"
StandardOutput=append:/var/log/lm/lm-le.log
StandardError=append:/var/log/lm/lm-le.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lm-le
# Start it now (and pick up new code on a re-install). enable alone left the unit
# inactive until the next reboot, so the spoke never connected to --hub.
systemctl restart lm-le

echo "🎉 Certificate Management (le) installation complete!"
echo "🌐 Hub Target: $HUB_URL"
echo "🆔 Spoke ID: $SPOKE_ID"
echo "📦 Version: $(cat VERSION 2>/dev/null || echo unknown)"