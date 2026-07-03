#!/bin/bash
set -e

# Lab Manager — Certificate Management (le) spoke installer.
# Mirrors install_opnsense.sh: clones core + le into /opt/lm, builds the venv,
# writes .env, and installs the lm-le systemd service. Runs as ROOT because
# certbot binds port 80 (HTTP-01 standalone), writes /etc/letsencrypt, and the
# spoke writes root-only DNS credentials to /etc/lm-le.

# Default Configuration
HUB_URL="ws://localhost:8765"
SPOKE_ID="${SPOKE_ID:-le-$(hostname -s)}"
SPOKE_SECRET="lm-secret"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_URL="$2"; shift ;;
        --id|--name) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --hub-secret) HUB_SECRET="$2"; shift ;;
        --all-prereqs) ;;  # no-op; accepted for LM hub compat
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

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

# Hub core is required (BaseControlPlane / BaseSpoke live in lm/core/src).
if [ ! -d "core/.git" ]; then
    echo "🌐 Cloning required Hub repository..."
    git clone https://github.com/lbockenstedt/lm.git core
fi

if [ -d "le/.git" ]; then
    echo "📂 le repository already exists. Updating..."
    cd le && git pull --rebase --autostash && cd ..
else
    echo "🌐 Cloning Certificate Management (le) repository..."
    git clone https://github.com/lbockenstedt/le.git
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
cat <<EOF > .env
HUB_URL=$HUB_URL
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
HUB_SECRET=$HUB_SECRET
EOF

# Shared log dir; the service logs to stderr and systemd captures it to
# /var/log/lm/lm-le.log (root-owned append file). Root service owns the dir.
mkdir -p /var/log/lm

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
ExecStart=$INSTALL_DIR/le/venv/bin/python3 -m src.control_plane --id \$SPOKE_ID --secret=\$SPOKE_SECRET --hub \$HUB_URL --hub-secret=\$HUB_SECRET
StandardOutput=append:/var/log/lm/lm-le.log
StandardError=append:/var/log/lm/lm-le.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lm-le

echo "🎉 Certificate Management (le) installation complete!"
echo "🌐 Hub Target: $HUB_URL"
echo "🆔 Spoke ID: $SPOKE_ID"
echo "📦 Version: $(cat VERSION 2>/dev/null || echo unknown)"