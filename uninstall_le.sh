#!/bin/bash
# ------------------------------------------------------------------
# Lab Manager — Certificate Management (le) spoke UNINSTALLER.
# Removes the lm-le systemd service + the le spoke code/venv/identity +
# DNS-cred dir + cert ledger + log. Does NOT touch shared dirs
# (/opt/lm/core, /var/lib/lm, /var/log/lm) or the issued Let's Encrypt
# certs in /etc/letsencrypt unless --purge-certs is passed.
#
#   curl -sSL https://raw.githubusercontent.com/lbockenstedt/le/main/uninstall_le.sh | sudo bash
#   curl -sSL https://raw.githubusercontent.com/lbockenstedt/le/main/uninstall_le.sh | sudo bash -s -- --purge-certs
# ------------------------------------------------------------------
set -u

PURGE_CERTS=false
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --purge-certs) PURGE_CERTS=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--purge-certs]   (--purge-certs also deletes /etc/letsencrypt)"
            exit 0 ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Run as root (the installer wrote root-owned unit + /etc/lm-le)."
    exit 1
fi

echo "🧹 Uninstalling Lab Manager Certificate Management (le) spoke..."

# 1. Stop + disable the service, remove the unit.
systemctl disable --now lm-le 2>/dev/null || true
rm -f /etc/systemd/system/lm-le.service
systemctl daemon-reload 2>/dev/null || true

# 2. Spoke code + venv + .env identity.
rm -rf /opt/lm/le

# 3. DNS-01 credentials dir (root-only secrets).
rm -rf /etc/lm-le

# 4. Per-spoke cert ledger (spoke_id is le-<hostname> → /var/lib/lm/le-<host>).
#    Only the le spoke's subdir; leave /var/lib/lm (shared with other spokes).
rm -rf /var/lib/lm/le-* 2>/dev/null || true

# 5. Log file (leave /var/log/lm — shared with the hub + other spokes).
rm -f /var/log/lm/lm-le.log

# 6. Optional: the actual issued Let's Encrypt certs (certbot native state).
#    Off by default — those are real, possibly-in-use certs, not the spoke.
if [ "$PURGE_CERTS" = true ]; then
    echo "🔥 --purge-certs: removing /etc/letsencrypt (all issued certs)..."
    rm -rf /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt
fi

echo "✅ le spoke removed. (Shared /opt/lm/core, /var/lib/lm, /var/log/lm left intact.)"