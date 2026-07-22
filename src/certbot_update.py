"""Keep certbot current + ACME-profile-capable on the le spoke.

Debian/Ubuntu apt certbot tops out at 2.x–3.x — too old for ACME certificate
PROFILES (``--preferred-profile``, certbot >= 4.0), which LM needs to request the
clientAuth EKU for mTLS CLIENT certs (BugFixer, the mTLS wildcard). When the system
certbot is too old this installs a recent certbot into a self-contained pip venv
(LXC-friendly, vs snap which is flaky in unprivileged containers) WITH the DNS-01
plugins, and symlinks it ahead of the apt one on PATH (``/usr/local/bin`` precedes
``/usr/bin``) so a bare ``certbot`` resolves to it — no caller changes. A daily
refresh (``pip install -U``) keeps it current, i.e. certbot AUTO-UPDATES.

All best-effort + non-fatal: any failure leaves the working apt certbot in place,
so this can never break existing issuance. The venv certbot shares
``/etc/letsencrypt`` with the apt one, so existing certs + renewal configs keep
working across the switch.
"""

import asyncio
import logging
import os
import re
import shutil

logger = logging.getLogger("le.certbot_update")

VENV_DIR = os.getenv("LM_LE_CERTBOT_VENV", "/opt/lm-le/certbot-venv")
SYMLINK = os.getenv("LM_LE_CERTBOT_SYMLINK", "/usr/local/bin/certbot")
MIN_PROFILE = (4, 0)  # certbot >= 4.0 → --preferred-profile (ACME profiles)
# DNS-01 plugins bundled in the venv (pip names). Mirrors the apt preinstalls
# (cloudflare, route53) + the most common others; ensure_dns_plugin adds more on
# demand into the same venv.
VENV_PLUGINS = ["certbot-dns-cloudflare", "certbot-dns-route53",
                "certbot-dns-rfc2136"]
# provider → pip plugin package (for on-demand venv installs).
PIP_PLUGIN = {
    "cloudflare": "certbot-dns-cloudflare", "route53": "certbot-dns-route53",
    "google": "certbot-dns-google", "digitalocean": "certbot-dns-digitalocean",
    "linode": "certbot-dns-linode", "rfc2136": "certbot-dns-rfc2136",
    "hetzner": "certbot-dns-hetzner", "inwx": "certbot-dns-inwx",
    "transip": "certbot-dns-transip",
}


async def _run(argv, timeout=600):
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except Exception as e:  # noqa: BLE001
        return 127, "", str(e)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
        return 124, "", "timeout"
    return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")


def venv_certbot():
    """Path to the venv certbot if it exists, else None."""
    p = os.path.join(VENV_DIR, "bin", "certbot")
    return p if os.path.exists(p) else None


async def _version(bin_path):
    rc, out, err = await _run([bin_path, "--version"], timeout=20)
    m = re.search(r"(\d+)\.(\d+)", (out or "") + (err or ""))
    return (int(m.group(1)), int(m.group(2))) if m else None


async def ensure_certbot():
    """Ensure a profile-capable certbot is active — installing a pip-venv certbot
    (symlinked ahead on PATH) if the system one is too old. Idempotent + non-fatal.
    Returns the active certbot version tuple (or None)."""
    if venv_certbot():
        await refresh()  # already migrated — just keep it current
        return await _version(SYMLINK if os.path.exists(SYMLINK) else venv_certbot())

    sysbin = shutil.which("certbot") or "certbot"
    v = await _version(sysbin)
    if v and v >= MIN_PROFILE:
        logger.info("certbot %s already supports ACME profiles — no venv needed", v)
        return v

    logger.info("certbot %s too old for ACME profiles (need >= %s) — installing a "
                "recent certbot in %s", v, MIN_PROFILE, VENV_DIR)
    if not shutil.which("python3"):
        logger.warning("no python3 — cannot install a newer certbot")
        return v
    try:
        os.makedirs(os.path.dirname(VENV_DIR) or "/", exist_ok=True)
    except OSError as e:
        logger.warning("cannot create %s (%s)", VENV_DIR, e)
        return v
    rc, out, err = await _run(["python3", "-m", "venv", VENV_DIR], timeout=180)
    if rc != 0:
        logger.warning("certbot venv create failed: %s", (err or out)[:200])
        return v
    pip = os.path.join(VENV_DIR, "bin", "pip")
    rc, out, err = await _run([pip, "install", "--upgrade", "pip", "certbot",
                               *VENV_PLUGINS], timeout=900)
    if rc != 0 or not venv_certbot():
        logger.warning("certbot venv pip install failed: %s", (err or out)[:300])
        return v
    nv = await _version(venv_certbot())
    if not nv or nv < MIN_PROFILE:
        logger.warning("venv certbot %s still lacks profile support — keeping apt certbot", nv)
        return v
    try:
        if os.path.islink(SYMLINK) or os.path.exists(SYMLINK):
            os.remove(SYMLINK)
        os.symlink(venv_certbot(), SYMLINK)
        logger.info("certbot %s installed (venv) + symlinked %s -> %s — ACME "
                    "profiles now available (clientAuth EKU)", nv, SYMLINK, venv_certbot())
    except OSError as e:
        logger.warning("could not symlink venv certbot (%s) — set "
                       "LM_LE_CERTBOT_BIN=%s manually", e, venv_certbot())
    return nv


async def refresh():
    """Daily auto-update of whichever certbot is active (venv pip / snap / apt).
    Best-effort + non-fatal."""
    vc = venv_certbot()
    if vc:
        pip = os.path.join(VENV_DIR, "bin", "pip")
        rc, out, err = await _run([pip, "install", "--upgrade", "certbot",
                                   *VENV_PLUGINS], timeout=900)
        logger.info("certbot venv refresh rc=%s", rc)
        return
    if shutil.which("snap"):
        rc, _o, _e = await _run(["snap", "refresh", "certbot"], timeout=300)
        if rc == 0:
            logger.info("certbot snap refreshed")
            return
    await _run(["apt-get", "update", "-qq"], timeout=300)
    rc, _o, _e = await _run(["apt-get", "install", "--only-upgrade", "-y", "-qq",
                             "certbot"], timeout=600)
    logger.info("certbot apt upgrade rc=%s", rc)


async def ensure_venv_plugin(provider: str):
    """Install a DNS-01 plugin into the venv (when the venv certbot is active).
    Returns True on success / already-present, False if it can't. Used by
    acme.ensure_dns_plugin so on-demand plugins land where the active certbot
    can load them."""
    prov = (provider or "").strip().lower()
    if not venv_certbot():
        return False
    pkg = PIP_PLUGIN.get(prov)
    if not pkg:
        return False
    pip = os.path.join(VENV_DIR, "bin", "pip")
    # already installed?
    rc, out, _e = await _run([pip, "show", pkg], timeout=30)
    if rc == 0:
        return True
    rc, out, err = await _run([pip, "install", "--upgrade", pkg], timeout=600)
    if rc != 0:
        logger.warning("venv pip install %s failed: %s", pkg, (err or out)[:200])
        return False
    return True
