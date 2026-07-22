"""certbot ACME wrapper for the le spoke.

Pure argv-builders + thin async subprocess runners so the spoke (and tests) can
mock execution while asserting the exact ``certbot`` invocation. Certificates
are stored in certbot's native layout (``/etc/letsencrypt/live/<name>/``) so
``certbot renew`` and standard tooling keep working; the LM ledger (see
``ledger.py``) tracks which domains the spoke manages + their distribution
targets.

Secrets: DNS-provider credentials INIs are written to ``/etc/lm-le/`` at 0600
and are NEVER logged. Private keys are read on demand for transport and never
logged here (the spoke masks them at its command boundary).
"""
import asyncio
import functools
import hashlib
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("LEAcme")

# Overridable for tests / non-standard layouts.
LE_LIVE_DIR = os.getenv("LM_LE_LIVE_DIR", "/etc/letsencrypt/live")
LE_CONFIG_DIR = os.getenv("LM_LE_CONFIG_DIR", "/etc/letsencrypt")
DNS_CREDS_DIR = os.getenv("LM_LE_DNS_CREDS_DIR", "/etc/lm-le")
CERTBOT_BIN = os.getenv("LM_LE_CERTBOT_BIN", "certbot")
_PROPAGATION_DEFAULT = 60
_RENEW_WINDOW_DAYS = 7  # renew when not_after is within this many days (default; per-cert override via entry["renew_window_days"])

_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


# ── environment probes ───────────────────────────────────────────────────────

@functools.lru_cache(maxsize=8)
def present(bin_path: str = CERTBOT_BIN) -> bool:
    """True if a certbot binary is on PATH. Cached — the binary location
    doesn't change during a spoke's lifetime, and this is probed per issue."""
    return bool(shutil.which(bin_path))


async def acme_info(bin_path: str = CERTBOT_BIN) -> Dict[str, Any]:
    """certbot version + whether it supports ACME profiles (--preferred-profile,
    added in certbot 4.0) + the ACME directory's advertised profiles (real LE prod
    by default). Answers 'I requested clientAuth but got serverAuth-only': shows
    whether certbot is new enough and what the clientAuth-capable profile is
    actually NAMED on this CA (so LM_LE_CLIENTAUTH_PROFILE can be set correctly)."""
    info: Dict[str, Any] = {"clientauth_profile": CLIENTAUTH_PROFILE}
    try:
        _rc, out, err = await _run([bin_path, "--version"], timeout=20)
        info["certbot_version"] = (out or err).strip()
    except Exception as e:  # noqa: BLE001
        info["certbot_version"] = f"error: {e}"
    try:
        _rc, out, _err = await _run([bin_path, "--help", "all"], timeout=30)
        info["supports_profiles"] = "--preferred-profile" in (out or "")
    except Exception:  # noqa: BLE001
        info["supports_profiles"] = None
    directory = os.getenv("LM_LE_ACME_DIRECTORY",
                          "https://acme-v02.api.letsencrypt.org/directory")
    info["acme_directory"] = directory

    def _fetch_profiles():
        import urllib.request
        import json as _json
        with urllib.request.urlopen(directory, timeout=10) as r:  # noqa: S310
            d = _json.loads(r.read().decode())
        return (d.get("meta") or {}).get("profiles") or {}
    try:
        info["profiles"] = await asyncio.to_thread(_fetch_profiles)
    except Exception as e:  # noqa: BLE001
        info["profiles"] = {}
        info["profiles_error"] = str(e)[:200]
    return info


# certbot DNS-01 plugins → Debian apt package. cloudflare + route53 are
# apt-preinstalled by install_le.sh; the rest are apt-installed ON DEMAND by
# ensure_dns_plugin() when a DNS-01 issue targets them. The system certbot
# (not the venv python) loads these, so presence is checked via dpkg, not
# importlib (the venv doesn't see system site-packages).
_DNS_PLUGIN_APT: Dict[str, str] = {
    "cloudflare": "python3-certbot-dns-cloudflare",
    "route53": "python3-certbot-dns-route53",
    "google": "python3-certbot-dns-google",
    "digitalocean": "python3-certbot-dns-digitalocean",
    "linode": "python3-certbot-dns-linode",
    "rfc2136": "python3-certbot-dns-rfc2136",
    "hetzner": "python3-certbot-dns-hetzner",
    "inwx": "python3-certbot-dns-inwx",
    "transip": "python3-certbot-dns-transip",
}


@functools.lru_cache(maxsize=32)
def dns_plugin_present(provider: str) -> bool:
    """True if the certbot DNS-01 plugin apt package for ``provider`` is
    installed system-wide (the system certbot loads it, not the venv python).
    lru_cached — dpkg -s per DNS-01 issue was a wasted subprocess on the hot
    path. ensure_dns_plugin calls dns_plugin_present.cache_clear() after an
    apt install so the post-install check sees the new package."""
    pkg = _DNS_PLUGIN_APT.get((provider or "").strip().lower())
    if not pkg:
        return False
    try:
        p = subprocess.run(["dpkg", "-s", pkg],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10)
        return p.returncode == 0
    except Exception:
        return False


async def ensure_dns_plugin(provider: str) -> Dict[str, Any]:
    """Make sure the certbot DNS-01 plugin for ``provider`` is installed.

    cloudflare + route53 are preinstalled; others apt-install on demand here.
    Best-effort: a failure returns ``{status: ERROR}`` so the caller surfaces a
    clear message instead of a confusing certbot plugin-not-found traceback.
    The le spoke runs as root, so apt-get is available.
    """
    prov = (provider or "").strip().lower()
    # If a profile-capable certbot was installed into a venv (certbot_update), the
    # active certbot loads plugins from THAT venv, not apt — install there instead.
    try:
        import certbot_update  # type: ignore[import-not-found]
        if certbot_update.venv_certbot():
            if await certbot_update.ensure_venv_plugin(prov):
                return {"status": "SUCCESS",
                        "message": f"dns plugin {prov} installed in the certbot venv"}
            return {"status": "ERROR",
                    "message": f"no certbot-dns plugin mapped/installable for '{prov}' in the venv"}
    except Exception:  # noqa: BLE001 - fall back to the apt path below
        pass
    if dns_plugin_present(prov):
        return {"status": "SUCCESS", "message": f"dns plugin {prov} already installed"}
    pkg = _DNS_PLUGIN_APT.get(prov)
    if not pkg:
        return {"status": "ERROR",
                "message": f"no apt package mapped for dns provider '{prov}'; "
                           f"install the certbot plugin manually"}
    argv = ["apt-get", "install", "-y", "-qq", pkg]
    logger.info("installing DNS plugin on demand: %s", " ".join(argv))
    rc, out, err = await _run(argv, timeout=180.0)
    if rc != 0:
        return {"status": "ERROR",
                "message": f"apt install {pkg} failed: {(err or out).strip()[:300]}"}
    # apt just changed the package set — drop the lru_cache so the post-install
    # presence check re-runs dpkg instead of returning the stale pre-install hit.
    dns_plugin_present.cache_clear()
    if not dns_plugin_present(prov):
        return {"status": "ERROR",
                "message": f"{pkg} installed but dpkg still reports absent — "
                           f"retry or install manually"}
    return {"status": "SUCCESS", "message": f"installed {pkg}"}


def _dns_creds_path(provider: str, creds_dir: str = DNS_CREDS_DIR) -> str:
    return os.path.join(creds_dir, f"dns-{provider}.ini")


def write_dns_creds(provider: str, content: str,
                    creds_dir: str = DNS_CREDS_DIR) -> str:
    """Atomically write a DNS-provider credentials INI at mode 0600.

    ``content`` is a secret (e.g. ``dns_cloudflare_api_token = ...``); it is
    never logged. Returns the path certbot should reference via
    ``--dns-<provider>-credentials``.
    """
    os.makedirs(creds_dir, exist_ok=True)
    path = _dns_creds_path(provider, creds_dir)
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.replace(tmp, path)
    os.chmod(path, 0o600)  # belt + suspenders vs umask
    return path


# Hurricane Electric ACCOUNT-LOGIN provider (email/password web panel, no TSIG).
# Not a certbot DNS plugin — driven by the built-in ``manual`` authenticator with
# he_dns.py as the auth/cleanup hook (see issue_argv).
HE_LOGIN_PROVIDER = "he-login"
_HE_HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "he_dns.py")


def write_he_creds(username: str, password: str,
                   creds_dir: str = DNS_CREDS_DIR) -> str:
    """Persist Hurricane Electric account creds at 0600 for the DNS hook — read
    by he_dns.py on both issue AND renewal (certbot re-runs the hook with no env,
    so the file is the durable source). Never logged."""
    os.makedirs(creds_dir, exist_ok=True)
    path = os.path.join(creds_dir, "he-login.ini")
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"HE_USERNAME={username}\nHE_PASSWORD={password}\n")
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return path


def resolve_rfc2136_server(content: str) -> str:
    """certbot-dns-rfc2136 requires ``dns_rfc2136_server`` to be a literal IP —
    a hostname is rejected ("not a valid IPv4 or IPv6 address"). Resolve a
    hostname value to an IP in place; leave an already-numeric address (or an
    unresolvable value) untouched so certbot surfaces its own clear error. The
    secret lines are never touched/logged."""
    def _is_ip(v: str) -> bool:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(fam, v)
                return True
            except OSError:
                continue
        return False

    def _repl(m):
        prefix, val = m.group(1), m.group(2).strip()
        if not val or _is_ip(val):
            return m.group(0)
        try:
            ip = socket.getaddrinfo(val, None)[0][4][0]
            logger.info("rfc2136: resolved DNS server %s -> %s for certbot", val, ip)
            return f"{prefix}{ip}"
        except Exception as e:  # noqa: BLE001 — leave as-is; certbot errors clearly
            logger.warning("rfc2136: could not resolve DNS server '%s': %s", val, e)
            return m.group(0)
    return re.sub(r"(?m)^(\s*dns_rfc2136_server\s*=\s*)(\S+)\s*$", _repl, content)


# ── argv builders (pure) ─────────────────────────────────────────────────────

def _normalize_challenge(challenge: str) -> str:
    c = (challenge or "http").strip().lower()
    if c in ("http", "http-01", "http01"):
        return "http"
    if c in ("dns", "dns-01", "dns01"):
        return "dns"
    if c in ("tls-alpn", "tls-alpn-01", "tlsalpn01", "tls_alpn", "tls_alpn_01"):
        return "tls-alpn"
    raise ValueError(
        f"unsupported challenge '{challenge}' (expected http/dns/tls-alpn)")


# ACME profile (Let's Encrypt "certificate profiles"). LE bundles the EKU set AND
# the validity period into a named profile — the client can't request an arbitrary
# lifetime, only pick a profile:
#   classic     — ~90d, serverAuth + clientAuth (needed for mTLS CLIENT certs)
#   tlsserver   — ~90d, serverAuth only
#   shortlived  — ~7d,  serverAuth only (LE short-lived certs)
# The exact names/validities are advertised by the CA (see acme_info → profiles).
# CLIENTAUTH_PROFILE is the both-EKU profile requested by the clientAuth toggle;
# an explicit ``profile`` (e.g. a short-lived one) overrides it. Both env-tunable.
CLIENTAUTH_PROFILE = os.getenv("LM_LE_CLIENTAUTH_PROFILE", "classic")


def issue_argv(domain: str, email: str, challenge: str, *,
               webroot: Optional[str] = None, dns_provider: Optional[str] = None,
               dns_creds_ini: Optional[str] = None, staging: bool = False,
               key_type: str = "rsa", cert_name: Optional[str] = None,
               propagation_seconds: int = _PROPAGATION_DEFAULT,
               client_auth: bool = False, profile: Optional[str] = None,
               force_renewal: bool = False,
               bin_path: str = CERTBOT_BIN) -> List[str]:
    """Build the ``certbot certonly`` argv for one domain.

    HTTP-01     → ``--standalone`` (default) or ``--webroot -w <webroot>``.
    DNS-01      → ``--dns-<provider> --dns-<provider>-credentials <ini>``.
    TLS-ALPN-01 → ``--preferred-challenges tls-alpn-01``. certbot ships no
    authenticator for this challenge by default; it requires a TLS-ALPN-01
    plugin installed on the host. If none is present, certbot itself fails
    with a clear "no authenticator" message, surfaced verbatim by ``issue()``.

    ``client_auth`` requests the ACME profile that includes the clientAuth EKU
    (``--preferred-profile``) so the cert can be presented as an mTLS CLIENT cert
    (e.g. the BugFixer cert). certbot persists the profile into the renewal config,
    so renewals keep it. ``force_renewal`` re-issues even if not near expiry — used
    when toggling clientAuth on an existing cert so the new profile takes effect now.
    """
    ch = _normalize_challenge(challenge)
    argv: List[str] = [bin_path, "certonly", "--non-interactive",
                       "--agree-tos", "--no-eff-email"]
    argv += ["-d", domain, "--cert-name", cert_name or domain]
    # ACME profile: an explicit ``profile`` (e.g. a short-lived one) wins; else the
    # clientAuth toggle maps to the both-EKU profile. None → the CA's default (~90d).
    prof = (profile or "").strip() or (CLIENTAUTH_PROFILE if client_auth else "")
    if prof:
        argv += ["--preferred-profile", prof]
    if force_renewal:
        argv += ["--force-renewal"]
    if email:
        argv += ["-m", email]
    if key_type:
        argv += ["--key-type", key_type]
    argv += ["--preferred-challenges",
             "tls-alpn-01" if ch == "tls-alpn" else ch]
    if ch == "http":
        if webroot:
            argv += ["--webroot", "-w", webroot]
        else:
            argv += ["--standalone"]
    elif ch == "dns":
        if not dns_provider:
            raise ValueError("dns challenge requires dns_provider")
        if dns_provider == HE_LOGIN_PROVIDER:
            # Hurricane Electric account login → built-in manual authenticator
            # with he_dns.py setting/removing the _acme-challenge TXT via the HE
            # web panel. No --dns-<provider> plugin, no credentials INI.
            argv += ["--manual",
                     "--manual-auth-hook", f"{sys.executable} {_HE_HOOK} auth",
                     "--manual-cleanup-hook", f"{sys.executable} {_HE_HOOK} cleanup"]
        else:
            argv += [f"--dns-{dns_provider}"]
            if dns_creds_ini:
                argv += [f"--dns-{dns_provider}-credentials", dns_creds_ini]
            argv += [f"--dns-{dns_provider}-propagation-seconds",
                     str(propagation_seconds)]
    # tls-alpn: no extra argv — whatever authenticator plugin is installed on
    # the host picks up the challenge from --preferred-challenges above.
    if staging:
        argv.append("--staging")
    return argv


def renew_argv(domain: str, *, force: bool = False,
               bin_path: str = CERTBOT_BIN) -> List[str]:
    argv = [bin_path, "renew", "--cert-name", domain, "--non-interactive",
            "--no-random-sleep-on-renew"]
    if force:
        # certbot renew is a no-op unless within 30d of expiry; --force-renewal
        # re-issues NOW regardless (the per-cert "Renew now" button).
        argv.append("--force-renewal")
    return argv


def revoke_argv(domain: str, *, delete: bool = True,
                bin_path: str = CERTBOT_BIN) -> List[str]:
    argv = [bin_path, "revoke", "--cert-name", domain, "--non-interactive"]
    if delete:
        argv.append("--delete")
    return argv


# ── subprocess runner ─────────────────────────────────────────────────────────

async def _run(argv: List[str], timeout: float = 180.0,
               env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    """Run argv, return (returncode, stdout, stderr). On timeout, kill + return
    a synthetic -1 with a timeout message. ``env`` (e.g. route53 AWS creds) is
    merged onto the current environment — its values are never logged."""
    logger.info("acme run: %s", " ".join(argv))
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=({**os.environ, **env} if env else None),
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(),
                                                    timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"certbot timed out after {timeout}s"
    return proc.returncode, stdout_b.decode(errors="replace"), stderr_b.decode(errors="replace")


def _ok(rc: int) -> bool:
    return rc == 0


# ── high-level operations ─────────────────────────────────────────────────────

async def issue(domain: str, email: str, challenge: str, *,
                webroot: Optional[str] = None, dns_provider: Optional[str] = None,
                dns_creds: Optional[str] = None, dns_creds_ini: Optional[str] = None,
                he_username: Optional[str] = None, he_password: Optional[str] = None,
                route53_env: Optional[Dict[str, str]] = None,
                staging: bool = False, key_type: str = "rsa",
                cert_name: Optional[str] = None,
                propagation_seconds: int = _PROPAGATION_DEFAULT,
                client_auth: bool = False, profile: Optional[str] = None,
                force_renewal: bool = False,
                bin_path: str = CERTBOT_BIN) -> Dict[str, Any]:
    """Issue a cert. Returns {status, ...} with the live dir on success.

    For DNS-01, pass either ``dns_creds`` (raw INI content — written to
    /etc/lm-le/dns-<provider>.ini at 0600) or ``dns_creds_ini`` (an existing
    path). For ``dns_provider == "he-login"`` (Hurricane Electric account login),
    pass ``he_username``/``he_password`` (else the stored knob's he-login.ini is
    used). All secrets are 0600 and never logged.
    """
    if not present(bin_path):
        return {"status": "ERROR", "message": "certbot not installed"}
    ini = dns_creds_ini
    if _normalize_challenge(challenge) == "dns":
        if dns_provider == HE_LOGIN_PROVIDER:
            # Account-login HE uses the built-in manual authenticator + he_dns.py
            # hook (no DNS plugin to install). Persist any per-request creds so the
            # hook — and future renewals — can read them; otherwise rely on the
            # creds file the setup knob already wrote.
            if he_username and he_password:
                write_he_creds(he_username, he_password)
        else:
            if dns_creds and not ini:
                # certbot-dns-rfc2136 rejects a hostname server — resolve to an IP.
                if "dns_rfc2136_server" in dns_creds:
                    dns_creds = resolve_rfc2136_server(dns_creds)
                ini = write_dns_creds(dns_provider, dns_creds)
            # On-demand install of the DNS-01 plugin for providers not
            # preinstalled by the installer (cloudflare/route53 are). Best-effort;
            # a failure here surfaces a clear message instead of a certbot traceback.
            plug = await ensure_dns_plugin(dns_provider)
            if plug.get("status") != "SUCCESS":
                return {"status": "ERROR",
                        "message": f"DNS plugin unavailable: {plug.get('message')}"}
    argv = issue_argv(domain, email, challenge, webroot=webroot,
                      dns_provider=dns_provider, dns_creds_ini=ini,
                      staging=staging, key_type=key_type, cert_name=cert_name,
                      propagation_seconds=propagation_seconds,
                      client_auth=client_auth, profile=profile,
                      force_renewal=force_renewal, bin_path=bin_path)
    # route53 has no --dns-route53-credentials file; certbot-dns-route53 reads
    # AWS creds from the environment, passed through per-issue (never logged).
    rc, out, err = await _run(argv, env=route53_env or None)
    if not _ok(rc):
        return {"status": "ERROR",
                "message": (err or out or f"certbot exited {rc}").strip()[:500]}
    return {"status": "SUCCESS", "domain": domain,
            "live_dir": os.path.join(LE_LIVE_DIR, cert_name or domain)}


async def renew(domain: str, *, force: bool = False,
                bin_path: str = CERTBOT_BIN) -> Dict[str, Any]:
    """Renew one cert via ``certbot renew --cert-name <domain>``. Returns
    ``{status, domain, renewed, live_dir}``; ``renewed`` is False when certbot
    reports the cert isn't due yet (rc 0, no-op). ``force`` adds --force-renewal
    to re-issue NOW regardless of expiry (the per-cert 'Renew now' button)."""
    if not present(bin_path):
        return {"status": "ERROR", "message": "certbot not installed"}
    rc, out, err = await _run(renew_argv(domain, force=force, bin_path=bin_path))
    if not _ok(rc):
        # renew prints "No renewals were attempted." (rc 0) when nothing's due;
        # a non-zero here is a real failure.
        return {"status": "ERROR",
                "message": (err or out or f"certbot renew exited {rc}").strip()[:500]}
    renewed = "Cert not yet due for renewal" not in (out + err)
    return {"status": "SUCCESS", "domain": domain, "renewed": renewed,
            "live_dir": os.path.join(LE_LIVE_DIR, domain)}


async def revoke(domain: str, *, delete: bool = True,
                 bin_path: str = CERTBOT_BIN) -> Dict[str, Any]:
    """Revoke a cert via ``certbot revoke --cert-name <domain>``. When
    ``delete`` is True (default) certbot also removes the local material under
    ``/etc/letsencrypt/live/<domain>/``. Returns ``{status, domain, deleted}``."""
    if not present(bin_path):
        return {"status": "ERROR", "message": "certbot not installed"}
    rc, out, err = await _run(revoke_argv(domain, delete=delete, bin_path=bin_path))
    if not _ok(rc):
        return {"status": "ERROR",
                "message": (err or out or f"certbot revoke exited {rc}").strip()[:500]}
    return {"status": "SUCCESS", "domain": domain, "deleted": delete}


# ── cert material + ledger helpers ────────────────────────────────────────────

def _split_leaf(fullchain_pem: str) -> str:
    """Return the first (leaf) cert PEM block from a fullchain."""
    m = _PEM_CERT_RE.search(fullchain_pem or "")
    return m.group(0) if m else (fullchain_pem or "")


def _parse_not_after(cert_pem: str) -> Optional[str]:
    """ISO-8601 not_after of the leaf cert, or None if unparseable."""
    leaf = _split_leaf(cert_pem)
    if not leaf:
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_pem_x509_certificate(leaf.encode(), default_backend())
        return cert.not_valid_after_utc.isoformat() if hasattr(
            cert, "not_valid_after_utc") else cert.not_valid_after.isoformat()
    except Exception:
        pass
    # Fallback: openssl subprocess (best-effort, sync — only on parse failure).
    try:
        import subprocess
        p = subprocess.run(["openssl", "x509", "-enddate", "-noout"],
                           input=leaf.encode(), stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=10)
        out = p.stdout.decode(errors="replace").strip()
        # notAfter=Jun  1 12:00:00 2027 GMT → best-effort ISO via datetime
        if out.startswith("notAfter="):
            from datetime import datetime
            return datetime.strptime(out[len("notAfter="):],
                                     "%b %d %H:%M:%S %Y %Z").isoformat()
    except Exception:
        pass
    return None


def list_certs(live_dir: str = LE_LIVE_DIR) -> List[Dict[str, Any]]:
    """Enumerate certbot live certs. Each entry: {name, domain, fullchain_path,
    privkey_path, not_after, material_hash}. ``name`` is the cert-name (dir);
    ``domain`` is the leaf CN/SAN best-effort (falls back to the name)."""
    out: List[Dict[str, Any]] = []
    if not os.path.isdir(live_dir):
        return out
    for name in sorted(os.listdir(live_dir)):
        d = os.path.join(live_dir, name)
        fullchain = os.path.join(d, "fullchain.pem")
        privkey = os.path.join(d, "privkey.pem")
        if not os.path.isfile(fullchain):
            continue
        try:
            with open(fullchain, "r") as f:
                fc = f.read()
        except Exception:
            fc = ""
        out.append({
            "name": name,
            "domain": name,
            "fullchain_path": fullchain,
            "privkey_path": privkey if os.path.isfile(privkey) else None,
            "not_after": _parse_not_after(fc),
            "material_hash": _hash(fc),
        })
    return out


# mtime-keyed memo for read_material: the reconcile loop + LE_GET_CERT both
# call read_material for every cert every cycle, re-reading + re-x509-parsing
# fullchain.pem each time. Certbot only rewrites the file on issue/renew/revoke
# (which changes its mtime), so a memo keyed on fullchain's st_mtime reuses the
# parsed material until the cert actually changes. The material_hash the hub
# uses for change-detection is derived from fullchain, so an mtime-keyed cache
# stays consistent with what the hub would see if it re-fetched.
_read_material_cache: Dict[str, tuple] = {}  # {fullchain_path: (mtime, result)}


def read_material(domain: str, live_dir: str = LE_LIVE_DIR) -> Dict[str, Any]:
    """Read a cert's PEM material + hash for hub transport.

    Returns {status, fullchain, privkey, chain, material_hash, not_after} or
    {status:ERROR}. privkey is a secret — the caller masks it at the boundary.
    Memoized on fullchain.pem's mtime (see _read_material_cache).
    """
    d = os.path.join(live_dir, domain)
    fullchain_p = os.path.join(d, "fullchain.pem")
    if not os.path.isfile(fullchain_p):
        # File gone (revoke/teardown) — drop any stale memo for it.
        _read_material_cache.pop(fullchain_p, None)
        return {"status": "ERROR", "message": f"no live cert for {domain}"}
    try:
        mtime = os.stat(fullchain_p).st_mtime
    except OSError:
        mtime = None
    cached = _read_material_cache.get(fullchain_p)
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        with open(fullchain_p, "r") as f:
            fullchain = f.read()
    except Exception as e:
        return {"status": "ERROR", "message": f"read fullchain failed: {e}"}
    privkey = ""
    privkey_p = os.path.join(d, "privkey.pem")
    if os.path.isfile(privkey_p):
        try:
            with open(privkey_p, "r") as f:
                privkey = f.read()
        except Exception:
            privkey = ""
    chain = ""
    chain_p = os.path.join(d, "chain.pem")
    if os.path.isfile(chain_p):
        try:
            with open(chain_p, "r") as f:
                chain = f.read()
        except Exception:
            chain = ""
    result = {"status": "SUCCESS", "domain": domain, "fullchain": fullchain,
              "privkey": privkey, "chain": chain,
              "material_hash": _hash(fullchain),
              "not_after": _parse_not_after(fullchain)}
    if mtime is not None:
        _read_material_cache[fullchain_p] = (mtime, result)
    return result


def _hash(pem: str) -> str:
    return "sha256:" + hashlib.sha256((pem or "").encode()).hexdigest()


def expiring(cert_entry: Dict[str, Any], now_iso: Optional[str] = None,
             window_days: Optional[int] = None) -> bool:
    """True if a ledger/live cert entry's not_after is within the renewal
    window. The window is resolved per-cert, in priority order:

    1. ``cert_entry["renew_window_days"]`` — a per-cert override set at issue
       time (operator wants this cert renewed earlier/later than the default).
    2. ``window_days`` — an explicit caller override (legacy/programmatic).
    3. ``_RENEW_WINDOW_DAYS`` — the module default (7 days).

    Default 7 days: the renewal loop triggers at least a week before expiry so
    a failed renewal has ~7 daily retries before the cert actually expires.
    """
    na = cert_entry.get("not_after")
    if not na:
        return False
    wd = cert_entry.get("renew_window_days")
    if wd is None or wd == "":
        wd = window_days if window_days is not None else _RENEW_WINDOW_DAYS
    try:
        from datetime import datetime, timedelta, timezone
        # Normalize: tolerate trailing Z / naive.
        s = na.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            dt = datetime.fromisoformat(na)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        ref = datetime.now(timezone.utc)
        return dt - ref <= timedelta(days=wd)
    except Exception:
        return False