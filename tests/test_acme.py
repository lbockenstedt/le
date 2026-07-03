"""Pure-function tests for le/src/acme.py (argv builders, hashing, parsing).

No certbot subprocess is invoked — these cover the deterministic seams the
spoke relies on. Execution paths (issue/renew/revoke) are exercised in
test_le_spoke.py with acme monkeypatched.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import acme  # noqa: E402


# ── argv builders ────────────────────────────────────────────────────────────

def test_issue_http_standalone_argv():
    argv = acme.issue_argv("example.com", "a@b.com", "http")
    assert argv[0:3] == ["certbot", "certonly", "--non-interactive"]
    assert "-d" in argv and "example.com" in argv
    assert "--preferred-challenges" in argv
    i = argv.index("--preferred-challenges")
    assert argv[i + 1] == "http"
    assert "--standalone" in argv
    assert "--webroot" not in argv
    assert "--staging" not in argv
    # cert-name defaults to the domain so renew keys off it.
    i = argv.index("--cert-name")
    assert argv[i + 1] == "example.com"


def test_issue_http_webroot_argv():
    argv = acme.issue_argv("example.com", "a@b.com", "http-01",
                           webroot="/var/www")
    assert "--webroot" in argv and "-w" in argv
    assert "/var/www" in argv
    assert "--standalone" not in argv


def test_issue_dns_cloudflare_argv():
    argv = acme.issue_argv("example.com", "a@b.com", "dns",
                           dns_provider="cloudflare",
                           dns_creds_ini="/etc/lm-le/dns-cloudflare.ini",
                           propagation_seconds=45)
    assert "--dns-cloudflare" in argv
    assert "--dns-cloudflare-credentials" in argv
    i = argv.index("--dns-cloudflare-credentials")
    assert argv[i + 1] == "/etc/lm-le/dns-cloudflare.ini"
    assert "--dns-cloudflare-propagation-seconds" in argv
    i = argv.index("--dns-cloudflare-propagation-seconds")
    assert argv[i + 1] == "45"
    assert "--standalone" not in argv
    assert "--preferred-challenges" in argv
    i = argv.index("--preferred-challenges")
    assert argv[i + 1] == "dns"


def test_issue_dns_requires_provider():
    try:
        acme.issue_argv("example.com", "a@b.com", "dns")
    except ValueError:
        return
    assert False, "dns challenge without provider should raise"


def test_issue_staging_flag():
    argv = acme.issue_argv("example.com", "a@b.com", "http", staging=True)
    assert "--staging" in argv


def test_issue_bad_challenge_raises():
    for bad in ("tls", "tls-sni", "ftp"):
        try:
            acme.issue_argv("example.com", "a@b.com", bad)
        except ValueError:
            continue
        assert False, f"challenge {bad!r} should raise"


def test_issue_tls_alpn_argv():
    for alias in ("tls-alpn", "tls-alpn-01", "tlsalpn01"):
        argv = acme.issue_argv("example.com", "a@b.com", alias)
        assert "--preferred-challenges" in argv
        i = argv.index("--preferred-challenges")
        assert argv[i + 1] == "tls-alpn-01"
        # No HTTP/DNS-specific flags leak in.
        assert "--standalone" not in argv and "--webroot" not in argv
        assert not any(a.startswith("--dns-") for a in argv)


def test_issue_empty_or_none_challenge_defaults_to_http():
    for dflt in ("", None):
        argv = acme.issue_argv("example.com", "a@b.com", dflt)
        i = argv.index("--preferred-challenges")
        assert argv[i + 1] == "http"


def test_renew_argv():
    assert acme.renew_argv("example.com") == [
        "certbot", "renew", "--cert-name", "example.com",
        "--non-interactive", "--no-random-sleep-on-renew"]


def test_revoke_argv_delete_default():
    argv = acme.revoke_argv("example.com")
    assert "--cert-name" in argv and "example.com" in argv
    assert "--delete" in argv


def test_revoke_argv_no_delete():
    argv = acme.revoke_argv("example.com", delete=False)
    assert "--delete" not in argv


# ── hashing / parsing ────────────────────────────────────────────────────────

_FULLCHAIN = (
    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"
)


def test_hash_stable():
    h1 = acme._hash(_FULLCHAIN)
    h2 = acme._hash(_FULLCHAIN)
    assert h1 == h2 and h1.startswith("sha256:")
    assert acme._hash(_FULLCHAIN) != acme._hash("different")


def test_split_leaf_returns_first_block():
    leaf = acme._split_leaf(_FULLCHAIN)
    assert leaf.count("BEGIN CERTIFICATE") == 1
    assert "AAAA" in leaf and "BBBB" not in leaf


def test_split_leaf_empty():
    assert acme._split_leaf("") == ""
    assert acme._split_leaf(None) == ""


def test_expiring_within_window():
    from datetime import datetime, timedelta, timezone
    soon = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    assert acme.expiring({"not_after": soon}) is True


def test_expiring_outside_window():
    from datetime import datetime, timedelta, timezone
    far = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
    assert acme.expiring({"not_after": far}) is False


def test_expiring_no_not_after():
    assert acme.expiring({}) is False
    assert acme.expiring({"not_after": None}) is False


# ── write_dns_creds ──────────────────────────────────────────────────────────

def test_write_dns_creds_mode_and_content():
    with tempfile.TemporaryDirectory() as d:
        path = acme.write_dns_creds("cloudflare",
                                    "dns_cloudflare_api_token = sekrit",
                                    creds_dir=d)
        assert path == os.path.join(d, "dns-cloudflare.ini")
        with open(path) as f:
            assert f.read() == "dns_cloudflare_api_token = sekrit"
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600
        # No tmp file left behind.
        assert not os.path.exists(path + ".tmp")


def test_write_dns_creds_overwrite():
    with tempfile.TemporaryDirectory() as d:
        acme.write_dns_creds("cloudflare", "old = 1", creds_dir=d)
        acme.write_dns_creds("cloudflare", "new = 2", creds_dir=d)
        with open(os.path.join(d, "dns-cloudflare.ini")) as f:
            assert f.read() == "new = 2"

# ── DNS-01 on-demand plugin install ──────────────────────────────────────────

class _FakeProc:
    def __init__(self, rc): self.returncode = rc

def test_dns_plugin_present_true_on_dpkg_ok(monkeypatch):
    monkeypatch.setattr(acme.subprocess, "run", lambda *a, **k: _FakeProc(0))
    assert acme.dns_plugin_present("cloudflare") is True

def test_dns_plugin_present_false_on_dpkg_fail(monkeypatch):
    monkeypatch.setattr(acme.subprocess, "run", lambda *a, **k: _FakeProc(1))
    assert acme.dns_plugin_present("cloudflare") is False

def test_dns_plugin_present_false_for_unmapped_provider():
    # No apt package mapped for a bogus provider → False (don't even call dpkg).
    assert acme.dns_plugin_present("nosuchprovider") is False


def test_ensure_dns_plugin_noop_when_present(monkeypatch):
    import asyncio
    monkeypatch.setattr(acme, "dns_plugin_present", lambda p: True)
    res = asyncio.new_event_loop().run_until_complete(acme.ensure_dns_plugin("cloudflare"))
    assert res["status"] == "SUCCESS"
    assert "already installed" in res["message"]


def test_ensure_dns_plugin_installs_when_missing(monkeypatch):
    import asyncio
    # First lookup (present check) → False; after _run returns rc 0, the second
    # present check → True (plugin now installed).
    state = {"installed": False}
    def _present(p): return state["installed"]
    async def _fake_run(argv, timeout=180.0):
        state["installed"] = True
        return 0, "", ""
    monkeypatch.setattr(acme, "dns_plugin_present", _present)
    monkeypatch.setattr(acme, "_run", _fake_run)
    res = asyncio.new_event_loop().run_until_complete(acme.ensure_dns_plugin("google"))
    assert res["status"] == "SUCCESS"
    assert "python3-certbot-dns-google" in res["message"]


def test_ensure_dns_plugin_unmapped_provider_errors(monkeypatch):
    import asyncio
    monkeypatch.setattr(acme, "dns_plugin_present", lambda p: False)
    res = asyncio.new_event_loop().run_until_complete(acme.ensure_dns_plugin("nosuch"))
    assert res["status"] == "ERROR"
    assert "no apt package mapped" in res["message"]


def test_ensure_dns_plugin_apt_failure_errors(monkeypatch):
    import asyncio
    monkeypatch.setattr(acme, "dns_plugin_present", lambda p: False)
    async def _bad_run(argv, timeout=180.0):
        return 1, "", "E: Unable to locate package\n"
    monkeypatch.setattr(acme, "_run", _bad_run)
    res = asyncio.new_event_loop().run_until_complete(acme.ensure_dns_plugin("google"))
    assert res["status"] == "ERROR"
    assert "apt install" in res["message"]
