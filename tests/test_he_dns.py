"""Tests for le/src/he_dns.py — the Hurricane Electric DNS-01 hook.

Focus: the cleanup path must actually FIND and delete the _acme-challenge TXT
rows regardless of HE's attribute order (the old single-regex form required
recordid→data-name→data-content in that exact order and silently matched zero
rows when HE reordered them, leaving stale TXT behind), plus credential loading
from env / the 0600 creds file.

No network is touched: HE's session is faked and _login/_zones are stubbed.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import he_dns  # noqa: E402


class _Resp:
    def __init__(self, text):
        self.text = text


class _FakeSession:
    """Returns fixed HTML for GET; records delete POSTs."""

    def __init__(self, text=""):
        self._text = text
        self.deleted = []

    def get(self, *a, **k):
        return _Resp(self._text)

    def post(self, *a, **k):
        d = k.get("data", {}) or {}
        if d.get("hosted_dns_delrecord"):
            self.deleted.append(d.get("hosted_dns_recordid"))
        return _Resp("")


# ── _record_ids: order-independent parsing (the Issue-2 regression) ───────────

def test_record_ids_matches_regardless_of_attribute_order():
    # One row in canonical order, one with the attributes shuffled — the old
    # ordered regex would only have matched the first.
    html = (
        '<tr hosted_dns_recordid="123" data-name="_acme-challenge.example.com"'
        ' data-content="tok-A">'
        '<tr data-content="tok-B" data-name="_acme-challenge.example.com"'
        ' hosted_dns_recordid="456">'
    )
    ids = he_dns._record_ids(_FakeSession(html), "z1",
                             "_acme-challenge.example.com", None)
    assert set(ids) == {"123", "456"}


def test_record_ids_filters_by_value_when_given():
    html = (
        '<tr hosted_dns_recordid="123" data-name="_acme-challenge.example.com"'
        ' data-content="tok-A">'
        '<tr hosted_dns_recordid="456" data-name="_acme-challenge.example.com"'
        ' data-content="tok-B">'
    )
    ids = he_dns._record_ids(_FakeSession(html), "z1",
                             "_acme-challenge.example.com", "tok-A")
    assert ids == ["123"]


def test_record_ids_ignores_other_record_names():
    html = ('<tr hosted_dns_recordid="9" data-name="www.example.com"'
            ' data-content="x">')
    ids = he_dns._record_ids(_FakeSession(html), "z1",
                             "_acme-challenge.example.com", None)
    assert ids == []


def test_record_ids_strips_quotes_in_content_match():
    # HE HTML-encodes the TXT content's surrounding quotes (&quot;); the
    # substring value match must still succeed against the encoded form.
    html = ('<tr hosted_dns_recordid="7" data-name="_acme-challenge.example.com"'
            ' data-content="&quot;tok-A&quot;">')
    ids = he_dns._record_ids(_FakeSession(html), "z1",
                             "_acme-challenge.example.com", "tok-A")
    assert ids == ["7"]


# ── _run cleanup end-to-end: stale TXT is actually deleted ────────────────────

def test_run_cleanup_deletes_matching_txt(monkeypatch):
    zone_edit = ('<tr hosted_dns_recordid="77"'
                 ' data-name="_acme-challenge.example.com" data-content="V">')
    sess = _FakeSession(zone_edit)
    monkeypatch.setattr(he_dns.requests, "Session", lambda: sess)
    monkeypatch.setattr(he_dns, "_login", lambda s, u, p: "home")
    monkeypatch.setattr(he_dns, "_zones", lambda h: {"example.com": "zid1"})
    monkeypatch.setenv("CERTBOT_DOMAIN", "example.com")
    monkeypatch.setenv("CERTBOT_VALIDATION", "V")
    monkeypatch.setenv("HE_USERNAME", "u")
    monkeypatch.setenv("HE_PASSWORD", "p")
    rc = he_dns._run("cleanup")
    assert rc == 0
    assert sess.deleted == ["77"]


# ── credential loading ───────────────────────────────────────────────────────

def test_load_creds_env_takes_precedence(monkeypatch):
    monkeypatch.setenv("HE_USERNAME", "envuser")
    monkeypatch.setenv("HE_PASSWORD", "envpass")
    assert he_dns._load_creds() == ("envuser", "envpass")


def test_load_creds_from_file_for_renewals(tmp_path, monkeypatch):
    for k in ("HE_USERNAME", "HE_PASSWORD", "HE_Username", "HE_Password"):
        monkeypatch.delenv(k, raising=False)
    f = tmp_path / "he-login.ini"
    f.write_text("HE_USERNAME=me@example.com\nHE_PASSWORD=s3cret\n")
    monkeypatch.setattr(he_dns, "_CREDS_FILE", str(f))
    assert he_dns._load_creds() == ("me@example.com", "s3cret")


def test_run_reports_2_when_no_credentials(tmp_path, monkeypatch):
    for k in ("HE_USERNAME", "HE_PASSWORD", "HE_Username", "HE_Password"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(he_dns, "_CREDS_FILE", str(tmp_path / "missing.ini"))
    monkeypatch.setenv("CERTBOT_DOMAIN", "example.com")
    monkeypatch.setenv("CERTBOT_VALIDATION", "V")
    assert he_dns._run("auth") == 2
    assert he_dns._run("cleanup") == 2
