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


# ── _record_ids: parses HE's real record table ───────────────────────────────
# HE renders each record as <tr class="dns_tr..."> with <td> cells in order:
# 0 zone-id, 1 record-id, 2 name, 3 type (rrlabel span data=), 4 ttl,
# 5 priority, 6 value (data= attr), 7 is-dynamic — the same structure the
# henet module's import scraper parses. (The old cleanup regex looked for
# data-name/data-content/hosted_dns_recordid ATTRIBUTES that this table never
# emits, so it matched zero rows and never deleted the stale TXT.)

def _row(rid, name, rtype, content, ttl="300"):
    return (
        '<tr class="dns_tr">'
        '<td>zoneid</td>'
        f'<td>{rid}</td>'
        f'<td>{name}</td>'
        f'<td><span class="rrlabel" data="{rtype}">{rtype}</span></td>'
        f'<td>{ttl}</td>'
        '<td>-</td>'
        f'<td data="{content}">{content}</td>'
        '<td>0</td>'
        '</tr>'
    )


def test_record_ids_matches_all_rows_for_the_name():
    html = (_row("123", "_acme-challenge.example.com", "TXT", "tok-A")
            + _row("456", "_acme-challenge.example.com", "TXT", "tok-B"))
    ids = he_dns._record_ids(_FakeSession(html), "z1",
                             "_acme-challenge.example.com", None)
    assert set(ids) == {"123", "456"}


def test_record_ids_filters_by_value_when_given():
    html = (_row("123", "_acme-challenge.example.com", "TXT", "tok-A")
            + _row("456", "_acme-challenge.example.com", "TXT", "tok-B"))
    ids = he_dns._record_ids(_FakeSession(html), "z1",
                             "_acme-challenge.example.com", "tok-A")
    assert ids == ["123"]


def test_record_ids_ignores_other_record_names():
    html = _row("9", "www.example.com", "A", "1.2.3.4")
    ids = he_dns._record_ids(_FakeSession(html), "z1",
                             "_acme-challenge.example.com", None)
    assert ids == []


def test_record_ids_never_deletes_non_txt_records():
    # A same-named A record must never be matched for challenge cleanup.
    html = _row("5", "_acme-challenge.example.com", "A", "1.2.3.4")
    ids = he_dns._record_ids(_FakeSession(html), "z1",
                             "_acme-challenge.example.com", None)
    assert ids == []


def test_record_ids_strips_quotes_in_content_match():
    # HE HTML-encodes the TXT content's surrounding quotes (&quot;); the
    # substring value match must still succeed against the encoded form.
    html = _row("7", "_acme-challenge.example.com", "TXT", "&quot;tok-A&quot;")
    ids = he_dns._record_ids(_FakeSession(html), "z1",
                             "_acme-challenge.example.com", "tok-A")
    assert ids == ["7"]


# ── _run cleanup end-to-end: stale TXT is actually deleted ────────────────────

def test_run_cleanup_deletes_matching_txt(monkeypatch):
    zone_edit = _row("77", "_acme-challenge.example.com", "TXT", "V")
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
