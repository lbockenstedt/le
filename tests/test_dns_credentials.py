"""``dns_credentials`` — per-tenant DNS-01 store, encrypted at rest.

Pins the user-reported gap: with no hub-side Credential Vault configured, the
spoke-local store is the ONLY place a DNS-01 credential can live, so it must
both (a) work, and (b) not keep secrets in the clear. It previously wrote
plaintext JSON guarded only by 0600 permissions.

Also covers the tenant-isolation contract (one tenant can never read or clobber
another's credentials) and the sentinel-merge on upsert.
"""
import json
import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture()
def dc(tmp_path, monkeypatch):
    """dns_credentials bound to a temp store dir, with a fresh key cache."""
    monkeypatch.setenv("LM_LE_DNS_CREDS_DIR", str(tmp_path))
    monkeypatch.delenv("LM_LE_STORE_KEY", raising=False)
    for mod in ("dns_credentials", "local_secret_store"):
        sys.modules.pop(mod, None)
    import local_secret_store as lss
    lss.reset_key_cache()
    import dns_credentials as _dc
    _dc._DIR = str(tmp_path)
    yield _dc
    lss.reset_key_cache()


def _raw(tmp_path, tenant="t-acme"):
    return (tmp_path / f"{tenant}.json").read_bytes()


# ── encryption at rest ──────────────────────────────────────────────────────

def test_secret_never_hits_disk_in_plaintext(dc, tmp_path):
    dc.upsert("t-acme", "cf", "cloudflare", {"api_token": "SUPERSECRET123"})
    raw = _raw(tmp_path)
    assert b"SUPERSECRET123" not in raw
    assert raw.startswith(b"LMENC1:")


def test_he_login_password_never_hits_disk_in_plaintext(dc, tmp_path):
    dc.upsert("t-acme", "he", "he-login",
              {"username": "u@example.com", "password": "HEPASSWORD1"})
    raw = _raw(tmp_path)
    assert b"HEPASSWORD1" not in raw
    assert b"u@example.com" not in raw


def test_rfc2136_tsig_secret_never_hits_disk_in_plaintext(dc, tmp_path):
    dc.upsert("t-acme", "tsig", "rfc2136",
              {"server": "192.0.2.53", "name": "k", "secret": "TSIGSECRET1"})
    assert b"TSIGSECRET1" not in _raw(tmp_path)


def test_route53_secret_never_hits_disk_in_plaintext(dc, tmp_path):
    dc.upsert("t-acme", "r53", "route53",
              {"access_key_id": "AKIA1", "secret_access_key": "AWSSECRET1"})
    assert b"AWSSECRET1" not in _raw(tmp_path)


def test_store_file_and_key_are_0600(dc, tmp_path):
    dc.upsert("t-acme", "cf", "cloudflare", {"api_token": "x"})
    assert stat.S_IMODE(os.stat(tmp_path / "t-acme.json").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(tmp_path / ".store.key").st_mode) == 0o600


# ── round-trip / usability ──────────────────────────────────────────────────

def test_credential_round_trips_through_materialize(dc):
    dc.upsert("t-acme", "cf", "cloudflare", {"api_token": "tok-123"})
    assert "tok-123" in str(dc.materialize("t-acme", "cf"))


def test_list_public_never_returns_secret_values(dc):
    dc.upsert("t-acme", "cf", "cloudflare", {"api_token": "tok-123"})
    pub = dc.list_public("t-acme")
    assert "tok-123" not in json.dumps(pub)
    assert pub[0]["secrets_set"]["api_token"] is True
    assert pub[0]["name"] == "cf" and pub[0]["provider"] == "cloudflare"


def test_upsert_sentinel_merge_keeps_stored_secret(dc):
    dc.upsert("t-acme", "tsig", "rfc2136",
              {"server": "192.0.2.53", "name": "k", "secret": "KEEPME"})
    # Edit a non-secret field, omitting the secret entirely.
    dc.upsert("t-acme", "tsig", "rfc2136", {"server": "198.51.100.53", "name": "k"})
    out = str(dc.materialize("t-acme", "tsig"))
    assert "KEEPME" in out and "198.51.100.53" in out


def test_delete_removes_only_the_named_credential(dc):
    dc.upsert("t-acme", "a", "cloudflare", {"api_token": "1"})
    dc.upsert("t-acme", "b", "cloudflare", {"api_token": "2"})
    assert dc.delete("t-acme", "a") is True
    assert [c["name"] for c in dc.list_public("t-acme")] == ["b"]
    assert dc.delete("t-acme", "nope") is False


def test_empty_store_lists_nothing(dc):
    assert dc.list_public("t-nobody") == []


# ── tenant isolation ────────────────────────────────────────────────────────

def test_tenants_cannot_see_each_others_credentials(dc):
    dc.upsert("t-one", "cf", "cloudflare", {"api_token": "ONE"})
    dc.upsert("t-two", "cf", "cloudflare", {"api_token": "TWO"})
    assert "ONE" in str(dc.materialize("t-one", "cf"))
    assert "TWO" in str(dc.materialize("t-two", "cf"))
    assert [c["name"] for c in dc.list_public("t-one")] == ["cf"]


def test_tenant_id_is_sanitised_against_path_traversal(dc, tmp_path):
    dc.upsert("../../etc/passwd", "cf", "cloudflare", {"api_token": "x"})
    # Everything stays inside the store dir; no traversal escaped it.
    written = [p for p in os.listdir(str(tmp_path)) if p.endswith(".json")]
    assert written and all(os.sep not in p for p in written)
    assert not os.path.exists("/etc/passwd.json")


# ── lossless upgrade from the pre-encryption plaintext format ───────────────

def test_existing_plaintext_store_is_read_then_encrypted_on_next_write(dc, tmp_path):
    """An upgraded spoke must keep working with credentials written by an
    older build, and must not leave them in the clear afterwards."""
    legacy = [{"name": "old", "provider": "cloudflare",
               "fields": {"api_token": "LEGACYTOKEN"}}]
    (tmp_path / "t-acme.json").write_text(json.dumps(legacy), encoding="utf-8")

    assert [c["name"] for c in dc.list_public("t-acme")] == ["old"]
    assert "LEGACYTOKEN" in str(dc.materialize("t-acme", "old"))

    dc.upsert("t-acme", "new", "cloudflare", {"api_token": "NEWTOKEN"})
    raw = _raw(tmp_path)
    assert raw.startswith(b"LMENC1:")
    assert b"LEGACYTOKEN" not in raw and b"NEWTOKEN" not in raw
    # Both credentials survived the migration.
    assert "LEGACYTOKEN" in str(dc.materialize("t-acme", "old"))
    assert "NEWTOKEN" in str(dc.materialize("t-acme", "new"))
