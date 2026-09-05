"""``local_secret_store`` — Fernet encryption-at-rest for spoke-local stores.

A hub-side Credential Vault is OPTIONAL. Without one, the spoke-local store is
the only place a DNS-01 credential can live, and it used to be plaintext JSON
guarded by nothing but 0600 permissions — so a backup, snapshot, or copied disk
image carried every secret in the clear. These tests pin the replacement:

  * secrets are never present in the on-disk bytes;
  * the payload round-trips exactly;
  * files and the key are 0600, the directory 0700;
  * a LEGACY plaintext JSON store is still readable (lossless upgrade) and is
    re-written encrypted on the next save;
  * a lost/rotated key or a corrupt file degrades to "no credentials" rather
    than taking the spoke down.
"""
import json
import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import local_secret_store as lss  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_key_state(monkeypatch):
    monkeypatch.delenv(lss._KEY_ENV, raising=False)
    lss.reset_key_cache()
    yield
    lss.reset_key_cache()


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_round_trip_preserves_payload(tmp_path):
    p = str(tmp_path / "creds.json")
    payload = [{"name": "cf", "provider": "cloudflare",
                "fields": {"api_token": "s3cret"}}]
    lss.save_json(p, payload)
    assert lss.load_json(p) == payload


def test_secret_is_not_present_in_the_on_disk_bytes(tmp_path):
    p = str(tmp_path / "creds.json")
    lss.save_json(p, [{"fields": {"api_token": "SUPERSECRET123"}}])
    raw = open(p, "rb").read()
    assert b"SUPERSECRET123" not in raw
    assert b"api_token" not in raw  # even the field NAMES are inside the blob
    assert lss.is_encrypted(raw)


def test_file_and_key_permissions_are_locked_down(tmp_path):
    p = str(tmp_path / "creds.json")
    lss.save_json(p, {"a": 1})
    assert _mode(p) == 0o600
    assert _mode(os.path.join(str(tmp_path), lss._KEY_FILENAME)) == 0o600
    assert _mode(str(tmp_path)) == 0o700


def test_key_is_generated_once_and_reused(tmp_path):
    p = str(tmp_path / "creds.json")
    keyfile = os.path.join(str(tmp_path), lss._KEY_FILENAME)
    lss.save_json(p, {"a": 1})
    key1 = open(keyfile, "rb").read()
    lss.reset_key_cache()
    lss.save_json(p, {"a": 2})
    assert open(keyfile, "rb").read() == key1
    assert lss.load_json(p) == {"a": 2}


def test_env_key_overrides_the_key_file(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet
    monkeypatch.setenv(lss._KEY_ENV, Fernet.generate_key().decode())
    lss.reset_key_cache()
    p = str(tmp_path / "creds.json")
    lss.save_json(p, {"a": 1})
    # No key file is created when the operator supplies one.
    assert not os.path.exists(os.path.join(str(tmp_path), lss._KEY_FILENAME))
    assert lss.load_json(p) == {"a": 1}


def test_invalid_env_key_is_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.setenv(lss._KEY_ENV, "not-a-fernet-key")
    lss.reset_key_cache()
    with pytest.raises(ValueError, match="not a valid Fernet key"):
        lss.save_json(str(tmp_path / "creds.json"), {"a": 1})


def test_missing_file_returns_default(tmp_path):
    assert lss.load_json(str(tmp_path / "nope.json")) is None
    assert lss.load_json(str(tmp_path / "nope.json"), default=[]) == []


def test_empty_file_returns_default(tmp_path):
    p = tmp_path / "creds.json"
    p.write_bytes(b"   ")
    assert lss.load_json(str(p), default=[]) == []


# ── lossless upgrade from the pre-encryption plaintext format ───────────────

def test_legacy_plaintext_json_is_still_readable(tmp_path):
    """Upgrading a spoke must not lose existing credentials."""
    p = tmp_path / "creds.json"
    payload = [{"name": "legacy", "fields": {"api_token": "OLD"}}]
    p.write_text(json.dumps(payload), encoding="utf-8")
    assert lss.load_json(str(p)) == payload


def test_legacy_plaintext_is_rewritten_encrypted_on_next_save(tmp_path):
    p = tmp_path / "creds.json"
    p.write_text(json.dumps([{"fields": {"api_token": "OLD"}}]), encoding="utf-8")
    data = lss.load_json(str(p))
    lss.save_json(str(p), data)
    raw = p.read_bytes()
    assert lss.is_encrypted(raw)
    assert b"OLD" not in raw
    assert lss.load_json(str(p)) == data


# ── failure modes must degrade, never crash the spoke ───────────────────────

def test_undecryptable_file_returns_default_not_an_exception(tmp_path):
    """A lost or replaced key must not take the spoke down — the operator
    re-enters the credentials instead."""
    p = str(tmp_path / "creds.json")
    lss.save_json(p, {"a": 1})
    os.remove(os.path.join(str(tmp_path), lss._KEY_FILENAME))
    lss.reset_key_cache()
    assert lss.load_json(p, default=[]) == []


def test_corrupt_encrypted_blob_returns_default(tmp_path):
    p = tmp_path / "creds.json"
    lss.save_json(str(p), {"a": 1})
    p.write_bytes(lss._MAGIC + b"garbage-not-a-fernet-token")
    assert lss.load_json(str(p), default=[]) == []


def test_corrupt_plaintext_returns_default(tmp_path):
    p = tmp_path / "creds.json"
    p.write_bytes(b"{not json at all")
    assert lss.load_json(str(p), default=[]) == []


def test_save_is_atomic_no_tmp_left_behind(tmp_path):
    p = str(tmp_path / "creds.json")
    lss.save_json(p, {"a": 1})
    assert not os.path.exists(p + ".tmp")
    assert sorted(os.listdir(str(tmp_path))) == [lss._KEY_FILENAME, "creds.json"]


def test_two_stores_in_different_dirs_use_different_keys(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    lss.save_json(str(a / "c.json"), {"x": 1})
    lss.save_json(str(b / "c.json"), {"x": 1})
    ka = (a / lss._KEY_FILENAME).read_bytes()
    kb = (b / lss._KEY_FILENAME).read_bytes()
    assert ka != kb
    # ...and a blob from one does not decrypt under the other's key.
    (b / "c.json").write_bytes((a / "c.json").read_bytes())
    lss.reset_key_cache()
    assert lss.load_json(str(b / "c.json"), default="BAD") == "BAD"
