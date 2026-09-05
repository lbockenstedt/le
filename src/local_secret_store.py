"""Encryption-at-rest for spoke-local credential stores.

WHY THIS EXISTS
---------------
When a hub-side Credential Vault is configured, credentials live there and the
spoke never persists a raw secret. But a vault is OPTIONAL — plenty of
deployments run without one, and in that case the spoke-local store is the only
place a DNS-01 credential can go. Previously that store was plaintext JSON
protected by nothing but 0600 file permissions, so anything that could read the
file (a backup, a snapshot, a stray root process, a copied disk image) got the
secrets in the clear.

This module gives the spoke the same "encrypted at rest" property the hub
already has via ``security/encryption.py``, without needing the hub's key: the
le spoke is a separate process in a separate repo and has no access to the
hub's ``LM_FERNET_KEY`` or vault.

KEY MANAGEMENT
--------------
Fernet (AES-128-CBC + HMAC-SHA256, from ``cryptography``, already a dependency).

The key is resolved in this order:
  1. ``LM_LE_STORE_KEY`` env var — a urlsafe-base64 Fernet key. Lets an
     operator supply/rotate/escrow the key, or share one across a rebuilt spoke
     so an existing store stays readable.
  2. ``<store_dir>/.store.key`` — auto-generated on first use, 0600, in the
     same directory as the data it protects.

Being co-located with the data, the key is NOT a defence against an attacker
who already has root on the spoke — it can't be. What it does buy is that the
credential files are no longer readable on their own: backups, disk images,
config snapshots, and accidental file copies no longer leak secrets in the
clear, and the key is a single small file an operator can rotate or escrow.

MIGRATION
---------
:func:`load_json` transparently reads a legacy PLAINTEXT JSON file and returns
it, so upgrading a spoke never loses existing credentials. The next
:func:`save_json` rewrites it encrypted, so the migration completes on first
write with no operator action.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

logger = logging.getLogger("le.local_secret_store")

# Marks a file written by this module, so load_json can tell an encrypted blob
# from a legacy plaintext JSON file without guessing.
_MAGIC = b"LMENC1:"

_KEY_ENV = "LM_LE_STORE_KEY"
_KEY_FILENAME = ".store.key"

_key_cache: dict = {}  # store_dir -> Fernet instance


def _fernet(store_dir: str):
    """The Fernet for ``store_dir``, generating + persisting a key on first use.

    Cached per directory: key derivation is trivial but the file read isn't
    worth repeating on every credential lookup."""
    f = _key_cache.get(store_dir)
    if f is not None:
        return f
    from cryptography.fernet import Fernet

    raw = (os.getenv(_KEY_ENV) or "").strip()
    if raw:
        try:
            f = Fernet(raw.encode() if isinstance(raw, str) else raw)
            _key_cache[store_dir] = f
            return f
        except Exception as exc:  # noqa: BLE001
            raise ValueError(
                f"{_KEY_ENV} is set but is not a valid Fernet key: {exc}") from exc

    path = os.path.join(store_dir, _KEY_FILENAME)
    key: Optional[bytes] = None
    try:
        with open(path, "rb") as fh:
            key = fh.read().strip()
    except FileNotFoundError:
        key = None
    except OSError as exc:
        raise ValueError(f"could not read local store key {path}: {exc}") from exc

    if not key:
        key = Fernet.generate_key()
        os.makedirs(store_dir, exist_ok=True)
        try:
            os.chmod(store_dir, 0o700)
        except OSError:
            pass
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        logger.info("local_secret_store: generated a new encryption key at %s", path)

    f = Fernet(key)
    _key_cache[store_dir] = f
    return f


def reset_key_cache() -> None:
    """Drop the cached Fernet(s). For tests and for picking up a rotated key
    without a process restart."""
    _key_cache.clear()


def is_encrypted(blob: bytes) -> bool:
    return isinstance(blob, (bytes, bytearray)) and bytes(blob).startswith(_MAGIC)


def save_json(path: str, obj: Any) -> None:
    """Atomically write ``obj`` as an ENCRYPTED blob at ``path``, mode 0600.

    Atomic (tmp + ``os.replace``) so a crash mid-write can't leave a truncated
    or half-encrypted store that would read back as "no credentials"."""
    store_dir = os.path.dirname(path) or "."
    os.makedirs(store_dir, exist_ok=True)
    try:
        os.chmod(store_dir, 0o700)
    except OSError:
        pass
    token = _fernet(store_dir).encrypt(json.dumps(obj).encode("utf-8"))
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(_MAGIC + token)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_json(path: str, default: Any = None) -> Any:
    """Read a store written by :func:`save_json`.

    Transparently accepts a legacy PLAINTEXT JSON file so an upgraded spoke
    keeps its existing credentials (the next save_json re-writes it encrypted).
    Any unreadable/corrupt/undecryptable file logs a warning and returns
    ``default`` rather than raising — a broken store must not take the spoke
    down, and callers treat "no credentials" as a recoverable state."""
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except FileNotFoundError:
        return default
    except OSError as exc:
        logger.warning("local_secret_store: could not read %s: %s", path, exc)
        return default

    if not blob.strip():
        return default

    if is_encrypted(blob):
        try:
            plain = _fernet(os.path.dirname(path) or ".").decrypt(blob[len(_MAGIC):])
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "local_secret_store: could not decrypt %s (%s) — if the "
                "encryption key was lost or replaced, the stored credentials "
                "must be re-entered", path, exc)
            return default
        try:
            return json.loads(plain.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("local_secret_store: corrupt payload in %s: %s", path, exc)
            return default

    # Legacy plaintext JSON — accept it so the upgrade is lossless.
    try:
        obj = json.loads(blob.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("local_secret_store: could not parse %s: %s", path, exc)
        return default
    logger.info("local_secret_store: %s is plaintext (pre-encryption format); "
                "it will be re-written encrypted on the next change", path)
    return obj
