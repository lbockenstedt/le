"""Atomic on-disk ledger for the le spoke.

Persists the set of managed certs + per-domain distribution targets +
per-target ``last_pushed_hash`` so the hub can skip re-pushing unchanged
material. Mirrors the atomic ``tmp + os.replace`` idiom used across LM
(``nw_cache.py``); a ``threading.Lock`` guards concurrent writes from the
renewal loop vs. command handlers.

State shape (see plans/… for the full contract)::

    {"certs": {
      "example.com": {
        "domain", "email", "challenge", "dns_provider", "staging",
        "not_after", "material_hash",
        "targets": [{"module_type", "identifier",
                     "last_pushed_hash", "last_pushed_at",
                     "last_status", "last_message"}],
        "last_renewed_at", "last_error"
      }
    }}
"""
import asyncio
import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger("LELedger")


class Ledger:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    # ── load ────────────────────────────────────────────────────────────────
    def load(self) -> Dict[str, Any]:
        """Return the persisted state, or a fresh skeleton on miss/corruption."""
        try:
            with open(self.path, "r") as f:
                state = json.load(f)
            if isinstance(state, dict) and isinstance(state.get("certs"), dict):
                return state
            logger.warning("ledger %s: unexpected shape, resetting", self.path)
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning("ledger load failed (%s): %s", self.path, e)
        return {"certs": {}}

    # ── save ────────────────────────────────────────────────────────────────
    def save(self, state: Dict[str, Any]) -> None:
        """Atomic write: tmp file + os.replace (crash-safe; readers see whole
        old or whole new)."""
        with self._lock:
            tmp = f"{self.path}.tmp"
            with open(tmp, "w") as f:
                json.dump(state, f, indent=2)
            os.replace(tmp, self.path)

    async def save_async(self, state: Dict[str, Any]) -> None:
        """Offload the (small, lock-guarded) write off the event loop."""
        await asyncio.to_thread(self.save, state)

    # ── convenience mutators (operate on a state dict in place) ──────────────
    @staticmethod
    def get_cert(state: Dict[str, Any], domain: str) -> Optional[Dict[str, Any]]:
        return state.setdefault("certs", {}).get(domain)

    @staticmethod
    def upsert_cert(state: Dict[str, Any], entry: Dict[str, Any]) -> None:
        state.setdefault("certs", {})[entry["domain"]] = entry

    @staticmethod
    def remove_cert(state: Dict[str, Any], domain: str) -> bool:
        return state.setdefault("certs", {}).pop(domain, None) is not None

    @staticmethod
    def add_target(state: Dict[str, Any], domain: str,
                   module_type: str, identifier: str = "") -> Optional[Dict[str, Any]]:
        cert = state.setdefault("certs", {}).get(domain)
        if cert is None:
            return None
        targets: List[Dict[str, Any]] = cert.setdefault("targets", [])
        # Idempotent on (module_type, identifier).
        for t in targets:
            if t.get("module_type") == module_type and t.get("identifier", "") == identifier:
                return t
        t = {"module_type": module_type, "identifier": identifier,
             "last_pushed_hash": None, "last_pushed_at": None,
             "last_status": None, "last_message": None}
        targets.append(t)
        return t

    @staticmethod
    def remove_target(state: Dict[str, Any], domain: str, idx: int) -> bool:
        cert = state.setdefault("certs", {}).get(domain)
        if cert is None:
            return False
        targets: List[Dict[str, Any]] = cert.get("targets") or []
        if 0 <= idx < len(targets):
            targets.pop(idx)
            return True
        return False

    @staticmethod
    def target_key(module_type: str, identifier: str = "") -> str:
        return target_key(module_type, identifier)


def target_key(module_type: str, identifier: str = "") -> str:
    """Stable string key for a (module_type, identifier) target pair."""
    return f"{module_type}:{identifier}" if identifier else module_type