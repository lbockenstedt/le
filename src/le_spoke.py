"""Certificate Management spoke (le) for Lab Manager.

Translates hub ``LE_*`` commands into real certbot lifecycle actions and tracks
managed certs + their distribution targets in an atomic on-disk ledger. The hub
brokers cert material from this spoke to target spokes (each target applies the
cert to its own device); ``LE_GET_CERT`` is the pull the hub uses to transport
fullchain+key, and ``LE_MARK_DISTRIBUTED`` is the hub's ack so the ledger records
per-target push state.

Command contract (mirrors every LM spoke):
    {"status": "SUCCESS", "data": {...}} | {"status": "ERROR", "message": "..."}

Secrets: DNS-provider creds and private keys are never logged. ``privkey`` is
masked at the command boundary; ``LE_GET_CERT`` returns it for transport only.
"""
import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from acme import (  # type: ignore[import-not-found]
    expiring,
    list_certs,
    present as certbot_present,
    read_material,
    renew as acme_renew,
    issue as acme_issue,
    revoke as acme_revoke,
)
from ledger import Ledger  # type: ignore[import-not-found]

# BaseSpoke lives in the lm core (on PYTHONPATH in production). A standalone
# fallback keeps the spoke + its tests importable without the lm core checkout.
try:
    from core.src.base_spoke import BaseSpoke
except ImportError:
    class BaseSpoke:  # type: ignore[no-redef]
        def __init__(self, spoke_id: str, config: Dict[str, Any]):
            self.spoke_id = spoke_id
            self.config = config

        def log_info(self, message):
            pass

        def log_error(self, message):
            pass

logger = logging.getLogger("LESpoke")

_DEFAULT_LEDGER_DIR = "/var/lib/lm"
_RENEW_INTERVAL_DEFAULT = 86400  # daily
_RENEW_BACKOFF = 60


def _read_version() -> str:
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(os.path.dirname(here), "VERSION"), "r") as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class LESpoke(BaseSpoke):
    """Let's Encrypt / certificate-management spoke."""

    def __init__(self, spoke_id: str, config: Dict[str, Any],
                 control_plane: Any = None):
        # Set BEFORE super().__init__: background workers the base may start in
        # run() can read these (opnsense ordering rule).
        self._renew_task: Optional[asyncio.Task] = None
        # Reference to the LEControlPlane so the renewal loop can emit
        # LE_CERT_RENEWED to the hub (event-driven distribution) via send_to_hub.
        # None when constructed standalone (tests) — the hourly hub loop is the
        # fallback, so a missing control_plane just skips the notify.
        self.control_plane = control_plane
        ledger_path = config.get("ledger_path") or os.getenv(
            "LM_LE_LEDGER", os.path.join(_DEFAULT_LEDGER_DIR, spoke_id, "certs.json"))
        self.ledger = Ledger(ledger_path)
        self._certs: Dict[str, Dict[str, Any]] = self.ledger.load()
        self._renew_interval = int(config.get("renew_interval",
                                              _RENEW_INTERVAL_DEFAULT))

        super().__init__(spoke_id, config)
        self._start_renew_loop()
        logger.info("LESpoke initialized [%s] (%d managed cert(s))",
                    spoke_id, len(self._certs.get("certs", {})))

    # ── renewal loop (opnsense __init__-create_task pattern) ──────────────────

    def _start_renew_loop(self):
        if self._renew_task and not self._renew_task.done():
            self._renew_task.cancel()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop yet (construction outside asyncio.run). Don't
            # build the coroutine — an un-awaited coroutine would warn.
            logger.warning("Event loop not running; renewal loop deferred.")
            return
        self._renew_task = loop.create_task(self._renew_loop())

    async def _renew_loop(self):
        """Daily: reconcile ledger with /etc/letsencrypt/live and renew any cert
        within the 30-day window. On a successful renew, refresh material_hash +
        not_after so the hub's distribution loop re-pushes the new material."""
        # No blocking prime — reconciliation happens on the first tick.
        while True:
            try:
                await self._reconcile_and_renew()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("renewal loop error: %s", e)
                await asyncio.sleep(_RENEW_BACKOFF)
                continue
            await asyncio.sleep(self._renew_interval)

    async def _reconcile_and_renew(self):
        state = self.ledger.load()
        certs = state.get("certs", {})
        changed = False
        for domain, entry in list(certs.items()):
            # Refresh not_after + material_hash from disk (certbot may have
            # renewed out-of-band, or the ledger is stale post-restart).
            mat = read_material(domain)
            if mat.get("status") == "SUCCESS":
                entry["material_hash"] = mat.get("material_hash")
                entry["not_after"] = mat.get("not_after")
                changed = True
            if expiring(entry):
                logger.info("renewing %s (expiring)", domain)
                res = await acme_renew(domain)
                if res.get("status") == "SUCCESS":
                    entry["last_renewed_at"] = _now_iso()
                    entry["last_error"] = None
                    mat2 = read_material(domain)
                    if mat2.get("status") == "SUCCESS":
                        entry["material_hash"] = mat2.get("material_hash")
                        entry["not_after"] = mat2.get("not_after")
                    changed = True
                    # Event-driven distribution: tell the hub now so it
                    # re-pushes the new material instead of waiting up to 1h.
                    await self._notify_renewed(domain, entry)
                else:
                    entry["last_error"] = res.get("message")
                    logger.error("renew failed for %s: %s", domain,
                                 res.get("message"))
                    changed = True
        if changed:
            self.ledger.save(state)
            self._certs = state

    # ── helpers ───────────────────────────────────────────────────────────────

    def _persist(self):
        self.ledger.save(self._certs)

    def _public_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Ledger entry minus nothing sensitive (targets carry only push state).
        Ensures required keys exist for the UI/hub."""
        e = dict(entry)
        e.setdefault("targets", [])
        return e

    async def _notify_renewed(self, domain: str, entry: Dict[str, Any]) -> None:
        """Emit LE_CERT_RENEWED to the hub so it re-distributes the renewed
        cert material immediately (event-driven, vs. waiting up to 1h for the
        hourly poll). Best-effort: skipped when there's no control_plane or the
        spoke isn't connected yet — the hub's hourly loop is the fallback, so a
        missed event never leaves a cert undistributed."""
        if not self.control_plane:
            return
        try:
            await self.control_plane.send_to_hub("LE_CERT_RENEWED", {
                "domain": domain,
                "material_hash": entry.get("material_hash"),
                "targets": entry.get("targets", []),
            })
        except Exception as e:  # noqa: BLE001
            logger.warning("LE_CERT_RENEWED notify for %s failed: %s", domain, e)

    # ── BaseSpoke contract ────────────────────────────────────────────────────

    async def get_status(self) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "data": {
                "module": "le",
                "module_type": "certificates",
                "version": _read_version(),
                "certbot_present": certbot_present(),
                "certs_managed": len(self._certs.get("certs", {})),
            },
        }

    async def handle_command(self, command_type: str,
                             data: Dict[str, Any]) -> Dict[str, Any]:
        cmd = (command_type or "").upper()
        data = data or {}
        logger.info("Handling LE command: %s", cmd)

        if cmd == "LE_GET_STATUS":
            return await self.get_status()

        if cmd == "LE_LIST_CERTS":
            certs = [self._public_entry(e)
                     for e in self._certs.get("certs", {}).values()]
            return {"status": "SUCCESS", "data": {
                "certs": certs, "count": len(certs),
                "certbot_present": certbot_present()}}

        if cmd == "LE_GET_CERT":
            domain = data.get("domain")
            if not domain:
                return {"status": "ERROR", "message": "LE_GET_CERT requires 'domain'"}
            mat = read_material(domain)
            if mat.get("status") != "SUCCESS":
                return mat  # {status:ERROR, message}
            return {"status": "SUCCESS", "data": {
                "domain": domain, "fullchain": mat["fullchain"],
                "privkey": mat.get("privkey", ""), "chain": mat.get("chain", ""),
                "material_hash": mat["material_hash"],
                "not_after": mat.get("not_after")}}

        if cmd == "LE_ISSUE_CERT":
            return await self._issue(data)

        if cmd == "LE_RENEW_CERT":
            return await self._renew(data)

        if cmd == "LE_REVOKE_CERT":
            return await self._revoke(data)

        if cmd == "LE_ADD_TARGET":
            domain = data.get("domain")
            if not domain:
                return {"status": "ERROR", "message": "LE_ADD_TARGET requires 'domain'"}
            mt = (data.get("target") or {}).get("module_type") or data.get("module_type")
            if not mt:
                return {"status": "ERROR", "message": "target.module_type required"}
            ident = (data.get("target") or {}).get("identifier") or data.get("identifier") or ""
            t = Ledger.add_target(self._certs, domain, mt, ident)
            if t is None:
                return {"status": "ERROR", "message": f"no managed cert for {domain}"}
            self._persist()
            return {"status": "SUCCESS", "data": {"domain": domain, "target": t}}

        if cmd == "LE_REMOVE_TARGET":
            domain = data.get("domain")
            if not domain:
                return {"status": "ERROR", "message": "LE_REMOVE_TARGET requires 'domain'"}
            idx = data.get("idx")
            if idx is None:
                return {"status": "ERROR", "message": "LE_REMOVE_TARGET requires 'idx'"}
            ok = Ledger.remove_target(self._certs, domain, int(idx))
            if not ok:
                return {"status": "ERROR", "message": "target not found"}
            self._persist()
            return {"status": "SUCCESS", "data": {"domain": domain, "removed": True}}

        if cmd == "LE_MARK_DISTRIBUTED":
            return self._mark_distributed(data)

        if cmd == "UPDATE_CONFIG":
            self.config = data
            if "renew_interval" in data:
                try:
                    self._renew_interval = int(data["renew_interval"])
                    self._start_renew_loop()
                except (TypeError, ValueError):
                    pass
            return {"status": "SUCCESS", "message": "le configuration updated from hub"}

        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": _read_version()}

        if cmd == "SET_LOG_LEVEL":
            try:
                from logging_setup import set_log_level
            except ImportError:
                try:
                    from core.src.logging_setup import set_log_level
                except ImportError:
                    return {"status": "ERROR", "message": "logging_setup not available"}
            level = set_log_level(bool(data.get("enabled", False)))
            return {"status": "SUCCESS",
                    "message": f"Log level set to {logging.getLevelName(level)}"}

        return {"status": "ERROR", "message": f"Unknown command: {command_type}"}

    # ── command implementations ───────────────────────────────────────────────

    async def _issue(self, data: Dict[str, Any]) -> Dict[str, Any]:
        domain = data.get("domain")
        if not domain:
            return {"status": "ERROR", "message": "LE_ISSUE_CERT requires 'domain'"}
        email = data.get("email") or ""
        challenge = data.get("challenge", "http")
        try:
            res = await acme_issue(
                domain, email, challenge,
                webroot=data.get("webroot"),
                dns_provider=data.get("dns_provider"),
                dns_creds=data.get("dns_creds"),
                dns_creds_ini=data.get("dns_creds_ini"),
                staging=bool(data.get("staging", False)),
                key_type=data.get("key_type", "rsa"),
            )
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        if res.get("status") != "SUCCESS":
            return res
        mat = read_material(domain)
        entry: Dict[str, Any] = {
            "domain": domain,
            "email": email,
            "challenge": challenge,
            "dns_provider": data.get("dns_provider"),
            "staging": bool(data.get("staging", False)),
            "not_after": mat.get("not_after") if mat.get("status") == "SUCCESS" else None,
            "material_hash": mat.get("material_hash") if mat.get("status") == "SUCCESS" else None,
            "targets": [],
            "last_renewed_at": None,
            "last_error": None,
        }
        Ledger.upsert_cert(self._certs, entry)
        # Seed targets from the issue request AFTER upsert (upsert replaces the
        # whole entry, so adding first would be wiped). Idempotent.
        for t in (data.get("targets") or []):
            if isinstance(t, dict) and t.get("module_type"):
                Ledger.add_target(self._certs, domain, t["module_type"],
                                  t.get("identifier", "") or "")
        self._persist()
        saved = self._certs["certs"][domain]
        return {"status": "SUCCESS", "data": {
            "domain": domain, "action": "issue",
            "material_hash": saved.get("material_hash"),
            "not_after": saved.get("not_after"),
            "targets": saved.get("targets", [])}}

    async def _renew(self, data: Dict[str, Any]) -> Dict[str, Any]:
        domain = data.get("domain")
        renewed: List[Dict[str, Any]] = []
        domains = [domain] if domain else list(self._certs.get("certs", {}).keys())
        if domain and domain not in self._certs.get("certs", {}):
            return {"status": "ERROR", "message": f"No managed cert for {domain}"}
        for d in domains:
            res = await acme_renew(d)
            entry = self._certs.get("certs", {}).get(d)
            if entry is None:
                continue
            if res.get("status") == "SUCCESS":
                entry["last_renewed_at"] = _now_iso()
                entry["last_error"] = None
                mat = read_material(d)
                if mat.get("status") == "SUCCESS":
                    entry["material_hash"] = mat["material_hash"]
                    entry["not_after"] = mat.get("not_after")
                renewed.append({"domain": d, "renewed": res.get("renewed", True),
                                "material_hash": entry.get("material_hash"),
                                "targets": entry.get("targets", [])})
                # Event-driven distribution: tell the hub now so it re-pushes
                # the new material instead of waiting up to 1h for the poll.
                await self._notify_renewed(d, entry)
            else:
                entry["last_error"] = res.get("message")
                renewed.append({"domain": d, "renewed": False,
                                "error": res.get("message"),
                                "targets": entry.get("targets", [])})
        self._persist()
        return {"status": "SUCCESS", "data": {"renewed": renewed,
                                               "count": len(renewed)}}

    async def _revoke(self, data: Dict[str, Any]) -> Dict[str, Any]:
        domain = data.get("domain")
        if not domain:
            return {"status": "ERROR", "message": "LE_REVOKE_CERT requires 'domain'"}
        res = await acme_revoke(domain, delete=bool(data.get("delete", True)))
        if res.get("status") == "SUCCESS":
            Ledger.remove_cert(self._certs, domain)
            self._persist()
            return {"status": "SUCCESS", "data": {
                "domain": domain, "action": "revoke",
                "deleted": res.get("deleted", bool(data.get("delete", True)))}}
        return res

    def _mark_distributed(self, data: Dict[str, Any]) -> Dict[str, Any]:
        domain = data.get("domain")
        if not domain:
            return {"status": "ERROR", "message": "LE_MARK_DISTRIBUTED requires 'domain'"}
        mt = data.get("module_type")
        ident = data.get("identifier") or ""
        if not mt:
            return {"status": "ERROR", "message": "module_type required"}
        entry = self._certs.get("certs", {}).get(domain)
        if entry is None:
            return {"status": "ERROR", "message": f"no managed cert for {domain}"}
        for t in entry.get("targets", []):
            if t.get("module_type") == mt and t.get("identifier", "") == ident:
                t["last_pushed_hash"] = data.get("hash")
                t["last_pushed_at"] = _now_iso()
                t["last_status"] = data.get("status")
                t["last_message"] = data.get("message")
                self._persist()
                return {"status": "SUCCESS", "data": {"domain": domain, "target": t}}
        return {"status": "ERROR", "message": "target not found for distribution ack"}