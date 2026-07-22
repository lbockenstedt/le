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
import ssl
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from acme import (  # type: ignore[import-not-found]
    expiring,
    _RENEW_WINDOW_DAYS,
    present as certbot_present,
    read_material,
    renew as acme_renew,
    issue as acme_issue,
    revoke as acme_revoke,
    write_he_creds,
)
from ledger import Ledger  # type: ignore[import-not-found]
import dns_credentials  # type: ignore[import-not-found]  # per-tenant DNS-01 credential store

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

# Cert-install helper the spoke drives the dumb Agent to run (WRITE_FILE two
# 0600 temps → RUN_COMMAND this helper). Role-provisioned on the cert-target
# box (analogous to netbox-server provisioning lm-netbox-install-cert). Contract:
# `lm-le-install-cert <domain> <crt-tmp> <key-tmp>` prints `OK <msg>` on success
# / exits nonzero with stderr on failure. Override for non-default paths.
_LE_INSTALL_CERT_HELPER = os.getenv("LM_LE_INSTALL_CERT_HELPER",
                                    "/usr/local/bin/lm-le-install-cert")


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
        logger.info("LESpoke initialized [%s] v%s BUILD-MARKER-DNSCRED "
                    "(LE_SET_DNS_CRED/LE_LIST_DNS_CREDS handlers active) — %d managed cert(s)",
                    spoke_id, _read_version(), len(self._certs.get("certs", {})))

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
        not_after so the hub's distribution loop re-pushes the new material. Also
        ensures certbot is profile-capable + keeps it auto-updated (certbot_update)."""
        # One-time: make certbot ACME-profile-capable (installs a recent certbot in
        # a venv if the system one is too old for --preferred-profile). Best-effort.
        try:
            import certbot_update  # type: ignore[import-not-found]
            await certbot_update.ensure_certbot()
        except Exception as e:  # noqa: BLE001 - never let this break renewals
            logger.warning("certbot ensure/update skipped: %s", e)
        while True:
            try:
                # Keep certbot current each cycle (venv pip -U / snap / apt).
                try:
                    import certbot_update  # type: ignore[import-not-found]
                    await certbot_update.refresh()
                except Exception as e:  # noqa: BLE001
                    logger.debug("certbot refresh skipped: %s", e)
                await self._reconcile_and_renew()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("renewal loop error: %s", e)
                await asyncio.sleep(_RENEW_BACKOFF)
                continue
            await asyncio.sleep(self._renew_interval)

    async def _reconcile_and_renew(self):
        # Operate on self._certs IN PLACE — the SAME dict the command handlers
        # mutate. The old code loaded a separate ``state`` snapshot, awaited the
        # long acme_renew, then reassigned ``self._certs = state``, silently
        # clobbering any LE_ADD_TARGET / LE_MARK_DISTRIBUTED a handler applied
        # during the await (lost update). Iterating a list() snapshot means a
        # concurrent add/remove doesn't break the loop.
        certs = self._certs.setdefault("certs", {})
        changed = False
        for domain, entry in list(certs.items()):
            # Refresh not_after + material_hash from disk (certbot may have
            # renewed out-of-band, or the ledger is stale post-restart). Only mark
            # changed on an ACTUAL diff so we don't rewrite the ledger every tick.
            mat = read_material(domain)
            if mat.get("status") == "SUCCESS":
                if (entry.get("material_hash") != mat.get("material_hash")
                        or entry.get("not_after") != mat.get("not_after")):
                    entry["material_hash"] = mat.get("material_hash")
                    entry["not_after"] = mat.get("not_after")
                    changed = True
            else:
                # A transient read failure (perms, mid-renew race, disk) must
                # not silently skip this cert's renew evaluation — surface it so
                # a stuck cert is visible, then fall through to expiring() using
                # the ledger's last-known not_after.
                logger.warning("reconcile: read_material(%s) failed (%s); "
                               "evaluating renewal from ledger state",
                               domain, mat.get("message", "unknown"))
            if expiring(entry):
                logger.info("renewing %s (expiring)", domain)
                # No overall deadline on acme_renew means one domain stuck on
                # DNS propagation (or a certbot hang) would freeze renewals for
                # EVERY other domain. Bound it so a stuck domain can't starve
                # the rest; on timeout, log + continue to the next domain.
                try:
                    res = await asyncio.wait_for(acme_renew(domain), timeout=600)
                except asyncio.TimeoutError:
                    logger.error("renew for %s timed out after 600s; "
                                 "continuing with remaining domains", domain)
                    entry["last_error"] = "renew timed out after 600s"
                    changed = True
                    await self._notify_renew_failed(domain, "renew timed out after 600s")
                    continue
                if domain not in certs:
                    continue  # a handler removed this cert during the renew await
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
                    # Event-driven alert: tell the hub now so a renewal failure
                    # surfaces as a realtime cert alert (vs. the hourly pull).
                    await self._notify_renew_failed(domain, res.get("message"))
        if changed:
            self.ledger.save(self._certs)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _persist(self):
        self.ledger.save(self._certs)

    def _record_issue(self, domain: str, tenant_id: str, success: bool,
                      message: str, challenge: str, email: str,
                      staging: bool) -> None:
        """Record an issue attempt's outcome in the ledger so a FAILED issue
        persists — visible via LE_LIST_CERTS → the hub's le_cache → the
        Certificates list + Certificates log, and scannable by the hub's
        cert-issue-failed alert. A failed issue of a NEW domain creates a
        minimal entry (no cert material); a failed RE-issue of an existing
        domain MERGES (preserves material_hash/not_after/targets — the
        previously-issued cert is still valid) and just stamps the failure.
        ``last_issue_error`` (None on success) is the alert/UI marker; cleared
        on a successful issue so the alert edge recovers."""
        certs = self._certs.setdefault("certs", {})
        entry = certs.get(domain)
        if entry is None:
            entry = {"domain": domain, "email": email, "challenge": challenge,
                     "dns_provider": None, "dns_credential": None,
                     "tenant_id": tenant_id or "default", "staging": bool(staging),
                     "not_after": None, "material_hash": None,
                     "renew_window_days": None, "targets": [],
                     "last_renewed_at": None, "last_error": None}
            certs[domain] = entry
        # Refresh the operator-supplied issue params so a retry is pre-filled.
        if email:
            entry["email"] = email
        if challenge:
            entry["challenge"] = challenge
        if tenant_id:
            entry["tenant_id"] = tenant_id
        entry["staging"] = bool(staging)
        entry["last_issue_at"] = _now_iso()
        entry["last_issue_error"] = None if success else (message or "issue failed")
        self._persist()

    def _public_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Ledger entry minus nothing sensitive (targets carry only push state).
        Ensures required keys exist for the UI/hub."""
        e = dict(entry)
        e.setdefault("targets", [])
        # renew_window_days: None → the module default (7). Surface the EFFECTIVE
        # value as renew_window_days_effective so the UI can show "renews N days
        # before expiry" without re-deriving the default. Keep the raw stored
        # value (None = default) for round-tripping edits.
        e.setdefault("renew_window_days", None)
        e["renew_window_days_effective"] = (e["renew_window_days"]
                                            if e["renew_window_days"] else _RENEW_WINDOW_DAYS)
        e.setdefault("client_auth", False)   # clientAuth EKU requested (mTLS client use)
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

    async def _notify_renew_failed(self, domain: str, message: str) -> None:
        """Emit LE_CERT_RENEW_FAILED to the hub so a background (or on-demand)
        renewal failure can drive a realtime cert-renewal-failed alert instead
        of waiting for the hourly LE_LIST_CERTS pull. Best-effort, same shape as
        _notify_renewed; the ledger's ``last_error`` is the persisted record
        either way (the event is the prompt transport)."""
        if not self.control_plane:
            return
        try:
            await self.control_plane.send_to_hub("LE_CERT_RENEW_FAILED", {
                "domain": domain,
                "message": message or "renew failed",
            })
        except Exception as e:  # noqa: BLE001
            logger.warning("LE_CERT_RENEW_FAILED notify for %s failed: %s", domain, e)

    # ── BaseSpoke contract ────────────────────────────────────────────────────

    async def get_status(self) -> Dict[str, Any]:
        """Module status for the WebUI/hub: version, ``certbot_present``, and
        the number of certs currently managed in the ledger."""
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
        """Dispatch a hub ``LE_*`` command. Returns the standard spoke contract
        ``{"status": "SUCCESS", "data": ...}`` or ``{"status": "ERROR", ...}``.
        Long-running certbot work is awaited as an async subprocess so the event
        loop stays responsive; ``privkey`` material is returned for distribution
        but masked at the log boundary."""
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

        if cmd == "LE_SET_CLIENTAUTH":
            return await self._set_clientauth(data)

        if cmd == "LE_ACME_INFO":
            from acme import acme_info as _acme_info  # type: ignore[import-not-found]
            return {"status": "SUCCESS", "data": await _acme_info()}

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

        # ── Agent-host cert deploy (dumb Agent on a cert-target box) ───────────
        if cmd == "LE_DEPLOY_TO_AGENT":
            return await self._deploy_to_agent_command(data)

        # ── Per-tenant multi-provider DNS-01 credential store ──────────────────
        if cmd == "LE_LIST_DNS_CREDS":
            tid = data.get("tenant_id") or "default"
            return {"status": "SUCCESS", "credentials": dns_credentials.list_public(tid),
                    "providers": list(dns_credentials.PROVIDERS),
                    "provider_fields": dns_credentials.PROVIDER_FIELDS}

        if cmd == "LE_SET_DNS_CRED":
            tid = data.get("tenant_id") or "default"
            try:
                dns_credentials.upsert(tid, data.get("name") or "",
                                       data.get("provider") or "",
                                       data.get("fields") or {})
            except ValueError as e:
                return {"status": "ERROR", "message": str(e)}
            except Exception as e:  # noqa: BLE001
                return {"status": "ERROR", "message": f"failed to store credential: {e}"}
            return {"status": "SUCCESS", "message": "DNS credential saved"}

        if cmd == "LE_DELETE_DNS_CRED":
            tid = data.get("tenant_id") or "default"
            ok = dns_credentials.delete(tid, data.get("name") or "")
            if not ok:
                return {"status": "ERROR", "message": "credential not found"}
            return {"status": "SUCCESS", "message": "DNS credential deleted"}

        if cmd == "LE_SET_HE_LOGIN":
            # Persistent Hurricane Electric account-login knob: store the creds in
            # config AND to the durable 0600 file the DNS hook reads (issue +
            # unattended renewals). Empty password clears it.
            he_u = (data.get("he_username") or "").strip()
            he_p = data.get("he_password") or ""
            if not he_u or not he_p:
                return {"status": "ERROR",
                        "message": "he_username and he_password are required"}
            self.config["he_username"] = he_u
            self.config["he_password"] = he_p
            try:
                write_he_creds(he_u, he_p)
            except Exception as e:  # noqa: BLE001
                return {"status": "ERROR", "message": f"failed to store HE creds: {e}"}
            return {"status": "SUCCESS", "message": "Hurricane Electric login stored"}

        if cmd == "LE_GET_HE_LOGIN":
            # Report configuration status WITHOUT returning the password.
            u = self.config.get("he_username") or ""
            import os as _os
            configured = bool(u) or _os.path.exists(
                _os.getenv("LM_LE_HE_CREDS", "/etc/lm-le/he-login.ini"))
            return {"status": "SUCCESS", "configured": configured, "he_username": u}

        if cmd == "UPDATE_CONFIG":
            self.config = data
            if "renew_interval" in data:
                try:
                    self._renew_interval = int(data["renew_interval"])
                    self._start_renew_loop()
                except (TypeError, ValueError):
                    pass
            # Persist the Hurricane Electric account-login knob so the DNS hook
            # (issue + unattended renewals) can read it without per-request creds.
            he_u, he_p = data.get("he_username"), data.get("he_password")
            if he_u and he_p:
                try:
                    write_he_creds(he_u, he_p)
                except Exception as e:  # noqa: BLE001
                    logger.warning("failed to persist HE login creds: %s", e)
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

    async def _set_clientauth(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Toggle the clientAuth EKU on an EXISTING managed cert and re-issue now so
        the new ACME profile takes effect. Rebuilds the issue request from the cert's
        stored ledger params (challenge, email, DNS credential, tenant, staging) +
        the new flag, force-renewing. For mTLS CLIENT certs (BugFixer, the wildcard);
        certs that don't need it stay on the default server-only profile."""
        domain = data.get("domain")
        if not domain:
            return {"status": "ERROR", "message": "LE_SET_CLIENTAUTH requires 'domain'"}
        entry = self._certs.get("certs", {}).get(domain)
        if not entry:
            return {"status": "ERROR", "message": f"no managed cert for {domain}"}
        enabled = bool(data.get("client_auth", data.get("enabled", False)))
        issue_data = {
            "domain": domain,
            "email": entry.get("email") or "",
            "challenge": entry.get("challenge") or "http",
            "dns_provider": entry.get("dns_provider"),
            "dns_credential": entry.get("dns_credential"),
            "tenant_id": entry.get("tenant_id") or "default",
            "staging": bool(entry.get("staging", False)),
            "key_type": entry.get("key_type", "rsa"),
            "renew_window_days": entry.get("renew_window_days"),
            "client_auth": enabled,
            "force_renewal": True,
        }
        return await self._issue(issue_data)

    async def _issue(self, data: Dict[str, Any]) -> Dict[str, Any]:
        domain = data.get("domain")
        if not domain:
            return {"status": "ERROR", "message": "LE_ISSUE_CERT requires 'domain'"}
        email = data.get("email") or ""
        challenge = data.get("challenge", "http")
        # Named per-tenant DNS credential (multi-tenant store). When the request
        # names one, materialize it for THIS tenant and let it supply the provider
        # + secrets; an explicit per-request dns_provider/creds still wins if given.
        tenant_id = data.get("tenant_id") or "default"
        cred_name = data.get("dns_credential")
        mat: Dict[str, Any] = {}
        if cred_name:
            try:
                mat = dns_credentials.materialize(tenant_id, cred_name)
            except KeyError as e:
                self._record_issue(domain, tenant_id, False, str(e), challenge, email,
                                   bool(data.get("staging", False)))
                logger.error("issue failed for %s: %s", domain, e)
                return {"status": "ERROR", "message": str(e)}
            except Exception as e:  # noqa: BLE001
                self._record_issue(domain, tenant_id, False, f"DNS credential error: {e}",
                                  challenge, email, bool(data.get("staging", False)))
                logger.error("issue failed for %s: DNS credential error: %s", domain, e)
                return {"status": "ERROR", "message": f"DNS credential error: {e}"}
        try:
            res = await acme_issue(
                domain, email, challenge,
                webroot=data.get("webroot"),
                dns_provider=data.get("dns_provider") or mat.get("dns_provider"),
                dns_creds=data.get("dns_creds") or mat.get("dns_creds"),
                dns_creds_ini=data.get("dns_creds_ini"),
                # HE account-login creds: per-request wins, else the named
                # credential, else the legacy single knob (self.config).
                he_username=data.get("he_username") or mat.get("he_username") or self.config.get("he_username"),
                he_password=data.get("he_password") or mat.get("he_password") or self.config.get("he_password"),
                route53_env=mat.get("route53_env"),
                staging=bool(data.get("staging", False)),
                key_type=data.get("key_type", "rsa"),
                # clientAuth EKU (for mTLS CLIENT certs, e.g. BugFixer): request the
                # ACME "classic"-style profile. force_renewal lets a toggle on an
                # EXISTING cert take effect now instead of waiting for expiry.
                client_auth=bool(data.get("client_auth", False)),
                force_renewal=bool(data.get("force_renewal", False)),
            )
        except ValueError as e:
            self._record_issue(domain, tenant_id, False, str(e), challenge, email,
                               bool(data.get("staging", False)))
            logger.error("issue failed for %s: %s", domain, e)
            return {"status": "ERROR", "message": str(e)}
        if res.get("status") != "SUCCESS":
            self._record_issue(domain, tenant_id, False, res.get("message"),
                               challenge, email, bool(data.get("staging", False)))
            logger.error("issue failed for %s: %s", domain, res.get("message"))
            return res
        mat = read_material(domain)
        # Per-cert renewal window (days before expiry the loop triggers). Default
        # 7 (acme._RENEW_WINDOW_DAYS); operator can override at issue time. None
        # → expiring() falls back to the module default. Validated to a positive
        # int so a bad value can't disable renewal (None is "use default").
        rwd = data.get("renew_window_days")
        try:
            rwd = int(rwd) if rwd not in (None, "") else None
            if rwd is not None and rwd <= 0:
                rwd = None
        except (TypeError, ValueError):
            rwd = None
        # Re-add (re-issue of an existing domain): capture its current
        # distribution targets BEFORE the upsert replaces the whole entry.
        # Dropping them would silently unlink a live cert from its push
        # destinations; carrying them forward with RESET push markers (below)
        # guarantees a config-changing re-add re-fires distribution with the
        # freshly-issued material instead of leaving a stale last_pushed_hash
        # that makes the hub skip the re-push.
        prev = self._certs.get("certs", {}).get(domain) or {}
        prev_targets = [t for t in (prev.get("targets") or [])
                        if isinstance(t, dict) and t.get("module_type")]
        entry: Dict[str, Any] = {
            "domain": domain,
            "email": email,
            "challenge": challenge,
            "dns_provider": data.get("dns_provider") or mat.get("dns_provider"),
            "dns_credential": cred_name,
            "tenant_id": tenant_id,
            "staging": bool(data.get("staging", False)),
            "client_auth": bool(data.get("client_auth", False)),
            "not_after": mat.get("not_after") if mat.get("status") == "SUCCESS" else None,
            "material_hash": mat.get("material_hash") if mat.get("status") == "SUCCESS" else None,
            "renew_window_days": rwd,
            "targets": [],
            "last_renewed_at": None,
            "last_error": None,
            "last_issue_at": _now_iso(),
            "last_issue_error": None,
        }
        Ledger.upsert_cert(self._certs, entry)
        # Seed targets AFTER upsert (upsert replaces the whole entry, so adding
        # first would be wiped): carried-forward targets first, then any from
        # the issue request. add_target is idempotent on (module_type,
        # identifier) and creates each target with last_pushed_hash=None, so
        # every target re-enters an un-pushed state → distribution re-fires.
        for t in prev_targets + list(data.get("targets") or []):
            if isinstance(t, dict) and t.get("module_type"):
                Ledger.add_target(self._certs, domain, t["module_type"],
                                  t.get("identifier", "") or "")
        # Belt-and-suspenders: force the un-pushed state on ALL targets so a
        # re-add always re-distributes fresh material regardless of add_target's
        # defaults.
        for t in self._certs.get("certs", {}).get(domain, {}).get("targets", []):
            t["last_pushed_hash"] = None
            t["last_pushed_at"] = None
        self._persist()
        saved = self._certs["certs"][domain]
        return {"status": "SUCCESS", "data": {
            "domain": domain, "action": "issue",
            "material_hash": saved.get("material_hash"),
            "not_after": saved.get("not_after"),
            "renew_window_days": saved.get("renew_window_days"),
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
                # Event-driven alert for on-demand renewal failure too (mirrors
                # the background loop's _notify_renew_failed).
                await self._notify_renew_failed(d, res.get("message"))
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

    # ── Agent-host cert deploy (dumb Agent on a cert-target box) ───────────────
    # The le spoke brokers cert material to *spoke* targets through the hub (the
    # existing ledger `targets` flow, untouched). This is the ADDITIONAL path for
    # cert-target boxes that have no spoke module — a dumb device-mode Agent
    # dials this spoke's /ws/agent listener and the spoke drives it to install a
    # cert via WRITE_FILE + RUN_COMMAND (the netbox cert-custodian pattern).

    def _validate_cert_pair(self, fullchain: str, privkey: str):
        """Validate PEM shape + that the cert+key form a usable TLS pair, in
        process (0600 temps) before the material can reach any live host. Same
        guard netbox + the hub use. Returns None on success or an ERROR dict."""
        if not fullchain or not privkey:
            return {"status": "ERROR", "message": "missing cert material"}
        if "BEGIN CERTIFICATE" not in fullchain or "PRIVATE KEY" not in privkey:
            return {"status": "ERROR", "message": "fullchain/privkey not PEM"}
        crt_tmp = key_tmp = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".crt.pem",
                                              delete=False) as cf:
                cf.write(fullchain); crt_tmp = cf.name
            with tempfile.NamedTemporaryFile("w", suffix=".key.pem",
                                              delete=False) as kf:
                kf.write(privkey); key_tmp = kf.name
            os.chmod(crt_tmp, 0o600); os.chmod(key_tmp, 0o600)
            try:
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
                    crt_tmp, key_tmp)
            except Exception as e:  # noqa: BLE001
                return {"status": "ERROR", "message": f"cert validation failed: {e}"}
        finally:
            for p in (crt_tmp, key_tmp):
                if p:
                    try: os.unlink(p)
                    except OSError: pass
        return None

    async def _deploy_cert_to_agent(self, agent_id, fullchain, privkey, domain):
        """Drive the dumb Agent to install a cert: WRITE_FILE crt + key to 0600
        temps, then RUN_COMMAND the role-provisioned install helper (which places
        the cert + reloads the configured service). The Agent runs; the spoke
        holds the sequence. Mirrors netbox_spoke._deploy_cert_to_agent."""
        cp = self.control_plane
        if cp is None or not hasattr(cp, "send_to_agent"):
            return {"status": "ERROR", "message": "spoke is not an agent host"}
        ts = str(int(time.time() * 1000))
        crt_tmp = f"/tmp/lm-le-{ts}.crt.pem"
        key_tmp = f"/tmp/lm-le-{ts}.key.pem"
        try:
            await cp.send_to_agent("WRITE_FILE",
                                   {"path": crt_tmp, "content": fullchain,
                                    "mode": 0o600}, agent_id=agent_id, timeout=20.0)
            await cp.send_to_agent("WRITE_FILE",
                                   {"path": key_tmp, "content": privkey,
                                    "mode": 0o600}, agent_id=agent_id, timeout=20.0)
            cmd = f"sudo -n {_LE_INSTALL_CERT_HELPER} {domain} {crt_tmp} {key_tmp}"
            res = await cp.send_to_agent("RUN_COMMAND",
                                         {"command": cmd, "allow_shell": True,
                                          "timeout": 30}, agent_id=agent_id,
                                        timeout=40.0)
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": f"deploy to agent {agent_id}: {e}"}
        finally:
            try:
                await cp.send_to_agent("RUN_COMMAND",
                                       {"command": f"rm -f {crt_tmp} {key_tmp}",
                                        "allow_shell": True, "timeout": 10},
                                       agent_id=agent_id, timeout=15.0)
            except Exception:  # noqa: BLE001 - cleanup best-effort
                pass
        runner = (res or {}).get("result", {}) if isinstance(res, dict) else {}
        out = (runner.get("stdout") or "").strip()
        if runner.get("rc") == 0 and out.startswith("OK"):
            logger.info("[cert] %s → le agent %s: installed — %s",
                        domain, agent_id, out[2:].strip() or out)
            return {"status": "SUCCESS",
                     "message": out[2:].strip() or "installed on agent"}
        msg = (runner.get("stderr") or out or (res or {}).get("message")
               or "cert helper failed on agent")
        logger.warning("[cert] %s → le agent %s: FAILED — %s",
                       domain, agent_id, msg)
        return {"status": "ERROR", "message": msg}

    async def deploy_cert_to_agent(self, domain, fullchain, privkey, agent_id):
        """Validate a cert pair and deploy it to one connected Agent (explicit
        operator trigger via LE_DEPLOY_TO_AGENT). Reads no ledger state — the
        caller picks the cert + the agent. Returns the install result."""
        err = self._validate_cert_pair(fullchain, privkey)
        if err:
            return err
        return await self._deploy_cert_to_agent(agent_id, fullchain, privkey,
                                                 domain)

    async def _agent_hostname(self, agent_id):
        """Resolve a connected Agent's hostname (for the ledger target match).
        Falls back to agent_id when the rec is gone or the spoke isn't an agent
        host (tests / standalone)."""
        cp = self.control_plane
        rec = getattr(cp, "connected_agents", {}).get(agent_id) if cp else None
        return (rec or {}).get("hostname") or agent_id

    async def deploy_cached_cert_to_agent(self, agent_id):
        """Auto-deploy on Agent connect: for each managed cert whose ledger has
        an ``agent`` target matching this Agent's hostname (identifier == "" means
        any Agent), read the cert material from disk and deploy it. Best-effort —
        a failed deploy for one cert doesn't block the others. Called from
        LEControlPlane._on_agent_registered (mirrors netbox's custodian push)."""
        cp = self.control_plane
        if cp is None or not getattr(cp, "connected_agents", {}).get(agent_id):
            return  # agent gone / not an agent host — nothing to push
        hostname = await self._agent_hostname(agent_id)
        deployed = 0
        for domain, entry in list(self._certs.get("certs", {}).items()):
            for t in entry.get("targets", []):
                if t.get("module_type") != "agent":
                    continue
                ident = (t.get("identifier") or "").strip()
                if ident and ident != hostname:
                    continue  # target is for a different host
                mat = read_material(domain)
                if mat.get("status") != "SUCCESS":
                    logger.warning("[cert] skip auto-deploy %s → agent %s: "
                                   "material unreadable", domain, agent_id)
                    break
                logger.info("[cert] auto-deploy %s → le agent %s (host %s)",
                            domain, agent_id, hostname)
                res = await self._deploy_cert_to_agent(
                    agent_id, mat.get("fullchain", ""), mat.get("privkey", ""),
                    domain)
                # Record the push in the ledger (same shape as LE_MARK_DISTRIBUTED).
                t["last_pushed_hash"] = mat.get("material_hash")
                t["last_pushed_at"] = _now_iso()
                t["last_status"] = res.get("status")
                t["last_message"] = res.get("message") or res.get("data", {}).get("message")
                if res.get("status") == "SUCCESS":
                    deployed += 1
                break  # one agent target per cert is enough; don't double-deploy
        if deployed:
            self._persist()
            logger.info("[cert] auto-deploy to agent %s: %d cert(s) installed",
                        agent_id, deployed)

    async def _deploy_to_agent_command(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """LE_DEPLOY_TO_AGENT: deploy a managed cert's current material to a
        connected Agent now. ``domain`` required; ``agent_id`` optional (defaults
        to the first connected Agent). Reads material from disk so a renewed cert
        is current. Records the agent as an ``agent`` ledger target + marks the
        push (so the auto-deploy-on-connect path is idempotent for this host)."""
        domain = data.get("domain")
        if not domain:
            return {"status": "ERROR", "message": "LE_DEPLOY_TO_AGENT requires 'domain'"}
        mat = read_material(domain)
        if mat.get("status") != "SUCCESS":
            return mat  # {status:ERROR, message}
        fullchain, privkey = mat.get("fullchain", ""), mat.get("privkey", "")
        err = self._validate_cert_pair(fullchain, privkey)
        if err:
            return err
        cp = self.control_plane
        agent_id = data.get("agent_id")
        if agent_id:
            if not getattr(cp, "connected_agents", {}).get(agent_id):
                return {"status": "ERROR",
                        "message": f"Agent '{agent_id}' not connected"}
        else:
            if not getattr(cp, "connected_agents", {}):
                return {"status": "ERROR",
                        "message": "no le agent connected — start one and retry"}
            agent_id = next(iter(cp.connected_agents))
        res = await self._deploy_cert_to_agent(agent_id, fullchain, privkey, domain)
        # Record the agent as a ledger target so auto-deploy-on-connect is
        # idempotent + the UI reflects the push (mirrors LE_MARK_DISTRIBUTED).
        hostname = await self._agent_hostname(agent_id)
        t = Ledger.add_target(self._certs, domain, "agent", hostname)
        if t is not None:
            t["last_pushed_hash"] = mat.get("material_hash")
            t["last_pushed_at"] = _now_iso()
            t["last_status"] = res.get("status")
            t["last_message"] = res.get("message")
            self._persist()
        return {"status": res.get("status", "ERROR"),
                "data": {"domain": domain, "agent_id": agent_id,
                         "hostname": hostname,
                         "message": res.get("message", "")}}