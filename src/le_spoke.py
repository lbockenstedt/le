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
# Standard library: event loop, logging, files, regex, TLS, temp files and time.
import asyncio
import logging
import os
import re
import ssl
import tempfile
import time
from datetime import datetime, timezone
# Type hints only.
from typing import Any, Dict, List, Optional

# certbot operations and cert-material helpers from the sibling acme module.
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
# The on-disk cert ledger and the per-tenant DNS credential store.
from ledger import Ledger  # type: ignore[import-not-found]
import dns_credentials  # type: ignore[import-not-found]  # per-tenant DNS-01 credential store

# BaseSpoke lives in the lm core (on PYTHONPATH in production). A standalone
# fallback keeps the spoke + its tests importable without the lm core checkout.
try:
    from core.src.base_spoke import BaseSpoke
except ImportError:
    class BaseSpoke:  # type: ignore[no-redef]
        """Minimal stand-in for BaseSpoke when the lm core is not importable."""
        def __init__(self, spoke_id: str, config: Dict[str, Any]):
            """Remember the spoke id and config."""
            self.spoke_id = spoke_id
            self.config = config

        def log_info(self, message):
            """No-op info logger."""
            pass

        def log_error(self, message):
            """No-op error logger."""
            pass

# One named logger for the spoke.
logger = logging.getLogger("LESpoke")

# Ledger location and renewal loop timing.
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
# Domain names may only contain letters, digits, dots and dashes.
_LE_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def _read_version() -> str:
    """Read the spoke's semantic version from VERSION file."""
    try:
        # VERSION lives one level above this file's directory.
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(os.path.dirname(here), "VERSION"), "r") as f:
            return f.read().strip()
    # Missing or unreadable: unknown.
    except Exception:
        return "unknown"


def _now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    # Timezone-aware current time in UTC.
    return datetime.now(timezone.utc).isoformat()


class LESpoke(BaseSpoke):
    """Let's Encrypt / certificate-management spoke."""

    def __init__(self, spoke_id: str, config: Dict[str, Any],
                 control_plane: Any = None):
        """Load the ledger, then start the background renewal loop."""
        # Set BEFORE super().__init__: background workers the base may start in
        # run() can read these (opnsense ordering rule).
        self._renew_task: Optional[asyncio.Task] = None
        # Reference to the LEControlPlane so the renewal loop can emit
        # LE_CERT_RENEWED to the hub (event-driven distribution) via send_to_hub.
        # None when constructed standalone (tests) — the hourly hub loop is the
        # fallback, so a missing control_plane just skips the notify.
        self.control_plane = control_plane
        # Ledger path from config, the environment, or a per-spoke default.
        ledger_path = config.get("ledger_path") or os.getenv(
            "LM_LE_LEDGER", os.path.join(_DEFAULT_LEDGER_DIR, spoke_id, "certs.json"))
        # Load the ledger and the renewal interval.
        self.ledger = Ledger(ledger_path)
        self._certs: Dict[str, Dict[str, Any]] = self.ledger.load()
        self._renew_interval = int(config.get("renew_interval",
                                              _RENEW_INTERVAL_DEFAULT))

        # Base setup, then start renewals and log the startup summary.
        super().__init__(spoke_id, config)
        self._start_renew_loop()
        logger.info("LESpoke initialized [%s] v%s BUILD-MARKER-DNSCRED "
                    "(LE_SET_DNS_CRED/LE_LIST_DNS_CREDS handlers active) — %d managed cert(s)",
                    spoke_id, _read_version(), len(self._certs.get("certs", {})))

    # ── renewal loop (opnsense __init__-create_task pattern) ──────────────────

    def _start_renew_loop(self):
        """Schedule or reschedule the asynchronous daily certificate renewal loop."""
        # Cancel any loop that is still running.
        if self._renew_task and not self._renew_task.done():
            self._renew_task.cancel()
        # A running event loop is needed to schedule the task.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop yet (construction outside asyncio.run). Don't
            # build the coroutine — an un-awaited coroutine would warn.
            logger.warning("Event loop not running; renewal loop deferred.")
            return
        # Schedule the renewal loop.
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
        # Repeat: refresh certbot, reconcile and renew, then sleep.
        while True:
            try:
                # Keep certbot current each cycle (venv pip -U / snap / apt).
                try:
                    import certbot_update  # type: ignore[import-not-found]
                    await certbot_update.refresh()
                except Exception as e:  # noqa: BLE001
                    logger.debug("certbot refresh skipped: %s", e)
                await self._reconcile_and_renew()
            # Task cancelled: stop the loop.
            except asyncio.CancelledError:
                break
            # Any other error: log it and retry after a short back-off.
            except Exception as e:
                logger.error("renewal loop error: %s", e)
                await asyncio.sleep(_RENEW_BACKOFF)
                continue
            # Wait until the next cycle.
            await asyncio.sleep(self._renew_interval)

    async def _reconcile_and_renew(self):
        """Sync each managed cert with its files on disk and renew those near expiry."""
        # Operate on self._certs IN PLACE — the SAME dict the command handlers
        # mutate. The old code loaded a separate ``state`` snapshot, awaited the
        # long acme_renew, then reassigned ``self._certs = state``, silently
        # clobbering any LE_ADD_TARGET / LE_MARK_DISTRIBUTED a handler applied
        # during the await (lost update). Iterating a list() snapshot means a
        # concurrent add/remove doesn't break the loop.
        # Track whether the ledger needs saving.
        certs = self._certs.setdefault("certs", {})
        changed = False
        for domain, entry in list(certs.items()):
            # Refresh not_after + material_hash from disk (certbot may have
            # renewed out-of-band, or the ledger is stale post-restart). Only mark
            # changed on an ACTUAL diff so we don't rewrite the ledger every tick.
            mat = read_material(domain)
            # Material changed on disk: update the ledger.
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
            # Renew certs that are close to expiry.
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
                # Skip the cert if a handler removed it while the renewal ran.
                if domain not in certs:
                    continue  # a handler removed this cert during the renew await
                # Success: record the renewal time and refresh the material details.
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
                # Failure: record the error.
                else:
                    entry["last_error"] = res.get("message")
                    logger.error("renew failed for %s: %s", domain,
                                 res.get("message"))
                    changed = True
                    # Event-driven alert: tell the hub now so a renewal failure
                    # surfaces as a realtime cert alert (vs. the hourly pull).
                    await self._notify_renew_failed(domain, res.get("message"))
        # Save the ledger only if something changed.
        if changed:
            self.ledger.save(self._certs)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _persist(self):
        """Persist current certificate ledger state to disk."""
        # Write the ledger to disk.
        self.ledger.save(self._certs)

    def _write_he_from_payload(self, creds: Dict[str, Any]) -> bool:
        """(Re)write he-login.ini from a resolved HE account-login payload.
        Returns True on write. The secret is never logged or stored in ledger/
        config — only the 0600 hook file certbot's he_dns.py reads."""
        # Need a dict with both a username and a password.
        if not isinstance(creds, dict):
            return False
        u = (creds.get("he_username") or "").strip()
        p = creds.get("he_password") or ""
        if not (u and p):
            return False
        # Write the 0600 credentials file for the HE hook.
        try:
            write_he_creds(u, p)
            return True
        except Exception as e:  # noqa: BLE001 — never break renew on a write hiccup
            logger.warning("write he-login.ini from vault sync failed: %s", e)
            return False

    def _apply_renew_vault_creds(self, domain: str, data: Dict[str, Any]) -> None:
        """Before renewing ``domain``, apply any per-domain vault DNS creds the
        hub injected into the renew request (``vault_dns_creds`` map)."""
        # Look for a vault credentials map in the request.
        vmap = data.get("vault_dns_creds")
        if not isinstance(vmap, dict):
            return
        # Apply this domain's credentials, if any.
        vc = vmap.get(domain)
        if isinstance(vc, dict):
            self._write_he_from_payload(vc)

    def _sync_vault_dns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle LE_SYNC_VAULT_DNS: (re)write DNS-01 hook creds the hub resolved
        from the Credential Vault. Currently supports HE account-login
        (``he_username``/``he_password``), the durable source for HE DNS-01
        renewals across spoke reinstalls. Idempotent + best-effort."""
        # Write the HE login file if the payload contains one.
        wrote_he = self._write_he_from_payload(data or {})
        return {"status": "SUCCESS", "data": {"wrote_he_login": wrote_he}}

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
        # Find the domain's ledger entry, creating a minimal one for a new domain.
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
        # Record staging, the attempt time and the error (cleared on success), then save.
        entry["staging"] = bool(staging)
        entry["last_issue_at"] = _now_iso()
        entry["last_issue_error"] = None if success else (message or "issue failed")
        self._persist()

    def _public_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Ledger entry minus nothing sensitive (targets carry only push state).
        Ensures required keys exist for the UI/hub."""
        # Copy the entry and make sure the list of targets exists.
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
        e.setdefault("profile", None)        # ACME profile (validity/EKU) — None = CA default
        e.setdefault("dns_vault_credential", None)  # {bucket,name} vault ref (no secret) for UI round-trip
        # Return the copy.
        return e

    async def _notify_renewed(self, domain: str, entry: Dict[str, Any]) -> None:
        """Emit LE_CERT_RENEWED to the hub so it re-distributes the renewed
        cert material immediately (event-driven, vs. waiting up to 1h for the
        hourly poll). Best-effort: skipped when there's no control_plane or the
        spoke isn't connected yet — the hub's hourly loop is the fallback, so a
        missed event never leaves a cert undistributed."""
        # No control plane (e.g. tests): nothing to notify.
        if not self.control_plane:
            return
        # Send the renewal event; failures are only logged.
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
        # No control plane (e.g. tests): nothing to notify.
        if not self.control_plane:
            return
        # Send the failure event; failures are only logged.
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
        # Version, certbot availability and number of managed certs.
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
        # Normalise the command name and payload, then log the command.
        cmd = (command_type or "").upper()
        data = data or {}
        logger.info("Handling LE command: %s", cmd)

        # LE_GET_STATUS: module status.
        if cmd == "LE_GET_STATUS":
            return await self.get_status()

        # LE_LIST_CERTS: every managed cert, made safe for the UI.
        if cmd == "LE_LIST_CERTS":
            certs = [self._public_entry(e)
                     for e in self._certs.get("certs", {}).values()]
            return {"status": "SUCCESS", "data": {
                "certs": certs, "count": len(certs),
                "certbot_present": certbot_present()}}

        # LE_GET_CERT: a domain's PEM material for distribution.
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

        # Issue, profile change, ACME info and renewal are handled by helpers.
        if cmd == "LE_ISSUE_CERT":
            return await self._issue(data)

        if cmd == "LE_SET_CLIENTAUTH":
            return await self._set_clientauth(data)

        if cmd == "LE_ACME_INFO":
            from acme import acme_info as _acme_info  # type: ignore[import-not-found]
            return {"status": "SUCCESS", "data": await _acme_info()}

        if cmd == "LE_RENEW_CERT":
            return await self._renew(data)

        if cmd == "LE_SYNC_VAULT_DNS":
            # Hub push of freshly vault-resolved DNS-01 creds (e.g. on spoke
            # (re)connect) so certbot's he_dns hook has he-login.ini even after a
            # spoke reinstall wiped it. The SECRET lives only in the Credential
            # Vault; the hub resolves it and pushes it here to (re)write the
            # 0600 hook file. Not persisted in spoke state — only the on-disk
            # he-login.ini (which a reinstall wipes and this restores).
            return self._sync_vault_dns(data)

        # LE_REVOKE_CERT: revoke a certificate.
        if cmd == "LE_REVOKE_CERT":
            return await self._revoke(data)

        # LE_ADD_TARGET: add a distribution target to a managed cert.
        if cmd == "LE_ADD_TARGET":
            domain = data.get("domain")
            if not domain:
                return {"status": "ERROR", "message": "LE_ADD_TARGET requires 'domain'"}
            mt = (data.get("target") or {}).get("module_type") or data.get("module_type")
            if not mt:
                return {"status": "ERROR", "message": "target.module_type required"}
            ident = (data.get("target") or {}).get("identifier") or data.get("identifier") or ""
            # Add the target (no-op if it already exists) and save.
            t = Ledger.add_target(self._certs, domain, mt, ident)
            if t is None:
                return {"status": "ERROR", "message": f"no managed cert for {domain}"}
            self._persist()
            return {"status": "SUCCESS", "data": {"domain": domain, "target": t}}

        # LE_REMOVE_TARGET: remove a target by its position.
        if cmd == "LE_REMOVE_TARGET":
            domain = data.get("domain")
            if not domain:
                return {"status": "ERROR", "message": "LE_REMOVE_TARGET requires 'domain'"}
            idx = data.get("idx")
            if idx is None:
                return {"status": "ERROR", "message": "LE_REMOVE_TARGET requires 'idx'"}
            # Remove the target and save.
            ok = Ledger.remove_target(self._certs, domain, int(idx))
            if not ok:
                return {"status": "ERROR", "message": "target not found"}
            self._persist()
            return {"status": "SUCCESS", "data": {"domain": domain, "removed": True}}

        # LE_MARK_DISTRIBUTED: the hub's acknowledgement of a push.
        if cmd == "LE_MARK_DISTRIBUTED":
            return self._mark_distributed(data)

        # ── Agent-host cert deploy (dumb Agent on a cert-target box) ───────────
        if cmd == "LE_DEPLOY_TO_AGENT":
            return await self._deploy_to_agent_command(data)

        # ── Per-tenant multi-provider DNS-01 credential store ──────────────────
        # LE_LIST_DNS_CREDS: the tenant's credentials (no secrets) and provider field rules.
        if cmd == "LE_LIST_DNS_CREDS":
            tid = data.get("tenant_id") or "default"
            return {"status": "SUCCESS", "credentials": dns_credentials.list_public(tid),
                    "providers": list(dns_credentials.PROVIDERS),
                    "provider_fields": dns_credentials.PROVIDER_FIELDS}

        # LE_SET_DNS_CRED: add or update a tenant credential.
        if cmd == "LE_SET_DNS_CRED":
            tid = data.get("tenant_id") or "default"
            try:
                dns_credentials.upsert(tid, data.get("name") or "",
                                       data.get("provider") or "",
                                       data.get("fields") or {})
            # Validation error: report its message.
            except ValueError as e:
                return {"status": "ERROR", "message": str(e)}
            # Any other failure while saving.
            except Exception as e:  # noqa: BLE001
                return {"status": "ERROR", "message": f"failed to store credential: {e}"}
            return {"status": "SUCCESS", "message": "DNS credential saved"}

        # LE_DELETE_DNS_CRED: delete a tenant credential.
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
            # Both values are required.
            if not he_u or not he_p:
                return {"status": "ERROR",
                        "message": "he_username and he_password are required"}
            # Keep them in config and write the hook's credentials file.
            self.config["he_username"] = he_u
            self.config["he_password"] = he_p
            try:
                write_he_creds(he_u, he_p)
            # The file could not be written.
            except Exception as e:  # noqa: BLE001
                return {"status": "ERROR", "message": f"failed to store HE creds: {e}"}
            return {"status": "SUCCESS", "message": "Hurricane Electric login stored"}

        # LE_GET_HE_LOGIN: configured if a username is set or the creds file exists.
        if cmd == "LE_GET_HE_LOGIN":
            # Report configuration status WITHOUT returning the password.
            u = self.config.get("he_username") or ""
            import os as _os
            configured = bool(u) or _os.path.exists(
                _os.getenv("LM_LE_HE_CREDS", "/etc/lm-le/he-login.ini"))
            return {"status": "SUCCESS", "configured": configured, "he_username": u}

        # UPDATE_CONFIG: replace the config, restarting the loop if the interval changed.
        if cmd == "UPDATE_CONFIG":
            self.config = data
            if "renew_interval" in data:
                try:
                    self._renew_interval = int(data["renew_interval"])
                    self._start_renew_loop()
                # Invalid interval: keep the current one.
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

        # GET_VERSION: report the spoke version.
        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": _read_version()}

        # SET_LOG_LEVEL: find the shared logging helper, then switch debug logging on or off.
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

        # Unknown command.
        return {"status": "ERROR", "message": f"Unknown command: {command_type}"}

    # ── command implementations ───────────────────────────────────────────────

    async def _set_clientauth(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Toggle the clientAuth EKU on an EXISTING managed cert and re-issue now so
        the new ACME profile takes effect. Rebuilds the issue request from the cert's
        stored ledger params (challenge, email, DNS credential, tenant, staging) +
        the new flag, force-renewing. For mTLS CLIENT certs (AppBuilder, the wildcard);
        certs that don't need it stay on the default server-only profile."""
        # The domain must be a managed cert.
        domain = data.get("domain")
        if not domain:
            return {"status": "ERROR", "message": "LE_SET_CLIENTAUTH requires 'domain'"}
        entry = self._certs.get("certs", {}).get(domain)
        if not entry:
            return {"status": "ERROR", "message": f"no managed cert for {domain}"}
        # New clientAuth setting.
        enabled = bool(data.get("client_auth", data.get("enabled", False)))
        # Reuse the cert's stored issue settings with the new flag, forcing re-issue.
        issue_data = {
            "domain": domain,
            "email": entry.get("email") or "",
            "challenge": entry.get("challenge") or "http",
            "dns_provider": entry.get("dns_provider"),
            "dns_credential": entry.get("dns_credential"),
            "dns_vault_credential": entry.get("dns_vault_credential"),
            "tenant_id": entry.get("tenant_id") or "default",
            "staging": bool(entry.get("staging", False)),
            "key_type": entry.get("key_type", "rsa"),
            "renew_window_days": entry.get("renew_window_days"),
            "client_auth": enabled,
            "force_renewal": True,
        }
        # Issue it again.
        return await self._issue(issue_data)

    async def _issue(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Issue a certificate, then record it and its targets in the ledger."""
        # A domain is required.
        domain = data.get("domain")
        if not domain:
            return {"status": "ERROR", "message": "LE_ISSUE_CERT requires 'domain'"}
        # Account email and challenge type (HTTP-01 by default).
        email = data.get("email") or ""
        challenge = data.get("challenge", "http")
        # Named per-tenant DNS credential (multi-tenant store). When the request
        # names one, materialize it for THIS tenant and let it supply the provider
        # + secrets; an explicit per-request dns_provider/creds still wins if given.
        tenant_id = data.get("tenant_id") or "default"
        cred_name = data.get("dns_credential")
        mat: Dict[str, Any] = {}
        # Load the named credential; an unknown name or other error is recorded as failed.
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
        # Run certbot; per-request values win over the named credential and config.
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
                # clientAuth EKU (for mTLS CLIENT certs, e.g. AppBuilder): request the
                # ACME "classic"-style profile. An explicit ``profile`` (e.g. a
                # short-lived one) overrides. force_renewal lets a toggle on an
                # EXISTING cert take effect now instead of waiting for expiry.
                client_auth=bool(data.get("client_auth", False)),
                profile=(data.get("profile") or None),
                force_renewal=bool(data.get("force_renewal", False)),
            )
        # Invalid request (e.g. missing DNS provider): record and report the failure.
        except ValueError as e:
            self._record_issue(domain, tenant_id, False, str(e), challenge, email,
                               bool(data.get("staging", False)))
            logger.error("issue failed for %s: %s", domain, e)
            return {"status": "ERROR", "message": str(e)}
        # certbot failed: record and report the failure.
        if res.get("status") != "SUCCESS":
            self._record_issue(domain, tenant_id, False, res.get("message"),
                               challenge, email, bool(data.get("staging", False)))
            logger.error("issue failed for %s: %s", domain, res.get("message"))
            return res
        # Read the new certificate's material from disk.
        mat = read_material(domain)
        # Per-cert renewal window (days before expiry the loop triggers). Default
        # 7 (acme._RENEW_WINDOW_DAYS); operator can override at issue time. None
        # → expiring() falls back to the module default. Validated to a positive
        # int so a bad value can't disable renewal (None is "use default").
        rwd = data.get("renew_window_days")
        # Invalid values fall back to the default.
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
        # New ledger entry with the issue settings and certificate details.
        entry: Dict[str, Any] = {
            "domain": domain,
            "email": email,
            "challenge": challenge,
            "dns_provider": data.get("dns_provider") or mat.get("dns_provider"),
            "dns_credential": cred_name,
            # Vault DNS-01 credential reference ({bucket,name}) the hub resolved
            # for this issue. Stored so the UI round-trips the selection on edit
            # and so a renew/re-issue keeps using the same vault secret. The
            # SECRET itself is never stored here — only the reference; the hub
            # re-resolves it from the Credential Vault at issue/renew/reconnect.
            "dns_vault_credential": data.get("dns_vault_credential"),
            "tenant_id": tenant_id,
            "staging": bool(data.get("staging", False)),
            "client_auth": bool(data.get("client_auth", False)),
            "profile": (data.get("profile") or None),
            "not_after": mat.get("not_after") if mat.get("status") == "SUCCESS" else None,
            "material_hash": mat.get("material_hash") if mat.get("status") == "SUCCESS" else None,
            "renew_window_days": rwd,
            "targets": [],
            "last_renewed_at": None,
            "last_error": None,
            "last_issue_at": _now_iso(),
            "last_issue_error": None,
        }
        # Replace any existing entry for the domain.
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
        # Save and return the stored details.
        self._persist()
        saved = self._certs["certs"][domain]
        return {"status": "SUCCESS", "data": {
            "domain": domain, "action": "issue",
            "material_hash": saved.get("material_hash"),
            "not_after": saved.get("not_after"),
            "renew_window_days": saved.get("renew_window_days"),
            "targets": saved.get("targets", [])}}

    async def _renew(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Renew one certificate, or every managed cert when no domain is given."""
        domain = data.get("domain")
        # Per-cert "Renew now" forces re-issue regardless of expiry; "Renew all"
        # (no domain) stays soft so it only renews certs actually due.
        force = bool(data.get("force", False))
        # Collect per-domain results; an unknown domain is an error.
        renewed: List[Dict[str, Any]] = []
        domains = [domain] if domain else list(self._certs.get("certs", {}).keys())
        if domain and domain not in self._certs.get("certs", {}):
            return {"status": "ERROR", "message": f"No managed cert for {domain}"}
        # Renew each domain in turn.
        for d in domains:
            # Durable renew: if the hub pushed freshly-vault-resolved DNS creds
            # for this domain, (re)write he-login.ini BEFORE certbot re-runs the
            # he_dns hook — so a renew succeeds even if the spoke's local
            # he-login.ini was lost (e.g. after a spoke reinstall).
            self._apply_renew_vault_creds(d, data)
            res = await acme_renew(d, force=force)
            entry = self._certs.get("certs", {}).get(d)
            # Skip the domain if a handler removed it during the renewal.
            if entry is None:
                continue
            # Success: record the time and refresh the material details.
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
                # Failure: record the error.
                entry["last_error"] = res.get("message")
                renewed.append({"domain": d, "renewed": False,
                                "error": res.get("message"),
                                "targets": entry.get("targets", [])})
                # Event-driven alert for on-demand renewal failure too (mirrors
                # the background loop's _notify_renew_failed).
                await self._notify_renew_failed(d, res.get("message"))
        # Save and return the per-domain results.
        self._persist()
        return {"status": "SUCCESS", "data": {"renewed": renewed,
                                               "count": len(renewed)}}

    async def _revoke(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Revoke a certificate and remove it from the ledger."""
        # A domain is required.
        domain = data.get("domain")
        if not domain:
            return {"status": "ERROR", "message": "LE_REVOKE_CERT requires 'domain'"}
        # Revoke with certbot (deleting the local files by default).
        res = await acme_revoke(domain, delete=bool(data.get("delete", True)))
        # Success: drop the cert from the ledger and save.
        if res.get("status") == "SUCCESS":
            Ledger.remove_cert(self._certs, domain)
            self._persist()
            return {"status": "SUCCESS", "data": {
                "domain": domain, "action": "revoke",
                "deleted": res.get("deleted", bool(data.get("delete", True)))}}
        # certbot failed: pass its error through.
        return res

    def _mark_distributed(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record the hub's acknowledgement that a target received the cert."""
        # Domain and module type are required.
        domain = data.get("domain")
        if not domain:
            return {"status": "ERROR", "message": "LE_MARK_DISTRIBUTED requires 'domain'"}
        mt = data.get("module_type")
        ident = data.get("identifier") or ""
        if not mt:
            return {"status": "ERROR", "message": "module_type required"}
        # The domain must be a managed cert.
        entry = self._certs.get("certs", {}).get(domain)
        if entry is None:
            return {"status": "ERROR", "message": f"no managed cert for {domain}"}
        # Find the matching target and record the push hash, time and result.
        for t in entry.get("targets", []):
            if t.get("module_type") == mt and t.get("identifier", "") == ident:
                t["last_pushed_hash"] = data.get("hash")
                t["last_pushed_at"] = _now_iso()
                t["last_status"] = data.get("status")
                t["last_message"] = data.get("message")
                self._persist()
                return {"status": "SUCCESS", "data": {"domain": domain, "target": t}}
        # No target matched.
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
        # Both PEMs must be present and look like a certificate and a private key.
        if not fullchain or not privkey:
            return {"status": "ERROR", "message": "missing cert material"}
        if "BEGIN CERTIFICATE" not in fullchain or "PRIVATE KEY" not in privkey:
            return {"status": "ERROR", "message": "fullchain/privkey not PEM"}
        # Write both to private temp files so the TLS library can load them.
        crt_tmp = key_tmp = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".crt.pem",
                                              delete=False) as cf:
                cf.write(fullchain); crt_tmp = cf.name
            with tempfile.NamedTemporaryFile("w", suffix=".key.pem",
                                              delete=False) as kf:
                kf.write(privkey); key_tmp = kf.name
            os.chmod(crt_tmp, 0o600); os.chmod(key_tmp, 0o600)
            # Loading them into a TLS server context proves the cert and key match.
            try:
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
                    crt_tmp, key_tmp)
            except Exception as e:  # noqa: BLE001
                return {"status": "ERROR", "message": f"cert validation failed: {e}"}
        finally:
            # Always delete the temp files.
            for p in (crt_tmp, key_tmp):
                if p:
                    try: os.unlink(p)
                    except OSError: pass
        # Valid pair.
        return None

    async def _deploy_cert_to_agent(self, agent_id, fullchain, privkey, domain):
        """Drive the dumb Agent to install a cert: WRITE_FILE crt + key to 0600
        temps, then RUN_COMMAND the role-provisioned install helper (which places
        the cert + reloads the configured service). The Agent runs; the spoke
        holds the sequence. Mirrors netbox_spoke._deploy_cert_to_agent."""
        # Requires a control plane that can talk to Agents.
        cp = self.control_plane
        if cp is None or not hasattr(cp, "send_to_agent"):
            return {"status": "ERROR", "message": "spoke is not an agent host"}
        # Only allow safe domain characters, since the domain is passed to a command.
        if not isinstance(domain, str) or not _LE_DOMAIN_RE.fullmatch(domain):
            return {"status": "ERROR",
                    "message": "invalid domain: expected letters, digits, dots, and hyphens only"}

        # Unique temp paths on the Agent for the cert and key.
        ts = str(int(time.time() * 1000))
        crt_tmp = f"/tmp/lm-le-{ts}.crt.pem"
        key_tmp = f"/tmp/lm-le-{ts}.key.pem"
        # Write both files, then run the install helper without a shell.
        try:
            await cp.send_to_agent("WRITE_FILE",
                                   {"path": crt_tmp, "content": fullchain,
                                    "mode": 0o600}, agent_id=agent_id, timeout=20.0)
            await cp.send_to_agent("WRITE_FILE",
                                   {"path": key_tmp, "content": privkey,
                                    "mode": 0o600}, agent_id=agent_id, timeout=20.0)
            cmd = ["sudo", "-n", _LE_INSTALL_CERT_HELPER, domain, crt_tmp, key_tmp]
            res = await cp.send_to_agent("RUN_COMMAND",
                                         {"command": cmd, "allow_shell": False,
                                          "timeout": 30}, agent_id=agent_id,
                                        timeout=40.0)
        # Any transport error fails the deploy.
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": f"deploy to agent {agent_id}: {e}"}
        # Always ask the Agent to remove the temp files.
        finally:
            try:
                await cp.send_to_agent("RUN_COMMAND",
                                       {"command": ["rm", "-f", crt_tmp, key_tmp],
                                        "allow_shell": False, "timeout": 10},
                                       agent_id=agent_id, timeout=15.0)
            except Exception:  # noqa: BLE001 - cleanup best-effort
                pass
        # Success means exit code 0 with output starting "OK".
        runner = (res or {}).get("result", {}) if isinstance(res, dict) else {}
        out = (runner.get("stdout") or "").strip()
        if runner.get("rc") == 0 and out.startswith("OK"):
            logger.info("[cert] %s → le agent %s: installed — %s",
                        domain, agent_id, out[2:].strip() or out)
            return {"status": "SUCCESS",
                     "message": out[2:].strip() or "installed on agent"}
        # Otherwise report the best available error message.
        msg = (runner.get("stderr") or out or (res or {}).get("message")
               or "cert helper failed on agent")
        logger.warning("[cert] %s → le agent %s: FAILED — %s",
                       domain, agent_id, msg)
        return {"status": "ERROR", "message": msg}

    async def deploy_cert_to_agent(self, domain, fullchain, privkey, agent_id):
        """Validate a cert pair and deploy it to one connected Agent (explicit
        operator trigger via LE_DEPLOY_TO_AGENT). Reads no ledger state — the
        caller picks the cert + the agent. Returns the install result."""
        # Reject an invalid pair before it reaches the host.
        err = self._validate_cert_pair(fullchain, privkey)
        if err:
            return err
        # Install it on the Agent.
        return await self._deploy_cert_to_agent(agent_id, fullchain, privkey,
                                                 domain)

    async def _agent_hostname(self, agent_id):
        """Resolve a connected Agent's hostname (for the ledger target match).
        Falls back to agent_id when the rec is gone or the spoke isn't an agent
        host (tests / standalone)."""
        # Use the connected Agent's recorded hostname, or its id.
        cp = self.control_plane
        rec = getattr(cp, "connected_agents", {}).get(agent_id) if cp else None
        return (rec or {}).get("hostname") or agent_id

    async def deploy_cached_cert_to_agent(self, agent_id):
        """Auto-deploy on Agent connect: for each managed cert whose ledger has
        an ``agent`` target matching this Agent's hostname (identifier == "" means
        any Agent), read the cert material from disk and deploy it. Best-effort —
        a failed deploy for one cert doesn't block the others. Called from
        LEControlPlane._on_agent_registered (mirrors netbox's custodian push)."""
        # Nothing to do if the Agent has gone or this spoke does not host Agents.
        cp = self.control_plane
        if cp is None or not getattr(cp, "connected_agents", {}).get(agent_id):
            return  # agent gone / not an agent host — nothing to push
        # Match this Agent's hostname against each cert's agent targets.
        hostname = await self._agent_hostname(agent_id)
        deployed = 0
        for domain, entry in list(self._certs.get("certs", {}).items()):
            # Only agent targets are deployed here.
            for t in entry.get("targets", []):
                if t.get("module_type") != "agent":
                    continue
                # A blank identifier matches any Agent.
                ident = (t.get("identifier") or "").strip()
                if ident and ident != hostname:
                    continue  # target is for a different host
                # Read the current material from disk.
                mat = read_material(domain)
                if mat.get("status") != "SUCCESS":
                    logger.warning("[cert] skip auto-deploy %s → agent %s: "
                                   "material unreadable", domain, agent_id)
                    break
                # Deploy it.
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
        # Save the ledger if anything was deployed.
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
        # A domain is required.
        domain = data.get("domain")
        if not domain:
            return {"status": "ERROR", "message": "LE_DEPLOY_TO_AGENT requires 'domain'"}
        # Read the current material and validate the pair.
        mat = read_material(domain)
        if mat.get("status") != "SUCCESS":
            return mat  # {status:ERROR, message}
        fullchain, privkey = mat.get("fullchain", ""), mat.get("privkey", "")
        err = self._validate_cert_pair(fullchain, privkey)
        if err:
            return err
        # Use the requested Agent, or the first connected one.
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
        # Deploy the cert.
        res = await self._deploy_cert_to_agent(agent_id, fullchain, privkey, domain)
        # Record the agent as a ledger target so auto-deploy-on-connect is
        # idempotent + the UI reflects the push (mirrors LE_MARK_DISTRIBUTED).
        hostname = await self._agent_hostname(agent_id)
        t = Ledger.add_target(self._certs, domain, "agent", hostname)
        # Record the push result on the target and save.
        if t is not None:
            t["last_pushed_hash"] = mat.get("material_hash")
            t["last_pushed_at"] = _now_iso()
            t["last_status"] = res.get("status")
            t["last_message"] = res.get("message")
            self._persist()
        # Return the result with the Agent details.
        return {"status": res.get("status", "ERROR"),
                "data": {"domain": domain, "agent_id": agent_id,
                         "hostname": hostname,
                         "message": res.get("message", "")}}