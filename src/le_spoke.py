"""Certificate Management spoke (le) for Lab Manager.

Translates hub ``LE_*`` commands into certificate-lifecycle actions. This first
release ships **structured stubs**: the dispatch and the SUCCESS/ERROR contract
are real, but the certbot/acme.sh integration is not yet wired — each handler
returns a placeholder body plus a ``certbot_present`` probe so the hub/UI can
report "not yet wired" cleanly. The seams for the real implementation are the
``LE_*`` branches in ``handle_command`` below.

Command contract (mirrors every LM spoke):
    {"status": "SUCCESS", ...} | {"status": "ERROR", "message": "..."}
"""
import os
import shutil
import logging
from typing import Dict, Any

# BaseSpoke lives in the lm core (on PYTHONPATH in production). A standalone
# fallback keeps the spoke + its tests importable without the lm core checkout
# present (dev/tests); the fallback provides the minimal surface LESpoke uses.
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


def _read_version() -> str:
    """Read VERSION from the repo root (parent of this src/ dir)."""
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        version_path = os.path.join(os.path.dirname(here), "VERSION")
        with open(version_path, "r") as f:
            return f.read().strip()
    except Exception:
        return "unknown"


_NOT_WIRED = "certbot/acme.sh integration not yet wired"


class LESpoke(BaseSpoke):
    """Let's Encrypt / certificate-management spoke."""

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)
        # In-memory cert ledger for the stub. The real implementation will read
        # this from certbot's /etc/letsencrypt/live state.
        self._certs: Dict[str, Dict[str, Any]] = {}
        logger.info(f"LESpoke initialized [{spoke_id}]")

    # --- helpers -----------------------------------------------------------

    def _certbot_present(self) -> bool:
        return bool(shutil.which("certbot"))

    def _stub_success(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Stamp every stub payload with certbot_present + the not-wired note."""
        out = dict(data)
        out["certbot_present"] = self._certbot_present()
        out["message"] = out.get("message", _NOT_WIRED)
        return {"status": "SUCCESS", "data": out}

    # --- BaseSpoke contract ------------------------------------------------

    async def get_status(self) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "data": {
                "module": "le",
                "module_type": "certificates",
                "version": _read_version(),
                "certbot_present": self._certbot_present(),
                "certs_managed": len(self._certs),
            },
        }

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        cmd = (command_type or "").upper()
        data = data or {}
        logger.info(f"Handling LE command: {cmd}")

        if cmd == "LE_GET_STATUS":
            return await self.get_status()

        if cmd == "LE_LIST_CERTS":
            return self._stub_success({
                "certs": list(self._certs.values()),
                "count": len(self._certs),
            })

        if cmd == "LE_ISSUE_CERT":
            domain = data.get("domain")
            if not domain:
                return {"status": "ERROR", "message": "LE_ISSUE_CERT requires 'domain'"}
            email = data.get("email")
            challenge = data.get("challenge", "http-01")
            staging = bool(data.get("staging", False))
            # Stub: record the intent in the ledger; real impl shells out to
            # certbot certonly --domain <domain> --email <email> [-m] ...
            self._certs[domain] = {
                "domain": domain,
                "email": email,
                "challenge": challenge,
                "staging": staging,
                "state": "requested",
            }
            return self._stub_success({
                "domain": domain,
                "action": "issue",
                "challenge": challenge,
                "staging": staging,
            })

        if cmd == "LE_RENEW_CERT":
            domain = data.get("domain")
            if domain and domain not in self._certs:
                return {"status": "ERROR", "message": f"No managed cert for {domain}"}
            return self._stub_success({
                "domain": domain or "all",
                "action": "renew",
            })

        if cmd == "LE_REVOKE_CERT":
            domain = data.get("domain")
            if not domain:
                return {"status": "ERROR", "message": "LE_REVOKE_CERT requires 'domain'"}
            self._certs.pop(domain, None)
            return self._stub_success({
                "domain": domain,
                "action": "revoke",
            })

        if cmd == "UPDATE_CONFIG":
            self.config = data
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
            enabled = bool(data.get("enabled", False))
            level = set_log_level(enabled)
            return {"status": "SUCCESS", "message": f"Log level set to {logging.getLevelName(level)}"}

        return {"status": "ERROR", "message": f"Unknown command: {command_type}"}