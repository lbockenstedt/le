# Dependency self-heal — MUST run before the third-party imports below. A skewed
# auto-update / partial install can leave the venv missing a declared dep, which
# would hard-crash at import and crash-loop the unit under Restart=always.
# dep_guard is stdlib-only; it find_spec-checks requirements.txt and pip-installs
# any missing. Best-effort — an unavailable dep_guard is skipped, never fatal.
import os as _os
try:
    try:
        from core.src.dep_guard import ensure_requirements as _ensure_requirements
    except ImportError:
        from dep_guard import ensure_requirements as _ensure_requirements
    _ensure_requirements(_os.path.join(
        _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "requirements.txt"))
except Exception:
    pass

import logging
import argparse
import asyncio
import os
from typing import Dict, Any

# Two-tier import shim (deploy-order safe). In production the lm core is on
# PYTHONPATH (/opt/lm/core/src) so `core.src.messaging.control_plane` resolves;
# the bare `messaging.control_plane` fallback covers running from inside src/.
try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane

try:
    from le_spoke import LESpoke
except ImportError:
    from src.le_spoke import LESpoke

# Consistent logging: try the hub's logging_setup, then core.src, then an
# inline fallback so the spoke still logs at INFO if it boots before the core
# shim is importable (mirrors every other LM entrypoint).
try:
    from logging_setup import configure_logging
except ImportError:
    try:
        from core.src.logging_setup import configure_logging
    except ImportError:
        import logging as _logging
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=_logging.INFO, *, log_file=None, **_):
            handlers = ([_logging.FileHandler(log_file), _logging.StreamHandler()]
                        if log_file else None)
            _logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)

# Log to stderr only — the systemd unit (User=root, because certbot binds :80
# and writes /etc/letsencrypt + /etc/lm-le) captures stderr to
# /var/log/lm/lm-le.log via StandardOutput/StandardError=append:, and the
# systemd manager opens that file as root before the service starts.
# configure_logging() with no log_file attaches only the stderr StreamHandler.
configure_logging()
logger = logging.getLogger("LEControlPlane")


class LEControlPlane(BaseControlPlane):
    """Control plane for the Certificate Management (le) module.

    Inherits core connectivity/auth/routing from BaseControlPlane and registers
    a LESpoke under the module key "le". Advertises module_type "certificates"
    so the hub routes it into the Certificate Management nav + /api/le/* routes.
    """

    def get_service_name(self) -> str:
        return "lm-le"

    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None,
                 hub_url: str = None, config: Dict[str, Any] = None):
        # Set attributes before super().__init__ so background workers the base
        # class may start can see them.
        self.config = config or {}
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        self.module_type = "certificates"

    async def run_hub_mode(self):
        """Native LM spoke behavior: register the le spoke and run the loop."""
        logger.info(f"Starting Certificate Management (le) module -> {self.hub_url}")
        # Pass self so LESpoke can emit unsolicited LE_CERT_RENEWED events to the
        # hub via send_to_hub (event-driven distribution instead of hourly poll).
        le_spoke = LESpoke(self.spoke_id, self.config, control_plane=self)
        self.register_module("le", le_spoke)
        await self.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, help="Spoke ID")
    parser.add_argument("--secret", nargs='?', const="lm-secret", default="lm-secret",
                        help="Authentication secret (default: lm-secret)")
    parser.add_argument("--hub-secret", nargs='?', default="", const="",
                        help="Hub authentication secret for mutual auth")
    # --hub is NOT required: omit it (or pass 'auto'/empty) and BaseControlPlane
    # auto-discovers the hub (DNS lm-hub.<suffix> then mDNS) on each connect,
    # same as every other LM spoke. Default to the HUB_URL env (the installer
    # writes HUB_URL=auto to .env + EnvironmentFile) so an empty/unset value
    # becomes the auto-discovery sentinel instead of an argparse crash.
    parser.add_argument("--hub", default=os.getenv("HUB_URL") or "auto",
                        help="Hub WebSocket URL (or 'auto' to discover; default auto)")
    args = parser.parse_args()

    cp = LEControlPlane(args.id, args.secret, args.hub_secret, args.hub)
    try:
        asyncio.run(cp.run_hub_mode())
    except KeyboardInterrupt:
        pass