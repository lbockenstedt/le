"""Per-tenant multi-provider DNS-01 credential store for the le spoke.

MULTI-TENANT: each tenant keeps its OWN set of named DNS credentials (its own
HE / Cloudflare / rfc2136 / route53 accounts). Credentials are stored one file
per tenant, 0600, under ``/etc/lm-le/dns-credentials/<tenant>.json`` (override
the dir with ``LM_LE_DNS_CREDS_DIR``). Every function takes ``tenant_id``; the
hub routes derive it from the authenticated session (never client-supplied) so
one tenant can't read another's creds.

Each stored credential is ``{name, provider, fields}`` for one provider
(he-login / cloudflare / rfc2136 / route53). A managed cert references a
credential BY NAME; ``materialize()`` turns it into the kwargs ``acme.issue()``
needs. Secrets are never returned by ``list_public()`` (only a per-secret
"is set" flag) and never logged. ``upsert()`` sentinel-merges secrets, so a
partial edit doesn't wipe them.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("le.dns_credentials")

_DIR = os.getenv("LM_LE_DNS_CREDS_DIR", "/etc/lm-le/dns-credentials")

# Supported providers + their field contracts. ``secret`` fields are withheld
# from list_public() and sentinel-merged on upsert; ``optional`` may be omitted.
PROVIDERS = ("he-login", "cloudflare", "rfc2136", "route53")
PROVIDER_FIELDS: Dict[str, Dict[str, List[str]]] = {
    "he-login":   {"required": ["username", "password"], "secret": ["password"]},
    "cloudflare": {"required": ["api_token"], "secret": ["api_token"]},
    "rfc2136":    {"required": ["server", "name", "secret"], "secret": ["secret"],
                   "optional": ["algorithm"]},
    "route53":    {"required": ["access_key_id", "secret_access_key"],
                   "secret": ["secret_access_key"]},
}


def _safe_tenant(tenant_id: str) -> str:
    """Sanitise a tenant id into a filename component — defends the store dir
    against path traversal from an unexpected id. Empty → 'default'."""
    t = re.sub(r"[^A-Za-z0-9._-]", "_", str(tenant_id or "").strip())
    return t or "default"


def _store_path(tenant_id: str) -> str:
    return os.path.join(_DIR, f"{_safe_tenant(tenant_id)}.json")


def _load(tenant_id: str) -> List[Dict[str, Any]]:
    try:
        with open(_store_path(tenant_id), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []
    except Exception as exc:  # noqa: BLE001 — corrupt store → start empty, don't crash
        logger.warning("dns_credentials: could not read %s: %s", _store_path(tenant_id), exc)
        return []


def _save(tenant_id: str, creds: List[Dict[str, Any]]) -> None:
    os.makedirs(_DIR, exist_ok=True)
    try:
        os.chmod(_DIR, 0o700)
    except OSError:
        pass
    path = _store_path(tenant_id)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(creds, f, indent=2)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def _secret_fields(provider: str) -> set:
    return set(PROVIDER_FIELDS.get(provider, {}).get("secret", []))


def list_public(tenant_id: str) -> List[Dict[str, Any]]:
    """This tenant's credentials WITHOUT secret values — safe for the browser.
    Each: {name, provider, fields (non-secret), secrets_set {field: bool}}."""
    out: List[Dict[str, Any]] = []
    for c in _load(tenant_id):
        prov = c.get("provider")
        secret = _secret_fields(prov)
        fields = c.get("fields") or {}
        out.append({
            "name": c.get("name"),
            "provider": prov,
            "fields": {k: v for k, v in fields.items() if k not in secret},
            "secrets_set": {k: bool(fields.get(k)) for k in secret},
        })
    return sorted(out, key=lambda e: (e.get("provider") or "", e.get("name") or ""))


def get(tenant_id: str, name: str) -> Optional[Dict[str, Any]]:
    for c in _load(tenant_id):
        if c.get("name") == name:
            return c
    return None


def upsert(tenant_id: str, name: str, provider: str, fields: Dict[str, Any]) -> None:
    """Add or update one of this tenant's named credentials. Sentinel-merge:
    empty/absent secret fields KEEP the stored value."""
    name = (name or "").strip()
    if not name:
        raise ValueError("credential name is required")
    if provider not in PROVIDERS:
        raise ValueError(f"unknown provider {provider!r} (expected one of {', '.join(PROVIDERS)})")
    creds = _load(tenant_id)
    existing = next((c for c in creds if c.get("name") == name), None)
    secret = _secret_fields(provider)
    same_provider = bool(existing and existing.get("provider") == provider)
    merged = dict((existing or {}).get("fields") or {}) if same_provider else {}
    for k, v in (fields or {}).items():
        if k in secret and v in (None, ""):
            continue  # keep the stored secret
        merged[k] = v
    missing = [f for f in PROVIDER_FIELDS[provider]["required"] if not merged.get(f)]
    if missing:
        raise ValueError(f"{provider} credential missing required field(s): {', '.join(missing)}")
    entry = {"name": name, "provider": provider, "fields": merged}
    creds = [c for c in creds if c.get("name") != name]
    creds.append(entry)
    _save(tenant_id, creds)


def delete(tenant_id: str, name: str) -> bool:
    creds = _load(tenant_id)
    kept = [c for c in creds if c.get("name") != name]
    if len(kept) == len(creds):
        return False
    _save(tenant_id, kept)
    return True


def materialize(tenant_id: str, name: str) -> Dict[str, Any]:
    """Turn one of this tenant's stored credentials into ``acme.issue()`` kwargs:
      he-login  → {dns_provider, he_username, he_password}
      cloudflare→ {dns_provider, dns_creds (INI text)}
      rfc2136   → {dns_provider, dns_creds (INI text)}
      route53   → {dns_provider, route53_env {AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY}}
    Raises KeyError if the name is unknown for this tenant."""
    c = get(tenant_id, name)
    if not c:
        raise KeyError(f"no DNS credential named {name!r} for tenant {tenant_id!r}")
    prov = c.get("provider")
    f = c.get("fields") or {}
    if prov == "he-login":
        return {"dns_provider": "he-login",
                "he_username": f.get("username"), "he_password": f.get("password")}
    if prov == "cloudflare":
        return {"dns_provider": "cloudflare",
                "dns_creds": f"dns_cloudflare_api_token = {f.get('api_token', '')}\n"}
    if prov == "rfc2136":
        algo = f.get("algorithm") or "HMAC-SHA512"
        ini = (f"dns_rfc2136_server = {f.get('server', '')}\n"
               f"dns_rfc2136_name = {f.get('name', '')}\n"
               f"dns_rfc2136_secret = {f.get('secret', '')}\n"
               f"dns_rfc2136_algorithm = {algo}\n")
        return {"dns_provider": "rfc2136", "dns_creds": ini}
    if prov == "route53":
        return {"dns_provider": "route53", "route53_env": {
            "AWS_ACCESS_KEY_ID": f.get("access_key_id", ""),
            "AWS_SECRET_ACCESS_KEY": f.get("secret_access_key", ""),
        }}
    raise ValueError(f"unknown provider {prov!r}")
