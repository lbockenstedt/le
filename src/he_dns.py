"""Hurricane Electric (dns.he.net) DNS-01 hook — account login (no TSIG).

certbot ships no Hurricane Electric plugin, so this runs as a certbot
``--manual-auth-hook`` / ``--manual-cleanup-hook``. It logs into the HE web panel
with your ACCOUNT email + password (the same credentials Proxmox/acme.sh's
``dns_he`` use) and sets/removes the ``_acme-challenge.<domain>`` TXT record via
the panel — so you don't need per-record RFC 2136 / TSIG keys or an IP server.

certbot invokes it with the challenge in the environment:
  CERTBOT_DOMAIN     — the domain being validated (record = _acme-challenge.<it>)
  CERTBOT_VALIDATION — the TXT value to publish
Credentials come from the environment (HE_USERNAME / HE_PASSWORD) or, for
renewals (certbot re-runs the hook with no env), from the creds file written by
the le spoke (default /etc/lm-le/he-login.ini, override LM_LE_HE_CREDS).

Usage (certbot calls these): ``he_dns.py auth`` / ``he_dns.py cleanup``.
This scrapes HE's web panel (there is no official API); if HE changes its forms
the parsing here may need updating — mirrors acme.sh's dns_he.sh contract.
"""
import os
import re
import sys
import time

import requests

HE_URL = "https://dns.he.net/"
_CREDS_FILE = os.getenv("LM_LE_HE_CREDS", "/etc/lm-le/he-login.ini")
_UA = {"User-Agent": "lm-le-he/1.0"}


def _load_creds():
    """(username, password) from env first, then the creds file (renewals)."""
    user = os.getenv("HE_USERNAME") or os.getenv("HE_Username")
    pw = os.getenv("HE_PASSWORD") or os.getenv("HE_Password")
    if user and pw:
        return user, pw
    try:
        with open(_CREDS_FILE, "r", encoding="utf-8") as f:
            kv = {}
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                kv[k.strip().upper()] = v.strip()
        return (kv.get("HE_USERNAME") or kv.get("HE_USER"),
                kv.get("HE_PASSWORD") or kv.get("HE_PASS"))
    except OSError:
        return None, None


def _login(session, user, pw):
    """Log into dns.he.net. Raises RuntimeError on failure."""
    session.get(HE_URL, headers=_UA, timeout=30)  # seed cookies
    r = session.post(HE_URL, headers=_UA, timeout=30,
                     data={"email": user, "pass": pw})
    body = r.text or ""
    if "Incorrect" in body or 'name="email"' in body and "pass" in body and "dns_zoneid" not in body:
        raise RuntimeError("HE login failed — check the account email/password")
    return body


def _zones(html):
    """Map {zone_name: zone_id} from HE's home page delete-domain widgets:
    ``... onclick="delete_dom(this);" name="<zone>" value="<id>" ...`` (attr
    order varies, so match name= and value= near each delete_dom)."""
    out = {}
    for m in re.finditer(r"delete_dom\(this\);\"[^>]*", html):
        seg = m.group(0)
        nm = re.search(r'name="([^"]+)"', seg)
        vid = re.search(r'value="(\d+)"', seg)
        if nm and vid:
            out[nm.group(1).strip().lower()] = vid.group(1)
    # Fallback: some layouts put value= before name=.
    if not out:
        for m in re.finditer(r'value="(\d+)"[^>]*name="([^"]+)"[^>]*onclick="delete_dom', html):
            out[m.group(2).strip().lower()] = m.group(1)
    return out


def _zone_for(record, zones):
    """Longest registered zone that is a suffix of the record name."""
    labels = record.split(".")
    for i in range(len(labels)):
        cand = ".".join(labels[i:]).lower()
        if cand in zones:
            return cand, zones[cand]
    return None, None


def _add_txt(session, zone_id, name, value):
    session.post(HE_URL, headers=_UA, timeout=30, data={
        "account": "", "menu": "edit_zone", "Type": "TXT", "Priority": "",
        "Name": name, "Content": value, "TTL": "300",
        "hosted_dns_zoneid": zone_id, "hosted_dns_recordid": "",
        "hosted_dns_editzone": "1", "hosted_dns_editrecord": "Submit",
    })


def _record_ids(session, zone_id, name, value):
    """recordids of the TXT rows matching name (+ value if present)."""
    r = session.get(HE_URL, headers=_UA, timeout=30, params={
        "hosted_dns_zoneid": zone_id, "menu": "edit_zone", "hosted_dns_editzone": "1",
    })
    html = r.text or ""
    ids = []
    # Each editable row carries data-Name / data-Content and its recordid.
    for m in re.finditer(r'hosted_dns_recordid="(\d+)"[^>]*data-name="([^"]*)"[^>]*data-content="([^"]*)"', html, re.I):
        rid, rname, rcontent = m.group(1), m.group(2).strip().lower(), m.group(3).strip('"')
        if rname == name.lower() and (not value or value in rcontent):
            ids.append(rid)
    return ids


def _del_txt(session, zone_id, rid):
    session.post(HE_URL, headers=_UA, timeout=30, data={
        "menu": "edit_zone", "hosted_dns_zoneid": zone_id,
        "hosted_dns_recordid": rid, "hosted_dns_editzone": "1",
        "hosted_dns_delrecord": "1", "hosted_dns_delconfirm": "delete",
    })


def _run(mode):
    domain = os.getenv("CERTBOT_DOMAIN")
    value = os.getenv("CERTBOT_VALIDATION")
    if not domain or not value:
        sys.stderr.write("he_dns: CERTBOT_DOMAIN / CERTBOT_VALIDATION not set\n")
        return 2
    user, pw = _load_creds()
    if not user or not pw:
        sys.stderr.write("he_dns: no HE credentials (HE_USERNAME/HE_PASSWORD or "
                         f"{_CREDS_FILE})\n")
        return 2
    record = f"_acme-challenge.{domain}"
    session = requests.Session()
    try:
        home = _login(session, user, pw)
        zones = _zones(home)
        zname, zid = _zone_for(record, zones)
        if not zid:
            sys.stderr.write(f"he_dns: no HE zone hosts '{record}' (zones: "
                             f"{sorted(zones)})\n")
            return 3
        if mode == "auth":
            _add_txt(session, zid, record, value)
            # let the record propagate on HE's authoritative servers
            time.sleep(15)
        else:  # cleanup — best effort, non-fatal
            for rid in _record_ids(session, zid, record, value):
                _del_txt(session, zid, rid)
        return 0
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"he_dns {mode} failed: {e}\n")
        # cleanup failure must not fail the run (stale TXT is harmless)
        return 0 if mode == "cleanup" else 1


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    mode = (argv[0] if argv else "auth").lower()
    if mode not in ("auth", "cleanup"):
        sys.stderr.write("usage: he_dns.py auth|cleanup\n")
        return 2
    return _run(mode)


if __name__ == "__main__":
    raise SystemExit(main())
