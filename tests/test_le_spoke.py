"""Tests for the le spoke (LESpoke) real command dispatch + ledger.

Self-contained: inserts src/ on sys.path and uses the flat imports the spoke
uses itself, so it runs without a package install. acme (certbot) is
monkeypatched so no subprocess runs; read_material is stubbed to deterministic
PEM material so the ledger/hash path is exercised without /etc/letsencrypt.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import asyncio  # noqa: E402
import le_spoke  # noqa: E402
from le_spoke import LESpoke  # noqa: E402


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        # Cancel background tasks (e.g. a renewal loop started by
        # UPDATE_CONFIG) so closing the ephemeral loop doesn't warn about
        # destroyed-but-pending tasks.
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        for t in pending:
            t.cancel()
        if pending:
            loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True))
        loop.close()


_PEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
_KEY = "-----BEGIN PRIVATE KEY-----\nKKKK\n-----END PRIVATE KEY-----\n"
_HASH = "sha256:" + "a" * 64
_NOTAFTER = "2099-01-01T00:00:00+00:00"


def _material(domain="example.com", status="SUCCESS"):
    return {"status": status, "domain": domain, "fullchain": _PEM,
            "privkey": _KEY, "chain": "", "material_hash": _HASH,
            "not_after": _NOTAFTER}


def _install_acme_mocks(monkeypatch, issue_status="SUCCESS",
                        renew_status="SUCCESS", revoke_status="SUCCESS"):
    async def fake_issue(domain, email, challenge, **kw):
        if issue_status == "ERROR":
            return {"status": "ERROR", "message": "certbot failed"}
        return {"status": "SUCCESS", "domain": domain, "live_dir": "/tmp/x"}

    async def fake_renew(domain, **kw):
        if renew_status == "ERROR":
            return {"status": "ERROR", "message": "renew failed"}
        return {"status": "SUCCESS", "domain": domain, "renewed": True}

    async def fake_revoke(domain, **kw):
        if revoke_status == "ERROR":
            return {"status": "ERROR", "message": "revoke failed"}
        return {"status": "SUCCESS", "domain": domain, "deleted": True}

    monkeypatch.setattr(le_spoke, "acme_issue", fake_issue)
    monkeypatch.setattr(le_spoke, "acme_renew", fake_renew)
    monkeypatch.setattr(le_spoke, "acme_revoke", fake_revoke)
    monkeypatch.setattr(le_spoke, "read_material", _material)
    monkeypatch.setattr(le_spoke, "certbot_present", lambda: True)


def _spoke(tmp_path, monkeypatch):
    _install_acme_mocks(monkeypatch)
    cfg = {"ledger_path": str(tmp_path / "certs.json")}
    # No running event loop during sync construction → create_task raises
    # RuntimeError, which the spoke catches ("renewal loop deferred"). That's
    # the same path a real spoke hits when constructed outside asyncio.run;
    # the loop only matters in production (constructed inside run_hub_mode).
    return LESpoke("le-spoke-1", cfg)


def _cmd(spoke, command, data=None):
    return _run(spoke.handle_command(command, data or {}))


# ── status / list ────────────────────────────────────────────────────────────

def test_get_status_shape(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    res = _run(spoke.get_status())
    assert res["status"] == "SUCCESS"
    d = res["data"]
    assert d["module"] == "le" and d["module_type"] == "certificates"
    assert d["certbot_present"] is True
    assert d["certs_managed"] == 0


def test_list_certs_empty(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    res = _cmd(spoke, "LE_LIST_CERTS")
    assert res["status"] == "SUCCESS"
    assert res["data"]["count"] == 0
    assert res["data"]["certbot_present"] is True


# ── issue ─────────────────────────────────────────────────────────────────────

def test_issue_requires_domain(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    res = _cmd(spoke, "LE_ISSUE_CERT", {})
    assert res["status"] == "ERROR" and "domain" in res["message"]


def test_issue_success_seeds_targets_and_ledger(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    res = _cmd(spoke, "LE_ISSUE_CERT", {
        "domain": "example.com", "email": "a@b.com", "challenge": "http",
        "targets": [{"module_type": "firewall", "identifier": "edge-1"}]})
    assert res["status"] == "SUCCESS"
    assert res["data"]["domain"] == "example.com"
    assert res["data"]["material_hash"] == _HASH
    tgt = res["data"]["targets"]
    assert len(tgt) == 1 and tgt[0]["module_type"] == "firewall"
    assert tgt[0]["identifier"] == "edge-1"
    # Ledger reflects it.
    listing = _cmd(spoke, "LE_LIST_CERTS")
    assert listing["data"]["count"] == 1
    cert = listing["data"]["certs"][0]
    assert cert["domain"] == "example.com"
    assert cert["material_hash"] == _HASH
    assert cert["not_after"] == _NOTAFTER


def test_issue_failure_returns_error(tmp_path, monkeypatch):
    _install_acme_mocks(monkeypatch, issue_status="ERROR")
    cfg = {"ledger_path": str(tmp_path / "certs.json")}
    spoke = LESpoke("le-spoke-1", cfg)  # no loop → renewal deferred (ok)
    res = _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com"})
    assert res["status"] == "ERROR"
    # Nothing recorded on failure.
    assert _cmd(spoke, "LE_LIST_CERTS")["data"]["count"] == 0


# ── renew / revoke ───────────────────────────────────────────────────────────

def test_renew_all_updates_hash(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "a.com"})
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "b.com"})
    res = _cmd(spoke, "LE_RENEW_CERT", {})
    assert res["status"] == "SUCCESS"
    assert res["data"]["count"] == 2
    domains = {r["domain"] for r in res["data"]["renewed"]}
    assert domains == {"a.com", "b.com"}
    for r in res["data"]["renewed"]:
        assert r["renewed"] is True
        assert r["material_hash"] == _HASH


def test_renew_unknown_domain_errors(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    res = _cmd(spoke, "LE_RENEW_CERT", {"domain": "nope.com"})
    assert res["status"] == "ERROR"


def test_revoke_removes_from_ledger(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com"})
    res = _cmd(spoke, "LE_REVOKE_CERT", {"domain": "example.com"})
    assert res["status"] == "SUCCESS"
    assert res["data"]["deleted"] is True
    assert _cmd(spoke, "LE_LIST_CERTS")["data"]["count"] == 0


def test_revoke_requires_domain(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    res = _cmd(spoke, "LE_REVOKE_CERT", {})
    assert res["status"] == "ERROR"


# ── get cert (hub transport pull) ─────────────────────────────────────────────

def test_get_cert_returns_material(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    res = _cmd(spoke, "LE_GET_CERT", {"domain": "example.com"})
    assert res["status"] == "SUCCESS"
    d = res["data"]
    assert d["fullchain"] == _PEM
    assert d["privkey"] == _KEY
    assert d["material_hash"] == _HASH


def test_get_cert_missing_domain_errors(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    assert _cmd(spoke, "LE_GET_CERT", {})["status"] == "ERROR"


# ── targets ──────────────────────────────────────────────────────────────────

def test_add_then_remove_target(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com"})
    res = _cmd(spoke, "LE_ADD_TARGET", {"domain": "example.com",
                                        "target": {"module_type": "firewall"}})
    assert res["status"] == "SUCCESS"
    cert = _cmd(spoke, "LE_LIST_CERTS")["data"]["certs"][0]
    assert len(cert["targets"]) == 1
    rm = _cmd(spoke, "LE_REMOVE_TARGET", {"domain": "example.com", "idx": 0})
    assert rm["status"] == "SUCCESS"
    cert = _cmd(spoke, "LE_LIST_CERTS")["data"]["certs"][0]
    assert cert["targets"] == []


def test_add_target_missing_cert(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    res = _cmd(spoke, "LE_ADD_TARGET", {"domain": "nope.com",
                                        "target": {"module_type": "firewall"}})
    assert res["status"] == "ERROR"


# ── distribution ack ─────────────────────────────────────────────────────────

def test_mark_distributed_records_push(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com",
                                  "targets": [{"module_type": "firewall"}]})
    res = _cmd(spoke, "LE_MARK_DISTRIBUTED", {
        "domain": "example.com", "module_type": "firewall",
        "hash": _HASH, "status": "SUCCESS", "message": "installed"})
    assert res["status"] == "SUCCESS"
    cert = _cmd(spoke, "LE_LIST_CERTS")["data"]["certs"][0]
    t = cert["targets"][0]
    assert t["last_pushed_hash"] == _HASH
    assert t["last_status"] == "SUCCESS"
    assert t["last_message"] == "installed"
    assert t["last_pushed_at"] is not None


def test_mark_distributed_target_not_found(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com"})
    res = _cmd(spoke, "LE_MARK_DISTRIBUTED", {
        "domain": "example.com", "module_type": "ipam", "hash": _HASH})
    assert res["status"] == "ERROR"


# ── misc ─────────────────────────────────────────────────────────────────────

def test_update_config(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    res = _cmd(spoke, "UPDATE_CONFIG", {"renew_interval": 3600})
    assert res["status"] == "SUCCESS"
    assert spoke._renew_interval == 3600


def test_get_version(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    res = _cmd(spoke, "GET_VERSION")
    assert res["status"] == "SUCCESS" and res["version"]


def test_unknown_command_errors(tmp_path, monkeypatch):
    spoke = _spoke(tmp_path, monkeypatch)
    res = _cmd(spoke, "LE_NOPE")
    assert res["status"] == "ERROR" and "Unknown command" in res["message"]