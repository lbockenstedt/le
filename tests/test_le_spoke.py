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


def test_issue_renews_window_days_stored_and_listed(tmp_path, monkeypatch):
    """A per-cert renew_window_days from the issue request is stored on the
    ledger entry, returned by LE_ISSUE_CERT, and surfaced by LE_LIST_CERTS
    (renew_window_days_effective resolves None → the 7-day default)."""
    spoke = _spoke(tmp_path, monkeypatch)
    res = _cmd(spoke, "LE_ISSUE_CERT", {
        "domain": "example.com", "email": "a@b.com", "challenge": "http",
        "renew_window_days": 14})
    assert res["status"] == "SUCCESS"
    assert res["data"]["renew_window_days"] == 14
    cert = _cmd(spoke, "LE_LIST_CERTS")["data"]["certs"][0]
    assert cert["renew_window_days"] == 14
    assert cert["renew_window_days_effective"] == 14


def test_issue_renew_window_days_defaults_to_none(tmp_path, monkeypatch):
    """No renew_window_days in the request → stored None → effective = 7-day
    default (so a cert issued without the field still renews at 7 days)."""
    spoke = _spoke(tmp_path, monkeypatch)
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com", "challenge": "http"})
    cert = _cmd(spoke, "LE_LIST_CERTS")["data"]["certs"][0]
    assert cert["renew_window_days"] is None
    assert cert["renew_window_days_effective"] == 7


def test_issue_renew_window_days_bad_value_falls_back(tmp_path, monkeypatch):
    """A non-positive / non-int renew_window_days is normalized to None (use
    default) so a bad value can't disable renewal or crash the loop."""
    spoke = _spoke(tmp_path, monkeypatch)
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "a.com", "challenge": "http",
                                  "renew_window_days": 0})
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "b.com", "challenge": "http",
                                  "renew_window_days": "soon"})
    certs = {c["domain"]: c for c in _cmd(spoke, "LE_LIST_CERTS")["data"]["certs"]}
    assert certs["a.com"]["renew_window_days"] is None
    assert certs["b.com"]["renew_window_days"] is None
    assert certs["a.com"]["renew_window_days_effective"] == 7


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


# ── event-driven distribution (LE_CERT_RENEWED) ──────────────────────────────

class _FakeCP:
    """Records unsolicited send_to_hub calls so we can assert the le spoke
    notifies the hub on a renew without a real websocket."""
    def __init__(self):
        self.events = []

    async def send_to_hub(self, payload_type, data):
        self.events.append({"type": payload_type, "data": data})
        return True


def _spoke_with_cp(tmp_path, monkeypatch):
    _install_acme_mocks(monkeypatch)
    cfg = {"ledger_path": str(tmp_path / "certs.json")}
    cp = _FakeCP()
    return LESpoke("le-spoke-1", cfg, control_plane=cp), cp


def test_notify_renewed_emits_event_with_targets(tmp_path, monkeypatch):
    spoke, cp = _spoke_with_cp(tmp_path, monkeypatch)
    entry = {"material_hash": _HASH, "targets": [
        {"module_type": "firewall", "identifier": "edge-1"}]}
    _run(spoke._notify_renewed("example.com", entry))
    assert len(cp.events) == 1
    assert cp.events[0]["type"] == "LE_CERT_RENEWED"
    assert cp.events[0]["data"]["domain"] == "example.com"
    assert cp.events[0]["data"]["material_hash"] == _HASH
    assert cp.events[0]["data"]["targets"] == entry["targets"]


def test_notify_renewed_noop_without_control_plane(tmp_path, monkeypatch):
    # Default construction (no control_plane) — must not raise + must not try
    # to send. The hourly hub loop is the fallback for this path.
    spoke = _spoke(tmp_path, monkeypatch)
    assert spoke.control_plane is None
    _run(spoke._notify_renewed("example.com", {"material_hash": _HASH,
                                               "targets": []}))  # no error


def test_renew_emits_le_cert_renewed_event(tmp_path, monkeypatch):
    spoke, cp = _spoke_with_cp(tmp_path, monkeypatch)
    _cmd(spoke, "LE_ISSUE_CERT", {
        "domain": "example.com", "email": "a@b.com", "challenge": "http",
        "targets": [{"module_type": "firewall", "identifier": "edge-1"}]})
    res = _cmd(spoke, "LE_RENEW_CERT", {"domain": "example.com"})
    assert res["status"] == "SUCCESS"
    # The renew notified the hub so distribution fires immediately (vs. 1h poll).
    renewed = [e for e in cp.events if e["type"] == "LE_CERT_RENEWED"
               and e["data"]["domain"] == "example.com"]
    assert len(renewed) == 1
    assert renewed[0]["data"]["material_hash"] == _HASH
    assert renewed[0]["data"]["targets"][0]["module_type"] == "firewall"


def test_renew_failure_does_not_emit_event(tmp_path, monkeypatch):
    _install_acme_mocks(monkeypatch, renew_status="ERROR")
    cfg = {"ledger_path": str(tmp_path / "certs.json")}
    cp = _FakeCP()
    spoke = LESpoke("le-spoke-1", cfg, control_plane=cp)
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com", "challenge": "http"})
    _cmd(spoke, "LE_RENEW_CERT", {"domain": "example.com"})
    assert [e for e in cp.events if e["type"] == "LE_CERT_RENEWED"] == []


# ── Agent-host cert deploy (dumb Agent on a cert-target box) ────────────────────
# The spoke validates the cert+key pair in-process (ssl.load_cert_chain) before
# any material reaches a live host, then drives the Agent with WRITE_FILE +
# RUN_COMMAND. A real self-signed cert+key is generated with cryptography so the
# in-process validation passes for the success path (fake PEM bodies are
# rejected by the SSL library, exactly like netbox's install-cert tests).

import datetime as _dt  # noqa: E402


def _real_pair(cn="example.com"):
    """Real self-signed cert + matching privkey (PEM) so ssl.load_cert_chain
    accepts the pair during the spoke's in-process validation step."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = _dt.datetime.utcnow()
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    crt_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()).decode()
    return crt_pem, key_pem


class _FakeAgentCP:
    """Stand-in for LEControlPlane: holds connected_agents (so the spoke can
    resolve hostnames + target a specific Agent) and records send_to_agent calls
    (WRITE_FILE / RUN_COMMAND) with configurable RUN_COMMAND results. Mirrors the
    AgentHostingControlPlane.send_to_agent surface the deploy path uses."""

    def __init__(self, agent_id="le-agent-1", hostname="web-1",
                 helper_rc=0, helper_stdout="OK installed example.com",
                 helper_stderr=""):
        self.connected_agents = {agent_id: {"ws": object(), "hostname": hostname}}
        self.calls = []
        self._agent_id = agent_id
        self._helper_rc = helper_rc
        self._helper_stdout = helper_stdout
        self._helper_stderr = helper_stderr

    async def send_to_agent(self, cmd_type, data, agent_id=None, timeout=15.0):
        self.calls.append({"cmd": cmd_type, "data": data,
                           "agent_id": agent_id, "timeout": timeout})
        if cmd_type == "WRITE_FILE":
            return {"status": "SUCCESS"}
        if cmd_type == "RUN_COMMAND":
            cmd = (data or {}).get("command", "")
            if "rm -f" in cmd:  # cleanup — result ignored by the spoke
                return {"status": "SUCCESS", "result": {"rc": 0, "stdout": "",
                                                        "stderr": ""}}
            # The install-helper invocation.
            return {"status": "SUCCESS", "result": {
                "rc": self._helper_rc, "stdout": self._helper_stdout,
                "stderr": self._helper_stderr}}
        return {"status": "SUCCESS"}


def _spoke_with_agent_cp(tmp_path, monkeypatch, **cp_kwargs):
    _install_acme_mocks(monkeypatch)
    cfg = {"ledger_path": str(tmp_path / "certs.json")}
    cp = _FakeAgentCP(**cp_kwargs)
    return LESpoke("le-spoke-1", cfg, control_plane=cp), cp


def _material_real(monkeypatch, domain="example.com"):
    """Stub read_material to return a REAL cert pair so the deploy path's
    in-process ssl validation passes."""
    crt, key = _real_pair(domain)
    monkeypatch.setattr(le_spoke, "read_material", lambda d: {
        "status": "SUCCESS", "domain": d, "fullchain": crt, "privkey": key,
        "chain": "", "material_hash": _HASH, "not_after": _NOTAFTER})
    return crt, key


def test_validate_cert_pair_rejects_non_pem(tmp_path, monkeypatch):
    spoke, _ = _spoke_with_agent_cp(tmp_path, monkeypatch)
    r1 = spoke._validate_cert_pair("not a cert", _KEY)
    r2 = spoke._validate_cert_pair(_PEM, "not a key")
    assert r1["status"] == "ERROR" and "PEM" in r1["message"]
    assert r2["status"] == "ERROR" and "PEM" in r2["message"]


def test_validate_cert_pair_accepts_real_pair(tmp_path, monkeypatch):
    spoke, _ = _spoke_with_agent_cp(tmp_path, monkeypatch)
    crt, key = _real_pair()
    assert spoke._validate_cert_pair(crt, key) is None  # None == valid


def test_deploy_to_agent_success_validates_writes_runs_and_records(tmp_path, monkeypatch):
    spoke, cp = _spoke_with_agent_cp(tmp_path, monkeypatch,
                                     helper_stdout="OK installed example.com")
    _material_real(monkeypatch, "example.com")  # AFTER spoke build so it wins
    # Issue first so a managed-cert entry exists for the ledger target.
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com", "challenge": "http"})
    res = _cmd(spoke, "LE_DEPLOY_TO_AGENT", {"domain": "example.com"})
    assert res["status"] == "SUCCESS", res
    assert res["data"]["agent_id"] == "le-agent-1"
    assert res["data"]["hostname"] == "web-1"
    # Sequence: WRITE_FILE crt → WRITE_FILE key → RUN_COMMAND helper → RUN_COMMAND rm.
    cmds = [c["cmd"] for c in cp.calls]
    assert cmds[:2] == ["WRITE_FILE", "WRITE_FILE"]
    assert cmds.count("WRITE_FILE") == 2
    runs = [c["data"]["command"] for c in cp.calls if c["cmd"] == "RUN_COMMAND"]
    assert len(runs) == 2, runs
    assert runs[0].startswith("sudo -n ") and "example.com" in runs[0]
    assert "rm -f" in runs[1]  # cleanup of both temps
    # Temps written 0600 with distinct .crt.pem/.key.pem names.
    writes = [c["data"] for c in cp.calls if c["cmd"] == "WRITE_FILE"]
    assert writes[0]["mode"] == 0o600 and writes[1]["mode"] == 0o600
    assert writes[0]["path"].endswith(".crt.pem") and writes[1]["path"].endswith(".key.pem")
    # Ledger records the agent target + the push for this host (idempotent re-push).
    cert = _cmd(spoke, "LE_LIST_CERTS")["data"]["certs"][0]
    agent_targets = [t for t in cert["targets"] if t.get("module_type") == "agent"]
    assert len(agent_targets) == 1
    assert agent_targets[0]["identifier"] == "web-1"
    assert agent_targets[0]["last_status"] == "SUCCESS"


def test_deploy_to_agent_no_agent_connected_errors(tmp_path, monkeypatch):
    spoke, cp = _spoke_with_agent_cp(tmp_path, monkeypatch)
    _material_real(monkeypatch, "example.com")
    spoke.control_plane.connected_agents = {}  # no Agent connected
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com", "challenge": "http"})
    res = _cmd(spoke, "LE_DEPLOY_TO_AGENT", {"domain": "example.com"})
    assert res["status"] == "ERROR" and "no le agent connected" in res["message"]


def test_deploy_to_agent_helper_failure_records_error_status(tmp_path, monkeypatch):
    spoke, cp = _spoke_with_agent_cp(tmp_path, monkeypatch, helper_rc=1,
                                     helper_stdout="", helper_stderr="nginx -t failed")
    _material_real(monkeypatch, "example.com")
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com", "challenge": "http"})
    res = _cmd(spoke, "LE_DEPLOY_TO_AGENT", {"domain": "example.com"})
    assert res["status"] == "ERROR"
    cert = _cmd(spoke, "LE_LIST_CERTS")["data"]["certs"][0]
    agent_targets = [t for t in cert["targets"] if t.get("module_type") == "agent"]
    assert len(agent_targets) == 1 and agent_targets[0]["last_status"] == "ERROR"


def test_deploy_to_agent_requires_domain(tmp_path, monkeypatch):
    spoke, _ = _spoke_with_agent_cp(tmp_path, monkeypatch)
    res = _cmd(spoke, "LE_DEPLOY_TO_AGENT", {})
    assert res["status"] == "ERROR" and "domain" in res["message"]


def test_deploy_cached_cert_to_agent_matches_hostname_and_deploys(tmp_path, monkeypatch):
    spoke, cp = _spoke_with_agent_cp(tmp_path, monkeypatch, hostname="web-1")
    _material_real(monkeypatch, "example.com")
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com", "challenge": "http"})
    # Add an agent target scoped to web-1.
    _cmd(spoke, "LE_ADD_TARGET", {"domain": "example.com",
                                  "target": {"module_type": "agent",
                                             "identifier": "web-1"}})
    _run(spoke.deploy_cached_cert_to_agent("le-agent-1"))
    runs = [c["data"]["command"] for c in cp.calls if c["cmd"] == "RUN_COMMAND"]
    assert any(c.startswith("sudo -n ") for c in runs)  # helper fired
    cert = _cmd(spoke, "LE_LIST_CERTS")["data"]["certs"][0]
    t = [x for x in cert["targets"] if x.get("module_type") == "agent"][0]
    assert t["last_status"] == "SUCCESS"


def test_deploy_cached_cert_to_agent_skips_non_matching_hostname(tmp_path, monkeypatch):
    spoke, cp = _spoke_with_agent_cp(tmp_path, monkeypatch, hostname="web-1")
    _material_real(monkeypatch, "example.com")
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com", "challenge": "http"})
    _cmd(spoke, "LE_ADD_TARGET", {"domain": "example.com",
                                  "target": {"module_type": "agent",
                                             "identifier": "other-host"}})
    _run(spoke.deploy_cached_cert_to_agent("le-agent-1"))
    # No RUN_COMMAND helper call — target is for a different host.
    assert not [c for c in cp.calls if c["cmd"] == "RUN_COMMAND"
                and "sudo -n" in c["data"].get("command", "")]


def test_deploy_cached_cert_to_agent_noop_without_connected_agent(tmp_path, monkeypatch):
    spoke, cp = _spoke_with_agent_cp(tmp_path, monkeypatch)
    _material_real(monkeypatch, "example.com")
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com", "challenge": "http"})
    spoke.control_plane.connected_agents = {}  # agent gone mid-flight
    _run(spoke.deploy_cached_cert_to_agent("le-agent-1"))  # must not raise
    assert cp.calls == []