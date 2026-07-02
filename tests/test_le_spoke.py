"""Tests for the le spoke (LESpoke) command dispatch + get_status shape.

Self-contained: inserts src/ on sys.path and uses the flat imports the spoke
uses itself, so it runs without a package install. The spoke's BaseSpoke import
has a standalone fallback (no lm core checkout required).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import asyncio  # noqa: E402

from le_spoke import LESpoke  # noqa: E402


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _spoke():
    return LESpoke("le-spoke-1", {})


def _cmd(spoke, command, data=None):
    return _run(spoke.handle_command(command, data or {}))


def test_list_certs_success():
    res = _cmd(_spoke(), "LE_LIST_CERTS")
    assert res["status"] == "SUCCESS"
    assert isinstance(res["data"]["certs"], list)
    assert res["data"]["count"] == 0
    assert isinstance(res["data"]["certbot_present"], bool)


def test_get_status_shape():
    res = _run(_spoke().get_status())
    assert res["status"] == "SUCCESS"
    data = res["data"]
    assert data["module"] == "le"
    assert data["module_type"] == "certificates"
    assert isinstance(data["certbot_present"], bool)
    assert data["certs_managed"] == 0


def test_get_status_command_matches():
    spoke = _spoke()
    # LE_GET_STATUS should return the same shape as get_status().
    res = _cmd(spoke, "LE_GET_STATUS")
    assert res["status"] == "SUCCESS"
    assert res["data"]["module_type"] == "certificates"


def test_issue_cert_requires_domain():
    res = _cmd(_spoke(), "LE_ISSUE_CERT", {})
    assert res["status"] == "ERROR"
    assert "domain" in res["message"]


def test_issue_cert_records_intent():
    spoke = _spoke()
    res = _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com", "email": "a@b.com"})
    assert res["status"] == "SUCCESS"
    assert res["data"]["domain"] == "example.com"
    assert res["data"]["action"] == "issue"
    # The stub ledger records it so LIST_CERTS reflects it.
    listing = _cmd(spoke, "LE_LIST_CERTS")
    assert listing["data"]["count"] == 1
    assert listing["data"]["certs"][0]["domain"] == "example.com"


def test_revoke_cert_removes_from_ledger():
    spoke = _spoke()
    _cmd(spoke, "LE_ISSUE_CERT", {"domain": "example.com"})
    res = _cmd(spoke, "LE_REVOKE_CERT", {"domain": "example.com"})
    assert res["status"] == "SUCCESS"
    assert res["data"]["action"] == "revoke"
    assert _cmd(spoke, "LE_LIST_CERTS")["data"]["count"] == 0


def test_revoke_requires_domain():
    res = _cmd(_spoke(), "LE_REVOKE_CERT", {})
    assert res["status"] == "ERROR"


def test_renew_unknown_domain_errors():
    res = _cmd(_spoke(), "LE_RENEW_CERT", {"domain": "nope.example"})
    assert res["status"] == "ERROR"


def test_renew_all_success():
    res = _cmd(_spoke(), "LE_RENEW_CERT", {})
    assert res["status"] == "SUCCESS"
    assert res["data"]["domain"] == "all"


def test_update_config():
    res = _cmd(_spoke(), "UPDATE_CONFIG", {"acme_server": "staging"})
    assert res["status"] == "SUCCESS"


def test_unknown_command_errors():
    res = _cmd(_spoke(), "LE_DOES_NOT_EXIST")
    assert res["status"] == "ERROR"
    assert "Unknown command" in res["message"]


def test_get_version():
    res = _cmd(_spoke(), "GET_VERSION")
    assert res["status"] == "SUCCESS"
    assert res["version"]  # non-empty