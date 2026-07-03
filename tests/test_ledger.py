"""Tests for le/src/ledger.py — atomic persistence + target mutators."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ledger import Ledger, target_key  # noqa: E402


def _ledger(tmp_path):
    return Ledger(str(tmp_path / "certs.json"))


def test_load_missing_returns_skeleton(tmp_path):
    assert _ledger(tmp_path).load() == {"certs": {}}


def test_round_trip(tmp_path):
    lg = _ledger(tmp_path)
    state = {"certs": {"example.com": {"domain": "example.com", "targets": []}}}
    lg.save(state)
    assert lg.load() == state


def test_save_is_atomic_no_tmp_left(tmp_path):
    p = str(tmp_path / "certs.json")
    lg = Ledger(p)
    lg.save({"certs": {}})
    assert os.path.exists(p)
    assert not os.path.exists(p + ".tmp")


def test_load_corrupt_resets(tmp_path):
    p = str(tmp_path / "certs.json")
    with open(p, "w") as f:
        f.write("{not json")
    assert Ledger(p).load() == {"certs": {}}


def test_add_target_idempotent(tmp_path):
    state = {"certs": {"example.com": {"domain": "example.com", "targets": []}}}
    t1 = Ledger.add_target(state, "example.com", "firewall", "edge-1")
    t2 = Ledger.add_target(state, "example.com", "firewall", "edge-1")
    assert t1 is t2  # same object — not duplicated
    assert len(state["certs"]["example.com"]["targets"]) == 1
    Ledger.add_target(state, "example.com", "firewall", "edge-2")
    assert len(state["certs"]["example.com"]["targets"]) == 2


def test_add_target_missing_cert_returns_none():
    assert Ledger.add_target({"certs": {}}, "nope.com", "firewall") is None


def test_remove_target_by_idx():
    state = {"certs": {"example.com": {"domain": "example.com", "targets": [
        {"module_type": "firewall"}, {"module_type": "ipam"}]}}}
    assert Ledger.remove_target(state, "example.com", 0) is True
    assert state["certs"]["example.com"]["targets"] == [{"module_type": "ipam"}]
    assert Ledger.remove_target(state, "example.com", 99) is False
    assert Ledger.remove_target(state, "nope.com", 0) is False


def test_upsert_and_remove_cert():
    state = {"certs": {}}
    Ledger.upsert_cert(state, {"domain": "a.com", "targets": []})
    assert state["certs"]["a.com"]["domain"] == "a.com"
    assert Ledger.remove_cert(state, "a.com") is True
    assert Ledger.remove_cert(state, "a.com") is False


def test_target_key():
    assert target_key("firewall") == "firewall"
    assert target_key("firewall", "edge-1") == "firewall:edge-1"