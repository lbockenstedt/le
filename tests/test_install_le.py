"""install_le.sh: the .env it writes is owner-only, a re-run keeps the
secrets and TLS settings it already holds, and --tls-verify needs a CA."""
import fcntl
import os
import shutil
import stat
import subprocess
import time

import pytest

_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "install_le.sh")


def _env_block():
    """The installer's .env-writing block (from the secret-preserving step
    through the final chmod), to run in a sandbox."""
    text = open(_SCRIPT).read()
    start = text.index("# The installer owns only these keys.")
    marker = 'mv -f "$tmp" .env\n)\n'
    end = text.index(marker, start) + len(marker)
    return text[start:end]


def _write_env(tmp_path, existing=None, secret_given=0, hub_secret_given=0,
               secret="lm-secret", hub_secret="", tls_verify="false", ca=""):
    """Run the block in TMP_PATH under umask 022; return (result, .env)."""
    env_file = tmp_path / ".env"
    if existing is not None:
        env_file.write_text(existing)
        env_file.chmod(0o644)
    script = (f"set -e\numask 022\ncd {tmp_path}\nHUB_URL=auto SPOKE_ID=le-x "
              f"SPOKE_SECRET='{secret}' HUB_SECRET='{hub_secret}' "
              f"SECRET_GIVEN={secret_given} HUB_SECRET_GIVEN={hub_secret_given} "
              f"TLS_VERIFY={tls_verify} TLS_CA_CERT='{ca}'\n"
              + _env_block())
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    return res, env_file


def _start_env_write(tmp_path):
    """Start the block in the background; return the running process."""
    script = (f"set -e\ncd {tmp_path}\nHUB_URL=auto SPOKE_ID=le-x SPOKE_SECRET=s "
              f"HUB_SECRET= SECRET_GIVEN=1 HUB_SECRET_GIVEN=1 TLS_VERIFY=false TLS_CA_CERT=\n"
              + _env_block())
    return subprocess.Popen(["bash", "-c", script], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)


def test_env_is_owner_only(tmp_path):
    res, env_file = _write_env(tmp_path)
    assert res.returncode == 0, res.stderr
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600


def test_rerun_keeps_an_existing_env_owner_only(tmp_path):
    res, env_file = _write_env(tmp_path, existing="SPOKE_SECRET=s1\n")
    assert res.returncode == 0, res.stderr
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600


def test_rerun_without_secret_keeps_the_existing_secrets(tmp_path):
    res, env_file = _write_env(tmp_path, existing="SPOKE_SECRET=s3cr3t\nHUB_SECRET=h1\n")
    assert res.returncode == 0, res.stderr
    text = env_file.read_text()
    assert "SPOKE_SECRET=s3cr3t\n" in text and "HUB_SECRET=h1\n" in text
    assert "lm-secret" not in text


def test_rerun_keeps_an_empty_spoke_secret(tmp_path):
    # Core writes SPOKE_SECRET= after the hub rejects the secret (zero-touch
    # re-onboarding); a re-run must not turn that back into the default PSK.
    res, env_file = _write_env(tmp_path, existing="SPOKE_SECRET=\nHUB_SECRET=h1\n")
    assert res.returncode == 0, res.stderr
    text = env_file.read_text()
    assert "SPOKE_SECRET=\n" in text and "lm-secret" not in text


def test_a_given_secret_replaces_the_existing_one(tmp_path):
    res, env_file = _write_env(tmp_path, existing="SPOKE_SECRET=old\nHUB_SECRET=h1\n",
                               secret_given=1, secret="new", hub_secret_given=1, hub_secret="h2")
    assert res.returncode == 0, res.stderr
    text = env_file.read_text()
    assert "SPOKE_SECRET=new\n" in text and "HUB_SECRET=h2\n" in text


def test_tls_settings_are_written_and_then_kept(tmp_path):
    res, env_file = _write_env(tmp_path, tls_verify="true", ca="/etc/lm/hub-ca.pem")
    assert res.returncode == 0, res.stderr
    assert "LM_HUB_TLS_VERIFY=1\nLM_HUB_CA_CERT=/etc/lm/hub-ca.pem\n" in env_file.read_text()
    # A re-run without --tls-verify keeps them.
    res, env_file = _write_env(tmp_path, existing=env_file.read_text())
    assert res.returncode == 0, res.stderr
    assert "LM_HUB_TLS_VERIFY=1\nLM_HUB_CA_CERT=/etc/lm/hub-ca.pem\n" in env_file.read_text()


def test_tls_verify_requires_a_ca_cert():
    res = subprocess.run(["bash", _SCRIPT, "--tls-verify"], capture_output=True, text=True)
    assert res.returncode == 1 and "requires --tls-ca-cert" in res.stdout


def test_tls_ca_cert_must_be_readable(tmp_path):
    res = subprocess.run(["bash", _SCRIPT, "--tls-verify", "--tls-ca-cert", str(tmp_path / "nope.pem")],
                         capture_output=True, text=True)
    assert res.returncode == 1 and "not a readable file" in res.stdout


def test_tls_ca_cert_must_be_a_regular_file(tmp_path):
    # A readable directory passes -r but the spoke needs a file (isfile).
    res = subprocess.run(["bash", _SCRIPT, "--tls-verify", "--tls-ca-cert", str(tmp_path)],
                         capture_output=True, text=True)
    assert res.returncode == 1 and "not a readable file" in res.stdout


def test_a_relative_tls_ca_cert_is_stored_as_an_absolute_path(tmp_path):
    # The service runs from /opt/lm/le, so ./hub-ca.pem must be resolved
    # against the directory the installer was run from.
    (tmp_path / "hub-ca.pem").write_text("CA")
    text = open(_SCRIPT).read()
    start = text.index("if $TLS_VERIFY && [ -z")
    block = text[start:text.index('if [ -z "$SPOKE_SECRET" ]', start)]
    script = f"TLS_VERIFY=true TLS_CA_CERT=./hub-ca.pem\n{block}echo \"$TLS_CA_CERT\""
    res = subprocess.run(["bash", "-c", script], cwd=tmp_path, capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout.strip() == os.path.join(os.path.realpath(tmp_path), "hub-ca.pem")


def test_rerun_keeps_the_keys_core_persisted(tmp_path):
    # Core persists these into .env at runtime; a re-run must not drop them.
    runtime = ("INSTALL_UUID=u-1\nINSTALL_UUID_MACHINE=m-1\nLM_RECOVERY_PSK=r-1\n"
               "LM_MTLS_CA=/etc/lm/ca.pem\nLM_MTLS_CLIENT_CERT=/etc/lm/c.pem\n"
               "LM_MTLS_CLIENT_KEY=/etc/lm/c.key\nLM_MTLS_HUB_CLIENT_CERT=/etc/lm/h.pem\n"
               "LM_MTLS_HUB_CLIENT_KEY=/etc/lm/h.key\n")
    res, env_file = _write_env(tmp_path, existing="SPOKE_SECRET=s1\n" + runtime)
    assert res.returncode == 0, res.stderr
    text = env_file.read_text()
    for line in runtime.splitlines():
        assert line + "\n" in text


def test_owned_keys_are_replaced_not_duplicated(tmp_path):
    res, env_file = _write_env(tmp_path, existing="HUB_URL=old\nSPOKE_ID=old\nHUB_URL=older\n"
                                                  "LM_HUB_TLS_VERIFY=0\nLM_HUB_CA_CERT=/old.pem\n",
                               tls_verify="true", ca="/etc/lm/hub-ca.pem")
    assert res.returncode == 0, res.stderr
    lines = env_file.read_text().splitlines()
    assert lines.count("HUB_URL=auto") == 1 and not any(l.startswith("HUB_URL=old") for l in lines)
    assert "SPOKE_ID=le-x" in lines and "SPOKE_ID=old" not in lines
    assert "LM_HUB_TLS_VERIFY=1" in lines and "LM_HUB_TLS_VERIFY=0" not in lines
    assert "LM_HUB_CA_CERT=/etc/lm/hub-ca.pem" in lines and "LM_HUB_CA_CERT=/old.pem" not in lines


def test_no_temp_file_is_left_behind(tmp_path):
    res, _ = _write_env(tmp_path, existing="SPOKE_SECRET=s1\n")
    assert res.returncode == 0, res.stderr
    assert sorted(p.name for p in tmp_path.iterdir() if p.name != ".env.lock") == [".env"]


@pytest.mark.skipif(shutil.which("flock") is None, reason="flock(1) not installed")
def test_waits_for_the_env_lock_core_holds(tmp_path):
    # Core holds .env.lock while it persists a key; the installer must wait
    # for it rather than rewrite .env underneath.
    (tmp_path / ".env").write_text("SPOKE_SECRET=s1\n")
    fd = os.open(tmp_path / ".env.lock", os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        proc = _start_env_write(tmp_path)
        time.sleep(1.0)
        assert proc.poll() is None
        # Core persists a key while the installer waits; it must survive.
        with open(tmp_path / ".env", "a") as f:
            f.write("LM_RECOVERY_PSK=r-2\n")
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    out, err = proc.communicate(timeout=30)
    assert proc.returncode == 0, err
    assert "LM_RECOVERY_PSK=r-2\n" in (tmp_path / ".env").read_text()


def test_tls_ca_cert_needs_tls_verify(tmp_path):
    (tmp_path / "hub-ca.pem").write_text("CA")
    res = subprocess.run(["bash", _SCRIPT, "--tls-ca-cert", str(tmp_path / "hub-ca.pem")],
                         capture_output=True, text=True)
    assert res.returncode == 1 and "only with --tls-verify" in res.stdout
