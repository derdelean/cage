"""Tests for the cage.broker launcher (spawn_broker / BrokerProcess).

These exercise the launcher's process lifecycle, stdout handshake parsing,
sealed-credential handoff, and teardown against a FAKE broker — a tiny stand-in
that mimics the real cage-broker's startup contract — so they run fast and need
no Rust build. The real binary is covered end-to-end by examples/broker_demo.py.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time

import pytest

from cage.broker import BrokerClient, BrokerError, spawn_broker
from cage.exceptions import CageViolation


def _write_fake_broker(tmp_path, body: str) -> str:
    """Write an executable Python stand-in for cage-broker; return its path."""
    path = tmp_path / "fake-broker"
    path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    os.chmod(path, 0o755)
    return str(path)


# A faithful fake: it verifies the credential was handed over through the sealed
# file AND that the operator's public key was provisioned (refusing — exit non-zero,
# no pubkey — if either is missing), announces the pubkey + ready handshake, then
# idles until the launcher kills it. Because it only completes the handshake *after*
# validating both, a passing happy-path test is itself proof the sealed handoff and
# the operator-key provisioning worked. It prints NO bootstrap — there is none.
_FAKE_BROKER_PUBKEY = base64.b64encode(b"B" * 32).decode()
_GOOD_BROKER = f"""
    import os, time
    with open(os.environ["CAGE_BROKER_SECRET_FILE"]) as f:
        assert f.read().startswith("signing_key="), "credential not sealed-in"
    assert os.environ.get("CAGE_OPERATOR_PUBKEY"), "operator pubkey not provisioned"
    print("CAGE_BROKER_PUBKEY={_FAKE_BROKER_PUBKEY}", flush=True)
    print("CAGE_BROKER_READY=1", flush=True)
    time.sleep(60)  # stay alive until the launcher terminates us
"""

# A broken broker: dies immediately without revealing its pubkey.
_DEAD_BROKER = """
    import sys
    print("[cage-broker] FATAL: fake startup failure", file=sys.stderr)
    sys.exit(3)
"""

# Prints its pubkey, then dies before READY, as a broker does when the strict
# mlock check or the socket bind fails.
_DIES_AFTER_PUBKEY_BROKER = f"""
    import sys
    print("CAGE_BROKER_PUBKEY={_FAKE_BROKER_PUBKEY}", flush=True)
    print("[cage-broker] FATAL: fake bind failure", file=sys.stderr)
    sys.exit(3)
"""

# Records whether the launcher deleted the sealed credential file after the pubkey
# line and before READY, into <its own path>.observed.
_DELETE_CHECK_BROKER = f"""
    import os, sys, time
    cred = os.environ["CAGE_BROKER_SECRET_FILE"]
    print("CAGE_BROKER_PUBKEY={_FAKE_BROKER_PUBKEY}", flush=True)
    deadline = time.time() + 5
    while os.path.exists(cred) and time.time() < deadline:
        time.sleep(0.01)
    with open(sys.argv[0] + ".observed", "w") as f:
        f.write("present" if os.path.exists(cred) else "gone")
    print("CAGE_BROKER_READY=1", flush=True)
    time.sleep(60)
"""

# Records the environment it was started with, as JSON, into <its own path>.observed.
_ENV_RECORDING_BROKER = f"""
    import json, os, sys, time
    with open(sys.argv[0] + ".observed", "w") as f:
        json.dump(dict(os.environ), f)
    print("CAGE_BROKER_PUBKEY={_FAKE_BROKER_PUBKEY}", flush=True)
    print("CAGE_BROKER_READY=1", flush=True)
    time.sleep(60)
"""

# Records its credential file path, then stalls without printing anything.
_SILENT_BROKER = """
    import os, sys, time
    with open(sys.argv[0] + ".observed", "w") as f:
        f.write(os.environ["CAGE_BROKER_SECRET_FILE"])
    time.sleep(60)
"""


def test_captures_handshake_and_tears_down(tmp_path):
    fake = _write_fake_broker(tmp_path, _GOOD_BROKER)

    with spawn_broker(fake, signing_key="sk-test-credential") as bp:
        # The launcher generated an operator key (hex of a 32-byte pubkey) and
        # captured the broker's attestation key (base64), decoded to raw broker_id.
        assert bp.operator_pubkey is not None and len(bp.operator_pubkey) == 64
        assert bp.pubkey == _FAKE_BROKER_PUBKEY
        assert bp.broker_id == b"B" * 32
        assert bp.proc is not None and bp.proc.poll() is None  # running
        proc, sock_path = bp.proc, bp.socket_path

    # __exit__ stopped the process, removed the socket, and dropped the operator
    # signer (the control-plane root authority).
    assert proc.poll() is not None
    assert bp._signer is None
    assert bp.broker_id is None
    assert not os.path.exists(sock_path)


def test_owns_and_removes_temp_sockdir(tmp_path):
    fake = _write_fake_broker(tmp_path, _GOOD_BROKER)
    with spawn_broker(fake, signing_key="sk-test") as bp:
        sock_dir = os.path.dirname(bp.socket_path)
        assert os.path.isdir(sock_dir)
    assert not os.path.exists(sock_dir)  # private temp sockdir cleaned on exit


def test_honours_explicit_socket_path(tmp_path):
    fake = _write_fake_broker(tmp_path, _GOOD_BROKER)
    sock = str(tmp_path / "pinned.sock")
    with spawn_broker(fake, signing_key="sk-test", socket_path=sock) as bp:
        assert bp.socket_path == sock


def test_raises_when_no_pubkey_revealed(tmp_path, capfd):
    fake = _write_fake_broker(tmp_path, _DEAD_BROKER)
    with pytest.raises(BrokerError, match="did not reveal its attestation pubkey"):
        with spawn_broker(fake, signing_key="sk-test", timeout=5.0):
            pass
    # The broker's stderr is inherited, so the operator sees why it died.
    assert "FATAL: fake startup failure" in capfd.readouterr().err


def test_raises_when_broker_dies_after_pubkey(tmp_path):
    fake = _write_fake_broker(tmp_path, _DIES_AFTER_PUBKEY_BROKER)
    with pytest.raises(BrokerError, match="did not report ready"):
        with spawn_broker(fake, signing_key="sk-test", timeout=5.0):
            pass


def test_deletes_sealed_credential_once_pubkey_is_printed(tmp_path):
    fake = _write_fake_broker(tmp_path, _DELETE_CHECK_BROKER)
    with spawn_broker(fake, signing_key="sk-test"):
        pass
    assert (tmp_path / "fake-broker.observed").read_text() == "gone"


def test_drops_credentials_after_handoff_and_starts_once(tmp_path):
    fake = _write_fake_broker(tmp_path, _GOOD_BROKER)
    bp = spawn_broker(fake, signing_key="sk-test", llm_api_key="sk-llm")
    with bp:
        assert bp._signing_key is None
        assert bp._llm_api_key is None
    # A second start would hand the broker no credential, so it is refused.
    with pytest.raises(BrokerError, match="starts once"):
        with bp:
            pass


def _broker_env(tmp_path) -> dict:
    return json.loads((tmp_path / "fake-broker.observed").read_text())


def test_inherited_debugger_waiver_is_not_forwarded(tmp_path, monkeypatch):
    # A waiver planted in the caller's environment (a shell profile, a service
    # manager) must not reach the broker. Only allow_debugger=True passes it.
    fake = _write_fake_broker(tmp_path, _ENV_RECORDING_BROKER)
    monkeypatch.setenv("CAGE_BROKER_ALLOW_DEBUGGER", "1")
    with spawn_broker(fake, signing_key="sk-test"):
        pass
    assert "CAGE_BROKER_ALLOW_DEBUGGER" not in _broker_env(tmp_path)
    with spawn_broker(fake, signing_key="sk-test", allow_debugger=True):
        pass
    assert _broker_env(tmp_path)["CAGE_BROKER_ALLOW_DEBUGGER"] == "1"


def test_inherited_policy_waiver_is_not_forwarded(tmp_path, monkeypatch):
    # A waiver left in a shell profile must not hide a missing or misspelled
    # policy. Only allow_no_policy=True passes it, in any case of the name.
    fake = _write_fake_broker(tmp_path, _ENV_RECORDING_BROKER)
    monkeypatch.setenv("CAGE_BROKER_ALLOW_NO_POLICY", "1")
    monkeypatch.setenv("cage_broker_allow_no_policy", "1")
    with spawn_broker(fake, signing_key="sk-test"):
        pass
    env = _broker_env(tmp_path)
    assert "CAGE_BROKER_ALLOW_NO_POLICY" not in env
    assert "cage_broker_allow_no_policy" not in env
    with spawn_broker(fake, signing_key="sk-test", allow_no_policy=True):
        pass
    assert _broker_env(tmp_path)["CAGE_BROKER_ALLOW_NO_POLICY"] == "1"


def test_only_cage_settings_reach_the_broker_environment(tmp_path, monkeypatch):
    # A provider key or a preload in the caller's environment stays out of the
    # broker's environment block. The broker's own CAGE_* settings pass.
    fake = _write_fake_broker(tmp_path, _ENV_RECORDING_BROKER)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-for-the-broker")
    monkeypatch.setenv("LD_PRELOAD", "/nonexistent/inject.so")
    monkeypatch.setenv("CAGE_ISSUANCE_SCOPES", "sign.")
    monkeypatch.setenv("cage_issuance_max_uses", "2")
    with spawn_broker(fake, signing_key="sk-test"):
        pass
    env = _broker_env(tmp_path)
    assert "ANTHROPIC_API_KEY" not in env
    assert "LD_PRELOAD" not in env
    assert env["CAGE_ISSUANCE_SCOPES"] == "sign."
    # A miscased CAGE_ name passes too, so the broker can refuse it.
    assert env["cage_issuance_max_uses"] == "2"
    # Nothing else of the caller's either. (The fake broker is a Python interpreter,
    # which adds a few locale variables of its own on startup.)
    assert "PATH" not in env and "HOME" not in env


def test_silent_broker_hits_the_deadline_and_loses_its_credential_file(tmp_path):
    # readline() would block forever on a broker that never prints. The launcher
    # must give up at its deadline and still remove the credential file.
    fake = _write_fake_broker(tmp_path, _SILENT_BROKER)
    started = time.monotonic()
    with pytest.raises(BrokerError, match="did not reveal its attestation pubkey"):
        with spawn_broker(fake, signing_key="sk-test", timeout=1.0):
            pass
    assert time.monotonic() - started < 8
    cred_file = (tmp_path / "fake-broker.observed").read_text()
    assert not os.path.exists(cred_file)


def test_bare_broker_name_resolves_on_the_callers_path(tmp_path, monkeypatch):
    # The broker's environment carries no PATH, so a bare name must be resolved
    # with the caller's PATH before the launch.
    _write_fake_broker(tmp_path, _GOOD_BROKER)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")
    with spawn_broker("fake-broker", signing_key="sk-test") as bp:
        assert bp.pubkey == _FAKE_BROKER_PUBKEY


def test_failed_launch_leaves_no_credential_file(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    with pytest.raises(OSError):
        with spawn_broker(str(tmp_path / "no-such-broker"), signing_key="sk-test"):
            pass
    assert not list(tmp_path.glob("cage-cred-*"))


_HARDEN_PROBE = """
import ctypes, resource, sys
from cage.broker import harden_launcher
harden_launcher()
print(resource.getrlimit(resource.RLIMIT_CORE))
if sys.platform.startswith("linux"):
    print(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0))  # PR_GET_DUMPABLE
"""


def test_harden_launcher_denies_core_dumps_and_attach():
    # Run in a child: the hardening is permanent for the process that calls it.
    out = subprocess.run(
        [sys.executable, "-c", _HARDEN_PROBE], capture_output=True, text=True, check=True
    ).stdout.split("\n")
    assert out[0] == "(0, 0)"
    if sys.platform.startswith("linux"):
        assert out[1] == "0"


@pytest.mark.parametrize("value", ["false", 1, None])
def test_allow_debugger_must_be_a_bool(value):
    with pytest.raises(CageViolation, match="allow_debugger must be a bool"):
        spawn_broker("unused", signing_key="sk-test", allow_debugger=value)


@pytest.mark.parametrize("value", ["false", 1, None])
def test_allow_no_policy_must_be_a_bool(value):
    with pytest.raises(CageViolation, match="allow_no_policy must be a bool"):
        spawn_broker("unused", signing_key="sk-test", allow_no_policy=value)


def test_refusal_message_is_not_double_prefixed():
    # A `refused`-kind message is the core's CageError::Refused Display, which already
    # starts with "CAGE refused:". The client must surface it once, not doubled.
    # Driven by a one-shot fake socket server — no real broker, no network. Uses a
    # short tempdir path: an AF_UNIX socket path must fit the ~104-char sun_path limit,
    # which pytest's tmp_path can exceed.
    sock_dir = tempfile.mkdtemp(prefix="cage-test-")
    sock_path = os.path.join(sock_dir, "f.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)

    def serve_one_refusal():
        conn, _ = server.accept()
        conn.recv(4096)
        reply = {"ok": False, "error": {"kind": "refused",
                                        "message": 'CAGE refused: token "x" invalid'}}
        conn.sendall((json.dumps(reply) + "\n").encode())
        conn.close()

    thread = threading.Thread(target=serve_one_refusal)
    thread.start()
    try:
        with pytest.raises(CageViolation) as excinfo:
            BrokerClient(sock_path).audit_head()
    finally:
        thread.join(timeout=5)
        server.close()
        shutil.rmtree(sock_dir, ignore_errors=True)

    message = str(excinfo.value)
    assert message == 'CAGE refused: token "x" invalid'
    assert message.count("CAGE refused:") == 1


# -- real-broker integration (opt-in via CAGE_BROKER_BIN) --
#
# Point CAGE_BROKER_BIN at a freshly built cage-broker. Explicit rather than
# auto-discovered: guessing target/release vs target/debug can pick a stale binary.

_BROKER_BIN = os.environ.get("CAGE_BROKER_BIN")
_needs_broker = pytest.mark.skipif(
    not _BROKER_BIN,
    reason="set CAGE_BROKER_BIN=path/to/cage-broker to run the real-broker tests",
)

_LLM_BODY = {
    "model": "claude-haiku-4-5",
    "max_tokens": 8,
    "messages": [{"role": "user", "content": "ping"}],
}


def _issue_and_invoke(bp, provider):
    token = bp.client.issue_token(
        scope="llm.evaluate", context="it", ttl_seconds=60, max_uses=1,
    )
    return bp.client.invoke_llm(token, _LLM_BODY, provider=provider)


@_needs_broker
def test_provider_key_registers_llm_scope():
    # With a provider key supplied, an llm-scoped token resolves to it and reaches
    # provider validation: an UNKNOWN provider is rejected there (network-free),
    # proving scope->secret resolution + the invoke verb — not a missing secret.
    with spawn_broker(
        _BROKER_BIN, signing_key="sk-sign", llm_api_key="sk-fake", allow_no_policy=True,
    ) as bp:
        with pytest.raises(BrokerError, match="unknown provider"):
            _issue_and_invoke(bp, "no-such-provider")


def _audit_events(bp) -> list[str]:
    return [entry["event"] for entry in bp.client.audit_log()]


@_needs_broker
def test_debugger_waiver_is_recorded_on_the_audit_chain():
    # A chain without the entry came from a broker that denied debugger attach.
    with spawn_broker(_BROKER_BIN, signing_key="sk-sign", allow_no_policy=True) as bp:
        assert "debugger_attach_allowed" not in _audit_events(bp)
    with spawn_broker(
        _BROKER_BIN, signing_key="sk-sign", allow_debugger=True, allow_no_policy=True,
    ) as bp:
        assert "debugger_attach_allowed" in _audit_events(bp)


@_needs_broker
def test_llm_provider_pin_refuses_another_provider(monkeypatch):
    # CAGE_LLM_PROVIDER pins the broker's LLM key: a token cannot send it to another
    # provider's host. Refused before any network call.
    monkeypatch.setenv("CAGE_LLM_PROVIDER", "anthropic")
    with spawn_broker(
        _BROKER_BIN, signing_key="sk-sign", llm_api_key="sk-fake", allow_no_policy=True,
    ) as bp:
        with pytest.raises(CageViolation, match="pinned to provider"):
            _issue_and_invoke(bp, "openai")


@_needs_broker
def test_sign_only_broker_does_not_register_llm_scope():
    # Without a provider key the llm. scope is never registered, so an llm-scoped
    # token does not resolve — refused before any network.
    with spawn_broker(_BROKER_BIN, signing_key="sk-sign", allow_no_policy=True) as bp:
        with pytest.raises(CageViolation, match="unknown scope namespace"):
            _issue_and_invoke(bp, "anthropic")


@_needs_broker
def test_broker_without_a_policy_refuses_to_start(capfd):
    with pytest.raises(BrokerError, match="did not reveal its attestation pubkey"):
        with spawn_broker(_BROKER_BIN, signing_key="sk-sign"):
            pass
    assert "FATAL: no issuance policy" in capfd.readouterr().err


@_needs_broker
def test_a_miscased_policy_name_reaches_the_broker_and_is_refused(monkeypatch, capfd):
    # Read alone, the lowercase limit would leave the default of 50 uses in force.
    monkeypatch.setenv("CAGE_ISSUANCE_SCOPES", "sign.")
    monkeypatch.setenv("cage_issuance_max_uses", "2")
    with pytest.raises(BrokerError, match="did not reveal its attestation pubkey"):
        with spawn_broker(_BROKER_BIN, signing_key="sk-sign"):
            pass
    err = capfd.readouterr().err
    assert '"cage_issuance_max_uses"' in err and "case-sensitive" in err


@_needs_broker
def test_policy_waiver_is_recorded_on_the_audit_chain(monkeypatch):
    # The chain shows that a broker ran without a ceiling by request.
    with spawn_broker(_BROKER_BIN, signing_key="sk-sign", allow_no_policy=True) as bp:
        events = _audit_events(bp)
    assert "issuance_policy_waived" in events
    assert "issuance_policy_frozen" not in events
    monkeypatch.setenv("CAGE_ISSUANCE_SCOPES", "sign.")
    with spawn_broker(_BROKER_BIN, signing_key="sk-sign") as bp:
        events = _audit_events(bp)
    assert "issuance_policy_frozen" in events
    assert "issuance_policy_waived" not in events
