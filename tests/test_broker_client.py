"""Tests for ``cage.broker.BrokerClient``.

Two layers:

  * Unit tests drive the client against a *fake* Unix-socket server that records
    the exact request framing and returns canned responses — fast, no Rust, and
    they pin the wire contract (op names, field shapes, error mapping).
  * An integration test (``TestRealBroker``) drives a real ``cage-broker`` binary
    end-to-end and asserts the signing key never appears in any response. Skipped
    if the binary is not built (set ``CAGE_BROKER_BIN`` or run
    ``cargo build -p cage-broker``).
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from cage import CageViolation
from cage.broker import BrokerClient, BrokerError
from cage.token import CapabilityToken

# A serialized core CapabilityToken, as the broker emits it for `issue`.
_TOKEN_WIRE = {
    "token_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "scope": "sign.invoice",
    "context": "run-42",
    "issued_at_unix": 1_700_000_000,
    "ttl_seconds": 60,
    "max_uses": 2,
    "use_count": 0,
    "revoked": False,
}


class _FakeBroker:
    """A minimal stand-in for the broker: accepts one request per connection,
    records it, and replies with whatever ``handler(request)`` returns."""

    def __init__(self, handler: Callable[[dict], dict]) -> None:
        self.handler = handler
        self.requests: list[dict] = []
        self._dir = tempfile.mkdtemp(prefix="cage-fakebroker-")
        self.path = os.path.join(self._dir, "broker.sock")
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(self.path)
        self._srv.listen(16)
        self._srv.settimeout(5.0)
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                if not buf.strip():
                    continue
                req = json.loads(buf.decode())
                self.requests.append(req)
                resp = self.handler(req)
                conn.sendall((json.dumps(resp) + "\n").encode())

    def stop(self) -> None:
        self._stop = True
        try:
            self._srv.close()
        finally:
            shutil.rmtree(self._dir, ignore_errors=True)


def _ok(result: dict) -> dict:
    return {"ok": True, "result": result}


def _err(kind: str, message: str = "nope") -> dict:
    return {"ok": False, "error": {"kind": kind, "message": message}}


@pytest.fixture
def fake():
    """Yield a factory that starts a _FakeBroker with a given handler and a client
    pointed at it; tears the server down afterwards."""
    started: list[_FakeBroker] = []

    def _make(handler: Callable[[dict], dict]) -> tuple[BrokerClient, _FakeBroker]:
        srv = _FakeBroker(handler)
        started.append(srv)
        return BrokerClient(srv.path, timeout=5.0), srv

    yield _make
    for srv in started:
        srv.stop()


def _op_client(path: str) -> BrokerClient:
    """A control-plane client: a real operator signer + a dummy broker_id. The fake
    broker records the request without verifying the signature, so any 32-byte
    broker_id works for framing tests (a real broker would verify it)."""
    from cage.broker import NativeOperatorSigner

    return BrokerClient(
        path, operator_signer=NativeOperatorSigner(), broker_id=b"\x00" * 32, timeout=5.0
    )


# --------------------------------------------------------------------------- #
# Request framing + happy paths
# --------------------------------------------------------------------------- #


def test_issue_token_frames_request_and_reconstructs_token(fake):
    _, srv = fake(lambda req: _ok(_TOKEN_WIRE))
    client = _op_client(srv.path)
    token = client.issue_token(
        scope="sign.invoice",
        context="run-42",
        ttl_seconds=60,
        max_uses=2,
    )
    # Request framing matches the wire contract: the named fields, plus a signed
    # control-plane auth object (no bearer secret).
    req = srv.requests[0]
    assert req["op"] == "issue"
    assert req["scope"] == "sign.invoice"
    assert req["context"] == "run-42"
    assert req["ttl_seconds"] == 60
    assert req["max_uses"] == 2
    auth = req["auth"]
    assert set(auth) == {"key_id", "nonce", "ts", "sig"}
    # hex lengths: 32-byte key, 16-byte nonce, 64-byte signature.
    assert len(auth["key_id"]) == 64
    assert len(auth["nonce"]) == 32
    assert len(auth["sig"]) == 128
    # The issued-token JSON is reconstructed into a CapabilityToken, incl. the
    # issued_at_unix -> datetime mapping.
    assert isinstance(token, CapabilityToken)
    assert token.token_id == _TOKEN_WIRE["token_id"]
    assert token.scope == "sign.invoice"
    assert token.ttl_seconds == 60
    assert token.issued_at.year == 2023  # 1_700_000_000 -> 2023-11-14 UTC


def test_none_optionals_are_dropped_from_the_wire(fake):
    _, srv = fake(lambda req: _ok(_TOKEN_WIRE))
    client = _op_client(srv.path)
    client.issue_token(scope="sign.x")
    req = srv.requests[0]
    # Defaults left unset must not be sent as explicit nulls — the broker applies
    # its own clamps/defaults.
    assert "ttl_seconds" not in req
    assert "max_uses" not in req
    assert req["op"] == "issue"
    assert req["scope"] == "sign.x"
    assert req["context"] == ""
    assert "auth" in req  # control-plane is operator-signed


def test_control_plane_without_signer_raises(fake):
    # A client constructed without an operator signer cannot perform control-plane
    # operations — it fails fast client-side rather than sending an unsigned request.
    client, _ = fake(lambda req: _ok(_TOKEN_WIRE))
    with pytest.raises(BrokerError, match="operator_signer"):
        client.issue_token(scope="sign.x")


def test_sign_returns_signature_and_accepts_bytes(fake):
    client, srv = fake(lambda req: _ok({"signature": "deadbeef"}))
    sig = client.sign("tok123", b"invoice #1001")
    assert sig == "deadbeef"
    assert srv.requests[0] == {"op": "sign", "token_id": "tok123", "payload": "invoice #1001"}


def test_sign_accepts_a_capability_token_handle(fake):
    client, srv = fake(lambda req: _ok({"signature": "ab"}))
    token = _token()
    client.sign(token, "x")
    assert srv.requests[0]["token_id"] == token.token_id


def test_invoke_llm_forwards_body_and_provider(fake):
    # The broker relays the provider body as a JSON string, and the client parses it.
    client, srv = fake(lambda req: _ok({"response": '{"id": "msg_1"}'}))
    body = {"model": "claude-haiku-4-5", "messages": [{"role": "user", "content": "hi"}]}
    out = client.invoke_llm("tok", body, provider="anthropic")
    assert out == {"id": "msg_1"}
    req = srv.requests[0]
    assert req["op"] == "invoke"
    assert req["provider"] == "anthropic"
    assert req["request_body"] == body  # forwarded structurally intact


def test_caged_adapter_returns_the_documented_dict(fake):
    from cage.adapters import CagedAnthropic

    provider_body = json.dumps({"content": [{"type": "text", "text": "pong"}]})
    client, _ = fake(lambda req: _ok({"response": provider_body}))
    resp = CagedAnthropic(client, "tok").messages.create(model="m", messages=[])
    assert resp["content"][0]["text"] == "pong"


def test_invoke_llm_rejects_an_unparseable_response(fake):
    client, _ = fake(lambda req: _ok({"response": "<html>bad gateway</html>"}))
    with pytest.raises(BrokerError, match="no parseable provider response"):
        client.invoke_llm("tok", {"model": "m", "messages": []})


def test_revoke_returns_bool(fake):
    _, srv = fake(lambda req: _ok({"revoked": True}))
    client = _op_client(srv.path)
    assert client.revoke("tok") is True
    req = srv.requests[0]
    assert req["op"] == "revoke"
    assert req["token_id"] == "tok"
    assert "auth" in req  # operator-signed, no bearer secret


def test_audit_helpers(fake):
    def handler(req: dict) -> dict:
        return {
            "audit_head": _ok({"audit_head": "ff00"}),
            "verify_chain": _ok({"valid": True}),
            "audit_log": _ok({"entries": [{"seq": 0, "event": "genesis"}]}),
        }[req["op"]]

    client, srv = fake(handler)
    # audit_head / verify_chain are open agent reads (no signer needed).
    assert client.audit_head() == "ff00"
    assert client.verify_chain() is True
    # audit_log is control-plane (operator-signed — it exposes live token_ids).
    op = _op_client(srv.path)
    assert op.audit_log() == [{"seq": 0, "event": "genesis"}]


# --------------------------------------------------------------------------- #
# Error mapping
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("kind", ["refused", "not_found"])
def test_authority_refusals_map_to_cage_violation(fake, kind):
    client, _ = fake(lambda req: _err(kind, "over max_uses"))
    with pytest.raises(CageViolation, match="over max_uses"):
        client.sign("tok", "x")


@pytest.mark.parametrize("kind", ["transport", "crypto", "bad_request", "internal", "error"])
def test_non_authority_errors_map_to_broker_error(fake, kind):
    client, _ = fake(lambda req: _err(kind, "boom"))
    with pytest.raises(BrokerError, match=kind):
        client.sign("tok", "x")


def test_non_json_response_raises_broker_error():
    # A server that returns a non-JSON line.
    d = tempfile.mkdtemp(prefix="cage-badbroker-")
    path = os.path.join(d, "broker.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    srv.settimeout(5.0)
    stop = False

    def serve():
        while not stop:
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                break
            with conn:
                conn.recv(4096)
                conn.sendall(b"not json at all\n")

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        with pytest.raises(BrokerError, match="non-JSON"):
            BrokerClient(path, timeout=5.0).audit_head()
    finally:
        stop = True
        srv.close()
        shutil.rmtree(d, ignore_errors=True)


def test_unreachable_socket_raises_broker_error(tmp_path):
    client = BrokerClient(str(tmp_path / "does-not-exist.sock"), timeout=1.0)
    with pytest.raises(BrokerError):
        client.audit_head()


def _token() -> CapabilityToken:
    return CapabilityToken(scope="sign.invoice", context="t", token_id="f" * 32)


# --------------------------------------------------------------------------- #
# Integration: a real cage-broker binary, end to end
# --------------------------------------------------------------------------- #

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _find_broker_bin() -> str | None:
    env = os.environ.get("CAGE_BROKER_BIN")
    if env and os.path.exists(env):
        return env
    for build in ("debug", "release"):
        cand = _REPO_ROOT / "target" / build / "cage-broker"
        if cand.exists():
            return str(cand)
    return None


@pytest.mark.skipif(
    _find_broker_bin() is None,
    reason="cage-broker binary not built (set CAGE_BROKER_BIN or `cargo build -p cage-broker`)",
)
class TestRealBroker:
    SECRET = "sk-LIVE-broker-client-test-7e3a1f9c-not-a-real-key"

    @pytest.fixture
    def broker(self):
        """Start a real cage-broker via the launcher (which generates the operator
        key, provisions its public half, and pre-wires a signing client) and yield
        the BrokerProcess."""
        from cage.broker import spawn_broker

        with spawn_broker(_find_broker_bin(), signing_key=self.SECRET) as bp:
            yield bp

    def test_issue_sign_overuse_revoke_audit(self, broker):
        bp = broker
        client = bp.client  # control-plane: operator signer + broker_id pre-wired

        # Control plane issues a 2-use token.
        token = client.issue_token(
            scope="sign.invoice", context="run-42", ttl_seconds=60, max_uses=2,
        )
        assert isinstance(token, CapabilityToken)

        # Agent signs within budget.
        sig1 = client.sign(token, "invoice #1001 :: 4200.00 CHF")
        sig2 = client.sign(token, "invoice #1002 :: 380.00 CHF")
        assert sig1 and sig2 and sig1 != sig2

        # Third use exceeds max_uses -> structural refusal.
        with pytest.raises(CageViolation):
            client.sign(token, "invoice #1003")

        # An operator key the broker does not trust is refused broker-side: a valid
        # signature under an unprovisioned key still cannot mint.
        from cage.broker import NativeOperatorSigner

        rogue = BrokerClient(
            bp.socket_path,
            operator_signer=NativeOperatorSigner(),
            broker_id=bp.broker_id,
        )
        with pytest.raises(CageViolation):
            rogue.issue_token(scope="sign.evil", max_uses=999)

        # A fabricated token_id is refused.
        with pytest.raises(CageViolation):
            client.sign("00" * 16, "x")

        # Revoke is operator-signed and reflected.
        token2 = client.issue_token(scope="sign.invoice", max_uses=5)
        assert client.revoke(token2) is True
        with pytest.raises(CageViolation):
            client.sign(token2, "x")

        # Audit chain verifies; head is open, the log is operator-gated.
        assert client.verify_chain() is True
        assert isinstance(client.audit_head(), str)
        entries = client.audit_log()
        assert any(e["event"] == "issued" for e in entries)

    def test_signing_key_never_crosses_the_socket(self, broker):
        """The whole point: tokens go in, the key never comes back."""
        client = broker.client
        token = client.issue_token(scope="sign.invoice", max_uses=5)
        # Drive every response-bearing path and assert the secret appears in none.
        observed = [
            json.dumps(client.attest()),
            client.sign(token, "payload"),
            json.dumps(client.audit_log()),
            client.audit_head(),
        ]
        assert all(self.SECRET not in blob for blob in observed)
