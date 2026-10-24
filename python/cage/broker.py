"""
cage.broker — a thin, stdlib-only client for the out-of-process credential broker.

The broker (``cage-broker``) runs the signing / secret authority in its OWN
process; an agent holds only capability tokens and talks to it over a Unix-domain
socket. This module is the client side of that socket: it turns the
newline-delimited JSON wire protocol into ordinary Python calls, so adopting the
*secure* (out-of-process) deployment no longer means hand-rolling a socket
protocol.

    from cage.broker import BrokerClient, NativeOperatorSigner

    # Control plane — holds the operator signing key and the broker's identity.
    # Each control-plane call is signed; no bearer secret crosses the wire.
    control = BrokerClient(
        "/run/cage/broker.sock",
        operator_signer=NativeOperatorSigner(),
        broker_id=broker_pubkey_bytes,   # base64-decoded CAGE_BROKER_PUBKEY
    )
    token = control.issue_token(
        scope="sign.invoice", context="run-42", ttl_seconds=60, max_uses=2,
    )

    # Agent — holds only the token (a token_id); no key, no signer, no broker_id.
    agent = BrokerClient("/run/cage/broker.sock")
    signature = agent.sign(token, b"invoice #1001 :: 4200.00 CHF")

    control.revoke(token)

Control-plane vs agent: minting / revoking / attest / audit_log are **operator**
operations — they require an ``operator_signer`` (the operator's ed25519 key) and
the ``broker_id`` (the broker's attestation public key), and each request carries a
signature the broker verifies. Agent operations (``sign`` / ``invoke_llm`` /
``audit_head`` / ``verify_chain``) need none of that — only a token.

Wire model: one JSON request per line, one JSON response per line, **one request
per connection** (the broker serves a request and closes), so each call opens a
fresh connection. The signing key never crosses the socket — only tokens go in,
and signatures / provider responses / audit data come back.

Errors: a structural refusal (over-use, wrong scope, missing / expired / revoked
token, missing / invalid operator signature, unknown token) raises
:class:`cage.exceptions.CageViolation`; a transport / connection / protocol
failure raises :class:`BrokerError`. Pure stdlib — no third-party or native
dependency, matching the dependency-free core.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Any

from cage.exceptions import CageViolation
from cage.token import CapabilityToken

__all__ = [
    "BrokerClient",
    "BrokerError",
    "BrokerProcess",
    "NativeOperatorSigner",
    "harden_launcher",
    "spawn_broker",
]


def _native():
    """Lazily import the native extension.

    Imported only on the *operator* path (signing / canonical-message building), so
    the *agent* surface (``sign`` / ``invoke_llm`` / audit reads) stays pure-stdlib
    and native-free — an agent can talk to the broker without the Rust extension.
    """
    from cage import _cage_native

    return _cage_native


class NativeOperatorSigner:
    """Default operator signer — an ed25519 key held in the native extension.

    The control plane is authenticated by *proof of possession*: the operator signs
    each request; the broker holds only the matching public key. This is the default
    custody backend; any object exposing ``key_id`` (hex of the 32-byte public key)
    and ``sign(message: bytes) -> bytes`` (a 64-byte ed25519 signature) can replace
    it — e.g. an HSM- or OS-keystore-backed signer — without changing the wire format.
    """

    def __init__(self) -> None:
        self._key = _native().OperatorKey()

    @property
    def key_id(self) -> str:
        """Hex of the raw 32-byte ed25519 public key (the operator's ``key_id``)."""
        return self._key.public_key_hex

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

# Error kinds the broker returns that represent an authority decision (structural
# refusal) rather than a transport / protocol fault — these map to CageViolation.
_REFUSAL_KINDS = frozenset({"refused", "not_found"})

# Bound the bytes buffered for one response line. The broker's responses are small
# JSON, but a client must not be driven to unbounded memory by a misbehaving or
# spoofed peer occupying the socket path.
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_RECV_CHUNK = 65536


class BrokerError(RuntimeError):
    """A transport, connection, or protocol-level failure talking to the broker.

    Distinct from :class:`cage.exceptions.CageViolation`, which signals an
    authority decision (the broker *refused* the operation). A ``BrokerError``
    means the request never got a clean authority answer — the socket was
    unreachable, timed out, or the broker returned something unparseable.
    """


def _token_id(token: str | CapabilityToken) -> str:
    """Accept either a raw token_id or a CapabilityToken handle."""
    return token.token_id if isinstance(token, CapabilityToken) else token


def _token_from_wire(d: dict) -> CapabilityToken:
    """Reconstruct a CapabilityToken from the broker's issued-token JSON.

    The broker remains the authority for live state (use_count, revocation); this
    handle carries only the token_id and issue-time metadata.
    """
    return CapabilityToken(
        scope=d["scope"],
        context=d.get("context", ""),
        token_id=d["token_id"],
        issued_at=datetime.fromtimestamp(d["issued_at_unix"], tz=timezone.utc),
        ttl_seconds=int(d["ttl_seconds"]),
        max_uses=int(d["max_uses"]),
        use_count=int(d.get("use_count", 0)),
        revoked=bool(d.get("revoked", False)),
    )


class BrokerClient:
    """Client for a ``cage-broker`` listening on a Unix-domain socket.

    Holds no key and no long-lived connection: every method opens a fresh
    connection, sends one request, reads one response, and closes — mirroring the
    broker's one-request-per-connection model. Safe to share across threads: it
    keeps no mutable per-call state, and each call is independent.
    """

    def __init__(
        self,
        socket_path: str,
        *,
        operator_signer: Any | None = None,
        broker_id: bytes | None = None,
        timeout: float = 10.0,
    ) -> None:
        """:param socket_path: filesystem path of the broker's Unix socket.
        :param operator_signer: an operator signer (e.g. :class:`NativeOperatorSigner`)
            — required for control-plane calls (issue / revoke / attest / audit_log),
            unused by agent calls. Any object with ``key_id`` and
            ``sign(message: bytes) -> bytes`` works.
        :param broker_id: the target broker's attestation public key as raw 32 bytes
            (base64-decode the broker's ``CAGE_BROKER_PUBKEY=`` line). Bound into every
            control-plane signature so it cannot be replayed against a different broker.
        :param timeout: per-call connect / read / write deadline, in seconds.
        """
        self.socket_path = socket_path
        self.timeout = timeout
        self._operator_signer = operator_signer
        self._broker_id = broker_id

    # -- capability lifecycle (control plane; operator-signature-gated) -----

    def _sign_control(self, op: str, args: bytes) -> dict:
        """Build the signed ``auth`` object for a control-plane request: a fresh
        nonce + timestamp, the canonical message (built by the native core, the same
        bytes the gate reconstructs), and the operator's signature over it."""
        if self._operator_signer is None:
            raise BrokerError(
                "control-plane operations (issue / revoke / attest / audit_log) require "
                "an operator_signer; this client was constructed without one"
            )
        if self._broker_id is None:
            raise BrokerError(
                "control-plane operations require broker_id (the broker's attestation "
                "public key, raw 32 bytes); this client was constructed without one"
            )
        nonce = os.urandom(16)
        ts = int(time.time())
        message = _native().control_message(self._broker_id, op, args, nonce, ts)
        sig = self._operator_signer.sign(message)
        return {
            "key_id": self._operator_signer.key_id,
            "nonce": nonce.hex(),
            "ts": ts,
            "sig": sig.hex(),
        }

    def issue_token(
        self,
        *,
        scope: str,
        context: str = "",
        ttl_seconds: int | None = None,
        max_uses: int | None = None,
    ) -> CapabilityToken:
        """Mint a capability token (operator-signed). ttl_seconds / max_uses are
        clamped broker-side."""
        args = _native().control_args_issue(scope, context, ttl_seconds, max_uses)
        result = self._request(
            "issue",
            scope=scope,
            context=context,
            ttl_seconds=ttl_seconds,
            max_uses=max_uses,
            auth=self._sign_control("issue", args),
        )
        return _token_from_wire(result)

    def revoke(self, token: str | CapabilityToken) -> bool:
        """Revoke a token immediately (operator-signed). Returns whether the call
        changed state (False if it was already revoked)."""
        token_id = _token_id(token)
        args = _native().control_args_revoke(token_id)
        result = self._request(
            "revoke", token_id=token_id, auth=self._sign_control("revoke", args)
        )
        return bool(result.get("revoked", False))

    # -- agent operations (token only; no key, no bootstrap) ----------------

    def sign(self, token: str | CapabilityToken, payload: bytes | str) -> str:
        """HMAC-sign ``payload`` with the token's scoped key; returns a hex signature.

        ``payload`` is carried as a UTF-8 string on the JSON wire (``bytes`` must be
        UTF-8-decodable); the broker signs its exact bytes.
        """
        if isinstance(payload, (bytes, bytearray)):
            payload = bytes(payload).decode("utf-8")
        result = self._request("sign", token_id=_token_id(token), payload=payload)
        return result["signature"]

    def invoke_llm(
        self,
        token: str | CapabilityToken,
        request_body: dict,
        *,
        provider: str = "anthropic",
    ) -> dict[str, Any]:
        """Invoke an LLM provider with the token's scoped key.

        The key never crosses the socket: the broker decrypts it, makes the TLS
        call, and returns only the provider's response. ``request_body`` is
        forwarded to the provider byte-for-byte. Returns the provider's JSON
        response parsed into a ``dict``, as ``SecretVault.invoke_llm`` does.
        """
        result = self._request(
            "invoke",
            token_id=_token_id(token),
            provider=provider,
            request_body=request_body,
        )
        # The broker relays the provider's body as a JSON string.
        try:
            return json.loads(result["response"])
        except (KeyError, TypeError, json.JSONDecodeError) as e:
            raise BrokerError(f"broker returned no parseable provider response: {e}") from e

    # -- audit (head / verify are open; log / attest are bootstrap-gated) ---

    def audit_head(self) -> str:
        """Current audit-chain head hash (unauthenticated; carries no token_ids)."""
        return self._request("audit_head")["audit_head"]

    def verify_chain(self) -> bool:
        """Verify the whole audit chain from genesis (internal-consistency check)."""
        return bool(self._request("verify_chain")["valid"])

    def attest(self) -> dict:
        """Signed ed25519 attestation over the current audit head (operator-signed:
        it signs with the audit key, so it must not be an open signing oracle)."""
        return self._request("attest", auth=self._sign_control("attest", b""))

    def audit_log(self) -> list[dict]:
        """Snapshot of the audit log (operator-signed — entries carry live token_ids,
        a bearer handle that must not leak on an open channel)."""
        return self._request("audit_log", auth=self._sign_control("audit_log", b""))[
            "entries"
        ]

    # -- wire ---------------------------------------------------------------

    def _request(self, op: str, **fields: Any) -> dict:
        # Drop None-valued optionals so the broker applies its own defaults
        # (e.g. the ttl / max_uses clamps) rather than receiving explicit nulls.
        req: dict[str, Any] = {"op": op}
        for key, value in fields.items():
            if value is not None:
                req[key] = value
        raw = (json.dumps(req) + "\n").encode("utf-8")

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(raw)
                line = self._read_line(sock)
        except OSError as e:
            raise BrokerError(f"broker socket {self.socket_path!r}: {e}") from e

        try:
            resp = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise BrokerError(f"broker returned a non-JSON response: {e}") from e

        if resp.get("ok"):
            result = resp.get("result")
            return result if isinstance(result, dict) else {}

        err = resp.get("error") or {}
        kind = err.get("kind", "error")
        message = err.get("message", "broker refused the request")
        if kind in _REFUSAL_KINDS:
            # Mirror the in-process facade's "CAGE refused:" convention, but do not
            # double the prefix: a `refused`-kind message is the core's
            # `CageError::Refused` Display, which already starts with "CAGE refused:".
            if not message.startswith("CAGE refused:"):
                message = f"CAGE refused: {message}"
            raise CageViolation(message)
        raise BrokerError(f"broker error ({kind}): {message}")

    def _read_line(self, sock: socket.socket) -> bytes:
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(_RECV_CHUNK)
            if not chunk:
                break  # peer closed before sending a full line
            buf += chunk
            if len(buf) > _MAX_RESPONSE_BYTES:
                raise BrokerError("broker response exceeded the size cap")
        if not buf.endswith(b"\n"):
            raise BrokerError("broker closed the connection before a full response")
        return buf


# -- launcher: stand up a cage-broker process (dev / dogfood) ------------------
#
# Adopting the secure out-of-process deployment shouldn't mean hand-rolling the
# spawn ceremony. BrokerProcess captures it once: spawn the broker, read the
# bootstrap token and attestation pubkey it reveals on stdout, hand it its
# credential through a sealed file, and tear it all down on exit.


class BrokerProcess:
    """A running ``cage-broker`` child process, used as a context manager.

    ``__enter__`` generates an operator key, spawns the broker provisioned with that
    operator's *public* key (so the broker can verify control-plane signatures but
    holds no minting secret), and captures the broker's attestation ``pubkey``;
    ``__exit__`` terminates the process and removes the socket. The signing credential
    is handed over through a transient ``0600`` file the broker loads into its vault
    and which is then deleted — never an environment variable, whose value would
    linger in the broker's readable environment block. This launcher is for dev,
    tests, and dogfooding. In production, start the broker from a supervisor that
    is not the agent (see DEPLOY.md) and hold the operator key in a custody-backed
    signer.

        os.environ["CAGE_ISSUANCE_SCOPES"] = "llm."  # the issuance ceiling
        with spawn_broker("target/release/cage-broker", signing_key=key) as bp:
            token = bp.client.issue_token(
                scope="llm.evaluate", ttl_seconds=60, max_uses=3,
            )
            ...  # hand an agent only token.token_id

    The operator private key (held inside ``bp``'s signer) is the control-plane root
    authority: it lives only in this controlling process and is never given to an
    agent. ``bp.client`` is pre-wired to sign control-plane requests with it.
    """

    def __init__(
        self,
        broker_bin: str,
        *,
        signing_key: str,
        llm_api_key: str | None = None,
        socket_path: str | None = None,
        timeout: float = 10.0,
        allow_debugger: bool = False,
        allow_no_policy: bool = False,
    ) -> None:
        """:param broker_bin: path to the built ``cage-broker`` binary.
        :param signing_key: the credential the broker signs / decrypts with.
        :param llm_api_key: optional LLM-provider key; when given, the broker can
            serve token-gated LLM calls on the ``llm.`` scope (the key stays inside
            the broker). Omit it for a sign-only broker.
        :param socket_path: where the broker should listen; a private temp socket
            is created (and removed on exit) when omitted.
        :param timeout: seconds to wait for startup, and the client's per-call deadline.
        :param allow_debugger: start the broker without its debugger-attach hardening
            (``CAGE_BROKER_ALLOW_DEBUGGER=1``), for debugging or a memory-residency
            scan. Dev only: a same-user process can then read the key. The variable
            is never forwarded from the caller's environment.
        :param allow_no_policy: start the broker without an issuance policy
            (``CAGE_BROKER_ALLOW_NO_POLICY=1``). A stolen operator key can then mint
            any scope up to the hard ceilings. Like the debugger waiver, the variable
            is never forwarded from the caller's environment, so a waiver left in a
            shell profile cannot hide a missing or misspelled policy.
        """
        for name, value in (
            ("allow_debugger", allow_debugger),
            ("allow_no_policy", allow_no_policy),
        ):
            if not isinstance(value, bool):
                raise CageViolation(
                    f"{name} must be a bool, got {type(value).__name__}. "
                    'Refusing to coerce: a truthy string such as "false" would '
                    "otherwise switch off a broker safeguard."
                )
        self.allow_debugger = allow_debugger
        self.allow_no_policy = allow_no_policy
        self.broker_bin = broker_bin
        # Held only until _start hands them to the broker.
        self._signing_key: str | None = signing_key
        self._llm_api_key: str | None = llm_api_key
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None
        # Operator signer (the control-plane root authority) + the broker's identity,
        # populated on _start. self.pubkey is the broker's attestation key (base64);
        # self.broker_id is its raw 32 bytes, bound into every control-plane signature.
        self._signer: Any | None = None
        self.operator_pubkey: str | None = None
        self.pubkey: str | None = None
        self.broker_id: bytes | None = None
        # Own (and clean up) a temp socket dir unless the caller pins the path.
        self._owns_sockdir = socket_path is None
        if socket_path is None:
            self._sock_dir: str | None = tempfile.mkdtemp(prefix="cage-broker-")
            self.socket_path = os.path.join(self._sock_dir, "broker.sock")
        else:
            self._sock_dir = None
            self.socket_path = socket_path

    @property
    def client(self) -> BrokerClient:
        """A :class:`BrokerClient` bound to this broker's socket, pre-wired with the
        operator signer and broker identity so control-plane calls are signed."""
        return BrokerClient(
            self.socket_path,
            operator_signer=self._signer,
            broker_id=self.broker_id,
            timeout=self.timeout,
        )

    def __enter__(self) -> BrokerProcess:
        self._start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.terminate()

    def _start(self) -> None:
        if self._signing_key is None:
            raise BrokerError("a BrokerProcess starts once; create a new one to restart")
        # Generate the operator key; the broker is provisioned with its PUBLIC half
        # (so it can verify control-plane signatures but holds no minting secret).
        signer = NativeOperatorSigner()

        # Sealed credential handoff: a 0600 file the broker loads into Zeroizing
        # buffers and which we delete once loaded — never an env var.
        cred_dir = tempfile.mkdtemp(prefix="cage-cred-")
        cred = os.path.join(cred_dir, "cred.env")
        pubkey = None
        ready = False
        try:
            # O_EXCL: always a fresh file, never a symlink or FIFO planted at this path.
            fd = os.open(cred, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(f"signing_key={self._signing_key}\n")
                if self._llm_api_key is not None:
                    f.write(f"llm_api_key={self._llm_api_key}\n")
            # The broker owns the credentials from here on. Drop this object's
            # references so a long-lived launcher does not keep them reachable.
            # CPython does not zero the strings, and the caller's own copies stay
            # wherever the caller keeps them.
            self._signing_key = None
            self._llm_api_key = None

            # Resolve a bare name with the caller's PATH. The broker's own environment
            # carries no PATH, and Popen would search that one.
            binary = shutil.which(self.broker_bin) or self.broker_bin
            proc = subprocess.Popen(
                [binary, self.socket_path],
                stdout=subprocess.PIPE,
                # Inherited, so the broker's startup warnings and the reason for a
                # FATAL exit reach the operator.
                stderr=None,
                env=self._broker_env(cred, signer.key_id),
            )
            self.proc = proc
            deadline = time.monotonic() + self.timeout
            for line in _lines_until(proc.stdout, deadline):
                if line.startswith("CAGE_BROKER_PUBKEY="):
                    pubkey = line.split("=", 1)[1]
                    # The broker prints its pubkey only after loading the credential
                    # into vault memory, so the on-disk copy can go now.
                    shutil.rmtree(cred_dir, ignore_errors=True)
                elif line.startswith("CAGE_BROKER_READY="):
                    ready = True
                    break
        finally:
            # Covers every start that did not reach the pubkey line: the broker
            # exited, stalled past the deadline, or never launched.
            shutil.rmtree(cred_dir, ignore_errors=True)
        if not pubkey:
            self.terminate()
            raise BrokerError(
                f"broker {self.broker_bin!r} did not reveal its attestation pubkey "
                f"within {self.timeout:g}s (exit code {proc.poll()})"
            )
        if not ready:
            # The pubkey comes before the socket bind, so a broker can print it and
            # still die (bind failure, strict mlock) before it serves anything.
            self.terminate()
            raise BrokerError(
                f"broker {self.broker_bin!r} printed its pubkey but did not report "
                f"ready within {self.timeout:g}s (exit code {proc.poll()})"
            )
        self._signer = signer
        self.operator_pubkey = signer.key_id
        self.pubkey = pubkey
        # The broker binds its attestation key (raw bytes) into each control-plane
        # signature as its identity; decode the base64 it printed.
        self.broker_id = base64.b64decode(pubkey)

    def _broker_env(self, cred: str, operator_pubkey: str) -> dict[str, str]:
        # The broker reads only CAGE_* settings, so it gets only those. Everything
        # else in the caller's environment, a provider key or LD_PRELOAD included,
        # stays out of the broker's environment block. The prefix is matched in any
        # case, so a miscased policy name reaches the broker, which refuses it. The
        # waivers never ride in on the caller's environment: they take
        # allow_debugger=True and allow_no_policy=True.
        waivers = {"CAGE_BROKER_ALLOW_DEBUGGER", "CAGE_BROKER_ALLOW_NO_POLICY"}
        env = {
            name: value
            for name, value in os.environ.items()
            if name.upper().startswith("CAGE_") and name.upper() not in waivers
        }
        env["CAGE_BROKER_SECRET_FILE"] = cred
        # CAGE_OPERATOR_PUBKEY is PUBLIC (integrity, not secrecy), so an env var is
        # fine — unlike the signing credential, which goes via the sealed file.
        env["CAGE_OPERATOR_PUBKEY"] = operator_pubkey
        if self.allow_debugger:
            env["CAGE_BROKER_ALLOW_DEBUGGER"] = "1"
        if self.allow_no_policy:
            env["CAGE_BROKER_ALLOW_NO_POLICY"] = "1"
        return env

    def terminate(self) -> None:
        """Stop the broker and remove the socket (and any temp dir we own).

        Idempotent — safe to call more than once, and called for you by ``__exit__``.
        """
        proc, self.proc = self.proc, None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        # Drop the root-authority handle (the operator signer) once the broker is gone.
        self._signer = None
        self.broker_id = None
        try:
            if os.path.exists(self.socket_path):
                os.remove(self.socket_path)
        except OSError:
            pass
        if self._owns_sockdir and self._sock_dir and os.path.isdir(self._sock_dir):
            shutil.rmtree(self._sock_dir, ignore_errors=True)


def _lines_until(stream: Any, deadline: float):
    """Yield the lines a child writes to the binary pipe ``stream`` until EOF or
    the ``time.monotonic()`` ``deadline``. ``readline()`` would block past the
    deadline on a child that stalls without printing."""
    fd = stream.fileno()
    buf = b""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            return
        chunk = os.read(fd, 4096)
        if not chunk:
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            yield line.decode(errors="replace").strip()


def harden_launcher() -> None:
    """Deny debugger attach, memory reads and core dumps for the calling process.

    Call it in a supervisor that runs :func:`spawn_broker` and then starts the agent,
    before the agent starts. The supervisor holds the operator private key for as
    long as it runs, and the broker's own hardening does not cover it.

    * Linux: ``prctl(PR_SET_DUMPABLE, 0)``. A later ``exec`` resets the flag, so the
      broker and the agent are not affected.
    * macOS: ``ptrace(PT_DENY_ATTACH)``, best effort.
    * Everywhere: core-dump limit 0, hard limit included. Child processes inherit it.

    Debugging the process afterwards needs root on Linux and is refused on macOS.
    Raises :class:`BrokerError` on a platform with no mechanism, or if the call fails.
    """
    try:
        import resource  # POSIX only, so imported here rather than for every client

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, OSError, ValueError) as e:
        raise BrokerError(f"cannot disable core dumps for this process: {e}") from e
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        pr_set_dumpable = 4
        zero = ctypes.c_ulong(0)
        rc = libc.prctl(pr_set_dumpable, zero, zero, zero, zero)
    elif sys.platform == "darwin":
        pt_deny_attach = 31
        rc = libc.ptrace(pt_deny_attach, 0, None, 0)
    else:
        raise BrokerError(f"no debugger-attach hardening for {sys.platform}")
    if rc != 0:
        raise BrokerError(f"cannot harden this process: {os.strerror(ctypes.get_errno())}")


def spawn_broker(
    broker_bin: str,
    *,
    signing_key: str,
    llm_api_key: str | None = None,
    socket_path: str | None = None,
    timeout: float = 10.0,
    allow_debugger: bool = False,
    allow_no_policy: bool = False,
) -> BrokerProcess:
    """Create a :class:`BrokerProcess` for ``broker_bin`` — use it as a context manager.

    ``signing_key`` (and ``llm_api_key``, when given) are handed to the broker
    through a transient ``0600`` file (never an env var) and deleted once loaded.
    Supplying ``llm_api_key`` lets the broker serve token-gated LLM calls on the
    ``llm.`` scope. With ``socket_path`` omitted, a private temp socket is created
    and removed on exit. The broker reveals a one-time ``bootstrap`` token and an
    attestation ``pubkey`` on startup, both captured on the returned object once
    entered. ``allow_debugger=True`` starts the broker without its debugger-attach
    hardening (dev only, see :class:`BrokerProcess`).

    The broker gets the caller's ``CAGE_*`` settings and refuses to start without an
    issuance policy, so set ``CAGE_ISSUANCE_SCOPES`` (for example ``llm.,sign.``), or
    pass ``allow_no_policy=True`` to run without one (dev and tests).
    """
    return BrokerProcess(
        broker_bin,
        signing_key=signing_key,
        llm_api_key=llm_api_key,
        socket_path=socket_path,
        timeout=timeout,
        allow_debugger=allow_debugger,
        allow_no_policy=allow_no_policy,
    )
