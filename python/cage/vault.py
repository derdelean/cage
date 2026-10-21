"""
SecretVault — CAGE process-lifetime secret store (ring 2).

Composes a :class:`cage.core.Gate` (ring 1 — the universal authority: capability
tokens, structural refusal, audit chain) and adds secret custody on top:
encryption into Rust-owned memory and the zero-plaintext LLM transport.

Backend selection:
  Rust   — ChaCha20Poly1305 AEAD + zeroize-on-drop + mlock + rustls transport
  Python — ChaCha20 (no AEAD, no real zeroize) — development fallback

All token lifecycle, revocation, and audit logic is delegated to the Gate —
those operations handle no secret bytes. The ONLY path to a secret value is
through ``consume()`` (deprecated) or ``invoke_llm()`` (preferred); both
authorize against the Gate, record a use, append to the audit chain, and — for
``invoke_llm()`` — keep the decrypted key inside Rust (never crossing PyO3).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import warnings
from typing import Any, Optional

from cage.core import Gate
from cage.core.gate import _raise_mapped
from cage.exceptions import CageViolation
from cage.token import CapabilityToken


def _require_bool(name: str, value: object) -> bool:
    """Loosening switches are typed strictly, never coerced: a config- or
    env-sourced "false" is a truthy string, and bool() on it would silently
    ENABLE a development waiver on a vault its operator believes is fail-closed.
    Refuse the ambiguity at construction instead of guessing in either direction."""
    if not isinstance(value, bool):
        raise CageViolation(
            f"{name} must be a bool, got {type(value).__name__}. Refusing to "
            'coerce: a truthy string such as "false" would otherwise enable a '
            "development waiver on a production vault."
        )
    return value


def _warn_plaintext_consume() -> None:
    # Emitted only when plaintext is actually about to be handed back — a refused
    # consume() must surface as CageViolation, never as this warning.
    warnings.warn(
        "vault.consume() returns a Python str — bytes cross PyO3 and "
        "persist in CPython's interned-string heap. Prefer "
        "vault.invoke_llm() for the Anthropic path. Per-provider Rust "
        "transports replace consume() incrementally.",
        DeprecationWarning,
        stacklevel=3,
    )

logger = logging.getLogger("cage.vault")

# ---------------------------------------------------------------------------
# Rust backend (preferred) — Python fallback (always available)
# ---------------------------------------------------------------------------

try:
    from cage._cage_native import RustGate as _RustBackend  # type: ignore[import]

    _RUST_BACKEND_AVAILABLE = True
    _RUST_IMPORT_ERROR: Optional[ImportError] = None
    logger.debug("cage_backend backend=%s", "rust+chacha20poly1305+zeroize+mlock")
except ImportError as exc:
    _RustBackend = None  # type: ignore[assignment,misc]
    _RUST_BACKEND_AVAILABLE = False
    # Keep the reason so construction can distinguish "not installed" from
    # "present but failed to load" (e.g. an ABI mismatch) and warn accordingly.
    _RUST_IMPORT_ERROR = exc
    logger.debug("cage_backend backend=%s", "python+chacha20")


# ---------------------------------------------------------------------------
# _PythonVaultBackend — used when Rust extension is not built
# ---------------------------------------------------------------------------


class _PythonVaultBackend:
    """
    Pure-Python ChaCha20 secret store — development fallback only.

    Security notes vs Rust backend:
    - No real memory zeroing: `del` drops the reference; CPython GC decides
      when the buffer is collected. The allocator does NOT zero freed memory.
    - No mlock: the key may be swapped to disk under memory pressure.
    - No authentication tag: a memory-writing attacker could corrupt ciphertext
      without detection (raw ChaCha20 vs ChaCha20Poly1305).

    Still substantially better than plaintext: a log-scraper, env dump, or
    serialized heap snapshot will not expose the secret.

    Build the Rust extension for production deployments:
        maturin develop --release
    """

    def __init__(self) -> None:
        import os
        import secrets as _secrets
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

        self._Cipher = Cipher
        self._ChaCha20 = algorithms.ChaCha20
        self._enc_key: bytes = os.urandom(32)
        # name → (nonce: bytes[16], ciphertext: bytes)
        self._store: dict[str, tuple[bytes, bytes]] = {}
        # Bootstrap-token state — mirrors the Rust backend API.
        self._bootstrap_secret: bytes = _secrets.token_bytes(32)
        self._bootstrap_revealed: bool = False

    def store_secret(self, name: str, plaintext: str) -> None:
        import os

        nonce = os.urandom(16)
        raw = plaintext.encode("utf-8")
        cipher = self._Cipher(self._ChaCha20(self._enc_key, nonce), mode=None)
        enc = cipher.encryptor()
        self._store[name] = (nonce, enc.update(raw) + enc.finalize())

    def retrieve_secret(self, name: str) -> str:
        nonce, ct = self._store[name]
        cipher = self._Cipher(self._ChaCha20(self._enc_key, nonce), mode=None)
        dec = cipher.decryptor()
        return (dec.update(ct) + dec.finalize()).decode("utf-8")

    def has_secret(self, name: str) -> bool:
        return name in self._store

    def delete_secret(self, name: str) -> bool:
        return self._store.pop(name, None) is not None

    def unseal(self) -> str:
        if self._bootstrap_revealed:
            raise ValueError(
                "CAGE: vault already unsealed — the bootstrap token can be "
                "revealed exactly once per vault lifetime"
            )
        self._bootstrap_revealed = True
        return self._bootstrap_secret.hex()

    def is_unsealed(self) -> bool:
        return self._bootstrap_revealed

    def verify_bootstrap(self, token: str) -> bool:
        import hmac

        try:
            presented = bytes.fromhex(token)
        except ValueError:
            return False
        if len(presented) != 32:
            return False
        return hmac.compare_digest(presented, self._bootstrap_secret)

    def invoke(self, provider: str, name: str, request_body_json: str) -> str:
        """
        Python-fallback transport — used only when the Rust extension is
        unavailable (dev without maturin build). Anthropic is the only wired
        provider here, mirroring the Rust path; other providers raise.

        Honest limitations vs the Rust path:
        - httpx encodes the auth header into bytes that live in the request
          object for the full request lifetime; we cannot zero them.
        - The decrypted key is briefly a Python `str` between
          `retrieve_secret` and the httpx call — interned, never zeroed.
        - This path is for development only. Production must build the
          Rust extension.
        """
        if provider != "anthropic":
            raise ValueError(
                f"CAGE: provider {provider!r} has no Python-fallback transport; "
                "build the Rust extension or use provider='anthropic'."
            )

        import httpx  # local import — fallback path only

        key = self.retrieve_secret(name)
        try:
            response = httpx.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                content=request_body_json,
                timeout=60.0,
            )
        finally:
            del key  # drop the only Python reference — best-effort
        response.raise_for_status()
        return response.text


# ---------------------------------------------------------------------------
# SecretVault
# ---------------------------------------------------------------------------


class SecretVault:
    """
    Process-lifetime secret store (ring 2).

    Composes a :class:`cage.core.Gate` (token lifecycle + structural refusal +
    audit chain — no secret bytes) and adds secret custody. Backend selection
    is fixed at construction:
      Rust   — ChaCha20Poly1305 AEAD + zeroize-on-drop + mlock + rustls transport
      Python — ChaCha20 (no AEAD, no real zeroize) — development fallback

    The ONLY path to a secret value is consume() (deprecated) or invoke_llm()
    (preferred), which authorize via the Gate, record a use, append to the audit
    chain, and — for invoke_llm() — keep the decrypted key inside Rust.
    """

    def __init__(
        self,
        default_ttl_seconds: int = 300,
        default_max_uses: int = 50,
        strict_mlock: bool = False,
        insecure_dev_mode: bool = False,
        strict_backend: bool = False,
        broker_only_issuance: bool = False,
        allow_plaintext_consume: bool = False,
    ) -> None:
        """
        Parameters
        ----------
        default_ttl_seconds : int
            Default TTL applied to tokens that do not specify one.
        default_max_uses : int
            Default cumulative use ceiling applied to tokens that do not specify.
        strict_mlock : bool
            If True, raises CageViolation at construction if mlock(2) on the
            in-memory keys failed. Recommended for production deployments;
            the default is False to keep dev / smoke environments friendly
            (mlock typically requires CAP_IPC_LOCK or elevated privilege).
            See DEPLOY.md for per-platform CAP_IPC_LOCK setup instructions.
        insecure_dev_mode : bool
            If True, token issuance/revocation no longer require the bootstrap
            token — convenient for local development and tests. The default is
            False (**fail-closed**): a production vault must ``unseal()`` once and
            pass the returned bootstrap to every ``issue_token()`` / ``revoke()``,
            so in-process code cannot mint full-authority tokens on a vault that
            was simply never unsealed.
        strict_backend : bool
            If True, raises CageViolation at construction unless the Rust native
            extension is loaded. Use it in production so the vault cannot silently
            run on the pure-Python fallback (no AEAD, no mlock, an **unsigned,
            in-process-mutable** audit chain, and a key-leaking invoke path) and
            report green as if it were the signed/hardened backend.
        broker_only_issuance : bool
            If True (or env ``CAGE_BROKER_ONLY_ISSUANCE`` is set), ``unseal()`` /
            ``issue_token()`` / ``revoke()`` raise CageViolation: the in-process
            control plane is disabled and tokens must be issued via the
            out-of-process broker (``cage.broker.spawn_broker`` / ``BrokerClient``).
            This is the **secure production default**: it keeps the operator
            authority out of the application process entirely, rather than relying
            on an in-process bootstrap. Token-gated *use* (``invoke_llm``) is
            unaffected — only issuance/revocation move to the broker.
        allow_plaintext_consume : bool
            If True, re-enables the deprecated ``consume()`` path, which returns
            the secret as a Python ``str``. Development ONLY; the default is False
            and a vault left at the default refuses ``consume()`` structurally.
            This is a switch of its own — **not** a facet of ``insecure_dev_mode``
            — so a caller who still needs the leak for a scope with no non-leaking
            operation does not have to waive control-plane auth to get it.
        """
        # Broker-only issuance: disables the in-process control plane so the
        # operator authority never lives in the application process. Opt in via the
        # flag or the CAGE_BROKER_ONLY_ISSUANCE env var (ops-driven enforcement).
        self._broker_only_issuance = bool(broker_only_issuance) or (
            os.environ.get("CAGE_BROKER_ONLY_ISSUANCE", "").strip().lower()
            in ("1", "true", "yes", "on")
        )

        # Both loosening switches are typed strictly, never coerced — see
        # _require_bool. consume() is refused by default; on the Rust backend the
        # core enforces that, and this flag is consulted only on the pure-Python
        # fallback, where it is the sole enforcement point.
        insecure_dev_mode = _require_bool("insecure_dev_mode", insecure_dev_mode)
        self._allow_plaintext_consume = _require_bool(
            "allow_plaintext_consume", allow_plaintext_consume
        )

        if _RUST_BACKEND_AVAILABLE:
            self._backend: _PythonVaultBackend | _RustBackend = _RustBackend(  # type: ignore[valid-type]
                insecure_dev_mode=insecure_dev_mode,
                allow_plaintext_consume=allow_plaintext_consume,
            )
            self._backend_name = "rust"
        else:
            self._backend = _PythonVaultBackend()
            self._backend_name = "python"
            # Surface the silent downgrade loudly (not logger.debug): the fallback
            # has no AEAD/mlock, an unsigned in-process-mutable audit chain, and
            # invoke_llm is unavailable (it would leak the key). Distinguish
            # "not installed" from "present but failed to load".
            if isinstance(_RUST_IMPORT_ERROR, ModuleNotFoundError):
                reason = (
                    "the cage native extension is not installed "
                    "(build it: maturin develop --release)"
                )
            else:
                reason = (
                    "the cage native extension is present but failed to load: "
                    f"{_RUST_IMPORT_ERROR!r}"
                )
            warnings.warn(
                f"SecretVault is using the pure-Python development fallback: {reason}. "
                "This backend has no AEAD/mlock, an UNSIGNED in-process-mutable audit "
                "chain, and invoke_llm is unavailable. Do NOT use it in production; "
                "pass strict_backend=True to fail closed instead.",
                RuntimeWarning,
                stacklevel=2,
            )

        if strict_backend and self._backend_name != "rust":
            raise CageViolation(
                "strict_backend=True requires the cage native extension — the "
                "pure-Python fallback has no signed audit chain, AEAD, or mlock. "
                "Build it via `maturin develop --release` and reinstall."
            )

        # Strict-mlock enforcement. Only the Rust backend actually attempts
        # mlock; the Python fallback has no real memory pinning, so strict
        # mode rejects it outright.
        if strict_mlock:
            if self._backend_name != "rust":
                raise CageViolation(
                    "strict_mlock=True requires the Rust backend (the Python "
                    "fallback cannot pin memory). Build the cage extension "
                    "via `maturin develop --release` and reinstall."
                )
            if not self._backend.mlock_succeeded:
                raise CageViolation(
                    "strict_mlock=True and mlock(2) failed at vault "
                    "construction. The encryption key + bootstrap token "
                    "pages may be paged to disk under memory pressure. "
                    "Grant CAP_IPC_LOCK (Linux) or run with elevated "
                    "privilege. See DEPLOY.md for per-platform setup."
                )

        # Ring 1 — the authority. The native backend doubles as the Gate's
        # hardening backend (canonical audit chain, mlock'd bootstrap, ed25519
        # attestation); the Python fallback provides only bootstrap, so the
        # Gate's audit chain runs in pure Python on that path.
        self._gate = Gate(
            secure_backend=self._backend,
            backend_name=self._backend_name,
            default_ttl_seconds=default_ttl_seconds,
            default_max_uses=default_max_uses,
        )

        # Convenience default for the common AI-agent case: the "llm." scope
        # namespace resolves to a secret stored as "llm_api_key". The core Gate
        # ships no baked-in scope→secret mapping (it is generic and secret-less);
        # this default lives here, in the secret-custody ring. Callers can
        # override or extend it via register_scope_secret().
        self._gate.register_scope_secret("llm.", "llm_api_key")

        # Surface mlock state in the audit chain at boot — gives reviewers /
        # operators a forensic record of whether the process started with
        # memory protection. The structured-log line below mirrors this.
        if self._backend_name == "rust":
            self._gate.append_audit(
                "vault", "mlock_state",
                {"mlock_succeeded": bool(self._backend.mlock_succeeded)},
            )
            if not self._backend.mlock_succeeded:
                logger.warning(
                    "cage_mlock_failed: key pages may be swapped — grant "
                    "CAP_IPC_LOCK for full in-memory protection; see DEPLOY.md",
                )

    @property
    def backend(self) -> str:
        """Returns "rust" or "python" — useful for health-check endpoints."""
        return self._backend_name

    @property
    def audit_chain_signed(self) -> bool:
        """True if the audit chain is the Rust-owned, ed25519-attestable,
        mutation-immune chain; False on the pure-Python fallback (an unsigned,
        in-process-mutable list). On the fallback, :meth:`audit_chain_valid` proves
        only internal consistency — NOT tamper-evidence. Check this (or pass
        ``strict_backend=True``) before relying on the chain as tamper-evident."""
        return self._gate.audit_chain_signed

    @property
    def gate(self) -> Gate:
        """The underlying authority Gate (ring 1). Exposed for advanced callers
        that want to gate non-secret actions with the same token authority."""
        return self._gate

    # ------------------------------------------------------------------
    # Configuration — delegated to the Gate
    # ------------------------------------------------------------------

    def configure(
        self,
        default_ttl_seconds: Optional[int] = None,
        default_max_uses: Optional[int] = None,
    ) -> None:
        """Update default TTL and max-uses applied to new tokens."""
        self._gate.configure(default_ttl_seconds, default_max_uses)

    def register_scope_secret(
        self, scope_prefix: str, secret_name: str, provider: str | None = None
    ) -> None:
        """
        Map a scope prefix to a stored secret name.

        Example:
            vault.register_scope_secret("llm.", "llm_api_key", provider="anthropic")
            vault.register_scope_secret("bedrock.", "aws_session_token")

        Tokens issued with scope "llm.judge" or "llm.evaluate" will resolve
        to the secret stored under "llm_api_key". With ``provider`` the secret is
        pinned: ``invoke_llm`` refuses any other provider for every scope that
        resolves to this secret. The pin is write-once (pinning the same secret to
        another provider raises CageViolation), an unknown provider name raises
        CageViolation, and pinning needs the Rust backend, the only one that
        invokes providers.
        """
        if provider is not None:
            if self._backend_name != "rust":
                raise CageViolation(
                    "a provider pin needs the Rust backend, the only one that invokes providers"
                )
            # Pinned first, so an unknown provider leaves no unpinned mapping behind.
            try:
                self._backend.pin_secret_provider(secret_name, provider)
            except ValueError as exc:
                _raise_mapped(exc)
        self._gate.register_scope_secret(scope_prefix, secret_name)

    # ------------------------------------------------------------------
    # Secret storage
    # ------------------------------------------------------------------

    def store_secret(self, name: str, value: str) -> None:
        """
        Encrypt `value` into the vault under `name`. In the Rust backend the
        plaintext bytes are wrapped in Zeroizing before encryption; the
        ciphertext stays in opaque Rust memory.

        Note: ``value`` is passed in as a Python str — so the plaintext bytes
        exist in CPython's interned-string heap until allocator reuse. For
        bootstrap-from-disk where the plaintext should never become a Python
        str, use :meth:`load_from_env_file` instead.
        """
        self._backend.store_secret(name, value)
        if self._backend_name != "rust":
            # The Rust gate audits "secret_stored" itself (Invariant 4); the
            # pure-Python fallback backend does not, so record it here.
            self._gate.append_audit(
                "vault", "secret_stored",
                {"name": name, "backend": self._backend_name},
            )
        logger.debug("cage_secret_stored name=%s backend=%s", name, self._backend_name)

    def load_from_env_file(
        self,
        path: str,
        secret_names: list[str],
    ) -> int:
        """
        Load secrets from a `.env`-format file directly into vault memory.

        On the Rust backend the plaintext secret values **never cross the
        PyO3 boundary as Python strings** — they are read as bytes inside
        Rust into a ``Zeroizing<Vec<u8>>`` buffer, parsed, encrypted, and
        stored as ciphertext. The buffer is cryptographically zeroed on
        scope exit. This is the canonical bootstrap path for production
        deployments.

        On the Python fallback backend, the plaintext is briefly a Python
        ``str`` — same leak as :meth:`store_secret`. Build the Rust
        extension via ``maturin develop --release`` to close this gap.

        Parameters
        ----------
        path : str
            Filesystem path to a .env file.
        secret_names : list[str]
            Whitelist of keys to load; lines not matching any are ignored.

        Returns
        -------
        int
            Count of secrets successfully loaded.

        Raises
        ------
        ValueError
            If the file cannot be read, or if a whitelisted key appears
            more than once in the file.
        """
        if hasattr(self._backend, "load_from_env_file"):
            loaded = self._backend.load_from_env_file(
                str(path), list(secret_names)
            )
        else:
            # Python fallback — plaintext briefly as Python str (acknowledged).
            from pathlib import Path as _Path

            text = _Path(path).read_text()
            loaded = 0
            seen: set[str] = set()
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                elif val.startswith("'") and val.endswith("'"):
                    val = val[1:-1]
                if key not in secret_names:
                    continue
                if key in seen:
                    raise ValueError(
                        f"CAGE: duplicate key {key!r} in env file {path!r}"
                    )
                seen.add(key)
                self._backend.store_secret(key, val)
                loaded += 1
                del val

        for name in secret_names:
            if self._backend.has_secret(name):
                self._gate.append_audit(
                    "vault", "loaded_from_env",
                    {"name": name, "backend": self._backend_name},
                )

        logger.info(
            "cage_loaded_from_env path=%s loaded=%s backend=%s",
            str(path), loaded, self._backend_name,
        )
        return loaded

    def has_secret(self, name: str) -> bool:
        return self._backend.has_secret(name)

    def delete_secret(self, name: str) -> bool:
        ok = self._backend.delete_secret(name)
        if ok:
            self._gate.append_audit("vault", "secret_deleted", {"name": name})
        return ok

    # ------------------------------------------------------------------
    # Bootstrap auth + token lifecycle — delegated to the Gate
    # ------------------------------------------------------------------

    def unseal(self) -> object:
        """
        Reveal the bootstrap once (see :meth:`cage.core.Gate.unseal`). Capture the
        return value, keep it in a process-protected location, and pass it to every
        subsequent ``issue_token()`` / ``revoke()`` call. Callable once per lifetime.

        On the Rust backend this returns an **opaque ``Bootstrap`` handle**: the
        secret stays in Rust ``Zeroizing`` memory and never crosses PyO3 as a Python
        ``str`` (so it cannot persist in CPython's interned-string heap). On the
        pure-Python fallback (dev only) it returns a hex ``str`` — that backend is
        unhardened and warns accordingly.

        For production, prefer the out-of-process broker (or pass
        ``broker_only_issuance=True``), where the bootstrap never enters this process.
        """
        if self._broker_only_issuance:
            raise CageViolation(
                "in-process unseal() is disabled (broker_only_issuance). Issue tokens "
                "via the out-of-process broker — cage.broker.spawn_broker / "
                "BrokerClient — so the operator authority never lives in this process."
            )
        if self._backend_name != "rust":
            warnings.warn(
                "vault.unseal() on the pure-Python fallback returns the bootstrap as "
                "a Python str — it persists un-zeroable in CPython's heap. Build the "
                "Rust extension (maturin develop --release) for the opaque, "
                "zero-on-drop Bootstrap handle, or issue via the broker.",
                DeprecationWarning,
                stacklevel=2,
            )
        return self._gate.unseal()

    def is_unsealed(self) -> bool:
        """True if ``unseal()`` has been called on this vault."""
        return self._gate.is_unsealed()

    def issue_token(
        self,
        scope: str,
        context: str,
        ttl_seconds: Optional[int] = None,
        max_uses: Optional[int] = None,
        bootstrap_token: Optional[object] = None,
    ) -> CapabilityToken:
        """Issue a new CapabilityToken (see :meth:`cage.core.Gate.issue_token`).
        ``bootstrap_token`` is the value returned by :meth:`unseal` (an opaque
        ``Bootstrap`` handle on the Rust backend)."""
        if self._broker_only_issuance:
            raise CageViolation(
                "in-process issue_token() is disabled (broker_only_issuance). Issue "
                "tokens via the out-of-process broker — cage.broker.spawn_broker / "
                "BrokerClient.issue_token — so the operator authority never lives in "
                "this process."
            )
        return self._gate.issue_token(
            scope, context, ttl_seconds, max_uses, bootstrap_token
        )

    def revoke(self, token_id: str, bootstrap_token: Optional[object] = None) -> bool:
        """Immediately revoke a token before its TTL expires. Fail-closed: requires
        the bootstrap (the value from ``unseal()``) unless the vault was constructed
        with ``insecure_dev_mode``."""
        if self._broker_only_issuance:
            raise CageViolation(
                "in-process revoke() is disabled (broker_only_issuance). Revoke via "
                "the out-of-process broker — cage.broker.spawn_broker / BrokerClient."
            )
        return self._gate.revoke(token_id, bootstrap_token)

    # ------------------------------------------------------------------
    # Secret access — token-gated
    # ------------------------------------------------------------------

    def consume(self, token: CapabilityToken, scope: str) -> str:
        """
        DEPRECATED and **dev-only** — use `invoke_llm()` instead for LLM
        provider calls.

        Returns the cleartext secret as a Python `str`, which means the
        bytes cross the Rust/Python boundary and persist in CPython's
        interned-string heap. This is the plaintext-str leak that the
        CAGE design forbids on critical paths, so it is **refused by
        default** — it runs only when the vault was constructed with
        ``allow_plaintext_consume=True``.

        Kept available (behind that opt-in) for non-LLM scopes and for
        non-Anthropic providers until per-provider Rust transport adapters land;
        in production such scopes have no ``consume`` path and are unsupported
        until a non-leaking operation exists for them. Callers MUST pass the
        return value inline and MUST NOT assign to a variable.
        """
        if self._backend_name == "rust":
            # The core is the enforcement point: it authorizes, then refuses (and
            # audits) unless the gate was constructed with
            # allow_plaintext_consume=True; when it is on, authorize + charge +
            # audit + retrieve are one operation co-located with the secret. The
            # plaintext str still crosses PyO3 (the deprecated leak), but it is
            # never reachable as an *un*gated bypass.
            try:
                value = self._backend.consume(token.token_id, scope)
            except ValueError as exc:
                _raise_mapped(exc)
            _warn_plaintext_consume()
            return value

        # Python fallback (dev only).
        # Structural refusal (Invariant 6): authorize against the gate's own
        # record, never the caller-supplied object's fields.
        canonical = self._gate.authorize(token, scope)

        if not self._allow_plaintext_consume:
            # The only enforcement point on the fallback (its backend store is
            # ungated by design). Audited like every other refusal, tagged with the
            # writing layer because it arrives through the generic append channel.
            self._gate.append_audit(
                canonical.token_id,
                "consume_refused_plaintext_disabled",
                {"scope": scope, "layer": "facade"},
            )
            raise CageViolation(
                "vault.consume() is refused — it returns a Python str, leaking "
                "plaintext into CPython's heap. Use invoke_llm() for LLM scopes "
                "(the key never crosses PyO3) or the out-of-process broker "
                "(BrokerClient.sign() for signing scopes; the cage.adapters "
                "drop-ins for LLM calls); a scope with neither is not "
                "production-supported yet."
            )

        secret_key = self._gate.scope_to_secret(scope)
        if not self._backend.has_secret(secret_key):
            raise CageViolation(
                f"No secret loaded for scope={scope!r} "
                f"(expected stored name {secret_key!r})."
            )

        # Increment cumulative use counter — Invariant 3
        canonical = self._gate.record_use(canonical)

        self._gate.append_audit(
            canonical.token_id, "consumed",
            {"scope": scope, "use_count": canonical.use_count},
        )

        _warn_plaintext_consume()
        return self._backend.retrieve_secret(secret_key)

    async def invoke_llm(
        self,
        token: CapabilityToken,
        request_body: dict[str, Any],
        provider: str = "anthropic",
    ) -> dict[str, Any]:
        """
        Token-gated LLM invocation — replaces `consume()` for LLM provider calls.

        Authorizes the token, increments use_count, appends an audit entry,
        then delegates to the provider's transport which performs the HTTPS
        call with the decrypted key held only inside `Zeroizing<Vec<u8>>`. The
        decrypted key never crosses the PyO3 boundary, so no plaintext bytes
        enter CPython's heap on this path — a guarantee that holds **only on the
        Rust backend**, so ``invoke_llm`` raises CageViolation on any other backend
        rather than fall back to a key-leaking path.

        Parameters
        ----------
        token : a CapabilityToken issued by this vault.
        request_body : the provider's Messages/Chat request body, e.g.
            {"model": "claude-haiku-4-5", "max_tokens": 200,
             "system": "...", "messages": [...]}
        provider : transport selector. "anthropic" and "openai" are wired.
            Other providers (bedrock, azure-openai, vllm) raise until their
            adapter lands. The credential resolved for the token's scope is sent to the
            selected provider.

        Returns the parsed JSON response from the provider.
        Raises CageViolation on invalid token or on a provider other than the one
        the secret is pinned to (see ``register_scope_secret``), ValueError on
        unknown provider or transport/HTTP error.
        """
        body_json = json.dumps(request_body)

        # Fail closed off the Rust backend: invoke_llm's contract is that the
        # decrypted key never crosses PyO3, which holds ONLY on the Rust backend.
        # The pure-Python fallback would inject the key as a Python str — the exact
        # north-star violation this method exists to prevent — so refuse rather than
        # silently leak. The fallback is not a production backend: consume() is
        # dev-only there too, behind allow_plaintext_consume, and its in-process
        # store is ungated by design (strict_backend=True refuses the fallback).
        if self._backend_name != "rust":
            raise CageViolation(
                "invoke_llm() requires the Rust backend for its zero-plaintext "
                "guarantee (the decrypted key never crosses PyO3). The pure-Python "
                "fallback would leak the key as a Python str — refusing. Build the "
                "cage native extension (maturin develop --release)."
            )

        # The Rust gate runs authorize + reserve(charge) + network + settle as one
        # operation: it charges the use BEFORE the write, releases the GIL across the
        # TLS round-trip (so concurrent invoke_llm calls overlap and a max_uses=1
        # token can never be double-spent), refunds only on a pre-send failure, and
        # keeps the decrypted key inside Rust.
        try:
            response_text = await asyncio.to_thread(
                self._backend.invoke, token.token_id, provider, body_json
            )
        except ValueError as exc:
            _raise_mapped(exc)
        return json.loads(response_text)

    # ------------------------------------------------------------------
    # Audit chain + attestation — delegated to the Gate
    # ------------------------------------------------------------------

    def audit_chain_valid(self) -> bool:
        """Verify the entire Merkle audit chain from genesis."""
        return self._gate.audit_chain_valid()

    def get_audit_log(self) -> list[dict]:
        """Return a *fresh copy* of the audit log on every call."""
        return self._gate.get_audit_log()

    def audit_head(self) -> str:
        """Current chain head hash (SHA-256, hex)."""
        return self._gate.audit_head()

    def attestation_payload(self) -> dict[str, str]:
        """Generate a signed ed25519 attestation envelope over the audit head
        (requires the Rust backend)."""
        return self._gate.attestation_payload()

    def attestation_public_key(self) -> str:
        """Base64-encoded ed25519 verification key for attestation envelopes."""
        return self._gate.attestation_public_key()

    def checkpoint(self) -> dict:
        """Signed checkpoint over the current audit (head, len) to anchor off-box
        (Rekor). Anchoring it and later calling :meth:`verify_audit_chain_extends`
        is what makes a truncation/rewrite of the chain detectable — the in-memory
        :meth:`audit_chain_valid` proves only internal consistency."""
        return self._gate.checkpoint()

    def verify_audit_chain_extends(
        self, anchored_head: str, anchored_len: int, signature_b64: str
    ) -> bool:
        """Verify the chain extends an externally-held signed checkpoint (a
        truncation below it, or a rewrite of the anchored prefix, fails closed)."""
        return self._gate.verify_audit_chain_extends(
            anchored_head, anchored_len, signature_b64
        )

    def record_attestation(
        self,
        rekor_uuid: str,
        inclusion_proof: Optional[dict[str, Any]] = None,
        anchored_head: Optional[str] = None,
    ) -> None:
        """Record that the audit chain head was anchored to an external
        transparency log (typically Sigstore Rekor)."""
        self._gate.record_attestation(rekor_uuid, inclusion_proof, anchored_head)


# ---------------------------------------------------------------------------
# Module-level singleton — the standard import target for callers
# ---------------------------------------------------------------------------

vault = SecretVault()
