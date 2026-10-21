"""
Gate — the universal authority ring of CAGE.

A Gate issues short-lived, scope-bound, use-counted, revocable
``CapabilityToken``s and *structurally refuses* any action whose token it did
not itself issue or whose token is no longer valid. Every lifecycle event is
recorded in an append-only Merkle audit chain.

The Gate handles **no secret bytes** — it operates purely on token metadata.
This is what makes it the thing every project can import: it gates any action,
secret or not.

Hardening delegation
--------------------
A Gate optionally takes a ``secure_backend`` (the Rust extension, supplied by
``cage.vault.Vault``). When present, the audit chain, bootstrap-token custody,
and ed25519 attestation are delegated to Rust (tamper-resistant, mlock'd,
canonical chain immune to Python-side mutation). When absent — a standalone
``Gate()`` — the same operations run in pure Python:

  * the audit chain is a Python list (Python-mutable; a known fallback limit),
  * the bootstrap token is held as a Python ``bytes`` (no mlock),
  * ed25519 attestation is unavailable.

Either way the *authorization* logic is identical and lives only here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Optional

from cage.exceptions import CageViolation
from cage.token import CapabilityToken

logger = logging.getLogger("cage.core")


def _token_from_rust(d: dict) -> CapabilityToken:
    """Reconstruct a CapabilityToken from the Rust gate's token dict. Live state
    (use_count, revoked) is always the gate's, never a caller handle."""
    return CapabilityToken(
        scope=d["scope"],
        context=d["context"],
        token_id=d["token_id"],
        issued_at=datetime.fromtimestamp(d["issued_at_unix"], tz=timezone.utc),
        ttl_seconds=d["ttl_seconds"],
        max_uses=d["max_uses"],
        use_count=d["use_count"],
        revoked=d["revoked"],
    )


def _raise_mapped(exc: ValueError):
    """Map a cage_core error surfaced by the native gate as ValueError: a structural
    refusal ("CAGE refused:" prefix) becomes CageViolation; transport / value errors
    propagate unchanged."""
    if str(exc).startswith("CAGE refused:"):
        raise CageViolation(str(exc)) from exc
    raise exc


class Gate:
    """Capability-token authority + append-only audit chain. Handles no secrets.

    Parameters
    ----------
    secure_backend :
        Optional hardening backend (the Rust extension). When it exposes
        ``append_audit`` / ``unseal`` / ``attestation_payload`` etc., those
        operations are delegated to it; otherwise pure-Python fallbacks are
        used. ``cage.vault.Vault`` passes its native backend here.
    backend_name :
        Label recorded in audit entries that name the backend ("rust",
        "python", or "none" for a standalone gate).
    default_ttl_seconds, default_max_uses :
        Defaults applied to tokens that do not specify their own.
    """

    def __init__(
        self,
        *,
        secure_backend: Optional[Any] = None,
        backend_name: str = "none",
        default_ttl_seconds: int = 300,
        default_max_uses: int = 50,
    ) -> None:
        self._secure_backend = secure_backend
        self._backend_name = backend_name

        # When the backend is the native Gate (the Rust authority), the token
        # lifecycle + structural refusal run there atomically — co-located with the
        # secret, so no in-process Python can reach a secret without a valid token.
        # This Gate then delegates issue/authorize/record_use/revoke/scope to it.
        # A standalone Gate (no backend) keeps the pure-Python authority below.
        self._has_rust_authority = hasattr(self._secure_backend, "issue_token")

        self._tokens: dict[str, CapabilityToken] = {}  # token_id → token
        self._revoked: set[str] = set()                 # revoked token_ids
        self._audit_head: str = "0" * 64                # SHA-256 genesis hash
        self._audit_log: list[dict] = []

        self._default_ttl_seconds = default_ttl_seconds
        self._default_max_uses = default_max_uses

        # Scope-prefix → secret-name registry. Empty by default: the core Gate
        # is generic and carries no domain-specific mapping. Callers register
        # their own via register_scope_secret(); the LLM convenience default
        # ("llm." → "llm_api_key") lives in the secret-custody ring
        # (cage.vault.SecretVault), not here.
        self._scope_secret_registry: dict[str, str] = {}

        # Pure-Python bootstrap state — used only when the secure backend does
        # not provide its own (mlock'd) bootstrap token.
        self._has_backend_bootstrap = hasattr(self._secure_backend, "unseal")
        if not self._has_backend_bootstrap:
            self._bootstrap_secret: bytes = secrets.token_bytes(32)
            self._bootstrap_revealed: bool = False

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure(
        self,
        default_ttl_seconds: Optional[int] = None,
        default_max_uses: Optional[int] = None,
    ) -> None:
        """Update default TTL and max-uses applied to new tokens."""
        if default_ttl_seconds is not None:
            self._default_ttl_seconds = default_ttl_seconds
        if default_max_uses is not None:
            self._default_max_uses = default_max_uses

    def register_scope_secret(self, scope_prefix: str, secret_name: str) -> None:
        """
        Map a scope prefix to a stored secret name.

        Example:
            gate.register_scope_secret("llm.", "llm_api_key")
            gate.register_scope_secret("bedrock.", "aws_session_token")

        Tokens issued with scope "llm.judge" or "llm.evaluate" will resolve
        to the secret stored under "llm_api_key".
        """
        if self._has_rust_authority:
            # Resolution happens in Rust (invoke/consume/sign), so the registry
            # must live there.
            self._secure_backend.register_scope_secret(scope_prefix, secret_name)
            return
        self._scope_secret_registry[scope_prefix] = secret_name

    # ------------------------------------------------------------------
    # Bootstrap auth — close the "any in-process code can mint tokens" gap
    # ------------------------------------------------------------------

    def unseal(self) -> object:
        """
        Reveal the bootstrap once. Capture the return value, keep it in a
        process-protected location (never logged or serialized), and pass it to
        every subsequent ``issue_token()`` / ``revoke()`` call.

        Return type depends on the backend:
          * Rust authority — an **opaque ``Bootstrap`` handle**: the secret stays
            in Rust ``Zeroizing`` memory and never becomes a Python ``str``.
          * pure-Python fallback (dev only) — a hex ``str`` (the fallback is
            unhardened: no AEAD/mlock/zeroize).

        After ``unseal()``, any ``issue_token()`` without the bootstrap raises
        :class:`CageViolation`. Callable exactly once per gate lifetime.
        """
        if self._has_backend_bootstrap:
            # The Rust gate audits "unsealed" itself (Invariant 4) — don't double it.
            bootstrap = self._secure_backend.unseal()
        else:
            if self._bootstrap_revealed:
                raise ValueError(
                    "CAGE: vault already unsealed — the bootstrap token can be "
                    "revealed exactly once per vault lifetime"
                )
            self._bootstrap_revealed = True
            bootstrap = self._bootstrap_secret.hex()
            self.append_audit("vault", "unsealed", {"backend": self._backend_name})

        logger.info("cage_vault_unsealed backend=%s", self._backend_name)
        return bootstrap

    def is_unsealed(self) -> bool:
        """True if ``unseal()`` has been called on this gate."""
        if self._has_backend_bootstrap:
            return self._secure_backend.is_unsealed()
        return self._bootstrap_revealed

    def _verify_bootstrap(self, token: str) -> bool:
        if self._has_backend_bootstrap:
            return self._secure_backend.verify_bootstrap(token)
        try:
            presented = bytes.fromhex(token)
        except ValueError:
            return False
        if len(presented) != 32:
            return False
        return hmac.compare_digest(presented, self._bootstrap_secret)

    # ------------------------------------------------------------------
    # Token lifecycle
    # ------------------------------------------------------------------

    def issue_token(
        self,
        scope: str,
        context: str,
        ttl_seconds: Optional[int] = None,
        max_uses: Optional[int] = None,
        bootstrap_token: Optional[object] = None,
    ) -> CapabilityToken:
        """
        Issue a new CapabilityToken. Defaults from gate config.

        With the Rust authority, issuance is **fail-closed**: a valid bootstrap
        token (obtained once via ``unseal()``) is required unless the vault was
        constructed with ``insecure_dev_mode``. The pure-Python fallback below keeps
        the legacy behaviour (bootstrap required only after unseal).
        """
        if self._has_rust_authority:
            if isinstance(bootstrap_token, str):
                # On the Rust authority the bootstrap is an opaque handle from
                # unseal(), never a string — a str here is a forged/legacy value.
                raise CageViolation(
                    "issue_token expects the opaque Bootstrap handle returned by "
                    "unseal(), not a string. The bootstrap secret never crosses "
                    "into Python on the Rust backend."
                )
            try:
                d = self._secure_backend.issue_token(
                    scope, context, ttl_seconds, max_uses, bootstrap_token
                )
            except ValueError as exc:
                _raise_mapped(exc)
            logger.debug(
                "cage_token_issued token_id=%s… scope=%s context=%s",
                d["token_id"][:8], scope, context,
            )
            return _token_from_rust(d)

        if self.is_unsealed():
            if bootstrap_token is None:
                self.append_audit(
                    "vault", "issuance_rejected_no_bootstrap",
                    {"scope": scope, "context": context},
                )
                raise CageViolation(
                    "issue_token requires bootstrap_token after the vault has "
                    "been unsealed. Pass the value returned from vault.unseal() "
                    "via the bootstrap_token= parameter."
                )
            if not self._verify_bootstrap(bootstrap_token):
                self.append_audit(
                    "vault", "issuance_rejected_bad_bootstrap",
                    {"scope": scope, "context": context},
                )
                raise CageViolation(
                    "Invalid bootstrap token presented to issue_token."
                )

        token = CapabilityToken(
            scope=scope,
            context=context,
            ttl_seconds=ttl_seconds if ttl_seconds is not None
                        else self._default_ttl_seconds,
            max_uses=max_uses if max_uses is not None
                     else self._default_max_uses,
        )
        self._tokens[token.token_id] = token
        self.append_audit(
            token.token_id, "issued",
            {"scope": scope, "context": context, "max_uses": token.max_uses},
        )
        logger.debug(
            "cage_token_issued token_id=%s… scope=%s context=%s",
            token.token_id[:8], scope, context,
        )
        return token

    def revoke(self, token_id: str, bootstrap_token: Optional[object] = None) -> bool:
        """
        Immediately revoke a token before its TTL expires.

        Appends a 'revoked' entry to the audit chain so the revocation is
        tamper-evidently recorded. Subsequent authorize() calls with this
        token raise CageViolation regardless of TTL/use_count.

        With the Rust authority, revocation is **fail-closed** at parity with
        issuance: ``bootstrap_token`` is required (unless ``insecure_dev_mode``),
        so a rogue holder of only a token_id cannot revoke another agent's token.
        """
        if self._has_rust_authority:
            if isinstance(bootstrap_token, str):
                raise CageViolation(
                    "revoke expects the opaque Bootstrap handle returned by "
                    "unseal(), not a string. The bootstrap secret never crosses "
                    "into Python on the Rust backend."
                )
            try:
                return self._secure_backend.revoke(token_id, bootstrap_token)
            except ValueError as exc:
                _raise_mapped(exc)

        if token_id in self._revoked:
            return False

        token = self._tokens.get(token_id)
        if token is None:
            return False

        # Tokens are frozen — advance state by replacing the canonical record.
        self._tokens[token_id] = replace(token, revoked=True)
        self._revoked.add(token_id)
        self.append_audit(
            token_id, "revoked",
            {"scope": token.scope, "context": token.context,
             "use_count": token.use_count},
        )
        logger.info(
            "cage_token_revoked token_id=%s… scope=%s",
            token_id[:8], token.scope,
        )
        return True

    # ------------------------------------------------------------------
    # Structural refusal — the authority decision
    # ------------------------------------------------------------------

    def authorize(
        self,
        token: CapabilityToken,
        scope: Optional[str] = None,
        context: Optional[str] = None,
    ) -> CapabilityToken:
        """Resolve and validate this gate's canonical record for ``token``.

        A CapabilityToken is only a handle: its ``token_id`` identifies a
        record this gate issued and holds authoritatively. The caller-supplied
        object's other fields (``scope``, ``max_uses``, ``ttl_seconds``,
        ``issued_at``, ``use_count``, ``revoked``) are NOT trusted — an
        attacker can construct or hold a CapabilityToken. Structural refusal
        (Invariant 6) requires that only tokens this gate actually issued, and
        only within their issued bounds, are authorized.

        ``scope`` is the scope the caller is requesting; when None the token's
        own issued scope is used. Either way the check runs against the
        canonical record, never the caller's object.

        ``context``, when provided, must constant-time-match the token's issued
        context — a relying party binds a capability to an external identity
        (e.g. a verified OIDC subject or a SPIFFE/WIMSE workload id) by issuing
        with that identity as ``context`` and presenting it here, so a token_id
        stolen without its context is refused. Opt-in defense-in-depth.

        Returns the canonical token on success; raises CageViolation otherwise.
        Note: this does NOT increment the use counter — call :meth:`record_use`
        once the gated action is committed.
        """
        if self._has_rust_authority:
            # The Rust gate validates against its own canonical record and audits
            # any refusal — no double-audit here.
            try:
                d = self._secure_backend.authorize(token.token_id, scope, context)
            except ValueError as exc:
                _raise_mapped(exc)
            return _token_from_rust(d)

        canonical = self._tokens.get(token.token_id)
        if canonical is None:
            self.append_audit(
                str(token.token_id), "rejected_unknown_token",
                {"reason": "token not issued by this vault"},
            )
            raise CageViolation(
                f"Token {str(token.token_id)[:8]}… was not issued by this "
                "vault. Tokens must be obtained from vault.issue_token() and "
                "cannot be fabricated by the caller."
            )

        requested = scope if scope is not None else canonical.scope
        if not canonical.is_valid(requested):
            elapsed = (
                datetime.now(timezone.utc) - canonical.issued_at
            ).total_seconds()
            self.append_audit(
                canonical.token_id, "rejected",
                {
                    "scope_requested": requested,
                    "scope_token": canonical.scope,
                    "use_count": canonical.use_count,
                    "revoked": canonical.revoked,
                    "elapsed_s": round(elapsed, 1),
                },
            )
            raise CageViolation(
                f"Token {canonical.token_id[:8]}… invalid for "
                f"scope={requested!r}: revoked={canonical.revoked}, "
                f"uses={canonical.use_count}/{canonical.max_uses}, "
                f"elapsed={elapsed:.0f}s/{canonical.ttl_seconds}s"
            )

        # Optional context binding (parity with the Rust authority): a presented
        # context must constant-time-match the token's issued context, so a token
        # bound to an external identity cannot be exercised on another. Opt-in.
        if context is not None and not hmac.compare_digest(context, canonical.context):
            self.append_audit(
                canonical.token_id, "rejected_context_mismatch",
                {"scope_requested": requested},
            )
            raise CageViolation(
                f"Token {canonical.token_id[:8]}… presented context does not "
                "match its issued context."
            )
        return canonical

    def record_use(self, canonical: CapabilityToken) -> CapabilityToken:
        """Advance the use counter on this gate's canonical record.

        Tokens are frozen, so the stored record is replaced with an updated
        copy. The caller's handle is intentionally not mutated — the gate is
        the sole authority on live use_count.
        """
        if self._has_rust_authority:
            try:
                d = self._secure_backend.record_use(canonical.token_id)
            except ValueError as exc:
                _raise_mapped(exc)
            return _token_from_rust(d)
        updated = replace(canonical, use_count=canonical.use_count + 1)
        self._tokens[updated.token_id] = updated
        return updated

    def authorize_and_charge(
        self,
        token: CapabilityToken,
        scope: Optional[str] = None,
        context: Optional[str] = None,
    ) -> CapabilityToken:
        """Authorize ``token`` and immediately charge one use — the common path.

        Equivalent to :meth:`authorize` followed by :meth:`record_use`, returning
        the charged canonical token. Use this whenever the gated action commits
        unconditionally once authorized: it removes the footgun of authorizing but
        forgetting to :meth:`record_use`, which would silently let a token exceed
        its ``max_uses``. On refusal it raises CageViolation and charges nothing.

        Prefer the two-step :meth:`authorize` / :meth:`record_use` only when you
        must gate *before* an action that may not run, and charge the use solely
        once it commits.
        """
        canonical = self.authorize(token, scope, context)
        return self.record_use(canonical)

    def scope_to_secret(self, scope: str) -> str:
        """Resolve a scope to its registered secret name.

        Longest matching prefix wins, so resolution is deterministic regardless
        of the order in which prefixes were registered (e.g. "llm.judge." takes
        precedence over "llm.").
        """
        if self._has_rust_authority:
            try:
                return self._secure_backend.scope_to_secret(scope)
            except ValueError as exc:
                _raise_mapped(exc)
        matches = []
        for prefix, name in self._scope_secret_registry.items():
            # Anchor on a namespace boundary: a registered "llm" / "llm." matches
            # "llm" and "llm.<anything>", never "llmadmin" / "llm-evil".
            base = prefix[:-1] if prefix.endswith(".") else prefix
            if scope == base or scope.startswith(base + "."):
                matches.append((prefix, name))
        if not matches:
            raise CageViolation(
                f"Unknown scope namespace in: {scope!r}. "
                f"Register via vault.register_scope_secret(prefix, secret_name)."
            )
        _, name = max(matches, key=lambda kv: len(kv[0]))
        return name

    # ------------------------------------------------------------------
    # Audit chain
    # ------------------------------------------------------------------

    @property
    def audit_chain_signed(self) -> bool:
        """True if the audit chain is delegated to the Rust-owned signed chain
        (mutation-immune, ed25519-attestable); False for the pure-Python fallback,
        whose chain is an in-process-mutable list and whose :meth:`audit_chain_valid`
        proves only internal consistency, not append-only-ness. An explicit marker so
        a green :meth:`audit_chain_valid` on the fallback cannot be mistaken for the
        signed chain."""
        return hasattr(self._secure_backend, "attestation_payload")

    def audit_chain_valid(self) -> bool:
        """
        Verify the entire Merkle audit chain from genesis.

        With a secure backend, this calls into the Rust-owned canonical chain:
        Python-side mutation of any returned snapshot does NOT affect this
        verification — the source of truth is in Rust. Without one, it verifies
        the in-Python list, which is Python-mutable: a green result there proves
        only internal consistency, NOT tamper-evidence (an in-process adversary can
        rewrite the list and re-stitch the hashes). Check :attr:`audit_chain_signed`
        to tell the two apart.
        """
        if hasattr(self._secure_backend, "verify_audit_chain"):
            return self._secure_backend.verify_audit_chain()
        prev = "0" * 64
        for entry in self._audit_log:
            check = {k: v for k, v in entry.items() if k != "hash"}
            check["prev_hash"] = prev
            entry_json = json.dumps(check, sort_keys=True)
            expected = hashlib.sha256(
                (prev + entry_json).encode()
            ).hexdigest()
            if expected != entry["hash"]:
                return False
            prev = entry["hash"]
        return True

    def get_audit_log(self) -> list[dict]:
        """Return a *fresh copy* of the audit log on every call.

        With a secure backend the canonical chain lives in Rust memory; this
        materializes a Python-side snapshot whose mutation has no effect on the
        canonical chain or on :meth:`audit_chain_valid`.
        """
        if hasattr(self._secure_backend, "audit_log_entries"):
            entries = self._secure_backend.audit_log_entries()
            out: list[dict] = []
            for e in entries:
                out.append({
                    "seq": e["seq"],
                    "entity_id": e["entity_id"],
                    "event": e["event"],
                    "data": json.loads(e["data_json"]),
                    "timestamp": e["timestamp"],
                    "prev_hash": e["prev_hash"],
                    "hash": e["hash"],
                })
            return out
        return list(self._audit_log)

    def audit_head(self) -> str:
        """Current chain head hash (SHA-256, hex). Useful for periodic external
        attestation (e.g. Sigstore Rekor anchoring)."""
        if hasattr(self._secure_backend, "audit_head"):
            return self._secure_backend.audit_head()
        return self._audit_head

    def append_audit(self, entity_id: str, event: str, data: dict) -> None:
        """
        Append an entry to the Merkle hash chain.

        With a secure backend, delegates to the Rust-owned canonical chain. The
        caller passes ``data`` as a regular dict; serialization to canonical
        JSON happens inside Rust for the hash. Without one, hashes in Python
        (``json.dumps(..., sort_keys=True)``) and appends to the Python list
        (Python-mutable — known fallback limitation).

        Canonicalization contract
        -------------------------
        Each backend hashes *and* verifies its own chain, so a chain is always
        internally consistent — the Rust and Python forms do NOT need to (and do
        not) agree byte-for-byte. They differ even for plain strings/ints: the
        Rust core (serde_json) emits compact JSON, while this Python fallback
        uses ``json.dumps(..., sort_keys=True)`` with default ``", "`` / ``": "``
        spacing. So an external or cross-backend re-verifier must reproduce the
        *active* backend's exact form — for the Rust core that is
        ``json.dumps(obj, sort_keys=True, separators=(",", ":"))``. Either way,
        avoid floats in audit ``data``: their formatting (exponent, trailing
        zeros, signed zero) is not guaranteed to round-trip even within a single
        backend's re-verification.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        if hasattr(self._secure_backend, "append_audit"):
            data_json = json.dumps(data)
            self._secure_backend.append_audit(entity_id, event, data_json, timestamp)
            return

        entry: dict = {
            "entity_id": entity_id,
            "event": event,
            "data": data,
            "timestamp": timestamp,
            "prev_hash": self._audit_head,
        }
        entry_json = json.dumps(entry, sort_keys=True)
        new_hash = hashlib.sha256(
            (self._audit_head + entry_json).encode()
        ).hexdigest()
        entry["hash"] = new_hash
        self._audit_log.append(entry)
        self._audit_head = new_hash

    # ------------------------------------------------------------------
    # Audit-head attestation — Rekor anchoring (requires secure backend)
    # ------------------------------------------------------------------

    def attestation_payload(self) -> dict[str, str]:
        """
        Generate a signed attestation envelope over the current audit head
        (ed25519). Suitable for submission to Sigstore Rekor or any append-only
        transparency log. After submission, call :meth:`record_attestation`.

        Raises CageViolation if no secure backend provides ed25519 signing.
        """
        if not hasattr(self._secure_backend, "attestation_payload"):
            raise CageViolation(
                "attestation_payload requires the Rust backend "
                "(ed25519 signing not implemented in the Python fallback)"
            )
        # The timestamp is generated server-side inside the Rust gate (never
        # caller-supplied), so it cannot be backdated/forward-dated.
        envelope_json = self._secure_backend.attestation_payload()
        return json.loads(envelope_json)

    def attestation_public_key(self) -> str:
        """Base64-encoded ed25519 verification key for attestation envelopes."""
        if not hasattr(self._secure_backend, "attestation_public_key"):
            raise CageViolation(
                "attestation_public_key requires the Rust backend"
            )
        return self._secure_backend.attestation_public_key

    def checkpoint(self) -> dict:
        """Produce a signed checkpoint over the current audit (head, len) — the
        artifact to anchor off-box (e.g. Sigstore Rekor). The in-memory
        :meth:`audit_chain_valid` proves only internal consistency; anchoring a
        checkpoint and later calling :meth:`verify_audit_chain_extends` against it is
        what makes a truncation/rewrite detectable. Requires the Rust backend."""
        if not hasattr(self._secure_backend, "checkpoint"):
            raise CageViolation("checkpoint requires the Rust backend")
        return json.loads(self._secure_backend.checkpoint())

    def verify_audit_chain_extends(
        self, anchored_head: str, anchored_len: int, signature_b64: str
    ) -> bool:
        """Verify the current chain EXTENDS an externally-held signed checkpoint:
        the signature verifies under this vault's audit key, the chain is at least as
        long as the anchor, and the anchored head sits at the anchored position — so
        a truncation below it or a rewrite of the prefix fails closed. Requires the
        Rust backend."""
        if not hasattr(self._secure_backend, "verify_audit_chain_extends"):
            raise CageViolation(
                "verify_audit_chain_extends requires the Rust backend"
            )
        return self._secure_backend.verify_audit_chain_extends(
            anchored_head, anchored_len, signature_b64
        )

    def record_attestation(
        self,
        rekor_uuid: str,
        inclusion_proof: Optional[dict[str, Any]] = None,
        anchored_head: Optional[str] = None,
    ) -> None:
        """
        Record that the audit chain head was anchored to an external
        transparency log (typically Sigstore Rekor). Appends a ``rekor_anchor``
        entry so the anchor itself becomes tamper-evident under future
        verification.
        """
        head = anchored_head if anchored_head is not None else self.audit_head()
        self.append_audit(
            "vault", "rekor_anchor",
            {
                "rekor_uuid": rekor_uuid,
                "anchored_head": head,
                "inclusion_proof": inclusion_proof or {},
            },
        )
        logger.info(
            "cage_rekor_anchored rekor_uuid=%s anchored_head=%s…",
            rekor_uuid, head[:16],
        )
