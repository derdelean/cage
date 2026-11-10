"""
Smoke tests for CAGE — verify the basic vault lifecycle works on whichever
backend (Rust or Python) is loaded.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from cage import CapabilityToken, CageViolation, SecretVault


def _rust_only(v: SecretVault) -> None:
    if v.backend != "rust":
        pytest.skip("the gated sign() op is Rust-backend only")


def _signing_vault() -> SecretVault:
    """A dev vault with an HMAC key registered under the ``sign.`` namespace."""
    v = SecretVault(insecure_dev_mode=True)
    _rust_only(v)
    v.store_secret("hmac_key", "k-test-12345")
    v.register_scope_secret("sign.", "hmac_key")
    return v


def test_backend_is_rust_or_python() -> None:
    v = SecretVault(insecure_dev_mode=True)
    assert v.backend in ("rust", "python")


def test_store_and_token_lifecycle() -> None:
    v = SecretVault(insecure_dev_mode=True)
    v.store_secret("llm_api_key", "sk-test-12345")
    assert v.has_secret("llm_api_key")

    token = v.issue_token(
        scope="llm.evaluate",
        context="test-run",
        ttl_seconds=60,
        max_uses=3,
    )
    assert token.is_valid("llm.evaluate")
    assert token.remaining_uses() == 3


def test_sign_increments_use_count() -> None:
    v = _signing_vault()
    token = v.issue_token(scope="sign.invoice", context="t", max_uses=2)

    sig1 = v.sign(token, b"invoice #1")
    sig2 = v.sign(token, b"invoice #1")
    assert sig1 == sig2
    assert len(sig1) == 64

    # The third use exceeds max_uses.
    with pytest.raises(CageViolation):
        v.sign(token, b"invoice #1")

    # The use counter is authoritative on the vault side, not on the caller's
    # (frozen, stale) handle. Verify the progression via the audit chain.
    signed = [e for e in v.get_audit_log() if e["event"] == "signed"]
    assert [e["data"]["use_count"] for e in signed] == [1, 2]


def test_wrong_operation_class_is_refused_and_audited() -> None:
    # An llm.* token cannot drive sign(). The gate refuses before it resolves any
    # secret, charges nothing, and records the refusal with the operation it saw.
    v = SecretVault(insecure_dev_mode=True)
    _rust_only(v)
    v.store_secret("llm_api_key", "sk-test-12345")
    token = v.issue_token(scope="llm.evaluate", context="t", max_uses=1)
    with pytest.raises(CageViolation):
        v.sign(token, b"payload")
    refusals = [e for e in v.get_audit_log() if e["event"] == "rejected_wrong_verb"]
    assert len(refusals) == 1
    assert refusals[0]["entity_id"] == token.token_id
    assert refusals[0]["data"] == {"scope": "llm.evaluate", "operation": "sign"}
    assert not any(e["event"] == "signed" for e in v.get_audit_log())


def test_sign_rejects_a_non_bytes_payload() -> None:
    # bytes(5) is five zero bytes, so an int must not be coerced into a payload.
    v = _signing_vault()
    token = v.issue_token(scope="sign.invoice", context="t", max_uses=1)
    with pytest.raises(TypeError):
        v.sign(token, 5)  # type: ignore[arg-type]
    assert not any(e["event"] == "signed" for e in v.get_audit_log())
    # The refused call charged nothing: the single use is still available.
    assert len(v.sign(token, b"ok")) == 64


def test_no_operation_returns_a_stored_secret() -> None:
    # The in-process surface has no call that hands a stored credential back to
    # Python. The gated operations return a signature or a provider response.
    for name in ("consume", "retrieve_secret", "get_secret", "decrypt_secret"):
        assert not hasattr(SecretVault, name), f"SecretVault.{name} must not exist"


def test_dev_switch_is_recorded_on_the_chain() -> None:
    # A default vault's chain carries no such entry. A dev vault's chain says up
    # front that the waiver was on, before any token is issued under it.
    events = lambda v: [e["event"] for e in v.get_audit_log()]
    prod = SecretVault()
    if prod.backend != "rust":
        pytest.skip("switch audit is Rust-backend only")
    assert "insecure_dev_mode_enabled" not in events(prod)
    dev = SecretVault(insecure_dev_mode=True)
    assert events(dev).count("insecure_dev_mode_enabled") == 1
    assert dev.audit_chain_valid()


def test_non_bool_insecure_dev_mode_is_refused_not_coerced() -> None:
    # A config- or env-sourced "false" is truthy in Python. Coercing it would
    # silently waive control-plane auth on a vault its operator believes is
    # fail-closed, so construction refuses anything that is not a real bool.
    with pytest.raises(CageViolation):
        SecretVault(insecure_dev_mode="false")  # type: ignore[arg-type]


def test_revoke_blocks_sign() -> None:
    v = _signing_vault()
    token = v.issue_token(scope="sign.invoice", context="t")
    assert v.revoke(token.token_id) is True
    with pytest.raises(CageViolation):
        v.sign(token, b"invoice #1")


# ---------------------------------------------------------------------------
# Structural refusal — tokens must be vault-issued and unforgeable
# ---------------------------------------------------------------------------


def test_forged_token_rejected_by_sign() -> None:
    """A CapabilityToken the vault never issued must not unlock a secret,
    even though it is a public, constructable type (Invariant 6)."""
    v = _signing_vault()
    forged = CapabilityToken(
        scope="sign.invoice", context="attacker", max_uses=999_999
    )
    with pytest.raises(CageViolation):
        v.sign(forged, b"invoice #1")

    log = v.get_audit_log()
    assert any(e["event"] == "rejected_unknown_token" for e in log)
    assert v.audit_chain_valid()


def test_forged_token_rejected_by_invoke_llm() -> None:
    """invoke_llm rejects a non-issued token before any transport occurs."""
    import asyncio

    v = SecretVault(insecure_dev_mode=True)
    v.store_secret("llm_api_key", "sk-test-12345")
    forged = CapabilityToken(scope="llm.evaluate", context="attacker")

    with pytest.raises(CageViolation):
        asyncio.run(v.invoke_llm(forged, {"model": "x", "messages": []}))


def test_invoke_llm_unknown_provider_rejected() -> None:
    """A valid token still fails fast for a provider with no transport wired,
    before any network call (transport is provider-parametric)."""
    import asyncio

    v = SecretVault(insecure_dev_mode=True)
    v.store_secret("llm_api_key", "sk-test-12345")
    token = v.issue_token(scope="llm.evaluate", context="t", max_uses=1)

    with pytest.raises(ValueError, match="unknown provider"):
        asyncio.run(
            v.invoke_llm(token, {"model": "x", "messages": []}, provider="no-such-provider")
        )


def test_pinned_secret_refuses_another_provider() -> None:
    """A secret pinned to one provider is never sent to another, whichever scope
    it is reached through: invoke_llm is refused before any network call, and the
    refusal is audited. The pin is write-once."""
    import asyncio

    v = SecretVault(insecure_dev_mode=True)
    if v.backend != "rust":
        pytest.skip("provider pins need the Rust backend")
    v.store_secret("llm_api_key", "sk-test-12345")
    v.register_scope_secret("llm.", "llm_api_key", provider="anthropic")
    token = v.issue_token(scope="llm.evaluate", context="t", max_uses=1)

    with pytest.raises(CageViolation, match="pinned to provider"):
        asyncio.run(
            v.invoke_llm(token, {"model": "x", "messages": []}, provider="openai")
        )
    assert any(e["event"] == "rejected_provider" for e in v.get_audit_log())

    # Another prefix that resolves to the same secret is covered too.
    v.register_scope_secret("llm.judge.", "llm_api_key")
    judge = v.issue_token(scope="llm.judge.run", context="t", max_uses=1)
    with pytest.raises(CageViolation, match="pinned to provider"):
        asyncio.run(
            v.invoke_llm(judge, {"model": "x", "messages": []}, provider="openai")
        )

    # Write-once: the pin cannot be moved to another provider.
    with pytest.raises(CageViolation, match="already pinned"):
        v.register_scope_secret("llm.", "llm_api_key", provider="openai")


def test_token_is_immutable() -> None:
    """A caller cannot mutate an issued token to widen its authority."""
    v = SecretVault(insecure_dev_mode=True)
    token = v.issue_token(scope="llm.evaluate", context="t", max_uses=1)
    for field, value in (("max_uses", 999_999), ("use_count", 0), ("revoked", False)):
        # Frozen dataclass: setattr raises FrozenInstanceError (an AttributeError).
        with pytest.raises((TypeError, AttributeError)):
            setattr(token, field, value)


def test_audit_chain_intact() -> None:
    v = SecretVault(insecure_dev_mode=True)
    v.store_secret("llm_api_key", "sk-test-12345")
    token = v.issue_token(scope="llm.evaluate", context="t")
    v.revoke(token.token_id)
    assert v.audit_chain_valid()
    assert len(v.get_audit_log()) >= 3  # secret_stored + issued + revoked


def test_audit_chain_detects_tampering() -> None:
    """Python-fallback only: the in-Python audit log is mutable, so
    direct tampering breaks verification. Rust backend's chain is not
    Python-mutable — see test_rust_audit_chain_immune_to_python_mutation."""
    v = SecretVault(insecure_dev_mode=True)
    if v.backend == "rust":
        pytest.skip("This test exercises the Python-fallback chain")
    v.store_secret("llm_api_key", "sk-test-12345")
    v.issue_token(scope="llm.evaluate", context="t")
    # The pure-Python fallback audit log now lives on the composed Gate.
    v._gate._audit_log[0]["data"]["name"] = "different_secret"
    assert v.audit_chain_valid() is False


def test_unknown_scope_raises() -> None:
    v = SecretVault(insecure_dev_mode=True)
    _rust_only(v)
    v.store_secret("llm_api_key", "sk-test-12345")
    # Nothing is registered under "sign.", so the scope resolves to no secret.
    token = v.issue_token(scope="sign.deploy", context="t")
    with pytest.raises(CageViolation):
        v.sign(token, b"x")
    assert any(e["event"] == "rejected_unknown_scope" for e in v.get_audit_log())


def test_register_scope_secret() -> None:
    v = SecretVault(insecure_dev_mode=True)
    _rust_only(v)
    v.store_secret("release_key", "ASIAEXAMPLE")
    v.register_scope_secret("sign.release.", "release_key")
    token = v.issue_token(scope="sign.release.v1", context="t")

    sig = v.sign(token, b"artifact")
    # The signature was made with the registered secret, which never came back to
    # Python. Recompute it here from the known test value.
    expected = hmac.new(b"ASIAEXAMPLE", b"artifact", hashlib.sha256).hexdigest()
    assert sig == expected
    # A str payload is signed as its UTF-8 bytes.
    assert v.sign(token, "artifact") == expected


# ---------------------------------------------------------------------------
# Bootstrap-token auth (Gap 4 — token issuance authorization)
# ---------------------------------------------------------------------------


def test_vault_starts_sealed() -> None:
    v = SecretVault(insecure_dev_mode=True)
    assert v.is_unsealed() is False


def test_unseal_returns_opaque_handle() -> None:
    v = SecretVault(insecure_dev_mode=True)
    bootstrap = v.unseal()
    assert v.is_unsealed() is True
    if v.backend == "rust":
        # The secret stays in Rust: unseal() returns an opaque Bootstrap handle,
        # never a Python str, and the repr does not expose the secret.
        assert not isinstance(bootstrap, str)
        assert "Bootstrap" in type(bootstrap).__name__
        assert "sealed" in repr(bootstrap).lower()
    else:
        # Pure-Python fallback (dev only, unhardened): returns a hex str.
        assert isinstance(bootstrap, str)
        assert len(bootstrap) == 64
        assert all(c in "0123456789abcdef" for c in bootstrap)


def test_unseal_only_once() -> None:
    v = SecretVault(insecure_dev_mode=True)
    v.unseal()
    with pytest.raises(ValueError):
        v.unseal()


def test_issue_token_works_before_unseal() -> None:
    """Backward compat: dev/smoke mode does not require bootstrap."""
    v = SecretVault(insecure_dev_mode=True)
    v.store_secret("llm_api_key", "sk-test")
    token = v.issue_token(scope="llm.evaluate", context="dev")
    assert token.is_valid("llm.evaluate")


def test_issue_token_rejects_no_bootstrap_after_unseal() -> None:
    v = SecretVault()
    v.store_secret("llm_api_key", "sk-test")
    v.unseal()
    with pytest.raises(CageViolation):
        v.issue_token(scope="llm.evaluate", context="attacker")


def test_issue_token_rejects_wrong_bootstrap_after_unseal() -> None:
    v = SecretVault()
    v.store_secret("llm_api_key", "sk-test")
    v.unseal()
    with pytest.raises(CageViolation):
        v.issue_token(
            scope="llm.evaluate",
            context="attacker",
            bootstrap_token="0" * 64,
        )


def test_issue_token_accepts_correct_bootstrap_after_unseal() -> None:
    v = SecretVault()
    v.store_secret("llm_api_key", "sk-test")
    bootstrap = v.unseal()
    token = v.issue_token(
        scope="llm.evaluate",
        context="orchestrator",
        bootstrap_token=bootstrap,
        max_uses=1,
    )
    assert token.is_valid("llm.evaluate")


def test_bootstrap_rejection_is_audit_logged() -> None:
    v = SecretVault()
    v.store_secret("llm_api_key", "sk-test")
    v.unseal()
    with pytest.raises(CageViolation):
        v.issue_token(scope="llm.evaluate", context="x")
    # Audit chain should contain the rejection entry + remain valid.
    log = v.get_audit_log()
    rejections = [e for e in log if e["event"] == "issuance_rejected_auth"]
    assert len(rejections) == 1
    assert v.audit_chain_valid()


def test_malformed_bootstrap_token_rejected() -> None:
    v = SecretVault()
    v.store_secret("llm_api_key", "sk-test")
    v.unseal()
    for bad in ("", "not-hex", "abc", "z" * 64):
        with pytest.raises(CageViolation):
            v.issue_token(
                scope="llm.evaluate",
                context="x",
                bootstrap_token=bad,
            )


def test_broker_only_issuance_blocks_inprocess_control() -> None:
    """broker_only_issuance disables the in-process control plane: unseal / issue /
    revoke all refuse, directing the caller to the out-of-process broker (so the
    operator authority never lives in the application process)."""
    v = SecretVault(broker_only_issuance=True)
    v.store_secret("llm_api_key", "sk-test")  # storage is unaffected
    with pytest.raises(CageViolation):
        v.unseal()
    with pytest.raises(CageViolation):
        v.issue_token(scope="llm.evaluate", context="x")
    with pytest.raises(CageViolation):
        v.revoke("some-token-id")


def test_broker_only_issuance_via_env(monkeypatch) -> None:
    """The CAGE_BROKER_ONLY_ISSUANCE env var enforces broker-only at the ops layer
    without a code change."""
    monkeypatch.setenv("CAGE_BROKER_ONLY_ISSUANCE", "1")
    v = SecretVault()
    with pytest.raises(CageViolation):
        v.issue_token(scope="llm.evaluate", context="x")


# ---------------------------------------------------------------------------
# mlock state surfacing (Gap 8 — fail-loud on memory-protection failure)
# ---------------------------------------------------------------------------


def test_mlock_state_audit_entry_present() -> None:
    v = SecretVault(insecure_dev_mode=True)
    log = v.get_audit_log()
    mlock_entries = [e for e in log if e["event"] == "mlock_state"]
    if v.backend == "rust":
        assert len(mlock_entries) == 1
        assert "mlock_succeeded" in mlock_entries[0]["data"]
        assert isinstance(mlock_entries[0]["data"]["mlock_succeeded"], bool)
    else:
        # Python fallback does not emit the mlock_state entry
        assert len(mlock_entries) == 0


def test_strict_mlock_requires_rust_backend() -> None:
    # This passes on Rust; it would raise on the Python fallback path.
    # Skip cleanly if we are on Python fallback.
    v_probe = SecretVault(insecure_dev_mode=True)
    if v_probe.backend != "rust":
        pytest.skip("strict_mlock test requires Rust backend")
    # On Rust, mlock_succeeded is True on dev macOS / Linux without
    # special restrictions — so strict_mlock=True should not raise.
    if v_probe._backend.mlock_succeeded:
        v = SecretVault(strict_mlock=True)
        assert v.backend == "rust"


# ---------------------------------------------------------------------------
# load_from_env_file (Gap 3a — plaintext never crosses PyO3 on Rust backend)
# ---------------------------------------------------------------------------


def test_load_from_env_file_basic(tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# A comment\n"
        "LLM_API_KEY=sk-test-12345\n"
        "OTHER_SECRET=hunter2\n"
        "IGNORED=should-not-be-loaded\n"
        "\n"
        "QUOTED_KEY=\"with quotes\"\n"
    )
    v = SecretVault(insecure_dev_mode=True)
    loaded = v.load_from_env_file(
        str(env_file),
        ["LLM_API_KEY", "OTHER_SECRET", "QUOTED_KEY"],
    )
    assert loaded == 3
    assert v.has_secret("LLM_API_KEY")
    assert v.has_secret("OTHER_SECRET")
    assert v.has_secret("QUOTED_KEY")
    assert not v.has_secret("IGNORED")


def test_load_from_env_file_secret_recoverable(tmp_path) -> None:
    """The encrypted secret round-trips: a signature made with it equals one
    computed from the known plaintext, and the secret never came back to Python."""
    env_file = tmp_path / ".env"
    env_file.write_text("hmac_key=k-roundtrip-99\n")
    v = SecretVault(insecure_dev_mode=True)
    _rust_only(v)
    v.load_from_env_file(str(env_file), ["hmac_key"])
    v.register_scope_secret("sign.", "hmac_key")

    token = v.issue_token(scope="sign.check", context="t", max_uses=1)
    expected = hmac.new(b"k-roundtrip-99", b"probe", hashlib.sha256).hexdigest()
    assert v.sign(token, b"probe") == expected


def test_load_from_env_file_missing_path(tmp_path) -> None:
    v = SecretVault(insecure_dev_mode=True)
    with pytest.raises((ValueError, OSError, FileNotFoundError)):
        v.load_from_env_file(str(tmp_path / "does-not-exist.env"), ["X"])


def test_load_from_env_file_duplicate_key_rejected(tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("KEY=first\nKEY=second\n")
    v = SecretVault(insecure_dev_mode=True)
    with pytest.raises(ValueError):
        v.load_from_env_file(str(env_file), ["KEY"])


# ---------------------------------------------------------------------------
# Rust-owned audit chain (Gap 5 — chain immune to Python-side mutation)
# ---------------------------------------------------------------------------


def test_rust_audit_chain_immune_to_python_mutation() -> None:
    """Gap 5 closure: mutating returned audit snapshots must not affect
    the canonical chain's verification."""
    v = SecretVault(insecure_dev_mode=True)
    if v.backend != "rust":
        pytest.skip("Gap 5 closure is Rust-backend only")
    v.store_secret("llm_api_key", "sk-test")
    v.issue_token(scope="llm.evaluate", context="t")
    v.issue_token(scope="llm.evaluate", context="u")

    snap1 = v.get_audit_log()
    assert v.audit_chain_valid()

    # Attempt to tamper with the returned snapshot — should be a no-op
    # against the canonical chain.
    if snap1:
        snap1[0]["data"] = {"poisoned": True}
        snap1[0]["hash"] = "f" * 64

    assert v.audit_chain_valid(), \
        "Mutating Python snapshot must not break canonical-chain verification"

    snap2 = v.get_audit_log()
    assert snap2[0]["data"] != {"poisoned": True}, \
        "Canonical chain re-read must show original data, not tampered"


def test_audit_head_progresses_per_event() -> None:
    v = SecretVault(insecure_dev_mode=True)
    head0 = v.audit_head()
    assert isinstance(head0, str) and len(head0) == 64
    v.store_secret("llm_api_key", "sk-test")
    head1 = v.audit_head()
    assert head1 != head0
    v.issue_token(scope="llm.evaluate", context="t")
    head2 = v.audit_head()
    assert head2 != head1


def test_audit_log_len_matches_get_audit_log(tmp_path) -> None:
    v = SecretVault(insecure_dev_mode=True)
    if v.backend != "rust":
        pytest.skip("audit_log_len is Rust-backend only")
    v.store_secret("llm_api_key", "sk-test")
    v.issue_token(scope="llm.evaluate", context="t")
    v.revoke(v.issue_token(scope="llm.evaluate", context="u").token_id)
    assert v._backend.audit_log_len() == len(v.get_audit_log())


# ---------------------------------------------------------------------------
# Audit-head attestation (Gap 6 — Rekor anchor)
# ---------------------------------------------------------------------------


def test_attestation_payload_envelope_shape() -> None:
    v = SecretVault(insecure_dev_mode=True)
    if v.backend != "rust":
        pytest.skip("attestation is Rust-backend only in v0.1")
    v.store_secret("llm_api_key", "sk-test")
    v.issue_token(scope="llm.evaluate", context="t")

    env = v.attestation_payload()
    assert set(env.keys()) == {
        "payload_canonical",
        "signature_b64",
        "public_key_b64",
    }
    assert isinstance(env["payload_canonical"], str)
    import base64

    sig = base64.b64decode(env["signature_b64"])
    pub = base64.b64decode(env["public_key_b64"])
    assert len(sig) == 64  # ed25519 sig
    assert len(pub) == 32  # ed25519 pubkey


def test_attestation_signature_verifies() -> None:
    v = SecretVault(insecure_dev_mode=True)
    if v.backend != "rust":
        pytest.skip("attestation is Rust-backend only in v0.1")
    v.store_secret("llm_api_key", "sk-test")

    env = v.attestation_payload()
    import base64

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    pub_bytes = base64.b64decode(env["public_key_b64"])
    sig_bytes = base64.b64decode(env["signature_b64"])
    payload = env["payload_canonical"].encode("utf-8")
    pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    # Should not raise.
    pub.verify(sig_bytes, payload)

    # Tampered payload should fail verification.
    with pytest.raises(InvalidSignature):
        pub.verify(sig_bytes, payload + b"!")


def test_attestation_payload_contains_audit_head() -> None:
    v = SecretVault(insecure_dev_mode=True)
    if v.backend != "rust":
        pytest.skip("attestation is Rust-backend only in v0.1")
    v.store_secret("llm_api_key", "sk-test")
    v.issue_token(scope="llm.evaluate", context="t")

    env = v.attestation_payload()
    payload = json.loads(env["payload_canonical"])
    assert payload["audit_head"] == v.audit_head()
    assert payload["algorithm"] == "ed25519"
    assert payload["issuer"] == "cage/0.1"
    assert "timestamp" in payload
    assert isinstance(payload["audit_log_len"], int)


def test_record_attestation_appends_to_chain() -> None:
    v = SecretVault(insecure_dev_mode=True)
    if v.backend != "rust":
        pytest.skip("attestation is Rust-backend only in v0.1")
    v.store_secret("llm_api_key", "sk-test")
    head_before = v.audit_head()

    v.record_attestation(
        rekor_uuid="abc123-rekor-uuid",
        inclusion_proof={"logIndex": 42, "rootHash": "deadbeef"},
        anchored_head=head_before,
    )
    log = v.get_audit_log()
    anchors = [e for e in log if e["event"] == "rekor_anchor"]
    assert len(anchors) == 1
    assert anchors[0]["data"]["rekor_uuid"] == "abc123-rekor-uuid"
    assert anchors[0]["data"]["anchored_head"] == head_before
    assert anchors[0]["data"]["inclusion_proof"]["logIndex"] == 42
    assert v.audit_chain_valid()


import json  # noqa: E402  — used by the attestation tests above


def test_load_from_env_file_emits_audit_entries(tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("ALPHA=a\nBETA=b\n")
    v = SecretVault(insecure_dev_mode=True)
    v.load_from_env_file(str(env_file), ["ALPHA", "BETA"])
    log = v.get_audit_log()
    loaded_entries = [e for e in log if e["event"] == "loaded_from_env"]
    assert len(loaded_entries) == 2
    names = {e["data"]["name"] for e in loaded_entries}
    assert names == {"ALPHA", "BETA"}
    assert v.audit_chain_valid()
