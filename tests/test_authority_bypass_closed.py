"""
Regression tests for the second pentest critical (#2 / #9 / #16): the token
authority now lives in Rust, co-located with the secret, so there is no
token-less bypass, no concurrent double-spend, and issuance is fail-closed.

Each test reproduces one of the live PoCs and asserts it is now defeated.
"""

from __future__ import annotations

import threading
import warnings

import pytest

from cage import CapabilityToken, CageViolation, SecretVault


def test_no_token_less_backend_bypass() -> None:
    """PoC1: ``vault._backend.retrieve_secret(...)`` / raw ``invoke(...)`` used to
    return the plaintext key with no token and no audit. The native backend is now
    the Gate — it exposes no ungated secret reader, and ``invoke`` is token-gated."""
    v = SecretVault(insecure_dev_mode=True)
    if v.backend != "rust":
        pytest.skip("the un-gated bypass closure is Rust-backend specific")
    v.store_secret("llm_api_key", "sk-ant-SECRET")

    # The ungated plaintext readers are gone from the native surface.
    assert not hasattr(v._backend, "retrieve_secret")
    assert not hasattr(v._backend, "decrypt_secret")

    # The only native invoke is token-gated: a fabricated token_id is refused
    # (structural refusal) before any network call or key decryption.
    audit_before = len(v.get_audit_log())
    with pytest.raises(ValueError):
        v._backend.invoke("deadbeefdeadbeef", "anthropic", "{}")
    # The refusal is audited (authority enforced in Rust), and no secret left.
    assert len(v.get_audit_log()) > audit_before


def test_default_vault_is_fail_closed() -> None:
    """PoC2: a default ``SecretVault()`` was never unsealed, so any in-process code
    minted full-authority tokens with no secret. Issuance is now fail-closed."""
    v = SecretVault()  # the shipped default — NOT insecure_dev_mode
    if v.backend != "rust":
        pytest.skip("fail-closed issuance is enforced on the Rust authority")
    v.store_secret("llm_api_key", "sk-test")

    with pytest.raises(CageViolation):
        v.issue_token(scope="llm.evaluate", context="attacker", max_uses=999_999)

    # The legitimate path: unseal once, then issue with the bootstrap.
    bootstrap = v.unseal()
    token = v.issue_token(
        scope="llm.evaluate", context="orchestrator", bootstrap_token=bootstrap
    )
    assert token.is_valid("llm.evaluate")


def test_fail_closed_revoke_needs_bootstrap() -> None:
    """A rogue holder of only a token_id cannot revoke another agent's token on a
    fail-closed vault (revoke is at bootstrap parity with issuance)."""
    v = SecretVault()
    if v.backend != "rust":
        pytest.skip("fail-closed revoke is enforced on the Rust authority")
    v.store_secret("llm_api_key", "sk-test")
    bootstrap = v.unseal()
    token = v.issue_token(
        scope="llm.evaluate", context="victim", bootstrap_token=bootstrap
    )

    with pytest.raises(CageViolation):
        v.revoke(token.token_id)  # no bootstrap → refused
    assert v.revoke(token.token_id, bootstrap_token=bootstrap) is True


def test_concurrent_consume_does_not_double_spend() -> None:
    """PoC3: concurrent use of a max_uses=1 token used to succeed N times because
    authorize and record_use straddled the await non-atomically. The Rust gate
    charges the use atomically, so a max_uses=1 token is spent exactly once even
    under concurrency."""
    v = SecretVault(insecure_dev_mode=True, allow_plaintext_consume=True)
    v.store_secret("llm_api_key", "sk-secret-value")
    token = v.issue_token(scope="llm.evaluate", context="race", max_uses=1)

    results: list[str | None] = []

    def worker() -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                results.append(v.consume(token, "llm.evaluate"))
            except CageViolation:
                results.append(None)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    succeeded = [r for r in results if r == "sk-secret-value"]
    assert len(succeeded) == 1, (
        f"max_uses=1 token was spent {len(succeeded)} times — double-spend"
    )


def test_forged_token_cannot_drive_invoke_or_consume() -> None:
    """Structural refusal on the shipped path: a fabricated CapabilityToken the
    vault never issued unlocks nothing, even though the type is constructable."""
    v = SecretVault(insecure_dev_mode=True, allow_plaintext_consume=True)
    v.store_secret("llm_api_key", "sk-test")
    forged = CapabilityToken(scope="llm.evaluate", context="attacker", max_uses=10)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pytest.raises(CageViolation):
            v.consume(forged, "llm.evaluate")
    assert v.audit_chain_valid()
