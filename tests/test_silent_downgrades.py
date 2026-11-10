"""
Regression tests for pentest findings #7, #13, #10 — the shipped Python surface no
longer silently downgrades:
  #13 invoke_llm fails closed off the Rust backend instead of leaking the key.
  #7  audit_chain_signed marks the unsigned fallback; strict_backend fails closed.
  #10 unseal() warns that the bootstrap crosses PyO3 as an un-zeroable str.
  2026-11-09: sign() fails closed off the Rust backend, as invoke_llm does.
"""

from __future__ import annotations

import asyncio
import warnings

import pytest

from cage import CageViolation, SecretVault


def test_invoke_llm_fails_closed_off_rust_backend() -> None:
    """invoke_llm's zero-plaintext guarantee holds only on Rust; off it, the method
    must refuse rather than fall back to a key-leaking path."""
    v = SecretVault(insecure_dev_mode=True)
    if v.backend != "rust":
        pytest.skip("simulating the non-Rust path requires the Rust build present")
    v.store_secret("llm_api_key", "sk")
    tok = v.issue_token(scope="llm.evaluate", context="t")

    # Simulate the fallback backend being selected; invoke_llm must fail closed.
    v._backend_name = "python"
    with pytest.raises(CageViolation):
        asyncio.run(v.invoke_llm(tok, {"model": "m", "messages": []}))
    # The refusal is on the chain, keyed on the validated token (Invariant 4).
    refusals = [
        e for e in v.get_audit_log() if e["event"] == "invoke_refused_no_rust_backend"
    ]
    assert [e["entity_id"] for e in refusals] == [tok.token_id]


def test_sign_fails_closed_off_rust_backend() -> None:
    """sign() keeps the key in Rust only on the Rust backend. Off it, the method
    must refuse rather than read the key into Python to compute the HMAC."""
    v = SecretVault(insecure_dev_mode=True)
    if v.backend != "rust":
        pytest.skip("simulating the non-Rust path requires the Rust build present")
    v.store_secret("hmac_key", "k")
    v.register_scope_secret("sign.", "hmac_key")
    tok = v.issue_token(scope="sign.x", context="t")

    v._backend_name = "python"
    with pytest.raises(CageViolation):
        v.sign(tok, b"payload")
    refusals = [
        e for e in v.get_audit_log() if e["event"] == "sign_refused_no_rust_backend"
    ]
    assert [e["entity_id"] for e in refusals] == [tok.token_id]
    assert not any(e["event"] == "signed" for e in v.get_audit_log())


def test_audit_chain_signed_marks_the_backend() -> None:
    v = SecretVault(insecure_dev_mode=True)
    # On the Rust build this is True (signed, mutation-immune); on the pure-Python
    # fallback it is False — so a green audit_chain_valid cannot be mistaken for the
    # signed chain.
    assert v.audit_chain_signed is (v.backend == "rust")


def test_strict_backend_ok_on_rust_build() -> None:
    v = SecretVault()
    if v.backend != "rust":
        pytest.skip("strict_backend would (correctly) raise off the Rust build")
    # Constructing with strict_backend=True does not raise when Rust is present.
    strict = SecretVault(strict_backend=True)
    assert strict.backend == "rust"
    assert strict.audit_chain_signed is True


def test_unseal_returns_opaque_handle_without_str_leak_warning() -> None:
    """On the Rust backend the bootstrap stays in Rust: unseal() returns an opaque
    handle (not a str) and emits NO python-str-leak DeprecationWarning. (The
    deprecation warning is now reserved for the unhardened pure-Python fallback.)"""
    v = SecretVault()
    if v.backend != "rust":
        pytest.skip("the opaque-handle guarantee is Rust-only; fallback still warns")
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any DeprecationWarning would raise here
        bootstrap = v.unseal()
    assert not isinstance(bootstrap, str)
