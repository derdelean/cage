"""
Regression tests for pentest finding #4: the audit chain is anchorable. Each entry
carries a monotonic sequence number hashed into it, and a signed checkpoint lets a
verifier confirm the chain EXTENDS an externally-held anchor — so a truncation or
prefix-rewrite (which an in-memory adversary can make internally consistent) is
detectable against the off-box anchor, not just re-derived from genesis.
"""

from __future__ import annotations

import base64

import pytest

from cage import SecretVault


def _rust_vault() -> SecretVault:
    v = SecretVault(insecure_dev_mode=True)
    if v.backend != "rust":
        pytest.skip("audit anchoring is Rust-backend only")
    return v


def test_audit_log_has_monotonic_seq() -> None:
    v = _rust_vault()
    v.store_secret("llm_api_key", "sk")
    v.issue_token(scope="llm.evaluate", context="a")
    v.issue_token(scope="llm.evaluate", context="b")
    log = v.get_audit_log()
    seqs = [e["seq"] for e in log]
    assert seqs == list(range(len(log))), "seq must be 0..n strictly monotonic"


def test_checkpoint_verifies_and_binds_head_and_length() -> None:
    v = _rust_vault()
    v.store_secret("llm_api_key", "sk")
    v.issue_token(scope="llm.evaluate", context="a")

    cp = v.checkpoint()
    assert set(cp) >= {"audit_head", "audit_log_len", "signature_b64", "public_key_b64"}

    # The chain extends its own freshly-signed checkpoint.
    assert (
        v.verify_audit_chain_extends(
            cp["audit_head"], cp["audit_log_len"], cp["signature_b64"]
        )
        is True
    )

    # The signature binds the length: claiming a longer chain than was anchored
    # (a truncation indicator) does not verify under the same signature.
    assert (
        v.verify_audit_chain_extends(
            cp["audit_head"], cp["audit_log_len"] + 100, cp["signature_b64"]
        )
        is False
    )

    # A forged checkpoint signature is rejected.
    forged_sig = base64.b64encode(b"\x00" * 64).decode()
    assert (
        v.verify_audit_chain_extends(cp["audit_head"], cp["audit_log_len"], forged_sig)
        is False
    )


def test_checkpoint_anchors_a_prefix_of_a_growing_chain() -> None:
    v = _rust_vault()
    v.store_secret("llm_api_key", "sk")
    v.issue_token(scope="llm.evaluate", context="a")
    cp = v.checkpoint()

    # Grow the chain; it still extends the earlier anchor.
    v.issue_token(scope="llm.evaluate", context="b")
    v.issue_token(scope="llm.evaluate", context="c")
    assert v.verify_audit_chain_extends(
        cp["audit_head"], cp["audit_log_len"], cp["signature_b64"]
    )
    assert v.audit_chain_valid()
