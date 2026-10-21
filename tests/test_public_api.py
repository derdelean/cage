"""
Characterization tests — pin the public API surface so the Option-C
restructure (extracting the Gate ring, composing Vault on top) is provably
non-breaking. These assert *what is importable and callable*, not deep
behaviour (that lives in test_smoke.py).
"""

from __future__ import annotations

import warnings

import pytest


def test_top_level_exports_present() -> None:
    import cage

    for name in ("CapabilityToken", "CageViolation", "SecretVault", "vault"):
        assert hasattr(cage, name), f"cage.{name} must remain importable"
    assert cage.__version__


def test_submodule_imports_stable() -> None:
    # Consumers import these paths directly.
    from cage.exceptions import CageViolation  # noqa: F401
    from cage.token import CapabilityToken  # noqa: F401
    from cage.vault import SecretVault, vault  # noqa: F401


def test_qree_violation_remains_an_alias_of_cage_violation() -> None:
    # Code written against the original name keeps catching every refusal.
    import cage
    from cage.exceptions import CageViolation, QREEViolation

    assert QREEViolation is CageViolation
    assert cage.QREEViolation is cage.CageViolation
    gate = cage.Gate()
    token = gate.issue_token(scope="db.write", context="t", max_uses=1)
    gate.authorize_and_charge(token, "db.write")
    with pytest.raises(QREEViolation):
        gate.authorize_and_charge(token, "db.write")


def test_secretvault_public_methods_present() -> None:
    from cage import SecretVault

    v = SecretVault(insecure_dev_mode=True)
    for method in (
        "store_secret", "load_from_env_file", "has_secret", "delete_secret",
        "configure", "register_scope_secret",
        "unseal", "is_unsealed", "issue_token", "revoke",
        "consume", "invoke_llm",
        "audit_chain_valid", "get_audit_log", "audit_head",
        "attestation_payload", "attestation_public_key", "record_attestation",
    ):
        assert callable(getattr(v, method)), f"SecretVault.{method} missing"
    assert v.backend in ("rust", "python")


def test_end_to_end_lifecycle_surface() -> None:
    """One pass through the canonical flow, asserting the shapes callers rely on."""
    from cage import CapabilityToken, SecretVault

    v = SecretVault(insecure_dev_mode=True, allow_plaintext_consume=True)
    v.store_secret("llm_api_key", "sk-test")
    tok = v.issue_token(scope="llm.evaluate", context="api-test", max_uses=2)
    assert isinstance(tok, CapabilityToken)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert v.consume(tok, "llm.evaluate") == "sk-test"

    assert v.revoke(tok.token_id) is True
    assert v.audit_chain_valid() is True
    log = v.get_audit_log()
    assert {"entity_id", "event", "data", "timestamp", "prev_hash", "hash"} <= set(
        log[0].keys()
    )
    assert len(v.audit_head()) == 64
