"""
Ring-1 tests — the standalone Gate (cage.core.Gate) used with NO secrets and
NO Rust backend. This is the universal authority surface every project can
import. Also exercises the pure-Python bootstrap path that the Rust-backed
smoke tests never reach.
"""

from __future__ import annotations

import pytest

from cage import CapabilityToken, Gate, CageViolation, SecretVault


def test_gate_gates_a_non_secret_action() -> None:
    """The Gate authorizes arbitrary actions — no secret involved."""
    gate = Gate()
    tok = gate.issue_token(scope="db.write", context="job-1", max_uses=1)

    canonical = gate.authorize(tok, "db.write")     # does not raise
    gate.record_use(canonical)                      # commit the gated action

    # Second authorization fails — max_uses=1 exhausted.
    with pytest.raises(CageViolation):
        gate.authorize(tok, "db.write")


def test_gate_rejects_forged_token() -> None:
    """Structural refusal holds at ring 1 too: a non-issued token is refused."""
    gate = Gate()
    forged = CapabilityToken(scope="db.write", context="attacker", max_uses=999)
    with pytest.raises(CageViolation):
        gate.authorize(forged, "db.write")


def test_gate_scope_mismatch_refused() -> None:
    gate = Gate()
    tok = gate.issue_token(scope="db.read", context="c")
    with pytest.raises(CageViolation):
        gate.authorize(tok, "db.write")


def test_gate_context_binding_is_enforced_when_presented() -> None:
    """A presented context must match the token's issued context; binding is
    opt-in, so omitting it preserves prior behaviour. Lets a relying party bind
    a capability to an external identity (OIDC subject, SPIFFE/WIMSE id)."""
    gate = Gate()
    tok = gate.issue_token(scope="db.write", context="tenant-A", max_uses=5)

    gate.authorize(tok, "db.write", context="tenant-A")        # issued context — ok
    with pytest.raises(CageViolation):
        gate.authorize(tok, "db.write", context="tenant-B")    # wrong context — refused
    gate.authorize(tok, "db.write")                            # no context — opt-in, ok


def test_gate_audit_chain_intact() -> None:
    gate = Gate()
    gate.issue_token(scope="x.y", context="c")
    assert gate.audit_chain_valid() is True
    assert len(gate.get_audit_log()) >= 1
    assert len(gate.audit_head()) == 64


def test_gate_pure_python_bootstrap_flow() -> None:
    """Standalone Gate has no native backend, so bootstrap runs in pure Python."""
    gate = Gate()
    assert gate.is_unsealed() is False

    bootstrap = gate.unseal()
    assert len(bootstrap) == 64
    assert gate.is_unsealed() is True

    # After unseal, issuance requires the bootstrap token.
    with pytest.raises(CageViolation):
        gate.issue_token(scope="x", context="c")

    tok = gate.issue_token(scope="x", context="c", bootstrap_token=bootstrap)
    assert tok.is_valid("x")

    # Second unseal is rejected.
    with pytest.raises(ValueError):
        gate.unseal()


def test_gate_attestation_unavailable_without_backend() -> None:
    """ed25519 attestation needs the Rust backend; a bare Gate refuses cleanly."""
    gate = Gate()
    with pytest.raises(CageViolation):
        gate.attestation_payload()


def test_gate_has_no_baked_in_scope_default() -> None:
    """The core Gate ships no domain-specific scope→secret mapping; resolving
    any scope before registration is refused. The LLM default ("llm." →
    "llm_api_key") lives in the secret-custody ring (SecretVault), not here."""
    gate = Gate()
    with pytest.raises(CageViolation):
        gate.scope_to_secret("llm.evaluate")

    gate.register_scope_secret("llm.", "llm_api_key")
    assert gate.scope_to_secret("llm.evaluate") == "llm_api_key"


def test_vault_composes_a_gate() -> None:
    v = SecretVault()
    assert isinstance(v.gate, Gate)


def test_authorize_and_charge_charges_exactly_one_use() -> None:
    """authorize_and_charge = authorize + record_use atomically; forgetting the
    charge can no longer silently let a token exceed max_uses."""
    gate = Gate()
    tok = gate.issue_token(scope="db.write", context="c", max_uses=1)

    charged = gate.authorize_and_charge(tok, "db.write")
    assert charged.use_count == 1

    # The single use is spent — a second call is refused, and nothing more is charged.
    with pytest.raises(CageViolation):
        gate.authorize_and_charge(tok, "db.write")


def test_authorize_and_charge_enforces_context() -> None:
    """Context binding is forwarded to authorize: a wrong context is refused
    (and not charged)."""
    gate = Gate()
    tok = gate.issue_token(scope="db.write", context="tenant-A", max_uses=5)

    gate.authorize_and_charge(tok, "db.write", context="tenant-A")          # ok
    with pytest.raises(CageViolation):
        gate.authorize_and_charge(tok, "db.write", context="tenant-B")      # refused


def test_authorize_and_charge_parity_on_rust_backend() -> None:
    """Same behaviour on the Rust-backed gate (via SecretVault)."""
    v = SecretVault(insecure_dev_mode=True)
    if v.backend != "rust":
        pytest.skip("native cage extension not built")
    tok = v.issue_token(scope="db.write", context="c", max_uses=1)

    charged = v.gate.authorize_and_charge(tok, "db.write")
    assert charged.use_count == 1
    with pytest.raises(CageViolation):
        v.gate.authorize_and_charge(tok, "db.write")
