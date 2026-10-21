"""
Phase 4 — ``import cage`` is the pure-Python authority core only.

These pin the Option-C packaging seam: a bare ``import cage`` pulls ring 1
(Gate / CapabilityToken / CageViolation) with zero native or third-party
imports, and the secret-custody ring (``cage.vault`` — the native extension,
cryptography, httpx) is imported only when ``SecretVault`` / ``vault`` is
actually accessed.

Each check runs in a subprocess so ``sys.modules`` starts clean regardless of
what the rest of the suite already imported. The subprocess uses the same
interpreter (the dev venv, where the ring-2 deps ARE installed) — which makes
the assertion strictly stronger: it proves the lazy seam holds even when those
dependencies are available to import.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap


def _run(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
    )


def test_bare_import_cage_pulls_only_ring1() -> None:
    """``import cage`` must not import the vault ring or any native/crypto dep."""
    result = _run(
        """
        import sys
        import cage

        heavy = [
            m for m in (
                "cage.vault", "cage._cage_native",
                "cryptography", "httpx", "pydantic", "structlog",
            )
            if m in sys.modules
        ]
        assert not heavy, f"import cage pulled ring-2 deps: {heavy}"

        # Ring 1 gates an arbitrary (non-secret) action standalone.
        gate = cage.Gate()
        tok = gate.issue_token(scope="db.write", context="t", max_uses=1)
        assert isinstance(tok, cage.CapabilityToken)
        gate.authorize(tok, "db.write")            # allowed
        try:
            gate.authorize(tok, "db.delete")       # wrong scope -> refused
        except cage.CageViolation:
            pass
        else:
            raise SystemExit("expected CageViolation for wrong scope")

        # Still no ring-2 import after exercising the gate.
        assert "cage.vault" not in sys.modules
        print("OK")
        """
    )
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert result.stdout.strip().endswith("OK")


def test_vault_ring_loads_lazily_on_access() -> None:
    """Accessing ``SecretVault`` / ``vault`` imports ``cage.vault`` on demand."""
    result = _run(
        """
        import sys
        import cage
        assert "cage.vault" not in sys.modules          # not yet

        from cage import SecretVault, vault             # triggers the lazy load
        assert "cage.vault" in sys.modules
        assert SecretVault is sys.modules["cage.vault"].SecretVault
        assert vault is sys.modules["cage.vault"].vault  # cage.vault is the instance
        assert vault.backend in ("rust", "python")
        print("OK")
        """
    )
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert result.stdout.strip().endswith("OK")
