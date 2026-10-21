"""CAGE exceptions."""

from __future__ import annotations


class CageViolation(Exception):
    """Raised when any CAGE invariant is violated.

    Invariants:
      1. Structural Refusal — no protected operation executes without a
         valid CapabilityToken issued by this vault.
      2. Append-Only Audit  — the SHA-256 Merkle audit chain remains intact;
         tampering with prior entries breaks verification.
      3. Cumulative Limits  — use_count never exceeds max_uses.
    """


# The original name, kept as an alias of the same class so existing code that
# catches QREEViolation keeps working.
QREEViolation = CageViolation
