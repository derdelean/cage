"""
CapabilityToken — short-lived, scope-bound, context-bound handle.

A token replaces persistent credentials. After expiry the token can never be
reconstructed: there is no refresh path, no parent token to derive from, and
no secret embedded in the handle itself. The vault is the sole authority.

Tokens are **frozen** (immutable). A CapabilityToken is an opaque handle: its
only authority-bearing field is ``token_id``, which the vault maps to the
authoritative record it holds internally. A caller cannot mutate a token to
escalate it (e.g. bump ``max_uses`` or reset ``use_count``), and cannot
fabricate a token the vault will honour — the vault rejects any ``token_id``
it did not itself issue. The fields below reflect issue-time state; for live
state (current ``use_count``, revocation) the vault's record is authoritative,
not a long-held caller handle.

Implemented as a stdlib frozen ``dataclass`` so the universal core carries no
third-party dependency. The vault advances ``use_count`` / ``revoked`` by
replacing its own record via :func:`dataclasses.replace`; caller-held instances
cannot be tampered with to widen authority.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class CapabilityToken:
    """
    Fields
    ------
    token_id    : random 16-byte hex handle (non-guessable)
    scope       : dotted namespace, e.g. "llm.judge", "llm.evaluate"
    context     : caller context, e.g. "audit-run-42"
    issued_at   : UTC timestamp at issue time
    ttl_seconds : hard expiry
    max_uses    : cumulative use ceiling (Invariant 3)
    use_count   : incremented on each consume()/invoke_llm(); never decremented
    revoked     : True if vault.revoke() was called on this token

    ``scope`` and ``context`` are required; the rest carry defaults. (Dataclass
    field order puts the required fields first; all construction is keyword-based.)
    """

    scope: str
    context: str
    token_id: str = field(default_factory=lambda: secrets.token_hex(16))
    issued_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    ttl_seconds: int = 300
    max_uses: int = 50
    use_count: int = 0
    revoked: bool = False

    def is_valid(self, scope: str) -> bool:
        """All conditions must hold: not revoked, not expired, the clock did not roll
        back to before issue, scope matches exactly, below max_uses ceiling. (On the
        Rust gate the authoritative expiry is a monotonic clock; this wallclock check
        additionally rejects a negative elapsed.)"""
        elapsed = (datetime.now(timezone.utc) - self.issued_at).total_seconds()
        return (
            not self.revoked
            and elapsed >= 0  # reject a clock rollback to before issue
            and elapsed <= self.ttl_seconds
            and self.scope == scope
            and self.use_count < self.max_uses
        )

    def expires_at(self) -> datetime:
        return self.issued_at + timedelta(seconds=self.ttl_seconds)

    def remaining_uses(self) -> int:
        return max(0, self.max_uses - self.use_count)
