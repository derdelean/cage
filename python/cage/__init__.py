"""
CAGE — Credential-bound Agent Gating Engine.

Credential containment for AI agents:
  - ChaCha20Poly1305 AEAD vault with zeroize-on-drop and mlock(2)
  - CapabilityToken — short-lived, scope-bound, use-counted handles
  - rustls-direct LLM transport (Anthropic and OpenAI)
  - Append-only SHA-256 Merkle audit chain (Rekor anchoring planned)
  - ``cage.broker`` — stdlib client for the out-of-process credential broker
    (the agent holds tokens, never the key); imported only when used

Two import tiers (Option C — progressive enhancement):

  * ``import cage`` pulls only the pure-Python authority core (ring 1):
    :class:`~cage.core.Gate`, :class:`~cage.token.CapabilityToken`,
    :class:`~cage.exceptions.CageViolation`. Zero third-party and zero native
    dependencies — stdlib only — so any project can adopt the gate to gate any
    action (secret or not) with structural refusal + a tamper-evident audit chain.

  * The secret-custody + zero-plaintext transport ring (``SecretVault`` and the
    module-level ``vault`` singleton) is imported **lazily** on first access via
    PEP 562 ``__getattr__``. Only then is ``cage.vault`` imported and its
    dependencies touched (the bundled native extension, or the ``cage[vault]`` /
    ``cage[anthropic]`` pure-Python fallback). A bare ``import cage`` never
    imports it — that is what keeps the core dependency-free.

Apache 2.0 with a defensive-only patent pledge (see PATENT_PLEDGE.md).
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

from cage.core import Gate
from cage.exceptions import CageViolation, QREEViolation
from cage.token import CapabilityToken

__all__ = [
    "CapabilityToken",
    "Gate",
    "CageViolation",
    "QREEViolation",
    "SecretVault",
    "vault",
]

__version__ = "0.1.0"

# Ring 2 (secret custody) is exposed lazily so it — and its native / cryptography
# dependencies — is never imported by a bare ``import cage``. Resolving either
# name imports ``cage.vault`` once and caches both onto this package's namespace.
_LAZY_VAULT_EXPORTS = frozenset({"SecretVault", "vault"})


def __getattr__(name: str):  # PEP 562 — module-level lazy attribute resolution
    if name in _LAZY_VAULT_EXPORTS:
        module = importlib.import_module("cage.vault")
        # Cache the class AND the singleton onto this package's namespace, so
        # __getattr__ won't fire again and so ``cage.vault`` resolves to the
        # SecretVault instance — importing the submodule transiently binds that
        # name to the module object, which we overwrite here.
        globals()["SecretVault"] = module.SecretVault
        globals()["vault"] = module.vault
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)


if TYPE_CHECKING:  # give type-checkers / IDEs the lazy exports' real types
    from cage.vault import SecretVault as SecretVault
    from cage.vault import vault as vault
