"""
cage.core — ring 1: the universal authority gate.

Pure-Python, near-zero deps, handles **no secret bytes**. The Gate answers the
one question that defines cage — "is this credentialed action allowed right
now?" — and structurally refuses if not, recording every decision in an
append-only audit chain.

The Gate is usable standalone to gate *any* action (secret or not). The secret
custody + zero-plaintext transport rings (``cage.vault``) compose a Gate and add
secret storage on top; they do not reimplement its authorization logic.
"""

from __future__ import annotations

from cage.core.gate import Gate

__all__ = ["Gate"]
