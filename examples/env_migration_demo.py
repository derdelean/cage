#!/usr/bin/env python3
"""
cage env-migration demo — "the secret leaves process.env and enters the cage."

The 2025–26 incident pattern: an autonomous agent (or any in-process code, or a
prompt-injected tool call) reads a long-lived API key straight out of
``os.environ`` / a committed ``.env`` file and exfiltrates it. The key is a bare
string anyone in the address space can grab; once leaked it stays valid until
someone notices and rotates it.

This script shows the before/after of fixing that with CAGE:

  * BEFORE — the anti-pattern: a secret sitting in ``os.environ`` (loaded from a
    ``.env`` file). Two lines of "agent" code read it back. That is exactly the
    exposure we are removing.

  * AFTER — load the same secret into the CAGE vault. On the Rust backend the
    plaintext is read into a ``Zeroizing`` buffer *inside Rust*, encrypted, and
    stored as ciphertext — it never crosses PyO3 as a Python ``str``. The agent
    side then holds only a short-TTL, use-counted, verb-scoped CapabilityToken,
    never the key. We exercise the structural-refusal behaviour offline (an
    out-of-scope verb and an over-max-uses call are both refused) so the demo
    runs with no network and no real API key. A real ``invoke_llm`` round-trip
    is shown only if CAGE_DEMO_LIVE=1 and a real key are both provided.

This is the in-process library form (the gate + vault live in this process).
The companion ``broker_demo.py`` takes the next step — moving the key into a
separate process the agent cannot reach. Neither script defends against a
host attacker (root); see DEPLOY.md for the limits.

Usage:  python examples/env_migration_demo.py
        CAGE_DEMO_LIVE=1 ANTHROPIC_API_KEY=sk-ant-... python examples/env_migration_demo.py

Requires the native extension for the zero-plaintext guarantees:
        maturin develop --release
(without it the vault falls back to pure Python and warns; the structural-refusal
narrative still holds, but invoke_llm is unavailable and store is not zeroized.)
"""

from __future__ import annotations

import asyncio
import os
import tempfile

# Import the lazy secret-custody ring. A bare ``import cage`` would pull only the
# pure-Python authority core; reaching for ``vault`` is what loads the native
# extension (or the pure-Python fallback).
from cage import CageViolation, vault

# The demo's stand-in credential. Deliberately a recognizable literal so the
# "is it still in os.environ?" check below is unambiguous.
DEMO_SECRET = "sk-LIVE-env-migration-demo-credential-7b1e4d2a-not-a-real-key"

# The env var an agent would naively read. We use a demo-specific name so we
# never clobber a real ANTHROPIC_API_KEY in the operator's environment.
ENV_VAR = "DEMO_LLM_API_KEY"


def banner(text: str) -> None:
    print("\n" + "=" * 72)
    print(text)
    print("=" * 72)


def ok(what: str) -> None:
    print(f"   [ok]      {what}")


def refused(what: str, exc: Exception) -> None:
    print(f"   [REFUSED] {what}  ->  {exc}")


def write_env_file(path: str) -> None:
    """Write a 0600 .env file holding the demo secret — the artifact we migrate
    OFF of. A real deployment's .env looks exactly like this."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("# demo .env — the anti-pattern we are migrating away from\n")
        f.write(f"{ENV_VAR}={DEMO_SECRET}\n")


def before_anti_pattern(env_path: str) -> None:
    """BEFORE: the secret lives in os.environ / a .env file, readable by anyone
    in this process — including a prompt-injected agent tool call."""
    banner("BEFORE — the anti-pattern: secret in process.env / a .env file")

    # An app loads the .env into the environment at startup (python-dotenv etc.).
    # We do the same by hand so the demo has no extra dependency.
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ[k] = v

    # This is the leak: any in-process code can read the bare key back.
    leaked = os.environ.get(ENV_VAR, "")
    print(f"   [LEAK]    os.environ[{ENV_VAR!r}] = {leaked[:24]}…  (full key readable)")
    print("             a prompt-injected agent tool call does exactly this and")
    print("             exfiltrates a long-lived, fully-valid credential.")


async def after_credential_containment(env_path: str) -> None:
    """AFTER: the secret moves into the vault; the agent holds only a bounded
    token; structural refusal stops out-of-scope and over-limit use."""
    banner("AFTER — credential containment: the secret enters the cage")

    print(f"   backend = {vault.backend}  "
          f"(audit chain signed = {vault.audit_chain_signed})")

    # 1) Load the .env straight into vault memory. On the Rust backend the
    #    plaintext values never cross PyO3 as Python strings — they are read into
    #    a Zeroizing buffer inside Rust, encrypted, and stored as ciphertext.
    #    We map the env key onto the stored name "llm_api_key" so the default
    #    "llm." scope resolves to it.
    write_env_file(env_path)
    loaded = vault.load_from_env_file(env_path, [ENV_VAR])
    ok(f"loaded {loaded} secret from {ENV_VAR} into vault memory (ciphertext only)")
    vault.register_scope_secret("llm.", ENV_VAR)

    # 2) Remove the plaintext from os.environ — the agent can no longer read it.
    os.environ.pop(ENV_VAR, None)
    still_in_env = ENV_VAR in os.environ
    ok(f"removed {ENV_VAR} from os.environ  (present now: {still_in_env})")

    # 3) Bootstrap the authority once, then mint a bounded capability token.
    #    Fail-closed by default: issue_token requires the bootstrap from unseal().
    bootstrap = vault.unseal()
    token = vault.issue_token(
        scope="llm.evaluate",          # verb-bound: authorizes invoke, not sign/release
        context="env-migration-demo",
        ttl_seconds=60,
        max_uses=1,                    # exactly one use, so the over-use refusal is visible
        bootstrap_token=bootstrap,
    )
    ok("issued token  scope=llm.evaluate  ttl=60s  max_uses=1")
    print(f"             token_id = {token.token_id[:16]}…  "
          f"(this is all the agent holds — never the key)")

    # 4) Structural refusal, offline. The agent-side authority is the Gate, not
    #    the token object's own fields — so these refusals are unforgeable.
    print("\n[AGENT — structurally refused without ever touching a network]")

    # 4a) Out-of-scope verb: an "llm." token cannot authorize a "sign." action.
    try:
        vault.gate.authorize(token, "sign.invoice")
        raise SystemExit("BUG: out-of-scope authorize was NOT refused")
    except CageViolation as exc:
        refused("authorize an out-of-scope verb (sign.invoice on an llm. token)", exc)

    # 4b) Over-max-uses: spend the one allowed use, then the second is refused.
    #     authorize() returns the canonical token; record_use() advances the gate's
    #     own counter (Invariant 3), so a second authorize trips the ceiling.
    canonical = vault.gate.authorize(token, "llm.evaluate")
    vault.gate.record_use(canonical)
    ok("first in-scope authorize accepted, one use charged (1/1)")
    try:
        vault.gate.authorize(token, "llm.evaluate")
        raise SystemExit("BUG: over-max-uses authorize was NOT refused")
    except CageViolation as exc:
        refused("authorize a 2nd time (over max_uses=1)", exc)

    # 5) Optional: a real gated invoke_llm round-trip. Off by default so the demo
    #    needs no network and no real key. Requires the Rust backend; with a real
    #    Anthropic key the decrypted key never crosses PyO3 on this path.
    live = os.environ.get("CAGE_DEMO_LIVE") == "1"
    real_key = os.environ.get("ANTHROPIC_API_KEY")
    if live and real_key and vault.backend == "rust":
        print("\n[LIVE]  CAGE_DEMO_LIVE=1 — performing one real gated invoke_llm call")
        vault.store_secret("llm_api_key", real_key)
        live_token = vault.issue_token(
            scope="llm.evaluate", context="env-migration-demo-live",
            ttl_seconds=60, max_uses=1, bootstrap_token=bootstrap,
        )
        try:
            response = await vault.invoke_llm(live_token, {
                "model": "claude-haiku-4-5",
                "max_tokens": 64,
                "messages": [{"role": "user", "content": "Reply with the single word: caged."}],
            })
            text = "".join(
                block.get("text", "") for block in response.get("content", [])
            )
            ok(f"invoke_llm returned: {text.strip()[:48]!r}  "
               f"(decrypted key never crossed into Python)")
        except CageViolation as exc:
            refused("live invoke_llm", exc)
    else:
        print("\n[LIVE]  skipped (set CAGE_DEMO_LIVE=1 + ANTHROPIC_API_KEY, Rust backend, "
              "to run one real gated call)")

    # 6) Every lifecycle event is in the tamper-evident audit chain.
    print("\n[AUDIT]  every load / issue / authorize / refusal is recorded:")
    valid = vault.audit_chain_valid()
    entries = vault.get_audit_log()
    ok(f"audit_chain_valid = {valid}   entries = {len(entries)}")
    events = ", ".join(e["event"] for e in entries)
    print(f"             events: {events}")


def explain() -> None:
    banner("WHAT CHANGED")
    print("   - The secret is no longer in os.environ or readable by agent code:")
    print("     the plaintext lives only as ciphertext in vault-owned memory.")
    print("   - The agent holds a CapabilityToken — TTL-bound, scope-bound (an")
    print("     'llm.' verb cannot 'sign.'), and use-counted — never the key.")
    print("   - Out-of-scope and over-limit calls are structurally refused by the")
    print("     gate's own record, not the token object's fields, so they cannot")
    print("     be forged in-process.")
    print("   - Every issue / authorize / refusal is appended to a tamper-evident")
    print("     audit chain, so a leak attempt is observable after the fact.")
    print("\n   Next step (broker_demo.py): move the key into a separate process the")
    print("   agent's address space cannot reach at all.")


async def amain() -> int:
    tmp = tempfile.mkdtemp(prefix="cage-env-demo-")
    env_path = os.path.join(tmp, ".env")
    try:
        write_env_file(env_path)
        before_anti_pattern(env_path)
        await after_credential_containment(env_path)
        explain()
        return 0
    finally:
        if os.path.exists(env_path):
            os.remove(env_path)
        if os.path.isdir(tmp):
            os.rmdir(tmp)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(amain()))
