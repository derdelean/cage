#!/usr/bin/env python3
"""Recipe: gate an agent's LLM calls through the cage broker.

The pattern any agent app follows to adopt credential containment
on the secure out-of-process path:

  1. Stand up a cage-broker holding the provider key (`spawn_broker`).
  2. CONTROL PLANE issues a short-lived, scope-bound capability token.
  3. Hand the AGENT a ``CagedAnthropic(broker_client, token)`` — a drop-in for
     ``anthropic.Anthropic()``. The API key stays inside the broker; the agent's
     process holds only a token_id.
  4. The agent calls ``client.messages.create(...)`` exactly as it would the SDK.

The only call-site change to adopt this is swapping the client constructor — the
``messages.create(...)`` call is unchanged (it returns the provider's JSON dict,
so read ``resp["content"][0]["text"]`` rather than ``resp.content[0].text``).

Run:
  cargo build -p cage-broker
  python examples/agent_broker_adapter.py [path-to-cage-broker]

  # For a real Anthropic response instead of the containment-only walkthrough:
  CAGE_DEMO_LIVE=1 ANTHROPIC_API_KEY=sk-ant-... python examples/agent_broker_adapter.py
"""

from __future__ import annotations

import os
import sys

# Import the pure-stdlib client surface straight from ./python — no native
# extension needed to run this recipe (the broker is a separate process).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))

from cage.adapters import CagedAnthropic  # noqa: E402  (after the sys.path shim)
from cage.broker import spawn_broker  # noqa: E402
from cage.exceptions import CageViolation  # noqa: E402


def main() -> int:
    broker_bin = sys.argv[1] if len(sys.argv) > 1 else "target/debug/cage-broker"
    if not os.path.exists(broker_bin):
        raise SystemExit(f"broker binary not found: {broker_bin} (run: cargo build -p cage-broker)")

    live = os.environ.get("CAGE_DEMO_LIVE") == "1"
    if live and not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("CAGE_DEMO_LIVE=1 requires ANTHROPIC_API_KEY to be set")
    llm_key = os.environ["ANTHROPIC_API_KEY"] if live else "sk-ANTHROPIC-not-a-real-key"

    # The provider key is handed to the broker through a sealed file and lives only
    # inside it. This process holds the operator signing key (control-plane root);
    # the agent is handed only a token. bp.client is pre-wired to sign control-plane
    # requests with that operator key. The broker also needs an issuance ceiling,
    # which it reads from the CAGE_* settings spawn_broker hands it.
    os.environ.setdefault("CAGE_ISSUANCE_SCOPES", "llm.,sign.")
    with spawn_broker(broker_bin, signing_key="sk-broker-signing-key", llm_api_key=llm_key) as bp:
        print(f"cage-broker up (pid {bp.proc.pid}). The provider key is inside it; no RPC returns it.")

        # -- CONTROL PLANE: issue a short-lived, scope-bound token --------------
        token = bp.client.issue_token(
            scope="llm.evaluate", context="agent-run-1", ttl_seconds=60, max_uses=2,
        )
        print(f"issued llm.evaluate token {token.token_id[:16]}…  (ttl=60s, max_uses=2)")

        # -- AGENT: a drop-in for anthropic.Anthropic(), but key-free ----------
        client = CagedAnthropic(bp.client, token)
        assert not hasattr(client, "api_key")  # the agent's client holds no key

        if live:
            resp = client.messages.create(
                model="claude-haiku-4-5", max_tokens=64,
                messages=[{"role": "user", "content": "Reply with exactly: cage works."}],
            )
            print("LIVE Anthropic response:", resp["content"][0]["text"])
        else:
            print("agent client ready — set CAGE_DEMO_LIVE=1 + ANTHROPIC_API_KEY for a real call")

        # -- Containment: the token's authority is bounded and verb-locked -----
        # A sign-scoped token cannot drive an LLM call, even through the adapter.
        sign_token = bp.client.issue_token(
            scope="sign.invoice", context="agent-run-1", ttl_seconds=60, max_uses=1,
        )
        try:
            CagedAnthropic(bp.client, sign_token).messages.create(
                model="claude-haiku-4-5", max_tokens=8,
                messages=[{"role": "user", "content": "x"}],
            )
            print("UNEXPECTED: a sign-scoped token invoked an LLM")
        except CageViolation as exc:
            print("refused a sign-scoped token at the LLM verb:", str(exc)[:80])

        return 0


if __name__ == "__main__":
    sys.exit(main())
