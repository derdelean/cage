"""Tests for cage.adapters — broker-backed, SDK-shaped LLM clients.

The adapters are pure translation: an SDK-shaped call -> ``broker.invoke_llm`` with
the right provider -> the response passed back. These drive that translation against
a fake broker (no socket, no network, no key), asserting the request is forwarded
unchanged, the provider is selected correctly, refusals propagate, and the adapter
can never be handed a raw key.
"""

from __future__ import annotations

import os

import pytest

from cage.adapters import (
    AsyncCagedAnthropic,
    AsyncCagedOpenAI,
    CagedAnthropic,
    CagedOpenAI,
)
from cage.exceptions import CageViolation


class _FakeBroker:
    """Stand-in BrokerClient: records the invoke_llm call and returns a canned reply."""

    def __init__(self, response=None, raise_exc=None):
        self.calls: list[tuple] = []
        self._response = response if response is not None else {"ok": True}
        self._raise = raise_exc

    def invoke_llm(self, token, request_body, *, provider="anthropic"):
        self.calls.append((token, request_body, provider))
        if self._raise is not None:
            raise self._raise
        return self._response


_BODY = {
    "model": "claude-haiku-4-5",
    "max_tokens": 8,
    "messages": [{"role": "user", "content": "ping"}],
}


def test_anthropic_create_routes_through_broker():
    fake = _FakeBroker(response={"content": [{"text": "pong"}]})
    client = CagedAnthropic(fake, "tok-123")

    resp = client.messages.create(**_BODY)

    assert fake.calls == [("tok-123", _BODY, "anthropic")]
    assert resp == {"content": [{"text": "pong"}]}


def test_openai_create_uses_openai_provider():
    fake = _FakeBroker(response={"choices": []})
    client = CagedOpenAI(fake, "tok-123")

    client.chat.completions.create(**_BODY)

    token, body, provider = fake.calls[0]
    assert provider == "openai"
    assert body == _BODY


def test_refusal_propagates_as_cage_violation():
    fake = _FakeBroker(raise_exc=CageViolation("CAGE refused: out of scope"))
    client = CagedAnthropic(fake, "tok-123")
    with pytest.raises(CageViolation):
        client.messages.create(**_BODY)


def test_adapter_cannot_be_handed_a_key():
    # The constructor takes only (broker, token); passing a key is a TypeError, so a
    # caller cannot accidentally reintroduce the API key into this process.
    fake = _FakeBroker()
    with pytest.raises(TypeError):
        CagedAnthropic(fake, "tok-123", api_key="sk-should-not-exist")


async def test_async_anthropic_awaits_broker_call():
    fake = _FakeBroker(response={"content": [{"text": "pong"}]})
    client = AsyncCagedAnthropic(fake, "tok-123")

    resp = await client.messages.create(**_BODY)

    assert fake.calls == [("tok-123", _BODY, "anthropic")]
    assert resp == {"content": [{"text": "pong"}]}


async def test_async_openai_awaits_with_openai_provider():
    fake = _FakeBroker(response={"choices": []})
    client = AsyncCagedOpenAI(fake, "tok-123")

    await client.chat.completions.create(**_BODY)

    assert fake.calls[0][2] == "openai"


# -- real-broker integration --
#
# Opt-in: point CAGE_BROKER_BIN at a freshly built cage-broker (e.g.
# `cargo build -p cage-broker` -> target/debug/cage-broker). It is deliberately
# explicit rather than auto-discovered: guessing target/release vs target/debug
# can pick up a stale binary whose behaviour no longer matches the source.

_BROKER_BIN = os.environ.get("CAGE_BROKER_BIN")


@pytest.mark.skipif(
    not _BROKER_BIN,
    reason="set CAGE_BROKER_BIN=path/to/cage-broker to run the real-broker test",
)
def test_real_broker_refuses_out_of_scope_through_adapter(monkeypatch):
    # End-to-end over a real Unix socket: a sign-scoped token driving an LLM invoke
    # must be refused at the broker's authority layer (verb-bound), proving the
    # adapter -> BrokerClient -> socket -> broker -> gate path and structural refusal
    # (and that the broker invoke op parses — guarding the RawValue->Value fix).
    from cage.broker import spawn_broker

    monkeypatch.setenv("CAGE_BROKER_ALLOW_NO_POLICY", "1")
    with spawn_broker(_BROKER_BIN, signing_key="sk-test-not-a-real-key") as bp:
        token = bp.client.issue_token(
            scope="sign.invoice", context="adapter-it",
            ttl_seconds=60, max_uses=1,
        )
        client = CagedAnthropic(bp.client, token)
        with pytest.raises(CageViolation):
            client.messages.create(
                model="claude-haiku-4-5", max_tokens=8,
                messages=[{"role": "user", "content": "ping"}],
            )
