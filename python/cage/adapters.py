"""cage.adapters — drop-in-shaped LLM clients that route through a cage broker.

Adopting credential containment shouldn't mean rewriting every LLM call site.
These adapters mirror the provider SDKs' call shapes — ``client.messages.create``
(Anthropic) and ``client.chat.completions.create`` (OpenAI) — but each call is
gated by a capability token and executed *inside the out-of-process broker*, so
the API key never enters the agent's process. Swap the SDK client for the caged
one and pass a scoped token; the call sites stay the same.

    from cage.broker import spawn_broker
    from cage.adapters import CagedAnthropic

    with spawn_broker(broker_bin, signing_key=key) as bp:
        token = bp.client.issue_token(
            scope="llm.evaluate", ttl_seconds=60, max_uses=3,
        )
        client = CagedAnthropic(bp.client, token)        # hand THIS to the agent
        resp = client.messages.create(
            model="claude-haiku-4-5", max_tokens=200,
            messages=[{"role": "user", "content": "..."}],
        )
        text = resp["content"][0]["text"]

An adapter is constructed from only a broker and a token — never an API key — so
it cannot reintroduce the key into this process. ``create(**body)`` forwards the
keyword arguments to the provider byte-for-byte and returns the provider's native
JSON response (a ``dict``), not a typed SDK object: read ``resp["content"]`` /
``resp["choices"]`` rather than ``resp.content`` / ``resp.choices``.

A token that is out of scope, expired, revoked, or over its use ceiling is refused
broker-side and surfaces here as :class:`cage.exceptions.CageViolation`, exactly
as it would calling the broker client directly.

The async variants (:class:`AsyncCagedAnthropic` / :class:`AsyncCagedOpenAI`) run
the broker's blocking socket call in a worker thread so they don't stall the event
loop; their ``create`` is awaitable but otherwise identical.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cage.broker import BrokerClient
    from cage.token import CapabilityToken

    _Token = CapabilityToken | str

__all__ = [
    "AsyncCagedAnthropic",
    "AsyncCagedOpenAI",
    "CagedAnthropic",
    "CagedOpenAI",
]


# -- synchronous adapters ------------------------------------------------------


class _Messages:
    """``client.messages`` — the Anthropic SDK's messages namespace, broker-gated."""

    def __init__(self, broker: BrokerClient, token: _Token) -> None:
        self._broker = broker
        self._token = token

    def create(self, **body: Any) -> Any:
        """Gate ``messages.create(**body)`` through the broker (provider=anthropic)."""
        return self._broker.invoke_llm(self._token, body, provider="anthropic")


class CagedAnthropic:
    """Anthropic-SDK-shaped client whose every call is token-gated in the broker.

    Mirrors ``anthropic.Anthropic(...).messages.create(**body)``; the key never
    enters this process. Construct with a :class:`~cage.broker.BrokerClient` and a
    capability token scoped for LLM use — never an API key.
    """

    def __init__(self, broker: BrokerClient, token: _Token) -> None:
        self._broker = broker
        self._token = token
        self.messages = _Messages(broker, token)


class _Completions:
    def __init__(self, broker: BrokerClient, token: _Token) -> None:
        self._broker = broker
        self._token = token

    def create(self, **body: Any) -> Any:
        """Gate ``chat.completions.create(**body)`` through the broker (provider=openai)."""
        return self._broker.invoke_llm(self._token, body, provider="openai")


class _Chat:
    def __init__(self, broker: BrokerClient, token: _Token) -> None:
        self.completions = _Completions(broker, token)


class CagedOpenAI:
    """OpenAI-SDK-shaped client whose every call is token-gated in the broker.

    Mirrors ``openai.OpenAI(...).chat.completions.create(**body)``; the key never
    enters this process. Construct with a :class:`~cage.broker.BrokerClient` and a
    capability token scoped for LLM use — never an API key.
    """

    def __init__(self, broker: BrokerClient, token: _Token) -> None:
        self._broker = broker
        self._token = token
        self.chat = _Chat(broker, token)


# -- asynchronous adapters -----------------------------------------------------
#
# BrokerClient does blocking socket I/O; offload it to a worker thread so awaiting
# a caged call doesn't block the event loop while the broker talks to the provider.


class _AsyncMessages:
    def __init__(self, broker: BrokerClient, token: _Token) -> None:
        self._broker = broker
        self._token = token

    async def create(self, **body: Any) -> Any:
        return await asyncio.to_thread(
            self._broker.invoke_llm, self._token, body, provider="anthropic"
        )


class AsyncCagedAnthropic:
    """Async :class:`CagedAnthropic` — ``await client.messages.create(**body)``."""

    def __init__(self, broker: BrokerClient, token: _Token) -> None:
        self._broker = broker
        self._token = token
        self.messages = _AsyncMessages(broker, token)


class _AsyncCompletions:
    def __init__(self, broker: BrokerClient, token: _Token) -> None:
        self._broker = broker
        self._token = token

    async def create(self, **body: Any) -> Any:
        return await asyncio.to_thread(
            self._broker.invoke_llm, self._token, body, provider="openai"
        )


class _AsyncChat:
    def __init__(self, broker: BrokerClient, token: _Token) -> None:
        self.completions = _AsyncCompletions(broker, token)


class AsyncCagedOpenAI:
    """Async :class:`CagedOpenAI` — ``await client.chat.completions.create(**body)``."""

    def __init__(self, broker: BrokerClient, token: _Token) -> None:
        self._broker = broker
        self._token = token
        self.chat = _AsyncChat(broker, token)
