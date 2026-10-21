# CAGE: Credential-bound Agent Gating Engine

**Credential containment for AI agents.** Capability-token-gated, structurally refusing, audit-chained.

> *We don't filter what the agent says. We cage what the agent can do.*

CAGE is AI control infrastructure: the authority layer that decides *what an autonomous agent is allowed to do*. It sits above secret stores and HSMs, and away from prompt filters. It replaces the persistent API key with short-lived, scope-bound capability tokens, optionally bound to a context. With the broker deployed as [DEPLOY.md](./DEPLOY.md) describes, a prompt-injected or otherwise compromised agent never holds the credential it works with.

---

## What CAGE is

**The engine is Rust. Python is the first client.** On the Rust backend (the bundled native extension) the master key lives only in Rust-owned memory and never crosses into Python as plaintext. Python is a thin binding that holds capability tokens. It came first because the AI-agent ecosystem (LangChain, the provider SDKs) lives there, and the broker speaks a language-neutral protocol, so clients in other languages can follow. The out-of-process **broker** goes further: the agent runs in a separate process holding only token IDs, and the key never enters its address space.

- **A Rust-core secret vault.** ChaCha20Poly1305 AEAD, zeroize-on-drop, and `mlock(2)` to keep the master key pinned in RAM.
- **Structural refusal.** No secret-bearing operation (an LLM call, a signature, a release signature) runs without a valid capability token for that verb. Tokens are TTL-bound, scope-bound, use-count-bound and revocable. Issuance, use, revocation and the refusals on the secret-bearing and control paths are recorded on a tamper-evident audit chain.
- **A frozen issuance policy** that bounds the *issuer* as well as the agent, where the operator provisions one. The broker reads it from `CAGE_ISSUANCE_SCOPES` at start. Allowed scope namespaces and the TTL, use and per-scope lifetime ceilings are then fixed, and no setter exists. A remote caller who later reaches the control plane, even with a stolen operator key, cannot widen them. An out-of-policy scope is refused and audited, TTL and use counts are clamped, and the policy's fingerprint is recorded on every issued token. The lifetime ceiling is counted per running instance, so a restart starts it from zero. A malformed policy variable, or an unknown one starting with `CAGE_ISSUANCE_`, stops the broker at start. The policy is a broker feature: the in-process vault and the pure-Python gate have none.
- **A rustls-direct transport** for the Anthropic Messages API and OpenAI Chat Completions. The decrypted API key lives only in `Zeroizing<Vec<u8>>` buffers inside Rust and never crosses into Python. Each provider trusts only root CAs from the organizations named in its DNS CAA records. A secret can be pinned to one provider.
- **An append-only SHA-256 Merkle audit chain** of token lifecycle events (issued, used, revoked, rejected), each with a sequence number. In the in-process API, signed checkpoints (`checkpoint()` and `verify_audit_chain_extends()`) let a head anchored off-box prove the chain was extended and not truncated or rewritten. The broker offers a signed attestation over its chain head. Automatic anchoring to Sigstore Rekor is planned.

## What CAGE is not

- **A prompt filter or content-moderation gateway.** Lakera, Lasso and NeMo Guardrails inspect what the agent says. CAGE constrains what the agent can do.
- **A replacement for HashiCorp Vault or AWS Secrets Manager.** CAGE sits above them and decides whether a given agent action is permitted at all, wherever the underlying secret is stored.
- **Finished.** It is pre-1.0. The known gaps are listed below.

## How to think about CAGE

Three terms from capability security and the agent-safety literature place CAGE:

- **It abolishes ambient authority.** An agent handed an API key has *ambient authority*: standing, unscoped power over everything that key can do, usable at any time and invisibly. CAGE replaces it with capability tokens that are verb-bound, short-lived, use-counted and revocable. Authority stops being something the agent holds and becomes a decision made at each action.
- **It keeps the agent secretless.** With the broker, started and provisioned outside the agent, the agent's process holds only token IDs. The guarantee underneath is *co-location*: the authority check and the secret operation are one atomic Rust operation, with no ungated path to the credential. Short-lived tokens alone are policy. Co-location is mechanism.
- **It removes the payoff of the lethal trifecta.** Simon Willison names the dangerous combination as *private data, untrusted content and the ability to communicate externally* ([the lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)). CAGE leaves all three in place and removes the reward: with the broker deployed as DEPLOY.md describes, an agent without a valid token, even one fully driven by a prompt injection, cannot reach the credential it would need to exfiltrate.

CAGE provides **process verifiability**: cryptographic evidence, on an append-only chain, of what an agent was authorized to do and what it attempted. Whether the agent did the *right* thing is a separate question for a separate layer. CAGE constrains capability and does not evaluate intent.

## Quickstart

`import cage` gives you the pure-Python **authority core**, with no native extension and no third-party dependencies. It gates any action with a capability token and a tamper-evident audit chain:

```python
import cage

gate = cage.Gate()
token = gate.issue_token(scope="db.write", context="job-42", ttl_seconds=60, max_uses=1)

gate.authorize_and_charge(token, "db.write")   # authorize + charge one use atomically, or raise CageViolation
do_the_write()                                 # your gated action
```

The secret-custody and LLM transport ring loads only when you reach for it. LLM calls need the bundled native extension, and the pure-Python fallback refuses them:

```python
from cage import vault

vault.store_secret("llm_api_key", api_key)  # encrypts into Rust-owned memory

# Fail-closed by default: unseal once for the bootstrap (the authority root),
# then pass it to every issue_token / revoke. On the Rust backend unseal()
# returns an opaque handle, so the secret stays in Rust memory.
# In production, broker_only_issuance=True routes issuance through the
# out-of-process broker so the authority never lives in your process.
bootstrap = vault.unseal()

token = vault.issue_token(
    scope="llm.evaluate",
    context="security-audit-run-42",
    ttl_seconds=60,
    max_uses=3,
    bootstrap_token=bootstrap,
)

# The decrypted key never crosses into Python.
# provider= selects the transport ("anthropic" by default, "openai" also wired).
response = await vault.invoke_llm(token, {
    "model": "claude-haiku-4-5",
    "max_tokens": 200,
    "messages": [{"role": "user", "content": "..."}],
})
```

For the strongest containment, run the out-of-process **broker**. The key lives in a separate process and the agent holds only token IDs. `cage.broker.spawn_broker` starts it, and `cage.adapters.CagedAnthropic` / `CagedOpenAI` take the provider SDKs' call shape (they return the provider's JSON as a dict). See [`examples/broker_demo.py`](./examples/broker_demo.py), which drives a real agent child process that is refused every escalation, and [`examples/agent_broker_adapter.py`](./examples/agent_broker_adapter.py). Read [DEPLOY.md](./DEPLOY.md) before running the broker in production: it only keeps the key from a same-user agent when the agent cannot control how the broker starts.

## Threat model in one paragraph

CAGE is built to contain a compromised agent: an LLM agent driven by prompt injection, or agent code that turned hostile, running in its own process and possibly as the same OS user as the broker. Against that agent the broker keeps the key out of reach, provided the agent cannot write the broker binary, its launcher or its environment (see DEPLOY.md). A remote attacker holding the operator key is bounded by the frozen issuance policy, where one is provisioned. Root, the kernel, and anyone who controls how the broker starts are out of scope. CAGE does not claim to defeat an adversary with unrestricted code execution on the host. It aims to make credential compromise slow and visible.

## Known limitations

These are the gaps as of v0.1. Reports and fixes are welcome (see [SECURITY.md](./SECURITY.md)).

**Host and deployment**
- Root, a kernel exploit, or a process that controls how the broker starts (binary, launcher, environment, `LD_PRELOAD`) can read or subvert the broker. On Linux the broker is dumpable between `execve` and its own hardening call. Host configuration closes that window (DEPLOY.md).
- A same-user agent can kill the broker. Audit entries not yet anchored off-box are lost, and a restart starts the issuance lifetime ceiling from zero.
- The broker socket is `0600`, so `CAGE_BROKER_ALLOWED_UIDS` has no effect yet, and broker responses are not signed.
- `mlock` requires `CAP_IPC_LOCK`. Without it CAGE warns and continues, unless `CAGE_STRICT_MLOCK` is set.

**Key handling**
- During an LLM call the decrypted provider key is resident from the decrypt until the request is written: up to about 50 s of network time on a stalled connection, longer if the process is stopped. That window is not mlocked.
- Plaintext request bytes transit rustls' reusable write buffer.
- TLS to the providers is classical. No provider offers post-quantum key exchange on its API endpoint yet.
- The vault's AEAD uses no associated data, so an attacker who can write the broker's memory can swap ciphertexts between secret names.

**Authority and audit**
- The Rust API lets a caller holding an invoke reservation settle it more than once. The Python and broker paths settle exactly once.
- A failed connection or TLS handshake refunds the use, with no cap, so a one-use token can retry a failing call indefinitely.
- An operator signature can be replayed if the broker's wall clock is rolled back.
- The provider pin binds a secret's name, and secrets are unpinned by default.
- The CA allowlist filters on the root CA only, by organization name. Subordinate CAs run by other organizations under an admitted root are accepted, and revocation is not checked.
- In-process, `register_scope_secret` and the audit writer need no authority. In-process code is trusted. The broker exposes neither.
- `vault.consume()` still exists for scopes without a Rust transport. It is deprecated, refused by default, and will be removed before 1.0.

## Verifying signed releases

Every CAGE wheel published on GitHub Releases is signed with [Sigstore](https://sigstore.dev/) through GitHub Actions OIDC and Fulcio. The signing is keyless: no long-lived signing key exists in the repo or in CI. Every signature is recorded in the public [Rekor](https://docs.sigstore.dev/rekor/overview/) transparency log.

To verify a downloaded wheel before installing:

```bash
cosign verify-blob \
  --certificate cage_ai-X.Y.Z-*.whl.cert \
  --signature   cage_ai-X.Y.Z-*.whl.sig \
  --certificate-identity-regexp \
    "https://github.com/derdelean/cage/\.github/workflows/release\.yml@.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  cage_ai-X.Y.Z-*.whl
```

A passing verification proves the wheel was built by this repository's release workflow at the tagged commit, and the proof is publicly recorded in Rekor. The same workflow publishes to PyPI through trusted publishing (no API token), and PyPI shows a Sigstore attestation for each file. CAGE proposes credential containment through capability tokens and an audit chain, and its own releases are signed with the same Sigstore, Fulcio and Rekor model.

## Installing

From PyPI (the distribution is named `cage-ai`, the import stays `import cage`):

```bash
pip install cage-ai
```

Or install a signed wheel from [GitHub Releases](https://github.com/derdelean/cage/releases) (verify it first, as above), or build from source:

```bash
uv pip install maturin
maturin develop --release
```

A bare `import cage` (the authority core) needs no native extension. The vault and transport ring load it on first use.

To use CAGE from another local project, build a wheel and install it:

```bash
maturin build --release                      # -> target/wheels/cage_ai-0.1.1-*.whl
pip install target/wheels/cage_ai-0.1.1-*.whl
```

or reference the checkout as a path dependency:

```toml
# pyproject.toml of the consuming project (uv)
[tool.uv.sources]
cage-ai = { path = "../cage" }
```

Locally built wheels are not signed.

## License and patents

CAGE is open-source under the [Apache License 2.0](./LICENSE). Two Swiss patent applications are pending, filed on 21 October 2025 and 19 September 2026. They will **not be enforced offensively against good-faith users**. See [PATENT_PLEDGE.md](./PATENT_PLEDGE.md) for the binding defensive-only pledge, modeled on Tesla's 2014 EV patent pledge and the Open Invention Network.

## Status

Pre-1.0. The API may change.

---

*Apache 2.0 with a defensive-only patent pledge. Built in Switzerland.*
