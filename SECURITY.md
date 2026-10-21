# Security Policy

CAGE is credential-containment infrastructure. Its job is to keep a secret usable
without letting it be stolen, so security reports are among the most valuable
contributions this project can receive.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately through either channel:

- **GitHub:** open a private report under the repository's
  **Security → Report a vulnerability** (GitHub private vulnerability reporting).
- **Email:** `dennis.erdelean@proton.me`. For a sensitive proof-of-concept,
  ask for a key and send it encrypted.

Please include, where you can:

- the affected component (for example the `cage-core` gate, vault or transport,
  `cage-broker`, or the Python facade) and the version or commit,
- the impact (what authority or secret is exposed),
- a minimal proof-of-concept or the steps to reproduce.

We aim to acknowledge a report within **3 business days** and to agree on a
disclosure timeline with you from there. We practice coordinated disclosure,
credit you if you wish, and will not take legal action against good-faith
security research.

## Supported versions

CAGE is pre-1.0. Security fixes land on `main` and in the latest release. There
is no back-port guarantee for older pre-release tags until a 1.0 line exists.

## Scope: what we want to hear about

The properties CAGE claims, and where a break is in scope:

- **Authority bypass:** performing a gated operation (sign, invoke, release)
  without a valid capability token, exceeding a token's scope, TTL or use count,
  or forging or replaying a token, the bootstrap or an operator signature.
- **Issuer bypass:** issuing a token outside the frozen issuance policy.
- **Key disclosure:** recovering a stored secret in plaintext through any
  supported path (the Rust core, the broker, or the PyO3 surface), other than
  the documented limitations.
- **Audit integrity:** rewriting, truncating or forging the append-only audit
  chain so that verification or a signed checkpoint still passes.
- **Release signing:** getting a release signature or provenance statement
  accepted for an artifact that should be refused.
- **Transport:** anything that moves the decrypted key outside its `Zeroizing`
  buffers on the LLM-call path, sends it to a host other than the provider's,
  or breaks the TLS 1.3 guarantees.

## Known limitations (not new findings)

The full list is in the README under
[Known limitations](./README.md#known-limitations). Please don't file those as
new vulnerabilities. A *new* way to exploit one is in scope.

The two that matter most:

- The in-process library cannot hide a use-time secret from native code running
  in the **same address space**. The out-of-process **broker** is the
  mitigation: the key lives in a separate process and the agent holds only
  token IDs.
- A **host-level attacker** (root, the kernel, or whoever controls how the
  broker starts) can read the master key from the broker's memory. `mlock` pins
  it in RAM and does not hide it from root.

Thank you for helping keep CAGE, and the people who depend on it, safe.
