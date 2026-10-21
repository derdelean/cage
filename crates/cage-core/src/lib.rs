/*!
cage-core: the pure-Rust credential core of CAGE.

This crate holds all of CAGE's security-load-bearing logic with **no PyO3 and no
RPC framing**: the ChaCha20Poly1305 vault, the bootstrap-gated capability
authority, the append-only Merkle audit chain, ed25519 audit-head attestation,
and the rustls-direct zero-plaintext transport.

It is consumed by two thin shells that never re-implement any of it:
  * `cage._cage_native` (the PyO3 extension) — the in-process library form.
  * `cage-broker` (the standalone binary) — the out-of-process form, where the key
    lives in a separate process the agent cannot read.

Keeping one audited core means the in-process and the broker deployments share
identical crypto, identical structural-refusal logic, and identical audit
semantics — the boundary moves, the guarantees do not.
*/

mod error;
mod gate;
mod operator;
mod release;
mod transport;
mod vault;

pub use error::CageError;
pub use gate::{CapabilityToken, Gate, InvokeReservation, IssuancePolicy};
pub use operator::{
    control_args_issue, control_args_revoke, control_message, ControlAuth, OperatorKey, SignedAuth,
    CONTROL_AUTH_WINDOW_SECS,
};
pub use release::{ProvenanceError, ReleasePolicy, VerifiedRelease};
pub use transport::{post_messages, provider_exists, TransportError};
pub use vault::{AuditEntrySnapshot, Vault};
