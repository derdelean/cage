//! Operator authority — asymmetric proof-of-possession for the control plane.
//!
//! The broker's control plane (issue / revoke / attest / audit_log) is gated by
//! an *operator signature*, not a bearer secret. The operator holds an ed25519
//! private key; the broker holds only the matching **public** key and verifies a
//! per-request signature. Nothing secret crosses stdout, the wire, or sits in
//! broker memory as a forge-the-authority value — a broker-memory disclosure or a
//! same-UID peer cannot mint tokens, because forging authority requires the
//! operator's private key, which never leaves the operator's custody.
//!
//! The signed message binds the *target broker's* identity (its ed25519
//! attestation key) so a signature for broker A cannot be replayed against broker
//! B, plus a random nonce and a freshness timestamp so a captured request cannot
//! be replayed against the same broker. This canonical message is built **here**,
//! in one place, and used by both the signer (via the PyO3 surface) and the
//! verifier ([`crate::gate::Gate`]) — there is no second implementation to drift.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// Domain-separation tag for the control-plane signed message. Bumped if the
/// canonical layout ever changes, so an old signature cannot validate under a new
/// format.
pub const CONTROL_DOMAIN: &[u8] = b"cage-control-plane-v1";

/// Symmetric freshness window for a control-plane timestamp, in seconds. The
/// broker accepts a request whose `ts` is within ±this of its own clock, so it
/// tolerates operator/broker clock skew in either direction; a replay is bounded
/// to at most `2 * window` and the nonce cache evicts past that.
pub const CONTROL_AUTH_WINDOW_SECS: u64 = 60;

/// An operator signing key (ed25519). The default control-plane custody backend;
/// custody is pluggable above this (an HSM or OS-keystore key can replace it
/// without changing the wire format, since only `public_key`/`sign` matter).
pub struct OperatorKey {
    signing: SigningKey,
}

impl OperatorKey {
    /// Generate a fresh operator key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        OperatorKey {
            signing: SigningKey::generate(&mut rng),
        }
    }

    /// Raw 32-byte ed25519 public key — the operator's `key_id`.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Hex of [`public_key_bytes`](Self::public_key_bytes) — provisioned to the
    /// broker (public; safe on stdout / in a config / env).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    /// Sign `message` (an already-built canonical control message). Returns the
    /// raw 64-byte ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

/// A verified-on-the-wire operator authorization. Decoded from the request's
/// `auth` object by the broker; reconstructed-and-verified by the gate.
pub struct SignedAuth {
    /// The operator public key (raw 32 bytes) claimed to have signed.
    pub key_id: [u8; 32],
    /// Per-request random nonce (replay defense).
    pub nonce: [u8; 16],
    /// Operator-supplied unix timestamp (freshness; ±window).
    pub ts: u64,
    /// ed25519 signature over the canonical control message.
    pub sig: [u8; 64],
}

/// Control-plane authorization, in one of two forms:
/// - `Bootstrap` — the in-process bearer secret (same-process operator == gate, no
///   stdout/wire; the broker never constructs this — the wire has no bearer form).
/// - `Signed` — the broker's asymmetric proof-of-possession.
pub enum ControlAuth<'a> {
    Bootstrap(&'a str),
    Signed(SignedAuth),
}

/// `u32_be(len) || bytes` — unambiguous length-framing for a variable field.
pub(crate) fn framed(out: &mut Vec<u8>, x: &[u8]) {
    out.extend_from_slice(&(x.len() as u32).to_be_bytes());
    out.extend_from_slice(x);
}

/// `0x01 || u64_be(v)` if `Some`, else `0x00` — unambiguous optional encoding.
fn opt_u64(out: &mut Vec<u8>, v: Option<u64>) {
    match v {
        Some(n) => {
            out.push(1);
            out.extend_from_slice(&n.to_be_bytes());
        }
        None => out.push(0),
    }
}

pub(crate) fn opt_u32(out: &mut Vec<u8>, v: Option<u32>) {
    match v {
        Some(n) => {
            out.push(1);
            out.extend_from_slice(&n.to_be_bytes());
        }
        None => out.push(0),
    }
}

/// Canonical per-op argument binding for `issue_token` (the *requested*, pre-clamp
/// ttl/max_uses — what the operator actually authorized).
pub fn control_args_issue(
    scope: &str,
    context: &str,
    ttl_seconds: Option<u64>,
    max_uses: Option<u32>,
) -> Vec<u8> {
    let mut a = Vec::new();
    framed(&mut a, scope.as_bytes());
    framed(&mut a, context.as_bytes());
    opt_u64(&mut a, ttl_seconds);
    opt_u32(&mut a, max_uses);
    a
}

/// Canonical per-op argument binding for `revoke`.
pub fn control_args_revoke(token_id: &str) -> Vec<u8> {
    let mut a = Vec::new();
    framed(&mut a, token_id.as_bytes());
    a
}

/// Build the canonical message the operator signs and the gate verifies:
/// `framed(DOMAIN) || broker_id(32) || framed(op) || args || nonce(16) || ts_be(8)`.
/// `args` is op-specific (empty for attest / audit_log); it sits between the framed
/// `op` and the fixed 24-byte `nonce||ts` tail, so the layout is unambiguous.
pub fn control_message(
    broker_id: &[u8; 32],
    op: &str,
    args: &[u8],
    nonce: &[u8; 16],
    ts: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + CONTROL_DOMAIN.len() + 32 + 4 + op.len() + args.len() + 24);
    framed(&mut m, CONTROL_DOMAIN);
    m.extend_from_slice(broker_id);
    framed(&mut m, op.as_bytes());
    m.extend_from_slice(args);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&ts.to_be_bytes());
    m
}

/// Parse a 32-byte raw ed25519 public key into a `VerifyingKey`.
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Option<VerifyingKey> {
    VerifyingKey::from_bytes(bytes).ok()
}

/// Strict ed25519 verification (rejects non-canonical / small-order keys).
pub fn verify_operator_sig(vk: &VerifyingKey, message: &[u8], sig: &[u8; 64]) -> bool {
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let key = OperatorKey::generate();
        let vk = verifying_key_from_bytes(&key.public_key_bytes()).unwrap();
        let broker_id = [7u8; 32];
        let args = control_args_issue("llm.evaluate", "run-1", Some(60), Some(3));
        let nonce = [9u8; 16];
        let msg = control_message(&broker_id, "issue", &args, &nonce, 1_000_000);
        let sig = key.sign(&msg);
        assert!(verify_operator_sig(&vk, &msg, &sig));
    }

    #[test]
    fn a_tampered_message_fails() {
        let key = OperatorKey::generate();
        let vk = verifying_key_from_bytes(&key.public_key_bytes()).unwrap();
        let broker_id = [7u8; 32];
        let args = control_args_revoke("abc");
        let nonce = [9u8; 16];
        let msg = control_message(&broker_id, "revoke", &args, &nonce, 1_000_000);
        let sig = key.sign(&msg);
        // Same signature, a DIFFERENT target broker — must not verify (cross-broker).
        let other = control_message(&[8u8; 32], "revoke", &args, &nonce, 1_000_000);
        assert!(!verify_operator_sig(&vk, &other, &sig));
    }

    #[test]
    fn a_wrong_key_fails() {
        let key = OperatorKey::generate();
        let other = OperatorKey::generate();
        let vk_other = verifying_key_from_bytes(&other.public_key_bytes()).unwrap();
        let msg = control_message(&[1u8; 32], "attest", &[], &[2u8; 16], 5);
        let sig = key.sign(&msg);
        assert!(!verify_operator_sig(&vk_other, &msg, &sig));
    }
}
