//! Broker wire protocol: one JSON request per line, one JSON response per line.
//!
//! The request is an internally-tagged enum (`{"op": "...", ...}`), so each
//! operation carries exactly the fields it needs — no flat bag of optionals.
//! Responses are uniform: `ok` plus either a `result` object or a structured
//! `error` with a machine-readable `kind`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Operator proof-of-possession for a control-plane request. The operator signs a
/// canonical message (domain ∥ this broker's id ∥ op ∥ args ∥ nonce ∥ ts) with its
/// ed25519 key; the broker holds only the matching public key and verifies. No
/// bearer secret crosses the wire — replacing the old `bootstrap_token`. All three
/// byte fields are hex; `ts` is unix seconds (freshness window, replay-bounded).
#[derive(Debug, Deserialize)]
pub struct ControlAuth {
    /// Operator public key, hex of the raw 32-byte ed25519 key (the `key_id`).
    pub key_id: String,
    /// Per-request random nonce, hex of 16 bytes (replay defense).
    pub nonce: String,
    /// Operator-supplied unix timestamp (freshness).
    pub ts: u64,
    /// ed25519 signature over the canonical message, hex of 64 bytes.
    pub sig: String,
}

/// A request from a client (agent or control plane). `op` selects the variant.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Control-plane: mint a capability token (requires an operator signature).
    Issue {
        scope: String,
        #[serde(default)]
        context: String,
        #[serde(default)]
        ttl_seconds: Option<u64>,
        #[serde(default)]
        max_uses: Option<u32>,
        #[serde(default)]
        auth: Option<ControlAuth>,
    },
    /// Agent: HMAC-sign a payload with the token's scoped key.
    Sign {
        token_id: String,
        #[serde(default)]
        payload: String,
    },
    /// Agent: invoke an LLM provider with the token's scoped key (network). The
    /// body is captured as a JSON value and forwarded to the provider. A `RawValue`
    /// would forward it byte-for-byte, but it cannot live inside an internally-tagged
    /// enum — serde buffers the tagged content and cannot reconstruct a `RawValue`
    /// from that buffer (every `invoke` would fail to parse) — so we carry a `Value`;
    /// the re-serialized request is semantically identical.
    Invoke {
        token_id: String,
        #[serde(default = "default_provider")]
        provider: String,
        request_body: Value,
    },
    /// Revoke a token immediately (control-plane; operator-signature-gated).
    Revoke {
        token_id: String,
        #[serde(default)]
        auth: Option<ControlAuth>,
    },
    /// Current audit-chain head hash (no token_ids; unauthenticated).
    AuditHead,
    /// Verify the whole audit chain from genesis (returns only a bool).
    VerifyChain,
    /// Signed ed25519 attestation over the current head. **Operator-gated**: it
    /// signs with the audit key, so it must not be an open signing oracle.
    Attest {
        #[serde(default)]
        auth: Option<ControlAuth>,
    },
    /// Snapshot of the audit log. **Operator-gated**: entries carry `entity_id`
    /// (= the live `token_id` for token events), a bearer handle that must never
    /// leak on an unauthenticated channel.
    AuditLog {
        #[serde(default)]
        auth: Option<ControlAuth>,
    },
}

fn default_provider() -> String {
    "anthropic".to_string()
}

/// A response. Exactly one of `result` / `error` is present.
#[derive(Debug, Serialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

/// Structured error. `kind` is stable and machine-readable (e.g. "refused",
/// "not_found", "transport", "bad_request"); `message` is human-facing.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub kind: String,
    pub message: String,
}

impl Response {
    pub fn ok(result: Value) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(kind: &str, message: String) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(ErrorBody {
                kind: kind.to_string(),
                message,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression: an `invoke` request carrying a JSON body must deserialize. A
    // `Box<RawValue>` body silently broke this — a RawValue cannot be rebuilt from
    // the buffer serde uses for an internally-tagged enum, so every invoke failed
    // to parse with "invalid type: newtype struct, expected any".
    #[test]
    fn invoke_request_with_body_deserializes() {
        let line = r#"{"op":"invoke","token_id":"abc","provider":"anthropic","request_body":{"model":"m","messages":[]}}"#;
        match serde_json::from_str::<Request>(line).expect("invoke must parse") {
            Request::Invoke {
                token_id,
                provider,
                request_body,
            } => {
                assert_eq!(token_id, "abc");
                assert_eq!(provider, "anthropic");
                assert_eq!(request_body["model"], "m");
            }
            other => panic!("expected Invoke, got {other:?}"),
        }
    }

    #[test]
    fn invoke_request_defaults_provider() {
        let line = r#"{"op":"invoke","token_id":"abc","request_body":{}}"#;
        match serde_json::from_str::<Request>(line).expect("must parse with default provider") {
            Request::Invoke { provider, .. } => assert_eq!(provider, "anthropic"),
            other => panic!("expected Invoke, got {other:?}"),
        }
    }
}
