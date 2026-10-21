//! Request dispatch — pure, socket-free, and therefore unit-testable.
//!
//! `handle` maps a parsed [`Request`] to a [`Response`] against a borrowed
//! `Gate`. It contains no I/O and no concurrency: the server layer owns the
//! socket and the lock, this layer owns the protocol↔authority mapping.

use cage_core::{CageError, ControlAuth as CoreControlAuth, Gate, SignedAuth};
use serde_json::{json, Value};

use crate::protocol::{ControlAuth, Request, Response};

/// Decode a fixed-length byte field from hex. `None` on bad hex or wrong length.
fn decode_fixed<const N: usize>(hexstr: &str) -> Option<[u8; N]> {
    hex::decode(hexstr)
        .ok()
        .and_then(|b| <[u8; N]>::try_from(b.as_slice()).ok())
}

/// Wire `ControlAuth` → core `SignedAuth`. Any malformed field yields `None` — the
/// gate then sees no authorization and structurally refuses.
fn to_signed_auth(a: &ControlAuth) -> Option<SignedAuth> {
    Some(SignedAuth {
        key_id: decode_fixed::<32>(&a.key_id)?,
        nonce: decode_fixed::<16>(&a.nonce)?,
        ts: a.ts,
        sig: decode_fixed::<64>(&a.sig)?,
    })
}

/// Lift an optional wire auth into the core control-auth (signed form). Absent or
/// malformed auth becomes `None`, which the gate refuses (fail-closed). The broker
/// only ever presents the *signed* form — there is no bearer-secret path on the wire.
fn core_auth(auth: &Option<ControlAuth>) -> Option<CoreControlAuth<'static>> {
    auth.as_ref()
        .and_then(to_signed_auth)
        .map(CoreControlAuth::Signed)
}

/// Execute one request against the authority. Errors become structured
/// responses; the authority's own audit chain records every decision.
pub fn handle(gate: &mut Gate, req: Request) -> Response {
    let result: Result<Value, CageError> = match req {
        Request::Issue {
            scope,
            context,
            ttl_seconds,
            max_uses,
            auth,
        } => gate
            .issue_token(&scope, &context, ttl_seconds, max_uses, core_auth(&auth))
            .map(|t| serde_json::to_value(t).unwrap_or(Value::Null)),

        Request::Sign { token_id, payload } => gate
            .sign(&token_id, payload.as_bytes())
            .map(|sig| json!({ "signature": sig })),

        // Forward the (re-serialized) JSON body to the provider. NOTE: at runtime the
        // serving layer intercepts Invoke and runs it WITHOUT holding the Gate lock
        // across the network (see `server::serve_invoke`); this arm is the
        // direct/all-in-one path.
        Request::Invoke {
            token_id,
            provider,
            request_body,
        } => gate
            .invoke(&token_id, &provider, &request_body.to_string())
            .map(|r| json!({ "response": r })),

        Request::Revoke { token_id, auth } => gate
            .revoke(&token_id, core_auth(&auth))
            .map(|revoked| json!({ "revoked": revoked })),

        Request::AuditHead => Ok(json!({ "audit_head": gate.audit_head() })),

        Request::VerifyChain => Ok(json!({ "valid": gate.verify_audit_chain() })),

        // Bootstrap-gated: it signs with the audit key, so it must not be an open
        // signing oracle.
        Request::Attest { auth } => {
            if !gate.authorize_control("attest", core_auth(&auth)) {
                Err(CageError::Refused(
                    "attest requires a valid operator signature".into(),
                ))
            } else {
                gate.attestation_payload()
                    .map(|env| serde_json::from_str::<Value>(&env).unwrap_or(Value::Null))
            }
        }

        // Bootstrap-gated: entries carry entity_id (= live token_id), a bearer
        // handle that must not leak on an unauthenticated channel.
        Request::AuditLog { auth } => {
            if !gate.authorize_control("audit_log", core_auth(&auth)) {
                Err(CageError::Refused(
                    "audit_log requires a valid operator signature (it exposes live token_ids)"
                        .into(),
                ))
            } else {
                let entries: Vec<Value> = gate
                    .audit_log_snapshot()
                    .into_iter()
                    .map(|e| {
                        json!({
                            "seq": e.seq,
                            "entity_id": e.entity_id,
                            "event": e.event,
                            "data_json": e.data_json,
                            "timestamp": e.timestamp,
                            "prev_hash": e.prev_hash,
                            "hash": e.hash,
                        })
                    })
                    .collect();
                Ok(json!({ "entries": entries }))
            }
        }
    };

    match result {
        Ok(v) => Response::ok(v),
        Err(e) => Response::err(error_kind(&e), e.to_string()),
    }
}

/// Stable machine-readable category for a core error.
pub(crate) fn error_kind(e: &CageError) -> &'static str {
    match e {
        CageError::Refused(_) => "refused",
        CageError::NotFound(_) => "not_found",
        CageError::Transport(_) => "transport",
        CageError::Crypto(_) => "crypto",
        _ => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> Gate {
        let mut g = Gate::new();
        g.set_insecure_dev_mode(true); // dispatch tests issue tokens without a bootstrap
        g.store_secret("k", "secret").unwrap();
        g.register_scope_secret("sign.", "k");
        g
    }

    fn issue(g: &mut Gate, max_uses: u32) -> String {
        let resp = handle(
            g,
            Request::Issue {
                scope: "sign.x".into(),
                context: "t".into(),
                ttl_seconds: None,
                max_uses: Some(max_uses),
                auth: None,
            },
        );
        assert!(resp.ok);
        resp.result.unwrap()["token_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A fail-closed gate trusting a fresh operator key; returns both.
    fn operator_gate() -> (Gate, cage_core::OperatorKey) {
        let mut g = Gate::new();
        g.store_secret("k", "secret").unwrap();
        let key = cage_core::OperatorKey::generate();
        g.authorize_operator(&key.public_key_hex()).unwrap();
        (g, key)
    }

    /// A wire `ControlAuth` signing `op`+`args` against `g`'s broker identity, now.
    fn signed(
        g: &Gate,
        key: &cage_core::OperatorKey,
        op: &str,
        args: &[u8],
        nonce: [u8; 16],
    ) -> ControlAuth {
        let broker_id = g.attestation_verifying_key();
        let ts = now();
        let msg = cage_core::control_message(&broker_id, op, args, &nonce, ts);
        ControlAuth {
            key_id: hex::encode(key.public_key_bytes()),
            nonce: hex::encode(nonce),
            ts,
            sig: hex::encode(key.sign(&msg)),
        }
    }

    #[test]
    fn sign_through_dispatch_succeeds() {
        let mut g = gate();
        let tid = issue(&mut g, 2);
        let resp = handle(
            &mut g,
            Request::Sign {
                token_id: tid,
                payload: "hello".into(),
            },
        );
        assert!(resp.ok);
        assert!(resp.result.unwrap()["signature"].is_string());
    }

    #[test]
    fn audit_log_requires_operator_auth_when_not_dev_mode() {
        // A fail-closed (production) gate refuses audit_log without a valid operator
        // signature — it would otherwise leak live token_ids to any socket peer.
        let (mut g, key) = operator_gate();
        let refused = handle(&mut g, Request::AuditLog { auth: None });
        assert!(!refused.ok);
        assert_eq!(refused.error.unwrap().kind, "refused");
        assert!(g
            .audit_log_snapshot()
            .iter()
            .any(|e| e.event == "control_rejected_auth"
                && e.data_json.contains("\"op\":\"audit_log\"")));

        // A valid operator signature is accepted.
        let auth = signed(&g, &key, "audit_log", &[], [1u8; 16]);
        let ok = handle(&mut g, Request::AuditLog { auth: Some(auth) });
        assert!(ok.ok);
    }

    #[test]
    fn attest_requires_operator_auth_when_not_dev_mode() {
        let (mut g, _key) = operator_gate();
        let refused = handle(&mut g, Request::Attest { auth: None });
        assert!(!refused.ok);
        assert_eq!(refused.error.unwrap().kind, "refused");
        assert!(g.audit_log_snapshot().iter().any(
            |e| e.event == "control_rejected_auth" && e.data_json.contains("\"op\":\"attest\"")
        ));
    }

    #[test]
    fn issue_through_dispatch_with_operator_signature_and_replay_refused() {
        // End-to-end through the broker dispatch: a valid operator signature mints a
        // token; replaying the identical signed auth (same nonce) is refused.
        let (mut g, key) = operator_gate();
        let nonce = [7u8; 16];
        let ts = now();
        let args = cage_core::control_args_issue("sign.x", "ctx", None, Some(2));
        let broker_id = g.attestation_verifying_key();
        let msg = cage_core::control_message(&broker_id, "issue", &args, &nonce, ts);
        let sig = hex::encode(key.sign(&msg));
        let key_id = hex::encode(key.public_key_bytes());
        let mk = || ControlAuth {
            key_id: key_id.clone(),
            nonce: hex::encode(nonce),
            ts,
            sig: sig.clone(),
        };
        let req = |a| Request::Issue {
            scope: "sign.x".into(),
            context: "ctx".into(),
            ttl_seconds: None,
            max_uses: Some(2),
            auth: Some(a),
        };
        assert!(
            handle(&mut g, req(mk())).ok,
            "valid operator signature issues"
        );
        let replayed = handle(&mut g, req(mk()));
        assert!(!replayed.ok, "replayed signed auth (same nonce) is refused");
        assert_eq!(replayed.error.unwrap().kind, "refused");
    }

    #[test]
    fn over_use_returns_structured_refusal() {
        let mut g = gate();
        let tid = issue(&mut g, 1);
        let ok = handle(
            &mut g,
            Request::Sign {
                token_id: tid.clone(),
                payload: "a".into(),
            },
        );
        assert!(ok.ok);
        let refused = handle(
            &mut g,
            Request::Sign {
                token_id: tid,
                payload: "b".into(),
            },
        );
        assert!(!refused.ok);
        assert_eq!(refused.error.unwrap().kind, "refused");
    }
}
