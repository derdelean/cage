/*!
Gate — the capability authority. Issues short-lived, scope-bound, use-counted
capability tokens and *structurally refuses* any action whose token it did not
itself issue or whose token is no longer valid. Composes a [`Vault`] and records
every decision in the vault's append-only audit chain.

In the broker, the Gate runs in a trust domain separate from the agent: the
agent holds only a `token_id` and asks the Gate to act on its behalf. Structural
refusal is enforced *here*, broker-side — so a compromised agent cannot mint
tokens (it lacks the bootstrap secret), cannot exceed the bounds of the tokens it
holds, and never touches the key. The agent gets a result; the Gate keeps the
authority.
*/

use std::collections::{HashMap, HashSet};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::CageError;
use crate::operator::{
    control_args_issue, control_args_revoke, control_message, verify_operator_sig, ControlAuth,
    SignedAuth, CONTROL_AUTH_WINDOW_SECS,
};
use crate::release::ReleasePolicy;
use crate::transport::{provider_exists, TransportError};
use crate::vault::{AuditEntrySnapshot, Vault};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Ceiling on a token's TTL (7 days) — the gate, not the requester, bounds token
/// power, so a client-supplied `u64::MAX` cannot mint an effectively-permanent key.
const MAX_TTL_SECONDS: u64 = 7 * 24 * 3600;
/// Ceiling on a token's cumulative uses — a client-supplied `u32::MAX` cannot mint
/// an effectively-unlimited key.
const MAX_USES: u32 = 100_000;

/// Domain tag for [`IssuancePolicy::fingerprint`]. Bump if the encoding ever changes,
/// so a digest under the old layout can never be mistaken for one under the new.
const ISSUANCE_POLICY_DOMAIN: &[u8] = b"cage-issuance-policy-v1";

/// An operator-provisioned ceiling on what *any* token this gate issues may
/// authorize. Moved into the gate at construction ([`Gate::with_issuance_policy`]);
/// the gate exposes no setter, so it cannot be relaxed at runtime.
///
/// Why this exists: authority separation puts the secret out of the *agent's* reach
/// but does not bound the *issuer*. Whoever holds the bootstrap secret or an operator
/// key is the authority, and a stolen key can mint anything the hard ceilings allow.
/// The policy bounds that, without solving key custody.
///
/// Scope entries anchor on a namespace boundary, exactly like
/// [`Gate::scope_to_secret`]: `llm.` and `llm` both admit `llm` and `llm.<anything>`
/// at any depth, never `llmadmin`. An empty list admits nothing — a mis-provisioned
/// policy denies rather than permits.
///
/// It does not bind an attacker who controls the *host* and can restart the instance
/// with a laxer policy. [`Self::fingerprint`], recorded on the audit chain, shows a
/// verifier which policy an instance ran under.
///
/// Fields are public and there is no constructor: naming every field at the call site
/// is what stops a transposed `ttl`/`uses` pair from silently provisioning the wrong
/// ceiling. Matches [`crate::release::ReleasePolicy`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuancePolicy {
    /// Namespaces (or exact scopes) this gate may issue for. Empty admits nothing.
    pub allowed_scopes: Vec<String>,
    pub max_ttl_seconds: u64,
    pub max_uses: u32,
    /// Cap on how many tokens this gate will issue for one *policy entry* over its
    /// whole lifetime — not a rate: there is no window and no decay, and revocation
    /// or expiry never returns a slot. Sized for the instance's expected lifetime
    /// workload; once reached, that namespace is closed until the instance is
    /// re-provisioned and restarted. The count lives in this instance: a restart, or
    /// a parallel instance with the same policy, starts from zero, so against a host
    /// that can relaunch the instance this is a per-boot cap. `None` leaves issuance
    /// count unbounded.
    pub max_tokens_per_scope: Option<u32>,
}

impl IssuancePolicy {
    /// The policy entry admitting `scope`, if any. Returned rather than a bool so the
    /// cumulative counter can be keyed by the *entry* — keying it by the requested
    /// scope would let `llm.a`, `llm.b`, … each open a fresh budget under one entry.
    fn matching_entry(&self, scope: &str) -> Option<&str> {
        self.allowed_scopes
            .iter()
            .find(|allowed| {
                let p = allowed.strip_suffix('.').unwrap_or(allowed);
                scope == p || scope.strip_prefix(p).is_some_and(|r| r.starts_with('.'))
            })
            .map(String::as_str)
    }

    /// Why this issuance must be refused, or `None` to allow. Takes the count already
    /// issued against the matched entry so the caller owns all gate state.
    fn refusal(&self, scope: &str, issued_for_entry: u32) -> Option<String> {
        let Some(entry) = self.matching_entry(scope) else {
            return Some("scope not permitted by issuance policy".into());
        };
        match self.max_tokens_per_scope {
            Some(limit) if issued_for_entry >= limit => Some(format!(
                "cumulative issuance ceiling reached for policy entry {entry:?}"
            )),
            _ => None,
        }
    }

    /// Refuse two distinct entries whose namespaces are equal or nested, such as
    /// `sign.` and `sign.a` or `llm` and `llm.`. Matching takes the first entry in
    /// provisioning order and the cumulative cap is counted per entry, so with
    /// overlapping entries a reordered policy would enforce different budgets under
    /// the same [`fingerprint`](Self::fingerprint). An exact duplicate is allowed:
    /// it never changes which entry matches.
    pub fn validate(&self) -> Result<(), CageError> {
        let stem = |entry: &str| entry.strip_suffix('.').unwrap_or(entry).to_string();
        let nested = |outer: &str, inner: &str| {
            inner
                .strip_prefix(outer)
                .is_some_and(|rest| rest.starts_with('.'))
        };
        for (i, a) in self.allowed_scopes.iter().enumerate() {
            for b in &self.allowed_scopes[i + 1..] {
                if a == b {
                    continue;
                }
                let (sa, sb) = (stem(a), stem(b));
                if sa == sb || nested(&sa, &sb) || nested(&sb, &sa) {
                    return Err(CageError::Refused(format!(
                        "issuance policy entries {a:?} and {b:?} overlap: name each namespace once"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Stable identity of this policy: same policy in, same digest out; any change to
    /// any bound changes it. Recorded in the audit chain so entries can be tied to the
    /// policy in force.
    ///
    /// Canonicalizes first (sort + dedup), because order of provisioning and a
    /// repeated entry are not policy changes: [`validate`](Self::validate) refuses
    /// overlapping entries, so no scope can match two entries and order cannot
    /// change which one applies. Uses the crate's canonical framing plus a domain
    /// tag, so this digest can never be confused with another SHA-256 construction
    /// in the system.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut buf = Vec::new();
        crate::operator::framed(&mut buf, ISSUANCE_POLICY_DOMAIN);
        let mut scopes: Vec<&str> = self.allowed_scopes.iter().map(String::as_str).collect();
        scopes.sort_unstable();
        scopes.dedup();
        buf.extend_from_slice(&(scopes.len() as u32).to_be_bytes());
        for s in scopes {
            crate::operator::framed(&mut buf, s.as_bytes());
        }
        buf.extend_from_slice(&self.max_ttl_seconds.to_be_bytes());
        buf.extend_from_slice(&self.max_uses.to_be_bytes());
        crate::operator::opt_u32(&mut buf, self.max_tokens_per_scope);
        hex::encode(Sha256::digest(&buf))
    }
}

fn random_token_id() -> String {
    use rand_core::RngCore;
    let mut buf = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// First up to 8 *characters* of an id, for log/error display. Char-based, never
/// a byte slice: slicing a `&str` by byte index panics on a multi-byte UTF-8
/// boundary, and `id` may be attacker-supplied (an unknown token_id reaches this
/// via the refusal path before any validation).
fn short(id: &str) -> String {
    id.chars().take(8).collect()
}

/// The verb a capability is being exercised for. A token's scope namespace (its
/// first dotted segment) binds it to one verb, so a token issued for one operation
/// cannot drive another — an LLM token can neither reach the release-signing key
/// nor become an HMAC oracle on the provider key (operation isolation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// HMAC signing — requires a `sign.` scope.
    Sign,
    /// LLM / provider invocation — any provider scope (not the reserved sign/release verbs).
    Invoke,
    /// Release signing — requires a `release.` scope (so it reaches the ed25519
    /// release key only from a release-scoped token).
    SignRelease,
}

impl Operation {
    fn verb(&self) -> &'static str {
        match self {
            Operation::Sign => "sign",
            Operation::Invoke => "invoke",
            Operation::SignRelease => "release",
        }
    }

    /// True if a token with `scope` may exercise this operation.
    fn permits(&self, scope: &str) -> bool {
        let ns = scope.split('.').next().unwrap_or("");
        match self {
            Operation::Sign => ns == "sign",
            Operation::SignRelease => ns == "release",
            // Invoke is for provider scopes — never the reserved sign/release verbs.
            Operation::Invoke => ns != "sign" && ns != "release",
        }
    }
}

/// A capability token — an opaque handle. The only authority-bearing field is
/// `token_id`; the Gate holds the canonical record and never trusts a
/// caller-supplied copy. Serialized to the agent as JSON (it is not secret).
#[derive(Clone, Debug, Serialize)]
pub struct CapabilityToken {
    pub token_id: String,
    pub scope: String,
    pub context: String,
    pub issued_at_unix: u64,
    pub ttl_seconds: u64,
    pub max_uses: u32,
    pub use_count: u32,
    pub revoked: bool,
}

impl CapabilityToken {
    fn is_valid(&self, requested_scope: &str, now: u64) -> bool {
        !self.revoked
            && now >= self.issued_at_unix // reject a clock rollback to before issue
            && now - self.issued_at_unix <= self.ttl_seconds
            && self.scope == requested_scope
            && self.use_count < self.max_uses
    }
}

/// A reserved invocation: the token use has been charged and the credential
/// decrypted, under the gate's lock. The caller performs the network round-trip
/// with the lock released, then settles the reservation via
/// [`Gate::finalize_invoke`] (success), [`Gate::refund_invoke`] (a pre-send
/// failure — refunds the use), or [`Gate::fail_invoke`] (a post-send failure —
/// the use stays charged). This split is what lets the PyO3 / broker paths drop
/// their lock across the network while keeping authorize+charge atomic.
pub struct InvokeReservation {
    token_id: String,
    scope: String,
    provider: String,
    key: Zeroizing<Vec<u8>>,
}

impl InvokeReservation {
    /// Hand the decrypted credential to the transport, which zeroes it once the
    /// request buffer holds it, so no copy waits here through the response. It stays
    /// in Rust-owned `Zeroizing` memory and never crosses PyO3. After the first
    /// call the reservation holds an empty buffer.
    pub fn take_key(&mut self) -> Zeroizing<Vec<u8>> {
        std::mem::replace(&mut self.key, Zeroizing::new(Vec::new()))
    }

    /// The provider this reservation targets.
    pub fn provider(&self) -> &str {
        &self.provider
    }
}

/// Capability authority composing a [`Vault`].
pub struct Gate {
    vault: Vault,
    tokens: HashMap<String, CapabilityToken>,
    revoked: HashSet<String>,
    scope_secret: HashMap<String, String>,
    /// Secret name → the only provider it may be sent to. Write-once.
    secret_provider: HashMap<String, String>,
    default_ttl_seconds: u64,
    default_max_uses: u32,
    release_policy: Option<ReleasePolicy>,
    /// Frozen issuance ceiling (see [`IssuancePolicy`]). No setter exists.
    issuance_policy: Option<IssuancePolicy>,
    /// `fingerprint()` of the above, computed once — it cannot change.
    policy_fingerprint: Option<String>,
    /// Tokens issued per *policy entry*, for the cumulative ceiling. Counts issuance,
    /// so revoking a token does not buy another one. Only maintained when a policy
    /// with a ceiling is set — nothing else reads it.
    issued_per_entry: HashMap<String, u32>,
    /// When true, token issuance/revocation do NOT require the bootstrap token.
    /// Development/testing ONLY — production stays fail-closed (the default).
    insecure_dev_mode: bool,
    /// When true, [`Gate::consume`] may hand plaintext back to the caller.
    /// Development ONLY — and deliberately **separate** from `insecure_dev_mode`:
    /// the switch that re-enables the deprecated leak must not be the same switch
    /// that waives control-plane auth, or restoring `consume()` would silently
    /// unlock issuance/revocation too.
    allow_plaintext_consume: bool,
    /// Monotonic issue stamp per token — the TTL is enforced against this, not the
    /// wallclock, so a host clock rollback cannot revive or extend a token.
    token_issued_at: HashMap<String, Instant>,
    /// Trusted operator public keys for control-plane proof-of-possession (broker
    /// path). The broker holds only these public keys — never a forge-the-authority
    /// secret. Empty in the in-process / dev configuration, which uses the bootstrap.
    operator_keys: Vec<VerifyingKey>,
    /// Seen control-plane nonces → eviction deadline (unix). Replay defense for
    /// signed auth; time-window-bounded (entries past `ts + window` are evicted), so
    /// unlike the token map it cannot grow without bound.
    cp_nonces: HashMap<[u8; 16], u64>,
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

impl Gate {
    pub fn new() -> Self {
        Gate {
            vault: Vault::new(),
            tokens: HashMap::new(),
            revoked: HashSet::new(),
            scope_secret: HashMap::new(),
            secret_provider: HashMap::new(),
            default_ttl_seconds: 300,
            default_max_uses: 50,
            release_policy: None,
            issuance_policy: None,
            policy_fingerprint: None,
            issued_per_entry: HashMap::new(),
            insecure_dev_mode: false,
            allow_plaintext_consume: false,
            token_issued_at: HashMap::new(),
            operator_keys: Vec::new(),
            cp_nonces: HashMap::new(),
        }
    }

    /// Construct a gate whose issuance is bounded by a frozen [`IssuancePolicy`].
    /// Refuses a policy that fails [`IssuancePolicy::validate`].
    ///
    /// The policy is provisioned here and **cannot be changed afterwards** — that
    /// immutability is the point: it bounds the holder of the issuing authority, not
    /// just the agent. Relaxing it requires restarting the enforcement instance with
    /// different provisioning, so it does not bind whoever can restart the instance.
    /// A restart starts the cumulative counts from zero.
    pub fn with_issuance_policy(policy: IssuancePolicy) -> Result<Self, CageError> {
        policy.validate()?;
        let mut gate = Gate::new();
        let fingerprint = policy.fingerprint();
        // Audited before the policy is installed, so this entry always precedes every
        // `issued` entry minted under it. Records the bounds too: the policy is
        // operator-provisioned, not secret, and a bare digest would let an auditor
        // prove only that one policy was in force, never which.
        gate.audit(
            "vault",
            "issuance_policy_frozen",
            &serde_json::json!({
                "policy_fingerprint": fingerprint,
                "allowed_scopes": policy.allowed_scopes,
                "max_ttl_seconds": policy.max_ttl_seconds,
                "max_uses": policy.max_uses,
                "max_tokens_per_scope": policy.max_tokens_per_scope,
            }),
        );
        gate.policy_fingerprint = Some(fingerprint);
        gate.issuance_policy = Some(policy);
        Ok(gate)
    }

    /// Fingerprint of the frozen issuance policy, or `None` when this gate was
    /// constructed without one.
    pub fn issuance_policy_fingerprint(&self) -> Option<String> {
        self.policy_fingerprint.clone()
    }

    /// Enable insecure dev mode: issuance/revocation no longer require the
    /// bootstrap token. For development and tests ONLY — a production gate stays
    /// fail-closed so the shipped vault cannot mint full-authority tokens without
    /// proof of the bootstrap secret.
    ///
    /// Construction-only: call it right after [`Gate::new`] and never wire it to a
    /// runtime input. The PyO3 shell takes it as a constructor argument with no
    /// setter; the broker binary never calls it. Enabling it is
    /// recorded on the chain, so a chain without that entry was minted fail-closed.
    pub fn set_insecure_dev_mode(&mut self, enabled: bool) {
        self.insecure_dev_mode = enabled;
        if enabled {
            self.audit("vault", "insecure_dev_mode_enabled", &serde_json::json!({}));
        }
    }

    /// Enable the deprecated plaintext [`Gate::consume`] path. Development ONLY;
    /// same construction-only contract and chain entry as
    /// [`Gate::set_insecure_dev_mode`].
    ///
    /// It is a switch of its own rather than a facet of `insecure_dev_mode` on
    /// purpose: an integrator who needs the leak for a scope with no gated
    /// operation yet must not have to waive control-plane auth to get it.
    pub fn set_allow_plaintext_consume(&mut self, enabled: bool) {
        self.allow_plaintext_consume = enabled;
        if enabled {
            self.audit("vault", "plaintext_consume_enabled", &serde_json::json!({}));
        }
    }

    /// Store a credential in the vault (control plane / broker startup). The
    /// vault is never exposed directly — callers reach it only through the gated
    /// operations on this authority, so a credential cannot be read back out.
    pub fn store_secret(&mut self, name: &str, value: &str) -> Result<(), CageError> {
        self.vault
            .store_secret(name.to_string(), value.to_string())?;
        // Audit the genesis credential event (Invariant 4) — so the broker's chain
        // records when a credential entered the vault (never the secret value).
        self.audit(
            "vault",
            "secret_stored",
            &serde_json::json!({ "name": name }),
        );
        Ok(())
    }

    /// Load credentials from a `.env` file straight into vault memory (the
    /// plaintext never leaves Rust). Returns the count loaded.
    pub fn load_credentials_from_env(
        &mut self,
        path: &str,
        names: &[String],
    ) -> Result<usize, CageError> {
        let loaded = self.vault.load_from_env_file(path, names.to_vec())?;
        // Audit the genesis credential-load event (broker startup), never the
        // secret values — only the count.
        self.audit(
            "vault",
            "credentials_loaded",
            &serde_json::json!({ "count": loaded }),
        );
        Ok(loaded)
    }

    /// Map a scope prefix to a stored secret name (longest prefix wins).
    pub fn register_scope_secret(&mut self, scope_prefix: &str, secret_name: &str) {
        self.scope_secret
            .insert(scope_prefix.to_string(), secret_name.to_string());
    }

    /// Pin the secret `secret_name` to `provider`. An invoke that resolves to this
    /// secret and names another provider is refused before anything is decrypted or
    /// charged, whichever scope prefix it came through. Write-once: pinning again to
    /// the same provider is a no-op, to another one is refused. Audited.
    pub fn pin_secret_provider(
        &mut self,
        secret_name: &str,
        provider: &str,
    ) -> Result<(), CageError> {
        if !provider_exists(provider) {
            return Err(CageError::Refused(format!(
                "cannot pin {secret_name:?} to unknown provider {provider:?}"
            )));
        }
        match self.secret_provider.get(secret_name) {
            Some(pinned) if pinned == provider => return Ok(()),
            Some(pinned) => {
                return Err(CageError::Refused(format!(
                    "secret {secret_name:?} is already pinned to provider {pinned:?}"
                )));
            }
            None => {}
        }
        self.secret_provider
            .insert(secret_name.to_string(), provider.to_string());
        self.audit(
            "vault",
            "provider_pinned",
            &serde_json::json!({ "secret": secret_name, "provider": provider }),
        );
        Ok(())
    }

    pub fn unseal(&mut self) -> Result<Zeroizing<String>, CageError> {
        let bootstrap = self.vault.unseal()?;
        self.audit("vault", "unsealed", &serde_json::json!({}));
        Ok(bootstrap)
    }

    pub fn is_unsealed(&self) -> bool {
        self.vault.is_unsealed()
    }

    /// Issue a capability token. Fail-closed: requires valid control-plane
    /// authorization — an operator signature ([`ControlAuth::Signed`], the broker
    /// path) or the in-process bootstrap secret ([`ControlAuth::Bootstrap`]). A
    /// caller without it cannot mint tokens, closing the "any in-process code mints
    /// full-authority tokens" gap. `set_insecure_dev_mode(true)` waives this for
    /// development/tests only.
    pub fn issue_token(
        &mut self,
        scope: &str,
        context: &str,
        ttl_seconds: Option<u64>,
        max_uses: Option<u32>,
        auth: Option<ControlAuth<'_>>,
    ) -> Result<CapabilityToken, CageError> {
        let args = control_args_issue(scope, context, ttl_seconds, max_uses);
        if !self.verify_control_auth("issue", &args, auth.as_ref()) {
            self.audit(
                "vault",
                "issuance_rejected_auth",
                &serde_json::json!({"scope": scope, "context": context}),
            );
            return Err(CageError::Refused(
                "issue_token requires valid control-plane authorization (an operator \
                 signature or the bootstrap; insecure_dev_mode waives it for development)"
                    .into(),
            ));
        }

        // The control-plane check above proves *who* is asking; the frozen policy
        // bounds *what* they may obtain. Scope is refused outright; ttl/max_uses are
        // clamped below rather than refused, matching the pre-existing clamp.
        let matched_entry = match &self.issuance_policy {
            Some(policy) => {
                let entry = policy.matching_entry(scope).map(str::to_string);
                let issued = entry
                    .as_deref()
                    .and_then(|e| self.issued_per_entry.get(e).copied())
                    .unwrap_or(0);
                if let Some(reason) = policy.refusal(scope, issued) {
                    self.audit(
                        "vault",
                        "issuance_rejected_policy",
                        &serde_json::json!({
                            "scope": scope,
                            "reason": reason,
                            "policy_fingerprint": self.policy_fingerprint,
                        }),
                    );
                    // The limit itself stays out of the caller-visible error: the
                    // caller here is the party the policy exists to bound.
                    return Err(CageError::Refused(format!(
                        "{reason} (requested scope {scope:?})"
                    )));
                }
                entry
            }
            None => None,
        };

        // Clamp client-supplied bounds at the gate (the authority on token power), so
        // an unbounded ttl/max_uses cannot mint an effectively-permanent or unlimited
        // "skeleton key". A policy only ever narrows this further.
        let (ttl_ceiling, uses_ceiling) = match &self.issuance_policy {
            Some(p) => (
                p.max_ttl_seconds.min(MAX_TTL_SECONDS),
                p.max_uses.min(MAX_USES),
            ),
            None => (MAX_TTL_SECONDS, MAX_USES),
        };
        let ttl_seconds = ttl_seconds
            .unwrap_or(self.default_ttl_seconds)
            .min(ttl_ceiling);
        let max_uses = max_uses.unwrap_or(self.default_max_uses).min(uses_ceiling);
        let token = CapabilityToken {
            token_id: random_token_id(),
            scope: scope.to_string(),
            context: context.to_string(),
            issued_at_unix: now_unix(),
            ttl_seconds,
            max_uses,
            use_count: 0,
            revoked: false,
        };
        self.tokens.insert(token.token_id.clone(), token.clone());
        self.token_issued_at
            .insert(token.token_id.clone(), Instant::now());
        // Count issuance (not live tokens): revoking a token must not free a slot, or
        // the ceiling would be bypassable by issue→revoke→issue. Keyed by the policy
        // entry, so every scope in a namespace shares one budget. Only maintained when
        // a ceiling is configured — otherwise nothing reads it and it would grow
        // without bound on a long-lived broker.
        if let Some(entry) = matched_entry {
            if self
                .issuance_policy
                .as_ref()
                .and_then(|p| p.max_tokens_per_scope)
                .is_some()
            {
                let n = self.issued_per_entry.entry(entry).or_insert(0);
                *n = n.saturating_add(1);
            }
        }
        self.audit(
            &token.token_id,
            "issued",
            &serde_json::json!({
                "scope": scope, "context": context, "max_uses": token.max_uses,
                "ttl_seconds": token.ttl_seconds,
                // Record which policy was in force, so the audit chain proves the
                // bound a token was minted under — not merely that it was minted.
                "policy_fingerprint": self.policy_fingerprint,
            }),
        );
        Ok(token)
    }

    /// Structural refusal: resolve and validate this gate's canonical record for
    /// `token_id`. The caller's copy is never trusted. Returns the canonical
    /// token on success; a refusal (audited) otherwise.
    ///
    /// `context`, when `Some`, must constant-time-match the context the token was
    /// issued with — a relying party binds a capability to an external identity by
    /// placing that identity (e.g. a verified OIDC subject or a SPIFFE/WIMSE
    /// workload id) in `context` at issuance, so a token_id stolen without its
    /// issued context is refused. Opt-in: a `None` context preserves prior
    /// behaviour. This is defense-in-depth, not a cryptographic proof-of-possession
    /// (a challenge-response binding is a separate, larger change).
    pub fn authorize(
        &mut self,
        token_id: &str,
        requested_scope: Option<&str>,
        context: Option<&str>,
    ) -> Result<CapabilityToken, CageError> {
        let canonical = match self.tokens.get(token_id) {
            Some(t) => t.clone(),
            None => {
                self.audit(
                    token_id,
                    "rejected_unknown_token",
                    &serde_json::json!({"reason": "token not issued by this gate"}),
                );
                return Err(CageError::Refused(format!(
                    "token {}… was not issued by this gate",
                    short(token_id)
                )));
            }
        };

        let requested = requested_scope.unwrap_or(&canonical.scope);
        if !canonical.is_valid(requested, now_unix()) {
            self.audit(
                &canonical.token_id,
                "rejected",
                &serde_json::json!({
                    "scope_requested": requested,
                    "scope_token": canonical.scope,
                    "use_count": canonical.use_count,
                    "revoked": canonical.revoked,
                }),
            );
            return Err(CageError::Refused(format!(
                "token {}… invalid for scope {:?}: revoked={}, uses={}/{}",
                short(&canonical.token_id),
                requested,
                canonical.revoked,
                canonical.use_count,
                canonical.max_uses
            )));
        }

        // Authoritative TTL on a MONOTONIC clock: a host adversary rolling the
        // wallclock back (to revive an expired token, or extend a live one) cannot
        // affect this — the Instant stamp only moves forward.
        if let Some(issued) = self.token_issued_at.get(&canonical.token_id) {
            if issued.elapsed().as_secs() > canonical.ttl_seconds {
                self.audit(
                    &canonical.token_id,
                    "rejected",
                    &serde_json::json!({"reason": "monotonic ttl exceeded"}),
                );
                return Err(CageError::Refused(format!(
                    "token {}… expired (monotonic clock)",
                    short(&canonical.token_id)
                )));
            }
        }

        // Optional context binding: when the caller presents a context, it must
        // constant-time-match the one the token was issued with — so a token bound
        // at issuance to an external identity (the relying party places it in
        // `context`) cannot be exercised on a presented context it was not issued
        // for. `ct_eq` keeps the byte comparison constant-time (length, which is not
        // secret, may differ and short-circuits to a mismatch).
        if let Some(presented) = context {
            if !bool::from(presented.as_bytes().ct_eq(canonical.context.as_bytes())) {
                self.audit(
                    &canonical.token_id,
                    "rejected_context_mismatch",
                    &serde_json::json!({ "scope_requested": requested }),
                );
                return Err(CageError::Refused(format!(
                    "token {}… presented context does not match its issued context",
                    short(&canonical.token_id)
                )));
            }
        }
        Ok(canonical)
    }

    /// Authorize a token AND enforce that its scope namespace permits `op` — so a
    /// token issued for one verb cannot drive another (e.g. an LLM token cannot
    /// reach the release key, nor become an HMAC oracle on the provider key).
    fn authorize_op(
        &mut self,
        token_id: &str,
        op: Operation,
    ) -> Result<CapabilityToken, CageError> {
        let canonical = self.authorize(token_id, None, None)?;
        if !op.permits(&canonical.scope) {
            self.audit(
                token_id,
                "rejected_wrong_verb",
                &serde_json::json!({"scope": canonical.scope, "operation": op.verb()}),
            );
            return Err(CageError::Refused(format!(
                "token scope {:?} does not authorize {} (verb mismatch)",
                canonical.scope,
                op.verb()
            )));
        }
        Ok(canonical)
    }

    /// Immediately revoke a token. A control-plane operation: fail-closed, it
    /// requires valid control-plane authorization (an operator signature or the
    /// bootstrap), so a rogue agent holding only token_ids cannot revoke other
    /// agents' tokens (DoS). Audited; subsequent authorize() calls refuse.
    /// `set_insecure_dev_mode(true)` waives it for dev/tests.
    pub fn revoke(
        &mut self,
        token_id: &str,
        auth: Option<ControlAuth<'_>>,
    ) -> Result<bool, CageError> {
        let args = control_args_revoke(token_id);
        if !self.verify_control_auth("revoke", &args, auth.as_ref()) {
            self.audit(token_id, "revoke_rejected_auth", &serde_json::json!({}));
            return Err(CageError::Refused(
                "revoke requires valid control-plane authorization (an operator \
                 signature or the bootstrap; insecure_dev_mode waives it for development)"
                    .into(),
            ));
        }
        if self.revoked.contains(token_id) {
            return Ok(false);
        }
        let scope = match self.tokens.get_mut(token_id) {
            Some(t) => {
                t.revoked = true;
                t.scope.clone()
            }
            None => return Ok(false),
        };
        self.revoked.insert(token_id.to_string());
        self.audit(token_id, "revoked", &serde_json::json!({ "scope": scope }));
        Ok(true)
    }

    /// Resolve a scope to its registered secret name (longest prefix wins).
    pub fn scope_to_secret(&self, scope: &str) -> Result<String, CageError> {
        let mut best: Option<(&String, &String)> = None;
        for (prefix, name) in &self.scope_secret {
            // Anchor on a namespace boundary: a registered "llm" / "llm." matches
            // "llm" and "llm.<anything>", never "llmadmin" / "llm-evil".
            let p = prefix.strip_suffix('.').unwrap_or(prefix);
            let matches = scope == p || scope.strip_prefix(p).is_some_and(|r| r.starts_with('.'));
            if matches {
                let better = match best {
                    Some((bp, _)) => prefix.len() > bp.len(),
                    None => true,
                };
                if better {
                    best = Some((prefix, name));
                }
            }
        }
        best.map(|(_, n)| n.clone())
            .ok_or_else(|| CageError::Refused(format!("unknown scope namespace: {scope:?}")))
    }

    /// High-level signing operation: authorize the token against its own scope,
    /// resolve the secret, record a use, audit, and HMAC-sign `payload` with the
    /// vault-held key. The agent gets a signature; the key never leaves the Gate.
    pub fn sign(&mut self, token_id: &str, payload: &[u8]) -> Result<String, CageError> {
        let canonical = self.authorize_op(token_id, Operation::Sign)?;
        let secret = self.resolve_secret_for(token_id, &canonical.scope)?;
        let uses = self.record_use(token_id)?;
        let sig = self.vault.sign_hmac(&secret, payload)?;
        // Fail-closed: a signature is returned only once its audit entry exists.
        self.audit_checked(
            token_id,
            "signed",
            &serde_json::json!({"scope": canonical.scope, "use_count": uses}),
        )?;
        Ok(sig)
    }

    /// High-level LLM invocation (real network), all-in-one: authorize, charge,
    /// call the provider, settle. Used by the broker. The PyO3 path instead uses
    /// [`reserve_invoke`](Self::reserve_invoke) + [`finalize_invoke`](Self::finalize_invoke)
    /// so it can drop its lock across the network while keeping authorize+charge
    /// atomic. Both share the same charge-on-reserve / refund-only-pre-send accounting.
    pub fn invoke(
        &mut self,
        token_id: &str,
        provider: &str,
        body_json: &str,
    ) -> Result<String, CageError> {
        let mut reservation = self.reserve_invoke(token_id, provider)?;
        let key = reservation.take_key();
        let result =
            crate::transport::post_messages(reservation.provider(), key, body_json.as_bytes());
        match result {
            Ok(response) => {
                self.finalize_invoke(&reservation)?;
                Ok(response)
            }
            Err(e) => {
                let msg = e.to_string();
                if e.is_pre_send() {
                    self.refund_invoke(&reservation, &msg);
                } else {
                    self.fail_invoke(&reservation, &msg);
                }
                Err(CageError::from(e))
            }
        }
    }

    /// Authorize, validate the provider, **charge a use** (before the network),
    /// and decrypt the credential — all under the caller's exclusive borrow. The
    /// decrypted key stays inside the returned [`InvokeReservation`] until the caller
    /// hands it to the transport ([`InvokeReservation::take_key`]), performs the TLS
    /// round-trip with its lock released, then settles via finalize / refund / fail.
    /// Charging before the write (and refunding only on a pre-send failure) means a
    /// provider that received the key-bearing request always costs a use — closing
    /// the "force a rejection for unbounded billed calls" gap.
    pub fn reserve_invoke(
        &mut self,
        token_id: &str,
        provider: &str,
    ) -> Result<InvokeReservation, CageError> {
        // Unknown provider: refuse before charging or decrypting anything — no
        // network performed, no use spent.
        if !provider_exists(provider) {
            self.audit(
                token_id,
                "invoke_failed",
                &serde_json::json!({"provider": provider, "reason": "unknown provider"}),
            );
            return Err(CageError::Transport(TransportError::UnknownProvider(
                provider.to_string(),
            )));
        }
        let canonical = self.authorize_op(token_id, Operation::Invoke)?;
        let secret = self.resolve_secret_for(token_id, &canonical.scope)?;
        if let Some(pinned) = self.secret_provider.get(&secret).cloned() {
            if pinned != provider {
                self.audit(
                    token_id,
                    "rejected_provider",
                    &serde_json::json!({
                        "scope": canonical.scope, "provider": provider, "pinned": pinned,
                    }),
                );
                return Err(CageError::Refused(format!(
                    "the credential for scope {:?} is pinned to provider {pinned:?}, not {provider:?}",
                    canonical.scope
                )));
            }
        }
        let key = self.vault.decrypt_secret(&secret)?;
        self.record_use(token_id)?; // reserve: charge before the network
        Ok(InvokeReservation {
            token_id: token_id.to_string(),
            scope: canonical.scope,
            provider: provider.to_string(),
            key,
        })
    }

    /// Record a successful invocation (the provider returned a response).
    /// Fail-closed: the "invoked" entry is part of settling the call, so the
    /// response is handed back only once that entry exists.
    pub fn finalize_invoke(&mut self, reservation: &InvokeReservation) -> Result<(), CageError> {
        let uses = self
            .tokens
            .get(&reservation.token_id)
            .map(|t| t.use_count)
            .unwrap_or(0);
        self.audit_checked(
            &reservation.token_id,
            "invoked",
            &serde_json::json!({
                "scope": reservation.scope, "use_count": uses, "provider": reservation.provider,
            }),
        )
    }

    /// Refund the reserved use after a PRE-SEND failure (the provider saw nothing).
    pub fn refund_invoke(&mut self, reservation: &InvokeReservation, reason: &str) {
        if let Some(t) = self.tokens.get_mut(&reservation.token_id) {
            t.use_count = t.use_count.saturating_sub(1);
        }
        self.audit(
            &reservation.token_id,
            "invoke_refunded",
            &serde_json::json!({
                "scope": reservation.scope, "provider": reservation.provider, "reason": reason,
            }),
        );
    }

    /// Record a POST-SEND failure (the provider received the request). The reserved
    /// use stays charged — a rejected response must not buy a free retry.
    pub fn fail_invoke(&mut self, reservation: &InvokeReservation, reason: &str) {
        self.audit(
            &reservation.token_id,
            "invoke_failed",
            &serde_json::json!({
                "scope": reservation.scope, "provider": reservation.provider, "reason": reason,
            }),
        );
    }

    /// Token-gated plaintext retrieval — the deprecated `consume` path. Authorizes
    /// against `requested_scope`, charges a use, audits, and returns the secret as a
    /// String. The plaintext crosses the binding boundary here; this is the
    /// deprecated leak path, kept **token-gated** until per-provider transports
    /// replace it (so it is never an *un*gated bypass like the old raw retrieve).
    ///
    /// **Off unless [`Gate::set_allow_plaintext_consume`] was set.** Because it
    /// hands plaintext back into the caller's address space, a gate refuses it
    /// structurally by default — so the "no plaintext key in the agent" property
    /// holds for a gate built at the defaults, regardless of the deprecation. The
    /// switch is same-trust-domain hygiene, not a boundary: a caller who controls
    /// construction can build a gate with it on. The token is authorized first,
    /// so the refusal — audited like every other — is keyed on a validated token
    /// and a forged one is rejected as unknown, exactly as on the other ops. Full
    /// removal follows once every provider a customer needs has a Rust transport.
    pub fn consume(&mut self, token_id: &str, requested_scope: &str) -> Result<String, CageError> {
        self.authorize(token_id, Some(requested_scope), None)?;
        if !self.allow_plaintext_consume {
            self.audit(
                token_id,
                "consume_refused_plaintext_disabled",
                &serde_json::json!({ "scope": requested_scope }),
            );
            return Err(CageError::Refused(
                "consume() returns plaintext into the caller's address space and is \
                 disabled by default. Use a gated op that keeps the key in the \
                 vault — invoke for LLM scopes, sign for signing scopes; a scope \
                 with neither is not production-supported."
                    .to_string(),
            ));
        }
        let secret = self.resolve_secret_for(token_id, requested_scope)?;
        let uses = self.record_use(token_id)?;
        let value = self.vault.retrieve_secret(&secret)?;
        // Fail-closed: the plaintext is returned only once its audit entry exists.
        self.audit_checked(
            token_id,
            "consumed",
            &serde_json::json!({"scope": requested_scope, "use_count": uses}),
        )?;
        Ok(value)
    }

    /// Configure the release-signing policy (control plane). The requester never
    /// supplies the policy — a compromised CI must not be able to relax it.
    pub fn set_release_policy(&mut self, policy: ReleasePolicy) {
        self.release_policy = Some(policy);
    }

    /// Sign a release artifact **iff** the capability token authorizes it AND the
    /// DSSE-wrapped in-toto/SLSA attestation passes the configured policy. The
    /// signing key never leaves the gate, so a compromised CI holding only a token
    /// cannot get a malicious or off-policy artifact signed — and every decision is
    /// audited. `attestation_dsse` is a standard DSSE envelope (as GitHub/Sigstore
    /// emit); `artifact_sha256` is the raw hex digest it must bind.
    pub fn sign_release(
        &mut self,
        token_id: &str,
        artifact_sha256: &str,
        attestation_dsse: &[u8],
    ) -> Result<String, CageError> {
        // Gate the action on a valid capability token; the returned record is
        // unused because release authority comes from the token + the server-side
        // policy, not from a scope→secret mapping. A failed check is audited
        // inside authorize().
        self.authorize_op(token_id, Operation::SignRelease)?;
        // Validate the digest BEFORE signing anything, so the release path is never
        // a signing oracle over short, attacker-chosen strings.
        if !crate::release::is_sha256_hex(artifact_sha256) {
            self.audit(
                token_id,
                "release_refused",
                &serde_json::json!({
                    "artifact": artifact_sha256,
                    "reason": "artifact_sha256 must be 64 lowercase hex",
                }),
            );
            return Err(CageError::Refused(
                "artifact_sha256 must be exactly 64 lowercase hex".into(),
            ));
        }
        let policy = match self.release_policy.clone() {
            Some(p) => p,
            None => {
                self.audit(
                    token_id,
                    "release_refused",
                    &serde_json::json!({
                        "artifact": artifact_sha256,
                        "reason": "no release policy configured",
                    }),
                );
                return Err(CageError::Refused("no release policy configured".into()));
            }
        };
        let verified = match crate::release::verify(&policy, attestation_dsse, artifact_sha256) {
            Ok(v) => v,
            Err(e) => {
                self.audit(
                    token_id,
                    "release_refused",
                    &serde_json::json!({"artifact": artifact_sha256, "reason": e.to_string()}),
                );
                return Err(CageError::Refused(format!("release refused: {e}")));
            }
        };
        let uses = self.record_use(token_id)?;
        // Sign the STRUCTURED statement binding the policy-verified provenance
        // (digest + source repo/ref/builder) with the vault's RELEASE identity —
        // a key distinct from the audit-attestation key, publicly verifiable with
        // `release_public_key()`. Signing the verified provenance (not the bare
        // digest) means the published signature commits to what was actually
        // checked, and it can never be confused with an audit-head attestation.
        let statement = crate::release::release_signing_statement(&verified, artifact_sha256);
        let sig = self.vault.sign_release(&statement);
        // Fail-closed: the release signature is returned only once its entry exists.
        self.audit_checked(
            token_id,
            "release_signed",
            &serde_json::json!({
                "artifact": artifact_sha256,
                "source_repo": verified.source_repo,
                "source_ref": verified.source_ref,
                "builder": verified.builder,
                "use_count": uses,
            }),
        )?;
        Ok(sig)
    }

    pub fn audit_head(&self) -> String {
        self.vault.audit_head()
    }

    pub fn verify_audit_chain(&self) -> bool {
        self.vault.verify_audit_chain()
    }

    /// Signed checkpoint over the current audit (head, len) — the artifact to anchor
    /// off-box (Rekor). See [`Vault::checkpoint`].
    pub fn checkpoint(&self) -> Result<String, CageError> {
        self.vault.checkpoint()
    }

    /// Verify the chain extends an externally-held signed checkpoint (truncation /
    /// prefix-rewrite is detected). See [`Vault::verify_audit_chain_extends`].
    pub fn verify_audit_chain_extends(
        &self,
        anchored_head: &str,
        anchored_len: u64,
        signature_b64: &str,
    ) -> bool {
        self.vault
            .verify_audit_chain_extends(anchored_head, anchored_len, signature_b64)
    }

    pub fn audit_log_snapshot(&self) -> Vec<AuditEntrySnapshot> {
        self.vault.audit_log_snapshot()
    }

    /// Signed attestation over the current audit head. The timestamp is generated
    /// server-side (monotonic-ish wall clock) — never caller-supplied — so a caller
    /// cannot backdate/forward-date the only signed binding of the audit head.
    pub fn attestation_payload(&self) -> Result<String, CageError> {
        self.vault.attestation_payload(now_unix().to_string())
    }

    pub fn attestation_public_key(&self) -> String {
        self.vault.attestation_public_key()
    }

    /// Base64 ed25519 public key that verifies **release** signatures (distinct
    /// from the audit-attestation key).
    pub fn release_public_key(&self) -> String {
        self.vault.release_public_key()
    }

    /// Raw 32-byte ed25519 verifying key of the audit-attestation identity. The
    /// release-signing key is a different key.
    pub fn attestation_verifying_key(&self) -> [u8; 32] {
        self.vault.attestation_verifying_key_bytes()
    }

    /// True if a secret is stored under `name`, so a provisioning path can fail
    /// closed rather than silently overwrite a credential.
    pub fn has_secret(&self, name: &str) -> bool {
        self.vault.has_secret(name)
    }

    /// Remove and zero a stored secret. Returns whether it existed.
    pub fn delete_secret(&mut self, name: &str) -> bool {
        self.vault.delete_secret(name)
    }

    /// Number of entries in the canonical audit chain.
    pub fn audit_log_len(&self) -> usize {
        self.vault.audit_log_len()
    }

    /// Constant-time verification of a presented bootstrap token (hex). Retained for
    /// the in-process facade ([`ControlAuth::Bootstrap`]); the broker never calls it.
    pub fn verify_bootstrap(&self, token: &str) -> bool {
        self.vault.verify_bootstrap(token)
    }

    /// Trust an operator public key (hex of the raw 32-byte ed25519 key) for
    /// control-plane proof-of-possession. The broker is provisioned with this at
    /// startup; thereafter issue / revoke / attest / audit_log require a signature it
    /// verifies against this key. Idempotent.
    pub fn authorize_operator(&mut self, pubkey_hex: &str) -> Result<(), CageError> {
        let bytes = hex::decode(pubkey_hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .ok_or_else(|| CageError::Refused("operator public key must be 32-byte hex".into()))?;
        let vk = crate::operator::verifying_key_from_bytes(&bytes).ok_or_else(|| {
            CageError::Refused("operator public key is not a valid ed25519 key".into())
        })?;
        if !self.operator_keys.iter().any(|k| k.to_bytes() == bytes) {
            self.operator_keys.push(vk);
        }
        self.audit(
            "operator",
            "operator_key_authorized",
            &serde_json::json!({ "key_id": pubkey_hex }),
        );
        Ok(())
    }

    /// True if `auth` authorizes a control-plane operation bound to `op` + `args`:
    /// dev-mode waiver, a matching bootstrap secret, or a valid operator signature.
    /// `&mut self` because the signed path records the nonce (replay defense).
    fn verify_control_auth(
        &mut self,
        op: &str,
        args: &[u8],
        auth: Option<&ControlAuth<'_>>,
    ) -> bool {
        if self.insecure_dev_mode {
            return true;
        }
        match auth {
            Some(ControlAuth::Bootstrap(t)) => self.vault.verify_bootstrap(t),
            Some(ControlAuth::Signed(sa)) => self.verify_signed_auth(op, args, sa),
            None => false,
        }
    }

    /// Verify an operator-signed control request: trusted key → fresh timestamp →
    /// valid signature over the canonical message → unseen nonce. The nonce cache is
    /// touched only AFTER the signature verifies, so an unauthenticated peer cannot
    /// pollute it.
    fn verify_signed_auth(&mut self, op: &str, args: &[u8], sa: &SignedAuth) -> bool {
        let vk = match self
            .operator_keys
            .iter()
            .find(|k| k.to_bytes() == sa.key_id)
        {
            Some(k) => *k,
            None => return false,
        };
        let now = now_unix();
        if sa.ts.abs_diff(now) > CONTROL_AUTH_WINDOW_SECS {
            return false;
        }
        let broker_id = self.vault.attestation_verifying_key_bytes();
        let message = control_message(&broker_id, op, args, &sa.nonce, sa.ts);
        if !verify_operator_sig(&vk, &message, &sa.sig) {
            return false;
        }
        // Evict stale nonces, then reject a replay — only reached on a valid signature.
        self.cp_nonces.retain(|_, evict_at| *evict_at >= now);
        if self.cp_nonces.contains_key(&sa.nonce) {
            return false;
        }
        self.cp_nonces
            .insert(sa.nonce, sa.ts.saturating_add(CONTROL_AUTH_WINDOW_SECS));
        true
    }

    /// Authorize a control-plane op that carries no arguments (attest / audit_log).
    /// A refusal is audited here; `issue_token` / `revoke` audit their own.
    pub fn authorize_control(&mut self, op: &str, auth: Option<ControlAuth<'_>>) -> bool {
        let authorized = self.verify_control_auth(op, &[], auth.as_ref());
        if !authorized {
            self.audit(
                "vault",
                "control_rejected_auth",
                &serde_json::json!({ "op": op }),
            );
        }
        authorized
    }

    /// Permanently discard the bootstrap secret (broker / operator-PoP mode). The
    /// broker authenticates the control plane by operator signature, never the
    /// bootstrap, so the secret has no reason to remain resident — zeroing it means a
    /// broker-memory disclosure yields no forge-the-authority value.
    pub fn discard_bootstrap(&mut self) {
        self.vault.discard_bootstrap();
    }

    /// Advance the use counter and return the updated canonical token. The
    /// delegation target for a Python facade that mirrors `record_use`; the
    /// internal `record_use` returns only the count.
    pub fn record_use_token(&mut self, token_id: &str) -> Result<CapabilityToken, CageError> {
        self.record_use(token_id)?;
        self.tokens
            .get(token_id)
            .cloned()
            .ok_or_else(|| CageError::Refused("record_use on unknown token".into()))
    }

    /// Append an external lifecycle event (e.g. "secret_stored", "mlock_state") to
    /// the canonical audit chain. The gate's own authority decisions are audited
    /// internally; this is the delegation target for the facade's audit appends.
    pub fn append_audit(
        &mut self,
        entity_id: String,
        event: String,
        data_json: String,
        timestamp: String,
    ) -> Result<String, CageError> {
        self.vault
            .append_audit(entity_id, event, data_json, timestamp)
    }

    /// True if `mlock(2)` succeeded on the key + bootstrap pages at construction.
    pub fn mlock_succeeded(&self) -> bool {
        self.vault.mlock_succeeded()
    }

    /// Resolve `scope` to a loaded secret, auditing both refusals (unknown
    /// namespace, registered-but-unloaded secret) under the requesting token so
    /// every path that stops short of the secret leaves a chain entry.
    fn resolve_secret_for(&mut self, token_id: &str, scope: &str) -> Result<String, CageError> {
        let secret = match self.scope_to_secret(scope) {
            Ok(s) => s,
            Err(e) => {
                self.audit(
                    token_id,
                    "rejected_unknown_scope",
                    &serde_json::json!({ "scope": scope }),
                );
                return Err(e);
            }
        };
        if !self.vault.has_secret(&secret) {
            self.audit(
                token_id,
                "rejected_no_secret",
                &serde_json::json!({ "scope": scope }),
            );
            return Err(CageError::Refused(format!(
                "no secret loaded for scope {scope:?}"
            )));
        }
        Ok(secret)
    }

    fn record_use(&mut self, token_id: &str) -> Result<u32, CageError> {
        let t = self
            .tokens
            .get_mut(token_id)
            .ok_or_else(|| CageError::Refused("record_use on unknown token".into()))?;
        t.use_count += 1;
        Ok(t.use_count)
    }

    fn audit(&mut self, entity_id: &str, event: &str, data: &serde_json::Value) {
        let ts = now_unix().to_string();
        // data is always constructed here, so it always serializes; append_audit
        // only errors on malformed JSON.
        let _ = self.vault.append_audit(
            entity_id.to_string(),
            event.to_string(),
            data.to_string(),
            ts,
        );
    }

    /// Fail-closed audit: like [`audit`](Self::audit) but propagates an append
    /// failure instead of swallowing it. Used on the secret-materializing success
    /// paths (`sign` / `invoke` / `consume` / `sign_release`) so a secret-derived
    /// result is never returned to the caller without its audit-chain entry — the
    /// append is part of the operation, not best-effort. In practice `append_audit`
    /// only fails on malformed JSON, which the gate never constructs, so this never
    /// triggers today; the point is that non-bypass is structural (fail-closed)
    /// rather than relying on the data always serializing.
    fn audit_checked(
        &mut self,
        entity_id: &str,
        event: &str,
        data: &serde_json::Value,
    ) -> Result<(), CageError> {
        let ts = now_unix().to_string();
        self.vault
            .append_audit(
                entity_id.to_string(),
                event.to_string(),
                data.to_string(),
                ts,
            )
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::OperatorKey;

    /// Dev-mode gate (issuance/revocation need no bootstrap) for the tests that
    /// exercise signing / use-counting rather than the bootstrap gate itself.
    fn gate_with_secret() -> Gate {
        let mut g = Gate::new();
        g.set_insecure_dev_mode(true);
        g.store_secret("k", "super-secret-value").unwrap();
        g.register_scope_secret("sign.", "k");
        g.register_scope_secret("llm.", "k"); // an invoke-verb scope for the invoke tests
        g
    }

    /// Fail-closed gate (the production default) for the bootstrap-gate tests.
    fn sealed_gate_with_secret() -> Gate {
        let mut g = Gate::new();
        g.store_secret("k", "super-secret-value").unwrap();
        g.register_scope_secret("sign.", "k");
        g
    }

    #[test]
    fn sign_succeeds_and_is_deterministic_for_same_key_and_payload() {
        let mut g = gate_with_secret();
        let t1 = g.issue_token("sign.x", "ctx", None, Some(2), None).unwrap();
        let t2 = g.issue_token("sign.x", "ctx", None, Some(2), None).unwrap();
        let s1 = g.sign(&t1.token_id, b"payload").unwrap();
        let s2 = g.sign(&t2.token_id, b"payload").unwrap();
        assert_eq!(s1, s2, "HMAC over same key+payload must match");
        assert_eq!(s1.len(), 64, "SHA-256 HMAC is 32 bytes = 64 hex chars");
    }

    #[test]
    fn max_uses_is_enforced() {
        let mut g = gate_with_secret();
        let t = g.issue_token("sign.x", "ctx", None, Some(1), None).unwrap();
        assert!(g.sign(&t.token_id, b"a").is_ok());
        assert!(matches!(
            g.sign(&t.token_id, b"b").unwrap_err(),
            CageError::Refused(_)
        ));
    }

    #[test]
    fn unknown_token_is_refused() {
        let mut g = gate_with_secret();
        assert!(matches!(
            g.sign(&"00".repeat(16), b"x").unwrap_err(),
            CageError::Refused(_)
        ));
    }

    #[test]
    fn revoked_token_is_refused_and_revoke_is_idempotent() {
        let mut g = gate_with_secret();
        let t = g.issue_token("sign.x", "ctx", None, Some(5), None).unwrap();
        // Pre-unseal (test/dev mode) revoke needs no bootstrap.
        assert!(g.revoke(&t.token_id, None).unwrap());
        assert!(
            !g.revoke(&t.token_id, None).unwrap(),
            "second revoke returns false"
        );
        assert!(matches!(
            g.sign(&t.token_id, b"x").unwrap_err(),
            CageError::Refused(_)
        ));
    }

    #[test]
    fn revoke_requires_bootstrap_after_unseal() {
        let mut g = sealed_gate_with_secret();
        let bootstrap = g.unseal().unwrap();
        let t = g
            .issue_token(
                "sign.x",
                "ctx",
                None,
                Some(5),
                Some(ControlAuth::Bootstrap(&bootstrap)),
            )
            .unwrap();
        assert!(
            g.revoke(&t.token_id, None).is_err(),
            "no bootstrap -> refused"
        );
        assert!(
            g.revoke(&t.token_id, Some(ControlAuth::Bootstrap(&bootstrap)))
                .unwrap(),
            "valid bootstrap -> revoked"
        );
    }

    #[test]
    fn multibyte_token_id_is_refused_not_panic() {
        // Regression: short() must not byte-slice a multi-byte UTF-8 token_id
        // (a '€' straddling byte index 8 used to panic and crash the broker).
        let mut g = gate_with_secret();
        assert!(matches!(
            g.sign("abcdefg\u{20AC}", b"x").unwrap_err(),
            CageError::Refused(_)
        ));
    }

    #[test]
    fn issuance_requires_valid_bootstrap_after_unseal() {
        let mut g = sealed_gate_with_secret();
        let bootstrap = g.unseal().unwrap();
        assert!(matches!(
            g.issue_token("sign.x", "c", None, None, None).unwrap_err(),
            CageError::Refused(_)
        ));
        assert!(g
            .issue_token(
                "sign.x",
                "c",
                None,
                None,
                Some(ControlAuth::Bootstrap("deadbeef"))
            )
            .is_err());
        assert!(g
            .issue_token(
                "sign.x",
                "c",
                None,
                None,
                Some(ControlAuth::Bootstrap(&bootstrap))
            )
            .is_ok());
    }

    #[test]
    fn fail_closed_refuses_issuance_without_bootstrap_even_before_unseal() {
        // The shipped vault is never unsealed; issuance must still be refused
        // without the bootstrap (the PoC2 fail-open). A holder of the bootstrap
        // (obtained via unseal) can issue.
        let mut g = sealed_gate_with_secret();
        assert!(
            matches!(
                g.issue_token("sign.x", "c", None, None, None).unwrap_err(),
                CageError::Refused(_)
            ),
            "fail-closed: no bootstrap, no token — even pre-unseal"
        );
        let bootstrap = g.unseal().unwrap();
        assert!(g
            .issue_token(
                "sign.x",
                "c",
                None,
                None,
                Some(ControlAuth::Bootstrap(&bootstrap))
            )
            .is_ok());
    }

    #[test]
    fn reserve_invoke_charges_before_the_network_and_refunds_only_pre_send() {
        let mut g = gate_with_secret();
        let t = g.issue_token("llm.x", "c", None, Some(3), None).unwrap();

        // Reserve charges a use up front (before any network write).
        let res = g.reserve_invoke(&t.token_id, "anthropic").unwrap();
        assert_eq!(
            g.authorize(&t.token_id, None, None).unwrap().use_count,
            1,
            "reserve charges before the network"
        );

        // A PRE-SEND failure (connect/handshake/unknown provider) refunds the use.
        g.refund_invoke(&res, "tcp connect refused");
        assert_eq!(
            g.authorize(&t.token_id, None, None).unwrap().use_count,
            0,
            "pre-send failure returns the reserved use"
        );

        // A POST-SEND failure (provider received the request) keeps the charge —
        // closing the "force a rejection for unbounded billed calls" gap.
        let res2 = g.reserve_invoke(&t.token_id, "anthropic").unwrap();
        g.fail_invoke(&res2, "provider returned 400");
        assert_eq!(
            g.authorize(&t.token_id, None, None).unwrap().use_count,
            1,
            "post-send failure keeps the use charged"
        );
    }

    #[test]
    fn take_key_leaves_no_copy_in_the_reservation() {
        let mut g = gate_with_secret();
        let t = g.issue_token("llm.x", "c", None, Some(1), None).unwrap();
        let mut res = g.reserve_invoke(&t.token_id, "anthropic").unwrap();
        let key = res.take_key();
        assert!(!key.is_empty());
        // The reservation that waits through the response holds nothing.
        assert!(res.key.is_empty());
        assert!(res.take_key().is_empty());
        // Settling still works without the key.
        g.refund_invoke(&res, "tcp connect refused");
    }

    #[test]
    fn reserve_invoke_unknown_provider_refuses_without_charging() {
        let mut g = gate_with_secret();
        let t = g.issue_token("llm.x", "c", None, Some(1), None).unwrap();
        assert!(g.reserve_invoke(&t.token_id, "no-such-provider").is_err());
        assert_eq!(
            g.authorize(&t.token_id, None, None).unwrap().use_count,
            0,
            "an unknown provider performs no network and charges nothing"
        );
    }

    #[test]
    fn consume_is_token_gated_and_use_counted() {
        let mut g = gate_with_secret();
        g.set_allow_plaintext_consume(true);
        let t = g.issue_token("sign.x", "c", None, Some(1), None).unwrap();
        assert_eq!(
            g.consume(&t.token_id, "sign.x").unwrap(),
            "super-secret-value"
        );
        // Over max_uses → refused (no second plaintext).
        assert!(matches!(
            g.consume(&t.token_id, "sign.x").unwrap_err(),
            CageError::Refused(_)
        ));
    }

    #[test]
    fn consume_refused_unless_plaintext_is_explicitly_allowed() {
        // A sealed, default-built gate (no dev mode, no leak switch) refuses
        // consume() on a legitimately issued token — the plaintext-into-the-caller
        // path is opt-in only.
        let mut g = sealed_gate_with_secret();
        let bootstrap = g.unseal().unwrap();
        let t = g
            .issue_token(
                "sign.x",
                "c",
                None,
                Some(1),
                Some(ControlAuth::Bootstrap(&bootstrap)),
            )
            .unwrap();
        assert!(matches!(
            g.consume(&t.token_id, "sign.x").unwrap_err(),
            CageError::Refused(_)
        ));
        assert!(g
            .audit_log_snapshot()
            .iter()
            .any(|e| e.event == "consume_refused_plaintext_disabled" && e.entity_id == t.token_id));
    }

    #[test]
    fn consume_on_a_forged_token_is_rejected_as_unknown_even_when_disabled() {
        // authorize() runs before the switch check, so a forged probe is recorded
        // the way every other op records it — not as a plaintext refusal keyed on
        // an attacker-chosen id.
        let mut g = sealed_gate_with_secret();
        assert!(matches!(
            g.consume(&"00".repeat(16), "sign.x").unwrap_err(),
            CageError::Refused(_)
        ));
        let log = g.audit_log_snapshot();
        assert!(log.iter().any(|e| e.event == "rejected_unknown_token"));
        assert!(!log
            .iter()
            .any(|e| e.event == "consume_refused_plaintext_disabled"));
    }

    #[test]
    fn insecure_dev_mode_alone_does_not_re_enable_consume() {
        // The two switches are decoupled: waiving control-plane auth must not also
        // restore the plaintext path, or the escape hatch for one becomes the
        // detonator for the other. `gate_with_secret()` is already in dev mode.
        let mut g = gate_with_secret();
        assert!(g.verify_control_auth("issue", b"", None), "dev mode is on");
        let t = g.issue_token("sign.x", "c", None, Some(1), None).unwrap();
        assert!(matches!(
            g.consume(&t.token_id, "sign.x").unwrap_err(),
            CageError::Refused(_)
        ));
    }

    #[test]
    fn plaintext_consume_alone_does_not_waive_control_auth() {
        // The inverse direction of the decoupling: opting into the leak must not
        // also waive control-plane auth.
        let mut g = sealed_gate_with_secret();
        g.set_allow_plaintext_consume(true);
        assert!(!g.verify_control_auth("issue", b"", None));
        assert!(matches!(
            g.issue_token("sign.x", "c", None, Some(1), None)
                .unwrap_err(),
            CageError::Refused(_)
        ));
    }

    #[test]
    fn enabling_a_dev_switch_is_recorded_on_the_chain() {
        // A default gate's chain carries neither entry; enabling a waiver writes one
        // before anything can be issued or consumed under it.
        let g = Gate::new();
        let ev = |g: &Gate, name: &str| {
            g.audit_log_snapshot()
                .iter()
                .filter(|e| e.event == name)
                .count()
        };
        assert_eq!(ev(&g, "insecure_dev_mode_enabled"), 0);
        assert_eq!(ev(&g, "plaintext_consume_enabled"), 0);
        let mut g = Gate::new();
        g.set_insecure_dev_mode(false);
        g.set_allow_plaintext_consume(false);
        assert_eq!(g.audit_log_len(), 0, "the default-false calls stay silent");
        g.set_insecure_dev_mode(true);
        g.set_allow_plaintext_consume(true);
        assert_eq!(ev(&g, "insecure_dev_mode_enabled"), 1);
        assert_eq!(ev(&g, "plaintext_consume_enabled"), 1);
        assert!(g.verify_audit_chain());
    }

    #[test]
    fn consume_refusal_is_audited() {
        // A refused consume() must leave a chain entry like every other refusal in
        // the gate — otherwise a compromised agent could probe the raw-key path in
        // production with zero trace (invariant 4).
        let mut g = gate_with_secret();
        let t = g.issue_token("sign.x", "c", None, Some(1), None).unwrap();
        assert!(matches!(
            g.consume(&t.token_id, "sign.x").unwrap_err(),
            CageError::Refused(_)
        ));
        let log = g.audit_log_snapshot();
        let refusals: Vec<_> = log
            .iter()
            .filter(|e| e.event == "consume_refused_plaintext_disabled")
            .collect();
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].entity_id, t.token_id);
        assert!(refusals[0].data_json.contains("\"scope\":\"sign.x\""));
        assert!(g.verify_audit_chain());
    }

    #[test]
    fn unknown_scope_refusal_is_audited() {
        // A token whose namespace has no registered secret is refused before any
        // charge, and the refusal is on the chain.
        let mut g = Gate::new();
        g.set_insecure_dev_mode(true);
        g.store_secret("k", "super-secret-value").unwrap();
        g.register_scope_secret("sign.", "k");
        let t = g.issue_token("other.x", "c", None, Some(1), None).unwrap();
        // `.err()` rather than `unwrap_err()`: the reservation type carries the
        // key and deliberately has no Debug impl.
        let err = g.reserve_invoke(&t.token_id, "anthropic").err();
        assert!(matches!(err, Some(CageError::Refused(_))));
        let log = g.audit_log_snapshot();
        assert!(log
            .iter()
            .any(|e| e.event == "rejected_unknown_scope" && e.entity_id == t.token_id));
        assert_eq!(
            g.authorize(&t.token_id, None, None).unwrap().use_count,
            0,
            "an unresolvable scope charges nothing"
        );
    }

    #[test]
    fn missing_secret_refusal_is_audited() {
        let mut g = Gate::new();
        g.set_insecure_dev_mode(true);
        g.register_scope_secret("sign.", "never-stored");
        let t = g.issue_token("sign.x", "c", None, Some(1), None).unwrap();
        assert!(matches!(
            g.sign(&t.token_id, b"x").unwrap_err(),
            CageError::Refused(_)
        ));
        let log = g.audit_log_snapshot();
        assert!(log
            .iter()
            .any(|e| e.event == "rejected_no_secret" && e.entity_id == t.token_id));
    }

    #[test]
    fn release_without_policy_is_audited() {
        let mut g = gate_with_secret();
        let t = g
            .issue_token("release.x", "c", None, Some(1), None)
            .unwrap();
        let digest = "a".repeat(64);
        assert!(matches!(
            g.sign_release(&t.token_id, &digest, b"{}").unwrap_err(),
            CageError::Refused(_)
        ));
        let log = g.audit_log_snapshot();
        assert!(log.iter().any(|e| e.event == "release_refused"
            && e.entity_id == t.token_id
            && e.data_json.contains("no release policy configured")));
    }

    #[test]
    fn control_refusal_via_authorize_control_is_audited() {
        // The bool wrapper the broker uses for attest / audit_log audits its own
        // refusal; issue / revoke audit theirs directly, so nothing double-audits.
        let mut g = sealed_gate_with_secret();
        assert!(!g.authorize_control("attest", None));
        g.issue_token("sign.x", "c", None, None, None).unwrap_err();
        let log = g.audit_log_snapshot();
        let ev = |name: &str| log.iter().filter(|e| e.event == name).count();
        assert_eq!(ev("control_rejected_auth"), 1);
        assert!(log.iter().any(
            |e| e.event == "control_rejected_auth" && e.data_json.contains("\"op\":\"attest\"")
        ));
        assert_eq!(ev("issuance_rejected_auth"), 1);
        assert!(g.verify_audit_chain());
    }

    #[test]
    fn issue_token_clamps_unbounded_ttl_and_max_uses() {
        let mut g = gate_with_secret();
        let t = g
            .issue_token("sign.x", "c", Some(u64::MAX), Some(u32::MAX), None)
            .unwrap();
        assert_eq!(t.ttl_seconds, MAX_TTL_SECONDS, "ttl clamped to the ceiling");
        assert_eq!(t.max_uses, MAX_USES, "max_uses clamped to the ceiling");
    }

    /// Baseline policy: the `llm.` namespace, 60s, 3 uses, no cumulative ceiling.
    fn policy(scopes: &[&str]) -> IssuancePolicy {
        IssuancePolicy {
            allowed_scopes: scopes.iter().map(|s| s.to_string()).collect(),
            max_ttl_seconds: 60,
            max_uses: 3,
            max_tokens_per_scope: None,
        }
    }

    fn provision(g: &mut Gate) {
        g.set_insecure_dev_mode(true);
        g.store_secret("k", "super-secret-value").unwrap();
        g.register_scope_secret("sign.", "k");
        g.register_scope_secret("llm.", "k");
    }

    fn gate_with_policy(p: IssuancePolicy) -> Gate {
        let mut g = Gate::with_issuance_policy(p).unwrap();
        provision(&mut g);
        g
    }

    #[test]
    fn overlapping_policy_entries_are_refused() {
        for scopes in [
            &["sign.", "sign.a"][..],
            &["sign.a.", "sign."][..],
            &["llm", "llm."][..],
        ] {
            assert!(
                Gate::with_issuance_policy(policy(scopes)).is_err(),
                "{scopes:?} was accepted"
            );
        }
        for scopes in [
            &["llm.", "sign."][..],
            &["llm.", "llm."][..],
            &["llm.", "llmx."][..],
        ] {
            assert!(
                Gate::with_issuance_policy(policy(scopes)).is_ok(),
                "{scopes:?} was refused"
            );
        }
    }

    #[test]
    fn issuance_policy_refuses_a_scope_outside_the_policy() {
        let mut g = gate_with_policy(policy(&["llm."]));
        assert!(g.issue_token("llm.evaluate", "c", None, None, None).is_ok());
        let err = g
            .issue_token("sign.anything", "c", None, None, None)
            .unwrap_err();
        assert!(
            matches!(err, CageError::Refused(_)),
            "out-of-policy scope must be refused fail-closed, got {err:?}"
        );
    }

    /// The load-bearing claim: a caller presenting a VALID operator signature — i.e.
    /// someone holding the stolen issuing authority — is still bounded. The other
    /// tests waive control-plane auth via dev mode and so cannot show this.
    #[test]
    fn issuance_policy_binds_a_validly_signed_operator() {
        let mut g = Gate::with_issuance_policy(policy(&["llm."])).unwrap();
        g.store_secret("k", "super-secret-value").unwrap();
        g.register_scope_secret("sign.", "k");
        g.register_scope_secret("llm.", "k");
        let key = OperatorKey::generate();
        g.authorize_operator(&hex::encode(key.public_key_bytes()))
            .unwrap();
        let broker_id = g.vault.attestation_verifying_key_bytes();

        let sign = |op: &str, args: &[u8], nonce: [u8; 16], ts: u64| {
            let msg = control_message(&broker_id, op, args, &nonce, ts);
            SignedAuth {
                key_id: key.public_key_bytes(),
                nonce,
                ts,
                sig: key.sign(&msg),
            }
        };
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // In-policy, correctly signed → allowed.
        let args = control_args_issue("llm.evaluate", "c", None, None);
        let auth = sign("issue", &args, [1u8; 16], ts);
        assert!(g
            .issue_token(
                "llm.evaluate",
                "c",
                None,
                None,
                Some(ControlAuth::Signed(auth))
            )
            .is_ok());

        // Out-of-policy, equally correctly signed → still refused.
        let args = control_args_issue("sign.anything", "c", None, None);
        let auth = sign("issue", &args, [2u8; 16], ts);
        let err = g
            .issue_token(
                "sign.anything",
                "c",
                None,
                None,
                Some(ControlAuth::Signed(auth)),
            )
            .unwrap_err();
        assert!(
            matches!(err, CageError::Refused(_)),
            "a valid operator signature must not escape the policy, got {err:?}"
        );
    }

    #[test]
    fn issuance_policy_narrows_but_can_never_widen_the_hard_ceilings() {
        let mut wide = policy(&["llm."]);
        wide.max_ttl_seconds = u64::MAX;
        wide.max_uses = u32::MAX;
        let mut g = gate_with_policy(wide);
        let t = g
            .issue_token("llm.evaluate", "c", Some(u64::MAX), Some(u32::MAX), None)
            .unwrap();
        assert_eq!(
            t.ttl_seconds, MAX_TTL_SECONDS,
            "policy cannot exceed MAX_TTL"
        );
        assert_eq!(t.max_uses, MAX_USES, "policy cannot exceed MAX_USES");

        let mut g = gate_with_policy(policy(&["llm."]));
        let t = g
            .issue_token("llm.evaluate", "c", Some(u64::MAX), Some(u32::MAX), None)
            .unwrap();
        assert_eq!(t.ttl_seconds, 60, "policy ttl binds the caller");
        assert_eq!(t.max_uses, 3, "policy max_uses binds the caller");
    }

    #[test]
    fn issuance_policy_anchors_on_the_namespace_boundary() {
        let mut g = gate_with_policy(policy(&["llm."]));
        // Neighbouring namespace that merely shares a prefix.
        assert!(g
            .issue_token("llmx.evaluate", "c", None, None, None)
            .is_err());
        // Bare namespace and arbitrary depth both admitted, matching scope_to_secret.
        assert!(g.issue_token("llm", "c", None, None, None).is_ok());
        assert!(g
            .issue_token("llm.eu.evaluate", "c", None, None, None)
            .is_ok());

        // A multi-segment entry must actually work (it silently matched nothing before).
        let mut g = gate_with_policy(policy(&["llm.eu."]));
        assert!(g
            .issue_token("llm.eu.evaluate", "c", None, None, None)
            .is_ok());
        assert!(g
            .issue_token("llm.us.evaluate", "c", None, None, None)
            .is_err());
    }

    #[test]
    fn issuance_policy_exact_scope_entry_admits_only_that_scope() {
        let mut g = gate_with_policy(policy(&["llm.evaluate"]));
        assert!(g.issue_token("llm.evaluate", "c", None, None, None).is_ok());
        assert!(g
            .issue_token("llm.evaluate2", "c", None, None, None)
            .is_err());
        assert!(g.issue_token("llm.other", "c", None, None, None).is_err());
        // An exact entry still anchors: it admits its own sub-namespace, never a sibling.
        assert!(g
            .issue_token("llm.evaluate.fast", "c", None, None, None)
            .is_ok());
    }

    #[test]
    fn issuance_policy_cumulative_ceiling_is_per_entry_not_per_scope() {
        let mut p = policy(&["llm."]);
        p.max_tokens_per_scope = Some(2);
        let mut g = gate_with_policy(p);
        let t1 = g.issue_token("llm.a", "c", None, None, None).unwrap();
        g.issue_token("llm.b", "c", None, None, None).unwrap();
        // Varying the sub-scope must NOT open a fresh budget.
        assert!(
            g.issue_token("llm.c", "c", None, None, None).is_err(),
            "the ceiling is per policy entry; a new sub-scope must not reset it"
        );
        // Revocation must not buy another issuance either.
        g.revoke(&t1.token_id, None).unwrap();
        assert!(
            g.issue_token("llm.d", "c", None, None, None).is_err(),
            "revocation must not return a slot"
        );
    }

    #[test]
    fn issuance_policy_ceilings_are_independent_across_entries() {
        let mut p = policy(&["llm.", "sign."]);
        p.max_tokens_per_scope = Some(1);
        let mut g = gate_with_policy(p);
        g.issue_token("llm.evaluate", "c", None, None, None)
            .unwrap();
        assert!(g.issue_token("llm.other", "c", None, None, None).is_err());
        assert!(
            g.issue_token("sign.thing", "c", None, None, None).is_ok(),
            "exhausting one entry must not close another"
        );
    }

    #[test]
    fn issuance_policy_empty_allowlist_is_fail_closed() {
        let mut g = gate_with_policy(policy(&[]));
        assert!(
            g.issue_token("llm.evaluate", "c", None, None, None)
                .is_err(),
            "an empty policy must deny, not permit"
        );
    }

    #[test]
    fn issuance_policy_fingerprint_is_canonical_and_change_sensitive() {
        let a = policy(&["llm.", "sign."]);
        // Order and repetition are not policy changes; the digest must agree with Eq.
        assert_eq!(
            a.fingerprint(),
            policy(&["sign.", "llm."]).fingerprint(),
            "provisioning order must not change policy identity"
        );
        assert_eq!(
            a.fingerprint(),
            policy(&["llm.", "sign.", "llm."]).fingerprint(),
            "a duplicated entry must not change policy identity"
        );
        // Every bound is part of the identity.
        let mut ttl = a.clone();
        ttl.max_ttl_seconds = 61;
        let mut uses = a.clone();
        uses.max_uses = 4;
        let mut cap = a.clone();
        cap.max_tokens_per_scope = Some(5);
        let mut cap_max = a.clone();
        cap_max.max_tokens_per_scope = Some(u32::MAX);
        for (label, other) in [
            ("ttl", ttl),
            ("uses", uses),
            ("ceiling", cap),
            // None must not alias Some(u32::MAX).
            ("ceiling=u32::MAX", cap_max),
        ] {
            assert_ne!(
                a.fingerprint(),
                other.fingerprint(),
                "{label} must change it"
            );
        }
        // Field boundaries are framed: ["a.","b."] must not collide with ["a.b."].
        assert_ne!(
            policy(&["a.", "b."]).fingerprint(),
            policy(&["a.b."]).fingerprint()
        );
    }

    /// Known-answer test: the digest is recorded in audit chains, so re-encoding it
    /// silently invalidates those records. Pin the bytes.
    #[test]
    fn issuance_policy_fingerprint_is_stable_across_builds() {
        assert_eq!(
            policy(&["llm."]).fingerprint(),
            "4bee8e7403fb049a3f88a6e97a37215c63ea02629758d00d5fae66d02bc6d313"
        );
    }

    #[test]
    fn issuance_policy_is_recorded_in_the_audit_chain() {
        let mut p = policy(&["llm."]);
        p.max_tokens_per_scope = Some(1);
        let fp = p.fingerprint();
        let mut g = gate_with_policy(p);
        g.issue_token("llm.evaluate", "c", None, None, None)
            .unwrap();
        g.issue_token("llm.other", "c", None, None, None)
            .unwrap_err(); // ceiling
        g.issue_token("sign.x", "c", None, None, None).unwrap_err(); // out of policy
        let log = g.audit_log_snapshot();
        let ev = |name: &str| log.iter().filter(|e| e.event == name).count();
        assert_eq!(
            ev("issuance_policy_frozen"),
            1,
            "the freeze must be recorded"
        );
        assert_eq!(
            ev("issuance_rejected_policy"),
            2,
            "both refusal reasons recorded"
        );
        let issued = log.iter().find(|e| e.event == "issued").unwrap();
        let data: serde_json::Value = serde_json::from_str(&issued.data_json).unwrap();
        assert_eq!(
            data["policy_fingerprint"], fp,
            "an issued token must record the policy it was minted under"
        );
        // The freeze entry must carry the bounds themselves, not just the digest.
        let frozen = log
            .iter()
            .find(|e| e.event == "issuance_policy_frozen")
            .unwrap();
        let data: serde_json::Value = serde_json::from_str(&frozen.data_json).unwrap();
        assert_eq!(data["max_ttl_seconds"], 60);
        assert_eq!(data["max_tokens_per_scope"], 1);
        assert_eq!(
            g.issuance_policy_fingerprint().as_deref(),
            Some(fp.as_str())
        );
    }

    #[test]
    fn gate_without_a_policy_reports_no_fingerprint() {
        let mut g = gate_with_secret();
        assert!(g.issuance_policy_fingerprint().is_none());
        assert!(g.issue_token("sign.x", "c", None, None, None).is_ok());
    }

    #[test]
    fn verb_binding_isolates_operations() {
        let mut g = gate_with_secret();
        let llm = g
            .issue_token("llm.evaluate", "c", None, Some(5), None)
            .unwrap();
        let sign = g.issue_token("sign.x", "c", None, Some(5), None).unwrap();

        // An llm token cannot sign (HMAC) — that would be an oracle on the key …
        assert!(matches!(
            g.sign(&llm.token_id, b"x").unwrap_err(),
            CageError::Refused(_)
        ));
        // … nor reach the release-signing key (verb mismatch, checked before policy).
        assert!(matches!(
            g.sign_release(&llm.token_id, &"a".repeat(64), b"{}")
                .unwrap_err(),
            CageError::Refused(_)
        ));
        // A sign token cannot invoke (exfil the sign key via a provider call). Match
        // the Result directly — InvokeReservation is intentionally not Debug (it
        // holds the decrypted key), so unwrap_err() would not compile.
        assert!(matches!(
            g.reserve_invoke(&sign.token_id, "anthropic"),
            Err(CageError::Refused(_))
        ));
        // The matching verbs are allowed.
        assert!(g.sign(&sign.token_id, b"x").is_ok());
        assert!(g.reserve_invoke(&llm.token_id, "anthropic").is_ok());
    }

    #[test]
    fn context_binding_refuses_a_mismatched_context_but_allows_the_issued_one() {
        let mut g = gate_with_secret();
        let t = g
            .issue_token("sign.x", "agent-7", None, Some(5), None)
            .unwrap();
        // The issued context authorizes.
        assert!(g.authorize(&t.token_id, None, Some("agent-7")).is_ok());
        // A wrong context is refused — a token_id stolen without its issued context.
        assert!(matches!(
            g.authorize(&t.token_id, None, Some("attacker"))
                .unwrap_err(),
            CageError::Refused(_)
        ));
        // Omitting the context preserves prior behaviour (binding is opt-in).
        assert!(g.authorize(&t.token_id, None, None).is_ok());
        // The refusal is audited.
        let log = g.audit_log_snapshot();
        assert!(log.iter().any(|e| e.event == "rejected_context_mismatch"));
    }

    #[test]
    fn authorize_expires_on_the_monotonic_clock() {
        use std::time::Duration;
        let mut g = gate_with_secret();
        let t = g
            .issue_token("sign.x", "c", Some(60), Some(5), None)
            .unwrap();
        // Backdate the monotonic issue stamp past the TTL: expiry is checked against
        // this Instant, not the wallclock, so a host clock rollback cannot revive it.
        if let Some(backdated) = Instant::now().checked_sub(Duration::from_secs(120)) {
            *g.token_issued_at.get_mut(&t.token_id).unwrap() = backdated;
            assert!(matches!(
                g.authorize(&t.token_id, None, None).unwrap_err(),
                CageError::Refused(_)
            ));
        }
    }

    #[test]
    fn unseal_is_one_shot() {
        let mut g = Gate::new();
        assert!(g.unseal().is_ok());
        assert!(g.unseal().is_err());
    }

    #[test]
    fn scope_to_secret_longest_prefix_wins() {
        let mut g = Gate::new();
        g.register_scope_secret("llm.", "general");
        g.register_scope_secret("llm.judge.", "judge_key");
        assert_eq!(g.scope_to_secret("llm.judge.run").unwrap(), "judge_key");
        assert_eq!(g.scope_to_secret("llm.other").unwrap(), "general");
        assert!(g.scope_to_secret("unknown.x").is_err());
    }

    #[test]
    fn pinned_secret_refuses_another_provider_before_charging() {
        let mut g = gate_with_secret();
        g.pin_secret_provider("k", "anthropic").unwrap();
        let t = g.issue_token("llm.x", "c", None, Some(2), None).unwrap();

        assert!(matches!(
            g.reserve_invoke(&t.token_id, "openai"),
            Err(CageError::Refused(_))
        ));
        assert_eq!(
            g.authorize(&t.token_id, None, None).unwrap().use_count,
            0,
            "a refused provider charges nothing"
        );
        let refusals = g
            .audit_log_snapshot()
            .iter()
            .filter(|e| e.event == "rejected_provider")
            .count();
        assert_eq!(refusals, 1, "the refusal is audited");

        // The pinned provider proceeds.
        assert!(g.reserve_invoke(&t.token_id, "anthropic").is_ok());
    }

    #[test]
    fn provider_pin_covers_every_scope_that_resolves_to_the_secret() {
        let mut g = gate_with_secret();
        g.register_scope_secret("llm.judge.", "k");
        g.register_scope_secret("llm", "k");
        g.pin_secret_provider("k", "anthropic").unwrap();
        for scope in ["llm.x", "llm.judge.run", "llm"] {
            let t = g.issue_token(scope, "c", None, Some(1), None).unwrap();
            assert!(
                matches!(
                    g.reserve_invoke(&t.token_id, "openai"),
                    Err(CageError::Refused(_))
                ),
                "{scope} reached another provider"
            );
        }
    }

    #[test]
    fn provider_pin_is_validated_write_once_and_audited() {
        let mut g = gate_with_secret();
        assert!(g.pin_secret_provider("k", "no-such-provider").is_err());
        g.pin_secret_provider("k", "anthropic").unwrap();
        g.pin_secret_provider("k", "anthropic").unwrap();
        assert!(g.pin_secret_provider("k", "openai").is_err());

        // Registering the scope again does not touch the pin.
        g.register_scope_secret("llm.", "k");
        let t = g.issue_token("llm.x", "c", None, Some(1), None).unwrap();
        assert!(g.reserve_invoke(&t.token_id, "openai").is_err());

        let pins = g
            .audit_log_snapshot()
            .iter()
            .filter(|e| e.event == "provider_pinned")
            .count();
        assert_eq!(pins, 1, "one pin, one entry");
    }

    #[test]
    fn scope_to_secret_anchors_on_namespace_boundary() {
        let mut g = Gate::new();
        g.register_scope_secret("llm.", "llm_key");
        assert_eq!(g.scope_to_secret("llm").unwrap(), "llm_key");
        assert_eq!(g.scope_to_secret("llm.evaluate").unwrap(), "llm_key");
        // A non-delimiter prefix must NOT resolve to the namespace's secret.
        assert!(g.scope_to_secret("llmadmin").is_err());
        assert!(g.scope_to_secret("llm-evil").is_err());
    }

    #[test]
    fn token_validity_respects_ttl_scope_uses_and_revocation() {
        let now = 1_000_000u64;
        let mut t = CapabilityToken {
            token_id: "id".into(),
            scope: "s".into(),
            context: "c".into(),
            issued_at_unix: now,
            ttl_seconds: 60,
            max_uses: 3,
            use_count: 0,
            revoked: false,
        };
        assert!(t.is_valid("s", now));
        assert!(t.is_valid("s", now + 60), "ttl boundary is inclusive");
        assert!(!t.is_valid("s", now + 61), "expired past ttl");
        assert!(
            !t.is_valid("s", now - 1),
            "a clock rollback to before issue is rejected"
        );
        assert!(!t.is_valid("other", now), "scope must match exactly");
        t.use_count = 3;
        assert!(!t.is_valid("s", now), "at max_uses");
        t.use_count = 0;
        t.revoked = true;
        assert!(!t.is_valid("s", now), "revoked");
    }

    #[test]
    fn audit_chain_records_decisions_and_verifies() {
        let mut g = gate_with_secret();
        let t = g.issue_token("sign.x", "ctx", None, Some(2), None).unwrap();
        let _ = g.sign(&t.token_id, b"x");
        let _ = g.sign(&"bad".repeat(8), b"x"); // refused -> still audited
        assert!(g.verify_audit_chain());
        let log = g.audit_log_snapshot();
        assert!(log.iter().any(|e| e.event == "issued"));
        assert!(log.iter().any(|e| e.event == "signed"));
        assert!(log.iter().any(|e| e.event == "rejected_unknown_token"));
    }

    // -- operator proof-of-possession (broker control-plane auth) --

    /// Build an operator-signed `issue` authorization for `scope` against `g`'s
    /// broker identity — the same canonical message the operator's client builds.
    fn signed_issue(
        g: &Gate,
        key: &OperatorKey,
        scope: &str,
        ttl: Option<u64>,
        max_uses: Option<u32>,
        nonce: [u8; 16],
        ts: u64,
    ) -> ControlAuth<'static> {
        let broker_id = g.attestation_verifying_key();
        let args = control_args_issue(scope, "ctx", ttl, max_uses);
        let msg = control_message(&broker_id, "issue", &args, &nonce, ts);
        ControlAuth::Signed(SignedAuth {
            key_id: key.public_key_bytes(),
            nonce,
            ts,
            sig: key.sign(&msg),
        })
    }

    #[test]
    fn operator_signed_issue_succeeds_then_replay_is_refused() {
        let mut g = sealed_gate_with_secret();
        let key = OperatorKey::generate();
        g.authorize_operator(&key.public_key_hex()).unwrap();
        let (nonce, ts) = ([1u8; 16], now_unix());
        let auth = signed_issue(&g, &key, "sign.x", None, Some(2), nonce, ts);
        assert!(g
            .issue_token("sign.x", "ctx", None, Some(2), Some(auth))
            .is_ok());
        // Same nonce again → replay refused (state recorded only after sig verified).
        let replay = signed_issue(&g, &key, "sign.x", None, Some(2), nonce, ts);
        assert!(matches!(
            g.issue_token("sign.x", "ctx", None, Some(2), Some(replay))
                .unwrap_err(),
            CageError::Refused(_)
        ));
    }

    #[test]
    fn operator_signed_issue_refuses_untrusted_key() {
        let mut g = sealed_gate_with_secret();
        let trusted = OperatorKey::generate();
        g.authorize_operator(&trusted.public_key_hex()).unwrap();
        // A different (untrusted) key's signature must not authorize issuance.
        let attacker = OperatorKey::generate();
        let auth = signed_issue(
            &g,
            &attacker,
            "sign.x",
            None,
            Some(1),
            [2u8; 16],
            now_unix(),
        );
        assert!(g
            .issue_token("sign.x", "ctx", None, Some(1), Some(auth))
            .is_err());
    }

    #[test]
    fn operator_signed_issue_refuses_stale_timestamp() {
        let mut g = sealed_gate_with_secret();
        let key = OperatorKey::generate();
        g.authorize_operator(&key.public_key_hex()).unwrap();
        let stale = now_unix().saturating_sub(CONTROL_AUTH_WINDOW_SECS + 10);
        let auth = signed_issue(&g, &key, "sign.x", None, Some(1), [3u8; 16], stale);
        assert!(g
            .issue_token("sign.x", "ctx", None, Some(1), Some(auth))
            .is_err());
    }

    #[test]
    fn operator_signed_auth_is_bound_to_its_op_args() {
        // A signature minted to issue "sign.x" must not authorize issuing a different
        // scope: the gate rebuilds the args binding from the ACTUAL request, so the
        // signature no longer matches.
        let mut g = sealed_gate_with_secret();
        let key = OperatorKey::generate();
        g.authorize_operator(&key.public_key_hex()).unwrap();
        let auth = signed_issue(&g, &key, "sign.x", None, Some(1), [4u8; 16], now_unix());
        assert!(g
            .issue_token("release.sign", "ctx", None, Some(1), Some(auth))
            .is_err());
    }

    #[test]
    fn no_auth_is_refused_when_no_operator_key_provisioned() {
        let mut g = sealed_gate_with_secret();
        assert!(g.issue_token("sign.x", "ctx", None, Some(1), None).is_err());
    }
}
