/*!
Release signing — a capability-gated, provenance-verifying signing authority that
survives a **compromised build pipeline**.

The supply-chain twin of the broker's "survives a compromised host": the signing
key does **not** live in CI. CI holds only a capability token and a build
attestation; a separate signer (this authority) verifies the attestation against a
**server-side** policy and signs only then. A compromised CI cannot steal the key
(it is not there), cannot get an artifact signed whose provenance is unattested or
off-policy, and cannot sign silently (every decision is audited).

# Standard format, not a bespoke one
The attestation cage verifies is a **standard DSSE envelope** (Dead Simple Signing
Envelope) wrapping an **in-toto Statement v1** whose predicate is **SLSA Provenance
v1** — exactly what GitHub Actions, Sigstore, and the `slsa-github-generator` emit.
We implement the small, precise DSSE/in-toto wire spec to-spec (interop comes from
matching the format, not from a heavyweight 0.x crate in the audited core), and the
signature is verified over the DSSE **PAE** (Pre-Authentication Encoding) — the
standard canonicalization, which removes the signing-canonicalization footgun.

What this enforces — and, honestly, what it does not:
  * **Enforces:** the DSSE is **signed by the trusted builder** (a signature a
    compromised CI cannot forge), the in-toto subject **binds this exact artifact**
    (digest match — a genuine attestation can't be rebound to malware), the
    predicate is the expected **SLSA type**, and the SLSA provenance source/builder
    fields match **policy** held by the signer (never by the requester).
  * **Does not** prove the source is benign: an honest builder produces honest
    provenance for a maliciously-modified source (a poisoned commit/dependency).
    Defending that needs reproducible builds + review + quorum — orthogonal layers
    that plug in at this same choke point.
  * **Trust root:** we verify the DSSE signature against a **configured** attestor
    key. Verifying GitHub's *keyless* (Fulcio cert) attestations additionally needs
    a Sigstore cert-chain adapter (the key comes from the cert) — a clean future
    adapter, not core.
*/

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

const INTOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
const INTOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";

// --- standard wire types (only the fields we read; serde ignores the rest) ---

/// A DSSE envelope (<https://github.com/secure-systems-lab/dsse>).
#[derive(Deserialize)]
struct Envelope {
    /// base64(std) of the serialized in-toto Statement.
    payload: String,
    #[serde(rename = "payloadType")]
    payload_type: String,
    signatures: Vec<EnvelopeSig>,
}

#[derive(Deserialize)]
struct EnvelopeSig {
    /// base64(std) of the signature over `PAE(payloadType, payload)`.
    sig: String,
}

/// An in-toto Statement v1 (<https://in-toto.io/Statement/v1>).
#[derive(Deserialize)]
struct Statement {
    #[serde(rename = "_type")]
    type_: String,
    subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: serde_json::Value,
}

#[derive(Deserialize)]
struct Subject {
    /// e.g. `{"sha256": "<hex>"}`.
    digest: BTreeMap<String, String>,
}

// --- public surface ---

/// Server-side release policy. Held by the signer; **never** supplied by the
/// requester (a compromised CI must not be able to relax it).
#[derive(Clone, Debug)]
pub struct ReleasePolicy {
    /// The build platform's public key. The DSSE must be signed by it.
    pub trusted_attestor: VerifyingKey,
    /// The predicate type required (e.g. `"https://slsa.dev/provenance/v1"`).
    pub allowed_predicate_type: String,
    pub allowed_repo: String,
    /// SLSA `source_ref` must start with this (e.g. `"refs/tags/"`).
    pub allowed_ref_prefix: String,
    pub allowed_builder: String,
}

/// What a verified attestation established — recorded in the audit log on a sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRelease {
    pub source_repo: String,
    pub source_ref: String,
    pub builder: String,
}

/// Why a release was refused. Every variant is fail-closed — no signature is produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvenanceError {
    /// The DSSE envelope is unparseable, has the wrong payload type, or bad base64.
    MalformedEnvelope,
    /// No DSSE signature verifies under the trusted builder's key.
    UntrustedAttestor,
    /// The in-toto Statement is unparseable or not a v1 Statement.
    MalformedStatement,
    /// No subject binds the artifact being signed (a real attestation can't be
    /// rebound to a different artifact).
    DigestMismatch,
    /// The predicate type is not the one the policy allows.
    UnsupportedPredicateType,
    /// A SLSA provenance field (`builder` / `source_repo` / `source_ref`) is off-policy.
    PolicyMismatch(&'static str),
}

impl std::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvenanceError::MalformedEnvelope => f.write_str("malformed DSSE envelope"),
            ProvenanceError::UntrustedAttestor => {
                f.write_str("DSSE not signed by the trusted builder")
            }
            ProvenanceError::MalformedStatement => f.write_str("malformed in-toto Statement"),
            ProvenanceError::DigestMismatch => {
                f.write_str("attestation subject does not bind the artifact being signed")
            }
            ProvenanceError::UnsupportedPredicateType => {
                f.write_str("predicate type not allowed by the release policy")
            }
            ProvenanceError::PolicyMismatch(field) => {
                write!(f, "provenance {field} does not match the release policy")
            }
        }
    }
}

impl std::error::Error for ProvenanceError {}

/// DSSE Pre-Authentication Encoding: `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP
/// body`. The signature is over this, never the raw payload — the standard
/// canonicalization.
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

fn sig_verifies(key: &VerifyingKey, msg: &[u8], sig_b64: &str) -> bool {
    BASE64_STD
        .decode(sig_b64.as_bytes())
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
        .map(|arr| key.verify(msg, &Signature::from_bytes(&arr)).is_ok())
        .unwrap_or(false)
}

/// Verify a DSSE-wrapped in-toto/SLSA attestation against `policy` for the artifact
/// `expected_sha256` (raw hex). Pure — no key custody. Order: authenticity, then
/// artifact-binding, then policy.
pub fn verify(
    policy: &ReleasePolicy,
    attestation_dsse: &[u8],
    expected_sha256: &str,
) -> Result<VerifiedRelease, ProvenanceError> {
    // 1. Parse the DSSE envelope and decode the payload.
    let env: Envelope =
        serde_json::from_slice(attestation_dsse).map_err(|_| ProvenanceError::MalformedEnvelope)?;
    if env.payload_type != INTOTO_PAYLOAD_TYPE {
        return Err(ProvenanceError::MalformedEnvelope);
    }
    let payload = BASE64_STD
        .decode(env.payload.as_bytes())
        .map_err(|_| ProvenanceError::MalformedEnvelope)?;

    // 2. Authenticity: a trusted-builder signature over the DSSE PAE. A compromised
    //    CI cannot forge this.
    let pae = pae(&env.payload_type, &payload);
    let authentic = env
        .signatures
        .iter()
        .any(|s| sig_verifies(&policy.trusted_attestor, &pae, &s.sig));
    if !authentic {
        return Err(ProvenanceError::UntrustedAttestor);
    }

    // 3. Parse the in-toto Statement.
    let stmt: Statement =
        serde_json::from_slice(&payload).map_err(|_| ProvenanceError::MalformedStatement)?;
    if stmt.type_ != INTOTO_STATEMENT_V1 {
        return Err(ProvenanceError::MalformedStatement);
    }

    // 4. The subject must bind the artifact we are asked to sign — so a genuine
    //    attestation for the real release cannot be rebound to malware.
    let bound = stmt
        .subject
        .iter()
        .any(|s| s.digest.get("sha256").is_some_and(|d| d == expected_sha256));
    if !bound {
        return Err(ProvenanceError::DigestMismatch);
    }

    // 5. Predicate type, then SLSA Provenance v1 fields, against server-side policy.
    if stmt.predicate_type != policy.allowed_predicate_type {
        return Err(ProvenanceError::UnsupportedPredicateType);
    }
    let builder = stmt
        .predicate
        .pointer("/runDetails/builder/id")
        .and_then(|v| v.as_str())
        .ok_or(ProvenanceError::PolicyMismatch("builder"))?;
    if builder != policy.allowed_builder {
        return Err(ProvenanceError::PolicyMismatch("builder"));
    }
    let repo = stmt
        .predicate
        .pointer("/buildDefinition/externalParameters/workflow/repository")
        .and_then(|v| v.as_str())
        .ok_or(ProvenanceError::PolicyMismatch("source_repo"))?;
    if repo != policy.allowed_repo {
        return Err(ProvenanceError::PolicyMismatch("source_repo"));
    }
    let git_ref = stmt
        .predicate
        .pointer("/buildDefinition/externalParameters/workflow/ref")
        .and_then(|v| v.as_str())
        .ok_or(ProvenanceError::PolicyMismatch("source_ref"))?;
    if !git_ref.starts_with(&policy.allowed_ref_prefix) {
        return Err(ProvenanceError::PolicyMismatch("source_ref"));
    }

    Ok(VerifiedRelease {
        source_repo: repo.to_string(),
        source_ref: git_ref.to_string(),
        builder: builder.to_string(),
    })
}

/// True iff `s` is exactly 64 lowercase hex characters — a canonical SHA-256
/// digest. The release path validates this so the signer is never a signing oracle
/// over short, attacker-chosen strings.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The canonical, length-framed statement the vault signs for a release — and that
/// a verifier reconstructs. It binds the artifact digest AND the policy-verified
/// provenance (source repo / ref / builder), so the published signature commits to
/// *what was verified*, not merely the digest. Length-framing under a domain tag
/// removes any concatenation ambiguity.
pub fn release_signing_statement(verified: &VerifiedRelease, artifact_sha256: &str) -> Vec<u8> {
    fn frame(out: &mut Vec<u8>, field: &[u8]) {
        out.extend_from_slice(&(field.len() as u64).to_le_bytes());
        out.extend_from_slice(field);
    }
    let mut out = Vec::new();
    frame(&mut out, b"cage/release-statement/v1");
    frame(&mut out, artifact_sha256.as_bytes());
    frame(&mut out, verified.source_repo.as_bytes());
    frame(&mut out, verified.source_ref.as_bytes());
    frame(&mut out, verified.builder.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Gate;
    use ed25519_dalek::{Signer, SigningKey};

    const REPO: &str = "github.com/derdelean/cage";
    const BUILDER: &str = "https://github.com/derdelean/cage/.github/workflows/release.yml";
    const SLSA_V1: &str = "https://slsa.dev/provenance/v1";
    // Canonical 64-lowercase-hex SHA-256 digests (the release path now validates this).
    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const OTHER_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn attestor() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn vk_from_b64(b64: &str) -> VerifyingKey {
        let bytes = BASE64_STD.decode(b64).unwrap();
        VerifyingKey::from_bytes(&<[u8; 32]>::try_from(bytes.as_slice()).unwrap()).unwrap()
    }

    fn policy(att: &SigningKey) -> ReleasePolicy {
        ReleasePolicy {
            trusted_attestor: att.verifying_key(),
            allowed_predicate_type: SLSA_V1.into(),
            allowed_repo: REPO.into(),
            allowed_ref_prefix: "refs/tags/".into(),
            allowed_builder: BUILDER.into(),
        }
    }

    /// Build a real DSSE envelope wrapping an in-toto Statement v1 with a SLSA
    /// Provenance v1 predicate — the same shape GitHub/Sigstore emit — signed by
    /// `signer` over the DSSE PAE.
    fn build_dsse(signer: &SigningKey, sha256: &str, git_ref: &str, builder: &str) -> Vec<u8> {
        let statement = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "subject": [{"name": "cage.whl", "digest": {"sha256": sha256}}],
            "predicateType": SLSA_V1,
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                    "externalParameters": {
                        "workflow": {"repository": REPO, "ref": git_ref, "path": ".github/workflows/release.yml"}
                    }
                },
                "runDetails": {"builder": {"id": builder}}
            }
        });
        let payload = serde_json::to_vec(&statement).unwrap();
        let sig = signer.sign(&pae(INTOTO_PAYLOAD_TYPE, &payload));
        let envelope = serde_json::json!({
            "payload": BASE64_STD.encode(&payload),
            "payloadType": INTOTO_PAYLOAD_TYPE,
            "signatures": [{"keyid": "builder", "sig": BASE64_STD.encode(sig.to_bytes())}]
        });
        serde_json::to_vec(&envelope).unwrap()
    }

    fn signer_and_ci_token(pol: ReleasePolicy, max_uses: Option<u32>) -> (Gate, String) {
        let mut g = Gate::new();
        g.store_secret("release_signing_key", "sk-release-hmac-not-a-real-key")
            .unwrap();
        g.register_scope_secret("release.", "release_signing_key");
        g.set_release_policy(pol);
        let bootstrap = g.unseal().unwrap();
        let token = g
            .issue_token(
                "release.sign",
                "ci-run",
                None,
                max_uses,
                Some(crate::ControlAuth::Bootstrap(&bootstrap)),
            )
            .unwrap()
            .token_id;
        (g, token)
    }

    #[test]
    fn legit_ci_signs_a_release() {
        let att = attestor();
        let (mut g, token) = signer_and_ci_token(policy(&att), None);
        let git_ref = "refs/tags/v1.2.3";
        let dsse = build_dsse(&att, DIGEST, git_ref, BUILDER);
        let sig = g
            .sign_release(&token, DIGEST, &dsse)
            .expect("legit release signs");
        assert!(!sig.is_empty());
        assert!(g.verify_audit_chain());

        // The release signature is over the STRUCTURED statement (digest + verified
        // provenance) under the RELEASE key, verifiable with release_public_key().
        let verified = VerifiedRelease {
            source_repo: REPO.into(),
            source_ref: git_ref.into(),
            builder: BUILDER.into(),
        };
        let statement = release_signing_statement(&verified, DIGEST);
        let sig_bytes = BASE64_STD.decode(&sig).unwrap();
        let signature = Signature::from_bytes(&<[u8; 64]>::try_from(sig_bytes.as_slice()).unwrap());
        assert!(vk_from_b64(&g.release_public_key())
            .verify(&statement, &signature)
            .is_ok());

        // Cross-protocol separation: the release signature does NOT verify under the
        // audit-attestation key (distinct identities), nor over the bare digest.
        assert!(vk_from_b64(&g.attestation_public_key())
            .verify(&statement, &signature)
            .is_err());
        assert!(vk_from_b64(&g.release_public_key())
            .verify(DIGEST.as_bytes(), &signature)
            .is_err());
    }

    #[test]
    fn compromised_ci_cannot_forge_provenance() {
        // The CI signs the DSSE with its own key, not the trusted builder's.
        let att = attestor();
        let (mut g, token) = signer_and_ci_token(policy(&att), None);
        let digest = DIGEST;
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let dsse = build_dsse(&attacker, digest, "refs/tags/v9", BUILDER);
        assert!(g.sign_release(&token, digest, &dsse).is_err());
    }

    #[test]
    fn compromised_ci_cannot_rebind_a_real_attestation_to_malware() {
        // A genuine attestation for the real artifact cannot be reused to sign a
        // different (malicious) digest — the subject binds the artifact.
        let att = attestor();
        let (mut g, token) = signer_and_ci_token(policy(&att), None);
        let real = build_dsse(&att, DIGEST, "refs/tags/v1.2.3", BUILDER);
        assert!(g.sign_release(&token, OTHER_DIGEST, &real).is_err());
    }

    #[test]
    fn tampered_payload_fails_dsse() {
        // Flip a byte in the envelope: the PAE no longer matches the signature.
        let att = attestor();
        let (mut g, token) = signer_and_ci_token(policy(&att), None);
        let digest = DIGEST;
        let mut dsse = build_dsse(&att, digest, "refs/tags/v1.2.3", BUILDER);
        let i = dsse.len() / 2;
        dsse[i] ^= 0x01;
        assert!(g.sign_release(&token, digest, &dsse).is_err());
    }

    #[test]
    fn off_protected_ref_is_refused() {
        let att = attestor();
        let (mut g, token) = signer_and_ci_token(policy(&att), None);
        let digest = DIGEST;
        let dsse = build_dsse(&att, digest, "refs/heads/attacker", BUILDER);
        assert!(g.sign_release(&token, digest, &dsse).is_err());
    }

    #[test]
    fn unauthorized_builder_is_refused() {
        let att = attestor();
        let (mut g, token) = signer_and_ci_token(policy(&att), None);
        let digest = DIGEST;
        let dsse = build_dsse(&att, digest, "refs/tags/v1", "evil://builder");
        assert!(g.sign_release(&token, digest, &dsse).is_err());
    }

    #[test]
    fn fabricated_capability_token_is_refused() {
        let att = attestor();
        let (mut g, _token) = signer_and_ci_token(policy(&att), None);
        let digest = DIGEST;
        let dsse = build_dsse(&att, digest, "refs/tags/v1", BUILDER);
        assert!(g.sign_release(&"00".repeat(16), digest, &dsse).is_err());
    }

    #[test]
    fn over_max_uses_is_refused() {
        let att = attestor();
        let (mut g, token) = signer_and_ci_token(policy(&att), Some(1));
        let digest = DIGEST;
        let dsse = build_dsse(&att, digest, "refs/tags/v1", BUILDER);
        assert!(g.sign_release(&token, digest, &dsse).is_ok());
        assert!(g.sign_release(&token, digest, &dsse).is_err());
    }

    #[test]
    fn non_hex_digest_is_refused_before_signing() {
        let att = attestor();
        let (mut g, token) = signer_and_ci_token(policy(&att), None);
        // A real DSSE, but the artifact digest is not 64-lowercase-hex — the signer
        // must refuse before signing, so it is never an oracle over short strings.
        let dsse = build_dsse(&att, "not-a-64-hex-digest", "refs/tags/v1", BUILDER);
        assert!(g
            .sign_release(&token, "not-a-64-hex-digest", &dsse)
            .is_err());
        assert!(g.sign_release(&token, "abcdef", &dsse).is_err());
        // Uppercase hex is rejected (canonical form is lowercase).
        assert!(g.sign_release(&token, &"A".repeat(64), &dsse).is_err());
    }

    #[test]
    fn is_sha256_hex_accepts_only_64_lowercase_hex() {
        assert!(is_sha256_hex(DIGEST));
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"a".repeat(63)));
        assert!(!is_sha256_hex(&"a".repeat(65)));
        assert!(!is_sha256_hex(&"A".repeat(64))); // uppercase
        assert!(!is_sha256_hex(&"g".repeat(64))); // non-hex
        assert!(!is_sha256_hex(""));
    }
}
