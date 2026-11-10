/*!
Vault — the credential core: ChaCha20Poly1305 storage, bootstrap-gated
capability authority, append-only Merkle audit chain, and ed25519 audit-head
attestation. Pure Rust; no PyO3, no RPC.

Memory security (why this is Rust, not Python):
  • `Zeroizing<T>` overwrites the key with zeros on drop, at the language level,
    before the allocator reclaims the pages. Release builds abort on panic
    (`panic = "abort"`), so a panic skips the drops and whatever was live at that
    moment is not zeroed before the process exits. The abort raises SIGABRT, so
    where core dumps are enabled that memory can land in a core file. Run a
    process that holds a `Vault` with a core-dump limit of 0.
  • `mlock(2)` pins the key + bootstrap pages in physical RAM (best-effort;
    requires CAP_IPC_LOCK on Linux).
  • ChaCha20Poly1305 AEAD: a memory-writing attacker gets a decrypt error, not
    silently corrupted plaintext.

When this `Vault` runs inside the `cage-broker` binary in a separate trust
domain (a hardened process), the decrypted
key never enters the agent's address space at all — the agent holds only
capability tokens and talks to the broker over an RPC boundary.
*/

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CageError;
use crate::transport;

/// Domain marker bound into the audit-head attestation JSON — defense in depth on
/// top of the *separate* attestation key, so the two signing protocols cannot be
/// confused even if a future refactor touched the key handling. (The release path
/// is domain-tagged inside its own length-framed statement.)
const AUDIT_ATTESTATION_DOMAIN: &str = "cage/audit-head/v1";
/// Domain tag for the signed audit-chain checkpoint — the off-box anchor against
/// which chain extension is later verified.
const CHECKPOINT_DOMAIN: &[u8] = b"cage/audit-checkpoint/v1";

/// The exact bytes a checkpoint signs (and a verifier reconstructs): a
/// domain-separated, length-framed binding of the audit head and length.
fn checkpoint_message(head: &str, len: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHECKPOINT_DOMAIN.len() + head.len() + 24);
    out.extend_from_slice(&(CHECKPOINT_DOMAIN.len() as u64).to_le_bytes());
    out.extend_from_slice(CHECKPOINT_DOMAIN);
    out.extend_from_slice(&(head.len() as u64).to_le_bytes());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// Audit chain
// ---------------------------------------------------------------------------

/// One entry in the canonical Merkle audit chain. Held inside the vault;
/// callers receive only read-only [`AuditEntrySnapshot`]s whose mutation
/// cannot affect the canonical chain or its hash verification.
#[derive(Clone, Debug)]
struct StoredAuditEntry {
    /// Strictly-monotonic position in the chain (0-based), hashed into the entry
    /// so positions are non-fungible — an entry cannot be reordered or dropped
    /// without breaking the hash at its position.
    seq: u64,
    entity_id: String,
    event: String,
    data: serde_json::Value,
    timestamp: String,
    prev_hash: String,
    hash: String,
}

/// Read-only snapshot of one audit entry, safe to hand across a binding
/// boundary (PyO3 dict, broker RPC). `data_json` is the entry's `data`
/// re-serialized to JSON.
#[derive(Clone, Debug, Serialize)]
pub struct AuditEntrySnapshot {
    pub seq: u64,
    pub entity_id: String,
    pub event: String,
    pub data_json: String,
    pub timestamp: String,
    pub prev_hash: String,
    pub hash: String,
}

/// Canonical entry hash: `SHA-256( prev_hash || JSON(entry_with_sorted_keys) )`,
/// where the entry includes its monotonic `seq`.
///
/// `serde_json::Map` is BTreeMap-backed — keys serialize in lexicographic order
/// at every nesting level; the canonical form is compact (no inter-token
/// whitespace). NOTE for external / cross-language verifiers: `serde_json` emits
/// no separators, so a Python re-verifier MUST use
/// `json.dumps(obj, sort_keys=True, separators=(",", ":"))` — Python's default
/// adds ", " / ": " spacing and would NOT reproduce this byte sequence — and MUST
/// include the integer `seq`. Within a single backend the chain always
/// self-verifies regardless.
fn compute_entry_hash(
    prev_hash: &str,
    seq: u64,
    entity_id: &str,
    event: &str,
    data: &serde_json::Value,
    timestamp: &str,
) -> String {
    let mut entry_obj = serde_json::Map::new();
    entry_obj.insert("data".to_string(), data.clone());
    entry_obj.insert(
        "entity_id".to_string(),
        serde_json::Value::String(entity_id.to_string()),
    );
    entry_obj.insert(
        "event".to_string(),
        serde_json::Value::String(event.to_string()),
    );
    entry_obj.insert(
        "prev_hash".to_string(),
        serde_json::Value::String(prev_hash.to_string()),
    );
    entry_obj.insert("seq".to_string(), serde_json::Value::Number(seq.into()));
    entry_obj.insert(
        "timestamp".to_string(),
        serde_json::Value::String(timestamp.to_string()),
    );
    let entry_json = serde_json::to_string(&serde_json::Value::Object(entry_obj))
        .expect("canonical audit JSON serialize must succeed");

    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(entry_json.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 over owned state
// ---------------------------------------------------------------------------

const SHA256_BLOCK: usize = 64;

/// SHA-256 initial hash value (FIPS 180-4, section 5.3.3).
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Bytes of stack that `scrub_stack` overwrites. Measured 2026-10-26 on aarch64
/// macOS, the decrypt and HMAC under `sign_hmac` reached about 2 KiB below it in a
/// release build and about 14 KiB in a debug build. The rest is room for a signal
/// frame, which saves the vector registers onto the stack.
const STACK_SCRUB_BYTES: usize = 32 * 1024;

/// Feed whole blocks of `data` to the SHA-256 compression function. Each block is
/// passed by reference, so no copy of it is made here.
fn sha256_compress_blocks(state: &mut [u32; 8], data: &[u8]) {
    debug_assert_eq!(data.len() % SHA256_BLOCK, 0);
    for block in data.chunks_exact(SHA256_BLOCK) {
        let block: &[u8; SHA256_BLOCK] =
            block.try_into().expect("chunks_exact yields whole blocks");
        sha2::block_api::compress256(state, std::slice::from_ref(block));
    }
}

/// Hash the rest of a message of `total_len` bytes: `data`, then the padding of
/// FIPS 180-4 section 5.1.1. `state` then holds the digest. The last partial block
/// is padded in a buffer that is zeroed on drop.
fn sha256_finish(state: &mut [u32; 8], data: &[u8], total_len: usize) {
    let whole = data.len() - data.len() % SHA256_BLOCK;
    sha256_compress_blocks(state, &data[..whole]);
    let tail = &data[whole..];
    let mut last = Zeroizing::new([0u8; 2 * SHA256_BLOCK]);
    last[..tail.len()].copy_from_slice(tail);
    last[tail.len()] = 0x80;
    // The bit length fills the last 8 bytes, so a tail of 56 bytes or more spills
    // into a second block.
    let end = if tail.len() < SHA256_BLOCK - 8 {
        SHA256_BLOCK
    } else {
        2 * SHA256_BLOCK
    };
    let bit_len = total_len as u64 * 8;
    last[end - 8..end].copy_from_slice(&bit_len.to_be_bytes());
    sha256_compress_blocks(state, &last[..end]);
}

/// Write the digest held in `state` to `out`.
fn sha256_digest_into(state: &[u32; 8], out: &mut [u8; 32]) {
    for (bytes, word) in out.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
}

/// HMAC-SHA256 (RFC 2104). The `sha2` hasher does not zero its chaining state and
/// is moved by value, which leaves copies of it on the stack (three of each
/// chaining state in a debug build). So every key-derived value here (the padded
/// key, the chaining state, the inner digest) lives in a `Zeroizing` buffer of its
/// own and is only passed by reference. The compression function still works on
/// its own stack frame and in registers. `scrub_stack` covers the frame.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut state = Zeroizing::new(SHA256_IV);
    // K0, built in the one buffer that then becomes ipad and opad in turn: the
    // key, or H(K) when it is longer than the hash block, zero-padded.
    let mut pad = Zeroizing::new([0u8; SHA256_BLOCK]);
    if key.len() > SHA256_BLOCK {
        sha256_finish(&mut state, key, key.len());
        let head: &mut [u8; 32] = (&mut pad[..32]).try_into().expect("32 bytes");
        sha256_digest_into(&state, head);
    } else {
        pad[..key.len()].copy_from_slice(key);
    }
    let mut inner = Zeroizing::new([0u8; 32]);
    let mut mac = [0u8; 32];

    // inner = H((K0 ^ ipad) || msg)
    for p in pad.iter_mut() {
        *p ^= 0x36;
    }
    *state = SHA256_IV;
    sha256_compress_blocks(&mut state, &pad[..]);
    sha256_finish(&mut state, msg, SHA256_BLOCK + msg.len());
    sha256_digest_into(&state, &mut inner);

    // mac = H((K0 ^ opad) || inner). ipad turns into opad in place.
    for p in pad.iter_mut() {
        *p ^= 0x36 ^ 0x5c;
    }
    *state = SHA256_IV;
    sha256_compress_blocks(&mut state, &pad[..]);
    sha256_finish(&mut state, &inner[..], SHA256_BLOCK + inner.len());
    sha256_digest_into(&state, &mut mac);
    mac
}

/// Overwrite the stack that a secret operation called from the same frame just
/// used. `Zeroizing` clears the buffers it owns, but the cipher and hash code under
/// them work on dead frames below the caller that nothing clears. What stays there
/// depends on the build profile and the caller. On aarch64 macOS, a release build
/// without LTO left a ChaCha20 state holding the vault's master key there, outside
/// the mlocked pages. Call this right after the secret
/// operation, from the frame that called it, and keep that operation
/// `#[inline(never)]` so all of its locals lie below that frame. Registers are not
/// cleared.
#[inline(never)]
fn scrub_stack() {
    let mut area = [0u128; STACK_SCRUB_BYTES / 16];
    area.zeroize();
}

// ---------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------

/// Process-lifetime credential store + capability authority + audit chain.
pub struct Vault {
    /// 256-bit process-ephemeral ChaCha20Poly1305 key, zeroed on drop.
    enc_key: Zeroizing<Vec<u8>>,
    /// name → (nonce_bytes: [u8;12], ciphertext_with_tag: Vec<u8>)
    store: HashMap<String, ([u8; 12], Vec<u8>)>,
    /// 256-bit bootstrap token. Revealed once via `unseal()`, then required as
    /// proof of authorization for every subsequent token issuance.
    bootstrap_token: Zeroizing<Vec<u8>>,
    /// True after `unseal()` has been called once.
    bootstrap_revealed: bool,
    /// True if `mlock(2)` on both the key and bootstrap pages succeeded.
    mlock_succeeded: bool,
    /// Canonical Merkle audit chain.
    audit_log: Vec<StoredAuditEntry>,
    /// SHA-256 head pointer for the audit chain.
    audit_head: String,
    /// Ed25519 signing key for external-attestation envelopes (Rekor anchoring).
    attestation_key: SigningKey,
    /// Ed25519 signing key for **release** signatures — independent from
    /// `attestation_key` so a release signature can never validate as an audit
    /// attestation, and the ungated audit-attestation path is not an oracle on the
    /// release-trusted key.
    release_key: SigningKey,
}

impl Drop for Vault {
    fn drop(&mut self) {
        // Belt-and-suspenders: explicitly zero every stored ciphertext too.
        for (nonce, ct) in self.store.values_mut() {
            nonce.zeroize();
            ct.zeroize();
        }
        // enc_key + bootstrap_token are zeroed by Zeroizing<T> automatically.
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault {
    /// Create a new vault with a fresh OS-random 256-bit key. On UNIX, `mlock(2)`
    /// pins the key + bootstrap pages (best-effort; needs CAP_IPC_LOCK).
    pub fn new() -> Self {
        use rand_core::RngCore;
        // Heap-allocate the key + bootstrap so their byte buffers have a STABLE
        // address. The Vault is returned by value (moved to the caller); an
        // inline [u8;32] would relocate on every move, leaving any mlock'd page
        // behind and silently defeating Invariant 7. A Vec's heap buffer does
        // not move when the owning struct moves, so the mlock below stays valid
        // for the life of the key.
        let mut raw_key = Zeroizing::new(vec![0u8; 32]);
        let mut bootstrap = Zeroizing::new(vec![0u8; 32]);

        let mut mlock_succeeded = true;
        #[cfg(unix)]
        {
            let rc_key = unsafe { libc::mlock(raw_key.as_ptr() as *const libc::c_void, 32) };
            let rc_bootstrap =
                unsafe { libc::mlock(bootstrap.as_ptr() as *const libc::c_void, 32) };
            if rc_key != 0 || rc_bootstrap != 0 {
                mlock_succeeded = false;
                eprintln!(
                    "[cage] mlock failed (errno={}): keys may be swapped to disk. \
                     Grant CAP_IPC_LOCK (Linux) or set ulimit -l unlimited. \
                     See DEPLOY.md. Process can continue, but the in-memory \
                     protection claim is degraded — use strict_mlock to refuse \
                     to start in this state.",
                    std::io::Error::last_os_error()
                );
            }
        }
        #[cfg(not(unix))]
        {
            mlock_succeeded = false;
            eprintln!(
                "[cage] mlock unavailable on this platform: keys may be paged. \
                 strict_mlock will refuse to start."
            );
        }

        // Filled after the mlock call, so on success these bytes never sit in an
        // unlocked page. getrandom writes them straight into these buffers. A
        // userspace generator such as rand's thread_rng() keeps a copy of its
        // output in a heap block that is never locked or wiped, which is why this
        // crate depends on rand_core and not on rand.
        OsRng.fill_bytes(raw_key.as_mut_slice());
        OsRng.fill_bytes(bootstrap.as_mut_slice());
        let attestation_key = SigningKey::generate(&mut OsRng);
        let release_key = SigningKey::generate(&mut OsRng);

        Vault {
            enc_key: raw_key,
            store: HashMap::new(),
            bootstrap_token: bootstrap,
            bootstrap_revealed: false,
            mlock_succeeded,
            audit_log: Vec::new(),
            audit_head: "0".repeat(64),
            attestation_key,
            release_key,
        }
    }

    /// Encrypt `plaintext` under the vault key and store under `name`.
    pub fn store_secret(&mut self, name: String, plaintext: String) -> Result<(), CageError> {
        let plaintext_bytes = Zeroizing::new(plaintext.into_bytes());
        self.encrypt_and_store(name, plaintext_bytes.as_slice())
    }

    /// True if a secret with this name is stored.
    pub fn has_secret(&self, name: &str) -> bool {
        self.store.contains_key(name)
    }

    /// Remove and explicitly zero a stored secret. Returns whether it existed.
    pub fn delete_secret(&mut self, name: &str) -> bool {
        if let Some((mut nonce, mut ct)) = self.store.remove(name) {
            nonce.zeroize();
            ct.zeroize();
            true
        } else {
            false
        }
    }

    /// Reveal the bootstrap token once (64-char hex). After this, no token can
    /// be issued without presenting it. Errors on the second call.
    pub fn unseal(&mut self) -> Result<Zeroizing<String>, CageError> {
        if self.bootstrap_revealed {
            return Err(CageError::AlreadyUnsealed);
        }
        self.bootstrap_revealed = true;
        // Wrap this handout copy of the authority root in Zeroizing so it is wiped on
        // drop (the mlock'd token stays; this is the second, returnable hex copy that
        // would otherwise linger un-zeroed in the caller's String).
        Ok(Zeroizing::new(hex::encode(self.bootstrap_token.as_slice())))
    }

    /// True after `unseal()` has been called.
    pub fn is_unsealed(&self) -> bool {
        self.bootstrap_revealed
    }

    /// True if `mlock(2)` succeeded on both the key and bootstrap pages.
    pub fn mlock_succeeded(&self) -> bool {
        self.mlock_succeeded
    }

    /// Constant-time verification of a presented bootstrap token (hex).
    pub fn verify_bootstrap(&self, token: &str) -> bool {
        let presented = match hex::decode(token) {
            Ok(b) => b,
            Err(_) => return false,
        };
        if presented.len() != 32 {
            return false;
        }
        let stored: &[u8] = self.bootstrap_token.as_slice();
        bool::from(presented.ct_eq(stored))
    }

    /// Permanently zero the bootstrap secret. Used by the broker / operator-PoP
    /// path, which authenticates the control plane by operator signature and never
    /// presents the bootstrap — so the secret should not linger in broker memory as
    /// a forge-the-authority value. After this, `verify_bootstrap` always fails (the
    /// stored bytes are empty) and `unseal` is treated as already done.
    pub fn discard_bootstrap(&mut self) {
        self.bootstrap_token = Zeroizing::new(Vec::new());
        self.bootstrap_revealed = true;
    }

    /// Load secrets from a `.env`-format file directly into vault memory. The
    /// plaintext values never leave a `Zeroizing<Vec<u8>>` inside this method.
    /// Returns the count loaded.
    pub fn load_from_env_file(
        &mut self,
        path: &str,
        secret_names: Vec<String>,
    ) -> Result<usize, CageError> {
        let raw_bytes = std::fs::read(path)
            .map_err(|e| CageError::Io(format!("cannot read env file {path:?}: {e}")))?;
        let raw_bytes = Zeroizing::new(raw_bytes);

        let mut loaded = 0usize;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for line_bytes in raw_bytes.split(|&b| b == b'\n') {
            let line = match std::str::from_utf8(line_bytes) {
                Ok(s) => s.trim(),
                Err(_) => continue,
            };
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, val_raw) = match line.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => continue,
            };
            let val =
                if let Some(inner) = val_raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                    inner
                } else if let Some(inner) = val_raw
                    .strip_prefix('\'')
                    .and_then(|s| s.strip_suffix('\''))
                {
                    inner
                } else {
                    val_raw
                };

            if !secret_names.iter().any(|n| n == key) {
                continue;
            }
            if !seen.insert(key.to_string()) {
                return Err(CageError::DuplicateEnvKey {
                    key: key.to_string(),
                    path: path.to_string(),
                });
            }

            let plaintext_bytes = Zeroizing::new(val.as_bytes().to_vec());
            self.encrypt_and_store(key.to_string(), plaintext_bytes.as_slice())?;
            loaded += 1;
        }

        Ok(loaded)
    }

    /// POST `request_body_json` to `provider`'s endpoint authenticated with the
    /// secret named `secret_name`. The decrypted key is held only in
    /// `Zeroizing<Vec<u8>>` buffers from decryption through connect, TLS handshake
    /// and write, first the decrypted buffer and then the request buffer. It never
    /// leaves the vault as a plaintext value.
    pub fn invoke(
        &self,
        provider: &str,
        secret_name: &str,
        request_body_json: &str,
    ) -> Result<String, CageError> {
        let plaintext = self.decrypt_to_zeroizing(secret_name)?;
        Ok(transport::post_messages(
            provider,
            plaintext,
            request_body_json.as_bytes(),
        )?)
    }

    /// Append an entry to the canonical chain. Returns the new head hash.
    pub fn append_audit(
        &mut self,
        entity_id: String,
        event: String,
        data_json: String,
        timestamp: String,
    ) -> Result<String, CageError> {
        let data: serde_json::Value =
            serde_json::from_str(&data_json).map_err(|e| CageError::BadAuditData(e.to_string()))?;

        let prev = self.audit_head.clone();
        let seq = self.audit_log.len() as u64;
        let new_hash = compute_entry_hash(&prev, seq, &entity_id, &event, &data, &timestamp);

        self.audit_log.push(StoredAuditEntry {
            seq,
            entity_id,
            event,
            data,
            timestamp,
            prev_hash: prev,
            hash: new_hash.clone(),
        });
        self.audit_head = new_hash.clone();
        Ok(new_hash)
    }

    /// Verify internal link consistency from genesis: every entry's hash recomputes,
    /// its `prev_hash` chains, and its `seq` equals its position.
    ///
    /// This proves the chain is an internally-consistent hash list — it does **not**
    /// by itself prove append-only-ness, because an adversary who can mutate the
    /// in-memory log can rewrite every entry consistently and reset the head. To
    /// detect truncation/rewrite you must compare against an **external** anchor:
    /// publish a signed [`checkpoint`](Self::checkpoint) off-box and later call
    /// [`verify_audit_chain_extends`](Self::verify_audit_chain_extends).
    pub fn verify_audit_chain(&self) -> bool {
        let mut prev = "0".repeat(64);
        for (i, entry) in self.audit_log.iter().enumerate() {
            let seq = i as u64;
            let expected = compute_entry_hash(
                &prev,
                seq,
                &entry.entity_id,
                &entry.event,
                &entry.data,
                &entry.timestamp,
            );
            if entry.seq != seq || expected != entry.hash || entry.prev_hash != prev {
                return false;
            }
            prev = entry.hash.clone();
        }
        true
    }

    /// Number of entries in the chain.
    pub fn audit_log_len(&self) -> usize {
        self.audit_log.len()
    }

    /// Current chain head hash (SHA-256, hex).
    pub fn audit_head(&self) -> String {
        self.audit_head.clone()
    }

    /// Read-only snapshot of the whole chain. Mutating the returned vec does
    /// not affect the canonical chain.
    pub fn audit_log_snapshot(&self) -> Vec<AuditEntrySnapshot> {
        self.audit_log
            .iter()
            .map(|e| AuditEntrySnapshot {
                seq: e.seq,
                entity_id: e.entity_id.clone(),
                event: e.event.clone(),
                data_json: serde_json::to_string(&e.data).unwrap_or_else(|_| "null".to_string()),
                timestamp: e.timestamp.clone(),
                prev_hash: e.prev_hash.clone(),
                hash: e.hash.clone(),
            })
            .collect()
    }

    /// Generate a signed ed25519 attestation envelope over the current audit
    /// head — submit to Sigstore Rekor / any append-only ledger.
    pub fn attestation_payload(&self, timestamp: String) -> Result<String, CageError> {
        let mut payload = serde_json::Map::new();
        payload.insert(
            "algorithm".to_string(),
            serde_json::Value::String("ed25519".to_string()),
        );
        payload.insert(
            "domain".to_string(),
            serde_json::Value::String(AUDIT_ATTESTATION_DOMAIN.to_string()),
        );
        payload.insert(
            "audit_head".to_string(),
            serde_json::Value::String(self.audit_head.clone()),
        );
        payload.insert(
            "audit_log_len".to_string(),
            serde_json::Value::Number(self.audit_log.len().into()),
        );
        payload.insert(
            "issuer".to_string(),
            serde_json::Value::String("cage/0.1".to_string()),
        );
        payload.insert(
            "timestamp".to_string(),
            serde_json::Value::String(timestamp),
        );
        let payload_canonical = serde_json::to_string(&serde_json::Value::Object(payload))
            .map_err(|e| CageError::Serialize(e.to_string()))?;

        let signature = self.attestation_key.sign(payload_canonical.as_bytes());

        let mut envelope = serde_json::Map::new();
        envelope.insert(
            "payload_canonical".to_string(),
            serde_json::Value::String(payload_canonical),
        );
        envelope.insert(
            "signature_b64".to_string(),
            serde_json::Value::String(BASE64_STD.encode(signature.to_bytes())),
        );
        envelope.insert(
            "public_key_b64".to_string(),
            serde_json::Value::String(
                BASE64_STD.encode(self.attestation_key.verifying_key().as_bytes()),
            ),
        );
        serde_json::to_string(&serde_json::Value::Object(envelope))
            .map_err(|e| CageError::Serialize(e.to_string()))
    }

    /// Base64-encoded ed25519 public key used to verify attestation envelopes.
    pub fn attestation_public_key(&self) -> String {
        BASE64_STD.encode(self.attestation_key.verifying_key().as_bytes())
    }

    /// Raw 32-byte ed25519 verifying key of the audit-attestation identity, the same
    /// key [`attestation_public_key`](Self::attestation_public_key) returns base64.
    /// The release-signing key is a different key.
    pub fn attestation_verifying_key_bytes(&self) -> [u8; 32] {
        self.attestation_key.verifying_key().to_bytes()
    }

    /// HMAC-SHA256 sign `payload` with the secret named `secret_name`, returning
    /// the hex signature. This is the vault-held signing operation: a caller proves
    /// authority (via a capability token) and gets a signature back without ever
    /// holding the key. The key and every value derived from it live in `Zeroizing`
    /// buffers (see `hmac_sha256`), and the stack that the decrypt and the HMAC
    /// used is overwritten before this returns (see `scrub_stack`).
    pub fn sign_hmac(&self, secret_name: &str, payload: &[u8]) -> Result<String, CageError> {
        let mac = self.hmac_with_secret(secret_name, payload);
        scrub_stack();
        mac.map(hex::encode)
    }

    /// The part of `sign_hmac` that touches the key, kept out of line so all of its
    /// stack lies below `sign_hmac`'s frame, where `scrub_stack` reaches it.
    #[inline(never)]
    fn hmac_with_secret(&self, secret_name: &str, payload: &[u8]) -> Result<[u8; 32], CageError> {
        let key = self.decrypt_to_zeroizing(secret_name)?;
        Ok(hmac_sha256(&key, payload))
    }

    /// Ed25519-sign a (domain-tagged, length-framed) release `statement` with the
    /// vault's **release identity** — a key distinct from the audit-attestation key,
    /// so a release signature can never validate as an audit attestation. The
    /// statement carries its own domain tag (see `release_signing_statement`).
    /// Publicly verifiable with [`release_public_key`](Self::release_public_key);
    /// the private key never leaves the vault.
    pub fn sign_release(&self, statement: &[u8]) -> String {
        BASE64_STD.encode(self.release_key.sign(statement).to_bytes())
    }

    /// Base64-encoded ed25519 public key that verifies release signatures (the
    /// release identity — distinct from the audit-attestation key).
    pub fn release_public_key(&self) -> String {
        BASE64_STD.encode(self.release_key.verifying_key().as_bytes())
    }

    /// Produce a signed checkpoint over the current audit (head, len) — the artifact
    /// to anchor off-box (e.g. Sigstore Rekor). Signed with the audit-attestation
    /// key and reconstructible (no timestamp), so a later
    /// [`verify_audit_chain_extends`](Self::verify_audit_chain_extends) can re-derive
    /// the signed bytes. Returns a JSON envelope
    /// `{audit_head, audit_log_len, signature_b64, public_key_b64}`.
    pub fn checkpoint(&self) -> Result<String, CageError> {
        let head = self.audit_head.clone();
        let len = self.audit_log.len() as u64;
        let sig = self.attestation_key.sign(&checkpoint_message(&head, len));
        let mut envelope = serde_json::Map::new();
        envelope.insert("audit_head".to_string(), serde_json::Value::String(head));
        envelope.insert(
            "audit_log_len".to_string(),
            serde_json::Value::Number(len.into()),
        );
        envelope.insert(
            "signature_b64".to_string(),
            serde_json::Value::String(BASE64_STD.encode(sig.to_bytes())),
        );
        envelope.insert(
            "public_key_b64".to_string(),
            serde_json::Value::String(
                BASE64_STD.encode(self.attestation_key.verifying_key().as_bytes()),
            ),
        );
        serde_json::to_string(&serde_json::Value::Object(envelope))
            .map_err(|e| CageError::Serialize(e.to_string()))
    }

    /// Verify the in-memory chain **extends** an externally-held signed checkpoint:
    /// the checkpoint signature verifies under this vault's audit key, the chain is
    /// internally consistent, it is at least as long as the anchored length, and the
    /// entry at the anchored position carries the anchored head. A truncation below
    /// the anchored length — or any rewrite of the anchored prefix — fails closed.
    /// This is the tamper-evidence `verify_audit_chain` cannot give alone: the root
    /// of trust is the off-box anchor, not the public genesis constant.
    pub fn verify_audit_chain_extends(
        &self,
        anchored_head: &str,
        anchored_len: u64,
        signature_b64: &str,
    ) -> bool {
        // 1. The checkpoint must be one this vault actually signed.
        let sig_bytes = match BASE64_STD
            .decode(signature_b64)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
        {
            Some(b) => b,
            None => return false,
        };
        let signature = Signature::from_bytes(&sig_bytes);
        if self
            .attestation_key
            .verifying_key()
            .verify(&checkpoint_message(anchored_head, anchored_len), &signature)
            .is_err()
        {
            return false;
        }
        // 2. The current chain must be internally consistent.
        if !self.verify_audit_chain() {
            return false;
        }
        // 3. At least as long as the anchor, with the anchored head at its position —
        //    so neither a truncation below it nor a rewrite of the prefix passes.
        let len = self.audit_log.len() as u64;
        if len < anchored_len {
            return false;
        }
        if anchored_len == 0 {
            anchored_head == "0".repeat(64).as_str()
        } else {
            self.audit_log[(anchored_len - 1) as usize].hash == anchored_head
        }
    }

    /// Decrypt the named secret into a zeroizing buffer. Used by the PyO3 `invoke`
    /// path, which decrypts under its lock, releases the lock, then performs the
    /// network round-trip with the GIL released so concurrent invocations overlap.
    /// The plaintext stays inside the returned `Zeroizing<Vec<u8>>` (Rust-owned).
    pub fn decrypt_secret(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, CageError> {
        self.decrypt_to_zeroizing(name)
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    fn encrypt_and_store(&mut self, name: String, plaintext: &[u8]) -> Result<(), CageError> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher =
            ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(self.enc_key.as_slice()));
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| CageError::Crypto(format!("encrypt: {e}")))?;

        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce);

        if let Some((mut old_nonce, mut old_ct)) = self.store.insert(name, (nonce_arr, ciphertext))
        {
            // Re-storing under an existing name (key rotation / repeated env load)
            // drops the previous ciphertext+nonce — zero it, mirroring delete_secret,
            // so a superseded secret's ciphertext does not linger in freed memory.
            old_nonce.zeroize();
            old_ct.zeroize();
        }
        Ok(())
    }

    fn decrypt_to_zeroizing(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, CageError> {
        let (nonce_arr, ciphertext) = self
            .store
            .get(name)
            .ok_or_else(|| CageError::NotFound(name.to_string()))?;

        let nonce = Nonce::from_slice(nonce_arr);
        let key = chacha20poly1305::Key::from_slice(self.enc_key.as_slice());
        let cipher = ChaCha20Poly1305::new(key);

        let plaintext_bytes = cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(|e| CageError::Crypto(format!("decrypt/auth: {e}")))?;

        Ok(Zeroizing::new(plaintext_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append_n(v: &mut Vault, n: u64) {
        for i in 0..n {
            v.append_audit(
                "e".into(),
                "ev".into(),
                format!("{{\"i\":{i}}}"),
                "t".into(),
            )
            .unwrap();
        }
    }

    /// Parse a checkpoint envelope into (head, len, sig_b64).
    fn read_checkpoint(v: &Vault) -> (String, u64, String) {
        let cp: serde_json::Value = serde_json::from_str(&v.checkpoint().unwrap()).unwrap();
        (
            cp["audit_head"].as_str().unwrap().to_string(),
            cp["audit_log_len"].as_u64().unwrap(),
            cp["signature_b64"].as_str().unwrap().to_string(),
        )
    }

    #[test]
    fn seq_is_monotonic_and_chain_self_verifies() {
        let mut v = Vault::new();
        append_n(&mut v, 5);
        assert!(v.verify_audit_chain());
        let seqs: Vec<u64> = v.audit_log_snapshot().iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn chain_extends_a_genuine_checkpoint() {
        let mut v = Vault::new();
        append_n(&mut v, 4);
        let (head, len, sig) = read_checkpoint(&v);
        assert_eq!(len, 4);
        append_n(&mut v, 3); // grow past the anchor
        assert!(v.verify_audit_chain_extends(&head, len, &sig));
    }

    #[test]
    fn truncation_is_detected_against_the_anchor() {
        let mut v = Vault::new();
        append_n(&mut v, 5);
        let (head, len, sig) = read_checkpoint(&v);

        // A host adversary truncates the log and resets the head CONSISTENTLY — the
        // in-memory chain still self-verifies (they recomputed), but it no longer
        // extends the off-box anchor.
        v.audit_log.truncate(2);
        v.audit_head = v.audit_log.last().unwrap().hash.clone();
        assert!(
            v.verify_audit_chain(),
            "a consistent truncation self-verifies"
        );
        assert!(
            !v.verify_audit_chain_extends(&head, len, &sig),
            "but it no longer extends the anchored checkpoint"
        );
    }

    #[test]
    fn prefix_rewrite_is_detected_against_the_anchor() {
        let mut v = Vault::new();
        append_n(&mut v, 5);
        let (head, len, sig) = read_checkpoint(&v);

        // Rewrite a past entry and re-stitch every hash forward (a fully consistent
        // forge). verify_audit_chain passes, but the anchored head no longer sits at
        // its position.
        v.audit_log[1].data = serde_json::json!({"i": "FORGED"});
        let mut prev = "0".repeat(64);
        for (i, e) in v.audit_log.iter_mut().enumerate() {
            e.seq = i as u64;
            e.prev_hash = prev.clone();
            e.hash = compute_entry_hash(
                &prev,
                i as u64,
                &e.entity_id,
                &e.event,
                &e.data,
                &e.timestamp,
            );
            prev = e.hash.clone();
        }
        v.audit_head = prev;
        assert!(v.verify_audit_chain(), "the forge is internally consistent");
        assert!(
            !v.verify_audit_chain_extends(&head, len, &sig),
            "but the anchored head no longer matches at its position"
        );
    }

    #[test]
    fn forged_checkpoint_signature_is_rejected() {
        let v = Vault::new();
        // A checkpoint not signed by this vault's audit key never verifies.
        assert!(!v.verify_audit_chain_extends(&"0".repeat(64), 0, &BASE64_STD.encode([0u8; 64])));
    }

    #[test]
    fn genesis_checkpoint_extends_an_empty_chain() {
        let v = Vault::new();
        let (head, len, sig) = read_checkpoint(&v);
        assert_eq!(len, 0);
        assert!(v.verify_audit_chain_extends(&head, len, &sig));
    }

    #[test]
    fn sign_hmac_matches_rfc4231_test_case_1() {
        // RFC 4231 section 4.2, test case 1, through the vault path: store, decrypt,
        // HMAC. `hmac_sha256_matches_rfc4231` covers the HMAC core itself.
        let mut v = Vault::new();
        v.store_secret("k".into(), "\u{0b}".repeat(20)).unwrap();
        assert_eq!(
            v.sign_hmac("k", b"Hi There").unwrap(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn sha256_padding_matches_sha2_for_every_length_up_to_three_blocks() {
        let data: Vec<u8> = (0..=255u8).collect();
        for len in 0..=3 * SHA256_BLOCK + 1 {
            let mut state = SHA256_IV;
            sha256_finish(&mut state, &data[..len], len);
            let mut digest = [0u8; 32];
            sha256_digest_into(&state, &mut digest);
            assert_eq!(digest[..], Sha256::digest(&data[..len])[..], "length {len}");
        }
    }

    #[test]
    fn hmac_sha256_matches_rfc4231() {
        // RFC 4231 section 4, test cases 1 to 4, 6 and 7 (case 5 truncates the output).
        let long_key = vec![0xaa; 131];
        let cases: [(&[u8], &[u8], &str); 6] = [
            (&[0x0b; 20], b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            (b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            (&[0xaa; 20], &[0xdd; 50], "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
            (&(1..=25).collect::<Vec<u8>>(), &[0xcd; 50], "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
            (&long_key, b"Test Using Larger Than Block-Size Key - Hash Key First", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
            (&long_key, b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
        ];
        for (i, (key, msg, expected)) in cases.iter().enumerate() {
            assert_eq!(
                hex::encode(hmac_sha256(key, msg)),
                *expected,
                "case index {i}"
            );
        }
    }

    #[test]
    fn hmac_sha256_matches_the_hmac_crate_around_block_boundaries() {
        use hmac::{Hmac, Mac};
        let lengths = [
            0, 1, 31, 32, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 200, 1000,
        ];
        let bytes: Vec<u8> = (0..1200u32).map(|i| (i * 7 + 3) as u8).collect();
        for &k in &lengths {
            for &m in &lengths {
                let (key, msg) = (&bytes[..k], &bytes[100..100 + m]);
                let mut oracle =
                    <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key).unwrap();
                oracle.update(msg);
                assert_eq!(
                    hmac_sha256(key, msg)[..],
                    oracle.finalize().into_bytes()[..],
                    "key {k} bytes, message {m} bytes"
                );
            }
        }
    }
}
