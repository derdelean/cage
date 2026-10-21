/*!
CAGE — PyO3 binding layer (`cage._cage_native`).

This is a thin shell: every method delegates to the audited `cage_core::Gate`
and maps `CageError` to a Python exception. All crypto, capability, audit, and
transport logic lives in the `cage-core` crate, so the identical core also runs
in the standalone `cage-broker` binary with no PyO3 present.

# The authority lives in Rust (no token-less bypass)

The Python-visible object is the **`Gate`**, not the bare vault: the credential
store and the capability authority are the *same* Rust object, so the token check
and the secret use are one atomic operation that no in-process Python code can
step around. There is deliberately **no** un-gated `retrieve_secret` / raw
`invoke` on this surface — the only paths to a secret value are the token-gated
`invoke` (zero-plaintext, key never crosses PyO3) and the deprecated, still
token-gated `consume`.

The `Gate` is held behind a `Mutex` so every method borrows the pyclass as
`&self` (shared). `invoke` reserves a use + decrypts under the lock, **releases
the lock**, performs the TLS round-trip with the GIL released (`py.detach`), then
re-acquires the lock only to settle the reservation — so concurrent `invoke_llm`
calls overlap while authorize+charge stays atomic and a `max_uses=1` token can
never be double-spent.

Apache 2.0 with a defensive-only patent pledge (see PATENT_PLEDGE.md).
*/

// pyo3's #[pymethods] macro can emit `PyErr -> PyErr` `.into()` conversions that
// clippy flags as `useless_conversion`; the lint is a macro artifact.
#![allow(clippy::useless_conversion)]

use std::sync::{Mutex, MutexGuard};

use cage_core::{post_messages, CageError, CapabilityToken, ControlAuth, Gate};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::wrap_pyfunction;

/// Map the core error type to a Python exception. Refusals carry the stable
/// "CAGE refused:" prefix so the Python facade can re-map them to `CageViolation`
/// while leaving transport / value errors as `ValueError`. (The orphan rule
/// prevents a `From<CageError> for PyErr` impl here — both types are foreign.)
fn to_py(e: CageError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Build a Python dict mirroring a `CapabilityToken`. The Python facade
/// reconstructs a `cage.token.CapabilityToken` from this — the canonical live
/// state (use_count, revoked) always comes from the Rust gate, never a caller
/// handle.
fn token_to_dict<'py>(py: Python<'py>, t: &CapabilityToken) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("token_id", &t.token_id)?;
    d.set_item("scope", &t.scope)?;
    d.set_item("context", &t.context)?;
    d.set_item("issued_at_unix", t.issued_at_unix)?;
    d.set_item("ttl_seconds", t.ttl_seconds)?;
    d.set_item("max_uses", t.max_uses)?;
    d.set_item("use_count", t.use_count)?;
    d.set_item("revoked", t.revoked)?;
    Ok(d)
}

/// Opaque Python-visible capability authority. Wraps `cage_core::Gate` behind a
/// `Mutex`; the encryption key, bootstrap token, capability records, and audit
/// chain live entirely inside the Rust core and are never reachable as Python
/// objects.
#[pyclass]
pub struct RustGate(Mutex<Gate>);

impl RustGate {
    fn lock(&self) -> MutexGuard<'_, Gate> {
        self.0.lock().expect("cage: gate mutex poisoned")
    }
}

#[pymethods]
impl RustGate {
    /// Construct a gate. `insecure_dev_mode` waives the bootstrap requirement on
    /// issuance/revocation; `allow_plaintext_consume` re-enables the deprecated
    /// `consume()` leak. Both are development/tests ONLY, and both are constructor
    /// arguments with no setter, so neither can be flipped from Python once the gate exists.
    /// They are separate switches on purpose — see `Gate::set_allow_plaintext_consume`.
    #[new]
    pub fn new(insecure_dev_mode: bool, allow_plaintext_consume: bool) -> Self {
        let mut gate = Gate::new();
        gate.set_insecure_dev_mode(insecure_dev_mode);
        gate.set_allow_plaintext_consume(allow_plaintext_consume);
        RustGate(Mutex::new(gate))
    }

    // -- secret storage --------------------------------------------------

    pub fn store_secret(&self, name: &str, value: &str) -> PyResult<()> {
        self.lock().store_secret(name, value).map_err(to_py)
    }

    pub fn load_from_env_file(&self, path: &str, secret_names: Vec<String>) -> PyResult<usize> {
        self.lock()
            .load_credentials_from_env(path, &secret_names)
            .map_err(to_py)
    }

    pub fn has_secret(&self, name: &str) -> bool {
        self.lock().has_secret(name)
    }

    pub fn delete_secret(&self, name: &str) -> bool {
        self.lock().delete_secret(name)
    }

    // -- scope registry --------------------------------------------------

    pub fn register_scope_secret(&self, scope_prefix: &str, secret_name: &str) {
        self.lock().register_scope_secret(scope_prefix, secret_name)
    }

    pub fn pin_secret_provider(&self, secret_name: &str, provider: &str) -> PyResult<()> {
        self.lock()
            .pin_secret_provider(secret_name, provider)
            .map_err(to_py)
    }

    pub fn scope_to_secret(&self, scope: &str) -> PyResult<String> {
        self.lock().scope_to_secret(scope).map_err(to_py)
    }

    // -- bootstrap / seal ------------------------------------------------

    pub fn unseal(&self) -> PyResult<Bootstrap> {
        // The bootstrap (the in-process authority root) stays inside Rust: it is
        // returned wrapped in the opaque `Bootstrap` handle (zero-on-drop), NOT as a
        // Python `str`, so it never lands in CPython's interned-string heap. Pass the
        // handle back to issue_token / revoke. (Production issues via the broker,
        // where the bootstrap never enters this process at all.)
        Ok(Bootstrap(self.lock().unseal().map_err(to_py)?))
    }

    pub fn is_unsealed(&self) -> bool {
        self.lock().is_unsealed()
    }

    pub fn verify_bootstrap(&self, token: &str) -> bool {
        self.lock().verify_bootstrap(token)
    }

    #[getter]
    pub fn mlock_succeeded(&self) -> bool {
        self.lock().mlock_succeeded()
    }

    // -- token lifecycle (delegated authority surface) -------------------

    #[pyo3(signature = (scope, context, ttl_seconds=None, max_uses=None, bootstrap_token=None))]
    pub fn issue_token<'py>(
        &self,
        py: Python<'py>,
        scope: &str,
        context: &str,
        ttl_seconds: Option<u64>,
        max_uses: Option<u32>,
        bootstrap_token: Option<PyRef<'_, Bootstrap>>,
    ) -> PyResult<Bound<'py, PyDict>> {
        // The secret is read straight out of the handle's Rust-owned buffer; it is
        // never materialized as a Python value on this path.
        let token = self
            .lock()
            .issue_token(
                scope,
                context,
                ttl_seconds,
                max_uses,
                bootstrap_token
                    .as_ref()
                    .map(|b| ControlAuth::Bootstrap(b.0.as_str())),
            )
            .map_err(to_py)?;
        token_to_dict(py, &token)
    }

    #[pyo3(signature = (token_id, scope=None, context=None))]
    pub fn authorize<'py>(
        &self,
        py: Python<'py>,
        token_id: &str,
        scope: Option<&str>,
        context: Option<&str>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let token = self
            .lock()
            .authorize(token_id, scope, context)
            .map_err(to_py)?;
        token_to_dict(py, &token)
    }

    pub fn record_use<'py>(&self, py: Python<'py>, token_id: &str) -> PyResult<Bound<'py, PyDict>> {
        let token = self.lock().record_use_token(token_id).map_err(to_py)?;
        token_to_dict(py, &token)
    }

    #[pyo3(signature = (token_id, bootstrap_token=None))]
    pub fn revoke(
        &self,
        token_id: &str,
        bootstrap_token: Option<PyRef<'_, Bootstrap>>,
    ) -> PyResult<bool> {
        self.lock()
            .revoke(
                token_id,
                bootstrap_token
                    .as_ref()
                    .map(|b| ControlAuth::Bootstrap(b.0.as_str())),
            )
            .map_err(to_py)
    }

    // -- token-gated secret operations -----------------------------------

    /// Token-gated LLM invocation. Reserves a use + decrypts the key under the
    /// lock, releases the lock, performs the TLS round-trip with the GIL released,
    /// then settles (success records; a pre-send failure refunds the use; a
    /// post-send failure keeps it charged). The decrypted key stays in Rust-owned
    /// memory (the reservation, then the transport, which zeroes it once the request
    /// is assembled) and never becomes a Python object.
    pub fn invoke(
        &self,
        py: Python<'_>,
        token_id: &str,
        provider: &str,
        request_body_json: &str,
    ) -> PyResult<String> {
        let mut reservation = {
            let mut gate = self.lock();
            gate.reserve_invoke(token_id, provider).map_err(to_py)?
        };
        let key = reservation.take_key();
        let result =
            py.detach(|| post_messages(reservation.provider(), key, request_body_json.as_bytes()));
        let mut gate = self.lock();
        match result {
            Ok(response) => {
                gate.finalize_invoke(&reservation).map_err(to_py)?;
                Ok(response)
            }
            Err(e) => {
                let msg = e.to_string();
                if e.is_pre_send() {
                    gate.refund_invoke(&reservation, &msg);
                } else {
                    gate.fail_invoke(&reservation, &msg);
                }
                Err(to_py(CageError::from(e)))
            }
        }
    }

    /// Deprecated token-gated plaintext retrieval. Token-gated (authorize + charge
    /// + audit), but returns the secret as a Python `str` — the bytes cross PyO3 and
    /// persist in CPython's interned-string heap. Removed before 1.0.
    pub fn consume(&self, token_id: &str, scope: &str) -> PyResult<String> {
        self.lock().consume(token_id, scope).map_err(to_py)
    }

    /// HMAC-SHA256 sign with the vault-held key for the token's scope. The key
    /// never leaves the gate.
    pub fn sign(&self, token_id: &str, payload: &[u8]) -> PyResult<String> {
        self.lock().sign(token_id, payload).map_err(to_py)
    }

    // -- audit chain + attestation ---------------------------------------

    pub fn append_audit(
        &self,
        entity_id: String,
        event: String,
        data_json: String,
        timestamp: String,
    ) -> PyResult<String> {
        self.lock()
            .append_audit(entity_id, event, data_json, timestamp)
            .map_err(to_py)
    }

    pub fn verify_audit_chain(&self) -> bool {
        self.lock().verify_audit_chain()
    }

    pub fn checkpoint(&self) -> PyResult<String> {
        self.lock().checkpoint().map_err(to_py)
    }

    pub fn verify_audit_chain_extends(
        &self,
        anchored_head: &str,
        anchored_len: u64,
        signature_b64: &str,
    ) -> bool {
        self.lock()
            .verify_audit_chain_extends(anchored_head, anchored_len, signature_b64)
    }

    pub fn audit_log_len(&self) -> usize {
        self.lock().audit_log_len()
    }

    pub fn audit_head(&self) -> String {
        self.lock().audit_head()
    }

    pub fn audit_log_entries<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        // Snapshot under the lock, then build the Python dicts after releasing it.
        let snapshots = self.lock().audit_log_snapshot();
        let mut out = Vec::with_capacity(snapshots.len());
        for e in snapshots {
            let d = PyDict::new(py);
            d.set_item("seq", e.seq)?;
            d.set_item("entity_id", &e.entity_id)?;
            d.set_item("event", &e.event)?;
            d.set_item("data_json", &e.data_json)?;
            d.set_item("timestamp", &e.timestamp)?;
            d.set_item("prev_hash", &e.prev_hash)?;
            d.set_item("hash", &e.hash)?;
            out.push(d);
        }
        Ok(out)
    }

    pub fn attestation_payload(&self) -> PyResult<String> {
        // The timestamp is generated server-side inside the gate — never
        // caller-supplied — so it cannot be backdated/forward-dated.
        self.lock().attestation_payload().map_err(to_py)
    }

    #[getter]
    pub fn attestation_public_key(&self) -> String {
        self.lock().attestation_public_key()
    }

    /// Base64 ed25519 public key that verifies release signatures (distinct from
    /// the audit-attestation key).
    #[getter]
    pub fn release_public_key(&self) -> String {
        self.lock().release_public_key()
    }
}

/// Opaque, single-use handle to the in-process bootstrap secret (the authority
/// root), returned by [`RustGate::unseal`]. The secret lives only inside Rust
/// `Zeroizing` memory and is wiped on drop; it is deliberately **never** exposed as
/// a Python `str`, so it cannot persist in CPython's interned-string heap. Hold it
/// and pass it back to `issue_token` / `revoke`; there is no accessor for the bytes.
#[pyclass]
pub struct Bootstrap(zeroize::Zeroizing<String>);

#[pymethods]
impl Bootstrap {
    /// Redacted repr — never prints the secret.
    fn __repr__(&self) -> &'static str {
        "<cage.Bootstrap: sealed authority handle (secret hidden)>"
    }
}

/// An operator signing key (ed25519) for control-plane proof-of-possession. The
/// operator process holds this; the broker is provisioned only with the matching
/// public key. Wraps `cage_core::OperatorKey` — the default custody backend; an
/// HSM / OS-keystore signer can replace it behind the same `key_id` + `sign` shape
/// without touching the wire format.
#[pyclass]
pub struct OperatorKey(cage_core::OperatorKey);

#[allow(clippy::new_without_default)] // PyO3 #[new] is the Python constructor.
#[pymethods]
impl OperatorKey {
    /// Generate a fresh operator key from the OS CSPRNG.
    #[new]
    pub fn new() -> Self {
        OperatorKey(cage_core::OperatorKey::generate())
    }

    /// Hex of the raw 32-byte ed25519 public key — the operator's `key_id`, handed
    /// to the broker at startup (public; safe to log / pass via env).
    #[getter]
    pub fn public_key_hex(&self) -> String {
        self.0.public_key_hex()
    }

    /// Sign a canonical control message (built by `control_message`). Returns the
    /// raw 64-byte ed25519 signature.
    pub fn sign<'py>(&self, py: Python<'py>, message: &[u8]) -> Bound<'py, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, &self.0.sign(message))
    }
}

/// Build the canonical control-plane message the operator signs and the gate
/// verifies. `broker_id` is the target broker's raw 32-byte attestation key;
/// `nonce` is 16 bytes. Single source of truth shared with the verifier — there is
/// no second (drift-prone) implementation.
#[pyfunction]
fn control_message<'py>(
    py: Python<'py>,
    broker_id: &[u8],
    op: &str,
    args: &[u8],
    nonce: &[u8],
    ts: u64,
) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
    let bid: [u8; 32] = broker_id
        .try_into()
        .map_err(|_| PyValueError::new_err("broker_id must be 32 bytes"))?;
    let n: [u8; 16] = nonce
        .try_into()
        .map_err(|_| PyValueError::new_err("nonce must be 16 bytes"))?;
    Ok(pyo3::types::PyBytes::new(
        py,
        &cage_core::control_message(&bid, op, args, &n, ts),
    ))
}

/// Canonical per-op argument binding for an `issue` request (pre-clamp ttl/max_uses).
#[pyfunction]
#[pyo3(signature = (scope, context, ttl_seconds=None, max_uses=None))]
fn control_args_issue<'py>(
    py: Python<'py>,
    scope: &str,
    context: &str,
    ttl_seconds: Option<u64>,
    max_uses: Option<u32>,
) -> Bound<'py, pyo3::types::PyBytes> {
    pyo3::types::PyBytes::new(
        py,
        &cage_core::control_args_issue(scope, context, ttl_seconds, max_uses),
    )
}

/// Canonical per-op argument binding for a `revoke` request.
#[pyfunction]
fn control_args_revoke<'py>(py: Python<'py>, token_id: &str) -> Bound<'py, pyo3::types::PyBytes> {
    pyo3::types::PyBytes::new(py, &cage_core::control_args_revoke(token_id))
}

#[pymodule]
fn _cage_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RustGate>()?;
    m.add_class::<Bootstrap>()?;
    m.add_class::<OperatorKey>()?;
    m.add_function(wrap_pyfunction!(control_message, m)?)?;
    m.add_function(wrap_pyfunction!(control_args_issue, m)?)?;
    m.add_function(wrap_pyfunction!(control_args_revoke, m)?)?;
    Ok(())
}
