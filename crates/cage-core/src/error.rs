//! `CageError` — the core error type, independent of any binding layer.
//!
//! The PyO3 shell maps this to `ValueError`; the broker maps it to an RPC error
//! object. The core itself never depends on either.

use crate::transport::TransportError;

#[derive(Debug)]
pub enum CageError {
    /// No secret stored under the given name.
    NotFound(String),
    /// Encrypt / decrypt / authentication failure (AEAD tag mismatch, bad UTF-8).
    Crypto(String),
    /// `unseal()` called more than once in a vault lifetime.
    AlreadyUnsealed,
    /// `append_audit` received `data_json` that is not valid JSON.
    BadAuditData(String),
    /// A whitelisted key appeared more than once in a `.env` file.
    DuplicateEnvKey { key: String, path: String },
    /// A line of a `.env` file is not valid UTF-8. Carries the line number,
    /// never the line.
    EnvNotUtf8 { path: String, line: usize },
    /// A line of a `.env` file was refused: `carriage_return` (a carriage
    /// return inside the line) or `empty_value` (a whitelisted name with no
    /// value). Carries the line number, never the line.
    EnvLineRefused {
        path: String,
        line: usize,
        kind: &'static str,
    },
    /// Filesystem error reading an env file (the path is not itself secret).
    Io(String),
    /// Canonical-JSON serialization failure (attestation / audit).
    Serialize(String),
    /// Structural refusal — a capability check failed (unknown / expired /
    /// revoked / over-used token, scope mismatch, or missing bootstrap).
    Refused(String),
    /// Provider transport error (TLS, HTTP status, unknown provider, timeout).
    Transport(TransportError),
}

impl std::fmt::Display for CageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(name) => write!(f, "CAGE: no secret {name:?}"),
            Self::Crypto(msg) => write!(f, "CAGE crypto error: {msg}"),
            Self::AlreadyUnsealed => write!(
                f,
                "CAGE: vault already unsealed — the bootstrap token can be \
                 revealed exactly once per vault lifetime"
            ),
            Self::BadAuditData(msg) => write!(f, "CAGE audit: bad data_json: {msg}"),
            Self::DuplicateEnvKey { key, path } => {
                write!(f, "CAGE: duplicate key {key:?} in env file {path:?}")
            }
            Self::EnvNotUtf8 { path, line } => {
                write!(f, "CAGE: env file {path:?} line {line} is not valid UTF-8")
            }
            Self::EnvLineRefused { path, line, kind } => {
                write!(f, "CAGE: env file {path:?} line {line} refused: {kind}")
            }
            Self::Io(msg) => write!(f, "CAGE io: {msg}"),
            Self::Serialize(msg) => write!(f, "CAGE serialize: {msg}"),
            Self::Refused(msg) => write!(f, "CAGE refused: {msg}"),
            Self::Transport(e) => write!(f, "CAGE transport: {e}"),
        }
    }
}

impl std::error::Error for CageError {}

impl From<TransportError> for CageError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}
