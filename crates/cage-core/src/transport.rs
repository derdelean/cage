/*!
Provider HTTPS transport (Anthropic + OpenAI wired) — rustls-direct, no reqwest/hyper.

Why hand-rolled HTTP/1.1 over rustls:
  • reqwest stores header values in an Arc<Bytes> for the lifetime of the
    request future (hundreds of ms). That buffer is not zeroized.
  • hyper's HTTP encoder copies headers into intermediate Vec<u8> buffers
    that we cannot control.
  • The design goal is zero plaintext bytes in RAM at any point in time.
    On this path the decrypted key lives only in cage's own `Zeroizing<Vec<u8>>`
    buffers: the key buffer the caller moves in, zeroed once the request buffer
    holds the key, then the request buffer, zeroed right after the write and
    before the response is read. See `post_messages` for how long that takes.

Residual leak (acknowledged, follow-up — Issue #1):
  rustls' internal write buffer holds plaintext between `writer().write()`
  and the actual TLS encrypt call. That buffer is reused (not zeroized).
  Closing this requires a fork of rustls with `Zeroizing<Vec<u8>>` as the
  plaintext write buffer — tracked separately.
*/

use std::io;
use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::Lazy;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Bound the request write/flush too — a peer holding the receive window at zero
/// would otherwise keep the decrypted key resident and tie up the thread.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Hard cap on a response body (and on any single chunk): bounds memory and stops
/// a malicious provider from forcing an unbounded allocation.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// A provider's HTTPS endpoint plus how its credential and fixed headers are
/// presented. Adding a provider is a localized change — a new `Provider`
/// descriptor and a `provider_by_name` arm (plus, for SigV4 providers like
/// Bedrock, a signing step). The TLS machinery, HTTP/1.1 framing, and
/// zero-plaintext key handling in `post_inner` are provider-independent: the
/// decrypted key is written only into the `Zeroizing` request buffer.
struct Provider {
    host: &'static str,
    port: u16,
    path: &'static str,
    /// Header carrying the credential, e.g. "x-api-key" or "authorization".
    auth_header_name: &'static str,
    /// Literal prefix before the key in the auth value: "" for Anthropic's
    /// x-api-key, "Bearer " for OpenAI-style Authorization.
    auth_value_prefix: &'static str,
    /// Fixed extra headers (e.g. Anthropic's required version header).
    extra_headers: &'static [(&'static str, &'static str)],
    /// Organizations of the root CAs trusted for this host: those of the CAs its
    /// DNS CAA records authorize. A certificate chaining to any other root is
    /// refused, so a CA outside these hierarchies cannot mis-issue one that passes.
    /// Subordinate CAs that other organizations run under an admitted root pass too.
    /// Matched against the root's subject. Update it when the provider changes its
    /// CAA records.
    trusted_root_orgs: &'static [&'static str],
}

/// Root-CA organizations per CA named in a CAA record.
const PKI_GOOG: &str = "Google Trust Services LLC";
const LETSENCRYPT: &str = "Internet Security Research Group";
const DIGICERT: &str = "DigiCert";
const SECTIGO: [&str; 3] = [
    "Sectigo Limited",
    "COMODO CA Limited",
    "The USERTRUST Network",
];

static ANTHROPIC: Provider = Provider {
    host: "api.anthropic.com",
    port: 443,
    path: "/v1/messages",
    auth_header_name: "x-api-key",
    auth_value_prefix: "",
    extra_headers: &[("anthropic-version", "2023-06-01")],
    // CAA of api.anthropic.com (2026-10-14): pki.goog, letsencrypt.org, digicert.com,
    // ssl.com, comodoca.com.
    trusted_root_orgs: &[
        PKI_GOOG,
        LETSENCRYPT,
        DIGICERT,
        "SSL Corporation",
        SECTIGO[0],
        SECTIGO[1],
        SECTIGO[2],
    ],
};

static OPENAI: Provider = Provider {
    host: "api.openai.com",
    port: 443,
    path: "/v1/chat/completions",
    // Bearer auth: "Authorization: Bearer <key>". The key still lives only in the
    // Zeroizing request buffer — the prefix changes, the key handling does not.
    auth_header_name: "authorization",
    auth_value_prefix: "Bearer ",
    // No fixed extra headers; org/project selection is a per-request body concern.
    extra_headers: &[],
    // CAA of openai.com, inherited by api.openai.com (2026-10-14): amazon.com,
    // digicert.com, godaddy.com, letsencrypt.org, pki.goog, sectigo.com.
    trusted_root_orgs: &[
        PKI_GOOG,
        LETSENCRYPT,
        DIGICERT,
        "Amazon",
        "GoDaddy.com",
        "Starfield Technologies",
        SECTIGO[0],
        SECTIGO[1],
        SECTIGO[2],
    ],
};

/// Resolve a provider name to its descriptor; None for unknown names.
/// New providers (Bedrock, Azure OpenAI, vLLM) are wired in here.
fn provider_by_name(name: &str) -> Option<&'static Provider> {
    match name {
        "anthropic" => Some(&ANTHROPIC),
        "openai" => Some(&OPENAI),
        _ => None,
    }
}

/// Shared tokio runtime — built lazily on first call.
/// Multi-thread so concurrent callers can each `block_on`.
static TOKIO: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .expect("cage: tokio runtime build")
});

/// The webpki-roots trust anchors whose subject names one of the provider's
/// trusted root organizations.
fn trusted_roots(provider: &Provider) -> RootCertStore {
    let names_org = |subject: &[u8], org: &str| {
        subject
            .windows(org.len())
            .any(|window| window == org.as_bytes())
    };
    let mut roots = RootCertStore::empty();
    roots.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .filter(|anchor| {
                provider
                    .trusted_root_orgs
                    .iter()
                    .any(|org| names_org(anchor.subject.as_ref(), org))
            })
            .cloned(),
    );
    roots
}

/// TLS client config for one provider — only that provider's trusted roots, TLS
/// 1.3 only (Invariant 3; 1.2 explicitly excluded), ALPN pinned to http/1.1 (we
/// don't speak HTTP/2 framing), no client auth, ring crypto provider explicitly
/// configured (no reliance on rustls global default).
fn tls_config(provider: &Provider) -> Arc<ClientConfig> {
    let crypto = rustls::crypto::ring::default_provider();
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(crypto))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("rustls: TLS 1.3 protocol version")
        .with_root_certificates(trusted_roots(provider))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
    Tls(rustls::Error),
    Timeout(&'static str),
    HttpStatus {
        status: u16,
        body: String,
    },
    BadResponse(String),
    UnknownProvider(String),
    /// Failure establishing the connection (TCP connect / TLS handshake) BEFORE
    /// the request was written — the provider saw nothing, so a reserved use is
    /// refundable (see [`TransportError::is_pre_send`]).
    Connect(String),
}

impl TransportError {
    /// True if the failure occurred BEFORE the request was written to the
    /// provider, so no provider-side effect happened and a reserved token use may
    /// be refunded. Everything from the request write onward — `Io` (write/read),
    /// `HttpStatus`, `BadResponse`, the response-read `Timeout` — is post-send: the
    /// provider received the key-bearing request (and may bill it), so the use
    /// must stay charged. `UnknownProvider` never touches the network at all.
    pub fn is_pre_send(&self) -> bool {
        matches!(
            self,
            Self::UnknownProvider(_)
                | Self::Connect(_)
                | Self::Timeout("tcp connect")
                | Self::Timeout("tls handshake")
        )
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Tls(e) => write!(f, "tls: {e}"),
            Self::Timeout(stage) => write!(f, "timeout during {stage}"),
            Self::HttpStatus { status, body } => {
                write!(f, "provider returned {status}: {body}")
            }
            Self::BadResponse(s) => write!(f, "bad response: {s}"),
            Self::UnknownProvider(p) => write!(f, "unknown provider: {p:?}"),
            Self::Connect(s) => write!(f, "connect: {s}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// True if `name` resolves to a wired provider. Performs no network I/O — lets the
/// authority reject an unknown provider before charging a use or decrypting a key.
pub fn provider_exists(name: &str) -> bool {
    provider_by_name(name).is_some()
}

impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rustls::Error> for TransportError {
    fn from(e: rustls::Error) -> Self {
        Self::Tls(e)
    }
}

/// POST `body` to `provider_name`'s messages endpoint, authenticated with
/// `api_key`. Returns the response body as a String (the response is not
/// secret — only the request-side credential is).
///
/// `api_key` is moved in and zeroed as soon as the request buffer holds it. From
/// then on cage keeps the key only in that buffer, which is zeroed right after the
/// write, so cage holds no copy while the response is read. The buffer is built
/// before connecting, so the key stays resident through TCP connect, the TLS
/// handshake and the write: up to `2 * CONNECT_TIMEOUT + WRITE_TIMEOUT` (about 50 s)
/// on a network that stalls. Before this call the key already sits in the caller's
/// buffer, from the decrypt in `Gate::reserve_invoke` on. The bound is network time
/// on a monotonic clock. A process that is stopped or paused in that window (SIGSTOP,
/// a VM pause) keeps the key resident for as long as it is stopped, and a VM
/// snapshot taken then writes it to disk. rustls' own buffers are the residual
/// described in the module doc.
pub fn post_messages(
    provider_name: &str,
    api_key: Zeroizing<Vec<u8>>,
    body: &[u8],
) -> Result<String, TransportError> {
    let provider = provider_by_name(provider_name)
        .ok_or_else(|| TransportError::UnknownProvider(provider_name.to_string()))?;
    TOKIO.block_on(post_inner(provider, api_key, body))
}

async fn post_inner(
    provider: &Provider,
    api_key: Zeroizing<Vec<u8>>,
    body: &[u8],
) -> Result<String, TransportError> {
    // Phase 1 — assemble the HTTP/1.1 request into a Zeroizing buffer.
    // Together with the moved-in `api_key`, which is dropped once its bytes are
    // copied in, this is the only place outside the vault where the decrypted key
    // exists. Drop zeroes the entire buffer (request line + headers + key + body)
    // on scope exit. A release-build panic aborts instead (`panic = "abort"`), so
    // it skips the zeroing.
    let content_length = body.len().to_string();
    // Pre-size for the ENTIRE request (static headers ≤512 B + key + body) so the
    // buffer cannot reallocate after the key is written: a realloc frees the old
    // allocation — with the key in it — WITHOUT zeroizing, since `Zeroizing` only
    // wipes its final buffer. Budgeting `api_key.len()` keeps the zero-plaintext
    // guarantee robust regardless of credential length or future provider headers.
    let mut request: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(512 + api_key.len() + body.len()));

    request.extend_from_slice(b"POST ");
    request.extend_from_slice(provider.path.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\n");
    request.extend_from_slice(b"Host: ");
    request.extend_from_slice(provider.host.as_bytes());
    request.extend_from_slice(b"\r\n");
    // Auth header: the key bytes go into this Zeroizing buffer, zeroed on scope
    // exit (not on a release-build panic, which aborts).
    request.extend_from_slice(provider.auth_header_name.as_bytes());
    request.extend_from_slice(b": ");
    request.extend_from_slice(provider.auth_value_prefix.as_bytes());
    request.extend_from_slice(&api_key); // ← key bytes
    request.extend_from_slice(b"\r\n");
    // Provider-specific fixed headers (e.g. anthropic-version).
    for &(name, value) in provider.extra_headers {
        request.extend_from_slice(name.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(value.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"Content-Type: application/json\r\n");
    request.extend_from_slice(b"Connection: close\r\n");
    request.extend_from_slice(b"User-Agent: cage/0.1\r\n");
    request.extend_from_slice(b"Content-Length: ");
    request.extend_from_slice(content_length.as_bytes());
    request.extend_from_slice(b"\r\n\r\n");
    request.extend_from_slice(body);
    // The request buffer holds the only copy the write needs. Zero the caller's.
    drop(api_key);

    // Phase 2 — TCP + TLS connect.
    let server_name = ServerName::try_from(provider.host)
        .map_err(|_| TransportError::BadResponse("invalid server name".into()))?
        .to_owned();
    let connector = TlsConnector::from(tls_config(provider));

    // Connect + handshake are PRE-SEND: a failure here means the request was never
    // written, so the caller may refund a reserved use. Tag them as `Connect`
    // (not the generic `Io`/`Tls`, which also cover the post-write phases).
    let tcp = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((provider.host, provider.port)),
    )
    .await
    .map_err(|_| TransportError::Timeout("tcp connect"))?
    .map_err(|e| TransportError::Connect(format!("tcp connect: {e}")))?;
    let mut tls = timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| TransportError::Timeout("tls handshake"))?
        .map_err(|e| TransportError::Connect(format!("tls handshake: {e}")))?;

    // Phase 3 — write the request, flush, drop the Zeroizing buffer ASAP. The
    // write/flush is bounded (POST-SEND on timeout: the provider may have received
    // part of the request, so the use stays charged): an on-path peer holding the
    // receive window at zero must not keep the decrypted key resident indefinitely.
    timeout(WRITE_TIMEOUT, async {
        tls.write_all(&request).await?;
        tls.flush().await
    })
    .await
    .map_err(|_| TransportError::Timeout("request write"))??;
    drop(request); // explicit Drop → Zeroizing zeroes the key

    // Phase 4 — read full response (Connection: close means read-to-end).
    // Cap at 4 MiB to bound memory; provider responses are typically <100 KiB.
    let mut response = Vec::with_capacity(8192);
    let read_result = timeout(READ_TIMEOUT, async {
        let mut buf = [0u8; 8192];
        loop {
            let n = tls.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buf[..n]);
            if response.len() > MAX_RESPONSE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response exceeds 4 MiB cap",
                ));
            }
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| TransportError::Timeout("response read"))?;
    read_result?;

    parse_http_response(&response)
}

/// Parse an HTTP/1.1 response into (status, body). Handles both
/// Content-Length and Transfer-Encoding: chunked.
fn parse_http_response(raw: &[u8]) -> Result<String, TransportError> {
    let header_end = find_subslice(raw, b"\r\n\r\n")
        .ok_or_else(|| TransportError::BadResponse("no header terminator".into()))?;

    let headers_blob = &raw[..header_end];
    let body_blob = &raw[header_end + 4..];

    // Parse status line (first line of headers blob).
    let status_line_end = find_subslice(headers_blob, b"\r\n").unwrap_or(headers_blob.len());
    let status_line = std::str::from_utf8(&headers_blob[..status_line_end])
        .map_err(|e| TransportError::BadResponse(format!("status utf8: {e}")))?;
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next();
    let status_str = parts
        .next()
        .ok_or_else(|| TransportError::BadResponse("missing status code".into()))?;
    let status: u16 = status_str
        .parse()
        .map_err(|_| TransportError::BadResponse(format!("bad status: {status_str}")))?;

    // Scan headers for Transfer-Encoding (case-insensitive). A header-less response
    // (status line then the blank line) leaves nothing after the status line — use
    // a checked slice so `status_line_end + 2` past the end yields empty, not a panic.
    let headers_rest = headers_blob
        .get(status_line_end.saturating_add(2)..)
        .unwrap_or(&[]);
    let chunked = headers_iter(headers_rest).any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked")
    });

    let body_bytes = if chunked {
        decode_chunked(body_blob)?
    } else {
        body_blob.to_vec()
    };

    let body_str = String::from_utf8(body_bytes)
        .map_err(|e| TransportError::BadResponse(format!("body utf8: {e}")))?;

    if (200..300).contains(&status) {
        Ok(body_str)
    } else {
        Err(TransportError::HttpStatus {
            status,
            body: body_str,
        })
    }
}

/// Iterate over `Name: value` lines until end of headers blob.
fn headers_iter(headers: &[u8]) -> impl Iterator<Item = (&str, &str)> {
    headers.split(|&b| b == b'\n').filter_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            return None;
        }
        let s = std::str::from_utf8(line).ok()?;
        let colon = s.find(':')?;
        Some((&s[..colon], s[colon + 1..].trim()))
    })
}

/// Decode HTTP/1.1 chunked transfer encoding.
fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, TransportError> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let size_end = find_subslice(&body[i..], b"\r\n")
            .ok_or_else(|| TransportError::BadResponse("chunk size line not terminated".into()))?;
        let size_line = std::str::from_utf8(&body[i..i + size_end])
            .map_err(|_| TransportError::BadResponse("chunk size not utf8".into()))?;
        // Chunk extensions (e.g. "1a;name=value") — strip after ';'.
        let size_str = size_line.split(';').next().unwrap_or(size_line).trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| TransportError::BadResponse(format!("bad chunk size: {size_str:?}")))?;
        // Cap the declared size to the response cap BEFORE any arithmetic. A size up
        // to usize::MAX would otherwise wrap `i + size` in the release profile,
        // bypass the bounds check, and panic on the slice — a single malicious
        // response aborting the whole process under panic=abort.
        if size > MAX_RESPONSE_BYTES {
            return Err(TransportError::BadResponse(
                "chunk exceeds response cap".into(),
            ));
        }
        i += size_end + 2; // past the size line; stays <= body.len()
        if size == 0 {
            break;
        }
        // Checked: i <= body.len() here, so `body.len() - i` cannot underflow and the
        // comparison cannot wrap (unlike the old `i + size > body.len()`).
        if size > body.len() - i {
            return Err(TransportError::BadResponse("truncated chunk body".into()));
        }
        out.extend_from_slice(&body[i..i + size]);
        i += size + 2; // skip chunk data + trailing CRLF
    }
    Ok(out)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The labels of the roots a provider trusts.
    fn trusted_root_names(provider: &Provider) -> Vec<String> {
        let store = trusted_roots(provider);
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .filter(|anchor| store.roots.iter().any(|r| r.subject == anchor.subject))
            .map(|anchor| String::from_utf8_lossy(anchor.subject.as_ref()).into_owned())
            .collect()
    }

    #[test]
    fn each_provider_trusts_only_its_caa_authorized_roots() {
        for provider in [&ANTHROPIC, &OPENAI] {
            let roots = trusted_roots(provider);
            assert!(roots.len() < webpki_roots::TLS_SERVER_ROOTS.len() / 3);
            // Every configured organization matches at least one root, so a typo
            // cannot silently drop a CA.
            for org in provider.trusted_root_orgs {
                assert!(
                    trusted_root_names(provider).iter().any(|s| s.contains(org)),
                    "{}: no root for {org}",
                    provider.host
                );
            }
            // Both hosts chain to GTS Root R4 today.
            assert!(trusted_root_names(provider)
                .iter()
                .any(|s| s.contains("GTS Root R4")));
            // A CA neither provider authorizes is out.
            assert!(!trusted_root_names(provider)
                .iter()
                .any(|s| s.contains("GlobalSign")));
        }
        // Amazon is authorized for openai.com only.
        assert!(!trusted_root_names(&ANTHROPIC)
            .iter()
            .any(|s| s.contains("Amazon")));
        assert!(trusted_root_names(&OPENAI)
            .iter()
            .any(|s| s.contains("Amazon")));
    }

    #[test]
    fn anthropic_and_openai_are_wired() {
        let a = provider_by_name("anthropic").expect("anthropic is wired");
        assert_eq!(a.host, "api.anthropic.com");
        assert_eq!(a.path, "/v1/messages");
        assert_eq!(a.auth_header_name, "x-api-key");
        assert_eq!(a.auth_value_prefix, "");

        let o = provider_by_name("openai").expect("openai is wired");
        assert_eq!(o.host, "api.openai.com");
        assert_eq!(o.path, "/v1/chat/completions");
        assert_eq!(o.auth_header_name, "authorization");
        assert_eq!(o.auth_value_prefix, "Bearer ");
        assert!(o.extra_headers.is_empty());

        assert!(provider_exists("anthropic"));
        assert!(provider_exists("openai"));
    }

    #[test]
    fn unknown_provider_is_not_wired() {
        assert!(provider_by_name("gemini").is_none());
        assert!(!provider_exists("gemini"));
    }

    #[test]
    fn decode_chunked_decodes_a_valid_body() {
        assert_eq!(
            decode_chunked(b"5\r\nhello\r\n0\r\n\r\n").unwrap(),
            b"hello"
        );
    }

    #[test]
    fn decode_chunked_rejects_oversized_chunk_without_panicking() {
        // 0xffff...ff = usize::MAX: the old unchecked `i + size` wrapped, bypassed
        // the bounds check, and panicked on the slice. Now it is a clean error.
        let body = b"ffffffffffffffff\r\nx\r\n0\r\n\r\n";
        assert!(matches!(
            decode_chunked(body),
            Err(TransportError::BadResponse(_))
        ));
    }

    #[test]
    fn decode_chunked_rejects_truncated_chunk() {
        // Declares 0x10 = 16 bytes but provides fewer.
        assert!(matches!(
            decode_chunked(b"10\r\nshort\r\n"),
            Err(TransportError::BadResponse(_))
        ));
    }

    #[test]
    fn parse_http_response_handles_header_less_status_line() {
        // Status line then the blank line, no header fields — must not panic on the
        // status-line+2 slice.
        assert_eq!(parse_http_response(b"HTTP/1.1 200 OK\r\n\r\n").unwrap(), "");
    }

    #[test]
    fn parse_http_response_non_2xx_is_httpstatus() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nnope";
        assert!(matches!(
            parse_http_response(raw),
            Err(TransportError::HttpStatus { status: 404, .. })
        ));
    }

    #[test]
    fn parse_http_response_decodes_a_chunked_2xx_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(raw).unwrap(), "hello");
    }
}
