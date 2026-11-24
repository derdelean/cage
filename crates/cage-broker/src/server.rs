//! The serving layer: a bounded worker pool over a Unix-domain listener.
//!
//! Concurrency model: the `Gate` is the authority over mutable, security-load-
//! bearing state (token use-counts, the append-only audit chain), so all access
//! goes through a single `Mutex`. That makes every authority decision a short
//! serialized critical section — which is exactly what prevents use-count races
//! (two concurrent `sign`s on a `max_uses=1` token must not both succeed). The
//! worker pool exists so that connection I/O (a slow or stalled client) never
//! blocks other agents — fixing the head-of-line blocking of a single-threaded
//! loop — while keeping resource use bounded (no unbounded thread spawning).
//!
//! `invoke` (a network LLM call) does NOT hold the Gate lock across the TLS
//! round-trip: the serving layer reserves the use + decrypts the key under the
//! lock, releases it, performs the network, then re-acquires only to settle the
//! reservation (record / refund). So one slow upstream cannot stall every other
//! agent's ops, while authorize+charge stays atomic (no use-count race).
//!
//! Peer authentication: the listener restricts the socket to the broker UID
//! (0600) and checks the peer UID (`SO_PEERCRED` on Linux, `getpeereid` on
//! macOS/BSD) on every accept, refusing any peer whose UID is not allow-listed —
//! so a co-tenant / sidecar at a different UID
//! cannot reach the authority.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use cage_core::{post_messages, Gate};

use crate::protocol::{Request, Response};
use crate::service;

/// Number of connection-handling workers. Bounded so a flood of connections
/// cannot exhaust process resources.
const WORKERS: usize = 8;
/// Backlog of accepted-but-not-yet-served connections. A bounded channel applies
/// backpressure to the accept loop instead of growing memory without limit.
const QUEUE_CAP: usize = 128;
/// Per-connection read/write deadline. A stalled or slow client cannot tie up a
/// worker (and thus a share of the pool) indefinitely.
const CONN_TIMEOUT: Duration = Duration::from_secs(10);
/// Hard cap on one request line (requests are small JSON). Bounds the memory a
/// single client can force us to buffer with a newline-less stream.
const MAX_REQUEST_BYTES: u64 = 256 * 1024;

/// Bind `socket_path` and serve until the listener errors. Prints a
/// `CAGE_BROKER_READY=<path>` line on stdout once bound, so a supervisor can
/// wait for readiness. Call it before the process starts any other thread: the
/// bind changes the process umask for a moment.
pub fn serve_unix(gate: Gate, socket_path: &str) -> std::io::Result<()> {
    // Start from a clean socket path.
    let _ = std::fs::remove_file(socket_path);
    let listener = bind_private(socket_path)?;
    // Restrict the socket to the broker UID (0600): a different-UID co-tenant cannot
    // connect even before the per-accept peer-credential check below. The socket is
    // already created 0600 by `bind_private`, this pins the mode explicitly.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    }

    let allowed = Arc::new(allowed_uids());
    println!("CAGE_BROKER_READY={socket_path}");
    let _ = std::io::stdout().flush();
    eprintln!(
        "[cage-broker] listening on {socket_path} ({WORKERS} workers, {} allowed uid(s))",
        allowed.len()
    );

    let gate = Arc::new(Mutex::new(gate));
    let (tx, rx) = mpsc::sync_channel::<UnixStream>(QUEUE_CAP);
    let rx = Arc::new(Mutex::new(rx));

    let mut workers = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let rx = Arc::clone(&rx);
        let gate = Arc::clone(&gate);
        let allowed = Arc::clone(&allowed);
        workers.push(thread::spawn(move || {
            loop {
                // Hold the receiver lock only to dequeue, never while serving.
                let conn = {
                    let guard = rx.lock().expect("recv mutex poisoned");
                    guard.recv()
                };
                match conn {
                    Ok(stream) => {
                        // Refuse a peer whose UID is not allow-listed (co-tenant /
                        // sidecar at a different UID) before any dispatch.
                        if !peer_allowed(&stream, &allowed) {
                            eprintln!(
                                "[cage-broker] refused connection from a non-allowlisted peer"
                            );
                            continue;
                        }
                        // Bound how long a single client can occupy this worker.
                        let _ = stream.set_read_timeout(Some(CONN_TIMEOUT));
                        let _ = stream.set_write_timeout(Some(CONN_TIMEOUT));
                        handle_conn(stream, &gate);
                    }
                    Err(_) => break, // all senders dropped → shut down
                }
            }
        }));
    }

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                if tx.send(stream).is_err() {
                    break; // all workers gone
                }
            }
            Err(e) => eprintln!("[cage-broker] accept error: {e}"),
        }
    }
    Ok(())
}

/// Read one request line, dispatch it under the Gate lock, write one response.
/// Generic over the stream type so a vsock connection works identically.
fn handle_conn<S: Read + Write>(mut stream: S, gate: &Arc<Mutex<Gate>>) {
    let line = {
        // Cap the bytes buffered for one request line: a client streaming data
        // with no newline must not be able to drive the broker to OOM.
        let mut reader = BufReader::new((&mut stream).take(MAX_REQUEST_BYTES));
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            return;
        }
        line
    };
    if line.trim().is_empty() {
        return;
    }

    let resp = match serde_json::from_str::<Request>(&line) {
        // Invoke runs WITHOUT holding the Gate lock across the network: reserve under
        // the lock, network unlocked, settle under the lock.
        Ok(Request::Invoke {
            token_id,
            provider,
            request_body,
        }) => serve_invoke(gate, &token_id, &provider, &request_body.to_string()),
        Ok(req) => {
            let mut gate = gate.lock().expect("gate mutex poisoned");
            service::handle(&mut gate, req)
        }
        Err(e) => Response::err("bad_request", format!("malformed request: {e}")),
    };

    let mut out = serde_json::to_string(&resp).unwrap_or_else(|_| {
        r#"{"ok":false,"error":{"kind":"internal","message":"response serialize failed"}}"#
            .to_string()
    });
    out.push('\n');
    let _ = stream.write_all(out.as_bytes());
}

/// Run an Invoke without holding the Gate lock across the network: reserve the use
/// and decrypt the key under the lock (microseconds), release the lock, hand the key
/// to the transport (which zeroes its copy once the request buffer holds it, and
/// that buffer once the request is written), perform the TLS
/// round-trip, then re-acquire only to settle (record / refund). Authorize and
/// charge stay atomic (no use-count race) while a slow upstream blocks no one else.
fn serve_invoke(gate: &Arc<Mutex<Gate>>, token_id: &str, provider: &str, body: &str) -> Response {
    let mut reservation = {
        let mut g = gate.lock().expect("gate mutex poisoned");
        match g.reserve_invoke(token_id, provider) {
            Ok(r) => r,
            Err(e) => return Response::err(service::error_kind(&e), e.to_string()),
        }
    };
    let key = reservation.take_key();
    let result = post_messages(reservation.provider(), key, body.as_bytes());
    let mut g = gate.lock().expect("gate mutex poisoned");
    match result {
        Ok(resp) => match g.finalize_invoke(&reservation) {
            Ok(()) => Response::ok(serde_json::json!({ "response": resp })),
            // Fail-closed: if the "invoked" entry can't be recorded, don't hand
            // back the response — the call must not escape the audit chain.
            Err(e) => Response::err(service::error_kind(&e), e.to_string()),
        },
        Err(e) => {
            let msg = e.to_string();
            if e.is_pre_send() {
                g.refund_invoke(&reservation, &msg);
            } else {
                g.fail_invoke(&reservation, &msg);
            }
            Response::err("transport", msg)
        }
    }
}

/// Bind `socket_path` so the socket is created with mode 0600, whatever umask the
/// broker was started under. Under a permissive umask (002 or 000) the socket was
/// connectable by other users until the chmod that follows. The peer-UID check
/// refused them even then, so this is defense in depth. The umask is process-wide:
/// call this only while no other thread exists.
fn bind_private(socket_path: &str) -> std::io::Result<UnixListener> {
    let previous = unsafe { libc::umask(0o177) };
    let listener = UnixListener::bind(socket_path);
    unsafe { libc::umask(previous) };
    listener
}

/// Peer UIDs allowed to connect: the broker's own euid, plus any in the
/// `CAGE_BROKER_ALLOWED_UIDS` (comma-separated) allowlist for a differently-UID'd
/// agent. An entry that is not a UID is not allowed in, and is reported on stderr
/// so a typo does not pass unnoticed.
fn allowed_uids() -> HashSet<u32> {
    let mut set = HashSet::new();
    set.insert(unsafe { libc::geteuid() });
    if let Some(list) = std::env::var_os("CAGE_BROKER_ALLOWED_UIDS") {
        let (uids, rejected) = parse_uid_list(&list.to_string_lossy());
        set.extend(uids);
        for entry in rejected {
            eprintln!(
                "[cage-broker] WARNING: ignoring CAGE_BROKER_ALLOWED_UIDS entry {entry:?}: not a numeric UID"
            );
        }
    }
    set
}

/// Split a comma-separated UID list into the UIDs and the entries that are not
/// one. Empty entries (a trailing comma) are neither.
fn parse_uid_list(list: &str) -> (Vec<u32>, Vec<String>) {
    let mut uids = Vec::new();
    let mut rejected = Vec::new();
    for part in list.split(',') {
        let entry = part.trim();
        if entry.is_empty() {
            continue;
        }
        match entry.parse::<u32>() {
            Ok(uid) => uids.push(uid),
            Err(_) => rejected.push(entry.to_string()),
        }
    }
    (uids, rejected)
}

/// The connected peer's UID. `None` if it cannot be determined — treated as not
/// allowed. Linux reads `SO_PEERCRED`; macOS/BSD use `getpeereid(2)`, which Linux's
/// libc does not expose.
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        Some(cred.uid)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc == 0 {
        Some(uid)
    } else {
        None
    }
}

fn peer_allowed(stream: &UnixStream, allowed: &HashSet<u32>) -> bool {
    matches!(peer_uid(stream), Some(uid) if allowed.contains(&uid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_is_created_private_under_an_open_umask() {
        use std::os::unix::fs::PermissionsExt;
        // `create_dir` fails if the name exists, so nobody else prepared it.
        let dir = std::env::temp_dir().join(format!("cage-sock-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("b.sock");
        // The umask is process-wide and tests share the process. No other test
        // in this crate creates a file, so opening it up for one bind is safe.
        let before = unsafe { libc::umask(0) };
        let listener = bind_private(path.to_str().unwrap());
        let after = unsafe { libc::umask(before) };
        let mode = std::fs::metadata(&path).map(|m| m.permissions().mode() & 0o777);
        std::fs::remove_dir_all(&dir).unwrap();
        listener.unwrap();
        assert_eq!(mode.unwrap(), 0o600);
        assert_eq!(after, 0, "bind_private must restore the umask it found");
    }

    #[test]
    fn uid_list_reports_entries_that_are_not_uids() {
        let (uids, rejected) = parse_uid_list("1000, 1001,abc,-1, ,10o1,");
        assert_eq!(uids, vec![1000, 1001]);
        assert_eq!(rejected, vec!["abc", "-1", "10o1"]);
    }
}
