//! A same-user process must not be able to read the running broker's memory.
//!
//! The test process is the broker's parent and runs as the same user, which is the
//! default T2 deployment. Without the hardening, Linux (Yama ptrace_scope 0 or 1)
//! lets a parent open `/proc/<child>/mem`. With it, the kernel refuses.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use cage_core::OperatorKey;

const SIGNING_KEY: &str = "test-signing-key-7c41e9d2b8a05f63";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);

/// Removes a test's files even when an assertion fails.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Kills the broker even when an assertion fails.
struct Broker {
    child: Child,
    _dir: TempDir,
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A broker command with its own socket, secret file and operator key.
fn broker_command(name: &str) -> (Command, TempDir) {
    let dir = std::env::temp_dir().join(format!("cage-hardening-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret_file = dir.join("secrets.env");
    std::fs::write(&secret_file, format!("signing_key={SIGNING_KEY}\n")).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cage-broker"));
    cmd.arg(dir.join("broker.sock"))
        .env("CAGE_BROKER_SECRET_FILE", &secret_file)
        .env(
            "CAGE_OPERATOR_PUBKEY",
            OperatorKey::generate().public_key_hex(),
        )
        .env_remove("CAGE_BROKER_ALLOW_DEBUGGER")
        .env("CAGE_BROKER_ALLOW_NO_POLICY", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    (cmd, TempDir(dir))
}

/// Start a broker, with `CAGE_BROKER_ALLOW_DEBUGGER` set to `waiver` if given, and
/// wait until it is serving, so a check runs against a live process that holds its
/// keys.
fn start_broker(name: &str, waiver: Option<&str>) -> Broker {
    let (mut cmd, dir) = broker_command(name);
    if let Some(value) = waiver {
        cmd.env("CAGE_BROKER_ALLOW_DEBUGGER", value);
    }
    let mut broker = Broker {
        child: cmd.spawn().unwrap(),
        _dir: dir,
    };

    // Read stdout on a thread, so a broker that never gets ready fails the test
    // instead of blocking it. The thread keeps reading until the broker exits,
    // which keeps the pipe open.
    let stdout = broker.child.stdout.take().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.starts_with("CAGE_BROKER_READY=") {
                let _ = ready_tx.send(());
            }
        }
    });
    match ready_rx.recv_timeout(STARTUP_TIMEOUT) {
        Ok(()) => broker,
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("broker exited before it was ready"),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("broker not ready within {STARTUP_TIMEOUT:?}")
        }
    }
}

fn open_memory(broker: &Broker) -> std::io::Result<std::fs::File> {
    std::fs::File::open(format!("/proc/{}/mem", broker.child.id()))
}

#[test]
fn same_user_parent_cannot_open_broker_memory() {
    // Root holds CAP_SYS_PTRACE and bypasses the hardening, so a pass as root would
    // prove nothing.
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run this test as a non-root user: root bypasses the hardening"
    );

    // Positive control: the same binary with the hardening waived. If this open is
    // refused too, the host blocks the read by itself (Yama ptrace_scope 2 or more,
    // hidepid, a hardened container) and the check below would pass for the wrong
    // reason.
    let waived = start_broker("waived", Some("1"));
    open_memory(&waived).expect(
        "this host refuses same-user memory reads even without the hardening, so the \
         test cannot tell whether the hardening works",
    );
    drop(waived);

    let mut broker = start_broker("hardened", None);
    let opened = open_memory(&broker);
    assert!(
        broker.child.try_wait().unwrap().is_none(),
        "broker exited during the check"
    );
    let err = opened.expect_err("a same-user parent could open the broker's memory");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn waiver_other_than_1_keeps_the_hardening() {
    // Only the exact value 1 waives. A "0" or "false" meant as "off" must not switch
    // the hardening off by being present.
    for value in ["0", "false", ""] {
        let broker = start_broker("waiver-value", Some(value));
        let err = open_memory(&broker).expect_err("a non-1 waiver value disabled the hardening");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "value {value:?}"
        );
    }
}

#[test]
fn broker_writes_no_core_dumps() {
    // A core would hold the master key and every ciphertext. The limit is 0, hard
    // limit included, with the hardening and under the waiver alike.
    for waiver in [None, Some("1")] {
        let broker = start_broker("core-limit", waiver);
        let limits =
            std::fs::read_to_string(format!("/proc/{}/limits", broker.child.id())).unwrap();
        let core = limits
            .lines()
            .find(|line| line.starts_with("Max core file size"))
            .expect("no core limit in /proc/<pid>/limits");
        let fields: Vec<&str> = core.split_whitespace().collect();
        assert_eq!(fields[4..6], ["0", "0"], "waiver {waiver:?}: {core}");
    }
}

/// The regression check from the 2026-05-31 host-memory audit: the broker keeps the
/// credential encrypted and never leaves a plaintext copy in its heap or stack.
#[test]
fn broker_memory_holds_no_plaintext_credential() {
    // Reading the memory needs the hardening off, which is what the waiver is for.
    let broker = start_broker("residency", Some("1"));
    let pid = broker.child.id();
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    let mut mem = open_memory(&broker).unwrap();
    let needle = SIGNING_KEY.as_bytes();

    let mut scanned = 0;
    for line in maps.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let perms = fields[1];
        let path = fields.get(5).copied().unwrap_or("");
        // A stray copy would sit in anonymous, heap or stack memory. File-backed
        // mappings and kernel pages cannot hold it.
        let kernel_page = matches!(path, "[vvar]" | "[vdso]" | "[vsyscall]");
        if !perms.contains('r') || path.starts_with('/') || kernel_page {
            continue;
        }
        let (start, end) = fields[0].split_once('-').unwrap();
        let start = u64::from_str_radix(start, 16).unwrap();
        let end = u64::from_str_radix(end, 16).unwrap();
        let mut region = vec![0u8; (end - start) as usize];
        if mem.seek(SeekFrom::Start(start)).is_err() || mem.read_exact(&mut region).is_err() {
            continue;
        }
        scanned += region.len();
        let found = region.windows(needle.len()).any(|w| w == needle);
        assert!(
            !found,
            "plaintext credential in broker memory ({})",
            fields[0]
        );
    }
    assert!(scanned > 0, "no broker memory was scanned");
}

#[test]
fn broker_refuses_to_start_when_already_traced() {
    let (mut cmd, _dir) = broker_command("traced");
    cmd.stdout(Stdio::null()).stderr(Stdio::piped());
    // The child asks this test process to trace it before exec, so it is traced
    // from its first instruction, like a same-user process that attached in the
    // window before the hardening.
    unsafe {
        cmd.pre_exec(|| {
            let none = std::ptr::null_mut::<libc::c_void>();
            if libc::ptrace(libc::PTRACE_TRACEME, 0, none, none) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // resume_until_exit reaps the child with waitpid, which clippy cannot see.
    #[allow(clippy::zombie_processes)]
    let mut child = cmd.spawn().unwrap();
    let status = resume_until_exit(child.id() as libc::pid_t);

    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 1,
        "a traced broker did not refuse to start (wait status {status:#x}): {stderr}"
    );
    assert!(
        stderr.contains("traced by pid"),
        "unexpected stderr: {stderr}"
    );
}

/// Act as the tracer: let the tracee run past each stop until it exits, and return
/// its wait status. Kills it if it is still running at the timeout.
fn resume_until_exit(pid: libc::pid_t) -> libc::c_int {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(waited >= 0, "waitpid: {}", std::io::Error::last_os_error());
        if waited == 0 {
            if Instant::now() >= deadline {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, &mut status, 0);
                }
                panic!("a traced broker kept running");
            }
            std::thread::sleep(Duration::from_millis(20));
            continue;
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return status;
        }
        // A stop. The first is the SIGTRAP at exec, which is swallowed. Any other
        // signal is passed on.
        let signal = match libc::WSTOPSIG(status) {
            libc::SIGTRAP => 0,
            other => other as usize,
        };
        let none = std::ptr::null_mut::<libc::c_void>();
        let data = std::ptr::without_provenance_mut::<libc::c_void>(signal);
        unsafe { libc::ptrace(libc::PTRACE_CONT, pid, none, data) };
    }
}
