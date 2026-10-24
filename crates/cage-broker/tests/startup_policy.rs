//! The broker binary refuses to start without an issuance policy unless the
//! operator waives it, and refuses an unknown policy variable. These run the real
//! binary, so the names it checks come from its real environment.

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use cage_core::OperatorKey;

const TIMEOUT: Duration = Duration::from_secs(20);

/// Kills the broker even when an assertion fails.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn socket(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cage-policy-{}-{name}.sock", std::process::id()))
}

/// The broker with an operator key and only `vars` in its environment. The
/// debugger waiver keeps these tests about the policy: the attach hardening runs
/// first and fails where it is unsupported or the test runs under a tracer.
fn broker(socket: &PathBuf, vars: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cage-broker"));
    cmd.env_clear()
        .env(
            "CAGE_OPERATOR_PUBKEY",
            OperatorKey::generate().public_key_hex(),
        )
        .env("CAGE_BROKER_ALLOW_DEBUGGER", "1")
        .envs(vars.iter().copied())
        .arg(socket)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Run until the broker exits, which must be a refusal, and return its stderr. A
/// broker still running at the timeout fails the test.
fn refusal(vars: &[(&str, &str)]) -> String {
    let mut child = Running(broker(&socket("refused"), vars).spawn().unwrap());
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "cage-broker kept running");
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(status.code(), Some(1), "{stderr}");
    stderr
}

/// Start the broker, wait until it serves or the timeout passes, stop it, and
/// return whether it served along with its stderr.
fn serves(name: &str, vars: &[(&str, &str)]) -> (bool, String) {
    let socket = socket(name);
    let mut running = Running(broker(&socket, vars).spawn().unwrap());
    let stdout = running.0.stdout.take().unwrap();
    let mut stderr = running.0.stderr.take().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.starts_with("CAGE_BROKER_READY=") {
                let _ = ready_tx.send(());
            }
        }
    });
    let ready = ready_rx.recv_timeout(TIMEOUT).is_ok();
    drop(running);
    let _ = std::fs::remove_file(&socket);
    let mut text = String::new();
    stderr.read_to_string(&mut text).unwrap();
    (ready, text)
}

#[test]
fn refuses_to_start_without_a_policy() {
    let stderr = refusal(&[]);
    assert!(
        stderr.contains("CAGE_ISSUANCE_SCOPES") && stderr.contains("CAGE_BROKER_ALLOW_NO_POLICY"),
        "{stderr}"
    );
}

#[test]
fn a_typo_in_the_prefix_is_refused_as_no_policy() {
    // The parser does not see this name at all. The missing policy stops it.
    let stderr = refusal(&[("CAGE_ISSUANSE_SCOPES", "sign.")]);
    assert!(stderr.contains("no issuance policy"), "{stderr}");
}

#[test]
fn an_unknown_policy_variable_is_refused() {
    let stderr = refusal(&[
        ("CAGE_ISSUANCE_SCOPES", "sign."),
        ("CAGE_ISSUANCE_MAX_USE", "2"),
    ]);
    assert!(stderr.contains("\"CAGE_ISSUANCE_MAX_USE\""), "{stderr}");
}

#[test]
fn only_the_value_1_waives_the_policy() {
    for value in ["0", "true", "yes", ""] {
        let stderr = refusal(&[("CAGE_BROKER_ALLOW_NO_POLICY", value)]);
        assert!(stderr.contains("no issuance policy"), "{value:?}: {stderr}");
    }
}

#[test]
fn the_waiver_starts_without_a_policy_and_says_so() {
    let (ready, stderr) = serves("waived", &[("CAGE_BROKER_ALLOW_NO_POLICY", "1")]);
    assert!(ready, "the waived broker did not serve: {stderr}");
    assert!(
        stderr.contains("WARNING: CAGE_BROKER_ALLOW_NO_POLICY=1"),
        "{stderr}"
    );
}

#[test]
fn a_policy_starts_without_the_waiver() {
    let (ready, stderr) = serves("policy", &[("CAGE_ISSUANCE_SCOPES", "sign.")]);
    assert!(ready, "the broker with a policy did not serve: {stderr}");
    assert!(stderr.contains("issuance policy frozen"), "{stderr}");
}
