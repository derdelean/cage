//! cage-broker binary: build the Gate, load the signing credential from a sealed
//! file, and serve. All serving logic lives in the `cage_broker` library
//! (`serve_unix`).

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use cage_broker::{deny_core_dumps, deny_debugger_attach, issuance_policy_from_env, serve_unix};
use cage_core::Gate;

const DEFAULT_SOCKET: &str = "/tmp/cage-broker.sock";
const DEMO_SECRET: &str = "sk-DEMO-signing-key-not-a-real-secret";

fn main() {
    // Always, even under the waiver below: a core dump would write the master key
    // and every ciphertext to disk.
    if let Err(e) = deny_core_dumps() {
        eprintln!("[cage-broker] FATAL: cannot disable core dumps: {e}");
        std::process::exit(1);
    }

    // Before the Gate exists: building it generates the master key. A same-user
    // agent must not be able to attach to this process or read its memory.
    // CAGE_BROKER_ALLOW_DEBUGGER=1 skips this for debugging, for memory-residency
    // tests and for platforms without a mechanism. Dev and diagnostics only. Any
    // other value, 0 included, keeps the hardening.
    let allow_debugger = std::env::var("CAGE_BROKER_ALLOW_DEBUGGER").as_deref() == Ok("1");
    if allow_debugger {
        eprintln!(
            "[cage-broker] WARNING: CAGE_BROKER_ALLOW_DEBUGGER=1. Debugger attach and \
             memory reads are not denied, so a same-user process can read the key. \
             Not for production."
        );
    } else if let Err(e) = deny_debugger_attach() {
        eprintln!("[cage-broker] FATAL: cannot deny debugger attach: {e}");
        std::process::exit(1);
    }

    let socket_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_SOCKET.to_string());

    // The frozen issuance ceiling, required unless waived below
    // (`issuance_policy_from_env` lists the variables). Provisioned here and never again: the gate has no setter, so a
    // caller who later reaches the control plane — including one holding a stolen
    // operator key — cannot widen it. Relaxing it means restarting this process with
    // different provisioning, so it does not bind whoever can restart the process.
    let policy = issuance_policy_from_env().unwrap_or_else(|e| {
        eprintln!("[cage-broker] FATAL: issuance policy: {e}");
        std::process::exit(1);
    });
    let mut gate = match policy {
        Some(policy) => {
            let scopes = policy.allowed_scopes.len();
            let fingerprint = policy.fingerprint();
            let gate = Gate::with_issuance_policy(policy).unwrap_or_else(|e| {
                eprintln!("[cage-broker] FATAL: issuance policy: {e}");
                std::process::exit(1);
            });
            eprintln!(
                "cage-broker: issuance policy frozen ({scopes} scope(s), fingerprint {})",
                &fingerprint[..16]
            );
            gate
        }
        // No policy only on request. Otherwise an unset or misspelled
        // CAGE_ISSUANCE_SCOPES would leave the issuer bounded by the hard ceilings
        // alone, without a word. Only the value 1 waives.
        None if std::env::var("CAGE_BROKER_ALLOW_NO_POLICY").as_deref() == Ok("1") => {
            eprintln!(
                "[cage-broker] WARNING: CAGE_BROKER_ALLOW_NO_POLICY=1. No issuance policy, \
                 so a stolen operator key can mint tokens for any scope, in any number, up \
                 to the hard TTL and use ceilings. Not for production."
            );
            Gate::new()
        }
        None => {
            eprintln!(
                "[cage-broker] FATAL: no issuance policy. Set CAGE_ISSUANCE_SCOPES (for \
                 example llm.,sign.), or CAGE_BROKER_ALLOW_NO_POLICY=1 to run without one."
            );
            std::process::exit(1);
        }
    };

    // Record the waiver on the chain, as the core records its own dev switches, so a
    // chain without this entry came from a broker that denied debugger attach. A
    // waived broker's memory is readable, so this holds only up to the first anchor.
    if allow_debugger {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        gate.append_audit(
            "broker".to_string(),
            "debugger_attach_allowed".to_string(),
            "{}".to_string(),
            now.to_string(),
        )
        .unwrap_or_else(|e| {
            eprintln!("[cage-broker] FATAL: cannot record the debugger waiver: {e}");
            std::process::exit(1);
        });
    }

    // Load the signing credential from a SEALED SOURCE, never from an environment
    // variable: an env value sits in the process's readable environment block for
    // the whole run, so a host attacker with debug rights can dump it straight out
    // of memory (out-of-process isolation does not hide it).
    // `load_credentials_from_env` streams the file into the vault inside `Zeroizing`
    // buffers — no plaintext `String` is ever retained here.
    match std::env::var_os("CAGE_BROKER_SECRET_FILE") {
        Some(path) => {
            let path = path.to_string_lossy().into_owned();
            // `signing_key` is required; `llm_api_key` is optional — load whichever
            // the sealed file provides, so one broker can both sign and serve LLM
            // calls. Names absent from the file are simply not loaded.
            gate.load_credentials_from_env(
                &path,
                &["signing_key".to_string(), "llm_api_key".to_string()],
            )
            .unwrap_or_else(|e| {
                eprintln!("[cage-broker] FATAL: cannot load CAGE_BROKER_SECRET_FILE: {e}");
                std::process::exit(1);
            });
            if !gate.has_secret("signing_key") {
                eprintln!(
                    "[cage-broker] FATAL: no 'signing_key=' entry in CAGE_BROKER_SECRET_FILE ({path})"
                );
                std::process::exit(1);
            }
        }
        None => {
            // Dev fallback only — a compile-time literal, no external key source.
            // The demo always sets CAGE_BROKER_SECRET_FILE, so this path is dev-only.
            eprintln!(
                "[cage-broker] WARNING: CAGE_BROKER_SECRET_FILE unset — using the built-in \
                 DEMO credential. Not for production."
            );
            gate.store_secret("signing_key", DEMO_SECRET)
                .expect("store demo secret");
        }
    }
    gate.register_scope_secret("sign.", "signing_key");
    // If a provider key was supplied, expose the invoke verb on the `llm.` scope,
    // mirroring SecretVault's in-process default (`llm.` -> `llm_api_key`). Without
    // it the broker signs only; with it, agents make token-gated LLM calls whose key
    // never leaves the broker. CAGE_LLM_PROVIDER pins the key to its provider, so no
    // token can send it to another provider's host.
    if gate.has_secret("llm_api_key") {
        gate.register_scope_secret("llm.", "llm_api_key");
        match std::env::var("CAGE_LLM_PROVIDER") {
            Ok(provider) => gate
                .pin_secret_provider("llm_api_key", &provider)
                .unwrap_or_else(|e| {
                    eprintln!("[cage-broker] FATAL: CAGE_LLM_PROVIDER: {e}");
                    std::process::exit(1);
                }),
            Err(std::env::VarError::NotPresent) => {}
            Err(e) => {
                eprintln!("[cage-broker] FATAL: CAGE_LLM_PROVIDER is unreadable: {e}");
                std::process::exit(1);
            }
        }
    }

    // Provision the operator's PUBLIC key (control-plane proof-of-possession). The
    // operator holds the matching private key and signs every issue / revoke /
    // attest / audit_log request; the broker holds only this public key and verifies.
    // Nothing secret crosses stdout or the wire, and the broker holds no
    // forge-the-authority value. CAGE_OPERATOR_PUBKEY is public (integrity, not
    // secrecy), so an env var is fine — anyone who can set the broker's env already
    // controls the broker.
    match std::env::var("CAGE_OPERATOR_PUBKEY") {
        Ok(pk) => gate.authorize_operator(&pk).unwrap_or_else(|e| {
            eprintln!("[cage-broker] FATAL: invalid CAGE_OPERATOR_PUBKEY: {e}");
            std::process::exit(1);
        }),
        Err(_) => {
            eprintln!(
                "[cage-broker] FATAL: CAGE_OPERATOR_PUBKEY unset — without an operator key \
                 no one can mint tokens. Provision the operator's ed25519 public key (hex)."
            );
            std::process::exit(1);
        }
    }
    // The control plane authenticates by operator signature, never the bootstrap, so
    // discard the bootstrap secret: a broker-memory disclosure then yields no
    // forge-the-authority value. Publish only the (public) attestation key, which
    // the operator binds into each signature as this broker's identity.
    gate.discard_bootstrap();
    println!("CAGE_BROKER_PUBKEY={}", gate.attestation_public_key());
    let _ = std::io::stdout().flush();

    // Strict mlock: production sets CAGE_STRICT_MLOCK to refuse to start if the
    // key pages could not be pinned, rather than run with them swappable to disk.
    if std::env::var_os("CAGE_STRICT_MLOCK").is_some() && !gate.mlock_succeeded() {
        eprintln!(
            "[cage-broker] FATAL: CAGE_STRICT_MLOCK set but mlock(2) failed — key \
             pages may be swapped to disk. Grant CAP_IPC_LOCK or unset the var."
        );
        std::process::exit(1);
    }

    if let Err(e) = serve_unix(gate, &socket_path) {
        eprintln!("[cage-broker] fatal: {e}");
        std::process::exit(1);
    }
}
