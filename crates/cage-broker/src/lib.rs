/*!
cage-broker — the credential broker (library).

Runs a `cage_core::Gate` (capability authority + vault) in a trust domain separate
from the agent. The agent connects over a Unix-domain socket, holds only capability
tokens, and asks the broker to act. The decrypted key never enters the agent's
address space; structural refusal is enforced here, broker-side.

Layering (so the security-load-bearing logic is small and testable):
  * `protocol` — the wire types (tagged-enum requests, structured responses).
  * `service`  — pure request→response dispatch against a borrowed `Gate`. No I/O.
  * `server`   — the Unix listener + bounded worker pool + the `Gate` mutex.

[`serve_unix`] is the entry point, used by the `cage-broker` binary (`main.rs`),
which loads the credential from a sealed file.
*/

mod hardening;
mod policy;
mod protocol;
mod server;
mod service;

pub use hardening::{deny_core_dumps, deny_debugger_attach};
pub use policy::issuance_policy_from_env;
pub use server::serve_unix;
