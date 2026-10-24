# Deploying CAGE: `CAP_IPC_LOCK` and memory protection

CAGE pins the encryption key + bootstrap token pages in RAM via [`mlock(2)`](https://man7.org/linux/man-pages/man2/mlock.2.html) so the kernel will not swap them to disk under memory pressure. Without this capability the in-memory protection is degraded: the keys can land in swap files, which are *not* zeroed at process exit.

mlock covers those two only. A provider key decrypted for an LLM call, and the request buffer that carries it, are not pinned. They stay resident from the decrypt until the request is written (up to about 50 s on a stalled network), and swap or a core dump in that window can persist them.

Most container runtimes drop `CAP_IPC_LOCK` by default. **For production deployments, grant the capability and use `SecretVault(strict_mlock=True)`.** The vault then refuses to start without it, so a missing capability fails loudly.

```python
from cage import SecretVault

vault = SecretVault(strict_mlock=True)  # raises CageViolation if mlock fails
```

**Prefer a self-managed runtime.** `CAP_IPC_LOCK` can be granted on bare metal and VMs, Kubernetes, Docker, and ECS or EKS on EC2. Deploy CAGE there for full in-memory protection. The managed serverless runtimes (AWS Fargate, GCP Cloud Run, Azure Container Apps) cannot grant it. Run those in [degraded mode](#degraded-mode-when-cap_ipc_lock-is-not-available) with the swap mitigations below, and document the trade-off for your auditors.

## Per-platform setup

**Self-managed runtimes, where `CAP_IPC_LOCK` is available (recommended):**

### Docker (Compose)

```yaml
services:
  agent:
    image: my-agent:latest
    cap_add:
      - IPC_LOCK
    # IPC_LOCK alone is enough, no extra ulimits needed.
```

### Docker (CLI)

```bash
docker run --cap-add=IPC_LOCK my-agent:latest
```

### Kubernetes

`CAP_IPC_LOCK` requires elevating the pod's `securityContext.capabilities.add`. This is incompatible with a fully restricted PodSecurityPolicy, so coordinate with your cluster operators.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: agent
spec:
  containers:
    - name: agent
      image: my-agent:latest
      securityContext:
        capabilities:
          add: ["IPC_LOCK"]
```

If your cluster enforces Pod Security Admission with `restricted` profile, you will need an exception or to run the workload in a `baseline`-labeled namespace.

### Bare metal / VM

Either set `CAP_IPC_LOCK` on the interpreter binary via `setcap`:

```bash
setcap cap_ipc_lock+ep "$(readlink -f "$(which python3.12)")"
```

`setcap` must target the **real** ELF binary, not a `pyenv` / `uv` shim or
symlink. File capabilities do not follow symlinks, hence `readlink -f`. The
capability is stripped on copy or reinstall, so re-apply it after upgrading the
interpreter, and note it grants `CAP_IPC_LOCK` to *every* process running that
interpreter. Where you can, prefer the narrower per-user `memlock` ulimit:

```bash
# /etc/security/limits.conf
agent_user soft memlock unlimited
agent_user hard memlock unlimited
```

Test with:

```bash
ulimit -l  # should be "unlimited" or large
```

**Managed serverless, where `CAP_IPC_LOCK` is unavailable. Use [degraded mode](#degraded-mode-when-cap_ipc_lock-is-not-available) below:**

### AWS Fargate / ECS

`CAP_IPC_LOCK` is **not** in the [default allow-list for Fargate tasks](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#container_definition_linuxparameters). You have two options:

1. **Run on ECS on EC2** instead of Fargate, with full Linux capability control.
2. **Use AWS App Runner or EKS-on-EC2** where you control the container runtime.

Document the choice for your auditors. If neither is feasible, use the **degraded mode** below.

### Azure Container Apps

`CAP_IPC_LOCK` is currently **not exposable** via Container Apps' restricted runtime. Use **AKS** (Azure Kubernetes Service) or **Azure Container Instances** with explicit capability add.

### GCP Cloud Run

Cloud Run runs in a [sandboxed gVisor environment](https://cloud.google.com/run/docs/securing/security) that does not honor `CAP_IPC_LOCK`. Use **GKE** with the capability granted, or **Compute Engine** containers where you control the runtime.

### macOS (development only)

macOS does not enforce `CAP_IPC_LOCK` and `mlock` typically succeeds for small allocations without elevated privilege. For development, no setup needed. **Production macOS deployments are not recommended.** macOS is a developer OS.

## Degraded mode (when CAP_IPC_LOCK is not available)

If your environment forbids `CAP_IPC_LOCK` (e.g. Fargate, Cloud Run), you can run CAGE in degraded mode. Document the choice in your security model:

```python
vault = SecretVault(strict_mlock=False)  # default

if not vault._backend.mlock_succeeded:
    # Log + alert your audit pipeline.
    audit_log.warn("cage running with mlock disabled: swap exposure risk")
```

The structural-refusal claim (capability tokens + audit chain) still holds in degraded mode. The in-memory protection is weaker, because swap files may persist the key after process exit. Mitigations:

- **Disable swap entirely** on the host (cloud VMs: `swapoff -a`).
- **Use encrypted swap** (`dm-crypt` plain mode with random ephemeral key).
- **Memory-only filesystems** for any persistent storage.

## Broker socket and mlock

The credential broker (`cage-broker`) serves the Gate over a Unix-domain socket. It creates the socket `0600` (broker UID only) and checks the peer UID on every accept (`SO_PEERCRED` on Linux, `getpeereid(2)` on macOS), refusing any UID that is not allow-listed. A co-tenant or sidecar under a different UID cannot reach the authority.

- The default allow-list is the broker's own euid. Add others with `CAGE_BROKER_ALLOWED_UIDS=<uid>,<uid>`. The socket file is `0600`, so a peer under another UID also needs file access to the socket, which the broker does not grant today.
- **Place the socket in a `0700` directory owned by the broker UID** (a non-`/tmp` runtime path such as `/run/cage/`), so the path itself is not world-traversable.

In the broker, strict mlock is opt-in: with `CAGE_STRICT_MLOCK` set, the broker refuses to start if the master-key pages could not be pinned.

### Operator key (control-plane authority)

The broker control plane (mint / revoke / attest / audit-log) is authenticated by an **operator ed25519 signature**, not a bearer secret. Provision the operator's **public** key (hex of the raw 32-byte key) to the broker via `CAGE_OPERATOR_PUBKEY` at startup. The broker holds only that public key and verifies a per-request signature bound to the broker's identity, a nonce and a freshness timestamp. **Fail-closed:** with `CAGE_OPERATOR_PUBKEY` unset (and not in dev mode) the broker refuses to start, because without an operator key no token could ever be minted.

- `CAGE_OPERATOR_PUBKEY` is **public** (it needs integrity, not secrecy), so an environment variable is an acceptable channel. Anyone able to set the broker's environment already controls the broker.
- The operator's **private** key is the control-plane root authority. The launcher (`spawn_broker`) generates one in-process and pre-wires the client to sign with it. In production, hold it in the operator process, ideally in an OS keystore or an HSM. The broker prints nothing secret on stdout, only its public attestation key.
- Protecting the authority root against a compromised host requires the operator key to live in a **separate trust domain** from the broker, such as an HSM or a hardware token. The signer is pluggable, so such a custody backend fits in without a wire-protocol change.

### Issuance policy

The broker refuses to start without an issuance policy. Set `CAGE_ISSUANCE_SCOPES` to the scope namespaces the operator may mint, for example `llm.,sign.`, and optionally `CAGE_ISSUANCE_MAX_TTL`, `CAGE_ISSUANCE_MAX_USES` and `CAGE_ISSUANCE_MAX_TOKENS_PER_SCOPE`. The policy is frozen at start, so a stolen operator key can mint only what it allows. A malformed value, a limit set without `CAGE_ISSUANCE_SCOPES`, or an unknown name starting with `CAGE_ISSUANCE_` in any case stops the broker at start. A scope list misspelled outside that prefix leaves the broker without a policy, so it refuses to start as well. A limit misspelled outside the prefix is not caught and takes its default.

- To run without a policy, set `CAGE_BROKER_ALLOW_NO_POLICY=1`. Only the value `1` waives. The broker then prints a warning, and a stolen operator key can mint tokens for any scope, in any number, up to the hard ceilings of 7 days and 100,000 uses per token. The audit chain of such a broker has no `issuance_policy_frozen` entry.
- `spawn_broker` hands the broker the caller's `CAGE_*` settings. A name written in another case, such as `cage_issuance_scopes`, does not reach the broker.

### Keeping the agent out of the broker's memory

The broker protects the key only if the agent cannot read the broker's memory. In the default layout the agent and the broker run under the same user, and most systems let a user debug their own processes.

- **The agent must not control how the broker starts.** Everything below assumes it. Code that runs before the broker's `main`, such as a library loaded through `LD_PRELOAD` or `DYLD_INSERT_LIBRARIES`, can undo or fake all of the hardening, and so can a replaced binary. The same environment also carries the issuance ceiling (`CAGE_ISSUANCE_SCOPES`). A same-user agent can kill the broker and wait for a restart, so the agent's user must not be able to write the broker binary, the launcher code (for `spawn_broker`, the Python environment it is installed in), or anything the launcher's environment comes from: shell profiles, `systemd --user` units and `environment.d`, launchd agents. `spawn_broker` passes the broker only the caller's `CAGE_*` variables, but a launcher whose own environment is poisoned is compromised already. On Linux, the file-capability install below also makes the loader ignore `LD_PRELOAD` for the broker.
- **The broker hardens itself at start.** It first sets its core-dump limit to 0, hard limit included, on every platform. A core would hold the master key and every ciphertext. Then, before it creates any key material, it calls `prctl(PR_SET_DUMPABLE, 0)` on Linux. From then on the kernel refuses ptrace attach and `/proc/<pid>/mem` opens by any process without `CAP_SYS_PTRACE`. It then refuses to start if a tracer is already attached. That check reads `/proc/self/status`, so on Linux the broker refuses to start without procfs. On macOS it calls `ptrace(PT_DENY_ATTACH)`, which blocks ptrace-based debugger attach on a best-effort basis. On other platforms it refuses to start. `crates/cage-broker/tests/hardening.rs` checks the Linux behavior.
- **Close the start-up window on Linux.** Between `execve` and that call the broker is still dumpable, and a same-user process that opens its memory or attaches in that window keeps the access. The tracer check catches a tracer that only watches. A tracer that also rewrites the broker's registers can skip the check, so close the window on the host:
  - Set `kernel.yama.ptrace_scope` to 2 or 3. The kernel then refuses attach and memory opens by every process without `CAP_SYS_PTRACE`, for the broker's whole life. With the Ubuntu default of 1, only the broker's ancestors can attach, so an agent that did not start the broker cannot use the window either.
  - Or install the binary root-owned with a file capability: `setcap cap_ipc_lock+ep /usr/local/bin/cage-broker`. The broker then runs in secure-execution mode, so the dynamic loader ignores `LD_PRELOAD`, and the kernel applies `fs.suid_dumpable` at exec. The capability also lets `mlock` succeed. This is the strongest Linux install.
  - Or install the binary execute-only, for example owned by root with mode `0711`. When the broker's user can execute it but not read it, the kernel also applies `fs.suid_dumpable` at exec. It does not change how the loader treats `LD_PRELOAD`.
  - With `fs.suid_dumpable` at 0 or 2 (Ubuntu with apport sets 2), either install leaves only root able to attach from exec on. With 1 the window stays open. Neither stops a process that attached to the launcher's child before `execve`.
  - The broker prints a warning when it started dumpable on a host where Yama does not restrict attach (`ptrace_scope` 0, or no Yama).
- **Keep the secret file away from the agent.** The broker reads `CAGE_BROKER_SECRET_FILE` at start and does not delete it. An agent running as the same user can read that file directly, so delete it once the broker has printed its public key, or make it unreadable to the agent's user. `spawn_broker` deletes it as soon as it reads the public key.
- **Start and provision the broker outside the agent, and protect the launcher.** The hardening does not help against a process that held the keys before they reached the broker. `spawn_broker` starts the broker from the calling Python process and passes the keys through it. Use it only when that process is not the agent, for example a supervisor that starts the broker and then launches the agent separately. That supervisor is an ordinary process the broker's hardening does not cover, and it holds the operator private key for as long as it runs. Keep the agent from attaching to it: call `cage.broker.harden_launcher()` in the supervisor before it starts the agent. That denies debugger attach and core dumps for the supervisor itself (`prctl(PR_SET_DUMPABLE, 0)` on Linux, `PT_DENY_ATTACH` on macOS). On Linux, `kernel.yama.ptrace_scope` of 1 or more with the agent started by the supervisor also keeps the agent out, because a descendant cannot attach upward. `spawn_broker` drops its own references to the credentials after the handoff. CPython does not zero strings, though, and the caller's copies stay wherever the caller keeps them.
- **Root, the kernel and rootless containers are out of scope.** Root or a kernel exploit can still read the broker's memory. So can the agent's user if the broker runs in a user namespace that user owns (for example rootless Podman), because that user holds `CAP_SYS_PTRACE` inside it. That is the host-level threat, which needs hardware isolation beyond this project.
- **Running without the hardening.** `CAGE_BROKER_ALLOW_DEBUGGER=1` starts the broker without the attach hardening. Only the exact value `1` counts, and any other value, `0` included, keeps the hardening. The core-dump limit stays 0. Use it to debug the broker as a normal user, to scan its memory for a resident plaintext key (`examples/broker_demo.py` and the Linux test do this), or on a platform without a mechanism, such as FreeBSD. Never in production.
  - The broker prints a warning and records `debugger_attach_allowed` on its audit chain, so a chain without that entry came from a broker that denied attach. A waived broker's memory is readable, so a same-user process can still rewrite the chain up to its first off-box anchor.
  - `spawn_broker` never forwards the variable from the caller's environment. Pass `allow_debugger=True` instead.
  - On Linux under the waiver, a crash handler behind a pipe `core_pattern` (systemd-coredump, apport) decides for itself whether to honor the core limit.
  - Without the waiver, debugging the broker requires root on Linux (for example `sudo gdb -p <pid>`), and on macOS ptrace-based debuggers cannot attach.

### Pinning the LLM key to its provider

A token on the `llm.` scope names the provider on each call. Without a pin, an agent holding such a token can send the key to another wired provider's host. It cannot reach an arbitrary host, because the provider hosts and trust roots are compiled in. When the broker holds an `llm_api_key`, set `CAGE_LLM_PROVIDER` (for example `anthropic`). The pin belongs to the secret's name: an invoke that resolves to that name and names another provider is refused before anything is decrypted or charged, whichever scope it came through, and the refusal is audited as `rejected_provider`. The pin follows the name. In-process code that stores the same key under another name, or another key under the pinned name, is not covered by it. The broker protocol has no request that stores a secret or registers a scope, so over the broker this cannot happen. Setting the pin is audited as `provider_pinned`, and it cannot be changed while the process runs. An unknown or unreadable name stops the broker at start. In-process, pass `provider=` to `SecretVault.register_scope_secret`.

### Provider TLS trust

For each provider the transport trusts only the root certificates of the CA organizations named in the provider's DNS CAA records (for example Google Trust Services, Let's Encrypt and DigiCert), not the whole public root store. A certificate that chains to any other root is refused. The filter checks the root only, so subordinate CAs that other organizations run under an admitted root are accepted too. To intercept the key, an attacker needs a certificate from one of the admitted hierarchies, for example by passing domain validation at an authorized CA against the provider's public DNS. Revocation is not checked. If a provider moves to a CA outside its list, calls fail at the TLS handshake (before anything is sent, so the use is refunded) until cage is updated.

## Verification

After deploy, check the vault's mlock state at startup via your application logs. When mlock did not succeed, the core prints an `[cage] mlock failed` line on stderr, in the broker as well as in-process. The in-process `SecretVault` also logs `cage_mlock_failed` and appends an `mlock_state` entry to its audit chain. The broker does not record mlock state on its chain. Set `CAGE_STRICT_MLOCK` to make the broker refuse to start instead.

You can also verify programmatically:

```python
from cage import vault

assert vault._backend.mlock_succeeded, "cage: mlock failed, see DEPLOY.md"
```
