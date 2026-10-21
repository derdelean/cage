//! Process hardening applied before the broker holds any secret.
//!
//! The broker is the T2 boundary: the key lives here so that an agent running code
//! in its own process cannot read it. In the default deployment the agent and the
//! broker run under the same user, and the operating system then lets that user
//! attach a debugger to the broker or read `/proc/<pid>/mem`. This module narrows
//! that path for non-root processes.
//!
//! * Linux: `prctl(PR_SET_DUMPABLE, 0)`. From then on the kernel refuses ptrace
//!   attach and `/proc/<pid>/mem` opens by any process without `CAP_SYS_PTRACE`,
//!   and the broker writes no core dump. Between `execve` and this call the
//!   process is still dumpable, and a descriptor or tracer obtained in that window
//!   survives the call. The broker refuses to start when a tracer is attached after
//!   the call. That catches a tracer that only watches. A tracer that rewrites the
//!   broker's registers can skip the refusal, so the window itself has to be closed
//!   by the host: `kernel.yama.ptrace_scope` of 1 or more (1 leaves it open to the
//!   broker's ancestors only), or a binary that is execute-only or carries a file
//!   capability, with `fs.suid_dumpable` of 0 or 2. The broker warns when it started
//!   dumpable on a host where none of these holds.
//! * macOS: `ptrace(PT_DENY_ATTACH)`. This blocks ptrace-based debugger attach, and
//!   the kernel ends the process if it is already traced. It is best effort and
//!   weaker than the Linux guarantee. Other memory-access paths are left to the
//!   platform.
//!
//! Root, the kernel and a user namespace owned by the agent's user (rootless
//! containers) are out of scope. That is host compromise, the T3 threat.
//!
//! [`deny_core_dumps`] is separate because it applies even when the attach
//! hardening is waived.

/// Stop this process from writing a core dump, which would hold the master key and
/// every ciphertext. The hard limit drops too, so only root can raise it again.
#[cfg(unix)]
pub fn deny_core_dumps() -> std::io::Result<()> {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit only reads the struct, which lives for the whole call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Deny ptrace attach and memory reads by other non-root processes from now on.
/// Call it first in `main`, before any key material exists.
#[cfg(target_os = "linux")]
pub fn deny_debugger_attach() -> std::io::Result<()> {
    // prctl is variadic and the kernel reads each extra argument as unsigned long.
    let zero: libc::c_ulong = 0;
    // SAFETY: both prctl options take integer arguments and touch no memory.
    let started = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, zero, zero, zero, zero) };
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, zero, zero, zero, zero) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // The kernel refuses new tracers from here on, so one check covers any tracer
    // that attached in the window before the call.
    let tracer = tracer_pid()?;
    if tracer != 0 {
        return Err(std::io::Error::other(format!(
            "traced by pid {tracer}, which attached before the hardening"
        )));
    }
    // 1 is SUID_DUMP_USER: same-user processes could attach until now. 2 is
    // SUID_DUMP_ROOT, which the kernel sets at exec for a binary its user cannot
    // read when fs.suid_dumpable is 2, and which already limited that to root. Even
    // at 1, Yama at ptrace_scope 1 or more kept out every same-user process that is
    // not an ancestor of this one.
    if started == 1 && !yama_restricts_attach() {
        eprintln!(
            "[cage-broker] WARNING: started dumpable on a host where Yama does not restrict \
             ptrace. Any same-user process could open this process's memory between exec \
             and now. Set kernel.yama.ptrace_scope to 1 or more, or install the binary \
             execute-only or with a file capability, to close that window. See DEPLOY.md."
        );
    }
    Ok(())
}

/// True if Yama limits ptrace attach to ancestors or to root (ptrace_scope 1 or
/// more). False at 0 and on kernels without Yama.
#[cfg(target_os = "linux")]
fn yama_restricts_attach() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|scope| scope.trim().parse::<u8>().ok())
        .is_some_and(|scope| scope >= 1)
}

/// The pid of the process tracing this one, or 0.
#[cfg(target_os = "linux")]
fn tracer_pid() -> std::io::Result<u32> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .and_then(|pid| pid.trim().parse().ok())
        .ok_or_else(|| std::io::Error::other("no TracerPid in /proc/self/status"))
}

/// Deny ptrace-based debugger attach (best effort). Call it first in `main`,
/// before any key material exists.
#[cfg(target_os = "macos")]
pub fn deny_debugger_attach() -> std::io::Result<()> {
    // SAFETY: PT_DENY_ATTACH ignores the pid, address and data arguments.
    let rc = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// No mechanism is wired for this platform, so the caller must decide whether to
/// run without it.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn deny_debugger_attach() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no debugger-attach hardening for this platform",
    ))
}
