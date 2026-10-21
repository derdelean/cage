#!/usr/bin/env python3
"""
cage-broker demo — "the agent holds tokens, never the key."

Starts the standalone credential broker in its own process, then exercises it
across two real trust domains over a Unix-domain socket:

  * CONTROL PLANE (this process) — holds the operator signing key; issues
    short-lived, scope-bound, use-counted capability tokens, signing each
    control-plane request so the broker can verify it. The signing key never
    leaves the broker.
  * AGENT (a SEPARATE child process) — spawned with only the token_ids it is
    allowed to use, passed on stdin. It never receives the operator key and
    never binds the signing key. It first signs legitimately, then goes rogue and
    tries to mint/forge tokens, exceed limits, and use expired/revoked tokens.
    Every escalation is structurally refused, broker-side, and recorded in a
    tamper-evident chain.

This is the out-of-process pivot: the key lives in a separate process;
the agent's process never holds it. The agent running as its own process — not a
function in this script — is the point: a compromised agent cannot mint tokens,
because the operator signing key was never in its address space.

The demo also tries to read the broker's memory from this process, which runs as
the same user. The broker denies debugger attach and memory reads at start, so the
read is refused. Root can still read it, and the 32-byte master key stays resident
in host RAM. Hiding the key from root needs hardware isolation, which this project
does not provide.

Run with CAGE_BROKER_ALLOW_DEBUGGER=1 to start the broker without that hardening.
The read then succeeds and checks that no plaintext copy of the key is resident:
cage keeps the secret ChaCha20Poly1305-encrypted and zeroizes the decrypted copy
after each use. crates/cage-broker/tests/hardening.rs runs the same check on Linux.

Usage:  python examples/broker_demo.py [path-to-cage-broker-binary]
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

# Dogfood the packaged launcher + client: stand the broker up with
# cage.broker.spawn_broker and talk to it through the BrokerClient it hands back,
# rather than a hand-rolled spawn ceremony or socket protocol. Both are pure
# stdlib, so we import straight from ./python — no native extension needed here.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))

from cage.broker import spawn_broker  # noqa: E402  (intentionally after the sys.path shim)

# The demo's stand-in signing credential. Deliberately DIFFERENT from the broker's
# built-in DEMO_SECRET literal, so the host-memory scan for this exact string is
# unambiguous: any hit is the live credential in RAM, never a compiled-in constant.
# It is handed to the broker through a sealed file (see start_broker), bound only in
# the control-plane process, and the whole demo turns on it never reaching an agent.
SECRET = "sk-LIVE-broker-demo-credential-3f9a2c7e-not-a-real-key"


def _roundtrip(sock_path: str, req: dict) -> tuple[dict, str]:
    """Send one JSON request, read one JSON response, over a fresh connection.

    Returns (parsed_response, raw_text) — the raw bytes are kept so the leak
    check scans exactly what was received, not a re-serialization that could
    differ from the wire bytes.
    """
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    s.sendall((json.dumps(req) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.close()
    text = buf.decode().strip()
    return json.loads(text), text


def ok(what: str) -> None:
    """Print the demo's `[ok]` narrative line for a control-plane step the
    BrokerClient already validated (it raises on refusal, so reaching here is OK)."""
    print(f"   [ok]      {what}")


def expect_refused(resp: dict, what: str) -> None:
    assert not resp.get("ok"), f"expected REFUSAL for {what}, but it succeeded: {resp}"
    err = resp.get("error") or {}
    print(f"   [REFUSED] {what}  ->  ({err.get('kind', '?')}) {err.get('message', err)}")


def host_memory_scan(pid: int, needle: str) -> dict:
    """Model a HOST-LEVEL attacker: with debug rights
    over the broker process, dump its memory and search for the plaintext key.

      * Linux — read the broker's anonymous/heap/stack regions via /proc/<pid>/mem.
      * macOS — lldb `process save-core`.

    Both are refused unless the broker runs with CAGE_BROKER_ALLOW_DEBUGGER.

    Returns one of:
      {"method", "scanned_bytes", "found": bool}
      {"method", "blocked": True, "hardened": True, "reason": str}  (the broker refused)
      {"method", "blocked": True, "reason": str}  (the scan could not run here)
    """
    target = needle.encode()
    plat = sys.platform  # bound to a local so the cross-platform branches stay reachable

    if plat.startswith("linux"):
        try:
            regions = []
            with open(f"/proc/{pid}/maps") as maps:
                for line in maps:
                    parts = line.split()
                    perms = parts[1]
                    path = parts[5] if len(parts) > 5 else ""
                    if "r" not in perms:
                        continue
                    # Skip file-backed libraries and kernel maps — the decrypted
                    # key, if resident at all, lives in anonymous/heap memory.
                    if path.startswith("/") or path in ("[vvar]", "[vdso]", "[vsyscall]"):
                        continue
                    start, end = (int(x, 16) for x in parts[0].split("-"))
                    regions.append((start, end))
            scanned = 0
            with open(f"/proc/{pid}/mem", "rb") as mem:
                for start, end in regions:
                    try:
                        mem.seek(start)
                        chunk = mem.read(end - start)
                    except (OSError, ValueError, OverflowError):
                        continue
                    scanned += len(chunk)
                    if target in chunk:
                        return {"method": "/proc/<pid>/mem", "scanned_bytes": scanned, "found": True}
            return {"method": "/proc/<pid>/mem", "scanned_bytes": scanned, "found": False}
        except PermissionError as e:
            return {"method": "/proc/<pid>/mem", "blocked": True, "hardened": True, "reason": str(e)}
        except FileNotFoundError as e:
            return {"method": "/proc/<pid>/mem", "blocked": True, "reason": str(e)}

    if plat == "darwin":
        if not shutil.which("lldb"):
            return {"method": "lldb save-core", "blocked": True, "reason": "lldb not installed"}
        core_dir = tempfile.mkdtemp(prefix="cage-core-")
        core = os.path.join(core_dir, "broker.core")
        try:
            res = subprocess.run(
                ["lldb", "--batch",
                 "-o", f"process attach -p {pid}",
                 "-o", f"process save-core {core}",
                 "-o", "detach", "-o", "quit"],
                capture_output=True, text=True, timeout=30,
            )
            if not os.path.exists(core):
                blob = res.stdout + res.stderr
                if "lost connection" in blob:
                    # PT_DENY_ATTACH kills lldb's debugserver as it attaches.
                    return {"method": "lldb save-core", "blocked": True, "hardened": True,
                            "reason": "attach denied by the broker (PT_DENY_ATTACH)"}
                reason = ("attach denied by macOS (Not allowed to attach)"
                          if "Not allowed to attach" in blob else "lldb could not save a core")
                return {"method": "lldb save-core", "blocked": True, "reason": reason}
            with open(core, "rb") as f:
                data = f.read()
            return {"method": "lldb save-core", "scanned_bytes": len(data), "found": target in data}
        except subprocess.TimeoutExpired:
            return {"method": "lldb save-core", "blocked": True, "reason": "lldb attach timed out"}
        finally:
            shutil.rmtree(core_dir, ignore_errors=True)

    return {"method": "n/a", "blocked": True, "reason": f"unsupported platform {plat}"}


def agent_worker(sock_path: str) -> int:
    """The AGENT — runs in its OWN process.

    Receives only the token_ids it may use, on stdin. It never holds the
    bootstrap token and never binds the signing key. It prints its narrative to
    stderr (inherited, so it shows live) and reports every response byte it
    received back to the parent on stdout, so the leak check runs OUTSIDE this
    process — the agent never even holds the secret to compare against.

    It deliberately keeps the raw socket round-trip (not cage.broker.BrokerClient):
    the leak scan must see the exact bytes received, not a parsed re-serialization
    that could differ from the wire.
    """
    cfg = json.loads(sys.stdin.readline())
    main_token = cfg["main_token"]
    expired_token = cfg["expired_token"]
    revoked_token = cfg["revoked_token"]
    seen: list[str] = []

    def agent_call(req: dict, label: str, expect: str) -> dict:
        resp, text = _roundtrip(sock_path, req)
        seen.append(text)
        ok = bool(resp.get("ok"))
        if expect == "ok":
            assert ok, f"expected OK for {label}, got: {resp}"
            print(f"   [ok]      {label}", file=sys.stderr)
        else:
            assert not ok, f"expected REFUSAL for {label}, but it succeeded: {resp}"
            err = resp.get("error") or {}
            print(f"   [REFUSED] {label}  ->  ({err.get('kind', '?')}) {err.get('message', err)}",
                  file=sys.stderr)
        return resp

    print(f"\n[AGENT pid={os.getpid()}]  a separate process — holds token_ids, no operator key, no signing key:",
          file=sys.stderr)
    r1 = agent_call({"op": "sign", "token_id": main_token, "payload": "invoice #1001 :: 4200.00 CHF"},
                    "sign payload #1  (use 1/2)", "ok")
    print(f"             signature = {r1['result']['signature'][:32]}…", file=sys.stderr)
    r2 = agent_call({"op": "sign", "token_id": main_token, "payload": "invoice #1002 :: 380.00 CHF"},
                    "sign payload #2  (use 2/2)", "ok")
    print(f"             signature = {r2['result']['signature'][:32]}…", file=sys.stderr)

    print("\n[AGENT gone rogue]  tries everything it can reach without the operator key:", file=sys.stderr)
    agent_call({"op": "sign", "token_id": main_token, "payload": "invoice #1003"},
               "sign a 3rd time (over max_uses)", "refused")
    agent_call({"op": "issue", "scope": "sign.anything", "context": "evil", "max_uses": 999999},
               "mint its own token (no operator signature)", "refused")
    agent_call({"op": "issue", "scope": "sign.anything", "context": "evil", "max_uses": 999999,
                "auth": {"key_id": "00" * 32, "nonce": "11" * 16,
                         "ts": int(time.time()), "sig": "22" * 64}},
               "mint a token with a forged operator signature", "refused")
    agent_call({"op": "sign", "token_id": "00" * 16, "payload": "x"},
               "sign with a fabricated token_id", "refused")
    agent_call({"op": "sign", "token_id": expired_token, "payload": "x"},
               "sign with an expired token", "refused")
    agent_call({"op": "sign", "token_id": revoked_token, "payload": "x"},
               "sign with a revoked token", "refused")

    # Hand the parent every byte the agent received; the leak check runs there.
    print(json.dumps({"agent_seen": seen}))
    return 0


def main() -> int:
    broker_bin = sys.argv[1] if len(sys.argv) > 1 else "target/debug/cage-broker"
    if not os.path.exists(broker_bin):
        raise SystemExit(f"broker binary not found: {broker_bin} (run: cargo build -p cage-broker)")
    # spawn_broker never forwards the waiver from the environment, so pass it on.
    allow_debugger = os.environ.get("CAGE_BROKER_ALLOW_DEBUGGER") == "1"
    with spawn_broker(broker_bin, signing_key=SECRET, allow_debugger=allow_debugger) as bp:
        proc, sock, pubkey, broker = (
            bp.proc, bp.socket_path, bp.pubkey, bp.client,
        )
        print("=" * 72)
        print("cage-broker is running in its own process (pid {}).".format(proc.pid))
        print("The signing key is loaded INSIDE it. No RPC returns the key.")
        print("Attestation pubkey:", pubkey[:32] + "...")
        print("=" * 72)

        # -- CONTROL PLANE (has the bootstrap token) ------------------------
        # Issue every token the agent will hold up front. The 1-second token is
        # left to expire and one token is revoked — both before the agent process
        # starts, so the agent only ever receives token_ids, never the bootstrap.
        print("\n[CONTROL PLANE]  holds the operator key; issues capability tokens (agent gets only token_ids):")
        main_t = broker.issue_token(
            scope="sign.invoice", context="run-42", ttl_seconds=60, max_uses=2,
        )
        ok("issue token  scope=sign.invoice  max_uses=2")
        main_token = main_t.token_id
        print(f"             token_id = {main_token[:16]}…  (this is all the agent gets)")

        short_t = broker.issue_token(
            scope="sign.invoice", context="ttl", ttl_seconds=1, max_uses=5,
        )
        ok("issue a 1-second token (will expire before the agent runs)")
        short_token = short_t.token_id

        rev = broker.issue_token(scope="sign.invoice", context="rev", max_uses=5)
        ok("issue a token (will be revoked)")
        broker.revoke(rev)
        ok("revoke it")
        print("             waiting for the 1-second token to expire…")
        time.sleep(2.2)

        # -- AGENT (its own process; holds only token_ids) ------------------
        cfg = json.dumps({
            "main_token": main_token,
            "expired_token": short_token,
            "revoked_token": rev.token_id,
        })
        sys.stdout.flush()  # emit the control-plane block before the agent's (stderr) narrative
        worker = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "--agent-worker", sock],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        out, _ = worker.communicate(cfg + "\n")
        if worker.wait() != 0:
            raise SystemExit(f"agent worker failed (rc={worker.returncode})")
        agent_seen = json.loads(out.strip().splitlines()[-1])["agent_seen"]

        # -- The key never reached the agent --------------------------------
        # This runs in the CONTROL-PLANE process. The agent process never bound
        # SECRET, so it could not have checked itself — we check on its behalf,
        # against the exact bytes it received over the socket.
        print("\n[PROOF — token authority + RPC surface]  the key never crossed the socket:")
        leaked = any(SECRET in seen for seen in agent_seen)
        assert not leaked, "SECRET LEAKED to the agent!"
        print(f"   [ok]      scanned {len(agent_seen)} responses the agent received — "
              f"the key appears in NONE")
        print("   [scope]   this shows the RPC never returns the key and the agent cannot")
        print("             exceed its tokens — a same-host memory read is tested next.")

        # -- HOST-LEVEL ATTACKER ---------------------------------------------
        # The agent above was fully contained. This models the *other* adversary:
        # code on the host with debug rights over the broker process, which process
        # isolation does not defend against.
        print("\n[HOST-LEVEL ATTACKER]  dumps the broker's memory and greps for the key:")
        scan = host_memory_scan(proc.pid, SECRET)
        # Under the waiver a refused read comes from the host (Yama, hidepid), not
        # from the broker, so it is reported as blocked.
        if scan.get("hardened") and not allow_debugger:
            print(f"   [REFUSED] {scan['method']}: {scan['reason']}")
            print("             the broker denied debugger attach and memory reads at start, so")
            print("             a same-user process cannot read the key. Root still can, and")
            print("             only hardware isolation hides the key from the host. Run with")
            print("             CAGE_BROKER_ALLOW_DEBUGGER=1 to lift the hardening and scan for a")
            print("             resident plaintext copy instead.")
        elif scan.get("blocked"):
            print(f"   [blocked] {scan['method']}: {scan['reason']}")
            print("             on a deploy host a root / CAP_SYS_PTRACE attacker reads freely;")
            print("             the point stands: process isolation doesn't hide the key from")
            print("             the host.")
        elif scan.get("found"):
            print(f"   [BREACH]  {scan['method']}: the PLAINTEXT key was read from broker memory.")
            print("             Out-of-process isolation does NOT hide it from a host attacker")
            print("             with debug rights.")
            print("             (Resident copy = the broker's startup credential / env var; the")
            print("             vault stores it encrypted, so the glue around it must go too.)")
        else:
            kib = scan.get("scanned_bytes", 0) // 1024
            print(f"   [ok]      {scan['method']}: scanned ~{kib} KiB of broker memory — the")
            print("             PLAINTEXT key appears NOWHERE. cage stores it ChaCha20Poly1305-")
            print("             encrypted and zeroizes the decrypted copy after each sign, so a")
            print("             naive memory scrape recovers nothing.")
            print("   [residual] the 32-byte master key is still resident in host RAM — mlock")
            print("             pins it in RAM, it does not hide it from root. A cage-aware")
            print("             attacker lifts master-key + ciphertext and decrypts offline.")

        # -- Tamper-evident record ------------------------------------------
        print("\n[AUDIT]  every issue / sign / refusal is in the chain:")
        valid = broker.verify_chain()
        ok("verify_audit_chain")
        head = broker.audit_head()
        ok("audit_head")
        print(f"             chain valid = {valid}   head = {head[:24]}…")
        attest = broker.attest()
        ok("ed25519 attestation over the head")
        print(f"             signed envelope: {json.dumps(attest)[:64]}…")
        entries = broker.audit_log()
        ok("fetch the audit log")
        events = [json.loads(e["data_json"]) | {"event": e["event"]} for e in entries]
        print(f"             {len(events)} entries; events: "
              + ", ".join(e["event"] for e in events))

        print("\n" + "=" * 72)
        print("RESULT: the agent signed real payloads, was refused every escalation, and")
        print("        never received the key. The host-level memory read above shows the")
        print("        limit of process isolation.")
        print("=" * 72)
        return 0


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--agent-worker":
        sys.exit(agent_worker(sys.argv[2]))
    sys.exit(main())
