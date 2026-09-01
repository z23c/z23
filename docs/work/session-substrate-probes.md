# Session-substrate gating probes (P0.0, multi-user-server program)

Empirical results for the six gating probes that determine what per-session
isolation is achievable on this box. Every claim below was produced by
compiling and **running** a throwaway C23 probe (`cc -std=c23 -O0`) and
capturing its real stdout/exit status — no claim is inferred from a man page
or from `docs/adr/0003-os-substrate-verdict.md` (read for context, cited
where it corroborates or is corroborated by these probes, but every number
below was independently re-measured). The node, live datadirs, and the live
service were not touched — every probe ran against throwaway scratch files.
Probe sources: `probe{1..5}_*.c`, run from the scratchpad (not checked in —
throwaway; re-run to reproduce). Probe 6 is a code read, not a runtime probe.
This doc is the empirical follow-on to `docs/adr/0003-os-substrate-verdict.md`'s
Rung-2 design section, for the *separate* multi-user-server program
(per-session process isolation), not the ADR's single-process self-sandbox.

**Box:** Ubuntu 24.04.3 LTS, kernel 6.8.0-111-generic x86_64, `nproc`=32,
93 GiB RAM, uid 1000 rootless throughout (no `sudo` in any probe), AppArmor
loaded with the current shell `unconfined` — load-bearing for Probe 1.

## PROBE 1 (THE GATE) — unprivileged user namespaces

`unshare(CLONE_NEWUSER)` returns 0 (no `EPERM`); `clone(CLONE_NEWUSER|
NEWNET|NEWPID|NEWNS|SIGCHLD, ...)` as uid 1000 returns a valid child pid
(child observes `getuid()==65534`, the expected unmapped-uid view before
`/proc/<pid>/uid_map` is written). `apparmor_restrict_unprivileged_userns=1`
is set on this box (Ubuntu's default hardening since 23.10) yet did **not**
block either call.

**VERDICT — THE GATE IS OPEN, with one sharp caveat.** Full-namespace
isolation is available rootless today. The caveat:
`apparmor_restrict_unprivileged_userns` only blocks unprivileged userns
creation for processes that are **AppArmor-confined** by a profile lacking
the `userns,` rule; our probe process (and the current shell) is
`unconfined`, which is why it worked. **Any future AppArmor hardening pass
on the z23 binary or a session-child binary must add an explicit
`userns,` rule**, or this exact path silently reverts to `EPERM` on that
host — a deployment-time regression risk, not a code bug; record it as a
standing constraint on any AppArmor profile ever attached. Do **not**
degrade to Landlock+seccomp+rlimits-only on this box — full namespace
stacking works (see the degraded-fallback profile below for a host that
answers this probe differently).

## PROBE 2 — rootless PTY

Full cycle — `posix_openpt(O_RDWR|O_NOCTTY)` → `grantpt` → `unlockpt` →
`ptsname_r` → child `setsid()` + `open(slave)` + `ioctl(TIOCSCTTY)` + write
→ parent read from master — succeeds end to end with **zero** setuid helper
(modern glibc/kernel handle devpts permission bits directly; `pt_chown` was
never invoked). `TIOCSCTTY` succeeds because the child is a fresh session
leader with no controlling tty yet.

**VERDICT:** a per-session controlling PTY (job control, `^C`/`^Z` signals,
window resize via `TIOCSWINSZ`) is achievable rootless with no privileged
component.

## PROBE 3 — seccomp-bpf against a real forked child (hand-rolled, no libseccomp)

Hand-written `struct sock_fprog` via `<linux/filter.h>`/`<linux/seccomp.h>`
BPF (arch check → kill; `execve`/`execveat` → `SECCOMP_RET_KILL_PROCESS`;
default `SECCOMP_RET_ALLOW`). Confirmed: the child runs a normal loop,
`malloc`, `memset`, two `printf`s **after** the filter is installed with no
disruption, then `execve("/bin/true", ...)` terminates it — `waitpid`
reports `WIFSIGNALED`, `WTERMSIG == 31 == SIGSYS`.

**Tuning note (the "any OTHER syscall" ask):** `strace -f -c` over the same
trivial glibc program shows **~50 syscalls across 20 distinct names** before
the one deliberate `execve` (`read write close fstat mmap mprotect munmap
brk pread64 access clone execve wait4 prctl arch_prctl set_tid_address
openat set_robust_list prlimit64 getrandom rseq`), most firing during
dynamic-loader/libc startup alone. This empirically re-confirms
`docs/adr/0003-os-substrate-verdict.md` §Rung-2's choice of a **deny-list**
over an allow-list: even a do-nothing glibc program touches ~20 syscall
names, so a hand-picked allowlist under the node's real dependency stack
(OpenSSL, SQLite, embedded Tor, pthreads) would be exactly the "slow-drip
crash generator" the ADR predicted.

**VERDICT:** a hand-rolled seccomp-bpf deny-list, no libseccomp dependency,
correctly kills `execve`/`execveat` while leaving normal glibc operation
untouched — confirmed by direct execution, not inference.

## PROBE 4 — Landlock

Raw syscalls only (`landlock_create_ruleset`/`_add_rule`/`_restrict_self`
via `<linux/landlock.h>`, no liblandlock). **ABI version 4** — this kernel
also supports network rules (`LANDLOCK_ACCESS_NET_BIND_TCP`/`CONNECT_TCP`),
not empirically exercised here but available for a future probe. All four
sub-checks matched prediction: (1) a ruleset granting
`READ_FILE|WRITE_FILE|READ_DIR` under one scratch dir only; (2) `open()`
outside that dir, after `landlock_restrict_self`, returns `-1 EACCES`; (3)
`open()`/`write()` inside the granted dir, after restrict, succeeds; (4) an
fd opened **before** `landlock_restrict_self` to a file outside the granted
dir remains fully writable afterward — confirms `linux/landlock.h`'s own doc <!-- doc-path-ok: Linux system header -->
comment that pre-opened fds are not subject to the restriction.

**VERDICT:** Landlock (ABI v4) is fully functional rootless for path-scoped
FS confinement, and the pre-opened-fd-survives-enforcement property holds —
useful for handing a session child exactly the fds it needs (PTY master/
slave, log fd) *before* calling `landlock_restrict_self`, rather than
needing a path grant for everything.

## PROBE 5 — socketpair round-trip latency

`AF_UNIX`/`SOCK_STREAM` `socketpair`, fork, N=10000 round trips of a small
`{path,json}`-shaped request (~90 bytes) and bounded JSON reply (~70 bytes),
`CLOCK_MONOTONIC` timed per-iteration. **Result:** median 6.11 μs, p90
6.87 μs, worst-case 22.72 μs — roughly **160x** headroom under the ~1 ms
interactive-feel budget.

**VERDICT:** a "child renders, parent executes" split over `socketpair` is
unconditionally fast enough; latency is a non-issue for this design.

## PROBE 6 — Tor stream API (code read, not a runtime probe)

Read `core/modules/net/include/net/tor_integration.h`, `core/modules/net/include/net/onion_service.h`,
and `core/modules/net/src/tor_integration.c:404-473`. Inbound:
`onion_service_handle_request(...)` is a synchronous one-call-in/one-response-
out callback, not a stream. Outbound: `tor_integration_fetch_onion(...)` and
its blocking wrapper are a **single GET-shaped fetch** per call, callback
fires exactly once with status + complete body — no handle for a second
write, no persistent circuit/session object, no raw-socket-equivalent API
anywhere in either header. No `.c`/`.h` in `core/modules/net/` or `vendor/tor_stub.c`
exposes a bidirectional, long-lived onion stream.

**VERDICT — code-confirmed:** z23's embedded-Tor surface is
**request/response only, both directions**. This independently re-confirms
`docs/adr/0003-os-substrate-verdict.md`'s framing ("no outbound-stream API
in that header"). **Grounds the P1 boundary: P1 session traffic must use
raw TCP (direct clearnet, or the existing one-shot onion request/response
surfaces) — a persistent onion-tunneled session stream is new scope,
correctly deferred past P1.**

## CAPABILITY MATRIX

| # | Capability | Rootless on this box? | Evidence |
|---|---|---|---|
| 1 | `unshare(CLONE_NEWUSER)` | **YES** (0, no EPERM) | Probe 1 |
| 1 | `clone()` stacking `NEWUSER\|NEWNET\|NEWPID\|NEWNS` | **YES** (valid child pid) | Probe 1 |
| 1 | ...but only while AppArmor-**unconfined** | caveat, not a failure today | Probe 1 |
| 2 | Rootless PTY (`posix_openpt`→`TIOCSCTTY`), no setuid helper | **YES**, full cycle | Probe 2 |
| 3 | Hand-rolled seccomp-bpf (no libseccomp), kills `execve`/`execveat` | **YES**, confirmed SIGSYS (31) | Probe 3 |
| 3 | Normal glibc code (malloc/printf/loop) survives the same filter | **YES** | Probe 3 |
| 4 | Landlock LSM, raw syscalls, path-scoped FS grants | **YES**, ABI v4 | Probe 4 |
| 4 | Landlock: outside-grant `open()` → EACCES | **YES** | Probe 4 |
| 4 | Landlock: pre-opened fd survives `restrict_self` | **YES** | Probe 4 |
| 5 | `socketpair` round trip fast enough for interactive feel (<~1ms) | **YES**, median 6.11 us (~160x headroom) | Probe 5 |
| 6 | Persistent/bidirectional outbound or inbound Tor **stream** API | **NO** — request/response only, both directions | Probe 6 (code read) |

## BOTTOM LINE

**#1 verdict: user namespaces ARE available rootless on this box (uid 1000,
Ubuntu 24.04.3, kernel 6.8.0-111-generic) — the gate is open, not degraded.**
Both `unshare(CLONE_NEWUSER)` and the stacked `clone()` succeed cleanly as
long as the calling process is AppArmor-unconfined (true today; must stay
true, or be given an explicit `userns,` grant, for any hardened profile
applied later).

### Achievable P1 isolation profile — full-namespace (this box, today)

Per session: (1) `clone(NEWUSER|NEWNET|NEWPID|NEWNS|SIGCHLD, ...)` — private
user/net/pid/mount namespace (`NEWNET` isolates the network stack until
deliberately bridged; `NEWPID` hides host/other-session processes; `NEWNS`
allows a private mount view for a scoped bind-mount); (2) a dedicated
controlling PTY (Probe 2), no setuid helper; (3) Landlock path-beneath
grants (Probe 4, ABI v4) scoping the process to its own session directory —
open any fds the child needs (PTY slave, log file) **before**
`landlock_restrict_self` so they survive enforcement without a path grant;
(4) a seccomp-bpf **deny-list** (Probe 3, matching ADR-0003 Rung 2's already-
decided design) — `execve`/`execveat`, `ptrace`, `process_vm_readv/writev`,
the `mount` family, `bpf`, `kexec_load`/`kexec_file_load`,
`add_key`/`request_key`/`keyctl` — applied *after* the child's own one-time
setup (namespace entry, PTY open, Landlock restrict) completes, since that
setup itself needs syscalls a deny-list would otherwise have to special-
case; (5) `socketpair(AF_UNIX, SOCK_STREAM)` (Probe 5) for the control-plane
channel — ~6μs median round trip, no latency concern for a render-in-
child/execute-in-parent split; (6) **raw TCP only** at P1 (direct clearnet,
or the existing one-shot onion request/response surfaces) — a persistent
onion-tunneled session stream (Probe 6) does not exist in-tree today and is
out of scope for P1 by design, not oversight.

### Degraded fallback — if a target host answers Probe 1 differently

If a future deployment host reports `unshare(CLONE_NEWUSER) == -1 (EPERM)`
(`unprivileged_userns_clone=0`, a kernel without `CONFIG_USER_NS`, or an
AppArmor profile without a `userns,` rule), in order: (1) drop `NEWUSER`/
`NEWNET`/`NEWPID`/`NEWNS` entirely — none of Probes 2-5 depend on user
namespaces; (2) Landlock (Probe 4) becomes the sole filesystem confinement
layer, still ABI-version-gated (if `landlock_create_ruleset` querying the
version itself returns `< 0`, filesystem confinement degrades further to
application-level path validation, not kernel-enforced); (3) seccomp-bpf
(Probe 3) becomes the sole exec/introspection confinement layer, unaffected
by userns availability; (4) POSIX rlimits (`RLIMIT_NOFILE`/`AS`/`CPU`/
`NPROC`) close the resource-isolation gap left by no `NEWPID`/`NEWNET`,
available unconditionally; (5) PID isolation without `CLONE_NEWPID`: track
the session by process group (`setpgid`+`killpg` on session end) instead of
namespace containment — weaker than Probe 1's result (the child can still
see host PIDs via `/proc`) but bounds signal/kill blast radius; (6) network
isolation without `CLONE_NEWNET` has no cheap unprivileged substitute —
either rely on the seccomp deny-list to block raw sockets/netlink while
otherwise sharing the host network namespace, or (if network confinement is
a hard requirement) run session children under a delegated network
namespace from a privileged one-time setup step, explicitly a fallback not
the default design.

This fallback matches `docs/adr/0003-os-substrate-verdict.md`'s Rung 2 scope
(Landlock + seccomp deny-list, no user namespaces) — even in the degraded
case, the multi-user-server program inherits a design the ADR already
committed to, rather than needing a new primitive class.

---

*Reproduction: probe sources are throwaway scratch files (not checked in),
compiled with `cc -std=c23 -O0 -o probeN probeN.c` and run directly — no
`sudo`, no node/datadir/service touched. Re-run against any candidate
deployment host before trusting this doc's verdict for that host; Probe 1's
result in particular is host- and AppArmor-profile-specific, not a Linux-wide
constant.*
