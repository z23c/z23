<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Native macOS maintenance runbook

Maintenance reference for native arm64 macOS work: what is expected green,
what the platform seam selects per host, which host quirks have already cost
gate cycles, and the first fix move for each gate that can go red here.

Written against tree `4909a816d9` (then tip of `origin/main`) on 2026-08-26.
Measured facts below carry the command or `file:line` they come from; the rest
is code citation. Prose rots, code is authoritative — re-verify a line number
before editing the file it names. The measured host is the maintainer's arm64
Mac16,10 (macOS 26.0.1, Apple Clang 17.0.0), the machine recorded in
[`AGENTS.md`](../../AGENTS.md) §"Verified platform baseline". Intel macOS is
unmeasured (`docs/GETTING_STARTED.md:128`); nothing in this runbook covers it.

Setup prerequisites are `docs/GETTING_STARTED.md:40-52`; this page does not
repeat them.

---

## §1 Build matrix

### Expected green on arm64

| Command | Proves | Notes |
|---|---|---|
| `make z23` | whole-program C23 node links natively | front door at `Makefile:4164`; link rule at `Makefile:4210`. Darwin branch ends with `tools/scripts/check_c23_node_binary.sh`, whose Mach-O arm needs `otool` + `nm` and refuses anything outside `/usr/lib/*` and `/System/Library/Frameworks/*` (`tools/scripts/check_c23_node_binary.sh:13-46`) |
| `make t-fast ONLY=<group>` | one registered group, non-LTO harness | `Makefile:2566`. `ONLY=` is mandatory |
| `make t-fast-exact EXACT_ONLY_MATCHED=<id>` | same, exact group id for receipts | `Makefile:2577` |
| `make t ONLY=<group>` | strict cached per-TU non-LTO harness | `Makefile:2554`; use before push / when chasing optimizer behavior |
| `make test-parallel TEST_PARALLEL_ARGS=--no-cache` | full uncached suite | `Makefile:2107` |
| `make pre-push-ci` | mapped focused proof for pushed files | unmapped code fails closed |
| groups: `crypto`, `sqlite`, `rng`, `thread_qos`, `os_sandbox`, `os_proc`, `sandbox_process_budget`, `self_backtrace`, `binary_ab_fallback`, `binary_staleness`, `dev_platform`, `cold_join_sovereign` | platform contracts named in `AGENTS.md` §"Verified platform baseline" | ids are from `tools/dev/test_group_catalog.def`; `make t-list` is the source of truth |

These groups, not a green `make lint`, are the macOS evidence base.
`AGENTS.md`'s baseline is startup and platform-contract evidence only; it is
not chain-sync acceptance.

### Package/lint checks expected green

| Command | What it does | Host note |
|---|---|---|
| `make check-package-anatomy` | script self-test + run (`Makefile:2484`) | green here |
| `make check-zcode-package-registry` | compiles `build/bin/zcode-package-registry-check`, then the script asserts every package source occurs exactly once in monolith `LIB_SRCS` and that exactly one host sandbox backend is selected (`tools/lint/check_zcode_package_registry.sh:54-61`) | the *script* half is host-neutral; its binary prerequisite links a GNU-ld spelling at `Makefile:2511`, so see §4 row 1 before trusting this one |
| `make lint-fast` | inner lint subset (~7 s); `LINT_FAST_GATES` at `Makefile:3707` | green here |
| `make lint-cached` / `make lint-cold-audit` | result-cache variants of the umbrella | same Linux-only rules as `make lint` |

Full `make lint` (`Makefile:10079`, gates listed from `Makefile:9915`) still
hits intentional Linux-resident checks on this host; the tool-link rules in
§4 use host-specific linker flags and sandbox sources.
Do not report "lint is red on mac" as a mac regression without naming which
rule; separate those failures from real portability breaks before acting, and
separately again from the standalone-tool rules nobody but
`check-standalone-tools-link` ever builds.

### Parallelism

Job-count plumbing calls `nproc`: the lint umbrella defaults to
`$(shell nproc 2>/dev/null || echo 8)` (`Makefile:9911`) and clamps to 8-24
(`Makefile:9912`). Apple ships no `nproc` (measured: not in `/usr/bin`), so on
a stripped PATH you silently get 8 workers. Prefer
`make -j"$(getconf _NPROCESSORS_ONLN)" …`, which is what
`docs/GETTING_STARTED.md` uses.

### Linux-resident at this revision

| Surface | Where | Why |
|---|---|---|
| Release packager | `packaging/release/build_release.sh:57-59` | dies with "this packager produces x86_64-linux only (host is …)" — an intentional refusal, not a defect |
| Release split-debug via `objcopy --add-gnu-debuglink` | `Makefile:4228` takes the Darwin branch instead (`cp` sidecar + `strip -S -x`) | Mach-O has no `.gnu_debuglink`; there is no back-reference, so symbolize against `build/bin/z23.debug` explicitly |
| `ci-symbol-floor` | `Makefile:10131` | designed SKIP (exit 2 → 0) when `objdump`/`ldd` are absent; both are absent here, so the gate passes by skipping, not by proving |
| Standalone tool links | `ZCL_GC_SECTIONS_LDFLAG` and `ZCL_TOOL_SANDBOX_SRC` in `Makefile` | host-specific linker and sandbox selections are centralized; a red gate is a regression |
| Landlock/seccomp package confinement, full Tor, inotify dev watcher, signal-context self-backtrace, `O_TMPFILE` snapshot export | `docs/GETTING_STARTED.md:122-127` | refuse or report unavailable; never fake a pass |

---

## §2 Compat-API contract

`lib/platform/include/platform/` is the blessed home for direct OS calls.
There are no `*_darwin.c` files: Darwin selection happens two ways — inline
`#if defined(__APPLE__)` inside shared `.c` files, and whole-file swap through
the source list (`Makefile:420-427`, non-Linux drops
`lib/platform/src/os_sandbox_linux.c` and `lib/util/src/self_backtrace.c`,
keeps the `_stub` variants).

| Header | Purpose | Darwin primitive | Linux primitive |
|---|---|---|---|
| `rng.h` (+ `lib/platform/src/rng.c:76-79`) | injectable entropy | `arc4random_buf(out, len)` | `getrandom(2)` loop, `/dev/urandom` fallback |
| `thread_compat.h` | bounded thread join | `pthread_join()`; deadline discarded | `pthread_timedjoin_np()` |
| `path_compat.h` | one identity string per path | `realpath()`, including the parent of a not-yet-created path | verbatim copy |
| `fd_path.h` | fd → path | root `/dev/fd`; dirfd children need `fcntl(fd, F_GETPATH)` **plus** a `fstat`/`stat` inode recheck | `/proc/self/fd/<fd>[/<leaf>]` |
| `process_compat.h` | pinned-file exec, env clear | `F_GETPATH` + inode compare, `ESTALE` on mismatch, then `execve()`; env via `_NSGetEnviron()` | `fexecve()`; `clearenv()` |
| `rename_compat.h` | create-exclusive rename | `renameatx_np(…, RENAME_EXCL)` | `renameat2(…, RENAME_NOREPLACE)`; other hosts return `ENOTSUP` rather than emulating |
| `pipe_compat.h`, `socket_compat.h` | atomic CLOEXEC/NONBLOCK setup | `pipe()`/`socket()` then per-fd `fcntl`; rolled back if any step fails | single `pipe2(O_CLOEXEC\|O_NONBLOCK)` / type-flag OR-ing |
| `file_sync.h` | data-integrity sync | `fsync(fd)` | `fdatasync(fd)` |
| `file_advice.h` | read-ahead / cache eviction | `fcntl(fd, F_RDAHEAD, 1)`; `fcntl(fd, F_NOCACHE, 1)` | `posix_fadvise(POSIX_FADV_SEQUENTIAL / _DONTNEED)` |
| `file_watch_compat.h` | dev-loop mutation events | stub: `inotify_init1()` sets `ENOTSUP` and returns -1 | `<sys/inotify.h>` |
| `system_memory.h` | total RAM | `sysctlbyname("hw.memsize")` | `sysinfo().totalram × mem_unit` |
| `device_compat.h` | major/minor extraction | manual bit fields `(dev >> 24) & 0xff` / `dev & 0x00ffffff` | `sys/sysmacros.h` `major()`/`minor()` |
| `allocator_compat.h` | glibc malloc tuning | both functions compile empty (keyed on `__GLIBC__`, not on OS) | `mallopt(M_MMAP_THRESHOLD, …)`, `malloc_trim(0)` |
| `clock.h` (+ `lib/platform/src/clock.c`) | injectable clock | same `clock_gettime(CLOCK_MONOTONIC/_REALTIME)` calls; feature-tested fallbacks for `_RAW` and per-thread CPU clocks, no Mach timebase | identical shape |
| `os_proc.h` (+ `lib/platform/src/os_proc.c`) | process/host introspection | `proc_pid_rusage(RUSAGE_INFO_V2)`, `task_info(MACH_TASK_BASIC_INFO)`, `proc_pidinfo(PROC_PIDTBSDINFO)`, `sysctlbyname("hw.memsize")`, `_NSGetExecutablePath`, `_NSGetArgc/_NSGetArgv`; cgroup and available-memory stay `-1` | `/proc/self/status`, `/proc/meminfo`, `/proc/uptime` + field 22, `readlink("/proc/self/exe")`, cgroup v2 |
| `os_sandbox.h` (+ `lib/platform/src/os_sandbox_stub.c`) | confinement builders | stub returns typed unavailability ("… is unavailable on this operating system"); `os_sandbox_active()` false; but uid/pgid census answers from `sysctl(KERN_PROC_ALL)` + `proc_pidinfo` | `prctl(PR_SET_NO_NEW_PRIVS)`, Landlock, seccomp-BPF, namespace clone, rlimits |

Read `lib/platform/src/os_sandbox_stub.c:2` as the governing sentence:
*"Non-Linux confinement backend. Linux-only guarantees fail closed."*

Two behavioral notes worth memorizing:

- **Bounded joins do not bound on Darwin.** `platform_thread_join_until`
  ignores its deadline off-Linux (`thread_compat.h`), so the caller cannot
  distinguish "finished in time" from "blocked past the deadline". Every
  direct `pthread_timedjoin_np` call site must be Linux-gated — the only one
  left is `app/services/src/bg_validation_service.c:679-692`; everywhere else
  the calls already went through this seam (`lib/net/src/connman.c:2611-2631`).
  A new call site without that gate will not build here.
- **Host quirk priced into the API:** Darwin implements `flock()` through
  fcntl, so lease locks and SQLite byte-range locks share one kernel lock
  space. The owner lease therefore locks a *different inode* per host
  (`app/models/src/database_owner_lease.c:152-155`, comment quoted below).

```c
/* Linux flock and SQLite's POSIX byte locks are independent, so the
 * database inode is the lease. Darwin implements flock through fcntl and
 * would make SQLite conflict with its own process; use one persistent
 * per-database lock inode there. Independent databases remain independent. */
```

Consequences you can observe on disk: on Darwin the lease object is
`<db>.owner-lock`, opened `O_RDWR|O_CLOEXEC|O_NOFOLLOW` with unconditional
`O_CREAT` (`app/models/src/database_owner_lease.c:32-47`, `:156-161`); on
Linux it is the database path itself, created only when asked. Both arms then
take `flock(fd, LOCK_EX | LOCK_NB)` and report
`DATABASE_OWNERSHIP_CONFLICT: canonical database owner already holds path=…`
on failure (`:164-170`). A `.owner-lock` sidecar in a datadir is expected on
macOS only — do not "clean" it while the node holds it, and do not expect it
to exist on Linux.

---

## §3 Known host quirks

Each row carries how it was established: (m) = measured on this host,
(c) = code citation.

| Quirk | Evidence | Consequence / move |
|---|---|---|
| GNU userland is not optional | (m) not in `/usr/bin`: `sha256sum`, `timeout`, `nproc`, `flock`, `bash`. Present: `make` (GNU 3.81!), `sed`, `grep`, `stat`, `readlink`, `cc`, `otool`, `nm`, `lldb` | Order the PATH exactly as `docs/GETTING_STARTED.md:48` says: brew `make` gnubin first. Apple's `/usr/bin/stat` rejects `-c %N`; coreutils `stat` accepts it |
| Build identity hashes with literal `sha256sum` | (c) `Makefile:211` builds `BUILD_INVOCATION_ID` from `printf … \| sha256sum`; vendor pins use `sha256sum --check vendor/*/SHA256SUMS` (`Makefile:1251-1254`) | No Makefile-level `shasum` fallback exists. Only `tools/dev/source-identity.sh:79-96` has one (`shasum -a 256`). Run `command -v sha256sum` before a long build instead of diagnosing a half-empty hash later |
| Checkout lock needs Homebrew `flock` | (m) `/opt/homebrew/bin/flock` → Cellar 0.4.0; (c) `tools/dev/checkout-lock.sh:35` fails hard: "flock is required for the checkout lock" | Every `t`, `t-fast`, `t-fast-exact` target goes through `$(CHECKOUT_LOCK_TOOL)`; without the formula you fail before compiling anything |
| `/bin/bash` is 3.2 | (m) `/bin/bash -c 'declare -A A=([k]=1)'` → "declare: -A: invalid option"; Homebrew bash 5.3.15 resolves first via `#!/usr/bin/env bash` | `tools/lint/*.sh` use associative arrays (`tools/lint/check_standalone_tools_link.sh:50`). Keep a modern bash ahead on PATH or the lint umbrella dies in `declare` |
| Process ceiling is uid-wide | (m) `sysctl kern.maxprocperuid` → 2666, equal to `ulimit -u`; (c) `lib/platform/src/os_sandbox_stub.c:139-147` reads `getrlimit(RLIMIT_NPROC)` even in the stub; `RLIMIT_NPROC` is charged per REAL UID (`app/controllers/include/controllers/agent_impact_rules.def:1396`) | Symptom inside confined builds: `cc: fatal error: cannot execute '…/cc1': posix_spawn: Resource temporarily unavailable` — recorded verbatim in `lib/test/src/test_sandbox_process_budget.c:17-18`. Lower `-j` or raise `kern.maxprocperuid`; never widen a budget constant so the number looks healthy |
| Stale-lock leads are local, not sync/indexing | (c) `config/src/boot_stale_locks.c:103-140` inspects exactly `blocks/index/LOCK`, `chainstate/LOCK`, `node.db-wal`; LevelDB LOCK carries a PID checked with `kill(pid, 0)` (`:54`) | Before blaming iCloud drive indexing or Spotlight, take the lock's word: read the boot log line, identify the holder with `lsof <path>`, and remember `kill(pid, 0)` succeeds for any process you own — including a recycled PID, which is what makes a stale `blocks/index/LOCK` look live |
| Datadir path identity resolves symlinks | (c) `lib/platform/include/platform/path_compat.h:12-14`: "Darwin exposes /tmp through /private/tmp" → leases and ownership registries key on the resolved path | Keep datadirs on the local APFS volume, not under a synced or symlinked folder; `$TMPDIR` spellings of the same directory are one resource after resolution |
| Debugger attach needs developer mode | (m) `DevToolsSecurity -status` → "Developer mode is currently disabled"; no passwordless sudo | Attaching `lldb` to a process you did not spawn prompts for credentials and fails closed otherwise. Run `DevToolsSecurity -enable` once, deliberately, on a box where that is acceptable |
| Crash post-mortem lags and is thin | (m) reports land under `~/Library/Logs/DiagnosticReports`; (c) self-backtrace is a stub off-Linux (`Makefile:420-427`, `docs/GETTING_STARTED.md:125-126`) | `.ips` reports are written asynchronously after the crash, so "nothing there yet" is not evidence of health. For native crashes, reproduce against `build/bin/z23.debug` rather than waiting on DiagnosticReports |
| Symbolicating the shipped binary | (c) Darwin branch strips the sidecar copy and keeps no debuglink (`Makefile:4228-4230`) | Use `build/bin/z23.debug`, and expect `ldd`/`readelf` habits to be wrong: `otool -L`, `nm -m`, `atos` |
| Reproducibility proofs differ per host | (c) `ZCL_TU_RANDOM_SEED` is empty on Darwin because it is a GCC flag (`Makefile:655`); guard that enforces it inspects Makefile text only (`tools/lint/check_tu_random_seed.sh:53-58`) | Cross-machine byte-identity gates stay on Linux. Mach-O fixture packages compensate with a fixed nonzero UUID and fixed-identifier ad-hoc signature (`AGENTS.md` baseline) |

---

## §4 Gate-by-gate triage

| Symptom | Likely cause | First fix move |
|---|---|---|
| `ld: library ':libsqlite3.a' not found` while building a standalone tool | a new rule bypassed the existing host-specific archive selection | Use the same direct archive and host selector as the neighboring standalone rules; do not add a Darwin-only ad hoc fallback |
| `--gc-sections` rejected (or a tool links in far more than it should) | a rule bypassed `ZCL_GC_SECTIONS_LDFLAG` | Use the centralized flag, which selects `-Wl,-dead_strip` on Darwin and `-Wl,--gc-sections` elsewhere |
| Undefined symbols (`_dynhost_*`, `_tor_*`, `_ed25519_secret_key_from_seed`) in a standalone tool | The node tolerates absent stub symbols through weak `-Wl,-U,_<sym>` allowances (`Makefile:29-34`); single-TU tool rules get neither that list nor the right objects | Either name the object that defines the symbol in that tool's rule, or route it through the stub backend like the node does. `arena_runner` currently names the Landlock backend directly at `Makefile:4426` |
| A standalone sandboxed tool will not compile on Darwin | a new source list bypassed `ZCL_TOOL_SANDBOX_SRC` | Use the centralized backend selector; the Darwin stub gives runtime refusals, not compile-time ones |
| `check-standalone-tools-link` FAIL names several `build/bin/*` targets | This gate derives its tool list from the Makefile and must build everything not exempt (`tools/lint/check_standalone_tools_link.sh:15-19`, exempt set `:50-89`) — so it is where every standalone-rule break surfaces | Read the build output tail the gate prints (`:164-168`); fix the rule's `-I` paths/object list. Exemptions need a written reason and an unknown tool is not exempt — do not add an exemption to go green |
| `check-file-size-ceiling` drift after adding macOS branches | Inline `#if defined(__APPLE__)` blocks grew existing units | Put the next variant behind a per-platform seam file or header seam. Raising a baseline requires explicit review; shrinking is always preferred |
| `zcode-package-registry: FAIL — platform sandbox alternatives appear N times` | `LIB_SRCS` selected zero or both sandbox backends | Exactly one of `os_sandbox_linux.c` / `os_sandbox_stub.c` may be present (`tools/lint/check_zcode_package_registry.sh:54-61`); check whether your edit bypassed the `filter-out` at `Makefile:420-427` |
| Pre-push hook SIGPIPE/write failure after the gate completed | Hook pipe broke late, not a red gate (`docs/DEVELOPING.md:375-378`) | Inspect the saved log and rerun that gate out-of-band; do not accept a bypass you did not document |
| Node refuses to boot with `DATABASE_OWNERSHIP_CONFLICT: canonical database owner already holds path=…` | Another live holder, or a stale `blocks/index/LOCK` PID that is alive because the PID was recycled | `lsof <path>` for the truth; for LevelDB LOCK, compare the PID against the actual process (`config/src/boot_stale_locks.c:54`). Never delete a lock file while any holder is identified |
| Shutdown stalls past the diagnostic join deadline | Deadline joins do not exist off-Linux (`thread_compat.h`), so the stall hides until the watchdog acts | Reproduce with the stage watchdog enabled; treat "join timed out" telemetry as Linux-only observability |
| Fetched-package build that demands Linux isolation refuses | Full-isolation confinement is unavailable here (`docs/GETTING_STARTED.md:123-126`) | Expected refusal. Re-run that step on a Linux host; do not weaken the refusal |

The host-specific linker and sandbox seams are explicit:

```sh
git grep -nE 'ZCL_GC_SECTIONS_LDFLAG|ZCL_TOOL_SANDBOX_SRC' -- Makefile
```

Use those seams rather than adding per-recipe platform branches.
