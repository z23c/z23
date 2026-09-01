# OS-substrate working plan: the three rungs

Working plan for `docs/adr/0003-os-substrate-verdict.md`. That ADR is the
decision record (no OS, no scheduler, build the missing organs in-tree,
FreeBSD/OpenBSD-sourced where they fit); this doc is the file-level
inventory and the ordered checklist for actually doing it. All file:line
citations below were verified by reading the cited file at the time this
plan was written — re-verify before acting, per the repo-wide rule that
prose rots and code is authoritative.

---

## §1 Rung 0 — "no shell-outs"

**Why this is first:** every later rung (the `os_proc` shim, and especially
the Rung-2 sandbox's `execve` deny-list) is worthless while the node itself
routinely calls `system()`/`popen()`/`execlp()`. A seccomp deny-list that
denies `execve` to *itself* would break the node on boot.

### The 12-site inventory

| # | Site | What it does | Replacement |
|---|------|---------------|--------------|
| 1 | `engine/modules/event/src/alerts.c:77-95` | `fork()` + `execlp("curl", ...)` to POST an alert webhook. **`alerts_init()` at :287-291 installs `SIGCHLD` with `SA_NOCLDWAIT`, process-wide** — this is *why* every other `system()` return code in the tree is untrustworthy (see site 2's comment). Its removal must be the **last** step of Rung 0, once nothing else needs `system()`'s reap-then-waitpid semantics either. | `zcl_spawn_detached()` (new `spawn` primitive) |
| 2 | `engine/services/src/utxo_recovery_ldb_copy.c:86` | `system("rm -rf '%s' && cp -a '%s' '%s'")`, chainstate copy. The in-code comment (:76-85) explains `system()`'s return is ignored because `SA_NOCLDWAIT` makes its internal `waitpid()` fail `ECHILD`; correctness is instead proven structurally via `chainstate_dir_signature()` — an FNV-1a fold over `(name, size, mtime_ns)` for every entry (:41-58), which makes `cp -a`'s timestamp preservation **load-bearing** (`PRESERVE_TIMES` in the new primitive must be on here). | `zcl_file_tree_copy(..., PRESERVE_TIMES)` |
| 3 | `engine/services/src/utxo_recovery_restore.c:436` | `system("rm -rf '%s'")` cleanup of a temp import path. | `zcl_file_tree_remove()` |
| 4 | `engine/models/src/leveldb_store.c:57-61` | `system("rm -rf '%s' && mkdir -p '%s' && cp -a '%s'/. '%s'/ 2>/dev/null")` — errors silenced by `2>/dev/null`. | `zcl_file_tree_copy()` (errors become real return codes, not `/dev/null`) |
| 5 | `engine/models/src/block_data.c:81,89` | Two `system("cp -au '%s'/blk*.dat ...")` / `rev*.dat` globs. | `zcl_file_tree_copy(..., UPDATE_ONLY, filter=glob)` |
| 6 | `engine/conditions/src/sapling_anchor_frontier_unavailable.c:381-387` | `system("rm -rf '%s'")` — cleans up a one-time-read borrow copy. | `zcl_file_tree_remove()` |
| 7 | `engine/entry/main.c:2531-2541` | `system("rm -rf ... && mkdir -p ... && cp -a ...")` — temp copy of `blocks/index` when the source `LOCK` file is present (`--importblockindex`). | `zcl_file_tree_copy()` |
| 8 | `engine/entry/main.c:2554-2559` | `system("rm -rf '%s'")` — cleanup of the site-7 temp copy, plus a bare `unlink()` of the copied `LOCK` file (already not a shell-out; left as-is). | `zcl_file_tree_remove()` |
| 9 | `cognition/controllers/src/agent_copy_prove_controller.c:402-436` | `system("nohup %s ... > log 2>&1 < /dev/null &")` — launches a detached copy-prove script. Args are allowlist-validated (alnum/`-_.:=,/` only) before being appended unquoted (:416-420), so this is not a shell-injection bug today, just a shell-out. | `zcl_spawn_detached()` |
| 10 | `cognition/controllers/src/agent_test_controller.c:186,428` | `popen("%s --list 2>/dev/null", "r")` to enumerate tests; `system(cmd)` to launch `test_parallel` as a detached runner. | `zcl_spawn_capture()` (site 186), `zcl_spawn_detached()` (site 428) |
| 11 | `cognition/controllers/src/agent_controller.c:61-94` | `popen(command, "r")` — runs `tools/dev/agent-dev-status.sh` and captures stdout. | `zcl_spawn_capture()` |
| 12 | `engine/entry/main.c:770` | `popen("systemctl --user show zclassic23 -p ExecStart --value 2>/dev/null", "r")` — reads the live systemd `ExecStart=` line. | `zcl_spawn_capture()` |

(`tools/*.c` — `zcl-nodectl.c`, `zcl-rpc.c`, `devloop_process.c`,
`check_observability_pairing.c`, `soak/main.c`, `bench_fresh_sync.c` — also
call `system`/`popen`/`execvp`/`execlp`. Those are standalone dev/bench/CLI
binaries, not part of the always-running node process, so they are **out of
scope** for Rung 0/2 — the sandbox only ever wraps the node binary's own
runtime, never a dev tool a human invokes directly.)

### New primitives

**`platform/modules/util` `file_tree_ops`** — one `fd`-based `openat()`/`fdopendir()`
recursive walker (`O_NOFOLLOW` throughout — never follow a symlink during
copy or remove), parameterized by:
- `PRESERVE_TIMES` — copy `st_mtim`/`st_atim` after each file (site 2's
  correctness proof depends on this matching `cp -a`'s behavior exactly).
- `UPDATE_ONLY` — skip a destination file whose mtime is `>=` the source's
  (the `cp -au` semantics sites 5 needs).
- an optional filter callback (glob-equivalent, for sites 5's `blk*.dat` /
  `rev*.dat` selection).

`engine/composition/src/file_ops.c` (today: `file_copy()` — a plain `fopen`/`fread`/
`fwrite` byte-copy loop, no shell-out, already primitive-shaped) becomes a
thin wrapper that calls into `file_tree_ops` for its directory-copy paths,
rather than a second parallel implementation.

**`platform/modules/util` `spawn`**:
- `zcl_spawn_detached(argv[])` — double-fork + `setsid()`, for the
  fire-and-forget launches (sites 1, 9, 10b, and eventually replacing the
  `SA_NOCLDWAIT` reap model entirely once site 1 is gone).
- `zcl_spawn_capture(argv[], out_buf, out_len)` — `fork()` + pipe +
  `execvp()`, waits and captures stdout, for sites 10a, 11, 12. Must
  tolerate `ECHILD` from a stale `SA_NOCLDWAIT` install until site 1 (the
  installer) is migrated — i.e. `spawn`'s own child-reap path cannot assume
  a trustworthy `waitpid()` return until it is the *sole* installer of the
  `SIGCHLD` disposition.

**`core/modules/net` `http_post_json`** — OpenSSL is already linked (the node's own
HTTPS server), so a direct TLS POST replaces site 1's `curl` shell-out for
clearnet webhook URLs. **`.onion` webhook URLs are honestly out of scope**:
the embedded Tor fork is dynhost — **inbound**-request-only
(`core/modules/net/include/net/tor_integration.h`'s own architecture comment: "Tor is
compiled into z23 ... routes `.onion` requests directly into our
process via C function calls" — there is no outbound-stream API in that
header or in `vendor/tor_stub.c`). An outbound Tor SOCKS/stream client would
be new scope, not a Rung-0 deliverable.

### The gate: `check-no-shell-out`

Same three-stage ratchet shape as other doc/lint gates in this tree
(`tools/lint/check_no_raw_clock_outside_platform.sh` is the pattern to
clone): **WARN** (new violations print, do not fail) → **RATCHET**
(baseline = current site count, shrink-only — a new site fails, an existing
one migrating away shrinks the baseline) → **HARD** (baseline is empty,
zero tolerance). Allowlist seeds with the two files that are *expected* to
call `fork`/`exec` forever: `platform/modules/util/src/spawn.c` itself (the primitive's
own implementation necessarily calls the real syscalls) and `engine/entry/main.c`'s
self-respawn `execv()` (`:3104` — an intentional, already-conditioned
in-process re-exec, not a shell-out to be replaced).

---

## §2 Rung 1 — `os_proc` introspection shim

### API (new: `platform/modules/platform/include/platform/os_proc.h`)

```
int64_t os_proc_rss_bytes(void);
int64_t os_proc_uptime_seconds(void);
bool    os_proc_exe_path(char *out, size_t out_sz);
int64_t os_proc_memory_limit_bytes(void);      /* cgroup/rlimit-derived, -1 if unbounded */
bool    os_proc_cgroup_memory_stat(struct json_value *out);
int     os_proc_fd_pin_path(int fd, char *out, size_t out_sz);
```

### Linux implementation

Consolidates the **duplicated** `/proc/self/stat` starttime parser that
exists identically in two places today:
- `engine/services/src/node_health_service.c:54-90` (`proc_uptime_seconds()`)
- `cognition/controllers/src/agent_resources.c:61-118` (`agent_resources_uptime_seconds()`)

Both read `/proc/uptime` for system uptime, then `/proc/self/stat`, skip to
field 22 (`starttime`, by skipping 19 fields past the `)` that closes the
`comm` field), divide by `sysconf(_SC_CLK_TCK)`, and subtract from system
uptime — the same algorithm, hand-duplicated. `os_proc_uptime_seconds()`
becomes the one implementation both call sites delegate to.

`os_proc_fd_pin_path()` on Linux is exactly today's
`/proc/self/fd/%d` pattern already used by the hot-swap loader
(`engine/modules/hotswap/src/hotswap_loader.c:693-695`, whose own comment explains
*why*: opening by the original pathname after hashing risks a
replacement race during rapid editor/build activity, so the `/proc/self/fd`
path pins the exact inode through the `dlopen()` call at :696).

### FreeBSD mapping (header comments only — no FreeBSD build in this repo)

- `os_proc_rss_bytes` / `os_proc_uptime_seconds` → `kinfo_getproc()` (from
  `libutil`), which returns `struct kinfo_proc` with `ki_rssize` and
  `ki_start` directly — no `/proc` parsing needed at all on FreeBSD, which
  is the whole point of the shim.
- `os_proc_exe_path` → `sysctl` with `{CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1}`.
- `os_proc_fd_pin_path` → FreeBSD's `dlopen()` has no `/proc/self/fd`
  equivalent path syntax; the FreeBSD backing would use `fdlopen(fd, ...)`
  (a real libc entry point on FreeBSD, taking the fd directly) instead of a
  path trick — this is a **behavioral** fork in the shim, not just a path
  string swap, and is the header-comment note to get right before anyone
  attempts a FreeBSD build.

### Migration site list

- `engine/modules/metrics/src/metrics.c:346` — `fopen("/proc/self/status", "r")` for
  RSS in the periodic metrics snapshot.
- `engine/services/src/node_health_service.c` (the :54-90 function above, plus
  its `get_rss_kb()` sibling at :92+ reading `/proc/self/status`).
- `cognition/controllers/src/agent_resources.c` (the :61-118 function above, plus
  `rss_kb()` at :37+ and the cgroup read at :136).
- `engine/modules/sim/src/postmortem.c:65` — `copy_proc_status()`, a **regular**
  (non-signal-context) diagnostic snapshot copy; migrates to the shim.
  **`postmortem.c:1040` does NOT migrate** — it runs inside the
  async-signal-safe crash handler (`signal_copy_file_limited`, called from a
  signal frame), where only async-signal-safe calls are permitted; the shim
  is not signal-safe, so this stays a marked raw `/proc/self/status` read by
  design, not an oversight.
- `engine/entry/main.c:3097` — `readlink("/proc/self/exe", ...)` for the self-respawn
  path; migrates to `os_proc_exe_path()`.

### Optional door-keeper gate

`check-no-raw-proc-outside-platform` — a clone of
`tools/lint/check_no_raw_clock_outside_platform.sh`'s pattern (grep for the
raw pattern — here `/proc/self` or `/proc/uptime` — outside
`platform/modules/platform/src/`, HARD with an explicit allowlist for the two async-signal-safe
exceptions in `postmortem.c`).

---

## §3 Rung 2 — sandbox façade (DESIGN ONLY, no implementation in this lane)

### API (new: `platform/modules/platform/include/platform/os_sandbox.h`)

```
enum os_sandbox_profile { SANDBOX_NODE_STEADY_STATE, SANDBOX_HOTSWAP_LOADER, SANDBOX_CLI };
bool os_sandbox_enter(enum os_sandbox_profile profile);  /* one-way: no exit */
bool os_sandbox_active(void);
bool os_sandbox_dump_state_json(struct json_value *out, const char *key);  /* diagnostics registry, per CLAUDE.md's "Adding state introspection" convention */
```

### Linux backing

- `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)`.
- **Landlock** path grants: datadir read-write, including the
  **late-opened** `<datadir>/ssl` directory — HTTPS defers its cert/key
  open until the node is near tip (it does not start during IBD), so the
  sandbox must grant the **path**, not rely on a pre-opened fd captured
  before `os_sandbox_enter()` runs. This is the reason Landlock (path-based)
  is the right primitive here over a plain `chroot`+pre-open scheme.
- **seccomp-bpf, deny-list**: `execve`/`execveat`, `ptrace`,
  `process_vm_readv`/`process_vm_writev`, the `mount` family, `bpf`,
  `kexec_load`/`kexec_file_load`, `add_key`/`request_key`/`keyctl`. A
  deny-list, not an allow-list — OpenSSL + SQLite + the embedded Tor fork +
  pthreads between them touch a long, version-drifting tail of syscalls
  (futex variants, `mprotect` patterns, `io_uring` if ever adopted, TLS
  entropy syscalls); a strict allow-list under that surface is a slow-drip
  crash generator on every dependency bump, whereas the actual prize — an
  attacker who reached this process cannot `execve()` a shell — comes
  entirely from the deny-list once Rung 0 has made `execve` genuinely
  unused by the steady-state node.

### Placement

`engine/entry/main.c`, immediately after the `if (!app_init(&ctx))` check passes
(`engine/entry/main.c:2969-2972`) — by that point `BOOT_STAGE_READY` has already been
reached inside `app_init`'s own boot chain
(`engine/composition/src/boot.c:3834` the `-mint-anchor` offline path, `:3869` the
normal path — both call `boot_stage_advance_to(BOOT_STAGE_READY)` only
*after* `app_init_services()` has started connman, the HTTPS/onion
services, and `alerts_init()`), so entering the sandbox here is genuinely
after every service that needs to open a socket, a cert file, or install a
signal handler has already done so.

### The honest breaks list

1. **Self-respawn `execv()`** (`engine/entry/main.c:3104`) — already conditioned on
   `!sd_notify_is_active() && g_saved_argv` (verified: the surrounding
   comment explains this exists for the off-systemd liveness-recovery path;
   under systemd the flag is never set and `Restart=always` owns recovery
   instead). Under systemd: deny `execve` outright — this path is dead
   code there. Off-systemd: the deny-list needs a **scoped** Landlock
   EXECUTE grant restricted to the node's own binary path
   (`os_proc_exe_path()` from Rung 1), not a bare `execve` allow.
2. **Dev/agent runners** (`repro_on_copy.sh`, the `agent_test_controller.c`
   detached test-runner launch, `agent_copy_prove_controller.c`'s script
   launch) are structurally incompatible with `SANDBOX_NODE_STEADY_STATE`
   (they need real `execve`). Dev builds (`ZCL_DEV_BUILD`) get a weaker
   profile, or `SANDBOX_CLI` skips the deny-list for these specific
   controllers.
3. **SQLite `-wal`/`-shm`/temp files and the agent-test status directory**
   must be audited/relocated under the datadir *before* enabling a
   path-grant sandbox by default: `agent_test_controller.c:130-139`
   (`at_status_dir()`) defaults to `$HOME/.zclassic-c23-agent-test-status`
   when `ZCL_AGENT_TEST_STATUS_DIR` is unset — outside any datadir grant.
4. **Network confinement is out of scope.** Rung 2 is a local
   resource/exec confinement facade; outbound-connection filtering (e.g. a
   allow-only-to-known-peer-ports policy) is a distinct, unaddressed
   problem.

### Phasing

- **P0** — this doc + `docs/adr/0003-os-substrate-verdict.md` (done, this
  lane).
- **P1** — `-sandbox=on` opt-in flag: `no_new_privs` + Landlock only (no
  seccomp yet, so no `execve` risk from an unmigrated shell-out site that
  Rung 0 missed).
- **P2** — default-on for release builds running under systemd + the
  seccomp deny-list + a `dumpstate` sandbox witness (so `z23 core status`-style
  introspection can prove the sandbox is actually active, not just
  requested).
- **P3** — a weaker dev profile for `ZCL_DEV_BUILD` (Landlock only, no
  seccomp, so the hot-swap loader's `dlopen()` and the dev-loop's spawn
  calls keep working).
- Capsicum (FreeBSD's sandboxing primitive) only if/when a FreeBSD
  appliance target actually happens — not scheduled.

---

## §4 Lane split

Follow-on implementation lanes (this docs lane is L7, already complete —
listed for continuity with the rest of this plan's dependency graph):

| Lane | Scope | Depends on |
|------|-------|------------|
| L1 | `file_tree_ops` primitive (`platform/modules/util`) + migrate sites 2-8 (the `cp`/`rm -rf` sites: `utxo_recovery_ldb_copy.c`, `utxo_recovery_restore.c`, `leveldb_store.c`, `block_data.c`, `sapling_anchor_frontier_unavailable.c`, `main.c`'s two import-temp-copy sites) + make `engine/composition/src/file_ops.c` a thin wrapper. | none |
| L2 | `spawn` primitive (`platform/modules/util`) + `http_post_json` (`core/modules/net`) + migrate sites 1, 9, 10, 11, 12 (`alerts.c` **last**, since it owns the `SA_NOCLDWAIT` install every other `system()` call in the tree currently depends on for its "ignore the return code" correctness argument). | none (parallel with L1) |
| L3 | `check-no-shell-out` lint gate, WARN mode first, wired into `make lint`'s dependency list once L1+L2 land enough sites to make the baseline meaningful. | L1, L2 (for a non-trivial ratchet baseline) |
| L4 | `os_proc` shim (`platform/modules/platform`), Linux implementation + migrate `node_health_service.c`, `agent_resources.c`, `metrics.c`, `main.c:3097`; leave `postmortem.c:1040` alone (signal-safety). | none (parallel with L1-L3) |
| L5 | `check-no-raw-proc-outside-platform` gate. | L4 |
| L6 | Sandbox façade feasibility spike: prototype `os_sandbox_enter()` behind `-sandbox=on` on a throwaway branch, prove Landlock path grants don't break datadir/`ssl`/WAL access, **before** committing to the P1 rollout in §3. | L1, L2 (execve must be genuinely unused first), L4 (for `os_proc_exe_path` in the self-respawn grant) |
| L7 | This docs lane (`docs/adr/0003-os-substrate-verdict.md` + this plan). | none — informs all lanes |

### Deferred (restated from the ADR, for the lane owner who only reads this file)

epoll/kqueue reactor, custom allocator, thread priorities/QoS, a FreeBSD
port, a unikernel — none scheduled; reasons are in `docs/adr/0003`'s
"Explicitly deferred" section.
