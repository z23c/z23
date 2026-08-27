<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Building z23

This is the focused build reference — vendored-library sources/versions, the
fast dev-compile targets, and the sanitizer profiles. For the full setup
path (build → run in production → run in development), start at
[`docs/GETTING_STARTED.md`](GETTING_STARTED.md) instead; this page is what it
links to for build detail.

`z23` is one whole-program C23 binary. The build is a single `cc` over
~660–1400 `.c` files with LTO, linked against a set of **static** third-party
archives in `vendor/lib/`.

Linux and macOS use the same C23 source graph. The host-specific layer selects
ELF or Mach-O linking, GNU libstdc++ or Apple libc++, system capability
implementations, and the matching dependency audit. On macOS, `make z23`
produces a native executable and an unstripped `build/bin/z23.debug` sidecar;
it does not invoke a VM. The first native secp256k1 build is derived from the
checksum-pinned v0.8.0 source and cached as
`vendor/lib/libsecp256k1-darwin.a`.

## What the first build costs

Measured, not estimated. `make first-build-timing` clones this repository into
a scratch directory, runs the whole fresh-clone sequence with a wall clock on
each stage, and writes `.cache/first-build-timing/last-run.json`;
`make timings` reads it back. Both numbers below and the ones in the README
come from that artifact, so refreshing them is a command, not an edit.

| Stage | Command | Wall time | Disk after the stage |
|---|---|---|---|
| Clone | `git clone` | 0 s from a local path (hard-linked) | 1007 MiB |
| Vendored archives | `make vendor` | 92 s | 1070 MiB |
| Arm the clone | `make setup` | 41 s | 1073 MiB |
| Binaries | `make -j32` | 205 s | 1233 MiB |
| Full test suite | `make -j32 test-parallel` | 252 s | 1581 MiB |
| **Clone to passing suite** | | **590 s** | **1581 MiB peak** |

Host: 32 cores, gcc 14.2.0, compiler cache disabled, 1-minute
load average 29.3 at the start and 48.6 at the end — the machine was running
other builds throughout, so a quiet host of the same size finishes sooner. The
suite stage ends with the runner's own pass line; 224 s of its 252 s is the
suite actually running, the rest is compiling the test tree.

How to read this:

- **The measurement runs with the compiler cache switched off** (the in-tree
  cache described below is disabled for the run). A host that has built this
  project before finishes far faster, and that faster number is not a first
  build.
- **The 92 s vendor stage is historical.** It was measured before the Rust
  archive path was removed, so current `make vendor` does strictly less work.
  The row is left as measured rather than guessed at—re-run
  `make first-build-timing` to replace it with a fresh measurement.
- **The clone stage is a local clone**, which git satisfies by hard-linking —
  effectively free. A real `git clone` from GitHub transfers the pack, and the
  history is 932 MiB of packed objects for a 3558-file tracked tree, so over a
  home connection the clone takes minutes and can cost more than every other
  line combined. `git clone --depth 1` fetches far less when all you want is
  to build. This is a known cost of the repository's history, recorded here
  rather than hidden.
- **`make vendor` and `make setup` are interchangeable as the first command.**
  `make setup` regenerates `compile_commands.json`, which crosses the
  Makefile's vendor barrier and pulls the vendored-archive build in with it.
  Whichever you type first pays for the archives; the second one is cheap. The
  measurement runs `make vendor` first so the cost is billed where it belongs.
- **The suite stage compiles before it runs.** `make test-parallel` builds a
  ~1400-file per-TU test tree, and those objects are ordinary Make
  prerequisites — a bare `make test-parallel` compiles them one at a time.
  Pass `-j` (`make -j"$(getconf _NPROCESSORS_ONLN)" test-parallel`, which is what the measurement
  runs) or the first suite run is dominated by a missing flag. This is a known
  cost, written down rather than papered over.
- **Host load matters and is recorded.** The artifact carries the 1-minute
  load average at both ends of the run, because the same machine under
  someone else's build reports a different first-build cost.

Peak disk is the size of the built clone: source, git history, vendored
archives, both binaries with debug info, and the per-TU test object tree.

To refresh the numbers on your own machine:

```bash
make first-build-timing    # clone + build + suite in a scratch dir, timed
make timings               # print what was measured here, never elsewhere
```

`make timings` labels the artifact `STALE` once HEAD moves past it and prints
`NOT MEASURED` when it is absent, so this page can be re-derived rather than
believed. A run whose stage exits nonzero is reported as `FAILED` with the
total withheld: a build that did not work has no first-build cost.

## The compile cache is in the repository

Second and later builds are fast because of `tools/zcc.c`, a content-addressed
compile cache that ships **with this repository**. There is nothing to install
and nothing to switch on: the Makefile builds it at parse time
(`tools/dev/zcc_bootstrap.sh`, one ~0.3 s compile on a fresh clone, two `stat`
calls after that) and puts it in front of `$(CC)`. A developer who cloned five
minutes ago gets the same rebuild speed as the maintainer. That is the same
promise the node itself makes about its runtime: stock libc plus in-tree
sources, nothing to fetch.

What it is for, measured on the reference host. `check-standalone-tools-link`
is a lint gate that rebuilds 47 one-shot compile-and-link tool binaries; the
`z23`, `z23-dev`, `z23-dev-asan` and `z23-dev-tsan` links it pulls in are the
expensive part. Same work, same tree, cache cold then warm:

| | Wall | CPU |
|---|---|---|
| Cold (nothing cached) | 178.7 s | 1261 s |
| Warm (served from the cache) | 25.1 s | 41.9 s |

The cache keys any single-output compiler invocation, **link steps included** —
those tool rules have no `-c`, so a per-object cache would not touch them.

It also covers the ordinary case. Rebuilding every object in the tree, 1733
translation units, after deleting the epoch's objects but keeping the cache:

| | Wall | CPU |
|---|---|---|
| Cold (nothing cached) | 15.7 s | 224 s |
| Warm (1733 of 1733 served) | 8.8 s | 45 s |

```bash
make cc-cache-stats      # hits, misses, bypasses, size on disk
make cc-cache-trim       # evict oldest entries down to ZCC_TRIM_MB (4096)
make cc-cache-clear      # start over — do this after a toolchain change
make cc-cache-audit      # recompile every hit and byte-compare it
ZCL_USE_CCACHE=0 make …  # one build with no cache at all
ZCC_LOG=/tmp/zcc.log make …   # one line per compile: HIT / MISS / BYPASS
```

### Why you can believe a hit

A compile cache that serves the wrong bytes is worse than no cache, because
every other proof in this project is a statement about bytes. Four things
keep it honest:

- **The key is what the compiler actually reads.** The content key hashes the
  *preprocessed* text of every `.c` input, so headers, `-I` paths, `-D` macros
  and include order are folded in exactly rather than approximated.
- **The fast path records its own include set.** A stat-only fast path is
  cheap but blind: an earlier version of this cache keyed it on the files named
  on the command line, and editing a header left the `.c` file's timestamp
  untouched, so it served a stale object. The fast path now stores a manifest
  of every file the compile read and re-checks all of them. `check-zcc-cache`
  builds a fixture seven ways on every `make lint` and fails if a header edit is
  ever served from cache.
- **A compile it cannot key says so.** Silently declining to cache is a
  performance bug nobody can see: one unconsumed `-MT` value made every node
  object skip the cache while the counters looked healthy. Those invocations
  are now counted as `unkeyable` in `make cc-cache-stats`, logged as `UNKEY`,
  and the gate fails if the count is not zero.
- **`make cc-cache-audit` proves it empirically**, recompiling every hit for
  real and byte-comparing the result. Run it after touching `tools/zcc.c`.

`ZCC_STRICT=1` skips the fast path entirely if you would rather pay for
certainty, and the hermetic goals (`ci-reproducible`, `repro-verify`) already
force the cache off, so no reproducibility claim is ever served from it.

## One command: `make vendor`

The static third-party archives in `vendor/lib/` are **built from source** by
`make vendor`. Only `vendor/lib/libsecp256k1.a` (a custom Bitcoin Core fork
build) is committed to git; everything else is produced locally from
SHA256-pinned sources. A fresh clone links in one shot:

```bash
git clone https://github.com/z23c/z23.git && cd z23
make z23     # auto-runs `make vendor` if vendor/lib/ archives are absent
```

`make z23` first crosses a Make restart barrier when vendor archives are
missing. The first parse invokes `tools/scripts/build_vendor.sh`; the restarted
parse then captures source identity from the final archive bytes. Link targets
also retain the archives as order-only prerequisites. This prevents a fresh
clone from baking an identity that omitted inputs generated later in the same
build. To build them explicitly:

```bash
make vendor         # build every missing vendor/lib/*.a (idempotent — no-op if present)
make vendor-force   # rebuild all of them from scratch
tools/scripts/build_vendor.sh libz.a libsqlite3.a   # a subset
ZCL_VENDOR_OFFLINE=1 make vendor  # cached pinned sources only; network refused
```

`ZCL_VENDOR_OFFLINE=1` turns a missing or checksum-invalid source archive into
an immediate named failure before either downloader is invoked. P2P source
carriers include the five default-build archives under `vendor/.cache/`, so a
Git-free consumer can prove it did not fall back to GitHub while retaining the
same pin checks and source-build recipes. See
[`P2P_SOURCE_HOSTING.md`](./P2P_SOURCE_HOSTING.md#git-free-consumer-build) for
the complete trust inputs and commands.

Release reproduction is intentionally stricter than the ordinary first-build
convenience path. `make ci-reproducible` and `make repro-verify` always force
`ZCL_VENDOR_OFFLINE=1`, including during Make's early vendor-input parse
barrier, and direct invocation of either backing script enforces the same
policy. The scripts also pin C locale, UTC, `/nonexistent` HOME,
`/usr/bin:/bin` search path and umask 022, and disable host compiler caches.
Run `make vendor` as a separate checksum-pinned acquisition phase first. A
missing or corrupt cached source then leaves reproduction RED; the release
gate never downloads, retries, or falls back to a clean online build.

The exact source identity also recursively covers generated headers under
`vendor/include/`, including ignored SQLite, OpenSSL, and zlib headers used by
the global include path. Unsupported file types and symlinks there fail closed.
The generated wallet-template and explorer-CSS headers use the same ordering
rule: an included-Makefile barrier regenerates stale view outputs and restarts
parsing before the source record is captured.

`make -j"$(getconf _NPROCESSORS_ONLN)" build-only` (compile every `.o`, no link) does not need the archives and
is the fastest way to confirm a clean checkout compiles.

## Fast development binary

Release builds intentionally use one whole-program LTO link. For day-to-day C
development, use the non-release dev binary instead:

```bash
make dev-watch
make agent-loop
make fast-rebuild
make agent-index
make dev-loop-bench
build/bin/z23 discover help          # enumerate native commands
build/bin/z23 status                 # local node status
build/bin/z23-dev status             # dev-lane status
make agent-doctor
make agent-dev-status
build/bin/z23-dev agentdevstatus
build/bin/z23-dev agentbuild
```

`make dev-watch` is the save-driven AI/operator loop: `MODE=verify` (default)
and `MODE=check` are the two public modes and only ever verify; `auto`,
`apply`, `hotswap`, `reload`, and `stage` are Phase-0 contained and refuse
before any runtime publication. Each attempted save writes one
`zcl.dev_cycle.v1` verdict under `~/.local/state/zclassic23-dev/cycles/` and
refreshes `latest-cycle.json`. `make dev-watch-selftest` is the deterministic
contract test; `make dev-activation-selftest` and
`make dev-recovery-selftest` exercise the otherwise-unreachable
activation/recovery machinery inside `/tmp` fixtures only — no public
environment variable reaches the real dev HOME/unit.
The registry-owned C23 interface (`build/bin/z23-dev dev loop
ensure|status|wait`) reaches the same verify-only cycle without the shell
wrapper. `make agent-loop` is the manual one-shot form
(`ZCL_AGENT_LOOP_BIN=1` also links the dev binary); `make agent-doctor` and
`make agent-dev-status` are the no-build status checks
(`ARGS=--json` for `zcl.agent_doctor.v1` / `zcl.agent_dev_status.v2`).
`make agent-index` regenerates `compile_commands.json`; `make dev-loop-bench`
writes `zcl.dev_loop_bench.v1` latency samples. Full field-level semantics —
every mode, the content-addressed generation/activation transaction, deploy
guards, and the `agent-*` status contracts — live in
[`docs/AGENT_API.md`](./AGENT_API.md) "Build loop"; this page stays the
practical command list.

Foreground candidate preflight uses `build/bin/z23 ops selftest`. It
validates every native leaf and generated input schema inside the candidate
without depending on the health of the process being replaced. The exhaustive
handler-dispatch self-test remains a background/live diagnostic.

**Hot-swap (Tier-1, in-process).** Build/verify without resident loading:

```bash
make hotswap-so FILES=app/controllers/src/status_native_handlers.c
make t ONLY=hotswap_loader
make hotswap-sim
```

`make hotswap` and `tools/dev/hotswap-running-dev.sh` always refuse. The live
runtime surface is `make hotswap-try HANDLER=<leaf> ARGS="<cmd>"` (rebuilds
one swappable leaf into a module `.so`, runs the command in a one-shot CLI via
`ZCL_HOTSWAP_PRELOAD`) and `make hotswap-apply HANDLER=<leaf>` (commits the
override in the running `zcl23-dev` node, gated on `-hotswap-activate` +
`ZCL_HOTSWAP_ACTIVATE=1`; canonical refused). Only the six read-only leaves in
`config/hotswap_swappable.def` are eligible. Inspect provenance with
`z23 dumpstate hotswap` (`zcl.hotswap_generation.v2`,
`artifact_inode_pinned=true` per accepted generation) — full contract in
`docs/AGENT_API.md`.

`make fast-rebuild` (alias for `make dev-bin`) links without LTO, keeps
symbols, defaults to `ZCL_DEV_OPT=-Og` with consensus/crypto/script/validation
hot paths at `ZCL_DEV_HOT_OPT=-O2` (both overrideable), and auto-selects
  `mold`/`ld.lld`/`ld.gold` via `ZCL_DEV_LINKER`. `make fast-changed-compile` /
`make fast-compile` are the cheapest no-link edit check. The compile-epoch key
(source SHA-256 + toolchain fingerprint + flags) makes per-TU object/candidate
publication atomic and `ccache`/`sccache`-cacheable; retention is bounded by
`BUILD_EPOCH_KEEP` (default `3`), pruned only when a lease's `/proc` PID and
start tick no longer match a live build.

This binary is for local AI/operator iteration only. `make z23`,
`make deploy`, reproducible builds, and releases continue to use
`build/bin/z23` with the release flag profile.

## Cached full test suite (`test_parallel`)

`build/bin/test_parallel` — the binary `make t`, `make test`, and `make ci`
run — is built from a **cached per-TU object tree**
(`build/test-rel-obj/epochs/<compile-epoch>/`),
not one whole-program `cc`. Each source is addressed under
`build/test-rel-obj/epochs/<compile-epoch>/` with `-MD -MP` depfiles, and the
exact candidate is linked under `build/bin/test-strict/epochs/`. Consequences:

- **Every edit gets a fresh immutable epoch.** Make resolves every current
  source in that epoch; compiler-cache hits recover unchanged TU work before
  one plain link. A no-edit invocation reuses the exact verified epoch.
- **Header/`.def` and system-header inputs are tracked** via complete `-MD -MP`
  depfiles plus the epoch key, so a header-only edit reliably rebuilds
  `test_parallel` — it is never a false-green no-op.
- **`ccache` makes it cacheable.** A giant multi-source `cc` invocation cannot
  be cached; per-TU `.o` compiles hit the cache, so a clean object tree with a
  warm cache rebuilds in a few seconds. `ccache` stays optional (auto-detected
  via `ZCL_USE_CCACHE`); everything works without it, just slower on the first
  build.
- **The cache is already cross-worktree, not just cross-edit.** `CFLAGS`
  unconditionally carries `REPRO_CFLAGS`
  (`-ffile-prefix-map=$(CURDIR)=$(ZCL_REPRO_ROOT)`, default
  `ZCL_REPRO_ROOT=/zclassic23`), which was added for build-host determinism
  but has a second effect: it makes every compiled object byte-identical
  regardless of which worktree's absolute path produced it, and ccache 4.x
  recognizes the prefix map and keys its cache on the mapped (worktree-
  independent) path rather than the real `$(CURDIR)`. Measured on this host
  (two real `git worktree`s, one shared `ccache` dir, `build-only`): a second
  worktree building identical source after a first worktree's cold build got
  1118/1119 objects served from cache (99.91%) — spot-checked object files
  came back byte-for-byte identical (`sha256sum`) to the first worktree's. The
  one designed miss is `lib/util/src/clientversion.o`, which intentionally
  gets the real per-build identity stamp appended
  (`BUILD_ONLY_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS)`) and so is never
  cacheable across builds. No extra flag or opt-in is needed to get this — a
  fleet of parallel worktree agents building the same or overlapping source
  already shares one compile cache for free. Do **not** disable
  `-ffile-prefix-map` or point `ZCL_REPRO_ROOT` at a per-worktree path; either
  change would silently turn this back into a per-worktree-only cache.

**Flag profile.** The cached objects use the identical release flags of the old
whole-program `test_parallel` (`-O3 -Werror -pedantic`, the hardening flags,
`-DZCL_TESTING`) with two documented, semantics-neutral deltas: `-flto=auto` is
dropped (LTO is a link-time whole-program optimization — caching per-TU GIMPLE
would still force the slow whole-program codegen at every link; dropping it lets
each TU be cached and code-generated independently), and the `-O3`+FORTIFY
heuristic-warning family (`-Wformat-truncation`/`-overflow`, `-Warray-bounds`,
`-Wstringop-truncation`/`-overread`, `-Wrestrict`, `-Wnonnull`,
`-Wmaybe-uninitialized`) is `-Wno`'d — those fire only once real per-TU codegen
runs at `-O3`, and no other build in the tree enforces them (release and
`build-only` defer codegen to the LTO link; `test_parallel_fast` runs at `-O1`),
so excluding them keeps the enforced warning set a superset-or-equal of the
whole-program build's (`test_parallel_wpo`). Neither delta can change test
behavior.

**Whole-program variant for debugging.** `make test_parallel_wpo` still builds
the original monolithic whole-program LTO binary at
`build/bin/test_parallel_wpo`. Use it to rule out any per-TU-vs-LTO divergence
if a test ever behaves differently between the two (it should not). `test_zcl`
(the serial runner) also remains a whole-program build.

**Fast inner-loop variant.** `make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=<group>` uses the separate
exact candidate and object tree (`build/bin/test-fast/epochs/<compile-epoch>/`
and `build/test-obj/epochs/<compile-epoch>/`, `-O1`, non-`-Werror`) for the
tightest edit loop; run strict `make -j"$(getconf _NPROCESSORS_ONLN)" t` /
`make -j"$(getconf _NPROCESSORS_ONLN)" test` before commit.

## Sanitizer profiles (opt-in)

Two ASan/UBSan profiles extend the fuzz-only sanitizer coverage to the test
suite and the dev node. Both compile with
`-fsanitize=address,undefined -fno-omit-frame-pointer` (plus
`-fno-sanitize=alignment`, mirroring the fuzz harnesses' established UBSan
profile), no LTO, into their own epoch-keyed object trees — the flags are
referenced only by these profiles and can never leak into the
release/dev/test default builds.

- **`make t-asan ONLY=<group>`** — one test group under the instrumented
  harness (`build/bin/test-asan`, object tree `build/test-asan-obj/`).
  ASan aborts the failing child, so a memory error is a red group with the
  full report in its replayed log; UBSan stays in gcc's recover-and-continue
  default so one run collects every finding (export
  `UBSAN_OPTIONS=halt_on_error=1` to make reports fatal). Findings are the
  point — fix forward, don't suppress.
- **`make asan-ci`** — opt-in smoke: a small set of fast, params-free groups
  under test-asan with `UBSAN_OPTIONS=halt_on_error=1` so any report fails
  the run. Deliberately **not** wired into `make ci` (instrumented runs are
  several times slower and push times must stay stable). Override the set
  with `ASAN_CI_GROUPS="..."`.
- **`make zcode-package-asan`** — permanent self-hosted-package gate. It first
  builds and runs `base`, `sha3`, and `codec` from their authoritative package
  trees with full ASan+UBSan instrumentation, then runs the package registry,
  prepare/seal, accept/publish, work/proof/PROVEN, and score paths through the
  instrumented monolith harness. UBSan is fail-fast and no sanitizer class is
  suppressed.
- **`make dev-asan`** — the dev node under ASan/UBSan
  (`build/bin/z23-dev-asan`, `-Og`, non-LTO, object tree
  `build/dev-asan-obj/`). For local memory/UB debugging on a scratch
  datadir; boot with `ASAN_OPTIONS=detect_leaks=0` until leak triage is
  done.

<!-- claim: symbol-present zcode-package-asan Makefile -->

The test runners set a large **finite** stack limit (1 GiB) rather than the
usual `ulimit -s unlimited`: ASan + PIE with an unlimited stack
intermittently aborts at startup with "Shadow memory range interleaves with
an existing memory mapping" (google/sanitizers#856).

**Known limitation — UBSan "left shift" in `lib/crypto/src/ed25519.c` and
`curve25519.c`:** `make t-asan` flags UBSan shift-base reports at
`ed25519.c:81`/`:304` and `curve25519.c:50`, the TweetNaCl `int64_t`
carry-propagation idiom (`o[i] -= c << 16;`). The left operand is
legitimately negative (gf limbs are signed by design); the project builds
`-std=c23`, which redefines signed left shift as modular (the C++20 rule), so
this is not UB at the language level even though gcc's UBSan instrumentation
still flags it under the pre-C23 rule. Not a live miscompilation: both
expressions lower to a plain `shlq`, identical to the C23-defined result, and
the reachable magnitudes (`|c| <= 2^47`, `|carry| << 2^24`) never approach
overflow. Fix not yet applied — Ed25519 is consensus-adjacent per
`docs/CONSENSUS_PARITY_DOCTRINE.md`, so silencing it needs the full
replay-canary bar, not just green ASan: cast through `uint64_t` before the
shift, `(int64_t)((uint64_t)c << 16)` — bit-exact for all inputs, same `shlq`
codegen (objdump-diff verifiable), silencing the sanitizer noise without
touching consensus-relevant math.

## ThreadSanitizer profiles (opt-in)

Two TSan profiles mirror the ASan ones above for data-race detection. Both
compile with `-fsanitize=thread -fno-omit-frame-pointer`, `-g`, **no LTO**,
into their own epoch-keyed object trees. LTO is deliberately off (beyond
mirroring every instrumented profile here): race reports need precise per-TU
PC/stack attribution, whole-program LTO inlining degrades exactly that, and
`-fsanitize=thread` under `-flto=auto` is a far less-traveled gcc path.
`-fsanitize=thread` is mutually exclusive with address/undefined, so these
are sibling profiles, not an extension of the ASan flag set. Vendored static
archives (OpenSSL/leveldb/libevent/rustzcash) are NOT rebuilt — TSan works
fine against uninstrumented libraries, with proportionally less coverage
inside them.

- **`make t-tsan ONLY=<group>`** — one test group under the
  thread-instrumented harness (`build/bin/test-tsan`, object tree
  `build/test-tsan-obj/`). TSan's default report-and-continue mode collects
  every race in one run, then exits the failing child with `exitcode=66`,
  so a group with reports surfaces red with the full stacks in its replayed
  log. Findings are the point — fix forward, don't suppress.
- **`make tsan-ci`** — opt-in smoke: a small set of fast, thread-spawning
  groups (supervisor / workpool / mailbox / parallel fold / parallel
  validation / net bootstrap / cpu topology) with
  `TSAN_OPTIONS=halt_on_error=1` so the first report fails the run.
  Deliberately **not** wired into `make ci` (instrumented runs are several
  times slower and push times must stay stable). Override the set with
  `TSAN_CI_GROUPS="..."`.
- **`make dev-tsan`** — the dev node under TSan
  (`build/bin/z23-dev-tsan`, `-Og`, non-LTO, object tree
  `build/dev-tsan-obj/`). For local data-race debugging on a scratch
  datadir; race reports go to stderr.

`t-tsan` and `tsan-ci` both read `tools/tsan.supp` via
`TSAN_OPTIONS=suppressions=...`. Every active entry there must be confirmed
benign with a written justification — never suppress an untriaged report. It
ships with zero active suppressions (comments only): fix a real race in code,
never hide it behind a suppression.

`thread_liveness_child.id` (`lib/util/src/thread_liveness.c`) is
`_Atomic supervisor_child_id`, release-stored after `supervisor_register()`
completes and acquire-loaded by every reader (beat, worker_alive/_exited,
stop_begin/_finish, retire, idempotent guards) — a worker observing a valid
id also observes the completed registry insertion. `tsan-ci` runs the
7 thread-spawning groups 3x for timing sensitivity. A full-suite TSan pass and
a `dev-tsan` boot on a scratch datadir remain open (`tsan-ci` covers only a
thin, short-unit-style subset with small race windows).

Both runners wrap the harness in `setarch -R` (ASLR off): TSan reserves
fixed shadow address ranges and the default-ASLR PIE/mmap placement
intermittently collides at startup (`FATAL: ThreadSanitizer: unexpected
memory mapping`). These are opt-in triage binaries, never release artifacts,
so no-ASLR is an acceptable trade.

## Prerequisites

`make doctor` is the authority: it probes the host against
`tools/scripts/vendor_prereqs.tsv` and prints one install line for exactly what
is missing. That table is machine-checked against every `need <tool>` call in
`tools/scripts/build_vendor.sh`, so a new vendor prerequisite cannot appear
without the doctor learning about it. Prose here can only describe it.

- **Node build:** **gcc 14+** (or clang with a working `-std=c23`), **GNU
  make**, **git**.
- **`make vendor`:** `ar`, `nm`, `sha256sum`, `tar`, `unzip`, `patch`, `perl`
  (OpenSSL's `Configure` is a perl program), and `curl` **or** `wget`.
- **No Rust toolchain or library.** Sapling send and receive are native C23,
  including Spend and Output proof creation, binding signatures, consensus
  verification, note encryption, and outgoing recovery. Fixed vectors derived
  from historical implementations remain inert test data; there is no in-tree
  path that fetches, builds, or links Rust.
- **A C++ compiler is needed only for test/dev differential oracles.** The
  shipped `z23` node is compiled as C23, reads legacy LevelDB through the
  in-tree C23 reader, and does not link `libleveldb` or `libstdc++`. A focused
  `make z23` therefore needs no C++ compiler. The full test/dev build
  still builds pinned LevelDB with `c++`/`g++` so the native reader can be
  checked byte-for-byte against the upstream implementation.
- **Not needed:** `autoconf`. The zlib and libevent tarballs ship a generated
  `./configure`; `make vendor` runs it and never regenerates it.
- The first `make vendor` needs **network access** for the pinned tarballs.
  Every later build is offline.
- For the embedded Tor onion service (optional): run `make tor-full`. It
  initializes the pinned `vendor/tor` submodule, configures a self-contained
  embedding profile without optional host-library integrations, and
  incrementally produces the four archives the node links. Otherwise the node
  links the in-tree `libtor_stub.a` that `make vendor` builds from
  `vendor/tor_stub.c`.

## Vendored archives

`make vendor` produces every archive below. **Source class** is either
*in-tree* (a source file already in the repo) or *fetched* (pulled from the
pinned URL, verified against the pinned SHA256 in
`tools/scripts/build_vendor.sh`, then built static). `./tools/dep_audit.sh`
(`make audit`) re-detects versions from the built archives and checks each
against its minimum-safe version.

| Archive | Upstream | Version | Source class | Origin |
|---|---|---|---|---|
| `libsecp256k1.a` *(committed)* | Bitcoin Core secp256k1 | fork | in git | https://github.com/bitcoin-core/secp256k1 |
| `libtor_stub.a` | Tor stub (`vendor/tor_stub.c`) | — | in-tree (built) | https://github.com/RhettCreighton/tor |
| `libcrypto.a`, `libssl.a` | OpenSSL | 3.0.16 | fetched + built | https://github.com/openssl/openssl |
| `libevent.a`, `libevent_openssl.a`, `libevent_pthreads.a` | libevent | 2.1.12 | fetched + built | https://github.com/libevent/libevent |
| `libleveldb.a` | LevelDB | 1.23 | fetched + built | https://github.com/google/leveldb |
| `libsqlite3.a` | SQLite (amalgamation) | 3.49.0 | fetched + built | https://www.sqlite.org/ |
| `libz.a` | zlib | 1.3.1 | fetched + built | https://github.com/madler/zlib |

That is 10 archives: nine source builds plus the committed
`libsecp256k1.a`.

Notes:
- **OpenSSL pinned to 3.0.16** — the project's minimum-safe floor (the older
  vendored 3.0.13 was below it). `make audit` reports the version.
- **libevent 2.1.12** carries the pinned, digest-bound
  `vendor/patches/libevent-2.1.12-secure-rng-abi.patch`. It preserves the
  public `evutil_secure_rng_add_bytes` symbol required by embedded Tor on
  newer glibc systems where libevent otherwise omits it; the vendor builder
  asserts the symbol before installing the archive.
- **LevelDB 1.23** is built, while the committed `vendor/include/leveldb/*.h`
  headers are 1.18. That is intentional and safe: the repo uses only LevelDB's
  stable C API (`<leveldb/c.h>`), which is unchanged across 1.18→1.23, so the
  headers and the built library stay compatible. `cmake` is used when present;
  otherwise `tools/scripts/build_vendor.sh` builds the same static source set
  directly with a C++11 compiler and a generated POSIX `port_config.h`. Final
  node links still use `cc`; the Makefile asks `c++` for libstdc++'s directory
  and adds it to the linker search path so mixed distro compiler packages do
  not break cold remote builds.
- **SQLite 3.49.0** amalgamation; `make vendor` also refreshes
  `vendor/include/sqlite3.h` and `vendor/sqlite3.c` so the rest of the build
  (e.g. `tools/sqlq.c`) stays in sync.
- **Historical external reference vectors are inert data.** They retain their
  source attribution for auditability, but no historical prover is fetched,
  built, or linked by Z23. Wallet proving and consensus verification
  stay in C23.
- Downloads are cached under `vendor/.cache/` (gitignored); build trees live in
  `vendor/.build/` (removed on a clean full run). To bump a version, edit the
  pinned version + SHA256 in `tools/scripts/build_vendor.sh`.
- **X11 compile-time headers are vendored, not a system dependency.** The
  presentation layer (`lib/presentation`) compiles the vendored RGFW single
  header, which `#include`s `<X11/…>` on Linux even though X11 itself is
  loaded at *runtime* by the vendored XDL layer (`-ldl`, no link-time
  `libX11`). The exact 17-header closure those includes need is committed
  under `vendor/x11/` (X.Org MIT license, verbatim upstream, SHA256-pinned and
  checked by `make check-vendor-provenance`), and the build adds
  `-Ivendor/x11/include`. A headless host with **zero** X11 `-dev` packages
  therefore builds the full binary; only the runtime `libX11.so` matters, and
  only when a window is actually opened.
<!-- claim: file-present vendor/x11/SHA256SUMS # vendored X11 header pin -->
<!-- claim: symbol-present vendor/x11/include Makefile # the include wiring -->

### Native instruments and deterministic text

The AI conversation is the default user interface. Status, proofs, diffs, and
explanations should be returned directly as typed data or plain text; a command
must not open a window merely because a visual instrument exists. Open native
pixels only for an explicit visual need, such as a QR code, image/media preview,
or direct manipulation/confirmation that is materially clearer on screen. The
agent returns to the conversation after that bounded interaction.

The primary visual path is the bounded renderer-neutral C23 model in
`lib/presentation`. A typed `app presentation ...` command submits that inert
model to the warm same-binary native host; the host owns pixels and bounded
input events, never node, wallet, package, publication, network, or consensus
authority. No browser or web runtime participates.

Every admitted model also has a deterministic paged plain-text companion from
the same C23 model. Add `"output":"text"` to the command input to receive it
without opening a window or requiring `DISPLAY`; add the zero-based
`"page":N` when the reply names more than one page. For example:

```bash
build/bin/z23 app qr show \
  --input='{"payload":"zclassic:t1...","output":"text"}'
build/bin/z23 app presentation show \
  --input='{"kind":"status","request_id":"check-1","title":"Node",\
"items":[{"kind":"key-value","label":"tip","value":"3216084"}],\
"output":"text"}'
build/bin/z23 app presentation corpus \
  --input='{"output":"text"}'
```

QR payloads are split only at the model's existing exact 256-byte chunk
boundaries. Structured instruments use one complete item per page and repeat
the bounded actions and authority label, so no row or decision is silently
truncated to fit the command-result ceiling.

The corpus instrument calls the existing
`zcode commons corpus status` reader rather than scanning source or creating a
second projection. Signed-checkpoint counts and the exact checkpoint root are
shown as corpus facts. Metrics that the canonical checkpoint does not yet bind,
including downstream-used LOC and cross-checkpoint velocity, are named
`unavailable` instead of being inferred from repository or agent state.

### C23 node and the C++ differential oracle

`libleveldb.a` remains only as a test/dev oracle. Nothing in the shipped node
uses LevelDB's C++ implementation; legacy bootstrap reads route through the
`ldbr_*` C23 API, while live state and block-index status durability use the
SQLite/event-sourced stores.

The replacement is in the tree and proven: **`lib/storage/src/ldb_reader_*.c`
is a read-only LevelDB reader written in C23** against stock `cc` and libc,
with no new dependency. It reads the real format — CURRENT, the MANIFEST
VersionEdit log, `.log` write-ahead logs, and `.ldb`/`.sst` tables — and
resolves sequence numbers and tombstones the way LevelDB does. Its contract,
including what it deliberately refuses, is documented in
`lib/storage/include/storage/ldb_reader.h`.

Byte identity is the acceptance bar, and it is checked differentially rather
than asserted:

```bash
make ldb_verify_c23
# both directories must be COPIES: the C++ open MUTATES its target
build/bin/ldb_verify_c23 /path/to/copy-a /path/to/copy-b
```

`tools/ldb_verify_c23.c` links **both** implementations, walks the entire
ordered keyspace comparing every key and value byte for byte, then sweeps
point reads (present and absent keys) and seek positions. It is the tool to
re-run against any datadir before trusting the reader on it. The in-suite
regression is `make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=ldb_reader`, which builds its own fixture with
overwrites, tombstones and unflushed log writes, compares it against
`libleveldb.a`, and then damages five different ways to confirm each is
refused by name rather than answered wrongly.

The release link runs `tools/scripts/check_c23_node_binary.sh` before atomic
publication. The gate rejects GTK/WebKit, `libstdc++`, C++ ABI symbols, and any
other unexpected dynamic dependency. On Linux the published executable may
use only the glibc runtime family and the ELF loader: libc/libm, plus the
separate libpthread/libdl DSOs required before those interfaces merged into
libc in glibc 2.34. All project dependencies are pinned static archives. It
also rejects any required symbol newer than
`GLIBC_2.38`, so building on a newer developer workstation cannot silently
produce an artifact that fails on supported deployment hosts. Build releases
with the oldest supported toolchain/sysroot; never raise the ceiling merely to
make a red build green. `tools/ldb_verify_c23.c` deliberately keeps linking
both readers: an independent oracle you delete cannot catch a native-reader
regression.

The canonical x86-64 portable build supplies that old userspace boundary even
on a newer workstation. The short operator command and its explicit alias are
identical:

```bash
make portable                 # recommended: build + old-loader runtime proof
make c23-portable-release     # same target, explicit name for automation
# or install the same four audited products
make c23-portable-install PREFIX="$HOME/.local"
```

It checksum-verifies three pinned Debian packages (the glibc 2.31 pair comes
from an immutable Debian snapshot), extracts the sysroot under ignored
`build/toolchains/`, rebuilds every
static archive linked by the node through the ordinary host C23 compiler, and
then builds and audits the node, RPC client, offline package signer, and
confined package verifier. The gate caps every product at GLIBC 2.31 and runs
the node's typed command discovery through that exact old loader and libc. It
also repeats that proof on QEMU's baseline `qemu64` CPU when `qemu-x86_64` is
already installed; QEMU is optional and reported rather than downloaded. It
needs no container, root, Zig, or
alternate-language compiler. Unlike the faster default developer build, this
release front door forces the original x86-64/SSE2 CPU baseline with generic
tuning; AVX2, FMA, BMI2, and host-specific instructions are not installation
requirements. The baseline intentionally uses the default Tor stub; a real
embedded-Tor release must build Tor and its static dependencies through the
same supported sysroot before linking. Other CPU architectures require their
own pinned sysroot and independently reproduced artifact; this target does not
mislabel an x86-64 executable as architecture-neutral.

Warm production boots also avoid rescanning the entire rebuildable
`progress.kv` projection store. A successful projection WAL checkpoint and
close writes a single-use `progress.kv.clean` receipt bound to the exact inode,
size, timestamps, and SQLite header counters. An unchanged WAL-free reopen
consumes that receipt and skips the O(file-size) `quick_check`. A crash,
non-empty WAL, malformed receipt, replaced file, or any in-place write takes
the full timed integrity scan and existing quarantine/rederive path. Never copy
the receipt independently of its database; a mismatch is intentionally treated
as a dirty boot.

### Verify

```bash
make audit          # tools/dep_audit.sh — versions vs minimum-safe CVE floors
make -j"$(getconf _NPROCESSORS_ONLN)" build-only  # compile every .o (no link) — should be clean
make -j"$(getconf _NPROCESSORS_ONLN)" dev-bin     # fast non-LTO local node binary: build/bin/z23-dev
make vendor         # build the vendored archives from source
make z23     # full link
```

## Build, test, deploy

```bash
make -j"$(getconf _NPROCESSORS_ONLN)"   # test_zcl + z23 + zclassic-cli
make -j"$(getconf _NPROCESSORS_ONLN)" dev-bin  # fast local node executable, not for deploy/release
make -j"$(getconf _NPROCESSORS_ONLN)" test     # full parallel suite via the cached per-TU test_parallel
make -j"$(getconf _NPROCESSORS_ONLN)" test_parallel_wpo  # whole-program LTO test binary (debug per-TU/LTO divergence)
make lint           # every defensive-coding gate; it prints the list it ran
make ci             # local gate: lint + tests + MVP slices (runs locally, not on GitHub Actions)
make deploy         # rebuild + restart; verify exact source ID and running executable SHA-256
make deploy DEPLOY_VERIFY_STAGE=challenger  # owner-only: activate exact bytes without claiming stable health
```

Warm fleet upgrades build and gate once, then activate the exact frozen daemon
and package-verifier bytes sequentially. Every remote must already run the
canonical `zclassic23` user service:

```bash
ZCL_SHIP_HOSTS='user@node1 user@node2 user@node3 user@node4' make ship
```

All remotes are ordinary serving peers unless one exact destination is named
with `ZCL_SHIP_PROOF_SERVER`. That host is skipped by default; an intentional
promotion additionally requires `ZCL_SHIP_ALLOW_PROOF_SERVER=1`. Preflight
requires the complete x86-64-v3 CPU feature set. After the candidate is built,
its maximum required GLIBC symbol version must be no newer than every target's
installed glibc; target versions need not equal the build host. Each activation
qualifies the running `/proc/<pid>/exe` bytes and status before the next host is
touched. A failure restores that host's prior daemon, identity, and workers and
stops the rollout.

This page deliberately does not state how many defensive-coding gates exist.
That number changes whenever a gate lands, and every copy of it in prose has
gone stale within weeks. The authoritative list is the `LINT_GATES` variable in
the `Makefile`; the same list is mirrored, and machine-checked against the
Makefile by the `check-doc-accuracy` gate, in the `<!-- LINT-GATES-BEGIN -->`
block of [`DEFENSIVE_CODING.md`](DEFENSIVE_CODING.md). To see what runs on your
tree, run `make lint` and read what it names, or print the list itself:

```bash
awk '/^LINT_GATES[[:space:]]*:=/{f=1} f{print; if ($0 !~ /\\[[:space:]]*$/) exit}' Makefile
```

`make deploy` pins its outer `BUILD_SOURCE_RECORD` into every recursive Make,
captures the running executable inode for rollback before the forced relink,
then freezes one candidate before any install or restart. Candidate-local
`agentbuild`, the current source record, the installed executable digest, and
the post-restart digest must all identify that same source/artifact pair. The
post-restart verifier ignores inherited `ZCL_DATADIR`, `ZCL_RPCPORT`, and
`ZCL_RPCCONNECT`: it derives the loopback RPC endpoint from the canonical
systemd service's captured `MainPID`/`ExecStart`/process argv, confirms that PID
owns the RPC listener, and rejects a PID or executable change during the proof.
The default `stable` stage also requires a healthy verdict. An owner maintaining
a node with already-named health blockers may explicitly select `challenger`;
that still proves exact bytes, process identity, RPC/P2P diagnostics, evidence
consistency, and a tip gap no greater than one, while clearly withholding any
stable-health claim. Invalid stage names fail before the relink.

The default developer target is `-march=x86-64-v3` (AVX2/FMA/BMI2); pass
`ZCL_NATIVE=1` to build for the host CPU only. Use `c23-portable-release` for
the wider original-x86-64 deployment baseline described above.

## Reproducible / signed releases

`tools/release.sh` does not build, package, sign, or publish anything. It
accepts exactly one invocation — `tools/release.sh --verify <archive.tar.gz>` —
which checks an *already existing* signed archive: it requires a sibling
`.sha3` manifest and a detached `.sha3.sig`, recomputes the archive's SHA3-256
and compares it to the manifest, verifies the GPG signature over the manifest,
confirms the tar structure is readable, and then prints
`legacy_local_artifact_verification=PASS`, `stable_release_verification=NOT_IMPLEMENTED`,
`publishable=false`. Every other invocation — including any attempt to produce
an artifact — prints a REFUSING message and exits 2, before touching the
workspace.

That refusal is the current release posture, not a missing feature. Stable
release publication stays contained until exact-candidate evidence, two
independently provisioned byte-identical builds, complete manifests/SBOM/
provenance, and the required offline signatures are all enforced. For a local
binary, use the ordinary build targets above. See
`docs/SECURITY_AND_INTEGRITY.md` for the integrity model.
