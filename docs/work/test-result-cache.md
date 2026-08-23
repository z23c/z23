# Content-addressed per-group test result cache

Bazel-style caching for `make test-parallel`: a test **group** is returned from
cache — never forked — when its exact transitive **input closure** is
byte-identical to the last time that group passed. Editing one leaf re-runs only
the handful of groups downstream of it; every unrelated group is a ~0-time cache
hit.

## The invariant: a run says what it actually did

The cache is **OFF by default** today. That default is scheduled to flip to ON
everywhere, so "the gate is cold by construction" is being replaced by "a run
cannot misreport whether it was cold."

Every run prints one machine-greppable line **before** any verdict word:

```
SUITE VERDICT mode=<cold|cached> groups_total=N groups_ran=N groups_cached=N \
  groups_gated=N groups_failed=N self_skips=N toolkey=<hex12>
```

`groups_ran` is the count actually forked, and it is the first number to read.
Only a skip-free fresh PASS is stored; a zero-exit group that prints `SKIP (`
never becomes a reusable PASS. The v3 key domain retires older records that
could have been stored before this rule existed.
Only a **cold** run prints the bare token `ALL TESTS PASSED`; a cached run prints
`ALL TESTS PASSED (CACHED)`. `tools/scripts/gate-and-report.sh` reads the
`SUITE VERDICT` line, rejects anything whose `mode` is not `cold`, and rejects
the `(CACHED)` headline explicitly.

This matters because the old headline printed `ALL TESTS PASSED — 0/743 groups
failed` whether 743 groups ran or 1 ran and 742 came from cache: `pre_skipped`
counted only `--only` filtering and the params gate, never cache hits. The gate
grepped exactly that string, so a run that executed nothing reported `GATE OK`.

The runner also prints, **before dispatch**, the cache plan and a histogram of
uncacheable reasons — that histogram is how a whole-run degradation (an absent
include graph making every group uncacheable, say) becomes visible instead of
looking like a normal cold run.

The resident save loop uses the narrower internal form
`--cache --cache-snapshot --changed-source=<path>`. It opens the already
verified code-index snapshot instead of rebuilding it in the feedback process.
That is safe only under a fail-closed rule: if a group's old forward closure
contains any changed translation unit, that group is uncacheable and runs
fresh (`changed-input-runs-fresh`). Only an old closure that excludes every
changed source may reuse an exact PASS. A missing snapshot, an empty changed
set, or an invalid path disables the cache; it never falls back to a smaller
key. This form is resident-loop plumbing, not a substitute for the ordinary
fresh-index and cold-audit gates.

`make ci`'s single retry on a `test_parallel` failure runs `--no-cache`. Its
justification — "a real regression fails BOTH passes" — holds only while both
passes execute the same groups. With the cache on, pass 1 would store a `PASS`
for the ~742 groups that succeeded, pass 2 would skip those and re-run the
failing group alone on an unloaded box, and a lucky result would be stored — so
the group would be skipped forever. Forcing the retry cold keeps it an
independent second opinion instead of a flake-laundering machine.

## Using it (inner dev loop)

```bash
ZCL_TEST_CACHE=1 make test-parallel   # opt in: skip unchanged groups, store passes
make test-parallel                    # default: cold, runs everything
make test-parallel TEST_PARALLEL_ARGS=--no-cache   # force cold even if ZCL_TEST_CACHE set
```

The canonical full suite remains cold by default. The mapped `make pre-push-ci`
lane deliberately enables the cache for its exact focused set and then
validates the runner's machine verdict: every selected group must be accounted
for as freshly run or reused, failures and runtime SKIPs must both be zero, and
the toolchain key must be present. `z23-dev dev begin` can populate those exact
receipts asynchronously during editing; `z23 dev status` shows the native cycle
receipt. Unbounded-input and stale/missing dependency-graph groups are never
reused.

The final summary gains one line: `cached N / ran M`, and the run reports its
plan and reason histogram up front. `.cache/test-timing/last-run.json` carries
`mode`, `groups_ran`, `groups_cached`, `groups_cacheable`, `toolkey`, and a
per-group `cached` flag.

### Where the include graph comes from

Every depfile the build writes lands in a per-build compile epoch,
`build/*/epochs/<epoch>/`. Each build mints a new epoch and the previous few are
retained, so the directory holds immutable receipts of trees that are no longer
checked out; reading them all duplicates every edge and inflates a warm lookup
to tens of thousands of files.

`tools/dev/build-epoch-session.sh` names the live generation in
`<object-root>/.current-epoch` while holding the lock that mints the epoch
directory and hands out the compile lease. Every profile reaches a compiler only
through that acquire, so the name and the build cannot disagree, and
`collect_dep_paths()` in `lib/codeindex/src/codeindex_deps.c` reads an
epoch-managed object root through that name and through nothing else — retained
generations stay out, and so do the pre-epoch `.d` files still sitting loose in
the old flat object roots.

This is what used to break the cache. The collector skipped any directory called
`epochs`, which by then was where the whole graph lived: measured in a worktree
after `make build-only` plus `make -j`, **0 of 3,111** depfiles were visible and
every group reported `no-include-graph`. The cache failed **closed** on it
(`no-include-graph` / `input-newer-than-include-graph`, both in the histogram),
so it never produced a wrong skip — it just never produced a hit either.

The cache asks the graph for its own inventory
(`codeindex_depfile_graph()`) instead of walking `build/` a second time. The
private copy it used to keep is what let the two answers drift apart in the
first place.

Inspect what a group keys on (the operator/proof lens):

```bash
ZCL_TEST_CACHE_DUMP=test_hkdf_sha256_rfc5869 <test_parallel binary>
# prints the toolchain key, the content key, cacheable=yes/no, and the closure
```

## How the key is computed

For group `test_<x>` the key is `SHA3-256` over, in order: a domain tag; the
compiled-in **toolchain + compile-flags fingerprint**; the **coverage-gating
environment digest**; the group name; and, for every file in the group's
**forward (callee) input closure** sorted by path, the file's path and its
`SHA3-256` content hash.

The forward closure is `codeindex_forward_closure()`
(`lib/codeindex/src/codeindex_impact.c`) — the mirror of the `code impact`
reverse-closure engine. From the entry symbol it walks the callee call graph and
collects every in-tree file that **defines** a reachable symbol, plus every
in-tree prerequisite those files pull in (compiler depfile edges — headers *and*
the `*.def` X-macro registries, which are prerequisites exactly like headers). A
stored `PASS` record addressed by the key lives in the `.zvcs` object store
(`vcs_object_put_addressed`); only `PASS` is ever stored.

### The toolkey binds the FLAGS, not just the compiler

`BUILD_COMPILER_ID` (`tools/dev/build-epoch-key.sh compiler-id`) fingerprints the
`CC`/`CXX` argv and the tool bytes — **never the flags**. `TEST_FAST_CFLAGS`
compiles at `-O1` and `TEST_REL_CFLAGS` at `-O3`, so using it alone put both
profiles in ONE keyspace and a `PASS` recorded by `make t-fast` was honored,
unexecuted, by the release gate binary. The toolkey is now a digest over the
compiler id **plus the profile name plus that profile's effective compile
flags**, injected per-object as `-DZCL_TESTCACHE_TOOLKEY` for the fast, release
and ASan trees (the ASan tree used to get no define at all and silently fell back
to `__VERSION__`).

The epoch machinery's own digest (`zcl_compile_epoch`) is deliberately **not**
reused as the toolkey: it binds `BUILD_SOURCE_ID` and `BUILD_MUTATION`, so it
changes on every source edit and would bust the entire cache every time.

### The environment is in the key

About 16 groups `return 0` from a `SKIP (set ZCL_STRESS_TESTS=1 ...)` path. Their
source bytes are identical whether the stress lane ran or not, so a normal run
stored a `PASS` for the *skipping* variant and a later `ZCL_STRESS_TESTS=1` run
got a cache HIT and never executed the stress lane — reporting green for coverage
that did not run. Every `ZCL_`-prefixed variable (plus `HOME`, `EQUIHASH_TEST`,
`REDUCER_FUZZ_SEED`) is therefore hashed into the key. Hashing beats denylisting
those 16 groups: it is exhaustive by construction and cannot rot when someone adds
the 17th gate. The cache's own controls (`ZCL_TEST_CACHE`,
`ZCL_TEST_CACHE_DUMP`) and the `ZCL_FAST_*` orchestration namespace are excluded.
Fast-CI's frozen source identity, changed-path hints, compiler selection and
scheduling knobs change no group's verdict; source bytes and toolchain/flags are
already bound directly. Folding those controls into the environment digest
would globally invalidate every unrelated receipt after any edit or docs-only
rebase.

## Soundness: a cached SKIP is provably equivalent to a fresh PASS

A group is **UNCACHEABLE (always runs)** when its inputs cannot be bounded:

- the forward closure came back `truncated` (a cap / fan-out / depth limit, or a
  closure path too long for the caller's row),
- the entry symbol does not resolve in the code index,
- the group is on the **external-input denylist** — it reads fixtures, the live
  node DB, an external `zclassicd`, `~/.zcash-params`, a legacy datadir, or (the
  load-bearing case) **execs a built binary**, whose behavior comes from the
  whole link and which the forward source closure never reaches
  (`group_reads_external_inputs()` in `lib/test/src/testcache.c`). Matching is on
  the **exact** group name — the previous `strstr()` form could not list `net`
  without also swallowing `netmask`/`subnet`/`net_bootstrap`, which is exactly
  why `test_net` went uncovered,
- **the include graph is absent** — no depfiles under `build/`. Zero include
  edges is not "a closure with no headers", it is *no closure*: a strictly
  smaller set that is never flagged `truncated` and therefore looks complete. On
  a fresh clone or after `make clean`, every key would otherwise cover zero
  headers,
- **an input is newer than the include graph** — if any closure file's mtime is
  newer than the newest depfile the graph was built from, the graph cannot
  describe that file, so an include added since is invisible to the key.
- **the resident snapshot closure reaches an edited translation unit** — its
  prior edges cannot describe the edited body, so that group runs fresh. The
  snapshot may serve only groups proven unrelated by the prior closure.

The one residual assumption is the standard one for any source-based
"affected-tests" analysis: the call graph captures a test's dependency edges by
name (an indirect/function-pointer/dlopen edge is invisible to source scanning,
exactly as it is to `code impact`). That assumption is backed by:

**`--cold-audit`** — runs *every* group fresh (cache disabled for execution) and
asserts that every group carrying a stored `PASS` at its current key also passes
the fresh run. A divergence is a closure/cache soundness bug and fails the run
loudly:

   ```bash
   ZCL_TEST_CACHE=1 make test-parallel                        # populate
   make test-parallel TEST_PARALLEL_ARGS=--cold-audit         # verify: 0 divergences
   ```

## Files

- `lib/codeindex/src/codeindex_impact.c` — `codeindex_forward_closure()`.
- `lib/test/src/testcache.c` + `lib/test/include/test/testcache.h` — the cache.
- `lib/test/src/test_parallel.c` — dispatch wiring, `--cache/--no-cache/--cold-audit`.
- `lib/test/src/test_testcache.c` — the cache's own contract test group.
- `Makefile` — bakes `BUILD_COMPILER_ID` into `testcache.o` as the toolchain key.
