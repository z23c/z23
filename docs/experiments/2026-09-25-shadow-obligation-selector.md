<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Shadow proof-obligation selection

Measured 2026-09-25 on an AMD Ryzen 9 7950X3D (32 logical CPUs) with GCC
14.2.0. The base is `52bee3bb8c719de149512ea9fdebe94b239cdf2a`. The code
is on branch `lane/muse-shadow-select-20260925`.

This is a shadow experiment and it changes nothing about acceptance. Landing
proofs still run every lint gate and every test group their own selector
names. The code only reports what a narrower selector would have run, what
that would cost, and which of its skips a checked rule could defend.

## Standing and qualification

**A passing corpus is not a soundness argument.** Zero RED on 28 entries
shows only that none of these 28 changes, with these seeded bugs, found a
hole. It does not show that the prediction is a superset of the required
obligations for every change. Mandatory acceptance (all lint gates plus the
landing selector's groups, run fresh) stays in force.

Qualifying the rule for use in admission would need at least the following:

1. **A proof that the reverse-caller and reverse-include closure is
   complete for every premise class.** That includes calls through function
   pointers and registries, `extern` declarations without a header,
   generated headers, and negative lookups. Today the depfile and the
   codeindex cannot see a header that does not exist yet (see
   syn-negative-lookup).
2. **A contract root computed from exact header bytes and declared
   premises.** The token-normalized root used here is an approximation. It
   should be derived by the proof-ticket library, or by
   `zcl.proof_frontier.v1` once that exists, so that a macro, a layout or
   an assertion cannot move without moving the root.
3. **A component lookup key that binds every execution input separately.**
   The key must cover unit, dependency closure, negative lookups, generated
   inputs, ABI generation, fixtures, invariants and integration edges (see
   "Missing key inputs"). A carried verdict is receivable only when every
   input matches.
4. **Independent, signed caller verdicts.** A verdict written by the
   candidate's own uid is writable by the candidate, so under the fail-closed
   same-uid decision it is never eligible.
5. **A mutation campaign much larger than this corpus, run against the full
   reference and not a bounded one.** Every seeded bug caught by a skipped
   obligation must become a regression test.
6. **An independent review of `zcl_shadow_reuse_admit()` and
   `zcl_shadow_reuse_eligible()`.** Each condition in them must already have
   a refusal test (tests/harness/src/test_dev_shadow_select.c).

## What runs

The whole report comes from one test group,
`make t-fast ONLY=test_dev_shadow_select`. For each frozen corpus entry it
does the following:

- It reproduces the landing selector with the calls dev proof uses:
  `zcl_devloop_plan_files` → `zcl_devloop_plan_add_closure` →
  `zcl_devloop_plan_proof_admissible`, with families expanded via
  `zcl_test_group_family_expand`. A universal or refused plan becomes the
  whole host-admitted catalog.
- The reference is the full landing proof: all 213 lint gates plus every
  host-admitted test group. `check-windows-cross-syntax` is counted at full
  cost, and lint premise selection is out of scope.
- It builds a proof dependency graph that is kept apart from build
  dependencies. The graph has three layers:
  - CONTRACT: the groups the changed files name through the impact rules;
  - CALLER: groups reached by reverse-caller or reverse-include closure
    inside the component, or by an opaque rule;
  - INTEGRATION: groups reached through another component's file.
- It writes the prediction (`predicted.tsv`) before any reference run, and
  compares it with the reference run (`observed.tsv`).

Every obligation is classified in one of two ways:

- **source-sensitive**: the lint gates. These always rerun when a source
  they read changes.
- **image-sensitive**: the test groups. An unchanged output artifact may stop
  propagation to them. It never waives a source gate.

The prediction has three cases:

- **ALL** (the reference) when any fallback reason fires. The reasons are
  conflict, policy, dependency-change and unknown-scope.
- **The contract layer only** when the compositional rule holds: the
  contract root is unchanged, no other TU reads a changed private file, and
  the build graph is known. Callers and integration edges are carried.
- **Every selected group** otherwise.

Every lint gate always runs. A second column prices the six gates that
declare a premise by their select runs and fresh units (see "Lint premise
lever"); every other gate is billed at its full weight.

The compositional rule (`zcl_shadow_reuse_admit`) needs three things: an
unchanged contract root, a fresh PASS of the callee's contract obligations
on exactly the new implementation root, and caller premises that reference
only the contract. An unchanged ABI or an old PASS is not an input to the
rule. The test "unchanged ABI with an old PASS never admits reuse" pins that.

## Measured numbers

Report from `test_dev_shadow_select` at head `16655819e6`, rebased onto
`52bee3bb8c`. That run was a PASS with 0 skipped. Seconds are
cost-weighted fresh worker CPU.

| set | fresh obligations | fresh s/candidate: rule | landing selector | reference | savings (rule) | savings (selector) | critical path s (rule / reference) | validation s |
|---|---|---|---|---|---|---|---|---|
| real (20 narrow commits) | 6030 / 28120 | 2082.3 | 2456.0 | 6402.1 | 67.5% | 61.6% | 134.0 / 257.9 | 1.21 |
| synthetic (8) | 10072 / 11248 | 5804.4 | 2312.0 | 6402.1 | 9.3% | 63.9% | 241.6 / 257.9 | 0.16 |
| all (28) | 16102 / 39368 | 3145.7 | 2414.9 | 6402.1 | 50.9% | 62.3% | 164.7 / 257.9 | 0.91 |

**Totals: 3145.7 fresh worker-seconds per candidate for the rule and
2414.9 for the landing selector, against 6402.1 for the reference.** The
landing selector is cheaper than the rule only because it expands no
fallback. It is also the predictor with five false hits (see below).

**Savings that are eligible today are zero.** Every carried obligation is
refused as `execution_inputs_incomplete`: the lookup key omits unit and
dependency closure. With a complete key the same obligations would still
be refused as `same_uid_local_verdict`. The only verdicts a host holds are
its own uid's, and under the fail-closed decision those never stand in for
a run. So the eligible-now bill equals the reference, 6402.1 s per
candidate. The 67.5% figure on narrow edits is the ceiling that
independent signed verdicts plus a complete key would allow. It is not a
saving available now. No hit-rate target is set.

Where the rule's remaining fresh bill goes on the 20 narrow commits,
largest first:

| obligation class | fresh s (20 entries) | share of reference |
|---|---|---|
| lint gates (source-sensitive, always fresh) | 23231.1 | 18.1% |
| contract layer of the changed unit | 8081.8 | 6.3% |
| fallback to reference (real-18, `unmapped-code-change`) | 5240.6 | 4.1% |
| additive contract or private reader, selected set kept (real-03, -12, -14, -19) | 5091.6 | 4.0% |

The contract layer includes the 13-group `make_lint_gates` family, which
the impact rules attach to every C change: about 328 s per candidate. Lint
premise selection is out of scope here; `check-windows-cross-syntax` is
being made reusable in a separate lane and is counted at full cost.

Per entry. Obligations are 213 lint gates plus 1193 host-admitted test
groups; seconds are per candidate:

| entry | kind | contract | fallback | predict | fresh / total | rule s | selector s | reference s | savings (rule) | critical path s (rule / reference) | name-only s |
|---|---|---|---|---|---|---|---|---|---|---|---|
| real-01 | real | none | none | exact | 239/1406 | 1954 | 2012 | 6402 | 69.5% | 128 / 258 | 0 |
| real-02 | real | none | none | exact | 242/1406 | 2054 | 2054 | 6402 | 67.9% | 128 / 258 | 0 |
| real-03 | real | additive | none | exact | 256/1406 | 2127 | 2127 | 6402 | 66.8% | 128 / 258 | 0 |
| real-04 | real | none | none | exact | 234/1406 | 1519 | 3622 | 6402 | 76.3% | 128 / 258 | 2103 |
| real-05 | real | none | none | exact | 231/1406 | 1633 | 1659 | 6402 | 74.5% | 128 / 258 | 26 |
| real-06 | real | none | none | exact | 232/1406 | 1634 | 2466 | 6402 | 74.5% | 128 / 258 | 26 |
| real-07 | real | none | none | exact | 232/1406 | 1644 | 2266 | 6402 | 74.3% | 128 / 258 | 52 |
| real-08 | real | none | none | exact | 241/1406 | 1980 | 2254 | 6402 | 69.1% | 128 / 258 | 0 |
| real-09 | real | none | none | exact | 234/1406 | 1692 | 1718 | 6402 | 73.6% | 128 / 258 | 26 |
| real-10 | real | none | none | exact | 230/1406 | 1522 | 2409 | 6402 | 76.2% | 128 / 258 | 26 |
| real-11 | real | none | none | exact | 230/1406 | 1522 | 2409 | 6402 | 76.2% | 128 / 258 | 26 |
| real-12 | real | additive | none | exact | 300/1406 | 2823 | 2823 | 6402 | 55.9% | 128 / 258 | 44 |
| real-13 | real | none | none | exact | 235/1406 | 1709 | 2213 | 6402 | 73.3% | 128 / 258 | 0 |
| real-14 | real | additive | none | exact | 260/1406 | 2430 | 2430 | 6402 | 62.0% | 128 / 258 | 26 |
| real-15 | real | none | none | exact | 235/1406 | 1709 | 2247 | 6402 | 73.3% | 128 / 258 | 0 |
| real-16 | real | none | none | exact | 239/1406 | 1954 | 2079 | 6402 | 69.5% | 128 / 258 | 0 |
| real-17 | real | none | none | exact | 226/1406 | 1489 | 2085 | 6402 | 76.7% | 128 / 258 | 596 |
| real-18 | real | none | unknown-scope | all | 1406/1406 | 6402 | 6402 | 6402 | 0.0% | 258 / 258 | 0 |
| real-19 | real | additive | none | exact | 302/1406 | 2358 | 2358 | 6402 | 63.2% | 128 / 258 | 28 |
| real-20 | real | none | none | exact | 226/1406 | 1489 | 1489 | 6402 | 76.7% | 128 / 258 | 0 |
| syn-header-decl | header_decl | moved | unknown-scope | all | 1406/1406 | 6402 | 1861 | 6402 | 0.0% | 258 / 258 | 26 |
| syn-abi | abi | moved | unknown-scope | all | 1406/1406 | 6402 | 1861 | 6402 | 0.0% | 258 / 258 | 26 |
| syn-flag | flag | none | dependency-change | all | 1406/1406 | 6402 | 1489 | 6402 | 0.0% | 258 / 258 | 0 |
| syn-contract | contract | moved | unknown-scope | all | 1406/1406 | 6402 | 1861 | 6402 | 0.0% | 258 / 258 | 26 |
| syn-private-impl | private_impl | none | none | exact | 230/1406 | 1621 | 1861 | 6402 | 74.7% | 128 / 258 | 26 |
| syn-generated-input | generated_input | none | dependency-change | all | 1406/1406 | 6402 | 6402 | 6402 | 0.0% | 258 / 258 | 0 |
| syn-negative-lookup | negative_lookup | none | unknown-scope | all | 1406/1406 | 6402 | 1633 | 6402 | 0.0% | 258 / 258 | 0 |
| syn-macro | macro | moved | unknown-scope | all | 1406/1406 | 6402 | 1527 | 6402 | 0.0% | 258 / 258 | 0 |

## Where the fresh seconds go

Measured 2026-09-25 on the host above, on `lane/muse-shadow-reuse90-20260925`
from `e1cbb7fe4a`. The report comes from the same test group; that run was a
PASS with 0 skipped. The catalog now has 1194 host-admitted groups (1407
obligations with the 213 lint gates). **Everything here is a shadow
prediction.** Every lint gate and every selected group still runs in the
landing proof. Eligible reuse stays 0 until verdicts come from a separate
uid (see "Measured numbers").

### Classes

Each obligation the rule predicts fresh falls in exactly one class
(`SHADOW-CLASS` and `SHADOW-CLASS-TOTAL` lines):

- **lint**: the 213 lint gates;
- **floor**: the 13-group `make_lint_gates` family. The impact rules attach
  it to almost every change, and any path no rule maps falls back to it;
- **direct**: the rest of the contract layer, meaning the groups the
  changed files name through the impact rules;
- **caller** and **integration**: groups on those layers that the rule could
  not carry;
- **fallback**: every test group of an entry predicted ALL.

The real set is 20 narrow commits, 128,048 s of reference:

| class | fresh obligations (20 entries) | fresh s | s per candidate | share of reference |
|---|---|---|---|---|
| lint gates | 4260 | 23231.1 | 1161.6 | 18.1% |
| floor (`make_lint_gates` family) | 247 | 6226.5 | 311.3 | 4.9% |
| direct test groups | 167 | 4589.9 | 229.5 | 3.6% |
| caller test groups | 31 | 641.1 | 32.1 | 0.5% |
| integration test groups | 132 | 1715.9 | 85.8 | 1.3% |
| fallback to ALL (real-18) | 1194 | 5240.9 | 262.0 | 4.1% |
| **total** | **6031 / 28140** | **41645.4** | **2082.3** | **32.5%** |

Lint gates are 56% of the bill. Test groups outside the floor are 29%, and
the largest part of that is one ALL fallback.

### Top 15 fresh obligations

Fresh seconds summed over the 20 real entries (`SHADOW-TOP` lines). The
last column prices the seven premise-declaring gates by their select runs,
always-run parts and fresh units (re-measured at the lane head):

| rank | kind | obligation | fresh s | entries | fresh s with lint premise |
|---|---|---|---|---|---|
| 1 | lint_gate | `check-windows-cross-syntax` | 2550.1 | 20 | 410.6 |
| 2 | lint_gate | `check-windows-acceptance` | 2314.0 | 20 | 670.3 |
| 3 | lint_gate | `check-doc-claims` | 2035.4 | 20 | 2035.4 |
| 4 | lint_gate | `check-build-epoch-integrity` | 1615.0 | 20 | 1615.0 |
| 5 | test_group | `test_make_lint_gates_realroot` | 1548.1 | 20 | 1548.1 |
| 6 | test_group | `test_make_lint_gates_heavy_02` | 1482.6 | 20 | 1482.6 |
| 7 | lint_gate | `check-capability-closure` | 1418.4 | 20 | 1418.4 |
| 8 | lint_gate | `check-vcs-no-sha1` | 1078.7 | 20 | 1078.7 |
| 9 | test_group | `test_dev_platform_shard_01` | 949.5 | 9 | 949.5 |
| 10 | test_group | `test_dev_platform_shard_04` | 945.0 | 9 | 945.0 |
| 11 | lint_gate | `check-clang-portability` | 927.3 | 20 | 266.0 |
| 12 | lint_gate | `check-no-api-keys` | 857.1 | 20 | 289.7 |
| 13 | test_group | `test_dev_platform` | 750.5 | 9 | 750.5 |
| 14 | lint_gate | `check-zcode-package-registry` | 721.2 | 20 | 721.2 |
| 15 | lint_gate | `check-capability-inventory-generated` | 710.5 | 20 | 710.5 |

Ten of the fifteen are lint gates. Two are the floor's heaviest shards,
and three are the `dev_platform` family that the `tools/dev` rules name
directly.

### Lint premise lever

Base-relative lint premise selection (`z23-lint select --dry` and
`z23-lint unit-exec`, on main since `d77adf0fc7`) lets a unit keep the
base's PASS iff its premise bytes are unchanged. The premise covers gate
code, the toolchain pin, the Makefile text the gate reads, the path set,
the unit's closure and the unit's own baseline rows. Seven gates now declare
a premise in `tools/lint/lintc/selection_gates.def`:

- two per-TU gates from the first slice, `check-windows-cross-syntax` and
  `check-clang-portability`;
- four added by lane lint-premise-decl: `check-no-api-keys`,
  `check-fortify-masked-decls` and `check-raw-sqlite` per file (the unit
  premise is the file's own bytes), and `check-windows-platform-seam` per
  seam TU (the unit premise is the include closure);
- `check-windows-acceptance` per catalog row, added by lane winacc-split
  after splitting the gate (see "Splitting check-windows-acceptance").

That lane also widened what counts as gate code, for all six gates:

- every gate's premise now carries the lint driver (`tools/lint/run_lint.sh`
  and `tools/lint/lint_cache.sh`) and its own Makefile rule and recipe
  (`"gate:"` in make_vars). The first two declarations omitted both;
- a `dir/` entry names every path under it;
- every word of the gate's Makefile text that names a tree path is gate
  code. A gate run by `z23-lint` names `LINTC_SRCS`, so every source the
  binary is built from is in its premise;
- the include closure of every `.c`/`.h` gate file is gate code. A
  computed include there means no unit inherits (`gate-computed-include`).

The tool was run once per corpus entry and gate against a verified base
(real: `<commit>^`; synthetic: the patched `7a9f354f3f` against itself).
The z23-lint binary was built at `1b2d7bc5eb`. After the rebase onto main
that commit is `0868432a3e`, and the two trees differ only in
`docs/CAPABILITY_INVENTORY.jsonl`. The rows are
frozen in `tools/dev/fixtures/shadow_select/lint_premise.tsv`. The two
older gates' unit and fresh counts are unchanged on all 28 entries.

Each premise gate is priced as the measured select run plus
max(gate weight / units, 1 s) per fresh unit. The unit part is capped at the
whole gate once selection has run. A cold cross-syntax run spent 209 ms CPU
per unit, so 1 s per unit is about five times the mean. The select run is
always paid: 8.1–32.1 s wall per gate, mostly the `make` unit listing and
the private fetch.

Re-measured at the lane head. The reference is 6391.9 s per candidate there
and the rule 2081.7 s (67.4%). With the two first-slice gates only, the rule
would be 1949.2 s, 69.5%, as before:

| set | fresh s per candidate: rule | rule + lint premise (7 gates) | reuse: rule | two gates | six gates | seven gates | seven gates, one select run |
|---|---|---|---|---|---|---|---|
| real (20) | 2081.7 | 1831.4 | 67.4% | 69.5% | 70.1% | **71.3%** | 72.2% |
| synthetic (8) | 5795.5 | 5608.1 | 9.3% | 11.0% | 11.4% | 12.3% | 13.1% |

The six-gate columns are the lint-premise-decl lane's figures (1913.6 s real,
5666.2 s synthetic). The seven-gate columns add `check-windows-acceptance`
at its select run, its always-run part and its fresh rows. The one-run
column subtracts the per-gate select runs and adds one combined `select
--dry` over all seven gates, measured on the same 28 entries: 16.4–35.0 s
wall per entry, 21.0 s per candidate on the real set. That run shared the
host with the corpus builds, so it is slower than the six-gate run's
13.6 s.

The six gates cost 247.9 s per candidate at full weight. Priced per gate,
they cost 79.8 s: 68.3 s of select runs and 11.5 s of fresh units. Two of
the four new gates cost more to select than they weigh:
`check-fortify-masked-decls` is 11.6 s against 9.2 s, and `check-raw-sqlite`
is 10.6 s against 9.0 s. Their only benefit is as part of a combined run.
One `select --dry` run over all six gates pays the walk, fetch and hashing
once. It took 12.1–18.0 s wall per entry, 13.6 s per candidate on the real
set. That puts the six gates at 25.2 s per candidate, or 70.9%. The shadow
test prices the per-gate runs; the combined figure is computed from the same
rows plus the combined run times.

`check-windows-acceptance` weighs 115.7 s and is priced at 33.5 s per
candidate: 9.9 s of select run, 18.1 s always run and 5.5 s of fresh rows.
The always-run part is the global part (1.8 s) plus the private sqlite
archive (16.3 s CPU). The four rows that link that archive never inherit, so
the archive is built on every candidate. The rest of the weight, 97.6 s, is
shared among the 72 rows at 1.36 s each. `lint_premise.tsv` carries this
as a seventh column, `always_ms`, which is 0 for the other six gates.

Per gate on the real set, full weight and then with the premise (select +
always-run part + fresh units, s per candidate):

| gate | full | with premise | fresh units / units (20 entries) |
|---|---|---|---|
| `check-windows-cross-syntax` | 127.5 | 20.5 | 46 / 46778 |
| `check-clang-portability` | 46.4 | 13.3 | 49 / 46741 |
| `check-no-api-keys` | 42.9 | 14.5 | 8464 / 167884 |
| `check-windows-platform-seam` | 12.9 | 9.3 | 0 / 820 |
| `check-fortify-masked-decls` | 9.2 | 11.6 | 35 / 85704 |
| `check-raw-sqlite` | 9.0 | 10.6 | 22 / 93799 |
| `check-windows-acceptance` | 115.7 | 33.5 | 81 / 1440 (80 of them the always-fresh sqlite rows) |

`check-no-api-keys` goes fully fresh on real-20 (8428 units,
`gate-code:tools/lint/lintc/gate_hotfork_stories.c`). A `z23-lint` gate's
premise holds every source of the binary. So any edit to any lint gate
written in C reruns it whole. That is sound but coarse. Linking the gate
from its own sources would narrow it.

The premise tool's own fail-closed paths show up on the adversarial entries.
syn-negative-lookup creates a header, which changes the path set, so all
22152 units are fresh and the entry costs 64 s more than without selection.
syn-header-decl makes 65 units fresh, syn-abi 62 and syn-macro 22. syn-flag
now makes 42 fresh. The dropped `-DZCL_DEV_BUILD` is a Makefile edit, and
`check-windows-platform-seam` reads the whole Makefile as gate code, so all
41 of its units rerun. The per-TU gates still declare that define as outside
their premise.

#### Which gates can declare a premise

A gate is eligible only if its verdict is the conjunction of per-unit
verdicts. Each unit's verdict may read only that unit's premise plus inputs
that are the same for every unit: gate code, the toolchain, Makefile text,
the path set, or a whole baseline carried as gate code. A count floor over
the path set is eligible, since the path set is in every premise. These are
not eligible:

- a count, sum or registry over file contents;
- a graph closure;
- an "every X has a Y" rule;
- a gate that builds or runs tree binaries.

Every lint gate at 9 s or more per candidate is listed, heaviest first:

| gate | s/candidate | decision | reason |
|---|---|---|---|
| `check-windows-cross-syntax` | 127.5 | declared, per TU (first slice) | one mingw `-fsyntax-only` compile per TU; closure plus own baseline rows |
| `check-windows-acceptance` | 115.7 | **split; declared, per catalog row** | the global part (self-test, reconcile "every program on disk has a row", `make -n` over the whole cross-link) always runs, about 1.8 s; the mingw compile-and-link of each row reads only the tree paths its row names plus their include closures, shown under Landlock for all 68 rows with a finite premise. The 4 rows that link the private sqlite archive (built from the untracked, pinned `vendor/sqlite3.c`) never inherit <!-- doc-path-ok: untracked vendored amalgamation installed by build_vendor.sh --> |
| `check-doc-claims` | 101.8 | ineligible | a claim resolves against the whole tree (`git grep`), and gate-passes and gate-fails claims run other gates |
| `check-build-epoch-integrity` | 80.8 | ineligible | the depfile self-test includes the real Makefile (51 `$(shell)`, 48 `$(wildcard)`, `-include`s) and runs `make -n`; the epoch self-test uses `build/bin/zcc` and `/proc/loadavg` |
| `check-capability-closure` | 70.9 | ineligible | `nm` closure over build objects, a symbol registry and a coverage floor |
| `check-vcs-no-sha1` | 53.9 | **measured; ineligible, not split** | 99.9% of its CPU is the global part: the source-identity self-tests build a helper with the host `cc`, drive host `git` in sandboxes, and capture the whole real checkout, ignored inputs included. The only per-file part is the `z23-lint` scan, 0.04 s CPU. A split would add a select run and save nothing (see "check-vcs-no-sha1: measured, not split") |
| `check-clang-portability` | 46.4 | declared, per TU (first slice) | one clang compile per oracle TU; closure plus own baseline rows |
| `check-no-api-keys` | 42.9 | **declared, per file** | a regex scan of each tracked file's own lines; the skip list is gate code; the 1,000-file floor counts the path set |
| `check-zcode-package-registry` | 36.1 | ineligible | exact-once source ownership across the registry |
| `check-capability-inventory-generated` | 35.5 | ineligible | a whole-tree derivation compared with a generated file |
| `check-outparam-init-before-return` | 31.4 | ineligible | the in-scope type set is every `<T>_free` anywhere in the tree (`tools/lint/check_outparam_init_before_return.sh` line 720), with a floor over it |
| `check-no-wallclock-assertion` | 22.9 | ineligible | an allowlist-sum ratchet ceiling and a floor over matched content |
| `check-live-datadir-isolation` | 21.8 | ineligible | baseline sum ceilings |
| `check-doc-inline-paths` | 21.0 | ineligible | token-count floors over all docs (`fcount` ≥ 200, `dcount` ≥ 100, `tools/lint/check_doc_inline_paths.sh` lines 143–145) |
| `check-ship-remote-transaction` | 20.8 | not declared | a single whole-gate unit is plausible, but it runs tree-built binaries and its self-test reads the whole Makefile; unproven without a confined run |
| `check-command-input-keys` | 20.0 | ineligible | callee closure plus cross-leaf consistency |
| `check-retrieval-historical-evidence` | 19.8 | not declared | runs the tree-built `retrieval-eval` and `jsonq`; as for ship |
| `check-package-anatomy` | 19.3 | not declared | needs per-directory units, which the unit kinds cannot express yet |
| `check-no-live-lab-history` | 13.8 | ineligible | duplicate basenames across the tree, and reads of the git index |
| `check-windows-platform-seam` | 12.9 | **declared, per TU** | one mingw compile per seam file against its own baseline row; the gate reads the Makefile text directly, so the whole Makefile and the baseline are gate code |
| `check-no-adx-overclaim` | 12.6 | ineligible | a content-selected file set with a count floor, and `make print-includes` |
| `check-standalone-tools-link` | 12.0 | ineligible | links every Makefile tool |
| `check-read-leaf-no-boot-ceremony` | 11.1 | ineligible | call-graph closure |
| `check-host-gc-selftest` | 10.9 | ineligible | reads host `df` free space and runs the real `worktree_gc.sh` |
| `check-z23-release-install` | 10.7 | not declared | runs the tree-built bootstrap binary; as for ship |
| `check-cookbook` | 10.0 | ineligible | RUN rows execute `z23-dev` |
| `check-fortify-masked-decls` | 9.2 | **declared, per file** | each `.c` is comment-stripped and grepped for calls into the masked set; the set is measured from the toolchain alone |
| `check-raw-sqlite` | 9.0 | **declared, per file** | each finding is judged inside one file; the allowlist is read with comment and space stripping, so all of it is gate code; the only gating count is over the path set |

The 185 gates under 9 s (160.9 s per candidate together) were not
reviewed.

Two residuals sit outside every premise. The selector prunes `.claude`
and `vendor/raylib`, but both hold tracked files. `check-no-api-keys` scans
the two `.claude/skills` files, and `check-fortify-masked-decls` greps the
six `vendor/raylib` `.c` files. A unit-selected run must always scan those
fresh. The `.def` comments say so.

#### Soundness evidence

The z23-lint binary was built at `1b2d7bc5eb`, sha256 `1517b9cc…16ad`. For
each of the four new gates, the verdicts were compared three ways: the full
gate on the candidate, the full gate on the base, and the unit-selected gate.
The unit-selected gate keeps the base verdict for inherited units and runs
the fresh units.

- `check-no-api-keys` runs exactly the fresh units, plus the `.claude`
  residual, through its `ZCL_API_KEY_SCAN_FILES` entry.
- The other three have no file-list entry. A fresh unit's verdict is read
  from the candidate run's per-file report. A fully fresh unit set is the
  candidate run itself.

These are the checks the lane asked for:

- **(a) Agreement on the frozen corpus.** On all 28 entries × 4 gates the
  full gate, the base gate and the unit-selected gate were all PASS (112 of
  112). Two harness failures, not verdict disagreements, were rerun. On
  real-20 and syn-negative-lookup every `check-no-api-keys` unit was fresh,
  and the first harness passed all 8428 and 8435 paths in one environment
  variable (`Argument list too long`). With a fully fresh set taken as the
  full run, both agree. Their select rows reproduced exactly.
- **(b) Seeded violation in an unchanged file** (real-01, candidate
  `c472356ff2`). Each seed made its file fresh with
  `closure-changed:<file>`, next to the commit's own unit. The full gate
  and the unit-selected gate both FAILED on the seeded site:

  | gate | seeded file | fresh / units | full | selected |
  |---|---|---|---|---|
  | `check-no-api-keys` | `README.md` (a runtime-assembled `ghp_` token) | 2 / 8383 | FAIL | FAIL |
  | `check-windows-platform-seam` | `platform/modules/platform/src/clock.c` (a `fork()` call) | 1 / 41 | FAIL | FAIL |
  | `check-fortify-masked-decls` | `engine/services/src/address_index_service.c` (an unguarded `realpath` call) | 2 / 4289 | FAIL | FAIL |
  | `check-raw-sqlite` | `engine/services/src/replay_verify_service.c` (a `sqlite3_step` call) | 2 / 4695 | FAIL | FAIL |

- **(c) An edit to gate code, a baseline or the driver only** (real-01).
  Every unit went fresh with `gate-code:<file>` in all 11 cases:
  - `check-no-api-keys` (8383/8383): `tools/lint/check_no_api_keys.sh`,
    `tools/lint/lintc/lib.c`, `platform/modules/base/include/base/hex.h`
    (reached through the lintc include closure) and `tools/lint/run_lint.sh`;
  - `check-windows-platform-seam` (41/41):
    `tools/lint/windows_platform_seam_baseline.txt`, `Makefile` and
    `tools/lint/check_windows_platform_seam.sh`;
  - `check-fortify-masked-decls` (4289/4289): `tools/lint/strip_c_comments.awk`
    and `tools/lint/check_fortify_masked_decls.sh`;
  - `check-raw-sqlite` (4695/4695): `tools/scripts/raw_sqlite_allowlist.txt`
    and `tools/lint/gate_lib.sh`.

  Real-20 is a live case of the same kind: a new lintc source made every
  `check-no-api-keys` unit fresh.

The unit tests in `tests/harness/src/test_lint_selection.c` pin the
mechanism:

- a per-file unit goes fresh on its own bytes only;
- gate code, a `dir/` entry, a `.c` gate file's closure and the gate's
  recipe each make every unit fresh;
- an edit to another Makefile rule makes nothing fresh;
- a computed include in gate code inherits nothing.

#### Splitting check-windows-acceptance

`tools/lint/check_windows_acceptance.sh` now has two parts. Run with no
argument it still does both, so the full gate's verdict is unchanged.

- **Global part (`--global`)**: the thirteen-case self-test, the reconcile
  ("every acceptance program on disk has a catalog row or a registered
  group", with its count floors) and `make -n` planning the whole
  cross-link. Planning evaluates every row and every generated view header
  the Makefile remakes at parse time. Measured cost: 1.14 s + 0.08 s + 0.48 s
  wall, about 1.8 s of CPU. It always runs.
- **Per-row part (`--row=ID...`)**: the mingw compile and link of exactly
  the named rows. It refuses (exit 2) any id not in the active catalog. A
  cold cross-link of all 72 rows at `-j8` took 20.1 s wall and 108.2 s CPU.
  Of that, 16.3 s is the private sqlite archive and the rest averages
  1.25 s per row (largest `dev_train_keep`, 5.5 s).

The unit kind is new: `SELECTION_UNITS_CATALOG_ROWS`, in
`tools/lint/lintc/premise_catalog.c`. It gives one unit per id in the
literal `ZCL_WINDOWS_ACCEPTANCE_TESTS` list. A row's premise has three
parts:

- the text of its own four variables (`_SOURCES`, `_FLAGS`, `_LIBS`,
  `_LIBDEPS`) and every catalog variable they reference;
- the include closure of every tree path those words name;
- the catalog residue (every line no row owns, comments outside `define`
  blocks excepted), which is gate-wide.

The whole Makefile and `engine/composition/lib_module_order.def` are gate
code. Every word of a row must be syntax, a reference to a catalog
variable, a tree path, or a flag whose pieces are tree paths or plain
text. Anything else makes the row computed, and a computed row never
inherits. The four rows that link `$(ZCL_WINDOWS_ACCEPTANCE_SQLITE)` are
computed this way: the archive is built from `vendor/sqlite3.c`, which is <!-- doc-path-ok: untracked vendored amalgamation installed by build_vendor.sh -->
untracked (installed by `tools/scripts/build_vendor.sh`, pinned by
`SQLITE_C_SHA`). Those rows are `consensus_export_fd_io_refusal`,
`database_lifetime`, `mint_anchor_preflight_refusal` and `sqlite_vfs_dir`.
A catalog list that is not a literal list of ids is refused (exit 2).

**Locality evidence.** Every row with a finite premise (68 of 72) was
compiled and linked under `z23-lint unit-exec` (Landlock). Only that row's
computed premise was readable, and all 68 passed. The negative control
dropped one header from the `rng` row's grants and came back
`PREMISE_INCOMPLETE` (3). No row's closure contains any of the three
generated view headers. `unit-exec` needed `--toolchain=/usr/share/mingw-w64`,
because the mingw C headers live under a root that
`tools/lint/lintc/unit_exec.c` does not list as a toolchain root.

The z23-lint binary was built at `b089f792ba`, sha256 `9a2a7176…94d2`.

- **(a) Agreement on the frozen corpus.** On all 28 entries the full gate
  on the candidate, the full gate on the base and the unit-selected run
  all PASSED. The unit-selected run is the global part plus a cross-link of
  exactly the fresh rows in an emptied directory. Fresh rows per entry: the
  4 sqlite rows everywhere, plus
  - `package_lifecycle_store_refusal` on real-11;
  - `package_prepare` on syn-header-decl, syn-abi, syn-contract and
    syn-private-impl;
  - all 68 other rows on syn-flag (`gate-code:Makefile`) and
    syn-negative-lookup (`path-set-changed`).

  In the same combined runs, the six older gates' counts equal the frozen
  rows on all 28 entries (168 of 168).
- **(b) A Windows-only break in a file exactly one row depends on**
  (real-01; the seed is `#if defined(_WIN32)` / `#error` / `#endif`):

  | seeded file | fresh rows (finite) | full | selected |
  |---|---|---|---|
  | `tests/harness/src/rng_acceptance.c` (a row's own source) | `rng`, `closure-changed` | FAIL (`#error` in `rng.exe`) | FAIL (same) |
  | `contexts/wallet/services/include/services/wallet_recovery_service.h` (a header in one row's closure) | `wallet_recovery_directory`, `closure-changed` | FAIL | FAIL |

- **(c) A catalog-completeness violation** (real-01). Two cases:
  - A new program, `platform/modules/platform/tests/test_seeded_orphan.c`, <!-- doc-path-ok: seeded in a scratch tree, never committed -->
    with no row. The reconcile in the global part FAILS ("acceptance
    program(s) on disk that NOTHING accounts for"), in both the full and
    the selected run. The path set changed, so all 68 finite rows went
    fresh.
  - An id added to the list without sources. The global part FAILS in
    both runs, and the new id is fresh as `unit-new`.
- **(d) Gate-code-only edits** (real-01). All 68 finite rows went fresh
  with `gate-code:<file>` for each of `tools/lint/check_windows_acceptance.sh`,
  `tools/scripts/sh_str.sh`, `Makefile`, `tools/lint/run_lint.sh` and
  `engine/composition/lib_module_order.def`. Edits to the catalog itself:
  - a new shared variable made all 68 fresh as `catalog-residue`;
  - a new comment line made none fresh;
  - `ZCL_WINDOWS_ACCEPTANCE_rng_FLAGS += …` made only `rng` fresh, as
    `catalog-row-changed`.

`tests/harness/src/test_lint_selection.c` pins the mechanism on a fixture
catalog: closure, row text, a missing source, residue, comment, a new row,
a Makefile edit and a non-literal list refusal.

#### check-vcs-no-sha1: measured, not split

The gate was measured to decide whether it could be split like
`check-windows-acceptance`. It cannot gain anything, so it declares no
premise and its code is unchanged.

The Makefile rule (`check-vcs-no-sha1`) runs three commands:

1. `z23-lint check-vcs-no-sha1`
   (`tools/lint/lintc/gate_vcs_sha1_fence.c`). This is a fixture self-test
   in a private temporary directory, then `vcs_scan_tree`. The scan greps
   the 342 `.c`, `.h`, `.sh` and `Makefile` files under
   `contexts/commons/modules/vcs` for
   `sha[-_]?1`. It checks the Git calls in `tools/dev/source-identity.sh`
   against an allowlist, sweeps 16 fixed authority files for SHA-1
   primitives, and checks several properties of the Makefile.
2. `tools/dev/source-identity-selftest.sh`. It starts
   `tools/dev/source-identity-batch-selftest.sh` in the background (line
   18), then drives the host `git` (line 8) through more than 50 capture,
   verify and race-injection cases in a sandbox repository.
3. `tools/dev/sovereign-source-identity-selftest.sh`, a sandbox-only test
   of the ZVCS identity adapter.

The batch self-test gets its helper from
`tools/dev/source-identity-batch-bootstrap.sh` (line 10). That script
compiles `tools/dev/source_identity_batch.c` with the host `cc`
(bootstrap lines 73 and 83–87) whenever the binary is older than its
inputs. The test then captures the real checkout twice, once through the
native helper and once through the portable path, and requires the two
records to be equal (batch self-test lines 213–219). `source-identity.sh`
inventories Git-ignored static archives, generated vendor headers and
every file under the C23 source roots whatever the ignore rules say (lines
8–11, and the ignored-directory walk at line 552). Those files are outside
the tracked path set, so no unit premise can name them.

A seeded case shows this. A Git-ignored symlink was added under
`vendor/include/openssl/`, which changes no tracked byte and no tracked
path. The three recipe commands were then run directly, without the
Makefile parse. `z23-lint` passed and the sovereign self-test passed.
`source-identity-selftest.sh` FAILED: the batch self-test's whole-tree
native capture stopped with "unsupported compiler input beneath
vendor/include". With the seed removed, the batch self-test passed again.
A premise over tracked bytes would have carried the base's PASS here.

Measured on this host under `devbuild`, each part run alone. Ranges are
two runs; the two captures were run once each:

| part | CPU s | wall s | kind |
|---|---|---|---|
| Makefile parse (`make -n check-vcs-no-sha1`) | 2.8 | 15.5 | global |
| `z23-lint check-vcs-no-sha1`: self-test plus scan | 0.04 | 0.1–1.4 | the only per-file candidate |
| `source-identity-selftest.sh`, batch self-test included | 30.4–30.5 | 57.5–62.9 | global |
| of which the batch self-test | 11.1–11.2 | 11.6–13.2 | global |
| of which the two whole-tree captures (native 4.3, portable 3.1) | 7.4 | 9.0 | global |
| `sovereign-source-identity-selftest.sh` | 0.2 | 0.7–1.3 | global |
| the whole rule (`make check-vcs-no-sha1`) | 33.2 | 92.2 | |

Only the scan could be split per file. Its checks depend only on each
file's bytes plus the gate code. The Makefile checks read only the
Makefile, and the delegation check reads exactly two fixed files
(`vcs_delegation_checked`, lines 461–480). The scan is 0.04 s CPU of
33.2, about 0.1% of the rule. Everything else is the global part defined
above:

- self-tests;
- a helper built by the host compiler;
- host `git` behaviour;
- a whole-checkout record that reads ignored files.

It would always run. A premise gate is priced as its select run plus its
always-run part plus its fresh units. Here that is 8–32 s of select plus
about the whole weight, which is more than the 53.9 s the gate costs
unselected. Declaring it would lower reuse.

A split of the global part itself would need a different kind of change:

- moving the whole-checkout parity case out of the lint gate, for example
  into a test group keyed on the helper's sources;
- caching the sandbox self-tests on a key that binds the host `git`,
  coreutils and `cc` as well as the scripts.

Neither fits the current unit kinds, so neither is proposed here. Reuse on
the real set stays 71.3% (1831.4 s per candidate) and
`tools/dev/fixtures/shadow_select/lint_premise.tsv` is unchanged.

### Private-implementation edits: is the rule over-expanding?

No, with one exception that needs machinery that does not exist yet.

- On the 15 real entries whose contract did not move, the rule already
  carries every caller and integration group: caller and integration are 0
  on all of them. What stays fresh is floor plus direct.
- Narrowing direct to the callee's own contract test would be unsound. In
  syn-private-impl the callee's own group, `codec_cursor`, passes on the
  buggy implementation. The two required groups, `zcode_package_registry`
  and `zcode_swarm_net`, are direct only because the impact rules name
  them for `codec/`. An own-test-only contract layer would be RED 2 against
  `observed.tsv`.
- The rule keeps callers on four entries whose contract is ADDITIVE:
  2357.0 s in total, 1.8% of reference. For real-03, real-12 and real-14
  the only contract growth is in the component's own test file
  (`test_codeindex_*`, `test_vcs_*`). Added test lines cannot be trusted:
  an added `#define` or an inserted `|| 1` weakens an old assertion without
  removing a line. The sound rule is the existing compositional rule, with
  the contract root taken over the header plus the **base** test bytes. It
  would need the base version of the contract test to run fresh against the
  new implementation. Nothing runs an old test file against a new tree
  today, so this stays fresh. It would carry 1518.1 s (1.2% of reference).
  real-19's growth is in a public header, so its callers stay fresh either
  way.

### Per entry

Obligations are 213 lint gates plus 1194 groups. Seconds are per candidate,
at the lane-head reference of 6391.9 s. The class columns split the rule's
fresh seconds; the premise columns price the seven declared gates.

| entry | fresh / total obligations | fresh / total s: rule | fresh / total s: rule + lint premise | reuse: rule | reuse: + lint premise | premise units fresh | lint | floor | direct | caller | integration | fallback |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| real-01 | 239/1407 | 1954/6392 | 1707/6392 | 69.4% | 73.3% | 8/22157 | 1162 | 328 | 465 | 0 | 0 | 0 |
| real-02 | 242/1407 | 2054/6392 | 1794/6392 | 67.9% | 71.9% | 8/22131 | 1162 | 328 | 564 | 0 | 0 | 0 |
| real-03 | 256/1407 | 2127/6392 | 1868/6392 | 66.7% | 70.8% | 11/22126 | 1162 | 328 | 570 | 22 | 45 | 0 |
| real-04 | 234/1407 | 1519/6392 | 1267/6392 | 76.2% | 80.2% | 6/22126 | 1162 | 328 | 30 | 0 | 0 | 0 |
| real-05 | 231/1407 | 1633/6392 | 1375/6392 | 74.4% | 78.5% | 11/22163 | 1162 | 328 | 144 | 0 | 0 | 0 |
| real-06 | 232/1407 | 1634/6392 | 1384/6392 | 74.4% | 78.4% | 11/22163 | 1162 | 328 | 145 | 0 | 0 | 0 |
| real-07 | 232/1407 | 1644/6392 | 1390/6392 | 74.3% | 78.3% | 11/22163 | 1162 | 328 | 155 | 0 | 0 | 0 |
| real-08 | 241/1407 | 1980/6392 | 1731/6392 | 69.0% | 72.9% | 11/22216 | 1162 | 328 | 491 | 0 | 0 | 0 |
| real-09 | 234/1407 | 1692/6392 | 1429/6392 | 73.5% | 77.6% | 9/22166 | 1162 | 328 | 203 | 0 | 0 | 0 |
| real-10 | 230/1407 | 1522/6392 | 1263/6392 | 76.2% | 80.2% | 11/22158 | 1162 | 328 | 33 | 0 | 0 | 0 |
| real-11 | 230/1407 | 1522/6392 | 1287/6392 | 76.2% | 79.9% | 17/22158 | 1162 | 328 | 33 | 0 | 0 | 0 |
| real-12 | 300/1407 | 2823/6392 | 2564/6392 | 55.8% | 59.9% | 11/22158 | 1162 | 328 | 216 | 462 | 655 | 0 |
| real-13 | 235/1407 | 1709/6392 | 1448/6392 | 73.3% | 77.4% | 11/22155 | 1162 | 328 | 220 | 0 | 0 | 0 |
| real-14 | 260/1407 | 2430/6392 | 2175/6392 | 62.0% | 66.0% | 11/22155 | 1162 | 328 | 608 | 0 | 333 | 0 |
| real-15 | 235/1407 | 1709/6392 | 1471/6392 | 73.3% | 77.0% | 31/22154 | 1162 | 328 | 220 | 0 | 0 | 0 |
| real-16 | 239/1407 | 1954/6392 | 1695/6392 | 69.4% | 73.5% | 8/22154 | 1162 | 328 | 465 | 0 | 0 | 0 |
| real-17 | 226/1407 | 1489/6392 | 1232/6392 | 76.7% | 80.7% | 7/22154 | 1162 | 328 | 0 | 0 | 0 | 0 |
| real-18 | 1407/1407 | 6392/6392 | 6144/6392 | 0.0% | 3.9% | 11/22154 | 1162 | 0 | 0 | 0 | 0 | 5230 |
| real-19 | 302/1407 | 2358/6392 | 2143/6392 | 63.1% | 66.5% | 59/22139 | 1162 | 328 | 30 | 156 | 682 | 0 |
| real-20 | 226/1407 | 1489/6392 | 1265/6392 | 76.7% | 80.2% | 8434/22216 | 1162 | 328 | 0 | 0 | 0 | 0 |
| syn-header-decl | 1407/1407 | 6392/6392 | 6190/6392 | 0.0% | 3.2% | 70/22222 | 1162 | 0 | 0 | 0 | 0 | 5230 |
| syn-abi | 1407/1407 | 6392/6392 | 6187/6392 | 0.0% | 3.2% | 67/22222 | 1162 | 0 | 0 | 0 | 0 | 5230 |
| syn-flag | 1407/1407 | 6392/6392 | 6230/6392 | 0.0% | 2.5% | 114/22222 | 1162 | 0 | 0 | 0 | 0 | 5230 |
| syn-contract | 1407/1407 | 6392/6392 | 6140/6392 | 0.0% | 3.9% | 12/22222 | 1162 | 0 | 0 | 0 | 0 | 5230 |
| syn-private-impl | 230/1407 | 1621/6392 | 1363/6392 | 74.6% | 78.7% | 10/22222 | 1162 | 328 | 131 | 0 | 0 | 0 |
| syn-generated-input | 1407/1407 | 6392/6392 | 6137/6392 | 0.0% | 4.0% | 9/22222 | 1162 | 0 | 0 | 0 | 0 | 5230 |
| syn-negative-lookup | 1407/1407 | 6392/6392 | 6467/6392 | 0.0% | -1.2% | 22224/22224 | 1162 | 0 | 0 | 0 | 0 | 5230 |
| syn-macro | 1407/1407 | 6392/6392 | 6151/6392 | 0.0% | 3.8% | 26/22222 | 1162 | 0 | 0 | 0 | 0 | 5230 |

Adversarial RED against the reference observations: **0** for the live
rule (`live_rule=0`). The frozen record keeps its one historical RED
(`syn-contract:test_zcode_recipe`) and the landing selector's five. Every
entry kind that must expand still predicts ALL for test groups: contract,
negative-lookup, flag, header, ABI, macro and generated-input. The test
pins that, and pins that syn-negative-lookup inherits no lint unit.

### What still blocks more than 90%

Re-measured at the lane-head reference of 6391.9 s per candidate. 90% reuse
means at most 639.2 fresh s per candidate. The rule with seven lint premise
gates is at 1831.4 s, or 1774.3 s with one combined select run:

| remaining fresh s per candidate | s | share of reference | what it would take |
|---|---|---|---|
| Lint gates of 9 s or more, ineligible (17 gates, table above) | 566.5 | 8.9% | restructuring, not a declaration: split each gate's per-file checks from its whole-tree part (claim resolution, closures, ratchet sums, floors over content), so that only the whole-tree part must rerun, as `check-windows-acceptance` now is. The five heaviest are `check-doc-claims` 101.8, `check-build-epoch-integrity` 80.8, `check-capability-closure` 70.9, `check-vcs-no-sha1` 53.9 and `check-zcode-package-registry` 36.1. `check-vcs-no-sha1` was measured and cannot gain from a split: its per-file part is 0.04 s of 33.2 s CPU |
| Lint gates under 9 s, not reviewed (185 gates) | 160.9 | 2.5% | a review like the one above; a declared gate still pays about 10 s of select, so most would gain only inside a combined run |
| Lint gates of 9 s or more, not declared (ship, retrieval, package-anatomy, release-install) | 70.6 | 1.1% | a confined whole-gate run (ship, retrieval, release-install) or a per-directory unit kind (package-anatomy) |
| floor, `make_lint_gates` family | 311.3 | 4.9% | a premise for the lint-gate test umbrella. `realroot` and `heavy_02` alone are 151.5 s |
| fallback, real-18 (`unmapped-code-change`) | 261.5 | 4.1% | an impact rule for `engine/services/src/replay_verify_service.c` (selector owner) |
| direct test groups | 229.5 | 3.6% | none that is sound (see above) |
| callers and integration on additive contracts | 117.9 | 1.8% | a base-test re-run (1.2%); real-19's header growth stays |
| the seven premise gates | 113.3 | 1.8% | one combined select run (56.2 s) |

The ineligible heavy gates alone (566.5 s) take 89% of the whole 90% budget
(639.2 s). With every test group carried and every plausible gate declared,
lint would still leave about 784 s per candidate, 87.7%. Past 90% the heavy
whole-tree gates have to be split so that their per-file part can be
selected, and the floor has to be carried too. More premise declarations
alone cannot get there.

## Obligations predicted fresh

This is the hand-off list: exactly what the rule would run fresh, with the
reason for each layer. The reason `contract_obligation_of_changed_unit`
marks the unit's own contract obligations. `contract_additive` marks a
contract that grew, so the selector's callers and integration edges are
kept. None of these groups is carried as eligible today (see above).

Every entry: all 213 lint gates are predicted fresh (reason:
source-sensitive, changed source always reruns).

Entries predicted ALL run the whole host-admitted catalog of 1193 groups,
for the fallback reason in the table above.

Exact entries run the test groups below:

- **real-01** (contract, contract_obligation_of_changed_unit): hotswap_simnet, hotswap_module_v2, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, native_api_contract, make_lint_gates, vcs_devloop, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-02** (contract, contract_obligation_of_changed_unit): hotswap_simnet, hotswap_module_v2, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, impact_composition, dev_proof_signer, command_registry_catalog, native_api_contract, make_lint_gates, vcs_devloop, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-03** (contract, contract_obligation_of_changed_unit): mind, code_capsule, code_impact, hotswap_module, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, command_registry_catalog, command_registry_latency, native_api_contract, command_handler_snapshot, make_lint_gates, codeindex, codeindex_scale, code_firsthour, code_fetch, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-03** (caller, contract_additive): code_merkle, code_merkle_proof, code_emitter, blocker, testcache
- **real-03** (integration, contract_additive): code_inventory, chainlog, code_growth, science
- **real-04** (contract, contract_obligation_of_changed_unit): hotswap_loader, hotswap_simnet, hotswap_module, hotswap_module_v2, binary_ab_fallback, make_lint_gates, group_selector, boot_shutdown_marker, self_backtrace, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-05** (contract, contract_obligation_of_changed_unit): zcode_package_registry, make_lint_gates, event_log, vcs_core, package_capability_claim, zcode_swarm_net, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-06** (contract, contract_obligation_of_changed_unit): zcode_package_registry, make_lint_gates, event_log, vcs_core, zcode_swarm, zcode_swarm_net, zcode_swarm_complete, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-07** (contract, contract_obligation_of_changed_unit): zcode_package_registry, make_lint_gates, event_log, vcs_core, zcode_verify, zcode_attransport, zcode_swarm_net, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-08** (contract, contract_obligation_of_changed_unit): hotswap_simnet, hotswap_module_v2, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, native_api_contract, make_lint_gates, vcs_devloop, group_selector, boot_shutdown_marker, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-09** (contract, contract_obligation_of_changed_unit): zcode_package_registry, db_migration_idempotent, make_lint_gates, os_sandbox, sandbox_process_budget, zcode_dev_objects, build_fabric, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02, resident_launch, resident_launch_contract
- **real-10** (contract, contract_obligation_of_changed_unit): command_registry_catalog, native_api_contract, make_lint_gates, zcode_verify, zcode_add, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-11** (contract, contract_obligation_of_changed_unit): command_registry_catalog, native_api_contract, make_lint_gates, zcode_verify, zcode_add, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-12** (contract, contract_obligation_of_changed_unit): zcode_package_registry, command_registry_catalog, make_lint_gates, event_log, vcs_core, zcode_public_shape, zcode_swarm_net, zcode_dev_objects, vcs_devloop, golden_revert_roundtrip, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-12** (caller, contract_additive): dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, story_graph, build_fabric
- **real-12** (integration, contract_additive): qr, engine, engine_rules, zid_seniority, robustness, wallet, shop_want, shop_fulfill, cold_join_sovereign, file_controller, rom_seed, rom_fetch, source_bundle_fetch, source_bundle_publish, spawn, integrity, hotswap_module, hotswap_service_registry, impact_composition, dev_activation, metaverse_agent_broker, metaverse_vocabulary, metaverse_broker_authority, native_api_contract, command_handler_snapshot, binary_ab_fallback, network_monitor, cli_argv_strict, condition_engine, blocker, zcode_store, zcode_publish, zcode_package_dev, zcode_verify, zcode_attransport, zcode_dht_service, zcode_badge, zcode_fetch, zcode_add, dev_land, group_selector, metaverse_catalog, site_routes, golden_dev_cycle, utxo_apply_stage, read_leaf_no_datadir_write, boot_shutdown_marker, zswap_quote, zswap_yardsale, zswap_ceremony, syncdiag_rpc, thread_qos, block_prefetch, agent_spend_policy
- **real-13** (contract, contract_obligation_of_changed_unit): zcode_package_registry, make_lint_gates, event_log, vcs_core, zcode_verify, zcode_public_shape, zcode_swarm_net, zcode_dev_objects, story_graph, build_fabric, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-14** (contract, contract_obligation_of_changed_unit): zcode_package_registry, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, make_lint_gates, event_log, vcs_core, zcode_swarm_net, vcs_devloop, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-14** (integration, contract_additive): hotswap_module, hotswap_service_registry, impact_composition, dev_activation, command_registry_catalog, native_api_contract, command_handler_snapshot, zcode_package_dev, zcode_verify, zcode_commons, zcode_public_shape, zcode_dev_objects, story_graph, group_selector, golden_revert_roundtrip, golden_dev_cycle, boot_shutdown_marker, vault_read, vault_dispatch, build_fabric
- **real-15** (contract, contract_obligation_of_changed_unit): zcode_package_registry, make_lint_gates, event_log, vcs_core, zcode_verify, zcode_public_shape, zcode_swarm_net, zcode_dev_objects, story_graph, build_fabric, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-16** (contract, contract_obligation_of_changed_unit): hotswap_simnet, hotswap_module_v2, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, native_api_contract, make_lint_gates, vcs_devloop, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-17** (contract, contract_obligation_of_changed_unit): make_lint_gates, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-19** (contract, contract_obligation_of_changed_unit): rpc, chain_evidence_controller, chain_evidence_live_advance, command_registry_catalog, make_lint_gates, supervisor, syncdiag_rpc, debug_bundle, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **real-19** (caller, contract_additive): rom_seed, rom_fetch, rom_fetch_onion, source_bundle_fetch, source_bundle_publish, rom_manifest, rom_journal_resume, hotswap_loader, native_api_contract, sysinit, supervisor_backstop, sd_notify, chain_tip_watchdog_bounded_restart, os_sandbox, operator_ux
- **real-19** (integration, contract_additive): net, sqlite, models, file_market, api, mesh_pairing, mesh_status_proto, mesh_status_wire, node_health_service, sync_service, snapshot_sync_service, snapshot_serve_loopback, file_controller, file_service_pow_gate, code_capsule, code_emitter, hotswap_module, dev_platform, dev_platform_shard_01, dev_platform_shard_02, dev_platform_shard_03, dev_platform_shard_04, dev_platform_shard_05, dev_platform_shard_06, dev_platform_shard_07, dev_platform_shard_08, command_registry_latency, command_handler_snapshot, dbquery_secret_denylist, db_maintenance, header_sync, header_sync_stall, db_migration_idempotent, msg_handlers, net_handshake_adversarial, condition_engine, blocker, boot_mesh_terminal, mesh_terminal_client, mesh_stream, body_persist_stage, zcode_store, zcode_dht_service, offline_datadir_query, db_maintenance_port, peer_lifecycle, telemetry_ontology, telemetry_storage, reducer_forward_progress_gate, stopwatch_skip_watch, slo_ledger_summary, tip_agreement_watch, health_rollup, command_input_bounds
- **real-20** (contract, contract_obligation_of_changed_unit): make_lint_gates, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02
- **syn-private-impl** (contract, contract_obligation_of_changed_unit): byte_order_codec, codec_cursor, zcode_package_registry, make_lint_gates, zcode_swarm_net, make_lint_gates_shard_01, make_lint_gates_shard_02, make_lint_gates_shard_03, make_lint_gates_shard_04, make_lint_gates_shard_05, make_lint_gates_shard_06, make_lint_gates_shard_07, make_lint_gates_shard_08, make_lint_gates_realroot, make_lint_gates_partition, make_lint_gates_heavy_01, make_lint_gates_heavy_02

## Proof premises versus build dependencies

Build dependencies are the TUs that recompile. Proof premises are what an
obligation's verdict depends on. The two diverge in both directions:

- **Premise outside the depfile.** syn-negative-lookup invalidates 0 of
  8315 build actions by the depfile graph, yet the new
  `contexts/commons/modules/vcs/src/codec/cursor.h` captures <!-- doc-path-ok: created only by the syn-negative-lookup patch -->
  `#include "codec/cursor.h"` for 34 vcs sources. A dry run of
  `make t-fast-exact` recompiled none of them, so incremental make links
  stale objects unless those sources are touched.
  syn-generated-input also invalidates 0 build actions by depfile, while the
  generator rewrites `install_script_gen.h`.
- **Build wider than premise.** For private edits (syn-private-impl,
  real-17) one TU recompiles, but the selector reruns 38 and 54 groups. The
  premises that actually moved are the 17 and 13 contract-layer groups.
- **Global premise.** syn-flag rebuilds all 8315 TUs: the Makefile is a
  build-graph input. The proof premise that moved, the `-DZCL_DEV_BUILD`
  gate in `hotswap_activate.o`, reaches only the hotswap groups, and the
  landing selector names none of them.
- **Name-only caller hops.** `codeindex_callers()` matches callees by bare
  name. Across all 28 entries, 235 selected groups (3081.9 s; 227 and
  2978.1 s on the real set) were reached only through a
  reverse-caller hop whose TU reads no header of any component the walk
  reached legitimately. real-04 alone accounts for 151 groups and 2102.6 s,
  real-17 for 41 groups and 595.6 s. This is reported as an
  over-approximation, not fixed; the code-index owner has it.

## False-hit witnesses

Each synthetic entry was reference-run under its patch with
`make t-fast-exact ONLY=<bounded set> T_FAST_EXACT_ARGS=--no-cache`,
touching every reader so that no stale object was reused. This ran after
`predicted.tsv` was committed (git order: 25aebccc04 then
8c49b46d1f). The frozen predictions were generated by 1079c9fb7c, which was 0016cffa9e before the rebase, and are
never regenerated. The
bound is the landing selector's groups plus candidate groups named by
grepping callers; it is not the full catalog.

| entry | seeded bug | failing groups | landing selector | frozen rule prediction |
|---|---|---|---|---|
| syn-private-impl | payload length equal to capacity refused | zcode_package_registry, zcode_swarm_net | covered | covered (contract layer) |
| syn-header-decl | `finish` stops flagging trailing bytes | codec_cursor, zcode_package_registry, zcode_swarm_net | covered | covered |
| syn-abi | reader fields reordered, length narrowed to 16 bits | zcode_package_registry, zcode_swarm_net, zcode_dev_objects | covered | covered |
| syn-macro | `ASTRO_YEAR_MAX` 9999 → 8999 | node_character_wire | covered | covered |
| syn-contract | `finish` accepts trailing bytes; callee test rewritten to agree | zcode_package_registry, zcode_swarm_net, story_graph, **zcode_recipe** | **MISS zcode_recipe** | **RED: zcode_recipe** |
| syn-negative-lookup | shadow header maps `finish` to a trailing-tolerant shim | zcode_package_registry, **zcode_recipe** | **MISS zcode_recipe** | covered (ALL) |
| syn-flag | `-DZCL_DEV_BUILD` dropped from `hotswap_activate.o` | **hotswap_module, hotswap_shelf, hotswap_rollback** | **MISS all three** | covered (ALL) |
| syn-generated-input | install script pin quoted with `'` | install_sh_site | covered (universal) | covered (ALL) |

What the witnesses show:

1. **One RED against the frozen prediction: syn-contract / zcode_recipe.**
   The contract moved, so the rule predicted the selector's own set. The
   recipe decoder reaches `zcl_codec_reader_finish` through
   `package_recipe.c`, a proof-owner file where the caller closure stops. The
   fix is that a moved contract now predicts the reference (`unknown-scope`).
   The test pins the frozen RED (`frozen_rule=1`,
   `syn-contract:test_zcode_recipe`) and requires `live_rule=0`.
2. **Five landing-selector false hits:**
   - zcode_recipe under syn-contract and under syn-negative-lookup;
   - hotswap_module, hotswap_shelf and hotswap_rollback under syn-flag.

   Any of these bugs would land under today's selector. The test pins
   `frozen_selector=5`.
3. **The compositional rule's premise is weaker than it looks
   (syn-private-impl).** The callee's own contract test, `codec_cursor`,
   PASSED on the buggy implementation. The two callers that caught the bug
   were covered only because the impact rules attach them to `codec/`
   directly. An "own contract tests passed fresh" condition proves only what
   those tests assert. That is why qualification item 2 asks for a contract
   root over declared premises and not over tests alone.
4. **Unchanged ABI is not enough (syn-contract).** Every declaration and
   layout is byte-identical, yet four groups fail.
   `zcl_shadow_reuse_admit` never takes ABI equality as an input, and its
   test refuses an unchanged ABI with an old PASS.

## Largest avoidable rerun

real-04, a change to a test file in `tests/harness`. The landing selector
runs 172 groups (3622 s). 151 of them, 2102.6 s, were reached only through
name-only caller hops. The rule would keep the 21 contract-layer groups.
That rerun is avoidable once caller lookup is symbol-exact: F1's frontier
seeds from changed functions and routes around the name collision.

## Missing key inputs

The fields that `zcl.zcode.component_input_key.v1`
(`contexts/commons/modules/vcs/include/vcs/zcode_action_input.h`) does not
bind separately, compared with the 19 fields of the proof-ticket branch's
`zcl.component_proof_key.v1`. Ranked by the reference cost above what the
rule would still run on the entries whose premises moved them:

| missing input | entries | broad invalidation (s) |
|---|---|---|
| **unit_id**: the key folds the whole candidate source tree into `candidate_source_root`, so any byte anywhere changes every key | 26 | 91178.8 |
| **dependency_closure**: no per-component closure root, so a callee edit cannot be told apart from an unrelated one | 21 | 81917.4 |
| integration_edges: no binding of which consumer edge a verdict covers | 8 | 15870.7 |
| abi_generation, invariants | 4 | 0 (these entries now fall back to the reference) |
| negative_lookups: a header that did not exist cannot appear in any root | 1 | 0 (falls back) |
| generated_inputs: generator input bytes are only inside the whole tree | 1 | 0 (falls back) |

The key also lacks linker, sysroot and fixtures as separate roots. These
fields are why every carried verdict is `execution_inputs_incomplete`:
unit_id and dependency_closure cause the most broad invalidation, and
negative_lookups and generated_inputs cause the unknown-scope fallbacks.

## Cost weights

The weights are in `tools/dev/fixtures/shadow_select/weights.tsv`. Each
weight is the mean of fresh (uncached) service milliseconds per obligation
from `costs.tsv`: 125,749 rows from 485 landing-proof attempt logs, sha256
`3b8b7a8b175830c915d17aa6d8c39283d1ef5bcd37ea258a4b3d150fc512d126`. A
group with no measurement is priced at the median group weight and counted
in `unweighted=`.

Validation overhead is measured, not assumed. For each carried obligation,
the per-obligation cost is 19 field SHA3 roots, a 624-byte preimage SHA3,
a 360-byte ticket SHA3 and one Ed25519 verification.

## Unfinished

- **Second predictor column (function-granular frontier F1, branch
  `frontier/symbol-seeds` at 427f6dba3f).** It is not computed. It needs a
  separate build of that tree with these files, plus the pre- and post-patch
  bytes of each changed file, fed through `zcl_frontier_dir_read` into
  `plan->frontier`. The predict step takes a tree root, so it can be rerun
  once F1 and the catalog mask are on main.
- **The reference runs are bounded.** Each covers the selector's groups plus
  the named candidate groups, not the whole catalog, so a RED outside that
  bound would go unseen.
- **The lint premise rows are frozen tool output.** They come from a
  `z23-lint` built at lane lint-premise-decl (`1b2d7bc5eb`). The first
  premise slices are on main; the four new declarations are not. The test
  cannot recompute the rows. The shadow evaluation should call the premise
  code in process and not read a fixture.
- **Three of the four new gates have no file-list entry.** Their
  unit-selected verdicts in the soundness check are read from the full
  run's per-file report. A real unit-selected run for them needs a
  file-list entry like the `ZCL_API_KEY_SCAN_FILES` one that
  `check-no-api-keys` has.
- **The toolchain pin is still absent.** `check-fortify-masked-decls`
  measures its masked set from the toolchain, and the per-TU gates compile
  with it. Until `tools/dev/toolchain.pin` exists, a toolchain change with
  no tree change is invisible to every premise.
- **Base-test re-run for additive contract tests** (1.2% of reference on
  the real set) needs a runner that builds the base bytes of a contract test
  against the candidate implementation.
