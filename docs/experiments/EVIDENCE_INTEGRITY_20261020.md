<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Evidence integer and cluster completeness qualification

Date: 2026-10-20. Baseline: 487e0d4a520153b0b02a32fb25b7d8f0ba0977d3.
Compiler: Ubuntu Clang 18.1.3. CPU: AMD Ryzen 9 7950X3D.
The fixtures use injected timestamps and isolated data; no live node was queried.

## Integer timestamps

Contributor: CesareFI. The original 9,886-byte patch has SHA256
6b0cf71dbcb03ceec2f85644084533ff78acc07f445867a969b11fe5c20e075d.
Its retained tests ran against both unchanged parent production files through
`make -j4 t-fast-exact ONLY=evidence_judge T_FAST_EXACT_ARGS='--no-cache --jobs=3'`.
Three independently invoked cases failed: out-of-range integer parsing,
unrepresentable signed row age, and malformed timestamp tokens. In particular,
the INT64_MIN row-age case ran after the parser case and failed separately.
The runner's automatic isolated retry also failed; its detailed capture was
retained. The runner did not preserve the first attempt's detailed capture.

Applying the contributor production changes without alteration produced one
cold passing group, zero skips, zero unobserved environments and zero flaky
results, without an isolated retry. The integer limits, invalid suffixes,
existing signed future-age behavior and oracle-distance boundaries all passed.
The compact admission scope limited memory to 2,147,483,648 bytes. Its observed
cache-inclusive peak was 766,685,184 bytes, with zero memory-limit or OOM events.
The parent-source RED peak was 794,775,552 bytes, also with zero limit/OOM events.
These measurements describe this focused warm workload only.

## Cluster census

Contributor: CesareFI. The original cluster-v3 patch has SHA256
2ba3b151f9076474c6f82284bfe8dde2032af92fc2934fe73ff6129ea4cc08ca.
The existing `make tip-agreement-selftest` passed with the candidate recorder
and judge. Named controls verified that thirteen qualifying clusters cannot
accrue PASS, exactly twelve complete clusters remain usable, below-threshold
tail clusters preserve agreement, and missing or out-of-range sentinel counts
remain unknown. The executable modes of both existing scripts remained 100755.
The earlier independent isolated original-recorder RED and restored-candidate
GREEN receipts were reviewed separately; this experiment did not repeat them.

## Scope

These results qualify deterministic fixture behavior. They do not establish
live peer agreement, consensus parity, deployment, publication, or a complete
atomic network snapshot. Required full candidate qualification remains a
separate native receipt.

The six-gate lint preflight passed five checks and refused the stale generated
capability inventory. Canonical regeneration followed by the generated-inventory
check passed. The generated delta was retained as evidence and removed from the
author's source changes; native integration owns regeneration at the assembled
tip. No full qualification was inferred from this preflight.

## Full-gate refusal and bounded repair

The first combined native qualification completed 222 lint gates and refused
one: the complexity ratchet measured integer parsing at 16 and the combined
boundary fixture at 24, above the existing cap of 15. The other 221 gates
passed. No candidate was queued and affected-group proof did not run.
Full lint took 532.851 seconds with 21 workers; its longest gate was standalone
tool linking at 507.477 seconds. The 8 GiB admission scope reached its charged
memory limit with 799 max events and zero OOM events. These observations do not
identify an individual process working set or establish a bottleneck cause.

The repair extracted the unchanged delimiter predicate and split malformed
timestamps, signed ages and oracle distances into independent cases. Every
assertion remained, including the separately invoked INT64_MIN age case. The
canonical complexity ratchet passed before the focused rebuild: 86,668 functions
in 5,205 files, with all 3,899 existing baseline pins exact at cap 15. The cap
and baseline were unchanged. The subsequent cold evidence-judge group passed
with zero skips, unobserved environments, flaky results or isolated retries.
The unchanged cluster suite was not repeated. Full qualification of the
repaired source remains a separate receipt.

## Early complexity screen

The late refusal above motivated running the existing canonical complexity
check after native preparation and before full lint. Preparation still runs
capability generation, producer builds, hook installation and lint-ready first.
The reviewed early-screen source patch has SHA256
e0cca7fa85d3ffbac650747b13132e446f13f9c96dcbfd5f3af2d7324c66899a.

The RED run used the original qualifier and the new fixtures with their
original uninitialized trace buffers. The qualifier lacked the early stage;
two assertions failed, and the native runner's single automatic isolated retry
also failed. The combined RED receipt took 514.7 seconds. A bounded
string-termination repair was then made to the fixtures before candidate
GREEN; that fixture revision must not be attributed to the earlier RED run.
Candidate GREEN passed one cold registered landing group with zero failures,
skips, flaky results or isolated retries. Tests took 241.5 seconds; the
505.67-second admitted command included 235.198 seconds waiting for admission.
The GREEN log has SHA256
5280a20ebd3ca466cfd55e85abf71a770bec1ff5b0cc895287e3b33e4ecdef05.
Full candidate qualification remains a separate receipt.

## Published wiki and retained-rival controls

The actual producer and wiki targets built successfully from signed source
e9a2438659eff63d245f954a02e0f49e118ed562. The admitted command took 445.14
seconds, including 0.045 seconds waiting. Its cache-inclusive scope peak was
7,153,430,528 bytes, with zero memory-limit or OOM events. The published wiki
image has SHA256
536410f1837a10496e599e3afbe5100e2fe750aa582d03000451f3dc37e565cf.
Independent isolated checks of that unchanged image returned positive
propagation verification and refused a tampered signature. The positive result
explicitly reported full_qualification=false. The checked evidence manifest
has SHA256
d876a8b36d28fec2b0a7a6f83d36506c6870cad653118ebef2812f62e47ef5ee.

The additional CesareFI test-only patch has SHA256
fdd0c6a43107bad3a7cafc1b5aa53fd1a8aa0afdc6c64d963753b3cf1738fd3c.
Independent isolated execution passed: a matching modal cluster retains four
contested peers from a rank-12 rival despite a below-threshold sentinel; eight
real recorder samples then produce DISAGREE through the judge. The verified
incremental evidence manifest has SHA256
f342712814574e60bc48f0798cb00d30c28c503709ce7505c0480a4c5cf2ed80.
This patch adds assertions without changing the recorder or judge policy.

## Native contract capture preparation

The candidate test blob matched the exact preimage of signed peer commit
379b1708102bfe59e7e283135296020231d2512b. A 16 KiB test capture could not hold
the observed 16,985-byte fleet-goals result. Only that commit's test-path delta
was imported: the capture now accommodates the documented 65,536-byte JSON
bound, newline, overflow sentinel and NUL, and reports a failing leaf by name.
The peer's cold native API contract test passed. This packet did not repeat
that test before the required combined qualification. The peer branch and its
experiment document were not imported. Production result bounds are unchanged.

## Canonical qualifier selection and admitted Make jobs

Measured on 2026-10-20 with GCC 14.2.0 and an AMD Ryzen 9 7950X3D.
The original selection baseline was
`d30ab4d26849f286286cbd8179ff84e5e60e11d4`. The focused candidate included
`55c7abadea22173532515851dc988a551ff55b99`, preserving its early complexity
stage. Integration onto `7d98d18be20b9b3f45eb67bf91f7f8df26b4da49` changed
neither qualifier source, fixture source nor Makefile relative to that tested
candidate's base.

Two routed names, `test_group_selector` and `test_test_group_selector`, refer
to the same registered full ID. The original qualifier counted them separately
and assigned the canonical PASS header to the earlier alias, leaving another
expected section unseen. The repair uses the existing exact catalog resolver
before bounded deduplication and matches canonical headers exactly. Unknown,
ambiguous or oversized IDs are refused. A registered prefix-named group remains
`test_test_fdt`; it is not confused with the selector group.

The alias RED retained duplicate selection names and their emitted PASS
headers. Its registered group failed in both the initial attempt and the
runner's automatic isolated retry. Updated canonical fixture expectations also
produced collateral failures; those are not independent defect evidence.
A separate RED retained canonical selection but removed Make-cap propagation.
Its four empty, zero, malformed and overflowing cap cases failed the required
pre-dispatch refusal assertions. Three additional trace failures exposed a
fixture assumption: earlier phases inherit the caller's `ONLY` value. The
fixture now copies that value before environment mutation and compares it
exactly; the final phase still requires `test_leaf_smoke`.

An explicit `ZCL_BUILD_MAX_JOBS` is validated by the existing CPU/memory-aware
helper before qualifier subprocesses and supplied to every owned Make phase.
It overrides inherited Make parallel settings, including a lower setting;
it does not enlarge the enclosing CPU quota. Unset behavior is preserved.
Per-case real Make recipe traces recorded `-j4` in all seven phases for cap4
and `-j2` for cap2. The unset control retained inherited `-j2` except for the
existing automatic dev-bin `-j28` allocation. The seventh phase is the early
complexity gate. These traces demonstrate dispatch, not peak concurrency or
performance improvement.

A cheap preflight caught fixture complexity M=18 against the unchanged cap15.
Extracting environment cleanup preserved assertion-path restoration and
allocation-failure behavior. The corrected canonical gate passed, followed by
one cold registered `dev_land` group: zero failures, cached groups, skips,
unobserved conditions, flaky results or retries; tests took 131.9 seconds.
The complete admitted command, including compilation, took 537.91 seconds
under a three-CPU, 2 GiB limit. Its cache-inclusive memory peak was
1,806,639,104 bytes with zero memory-limit or OOM events. The GREEN log SHA256 is
`2efa0eb0a39423a5b6f594e88f3dd09f3dc219e03346f748eebc2c86fa913c0c`.
The retained trace manifest is verified from the worktree root and has SHA256
`f37e2e07ccd16a0671e0fe61bb1d04415102b18ad174ab4ae4eaad2d1a7826ca`.
Full candidate qualification and publication remain separate evidence.
