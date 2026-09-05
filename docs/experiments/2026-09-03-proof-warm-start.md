<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Proof warm-start: cold-vs-warm measurement (2026-09-03)

Lane `agent/proofwarm-20260903-measure`, continuation of
`agent/proofwarm-20260903`. Branch keeps the four warm-start commits;
probe commits K1/K2/K3 from the prior run and M1/M2 from this run were
measurement scaffolding and were removed before the final commit.

## What changed

`dev proof ensure` seeds a new proof generation's `build/` tree from the
newest complete donor generation for the same checkout root: hard links
for immutable `.o`/`.d` outputs, a byte copy for the small `bin/zcc`
wrapper, nothing else. Timestamps are repaired so exactly the
donor-to-local changed set reads newer than the seeds. Any failure
rolls the seeds back to a cold build. The receipt wire schema is
untouched; reuse is reported in a `<key>.warmstart` sidecar:

```text
zcl.dev_proof_warmstart.v1
warm=1
donor=<generation tag>
donor_local=<donor commit>
files_linked=<n>
bytes_linked=<n>
compile_mode=built|reused|skipped|failed
compile_ms=<build-only wall time>
bundle_ms=<dev-proof-bundle wall time>
```

`ZCL_DEV_PROOF_WARM=0` forces the cold path for measurement. It is
outside the sealed proof environment allowlist, so it changes no proof
input: warm and cold receipts for the same pair stay comparable. The
switch is proven by the `test_pw_disable_switch_forces_cold` seam test,
not by the M1 run below (see honesty note).

## Method

One-line comment change to `platform/modules/codec/src/cursor.c`
(docs-only changes skip the compile dimension, so the probe must be
code; a comment changes no behavior):

- COLD (M1 `994bc0858`, base `afbeb054f`): warm start disabled.
- WARM (M2 `0510045c`, base M1): warm start enabled, seeding from the
  M1 generation's donor marker.

Both runs foreground through the resident watcher, `-j16` (proof cap
on a 32-CPU host). Numbers below are the receipt sidecars verbatim.

## Results

| run | commit | warm | donor_local | files_linked | bytes_linked | compile_mode | compile_ms | bundle_ms | receipt |
|-----|--------|------|-------------|--------------|--------------|--------------|------------|-----------|---------|
| cold | `994bc0858` | 0 | - | 0 | 0 | built | 109180 | 102573 | FAILED (2 test groups <!-- doc-count-ok: this run's failing-group count, not a whole-repo total -->, build phases green) |
| warm | `0510045c` | 1 | `994bc0858` | 15098 | 835402816 | built | 126584 | 114209 | FAILED (same 2 test groups <!-- doc-count-ok: this run's failing-group count, not a whole-repo total -->, build phases green) |

Prior-session sidecars, same host, same probe shape (supporting data):

| run | commit | warm | files_linked | bytes_linked | compile_ms | receipt |
|-----|--------|------|--------------|--------------|------------|---------|
| K1 cold | `797b3ce47` | 0 | 0 | 0 | 51386 | FAILED (same 2 groups) |
| K2 warm | `16817a08e` | 1 | 4259 | 148848846 | 87385 | FAILED (same 2 groups) |

(K1's sidecar predates the `bundle_ms` sidecar field: no bundle line.)

Host load (11-day uptime, shared fleet host, other lanes proving
concurrently):

```text
12:35 UTC  load average: 106.07, 86.63, 64.74
12:48 UTC  load average: 101.45, 92.24, 78.02   (M1 queued 12:54)
13:33 UTC  load average: 91.97, 79.25, 77.64    (M2 queued 13:34)
```

## Reading the numbers honestly

No speedup is demonstrated by these runs, and the data says why:

- Cold-vs-cold variance is ~2x on this host (K1 51 s vs M1 109 s
  for equivalent full `build-only` runs of 7534 objects). Load noise
  swamps any single-run comparison.
- "Cold" here is not cache-cold: the shared zcc content cache
  (keyed without the output path) serves the unchanged TUs in a fresh
  generation, so a one-line probe's cold build is already fast
  (~1–2 min). Warm start's seeding (15098 files, 835 MB by hard link
  for M2) skips even that serve path, but the difference is
  unmeasurable under ±2x load noise.
- What IS proven: the mechanism engages in production (M2
  `warm=1`, donor is M1's generation, 15098 files linked), the
  timestamp repair is correct (only the changed TU rebuilt; the proof
  reached the test phase on reused objects), and every refusal degrades
  to cold (M1 `warm=0` with no eligible donor).

## Honesty notes

- M1's `warm=0` was natural cold, not switch-forced: the prior probes'
  donor markers (`build/.proof-build-complete` in the K1/K2
  generations) were gone by M1's prepare time, so no donor was
  eligible. The remover is unknown — the reaper only deletes whole
  generations, and both K1/K2 build trees still stand. Separately, the
  M1 worker forked from the resident watcher, whose environment does
  not set `ZCL_DEV_PROOF_WARM`, so the CLI-side variable could not
  have reached it. The switch logic itself is covered by the new seam
  test.
- Both receipts FAILED on the same two test groups,
  `test_zcode_package_registry` and `test_zcode_swarm_net` — as did the
  prior session's K1 probe, whose tree differed from its base only by
  the same kind of comment line. Root cause found: the registry test
  re-derives the pinned C23 Commons package roots from tree sources,
  and the probe sat inside the pinned `zclassic23/codec` package
  (`platform/modules/codec`), so the comment byte-change drifted its
  content root (`19074c1e…` vs pinned `1a57e382…`; the log even prints
  the re-derive fix). The swarm failure is the same drift one step
  down (`prepare_package_transport` against expected package roots;
  M1's instance additionally died by signal 9, the OOM-killer
  signature under load ~90+). Neither group touches warm-start code
  paths; both failures reproduce independent of the seeding decision
  (cold K1 and M1, warm K2 and M2). Lesson for the next probe: touch
  code outside the ten pinned Commons packages (the test names
  `tools/scripts/zcode_registry_rederive.sh` for legitimate root
  moves), or expect exactly these two red groups.
- The 40-minute measurement budget was exceeded (queue latency plus
  ~12 min test phases per run). No third run was made.

## What remains

1. Repeat cold-vs-warm on a quiet host (or with several alternating
   runs) to get a signal above the load noise.
2. A cache-bypass comparison (fresh `XDG_CACHE_HOME` or a moved epoch
   key) is where warm start should win outright; unmeasured.
3. Resolved during this run: the two red groups are probe-placement
   artifacts (pinned `zclassic23/codec` golden), not warm-start
   breakage. Next probe belongs outside the pinned packages.
4. Find what removed the K1/K2 donor markers; a pool that silently
   loses donors turns warm runs cold without a trace (the sidecar
   still says `warm=0`, which is the only signal).

## Update 2026-09-05: donor identity is now sealed

The donor scan above only ever compared `root`/`local`/`base`/`completed`
in the `build/.proof-build-complete` marker — a donor built under a
different compiler, `CFLAGS`, or a vendor archive rebuilt in place could
still be adopted, because none of those move a tracked source blob and the
wrapper-inputs diff never sees them. The marker now also seals the four
roots the receipt records — `compiler_root`, `flags_root`,
`environment_root`, `build_graph_root` — read from the one call that
derives them (`zcl_dev_proof_build_identity_v1_capture`), so the donor gate
and the receipt cannot disagree; `warm_donor_scan` refuses a candidate whose
identity does not match this proof's own, and a marker written before those
fields existed (a `fields != 8` shortfall) refuses outright rather than
being adopted unverified. Covered by
`test_pw_marker_identity_invalidates_stale_donor` in
`tests/harness/src/test_impact_composition.c`.
