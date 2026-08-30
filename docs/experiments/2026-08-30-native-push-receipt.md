<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Native push-receipt baseline

## Question

Can push admission verify an exact local commit and advertised remote base
without running build, lint, test, or shell work, and where does latency remain
outside that admission path?

## Environment

- Local time: `2026-08-30T04:36:46-04:00`
- UTC: `2026-08-30T08:36:46+00:00`
- Host: Linux 6.12.94-1-MANJARO x86_64
- CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics
- Compiler: GCC 16.1.1 20260430, `-std=c23`

## Method and observations

`make git-hook-selftest` created one valid fixed-width aggregate receipt,
read, parsed, and validated it 1,000 times, then exercised stale, incomplete,
hollow, skipped, aggregate-tamper, and child-tamper refusals. The measured p95
was 7 microseconds. The selftest spawned zero child processes.

An actual missing-receipt invocation used a real Git ref tuple and the native
hook's ancestry check. It refused with the exact `dev proof wait` command in
42 milliseconds. No compiler, test, lint, Make, Bash, or PowerShell process is
reachable from receipt admission; `make check-dev-proof-native-fast-path`
enforces that source boundary.

Native impact planning for only `docs/CAPABILITY_INVENTORY.jsonl` completed in
28 milliseconds and selected exactly `test_code_inventory`. It selected no
`make_lint_gates` shard. The generated-output freshness gate itself took
47,497 milliseconds despite warm generator artifacts. The directly executed
inventory test reported 4,332 milliseconds of runner startup and 34
milliseconds of test body.

The Equihash prose/freshness lint gate initially took 16.734 seconds warm even
after its generated tool was current. Its script recursively visited ignored
build, vendor, and proof-generation trees before filtering their output, and
started a nested Make invocation on every run. Restricting the scan to Git's
tracked source set and making the generated fact tool an explicit parent-Make
prerequisite reduced the same warm gate to 46 milliseconds, with the same
plant/trip/recover self-test and document comparison.

The combined 30-file integration delta selected 50 distinct registered test
groups. The previous 32-group storage bound refused the complete result as
`path-group-cap`; the shared impact accumulator now retains 64 distinct path
groups and the composed planner retains 256 groups so graph-derived additions
cannot consume the path floor's capacity. Both continue to fail closed beyond
their bounds. The plan's wire renderer remains independently bounded and
abridges only presentation.

## Knowledge gained

- Exact receipt admission is comfortably below the 250 millisecond target.
- Missing evidence fails below the one-second target and does not start proof
  work at push time.
- The former broad inventory impact route is not responsible for remaining
  inventory latency.
- Make startup, repeated generator scanning, and test-runner startup dominate
  the current generated-inventory path. A five-second warm acceptance claim is
  not yet supported by measurement.
- Exact input enumeration removed 16.688 seconds from the warm Equihash gate;
  native gate execution remains a separate parity task.
- A coherent multi-component push can legitimately exceed 32 focused groups;
  storage bounds must cover measured repository diffs without converting a
  complete impact answer into a permanent refusal.
- A self-sealed aggregate is insufficient by itself. Selected dimensions now
  name fixed-width content-addressed child receipts, and the hook requires each
  child object to exist and match its exact accounting.

## Next experiment

Give generated-output and remaining lint producers native content-keyed child
receipt publication, then compare a cold audit with warm direct admission.
Move compile-epoch session validation, depfile restoration, and hit batching
into `zcc` and count process creation before and after.
