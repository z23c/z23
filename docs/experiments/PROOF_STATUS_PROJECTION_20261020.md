<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Proof status execution projection — 2026-10-20

Compiler: GCC 14.2.0 (Ubuntu 14.2.0-4ubuntu2~24.04.1).
CPU: AMD Ryzen 9 7950X3D 16-Core Processor. Test baseline:
3c2d3eb0a7fc48bb4c54261ef492fe14a1b0f3c8.

The compatibility status remains running for an unclaimed request. The additive
projection distinguishes queued, reader-qualified executing, and unknown
execution. Request age is not worker activity; the existing ETA is remaining
timeout budget, not a completion prediction. Dispatch and receipt policy are
unchanged.

<!-- claim: symbol-present proof_execution_state tools/command/native_dev_proof_command.c -->

## Isolated evidence

The original proposed fixture exceeded the existing complexity cap: its live
worker helper measured 20 against cap 15. Runtime tests did not run for that
attempt. Extracting unconditional close, EINTR-aware wait and unlink cleanup
preserved their order and every assertion; the canonical ratchet then passed.
The cap and baseline were unchanged.

With unchanged parent production and the revised fixture, the cold registered
impact-composition group failed because execution_state was absent where queued
was required. The first attempt and the runner's single automatic isolated
retry both failed; both detailed captures were retained. Combined test wall
time was 191.9 seconds. The first capture has SHA256
fb891778fd56bbabb3b94b012cd988ec8c244d8b9041189fcefb42fa2f8a3a38.

With the reviewed production and documentation delta, the same fixture passed
one cold group in 82.7 seconds: zero failures, skips, unobserved environments,
flaky results or isolated retries. The real status reader established a live
fixture worker; queued age and unknown detail cases were asserted separately.
The GREEN log has SHA256
9ea8653ee5e87933b3800fe8af673b3be42c6f88544d2d6565be3d5964be25ea.

Both commands used compact 2 GiB admission with a three-CPU limit. Observed
cache-inclusive peaks were 1,781,288,960 bytes for RED and 1,507,618,816 bytes
for GREEN plus preflight, with zero memory-limit or OOM events. These are
focused workload observations, not full-qualification resource guarantees.

The six-gate preflight passed five checks, including capability closure, and
refused only stale generated capability inventory. Generated inventory remains
owned by native candidate preparation. No full qualification is inferred from
that preflight. Integration advanced to
7d203e340510e9906e5fca9116f570a75a7d32b2 with no change in the three scoped
source/document paths. Full native candidate qualification is a separate receipt.
