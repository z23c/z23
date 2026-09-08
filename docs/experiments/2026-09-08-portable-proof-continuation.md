<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Portable continuation of the repeated-work proof

The exact proof for `16b524458c767b29931b173c49bbc16eb3b69b5a` against
`100d8dd4cb1cdd4b82e86c10aff62f83e3f282d1` passed all 128 selected registered
groups with zero skips in 623.4 seconds on 2026-09-08. It also passed 208
lint gates. The remaining Windows syntax gate scanned 2255 source files:
2246 clean, nine failures, no generated-header or OpenSSL-header skips, no
baselined failures, and no infrastructure failure. No publication receipt
was admitted.

Seven failures were unguarded POSIX UTC conversion calls. Two were filesystem
calls in developer observation and landing preparation. The existing
`base/utc_tm.h` and platform file-metadata interfaces provide the portable
operations; no additional compatibility implementation is required.
Process observation through `/proc` must distinguish unavailable observation
from an observed absence of processes.

The measured Linux host was an AMD Ryzen 7 PRO 8840U. Native compilation used
GCC 16.1.1 20260430; the syntax gate used the installed MinGW GCC 16.1.0.
Its Windows cache selftests passed before the scan: unchanged inputs replayed
identical results, changed headers invalidated all dependent fixtures, one
source edit invalidated one fixture, and stored failures remained failures.
The real scan reported zero cache hits and 2255 stored observations. These
are exact syntax observations, not native Windows execution or deployment
acceptance.

The failed proof remains preserved while portable repairs undergo a new
complete composed proof. No baseline or acceptance threshold is relaxed.

A prospective `dev.change.plan` over the nine failing source paths, run from
the explicit integration worktree at that commit, took 36.932 seconds and
returned 7285 bytes. It selected 464 exact execution groups, with 275 closure
groups, no universal or truncated closure, and a valid admissible execution
set. Additional header and test edits were outside that measurement; the
final proof must derive its own complete selection. The raw response and
external timing are retained as `/tmp/z23-windows-nine-impact.json` and
`/tmp/z23-windows-nine-impact.time`.

## Complete portable proof and integration

The composed proposal `421297ba1ce09e904daa526575362e2e18d708a3` against
`503cf53c5f056e1a866abde7bce74e65eaed1ead` obtained a passing exact native
receipt on the same Linux host on 2026-09-08. All 358 selected registered
groups passed with zero cache hits and zero skips. One group,
`test_impact_composition`, exceeded the pooled silence bound and passed the
runner's normal isolated retry; the result retains `load_flaky=1`.
Registered execution took 860.3 seconds. All publication lint gates passed,
including 2255 clean Windows syntax observations with no skipped or baselined
sources. Recorded proof phases totaled 1410.981 seconds under ordinary host
load; this is not a controlled end-to-end speedup measurement.

An earlier attempt at the same source refused during its bounded source
verification. Independent verification of its exact mutation token passed,
and an explicit unchanged-source retry produced the receipt above. No source
identity check or timeout threshold was weakened.

The local push hook admitted that receipt, but the remote rejected its merge
history. A fresh signed linear commit retained the byte-identical tree and
preserved the proposal branch. Its new proof was superseded during shared-tool
preparation when upstream advanced to
`4d4bec5b8915b8f91437f7e11d6a0fc8d3c43ddf`. That interrupted attempt is not a
PASS. The reviewed upstream changes and the performance proposal require a
new exact composed receipt; prior receipts do not authorize the new commit.
