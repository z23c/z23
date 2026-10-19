<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# MVP parity reporter evidence boundary

Intention: prevent a zero mismatch counter from qualifying public-node C8
without the exact replay and continuous parity evidence required by
`docs/quality/MVP.md`. The previous classifier reported C8 `met` with an active
oracle, zero mismatches, and no canary evidence.

The classifier now requires a present genesis PASS, freshness within seven
days, matching running source and artifact identities, a current coarse
match, and retained identity-bound zero-mismatch parity coverage for 168 hours.
Each missing obligation produces `unknown` with a named reason. An explicit
canary FAIL or observed mismatch remains `unmet` and takes precedence over
missing or positive qualification evidence.

The live reporter does not produce these positive qualification claims.
The existing canary watcher exposes source and artifact identities, verdicts,
and timestamps, but retains historical slots after sentinel removal.
Its scan count and quiet FAIL latch do not establish a currently present,
fresh genesis PASS. The parity service exposes counters and checked heights,
but does not retain an identity-bound continuous 168-hour observation window.
The new positive flags therefore remain false in the live evidence collector.
This repair closes a false positive; it does not complete C8 acceptance.

Continuation: expose current sentinel presence through the existing canary
watcher and qualify its genesis verdict, timestamp, source identity, and
artifact against the running executable. Retain the complete 168-hour parity
window through the existing evidence owner, binding the oracle, exact source
and executable, interval, successful checks, mismatches, gaps, and freshness.
Only independently qualified facts may populate positive reporter evidence.
Existing `tools/mvp_gate.sh` remains the operator gate; its fresh exact genesis
and live coarse checks do not substitute for missing duration evidence here.

The registered `syncdiag_rpc` regression exercises the original zero-counter,
absent-canary counterexample, omission of each positive obligation, unknown
mismatch count, and negative-evidence precedence. Its positive case supplies
synthetic evidence to the pure classifier and makes no live parity claim.

Validation at source preparation: `git diff --check` passed. Exact candidate
build, focused execution, mutation sensitivity, and runtime acceptance are
`NOTRUN` until separately recorded. No production node or consensus predicate
was changed.

## Focused execution and mutation evidence

On 2026-10-08, candidate `9ea162b9d24b1ca69d4745adbc5e91ffea02e005`
passed the cold registered `syncdiag_rpc` group through `devbuild --wait`
on Linux x86-64, AMD Ryzen 9 7950X3D, GCC 14.2.0. The fixed run took
80.0 seconds: one group ran, zero failed, zero skipped. The remaining
1259 groups were outside this focused selection.

A production classifier mutation accepted `c8_parity_present` as an
alternative to `mvp_c8_qualified(ev)`. The regression named
`mvp C8 zero counters require exact genesis and complete window` failed,
and the registered runner returned failure. Restoring the exact source
produced a cold pass in 59.8 seconds, again with zero failures or skips.
The remote checkout was clean after restoration.

| Observation | Log SHA-256 |
|---|---|
| Fixed | `9d9ca80d077f4d60076e02fb1dae84a9236a1f2e9bf612214e8b856631cc730c` |
| Mutated | `670cc975e3534e95d60a248daf7811b07dca43dd780a74853d98efb06d4790e1` |
| Restored | `1e8af2454e9c6aee25b31e147355908db54ecbded39313baab09410a70170b05` |

This is focused classifier evidence for the named candidate, not public-node
C8 acceptance or an integration receipt for another commit. The three source
and regression files match candidate `8095f25067d1a1c797172ea3320bc0b38f6ae462`
on main `e0aa31975b9fcd30c11125ab50f3fadf6fafa931`; that source comparison
does not replace the new candidate's required integration gates.
