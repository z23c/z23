<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Repeated-work proof baseline

On 2026-09-08, Linux on an AMD Ryzen 7 PRO 8840U with GCC 16.1.1
20260430 ran the exact proof for `d6943d5f15b6dbdd5a037aa2a37bce08f29165a1`
against `100d8dd4cb1cdd4b82e86c10aff62f83e3f282d1`. The following are
observations under ordinary host load, not controlled before/after comparisons.

| Phase | Wall time |
| --- | ---: |
| Original plan preparation | 20.078 s |
| Generation preparation | 63.869 s |
| Impact closure | 13.473 s |
| Impact rendering | 1.943 s |
| Source identity capture | 7.080 s |
| Shared tool preparation before lint and tests | 222.088 s |
| 126 selected registered groups | 662.7 s |

All 126 selected groups passed with zero cached groups and zero skips. The
runner stored 102 eligible PASS observations; the other 24 groups were
ineligible for caching. Lint failed on duplicate hex decoding, stale generated
inventory, operator paths in two experiment notes, six existing capability
declaration mismatches, and a source-list query contaminated by dependency
setup output. This attempt produced no passing publication receipt.

The corrections reuse the canonical hex decoder, regenerate the inventory,
replace local paths with runtime-resolved worktree labels, match declarations
to independently inspected object references, and keep read-only Make queries
out of dependency setup. No acceptance threshold or baseline exemption changes.

A separate context baseline queried `code capsule` for `zcc_dispatch`: the
cold response was 2373 bytes with 61.051058 s command-reported elapsed time;
the warm response was 2369 bytes with 0.996607 s elapsed time. Both exceeded
the command's 250 ms budget. These response bytes are not model token counts,
and host load was not controlled. No context-retrieval improvement is claimed.

Shared-tool inspection found 2260 fuzz objects totaling 251009512 bytes,
whose modification times spanned 167.528 seconds. Four large links followed.
These objects are shared among harnesses within a generation, but their raw
Clang compile rule bypasses `zcc`. Cross-generation savings remain unmeasured;
the next experiment should compare fresh and cached sanitized objects,
dependency files, and fuzz replay before changing reuse eligibility.

Compile before/after measurements and their reproducible fixture are recorded
in [compile reuse](2026-09-08-compile-reuse.md). End-to-end publication latency
and actual model-token consumption remain unmeasured.
