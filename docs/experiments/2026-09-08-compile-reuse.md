<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Concurrent compile reuse on Linux

Four simultaneous cold requests for the same compiler inputs previously ran
four compilers. The existing content cache now coordinates those requests:
one compiles, and the other three consume its normal cache entry. Different
keys proceed independently. No command or acceptance authority was added.

One fixed lock inode uses a byte range selected from the existing content
key. This bounds coordination storage independently of the number of builds.
Hash collisions only serialize requests; they never establish cache identity.
The owner releases its range before cache eviction. Process death releases
the range even if a compiler child remains alive.

Waiters rederive the content key before reuse. Changed or unavailable inputs,
an unusable lock, and a 120-second coordination timeout fall back to actual
compilation without cache publication. Audit requests always compile. Cache
hits retain dependency-file rewriting and compiler diagnostics.

The existing key contract is unchanged: compiler identity includes pathname
and stat metadata, not a cryptographic closure of the compiler installation.
Strict mode hashes preprocessed source and the existing recorded link inputs;
ordinary mode retains its documented metadata-based shortcut. This change
does not turn cache hits into independent reproduction or publication proof.

## Controlled fixture

Baseline: `f7ec11759f3fad1d80ccde386c32196a44f08f83`, with the original
`tools/zcc.c`. Both executables were built using GCC 16.1.1 20260430 with
`-std=c23 -O2 -Wall -Wextra -Werror -pedantic` and the same in-tree libraries.
Host: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics, x86_64 Linux
6.12.94-1-MANJARO. The ordinary-affinity run began at
2026-09-08T02:38:05-04:00 / 2026-09-08T06:38:05+00:00.

The fixture contains 1,000 unsigned arithmetic functions, totaling 66,783
source bytes. Four concurrent requests use identical flags, source pathname,
working directory, and strict content-key mode, with distinct output paths.
Each of five rounds has a fresh isolated cache and then an unchanged warm
batch. Before/after ordering alternates. All 80 output objects compared equal.
The node and other ordinary host activity continued; these are host-specific
samples, not universal latency guarantees or p95 estimates.

| Ordinary affinity, five rounds | Before | After |
|---|---:|---:|
| Median cold batch wall time | 1,150 ms | 1,025 ms |
| Median cold batch user + system CPU | 4.53 s | 1.02 s |
| Cold actual compiles, all rounds | 20 | 5 |
| Cold cache hits, all rounds | 0/20 | 15/20 |
| Warm cache hits, all rounds | 20/20 | 20/20 |
| Median warm batch wall time | 12 ms | 11 ms |

This run reduced median cold CPU by 77.5% and avoided 15 duplicate compiles.
Median wall time fell 10.9%; an earlier exploratory run showed roughly
unchanged wall time while retaining the CPU saving. Parallel compilation on
spare cores already overlaps elapsed time, so CPU reduction is the stronger
claim.

| Round | Before cold ms | After cold ms | Before CPU s | After CPU s |
|---|---:|---:|---:|---:|
| 1 | 1,026 | 842 | 3.97 | 0.83 |
| 2 | 1,118 | 883 | 4.37 | 0.87 |
| 3 | 1,150 | 1,025 | 4.53 | 1.02 |
| 4 | 1,244 | 1,105 | 4.88 | 1.10 |
| 5 | 1,226 | 1,046 | 4.75 | 1.04 |

A supplemental run pinned the same script to CPU 15 with `taskset -c 15`
at 2026-09-08T02:38:44-04:00 / 2026-09-08T06:38:44+00:00. It again produced
five compiles and fifteen cold hits instead of twenty compiles, with all
outputs equal. Cold wall-time pairs in milliseconds were
31,617/7,390; 27,644/7,352; 3,331/829; 3,088/832; and 3,174/871.
The large within-run timing shift makes a general single-core latency claim
inappropriate without controlling and recording host frequency/load.

Source SHA-256:
`4769ccff5bf0be3afaeedf4888c57dda4284819a7e1f2c82b29b0b205b000072`.
Output SHA-256:
`eda94945c72625a8093f4a85d70bf69697337d98ab0f94722e74219003969877`.

## Reproduction

Run from this checkout with a C23 compiler. The source snapshot below is a
temporary measurement input; no checkout or Git authority changes.

```bash
measure=$(mktemp -d)
git show f7ec11759f3fad1d80ccde386c32196a44f08f83:tools/zcc.c > "$measure/before.c"
for version in before after; do
    source="$measure/before.c"
    if [ "$version" = after ]; then source=tools/zcc.c; fi
    cc -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
        -D_POSIX_C_SOURCE=200809L \
        -Iplatform/modules/sha3/include -Iplatform/modules/base/include \
        -Iplatform/modules/platform/include \
        -o "$measure/$version" "$source" \
        platform/modules/sha3/src/sha3.c platform/modules/base/src/safe_alloc.c
done
nice -n 10 tools/dev/zcc-reuse-bench.sh "$measure/before" "$measure/after"
```

The script prints its isolated result directory and retains all timing rows,
environment data, source/output hashes, compiler diagnostics, and cache logs.
CPU times sum Bash's child-process accounting for the four requests. Wall
time includes process startup and waiting. No cache or owner state outside
the fixture is changed. Native node services are not stopped for measurement.

## Verification and remaining measurements

`make -j8 lint-fast check-zcc-epoch-object check-zcc-epoch-batch` passed.
The existing cache gate now checks concurrent sharing, unrelated-key
progress, exact diagnostic replay, distinct dependency targets, independent
audits, changed headers during waits, failed and killed owners, and unusable
lock paths. The epoch tests retain source/authority checks, publication
ordering, cache-hit behavior, and allocation-failure coverage.

A separate isolated C23 lock holder exercised the real production timeout:
the waiter completed after 120,169 ms including compilation overhead, while
the holder remained active. It reported a bypass, stored no artifact, and
matched an uncached reference. No timeout override was added.

| Journey stage | Observation or next experiment |
|---|---|
| Intent and context | The native diff is 8,837 bytes versus the 131,105-byte complete tool. This is review-surface size, not model context actually consumed. Instrument retrieval responses before claiming token savings. |
| Compile | Cold compilation count, cache hits, wall time, CPU, and exact output equality measured above. |
| Focused proof | Existing cache and epoch gates pass. Their new concurrency cases add evidence; no before/after proof-latency claim is made. |
| Publication | Mandatory signed proof inputs, contradiction handling, and full publication lint remain required. Fast lint is development feedback, not publication admission. |

Model token usage, fleet-wide work avoided, independent-host performance,
and end-to-end publication latency remain unmeasured. Next experiments should
instrument actual retrieval bytes and proof input closures before changing
retrieval or evidence-reuse eligibility. Null or incomplete proof inputs must
continue to refuse reuse.
