<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# C23 code-growth cache latency

## Intent

Make repeated and incrementally updated `app presentation code-growth` reads
complete within the existing 750 ms command budget without accepting stale
source measurements.

## Environment

- Local time: `2026-09-03T13:01:35-04:00`
- UTC: `2026-09-03T17:01:35Z`
- CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics
- Compiler: GCC 16.1.1 20260430
- Baseline commit: `2a82d3a427a16d801a60c6db77fbf3183b5d518e`
- Candidate commit: `31016afbe17df3d9c894c1473671998ef6915fb8`

## Method

The baseline command reconstructed 85 UTC days and reported 12,415,316 us.
An isolated shell timing attributed 15.710 s to the full first-parent Git
numstat stream and 0.959 s to the maintained-tree corpus command. Exact HEAD
and maintained-root cleanliness checks took 0.068 s together before the
change.

The candidate stores the census-checked raw Git stream in an owner-only local
cache. Reads require an exact clean source identity, cache format and contract
version, root-set digest, payload SHA3-256 digest, and a stable HEAD across the
read. A descendant HEAD appends only its verified first-parent delta. Changed
rules, unrelated history, dirty source, malformed bytes, or a failed digest
fall back to the cold reconstruction and fresh census.

Five consecutive clean cache-hit commands were measured from the candidate:

| Sample | Elapsed (us) | Cache hit |
| ---: | ---: | :---: |
| 1 | 226,981 | yes |
| 2 | 190,258 | yes |
| 3 | 241,948 | yes |
| 4 | 382,275 | yes |
| 5 | 396,984 | yes |

## Result

All five reads completed within 750 ms. Median latency was 241,948 us, 51.3
times faster than the 12,415,316 us command baseline. The result contained 86
days, 1,151,366 non-test lines, and 708,111 test lines on every sample.
A subsequent documentation-only descendant commit exercised the incremental
first-parent path in 499,221 us and remained within the same budget.

`test_code_growth` passed cache-hit equivalence, corrupted-cache rebuild,
dirty-source refusal, and first-parent extension cases. The `science` and
`code_inventory` focused groups passed, and all 27 `lint-fast` gates passed.
