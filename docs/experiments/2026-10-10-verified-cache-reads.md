<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Verified cache reconstruction with caller-owned buffers

Package reconstruction now reads verified chunks directly into the final
output buffer. It preserves the store's exact-size check, chunk verification,
quarantine, lock and access accounting. Invalid bytes remain unpublished.
A valid chunk with an undersized destination still returns a limit refusal
without changing cache availability.

A manifest root commits to the sorted file set, not an arbitrary caller array
order. The indexed getter therefore validates the root and paths, then
requires strict canonical path order before allocating or reading. This is
necessary before removing the outer duplicate chunk verification.

## Source identity

The source was qualified against
`22a52e06e1fa28e71887bf006defdb98c983d362`. Its eight source, test and complexity
baseline preimages are unchanged at integration base
`cd6584925db468dcff685cd94a1394a508305db4`.

| Artifact | SHA256 |
|---|---|
| Source/test patch | `70a8031b0ad3ecb5afbd3018e9b7283468f46549a9bd57bd09f42186497d6028` |
| Source/test postimage inventory | `f7622abf6c8b4adc3c3913327f6f386ca64443e678efbd48499ff46eefcb060d` |
| `package_store.c` | `cc099a4b9cefa38d0c86ff4b3853a8f0eec515017d99a998af4a1dafc9be97d7` |
| `package_content.c` | `6118bafdb7a8012c7a6cc9c09915fe87ea903b5205cedce4eb21f0c395d4f94b` |
| Measured baseline removals | `f8b76bf6b9ed47aa5758fbebe13540f405ba24b8276ad0e72d602758129dbbf9` |

## Correctness evidence

On 2026-10-10, the registered `zcode_store,zcode_fetch` groups passed on the
repaired source and its exact restoration, with two groups run, no cached
results, failures, self-skips or unobserved environment requirements. Five
scoped gates passed: cyclomatic complexity, allocation checking, silent
Boolean errors, C23-only source and the Python prohibition. The measured
getter and chunk-reader complexities were 14 and 7; only their obsolete
baseline pins were removed.

At integration base `cd6584925db468dcff685cd94a1394a508305db4`, canonical
`agent-verify` also passed complexity, the same two exact registered groups,
capability inventory generation and `lint-fast`. The registered run had no
cached results, failures or skips.

The actual getter regression uses two distinct equal-sized 32-byte files.
Swapping their caller manifest entries preserves the package root. The
previous draft returned the wrong indexed file successfully; the regression
failed on that draft and when only the canonical-order check was removed.
The repair and restoration passed. Earlier actual receiver mutations also
proved the direct-buffer path and oversized final-chunk quarantine: restoring
the allocating loop failed native-admit counts; removing exact expected-size
validation failed corruption refusal followed by missing-chunk availability.
These earlier mutations apply to the preceding fixed-order draft and remain
separate from the repaired ordering witness.

## Bounded paired measurement

Host: AMD Ryzen 9 7950X3D on Linux; compiler: GCC 14.2.0. The ABBA run occurred
on 2026-10-10 from 04:22:53Z to 04:24:53Z under one native admission with eight
CPU tokens, 8 GiB RAM and `make -j8`. Admission wait was 0.040190187 seconds.

Each phase prepared the same `perf.bin` package with 8,388,625 bytes and nine
chunks. Byte `i` was `(i * 13 + 7 + (i / 1048576) * 37) mod 256`. The package
root was
`5bd9718c8e30c41e3e567fa235e3c4ca5971e93490375b4e773ca7e13d311a4d`.
Each process performed three warmups and nine measured actual getter calls.
Monotonic elapsed and thread CPU clocks enclosed only the getter; complete
byte validation and freeing followed the measurement. Clock failures refused.
The identical experiment-only test source was used in all phases and is not
part of the product test changes.

| Phase | Source | Elapsed ms: min / median / max | Thread CPU ms: min / median / max |
|---|---|---|---|
| A1 | Parent | 48.902 / 51.860 / 53.459 | 48.902 / 51.706 / 53.382 |
| B1 | Repaired | 14.020 / 14.170 / 14.223 | 14.019 / 14.170 / 14.222 |
| B2 | Repaired | 13.933 / 14.117 / 14.494 | 13.933 / 14.116 / 14.493 |
| A2 | Parent | 27.105 / 27.542 / 27.901 | 27.105 / 27.541 / 27.899 |

The B2 medians were about 49% below the later warmed A2 medians. Every repaired
sample was below every parent sample in this run. The substantial A1/A2 drift
is unexplained; scheduling, frequency and cache effects were not independently
controlled. This bounded observation does not establish a fleet-wide speedup.

Source-derived work removed for this nine-chunk fixture comprises nine
intermediate chunk allocations, 8,388,625 copied bytes and nine duplicate
chunk-verifier calls. Earlier receiver counters prove the API-path change;
they do not measure the benchmark's exact hash count or explain all timing.
Per-sample process high-water RSS stayed unchanged, between 52,612 and
53,332 KiB across phases. It cannot attribute getter peak allocation, so no
measured peak-memory or persistent-space saving is claimed.

Whole registered-command costs, including compilation and other fixtures,
were 45.90, 32.76, 21.56 and 19.62 seconds for A1, B1, B2 and A2. Combined
user/system CPU was 105.08, 76.60, 20.92 and 20.73 seconds. Maximum command
RSS ranged from 1,018,424 to 1,025,712 KiB. These are experiment costs, not
getter latency. No cache was purged.

The benchmark-only patch SHA256 is
`d974f9f42e0119b5e6c2ff02418249c3656bf14cef71c4d73316ba7accbe1a7a`;
its test source is
`8bed35ce651551b4574f40520f225e006b43e0dea83b595c67e3a50b454211e1`.
All 36 raw samples are bound by CSV SHA256
`5edaa99a09d24c5032d7c5049b7bd6e9981d620daf8a447d5bfa5b47577db515`;
the full log inventory is
`844b13f5a7343812db42993e673894e9417ba7f6afb3435d75c49096277521b0`.
All eight temporary source paths were restored to the exact original base
with an empty tracked and staged diff. Native macOS and sanitizer qualification
were not performed for this slice. Persistent disk optimization remains a
separate requirement.
