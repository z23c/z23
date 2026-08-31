<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Story-ranked product-loop retrieval

## Intention

Reduce the source context needed to begin a realistic application change by
ranking existing symbols from repository-owned product language before
proposing new code. Preserve a frozen pre-change literal selector so that the
comparison measures the production ordering change instead of reconstructing
a favorable baseline after the fact.

## Question

Can repository stories and symbol metadata move relevant implementation files
into a bounded first page for realistic historical application tasks, while
the product path remains source-bound, deterministic, and fast enough for an
interactive first turn?

## Environment

- Measurement local time: `2026-08-31T06:48:26-04:00`
- Measurement UTC: `2026-08-31T10:48:26+00:00`
- Source commit: `dbbfd61bf7b060d12f1a81e5365f65b0c7925d2c`
- Compared upstream: `d8868852556eb40d8e6c8caba8df2346456709d6`
- Host: Linux 6.12.94-1-MANJARO x86_64
- CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics
- Compiler: GCC 16.1.1 20260430, `-std=c23`

The measured source commit contains the implementation under review; it is not
presented as an accepted release commit.

## Method

The reviewed gold corpus contains 10 application-facing tasks. Each record
binds a query, relevant paths, a historical parent commit, and the exact clean
source-manifest root for that parent. Queries were recovered from same-change
documentation or commit subjects because the original interactive prompts are
not available. Relevant paths are reviewed outcome labels and are not added to
the retrieval index.

`make retrieval-gold-benchmark OUTPUT=<new-directory>` performs the following
operations once per record:

1. extracts the exact parent with `git archive` into an isolated directory;
2. invokes the native retrieval command once with the expected source root;
3. rejects a changed pre- or post-query source root;
4. records both the frozen literal ordering and production BM25 ordering; and
5. feeds the first 20 retained ranks to the maintained native evaluator.

The production index uses path, command group, purpose, symbol names,
signatures, documentation, and guards. The goal-context selector combines its
score with the existing literal signal. This is the current concrete link from
product story to work: story words select indexed taxonomy fields, ranked
symbols select source excerpts, and the existing work command carries those
excerpts into impact and proof planning. Formal Horn relations exposed by
`code relations` are not yet a ranking input; that remains a measured product
gap rather than an implied capability.

The runner made 10 native benchmark invocations, no compiler invocation, and
no retry inside the task loop. It made no model call. Development-session tool
calls outside this bounded runner were not instrumented and are not claimed.

## Retrieval result

All 10 tasks matched their expected source roots. The evaluator reported:

| Metric | Frozen literal | Production BM25 |
| --- | ---: | ---: |
| Recall@5 | unavailable | 8.42% |
| Recall@20 | unavailable | 31.52% |
| MRR | unavailable | unavailable |
| Unique file selections at 5 | 47 | 50 |
| Projected context bytes at 5 | 1,031,155 | 970,588 |
| Approximate tokens at 5 | 257,789 | 242,647 |
| Wrong-scope rate at 5 | unavailable | unavailable |

The literal metrics are unavailable because several frozen rankings terminate
before five unique files; the evaluator refuses to turn incomplete rankings
into zeros. The BM25 page contains 20 ranks, so Recall@20 is exact for that
page. MRR remains unavailable because a relevant result may exist beyond the
observed page. Context cost is projected from whole source-file sizes; those
bytes were not read into a model context. Production BM25 reduced that
projection by 60,567 bytes, or 5.87%, at rank five.

Before expanding the corpus, the original production literal selector was
also run over the first seven tasks. It placed no relevant path in the returned
16-file window: zero task hits, zero relevant hits from 31 labels, and zero
Recall@5. The hybrid selector produced four task hits in the same seven tasks,
three relevant hits at five, and seven relevant hits in the returned window.
This supplementary measurement is not substituted for the stricter 10-task
native evaluator above.

Per-task native elapsed time was:

| Task | Microseconds |
| --- | ---: |
| `zcode_embedded_nul` | 4,787,636 |
| `api_cache_cooperative_shutdown` | 6,057,549 |
| `package_verifier_object_reuse` | 5,943,514 |
| `connected_peer_manifest_refresh` | 6,112,792 |
| `private_object_grant_encryption_order` | 6,168,069 |
| `sync_discovery_liveness` | 6,059,191 |
| `windows_verified_checkout` | 6,151,388 |
| `vault_holdings_exact_units` | 6,155,178 |
| `mesh_capability_cancel_restart` | 6,150,018 |
| `onion_discovery_catchup_contention` | 5,907,689 |

The sum was 59,493,024 microseconds, the mean was 5,949,302 microseconds, and
the range was 4,787,636 to 6,168,069 microseconds. This exact-parent benchmark
is intentionally cold with respect to each extracted source tree. It does not
meet the one-second warm target.

## Product-path result

An isolated `zcode work start` requested `Count UTF-8 words in a text file and
print the total.` The production path selected one file and the existing
`textstat_words` symbol. Selected context was 1,143 bytes from a 3,272-byte
candidate corpus. Retrieval took 312 microseconds, context generation took
1,538 microseconds, and the complete command took 252,343 microseconds. No
compiler ran and no retry occurred. The command reported `reuse=no_match` and
left creation of the missing application code as the next action; discovery
did not silently install, execute, or accept code.

This meets the representative first-turn and fewer-than-20-files targets. It
does not prove the same latency or precision over the full historical corpus.

## Profile and largest waste

`perf` was unavailable on the measurement host. A Callgrind run recorded
28,311,864,261 total instructions for a cold exact-parent benchmark.
`vcs_walk.c:walk_dir` had 31,123,169,031 recursive inclusive instructions.
Recursive inclusive counts can exceed the program total because descendant
work is charged at multiple recursion levels, so this is evidence of the
dominant call tree, not a percentage. Exact source-manifest traversal is the
largest observed retrieval cost; ranking is not the dominant cost.

The next latency experiment should reuse an already verified source manifest
and index for unchanged trees, then separately measure warm query latency. It
must retain pre/post source binding and must refuse stale identity rather than
trading correctness for speed.

## Build, diagnostics, and cache limits

The combined C23 development binary built cleanly with GCC 16.1.1, and the
focused `codeindex` group passed with an approximately 0.5-second test body.
The build tree contained 2,085 development objects and 3,164 test objects;
these are retained artifacts, not compiler-execution counts. Current build
receipts did not expose exact compiler invocations, compile-cache hits, or
misses for this edit, and edit-to-first-diagnostic latency was not captured by
a machine-readable stopwatch. No values are inferred for those requested
measures.

The next development-loop experiment must enable the in-tree cache log before
the edit, record compiler executions and HIT/MISS/BYPASS outcomes, and time the
first emitted diagnostic. Until that receipt exists, the compiler/cache and
edit-to-diagnostic parts of the product-loop quality bar remain unknown.

## Conclusion

The change replaces duplicated command-local BM25 code with one shared C23
index and carries repository story ranking into the product goal-context path.
It improves measured first-page recall over the historical literal behavior
while slightly reducing projected five-file context. The representative
product request selects one reusable symbol in 252 milliseconds. Exact-parent
batch latency, incomplete baseline rankings, absent wrong-scope labels, and
unmeasured compiler/cache behavior remain explicit constraints on acceptance.
