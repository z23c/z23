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

`ZCL_RETRIEVAL_BENCH_KEEP=1 make retrieval-gold-benchmark` performs the
following operations for every record and preserves its sealed scratch
artifacts for inspection:

1. opens the exact parent as a clean detached worktree;
2. independently captures and checks the expected source root;
3. proves every relevance label is either present in or explicitly outside the
   C23 index;
4. paginates and independently re-roots all retained ranks from both the frozen
   literal ordering and production BM25 ordering;
5. rejects a changed post-query source root; and
6. feeds the complete retained rankings to the maintained native evaluator.

The production index uses path, command group, purpose, symbol names,
signatures, documentation, and guards. The goal-context selector combines its
score with the existing literal signal. This is the current concrete link from
product story to work: story words select indexed taxonomy fields, ranked
symbols select source excerpts, and the existing work command carries those
excerpts into impact and proof planning. The canonical work context root then
becomes StoryGraph's `agent_finds_code` evidence; later canonical receipts
project build, test, application-run, and acceptance relations without creating
a second authority. Formal Horn relations exposed by `code relations` are not
yet a ranking input; that remains a measured product gap rather than an implied
capability.

The runner made 63 native benchmark invocations over nine eligible tasks, 98
native membership queries, and 20 native source captures: 181 native command
invocations in the bounded loop. One task was proved outside the C23 index and
was not scored as a miss. The loop made no compiler invocation, retry, or model
call. One serial prerequisite build was stopped and restarted with 16 jobs
before the task loop; that setup retry is not hidden inside task timing.
Development-session tool calls outside this bounded runner were not
instrumented and are not claimed.

## Retrieval result

All 10 tasks matched their expected source roots. Nine were eligible for C23
index evaluation and one Make/shell task was explicitly unsupported. The
evaluator reported over the nine eligible tasks:

| Metric | Frozen literal | Production BM25 |
| --- | ---: | ---: |
| Recall@5 | unavailable | 9.36% |
| Recall@20 | unavailable | 35.02% |
| MRR | unavailable | unavailable |
| Unique file selections at 5 | 43 | 45 |
| Projected context bytes at 5 | 946,050 | 853,082 |
| Approximate tokens at 5 | 236,513 | 213,271 |
| Wrong-scope rate at 5 | unavailable | unavailable |

The literal metrics are unavailable because several frozen rankings terminate
before five unique files; the evaluator refuses to turn incomplete rankings
into zeros. All retained BM25 ranks were reconstructed across seven pages per
eligible task, so Recall@20 is exact within the retained 128-file bound. MRR
remains unavailable because a relevant result may exist beyond that bound.
Context cost is projected from whole source-file sizes; those bytes were not
read into a model context. Production BM25 reduced that projection by 92,968
bytes, or 9.83%, at rank five.

Before expanding the corpus, the original production literal selector was
also run over the first seven tasks. It placed no relevant path in the returned
16-file window: zero task hits, zero relevant hits from 31 labels, and zero
Recall@5. The hybrid selector produced four task hits in the same seven tasks,
three relevant hits at five, and seven relevant hits in the returned window.
This supplementary measurement is not substituted for the stricter nine-task
eligible evaluation and one explicit unsupported classification above.

Per-task native elapsed time was:

| Task | First page (µs) | All pages (µs) |
| --- | ---: | ---: |
| `zcode_embedded_nul` | 4,585,306 | 12,116,327 |
| `api_cache_cooperative_shutdown` | 6,191,216 | 19,108,627 |
| `package_verifier_object_reuse` | unsupported | unsupported |
| `connected_peer_manifest_refresh` | 6,114,353 | 19,197,012 |
| `private_object_grant_encryption_order` | 6,376,380 | 20,003,797 |
| `sync_discovery_liveness` | 6,708,151 | 20,345,808 |
| `windows_verified_checkout` | 6,416,448 | 19,878,431 |
| `vault_holdings_exact_units` | 32,378,487 | 77,739,656 |
| `mesh_capability_cancel_restart` | 5,743,449 | 18,211,693 |
| `onion_discovery_catchup_contention` | 6,569,158 | 19,507,093 |

First-page time summed to 81,082,948 microseconds, with a 9,009,216
microsecond mean and a 4,585,306 to 32,378,487 microsecond range. All-page time
summed to 226,108,444 microseconds, with a 25,123,160 microsecond mean. This
exact-parent benchmark is intentionally cold with respect to each source tree.
It does not meet the one-second warm target; the vault epoch was a clear
outlier rather than a value replaced by the mean.

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
The final build epochs contained 2,087 development objects and 3,167 test
objects;
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
