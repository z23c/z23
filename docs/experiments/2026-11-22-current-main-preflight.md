<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Current-main verification on a remote development host

## Comparison base

The sender supplied candidate `8c634e979696` to the remote development
gate on 2026-11-22. Its parent was `53b6b2567e08`. The receiver cloned its
local checkout and verified the submitted commit and tree. Without an
explicit comparison base, Make selected the merge-base of the candidate
and the clone's `origin/main`, `43026f1ca900`. That base was 401 commits
behind the candidate's parent. The selection ran after producer bootstrap.

The remote proof assignment in `tools/dev/dev_proof_remote.c` binds the
offer, receipt and impact evidence to the requested commit/base pair.
The offer verifier rejects an empty selection or a reported base other than
the offered base after running the child. Both support exact historical
evidence. The native land driver independently observes main during proof
and checks the publication base at push. The offloaded Make job did not
invoke these offer checks.

## Retained job measurements

The receiver broker recorded one interrupted job, `run.AOIajZj8`, with
0.064 s in queue and 620.834 s from queue entry to reap. Its systemd scope
used 1,397.931 CPU-seconds. Producer bootstrap took 246 s, group selection
74 s and capability closure 88 s. It selected 1,608 groups. The interrupted
test step produced no suite verdict. There were 8,888 object files in the
retained scratch tree; cache misses and completed test groups are unknown.

The same candidate subsequently passed against its parent on the sender.
That run selected and executed 54 groups in a 792 s verification. The native
landing proof took 445.709 s and queue row 3721 landed on its first attempt.
Commit to landing took 2,027 s, including the interrupted remote attempt.
The task accounting was 600,829 tokens, including the build-cache work.
Neither the worker logs nor task accounting isolate tokens for the stale run.

## Controlled sender comparison

One run per case on r1 used a disposable two-repository fixture, a real C23
compile and test, and the original or patched sender adapter. SSH, transfer,
inner admission and durable sync were local fixture substitutes. The enclosing
job used host admission. Wall times include local scheduling.

| Receiver case | Sender | Wall s | CPU s | Compiles | Test executions | Result |
|---|---|---:|---:|---:|---:|---|
| 401 behind | Original | 0.58 | 0.20 | 1 | 1 | Passed |
| 401 behind | Patched | 1.44 | 0.04 | 0 | 0 | Refused before bundle |
| Matching | Original | 2.22 | 0.14 | 1 | 1 | Passed |
| Matching | Patched | 1.14 | 0.29 | 1 | 1 | Passed |
| Advanced after execution | Patched | 0.37 | 0.27 | 1 | 1 | Refused at return |

The sender rejected missing, wrong-base and empty-universal selection reports.
An exact zero-group report with static checks passed with zero test executions.
Explicit historical verification retained the requested base. The native
command fixture exercised divergent history, missing objects, an annotated tag,
an unavailable origin and a missing main ref. The focused group passed once.
A separate live-origin stale query took 0.83 s wall and 0.09 s CPU. This
sample does not establish fleet-wide savings or a token cost per refusal.
