<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Named landing-drive scope

Date: 2026-10-20. Baseline: `bd42f6ee512d8423168256379cb736adf1de1d67`.
Compiler: GCC 14.2.0 (`cc (Ubuntu 14.2.0-4ubuntu2~24.04.1) 14.2.0`).
CPU: AMD Ryzen 9 7950X3D 16-Core Processor.

## Intent and boundary

A maintainer requesting `dev land drive --seq=N` must not advance another
queued row. The original driver ran a global session before checking its
named target, so an older eligible row could be changed even for an unknown
or already terminal target.

The candidate inspects unknown and terminal targets before starting a
session. Under the existing step lock it checks the ordinary selected row
before shared work and again at the actual selection. A different selected
row refuses with the requested and blocking sequence in the existing typed
refusal. FIFO and dependencies remain in force; naming a later row does not
jump the queue.

Named drives skip global pool sweeping and queued-row prechecking, and
refuse a publication fence spanning another row. Queue-wide drive/step paths
retain those operations. The normal proof selector filters by the requested
sequence without fallback; existing exact local/base pins remain in place.
It does not hold the step lock across proof execution.

## Focused experiment

The registered `dev_land` group ran through supported compact admission,
CPU3 and a 2 GiB memory limit. Each corrected invocation used a different
fresh owner-private absolute outer `XDG_STATE_HOME`, with HOME/XDG captured
in its private receipt. Native claims and submissions use canonical state;
this outer override applies only to the focused test invocation.

```sh
private_state=$(mktemp -d) || exit
case "$private_state" in /*) ;; *) exit 64 ;; esac
XDG_STATE_HOME="$private_state" ZCL_BUILD_MAX_JOBS=3 \
  devbuild --wait --project z23 --class compact --cpu-limit 3 \
  make -j3 t-fast-exact ONLY=dev_land \
  T_FAST_EXACT_ARGS='--no-cache --jobs=3'
```

Six handler cases cover an older queued row 674 with requested row 685,
unknown and terminal targets, the positive requested head, and a shared
signed publication fence. Negative cases check the queue, landing worktree
and private origin; the shared-fence case also checks its sealed fence bytes
and worktree HEAD. The positive head case compares the entire unrelated row
685 before and after. Existing queue-wide proving and bounded-row cases stay
in the same registered group.

| Source | Observed result |
| --- | --- |
| Original production plus guarded fixtures | Six expected failures in the first attempt and canonical isolated retry; one cold group failed, zero skips, unobserved results or flaky verdicts; 290.2 seconds reported test wall time |
| Candidate production plus the same fixtures | One cold group passed; zero failures, skips, unobserved results or flaky verdicts; 137.8 seconds reported test wall time; no retry |

The corrected RED command waited 44.396 seconds for admission and peaked at
892149760 cgroup bytes. GREEN waited 0.026 seconds and peaked at 657502208
bytes. Both recorded zero memory-max and OOM events. These are workload
observations, not a speedup comparison.

Canonical fixture-tag identities were byte-identical before, during and
after both corrected runs: no new matching canonical submissions were
observed. Their normalized before/after SHA256 is
`17d71f005484caeb99659540287b87c55f0b27400fe53687e29a955d95ad5481`.
The RED log SHA256 is
`930d899e1191415eb2bee13a320de22f27b8f53a6df95e41ddef513f4e8b3f61`;
GREEN is
`8a711df78a5711b1467ac89f0b7784f03d25ae2c19ef4c99465af38bb5ce2495`.

The first complexity check reported `dl_step` at M=18. Small entry and
precheck helper extractions preserved order and brought the candidate under
the unchanged ratchet. Final canonical complexity passed: 86787 functions,
5213 files and 3888 exact baseline pins at cap 15. No threshold or baseline
was raised. The two-file candidate patch SHA256 is
`97ece6ae5f0b4582d278d2953542b63a0b060386160e2d928eb846aefc706858`.

## Isolation failure and limits

An earlier RED fixture omitted explicit isolation before its shared-fence
preparation helper. It caused two unintended owner-queue submissions; the
owner subsequently cancelled both through the native queue. The owned test
command was stopped and its evidence retained. A preparation failure does
not establish that preceding native calls had no effect. Other historical
global-step effects remain unproven absent; that run is not clean
shared-fence qualification.
Only hashes of the original offending runner and object were retained before
their epoch paths were rebuilt; their original bytes were not frozen.
Serialized helper replies were not retained. Exact source and contemporaneous
logs and state snapshots remain separate evidence.

The repaired fixture explicitly isolates first and checks its effective
state base against its expected fixture state before any delegated native
submit or step. Absent and mismatched expected-state tests refuse without
creating a queue. Both guard checks passed in corrected RED and GREEN.

The production-only post-step cancellation window and actual proof-pool
preservation were source-reviewed, not reproduced by the hermetic proof
stubs. Focused PASS does not establish full candidate qualification, queue
acceptance or landing.
