<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Distinct actions with one component input occupy two worker slots

Date: 2026-09-25T02:39:10Z. Base commit:
`5c1aa2efc0c550f353021df18c6d56cdf64be452`. Host: AMD Ryzen 7 PRO
8840U. Compiler: GCC 16.1.1 20260430, C23.

The worker currently finds an occupied slot by `action_root`. Its equality
check includes the task, candidate, action, input, context, proof policy,
toolchain, target, work kind, and resource limits. The existing registered
`zcode_dev_objects` fixture sends two signed requests with identical task,
candidate, input, context, policy, toolchain, target, work kind, and limits,
but distinct action roots and requester signers. With one advertised slot,
the second receives `BUSY`. The patch in this directory advertises two slots
and observes whether the second request attaches to the first physical work.

```bash
git apply --check docs/experiments/2026-09-25-component-input-duplicate.patch
git apply docs/experiments/2026-09-25-component-input-duplicate.patch
make CC=gcc -j4 t-fast ONLY=zcode_dev_objects \
  > test-tmp/component-input-duplicate.log 2>&1
git apply -R docs/experiments/2026-09-25-component-input-duplicate.patch
git status --short
```

The patched test **intentionally fails** on the unmet attachment assertion.
The local run printed:

```text
COMPONENT_INPUT_PROBE jobs=2 same_input=1 distinct_action=1 disposition=1
FAIL at tests/harness/src/test_zcode_dev_objects.c:1871 (admission.disposition != VCS_ZCODE_WORK_ADMISSION_ATTACHED): 1 != 2
```

`disposition=1` is `GRANTED`; `2` is `ATTACHED`. Both requests were returned
from the worker's physical work queue. The registered group failed 1/1 with
zero skipped groups, after the runner's isolated rerun; the captured log
SHA-256 is `33a54eaf1bcda4bd677218045040b799f1bac6bce5b74a923a5b6eb029085315`.
The patch SHA-256 is
`b901c23b7d5d8b04cdb24c5460147a5604dd847974bbbbfc5a007789c3a9c7d8`.
The original test source was restored to SHA-256
`2dbcd3579744427904a7434a0730fcf26a545ca72ff55acd8daf07b5855e761a`;
the tracked worktree was clean afterward. The 159.5 s test wall time was
under simultaneous full landing proof load and is not a throughput estimate.

This is an executable counterexample to an assertion that equal component
inputs attach across distinct action roots. It measures two dispatchable jobs,
not two completed compilations. A safe fix needs a canonical component input
key that independently binds source, dependency closure, toolchain, flags,
target, harness, environment, and policy. The receiver should verify that
key before attaching a second action to qualified in-flight computation, then
issue separately bound action receipts. A remote success remains evidence
under receiver policy, not automatic acceptance. A follow-up fixture must
measure completed duplicate jobs prevented, queue latency, and receipt
publication after worker death and partition.
