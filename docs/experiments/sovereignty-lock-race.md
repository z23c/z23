<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Sovereignty projection lock race

A synthetic progress store reproduced a race in the trust display projection:
when another thread acquired the progress transaction lock immediately after the
initial scan, later transition-stamp and guard reads waited for that thread.
The fixture used a test-only post-unlock handshake and released the contender
before joining either worker. The baseline focused group failed its completion
assertion. An intermediate candidate still failed because the guard probes also
reacquired the lock.

The candidate captures stamps and the actual guard results while holding the
original trylock, preserving their ordering and rendering after release. The
focused synthetic fixture exercises a malformed stamp and an eligible guard,
while existing cases cover busy-cache, absent store, timestamp idempotence and
trust/capability behavior. The focused groups passed without skips.

The race is a source-backed explanation for a possible delay, not proof of the
cause of an observed device timeout. The initial scan and SQLite work can still
take time after a successful trylock; this change does not establish an overall
latency bound or change enforcement.

```sh
make -j4 t-fast-exact ONLY=stage_dump_trylock,sovereignty_guard
```

On source `dfd4a628a7b1ffd3e823d7c8336d4fe0a0bf1650`, the final
fixture against the original implementation failed only its two completion
assertions in both the initial run and automatic retry. The repaired source
passed both registered groups cold with zero failures or skips. The test-only
hook does not exist in production builds. Cyclomatic complexity, file-size and
real-clock test checks passed after splitting the fixture helpers; the first
complexity check identified an oversized test helper and failed before that
refactor.
