<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->

# Slow-storage scheduling regression evidence

Date: 2026-09-09. Compiler: GCC 14.2.0 (Ubuntu
14.2.0-4ubuntu2~24.04.1). CPU: AMD Ryzen 9 7950X3D, 16 cores.
The initial focused checks used a working tree based on
66389f42ef733331fe86d528531d27d6541b6556. These are functional test results,
not startup-speed benchmarks or long-term node acceptance.

`make -j8 t-fast ONLY=block_scan` passed its one selected group with zero
failures, skips, or cached groups. The new cases exercise the actual scanner's
worker selection: rotating and unknown storage choose one reader; solid
storage retains CPU/file bounds; explicit overrides remain capped; malformed
and overflowing overrides fall back to the hardware policy.

`make -j8 t-fast ONLY=sqlite` passed all three selected groups with zero
failures, skips, or cached groups. The new fixture holds the serialized worker
inside a callback. A try-write refuses without retaining its callback, an
ordinary queued callback still executes exactly once after release, and chain
evidence persists through the detached connection before the worker is
released. A separate SQLite writer lock makes the detached attempt refuse
within the test's two-second hang bound. Subsequent idle and nested writes
still succeed. The existing 250-millisecond lock-release fixture also passes.

The queue mutex covers both the idle admission check and enqueue, so a
catch-up job cannot slip between them. Normal synchronous writes keep their
existing admission semantics. A try-write admitted to an idle worker still
waits for its own execution: no fixed disk-I/O or whole-RPC deadline is
claimed. Detached attempts use a 100-millisecond SQLite busy timeout and the
existing bounded retry policy. Persistence failure remains a failure.

Remaining acceptance includes live slow-disk soak, shutdown/restart recovery,
and responsive status during sustained replay. Historical catch-up still owns
the serialized worker for a whole pass; this change lets evidence collection
avoid that queue, rather than making every database operation preemptible.
No consensus predicate, wallet acceptance rule, database schema, producer
authorization, or watchdog threshold changes.

The strict broad run used `make -j12 test-parallel
TEST_PARALLEL_ARGS="--jobs=12 --no-cache"`: 1,133 groups ran in 272.1 seconds,
with two failed groups, nine parameter-gated groups and 19 self-skips.
The writer census identified the new runtime API's missing declaration in
`fact_store_writers.def`; that declaration is now present. The certificate
permissions failure came from the host build wrapper imposing umask 077 on
its child command. The wrapper now preserves the caller's umask for commands
while keeping its own lock files private. Separate uncached focused reruns
of `fact_writers` and `acme_selfsigned` each passed one group with zero skips.
This does not promote the earlier broad run to a pass.

Explicit stress-enabled focused runs also passed without skips:
`ZCL_STRESS_TESTS=1 make -j12 t-fast ONLY=kill9_recovery` completed its
UTXO-apply, mint-fold and index-import crash fixtures in 4.7 seconds;
`ZCL_STRESS_TESTS=1 make -j12 t-fast ONLY=cold_start_sync` completed in
7.0 seconds. The latter exercises state-machine transitions, not a full
network synchronization or a real-node boot. The crash fixtures use isolated
temporary databases, not either canonical host's datadir.
