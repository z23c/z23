<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Agent summary synthetic timing

On 2026-11-15 UTC, a test-only fixture measured the agent summary with four
million synthetic nullifiers in a SQLite table using the production nullifier
key and height index shape. The AMD Ryzen 9 7950X3D host used GCC 14.2.0.
The admitted `make t-fast ONLY=stage_dump_trylock` run passed one group.

Three in-process summary calls took 332700, 316673 and 315357 microseconds;
their `first_call.elapsed_ms` values were zero. A separate trust-tier call
on the same fixture took 156723 microseconds, and a separate detail call took
26 microseconds. With the progress lock held by a test thread, the trust-tier
call took 3 microseconds. These are individual measurements, not simultaneous
instrumentation of internal stages; file size and phone hardware were not
measured. The test summary exceeds 250 ms with caches disabled; a separately
measured fresh production-shaped trust collector took 156723 microseconds.
Production normally caches the second lookup. The measurements do not establish
the cause of a phone timeout or include network transport.

The test build disables the trust-tier cache. The readiness facts collector
and trust-tier output each call that collector, so the repeated fresh scans in
this test do not represent production warm-cache behavior.

<!-- claim: symbol-present rpc_agent_summary cognition/controllers/src/event_agent_summary.c # agent summary -->

The display projection was then changed to share the sovereignty trust
predicates without collecting pool counts. Replaying the same synthetic fixture
on the same host yielded summary calls of 707, 437 and 410 microseconds, a
separate fresh trust-tier call of 59 microseconds, and a contended trust-tier
call of 3 microseconds. These are individual in-process samples with test
caches disabled; they are not phone or network measurements.

The focused `stage_dump_trylock` group passed after the change. Its small
fixture traces SQL and checks that the full sovereignty dump runs four pool
counts, while the agent summary runs none; trust and capability fields are
compared against the full dump. It also checks the unavailable store and both
initial and previously populated busy-cache paths. Complexity and file-size
checks passed. An initial focused run failed because the synthetic SQL fixture
used an invalid C hex escape; the fixture was corrected and the run repeated.
