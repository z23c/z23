<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Projection MVCC test progress

A retained projection_adoption run stopped after 300 seconds without output
in both the shared pool and its isolated retry. The cause remains UNKNOWN.
That observation does not establish whether the writer was blocked or was
completing slow updates.

The test reports completed phases: database seed, successful creation of the
writer and four reader threads, successful writer join, and successful joins
of all four readers. The writer reports its first successful autocommit UPDATE
and every tenth completion through 1000. Each message is flushed immediately,
following the existing completed-work reporting convention. No timer thread or
periodic heartbeat reports progress while work is blocked.

<!-- claim: symbol-present projection_writer_thread tests/harness/src/test_projection_adoption.c -->
<!-- claim: symbol-present check_projection_mvcc_under_load tests/harness/src/test_projection_adoption.c -->

The workload remains 1000 updates with four readers, the existing sleeps and
error checks, at least 100 successful reader observations, and final height
1100. The runner's 300-second silence limit is unchanged. Progress output
provides phase and completion evidence; it does not guarantee completion or
identify the cause of the earlier termination.

## Observed qualification

On 2026-10-27, the registered group passed with one group run, zero failures,
zero skips and zero load-flaky results. Its test body took 111538 ms. The
transcript contained exactly 101 completed-update milestones in order:
1, 10, 20, through 1000. It also reported the seeded, workers-created,
writer-joined and readers-joined phases. All original final checks passed,
including at least 100 reader observations and final height 1100; the
transcript does not expose their individual measured values.

The tested source blob was
`4d52f5367373137cf62065b53ae6e75ef6373442`. The focused transcript SHA-256 was
`3796fa1b871ed4678e99e0b92440d31edb8700df492dd1afb99d8f8f5ce7cb66`.
The command was:

~~~sh
make -j28 t-fast ONLY=projection_adoption
~~~

The admitted normal-class batch ran from 2026-10-27T06:03:49Z through
2026-10-27T06:13:38Z, including compilation and the required complexity,
file-size, architecture and documentation checks. All those checks passed.
Admission accounting recorded a 2-second wait, 587-second admitted run,
2515 MiB peak memory and 2414 CPU seconds. These are batch measurements,
not isolated test costs. The compiler was GCC 14.2.0
(Ubuntu 14.2.0-4ubuntu2~24.04.1) on an AMD Ryzen 9 7950X3D.
The actual resource scope allowed 28 CPU equivalents and 24 GiB memory;
a retained intermediate sample reported zero memory-limit and OOM events.

This run demonstrates truthful progress on completed work and passing
existing checks for the identified source. It does not explain the earlier
termination or establish a speedup. Native exact-candidate landing proof
remains pending.
