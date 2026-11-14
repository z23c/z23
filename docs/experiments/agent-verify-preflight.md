<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Agent verification preflight

On 2026-11-14, Android-only candidate `c2d5022a` spent about ten minutes
building the selector producer before reporting a complexity failure. A later
startup-wording candidate `91b4bf9c` built distinct producer and exact-suite
test epochs: the former used the default test flags and the
latter used `ZCL_TEST_WERROR=1`. The bootstrap and exact suite now request the
same strict policy. This observation does not measure end-to-end savings.

The recipe fixture exercised empty input, dirty selections, complexity failure,
changed and route selections, strict bootstrap arguments, explicit groups,
and aggregation after a later failure. Its focused group passed once with no
skips in 54.697 seconds of test-body time.

A cold full lint at candidate `ab17e9a224338b872c7898cdead3da771b6bbb7e`
failed because parallel lint could not find `build/bin/depfile-scope-launch`.
The direct gate named the helper as a prerequisite; the parallel umbrella did
not. A first repair put the edge on the wrong target; its focused run was
cancelled and produced no verdict. The corrected umbrella edge and a test that
removes it in memory passed the strict focused group with no skips in 51.004
seconds of test-body time. Full candidate validation is recorded separately.

The 83-group candidate suite at `06df1575425a93a1f3f4dc101d00490af9950e17`
returned success with one self-skip and one native-classified load-flaky group. The first
`test_device_host_runtime` attempt failed its expected receiver `refused`
terminal assertion after a revoke; its isolated retry passed. The captured log
contained authority-lock errors but did not retain the terminal diagnostic, so
the cause remains unknown. A test-only failure report now emits only allowlisted
terminal and cleanup values, read/buffer state and child exit status; the
assertion and deadlines remain unchanged. The strict focused group passed 1/1
with no skips or retries in 10.399 seconds of test-body time. This run did not
reproduce the failure and therefore does not establish its cause.

The first diagnostic-only candidate was rejected by the complexity preflight
before producer bootstrap; its concurrent lint was stopped and has no verdict.
A literal helper extraction passed the complexity gate. The terminal fixture
previously made one nonblocking diagnostic read, which could stop on an
interrupted or short read. A terminal-only bounded drain now retries interrupted
reads and consumes fragments while retaining the same assertion and deadlines.
A deterministic scripted interrupted/split-read case passed, as did its
EAGAIN, error, full-buffer and call-budget checks. The strict focused group
passed 1/1 with no skips or retries in 9.699 seconds of test-body time. This
fixture defect is established independently; it is not an identified cause of
the earlier load-flaky result.
