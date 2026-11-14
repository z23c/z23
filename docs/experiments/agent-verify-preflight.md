<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Agent verification preflight

On 2026-11-14, an Android-only candidate spent about ten minutes building the
selector producer before reporting a complexity failure. Its producer and exact
suite built distinct test epochs: the former used the default test flags and the
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
