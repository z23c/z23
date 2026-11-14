<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Peer latency without a sample

On 2026-11-14, the peer latency response was changed to report an unknown
measurement as JSON null. A positive completed ping remains a numeric
millisecond value. The separate `pingpeer` response was not changed.

At base `6ff1d9c1ddcce28d3f535a226ea99e0d002069f5`, the focused strict
`make -j8 t-fast ONLY=game ZCL_TEST_WERROR=1` run passed four groups with no
skips, environment gaps or load-flaky results. The fixture checked the
uninitialized minimum sentinel, zero and negative values, and positive
measurements including one microsecond. The complexity gate also passed at
cap 15. The host used GCC 14.2.0 and an AMD Ryzen 9 7950X3D. These are
correctness checks, not a performance benchmark or live peer measurement.

The candidate proof on 2026-11-14 ran 1,592 groups and failed
`test_dev_land_remote`: a substring assertion matched `agent-verify` in the
worktree path, rather than a command target. The fixture now compares the
complete expected command sequences. The strict focused test in the same
worktree passed 1/1 cold, with zero skips, environment-unobserved or load-flaky
results. The failed proof remains distinct from this focused result. Full lint
on the earlier candidate passed; its wall time was 184.166 seconds, above its
75-second soft budget.
