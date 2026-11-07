<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Ship test isolation and package hint paths

A release gate inherited canonical deployment authorization into its test
suite. The suite then failed tests that require the default refusal. The ship
runner now removes that authorization from the test subprocess; the deploy
operation retains its existing explicit authorization.

A package seal response also substituted a placeholder for a real artifact
directory of 120 bytes. File-backed seal hints now preserve bounded directory
paths. If the resulting next-command input cannot fit its existing bound, the
seal reports failure rather than returning a misleading hint. Hex-only seal
hints continue to use a placeholder.

The focused cold run of the install-runtime, deployment-gate and package
artifact groups passed 3/3, with no skips or load-flaky results. The ship
selftest passed with canonical authorization set in the parent; its fixture
checks that the suite child does not receive it and that the parent retains
it. Package hint cases covered directory lengths 119, 120 and 150 bytes and
an overflowing 480-byte directory. The originally failed suite and its
individual group logs remain the before evidence. No deployment was run.

<!-- claim: symbol-present ship_run_test_suite tools/ship.sh # suite environment isolation -->
<!-- claim: symbol-present zpd_seal_next_create tools/command/native_zcode_package_dev_command.c # bounded seal hint -->
