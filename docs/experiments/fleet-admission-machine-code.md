<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Fleet admission machine code

A successful fleet admission returns the exact operator-sealed machine row as
`machine_line` after the roster append succeeds. The row can be reviewed and
imported by another fleet member. The onion in the row is self-reported; it
is not evidence of a connection or handshake. An incomplete response after
admission reports that fleet state may already have changed.

<!-- claim: symbol-present fe_admit tools/command/native_fleet_enrol_command.c # returns admitted machine code -->

The focused fixture failed against the prior handler because no machine line
was returned. With this change, exact `test_fleet_enrol` and
`test_native_api_contract` both passed: two groups ran, none failed or skipped,
in 70.1 seconds of test wall time. The append-refusal fixture uses file
permissions under a non-root POSIX account. The response allocation-failure
path was reviewed in source; it was not fault-injected.
