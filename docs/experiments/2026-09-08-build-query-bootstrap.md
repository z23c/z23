<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Build queries preserve source enumeration without dependency bootstrap

The mandatory Windows syntax selftest obtained a configure progress message
joined to `engine/entry/main.c` instead of a source path. Its ordinary
`make -s ZCL_TARGET=windows-x86_64 print-node-c23-srcs` query had triggered
embedded dependency bootstrap while the cross archives were absent.

The existing Make goal classifier now treats the explicit source, help,
status, timing, and flag queries as dependency-bootstrap-free. These queries
retain the full node source declarations. A mixed query and build invocation
still establishes both generic vendor and embedded Tor dependencies.
No source scanner, source-count threshold, or build acceptance rule changes.

The existing offline-bootstrap fixture declares each queried target
independently of its production classification and observes both bootstrap
boundaries with archives absent. Before the fix, it failed specifically with
`nonlink goals invoked vendor bootstrap: print-node-c23-srcs`. The same fixture
checks all eleven query-only invocations and each query combined with `z23`.
Validation also runs the exact cross-target source query from the failed gate,
checks every returned path, and verifies the first-use flag-registry pointers.
Results are recorded with the commit; this is a correctness experiment, not
a measured full-build speedup.
