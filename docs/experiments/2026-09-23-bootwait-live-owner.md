<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Boot wait requires a live datadir owner

Observed on Linux host `t14` on 2026-09-23 UTC / 2026-09-23 local
(UTC-04:00), on an AMD Ryzen 7 PRO 8840U with Clang 22.1.6.

## Failure and boundary

A disposable datadir contained a schema-valid `boot_status.json` left at
`phase=serving`, `stage=ready`, with no `zclassic23.pid` lock or node process.
The native `core node bootwait` command returned exit 0, `ok=true`,
`serving=true` after 273 microseconds. Its transcript is
`/tmp/z23-stale-ready-before.log` (SHA-256
`64a6f4205f85f08d1396749dc304bd3404c9ce480afced3516d6633a51f5467f`).
The beacon records a past stage and survives a crash. It does not establish
that the node still owns the datadir.

## Repair and acceptance

Before returning ready, `bootwait` now probes the node's existing
single-writer pidfile lock without creating or modifying the file. An absent
or released lock returns `BOOT_NODE_NOT_RUNNING` with a start-and-retry
remedy. An unreadable or unqualified lock returns `BOOT_OWNER_UNVERIFIED`;
neither state is a successful readiness observation. A held lock retains the
existing ready result. The native command remains read-only.

The registered `command_registry_catalog` fixture publishes a serving beacon
in a private `mkdtemp` datadir, confirms that no owner refuses, holds the
pidfile lock, then confirms that the same beacon passes. `make -j4 t-fast
ONLY=command_registry_catalog` passed its one selected group with zero
failures or skips. The test body took 8,727 ms; a cold, source-bound build
took 288 s. Transcript `/tmp/z23-bootwait-stale-pass-after.log` has SHA-256
`e803b5bbe24884899b235887dd9532fea689759fbcd6037efb0537f43a09ca79`.

The rebuilt native CLI returned exit 3, `ok=false`, and
`BOOT_NODE_NOT_RUNNING` on the original fixture after 62 microseconds. Its
transcript `/tmp/z23-stale-ready-after.log` has SHA-256
`8de091dced76c64b0fba5e779c7e1c85de20616b81e8d19e403be3810eb46ae7`.
This is Linux native command and disposable-fixture evidence, not a GUI or
running-node restart claim. Windows owner-lock inspection refuses as
unqualified; Windows execution is not measured here.

The first `lint-fast` run passed 31 of 32 gates and refused the expanded
`bootwait` function at cyclomatic complexity 19 against the cap of 15. Its
transcript `/tmp/z23-bootwait-lint-fast.log` has SHA-256
`f943ef0c44fca9fff1125d89e072dd187b356cc0931479f096fde24518a67baa`.
Extracting owner verification and the ready-response projection brought the
handler under the unchanged cap. `make -j4 check-cyclomatic-complexity`
passed across 56,901 functions in 45 s; transcript
`/tmp/z23-bootwait-complexity-final2.log` has SHA-256
`6162d70454f17b5da65d1a310dd4f1ed33b7d31927489c20dde9c1caf3285b86`.

The final focused run passed one selected group with zero skips: test body
57,236 ms under concurrent build load, command wall 176 s. Transcript
`/tmp/z23-bootwait-test-final.log` has SHA-256
`bddbca6cb43e7d52a3c9fef52f1502bdef949c39f6ca3d3eca288f0453a32343`.
Final `lint-fast` passed 32/32 gates in 78 s; transcript
`/tmp/z23-bootwait-lint-fast-final.log` has SHA-256
`662a265797fa13d1f19ad9d3f725f68bfdfac673e07efb0d8f306c5cb7a7edc3`.
`lint-preflight` passed 5/5 gates in 262 s; transcript
`/tmp/z23-bootwait-lint-preflight.log` has SHA-256
`3a35cc8bd827fb2979cab2dc6f74053d3d9269ed985e5072500da93c15e69c43`.

The lock observation excludes a dead node with an unheld pidfile. It does not
verify an RPC response or bind a surviving beacon to a particular boot if
another process holds the lock. A later isolated restart acceptance should
bind the beacon generation to the owner and confirm the serving endpoint.
