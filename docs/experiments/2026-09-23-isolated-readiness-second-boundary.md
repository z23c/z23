<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Isolated readiness polling at a second boundary

On 2026-09-23, an exact landing proof's `check-shell-host-assumptions` gate
refused a successful height-zero RPC fixture with `successful height zero did
not become ready`. The helper computed a deadline with whole-second `date`
output, then checked the clock before its first poll. A call crossing a second
boundary could exhaust a one-second timeout without observing the reply.

The disposable selftest now supplies consecutive clock values 100 and 101.
Before the change, it fails with `successful height zero lost at second
boundary` (failure log SHA-256
`6414146cdbc08078070cab1112557ed769d4a4f8c712406ffbafda2f9ae41a0f`).
The RPC-ready, connected-peer, and peer-listener waits now perform one probe
before checking the deadline. Error and unobserved-listener returns remain
fail closed.

On Linux `t14`, the selftest passed three consecutive runs after the change.
A separate timed run passed in 3.810 s wall, 0.288 s user, and 0.629 s system
time. The host was an AMD Ryzen 7 PRO 8840U; the available compiler was GCC
16.1.1. This fixture proves the clock-boundary behavior, not live-node startup
or peer synchronization.
