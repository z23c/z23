<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Package verifier object reuse

## Question

Can the shipped package verifier reuse the node's C23 translation-unit object
graph without changing its isolation boundary or source-identity checks?

## Method

The verifier and node already used the same `NODE_C23_CFLAGS` for their common
sources. The build was changed so `tools/package_verify.c` is compiled as the
only verifier-specific object. Its response file then links that object before
the existing `ALL_SRCS` node-profile objects, preserving the prior source
order. The verifier remains a separate executable linked with the Tor stub and
the same static libraries. Invocation-local response files are removed after
each link, and a build-epoch session check prevents a changed source inventory
or mixed build session from publishing a stale result.

Measurements used a clean new object epoch on 2026-08-26T11:52:18+00:00:

- Compiler: GCC 16.1.1 20260430
- CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics
- Command 1: `make -j16 zclassic23-package-verify`
- Command 2: `make -j16 zclassic23`

## Result

The first command populated the shared production object epoch and linked the
verifier in 193.62 seconds wall time. The second command reused those common
objects, compiled the node entry objects, passed `check_c23_node_binary.sh`,
and linked the node in 179.33 seconds. No second compile of the common source
tree occurred. The verifier's help surface executed successfully after link.

These times establish the new-host baseline only. They are not compared with a
different host or compiler. The remaining cost is whole-program LTO at each
executable link; measuring whether a non-LTO verifier profile preserves build
and execution acceptance is the next experiment.
