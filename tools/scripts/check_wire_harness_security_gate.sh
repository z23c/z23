#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_wire_harness_security_gate.sh — the simnet_wire deterministic P2P
# wire harness (engine/modules/sim/src/simnet_wire*.c, tools/sim/*wire*) must be pure
# in-memory: no real sockets, ever. It exists to fuzz/replay P2P framing
# deterministically inside a single process; the moment it touches a real
# socket it stops being deterministic and stops being safe to run
# unattended in a nightly sweep.
#
# Scans engine/modules/sim/src/simnet_wire*.c and every tools/sim/*wire* file for
# recv(/send(/socket(/connect(/bind(/getaddrinfo( — whole-word matches,
# so identifiers like simnet_wire_peer_send_ping( or drain_nut_send( do
# NOT trip it (no word boundary between the preceding '_' and the token).
#
# Referenced by docs/work/io-harness-design.md (~line 65-68) and
# docs/work/wire-next-wave-specs.md Step F; this script is the gate that
# makes that documented intent enforceable instead of aspirational.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

WIRE_FILES=$(find engine/modules/sim/src -maxdepth 1 -name 'simnet_wire*.c' 2>/dev/null; \
             find tools/sim -maxdepth 1 -name '*wire*' \( -name '*.c' -o -name '*.h' \) 2>/dev/null)

if [[ -z "$WIRE_FILES" ]]; then
    echo "FAIL: check_wire_harness_security_gate found no simnet_wire source files — gate is hollow"
    exit 1
fi

hits=$(grep -nE '\b(recv|send|socket|connect|bind|getaddrinfo)[[:space:]]*\(' $WIRE_FILES 2>/dev/null || true)

if [[ -n "$hits" ]]; then
    echo "$hits"
    echo "FAIL: real-network call found in the simnet_wire in-memory harness"
    echo "  simnet_wire is pure in-memory transport by design (deterministic,"
    echo "  no wall-clock, no real sockets). If this is a legitimate need,"
    echo "  it does not belong in engine/modules/sim/src/simnet_wire*.c or tools/sim/*wire*."
    exit 1
fi

echo "OK: check_wire_harness_security_gate — no recv/send/socket/connect/bind/getaddrinfo in $(echo "$WIRE_FILES" | wc -l | tr -d ' ') wire harness file(s)"
exit 0
