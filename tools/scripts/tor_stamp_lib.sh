# Copyright 2026 Rhett Creighton - Apache License 2.0
# shellcheck shell=bash
# tor_stamp_lib — read a built node's Tor build identity, and refuse a stub.
#
# `zclassic23 -version` prints exactly one of:
#     tor: full
#     tor: stub
# It is derived from a WEAK SYMBOL that resolves only when the real Tor
# archives were linked (engine/composition/src/app_context.c), so the binary
# cannot be wrong about it the way a -D define could.
#
# Every step that packages, ships, installs or deploys a node reads that stamp
# and refuses `stub` with the SAME sentence. One string, so an operator who
# hits it once can grep for it, and so a lint gate can assert every packaging
# step still carries it.
#
# Sourced, never executed. install_z23.sh deliberately does NOT source this
# (it must run standalone on a box with no checkout) and carries its own copy
# of the sentence; check-tor-full-default is what keeps the copies identical.

# THE sentence. Do not reword it in place — a reworded refusal is a refusal
# nobody's runbook, gate, or grep will find.
ZCL_TOR_STUB_REFUSAL='refusing to package a tor=stub binary: it cannot reach the onion network; rebuild with make tor-full'

# Print `full`, `stub`, or nothing (binary unreadable / too old to stamp).
zcl_tor_stamp() {
    local node="$1"
    [ -x "$node" ] || return 1
    "$node" -version 2>/dev/null |
        sed -n 's/^tor: \(full\|stub\)$/\1/p' | head -1
}

# Fail closed. An unreadable or unstamped binary is refused too: "I could not
# tell" is not "it is fine", and every producer in this repository builds the
# binary it is about to package.
zcl_tor_require_full() {
    local node="$1" context="${2:-$1}" stamp
    stamp="$(zcl_tor_stamp "$node" 2>/dev/null || true)"
    case "$stamp" in
        full) return 0 ;;
        stub)
            printf '%s (%s reports tor: stub)\n' \
                "$ZCL_TOR_STUB_REFUSAL" "$context" >&2
            return 1
            ;;
        *)
            printf '%s (%s printed no tor: stamp, so nothing proves it links real Tor)\n' \
                "$ZCL_TOR_STUB_REFUSAL" "$context" >&2
            return 1
            ;;
    esac
}
