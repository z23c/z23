# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# command_leaf_paths.awk — emit one dotted command-leaf path per line from the
# authored command registry fragments (config/commands/**/*.def).
#
# The registry is X-macro source: every LEAF is registered by one of the eight
# ZCL_COMMAND_*_{READ,COMMAND} macros whose FIRST argument is `path_` (see the
# macro definitions in config/src/command_catalog.c). ZCL_COMMAND_BRANCH is
# deliberately NOT a leaf: its first argument is a single name segment, not a
# dotted path, and a branch dispatches nothing.
#
# The first argument may sit on the macro line or on the following line, so
# lines are accumulated until the first string literal is in hand. Emitting the
# macro kind alongside the path lets a caller separate READY/DEV/PLANNED
# without a second parser.
#
# Output: "<path>\t<macro>" per leaf, unsorted, in file order.
#
# Kept as a standalone .awk file (never inlined into a shell gate) because an
# apostrophe inside a single-quoted inline awk program swallows the rest of the
# script — see docs/AGENT_TRAPS.md.

/^ZCL_COMMAND_(READY_READ|READY_COMMAND|COMPAT_READ|COMPAT_COMMAND|PLANNED_READ|PLANNED_COMMAND|DEV_READ|DEV_COMMAND)\(/ {
    kind = $0
    sub(/\(.*/, "", kind)
    buf = $0
    sub(/^ZCL_COMMAND_[A-Z_]+\(/, "", buf)
    while (buf !~ /"/) {
        if ((getline nxt) <= 0)
            break
        buf = buf nxt
    }
    if (match(buf, /"[^"]*"/)) {
        path = substr(buf, RSTART + 1, RLENGTH - 2)
        if (path != "")
            printf "%s\t%s\n", path, kind
    }
    next
}
