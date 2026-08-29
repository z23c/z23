#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_remote_command_classes.sh — every command leaf has exactly one remote
# class, and the class table names nothing that does not exist.
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
# config/remote_command_classes.def answers, for each command leaf, "may a peer
# on our own mesh ask this node to run it?" (design:
# docs/work/REMOTE_COMMAND_CHANNEL.md). The table is only worth anything if it
# is COMPLETE. Two ways it rots, both silent:
#
#   A. A NEW leaf lands with no row. The table's own rule is that an
#      unclassified leaf is never_remote, so an omission is safe TODAY — and
#      that is exactly what makes it dangerous. Nothing breaks, nobody notices,
#      and the table stops being the place the decision is made. This gate makes
#      adding a command leaf a two-file operation: register it, and say whether
#      it may be reached remotely.
#
#   B. A row names a leaf that no longer exists. A renamed leaf leaves its old
#      name behind holding a permission. When the transport is written it will
#      look up by name; a stale row is a grant with no owner, and the next
#      person to add a leaf with a recycled name inherits it.
#
# Neither failure can be caught by reading one file. Both are set arithmetic
# between two sources of truth, which is what this gate does.
#
# ── SOURCES OF TRUTH (never re-parsed by hand) ──────────────────────────────
#   typed registry : config/commands/**/*.def, read with
#                    tools/lint/command_leaf_paths.awk (the eight
#                    ZCL_COMMAND_*_{READ,COMMAND} leaf macros; ZCL_COMMAND_BRANCH
#                    is not a leaf and dispatches nothing).
#   agent registry : app/controllers/include/controllers/agent_contracts.def,
#                    the flat AGENT_CONTRACT() method table that backs
#                    `z23 agentops`, `z23 agentdeployguard` and friends. It is a
#                    SECOND dispatchable command surface; leaving it out would
#                    leave `dbquery` and `dumpstate` unclassified.
#   class table    : config/remote_command_classes.def, read with
#                    tools/lint/remote_command_class_rows.awk.
#
# ── WHAT IS ASSERTED (all fail-closed) ──────────────────────────────────────
#   1. Every registry leaf has a row.                    (defect A)
#   2. Every row names a live registry leaf.             (defect B)
#   3. No leaf is classified twice. Two rows for one leaf is two decisions,
#      and which one wins is decided by include order rather than by anyone.
#   4. Every row's class is one of the three known tokens. A typo'd class is a
#      row the future dispatcher cannot act on; failing closed on an unknown
#      token beats guessing.
#   5. Every REMOTE_CLASS_READ_ONLY / REMOTE_CLASS_OWNER_CAPABILITY row carries
#      a non-empty reason. Refusing needs no defence; PERMITTING does, and an
#      unexplained permission is the one a later reader cannot audit or remove.
#      REMOTE_CLASS_NEVER rows carry an empty reason by design — their argument
#      is the section comment above their group.
#
# There is NO baseline and no allowlist. The tree is clean today (610 leaves,
# 610 rows), so a shrink-only baseline would only be a place to hide the next
# omission.
#
# Usage:
#   tools/lint/check_remote_command_classes.sh            # the gate
#   tools/lint/check_remote_command_classes.sh --selftest # prove it fires
# Env (self-test only; production never sets these):
#   ZCL_REMOTE_CLASS_DEF_DIR    typed command registry root
#   ZCL_REMOTE_CLASS_AGENT_DEF  agent-contract table
#   ZCL_REMOTE_CLASS_TABLE      remote class table
#
# Exit: 0 clean, 1 on any violation, 2 on a hollow/broken scan.

set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

GATE=check_remote_command_classes

LEAF_AWK="tools/lint/command_leaf_paths.awk"
ROW_AWK="tools/lint/remote_command_class_rows.awk"

# Floors. Production carries 578 typed leaves + 32 agent-contract methods. The
# floors sit below the live counts with headroom so an ordinary addition never
# trips them, but an emptied or renamed source does. A floor is not a baseline:
# it may only ever move DOWN if the surface genuinely shrinks, and it never
# excuses a missing row.
TYPED_FLOOR=500
AGENT_FLOOR=25

run_gate() {
    # Resolved per call, not once at load: the self-test re-invokes run_gate
    # with the three env overrides pointing at planted fixtures.
    local DEF_DIR AGENT_DEF TABLE
    DEF_DIR="${ZCL_REMOTE_CLASS_DEF_DIR:-config/commands}"
    AGENT_DEF="${ZCL_REMOTE_CLASS_AGENT_DEF:-app/controllers/include/controllers/agent_contracts.def}"
    TABLE="${ZCL_REMOTE_CLASS_TABLE:-config/remote_command_classes.def}"

    local tmp
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-remote-class.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN

    for f in "$LEAF_AWK" "$ROW_AWK"; do
        if [ ! -r "$f" ]; then
            echo "$GATE: FATAL — parser missing: $f" >&2
            return 2
        fi
    done
    if [ ! -r "$TABLE" ]; then
        echo "$GATE: FATAL — class table missing or unreadable: $TABLE" >&2
        echo "  Refusing to report 'clean' with nothing classified." >&2
        return 2
    fi
    if [ ! -r "$AGENT_DEF" ]; then
        echo "$GATE: FATAL — agent-contract table missing: $AGENT_DEF" >&2
        return 2
    fi

    # ── source A: the typed command registry ────────────────────────────────
    local def_files=()
    mapfile -t def_files < <(find "$DEF_DIR" -type f -name '*.def' 2>/dev/null | sort)
    gate_require_scanned "${#def_files[@]}" 1 "$GATE" \
        "no *.def under: $DEF_DIR"
    awk -f "$LEAF_AWK" "${def_files[@]}" | cut -f1 | sort -u > "$tmp/typed"
    local typed_n
    typed_n=$(wc -l < "$tmp/typed")
    gate_require_scanned "$typed_n" "$TYPED_FLOOR" "$GATE" \
        "typed leaf population collapsed under floor — parser or catalog broke"

    # ── source B: the flat agent-contract method table ──────────────────────
    grep -oE '^AGENT_CONTRACT\("[A-Za-z0-9_.-]+"' "$AGENT_DEF" \
        | sed -e 's/^AGENT_CONTRACT("//' -e 's/"$//' | sort -u > "$tmp/agent"
    local agent_n
    agent_n=$(wc -l < "$tmp/agent")
    gate_require_scanned "$agent_n" "$AGENT_FLOOR" "$GATE" \
        "AGENT_CONTRACT population collapsed under floor: $AGENT_DEF"

    sort -u "$tmp/typed" "$tmp/agent" > "$tmp/registry"

    # ── source C: the class table ───────────────────────────────────────────
    awk -f "$ROW_AWK" "$TABLE" > "$tmp/rows"
    local rows_n
    rows_n=$(wc -l < "$tmp/rows")
    gate_require_scanned "$rows_n" 1 "$GATE" \
        "class table parsed to zero rows: $TABLE"
    cut -f1 "$tmp/rows" | sort > "$tmp/classified_all"
    sort -u "$tmp/classified_all" > "$tmp/classified"

    local rc=0

    # (1) registry leaf with no row.
    comm -23 "$tmp/registry" "$tmp/classified" > "$tmp/unclassified"
    if [ -s "$tmp/unclassified" ]; then
        rc=1
        echo "$GATE: FAIL — command leaves with no remote class:" >&2
        sed -e 's/^/    /' "$tmp/unclassified" >&2
        echo "  Add one REMOTE_COMMAND_CLASS row per leaf to $TABLE." >&2
        echo "  A new command leaf is a new remote-authority decision; make it." >&2
    fi

    # (2) row naming a leaf that no longer exists.
    comm -13 "$tmp/registry" "$tmp/classified" > "$tmp/orphans"
    if [ -s "$tmp/orphans" ]; then
        rc=1
        echo "$GATE: FAIL — class table names leaves the registry does not have:" >&2
        sed -e 's/^/    /' "$tmp/orphans" >&2
        echo "  Delete the stale rows from $TABLE (or fix the rename)." >&2
        echo "  A row with no leaf is a permission with no owner." >&2
    fi

    # (3) duplicate classification.
    uniq -d "$tmp/classified_all" > "$tmp/dupes"
    if [ -s "$tmp/dupes" ]; then
        rc=1
        echo "$GATE: FAIL — leaves classified more than once:" >&2
        sed -e 's/^/    /' "$tmp/dupes" >&2
        echo "  Exactly one row per leaf; two rows is two decisions." >&2
    fi

    # (4) unknown class token, and (5) permission with no stated reason.
    local bad_class="" no_reason=""
    bad_class=$(awk -F'\t' '
        $2 != "REMOTE_CLASS_NEVER" &&
        $2 != "REMOTE_CLASS_OWNER_CAPABILITY" &&
        $2 != "REMOTE_CLASS_READ_ONLY" { print $1 "  (class: " $2 ")" }
    ' "$tmp/rows")
    if [ -n "$bad_class" ]; then
        rc=1
        echo "$GATE: FAIL — rows with an unknown class token:" >&2
        printf '    %s\n' "$bad_class" >&2
        echo "  Use REMOTE_CLASS_NEVER, REMOTE_CLASS_OWNER_CAPABILITY or" >&2
        echo "  REMOTE_CLASS_READ_ONLY." >&2
    fi
    no_reason=$(awk -F'\t' '
        ($2 == "REMOTE_CLASS_OWNER_CAPABILITY" || $2 == "REMOTE_CLASS_READ_ONLY") &&
        $3 ~ /^[[:space:]]*$/ { print $1 "  (" $2 ")" }
    ' "$tmp/rows")
    if [ -n "$no_reason" ]; then
        rc=1
        echo "$GATE: FAIL — remotable leaves with no stated reason:" >&2
        printf '    %s\n' "$no_reason" >&2
        echo "  Refusing needs no defence; permitting does. Say why." >&2
    fi

    if [ "$rc" -eq 0 ]; then
        echo "$GATE: OK — $rows_n rows cover $(wc -l < "$tmp/registry") command leaves" \
             "($typed_n typed, $agent_n agent-contract)."
    fi
    return "$rc"
}

# ── self-test ───────────────────────────────────────────────────────────────
# Plants each defect class in a fixture and asserts the gate fails on it. A gate
# nobody has watched fail is not an assertion.
selftest() {
    local tmp base rc fails=0
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-remote-class-selftest.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" RETURN

    base="$tmp/base"
    mkdir -p "$base/commands"
    # A miniature registry: one typed leaf per macro shape we care about.
    cat > "$base/commands/mini.def" <<'MINI'
ZCL_COMMAND_BRANCH("mini", "", "not a leaf", ZCL_COMMAND_LAYER_OPS)
ZCL_COMMAND_READY_READ(
    "mini.alpha", "mini", "", "s", "sem", 0, "k", "in", "out", "", "", "ex")
ZCL_COMMAND_READY_COMMAND(
    "mini.beta", "mini", "", "s", "sem", 0, "k", "in", "out", "", "", "ex")
MINI
    cat > "$base/agent.def" <<'AGENTDEF'
AGENT_CONTRACT("minimethod", "cap", "schema.v1", "z23 minimethod", "", "", "", 0, "", "", "p")
AGENTDEF
    cat > "$base/table.def" <<'TABLE'
REMOTE_COMMAND_CLASS("mini.alpha", REMOTE_CLASS_READ_ONLY, "bounded read")
REMOTE_COMMAND_CLASS("mini.beta", REMOTE_CLASS_NEVER, "")
REMOTE_COMMAND_CLASS("minimethod", REMOTE_CLASS_NEVER, "")
TABLE

    probe() {
        local name="$1" want="$2" table="$3"
        set +e
        ZCL_REMOTE_CLASS_DEF_DIR="$base/commands" \
        ZCL_REMOTE_CLASS_AGENT_DEF="$base/agent.def" \
        ZCL_REMOTE_CLASS_TABLE="$table" \
        ZCL_REMOTE_CLASS_FLOOR_OVERRIDE=1 \
            run_gate >/dev/null 2>&1
        rc=$?
        set -e
        if [ "$rc" -ne "$want" ]; then
            echo "$GATE: SELFTEST FAIL — $name: expected exit $want, got $rc" >&2
            fails=$((fails + 1))
        else
            echo "$GATE: selftest ok — $name (exit $rc)"
        fi
    }

    # Floors would abort the miniature fixture; drop them for the self-test.
    TYPED_FLOOR=1
    AGENT_FLOOR=1

    probe "clean fixture passes" 0 "$base/table.def"

    grep -v 'mini.beta' "$base/table.def" > "$tmp/missing.def"
    probe "missing classification fails" 1 "$tmp/missing.def"

    cp "$base/table.def" "$tmp/orphan.def"
    echo 'REMOTE_COMMAND_CLASS("mini.gone", REMOTE_CLASS_NEVER, "")' >> "$tmp/orphan.def"
    probe "stale row fails" 1 "$tmp/orphan.def"

    cp "$base/table.def" "$tmp/dupe.def"
    echo 'REMOTE_COMMAND_CLASS("mini.beta", REMOTE_CLASS_READ_ONLY, "second opinion")' \
        >> "$tmp/dupe.def"
    probe "duplicate row fails" 1 "$tmp/dupe.def"

    sed -e 's/REMOTE_CLASS_READ_ONLY, "bounded read"/REMOTE_CLASS_MAYBE, "bounded read"/' \
        "$base/table.def" > "$tmp/badclass.def"
    probe "unknown class token fails" 1 "$tmp/badclass.def"

    sed -e 's/REMOTE_CLASS_READ_ONLY, "bounded read"/REMOTE_CLASS_READ_ONLY, ""/' \
        "$base/table.def" > "$tmp/noreason.def"
    probe "unexplained permission fails" 1 "$tmp/noreason.def"

    probe "missing table is FATAL" 2 "$tmp/does-not-exist.def"

    if [ "$fails" -ne 0 ]; then
        echo "$GATE: SELFTEST FAILED ($fails)" >&2
        return 1
    fi
    echo "$GATE: selftest passed"
    return 0
}

if [ "${1:-}" = "--selftest" ]; then
    selftest
    exit $?
fi

run_gate
exit $?
