#!/usr/bin/env bash
# Gate: every authored persona still points at things that exist (HARD).
#
# lib/engine/include/engine/personas.def is the one place a territory's
# authored STANCE is written down. Everything else about a territory is
# derived from the code index on every call, precisely so it cannot go stale
# while still reading as true. A stance cannot be derived — it is a refusal
# somebody decided on — so it is written, and writing it buys the staleness
# problem back.
#
# This gate is the price. Each row names a territory and cites a tracked file
# where the reasoning already lives, and both must still exist:
#
#   TERRITORY  a directory in the tree that holds at least one tracked C
#              source or header. That is the same independent witness
#              config/lib_module_order.def uses for its own set — the tree
#              itself, which exists whether or not anyone declared it —
#              rather than a second .def, which would only prove two files
#              agree with each other.
#   EVIDENCE   a tracked file. A stance whose reasoning has been deleted is a
#              stance nobody is holding to any more; the row goes with it.
#
# It also refuses a duplicate territory (two stances for one module means the
# second is unreachable and nobody would notice), an empty or one-word stance,
# and a stance long enough to be a summary instead of a refusal.
#
# Per repo law 10 it FAILS LOUD on an empty scan set: a .def that stopped
# parsing must never read as "clean".
#
# There is no baseline. A row that no longer resolves is not a debt to be
# ratcheted down; it is a false statement, and the fix is to correct or
# delete it in the same change.
set -euo pipefail
cd "$(dirname "$0")/../.." || exit 2

GATE="check_persona_resolves"
DEF="${ZCL_PERSONA_DEF:-lib/engine/include/engine/personas.def}"
ROW_FLOOR="${ZCL_PERSONA_ROW_FLOOR:-3}"
STANCE_MIN=40
STANCE_MAX=700

# Parse PERSONA(...) rows out of the .def. Each row is
#   PERSONA("<territory>", "stance" "continued", "<evidence>")
# so the territory is the first quoted string and the evidence is the last;
# everything between them is the stance, whose adjacent literals we join.
# Output: one record per row, tab separated: territory, stance, evidence.
parse_rows() {
    awk '
    /^PERSONA\(/ { collecting = 1; buf = "" }
    collecting   { buf = buf $0 }
    collecting && /\)[[:space:]]*$/ {
        collecting = 0
        n = 0
        rest = buf
        while (match(rest, /"([^"\\]|\\.)*"/)) {
            lit = substr(rest, RSTART + 1, RLENGTH - 2)
            parts[++n] = lit
            rest = substr(rest, RSTART + RLENGTH)
        }
        if (n < 3) { printf "MALFORMED\t%s\t%s\n", buf, ""; next }
        stance = parts[2]
        for (i = 3; i < n; i++) stance = stance parts[i]
        printf "%s\t%s\t%s\n", parts[1], stance, parts[n]
    }
    ' "$1"
}

# A territory resolves if it is a directory holding at least one tracked C
# source or header. Directory-only is not enough: an empty shell would let a
# stance outlive the module it describes.
territory_resolves() {
    local t="$1"
    [ -d "$t" ] || return 1
    # Deliberately NOT `git ls-files … | head -1 | grep -q .`. Under
    # `set -o pipefail`, head exits after one line, git takes SIGPIPE, and the
    # pipeline reports 141 — so the BIGGEST modules, the ones with the most
    # files, would be the ones reported as holding no C. That is not a
    # hypothetical: lib/net, lib/test and app/models all failed that way and
    # lib/base did not, purely on how fast git filled the pipe.
    local found
    found="$(git ls-files -- "$t/*.c" "$t/*.h" 2>/dev/null)"
    [ -n "$found" ] || return 1
    return 0
}

# Prints one fault per line; prints nothing when every row resolves. It is
# always called in a command substitution, so it deliberately sets NOTHING:
# a count assigned in here would be assigned in a subshell and lost, which is
# exactly how the first version of this gate reported a hollow scan. The row
# count is taken separately, in the caller, from the same parser.
scan() { # $1 = def path
    local def="$1"
    local -A seen=()
    local t stance ev
    while IFS=$'\t' read -r t stance ev; do
        [ -n "$t" ] || continue
        if [ "$t" = "MALFORMED" ]; then
            echo "  a PERSONA row does not carry three strings (territory, stance, evidence)"
            continue
        fi
        if [ -n "${seen[$t]+x}" ]; then
            echo "  $t: a second stance for a territory that already has one"
        fi
        seen["$t"]=1
        territory_resolves "$t" \
            || echo "  $t: not a territory — no tracked .c or .h under that path"
        git ls-files --error-unmatch "$ev" >/dev/null 2>&1 \
            || echo "  $t: evidence '$ev' is not a tracked file"
        local len=${#stance}
        if [ "$len" -lt "$STANCE_MIN" ]; then
            echo "  $t: stance is $len characters; a refusal a reader can act on is longer"
        elif [ "$len" -gt "$STANCE_MAX" ]; then
            echo "  $t: stance is $len characters; that is a summary, not a refusal"
        fi
    done < <(parse_rows "$def")
}

# ── --selftest ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    fails=0

    expect() { # $1 = expect(clean|dirty) $2 = label ; reads $tmp/def
        local want="$1" label="$2" out

        out="$(scan "$tmp/def")"
        if [ "$want" = clean ] && [ -n "$out" ]; then
            echo "$GATE: SELFTEST FAILED — $label produced faults:" >&2
            echo "$out" >&2
            fails=$((fails + 1))
        elif [ "$want" = dirty ] && [ -z "$out" ]; then
            echo "$GATE: SELFTEST FAILED — $label produced no fault" >&2
            fails=$((fails + 1))
        else
            echo "  selftest ok: $label"
        fi
    }

    good='PERSONA("lib/base",
    "LOG_FAIL, LOG_ERR and LOG_NULL RETURN; they are not print statements.",
    "lib/base/include/base/log_macros.h")'

    printf '%s\n' "$good" > "$tmp/def"
    expect clean "a row whose territory and evidence both exist"

    printf '%s\n' 'PERSONA("lib/nope",
    "LOG_FAIL, LOG_ERR and LOG_NULL RETURN; they are not print statements.",
    "lib/base/include/base/log_macros.h")' > "$tmp/def"
    expect dirty "a territory the tree does not declare"

    printf '%s\n' 'PERSONA("docs",
    "LOG_FAIL, LOG_ERR and LOG_NULL RETURN; they are not print statements.",
    "lib/base/include/base/log_macros.h")' > "$tmp/def"
    expect dirty "a directory that exists but holds no C"

    printf '%s\n' 'PERSONA("lib/base",
    "LOG_FAIL, LOG_ERR and LOG_NULL RETURN; they are not print statements.",
    "lib/base/include/base/deleted_yesterday.h")' > "$tmp/def"
    expect dirty "evidence that is not a tracked file"

    printf '%s\n%s\n' "$good" "$good" > "$tmp/def"
    expect dirty "two stances for one territory"

    printf '%s\n' 'PERSONA("lib/base",
    "be careful",
    "lib/base/include/base/log_macros.h")' > "$tmp/def"
    expect dirty "a stance too short to act on"

    # A hollow scan must be LOUD, never a quiet pass.
    : > "$tmp/empty.def"
    rc=0
    ZCL_PERSONA_DEF="$tmp/empty.def" bash "$PWD/tools/lint/$GATE.sh" \
        >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "$GATE: SELFTEST FAILED — a .def with no rows did not exit 2" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a .def with no rows fails LOUD (exit 2), never clean"
    fi

    [ "$fails" -eq 0 ] || exit 1
    echo "[$GATE] SELFTEST PASS (unknown territory, C-less directory, deleted evidence, duplicate territory and an unusably short stance all fail; a resolving row passes; an empty .def exits 2)"
    exit 0
fi

# ── the real scan ────────────────────────────────────────────────────────
[ -f "$DEF" ] || {
    echo "[$GATE] FATAL — $DEF is missing; refusing to report a clean scan" >&2
    exit 2
}

# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

ROWS="$(parse_rows "$DEF" | grep -c . || true)"
faults="$(scan "$DEF")"
gate_require_scanned "$ROWS" "$ROW_FLOOR" "$GATE" \
    "personas.def parsed $ROWS row(s); the PERSONA( parser or the file changed shape"

if [ -n "$faults" ]; then
    echo ""
    echo "[$GATE] a persona names something that is no longer there:"
    echo "$faults"
    echo ""
    echo "  A stance is the one thing about a territory this project writes"
    echo "  down, and the deal is that it stays true. Correct the row or"
    echo "  delete it — there is no baseline to add it to."
    exit 1
fi

echo "[$GATE] PASS ($ROWS persona(s); every territory holds tracked C and every evidence file is tracked)"
