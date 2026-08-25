#!/usr/bin/env bash
# check-describe-budget — every leaf's `discover describe` document must fit
# ZCL_COMMAND_SPEC_BUDGET, and every branch's `discover help` menu must fit
# ZCL_COMMAND_BRANCH_BUDGET (root: ZCL_COMMAND_ROOT_BUDGET), so a leaf's
# written contract can actually be read and every branch menu can render.
#
# Why this gate exists. `discover describe <path>` is the ONLY surface that
# renders a leaf's long-form `semantics` text: docs/API_REFERENCE.md carries
# summaries and `discover help` carries a five-field child row. When the
# document outgrows the budget, zcl_command_registry_describe_json() returns 0
# and the CLI answers DESCRIBE_BUDGET (it used to answer UNKNOWN_PATH) — the
# leaf keeps dispatching, keeps showing up in help and search, and its contract
# is silently unreadable. core.wallet.recovery.restore shipped that way with a
# money-safety warning inside the invisible text, and zcode.endpoint.publish
# had already been that way for longer. Nothing rendered a describe document
# for every leaf, so nothing noticed.
#
# Mechanism: compile tools/check_describe_budget.c — a second consumer of the
# same command .def X-macro grammar — and let it call the REAL renderer on
# every leaf. No `make`, no build/ dependency, no second size model.
#
# Fix a failure by TRIMMING the named leaf's `semantics` in
# config/commands/*.def. Never by raising ZCL_COMMAND_SPEC_BUDGET: the budget
# is what keeps a describe document cheap enough for every transport to carry,
# and raising it would also re-hide the baselined pre-existing overflow.
#
# --selftest compiles the same tool against a COPY of config/commands with one
# leaf's summary padded past the budget and proves the gate goes red on it, so
# the gate cannot rot into a no-op.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"

TOOL_SRC="tools/check_describe_budget.c"
BASELINE="tools/lint/describe_budget_baseline.txt"
DEF_DIR="config/commands"

# Floors: refuse to report clean off a catalog that moved or emptied out.
DEF_FLOOR=8
LEAF_FLOOR=200

# The renderer and its transitive dependencies. Kept explicit so a missing
# object is a compile error here rather than a silently skipped gate.
LINK_SRCS=(
    lib/kernel/src/command_registry.c
    lib/json/src/json.c
    lib/crypto/src/sha256.c
    lib/base/src/safe_alloc.c
    lib/base/src/log_level.c
    lib/platform/src/clock.c
)
INCS=(
    -Ilib/kernel/include -Ilib/json/include -Ilib/crypto/include
    -Ilib/base/include -Ilib/platform/include -Ilib/util/include
    -Ilib/vcs/include -Iapp/services/include
)

# Build the gate binary. $1 = output path, $2 = directory holding `commands/`.
build_tool() {
    local out="$1" def_parent="$2" log="$3"
    "${CC:-cc}" -std=c23 -O1 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L \
        "-I$def_parent" "${INCS[@]}" \
        -o "$out" "$TOOL_SRC" "${LINK_SRCS[@]}" 2> "$log"
}

run_selftest() {
    local tmp out rc padded
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-describe-budget-selftest.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT HUP INT TERM

    # 1. The unmodified tree must pass.
    if ! build_tool "$tmp/gate" config "$tmp/cc.log"; then
        echo "check_describe_budget selftest: FAIL — $TOOL_SRC does not compile:" >&2
        sed 's/^/    /' "$tmp/cc.log" >&2
        exit 1
    fi
    if ! "$tmp/gate" "$BASELINE" > "$tmp/clean.log" 2>&1; then
        echo "check_describe_budget selftest: FAIL — the gate does not pass on" >&2
        echo "  an unmodified tree:" >&2
        sed 's/^/    /' "$tmp/clean.log" >&2
        exit 1
    fi

    # 2. Pad one leaf's summary past the budget in a COPY of the catalog. The
    #    padding rides as an adjacent string literal, so the C preprocessor
    #    concatenates it onto that leaf's summary and nothing else changes.
    mkdir -p "$tmp/defs/commands"
    cp "$DEF_DIR"/*.def "$tmp/defs/commands/"
    local anchor='    "Can this wallet be rebuilt from its words",'
    local hits
    hits="$(grep -Fxc "$anchor" "$tmp/defs/commands/core.def" || true)"
    if [ "$hits" != "1" ]; then
        echo "check_describe_budget selftest: FAIL — the padding anchor is no" >&2
        echo "  longer unique in $DEF_DIR/core.def (found $hits). Point the" >&2
        echo "  selftest at another leaf's summary line." >&2
        exit 1
    fi
    padded="$(printf 'P%.0s' $(seq 1 2000))"
    awk -v anchor="$anchor" -v pad="\"$padded\"" '
        $0 == anchor { sub(/,$/, " " pad ",", $0) } { print }
    ' "$tmp/defs/commands/core.def" > "$tmp/defs/commands/core.def.new"
    mv "$tmp/defs/commands/core.def.new" "$tmp/defs/commands/core.def"

    if ! build_tool "$tmp/gate_padded" "$tmp/defs" "$tmp/cc2.log"; then
        echo "check_describe_budget selftest: FAIL — the padded catalog does" >&2
        echo "  not compile, so the fixture proves nothing:" >&2
        sed 's/^/    /' "$tmp/cc2.log" >&2
        exit 1
    fi
    out="$tmp/padded.log"
    rc=0
    "$tmp/gate_padded" "$BASELINE" > "$out" 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "check_describe_budget selftest: FAIL — a leaf padded 2000 bytes" >&2
        echo "  past the budget did NOT trip the gate. The gate is hollow." >&2
        sed 's/^/    /' "$out" >&2
        exit 1
    fi
    if ! grep -q 'OVER BUDGET: core.wallet.recovery.status' "$out"; then
        echo "check_describe_budget selftest: FAIL — the failure did not name" >&2
        echo "  the padded leaf:" >&2
        sed 's/^/    /' "$out" >&2
        exit 1
    fi
    echo "check_describe_budget selftest: PASS — clean tree passes; a leaf" \
         "padded past ZCL_COMMAND_SPEC_BUDGET fails and is named"
    exit 0
}

if [ "${1:-}" = "--selftest" ]; then
    run_selftest
fi

for required in "$TOOL_SRC" "$BASELINE" "${LINK_SRCS[@]}"; do
    if [ ! -f "$required" ]; then
        echo "check_describe_budget: FATAL — missing $required" >&2
        exit 2
    fi
done

def_count=0
for f in "$DEF_DIR"/*.def; do
    [ -f "$f" ] || continue
    def_count=$((def_count + 1))
done
gate_require_scanned "$def_count" "$DEF_FLOOR" check_describe_budget \
    "no .def catalogs under $DEF_DIR — the command catalog moved?"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/zcl-describe-budget.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

if ! build_tool "$TMP/gate" config "$TMP/cc.log"; then
    echo "check_describe_budget: FATAL — $TOOL_SRC does not compile:" >&2
    sed 's/^/    /' "$TMP/cc.log" >&2
    exit 2
fi

rc=0
"$TMP/gate" "$BASELINE" > "$TMP/out.log" 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then
    echo "FAIL: a leaf's describe document does not fit its byte budget." >&2
    echo "" >&2
    sed 's/^/    /' "$TMP/out.log" >&2
    echo "" >&2
    echo "  Trim the named leaf's \`semantics\` in $DEF_DIR/*.def." >&2
    echo "  Do NOT raise ZCL_COMMAND_SPEC_BUDGET." >&2
    exit 1
fi

leaves="$(sed -n 's/^check-describe-budget: \([0-9]\{1,\}\) leaves render.*/\1/p' \
    "$TMP/out.log" | head -1)"
gate_require_scanned "${leaves:-0}" "$LEAF_FLOOR" check_describe_budget \
    "almost no leaves rendered — the X-macro expansion broke"

sed 's/^/  /' "$TMP/out.log"
exit 0
