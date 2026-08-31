#!/usr/bin/env bash
# Lint gate — test-registration drift guard (HARD).
#
# THE BUG THIS PREVENTS (lane-3, 2026-06-22): three test entry points
# (test_refold_from_anchor_fatal, test_refold_auto_arm, test_anchor_selfmint)
# lived in dedicated lib/test/src/test_<name>.c files, COMPILED and linked
# into the test binaries, yet were ABSENT from the canonical test group catalog
# (and not dispatched by the legacy serial runner
# lib/test/src/test.c either). They therefore proved NOTHING — green forever,
# never executed. This gate makes that drift FAIL CI.
#
# ── CONVENTION (verified against the source) ──────────────────────────────
# A test "entry point" is the function that bears the SAME name as its
# dedicated file: lib/test/src/test_<name>.c defining
#     int test_<name>(void)
# (with the body opener on its own line — the project style). Multi-test files
# (e.g. test_coins_amount_codec.c, test_models.c) and group files define helper
# / sub-test functions whose names do NOT match the host filename; those are
# deliberately NOT treated as entry points (no false positives on helpers).
#
# An entry point is "dispatched" (i.e. actually runs) iff its <name> is either
#   1. registered in tools/dev/test_group_catalog.def
#      (the `make test` parallel runner — the doctrine runner of record), OR
#   2. invoked as `test_<name>()` from the legacy serial runner test.c.
# Both runners link the same TEST_SRCS_NO_MAIN (Makefile:149), so a function
# dispatched by EITHER does run somewhere. A filename-matching entry point
# dispatched by NEITHER is an orphan: compiled but never executed.
#
# The catalog row ZCL_TEST_GROUP(foo) expands to the test_foo declaration and
# dispatch row in test_parallel.c and to the same full ID in native tooling.
#
# Fail-loud: grep exit >=2 (real error) aborts; an empty entry-point scan
# (convention drift) aborts — we never report "clean" off a broken scan.
set -euo pipefail

validate_unique_registrations() {
    local registered_raw="$1"
    local source_label="$2"
    local duplicates

    duplicates=$(printf '%s\n' "$registered_raw" | sort | uniq -d)
    if [ -z "$duplicates" ]; then
        return 0
    fi

    echo "FAIL: duplicate test group registration(s) in $source_label:" >&2
    while IFS= read -r name; do
        [ -n "$name" ] && echo "    $name" >&2
    done <<< "$duplicates"
    echo "  Each parallel test group must have one canonical row." >&2
    return 1
}

# Keep the duplicate detector from becoming a decorative check: prove its
# positive and negative controls on every gate run before trusting it on the
# real registry. This is pure string processing and never mutates the tree.
if ! validate_unique_registrations $'alpha\nbeta' '<selftest-clean>' \
        >/dev/null 2>&1; then
    echo "check_test_registration: FATAL — uniqueness selftest rejected clean input" >&2
    exit 2
fi
set +e
uniqueness_selftest_out=$(validate_unique_registrations \
    $'alpha\nbeta\nalpha' '<selftest-duplicate>' 2>&1)
uniqueness_selftest_rc=$?
set -e
if [ "$uniqueness_selftest_rc" -ne 1 ] || \
   ! grep -qF 'alpha' <<< "$uniqueness_selftest_out"; then
    echo "check_test_registration: FATAL — uniqueness negative control failed" >&2
    exit 2
fi

cd "$(dirname "$0")/../.."

# Impact plans are part of test registration: every plan token must have an
# exact primary group, and a rule naming a registered test source must select
# that source's own group. Keep this in the canonical lint gate so a broken
# map cannot evade the focused group intended to audit the map itself.
if ! tools/dev/test-group-list.sh --check-impact-rules; then
    echo "check_test_registration: FAIL — impact proof registration drift" >&2
    exit 1
fi

TEST_DIR="lib/test/src"
PARALLEL="$TEST_DIR/test_parallel.c"
SERIAL="$TEST_DIR/test.c"
CATALOG="tools/dev/test_group_catalog.def"
SEMANTIC_LEAVES="tools/dev/test_semantic_leaves.def"

for f in "$PARALLEL" "$SERIAL" "$CATALOG" "$SEMANTIC_LEAVES"; do
    if [ ! -f "$f" ]; then
        echo "check_test_registration: FATAL — expected runner file missing: $f" >&2
        echo "  The test-runner layout drifted; refusing to report 'clean'." >&2
        exit 2
    fi
done

# ── Registered names (canonical generated-code catalog) ──
registered_full=$(tools/dev/test-group-list.sh)
registered_raw=$(printf '%s\n' "$registered_full" | sed -n 's/^test_//p')

# A duplicate row runs the same group twice, inflates the advertised group
# count, and can hide the absence of a genuinely distinct test behind a green
# total. Check the raw list before de-duplicating it for membership lookups.
if ! validate_unique_registrations "$registered_full" "$CATALOG"; then
    exit 1
fi

registered=$(printf '%s\n' "$registered_raw" | sort -u)

# A semantic-leaf row is a deliberately narrow performance assertion: the
# owning exact group covers the whole TU, so walking the runner dispatch edge
# would add no behavioral proof. Prove that assertion mechanically before the
# planner is allowed to skip the graph. A leaf must be registered, define only
# its owning externally visible symbol, and have no callers outside the two
# runner surfaces and its public prototype. This is compiler/object evidence,
# not a source-text parser: one-line and multiline C definitions are covered.
semantic_leaves=$(awk '
/^[[:space:]]*ZCL_TEST_SEMANTIC_LEAF\([A-Za-z_0-9]+\)[[:space:]]*$/ {
    line = $0
    sub(/^[^(]*\(/, "", line); sub(/\).*/, "", line)
    print line
}' "$SEMANTIC_LEAVES")
if ! validate_unique_registrations "$semantic_leaves" "$SEMANTIC_LEAVES"; then
    exit 1
fi

LEAF_CC="${ZCL_TEST_LEAF_CC:-cc}"
for tool in "$LEAF_CC" nm; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "check_test_registration: FATAL — semantic-leaf audit needs $tool" >&2
        exit 2
    fi
done
LEAF_WORK=$(mktemp -d "${TMPDIR:-/tmp}/zcl-test-leaf-audit.XXXXXX") || {
    echo "check_test_registration: FATAL — semantic-leaf mktemp failed" >&2
    exit 2
}
trap 'rm -rf -- "$LEAF_WORK"' EXIT

leaf_symbols() {
    local source="$1"
    local object="$2"
    shift 2
    if ! "$LEAF_CC" -std=c23 -O0 -fno-lto "$@" -c "$source" -o "$object" \
            2>"$LEAF_WORK/compiler.err"; then
        echo "check_test_registration: semantic-leaf compile failed: $source" >&2
        sed -n '1,20p' "$LEAF_WORK/compiler.err" >&2
        return 2
    fi
    nm -g --defined-only --format=posix "$object" |
        awk '$2 ~ /^[A-Za-z]$/ { print $1 }' |
        # Mach-O spells every extern with one leading underscore; the
        # registry and the control compare plain C names.
        sed 's/^_//' | sort -u
}

# Born-red control for the exact parser weakness this audit replaces: both a
# same-line body and a multiline signature must be visible in object symbols.
cat > "$LEAF_WORK/control.c" <<'EOF'
int test_owner(void) { return 0; }
bool exported_helper(void) { return true; }
int multiline_helper(
    int value)
{
    return value;
}
EOF
control_symbols=$(leaf_symbols "$LEAF_WORK/control.c" \
    "$LEAF_WORK/control.o" -include stdbool.h) || exit 2
if [ "$control_symbols" != $'exported_helper\nmultiline_helper\ntest_owner' ]; then
    echo "check_test_registration: FATAL — object-symbol negative control failed" >&2
    printf '  observed:\n%s\n' "$control_symbols" >&2
    exit 2
fi

LEAF_INCLUDE_FLAGS=()
for dir in app/*/include config/include lib/*/include core/*/include \
           domain/*/include application/*/include adapters/*/*/include \
           ports/include; do
    [ -d "$dir" ] && LEAF_INCLUDE_FLAGS+=("-I$dir")
done
LEAF_INCLUDE_FLAGS+=("-Itools" "-Itools/dev" "-Ivendor/include")
if [ "$(uname -s)" = "Darwin" ]; then
    LEAF_INCLUDE_FLAGS+=("-D_DARWIN_C_SOURCE")
fi
leaf_drift=""
for name in $semantic_leaves; do
    source="$TEST_DIR/test_${name}.c"
    if [ ! -f "$source" ] || ! grep -qxF "$name" <<< "$registered"; then
        leaf_drift="${leaf_drift}${name}\tmissing source or canonical group\n"
        continue
    fi
    set +e
    global_symbols=$(leaf_symbols "$source" "$LEAF_WORK/${name}.o" \
        -D_POSIX_C_SOURCE=200809L -DZCL_AR_ENFORCE -DZCL_TESTING \
        "${LEAF_INCLUDE_FLAGS[@]}")
    symbol_rc=$?
    set -e
    if [ "$symbol_rc" -ne 0 ]; then
        exit "$symbol_rc"
    fi
    if [ "$global_symbols" != "test_${name}" ]; then
        leaf_drift="${leaf_drift}${name}\texports: ${global_symbols//$'\n'/, }\n"
    fi
    set +e
    refs=$(git grep -l -E "test_${name}[[:space:]]*\\(" -- \
        ':!build' ':!test-tmp')
    grc=$?
    set -e
    if [ "$grc" -ge 2 ]; then
        echo "check_test_registration: FATAL — reference scan failed for $name" >&2
        exit 2
    fi
    while IFS= read -r ref; do
        [ -n "$ref" ] || continue
        case "$ref" in
            "$source"|"$SERIAL"|lib/test/include/test/test_core.h) ;;
            *) leaf_drift="${leaf_drift}${name}\tcalled by $ref\n" ;;
        esac
    done <<< "$refs"
done
if [ -n "$leaf_drift" ]; then
    echo "FAIL: semantic test leaf claim(s) are no longer isolated:" >&2
    printf '%b' "$leaf_drift" >&2
    echo "  Remove the row or restore the one-entry/no-external-caller shape." >&2
    exit 1
fi

# FAIL-LOUD floor: the catalog must yield a non-trivial test set, else its
# parser or row shape drifted and a real orphan could slip through a tiny scan.
reg_count=$(printf '%s\n' "$registered" | grep -c . || true)
if [ "$reg_count" -lt 100 ]; then
    echo "check_test_registration: FATAL — only $reg_count test catalog entries parsed" >&2
    echo "  from $CATALOG (expected >=100). The row shape or parser drifted;" >&2
    echo "  refusing to validate against a near-empty registration set." >&2
    exit 2
fi

# ── Names dispatched by the legacy serial runner (test_<name>() calls) ──
set +e
serial_calls=$(grep -oE 'test_[a-zA-Z0-9_]+\(\)' "$SERIAL")
grc=$?
set -e
if [ "$grc" -ge 2 ]; then
    echo "check_test_registration: FATAL — grep over $SERIAL failed (exit $grc)" >&2
    exit 2
fi
dispatched=$(printf '%s\n' "$serial_calls" | sed -E 's/^test_(.*)\(\)$/\1/' | sort -u)

# Union: a name that runs in EITHER runner.
runs=$(printf '%s\n%s\n' "$registered" "$dispatched" | grep -v '^$' | sort -u)

# ── Enumerate filename-matching entry points and check each ──
orphans=""
entry_count=0
for f in "$TEST_DIR"/test_*.c; do
    [ -e "$f" ] || continue
    base=$(basename "$f" .c)        # test_<name>
    name=${base#test_}              # <name>
    # The runner files own main(), not entry points.
    if [ "$base" = "test_parallel" ] || [ "$base" = "test" ]; then
        continue
    fi
    # Entry point := defines `int test_<name>(void)` body opener (own line).
    set +e
    grep -qE "^int[[:space:]]+test_${name}\(void\)[[:space:]]*\$" "$f"
    grc=$?
    set -e
    if [ "$grc" -ge 2 ]; then
        echo "check_test_registration: FATAL — grep over $f failed (exit $grc)" >&2
        exit 2
    fi
    [ "$grc" -eq 0 ] || continue    # no filename-matching entry point in this file
    entry_count=$((entry_count + 1))
    # rc 1 = genuinely unregistered; rc >=2 (fork failure under load, etc.)
    # must FATAL, not masquerade as an orphan — seen misreporting a
    # registered test right after a 32-worker suite run (2026-07-10).
    # Feed grep with a here-string: `printf | grep -q` under pipefail can make
    # printf receive SIGPIPE after grep's early match and falsely report 141.
    set +e
    grep -qxF "$name" <<< "$runs"
    grc=$?
    set -e
    if [ "$grc" -ge 2 ]; then
        echo "check_test_registration: FATAL — membership grep for $name failed (exit $grc)" >&2
        exit 2
    fi
    if [ "$grc" -eq 1 ]; then
        orphans="${orphans}${name}\t${f}\n"
    fi
done

# FAIL-LOUD floor: we must have found a healthy number of entry points, else
# the convention/path drifted and the gate is hollow.
if [ "$entry_count" -lt 100 ]; then
    echo "check_test_registration: FATAL — only $entry_count filename-matching test" >&2
    echo "  entry points found under $TEST_DIR (expected >=100). The naming" >&2
    echo "  convention or path drifted; refusing to report 'clean'." >&2
    exit 2
fi

# ── PRONG B: canonical-registry drift ────────────────────────────────────
# Prong A above accepts a test dispatched by EITHER runner. That union is too
# weak in one direction, and the weak direction is the one that matters:
# test_group_catalog.def is the CANONICAL registry and `make test-parallel` is
# the doctrine runner (and the acceptance gate). test.c is the legacy sequential
# shape, and `build/bin/test_zcl` is explicitly never run. So a test dispatched
# ONLY by test.c runs in NO gate — it is dead coverage that reports nothing,
# exactly the failure prong A was written to prevent, just one runner over.
#
# Found on 2026-07-25 by this prong: 5 such names. One of them
# (test_lcc_write_rules) did not merely fail to run — it FAILED when finally
# executed, having been wrong since it was written, because no runner had ever
# reached it.
#
# A serial-dispatched name is canonical-clean iff EITHER
#   (1) it is itself in the canonical catalog, OR
#   (2) the filename-matching entry point of the FILE that defines it is in
#       the catalog — i.e. it is a sub-test reached through a
#       registered parent group (test_simnet_wire.c's per-scenario functions
#       are dispatched by the registered `simnet_wire` group).
# Index every entry-point definition ONCE (name -> defining file). Grepping
# per dispatched name re-scanned the whole test tree ~600 times and cost ~13 s
# of the lint wall on its own.
set +e
defs=$(grep -HE "^int[[:space:]]+test_[a-zA-Z0-9_]+\(void\)[[:space:]]*\$" \
       "$TEST_DIR"/*.c 2>/dev/null)
grc=$?
set -e
if [ "$grc" -ge 2 ]; then
    echo "check_test_registration: FATAL — grep indexing entry points failed (exit $grc)" >&2
    exit 2
fi
declare -A DEF_FILE=()
while IFS= read -r line; do
    [ -n "$line" ] || continue
    f=${line%%:*}
    fn=${line#*:}
    fn=${fn#int}
    fn=${fn##*[[:space:]]}          # test_<name>(void)
    fn=${fn%%(*}                    # test_<name>
    [ -n "${DEF_FILE[${fn#test_}]:-}" ] || DEF_FILE[${fn#test_}]="$f"
done <<< "$defs"

if [ "${#DEF_FILE[@]}" -lt 100 ]; then
    echo "check_test_registration: FATAL — indexed only ${#DEF_FILE[@]} entry-point" >&2
    echo "  definitions under $TEST_DIR (expected >=100). Refusing to report 'clean'." >&2
    exit 2
fi

drift=""
serial_checked=0
for name in $dispatched; do
    [ -n "$name" ] || continue
    # (1) directly registered?
    if grep -qxF "$name" <<< "$registered"; then
        serial_checked=$((serial_checked + 1))
        continue
    fi
    # Not defined in a dedicated lib/test/src file: a helper or an out-of-tree
    # symbol, not a registrable group. Out of scope.
    def_file="${DEF_FILE[$name]:-}"
    [ -n "$def_file" ] || continue
    serial_checked=$((serial_checked + 1))
    # (2) is the defining file's own group registered?
    parent=$(basename "$def_file" .c); parent=${parent#test_}
    if grep -qxF "$parent" <<< "$registered"; then
        continue
    fi
    drift="${drift}${name}\t${def_file}\n"
done

# FAIL-LOUD floor: the serial runner must have yielded a real population, else
# the scan silently emptied and this prong is decorative.
if [ "$serial_checked" -lt 100 ]; then
    echo "check_test_registration: FATAL — only $serial_checked serial-dispatched" >&2
    echo "  names resolved against the canonical registry (expected >=100)." >&2
    echo "  The dispatch or definition convention drifted; refusing to report 'clean'." >&2
    exit 2
fi

if [ -n "$drift" ]; then
    echo "FAIL: test(s) dispatched ONLY by the legacy serial runner (test.c) and"
    echo "  ABSENT from the canonical registry in $CATALOG."
    echo "  \`make test-parallel\` is the doctrine runner and the"
    echo "  acceptance gate; build/bin/test_zcl is never run. These therefore"
    echo "  execute in NO gate and prove NOTHING:"
    echo ""
    printf '%b' "$drift" | while IFS=$'\t' read -r n path; do
        [ -n "$n" ] && echo "    test_$n   ($path)"
    done
    echo ""
    echo "  Fix: add ZCL_TEST_GROUP(<name>) to $CATALOG — and"
    echo "  RUN it (make t-fast ONLY=test_<name>) before assuming it passes."
    echo "  Do NOT delete the test, and do NOT silence this by removing the"
    echo "  test.c dispatch."
    exit 1
fi

if [ -n "$orphans" ]; then
    echo "FAIL: test entry point(s) DEFINED + COMPILED but dispatched by NEITHER"
    echo "  the canonical catalog nor the serial runner"
    echo "  (test.c). They prove NOTHING — green forever, never executed:"
    echo ""
    printf '%b' "$orphans" | while IFS=$'\t' read -r n path; do
        [ -n "$n" ] && echo "    test_$n   ($path)"
    done
    echo ""
    echo "  Fix: add ZCL_TEST_GROUP(<name>) to $CATALOG (the doctrine"
    echo "  \`make test\` runner), or"
    echo "  dispatch it from lib/test/src/test.c. Do NOT delete the test to"
    echo "  silence this gate."
    exit 1
fi

echo "check_test_registration: clean — all $entry_count test entry points are dispatched"
echo "  ($reg_count registered in the canonical catalog; the rest covered by the serial runner)"
echo "  canonical-registry drift: 0 of $serial_checked serial-dispatched name(s)"
echo "  run only under the legacy test.c runner"
exit 0
