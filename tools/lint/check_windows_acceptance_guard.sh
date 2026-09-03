#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_windows_acceptance_guard.sh — a Windows acceptance translation unit
# that defines main() must be an empty TU off Windows, or it collides with
# every test binary that links the harness sources.
#
# ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
# Commit b562857bc added tests/harness/src/block_swarm_scale_windows_acceptance.c
# with an unguarded `int main(void)`. Every sibling *_windows_acceptance.c /
# *_acceptance.c TU under tests/harness/src opens with
#
#     #if defined(_WIN32)
#
# right after its header comment and closes with
#
#     #else
#     typedef int <name>_not_built;
#     #endif
#
# so on a POSIX host the file compiles to an empty translation unit and never
# contributes a symbol. The new file skipped both halves, and because the
# harness sources are linked into every test binary, EVERY test group failed
# at link time with "multiple definition of 'main'" — no test group could
# build at all, on all of main, until the file was healed. The push gate ran
# `make lint-fast` plus tests, and nothing checked this shape: the existing
# windows gates cross-compile the catalog for Windows (where the guard is
# open and everything looks fine) or reconcile catalog membership, but no
# gate asked "is this TU inert on THIS host?".
#
# The #else + typedef tail is not decoration: a file whose guard closes with
# a bare `#endif` leaves the off-Windows arm an EMPTY translation unit, which
# this repository compiles at -Werror=pedantic — ISO C requires a TU to
# contain at least one declaration — so the tail placeholder is part of the
# working idiom and is checked here too.
#
# ── WHAT IS SCANNED ──────────────────────────────────────────────────────────
# The union of:
#   1. every file matching tests/harness/src/*_windows_acceptance.c on disk,
#      declared in the catalog or not (the regression shape was a declared
#      row, but a stray future file must not escape); and
#   2. every source named by a ZCL_WINDOWS_ACCEPTANCE_*_SOURCES row in
#      platform/modules/platform/tests/windows_acceptance.mk that lives
#      under the top-level tests/ tree — those are the TUs linked into the
#      Linux test binaries. The catalog's other sources (engine/, platform/,
#      core/... subjects and the platform-modules test programs) do NOT ride
#      the harness link and are out of scope here.
# Each scanned file must either define no main() at all, or carry the full
# guard idiom: first non-comment, non-blank line exactly `#if defined(_WIN32)`,
# last non-comment line `#endif`, with an `#else` arm holding a
# `typedef int ..._not_built;` placeholder between them.
#
# ── FAIL-CLOSED SHAPE ────────────────────────────────────────────────────────
# A missing catalog, a catalog that yields no tests/-rooted sources, a
# catalog row naming a file that is not on disk, or a scan set below
# SCAN_FLOOR are all exit 2 (UNPROVEN), never a clean pass — a broken glob
# must not read as "nothing to check". Violations are exit 1, one
# `path:line: reason` line per offender.
#
# Usage:
#   tools/lint/check_windows_acceptance_guard.sh              # the gate
#   tools/lint/check_windows_acceptance_guard.sh --self-test  # prove red+green
#
# Env:
#   ZCL_WINDOWS_ACCEPTANCE_GUARD_ROOT  tree to scan (default: this repo).
#                                       The self-test aims it at fixtures under
#                                       $HOME/.local/state/zclassic23/scratch;
#                                       nothing else should set it.
#
# Exit: 0 clean, 1 on any guard-shape violation, 2 on a hollow/unreadable
#       scan (missing catalog, missing declared file, floor).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=tools/lint/gate_lib.sh
source "$REPO_ROOT/tools/lint/gate_lib.sh"

GATE=check-windows-acceptance-guard
CATALOG_REL="platform/modules/platform/tests/windows_acceptance.mk"
HARNESS_DIR_REL="tests/harness/src"
STRIP_AWK="$REPO_ROOT/tools/lint/strip_c_comments.awk"

# Floor on the scan set. The catalog alone declares well over twenty
# tests/-rooted acceptance TUs today; a scan that finds fewer than 8 has
# lost its subject (a renamed directory, an unparseable catalog silently
# downgraded to glob-only) and must refuse to grade. See
# docs/DEFENSIVE_CODING.md and gate_lib.sh gate_require_scanned.
SCAN_FLOOR=8

# Catalog sources under the top-level tests/ tree, continuation-row aware
# (same parse shape as check_windows_acceptance.sh catalog_sources).
catalog_tests_sources() {
    LC_ALL=C awk '
        function emit(s, n, a, i) {
            gsub(/\\/, " ", s)
            n = split(s, a, /[ \t]+/)
            for (i = 1; i <= n; i++)
                if (a[i] ~ /^tests\/[-A-Za-z0-9_.\/]+[.]c$/) print a[i]
        }
        /^ZCL_WINDOWS_ACCEPTANCE_[A-Za-z_0-9]+_SOURCES[ \t]*:=/ {
            line = $0
            more = (line ~ /\\[ \t]*$/)
            sub(/^[^:]*:=[ \t]*/, "", line)
            emit(line)
            active = more
            next
        }
        active {
            line = $0
            more = (line ~ /\\[ \t]*$/)
            emit(line)
            active = more
        }
    ' "$1"
}

# Per-file verdict. Reads the file with comments stripped (line numbers are
# preserved by strip_c_comments.awk) and prints nothing when the file is
# clean, or exactly one `line<TAB>reason` row when it is not.
inspect_file() {
    local file="$1"
    awk -f "$STRIP_AWK" "$file" | LC_ALL=C awk '
        {
            if ($0 ~ /^[[:space:]]*$/) next
            line = $0
            sub(/^[[:space:]]+/, "", line)
            sub(/[[:space:]]+$/, "", line)
            if (firstln == 0) { first = line; firstln = NR }
            last = line; lastln = NR
            if (line ~ /^(int|void)[[:space:]]+main[[:space:]]*\(/)
                mainln = NR
            if (line ~ /^#else/)
                elsln = NR
            if (line ~ /^typedef[[:space:]]+int[[:space:]]+[A-Za-z0-9_]+_not_built[[:space:]]*;/)
                tbln = NR
            if (line ~ /^#endif/)
                endifln = NR
        }
        END {
            if (mainln == 0) exit 0
            if (first != "#if defined(_WIN32)") {
                printf "%d\tdefines main() but the first non-comment line is not \047#if defined(_WIN32)\047 (it is: %s)\n", firstln, first
                exit 0
            }
            if (last != "#endif") {
                printf "%d\tguarded but the last non-comment line is not \047#endif\047 (it is: %s)\n", lastln, last
                exit 0
            }
            if (elsln == 0 || elsln > endifln) {
                printf "%d\tguarded but no \047#else\047 arm before the final \047#endif\047\n", endifln
                exit 0
            }
            if (tbln == 0 || tbln < elsln || tbln > endifln) {
                printf "%d\t\047#else\047 arm lacks a \047typedef int ..._not_built;\047 placeholder (an empty TU trips -Werror=pedantic)\n", endifln
                exit 0
            }
            exit 0
        }
    '
}

# ── the scan ────────────────────────────────────────────────────────────────
scan_root() {
    local root="$1"
    local catalog="$root/$CATALOG_REL"

    [ -f "$catalog" ] || {
        echo "$GATE: UNPROVEN — no acceptance catalog at $CATALOG_REL." >&2
        echo "  The scan set is derived from it; without the catalog this" >&2
        echo "  gate would grade only the glob and call that clean." >&2
        return 2
    }

    local declared="" p rel
    declared="$(catalog_tests_sources "$catalog")"
    if [ -z "${declared//[[:space:]]/}" ]; then
        echo "$GATE: UNPROVEN — $CATALOG_REL named no sources under tests/." >&2
        echo "  The row shape this gate parses may have changed; a scan over" >&2
        echo "  the glob alone must not stand in for the catalog." >&2
        return 2
    fi

    # Every declared tests/-rooted source must be present: a missing one is a
    # partial scan of exactly the kind the floor exists to stop, and the
    # offender is named instead of being skipped.
    local missing=""
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        [ -f "$root/$p" ] || missing="$missing$p\n"
    done <<EOF
$declared
EOF
    if [ -n "$missing" ]; then
        echo "$GATE: UNPROVEN — catalog rows naming files not on disk:" >&2
        printf '%b' "$missing" | sed 's/^/    /' >&2
        return 2
    fi

    # Union: the on-disk glob (declared or not) plus the catalog rows.
    local scan_set="" f
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        scan_set="${scan_set}${f#"$root/"}\n"
    done < <(find "$root/$HARNESS_DIR_REL" -maxdepth 1 -name '*_windows_acceptance.c' -type f 2>/dev/null || true)
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        scan_set="${scan_set}$p\n"
    done <<EOF
$declared
EOF
    scan_set="$(printf '%b' "$scan_set" | LC_ALL=C sort -u | sed '/^$/d')"

    local count
    count="$(printf '%s\n' "$scan_set" | grep -c .)"
    gate_require_scanned "$count" "$SCAN_FLOOR" "$GATE" \
        "The union of the ${HARNESS_DIR_REL} glob and the catalog's tests/ rows came back below the floor."

    local offenders="" verdict
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        verdict="$(inspect_file "$root/$rel" || true)"
        [ -n "$verdict" ] || continue
        offenders="${offenders}${rel}:$(printf '%s' "$verdict" | cut -f1):$(printf '%s' "$verdict" | cut -f2-)\n"
    done <<EOF
$scan_set
EOF

    if [ -n "${offenders//[[:space:]]/}" ]; then
        echo "$GATE: FAIL — Windows acceptance TU(s) that define main() without the full off-Windows guard:" >&2
        printf '%b' "$offenders" | sed 's/^/    /' >&2
        echo "" >&2
        echo "  A tests/-rooted acceptance TU is linked into every Linux test" >&2
        echo "  binary; an unguarded main() collides with the suite runner and" >&2
        echo "  NO test group can link. Wrap the whole body:" >&2
        echo "      #if defined(_WIN32)" >&2
        echo "      ...existing body..." >&2
        echo "      #else" >&2
        echo "      typedef int <name>_not_built;" >&2
        echo "      #endif" >&2
        return 1
    fi

    printf '%s: clean — %d file(s) scanned; every tests/-rooted Windows acceptance TU opens with \047#if defined(_WIN32)\047 and closes with an \047#else ... _not_built; #endif\047 tail, or defines no main()\n' \
        "$GATE" "$count"
    return 0
}

# ── self-test ────────────────────────────────────────────────────────────────
# A gate not proven able to go red is not evidence. Fixtures live under
# $HOME/.local/state/zclassic23/scratch (the operator scratch area), never
# /tmp: the planted acceptance TUs must not be picked up by any concurrent
# tree scan, and /tmp is shared with gates that fixture there.
FIXTURE_ROOT=""
selftest_cleanup() { [ -n "$FIXTURE_ROOT" ] && rm -rf "$FIXTURE_ROOT"; }

write_guarded() { # <path> <basename-without-.c>
    cat > "$1" <<EOF
/* Fixture Copyright header spanning
 * two comment lines like the real TUs. */

#if defined(_WIN32)

#include <stdio.h>

int main(void)
{
    return 0;
}

#else
typedef int ${2}_not_built;
#endif
EOF
}

expect_green() {
    local label="$1" d="$2" out rc
    out="$(scan_root "$d" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "SELF-TEST FAIL: $label — expected a PASS, got exit $rc."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  self-test ok (GREEN): $label"
    return 0
}

expect_red() { # <label> <expected-substring> <dir>
    local label="$1" needle="$2" d="$3" out rc
    out="$(scan_root "$d" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "SELF-TEST FAIL: $label — expected a RED, got a PASS."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    # Here-string, not a pipeline: grep -q under pipefail can surface the
    # producer's SIGPIPE on a match (see tools/lint/check_pipefail_status_pipe.sh).
    if ! grep -qF -- "$needle" <<<"$out"; then
        echo "SELF-TEST FAIL: $label — went red but never named '$needle'."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  self-test ok (RED): $label"
    printf '%s\n' "$out" | grep -F -- "$needle" | head -1 | sed 's/^/      | /'
    return 0
}

run_selftest() {
    local scratch="${ZCL_WINDOWS_ACCEPTANCE_GUARD_SCRATCH:-$HOME/.local/state/zclassic23/scratch}"
    mkdir -p "$scratch" || { echo "SELF-TEST FAIL: cannot create $scratch" >&2; return 1; }
    FIXTURE_ROOT="$(mktemp -d "$scratch/windows-acceptance-guard-selftest.XXXXXX")"
    trap selftest_cleanup EXIT
    local rc=0 d p name

    echo "══ $GATE self-test ══"

    # The GOOD fixture: the REAL catalog, and every tests/-rooted source it
    # declares present as a correctly guarded TU. The parse under test is the
    # parse that runs in production.
    d="$FIXTURE_ROOT/good"; mkdir -p "$d/$(dirname "$CATALOG_REL")"
    cp "$REPO_ROOT/$CATALOG_REL" "$d/$CATALOG_REL"
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        mkdir -p "$d/$(dirname "$p")"
        name="$(basename "$p" .c)"
        write_guarded "$d/$p" "$name"
    done < <(catalog_tests_sources "$REPO_ROOT/$CATALOG_REL")

    # 1. Positive control FIRST: none of the reds below may be unconditional.
    expect_green "1. the real catalog with every declared TU correctly guarded passes" "$d" || rc=1

    # 2. THE regression: one declared TU with an unguarded main() goes red
    #    and is named at the offending line.
    p="$(catalog_tests_sources "$REPO_ROOT/$CATALOG_REL" | head -1)"
    cat > "$d/$p" <<'EOF'
/* Fixture Copyright header. */

#include <stdio.h>

int main(void)
{
    return 0;
}
EOF
    expect_red "2. an unguarded main() (the b562857bc shape) is caught and named" "$p" "$d" || rc=1

    # 3. Restoring the guard restores the pass — the red was that file alone.
    name="$(basename "$p" .c)"
    write_guarded "$d/$p" "$name"
    expect_green "3. restoring the guard restores the pass" "$d" || rc=1

    # 4. Head-guarded but tailless: the guard opens and never closes with the
    #    #else/typedef/#endif trio.
    cat > "$d/$p" <<'EOF'
/* Fixture Copyright header. */
#if defined(_WIN32)
#include <stdio.h>
int main(void) { return 0; }
EOF
    expect_red "4. a missing '#else ... #endif' tail is caught" "guarded but the last non-comment line is not '#endif'" "$d" || rc=1
    write_guarded "$d/$p" "$name"

    # 5. The glob arm, independent of the catalog: a stray unguarded
    #    *_windows_acceptance.c that no catalog row names is still caught.
    p="$HARNESS_DIR_REL/stray_undeclared_windows_acceptance.c"
    mkdir -p "$d/$(dirname "$p")"
    printf 'int main(void) { return 0; }\n' > "$d/$p"
    expect_red "5. an undeclared stray *_windows_acceptance.c is caught by the glob" "$p" "$d" || rc=1
    rm -f "$d/$p"

    # 6. The no-main arm: a file that defines no main() needs no guard.
    printf '#include <stdio.h>\nint fixture_helper(void) { return 0; }\n' > "$d/$p"
    expect_green "6. an unguarded file that defines no main() passes" "$d" || rc=1
    rm -f "$d/$p"

    # 7. The floor: a scan set below SCAN_FLOOR must be exit 2, never clean.
    #    A synthetic small catalog (same row syntax) with only its 7 guarded
    #    programs on disk — the count alone decides.
    d="$FIXTURE_ROOT/floor"; mkdir -p "$d/$(dirname "$CATALOG_REL")" "$d/$HARNESS_DIR_REL"
    {
        echo 'ZCL_WINDOWS_ACCEPTANCE_TESTS := \'
        echo '	f1 \'
        echo '	f2 \'
        echo '	f3 \'
        echo '	f4 \'
        echo '	f5 \'
        echo '	f6 \'
        echo '	f7'
        for i in 1 2 3 4 5 6 7; do
            echo "ZCL_WINDOWS_ACCEPTANCE_f${i}_SOURCES := \\"
            echo "	$HARNESS_DIR_REL/f${i}_windows_acceptance.c \\"
            echo "	platform/modules/platform/src/subject.c"
        done
    } > "$d/$CATALOG_REL"
    for i in 1 2 3 4 5 6 7; do
        write_guarded "$d/$HARNESS_DIR_REL/f${i}_windows_acceptance.c" "f${i}_windows_acceptance"
    done
    expect_red "7. a scan below the floor of $SCAN_FLOOR refuses (exit 2)" "floor" "$d" || rc=1

    if [ "$rc" -eq 0 ]; then
        echo "══ self-test: PASS (7/7) — this gate is proven able to go red ══"
    else
        echo "══ self-test: FAIL ══"
    fi
    return "$rc"
}

main() {
    case "${1:-}" in
        --self-test) run_selftest; exit $? ;;
        "") ;;
        *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
    esac
    scan_root "${ZCL_WINDOWS_ACCEPTANCE_GUARD_ROOT:-$REPO_ROOT}"
    exit $?
}

main "$@"
