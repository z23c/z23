#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_windows_acceptance.sh — the platform-seam acceptance gate, in two
# steps, in this order: RECONCILE the catalog against the tree, then COMPILE.
#
# ── WHY THE RECONCILE STEP EXISTS ───────────────────────────────────────────
# lib/platform/tests/windows_acceptance.mk declares the acceptance programs
# that `make windows-acceptance-compile` cross-links with mingw. Until this
# script existed, NOTHING checked the other direction: that every acceptance
# program ON DISK is named by the catalog. The catalog could only ever be as
# complete as the last person to remember to edit it.
#
# It was not complete. test_directory_watcher.c and test_watcher_record.c
# arrived under lib/platform/tests and sat there read by nothing at all — no
# catalog row, no Makefile rule, not in lib/platform/zcode-package.json — while
# `make check-windows-acceptance` printed a clean PASS the whole time. A green
# gate over an incomplete catalog is the same false green as no gate: a test
# file existing proves nothing runs it, and a catalog row is the only thing
# that makes one run.
#
# So the gate now fails closed on an undeclared program, which is what the
# docs already claimed it did.
#
# ── THE THREE WAYS A PROGRAM ON DISK IS ACCOUNTED FOR ───────────────────────
#   1. It appears in a ZCL_WINDOWS_ACCEPTANCE_*_SOURCES row — the catalog
#      cross-compiles it.
#   2. It defines the `int test_<name>(void)` entry of a group registered in
#      tools/dev/test_group_catalog.def — the suite EXECUTES it natively,
#      which is strictly better than a cross-link.
#   3. It is in the EXEMPT table below, WITH a written reason. An exemption
#      with no reason is a hole; the table refuses to hold one.
# Anything else is exit 1, naming the file.
#
# ── FAIL-CLOSED SHAPE ───────────────────────────────────────────────────────
# An empty scan set, an empty catalog parse, an empty directory set or an
# empty group registry are all HARD FAILURES, never a clean pass. A broken
# glob that reads as "nothing to check" is exactly how the defect above
# survived; this script refuses to be that.
#
# ── THE COMPILE STEP ────────────────────────────────────────────────────────
# Unchanged from what the gate did before: with mingw present, run
# `make windows-acceptance-compile`. With mingw ABSENT, print UNOBSERVED, in
# that word, and exit 0 — an outside contributor is never blocked by a
# cross-compiler they do not have — but UNOBSERVED is not a pass and is not
# cached. The reconcile step runs either way: it needs no compiler at all, so
# a contributor without mingw still gets the catalog checked.
#
# Usage:
#   tools/lint/check_windows_acceptance.sh             # the gate
#   tools/lint/check_windows_acceptance.sh --self-test # prove it can go red
#
# Env:
#   ZCL_WINDOWS_ACCEPTANCE_ROOT  tree to reconcile (default: this repo).
#                                The self-test aims it at a mktemp fixture;
#                                nothing else should set it.
#   ZCL_WINDOWS_ACCEPTANCE_CC    cross-compiler probed for the compile step.
#   ZCL_REQUIRE_MINGW=1          missing compiler is a hard acceptance failure.
#
# Exit: 0 clean (or UNOBSERVED), 1 on any violation or a malformed tree.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=tools/scripts/sh_str.sh
source "$REPO_ROOT/tools/scripts/sh_str.sh"  # str_contains — see the F-note

# list_has <newline-separated list> <exact item> — pipeline-free membership.
# NEVER `printf ... | grep -Fxq` here: grep -q exits at the FIRST match, printf
# then takes SIGPIPE, and under `set -o pipefail` the pipeline reports printf's
# 141 — so a HIT reads as a MISS. Not theoretical: an earlier draft of this
# script used exactly that idiom and flaked 1 run in 15, reporting
# already-declared programs as undeclared. The full note is in
# tools/scripts/sh_str.sh; the rule is that any substring test whose EXIT
# STATUS is a decision must be pipeline-free.
NL=$'\n'
list_has() {
    case "${NL}$1${NL}" in
        *"${NL}$2${NL}"*) return 0 ;;
        *)                return 1 ;;
    esac
}

CATALOG_REL="lib/platform/tests/windows_acceptance.mk"
REGISTRY_REL="tools/dev/test_group_catalog.def"

# ── EXEMPT ──────────────────────────────────────────────────────────────────
# One row per file, "path<TAB>reason". A row with an empty reason is rejected
# by the parser below, because "exempt because someone typed it here" is how a
# catalog rots. Keep this table SHORT: an entry is a standing admission that
# the file is not covered by this gate, so say who does cover it.
exempt_table() {
    cat <<'EXEMPT_EOF'
lib/platform/tests/test_platform.c	Not an acceptance program: it is the zclassic23/platform zcode package's own standalone test, shipped in the files list of lib/platform/zcode-package.json. It carries its own AGENT_IMPACT_RULE in app/controllers/include/controllers/agent_impact_rules.def, which names the dev_platform and os_proc groups. Cross-linking it for Windows would say nothing the package pipeline does not already own.
lib/base/tests/test_base.c	Not an acceptance program: it is the zclassic23/base zcode package's own test binary. The Makefile builds and runs it as $(ZCODE_PACKAGE_BASE_TEST_BIN) and again under ASan as $(ZCODE_PACKAGE_BASE_ASAN_BIN), so it is executed natively on every run of those targets -- stronger evidence than a cross-link.
lib/base/tests/cleanse_probe.c	Not a program at all: it defines package_base_cleanse_probe() and no main(). It exists as a separate translation unit so memory_cleanse() cannot be optimised away, and it is compiled into both zcode base test binaries above.
EXEMPT_EOF
}

# ── catalog parse ───────────────────────────────────────────────────────────
# Active acceptance IDs, one per continuation row in the canonical list.
catalog_tests() {
    LC_ALL=C awk '
        /^ZCL_WINDOWS_ACCEPTANCE_TESTS[ \t]*:=[ \t]*\\[ \t]*$/ {
            active = 1
            next
        }
        active {
            line = $0
            more = (line ~ /\\[ \t]*$/)
            sub(/[ \t]*\\[ \t]*$/, "", line)
            gsub(/^[ \t]+|[ \t]+$/, "", line)
            if (line != "") print line
            if (!more) exit
        }
    ' "$1/$CATALOG_REL"
}

# IDs that actually define a _SOURCES row. These must be exactly the active
# list above: an orphan definition otherwise makes reconciliation count a file
# that Make never generates a binary for.
catalog_source_ids() {
    LC_ALL=C awk '
        /^ZCL_WINDOWS_ACCEPTANCE_[A-Za-z_0-9]+_SOURCES[ \t]*:=/ {
            line = $0
            sub(/^ZCL_WINDOWS_ACCEPTANCE_/, "", line)
            sub(/_SOURCES[ \t]*:=.*/, "", line)
            print line
        }
    ' "$1/$CATALOG_REL" | sort
}

# Every .c path in a real _SOURCES assignment (never a comment). Wider than
# the first source because subject sources are compiler inputs too.
catalog_sources() {
    LC_ALL=C awk '
        function emit(s, n, a, i) {
            gsub(/\\/, " ", s)
            n = split(s, a, /[ \t]+/)
            for (i = 1; i <= n; i++)
                if (a[i] ~ /^[-A-Za-z0-9_.\/]+[.]c$/) print a[i]
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
    ' "$1/$CATALOG_REL" | sort -u
}

# The directories the catalog actually keeps acceptance programs in, read off
# the FIRST source of each _SOURCES row (the program; the rest are its
# subjects). Derived, never typed here: add a row in a new directory and this
# gate starts scanning it without anybody remembering to.
catalog_program_dirs() {
    LC_ALL=C awk '
        /^ZCL_WINDOWS_ACCEPTANCE_[A-Za-z_0-9]+_SOURCES[ \t]*:=/ {
            getline
            gsub(/^[ \t]+/, "", $0); gsub(/[ \t]*\\[ \t]*$/, "", $0)
            if ($0 ~ /\.c$/) { sub(/\/[^\/]*$/, "", $0); print }
        }
    ' "$1/$CATALOG_REL" | sort -u
}

# ── registry parse ──────────────────────────────────────────────────────────
registry_groups() {
    LC_ALL=C awk '
        /^[[:space:]]*ZCL_TEST_GROUP\([A-Za-z_0-9]+\)[[:space:]]*$/ {
            line = $0; sub(/^[^(]*\(/, "", line); sub(/\).*/, "", line)
            print line
        }
    ' "$1/$REGISTRY_REL" | sort -u
}

# ── the scan set ────────────────────────────────────────────────────────────
# Which files in a catalog directory count as "an acceptance program on disk".
#
#   a dedicated */tests directory  -> EVERY .c file in it. Nothing else lives
#       there, and this is the rule that would have caught the two dead
#       programs: they were named test_*.c, so a *_acceptance.c-only scan
#       would have walked right past them, which is the whole defect.
#   any other directory (lib/test/src) -> *_acceptance.c only. That directory
#       holds the entire native suite; every other file in it is a registered
#       group and has nothing to do with this catalog.
scan_dir_files() {
    local root="$1" dir="$2"
    case "$dir" in
        */tests) find "$root/$dir" -maxdepth 1 -name '*.c' -type f 2>/dev/null ;;
        *)       find "$root/$dir" -maxdepth 1 -name '*_acceptance.c' -type f 2>/dev/null ;;
    esac
}

# ── does this file define a registered group's entry point? ─────────────────
file_defines_registered_group() {
    local file="$1" groups="$2" name
    while read -r name; do
        [ -n "$name" ] || continue
        name="${name##* }"
        name="${name%%(*}"
        name="${name#test_}"
        if list_has "$groups" "$name"; then
            printf '%s\n' "$name"
            return 0
        fi
    done < <(LC_ALL=C grep -oE '^int[[:space:]]+test_[A-Za-z0-9_]+\(void\)' "$file" 2>/dev/null)
    return 1
}

# ── step 1: reconcile ───────────────────────────────────────────────────────
reconcile_root() {
    local root="$1"
    local catalog="$root/$CATALOG_REL" registry="$root/$REGISTRY_REL"

    [ -f "$catalog" ]  || { echo "FAIL: no acceptance catalog at $catalog"; return 1; }
    [ -f "$registry" ] || { echo "FAIL: no test group registry at $registry"; return 1; }

    local declared dirs groups tests source_ids
    declared="$(catalog_sources "$root")"
    dirs="$(catalog_program_dirs "$root")"
    groups="$(registry_groups "$root")"
    tests="$(catalog_tests "$root")"
    source_ids="$(catalog_source_ids "$root")"

    if [ -z "${tests//[[:space:]]/}" ]; then
        echo "FAIL: $CATALOG_REL yielded no active acceptance IDs."
        return 1
    fi
    local test_count unique_test_count source_id_count
    test_count="$(printf '%s\n' "$tests" | grep -c .)"
    unique_test_count="$(printf '%s\n' "$tests" | sort -u | grep -c .)"
    source_id_count="$(printf '%s\n' "$source_ids" | grep -c .)"
    if [ "$test_count" -ne "$unique_test_count" ]; then
        echo "FAIL: $CATALOG_REL carries duplicate active acceptance IDs."
        return 1
    fi
    if [ "$(printf '%s\n' "$tests" | sort)" != "$source_ids" ]; then
        echo "FAIL: active acceptance IDs and _SOURCES IDs differ."
        echo "      Every active ID must define one source row, and every source"
        echo "      row must be active so Make actually links its program."
        diff -u <(printf '%s\n' "$tests" | sort) \
                <(printf '%s\n' "$source_ids") || true
        return 1
    fi
    if [ "$source_id_count" -lt 1 ]; then
        echo "FAIL: $CATALOG_REL yielded zero active source definitions."
        return 1
    fi

    if [ -z "${declared//[[:space:]]/}" ]; then
        echo "FAIL: $CATALOG_REL named no .c sources at all."
        echo "      A catalog this gate cannot read is worse than a missing row:"
        echo "      every program on disk would silently read as 'not required'."
        return 1
    fi
    if [ -z "${dirs//[[:space:]]/}" ]; then
        echo "FAIL: could not derive a single acceptance-program directory from"
        echo "      $CATALOG_REL. The scan set comes from the first source of each"
        echo "      ZCL_WINDOWS_ACCEPTANCE_*_SOURCES row; if that row shape changed,"
        echo "      this gate is scanning nothing and must say so, not pass."
        return 1
    fi
    if [ -z "${groups//[[:space:]]/}" ]; then
        echo "FAIL: $REGISTRY_REL yielded no ZCL_TEST_GROUP rows."
        echo "      The 'it is a registered suite group' escape hatch would then"
        echo "      accept nothing, turning real coverage into a false violation."
        return 1
    fi

    # Exempt table: parse and refuse a reasonless row.
    local exempt_paths="" path reason
    while IFS=$'\t' read -r path reason; do
        [ -n "$path" ] || continue
        if [ -z "${reason//[[:space:]]/}" ]; then
            echo "FAIL: EXEMPT row for '$path' carries no reason."
            echo "      An exemption without a written reason is just a hole."
            return 1
        fi
        exempt_paths="$exempt_paths$path$NL"
    done < <(exempt_table)
    exempt_paths="${exempt_paths%"$NL"}"

    local scanned="" d f
    while read -r d; do
        [ -n "$d" ] || continue
        [ -d "$root/$d" ] || continue
        while read -r f; do
            [ -n "$f" ] || continue
            scanned="$scanned${f#"$root/"}$NL"
        done < <(scan_dir_files "$root" "$d")
    done <<< "$dirs"
    scanned="$(printf '%s' "$scanned" | LC_ALL=C sort -u)"

    if [ -z "${scanned//[[:space:]]/}" ]; then
        echo "FAIL: the acceptance-program scan set came back EMPTY."
        echo "      Directories derived from the catalog:"
        printf '%s\n' "$dirs" | sed 's/^/          /'
        echo "      A broken glob must not read as clean. If those directories are"
        echo "      genuinely empty the catalog rows pointing into them are stale."
        return 1
    fi

    local n_scanned n_dirs n_declared_hit=0 n_group_hit=0 n_exempt_hit=0
    local violations="" rel
    n_scanned="$(printf '%s\n' "$scanned" | LC_ALL=C grep -c .)"
    n_dirs="$(printf '%s\n' "$dirs" | LC_ALL=C grep -c .)"

    while read -r rel; do
        [ -n "$rel" ] || continue
        if list_has "$declared" "$rel"; then
            n_declared_hit=$((n_declared_hit + 1))
            continue
        fi
        if file_defines_registered_group "$root/$rel" "$groups" >/dev/null; then
            n_group_hit=$((n_group_hit + 1))
            continue
        fi
        if list_has "$exempt_paths" "$rel"; then
            n_exempt_hit=$((n_exempt_hit + 1))
            continue
        fi
        violations="$violations$rel$NL"
    done <<< "$scanned"

    if [ -n "${violations//[[:space:]]/}" ]; then
        echo "FAIL: acceptance program(s) on disk that NOTHING accounts for:"
        printf '%s' "$violations" | sed 's/^/    /'
        echo ""
        echo "  Each file above is in a directory the acceptance catalog owns, and it"
        echo "  is none of: a source in a ZCL_WINDOWS_ACCEPTANCE_*_SOURCES row in"
        echo "  $CATALOG_REL; the int test_<name>(void) entry of a group registered"
        echo "  in $REGISTRY_REL; an EXEMPT row with a written reason in this script."
        echo ""
        echo "  A test file existing proves nothing runs it. Pick one:"
        echo "    - add a catalog row so mingw cross-links it, or"
        echo "    - rehome it into lib/test/src as a registered group so the suite"
        echo "      EXECUTES it (strictly better, when the program has a POSIX arm), or"
        echo "    - exempt it here and say why."
        return 1
    fi

    printf 'check-windows-acceptance: reconcile PASS — %s program(s) scanned in %s dir(s): %s catalog-declared, %s registered suite group(s), %s exempt.\n' \
        "$n_scanned" "$n_dirs" "$n_declared_hit" "$n_group_hit" "$n_exempt_hit"
    return 0
}

# ── step 2: compile ─────────────────────────────────────────────────────────
compile_step() {
    local cc="${ZCL_WINDOWS_ACCEPTANCE_CC:-x86_64-w64-mingw32-gcc}"
    if command -v "$cc" >/dev/null 2>&1; then
        local target=windows-acceptance-compile
        case "$(uname -s 2>/dev/null || true)" in
            MINGW*|MSYS*|CYGWIN*) target=windows-acceptance ;;
        esac
        make -C "$REPO_ROOT" --no-print-directory "$target"
        return $?
    fi
    if [ "${ZCL_REQUIRE_MINGW:-0}" = 1 ]; then
        printf '%s\n' "check-windows-acceptance: FAIL (required compiler $cc is unavailable)" >&2
        return 2
    fi
    printf '%s\n' "check-windows-acceptance: UNOBSERVED ($cc not installed; reconcile still ran and PASSED)"
    return 0
}

# ── self-test ───────────────────────────────────────────────────────────────
# A gate not proven able to go red is not evidence. Each case plants ONE thing
# in a throwaway fixture and asserts the reconcile verdict. The fixture is a
# REAL parse of the real catalog and registry (copied in), so the code under
# test is the code that runs in the gate, not a mock.
FIXTURE_ROOT=""
selftest_cleanup() { [ -n "$FIXTURE_ROOT" ] && rm -rf "$FIXTURE_ROOT"; }

make_fixture() {
    local d="$1" p
    mkdir -p "$d/$(dirname "$CATALOG_REL")" "$d/$(dirname "$REGISTRY_REL")"
    cp "$REPO_ROOT/$CATALOG_REL"  "$d/$CATALOG_REL"
    cp "$REPO_ROOT/$REGISTRY_REL" "$d/$REGISTRY_REL"
    # Every program the catalog declares, as an empty file: the reconcile only
    # ever asks whether a path is accounted for, never what is inside a
    # declared one.
    while read -r p; do
        [ -n "$p" ] || continue
        case "$p" in
            lib/test/src/*_acceptance.c|*/tests/*.c) ;;
            *) continue ;;
        esac
        mkdir -p "$d/$(dirname "$p")"
        : > "$d/$p"
    done < <(catalog_sources "$REPO_ROOT")
    # Every exempt file, likewise — they are on disk in the real tree.
    while IFS=$'\t' read -r p _; do
        [ -n "$p" ] || continue
        mkdir -p "$d/$(dirname "$p")"
        : > "$d/$p"
    done < <(exempt_table)
}

expect_red() {
    local label="$1" needle="$2" d="$3" out rc
    out="$(reconcile_root "$d" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "SELF-TEST FAIL: $label — expected a RED, got a PASS."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    if str_lacks "$out" "$needle"; then
        echo "SELF-TEST FAIL: $label — went red but never named '$needle'."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  self-test ok (RED): $label"
    printf '%s\n' "$out" | LC_ALL=C grep -F -- "$needle" | head -2 | sed 's/^/      | /'
    return 0
}

expect_green() {
    local label="$1" d="$2" out rc
    out="$(reconcile_root "$d" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "SELF-TEST FAIL: $label — expected a PASS, got a RED."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  self-test ok (GREEN): $label"
    printf '%s\n' "$out" | sed 's/^/      | /'
    return 0
}

run_selftest() {
    FIXTURE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/windows-acceptance-selftest.XXXXXX")"
    trap selftest_cleanup EXIT
    local rc=0 d planted

    echo "══ check-windows-acceptance self-test ══"

    # 1. Positive control FIRST: the clean fixture passes, so none of the reds
    #    below can be an unconditional failure.
    d="$FIXTURE_ROOT/clean"; mkdir -p "$d"; make_fixture "$d"
    expect_green "1. a fixture with every declared program and nothing else passes" "$d" || rc=1

    # 2. THE defect: an undeclared program in a catalog directory goes red and
    #    is named. Note the name — test_*.c, not *_acceptance.c — because that
    #    is the shape the two real dead programs had.
    planted="lib/platform/tests/test_planted_undeclared.c"
    printf 'int main(void) { return 0; }\n' > "$d/$planted"
    expect_red "2. a planted UNDECLARED program is caught and named" "$planted" "$d" || rc=1

    # 3. Removing it restores the pass — the red in 2 was caused by that file
    #    and by nothing else.
    rm -f "$d/$planted"
    expect_green "3. removing the planted program restores the pass" "$d" || rc=1

    # 4. The suite-group escape hatch really is an escape hatch: the same file,
    #    but defining a REGISTERED group's entry point, is accounted for.
    printf 'int test_directory_watcher(void) { return 0; }\n' > "$d/$planted"
    expect_green "4. the same file passes once it defines a registered group entry" "$d" || rc=1
    rm -f "$d/$planted"

    # 5. A program in lib/test/src named *_acceptance.c and declared nowhere is
    #    caught too — the second scanned directory, with its narrower glob.
    planted="lib/test/src/planted_undeclared_acceptance.c"
    printf 'int main(void) { return 0; }\n' > "$d/$planted"
    expect_red "5. an undeclared *_acceptance.c under lib/test/src is caught" "$planted" "$d" || rc=1
    rm -f "$d/$planted"

    # 6. An EMPTY scan set must be a HARD FAIL, never a clean pass. This is the
    #    direction that matters most: a broken glob reading as "nothing to
    #    check" is exactly how the real defect survived.
    d="$FIXTURE_ROOT/empty"; mkdir -p "$d"; make_fixture "$d"
    find "$d/lib" -name '*.c' -type f -delete
    expect_red "6. an empty scan set fails closed" "scan set came back EMPTY" "$d" || rc=1

    # 7. A catalog this gate cannot parse must also fail closed, rather than
    #    declaring every program on disk unrequired.
    d="$FIXTURE_ROOT/nocat"; mkdir -p "$d"; make_fixture "$d"
    printf '# every row removed\n' > "$d/$CATALOG_REL"
    expect_red "7. an unparseable catalog fails closed" "no active acceptance IDs" "$d" || rc=1

    # 8. Removing an ID from the active list while leaving its _SOURCES row
    #    used to keep the program "declared" to reconciliation while Make no
    #    longer generated or linked its binary.
    d="$FIXTURE_ROOT/orphan_sources"; mkdir -p "$d"; make_fixture "$d"
    sed '/^[[:space:]]*rng \\[[:space:]]*$/d' "$d/$CATALOG_REL" \
        > "$d/catalog.mutated"
    mv "$d/catalog.mutated" "$d/$CATALOG_REL"
    expect_red "8. an inactive orphan _SOURCES row is caught" \
               "active acceptance IDs and _SOURCES IDs differ" "$d" || rc=1

    # 9. The reverse mismatch is equally hollow: an active ID with no source
    #    definition would create a generated rule with no program input.
    d="$FIXTURE_ROOT/missing_sources"; mkdir -p "$d"; make_fixture "$d"
    sed '/^ZCL_WINDOWS_ACCEPTANCE_TESTS/ a\
\tplanted_without_sources \\' "$d/$CATALOG_REL" > "$d/catalog.mutated"
    mv "$d/catalog.mutated" "$d/$CATALOG_REL"
    expect_red "9. an active ID without _SOURCES is caught" \
               "active acceptance IDs and _SOURCES IDs differ" "$d" || rc=1

    if [ "$rc" -eq 0 ]; then
        echo "══ self-test: PASS (9/9) — this gate is proven able to go red ══"
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
    reconcile_root "${ZCL_WINDOWS_ACCEPTANCE_ROOT:-$REPO_ROOT}" || exit 1
    compile_step
    exit $?
}

main "$@"
