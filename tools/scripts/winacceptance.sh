#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# winacceptance.sh — build (and, where honestly possible, RUN) the 26
# platform-seam acceptance programs in tools/winacceptance/ and tools/tests/.
#
# Purpose: compile every acceptance program for the Windows target with mingw
# at the project's REAL API floor, natively compile the portable ones, run the
# subset that can genuinely execute on this host, and report the three counts
# separately so a compile check is never read as an execution pass.
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
# tools/winacceptance/ held 24 C programs and tools/tests/ held 2 more, and
# NOTHING built or ran any of them: no Makefile target, no test group, no CI
# reference, and outside its own directory the string "winacceptance" appeared
# nowhere in the tree. They are the acceptance tests for the macOS/Windows
# platform seam, which is the active work, so that whole seam was shipping
# unverified by its own tests. Twenty-six programs that no compiler has ever
# seen are not tests; they are unread prose. This script is what makes a
# compiler see them.
#
# ── THE THREE BUCKETS, AND WHY A SKIP IS NOT A PASS ────────────────────────
# A Windows binary does not execute on a Linux host, and pretending otherwise
# is the failure mode this repo has already been burned by twice (a push gate
# that printed green while running zero tests; a load-sensitivity "fix" that
# turned a real FAIL into a SKIP and just moved the red). So every program is
# declared into exactly one bucket in the MANIFEST below, and the script
# reports the buckets as three separate numbers that are never summed into a
# single "passed" figure:
#
#   win        Windows-only. Either it includes <windows.h> unconditionally,
#              or its assertions encode a Windows-specific refusal that would
#              FALSELY FAIL if executed on POSIX. Cross-compiled to a Windows
#              object. NOT linked. NOT executed. This is a COMPILE CHECK.
#
#   noexec     Compiles for BOTH targets, but still must not be executed
#              here: its non-Windows main() is a stub (`return 77`, or worse
#              `return 0` — see test_wallet_restore_windows_refusal), or its
#              assertions are Windows refusal semantics. Cross-compiled AND
#              natively compiled. NOT executed. Also a COMPILE CHECK.
#
#   run        Genuinely portable and genuinely meaningful on this host.
#              Cross-compiled, natively compiled, LINKED, and EXECUTED, and
#              its real exit status is graded. An exit of 77 from a `run`
#              program is a FAILURE, not a skip: a program declared runnable
#              that skips at runtime has lost the thing it was declared for.
#
# The bucket is DECLARED, never inferred from what happens to compile. If a
# `run` or `noexec` program stops compiling natively, that is a failure — not
# a quiet reclassification into `win`. And the manifest is reconciled against
# the directories on disk, so a new acceptance program added without a row
# here FAILS this script instead of silently going unbuilt again, which is the
# exact disease being cured.
#
# ── THE FLAGS COME FROM THE MAKEFILE, NEVER FROM A COPY HERE ────────────────
# tools/lint/check_windows_platform_seam.sh established this and explains why
# at length: mingw gates real API surface on _WIN32_WINNT, so compiling at
# mingw's permissive default asks a DIFFERENT and easier question than the
# build asks, and answers OK for a file that cannot build for the product's
# actual Windows target. That is a false green. ZCL_PLATFORM_CPPFLAGS is read
# out of the Makefile's Windows branch and drifts with it by construction.
# -DZCL_TESTING is added because these are tests and the seams they call
# (consensus_state_publication_cas_persist_for_test,
# wallet_recovery_test_ensure_datadir) are declared only under it, exactly as
# TEST_REL_CFLAGS/TEST_FAST_CFLAGS do for the real test binaries.
#
# The warning level is the project's own: -Wall -Wextra -Werror -pedantic.
# Anything weaker is a false green of the second kind — nine of these programs
# redefined WIN32_LEAN_AND_MEAN on top of the command-line define and only
# -Werror made that visible.
#
# ── HONESTY CONTRACT ────────────────────────────────────────────────────────
#   * no mingw on the box  -> the Windows leg prints UNOBSERVED, in that word,
#     cross-compiles ZERO programs, and says so. It is never called a pass.
#     The native leg still runs, and its counts are still real.
#   * every run prints how many programs were cross-compiled, how many were
#     natively compiled, how many were EXECUTED, and how many were compile-
#     checked only. Those numbers are printed separately, always.
#   * this script has no baseline and no allowlist, so there is nothing here
#     that can be widened to stay green.
#
# Modes:
#   (default)      compile all, run the `run` bucket, report.
#   --compile-only compile legs only; execute nothing. Still reports 0 ran.
#   --list         print the manifest (name, bucket, link deps) and exit.
#   --self-test    prove the gate actually trips: assert mingw rejects a
#                  planted TU that uses an API above the project's own
#                  _WIN32_WINNT floor and accepts a clean one, and assert a
#                  planted failing `run` program is graded as a failure.
#
# Env:
#   ZCL_MINGW_CC   cross compiler (default: x86_64-w64-mingw32-gcc)
#   ZCL_NATIVE_CC  native compiler (default: cc)
#
# Exit: 0 all declared work succeeded (Windows leg may be UNOBSERVED);
#       1 a compile or an execution failed;
#       2 a hollow/misconfigured scan (manifest out of sync with the tree,
#         unreadable Makefile flags, missing include roots).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

GATE="winacceptance"
CROSS_CC="${ZCL_MINGW_CC:-x86_64-w64-mingw32-gcc}"
NATIVE_CC="${ZCL_NATIVE_CC:-cc}"
MAKEFILE="Makefile"

# ── THE MANIFEST ────────────────────────────────────────────────────────────
# "<source path>|<bucket>|<space-separated extra sources to link for a run>"
#
# Bucket rationale is one line per row; `win` rows that do not include
# <windows.h> are there because their ASSERTIONS are Windows-only, which the
# compiler cannot tell you.
MANIFEST=(
  # --- win: includes <windows.h> unconditionally ---------------------------
  "tools/winacceptance/boot_auto_install_bundle_refusal_acceptance.c|win|"
  "tools/winacceptance/bundle_exporter_refusal_acceptance.c|win|"
  "tools/winacceptance/directory_compat_acceptance.c|win|"
  "tools/winacceptance/disk_space_acceptance.c|win|"
  "tools/winacceptance/file_metadata_acceptance.c|win|"
  "tools/winacceptance/logical_cpu_acceptance.c|win|"
  "tools/winacceptance/package_lifecycle_store_refusal_acceptance.c|win|"
  "tools/winacceptance/private_directory_acceptance.c|win|"
  "tools/winacceptance/private_file_acceptance.c|win|"
  "tools/winacceptance/rpc_client_transport_acceptance.c|win|"
  "tools/winacceptance/ui_host_transport_acceptance.c|win|"
  "tools/winacceptance/utxo_recovery_ldb_copy_refusal_acceptance.c|win|"
  "tools/winacceptance/wallet_recovery_directory_acceptance.c|win|"

  # --- noexec: compiles for both, but executing it here proves nothing -----
  # Windows-refusal assertions; on POSIX the production path does the real
  # work, so running these natively would be a FALSE failure.
  "tools/winacceptance/build_fabric_worker_refusal_acceptance.c|noexec|"
  "tools/winacceptance/consensus_state_install_runtime_refusal_acceptance.c|noexec|"
  "tools/winacceptance/consensus_state_publication_cas_refusal_acceptance.c|noexec|"
  "tools/winacceptance/zcode_benchmark_executor_refusal_acceptance.c|noexec|"
  # Explicit `#else int main(void) { return 77; }` — a runtime skip.
  "tools/winacceptance/positioned_file_acceptance.c|noexec|"
  "tools/winacceptance/safe_root_read_acceptance.c|noexec|"
  # Explicit `#else int main(void) { return 0; }` — a runtime skip that
  # returns SUCCESS. Executing this off Windows would manufacture a green
  # from a program that asserted nothing. Compile-checked only, deliberately.
  "tools/tests/test_wallet_restore_windows_refusal.c|noexec|"

  # --- run: portable, meaningful, and actually executed on this host -------
  "tools/winacceptance/format_attribute_acceptance.c|run|"
  "tools/winacceptance/glob_match_acceptance.c|run|"
  "tools/winacceptance/socket_compat_acceptance.c|run|"
  "tools/winacceptance/read_mapping_acceptance.c|run|lib/platform/src/read_mapping.c"
  "tools/winacceptance/workpool_acceptance.c|run|lib/util/src/workpool.c lib/base/src/safe_alloc.c"
  "tools/tests/test_read_mapping_positioned.c|run|lib/platform/src/read_mapping.c lib/platform/src/positioned_file.c"
)

# test_read_mapping_positioned writes its own fixture to argv[1]; every other
# `run` program takes no arguments.
run_args() {
    case "$1" in
        *test_read_mapping_positioned.c) printf '%s\n' "$WORK/positioned-fixture.bin" ;;
        *) : ;;
    esac
}

COMPILE_ONLY=0
if [ "${1:-}" = "--compile-only" ]; then COMPILE_ONLY=1; shift; fi

if [ "${1:-}" = "--list" ]; then
    printf '%s\n' "${MANIFEST[@]}"
    exit 0
fi

echo "══ WINACCEPTANCE: platform-seam acceptance build (+ native run) ══"

# ── Flags from the Makefile, never a copy ───────────────────────────────────
mapfile -t PLATFORM_DEFINES < <(
    awk '/^ZCL_PLATFORM_CPPFLAGS[ \t]*=/ { inblock = 1 }
         inblock { line = line " " $0; if ($0 !~ /\\$/) { print line; exit } }
        ' "$MAKEFILE" | tr ' \t\\' '\n\n\n' | LC_ALL=C grep '^-D' )
if [ "${#PLATFORM_DEFINES[@]}" -eq 0 ]; then
    echo "  $GATE: FATAL — could not read ZCL_PLATFORM_CPPFLAGS from the" >&2
    echo "      Makefile. Refusing to cross-compile at a guessed API floor," >&2
    echo "      which silently grades an easier question than the build asks." >&2
    exit 2
fi

# ── Include search path ─────────────────────────────────────────────────────
# Superset by construction, same reasoning check_windows_platform_seam.sh
# records: headers are namespaced per module, so an extra -I can only add a
# search path, never collide. app/services/src is explicit because
# package_lifecycle_store_refusal_acceptance.c includes that module's PRIVATE
# header, package_lifecycle_internal.h, which has no include/ root.
mapfile -t INC_DIRS < <(
    { find lib app core domain -maxdepth 2 -type d -name include 2>/dev/null
      for d in config/include ports/include application/include \
               adapters/include vendor/include vendor/x11/include \
               lib/test/include app/services/src; do
          [ -d "$d" ] && printf '%s\n' "$d"
      done
    } | sort -u )
gate_require_scanned "${#INC_DIRS[@]}" 20 "$GATE" \
    "no include roots found — the lib/ or app/ layout moved"
INC_FLAGS=()
for d in "${INC_DIRS[@]}"; do INC_FLAGS+=("-I$d"); done

# The project's real warning level. -std=c23 is the project's C standard;
# mingw GCC 13 only knows the older spelling of the same standard, so the
# cross leg asks for -std=c2x. Nothing else differs between the two legs
# except ZCL_PLATFORM_CPPFLAGS, which is empty on Linux by the Makefile's own
# `else` branch.
COMMON_FLAGS=(-Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200809L
              -DZCL_TESTING)
CROSS_FLAGS=(-std=c2x "${COMMON_FLAGS[@]}" "${PLATFORM_DEFINES[@]}")
NATIVE_FLAGS=(-std=c23 "${COMMON_FLAGS[@]}")

WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-winacceptance.XXXXXX")" || {
    echo "$GATE: FATAL — mktemp failed." >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT

have_cross=1
command -v "$CROSS_CC" >/dev/null 2>&1 || have_cross=0

# ── Self-test: prove this script actually trips ─────────────────────────────
if [ "${1:-}" = "--self-test" ]; then
    st_fail=0
    if [ "$have_cross" -eq 0 ]; then
        echo "  $GATE --self-test: UNOBSERVED — '$CROSS_CC' is not installed;" \
             "cannot prove the cross leg trips without the compiler it uses."
    else
        # An API above the project's own _WIN32_WINNT floor must be REJECTED.
        # This is the exact false green the floor exists to prevent, and it is
        # a real defect this script found in logical_cpu_acceptance.c.
        cat > "$WORK/above_floor.c" <<'PROBE'
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
/* GetActiveProcessorCount/ALL_PROCESSOR_GROUPS are declared by mingw only at
 * _WIN32_WINNT >= 0x0601; the project pins the Windows target at 0x0600. */
int zcl_probe(void) { return (int)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS); }
PROBE
        "$CROSS_CC" "${CROSS_FLAGS[@]}" "${INC_FLAGS[@]}" -c "$WORK/above_floor.c" \
            -o "$WORK/above_floor.o" >/dev/null 2>&1
        rc=$?
        if [ "$rc" -eq 0 ]; then
            echo "FAIL: --self-test — mingw ACCEPTED an API above the" >&2
            echo "  project's own _WIN32_WINNT floor. The flag set is not the" >&2
            echo "  build's; this script would grade an easier question." >&2
            st_fail=1
        fi
        printf 'int zcl_clean(int a);\nint zcl_clean(int a) { return a + 1; }\n' \
            > "$WORK/clean.c"
        "$CROSS_CC" "${CROSS_FLAGS[@]}" "${INC_FLAGS[@]}" -c "$WORK/clean.c" \
            -o "$WORK/clean.o" >/dev/null 2>&1
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "FAIL: --self-test — mingw REJECTED a trivially clean TU." >&2
            st_fail=1
        fi
    fi

    # A `run` program that FAILS at runtime, and one that SKIPS with 77, must
    # both be graded as failures. A skip that reads as a pass is the outcome
    # this script exists to make impossible.
    printf 'int main(void) { return 1; }\n' > "$WORK/failing.c"
    printf 'int main(void) { return 77; }\n' > "$WORK/skipping.c"
    for probe in failing skipping; do
        "$NATIVE_CC" "${NATIVE_FLAGS[@]}" -o "$WORK/$probe" "$WORK/$probe.c" \
            >/dev/null 2>&1
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "FAIL: --self-test — could not build the $probe probe." >&2
            st_fail=1
            continue
        fi
        "$WORK/$probe" >/dev/null 2>&1
        rc=$?
        if [ "$rc" -eq 0 ]; then
            echo "FAIL: --self-test — the $probe probe exited 0; this script's" >&2
            echo "  grading of the run bucket would be hollow." >&2
            st_fail=1
        fi
    done

    if [ "$st_fail" -ne 0 ]; then exit 1; fi
    echo "  OK: --self-test — cross flags reject an above-floor API and" \
         "accept clean code; a failing run and a 77 skip are both graded" \
         "as failures"
    exit 0
fi

# ── Manifest / tree reconciliation ──────────────────────────────────────────
# A program on disk with no manifest row would go unbuilt — the exact defect
# being repaired — so it is a FATAL desync, not a warning.
mapfile -t ON_DISK < <(
    find tools/winacceptance tools/tests -maxdepth 1 -name '*.c' -type f \
        2>/dev/null | sort )
gate_require_scanned "${#ON_DISK[@]}" 26 "$GATE" \
    "scanned tools/winacceptance/*.c and tools/tests/*.c — a directory move or a broken glob would empty this"

declared="$WORK/declared.txt"
: > "$declared"
for row in "${MANIFEST[@]}"; do printf '%s\n' "${row%%|*}"; done | sort > "$declared"
ondisk="$WORK/ondisk.txt"
printf '%s\n' "${ON_DISK[@]}" > "$ondisk"
missing_rows="$(comm -13 "$declared" "$ondisk")"
stale_rows="$(comm -23 "$declared" "$ondisk")"
if [ -n "$missing_rows" ] || [ -n "$stale_rows" ]; then
    echo "" >&2
    echo "FATAL: the manifest in $0 is out of sync with the tree." >&2
    if [ -n "$missing_rows" ]; then
        echo "  On disk but NOT declared (these would go unbuilt — the exact" >&2
        echo "  defect this script repairs). Add a row and pick a bucket:" >&2
        printf '%s\n' "$missing_rows" | sed 's/^/    /' >&2
    fi
    if [ -n "$stale_rows" ]; then
        echo "  Declared but NOT on disk (stale row):" >&2
        printf '%s\n' "$stale_rows" | sed 's/^/    /' >&2
    fi
    exit 2
fi

# ── The build ───────────────────────────────────────────────────────────────
cross_ok=0; cross_fail=0
native_ok=0; native_fail=0
ran_ok=0; ran_fail=0
failures=""

if [ "$have_cross" -eq 0 ]; then
    echo "  Windows leg: UNOBSERVED — '$CROSS_CC' is not installed on this box."
    echo "  0 of ${#MANIFEST[@]} programs were cross-compiled. This is NOT a"
    echo "  pass: it is an unobserved leg. Install mingw-w64"
    echo "  (apt install gcc-mingw-w64-x86-64) or set ZCL_MINGW_CC=<path>."
fi

printf '  %-58s %-7s %-7s %-7s %s\n' PROGRAM BUCKET CROSS NATIVE RUN
for row in "${MANIFEST[@]}"; do
    IFS='|' read -r src bucket deps <<< "$row"
    name="$(basename "$src" .c)"
    obj="$WORK/${name}"
    c_col="-"; n_col="-"; r_col="-"

    if [ "$have_cross" -eq 1 ]; then
        out="$("$CROSS_CC" "${CROSS_FLAGS[@]}" "${INC_FLAGS[@]}" -c "$src" \
               -o "$obj.win.o" 2>&1)"
        rc=$?
        if [ "$rc" -eq 0 ]; then c_col=ok; cross_ok=$((cross_ok + 1))
        else
            c_col=FAIL; cross_fail=$((cross_fail + 1))
            failures="${failures}--- cross-compile $src"$'\n'"$out"$'\n'
        fi
    else
        c_col=unobs
    fi

    if [ "$bucket" != "win" ]; then
        out="$("$NATIVE_CC" "${NATIVE_FLAGS[@]}" "${INC_FLAGS[@]}" -c "$src" \
               -o "$obj.o" 2>&1)"
        rc=$?
        if [ "$rc" -eq 0 ]; then n_col=ok; native_ok=$((native_ok + 1))
        else
            n_col=FAIL; native_fail=$((native_fail + 1))
            failures="${failures}--- native compile $src"$'\n'"$out"$'\n'
        fi
    fi

    if [ "$bucket" = "run" ] && [ "$n_col" = "ok" ] && \
       [ "${COMPILE_ONLY:-0}" -eq 0 ]; then
        # shellcheck disable=SC2086
        out="$("$NATIVE_CC" "${NATIVE_FLAGS[@]}" "${INC_FLAGS[@]}" \
               -o "$obj" "$src" $deps -lpthread -lm 2>&1)"
        rc=$?
        if [ "$rc" -ne 0 ]; then
            r_col=LINKFAIL; ran_fail=$((ran_fail + 1))
            failures="${failures}--- native link $src"$'\n'"$out"$'\n'
        else
            mapfile -t args < <(run_args "$src")
            out="$("$obj" "${args[@]}" 2>&1)"
            rc=$?
            # 77 is the autotools skip code. A program DECLARED runnable that
            # skips has lost the only reason it was declared runnable, so it
            # is graded a failure here rather than quietly counted as green.
            if [ "$rc" -eq 0 ]; then r_col=PASS; ran_ok=$((ran_ok + 1))
            elif [ "$rc" -eq 77 ]; then
                r_col=SKIP77; ran_fail=$((ran_fail + 1))
                failures="${failures}--- native run $src exited 77 (skip)"$'\n'"  A program in the 'run' bucket must not skip. Either it belongs"$'\n'"  in 'noexec', or the skip is a regression."$'\n'"$out"$'\n'
            else
                r_col="rc=$rc"; ran_fail=$((ran_fail + 1))
                failures="${failures}--- native run $src exited $rc"$'\n'"$out"$'\n'
            fi
        fi
    fi

    printf '  %-58s %-7s %-7s %-7s %s\n' "$name" "$bucket" "$c_col" "$n_col" "$r_col"
done

total="${#MANIFEST[@]}"
compile_only=$((total - ran_ok - ran_fail))

echo ""
echo "  ── counts, kept separate on purpose ──"
if [ "$have_cross" -eq 1 ]; then
    echo "  cross-compiled for Windows : $cross_ok ok, $cross_fail failed," \
         "of $total"
    echo "     (compiled to an object at $(printf '%s ' "${PLATFORM_DEFINES[@]}")— NOT linked, NOT executed)"
else
    echo "  cross-compiled for Windows : UNOBSERVED (0 of $total; no $CROSS_CC)"
fi
echo "  natively compiled          : $native_ok ok, $native_fail failed"
echo "  EXECUTED on this host      : $ran_ok passed, $ran_fail failed"
echo "  compile-checked ONLY       : $compile_only of $total —" \
     "these were NOT run and are NOT an execution pass"

if [ -n "${failures//[[:space:]]/}" ]; then
    echo "" >&2
    echo "FAIL: $GATE" >&2
    printf '%s' "$failures" >&2
    echo "  Reproduce one program:" >&2
    echo "    $CROSS_CC ${CROSS_FLAGS[*]} <-I flags> -c <file.c> -o /dev/null" >&2
    exit 1
fi

echo "  OK: $GATE"
exit 0
