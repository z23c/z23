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
#   linkblocked
#              Portable and genuinely meaningful on this host, but it cannot
#              be built as a FOCUSED binary: its call graph reaches the
#              node's consensus core and vendored crypto, so a standalone
#              link pulls 66+ translation units and still wants
#              secp256k1_context_create. Cross-compiled AND natively
#              compiled. NOT executed HERE — for a reason that is NOT
#              "it would falsely fail", so it is counted and reported
#              apart from `win`/`noexec` rather than quietly folded in
#              with them. The fix is to run it where the full graph
#              already exists (a test_parallel group), not to relax a
#              bucket.
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
#   --self-test    prove the gate actually trips: assert mingw really gates
#                  API surface on _WIN32_WINNT (a Windows 7 API is rejected
#                  at a planted 0x0600 target and accepted at the project's
#                  floor), assert the cross flags carry the Makefile's exact
#                  floor, and assert a planted failing `run` program — and a
#                  planted 77 skip — are both graded as failures.
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

  # ── Wave 2: the 29-commit macOS/Windows merge ───────────────────────────
  # --- win: <windows.h> unconditionally -----------------------------------
  "tools/winacceptance/codeindex_build_refusal_acceptance.c|win|"
  "tools/winacceptance/consensus_bundle_marker_acceptance.c|win|"
  "tools/winacceptance/mint_anchor_export_refusal_acceptance.c|win|"
  "tools/winacceptance/mint_anchor_preflight_refusal_acceptance.c|win|"
  "tools/winacceptance/rom_bundle_admission_refusal_acceptance.c|win|"
  "tools/winacceptance/snapshot_candidate_output_refusal_acceptance.c|win|"
  "tools/winacceptance/snapshot_export_refusal_acceptance.c|win|"
  "tools/winacceptance/snapshot_install_activate_refusal_acceptance.c|win|"
  "tools/winacceptance/stale_lock_capability_acceptance.c|win|"
  # --- win: no <windows.h>, but <io.h> and the _open/_read/_lseeki64 CRT,
  # which is just as Windows-only. Classified from reading the program, not
  # from the absence of a windows.h line.
  "tools/winacceptance/consensus_export_fd_io_refusal_acceptance.c|win|"
  "tools/winacceptance/positioned_io_acceptance.c|win|"

  # --- noexec: compiles for both, but executing it here proves nothing ----
  # Asserts consensus_export_seal_readonly()/descriptor_digest() REFUSE.
  # config/src/consensus_state_snapshot_export_fd_io.c gates that refusal
  # behind #if defined(_WIN32); on POSIX those functions do the real work,
  # so running this natively would be a FALSE failure.
  "tools/winacceptance/consensus_export_output_seal_refusal_acceptance.c|noexec|"
  # Asserts the error text contains "PE import validator" — a string
  # lib/hotswap/src/hotswap_elf_probe.c emits only on the Windows side of its
  # #if !defined(_WIN32) split. On Linux it probes a real ELF instead.
  "tools/winacceptance/hotswap_elf_probe_refusal_acceptance.c|noexec|"
  # boot_export_consensus_bundle() is documented TERMINAL — it never returns
  # (config/include/config/boot.h:708), so the trailing `return 3` is the
  # "it wrongly returned" path, not dead code. Correct as written. It is
  # noexec because on POSIX the call performs the REAL export and exits with
  # its own status, which says nothing about a Windows refusal.
  "tools/tests/test_boot_export_windows_refusal.c|noexec|"
  # Asserts result.reason contains "Windows consensus install refused".
  "tools/tests/test_consensus_install_windows_refusal.c|noexec|"

  # --- linkblocked: portable and meaningful, but not linkable standalone --
  "tools/tests/test_replay_receipt_root.c|linkblocked|"

  # --- run: portable, meaningful, and actually executed on this host ------
  "tools/winacceptance/log_level_acceptance.c|run|lib/base/src/log_level.c"
  "tools/tests/test_socket_resolve.c|run|"
  "tools/tests/test_private_link_no_clobber.c|run|lib/platform/src/private_file.c"
  "tools/tests/test_running_image_positioned.c|run|lib/platform/src/os_proc.c lib/platform/src/positioned_file.c"
  "tools/tests/test_boot_refusal_identity.c|run|config/src/boot_error.c config/src/boot_refusal_reports.c lib/platform/src/current_identity.c"
  "tools/tests/test_boot_shutdown_marker_persistence.c|run|config/src/boot_shutdown_marker.c lib/platform/src/clock.c lib/platform/src/file_metadata.c lib/platform/src/positioned_file.c lib/platform/src/private_directory.c lib/platform/src/private_file.c"
  "tools/tests/test_file_ops_copy.c|run|config/src/file_ops.c lib/platform/src/directory_compat.c lib/platform/src/positioned_file.c lib/platform/src/private_directory.c lib/platform/src/private_file.c lib/base/src/safe_alloc.c"

  # ── Wave 3: the 21-commit Windows/macOS merge ──────────────────────────
  # --- win: <windows.h> unconditionally, and its assertions ARE the
  # Windows-side refusal of os_binary_slots (on POSIX that seam does the real
  # directory/launch work), so this could only ever be a compile check here.
  "tools/winacceptance/os_binary_slots_refusal_acceptance.c|win|"

  # --- run: portable, meaningful, and actually executed on this host ------
  # No <windows.h> and no _WIN32 split anywhere: it drives rng_fill() through
  # the public seam and asserts properties that hold on EVERY arm — two
  # 64-byte draws are non-zero, they differ, a zero-length fill succeeds, and
  # a NULL/non-zero fill is REFUSED. On Linux that grades the real
  # getrandom(2) path, so executing it here is not a stand-in for the Windows
  # arm; it is the Linux arm being graded for real.
  "tools/winacceptance/rng_acceptance.c|run|lib/platform/src/rng.c"
)

# Arguments for the `run` programs that take them. Every path handed out here
# lives under this script's own mktemp WORK dir, never a datadir the node
# might be using: several of these programs CREATE and DELETE what they are
# pointed at, and one of them (test_file_ops_copy) calls dir_remove_tree() on
# argv[1]. A stray real path here would be a destructive test, so each gets a
# fresh private subdirectory made below.
run_args() {
    case "$1" in
        *test_read_mapping_positioned.c)
            printf '%s\n' "$WORK/positioned-fixture.bin" ;;
        *test_boot_shutdown_marker_persistence.c)
            printf '%s\n' "$WORK/run/shutdown-marker" ;;
        *test_file_ops_copy.c)
            printf '%s\n' "$WORK/run/file-ops" ;;
        *test_private_link_no_clobber.c)
            printf '%s\n%s\n' "$WORK/run/link-source.bin" \
                              "$WORK/run/link-target.bin" ;;
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

# The API floor itself, pulled out of those defines. It is the one number in
# the flag set whose absence would be INVISIBLE: without -D_WIN32_WINNT the
# cross leg still compiles everything, at mingw's own permissive default,
# and prints the same green — grading an easier question than the build asks
# while looking identical. So a missing floor is FATAL here, and the value is
# carried into the self-test so its probes track the Makefile instead of a
# number copied into this script that goes stale the day the floor moves
# (it already did: 0x0600 -> 0x0A00).
WINNT_FLOOR=""
for d in "${PLATFORM_DEFINES[@]}"; do
    case "$d" in -D_WIN32_WINNT=*) WINNT_FLOOR="${d#-D_WIN32_WINNT=}" ;; esac
done
if [ -z "$WINNT_FLOOR" ]; then
    echo "  $GATE: FATAL — ZCL_PLATFORM_CPPFLAGS no longer defines" >&2
    echo "      _WIN32_WINNT. Cross-compiling would fall back to mingw's" >&2
    echo "      default target and grade an easier question than the build" >&2
    echo "      asks, with no visible difference in this script's output." >&2
    exit 2
fi

# ── Include search path ─────────────────────────────────────────────────────
# Superset by construction, same reasoning check_windows_platform_seam.sh
# records: headers are namespaced per module, so an extra -I can only add a
# search path, never collide.
#
# The PRIVATE-header roots are DERIVED, not listed. Several acceptance
# programs include a module's internal header by bare name --
# package_lifecycle_internal.h, codeindex_priv.h,
# consensus_state_snapshot_export_internal.h,
# consensus_state_snapshot_install_internal.h -- and those live beside the
# .c files, with no include/ root. Hardcoding their directories would go
# stale the next time upstream adds a program that reaches into a different
# module, and the failure would look like a compile error in the program
# rather than a missing -I here. So instead: read the bare-name includes out
# of the acceptance programs themselves, find where each header actually
# lives outside any include/ tree, and add that directory. A new private
# header is picked up on the commit that introduces it.
mapfile -t PRIVATE_HDRS < <(
    LC_ALL=C grep -ho '^#include "[A-Za-z0-9_]*\.h"' \
        tools/winacceptance/*.c tools/tests/*.c 2>/dev/null \
    | sed 's/.*"\(.*\)"/\1/' | sort -u )
PRIVATE_DIRS=()
for h in ${PRIVATE_HDRS+"${PRIVATE_HDRS[@]}"}; do
    mapfile -t hits < <(find lib app config core domain -maxdepth 3 -name "$h" \
        -not -path '*/include/*' 2>/dev/null)
    for hit in ${hits+"${hits[@]}"}; do PRIVATE_DIRS+=("$(dirname "$hit")"); done
done
mapfile -t INC_DIRS < <(
    { find lib app core domain -maxdepth 2 -type d -name include 2>/dev/null
      for d in config/include ports/include application/include \
               adapters/include vendor/include vendor/x11/include \
               lib/test/include; do
          [ -d "$d" ] && printf '%s\n' "$d"
      done
      for d in ${PRIVATE_DIRS+"${PRIVATE_DIRS[@]}"}; do printf '%s\n' "$d"; done
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
mkdir -p "$WORK/run"

have_cross=1
command -v "$CROSS_CC" >/dev/null 2>&1 || have_cross=0

# ── Self-test: prove this script actually trips ─────────────────────────────
if [ "${1:-}" = "--self-test" ]; then
    st_fail=0
    if [ "$have_cross" -eq 0 ]; then
        echo "  $GATE --self-test: UNOBSERVED — '$CROSS_CC' is not installed;" \
             "cannot prove the cross leg trips without the compiler it uses."
    else
        # Two things have to be true for the cross leg to be worth anything,
        # and each is proved separately.
        #
        # (1) mingw's version gating is REAL in this toolchain: an API the
        #     SDK declares only above a given target must be REJECTED when
        #     compiled at a target below it. GetActiveProcessorCount and
        #     ALL_PROCESSOR_GROUPS appear only at _WIN32_WINNT >= 0x0601, so
        #     the probe is compiled at an explicitly LOWERED 0x0600 and must
        #     fail, then at the project's own floor and must succeed.
        #
        #     This used to be a single probe compiled at CROSS_FLAGS, on the
        #     standing assumption that the project floor was 0x0600. Upstream
        #     raised it to Windows 10 (0x0A00) and the probe silently became
        #     an assertion that the highest target rejects a Windows 7 API,
        #     which is false — the gate went red for the right reason. There
        #     is no API above 0x0A00 to substitute, so the gating check is
        #     pinned to a target this script chooses, and the separate
        #     question "is the BUILD's floor what actually reaches the
        #     compiler" is asked directly in (2) instead of being inferred.
        cat > "$WORK/above_floor.c" <<'PROBE'
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
/* GetActiveProcessorCount/ALL_PROCESSOR_GROUPS are declared by mingw only at
 * _WIN32_WINNT >= 0x0601. */
int zcl_probe(void) { return (int)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS); }
PROBE
        "$CROSS_CC" "${CROSS_FLAGS[@]}" "${INC_FLAGS[@]}" \
            -U_WIN32_WINNT -D_WIN32_WINNT=0x0600 \
            -c "$WORK/above_floor.c" -o "$WORK/above_floor.o" >/dev/null 2>&1
        rc=$?
        if [ "$rc" -eq 0 ]; then
            echo "FAIL: --self-test — mingw ACCEPTED a Windows 7 API while" >&2
            echo "  compiling at _WIN32_WINNT=0x0600. This toolchain is not" >&2
            echo "  gating API surface on the target at all, so compiling" >&2
            echo "  the acceptance programs at the build's floor proves" >&2
            echo "  nothing about what the build's target actually offers." >&2
            st_fail=1
        fi
        "$CROSS_CC" "${CROSS_FLAGS[@]}" "${INC_FLAGS[@]}" \
            -c "$WORK/above_floor.c" -o "$WORK/above_floor.o" >/dev/null 2>&1
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "FAIL: --self-test — mingw REJECTED a Windows 7 API at the" >&2
            echo "  project's own floor ($WINNT_FLOOR). The floor read from" >&2
            echo "  the Makefile is below what the product's own sources" >&2
            echo "  require; every cross compile below is grading a target" >&2
            echo "  the build does not ship." >&2
            st_fail=1
        fi

        # (2) EVERY -D the Makefile hands the Windows build actually reaches
        #     the compiler, with the Makefile's value. Asserted inside the
        #     TU, from PLATFORM_DEFINES, so a dropped flag fails here rather
        #     than somewhere downstream as a confusing error in a program.
        #
        #     Asserting only _WIN32_WINNT would NOT do it, and this was
        #     measured rather than assumed: mingw-w64 GCC 13 defaults
        #     _WIN32_WINNT to 0x0A00, which is now exactly the project floor,
        #     so an equality check on the floor alone passes identically
        #     whether the flag arrived or the default coincided — deleting
        #     the whole -D set from CROSS_FLAGS still went green. The other
        #     defines (WIN32_LEAN_AND_MEAN, __USE_MINGW_ANSI_STDIO) have no
        #     such default, so checking the set is what makes the probe
        #     sensitive to the flags actually being passed.
        {
            printf '/* generated by --self-test; see winacceptance.sh */\n'
            for d in "${PLATFORM_DEFINES[@]}"; do
                body="${d#-D}"
                nm="${body%%=*}"
                printf '#if !defined(%s)\n#error "%s never reached the compiler"\n#endif\n' \
                       "$nm" "$nm"
                case "$body" in
                    *=*)
                        val="${body#*=}"
                        # Only an integer constant expression can be compared
                        # in #if. A non-numeric value still gets the
                        # defined-ness assertion above rather than a probe
                        # that would fail to compile for the wrong reason.
                        case "$val" in
                            *[!0-9xXa-fA-F]*) : ;;
                            *) printf '#if (%s) != (%s)\n#error "%s is not the Makefile value"\n#endif\n' \
                                      "$nm" "$val" "$nm" ;;
                        esac ;;
                    *) : ;;
                esac
            done
            printf 'int zcl_flags(void);\nint zcl_flags(void) { return 0; }\n'
        } > "$WORK/flags_are_builds.c"
        "$CROSS_CC" "${CROSS_FLAGS[@]}" "${INC_FLAGS[@]}" \
            -c "$WORK/flags_are_builds.c" -o "$WORK/flags_are_builds.o" \
            2>"$WORK/flags_are_builds.err"
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "FAIL: --self-test — the cross flags do NOT carry the" >&2
            echo "  Makefile's ZCL_PLATFORM_CPPFLAGS set" >&2
            echo "  (${PLATFORM_DEFINES[*]}) to the compiler. Every cross" >&2
            echo "  compile below would grade a different API target than" >&2
            echo "  the build ships." >&2
            sed 's/^/    /' "$WORK/flags_are_builds.err" >&2
            st_fail=1
        fi
        # The negated form of (2). An #error that can never fire would make
        # the probe above a tautology that passes on an empty flag set.
        cat > "$WORK/floor_negated.c" <<PROBE
#if _WIN32_WINNT == $WINNT_FLOOR
#error "expected: the flag assertion machinery can fire"
#endif
int zcl_neg(void);
int zcl_neg(void) { return 0; }
PROBE
        "$CROSS_CC" "${CROSS_FLAGS[@]}" "${INC_FLAGS[@]}" \
            -c "$WORK/floor_negated.c" -o "$WORK/floor_negated.o" \
            >/dev/null 2>&1
        rc=$?
        if [ "$rc" -eq 0 ]; then
            echo "FAIL: --self-test — a TU whose #error fires on the" >&2
            echo "  Makefile's floor ($WINNT_FLOOR) still compiled. The" >&2
            echo "  flag assertion above is hollow." >&2
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
    echo "  OK: --self-test — mingw gates API surface on the target" \
         "(a Windows 7 API is rejected at 0x0600, accepted at the project" \
         "floor $WINNT_FLOOR), the cross flags carry the Makefile's whole" \
         "-D set (${PLATFORM_DEFINES[*]}) with its exact values, and a" \
         "failing run and a 77 skip are both graded as failures"
    exit 0
fi

# ── Manifest / tree reconciliation ──────────────────────────────────────────
# A program on disk with no manifest row would go unbuilt — the exact defect
# being repaired — so it is a FATAL desync, not a warning.
mapfile -t ON_DISK < <(
    find tools/winacceptance tools/tests -maxdepth 1 -name '*.c' -type f \
        2>/dev/null | sort )
gate_require_scanned "${#ON_DISK[@]}" 49 "$GATE" \
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
linkblocked=0
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

    if [ "$bucket" = "linkblocked" ]; then
        r_col=nolink; linkblocked=$((linkblocked + 1))
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
if [ "$linkblocked" -gt 0 ]; then
    echo "     of which $linkblocked are 'linkblocked': portable and"
    echo "     meaningful here, but NOT linkable as a focused binary — they"
    echo "     need the node's full link graph. Counted apart from the"
    echo "     Windows-only ones so the reason is never guessed."
fi

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
