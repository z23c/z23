#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_windows_cross_syntax.sh — syntax-only mingw sweep of every .c file
# under every production/dev source root whose text contains _WIN32.
#
# WHY THIS EXISTS
# gcc and clang on this box never take the _WIN32 branch, so a Windows-only
# syntax error or a bad #include sits undetected until a Windows machine hits
# it. make windows-acceptance-compile cross-links the catalogued acceptance
# programs; it does not read every other _WIN32 translation unit. This gate
# closes that gap with x86_64-w64-mingw32-gcc -std=c2x -fsyntax-only. It does
# not link, does not produce objects, and is not a substitute for the native
# UCRT64 build.
#
# File set is SELF-MAINTAINING: a file that gains Windows code joins the gate
# the day the token _WIN32 appears. This includes the public node entry points
# under src/ and release-visible command adapters under tools/command/;
# omitting those roots previously left current release TUs outside every
# Windows compile gate. Standalone and dev-only tools keep their own build
# targets rather than being misgraded as node translation units here.
#
# SKIP contract: when mingw is absent, print SKIP and exit 0. An outside
# contributor is never blocked by a cross-compiler they do not have. SKIP is
# not a pass.
#
# Generated / tools headers (command/native_command.h and
# command/native_dev_hotswap.h) live under tools/ and are found via -Itools,
# the same TOOLS_INCLUDES the node build uses. If they are still missing, a
# file whose ONLY errors are those header names is skipped — detected by the
# HEADER name, never by the source-file name.
#
# vendor/include/openssl is produced by the vendor build. When those headers
# are absent, a file whose ONLY errors are missing openssl/*.h is skipped
# the same way: that is an unbuilt vendor tree, not a Windows syntax bug.
# When openssl headers ARE present, those files are graded for real.
#
# Usage:
#   tools/lint/check_windows_cross_syntax.sh             # the gate
#   tools/lint/check_windows_cross_syntax.sh --self-test # prove it can go red
#
# PER-TU RESULT CACHE: the sweep runs through tools/lint/tu_result_cache.sh,
# which stores each translation unit's exit status and byte-exact compiler
# log under .cache/lint-tu/ and replays them when nothing that TU can see
# has changed. The classifiers below are unaware of it: a replay writes the
# same bytes into the same files a fresh mingw run would have. Measured on
# the dev reference host, script wall over 233 TUs: 4.2 s uncached, 0.6 s
# fully warm, 0.9 s after editing one .c (232 hit, 1 miss).
# ZCL_LINT_TU_CACHE=0 turns it off; run_lint.sh --cold-audit turns it off
# for you. See that file's header for why the key is sound.
#
# Env:
#   ZCL_MINGW_CC   compiler (default: x86_64-w64-mingw32-gcc)
#   ZCL_CC_JOBS    parallel workers (default: nproc, capped at 32)
#   ZCL_LINT_TU_CACHE=0  bypass the per-TU result cache (default: on)
#   ZCL_REQUIRE_MINGW=1  missing compiler is a hard acceptance failure
#
# Exit: 0 clean or SKIP; 1 on a new (non-baselined, non-skippable) failure
# or a stale baseline row; 2 on a hollow/misconfigured scan.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/tu_result_cache.sh
. tools/lint/tu_result_cache.sh

GATE="check-windows-cross-syntax"
CC_BIN="${ZCL_MINGW_CC:-x86_64-w64-mingw32-gcc}"
BASELINE="tools/lint/windows_cross_syntax_baseline.txt"
SRC_FLOOR=150
INC_FLOOR=50
SCAN_ROOTS=(core engine contexts cognition platform tools/command)
TEST_COMPAT_HEADER="test/windows_compat.h"

echo "══ LINT: Windows cross-syntax (mingw -fsyntax-only over every _WIN32 TU) ══"

# ── SKIP contract ──────────────────────────────────────────────────────────
if [ "${1:-}" != "--self-test" ] && ! command -v "$CC_BIN" >/dev/null 2>&1; then
    if [ "${ZCL_REQUIRE_MINGW:-0}" = 1 ]; then
        echo "  $GATE: FAIL — required compiler '$CC_BIN' is unavailable;" >&2
        echo "  acceptance cannot succeed after compiling zero files." >&2
        exit 2
    fi
    echo "  $GATE: SKIP — '$CC_BIN' is not installed on this box."
    echo "  0 files were compiled. This is not a pass: it is an unobserved"
    echo "  leg. Install mingw-w64 (apt install gcc-mingw-w64-x86-64) or set"
    echo "  ZCL_MINGW_CC=<path> to actually run this gate."
    exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-wincross-syntax.XXXXXX")" || {
    echo "$GATE: FATAL — mktemp failed." >&2
    exit 2
}
trap 'rm -rf "$WORK"' EXIT

# ── awk programs live in files: an apostrophe inside awk '...' swallows
#    the rest of this script. ──────────────────────────────────────────────
cat > "$WORK/api_floor.awk" <<'END_AWK'
/^ZCL_WINDOWS_API_FLOOR[ \t]*:?=/ { print; exit }
END_AWK

cat > "$WORK/platform_cppflags.awk" <<'END_AWK'
/^ZCL_PLATFORM_CPPFLAGS[ \t]*=/ { inblock = 1 }
inblock {
    print
    if ($0 !~ /\\$/) exit
}
END_AWK

# Classify one compiler log. Prints one word:
#   CLEAN            no error/fatal lines
#   SKIP_GENERATED   every error is a missing command/native_*.h
#   SKIP_OPENSSL     every error is a missing openssl/*.h
#   SKIP_HEADERS     mix of those two missing-header classes, nothing else
#   COMPILER_FAILURE driver/backend failure, not a source-located diagnostic
#   ERROR            any other diagnostic
cat > "$WORK/classify.awk" <<'END_AWK'
BEGIN {
    errors = 0
    gen = 0
    ossl = 0
    other = 0
    driver = 0
}
{
    line = $0
    lower = tolower(line)
    if (index(lower, "internal compiler error") > 0 ||
        index(lower, "cannot execute") > 0 ||
        index(lower, "createprocess") > 0 ||
        index(lower, "unable to execute command") > 0 ||
        index(lower, "frontend command failed") > 0 ||
        index(lower, "please submit a bug report") > 0 ||
        index(lower, "segmentation fault") > 0 ||
        index(lower, "stack dump") > 0 ||
        index(lower, "out of memory") > 0 ||
        index(lower, "killed signal") > 0 ||
        index(lower, "error in backend") > 0 ||
        index(lower, "llvm error") > 0 ||
        index(lower, "access violation") > 0 ||
        index(lower, "cc1.exe:") > 0)
        driver++
    is_fatal = 0
    is_error = 0
    if (index(line, ": fatal error: ") > 0) is_fatal = 1
    if (is_fatal == 0 && index(line, ": error: ") > 0) is_error = 1
    if (is_fatal == 0 && is_error == 0) next
    errors++
    # A source rejection is located as path:line[:column]: diagnostic. GCC
    # driver failures use the same words (`gcc: fatal error:`), but have no
    # source location and must never be absorbable by a per-source baseline.
    marker = is_fatal ? ": fatal error: " : ": error: "
    marker_at = index(line, marker)
    prefix = substr(line, 1, marker_at - 1)
    if (prefix !~ /:[0-9]+(:[0-9]+)?$/ ||
        driver > 0) {
        driver++
        next
    }
    if (is_fatal) {
        rest = line
        p = index(rest, "fatal error: ")
        rest = substr(rest, p + 13)
        ns = index(rest, ": No such file or directory")
        if (ns > 0) {
            hdr = substr(rest, 1, ns - 1)
            if (hdr == "command/native_command.h") { gen++; next }
            if (hdr == "command/native_dev_hotswap.h") { gen++; next }
            if (index(hdr, "openssl/") == 1) { ossl++; next }
        }
    }
    other++
}
END {
    if (driver > 0) { print "COMPILER_FAILURE"; exit 0 }
    if (errors == 0) { print "CLEAN"; exit 0 }
    if (other > 0) { print "ERROR"; exit 0 }
    if (gen == errors) { print "SKIP_GENERATED"; exit 0 }
    if (ossl == errors) { print "SKIP_OPENSSL"; exit 0 }
    print "SKIP_HEADERS"
}
END_AWK

# ── Windows API floor: read from the Makefile, never copied here. Compiling
#    at mingw's permissive default grades a different (easier) Windows than
#    the product ships. ────────────────────────────────────────────────────
mapfile -t API_FLOOR_DEFINES < <(
    awk -f "$WORK/api_floor.awk" Makefile |
        tr ' \t' '\n\n' | LC_ALL=C grep '^-D_WIN32_WINNT=' || true)
if [ "${#API_FLOOR_DEFINES[@]}" -ne 1 ]; then
    echo "  $GATE: FAIL — expected exactly one _WIN32_WINNT floor in the" >&2
    echo "      Makefile; refusing to compile against mingw's default." >&2
    exit 1
fi

platform_assignment="$(awk -f "$WORK/platform_cppflags.awk" Makefile)"
case "$platform_assignment" in
    *ZCL_WINDOWS_API_FLOOR*) ;;
    *)
        echo "  $GATE: FAIL — ZCL_PLATFORM_CPPFLAGS does not reference" >&2
        echo "      ZCL_WINDOWS_API_FLOOR; the product and gate can drift." >&2
        exit 1
        ;;
esac
mapfile -t PLATFORM_DEFINES < <(
    printf '%s\n' "$platform_assignment" |
        tr ' \t\\' '\n\n\n' | LC_ALL=C grep '^-D' || true)
if [ "${#PLATFORM_DEFINES[@]}" -eq 0 ]; then
    echo "  $GATE: FAIL — could not read ZCL_PLATFORM_CPPFLAGS from the" >&2
    echo "      Makefile. Refusing to cross-compile at a guessed API floor." >&2
    exit 1
fi

# Production files must be graded under the production preprocessor profile.
# Test-only declarations and the native Windows compatibility header are added
# per test translation unit in the worker below; applying ZCL_TESTING globally
# can hide a broken #ifndef ZCL_TESTING production arm.
COMPILE_FLAGS=(-std=c2x -fsyntax-only
               "${API_FLOOR_DEFINES[@]}" "${PLATFORM_DEFINES[@]}")

compile_result_kind() {
    local log=$1 rc=$2 raw
    raw="$(awk -f "$WORK/classify.awk" "$log")"
    case "$rc" in
        0)
            if [ "$raw" = CLEAN ]; then
                printf '%s' CLEAN
            else
                printf '%s' INCONSISTENT_SUCCESS
            fi
            ;;
        ''|*[!0-9]*) printf '%s' MISSING_RESULT ;;
        *)
            if [ "$raw" = CLEAN ]; then
                # Backend crashes, loader/DLL failures, OOM, and process-spawn
                # failures often have no GCC-style `: error:` diagnostic.
                # A nonzero compiler status is never a clean translation unit.
                printf '%s' COMPILER_FAILURE
            else
                printf '%s' "$raw"
            fi
            ;;
    esac
}

# The native Windows test profile force-includes one test-only compatibility
# header. Grade lib/test translation units under that same contract; applying
# it to production sources would hide a real platform-seam defect. Keep the
# header spelling tied to the Makefile assignment instead of inventing a
# second compatibility layer here.
test_compat_assignment="$(awk '/^ZCL_TEST_WINDOWS_COMPAT_FLAGS[ \t]*=/ {print; exit}' Makefile)"
case "$test_compat_assignment" in
    *'-include test/windows_compat.h'*) ;;
    *)
        echo "  $GATE: FAIL — could not bind the Windows test compatibility" >&2
        echo "      include to ZCL_TEST_WINDOWS_COMPAT_FLAGS in Makefile." >&2
        exit 1
        ;;
esac
[ -f "tests/harness/include/$TEST_COMPAT_HEADER" ] || {
    echo "  $GATE: FAIL — missing tests/harness/include/$TEST_COMPAT_HEADER." >&2
    exit 1
}

# ── Include search path ───────────────────────────────────────────────────
# Proven recipe: every source-tree directory named include, excluding build,
# test output, agent scratch, and vendor/tor, each as -I<dir>, plus -I. A
# hand-picked subset misses headers such as core/hash.h, sqlite3.h, and
# config/runtime.h.
INC_NUL="$WORK/inc.nul"
: > "$INC_NUL"
printf '%s\0' -I. >> "$INC_NUL"
# TOOLS_INCLUDES: command/native_command.h lives at tools/command/, not
# under a directory named include. Same -Itools the node build uses.
printf '%s\0' -Itools -Itools/dev >> "$INC_NUL"
find . \( -path './.git' -o -path './.git/*' \
          -o -path './build' -o -path './build/*' \
          -o -path './test-tmp' -o -path './test-tmp/*' \
          -o -path './.claude' -o -path './.claude/*' \
          -o -path './vendor/tor' -o -path './vendor/tor/*' \) -prune \
     -o -type d -name include -print0 2>/dev/null |
    while IFS= read -r -d '' d; do
        printf '%s\0' "-I$d"
    done >> "$INC_NUL"

# Private headers sit next to their .c files (codeindex_priv.h,
# *_internal.h). The Windows-acceptance catalog already passes those as
# extra -I per row; this sweep does the self-maintaining equivalent: every
# src/ directory that holds a .h.
existing_roots=()
for d in "${SCAN_ROOTS[@]}" tools; do
    [ -d "$d" ] && existing_roots+=("$d")
done
if [ "${#existing_roots[@]}" -gt 0 ]; then
    find "${existing_roots[@]}" -type d -name src -print0 2>/dev/null |
        while IFS= read -r -d '' d; do
            has_h=
            for h in "$d"/*.h; do
                if [ -f "$h" ]; then
                    has_h=1
                    break
                fi
            done
            if [ -n "$has_h" ]; then
                printf '%s\0' "-I$d"
            fi
        done >> "$INC_NUL" || true
fi

INC_COUNT="$(tr -cd '\0' < "$INC_NUL" | wc -c)"
gate_require_scanned "$INC_COUNT" "$INC_FLOOR" "$GATE" \
    "no include/ roots found — the layout moved or find was pruned too hard"

mapfile -t -d '' INC_FLAGS < "$INC_NUL"
if [ "${#INC_FLAGS[@]}" -gt 0 ]; then
    last=$((${#INC_FLAGS[@]} - 1))
    if [ -z "${INC_FLAGS[$last]}" ]; then
        unset "INC_FLAGS[$last]"
    fi
fi

printf '%s\0' "${COMPILE_FLAGS[@]}" "${INC_FLAGS[@]}" > "$WORK/flags.nul"

# ── Self-test: prove the flag set actually rejects a Windows-only error ──
if [ "${1:-}" = "--self-test" ]; then
    if ! command -v "$CC_BIN" >/dev/null 2>&1; then
        if [ "${ZCL_REQUIRE_MINGW:-0}" = 1 ]; then
            echo "  $GATE --self-test: FAIL — required compiler '$CC_BIN'" \
                 "is unavailable." >&2
            exit 2
        fi
        echo "  $GATE --self-test: SKIP — '$CC_BIN' is not installed;" \
             "cannot prove the gate trips without the compiler it gates."
        exit 0
    fi
    violating="$WORK/violating.c"
    cat > "$violating" <<'PROBE'
#if defined(_WIN32)
int zcl_gate_wincross_probe(void) { return this_identifier_does_not_exist; }
#else
int zcl_gate_wincross_probe(void) { return 0; }
#endif
PROBE
    mapfile -t -d '' flags < "$WORK/flags.nul"
    if [ "${#flags[@]}" -gt 0 ]; then
        last=$((${#flags[@]} - 1))
        if [ -z "${flags[$last]}" ]; then
            unset "flags[$last]"
        fi
    fi
    if "$CC_BIN" "${flags[@]}" "$violating" >/dev/null 2>&1; then
        echo "FAIL: --self-test — mingw ACCEPTED a TU with an undeclared"
        echo "  identifier inside #if defined(_WIN32). The gate is hollow:"
        echo "  it would report clean on a real Windows-only syntax error."
        exit 1
    fi
    clean="$WORK/clean.c"
    printf 'int zcl_gate_wincross_clean(int a);\nint zcl_gate_wincross_clean(int a) { return a + 1; }\n' > "$clean"
    if ! "$CC_BIN" "${flags[@]}" "$clean" >/dev/null 2>&1; then
        echo "FAIL: --self-test — mingw REJECTED a trivially clean TU."
        echo "  The gate would false-fail every contributor."
        exit 1
    fi
    compat="$WORK/test_compat.c"
    cat > "$compat" <<'PROBE'
#include <fcntl.h>
#include <sys/stat.h>
int zcl_gate_wincross_test_compat(void)
{
    zcl_win_suppress_abort_dialog();
    return mkdir("fixture", 0700) + O_CLOEXEC;
}
PROBE
    if ! "$CC_BIN" "${flags[@]}" -include test/windows_compat.h \
            "$compat" >/dev/null 2>&1; then
        echo "FAIL: --self-test — the native test-profile compatibility" \
             "header did not compile a representative POSIX-style test TU."
        exit 1
    fi
    fake_compiler="$WORK/fake-compiler"
    cat > "$fake_compiler" <<'PROBE'
#!/usr/bin/env bash
echo "gcc: fatal error: cannot execute 'cc1': CreateProcess: No such file or directory" >&2
exit 86
PROBE
    chmod +x "$fake_compiler"
    fake_log="$WORK/fake-compiler.log"
    set +e
    "$fake_compiler" "$clean" >"$fake_log" 2>&1
    fake_rc=$?
    set -e
    fake_kind="$(compile_result_kind "$fake_log" "$fake_rc")"
    if [ "$fake_kind" != COMPILER_FAILURE ]; then
        echo "FAIL: --self-test — a nonzero compiler with no conventional" \
             "source diagnostic was classified '$fake_kind', not an" \
             "infrastructure failure."
        exit 1
    fi
    mixed_log="$WORK/mixed-compiler.log"
    printf '%s\n' \
        'fixture.c:1:2: error: ordinary source rejection' \
        'cc1.exe: out of memory allocating 4096 bytes' > "$mixed_log"
    mixed_kind="$(compile_result_kind "$mixed_log" 1)"
    if [ "$mixed_kind" != COMPILER_FAILURE ]; then
        echo "FAIL: --self-test — a source diagnostic followed by a backend" \
             "crash was classified '$mixed_kind', not infrastructure failure."
        exit 1
    fi
    echo "  OK: --self-test — flag set trips on a Windows-only undeclared" \
         "identifier, passes clean and test-compat code, rejects a crashed" \
         "compiler backend"

    # The per-TU result cache, proven against this gate's real compiler and
    # real flag set. Everything above is hollow if a stale cached verdict
    # can be replayed, so the two are graded together.
    selftest_srcs="$WORK/selftest-srcs.txt"
    selftest_roots=()
    for d in "${SCAN_ROOTS[@]}"; do
        [ -d "$d" ] && selftest_roots+=("$d")
    done
    : > "$selftest_srcs"
    if [ "${#selftest_roots[@]}" -gt 0 ]; then
        find "${selftest_roots[@]}" -name '*.c' -type f -print0 2>/dev/null |
            xargs -0 -r grep -l '_WIN32' 2>/dev/null |
            LC_ALL=C sort > "$selftest_srcs" || true
    fi
    tu_cache_selftest "$GATE" "$SCRIPT_DIR/check_windows_cross_syntax.sh" \
        "$CC_BIN" "$WORK/flags.nul" "$WORK" "$(head -1 "$selftest_srcs")"
    exit 0
fi

# ── Source set: every .c under the scan roots whose text contains _WIN32 ─
present_roots=()
for d in "${SCAN_ROOTS[@]}"; do
    [ -d "$d" ] && present_roots+=("$d")
done
if [ "${#present_roots[@]}" -eq 0 ]; then
    echo "$GATE: FATAL — none of the scan roots exist." >&2
    exit 2
fi

SRC_LIST="$WORK/srcs.txt"
find "${present_roots[@]}" -name '*.c' -type f -print0 2>/dev/null |
    xargs -0 -r grep -l '_WIN32' 2>/dev/null |
    LC_ALL=C sort > "$SRC_LIST" || true
SRC_COUNT="$(grep -c . "$SRC_LIST" || true)"
[ -n "$SRC_COUNT" ] || SRC_COUNT=0
gate_require_scanned "$SRC_COUNT" "$SRC_FLOOR" "$GATE" \
    "scanned ${present_roots[*]} for .c files containing _WIN32 — a directory move would empty this"

# ── Parallel compile. Each TU writes its OWN log: concurrent writers
#    sharing one fd tear output once a diagnostic exceeds PIPE_BUF. ───────
JOBS="${ZCL_CC_JOBS:-$(nproc 2>/dev/null || echo 4)}"
case "$JOBS" in
    ''|*[!0-9]*) JOBS=4 ;;
esac
[ "$JOBS" -ge 1 ] || JOBS=4
[ "$JOBS" -le 32 ] || JOBS=32

OUT_DIR="$WORK/out"
mkdir -p "$OUT_DIR"

# Per-TU result cache. Its key covers this script, the helper, the compiler
# identity, the flag list, the whole include set and the TU's own bytes, so
# a hit replays the exact rc and log a fresh mingw run would have written
# and every classifier below this line is unaware it happened.
tu_cache_setup "$GATE" "$SCRIPT_DIR/check_windows_cross_syntax.sh" \
    "$CC_BIN" "$WORK/flags.nul" "$WORK"


# Where this gate's worker puts a TU's two artifacts. tu_cache_plan replays
# a hit into exactly these paths, which is why nothing below changed. The
# out-dir mirrors the source tree, so its directories are created once here
# rather than by a `mkdir` fork inside every replay.
tu_cache_paths_for() {
    TU_LOG="$OUT_DIR/$1.log"
    TU_RC="$OUT_DIR/$1.rc"
}
sed 's|/[^/]*$||' "$SRC_LIST" | LC_ALL=C sort -u | sed "s|^|$OUT_DIR/|" |
    tr '\n' '\0' | xargs -0 -r mkdir -p

# One parent pass replays every cached TU and leaves only the ones that
# still need a compiler, so a fully warm run forks no workers at all.
MISS_LIST="$WORK/misses.txt"
tu_cache_plan "$SRC_LIST" "$MISS_LIST"
cat > "$WORK/compile_one.sh" <<'END_WORKER'
#!/usr/bin/env bash
set -uo pipefail
. "$ZCL_TU_CACHE_LIB"
src=$1
log=$ZCL_GATE_OUT/${src}.log
rcf=$ZCL_GATE_OUT/${src}.rc
mkdir -p "${log%/*}"
mapfile -t -d '' flags < "$ZCL_GATE_FLAGS"
if [ ${#flags[@]} -gt 0 ]; then
    last=$((${#flags[@]} - 1))
    if [ -z "${flags[$last]}" ]; then
        unset "flags[$last]"
    fi
fi
# Match the native test profiles without polluting production translation
# units. The test-fast corpus receives both test declarations and the
# force-included compatibility header; standalone platform acceptance sources
# receive test declarations only.
case "$src" in
    tests/harness/include/test/*) flags+=(-DZCL_TESTING -include "$ZCL_GATE_TEST_COMPAT_HEADER") ;;
    */tests/*.c) flags+=(-DZCL_TESTING) ;;
esac
tu_cache_run "$log" "$rcf" "$ZCL_GATE_CC" "${flags[@]}" "$src"
exit 0
END_WORKER
chmod +x "$WORK/compile_one.sh"

# Always exit 0 from the worker so a failing compile cannot short-circuit
# xargs into a hollow pass over the remaining files.
tr '\n' '\0' < "$MISS_LIST" |
    env ZCL_GATE_FLAGS="$WORK/flags.nul" ZCL_GATE_CC="$CC_BIN" ZCL_GATE_OUT="$OUT_DIR" \
        ZCL_GATE_TEST_COMPAT_HEADER="$TEST_COMPAT_HEADER" \
        xargs -0 -r -P "$JOBS" -n 1 "$WORK/compile_one.sh" || true

tu_cache_summary

LOG_COUNT="$(find "$OUT_DIR" -name '*.log' -type f | grep -c . || true)"
[ -n "$LOG_COUNT" ] || LOG_COUNT=0
gate_require_scanned "$LOG_COUNT" "$SRC_COUNT" "$GATE" \
    "only $LOG_COUNT of $SRC_COUNT translation units produced a compiler log"

# ── Classify each TU ──────────────────────────────────────────────────────
OPENSSL_ABSENT=1
if [ -f vendor/include/openssl/ssl.h ]; then
    OPENSSL_ABSENT=0
fi

if [ ! -f "$BASELINE" ]; then
    echo "$GATE: FATAL — baseline '$BASELINE' is missing." >&2
    echo "  Refusing to report clean with nothing to ratchet against." >&2
    exit 2
fi

declare -A BASE=()
gate_load_list_file "$BASELINE" BASE

NEW_FAIL="$WORK/new_fail.txt"
STILL="$WORK/still.txt"
SKIP_GEN_LIST="$WORK/skip_gen.txt"
SKIP_OSSL_LIST="$WORK/skip_ossl.txt"
CLEAN_LIST="$WORK/clean.txt"
INFRA_LIST="$WORK/infra.txt"
: > "$NEW_FAIL"
: > "$STILL"
: > "$SKIP_GEN_LIST"
: > "$SKIP_OSSL_LIST"
: > "$CLEAN_LIST"
: > "$INFRA_LIST"

# One iteration per translation unit, so every fork here is paid 233 times
# in sequence. The status is read with `read` rather than `cat`, and the
# common case — the compiler exited 0 having written NOTHING — is answered
# without forking awk: classify.awk over a zero-byte log counts no errors
# and no driver failures, so it prints CLEAN, and compile_result_kind maps
# (rc 0, CLEAN) to CLEAN. Any log with content at all still goes through the
# real classifier.
while IFS= read -r src; do
    [ -n "$src" ] || continue
    log="$OUT_DIR/${src}.log"
    rcf="$OUT_DIR/${src}.rc"
    rc=missing
    read -r rc < "$rcf" 2>/dev/null || rc=missing
    [ -n "$rc" ] || rc=missing
    if [ "$rc" = 0 ] && [ ! -s "$log" ]; then
        echo "$src" >> "$CLEAN_LIST"
        continue
    fi
    kind="$(compile_result_kind "$log" "$rc")"
    case "$kind" in
        CLEAN)
            echo "$src" >> "$CLEAN_LIST"
            continue
            ;;
        SKIP_GENERATED)
            echo "$src" >> "$SKIP_GEN_LIST"
            continue
            ;;
        SKIP_OPENSSL|SKIP_HEADERS)
            if [ "$OPENSSL_ABSENT" = 1 ]; then
                echo "$src" >> "$SKIP_OSSL_LIST"
                continue
            fi
            ;;
        COMPILER_FAILURE|MISSING_RESULT|INCONSISTENT_SUCCESS)
            printf '%s|%s|%s\n' "$src" "$rc" "$kind" >> "$INFRA_LIST"
            continue
            ;;
    esac
    # Compiler error that is not a skippable missing header.
    if [ -n "${BASE[$src]:-}" ]; then
        echo "$src" >> "$STILL"
    else
        echo "$src" >> "$NEW_FAIL"
    fi
done < "$SRC_LIST"

# Stale baseline: a listed file now compiles clean (or is only a skippable
# missing header). Shrink-only — delete the row.
declare -A STILL_SET=()
while IFS= read -r row; do
    [ -n "$row" ] || continue
    STILL_SET["$row"]=1
done < "$STILL"
# An infrastructure failure proves nothing about whether a baseline row is
# stale. Keep that row out of the shrink decision until a compiler completes.
while IFS='|' read -r row _; do
    [ -n "$row" ] || continue
    STILL_SET["$row"]=1
done < "$INFRA_LIST"
STALE="$WORK/stale.txt"
: > "$STALE"
for k in "${!BASE[@]}"; do
    if [ -z "${STILL_SET[$k]:-}" ]; then
        echo "$k" >> "$STALE"
    fi
done

count_lines() {
    local n
    n="$(grep -c . "$1" || true)"
    [ -n "$n" ] || n=0
    printf '%s' "$n"
}
new_count="$(count_lines "$NEW_FAIL")"
stale_count="$(count_lines "$STALE")"
still_count="$(count_lines "$STILL")"
skip_gen_count="$(count_lines "$SKIP_GEN_LIST")"
skip_ossl_count="$(count_lines "$SKIP_OSSL_LIST")"
clean_count="$(count_lines "$CLEAN_LIST")"
infra_count="$(count_lines "$INFRA_LIST")"

rc=0

if [ "$infra_count" -gt 0 ]; then
    rc=2
    echo "$GATE: UNPROVEN — $infra_count compiler infrastructure failure(s);" \
         "no affected translation unit is counted clean:" >&2
    while IFS='|' read -r src compiler_rc kind; do
        [ -n "$src" ] || continue
        echo "  $src (compiler rc=$compiler_rc, result=$kind)" >&2
        if [ -s "$OUT_DIR/${src}.log" ]; then
            sed -n '1,80p' "$OUT_DIR/${src}.log" | sed 's/^/    /' >&2
        else
            echo "    (compiler produced no diagnostic output)" >&2
        fi
    done < "$INFRA_LIST"
    echo "" >&2
    echo "  Check compiler installation/DLL integrity, memory and process" \
         "limits, then rerun. A baseline cannot excuse infrastructure" \
         "failure." >&2
fi

if [ "$new_count" -gt 0 ]; then
    [ "$rc" -eq 0 ] && rc=1
    echo "$GATE: FAIL — $new_count file(s) failed mingw -fsyntax-only" \
         "(not baselined, not a skippable missing header):" >&2
    while IFS= read -r src; do
        [ -n "$src" ] || continue
        echo "  $src" >&2
        grep -a -E 'fatal error:|: error:' "$OUT_DIR/${src}.log" |
            sed 's/^/    /' >&2 || true
    done < "$NEW_FAIL"
    echo "" >&2
    echo "  A Windows-only syntax error or a bad #include is exactly what" >&2
    echo "  this gate exists to catch. Fix the source. Do not add the file" >&2
    echo "  to $BASELINE unless the failure is not a Windows bug (and then" >&2
    echo "  name why). The baseline may only shrink." >&2
fi

if [ "$stale_count" -gt 0 ]; then
    [ "$rc" -eq 0 ] && rc=1
    echo "$GATE: FAIL — $stale_count baseline entr(y|ies) now compile clean" \
         "or are only a skippable missing header." >&2
    echo "  This baseline is shrink-only. Delete these lines from $BASELINE:" >&2
    sed 's/^/    /' "$STALE" >&2
fi

if [ "$rc" -ne 0 ]; then
    echo "$GATE: compiled $SRC_COUNT file(s), $clean_count clean," \
         "$skip_gen_count generated-header skip, $skip_ossl_count openssl-header skip," \
         "$still_count baselined, $new_count new failure(s)," \
         "$infra_count infrastructure failure(s)."
    exit "$rc"
fi

echo "$GATE: PASS ($SRC_COUNT files compiled, $clean_count clean," \
     "$skip_gen_count generated-header skip, $skip_ossl_count openssl-header skip," \
     "$still_count baselined, 0 new failures)"
exit 0
