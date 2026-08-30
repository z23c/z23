#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_windows_cross_syntax.sh — syntax-only mingw sweep of every .c file
# under lib/, app/, config/, core/, domain/, and ports/ whose text contains
# _WIN32.
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
# File set is SELF-MAINTAINING: a file that gains Windows code joins the
# gate the day the token _WIN32 appears. Do not narrow the set to the files
# that already pass.
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
# Env:
#   ZCL_MINGW_CC   compiler (default: x86_64-w64-mingw32-gcc)
#   ZCL_CC_JOBS    parallel workers (default: nproc, capped at 32)
#
# Exit: 0 clean or SKIP; 1 on a new (non-baselined, non-skippable) failure
# or a stale baseline row; 2 on a hollow/misconfigured scan.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

GATE="check-windows-cross-syntax"
CC_BIN="${ZCL_MINGW_CC:-x86_64-w64-mingw32-gcc}"
BASELINE="tools/lint/windows_cross_syntax_baseline.txt"
SRC_FLOOR=150
INC_FLOOR=50
SCAN_ROOTS=(lib app config core domain ports)
TEST_COMPAT_HEADER="test/windows_compat.h"

echo "══ LINT: Windows cross-syntax (mingw -fsyntax-only over every _WIN32 TU) ══"

# ── SKIP contract ──────────────────────────────────────────────────────────
if [ "${1:-}" != "--self-test" ] && ! command -v "$CC_BIN" >/dev/null 2>&1; then
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
#   ERROR            any other diagnostic
cat > "$WORK/classify.awk" <<'END_AWK'
BEGIN {
    errors = 0
    gen = 0
    ossl = 0
    other = 0
}
{
    line = $0
    is_fatal = 0
    is_error = 0
    if (index(line, ": fatal error: ") > 0) is_fatal = 1
    if (is_fatal == 0 && index(line, ": error: ") > 0) is_error = 1
    if (is_fatal == 0 && is_error == 0) next
    errors++
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

# -DZCL_TESTING exposes test-only declarations. Without it, several _WIN32
# acceptance files fail with "invalid initializer" on an implicit int return
# of a function that actually returns struct zcl_result — a missing prototype,
# not a Windows syntax bug.
COMPILE_FLAGS=(-std=c2x -fsyntax-only -DZCL_TESTING
               "${API_FLOOR_DEFINES[@]}" "${PLATFORM_DEFINES[@]}")

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
[ -f "lib/test/include/$TEST_COMPAT_HEADER" ] || {
    echo "  $GATE: FAIL — missing lib/test/include/$TEST_COMPAT_HEADER." >&2
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
    echo "  OK: --self-test — flag set trips on a Windows-only undeclared" \
         "identifier, passes clean code"
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

cat > "$WORK/compile_one.sh" <<'END_WORKER'
#!/usr/bin/env bash
set -uo pipefail
src=$1
log=$ZCL_GATE_OUT/${src}.log
rcf=$ZCL_GATE_OUT/${src}.rc
mkdir -p "$(dirname "$log")"
mapfile -t -d '' flags < "$ZCL_GATE_FLAGS"
if [ ${#flags[@]} -gt 0 ]; then
    last=$((${#flags[@]} - 1))
    if [ -z "${flags[$last]}" ]; then
        unset "flags[$last]"
    fi
fi
case "$src" in
    lib/test/*) flags+=( -include "$ZCL_GATE_TEST_COMPAT_HEADER" ) ;;
esac
if "$ZCL_GATE_CC" "${flags[@]}" "$src" >"$log" 2>&1; then
    echo 0 > "$rcf"
else
    echo 1 > "$rcf"
fi
exit 0
END_WORKER
chmod +x "$WORK/compile_one.sh"

# Always exit 0 from the worker so a failing compile cannot short-circuit
# xargs into a hollow pass over the remaining files.
tr '\n' '\0' < "$SRC_LIST" |
    env ZCL_GATE_FLAGS="$WORK/flags.nul" ZCL_GATE_CC="$CC_BIN" ZCL_GATE_OUT="$OUT_DIR" \
        ZCL_GATE_TEST_COMPAT_HEADER="$TEST_COMPAT_HEADER" \
        xargs -0 -r -P "$JOBS" -n 1 "$WORK/compile_one.sh" || true

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
: > "$NEW_FAIL"
: > "$STILL"
: > "$SKIP_GEN_LIST"
: > "$SKIP_OSSL_LIST"
: > "$CLEAN_LIST"

while IFS= read -r src; do
    [ -n "$src" ] || continue
    log="$OUT_DIR/${src}.log"
    rcf="$OUT_DIR/${src}.rc"
    rc="$(cat "$rcf" 2>/dev/null || echo missing)"
    kind="$(awk -f "$WORK/classify.awk" "$log")"
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
    esac
    # Compiler error that is not a skippable missing header.
    if [ -n "${BASE[$src]:-}" ]; then
        echo "$src" >> "$STILL"
    else
        echo "$src" >> "$NEW_FAIL"
    fi
    # Keep rc for the summary; a CLEAN rc with ERROR kind is a classifier bug.
    if [ "$rc" = 0 ]; then
        echo "$GATE: FATAL — $src classified $kind but compiler exited 0." >&2
        exit 2
    fi
done < "$SRC_LIST"

# Stale baseline: a listed file now compiles clean (or is only a skippable
# missing header). Shrink-only — delete the row.
declare -A STILL_SET=()
while IFS= read -r row; do
    [ -n "$row" ] || continue
    STILL_SET["$row"]=1
done < "$STILL"
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

rc=0

if [ "$new_count" -gt 0 ]; then
    rc=1
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
    rc=1
    echo "$GATE: FAIL — $stale_count baseline entr(y|ies) now compile clean" \
         "or are only a skippable missing header." >&2
    echo "  This baseline is shrink-only. Delete these lines from $BASELINE:" >&2
    sed 's/^/    /' "$STALE" >&2
fi

if [ "$rc" -ne 0 ]; then
    echo "$GATE: compiled $SRC_COUNT file(s), $clean_count clean," \
         "$skip_gen_count generated-header skip, $skip_ossl_count openssl-header skip," \
         "$still_count baselined, $new_count new failure(s)."
    exit 1
fi

echo "$GATE: PASS ($SRC_COUNT files compiled, $clean_count clean," \
     "$skip_gen_count generated-header skip, $skip_ossl_count openssl-header skip," \
     "$still_count baselined, 0 new failures)"
exit 0
