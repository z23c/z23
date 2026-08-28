#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_windows_platform_seam.sh — Windows CROSS-COMPILE gate for the
# platform seam (lib/platform/src/*.c).
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
# Three people now write this repo on Linux, macOS and Windows, and nothing
# proved the node still compiles on the other two. On 2026-08-27 seven
# Windows commits landed and were reverted the same day, and a later commit
# had to repair `sockaddr_in` availability in the POSIX branch after Windows
# work broke it. That regression class was caught late, by a human, on
# another machine — the exact failure mode a fast local gate exists to catch
# before it ever leaves this box.
#
# `x86_64-w64-mingw32-gcc` (GCC 13) is already installed on the dev reference
# host, and `make presentation-portability` already cross-LINKS a demo with
# it, so a Windows compile check can run on Linux, in seconds, on every push.
# This gate runs
#
#     x86_64-w64-mingw32-gcc -std=c2x -fsyntax-only <lib/*/include -I flags>
#
# over every lib/platform/src/*.c — the platform seam, the one layer whose
# entire job is hiding OS differences behind one header per primitive — and
# ratchets the realized diagnostic sites against a recorded baseline, the
# same shape tools/lint/check_clang_portability.sh already established for
# its whole-tree second-compiler scan. A file that newly stops
# cross-compiling is a FAILURE; a file that starts passing should prompt
# `ZCL_LINT_MODE=UPDATE` to tighten the ratchet.
#
# Measured baseline (2026-08-28, GCC 13-posix mingw): 8 of 11 in-scope files
# compile clean; 3 hold real diagnostic sites — os_binary_slots.c (POSIX
# open()/openat()/flock() flags and calls with no Windows equivalent),
# os_sandbox_stub.c (`#include <sys/resource.h>` does not exist under
# mingw), and rng.c (`O_CLOEXEC` and `getrandom()` are POSIX/Linux-only).
# Those are genuine gaps another lane owns closing; this gate's job is only
# to make sure none of the OTHER files silently joins that list, and that
# the three above only ever shrink.
#
# ── THE EXEMPTION: os_sandbox_linux.c ────────────────────────────────────
# lib/platform/src/os_sandbox_linux.c is Linux's confinement backend; it is
# CORRECTLY excluded from every non-Linux build by the node's own Makefile
# (the `else` branch of the `ifeq ($(ZCL_HOST_OS),Linux)` guard around
# LIB_SRCS). Counting it as a Windows failure would be grading code the real
# Windows build never even compiles. This gate does not hardcode that
# filename: it PARSES the same Makefile branch the real build uses (see
# `exempt_files()` below), so the exemption tracks the build's own decision
# instead of drifting from it. Nothing else is exempt — os_sandbox_stub.c
# (the file the real Windows build *does* select) is graded like any other
# seam file and currently holds one real diagnostic.
#
# ── HONESTY CONTRACT ─────────────────────────────────────────────────────
# This repo has been burned twice: a push gate that printed green while
# running zero tests, and a load-sensitivity fix that turned a real FAIL
# into a SKIP that just moved the red. Neither happens here:
#   * a box with no mingw toolchain prints UNOBSERVED, in that word, checks
#     and passes ZERO files, and is never confused with a green run;
#   * every run prints exactly how many files it scanned;
#   * the gate never widens the baseline, drops a file from it, or silences
#     a real regression to stay green — the only writer of the baseline is
#     the explicit, human-invoked ZCL_LINT_MODE=UPDATE path below, and it
#     can only ever be run by hand, never by `make lint`.
#
# Modes:
#   (default)              scan + ratchet against the baseline; exit 1 on any
#                           new diagnostic site.
#   ZCL_LINT_MODE=UPDATE   re-record the baseline from the current tree.
#                           Never runs under `make lint`.
#   --self-test            prove the gate actually trips: cross-compile one
#                           planted POSIX-only TU and assert mingw rejects
#                           it, and one clean TU and assert mingw accepts
#                           it. Guards against a hollow pass from a
#                           mis-built flag/include set.
#   --sites                print every diagnostic site the seam currently
#                           produces (the to-do list the baseline
#                           summarizes).
#
# Env:
#   ZCL_MINGW_CC   compiler to run (default: x86_64-w64-mingw32-gcc)
#
# Exit: 0 clean (or UNOBSERVED — no mingw toolchain); 1 on a new diagnostic
# site; 2 on a hollow/misconfigured scan (gate_require_scanned floors, a
# missing baseline file).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

GATE="check-windows-platform-seam"
CC_BIN="${ZCL_MINGW_CC:-x86_64-w64-mingw32-gcc}"
MAKEFILE="Makefile"
SEAM_DIR="lib/platform/src"
BASELINE="tools/lint/windows_platform_seam_baseline.txt"

# Known floor for the in-scope seam file count (12 files on disk today, one
# exempt). A lower count means the directory moved or a glob broke — a
# "clean" verdict off that would be hollow, not honest.
SRC_FLOOR=8

# The Windows preprocessor flags come from the Makefile, never from a
# copy kept here. The build compiles the Windows target at
# ZCL_PLATFORM_CPPFLAGS -- notably -D_WIN32_WINNT=0x0600 -- and mingw
# gates real API surface on that macro: GetActiveProcessorCount and
# ALL_PROCESSOR_GROUPS, for instance, are declared only at 0x0601 and
# up. Compiling here at mingw's permissive default therefore asks a
# DIFFERENT and easier question than the build asks, and answers OK
# for a file that cannot build for the product's actual Windows
# target. That is a false green, and this gate existed to prevent
# exactly that, so the floor is read from the Makefile and drifts
# with it by construction.
mapfile -t PLATFORM_DEFINES < <(
    awk '/^ZCL_PLATFORM_CPPFLAGS[ \t]*=/ { inblock = 1 }
         inblock { line = line " " $0; if ($0 !~ /\\$/) { print line; exit } }
        ' Makefile | tr ' \t\\' '\n\n\n' | LC_ALL=C grep '^-D' )
if [ "${#PLATFORM_DEFINES[@]}" -eq 0 ]; then
    echo "  $GATE: FAIL — could not read ZCL_PLATFORM_CPPFLAGS from the" >&2
    echo "      Makefile. Refusing to cross-compile at a guessed API" >&2
    echo "      floor, which would silently grade an easier question." >&2
    exit 1
fi

WARN_FLAGS=(-std=c2x -fsyntax-only "${PLATFORM_DEFINES[@]}")

echo "══ LINT: Windows platform-seam cross-compile (mingw -fsyntax-only) ══"

# ── UNOBSERVED contract ───────────────────────────────────────────────────
# Absence of the cross-compiler is an honest environment gap, not a defect —
# an outside contributor without mingw must not be blocked by a tool they do
# not have. But it must never read as a pass: print the word UNOBSERVED, say
# plainly that zero files were checked, and exit 0 (non-fatal, same SKIP
# contract check_clang_portability.sh uses for an absent clang) — never OK,
# never PASS.
if [ "${1:-}" != "--self-test" ] && ! command -v "$CC_BIN" >/dev/null 2>&1; then
    echo "  $GATE: UNOBSERVED — '$CC_BIN' is not installed on this box."
    echo "  0 of $SRC_FLOOR+ platform-seam files were checked. This is NOT a"
    echo "  pass: it is an unobserved leg. Install mingw-w64"
    echo "  (apt install gcc-mingw-w64-x86-64) or set ZCL_MINGW_CC=<path> to"
    echo "  actually run this gate."
    exit 0
fi

# ── Include search path ───────────────────────────────────────────────────
# Same set the measured baseline reproduction used: every lib/*/include root
# (superset by construction — headers are namespaced per module, so an extra
# -I can only add a search path, never collide).
mapfile -t INC_DIRS < <(find lib -maxdepth 2 -type d -name include 2>/dev/null | sort)
gate_require_scanned "${#INC_DIRS[@]}" 15 "$GATE" \
    "no lib/*/include roots found — the lib/ layout moved"
INC_FLAGS=()
for d in "${INC_DIRS[@]}"; do INC_FLAGS+=("-I$d"); done

# ── Self-test: prove the flag set actually rejects a Windows violation ────
if [ "${1:-}" = "--self-test" ]; then
    if ! command -v "$CC_BIN" >/dev/null 2>&1; then
        echo "  $GATE --self-test: UNOBSERVED — '$CC_BIN' is not installed;" \
             "cannot prove the gate trips without the compiler it gates."
        exit 0
    fi
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-win-seam-selftest.XXXXXX")" || {
        echo "$GATE --self-test: FATAL — mktemp failed." >&2; exit 2; }
    trap 'rm -rf "$WORK"' EXIT

    violating="$WORK/violating.c"
    cat > "$violating" <<'PROBE'
#include <sys/resource.h> /* POSIX-only: does not exist under mingw */
int zcl_gate_probe(void) { return (int)RLIMIT_NOFILE; }
PROBE
    if "$CC_BIN" "${WARN_FLAGS[@]}" "${INC_FLAGS[@]}" "$violating" >/dev/null 2>&1; then
        echo "FAIL: --self-test — mingw ACCEPTED a TU that #includes a"
        echo "  POSIX-only header. The gate is hollow: it would report"
        echo "  'clean' on a real Windows-portability regression."
        exit 1
    fi

    clean="$WORK/clean.c"
    printf 'int zcl_gate_clean(int a);\nint zcl_gate_clean(int a) { return a + 1; }\n' > "$clean"
    if ! "$CC_BIN" "${WARN_FLAGS[@]}" "${INC_FLAGS[@]}" "$clean" >/dev/null 2>&1; then
        echo "FAIL: --self-test — mingw REJECTED a trivially clean TU."
        echo "  The gate would false-fail every contributor."
        exit 1
    fi
    echo "  OK: --self-test — flag set trips on a POSIX-only violation," \
         "passes clean code"
    exit 0
fi

# ── Exemption set: parsed from the Makefile's OWN non-Linux LIB_SRCS filter,
# not hardcoded ─────────────────────────────────────────────────────────────
# Mirrors exactly the `else` branch of the `ifeq ($(ZCL_HOST_OS),Linux)`
# guard around LIB_SRCS: whatever lib/platform/src/*.c the real build itself
# drops when the host is not Linux is exempt here too, so this gate tracks
# the build's own decision instead of drifting from it. If the build ever
# stops exempting a file, this gate starts grading it on the same commit —
# no separate exemption list to fall out of sync.
exempt_files() {
    awk '
        /^ifeq \(\$\(ZCL_HOST_OS\),Linux\)$/ { inblock = 1; branch = 0; next }
        inblock && /^else$/                  { branch = 1; next }
        inblock && /^endif$/                 { inblock = 0; next }
        inblock && branch == 1               { print }
    ' "$MAKEFILE" | grep -oE "${SEAM_DIR}/[A-Za-z0-9_]+\.c" | sort -u
}
mapfile -t EXEMPT < <(exempt_files)

is_exempt() {
    local f="$1" e
    for e in "${EXEMPT[@]}"; do [ "$f" = "$e" ] && return 0; done
    return 1
}

# ── Source set ─────────────────────────────────────────────────────────────
mapfile -t ALL_SRC < <(find "$SEAM_DIR" -maxdepth 1 -name '*.c' -type f 2>/dev/null | sort)
SRC_LIST=()
for f in "${ALL_SRC[@]}"; do
    is_exempt "$f" || SRC_LIST+=("$f")
done
SRC_COUNT="${#SRC_LIST[@]}"
gate_require_scanned "$SRC_COUNT" "$SRC_FLOOR" "$GATE" \
    "scanned '$SEAM_DIR'/*.c minus ${#EXEMPT[@]} Makefile-exempt file(s) — a directory move or an exemption parse gone wrong would empty this"

# ── The scan ────────────────────────────────────────────────────────────
DIAG_RE='^[A-Za-z0-9_./-]+\.[ch]:[0-9]+:[0-9]+: (fatal error|error|warning): .*$'
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-win-seam.XXXXXX")" || {
    echo "$GATE: FATAL — mktemp failed." >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT

SITES="$WORK/sites.txt"
: > "$SITES"
COUNTS="$WORK/counts.txt"
: > "$COUNTS"
for f in "${SRC_LIST[@]}"; do
    out="$("$CC_BIN" "${WARN_FLAGS[@]}" "${INC_FLAGS[@]}" "$f" 2>&1)" || true
    file_sites="$(printf '%s\n' "$out" | grep -oE "$DIAG_RE" | sort -u)"
    printf '%s\n' "$file_sites" | sed '/^$/d' >> "$SITES"
    count="$(printf '%s\n' "$file_sites" | grep -c . || true)"
    echo "$f $count" >> "$COUNTS"
done
TOTAL_SITES="$(grep -c . "$SITES" 2>/dev/null || true)"
[ -n "$TOTAL_SITES" ] || TOTAL_SITES=0

if [ "${1:-}" = "--sites" ]; then
    echo "  $TOTAL_SITES diagnostic site(s) over $SRC_COUNT in-scope file(s)" \
         "(${#EXEMPT[@]} Makefile-exempt):"
    sed 's/^/    /' "$SITES"
    exit 0
fi

# ── UPDATE mode: re-record the baseline ───────────────────────────────────
if [ "${ZCL_LINT_MODE:-}" = "UPDATE" ]; then
    {
        echo "# Windows platform-seam ratchet baseline — regenerate with:"
        echo "#   ZCL_LINT_MODE=UPDATE tools/lint/check_windows_platform_seam.sh"
        echo "#"
        echo "# One '<path> <count>' line per lib/platform/src/*.c file that"
        echo "# still holds mingw diagnostic sites under"
        echo "#   $CC_BIN ${WARN_FLAGS[*]} <lib/*/include -I flags>"
        echo "# A file absent from this list must produce ZERO diagnostics."
        echo "# Counts may only go DOWN. os_sandbox_linux.c and any other"
        echo "# file the Makefile's own non-Linux LIB_SRCS filter drops are"
        echo "# never listed here — they are exempt, not zero."
        echo "#"
        echo "# Recorded from $SRC_COUNT in-scope translation units with:"
        echo "#   $("$CC_BIN" --version 2>/dev/null | head -1)"
        grep -v ' 0$' "$COUNTS" | sort
    } > "$BASELINE"
    echo "  UPDATED: $BASELINE ($(grep -vc ' 0$' "$COUNTS" || true) file(s)," \
         "$TOTAL_SITES site(s))"
    exit 0
fi

if [ ! -f "$BASELINE" ]; then
    echo "$GATE: FATAL — baseline '$BASELINE' is missing." >&2
    echo "  Refusing to report 'clean' with nothing to ratchet against." >&2
    echo "  Regenerate: ZCL_LINT_MODE=UPDATE $0" >&2
    exit 2
fi

declare -A BASE=()
gate_load_kv_file "$BASELINE" BASE

regressions=""
improvements=""
while read -r file count; do
    [ -n "$file" ] || continue
    allowed="${BASE[$file]:-0}"
    if [ "$count" -gt "$allowed" ]; then
        regressions="${regressions}  $file: $count site(s), baseline allows $allowed"$'\n'
    elif [ "$count" -lt "$allowed" ]; then
        improvements="${improvements}  $file: $count site(s) (baseline $allowed)"$'\n'
    fi
done < "$COUNTS"

# A baselined file that now compiles clean (0 sites, no line in COUNTS'
# nonzero form) is an improvement worth surfacing too.
for file in "${!BASE[@]}"; do
    if ! gate_grep -qE "^${file//./\\.} " "$COUNTS"; then
        improvements="${improvements}  $file: 0 site(s) (baseline ${BASE[$file]})"$'\n'
    fi
done

if [ -n "${regressions//[[:space:]]/}" ]; then
    echo "" >&2
    echo "FAIL: mingw diagnostic site(s) — this change does not cross-" >&2
    echo "      compile cleanly for Windows under $CC_BIN." >&2
    echo "" >&2
    printf '%s' "$regressions" >&2
    echo "" >&2
    echo "  Diagnostics:" >&2
    while read -r f; do
        [ -n "$f" ] || continue
        gate_grep -E "^${f//./\\.}:" "$SITES" | sed 's/^/    /' >&2 || true
    done < <(printf '%s' "$regressions" | sed 's/^  //; s/:.*//')
    echo "" >&2
    echo "  Reproduce one file:" >&2
    echo "    $CC_BIN ${WARN_FLAGS[*]} ${INC_FLAGS[*]} <file.c>" >&2
    exit 1
fi

if [ -n "${improvements//[[:space:]]/}" ]; then
    echo "  NOTE: mingw diagnostics went DOWN — tighten the ratchet:"
    printf '%s' "$improvements"
    echo "    ZCL_LINT_MODE=UPDATE tools/lint/check_windows_platform_seam.sh"
fi

echo "  OK: $SRC_COUNT platform-seam file(s) cross-compiled with $CC_BIN" \
     "(${#EXEMPT[@]} Makefile-exempt); $TOTAL_SITES known diagnostic" \
     "site(s), no new ones"
exit 0
