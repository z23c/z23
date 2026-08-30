#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_platform_header_guards.sh — a platform-only system header may not be
# included outside a conditional that names that platform.
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
# Commit 1e1ce62af ("macOS: portable toolchain, package worker, and registry
# gates") added lib/hotswap/src/hotswap_macho_probe.c, which included
# <mach-o/fat.h>, <mach-o/loader.h>, <mach-o/nlist.h> and <mach-o/swap.h> with
# NO platform guard at all. Those headers ship only in the Apple SDK, so every
# Linux build that reached that translation unit died at
#
#     fatal error: mach-o/fat.h: No such file or directory
#
# main was red for a full day and nothing in the tree said so, because the
# build-epoch object cache still held objects compiled BEFORE that commit and
# only an unrelated edit rotated the epoch. The tree had FOUR Windows lint
# gates at the time (check-windows-acceptance, check-windows-cross-syntax,
# check-windows-platform-seam, check-published-platforms) and ZERO for Darwin,
# so the mirror-image mistake in the Windows direction would have been caught
# within the hour and this one was not caught at all.
#
# Every one of those Windows gates needs a cross-compiler. This gate needs
# nothing: an unguarded platform header is a LEXICAL fact, visible on any host,
# in milliseconds. It closes the class in every direction at once (Apple,
# Windows, Linux) rather than buying one more platform a toolchain.
#
# ── HOW THE HEADER TABLE WAS DERIVED (do not invent rows from memory) ───────
# The table below was NOT typed from recollection of what Apple/Windows/Linux
# ship. It was produced by walking every angle-bracket include in the tracked
# tree and classifying the result:
#
#     git ls-files '*.c' '*.h' \
#       | xargs grep -hoE '^[[:space:]]*#[[:space:]]*include[[:space:]]*<[^>]+>' \
#       | sed -E 's/.*<([^>]+)>/\1/' | sort | uniq -c | sort -rn
#
# That yields 187 distinct system headers. Each was kept only when its absence
# on another supported host is a HARD compile error, and dropped when it is
# merely unusual there. Headers deliberately NOT in the table, and why:
#
#   sys/syscall.h  Darwin ships it too (with different numbers). Present, so
#                  including it is not a compile error — a wrong __NR_* is a
#                  different bug and not this gate's class.
#   execinfo.h     Darwin ships it (backtrace/backtrace_symbols). Absent only
#                  on musl, which is not a supported host here.
#   sys/mman.h,
#   dirent.h, etc. POSIX; present on every supported host.
#   immintrin.h,
#   arm_neon.h     compiler-provided, keyed on the ARCH not the OS. A separate
#                  concern with its own gates (check-accel-oracle-pinned).
#   X11/, raylib.h,
#   wayland-*      vendor/ and the GUI apps, which are out of the scan roots.
#
# TO EXTEND: add the header to the table, run the gate, fix or exempt what it
# finds. Re-run the one-liner above after any large import to see whether a new
# platform-only header entered the tree unclassified. Do not narrow the table
# to what currently passes.
#
# ── WHAT COUNTS AS A GUARD ──────────────────────────────────────────────────
# The include must sit lexically inside an #if/#ifdef/#elif region whose
# condition MENTIONS one of the macros the header requires. Mentioning is the
# right bar, not implication: <sys/event.h> under
# `#if defined(__APPLE__) || defined(__FreeBSD__)` is correct code and must
# pass, while a mach-o include under `#if defined(_WIN32)` names the wrong
# platform and must fail.
#
# This needs a real preprocessor-conditional depth tracker, not a grep. A grep
# for "is __APPLE__ anywhere in the file" passes a file that guards one hunk
# and leaves another bare (the exact shape of the macho defect); a grep for
# "the previous line is an #if" fails every correctly-guarded whole-file TU.
# The scanner below keeps a stack of conditions, inverts a frame on #else
# (the #else of `#ifdef __APPLE__` is the NON-Apple branch, so an Apple header
# there is a violation, and the #else of `#ifndef __APPLE__` is the Apple one),
# replaces the top frame on #elif, strips comments so a header named in prose
# is not a finding, and joins backslash continuations.
#
# `#if defined(__has_include) && __has_include(<H>)` around `#include <H>` is
# also accepted, for the same header only. That is strictly stronger than a
# platform macro — it asks the compiler that is actually running.
#
# ── WHAT IS EXEMPT, AND WHO DECIDES ─────────────────────────────────────────
# Nothing is exempt by a hand-kept list in this file. Two classes of file are
# platform-EXCLUSIVE because the BUILD says so, and both sets are parsed out of
# the build's own text so they track it instead of drifting from it:
#
#   1. lib/ sources the Makefile's LIB_SRCS host branch filters out of every
#      host but one (lib/platform/src/os_sandbox_linux.c is dropped on Windows
#      and on Darwin, so it is Linux-exclusive and needs no __linux__ guard).
#   2. Sources named in a ZCL_WINDOWS_ACCEPTANCE_*_SOURCES row of
#      lib/platform/tests/windows_acceptance.mk. Those programs are only ever
#      cross-linked for Windows, and check-windows-acceptance already refuses
#      an acceptance program that is not in that catalog.
#
# An exemption is per-PLATFORM, not blanket: a Linux-exclusive file still fails
# this gate for an unguarded <mach-o/fat.h>. If either parse comes back empty
# the gate REFUSES (exit 2) instead of quietly grading a wider or narrower set.
#
# ── SCAN ROOTS ──────────────────────────────────────────────────────────────
# lib app config core domain ports — the same product surface
# check-windows-cross-syntax scans, .c and .h alike. tools/ is deliberately
# OUT: those are host-local developer programs built by explicit rules, never
# by directory enumeration, and several (tools/zcl_portfwd.c's epoll loop,
# tools/rebuild_recent.c's io_uring) are standalone Linux-only `main()`
# programs where a whole-TU guard would turn a clear "no such header" into a
# baffling "undefined reference to main".
#
# Usage:
#   tools/lint/check_platform_header_guards.sh             # the gate
#   tools/lint/check_platform_header_guards.sh --self-test # prove it can go red
#   tools/lint/check_platform_header_guards.sh --list      # every classified
#                                                          # include + verdict
#
# Exit: 0 clean; 1 on any unguarded platform header; 2 on a hollow scan (empty
# file set, unparseable build text).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || exit 2
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# str_contains / str_lacks: `printf | grep -q` under pipefail returns 141 on a
# MATCH once the payload exceeds the pipe buffer, inverting the decision.
# shellcheck source=tools/scripts/sh_str.sh
. tools/scripts/sh_str.sh

GATE="check-platform-header-guards"
SCAN_ROOTS=(lib app config core domain ports)
WIN_CATALOG="lib/platform/tests/windows_acceptance.mk"

# Anti-hollow floors. Every one is well under today's realized count (4543
# files / 470 candidates / 9135 includes / 203 classified / 27 catalogued
# Windows programs), so ordinary churn never trips them and a producer that
# silently empties always does. The self-test runs the same code with its own
# much smaller floors; production floors are never relaxed to get a green.
SRC_FLOOR=2000
CAND_FLOOR=40
INC_FLOOR=200
SEEN_FLOOR=50
WINCAT_FLOOR=10

WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-platform-header-guards.XXXXXX")" || {
    echo "$GATE: FATAL — mktemp failed." >&2
    exit 2
}
trap 'rm -rf "$WORK"' EXIT

# ── The table ───────────────────────────────────────────────────────────────
# One row per platform-only header (or header DIRECTORY, trailing slash):
#     <header-or-prefix>|<macro> [<macro>...]|<human platform name>
# Any ONE of the macros satisfies the row. Derivation is documented above; the
# Windows "and friends" rows past the ones the tree uses today are the Win32
# API headers a future seam is most likely to reach for, listed so the first
# use is guarded rather than caught later.
cat > "$WORK/table.txt" <<'END_TABLE'
mach-o/|__APPLE__ __MACH__|Apple SDK
mach/|__APPLE__ __MACH__|Apple SDK
CoreFoundation/|__APPLE__|Apple SDK
CoreGraphics/|__APPLE__|Apple SDK
CoreVideo/|__APPLE__|Apple SDK
CoreServices/|__APPLE__|Apple SDK
Foundation/|__APPLE__|Apple SDK
Security/|__APPLE__|Apple SDK
IOKit/|__APPLE__|Apple SDK
ApplicationServices/|__APPLE__|Apple SDK
objc/|__APPLE__|Apple SDK
libproc.h|__APPLE__|Apple SDK
crt_externs.h|__APPLE__|Apple SDK
sys/qos.h|__APPLE__|Apple SDK
sys/event.h|__APPLE__ __FreeBSD__ __OpenBSD__ __NetBSD__ BSD|kqueue (Apple/BSD)
sys/sysctl.h|__APPLE__ __FreeBSD__ __OpenBSD__ __NetBSD__ BSD|sysctl (Apple/BSD)
windows.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
winsock2.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
ws2tcpip.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
winternl.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
winuser.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
windowsx.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
winbase.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
winnt.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
wincrypt.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
shellscalingapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
shellapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
shlobj.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
knownfolders.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
aclapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
sddl.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
tlhelp32.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
psapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
bcrypt.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
netioapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
iphlpapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
mswsock.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
dxgi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
io.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
process.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
direct.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
processthreadsapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
synchapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
fileapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
handleapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
memoryapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
namedpipeapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
errhandlingapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
sysinfoapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
libloaderapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
securitybaseapi.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
versionhelpers.h|_WIN32 _WIN64 __MINGW32__ __CYGWIN__|Win32
sys/epoll.h|__linux__ __linux __gnu_linux__|Linux
sys/inotify.h|__linux__ __linux __gnu_linux__|Linux
sys/prctl.h|__linux__ __linux __gnu_linux__|Linux
sys/sysinfo.h|__linux__ __linux __gnu_linux__|Linux
sys/sysmacros.h|__linux__ __linux __gnu_linux__|Linux
sys/auxv.h|__linux__ __linux __gnu_linux__ __GLIBC__|Linux
linux/|__linux__ __linux __gnu_linux__|Linux
liburing.h|__linux__ __linux __gnu_linux__|Linux
END_TABLE

# ── The scanner ─────────────────────────────────────────────────────────────
# awk programs live in FILES: an apostrophe inside awk '...' swallows the rest
# of a shell script, and this one is full of prose.
#
# Emits one TAB-separated record per angle-bracket include:
#     <file> <header> <space-delimited macro tokens live here> <raw conditions>
cat > "$WORK/scan.awk" <<'END_AWK'
FNR == 1 { incomment = 0; depth = 0 }

function strip_comments(s,   out, i, c, n) {
    out = ""; n = length(s); i = 1
    while (i <= n) {
        c = substr(s, i, 1)
        if (incomment) {
            if (c == "*" && substr(s, i + 1, 1) == "/") { incomment = 0; i += 2; continue }
            i++; continue
        }
        if (c == "/" && substr(s, i + 1, 1) == "*") { incomment = 1; i += 2; continue }
        if (c == "/" && substr(s, i + 1, 1) == "/") break
        out = out c; i++
    }
    return out
}

function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }

# Every identifier token in a condition, space-delimited and space-fenced so a
# caller can test membership with index(t, " MACRO ") and never match a prefix.
function tokens_of(cond,   s) {
    s = cond
    gsub(/[^A-Za-z0-9_]/, " ", s)
    gsub(/[ \t]+/, " ", s)
    return " " trim(s) " "
}

# Whitespace squeezed out, so __has_include(< linux/landlock.h >) and
# __has_include(<linux/landlock.h>) compare equal.
function squeeze(s) { gsub(/[ \t]/, "", s); return s }

# Split a condition on TOP-LEVEL && (paren depth 0). Fills CONJ[1..n].
function split_conj(cond,   i, n, d, cur, k, c, c2) {
    k = 0; cur = ""; d = 0; n = length(cond)
    for (i = 1; i <= n; i++) {
        c = substr(cond, i, 1); c2 = substr(cond, i, 2)
        if (c == "(") d++
        else if (c == ")") d--
        if (d == 0 && c2 == "&&") { k++; CONJ[k] = cur; cur = ""; i++; continue }
        cur = cur c
    }
    k++; CONJ[k] = cur
    return k
}

# The macros an #else branch may claim: the negation of `!defined(X)` is
# `defined(X)`, so a top-level conjunct of that exact shape carries into the
# else. Anything else negates into a disjunction and claims nothing.
function else_tokens(cond,   e, k, j, cj, mm) {
    e = " "
    k = split_conj(cond)
    for (j = 1; j <= k; j++) {
        cj = trim(CONJ[j])
        while (cj ~ /^\(.*\)$/) { sub(/^\(/, "", cj); sub(/\)$/, "", cj); cj = trim(cj) }
        if (cj ~ /^![ \t]*defined[ \t]*\([ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*\)$/ ||
            cj ~ /^![ \t]*defined[ \t]+[A-Za-z_][A-Za-z0-9_]*$/ ||
            cj ~ /^![ \t]*[A-Za-z_][A-Za-z0-9_]*$/) {
            mm = cj
            gsub(/[^A-Za-z0-9_]/, " ", mm)
            mm = trim(mm)
            sub(/^defined[ \t]+/, "", mm)
            e = e trim(mm) " "
        }
    }
    return e
}

{
    # Comment stripping is the hot loop; a line with no slash and no star
    # cannot open, close, or sit inside a comment we have not already entered.
    if (incomment || index($0, "/") > 0 || index($0, "*") > 0) line = strip_comments($0)
    else if ($0 !~ /^[ \t]*#/) next
    else line = $0

    # Join backslash continuations: a multi-line #if is one condition.
    while (line ~ /\\[ \t]*$/) {
        sub(/\\[ \t]*$/, "", line)
        if ((getline nxt) <= 0) break
        line = line " " strip_comments(nxt)
    }

    if (line !~ /^[ \t]*#/) next
    d = line
    sub(/^[ \t]*#[ \t]*/, "", d)

    if (d ~ /^ifdef[ \t]/) {
        m = d; sub(/^ifdef[ \t]+/, "", m); m = trim(m)
        depth++
        CTOK[depth] = " " m " "; CRAW[depth] = squeeze(m)
        ETOK[depth] = " ";       ERAW[depth] = ""
        INELSE[depth] = 0
        next
    }
    if (d ~ /^ifndef[ \t]/) {
        m = d; sub(/^ifndef[ \t]+/, "", m); m = trim(m)
        depth++
        CTOK[depth] = " ";       CRAW[depth] = ""
        ETOK[depth] = " " m " "; ERAW[depth] = ""
        INELSE[depth] = 0
        next
    }
    if (d ~ /^if[ \t(!]/ || d == "if") {
        cond = d; sub(/^if/, "", cond); cond = trim(cond)
        depth++
        CTOK[depth] = tokens_of(cond); CRAW[depth] = squeeze(cond)
        ETOK[depth] = else_tokens(cond); ERAW[depth] = ""
        INELSE[depth] = 0
        next
    }
    if (d ~ /^elif/) {
        if (depth > 0) {
            cond = d; sub(/^elif/, "", cond); cond = trim(cond)
            CTOK[depth] = tokens_of(cond); CRAW[depth] = squeeze(cond)
            ETOK[depth] = else_tokens(cond); ERAW[depth] = ""
            INELSE[depth] = 0
        }
        next
    }
    if (d ~ /^else/) { if (depth > 0) INELSE[depth] = 1; next }
    if (d ~ /^endif/) { if (depth > 0) { INELSE[depth] = 0; depth-- } next }

    if (d ~ /^include[ \t]*</) {
        hdr = d
        sub(/^include[ \t]*</, "", hdr)
        sub(/>.*$/, "", hdr)
        hdr = trim(hdr)
        act = " "; raw = ""
        for (j = 1; j <= depth; j++) {
            if (INELSE[j]) { act = act ETOK[j]; raw = raw ERAW[j] " " }
            else           { act = act CTOK[j]; raw = raw CRAW[j] " " }
        }
        gsub(/[ \t]+/, " ", act)
        printf "%s\t%s\t%s\t%s\t%d\n", FILENAME, hdr, act, raw, FNR
        next
    }
}
END_AWK

# ── The classifier ──────────────────────────────────────────────────────────
# Reads the table, the exemption map, and the scanner records; prints one line
# per finding. -v mode=list prints every classified include with its verdict.
cat > "$WORK/classify.awk" <<'END_AWK'
BEGIN { FS = "\t" }

# Pass 1: the table.
FILENAME == TABLE {
    if ($0 ~ /^[ \t]*(#|$)/) next
    n = split($0, p, "|")
    if (n != 3) { printf "TABLE_MALFORMED\t%s\n", $0; bad = 1; next }
    NT++
    PREF[NT] = p[1]; MACS[NT] = p[2]; PLAT[NT] = p[3]
    next
}

# Pass 2: the build-derived exemption map, "<file>\t<macro>" per line.
FILENAME == EXEMPT {
    if ($0 ~ /^[ \t]*(#|$)/) next
    EX[$1 "\t" $2] = 1
    next
}

# Pass 3: scanner records.
{
    file = $1; hdr = $2; act = $3; raw = $4; ln = $5
    for (i = 1; i <= NT; i++) {
        pref = PREF[i]
        if (pref ~ /\/$/) { if (index(hdr, pref) != 1) continue }
        else              { if (hdr != pref) continue }

        SEEN++
        ok = 0; why = ""
        k = split(MACS[i], M, " ")
        for (j = 1; j <= k; j++) {
            if (index(act, " " M[j] " ") > 0) { ok = 1; why = "guard " M[j]; break }
            if (EX[file "\t" M[j]]) { ok = 1; why = "build-exclusive " M[j]; break }
        }
        # __has_include of this very header is a stronger guard than any macro.
        if (!ok && index(raw, "__has_include(<" hdr ">)") > 0) {
            ok = 1; why = "__has_include(<" hdr ">)"
        }
        if (ok) {
            if (mode == "list") printf "ok   %s:%s <%s> (%s)\n", file, ln, hdr, why
        } else {
            if (mode == "list") printf "FAIL %s:%s <%s> needs %s\n", file, ln, hdr, MACS[i]
            else printf "%s:%s\t<%s>\t%s\trequires one of: %s\n", file, ln, hdr, PLAT[i], MACS[i]
            FOUND++
        }
        break
    }
}

END {
    if (bad) exit 2
    printf "SEEN=%d FOUND=%d\n", SEEN + 0, FOUND + 0 > CTLFILE
}
END_AWK


# ── Build-derived exemptions ────────────────────────────────────────────────
# (1) The Makefile's LIB_SRCS per-host filter-out block. Every file it names is
#     collected per branch; a file that survives EXACTLY ONE branch is
#     exclusive to that branch's platform.
cat > "$WORK/libsrcs.awk" <<'END_AWK'
# Emits "<branch-index>\t<file>" for every source filtered OUT in that branch,
# plus "BRANCH\t<index>\t<condition text>" so the caller can label platforms.
/^ifneq \(\$\(filter Linux,\$\(ZCL_HOST_OS\)\),\)$/ { inb = 1; b = 0; printf "BRANCH\t%d\t%s\n", b, $0; next }
/^ifeq \(\$\(ZCL_HOST_OS\),Linux\)$/                { inb = 1; b = 0; printf "BRANCH\t%d\t%s\n", b, $0; next }
inb && /^endif$/  { inb = 0; next }
inb && /^else/    { b++; printf "BRANCH\t%d\t%s\n", b, $0; next }
inb {
    line = $0
    while (match(line, /(lib|app|config|core|domain|ports)\/[A-Za-z0-9_\/]+\.c/)) {
        printf "%d\t%s\n", b, substr(line, RSTART, RLENGTH)
        line = substr(line, RSTART + RLENGTH)
    }
}
END_AWK

# A file that is compiled by exactly ONE of the host branches is exclusive to
# that branch's platform, and the macro named there is the one it need not
# spell out. A file dropped by every branch, or by none, is claimed by nobody.
cat > "$WORK/exclusive.awk" <<'END_AWK'
BEGIN { FS = "\t" }
$1 == "BRANCH" {
    idx = $2 + 0
    cond = $3
    if (index(cond, "Linux") > 0)                   LAB[idx] = "__linux__"
    else if (index(cond, "ZCL_HOST_WINDOWS") > 0)   LAB[idx] = "_WIN32"
    else if (index(cond, "MINGW") > 0)              LAB[idx] = "_WIN32"
    else                                            LAB[idx] = "__APPLE__"
    KNOWN[idx] = 1
    if (idx + 1 > NB) NB = idx + 1
    next
}
{
    idx = $1 + 0
    OUT[$2 "\t" idx] = 1
    FILES[$2] = 1
    if (idx + 1 > NB) NB = idx + 1
}
END {
    for (f in FILES) {
        survivor = -1; count = 0
        for (i = 0; i < NB; i++) {
            if (!((f "\t" i) in OUT)) { survivor = i; count++ }
        }
        if (count == 1 && KNOWN[survivor]) printf "%s\t%s\n", f, LAB[survivor]
    }
}
END_AWK

# ── One scan ────────────────────────────────────────────────────────────────
# run_scan <root> <src-floor> <candidate-floor> <include-floor> <seen-floor>
#          <win-catalog-floor> <mode>
#
# Everything the gate grades lives under <root>, so the self-test can aim the
# REAL code at a fixture instead of at a mock. mode is "" (grade), "list"
# (print every classified include), or "quiet" (grade, findings only).
# Exit: 0 clean, 1 findings, 2 hollow/unparseable.
run_scan() {
    local root="$1" src_floor="$2" cand_floor="$3" inc_floor="$4"
    local seen_floor="$5" wincat_floor="$6" mode="${7:-}"
    local w="$WORK/scan.$$.d"
    rm -rf "$w"; mkdir -p "$w" || return 2

    (
    cd "$root" || exit 2

    # (1) LIB_SRCS host branches.
    if [ ! -f Makefile ]; then
        echo "$GATE: FATAL — no Makefile under $root." >&2
        exit 2
    fi
    awk -f "$WORK/libsrcs.awk" Makefile > "$w/libsrcs.txt"
    local branch_count
    branch_count="$(grep -c '^BRANCH' "$w/libsrcs.txt" || true)"
    if [ "${branch_count:-0}" -lt 2 ]; then
        echo "$GATE: FATAL — could not read the LIB_SRCS per-host branch out of Makefile." >&2
        echo "  This gate derives its platform-exclusive file set from that block" >&2
        echo "  (the 'ifneq (\$(filter Linux,\$(ZCL_HOST_OS)),)' ... else ... endif" >&2
        echo "  around LIB_SRCS := \$(filter-out ...)). It found ${branch_count:-0} branch(es)." >&2
        echo "  Either the block was rewritten into a shape the parser does not know," >&2
        echo "  or it is gone. Refusing to grade with an exemption set it cannot read:" >&2
        echo "  an empty set turns build-exclusive files into false failures and a" >&2
        echo "  wrong set hides real ones." >&2
        exit 2
    fi
    awk -f "$WORK/exclusive.awk" "$w/libsrcs.txt" > "$w/exempt.txt"

    # (2) The Windows acceptance catalog.
    if [ ! -f "$WIN_CATALOG" ]; then
        echo "$GATE: FATAL — missing $WIN_CATALOG under $root." >&2
        echo "  The Windows-exclusive exemption set is parsed out of that catalog." >&2
        exit 2
    fi
    local win_n
    grep -oE 'lib/platform/tests/[A-Za-z0-9_]+\.c' "$WIN_CATALOG" \
        | LC_ALL=C sort -u > "$w/wincat.txt" || true
    win_n="$(grep -c . "$w/wincat.txt" || true)"
    if [ "${win_n:-0}" -lt "$wincat_floor" ]; then
        echo "$GATE: FATAL — $WIN_CATALOG yielded only ${win_n:-0} source(s) (floor $wincat_floor)." >&2
        echo "  Expected the ZCL_WINDOWS_ACCEPTANCE_*_SOURCES rows. A parse this thin" >&2
        echo "  means the catalog moved or changed shape; refusing to grade the" >&2
        echo "  Windows acceptance programs against an exemption set it cannot read." >&2
        exit 2
    fi
    sed 's/$/\t_WIN32/' "$w/wincat.txt" >> "$w/exempt.txt"
    local exempt_n
    exempt_n="$(grep -c . "$w/exempt.txt" || true)"

    # (3) The file set.
    local r present_roots=()
    for r in "${SCAN_ROOTS[@]}"; do [ -d "$r" ] && present_roots+=("$r"); done
    if [ "${#present_roots[@]}" -eq 0 ]; then
        echo "$GATE: FATAL — none of the scan roots (${SCAN_ROOTS[*]}) exist under $root." >&2
        exit 2
    fi
    find "${present_roots[@]}" -type f \( -name '*.c' -o -name '*.h' \) -print \
        | LC_ALL=C sort > "$w/files.txt"
    local file_n
    file_n="$(grep -c . "$w/files.txt" || true)"
    gate_require_scanned "${file_n:-0}" "$src_floor" "$GATE" \
        "scanned ${present_roots[*]} for .c/.h — a directory move would empty this"

    # (4) Pre-filter. Only a file whose TEXT mentions one of the table headers
    #     can hold a finding, and the conditional tracker is the expensive
    #     part. The patterns are the raw header/prefix strings, so this
    #     OVER-selects (a comment, a quoted include, a path that merely ends in
    #     the same characters) — which is safe, because the scanner still
    #     decides. Under-selection would not be: never tighten these into
    #     anchored patterns.
    tr '\n' '\0' < "$w/files.txt" \
        | xargs -0 -n 400 grep -l -F -f "$WORK/needles.txt" 2>/dev/null \
        | LC_ALL=C sort -u > "$w/candidates.txt"
    local cand_n
    cand_n="$(grep -c . "$w/candidates.txt" || true)"
    gate_require_scanned "${cand_n:-0}" "$cand_floor" "$GATE" \
        "no file in the scan roots even mentions a table header — the pre-filter is broken, not the tree"

    tr '\n' '\0' < "$w/candidates.txt" \
        | xargs -0 -n 400 awk -f "$WORK/scan.awk" > "$w/includes.tsv"
    local inc_n
    inc_n="$(grep -c . "$w/includes.tsv" || true)"
    gate_require_scanned "${inc_n:-0}" "$inc_floor" "$GATE" \
        "the scanner found almost no #include <...> lines; it is broken, not the tree"

    # (5) Grade.
    local awk_mode=""
    [ "$mode" = "list" ] && awk_mode="list"
    if ! awk -v TABLE="$WORK/table.txt" -v EXEMPT="$w/exempt.txt" \
             -v CTLFILE="$w/ctl.txt" -v mode="$awk_mode" \
             -f "$WORK/classify.awk" \
             "$WORK/table.txt" "$w/exempt.txt" "$w/includes.tsv" > "$w/out.txt"; then
        echo "$GATE: FATAL — the header table is malformed:" >&2
        cat "$w/out.txt" >&2
        exit 2
    fi

    local seen found
    seen="$(sed -n 's/^SEEN=\([0-9]*\).*/\1/p' "$w/ctl.txt")"
    found="$(sed -n 's/.*FOUND=\([0-9]*\).*/\1/p' "$w/ctl.txt")"

    if [ "$mode" = "list" ]; then
        cat "$w/out.txt"
        echo "-- ${seen:-0} classified include(s), ${found:-0} unguarded"
        exit 0
    fi

    if [ "$mode" != "quiet" ]; then
        echo "══ LINT: platform header guards (${file_n} files, ${inc_n} includes, ${exempt_n} build-exclusive exemption(s)) ══"
    fi

    # A run that classified NOTHING is hollow: the tree unquestionably includes
    # <windows.h> in dozens of places today.
    gate_require_scanned "${seen:-0}" "$seen_floor" "$GATE" \
        "no include matched the header table at all — the table or the scanner is broken, not the tree"

    if [ "${found:-0}" -ne 0 ]; then
        echo "  $GATE: FAIL — ${found} platform-only header include(s) with no matching guard:" >&2
        sed 's/^/    /' "$w/out.txt" >&2
        echo "" >&2
        echo "  A header that ships only with one platform's SDK must sit inside an" >&2
        echo "  #if/#ifdef whose condition names that platform. Without it the FIRST" >&2
        echo "  build on any other host dies with 'No such file or directory', which" >&2
        echo "  is exactly how main went red on 2026-08-29 with <mach-o/fat.h>." >&2
        echo "" >&2
        echo "  Fix, in order of preference:" >&2
        echo "    1. Guard the hunk:      #if defined(<MACRO>) ... #endif" >&2
        echo "    2. Guard the whole TU, and give the other platforms one" >&2
        echo "       declaration so the file is not an empty translation unit" >&2
        echo "       (ISO C forbids that under -Wpedantic -Werror). See" >&2
        echo "       lib/hotswap/src/hotswap_macho_probe.c for the shape." >&2
        echo "    3. If the file is compiled on ONE platform only, say so in the" >&2
        echo "       BUILD (the LIB_SRCS host branch in Makefile, or the Windows" >&2
        echo "       acceptance catalog) — this gate reads both and exempts what" >&2
        echo "       the build itself excludes. Do not add a list to this script." >&2
        exit 1
    fi

    if [ "$mode" != "quiet" ]; then
        echo "  $GATE: OK — ${seen} platform-only header include(s), every one guarded or build-exclusive."
    fi
    exit 0
    )
}

# ── Self-test ───────────────────────────────────────────────────────────────
# A gate nobody has watched fail is a gate nobody should trust. Every case
# below plants ONE fixture OUTSIDE the repository — never a .c file inside it,
# because writing the Windows macro into a tracked source under lib/ app/
# config/ core/ domain/ ports/ silently enlists that file in
# check-windows-cross-syntax, whose file set is `grep -l` for that token.
FIXTURE_ROOT=""
selftest_cleanup() { [ -n "$FIXTURE_ROOT" ] && rm -rf "$FIXTURE_ROOT"; }

# make_fixture <dir> — a minimal but REAL tree: the LIB_SRCS host branch block
# in the same shape the Makefile uses, a Windows acceptance catalog, and one
# padding source so the floors have something to stand on.
make_fixture() {
    local d="$1"
    mkdir -p "$d/lib/util/src" "$d/lib/platform/src" "$d/lib/platform/tests"
    cat > "$d/Makefile" <<'END_MK'
LIB_SRCS = $(wildcard lib/*/src/*.c)
ifneq ($(filter Linux,$(ZCL_HOST_OS)),)
LIB_SRCS := $(filter-out lib/platform/src/os_sandbox_stub.c,$(LIB_SRCS))
else ifeq ($(ZCL_HOST_WINDOWS),1)
LIB_SRCS := $(filter-out lib/platform/src/os_sandbox_linux.c,$(LIB_SRCS))
else
LIB_SRCS := $(filter-out lib/platform/src/os_sandbox_linux.c,$(LIB_SRCS))
endif
END_MK
    # 12 catalogued Windows-only programs, enough to clear the catalog floor.
    : > "$d/lib/platform/tests/windows_acceptance.mk"
    local i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
        printf 'ZCL_WINDOWS_ACCEPTANCE_p%s_SOURCES := lib/platform/tests/p%s_windows_acceptance.c\n' \
            "$i" "$i" >> "$d/lib/platform/tests/windows_acceptance.mk"
        : > "$d/lib/platform/tests/p${i}_windows_acceptance.c"
    done
    # Padding: enough table-header mentions to clear the candidate/include
    # floors the self-test runs with, all of them correctly guarded.
    for i in 1 2 3 4 5 6 7 8; do
        cat > "$d/lib/util/src/pad$i.c" <<'END_C'
#include <stdio.h>
#if defined(__linux__)
#include <sys/epoll.h>
#endif
END_C
    done
}

# selftest floors: src 10, candidates 5, includes 10, seen 5, wincat 10.
fixture_scan() { run_scan "$1" 10 5 10 5 10 quiet; }

expect_reject() {
    local label="$1" needle="$2" d="$3" out rc
    out="$(fixture_scan "$d" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "SELFTEST FAIL: $label — expected rejection, got a PASS."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    if str_lacks "$out" "$needle"; then
        echo "SELFTEST FAIL: $label — rejected, but never named '$needle'."
        echo "  A gate that fails without naming the offender is a gate nobody can act on."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  selftest ok: $label"
    return 0
}

expect_accept() {
    local label="$1" d="$2" out rc
    out="$(fixture_scan "$d" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "SELFTEST FAIL: $label — expected a PASS, got rejection."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  selftest ok: $label"
    return 0
}

run_selftest() {
    FIXTURE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/zcl-platform-header-guards-selftest.XXXXXX")" || return 2
    trap 'selftest_cleanup; rm -rf "$WORK"' EXIT
    local rc=0 d

    echo "══ $GATE selftest ══"

    # A. THE defect: an Apple SDK header with no guard at all. This is the
    #    literal shape lib/hotswap/src/hotswap_macho_probe.c shipped in
    #    1e1ce62af and the reason this gate exists.
    d="$FIXTURE_ROOT/a"; make_fixture "$d"
    cat > "$d/lib/util/src/probe.c" <<'END_C'
#include <stdio.h>
#include <mach-o/fat.h>
END_C
    expect_reject "A: an unguarded <mach-o/fat.h> is caught" \
                  "mach-o/fat.h" "$d" || rc=1

    # B. The same include, correctly guarded. Positive control: without this
    #    an unconditionally-failing script would pass every other case.
    d="$FIXTURE_ROOT/b"; make_fixture "$d"
    cat > "$d/lib/util/src/probe.c" <<'END_C'
#include <stdio.h>
#if defined(__APPLE__)
#include <mach-o/fat.h>
#endif
END_C
    expect_accept "B: the same include under #if defined(__APPLE__) passes" "$d" || rc=1

    # C. Guarded by the WRONG platform. A grep for "is there any #if above
    #    this line" passes this; naming the required macro is the whole point.
    d="$FIXTURE_ROOT/c"; make_fixture "$d"
    {
        printf '#include <stdio.h>\n'
        printf '#if defined(%s)\n' "_WIN32"
        printf '#include <mach-o/fat.h>\n'
        printf '#endif\n'
    } > "$d/lib/util/src/probe.c"
    expect_reject "C: <mach-o/fat.h> guarded by the Windows macro is caught" \
                  "mach-o/fat.h" "$d" || rc=1

    # D. Inside the #else of an Apple guard — the NON-Apple branch. A depth
    #    tracker that ignores #else calls this guarded; it is the opposite.
    d="$FIXTURE_ROOT/d"; make_fixture "$d"
    cat > "$d/lib/util/src/probe.c" <<'END_C'
#include <stdio.h>
#ifdef __APPLE__
#include <stdlib.h>
#else
#include <mach-o/fat.h>
#endif
END_C
    expect_reject "D: an Apple header in the #else of #ifdef __APPLE__ is caught" \
                  "mach-o/fat.h" "$d" || rc=1

    # E. The mirror: the #else of #ifndef __APPLE__ IS the Apple branch.
    d="$FIXTURE_ROOT/e"; make_fixture "$d"
    cat > "$d/lib/util/src/probe.c" <<'END_C'
#include <stdio.h>
#ifndef __APPLE__
#include <stdlib.h>
#else
#include <mach-o/fat.h>
#endif
END_C
    expect_accept "E: the #else of #ifndef __APPLE__ counts as the Apple branch" "$d" || rc=1

    # F. A guard that opens and closes before the include. The macho defect
    #    would have survived a "does this file mention __APPLE__ anywhere"
    #    grep, because the file did mention it — elsewhere.
    d="$FIXTURE_ROOT/f"; make_fixture "$d"
    cat > "$d/lib/util/src/probe.c" <<'END_C'
#include <stdio.h>
#if defined(__APPLE__)
#define HOST_IS_APPLE 1
#endif
#include <mach-o/fat.h>
END_C
    expect_reject "F: a closed __APPLE__ block earlier in the file does not cover a later include" \
                  "mach-o/fat.h" "$d" || rc=1

    # G. The header named only in a comment is not an include.
    d="$FIXTURE_ROOT/g"; make_fixture "$d"
    cat > "$d/lib/util/src/probe.c" <<'END_C'
#include <stdio.h>
/* On Apple this would need #include <mach-o/fat.h>; it does not here. */
END_C
    expect_accept "G: a header named inside a comment is not a finding" "$d" || rc=1

    # H. __has_include of the very same header is a stronger guard than any
    #    platform macro, and lib/platform/src/os_sandbox_linux.c relies on it.
    d="$FIXTURE_ROOT/h"; make_fixture "$d"
    cat > "$d/lib/util/src/probe.c" <<'END_C'
#include <stdio.h>
#if defined(__has_include)
#  if __has_include(<linux/landlock.h>)
#    include <linux/landlock.h>
#  endif
#endif
END_C
    expect_accept "H: __has_include(<H>) around #include <H> passes" "$d" || rc=1

    # I. A build-exclusive file still owes a guard for a DIFFERENT platform.
    #    os_sandbox_linux.c is Linux-exclusive per the fixture Makefile, which
    #    excuses <sys/epoll.h> and excuses nothing about Apple.
    d="$FIXTURE_ROOT/i"; make_fixture "$d"
    cat > "$d/lib/platform/src/os_sandbox_linux.c" <<'END_C'
#include <stdio.h>
#include <sys/epoll.h>
END_C
    expect_accept "I: a Linux-exclusive source needs no __linux__ guard" "$d" || rc=1

    d="$FIXTURE_ROOT/j"; make_fixture "$d"
    cat > "$d/lib/platform/src/os_sandbox_linux.c" <<'END_C'
#include <stdio.h>
#include <mach-o/fat.h>
END_C
    expect_reject "J: a Linux-exclusive source is still graded for Apple headers" \
                  "mach-o/fat.h" "$d" || rc=1

    # K. An unreadable LIB_SRCS branch block must REFUSE, never pass vacuously.
    #    The exemption set is the one input where an empty parse silently
    #    changes the verdict in both directions.
    d="$FIXTURE_ROOT/k"; make_fixture "$d"
    printf 'LIB_SRCS = $(wildcard lib/*/src/*.c)\n' > "$d/Makefile"
    expect_reject "K: an unparseable LIB_SRCS host branch fails closed" \
                  "could not read the LIB_SRCS per-host branch" "$d" || rc=1

    # L. An emptied scan set must REFUSE, not report clean.
    d="$FIXTURE_ROOT/l"; make_fixture "$d"
    rm -rf "$d/lib/util/src"
    expect_reject "L: an emptied scan set fails closed" "FATAL" "$d" || rc=1

    if [ "$rc" -eq 0 ]; then
        echo "══ selftest: PASS (12/12) ══"
    else
        echo "══ selftest: FAIL ══"
    fi
    return "$rc"
}

# ── Entry ───────────────────────────────────────────────────────────────────
# needles.txt is the pre-filter pattern set, derived from the table so the two
# can never drift.
cut -d'|' -f1 "$WORK/table.txt" | grep -v '^[ \t]*#' | grep . > "$WORK/needles.txt"

case "${1:-}" in
    --self-test) run_selftest; exit $? ;;
    --list)      run_scan "$ROOT" "$SRC_FLOOR" "$CAND_FLOOR" "$INC_FLOOR" \
                          "$SEEN_FLOOR" "$WINCAT_FLOOR" list; exit $? ;;
    "")          run_scan "$ROOT" "$SRC_FLOOR" "$CAND_FLOOR" "$INC_FLOOR" \
                          "$SEEN_FLOOR" "$WINCAT_FLOOR"; exit $? ;;
    *)           echo "usage: $0 [--self-test|--list]" >&2; exit 2 ;;
esac
