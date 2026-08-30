#!/usr/bin/env bash
# Gate — a .c file may not call a POSIX/GNU function whose declaration
# reaches it ONLY through a fortify inline (i.e. only when optimisation is
# on), unless the file sets a feature-test macro before its first #include.
#
# THE BUG CLASS THIS CLOSES (found live, 2026-08-30).
# The build compiles with -std=c23 -D_POSIX_C_SOURCE=200809L
# -D_FORTIFY_SOURCE=2. Under glibc, realpath() is declared by <stdlib.h>
# only when __USE_MISC or __USE_XOPEN_EXTENDED is set, and _POSIX_C_SOURCE
# sets NEITHER. The declaration was arriving by exactly one route: the
# glibc fortify inline that _FORTIFY_SOURCE pulls in -- and glibc activates
# fortify ONLY when optimisation is on. So three translation units were
# compiling purely as a side effect of -O1+, and in C23 an implicit
# declaration is a hard error, not a warning. Every one of them breaks at
# -O0, under -U_FORTIFY_SOURCE, and on any non-glibc libc.
#
# It was found only because a lane tried to run the suite at -O0 to prove
# an encoding was optimisation-independent, and could not compile. Nobody
# builds at -O0 here, so without this gate the whole class stays invisible.
#
# WHY THIS GATE MEASURES INSTEAD OF HARDCODING A LIST.
# Which functions are masked is a property of the LIBC AND COMPILER IN
# USE, not of this repository, and it changes when either is upgraded. A
# hardcoded list would be correct on the day it was written and quietly
# wrong afterwards -- and wrong in the silent direction, since a list that
# has gone stale stops flagging things rather than flagging too much. So
# the gate re-derives the masked set on every run: for each candidate it
# compiles a four-line TU with the project's real flags at -O0 and at -O2,
# and calls the function MASKED when it fails at -O0 and succeeds at -O2.
# That difference is the definition of the defect, expressed directly.
#
# WHAT IT PROVES AND WHAT IT DOES NOT. It is a text scanner over C source,
# not a compiler. It strips comments and string literals first, so prose
# mentioning a name does not trigger it, but it does not expand macros: a
# call produced by macro expansion is invisible to it, and a file that
# obtains the macro from a project header rather than its own #define is
# reported even though it compiles. Both directions are reported plainly.
#
# THE BASELINE IS EMPTY, AND MUST STAY EMPTY. Every caller in the tree was
# fixed when this gate was written (17 files, 2026-08-30) rather than
# recorded as an accepted exception, because unlike a platform seam there
# is no legitimate reason for a file to depend on optimisation for a
# declaration. If this gate fails, add the guard -- do not add a row.
set -u

FAIL=0
SELFTEST=0
[ "${1:-}" = "--selftest" ] && SELFTEST=1

STD="-std=c23"
DEFS="-D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2"

# $CC in this tree is routinely a COMMAND LINE, not a program (the compiler
# cache is invoked as "<path>/zcc cc"). Word-splitting it here is deliberate
# and is why CC_ARGV is an array: passing it as a single argv[0] is a real
# bug that cost a suite failure on 2026-08-30.
if [ -n "${CC:-}" ]; then
    read -r -a CC_ARGV <<< "$CC"
else
    CC_ARGV=(cc)
fi

WORK="$(mktemp -d)" || { echo "check-fortify-masked-decls: cannot create work dir" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT

# --- control probe: fail closed if we cannot compile at all -----------------
printf '#include <stdlib.h>\nint main(void){return 0;}\n' > "$WORK/control.c"
if ! "${CC_ARGV[@]}" $STD $DEFS -O0 -c "$WORK/control.c" -o "$WORK/control.o" >/dev/null 2>&1; then
    echo "check-fortify-masked-decls: FAIL — the control probe does not compile with" >&2
    echo "  CC=\"${CC_ARGV[*]}\" $STD $DEFS -O0" >&2
    echo "  The gate cannot measure anything, so it refuses rather than passing vacuously." >&2
    exit 2
fi

# Candidates: POSIX/GNU functions that glibc guards behind a feature-test
# macro AND also gives a fortify inline, plus near neighbours. Being on this
# list asserts nothing; only the measurement below decides.
CANDIDATES="realpath ptsname_r getwd gethostname mktemp getcwd readlink readlinkat
stpcpy stpncpy mempcpy strcasestr memmem strsep strdup strndup
asprintf vasprintf getline getdelim
usleep random srandom initstate setstate lockf
pread pwrite ftruncate truncate fchdir symlink chroot
wcpcpy wcpncpy"

MASKED=""
for fn in $CANDIDATES; do
    cat > "$WORK/probe.c" <<EOF
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>
void *zcl_probe_sink;
void zcl_probe(void) { zcl_probe_sink = (void *)&$fn; }
EOF
    "${CC_ARGV[@]}" $STD $DEFS -O0 -c "$WORK/probe.c" -o "$WORK/probe.o" >/dev/null 2>&1
    rc0=$?
    "${CC_ARGV[@]}" $STD $DEFS -O2 -c "$WORK/probe.c" -o "$WORK/probe.o" >/dev/null 2>&1
    rc2=$?
    if [ $rc0 -ne 0 ] && [ $rc2 -eq 0 ]; then
        MASKED="$MASKED $fn"
    fi
done
MASKED="${MASKED# }"

if [ -z "$MASKED" ]; then
    echo "check-fortify-masked-decls: PASSED — this toolchain masks no candidate"
    echo "  declaration behind optimisation (control probe compiled, so the"
    echo "  measurement ran). CC=\"${CC_ARGV[*]}\""
    [ $SELFTEST -eq 1 ] && { echo "check-fortify-masked-decls: selftest cannot run without a masked function" >&2; exit 2; }
    exit 0
fi

# --- comment/string stripper ------------------------------------------------
cat > "$WORK/strip.awk" <<'AWKEOF'
BEGIN { inblk = 0 }
{
    line = $0; out = ""; i = 1; n = length(line)
    while (i <= n) {
        c = substr(line, i, 1); d = substr(line, i, 2)
        if (inblk) {
            if (d == "*/") { inblk = 0; i += 2 } else { i++ }
            continue
        }
        if (d == "/*") { inblk = 1; i += 2; continue }
        if (d == "//") { break }
        if (c == "\"" || c == "'") {
            q = c; i++
            while (i <= n) {
                e = substr(line, i, 1)
                if (e == "\\") { i += 2; continue }
                if (e == q) { i++; break }
                i++
            }
            out = out " "
            continue
        }
        out = out c; i++
    }
    print out
}
AWKEOF

# --- scan -------------------------------------------------------------------
scan_file() {
    f="$1"
    awk -f "$WORK/strip.awk" "$f" > "$WORK/stripped.c" || { echo "  $f: comment stripper failed — refusing to report this file clean"; return 1; }
    hits=""
    for fn in $MASKED; do
        if grep -qE "(^|[^A-Za-z0-9_])$fn[[:space:]]*\(" "$WORK/stripped.c"; then
            hits="$hits $fn"
        fi
    done
    [ -z "$hits" ] && return 0
    li="$(grep -n '^[[:space:]]*#[[:space:]]*include' "$f" | head -1 | cut -d: -f1)"
    [ -z "$li" ] && li=$(( $(wc -l < "$f") + 1 ))
    if head -n "$li" "$f" | grep -qE '^[[:space:]]*#[[:space:]]*define[[:space:]]+(_DEFAULT_SOURCE|_GNU_SOURCE|_XOPEN_SOURCE|_BSD_SOURCE)'; then
        return 0
    fi
    echo "  $f calls:$hits"
    return 1
}

OFFENDERS="$WORK/offenders.txt"
: > "$OFFENDERS"

if [ $SELFTEST -eq 1 ]; then
    first="${MASKED%% *}"
    mkdir -p "$WORK/st"
    printf "#include <stdlib.h>\nvoid f(void){ (void)%s(\"a\", 0); }\n" "$first" > "$WORK/st/bad.c"
    printf "#if !defined(_DEFAULT_SOURCE)\n#define _DEFAULT_SOURCE\n#endif\n#include <stdlib.h>\nvoid f(void){ (void)%s(\"a\", 0); }\n" "$first" > "$WORK/st/good.c"
    printf '/* %s( is only named in prose here */\n#include <stdlib.h>\nvoid f(void){}\n' "$first" > "$WORK/st/comment.c"
    st=0
    scan_file "$WORK/st/bad.c" >/dev/null   && { echo "selftest: FAILED — unguarded caller of $first was not flagged" >&2; st=1; }
    scan_file "$WORK/st/good.c" >/dev/null  || { echo "selftest: FAILED — guarded caller of $first was flagged" >&2; st=1; }
    scan_file "$WORK/st/comment.c" >/dev/null || { echo "selftest: FAILED — a comment mentioning $first was flagged" >&2; st=1; }
    if [ $st -ne 0 ]; then
        echo "check-fortify-masked-decls: SELFTEST FAILED" >&2
        exit 1
    fi
    echo "check-fortify-masked-decls: selftest PASSED (masked set measured as:$MASKED)"
    exit 0
fi

# Pre-filter: a file that never mentions a masked name anywhere -- comment,
# string or code -- cannot be an offender, so it is not worth stripping.
# This is a SUPERSET of the real scan (it still matches prose and literals);
# scan_file re-checks each survivor against stripped text. Cuts a 25s
# whole-tree strip to well under a second without changing any verdict.
GREPPAT="$(printf '%s' "$MASKED" | tr ' ' '\n' | sed 's/^/(^|[^A-Za-z0-9_])/; s/$/[[:space:]]*\\(/' | paste -sd'|' -)"
while IFS= read -r f; do
    [ -f "$f" ] || continue
    scan_file "$f" >> "$OFFENDERS" || FAIL=1
done < <(git grep -lE "$GREPPAT" -- '*.c')

if [ $FAIL -ne 0 ]; then
    echo "check-fortify-masked-decls: FAILED" >&2
    echo "" >&2
    echo "These files call a function this toolchain declares ONLY through the" >&2
    echo "fortify inline, which glibc enables only when optimisation is on:" >&2
    echo "" >&2
    cat "$OFFENDERS" >&2
    echo "" >&2
    echo "Measured masked set on CC=\"${CC_ARGV[*]}\":$MASKED" >&2
    echo "" >&2
    echo "Each one compiles today by accident of -O2 and is a hard C23 error at" >&2
    echo "-O0, under -U_FORTIFY_SOURCE, and on any non-glibc libc. Fix by adding" >&2
    echo "this BEFORE the file's first #include (after them it does nothing --" >&2
    echo "feature-test macros are read when <features.h> is first pulled in):" >&2
    echo "" >&2
    echo "    #if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)" >&2
    echo "    #define _DEFAULT_SOURCE" >&2
    echo "    #endif" >&2
    echo "" >&2
    echo "The baseline for this gate is empty by design. Add the guard, not a row." >&2
    exit 1
fi

echo "check-fortify-masked-decls: PASSED (masked set:$MASKED; no unguarded caller)"
exit 0
