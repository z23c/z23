#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check-toolchain.sh — prove $CC can compile C23 before the build spends
# minutes on vendor archives and hundreds of translation units.
#
# WHY THIS EXISTS. The tree compiles every TU with -std=c23. gcc 13 does
# not know that flag (it wants -std=c2x) and reports
#
#     gcc: error: unrecognized command-line option '-std=c23';
#     did you mean '-std=c2x'?
#
# once per file, after a vendor bootstrap that already ran for minutes, with
# no documented minimum compiler in the Makefile. A stranger bringing a node
# up on stable Linux cannot tell whether the project is broken or their
# toolchain is. This script answers that question by compiling an empty
# translation unit — capability, not a version parse — and prints what was
# tried, what their compiler is, the minimum that works, and how to point
# the build at a newer one.
#
# Exit: 0 if $CC accepts -std=c23, non-zero otherwise.
#   --selftest  prove a gcc-13-shaped wrapper is refused and a usable
#               compiler is accepted. Does not require gcc 13 to be installed.

set -euo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tools/scripts/sh_str.sh
source "$REPO_ROOT/tools/scripts/sh_str.sh"

CC="${CC:-cc}"

WORK=""
cleanup() {
    [ -n "$WORK" ] && rm -rf -- "$WORK"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

# First argv word of $CC: the program the user named (cc, gcc-14, a wrapper).
cc_prog() {
    # Intentional split: Make passes wrappers as `zcc cc` / `ccache gcc`.
    # shellcheck disable=SC2086
    set -- $CC
    printf '%s' "$1"
}

# Run $CC with the given args. Word-splitting of $CC is the contract: the
# Makefile wraps the compiler in zcc/ccache as multiple tokens.
run_cc() {
    # shellcheck disable=SC2086
    ${CC} "$@"
}

compiler_id() {
    local out
    set +e
    out="$(run_cc --version 2>/dev/null)"
    set -e
    if [ -n "$out" ]; then
        printf '%s\n' "$out" | sed -n '1p'
        return 0
    fi
    set +e
    out="$(run_cc -v 2>&1)"
    set -e
    if [ -n "$out" ]; then
        printf '%s\n' "$out" | sed -n '1p'
        return 0
    fi
    printf '%s' "$CC"
}

# Compile an empty translation unit with -std=<flag>. 0 = accepted.
# Captures the compiler's stderr/stdout in PROBE_ERR for the failure report.
PROBE_ERR=""
probe_std() {
    local std="$1" src obj rc
    src="$WORK/empty.c"
    obj="$WORK/empty-$std.o"
    : > "$src"
    rm -f "$obj"
    set +e
    PROBE_ERR="$(run_cc -std="$std" -c "$src" -o "$obj" 2>&1)"
    rc=$?
    set -e
    return "$rc"
}

print_failure() {
    local tried="$1" ident="$2" diagnosis="$3"
    printf 'check-toolchain: this compiler cannot compile C23.\n' >&2
    printf '\n' >&2
    printf '  Tried:     %s -std=c23  (empty translation unit)\n' "$tried" >&2
    printf '  Compiler:  %s\n' "$ident" >&2
    printf '  Diagnosis: %s\n' "$diagnosis" >&2
    printf '\n' >&2
    printf '  Minimum:   gcc 14 or newer. Apple Clang 17 is also known to work.\n' >&2
    printf '\n' >&2
    printf '  Next:      point the build at a newer compiler, for example:\n' >&2
    printf '               make CC=gcc-14\n' >&2
}

check() {
    local ident diagnosis prog
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-check-toolchain.XXXXXX")"

    prog="$(cc_prog)"
    if ! command -v "$prog" >/dev/null 2>&1 && [ ! -x "$prog" ]; then
        print_failure "$CC" "'$prog' is not on PATH and is not an executable" \
            "no C compiler was found."
        exit 1
    fi

    ident="$(compiler_id)"

    if probe_std c23; then
        printf 'check-toolchain: ok — %s accepts -std=c23\n' "$CC"
        exit 0
    fi
    c23_err="$PROBE_ERR"

    if probe_std c2x; then
        diagnosis="this compiler accepts -std=c2x but not -std=c23. It is too old for this project."
    else
        diagnosis="this compiler accepts neither -std=c23 nor -std=c2x. It is not a C compiler this project recognises."
    fi
    print_failure "$CC" "$ident" "$diagnosis"
    if [ -n "$c23_err" ]; then
        printf '\n  Compiler output:\n' >&2
        printf '%s\n' "$c23_err" | sed 's/^/    /' >&2
    fi
    exit 1
}

# ── --selftest ────────────────────────────────────────────────────────────
# A gate nobody has seen fail is not a gate. Two wrappers stand in for
# compilers this host does not have: one gcc-13-shaped (rejects -std=c23,
# accepts -std=c2x) and one that rejects both flags. The pass case uses the
# real compiler on this machine.
run_selftest() {
    local work rc out good
    work="$(mktemp -d "${TMPDIR:-/tmp}/zcl-check-toolchain-selftest.XXXXXX")"
    trap 'rm -rf -- "$work"' EXIT

    if [ -n "${CHECK_TOOLCHAIN_GOOD_CC:-}" ]; then
        good="$CHECK_TOOLCHAIN_GOOD_CC"
    else
        good=cc
    fi

    cat > "$work/old-cc" <<'EOF'
#!/bin/sh
for arg in "$@"; do
    if [ "$arg" = "-std=c23" ]; then
        echo "gcc: error: unrecognized command-line option '-std=c23'; did you mean '-std=c2x'?" >&2
        exit 1
    fi
done
if [ "${1:-}" = "--version" ] || [ "${1:-}" = "-v" ]; then
    echo "gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0"
    exit 0
fi
exit 0
EOF
    chmod +x "$work/old-cc"

    cat > "$work/not-cc" <<'EOF'
#!/bin/sh
for arg in "$@"; do
    case "$arg" in
        -std=c23|-std=c2x)
            echo "not-a-c-compiler: unrecognized option $arg" >&2
            exit 1
            ;;
    esac
done
if [ "${1:-}" = "--version" ] || [ "${1:-}" = "-v" ]; then
    echo "not-a-c-compiler 0.0"
    exit 0
fi
exit 0
EOF
    chmod +x "$work/not-cc"

    set +e
    out="$(CC="$work/old-cc" "$SCRIPT" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        printf 'check-toolchain --selftest: FAIL — gcc-13 wrapper was accepted\n' >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi
    if str_lacks "$out" "-std=c23"; then
        printf 'check-toolchain --selftest: FAIL — old-compiler message did not say what was tried\n' >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi
    if str_lacks "$out" "13.3.0"; then
        printf 'check-toolchain --selftest: FAIL — old-compiler message did not name the compiler\n' >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi
    if str_lacks "$out" "too old"; then
        printf 'check-toolchain --selftest: FAIL — gcc-13 wrapper was not diagnosed as too old\n' >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi
    if str_lacks "$out" "gcc 14"; then
        printf 'check-toolchain --selftest: FAIL — old-compiler message did not name gcc 14\n' >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi
    if str_lacks "$out" "make CC=gcc-14"; then
        printf 'check-toolchain --selftest: FAIL — old-compiler message did not say how to point the build at a newer compiler\n' >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi
    if str_contains "$out" "not a C compiler this project recognises"; then
        printf 'check-toolchain --selftest: FAIL — gcc-13 wrapper was misdiagnosed as not-a-C-compiler\n' >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi

    set +e
    out="$(CC="$work/not-cc" "$SCRIPT" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        printf 'check-toolchain --selftest: FAIL — not-a-C-compiler wrapper was accepted\n' >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi
    if str_lacks "$out" "not a C compiler this project recognises"; then
        printf 'check-toolchain --selftest: FAIL — neither-std wrapper was not distinguished from too-old\n' >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi
    if str_contains "$out" "too old"; then
        printf 'check-toolchain --selftest: FAIL — neither-std wrapper was misdiagnosed as too old\n' >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi

    set +e
    out="$(CC="$good" "$SCRIPT" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        printf 'check-toolchain --selftest: FAIL — usable compiler %s was rejected\n' "$good" >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi
    if str_lacks "$out" "accepts -std=c23"; then
        printf 'check-toolchain --selftest: FAIL — usable compiler produced no success line\n' >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi

    printf 'check-toolchain --selftest: PASS\n'
    exit 0
}

case "${1:-}" in
    --selftest) run_selftest ;;
    "")         check ;;
    *)
        printf 'usage: %s [--selftest]\n' "$SCRIPT" >&2
        exit 2
        ;;
esac
