#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_clang_portability.sh — SECOND-COMPILER portability gate.
#
# The node ships as one whole-program GCC build. Nothing in the repo ever
# asked a second C compiler whether the tree is even well-formed, so
# GCC-only spellings (a `/* fallthrough */` comment GCC honours and clang
# does not, a declaration that only exists because glibc's _FORTIFY_SOURCE
# wrapper pulled it in, a truncating snprintf GCC's analysis misses) landed
# invisibly. This gate runs a whole-tree
#
#     clang -std=c23 -Wall -Wextra -Werror -pedantic -Wimplicit-fallthrough
#           -fsyntax-only
#
# over the SAME source set the node binary is built from, and ratchets the
# realized diagnostic sites against a recorded baseline. A patch that adds a
# new clang diagnostic fails; the recorded pre-existing sites are a visible
# to-do list, not a silent allowance.
#
# Cost: measured 3.0 s wall at 32 workers over 1174 translation units on the
# dev reference host — cheaper than most gates in the umbrella.
#
# SKIP CONTRACT: when clang is absent this prints a loud SKIP and exits 0,
# exactly like `make ci-symbol-floor` does when objdump/ldd are missing. An
# outside contributor without clang installed must never be blocked by a gate
# whose tool they do not have.
#
# NOTE ON LTO SPELLING: the node's CFLAGS carry `-flto=auto`, which is a GCC
# spelling — clang wants `-flto=thin` (or plain `-flto`). This gate is
# -fsyntax-only, so it never reaches a link and never expands LTO flags; the
# difference only matters if a full clang LINK lane is added later. Do not
# copy `-flto=auto` into a clang link.
#
# Flag replication. The rule is: reproduce the node's PREPROCESSOR-visible
# environment exactly, then add warnings. Two points deserve explanation.
#
#   -O3 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2   Copied verbatim from the node
#       CFLAGS, and load-bearing even though -fsyntax-only never generates
#       code. glibc only arms its _FORTIFY_SOURCE wrapper headers when
#       __OPTIMIZE__ is defined, and those wrappers incidentally declare a
#       few POSIX functions (realpath) that _POSIX_C_SOURCE=200809L alone
#       leaves hidden. Drop the -O and the tree reports phantom "undeclared
#       identifier" errors that say nothing about clang. -fsyntax-only stops
#       before IR generation, so the -O costs nothing.
#       (Passing -D_DEFAULT_SOURCE instead was tried and rejected: several
#       lib/net TUs #define it themselves, so the command-line define
#       collides into -Wmacro-redefined — a gate artifact, not a finding.)
#
#   -Wno-gnu-zero-variadic-macro-arguments   util/log_macros.h and its
#       callers use the GNU `, ##__VA_ARGS__` comma-elision extension in
#       every LOG_* macro. GCC accepts it silently under -pedantic; clang
#       diagnoses it once per expansion, which would bury every real finding
#       under thousands of duplicates of one known, deliberate, both-compilers
#       -supported extension. The standard C23 spelling is `__VA_OPT__(,)`;
#       converting the LOG_* family is a separate change. This is the ONLY
#       warning class this gate switches off.
#
# The two sentences below name node flags in prose; they are not a compile
# surface, and both flags are annotated at their real use sites further down.
# suppression-ok: prose, not a build surface
# The node's `-Wno-unused-result` IS copied (clang spells it the same). Its
# suppression-ok: same prose sentence, continued
# `-Wno-stringop-overflow` is NOT: clang has no -Wstringop-overflow, and an
# unknown -Wno-* is itself an error under -Werror (-Wunknown-warning-option).
# Same class of trap as -flto=auto above — check a GCC flag exists in clang
# before adding it here.
#
# KNOWN BLIND SPOT: with _FORTIFY_SOURCE armed (as the real build has it),
# glibc redirects snprintf through __snprintf_chk, and clang's
# -Wformat-truncation stops seeing the call. Running this gate's flag set
# with `-U_FORTIFY_SOURCE` and no -O surfaces nine "'snprintf' will always
# be truncated" sites in the stage/blocker reason builders; those are real
# and worth fixing, but they are hidden from the faithful-to-the-build
# configuration this gate deliberately runs.
#
# SECOND COMPILER, NOT ONLY CLANG: point ZCL_CC at gcc and the same scan runs
# under GCC's front end with GCC's spelling of the diagnostic-format flags and
# its own baseline file. That is what lets one script answer "does this patch
# compile" for BOTH compilers in CI. Default is clang, because clang is the
# one the node is never built with.
#
# Modes:
#   (default)              scan + ratchet against the baseline; exit 1 on any
#                          new diagnostic site.
#   ZCL_LINT_MODE=UPDATE   re-record the baseline from the current tree.
#                          Never runs under `make lint`.
#   --self-test            prove the gate actually trips: compile a planted
#                          violating TU and assert the compiler rejects it.
#                          Guards against a hollow pass from a mis-built flag
#                          set.
#   --sites                print every diagnostic the tree currently produces
#                          (the to-do list the baseline summarizes).
#
# Env:
#   ZCL_CC             compiler to run (default: clang; gcc also supported)
#   ZCL_CC_JOBS        parallel workers (default: nproc, capped at 32)
#   ZCL_PORTABILITY_SCOPE
#       Path to a file of repo-relative paths (one per line) — normally the
#       set of files a pull request touched. When set:
#         * a diagnostic in a LISTED file FAILS, baseline or not: your patch
#           must compile;
#         * a diagnostic elsewhere that exceeds the baseline is reported as a
#           NOTE, not a failure.
#       This exists because the baseline is recorded against ONE compiler
#       build, and a CI runner's compiler is a different version with a
#       different diagnostic set. Scoping to the diff keeps the CI verdict
#       about the contributor's code instead of about GCC/clang version skew.
#       Unset (the `make lint` path) = full-tree ratchet.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

CC_BIN="${ZCL_CC:-clang}"
# Overridable so --self-test can aim the parse at a deliberately truncated
# copy and prove the coverage check below catches a layer that fell out.
MAKEFILE="${ZCL_CLANG_PORTABILITY_MAKEFILE:-Makefile}"

compiler_result_proven() {
    local log=$1 rc=$2
    local crash_re='internal compiler error|cannot execute|CreateProcess|unable to execute command|frontend command failed|PLEASE submit a bug report|segmentation fault|stack dump|out of memory|killed signal|error in backend|LLVM ERROR|access violation|cc1\.exe:'
    grep -aiEq "$crash_re" "$log" && return 1
    if [ "$rc" = 0 ]; then
        if grep -aEq '^[A-Za-z0-9_./\\:-]+\.[ch]:[0-9]+:[0-9]+: (fatal )?error:' \
                "$log"; then
            return 1
        fi
        return 0
    fi
    [ "$rc" = 1 ] || return 1
    grep -aEq '^[A-Za-z0-9_./\\:-]+\.[ch]:[0-9]+:[0-9]+: (fatal )?(error|warning):' \
        "$log" || return 1
    return 0
}

# Known floor for the scan set. The node's release source set is ~1174 TUs;
# anything under this means the Makefile variable parse below broke or a
# whole layer moved, and a "clean" verdict off that would be hollow.
SRC_FLOOR=900

# Common to both front ends. This gate's job is to reproduce the node's own
# compile environment and then ADD warnings, so it must carry the same
# suppressions the node build carries — otherwise it reports a diagnostic
# population the real build would never see, and its baseline measures a
# configuration nobody compiles.
WARN_FLAGS=(
    -std=c23
    -Wall
    -Wextra
    -Werror
    -pedantic
    -Wimplicit-fallthrough
    -fsyntax-only
    # The 119 sites behind this flag are tracked and driven to zero by the
    # node's ZCL_WARN_UNUSED_RESULT, not by this scanner.
    # suppression-ok: mirrors the node build so the baseline measures reality
    -Wno-unused-result
)

# The node CFLAGS' preprocessor-visible subset — see the header block on why
# the optimization level is not optional here.
BUILD_ENV_FLAGS=(
    -O3
    -U_FORTIFY_SOURCE
    -D_FORTIFY_SOURCE=2
)

DEFINES=(
    -D_POSIX_C_SOURCE=200809L
    -DZCL_AR_ENFORCE
    # Build-identity macros the node's CFLAGS inject; any value parses.
    -DZCL_BUILD_SOURCE_ID=\"clang-portability-gate\"
    -DZCL_BUILD_CLEAN=1
)
# Mirror the real build's platform defines: once any TU includes a Darwin
# SDK header (<sys/sysctl.h> for the arm64 feature probe), the SDK's own
# headers need _DARWIN_C_SOURCE and the st_*timespec aliases, or the pass
# fails inside the SDK instead of grading our sources.
if [[ "$(uname -s)" == "Darwin" ]]; then
    DEFINES+=(
        -D_DARWIN_C_SOURCE
        -Dst_atim=st_atimespec
        -Dst_mtim=st_mtimespec
        -Dst_ctim=st_ctimespec
    )
fi

echo "══ LINT: clang portability (second-compiler whole-tree syntax pass) ══"

# ── SKIP contract ────────────────────────────────────────────────────────
if ! command -v "$CC_BIN" >/dev/null 2>&1; then
    echo "  check-clang-portability: SKIP — '$CC_BIN' is not installed."
    echo "  This gate is a SECOND-compiler cross-check, not a build"
    echo "  requirement: the node builds with GCC and every other gate still"
    echo "  applies. Install clang (apt install clang) to run it, or set"
    echo "  ZCL_CC=<path>. Skipping is not a failure."
    exit 0
fi

# ── SKIP contract, part two: compiler VERSION skew ───────────────────────
# A ratchet baseline is a statement about one compiler version. A different
# version legitimately reports a different set, so running this baseline
# against another one measures the compiler, not the change.
#
# This is not hypothetical. The baseline was recorded with clang 20; the
# project's own build host carries clang 18, and clang 18 rejects STANDARD
# C23 as an extension:
#
#   lib/sapling/src/circuit_gadgets.c:475:38: error: binary integer literals
#     are a GNU extension [-Werror,-Wgnu-binary-literal]
#
# Binary literals are C23 (they are one of the few genuinely-C23 constructs
# in this tree), and clang 18 accepts -std=c23 while still diagnosing them.
# It also rejects the "vaes" and "sha" CPU feature strings that GCC — the
# compiler that actually ships the node — accepts. Nineteen "failures" in one
# file and two in another, none of them defects.
#
# Failing a contributor's `make lint` because their clang is a different
# version would be this gate reporting on the wrong thing, loudly. SKIP
# instead, naming both versions, so the skip is visible and actionable rather
# than silent. Same principle as the absent-compiler case above.
BASELINE_CC_MAJOR="$(sed -n 's/^#.*clang version \([0-9][0-9]*\)\..*/\1/p' \
    "$SCRIPT_DIR/portability_baseline.clang.txt" 2>/dev/null | head -1)"
LOCAL_CC_MAJOR="$("$CC_BIN" --version 2>/dev/null \
    | sed -n 's/.*clang version \([0-9][0-9]*\)\..*/\1/p' | head -1)"
if [ -n "$BASELINE_CC_MAJOR" ] && [ -n "$LOCAL_CC_MAJOR" ] &&
   [ "$LOCAL_CC_MAJOR" != "$BASELINE_CC_MAJOR" ] &&
   [ "${1:-}" != "--self-test" ] &&
   [ "${ZCL_INTERNAL_CLANG_COVERAGE_SELFTEST:-0}" != 1 ]; then
    echo "  check-clang-portability: SKIP — compiler version skew."
    echo "    baseline recorded with: clang $BASELINE_CC_MAJOR"
    echo "    installed here:         clang $LOCAL_CC_MAJOR"
    echo "  A ratchet baseline is only meaningful against the version it was"
    echo "  recorded with; judging one clang's output by another clang's"
    echo "  baseline measures the compilers, not the change. To run the gate"
    echo "  here, re-record it and commit the result:"
    echo "    ZCL_CC=$CC_BIN ZCL_LINT_MODE=UPDATE $0"
    echo "  Skipping is not a failure."
    exit 0
fi

# ── Compiler family: picks the diagnostic-format flags and the baseline ──
# Both front ends must be told "one line per diagnostic, no caret art, no
# colour" or the parsed log stops being stable, but they spell it
# differently — and an unknown -f/-W is itself fatal under -Werror.
cc_version_first="$("$CC_BIN" --version 2>/dev/null | head -1)"
if grep -qi clang <<<"$cc_version_first"; then
    FAMILY=clang
    WARN_FLAGS+=(
        # The one real suppression — see the header block.
        -Wno-gnu-zero-variadic-macro-arguments
        -fno-caret-diagnostics
        -fno-color-diagnostics
        -fno-diagnostics-fixit-info
    )
else
    FAMILY=gcc
    WARN_FLAGS+=(
        # Carried by the node CFLAGS; GCC-only, absent from clang. Retiring it
        # is owned by the node's ZCL_WARN_STRINGOP_OVERFLOW, not by this gate.
        # suppression-ok: mirrors the node build so the baseline measures reality
        -Wno-stringop-overflow
        -fno-diagnostics-show-caret
        -fdiagnostics-color=never
    )
fi
BASELINE="tools/lint/portability_baseline.${FAMILY}.txt"

# ── Include search path ──────────────────────────────────────────────────
# Superset by construction (every include/ root under the layer dirs); an
# extra -I can only add a search path, and headers are namespaced under
# include/<module>/ so there is nothing to collide.
mapfile -t INC_DIRS < <(find app config lib core domain application adapters \
    ports -maxdepth 3 -type d -name include 2>/dev/null | sort)
gate_require_scanned "${#INC_DIRS[@]}" 20 check-clang-portability \
    "no include/ roots found — the layer directory layout moved"

INC_FLAGS=()
for d in "${INC_DIRS[@]}"; do INC_FLAGS+=("-I$d"); done
# Fixed roots the Makefile adds by hand (TOOLS_INCLUDES, DEVLOOP_INCLUDES,
# vendor headers).
INC_FLAGS+=(-Itools -Itools/dev -Ivendor/include)

# ── Source set: derived from the Makefile, not hardcoded ─────────────────
# The build's layer lists are the single source of truth. Parsing them here
# means a new lib module or app dir is covered the day it is added, instead
# of silently falling out of the gate's scan.
makefile_list() {
    awk -v var="$1" '
        $0 ~ "^" var "[[:space:]]*[:+]?=" { inb = 1; sub("^" var "[[:space:]]*[:+]?=", "") }
        inb {
            line = $0
            cont = (line ~ /\\[[:space:]]*$/)
            sub(/\\[[:space:]]*$/, "", line)
            printf "%s ", line
            if (!cont) exit
        }
    ' "$MAKEFILE"
}

# APP_DIRS / LIB_MODULES / DOMAIN_CONTEXTS come from the shared reader rather
# than the local awk above: LIB_MODULES is no longer a literal in the Makefile
# at all — it is derived from config/lib_module_order.def — so scraping its
# assignment line here would yield the $(shell ...) text and silently collapse
# the lib/ arm of this scan to nothing. CORE_CONTEXTS and APPLICATION_CONTEXTS
# have no shared reader yet, so they keep using it.
# shellcheck source=tools/lint/repo_shape.sh
. "$(dirname "${BASH_SOURCE[0]}")/repo_shape.sh"
APP_DIRS="${ZCL_APP_SHAPES[*]}"
LIB_MODULES="${ZCL_LIB_MODULES[*]}"
CORE_CONTEXTS="$(makefile_list CORE_CONTEXTS)"
DOMAIN_CONTEXTS="${ZCL_DOMAIN_CONTEXTS[*]}"
APPLICATION_CONTEXTS="$(makefile_list APPLICATION_CONTEXTS)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-clang-portability.XXXXXX")" || {
    echo "check-clang-portability: FATAL — mktemp failed." >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT

SRC_RAW="$WORK/srcs.raw"
: > "$SRC_RAW"
collect() { find "$1" -maxdepth 1 -name '*.c' -type f 2>/dev/null >> "$SRC_RAW"; }

for d in $APP_DIRS;             do collect "app/$d/src"; done
for m in $LIB_MODULES;          do collect "lib/$m/src"; done
for c in $CORE_CONTEXTS;        do collect "core/$c/src"; done
for c in $DOMAIN_CONTEXTS;      do collect "domain/$c/src"; done
for c in $APPLICATION_CONTEXTS; do collect "application/$c/src"; done
collect config/src
collect adapters/outbound/persistence/src
collect tools/dev
collect tools/command
collect src

# `/_` marks an ephemeral source the build itself filters out
# (zcl_filter_ephemeral_sources in the Makefile) — mirror that exactly.
SRC_LIST="$WORK/srcs.txt"
grep -v '/_' "$SRC_RAW" | sort -u > "$SRC_LIST"
SRC_COUNT="$(wc -l < "$SRC_LIST")"

gate_require_scanned "$SRC_COUNT" "$SRC_FLOOR" check-clang-portability \
    "parsed APP_DIRS/LIB_MODULES/CORE_CONTEXTS from $MAKEFILE — a variable rename there empties this scan"

# ── Coverage: did the scan reach every source it claims to cover? ────────
# SRC_FLOOR above answers "did the parse produce anything at all". It cannot
# answer "did it produce everything": measured 2026-08-30 the realized set is
# 2069 sources against a floor of 900, so this gate could silently lose 1169
# of them — 56% of its own surface — and still report clean. The header above
# is explicit that this scan set is derived from the Makefile so a new module
# is covered the day it is added; nothing until now PROVED that derivation
# still enumerates everything, and LIB_MODULES has already once been one
# refactor away from collapsing this scan (see the note beside the parse).
#
# The expectation is derived from the git index and a structural rule about
# where a compiled source lives — deliberately NOT from the Makefile, so the
# oracle and the scan cannot fail together. A layer list that silently loses
# a module now names the dropped files instead of shrinking a count.
#
# The git pathspec is a superset (git's `*` crosses `/`), so the shape filter
# below narrows it to exactly the depth this gate's `find -maxdepth 1`
# reaches. `/_` mirrors the build's own ephemeral-source filter.
#
# lib/test is excluded because config/lib_module_order.def says so in as many
# words: "Not listed here: lib/test (the test runner is not part of the
# production link order)". It is not a lib module, this gate never compiled
# it, and pulling its 1040 sources in here would be a scope change wearing a
# coverage check's clothes.
#
# Allowance 0, shrink-only: the Makefile-derived scan reaches every source
# the oracle names today, both directions empty (expected 2069, scanned 2069,
# missing 0), so any shortfall at all is UNPROVEN.
CLANG_COVERAGE_ALLOWANCE="${ZCL_CLANG_PORTABILITY_COVERAGE_ALLOWANCE:-0}"
if [ "${ZCL_CLANG_PORTABILITY_COVERAGE:-1}" = "1" ]; then
    gate_git_oracle "$WORK/oracle.raw" check-clang-portability \
        'app/*/src/*.c' 'lib/*/src/*.c' 'core/*/src/*.c' 'domain/*/src/*.c' \
        'application/*/src/*.c' 'config/src/*.c' \
        'adapters/outbound/persistence/src/*.c' \
        'tools/dev/*.c' 'tools/command/*.c' 'src/*.c' ':!:lib/test/*'
    grep -vF '/_' "$WORK/oracle.raw" \
        | grep -E '^(app|lib|core|domain|application)/[^/]+/src/[^/]+\.c$|^config/src/[^/]+\.c$|^adapters/outbound/persistence/src/[^/]+\.c$|^tools/(dev|command)/[^/]+\.c$|^src/[^/]+\.c$' \
        > "$WORK/oracle.txt" || true
    gate_require_coverage "$SRC_LIST" "$WORK/oracle.txt" \
        "$CLANG_COVERAGE_ALLOWANCE" check-clang-portability \
        ZCL_CLANG_PORTABILITY_COVERAGE_ALLOWANCE \
        "A named file is a compiled source this gate never reached. Check that its layer still appears in APP_DIRS/LIB_MODULES/CORE_CONTEXTS/DOMAIN_CONTEXTS/APPLICATION_CONTEXTS as $MAKEFILE and config/lib_module_order.def define them — a layer that drops out of those lists drops out of this gate silently."
fi

# ── Self-test: prove the flag set actually rejects a violation ────────────
if [ "${1:-}" = "--self-test" ]; then
    probe="$WORK/probe.c"
    cat > "$probe" <<'PROBE'
int zcl_gate_probe(int a);
int zcl_gate_probe(int a)
{
    int unused_on_purpose = a + 1;
    switch (a) {
    case 1:
        a++;
    case 2:
        a += 2;
        break;
    default:
        break;
    }
    return a;
}
PROBE
    if "$CC_BIN" "${WARN_FLAGS[@]}" "${BUILD_ENV_FLAGS[@]}" "${DEFINES[@]}" "$probe" >/dev/null 2>&1; then
        echo "FAIL: --self-test — the flag set ACCEPTED a TU with an unused"
        echo "  variable and an unannotated switch fall-through. The gate is"
        echo "  hollow: it would report 'clean' on real violations."
        exit 1
    fi
    clean="$WORK/clean.c"
    printf 'int zcl_gate_clean(int a);\nint zcl_gate_clean(int a) { return a + 1; }\n' > "$clean"
    if ! "$CC_BIN" "${WARN_FLAGS[@]}" "${BUILD_ENV_FLAGS[@]}" "${DEFINES[@]}" "$clean" >/dev/null 2>&1; then
        echo "FAIL: --self-test — the flag set REJECTED a trivially clean TU."
        echo "  The gate would false-fail every contributor."
        exit 1
    fi
    crash_log="$WORK/compiler-crash.log"
    printf "%s\n" "gcc: fatal error: cannot execute 'cc1': CreateProcess failed" \
        > "$crash_log"
    if compiler_result_proven "$crash_log" 1; then
        echo "FAIL: --self-test — a cc1 driver failure was accepted as a" \
             "source diagnostic."
        exit 1
    fi
    source_log="$WORK/source-error.log"
    printf '%s\n' 'fixture.c:1:2: error: planted source rejection' > "$source_log"
    if ! compiler_result_proven "$source_log" 1; then
        echo "FAIL: --self-test — an ordinary source-located rejection was" \
             "misclassified as compiler infrastructure failure."
        exit 1
    fi
    mixed_log="$WORK/mixed-compiler.log"
    printf '%s\n' \
        'fixture.c:1:2: error: planted source rejection' \
        'LLVM ERROR: out of memory' > "$mixed_log"
    if compiler_result_proven "$mixed_log" 1; then
        echo "FAIL: --self-test — a mixed source/backend failure was accepted."
        exit 1
    fi
    success_error_log="$WORK/success-error.log"
    printf '%s\n' 'fixture.c:1:2: error: wrapper returned success' \
        > "$success_error_log"
    if compiler_result_proven "$success_error_log" 0; then
        echo "FAIL: --self-test — compiler rc=0 with an error was accepted."
        exit 1
    fi
    # COVERAGE, three answers not two. Cheap: all three settle before the
    # 2069-TU compile loop. The interesting case is the one no file-count
    # floor can reach — a whole layer falling out of the Makefile parse
    # while the count stays far above SRC_FLOOR.
    cov_self="$PWD/tools/lint/check_clang_portability.sh"
    cov_case() { # $1=want-rc $2=msg  rest: VAR=VAL
        local want="$1" msg="$2" rc=0
        shift 2
        env ZCL_INTERNAL_CLANG_COVERAGE_SELFTEST=1 "$@" "$cov_self" \
            >/dev/null 2>&1 || rc=$?
        if [ "$rc" -ne "$want" ]; then
            echo "FAIL: --self-test — $msg (wanted exit $want, got $rc)"
            exit 1
        fi
    }
    # (a) a layer emptied in the Makefile parse. CORE_CONTEXTS holds 30 of
    #     the 2069 sources, so the scan drops to 2039 — still more than
    #     DOUBLE SRC_FLOOR=900. The floor sees nothing; coverage names all
    #     30 and returns UNPROVEN, exit 2.
    cov_short="$WORK/Makefile.core_contexts_emptied"
    sed 's/^CORE_CONTEXTS[[:space:]]*[:+]\{0,1\}=.*/CORE_CONTEXTS =/' \
        "$MAKEFILE" > "$cov_short"
    cov_case 2 "a whole layer dropped from the Makefile parse was not UNPROVEN" \
        ZCL_CLANG_PORTABILITY_MAKEFILE="$cov_short"
    # (b) a shortfall SMALLER than the recorded allowance is a stale
    #     ratchet, exit 1 — an allowance that may only rise rusts shut.
    cov_case 1 "an allowance above the true shortfall was silently tolerated" \
        ZCL_CLANG_PORTABILITY_COVERAGE_ALLOWANCE=1
    # (c) the pass case needs no separate run: reaching this line at all
    #     means the real scan set above already cleared its expectation.

    echo "  OK: --self-test — flag set trips on a violation, passes clean code;"
    echo "      a layer emptied from the Makefile parse is UNPROVEN exit 2 (not"
    echo "      clean, and invisible to SRC_FLOOR), a stale allowance is exit 1"
    exit 0
fi

# ── The scan ─────────────────────────────────────────────────────────────
JOBS="${ZCL_CC_JOBS:-$(nproc 2>/dev/null || echo 4)}"
[[ "$JOBS" =~ ^[0-9]+$ ]] && [ "$JOBS" -ge 1 ] || JOBS=4
[ "$JOBS" -le 32 ] || JOBS=32

LOG="$WORK/clang.log"
OUT_DIR="$WORK/out"
mkdir -p "$OUT_DIR"
printf '%s\0' "${WARN_FLAGS[@]}" "${BUILD_ENV_FLAGS[@]}" "${DEFINES[@]}" "${INC_FLAGS[@]}" > "$WORK/flags.nul"

# One clang per TU, N at a time, each writing to its OWN file. Concurrent
# writers sharing one fd tear their output once a diagnostic block exceeds
# PIPE_BUF, which made an earlier draft of this gate report a different
# finding set on every run. Per-TU files make the scan bit-deterministic.
#
xargs -a "$SRC_LIST" -P "$JOBS" -n 1 -I '{}' \
    env ZCL_GATE_FLAGS="$WORK/flags.nul" ZCL_GATE_CC="$CC_BIN" ZCL_GATE_OUT="$OUT_DIR" \
    bash -c 'mapfile -t -d "" f < "$ZCL_GATE_FLAGS"
             k="$(printf "%s" "$1" | tr -c "[:alnum:]" "_")"
             o="$ZCL_GATE_OUT/$k.log"
             r="$ZCL_GATE_OUT/$k.rc"
             set +e
             "$ZCL_GATE_CC" "${f[@]}" "$1" > "$o" 2>&1
             rc=$?
             set -e
             printf "%s\n" "$rc" > "$r"
             exit 0' _ '{}' \
    >/dev/null 2>&1
cat "$OUT_DIR"/*.log > "$LOG" 2>/dev/null

# Every TU must have produced a log file. A missing one means its worker
# never ran (fork failure, ENOSPC) and its diagnostics would be invisible.
LOG_COUNT="$(find "$OUT_DIR" -maxdepth 1 -name '*.log' -type f | wc -l)"
gate_require_scanned "$LOG_COUNT" "$SRC_COUNT" check-clang-portability \
    "only $LOG_COUNT of $SRC_COUNT translation units produced a clang result"
RC_COUNT="$(find "$OUT_DIR" -maxdepth 1 -name '*.rc' -type f | wc -l)"
gate_require_scanned "$RC_COUNT" "$SRC_COUNT" check-clang-portability \
    "only $RC_COUNT of $SRC_COUNT translation units produced a compiler status"

INFRA="$WORK/compiler-infrastructure.txt"
: > "$INFRA"
while IFS= read -r src; do
    [ -n "$src" ] || continue
    key="$(printf '%s' "$src" | tr -c '[:alnum:]' '_')"
    log="$OUT_DIR/$key.log"
    status="$OUT_DIR/$key.rc"
    rc="$(cat "$status" 2>/dev/null || true)"
    case "$rc" in ''|*[!0-9]*) proven=false ;; *) proven=true ;; esac
    if [ "$proven" = true ] && compiler_result_proven "$log" "$rc"; then
        continue
    fi
    printf '%s|%s\n' "$src" "${rc:-missing}" >> "$INFRA"
done < "$SRC_LIST"
if [ -s "$INFRA" ]; then
    count="$(wc -l < "$INFRA")"
    echo "check-clang-portability: UNPROVEN — $count compiler/backend" \
         "failure(s); no baseline can excuse them:" >&2
    while IFS='|' read -r src rc; do
        key="$(printf '%s' "$src" | tr -c '[:alnum:]' '_')"
        echo "  $src (compiler rc=$rc)" >&2
        sed -n '1,80p' "$OUT_DIR/$key.log" | sed 's/^/    /' >&2 || true
    done < "$INFRA"
    exit 2
fi

# A diagnostic SITE is "<path>:<line>:<col>: error|warning". Deduplicate:
# a diagnostic inside a shared header is reported once per including TU, and
# counting those per-TU would make the gate trip when an UNRELATED new .c
# starts including that header. Attribute each unique site to the file it is
# reported in.
SITES="$WORK/sites.txt"
grep -oE '^[A-Za-z0-9_./-]+\.[ch]:[0-9]+:[0-9]+: (error|warning): .*$' "$LOG" \
    | sort -u > "$SITES"

COUNTS="$WORK/counts.txt"
cut -d: -f1 "$SITES" | sort | uniq -c \
    | awk '{ printf "%s %s\n", $2, $1 }' | sort > "$COUNTS"

TOTAL_SITES="$(wc -l < "$SITES")"

# --sites: print every diagnostic the tree currently produces. This is the
# to-do list the baseline summarizes; keep it out of the normal run so a
# green gate stays one line.
if [ "${1:-}" = "--sites" ]; then
    echo "  $TOTAL_SITES diagnostic site(s) over $SRC_COUNT TU(s):"
    sed 's/^/    /' "$SITES"
    exit 0
fi

# ── UPDATE mode: re-record the baseline ──────────────────────────────────
if [ "${ZCL_LINT_MODE:-}" = "UPDATE" ]; then
    {
        echo "# $FAMILY portability ratchet baseline — regenerate with:"
        echo "#   ZCL_CC=$CC_BIN ZCL_LINT_MODE=UPDATE tools/lint/check_clang_portability.sh"
        echo "#"
        echo "# One '<path> <count>' line per file that still holds $FAMILY"
        echo "# diagnostic sites under the gate's flag set. Every one is a real"
        echo "# second-compiler finding to be driven to zero; a file absent from"
        echo "# this list must produce ZERO diagnostics. Counts may only go DOWN."
        echo "#"
        echo "# Recorded from $SRC_COUNT translation units with:"
        echo "#   $("$CC_BIN" --version 2>/dev/null | head -1)"
        echo "# A different compiler VERSION legitimately reports a different"
        echo "# set; that is why CI scopes its verdict with"
        echo "# ZCL_PORTABILITY_SCOPE instead of trusting this file verbatim."
        cat "$COUNTS"
    } > "$BASELINE"
    echo "  UPDATED: $BASELINE ($(wc -l < "$COUNTS") file(s), $TOTAL_SITES site(s))"
    exit 0
fi

if [ ! -f "$BASELINE" ]; then
    echo "check-clang-portability: FATAL — baseline '$BASELINE' is missing." >&2
    echo "  Refusing to report 'clean' with nothing to ratchet against." >&2
    echo "  Regenerate: ZCL_CC=$CC_BIN ZCL_LINT_MODE=UPDATE $0" >&2
    exit 2
fi

declare -A BASE=()
gate_load_kv_file "$BASELINE" BASE

# ── Scope: PR-diff mode vs full-tree ratchet ─────────────────────────────
declare -A SCOPE=()
SCOPED=0
SCOPE_FILE="${ZCL_PORTABILITY_SCOPE:-}"
if [ -n "$SCOPE_FILE" ]; then
    if [ ! -f "$SCOPE_FILE" ]; then
        echo "check-clang-portability: FATAL — ZCL_PORTABILITY_SCOPE points at" >&2
        echo "  '$SCOPE_FILE', which does not exist. Refusing to guess a scope." >&2
        exit 2
    fi
    gate_load_list_file "$SCOPE_FILE" SCOPE SCOPE_N
    SCOPED=1
    echo "  scope: ${SCOPE_N:-0} changed file(s) must be diagnostic-FREE;" \
         "the rest is ratcheted advisory-only (compiler-version skew)."
fi

regressions=""
advisory=""
improvements=""
while read -r file count; do
    [ -n "$file" ] || continue
    allowed="${BASE[$file]:-0}"
    if [ "$SCOPED" -eq 1 ] && [ -n "${SCOPE[$file]:-}" ]; then
        # A file this patch touched. The baseline does not excuse it: the
        # whole point is that the code you are submitting compiles.
        [ "$count" -gt 0 ] && \
            regressions="${regressions}  $file: $count diagnostic(s) in a file this change touches"$'\n'
        continue
    fi
    if [ "$count" -gt "$allowed" ]; then
        if [ "$SCOPED" -eq 1 ]; then
            advisory="${advisory}  $file: $count site(s), baseline allows $allowed"$'\n'
        else
            regressions="${regressions}  $file: $count site(s), baseline allows $allowed"$'\n'
        fi
    elif [ "$count" -lt "$allowed" ]; then
        improvements="${improvements}  $file: $count site(s) (baseline $allowed)"$'\n'
    fi
done < "$COUNTS"

# A baselined file that now produces nothing at all is an improvement too.
for file in "${!BASE[@]}"; do
    if ! gate_grep -qE "^${file//./\\.} " "$COUNTS"; then
        improvements="${improvements}  $file: 0 site(s) (baseline ${BASE[$file]})"$'\n'
    fi
done

print_diags_for() {
    local list="$1" f
    while read -r f; do
        [ -n "$f" ] || continue
        gate_grep -E "^${f//./\\.}:" "$SITES" | sed 's/^/    /' >&2 || true
    done < <(printf '%s\n' "$list" | sed 's/^  //; s/:.*//')
}

if [ -n "${regressions//[[:space:]]/}" ]; then
    echo "" >&2
    echo "FAIL: $FAMILY diagnostic site(s) — this change does not compile" >&2
    echo "      cleanly under $CC_BIN." >&2
    echo "" >&2
    printf '%s' "$regressions" >&2
    echo "" >&2
    echo "  Diagnostics:" >&2
    print_diags_for "$regressions"
    echo "" >&2
    echo "  Fix the code. Cross-compiler traps that commonly land here:" >&2
    echo "    * '/* fallthrough */' COMMENTS — GCC honours them, clang does" >&2
    echo "      not. Use [[fallthrough]]; (C23) instead." >&2
    echo "    * a preprocessor directive inside a function-call argument list:" >&2
    echo "      undefined behaviour, and once _FORTIFY_SOURCE turns that call" >&2
    echo "      into a macro, clang rejects it outright." >&2
    echo "    * snprintf into a buffer smaller than the format literal." >&2
    echo "    * bitwise & / | on bool operands (cast if the branchless form is" >&2
    echo "      deliberate, e.g. constant-time compares)." >&2
    echo "  Reproduce one file:" >&2
    echo "    $CC_BIN ${WARN_FLAGS[*]} ${BUILD_ENV_FLAGS[*]} <the -I set> <file.c>" >&2
    exit 1
fi

if [ -n "${advisory//[[:space:]]/}" ]; then
    echo "  NOTE: diagnostics outside this change exceed the recorded baseline."
    echo "        Expected when this compiler differs in version from the one"
    echo "        the baseline was recorded with. Not failing the change:"
    printf '%s' "$advisory"
fi

if [ -n "${improvements//[[:space:]]/}" ] && [ "$SCOPED" -eq 0 ]; then
    echo "  NOTE: $FAMILY diagnostics went DOWN — tighten the ratchet:"
    printf '%s' "$improvements"
    echo "    ZCL_CC=$CC_BIN ZCL_LINT_MODE=UPDATE tools/lint/check_clang_portability.sh"
fi

if [ "$SCOPED" -eq 1 ]; then
    echo "  OK: $SRC_COUNT TU(s) syntax-checked with $CC_BIN ($FAMILY) at $JOBS jobs;" \
         "every changed file is diagnostic-free"
else
    echo "  OK: $SRC_COUNT TU(s) syntax-checked with $CC_BIN ($FAMILY) at $JOBS jobs;" \
         "$TOTAL_SITES known diagnostic site(s), no new ones"
fi
exit 0
