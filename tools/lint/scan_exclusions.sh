# shellcheck shell=bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# tools/lint/scan_exclusions.sh — the shared exclusion glob every
# repo-scanning lint gate sources, fixing the "scanner fixture-race"
# class of papercut (wf/dx-scanner-immunity).
#
# THE BUG (observed repeatedly): a gate's own SELFTEST (see
# tests/harness/src/test_make_lint_gates.c) plants a transient fixture file
# — by convention named `_<something>fixture<something>.c` — directly
# into a REAL scanned directory (app/**, domain/**, lib/**) to prove the
# gate's production scan catches a violation, then deletes it. Without
# any coordination, a DIFFERENT process scanning the SAME directory at
# that moment — another gate invoked via `make lint`, or the dev-watch
# loop's periodic `make lint` racing `make test` — can observe the file
# mid-flight and FAIL, pointing at a path that is gone a second later.
# Also: stray untracked files left behind by a crashed agent/worktree
# wedge every gate that walks the filesystem directly, indistinguishable
# from a real violation, until someone notices and hand-deletes them.
#
# THE FIX — two cooperating mechanisms:
#
#  1. Every scan invoked THROUGH `make` (`make lint`, `make check-<gate>`,
#     dev-watch's periodic lint pass) runs with ZCL_LINT_PRODUCTION_SCAN=1
#     in its environment (set once, Makefile-wide, via the `check-%:`
#     pattern-specific `export` — see Makefile). When that var is "1",
#     the arrays below EXCLUDE the shared fixture-name glob, the reserved
#     planted-fixture directory, and build/vendor/worktree noise, so NO
#     production `make lint` run ever sees ANYONE's transient fixture,
#     no matter which gate or process wrote it or when.
#
#  2. A gate's own selftest (tests/harness/src/test_make_lint_gates.c) execs
#     the gate script DIRECTLY (not through `make`), so
#     ZCL_LINT_PRODUCTION_SCAN is unset in that subprocess — the
#     exclusion arrays come back EMPTY, so the selftest's baseline/trip/
#     recover calls see the real, unfiltered tree exactly as they do
#     today. Detection power for selftests is therefore unchanged; only
#     concurrent OTHER-process production scans gain immunity.
#
# Because test_make_lint_gates.c runs all of its `t_*` fixture checks
# SEQUENTIALLY in one process (see test_make_lint_gates(), the single
# driver function), there is no same-process race to protect against —
# the only real race is cross-process (this file's mechanism handles
# exactly that). Two concurrent `make lint`/`make test` runs in one
# worktree are already forbidden by standing doctrine (see CLAUDE.md).
#
# Usage — source this file, then:
#   "${LINT_GREP_EXCLUDE_ARGS[@]}"   — append to any `grep -r` invocation
#   "${LINT_FIND_PRUNE_ARGS[@]}"     — append to any `find <dirs> ...`
#   lint_filter_excluded             — stdin->stdout filter (path or
#                                       "path:line:text" per line)
#   lint_path_is_excluded <path>     — predicate, for glob-based scans
#                                       (`for f in dir/*.c`) that can't
#                                       take find/grep flags
#   lint_annotate_stray <path>       — print path verbatim if git-tracked,
#                                       or annotated as an untracked stray
#                                       file otherwise (requires cwd at
#                                       repo root; used by gates that walk
#                                       the filesystem directly instead of
#                                       `git ls-files`, so a crashed
#                                       agent's leftover file is
#                                       diagnosable at a glance instead of
#                                       reading as a real code defect)
#
# The reserved planted-fixture directory: for the rare case a selftest
# needs a PERMANENT, committed fixture at a fixed real path (rather than a
# transient plant/unlink), it lives here. ALL production scans exclude
# this directory unconditionally, regardless of filename or
# ZCL_LINT_PRODUCTION_SCAN.
LINT_PLANTED_DIR="tools/lint/fixtures/planted"

# Regex mirror of the exclusion set (basename-anchored fixture glob, plus
# the planted dir / build / vendor / worktree noise) — always available
# for post-hoc filtering (mechanism 2b, stray-file detection) regardless
# of ZCL_LINT_PRODUCTION_SCAN, since "is this an orphaned lint fixture"
# is a useful classification even outside the race-immunity path.
LINT_FIXTURE_REGEX='(^|/)_[^/]*fixture[^/]*\.[ch]$'
LINT_NOISE_REGEX="(^|/)${LINT_PLANTED_DIR}/|(^|/)build/|(^|/)vendor/|(^|/)\\.claude/|(^|/)test-tmp/"
LINT_EXCLUDE_REGEX="${LINT_FIXTURE_REGEX}|${LINT_NOISE_REGEX}"

if [[ "${ZCL_LINT_PRODUCTION_SCAN:-0}" == "1" ]]; then
    LINT_FIND_PRUNE_ARGS=(
        -not -regex '.*/_[^/]*fixture[^/]*\.[ch]'
        -not -path "*/${LINT_PLANTED_DIR}/*"
        -not -path '*/build/*'
        -not -path '*/vendor/*'
        -not -path '*/.claude/*'
        -not -path '*/test-tmp/*'
    )
    LINT_GREP_EXCLUDE_ARGS=(
        '--exclude=_*fixture*.c'
        '--exclude=_*fixture*.h'
        '--exclude-dir=planted'
        '--exclude-dir=build'
        '--exclude-dir=vendor'
        '--exclude-dir=.claude'
        '--exclude-dir=test-tmp'
    )
else
    LINT_FIND_PRUNE_ARGS=()
    LINT_GREP_EXCLUDE_ARGS=()
fi

lint_path_is_excluded() {
    [[ "${ZCL_LINT_PRODUCTION_SCAN:-0}" == "1" && "$1" =~ $LINT_EXCLUDE_REGEX ]]
}

lint_filter_excluded() {
    if [[ "${ZCL_LINT_PRODUCTION_SCAN:-0}" == "1" ]]; then
        grep -vE "$LINT_EXCLUDE_REGEX"
    else
        cat
    fi
}

# Classify a scan-set path as tracked (real) or untracked (stray debris —
# not necessarily a code violation). Always active (not gated on
# ZCL_LINT_PRODUCTION_SCAN): the whole point is to make `make lint`'s
# output honest about WHAT kind of problem it found. Must be called with
# cwd at the repo root (every gate already `cd`s there).
lint_annotate_stray() {
    local path="$1"
    if git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
        printf '%s' "$path"
    else
        printf '%s [untracked stray file -- not a code violation; likely left by a crashed agent/worktree, delete it]' "$path"
    fi
}
