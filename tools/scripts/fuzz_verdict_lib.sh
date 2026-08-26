# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# fuzz_verdict_lib.sh — shared vocabulary for what counts as sufficient
# evidence to CLOSE a fuzz artifact as `regression-seed` (audited, does not
# reproduce). Sourced by tools/scripts/promote_fuzz_artifacts.sh (which
# WRITES verdict reasons) and tools/lint/check_fuzz_artifact_replay.sh
# (which READS them back and rejects an insufficient one). Keeping the
# marker spellings in exactly one file means the writer and the reader can
# never drift apart on what phrase means what.
#
# THE RULE. A stale-stack memory-safety bug (the `crash-` / `leak-` kinds —
# the ones a sanitizer raised, as opposed to `timeout-` / `oom-` / `slow-
# unit-`, which are algorithmic and unaffected by stack contents) can be
# probabilistic on a clean process: a freshly-mapped stack reads back as
# zero, so ONE clean replay proves nothing. `-ftrivial-auto-var-init=pattern`
# poisons every uninitialized stack slot with a recognizable non-zero byte
# pattern, which turns "probabilistic" into "deterministic" for exactly this
# bug class. So a `crash-`/`leak-` artifact may be closed `regression-seed`
# ONLY if the reason names one of:
#   (a) a fix commit ("fixed by <sha>" or "root cause:" + what changed), or
#   (b) an explicit pattern-init replay that ALSO came back clean
#       ("pattern-init: clean", "-ftrivial-auto-var-init=pattern ... clean").
# "It replayed clean" with neither is not enough — that is the exact shape
# of the mistake this file exists to catch (see ARTIFACT_VERDICTS.txt's
# header for the incident it is named after).
#
# `timeout-` / `oom-` / `slow-unit-` findings are a different bug class
# (an algorithm, not a stack read) and are NOT held to this rule — nothing
# here narrows what already closes them.
#
# Sourced, not executed: no shebang, set -e left to the caller.

# reason_has_named_fix REASON -> 0 if REASON names a fix / root cause
reason_has_named_fix() {
    local reason_lc
    reason_lc="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    case "$reason_lc" in
        *"fixed by"*|*"root cause:"*) return 0 ;;
        *) return 1 ;;
    esac
}

# reason_has_pattern_init_evidence REASON -> 0 if REASON records a
# pattern-init replay (either spelling: the flag itself, or the short name).
reason_has_pattern_init_evidence() {
    local reason_lc
    reason_lc="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    case "$reason_lc" in
        *"pattern-init"*|*"pattern_init"*|*"auto-var-init=pattern"*) return 0 ;;
        *) return 1 ;;
    esac
}

# verdict_kind_needs_pattern_init_evidence KIND -> 0 if KIND is a stale-stack
# class (crash / leak) rather than an algorithmic one (timeout / oom /
# slow-unit / minimized-from, which inherits whatever its own crash- sibling
# already proved and is not itself re-required to repeat the evidence).
verdict_kind_needs_pattern_init_evidence() {
    case "${1:-}" in
        crash|leak) return 0 ;;
        *) return 1 ;;
    esac
}

# regression_seed_reason_is_sufficient KIND REASON -> 0 if a regression-seed
# verdict of this KIND with this REASON is allowed to close the artifact.
regression_seed_reason_is_sufficient() {
    local kind="$1" reason="$2"
    verdict_kind_needs_pattern_init_evidence "$kind" || return 0
    reason_has_named_fix "$reason" && return 0
    reason_has_pattern_init_evidence "$reason" && return 0
    return 1
}
