#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# promote_fuzz_artifacts.sh — crash/timeout/OOM triage for the background
# fuzz lane (lane S2d, wf/s2d-replay-canary-crashloop).
#
# libFuzzer drops every crash/timeout/oom/slow-unit it finds under
# $ARTIFACT_DIR as "<harness>-<kind>-<sha1>" (the "<harness>-" part is the
# -artifact_prefix= background_quality_lane.sh passes per target — see
# run_fuzz() in tools/scripts/background_quality_lane.sh). Left alone
# those artifacts just accumulate: they are real, already-triggered
# regression inputs that never make it into the checked-in corpus, so the
# SAME bug class can be re-discovered (and re-timed-out on) forever
# instead of being fuzzed-past once it is fixed.
#
# THE INCIDENT THIS VERSION FIXES. Until 2026-08-26 this script filed its
# verdict from the FILENAME alone: a "crash-" prefix and a "timeout-" prefix
# both landed as the placeholder `unaudited` verdict, with nothing that ever
# ran the artifact to see what it actually does. A real heap-buffer-overflow
# (crash-478b30c0..., a peer-reachable wild free in transaction_free()) and
# three spurious -timeout=2 trips from a loaded box got the identical
# unaudited label — a human reading the ledger had no way to tell a live
# remote memory-safety bug from box noise. Worse, the append itself landed
# under the FIRST heading `>>` happened to find at end-of-file — this
# corpus's file, the "accepted" section — so a brand-new, never-triaged
# finding could visually read as living in the "nothing has earned this"
# section reserved for reproducing-but-accepted non-bugs.
#
# This script now REPLAYS every artifact it promotes, twice each: once
# against the stock sanitizer binary, once against a build compiled with
# -ftrivial-auto-var-init=pattern (which poisons every uninitialized stack
# slot with a recognizable non-zero pattern instead of leaving it
# zero-on-a-fresh-map). A `crash-`/`leak-` finding can be probabilistic on a
# clean process — a freshly-mapped stack reads back as zero, so ONE clean
# replay proves nothing about a stale-stack bug — and pattern-init is the
# tool that converts that "probabilistic" into "deterministic". Both results
# are recorded, distinctly, in the filed verdict line; an artifact this
# script could not replay under the binary its bug class requires is filed
# `unreplayable`, never `regression-seed` — fail closed, not fail quiet.
#
# Usage:
#   promote_fuzz_artifacts.sh [--artifact-dir=DIR] [--seed-root=DIR]
#                              [--size-cap-bytes=N] [--dry-run]
#                              [--replay-reps=N] [--replay-timeout=SECS]
#                              [--no-build-missing]
#
# Exit code is always 0 on a normal triage pass (best-effort, log-only —
# see the call site in background_quality_lane.sh's run_fuzz(), which
# must never fail the fuzz lane's own verdict over a triage hiccup); a
# non-zero exit is reserved for a usage error (bad flag) or a directory
# that cannot be created.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=tools/scripts/fuzz_verdict_lib.sh
. "$SCRIPT_DIR/fuzz_verdict_lib.sh"

STATE_ROOT="${ZCL_QUALITY_STATE_DIR:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/zclassic23-quality}"
ARTIFACT_DIR="$STATE_ROOT/artifacts"
SEED_ROOT="$REPO_ROOT/lib/test/fuzz_seeds"
SIZE_CAP_BYTES=1048576   # 1 MiB
DRY_RUN=0
BUILD_MISSING=1
REPLAY_REPS="${ZCL_PROMOTE_REPLAY_REPS:-10}"
REPLAY_TIMEOUT="${ZCL_PROMOTE_REPLAY_TIMEOUT:-5}"
BUILD_TIMEOUT="${ZCL_PROMOTE_BUILD_TIMEOUT:-600}"
STOCK_BUILD_DIR="${ZCL_PROMOTE_STOCK_BUILD_DIR:-$REPO_ROOT/build}"
PATTERNINIT_BUILD_DIR="${ZCL_PROMOTE_PATTERNINIT_BUILD_DIR:-$REPO_ROOT/build/fuzz-patterninit}"

for arg in "$@"; do
    case "$arg" in
        --artifact-dir=*)   ARTIFACT_DIR="${arg#--artifact-dir=}" ;;
        --seed-root=*)      SEED_ROOT="${arg#--seed-root=}" ;;
        --size-cap-bytes=*) SIZE_CAP_BYTES="${arg#--size-cap-bytes=}" ;;
        --replay-reps=*)    REPLAY_REPS="${arg#--replay-reps=}" ;;
        --replay-timeout=*) REPLAY_TIMEOUT="${arg#--replay-timeout=}" ;;
        --dry-run)          DRY_RUN=1 ;;
        --no-build-missing) BUILD_MISSING=0 ;;
        -h|--help)
            echo "usage: promote_fuzz_artifacts.sh [--artifact-dir=DIR] [--seed-root=DIR] [--size-cap-bytes=N] [--replay-reps=N] [--replay-timeout=SECS] [--no-build-missing] [--dry-run]"
            exit 0 ;;
        *) echo "promote-fuzz-artifacts: unknown arg '$arg'" >&2; exit 2 ;;
    esac
done

# After the arg loop: --seed-root= may have moved SEED_ROOT.
LEDGER="$SEED_ROOT/ARTIFACT_VERDICTS.txt"

if [ ! -d "$ARTIFACT_DIR" ]; then
    echo "promote-fuzz-artifacts: no artifact dir ($ARTIFACT_DIR) — nothing to triage"
    exit 0
fi

mkdir -p "$SEED_ROOT" 2>/dev/null || { echo "promote-fuzz-artifacts: cannot create seed root $SEED_ROOT" >&2; exit 1; }

# ── Known libFuzzer artifact "kind" markers ─────────────────────────
# The prefix before the FIRST of these (with its own trailing '-') is the
# harness name. "slow-unit" and "minimized-from" themselves contain a '-', so
# they must be checked before a naive single-token split would misparse them.
# Kept in step with ARTIFACT_RE in tools/lint/check_fuzz_artifact_replay.sh:
# these are the six prefixes libFuzzer writes. "minimized-from" is what
# `-minimize_crash=1` produces — the natural next step after a crash- lands,
# and until 2026-07-29 neither this script nor the gate could name it.
KIND_MARKERS="crash timeout oom slow-unit leak minimized-from"

derive_harness_and_kind() {  # $1 = basename -> prints "harness kind" or "" on no match
    local base="$1" marker rest
    for marker in $KIND_MARKERS; do
        case "$base" in
            *"-${marker}-"*)
                rest="${base##*-${marker}-}"
                # Only accept if what follows looks like a hex digest (the
                # libFuzzer convention) — guards against a harness name that
                # itself happens to contain "-timeout-" etc.
                case "$rest" in
                    [0-9a-fA-F]*)
                        printf '%s %s\n' "${base%-${marker}-*}" "$marker"
                        return 0 ;;
                esac ;;
        esac
    done
    return 1
}

# ── Replay machinery ──────────────────────────────────────────────────────
# One artifact, one binary, REPLAY_REPS independent process launches (a fresh
# process each time is the point: a stack's contents on entry are a property
# of the process, not the file, so N reps of the SAME clean binary sample N
# independent stack states rather than proving anything about the artifact
# itself. pattern-init needs no such sampling — it is deterministic by
# construction — but is still run REPLAY_REPS times for symmetry and so a
# flaky build/exec-environment problem cannot masquerade as "clean").
#
# Prints one of: clean | crash | nobin  — never partial, never silent.
replay_binary() {
    local bin="$1" artifact="$2" reps="$3" tmo="$4"
    local i rc work
    [ -x "$bin" ] || { printf 'nobin 0 0\n'; return 0; }
    work="$(mktemp -d "${TMPDIR:-/tmp}/zcl-promote-replay.XXXXXX")"
    local hit=0 ran=0
    for ((i = 0; i < reps; i++)); do
        rc=0
        ( cd "$work" && \
          ASAN_OPTIONS=detect_leaks=0:symbolize=0 \
          UBSAN_OPTIONS=print_stacktrace=0 \
          timeout -k 5 "$((tmo + 10))" "$bin" \
            -timeout="$tmo" -rss_limit_mb=2048 -runs=1 \
            -timeout_exitcode=70 -error_exitcode=77 \
            -artifact_prefix="$work/" \
            "$artifact" >"$work/rep.$i.out" 2>&1 ) || rc=$?
        ran=$((ran + 1))
        if [ "$rc" -ne 0 ]; then
            hit=$((hit + 1))
        fi
    done
    rm -rf "$work"
    if [ "$hit" -gt 0 ]; then
        printf 'crash %d %d\n' "$hit" "$ran"
    else
        printf 'clean %d %d\n' "$hit" "$ran"
    fi
}

# ensure_binary HARNESS PATTERNINIT(0|1) -> prints the binary path (may not
# exist if the build failed/was skipped) on stdout.
ensure_binary() {
    local harness="$1" patterninit="$2" bin bdir
    if [ "$patterninit" -eq 1 ]; then
        bdir="$PATTERNINIT_BUILD_DIR"
        bin="$bdir/bin/fuzz_$harness"
    else
        bdir="$STOCK_BUILD_DIR"
        bin="$bdir/bin/fuzz_$harness"
    fi
    if [ ! -x "$bin" ] && [ "$BUILD_MISSING" -eq 1 ]; then
        echo "promote-fuzz-artifacts: building fuzz_$harness (patterninit=$patterninit) into ${bdir#"$REPO_ROOT"/} ..." >&2
        if [ "$patterninit" -eq 1 ]; then
            timeout -k 10 "$BUILD_TIMEOUT" \
                make -C "$REPO_ROOT" BUILD_DIR="$bdir" \
                    ZCL_FUZZ_EXTRA_CFLAGS=-ftrivial-auto-var-init=pattern \
                    "fuzz_$harness" >&2 || \
                echo "promote-fuzz-artifacts: pattern-init build of fuzz_$harness FAILED or timed out" >&2
        else
            timeout -k 10 "$BUILD_TIMEOUT" \
                make -C "$REPO_ROOT" BUILD_DIR="$bdir" "fuzz_$harness" >&2 || \
                echo "promote-fuzz-artifacts: stock build of fuzz_$harness FAILED or timed out" >&2
        fi
    fi
    printf '%s\n' "$bin"
}

# summarize_replay STATE HIT RAN -> short human string, e.g. "clean (10x)"
# or "CRASHES (3/10)".
summarize_replay() {
    local state="$1" hit="$2" ran="$3"
    case "$state" in
        clean)  printf 'clean (%sx)' "$ran" ;;
        crash)  printf 'CRASHES (%s/%s)' "$hit" "$ran" ;;
        nobin)  printf 'UNAVAILABLE (no binary)' ;;
        *)      printf 'UNKNOWN' ;;
    esac
}

# replay_and_verdict HARNESS KIND ARTIFACT_PATH -> prints "<verdict>\t<reason>"
# This is the whole point of the rewrite: the verdict is DERIVED from what
# just happened, never from the filename.
replay_and_verdict() {
    local harness="$1" kind="$2" artifact="$3"
    local stock_bin stock_state stock_hit stock_ran
    local pi_bin pi_state pi_hit pi_ran
    local need_pi=0

    verdict_kind_needs_pattern_init_evidence "$kind" && need_pi=1

    stock_bin="$(ensure_binary "$harness" 0)"
    read -r stock_state stock_hit stock_ran < <(replay_binary "$stock_bin" "$artifact" "$REPLAY_REPS" "$REPLAY_TIMEOUT")

    pi_state="nobin"; pi_hit=0; pi_ran=0
    if [ "$need_pi" -eq 1 ]; then
        pi_bin="$(ensure_binary "$harness" 1)"
        read -r pi_state pi_hit pi_ran < <(replay_binary "$pi_bin" "$artifact" "$REPLAY_REPS" "$REPLAY_TIMEOUT")
    fi

    local stock_summary pi_summary
    stock_summary="stock: $(summarize_replay "$stock_state" "$stock_hit" "$stock_ran")"
    if [ "$need_pi" -eq 1 ]; then
        pi_summary="pattern-init: $(summarize_replay "$pi_state" "$pi_hit" "$pi_ran")"
    else
        pi_summary="pattern-init: not required for kind=$kind (algorithmic, not stack-state-dependent)"
    fi

    # ── The decision table. Ambiguous or partial evidence defaults to the
    # label that demands a human, never to the label that lets a build stay
    # green. "unreplayable" is reserved for genuinely could-not-tell; a
    # crash observed under EITHER binary is always "open", never smoothed
    # over by a clean result from the other one. ──
    if [ "$stock_state" = "crash" ] || [ "$pi_state" = "crash" ]; then
        printf 'open\t%s; %s — reproduces, needs a human owner and a fix, not a verdict\n' \
            "$stock_summary" "$pi_summary"
        return 0
    fi

    if [ "$stock_state" = "nobin" ] && { [ "$need_pi" -eq 0 ] || [ "$pi_state" = "nobin" ]; }; then
        printf 'unreplayable\t%s; %s — could not replay at all, never file this as clean\n' \
            "$stock_summary" "$pi_summary"
        return 0
    fi

    if [ "$need_pi" -eq 1 ] && { [ "$stock_state" = "nobin" ] || [ "$pi_state" = "nobin" ]; }; then
        printf 'unreplayable\t%s; %s — a %s finding needs BOTH halves clean to close; one half never ran\n' \
            "$stock_summary" "$pi_summary" "$kind"
        return 0
    fi

    # Both halves ran (or pattern-init was not required) and neither crashed.
    printf 'regression-seed\t%s; %s\n' "$stock_summary" "$pi_summary"
}

# ── Ledger insertion: file the line under the artifact's OWN corpus
# section, never blindly at end-of-file. Blind end-of-file append is exactly
# how the earlier version of this script landed a brand-new, never-triaged
# `unaudited` line inside the "accepted" section — the last section in this
# file, and the one meaning "reproduces and is a known non-bug". ──
insert_ledger_line() {
    local harness="$1" line="$2"
    local heading_pat="# ── ${harness} "
    if [ ! -f "$LEDGER" ]; then
        printf '%s\n' "$line" >> "$LEDGER"
        return 0
    fi
    if grep -qF "$heading_pat" "$LEDGER" 2>/dev/null || \
       grep -qE "^# ── ${harness}( |/)" "$LEDGER" 2>/dev/null; then
        awk -v newline="$line" -v pat="^# ── ${harness}( |/)" '
            BEGIN { in_sec = 0; done = 0 }
            {
                if (!done && in_sec && $0 ~ /^# ──/) {
                    print newline
                    in_sec = 0
                    done = 1
                }
                if (!done && in_sec && $0 == "") {
                    print newline
                    in_sec = 0
                    done = 1
                }
                print
                if (!done && $0 ~ pat) { in_sec = 1 }
            }
            END {
                if (!done && in_sec) print newline
            }
        ' "$LEDGER" > "$LEDGER.tmp"
        mv "$LEDGER.tmp" "$LEDGER"
    else
        # Brand-new corpus: file a small section right before "# ── accepted"
        # so accepted stays the last section, exactly as its own comment
        # promises. If that anchor is somehow missing, fall back to EOF
        # (still correct, just undecorated) rather than losing the line.
        if grep -qE '^# ── accepted' "$LEDGER" 2>/dev/null; then
            awk -v newline="$line" -v harness="$harness" '
                BEGIN { done = 0 }
                {
                    if (!done && $0 ~ /^# ── accepted/) {
                        print "# ── " harness " — new corpus, first artifact filed by promote_fuzz_artifacts.sh ──"
                        print newline
                        print ""
                        done = 1
                    }
                    print
                }
            ' "$LEDGER" > "$LEDGER.tmp"
            mv "$LEDGER.tmp" "$LEDGER"
        else
            {
                echo ""
                echo "# ── ${harness} — new corpus, first artifact filed by promote_fuzz_artifacts.sh ──"
                echo "$line"
            } >> "$LEDGER"
        fi
    fi
}

# ── Dedup index: sha256 of every file already in the corpus ────────
declare -A SEEN_HASH
while IFS= read -r -d '' f; do
    h="$(sha256sum "$f" | cut -d' ' -f1)"
    SEEN_HASH["$h"]="$f"
done < <(find "$SEED_ROOT" -type f -print0 2>/dev/null)

promoted=0
dup=0
oversize=0
unparsed=0
declare -A PROMOTED_BY_HARNESS

for f in "$ARTIFACT_DIR"/*; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"
    size="$(stat -c%s "$f" 2>/dev/null || wc -c < "$f")"

    if [ "$size" -gt "$SIZE_CAP_BYTES" ]; then
        echo "promote-fuzz-artifacts: SKIP oversize ($size > $SIZE_CAP_BYTES bytes) $base — left in place for manual triage"
        oversize=$((oversize + 1))
        continue
    fi

    hk="$(derive_harness_and_kind "$base" || true)"
    if [ -z "$hk" ]; then
        echo "promote-fuzz-artifacts: SKIP unparsed name (no harness-<kind>-<hex> pattern) $base — left in place"
        unparsed=$((unparsed + 1))
        continue
    fi
    harness="${hk% *}"
    kind="${hk#* }"

    hash="$(sha256sum "$f" | cut -d' ' -f1)"
    if [ -n "${SEEN_HASH[$hash]:-}" ]; then
        echo "promote-fuzz-artifacts: SKIP duplicate (content == ${SEEN_HASH[$hash]}) $base"
        dup=$((dup + 1))
        [ "$DRY_RUN" -eq 1 ] || rm -f "$f"
        continue
    fi

    dest_dir="$SEED_ROOT/$harness"
    # digest suffix from the artifact's own name (already a hex sha1 from
    # libFuzzer); keep it for traceability back to the original artifact.
    digest="${base##*-}"
    dest="$dest_dir/${kind}-${digest}.bin"

    if [ "$DRY_RUN" -eq 1 ]; then
        echo "promote-fuzz-artifacts: [dry-run] would promote $base -> $dest (and replay it before filing a verdict)"
        continue
    fi

    mkdir -p "$dest_dir"
    mv -f "$f" "$dest"
    echo "promote-fuzz-artifacts: promoted $base -> ${dest#"$REPO_ROOT"/}"
    SEEN_HASH["$hash"]="$dest"
    promoted=$((promoted + 1))
    PROMOTED_BY_HARNESS["$harness"]=$(( ${PROMOTED_BY_HARNESS["$harness"]:-0} + 1 ))

    # ── Replay BEFORE labeling. This is the fix: the old code filed
    # `unaudited` here from the filename alone and stopped. Now the artifact
    # is actually run — stock and, for crash-/leak- kinds, pattern-init too —
    # and the verdict below is what was OBSERVED, not what the name implies. ──
    echo "promote-fuzz-artifacts: replaying ${dest#"$REPO_ROOT"/} (stock x$REPLAY_REPS$( [ "$kind" = crash ] || [ "$kind" = leak ] && printf ', pattern-init x%s' "$REPLAY_REPS" ))..."
    verdict_line="$(replay_and_verdict "$harness" "$kind" "$dest")"
    verdict="${verdict_line%%$'\t'*}"
    reason="${verdict_line#*$'\t'}"
    rel="$harness/${kind}-${digest}.bin"

    if [ -f "$LEDGER" ] && grep -q "^$rel[[:space:]]" "$LEDGER" 2>/dev/null; then
        echo "promote-fuzz-artifacts: NOTE ${rel} already has a ledger line; leaving it — a re-promoted duplicate should not overwrite a human's verdict"
        continue
    fi

    entry="$rel  $verdict  $(date -u +%Y-%m-%d)  # auto-filed by promote_fuzz_artifacts.sh after replay: $reason"
    insert_ledger_line "$harness" "$entry"

    case "$verdict" in
        open)
            echo "promote-fuzz-artifacts: *** ${rel} REPRODUCES — filed 'open'. This is a live finding; it does not suppress the failure, it names it."
            ;;
        unreplayable)
            echo "promote-fuzz-artifacts: ${rel} filed 'unreplayable' — could not get the evidence this bug class requires; a human must build the missing binary and re-triage. Never treated as clean."
            ;;
        regression-seed)
            echo "promote-fuzz-artifacts: ${rel} filed 'regression-seed' — $reason"
            ;;
    esac
done

echo "promote-fuzz-artifacts: SUMMARY promoted=$promoted duplicate=$dup oversize=$oversize unparsed=$unparsed"
if [ "$promoted" -gt 0 ]; then
    for harness in "${!PROMOTED_BY_HARNESS[@]}"; do
        echo "promote-fuzz-artifacts:   $harness: ${PROMOTED_BY_HARNESS[$harness]}"
    done
fi
exit 0
