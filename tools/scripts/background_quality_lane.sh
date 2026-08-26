#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Background quality lanes for proof work that is valuable but too expensive
# for the synchronous pre-push path. systemd user timers run this script and
# the latest verdict is always available as JSON under ~/.local/state.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

STATE_ROOT="${ZCL_QUALITY_STATE_DIR:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/zclassic23-quality}"
STATUS_DIR="$STATE_ROOT/status"
LOG_DIR="$STATE_ROOT/logs"
ARTIFACT_DIR="$STATE_ROOT/artifacts"
QUALITY_TREE="$ROOT"
QUALITY_SOURCE_ID="unknown"
QUALITY_SOURCE_MUTATION="unknown"
QUALITY_SOURCE_RECORD=""

mkdir -p "$STATUS_DIR" "$LOG_DIR" "$ARTIFACT_DIR"

utc_now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
epoch_now() { date -u '+%s'; }

# shellcheck source=tools/scripts/stopwatch_json_lib.sh
. "$SCRIPT_DIR/stopwatch_json_lib.sh"  # json_escape

# Optional GitHub trace metadata only; source_id_sha256 owns freshness.
git_commit() {
    git -C "$QUALITY_TREE" rev-parse --short=12 HEAD 2>/dev/null ||
        printf 'unknown'
}

capture_quality_source_record() {
    local tree="$1" tool record source_id clean mutation extra
    tool="$tree/tools/dev/source-identity.sh"
    [ -x "$tool" ] || return 2
    record="$(cd "$tree" && "$tool" capture-record 2>/dev/null)" || return 2
    read -r source_id clean mutation extra <<< "$record"
    [[ "$source_id" =~ ^[0-9a-f]{64}$ ]] && [ "$clean" = 1 ] &&
        [[ "$mutation" =~ ^[0-9a-f]{64}$ ]] &&
        [ -z "${extra:-}" ] || return 2
    printf '%s %s %s\n' "$source_id" "$clean" "$mutation"
}

bind_quality_tree() {
    local tree="$1" clean
    QUALITY_TREE="$tree"
    QUALITY_SOURCE_RECORD="$(capture_quality_source_record "$tree")" || {
        QUALITY_SOURCE_RECORD=""
        QUALITY_SOURCE_ID="unknown"
        QUALITY_SOURCE_MUTATION="unknown"
        return 2
    }
    read -r QUALITY_SOURCE_ID clean QUALITY_SOURCE_MUTATION \
        <<< "$QUALITY_SOURCE_RECORD"
}

write_status() {
    local lane="$1" status="$2" started="$3" finished="$4" elapsed="$5" rc="$6" log="$7" detail="$8"
    local observed_record observed_id="unknown" observed_clean=0
    local observed_mutation="unknown" source_stable=false identity_rc=0
    local tmp="$STATUS_DIR/${lane}.json.tmp"
    local out="$STATUS_DIR/${lane}.json"
    observed_record="$(capture_quality_source_record "$QUALITY_TREE")" ||
        observed_record=""
    if [ -n "$observed_record" ]; then
        read -r observed_id observed_clean observed_mutation \
            <<< "$observed_record"
    fi
    if [ -n "$QUALITY_SOURCE_RECORD" ] &&
       [ "$observed_record" = "$QUALITY_SOURCE_RECORD" ]; then
        source_stable=true
    else
        source_stable=false
        status=failed
        rc=3
        detail="source identity unavailable or superseded; prior detail: $detail"
        identity_rc=3
    fi
    {
        printf '{'
        printf '"schema":"zcl.background_quality_lane.v1"'
        printf ',"lane":"%s"' "$(json_escape "$lane")"
        printf ',"status":"%s"' "$(json_escape "$status")"
        printf ',"started_at":"%s"' "$(json_escape "$started")"
        printf ',"finished_at":"%s"' "$(json_escape "$finished")"
        printf ',"elapsed_seconds":%s' "$elapsed"
        printf ',"exit_code":%s' "$rc"
        printf ',"source_identity_schema":"zcl.dev_source_identity.v2"'
        printf ',"freshness_authority":"source_id_sha256_plus_mutation_token"'
        printf ',"source_id_sha256":"%s"' "$(json_escape "$QUALITY_SOURCE_ID")"
        printf ',"source_mutation_token":"%s"' "$(json_escape "$QUALITY_SOURCE_MUTATION")"
        printf ',"observed_source_id_sha256":"%s"' "$(json_escape "$observed_id")"
        printf ',"observed_source_mutation_token":"%s"' "$(json_escape "$observed_mutation")"
        printf ',"source_record_stable":%s' "$source_stable"
        printf ',"commit":"%s"' "$(json_escape "$(git_commit)")"
        printf ',"commit_semantics":"display_only_github_trace_metadata"'
        printf ',"log":"%s"' "$(json_escape "$log")"
        printf ',"artifacts":"%s"' "$(json_escape "$ARTIFACT_DIR")"
        printf ',"detail":"%s"' "$(json_escape "$detail")"
        printf '}\n'
    } > "$tmp"
    mv "$tmp" "$out"
    return "$identity_rc"
}

run_logged() {
    local log="$1"
    shift
    set +e
    "$@" 2>&1 | tee -a "$log"
    local rc=${PIPESTATUS[0]}
    set -e
    return "$rc"
}

# Build/test lanes must NOT compile inside the operator's live checkout ($ROOT).
# A concurrent `git merge`/`checkout` there mutates sources mid-build, so the
# lane links object files compiled against inconsistent headers — an ODR/ABI
# mismatch whose binary fails spuriously at runtime (observed 2026-07-13: a
# valid block rejected as bad-txns-vout-negative / bad-txnmrklroot in the simnet
# self-test, while `make test` on the same clean commit was green). Each lane
# gets its own detached git worktree selected from $ROOT's HEAD at lane start —
# isolated from live edits AND from the other lanes. build/ (ccache-warm) and the
# untracked prebuilt vendor archives are preserved across runs. Isolation is a
# hard precondition: any HEAD/worktree/reset/clean failure returns a failed lane
# without compiling in the shared checkout. Git only locates a checkout; the
# exact v2 source record bound after selection owns every quality verdict.
prepare_lane_tree() {
    local lane="$1"
    local iso="$STATE_ROOT/checkout/$lane"
    local head
    head="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null)" || {
        echo "background_quality: cannot resolve isolated lane HEAD" >&2
        return 2
    }

    if [ ! -e "$iso/.git" ]; then
        rm -rf "$iso" || return 2
        mkdir -p "$(dirname "$iso")" || return 2
        git -C "$ROOT" worktree prune >/dev/null 2>&1 || return 2
        if ! git -C "$ROOT" worktree add --detach "$iso" "$head" >/dev/null 2>&1; then
            echo "background_quality: isolated worktree creation failed for $lane" >&2
            return 2
        fi
    else
        # Re-point the existing worktree at the current HEAD. reset --hard only
        # touches tracked files; gitignored build/ + vendor/lib survive (fast
        # incremental rebuilds). `clean -fd` (no -x) drops stray untracked source
        # without wiping ignored build artifacts.
        git -C "$iso" reset --hard "$head" >/dev/null 2>&1 || return 2
        git -C "$iso" clean -fd >/dev/null 2>&1 || return 2
    fi

    # Prebuilt vendor archives (vendor/lib/*.a) are untracked; seed them once.
    if [ -d "$ROOT/vendor/lib" ]; then
        mkdir -p "$iso/vendor/lib"
        cp -au "$ROOT"/vendor/lib/*.a "$iso/vendor/lib/" 2>/dev/null || true
    fi
    printf '%s' "$iso"
}

run_fuzz() {
    local started started_epoch finished finished_epoch elapsed rc log
    local duration timeout leak_detect
    started="$(utc_now)"
    started_epoch="$(epoch_now)"
    log="$LOG_DIR/fuzz-${started//[:]/}.log"
    duration="${ZCL_FUZZ_DURATION:-900}"
    timeout="${ZCL_FUZZ_TIMEOUT:-2}"
    leak_detect="${ZCL_FUZZ_DETECT_LEAKS:-0}"

    # prepare_lane_tree (below) faithfully re-points the isolated lane
    # worktree at $ROOT's CURRENT HEAD every run — but that only helps if
    # $ROOT itself is following `main`. A $ROOT pinned in detached HEAD (or
    # simply never fast-forwarded) makes every lane run refresh against a
    # HEAD that never moves: the fuzz lane re-fuzzes and re-reports an
    # already-fixed bug forever, exactly the "judged from a stale pinned
    # checkout" shape this repo has been bitten by before. Best-effort,
    # never fails the lane: a refresh that cannot proceed (dirty tree,
    # diverged history, no network) is logged loudly and the lane continues
    # against whatever HEAD $ROOT actually has, same as it always did.
    local freshness_tool="$SCRIPT_DIR/check_quality_lane_freshness.sh"
    if [ -x "$freshness_tool" ]; then
        {
            echo "background_quality: checking whether \$ROOT ($ROOT) is pinned behind main..."
            "$freshness_tool" --refresh --root="$ROOT" --ref=main
        } >>"$log" 2>&1 || \
            echo "background_quality: WARNING — \$ROOT freshness refresh did not complete cleanly; see $log. Proceeding with whatever HEAD \$ROOT currently has." | tee -a "$log"
    fi

    local tree
    if ! tree="$(prepare_lane_tree fuzz)"; then
        QUALITY_TREE="$ROOT"
        QUALITY_SOURCE_RECORD=""
        QUALITY_SOURCE_ID="unknown"
        QUALITY_SOURCE_MUTATION="unknown"
        write_status "fuzz" "failed" "$started" "$(utc_now)" 0 2 "$log" \
            "isolated lane checkout preparation failed" || true
        return 2
    fi
    bind_quality_tree "$tree" || {
        write_status "fuzz" "failed" "$started" "$(utc_now)" 0 2 "$log" \
            "could not bind exact lane source identity" || true
        return 2
    }

    write_status "fuzz" "running" "$started" "" 0 0 "$log" "building fuzz targets"
    {
        printf 'background_quality: lane=fuzz started=%s duration_per_target=%s timeout=%s commit=%s tree=%s\n' \
            "$started" "$duration" "$timeout" "$(git_commit)" "$tree"
    } | tee -a "$log"

    if ! command -v "${FUZZ_CC:-clang}" >/dev/null 2>&1; then
        finished="$(utc_now)"
        finished_epoch="$(epoch_now)"
        elapsed=$((finished_epoch - started_epoch))
        write_status "fuzz" "skipped" "$started" "$finished" "$elapsed" 0 "$log" "clang not available"
        echo "background_quality: fuzz skipped (clang not available)" | tee -a "$log"
        return 0
    fi

    if run_logged "$log" bash -c "cd \"$tree\" && make fuzz"; then
        :
    else
        rc=$?
        finished="$(utc_now)"
        finished_epoch="$(epoch_now)"
        elapsed=$((finished_epoch - started_epoch))
        write_status "fuzz" "failed" "$started" "$finished" "$elapsed" "$rc" "$log" "make fuzz failed"
        return "$rc"
    fi

    # Every fuzz target, derived from the Makefile's own FUZZ_TARGETS so a new
    # harness is covered the day its rule lands. This used to be the hand-typed
    # list "block script p2p http" — four of nine — so compactblock, overlay,
    # rom_manifest, snapshot and tx_bundle were fuzzed by nothing on this timer.
    local kinds
    kinds="$(sed -n 's/^FUZZ_TARGETS[[:space:]]*=//p' "$tree/Makefile" \
             | tr ' ' '\n' | sed -n 's|^\$(BIN_DIR)/fuzz_||p' | tr '\n' ' ')"
    if [ -z "${kinds// /}" ]; then
        write_status "fuzz" "failed" "$started" "$(utc_now)" 0 2 "$log" \
            "could not derive FUZZ_TARGETS from the Makefile" || true
        echo "background_quality: fuzz FAILED — no targets derived from FUZZ_TARGETS" | tee -a "$log"
        return 2
    fi

    rc=0
    local failed_kinds=""
    for kind in $kinds; do
        local bin="$tree/build/bin/fuzz_$kind"
        local seed_dir="$tree/lib/test/fuzz_seeds/$kind"
        local work_dir
        work_dir="$(mktemp -d "${TMPDIR:-/tmp}/zcl_fuzz_${kind}.XXXXXX")"
        echo "=== $bin (${duration}s background lane) ===" | tee -a "$log"
        set +e
        ASAN_OPTIONS="detect_leaks=$leak_detect" "$bin" \
            "-max_total_time=$duration" \
            "-timeout=$timeout" \
            "-artifact_prefix=$ARTIFACT_DIR/${kind}-" \
            -print_final_stats=1 \
            "$work_dir" "$seed_dir" 2>&1 | tee -a "$log"
        local one_rc=${PIPESTATUS[0]}
        set -e
        rm -rf "$work_dir"
        # Record the failure and KEEP GOING. This used to `break`, which is how
        # the 2026-07-14 script hang silently switched off every target after
        # it: script failed first, so p2p and http — the two remaining entries
        # in the old hand-typed list — never ran again on this timer, and the
        # p2p corpus went two weeks describing itself as "never audited". One
        # target's bug must not become every later target's blind spot.
        if [ "$one_rc" -ne 0 ]; then
            rc="$one_rc"
            failed_kinds="$failed_kinds $kind"
            echo "background_quality: fuzz target '$kind' failed (rc=$one_rc) — continuing with the rest" \
                | tee -a "$log"
        fi
    done

    # Triage step (final, always runs — best-effort, never flips the lane's
    # own verdict): promote every crash/timeout/oom artifact this run (or
    # any prior run) deposited under $ARTIFACT_DIR into the checked-in
    # regression corpus lib/test/fuzz_seeds/<harness>/, deduped by content
    # hash. Deliberately targets the REAL checkout ($SCRIPT_DIR is this
    # script's own tools/scripts/, i.e. $ROOT, not the throwaway isolated
    # $tree from prepare_lane_tree — that tree gets `reset --hard` + `clean
    # -fd` on the NEXT run, so anything promoted there would be silently
    # discarded). See tools/scripts/promote_fuzz_artifacts.sh for the
    # dedup/size-cap contract; promoted seeds still need `git add` +
    # a commit to actually enter history.
    echo "=== promote_fuzz_artifacts (triage $ARTIFACT_DIR -> lib/test/fuzz_seeds/) ===" | tee -a "$log"
    "$SCRIPT_DIR/promote_fuzz_artifacts.sh" --artifact-dir="$ARTIFACT_DIR" 2>&1 | tee -a "$log" || true

    finished="$(utc_now)"
    finished_epoch="$(epoch_now)"
    elapsed=$((finished_epoch - started_epoch))
    if [ "$rc" -eq 0 ]; then
        write_status "fuzz" "passed" "$started" "$finished" "$elapsed" 0 "$log" "all fuzz targets completed"
    else
        write_status "fuzz" "failed" "$started" "$finished" "$elapsed" "$rc" "$log" \
            "fuzzer failure or crash artifact emitted:${failed_kinds:- unknown}"
    fi
    return "$rc"
}

run_coverage() {
    local started started_epoch finished finished_epoch elapsed rc log
    started="$(utc_now)"
    started_epoch="$(epoch_now)"
    log="$LOG_DIR/coverage-${started//[:]/}.log"

    local tree
    if ! tree="$(prepare_lane_tree coverage)"; then
        QUALITY_TREE="$ROOT"
        QUALITY_SOURCE_RECORD=""
        QUALITY_SOURCE_ID="unknown"
        QUALITY_SOURCE_MUTATION="unknown"
        write_status "coverage" "failed" "$started" "$(utc_now)" 0 2 "$log" \
            "isolated lane checkout preparation failed" || true
        return 2
    fi
    bind_quality_tree "$tree" || {
        write_status "coverage" "failed" "$started" "$(utc_now)" 0 2 "$log" \
            "could not bind exact lane source identity" || true
        return 2
    }

    write_status "coverage" "running" "$started" "" 0 0 "$log" "running make coverage"
    printf 'background_quality: lane=coverage started=%s commit=%s tree=%s\n' \
        "$started" "$(git_commit)" "$tree" | tee -a "$log"

    if run_logged "$log" bash -c "cd \"$tree\" && make coverage"; then
        rc=0
    else
        rc=$?
    fi

    finished="$(utc_now)"
    finished_epoch="$(epoch_now)"
    elapsed=$((finished_epoch - started_epoch))
    if [ "$rc" -eq 0 ]; then
        write_status "coverage" "passed" "$started" "$finished" "$elapsed" 0 "$log" "coverage completed"
    else
        write_status "coverage" "failed" "$started" "$finished" "$elapsed" "$rc" "$log" "make coverage failed"
    fi
    return "$rc"
}

run_tests() {
    local started started_epoch finished finished_epoch elapsed rc log
    started="$(utc_now)"
    started_epoch="$(epoch_now)"
    log="$LOG_DIR/tests-${started//[:]/}.log"

    local tree
    if ! tree="$(prepare_lane_tree tests)"; then
        QUALITY_TREE="$ROOT"
        QUALITY_SOURCE_RECORD=""
        QUALITY_SOURCE_ID="unknown"
        QUALITY_SOURCE_MUTATION="unknown"
        write_status "tests" "failed" "$started" "$(utc_now)" 0 2 "$log" \
            "isolated lane checkout preparation failed" || true
        return 2
    fi
    bind_quality_tree "$tree" || {
        write_status "tests" "failed" "$started" "$(utc_now)" 0 2 "$log" \
            "could not bind exact lane source identity" || true
        return 2
    }

    write_status "tests" "running" "$started" "" 0 0 "$log" "running make test"
    printf 'background_quality: lane=tests started=%s commit=%s tree=%s\n' \
        "$started" "$(git_commit)" "$tree" | tee -a "$log"

    if run_logged "$log" bash -c "cd \"$tree\" && make test"; then
        rc=0
    else
        rc=$?
    fi

    finished="$(utc_now)"
    finished_epoch="$(epoch_now)"
    elapsed=$((finished_epoch - started_epoch))
    if [ "$rc" -eq 0 ]; then
        write_status "tests" "passed" "$started" "$finished" "$elapsed" 0 "$log" "full test suite completed"
    else
        write_status "tests" "failed" "$started" "$finished" "$elapsed" "$rc" "$log" "make test failed"
    fi
    return "$rc"
}

print_status() {
    local fuzz coverage tests
    fuzz="null"
    coverage="null"
    tests="null"
    [ -f "$STATUS_DIR/fuzz.json" ] && fuzz="$(cat "$STATUS_DIR/fuzz.json")"
    [ -f "$STATUS_DIR/coverage.json" ] && coverage="$(cat "$STATUS_DIR/coverage.json")"
    [ -f "$STATUS_DIR/tests.json" ] && tests="$(cat "$STATUS_DIR/tests.json")"
    printf '{'
    printf '"schema":"zcl.background_quality_status.v1"'
    printf ',"state_dir":"%s"' "$(json_escape "$STATE_ROOT")"
    printf ',"lanes":{"fuzz":%s,"coverage":%s,"tests":%s}' "$fuzz" "$coverage" "$tests"
    printf '}\n'
}

usage() {
    cat <<'EOF'
usage: tools/scripts/background_quality_lane.sh <fuzz|coverage|tests|status>

Environment:
  ZCL_QUALITY_STATE_DIR   status/log root (default ~/.local/state/zclassic23-quality)
  ZCL_FUZZ_DURATION       seconds per fuzz target in background mode (default 900)
  ZCL_FUZZ_TIMEOUT        libFuzzer per-input timeout (default 2)
  ZCL_FUZZ_DETECT_LEAKS   ASAN leak detection for fuzz lane (default 0)
EOF
}

case "${1:-status}" in
    fuzz) run_fuzz ;;
    coverage) run_coverage ;;
    tests) run_tests ;;
    status) print_status ;;
    -h|--help|help) usage ;;
    *)
        usage >&2
        exit 2
        ;;
esac
