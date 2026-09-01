#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Controlled developer-loop latency benchmark. Safe cases run build/check
# paths only. The hot-swap case defaults to the REAL dev-lane activation path
# (`make hotswap-apply HANDLER=core.status` — resident leaf re-point in the
# armed zcl23-dev node) and runs only under ZCL_DEV_BENCH_ACTIVATE=1; the
# process-reload case still requires an operator-supplied command because
# process-level generation publication remains contained.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${ZCL_DEV_BENCH_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
# shellcheck source=tools/dev/dev_lib.sh
. "$SCRIPT_DIR/dev_lib.sh"  # is_uint, is_true (fail() below satisfies is_true's contract)
OUTPUT="${ZCL_DEV_BENCH_OUTPUT:-$ROOT/.cache/zcl-dev-loop/bench-latest.json}"
ITERATIONS="${ZCL_DEV_BENCH_ITERATIONS:-5}"
WARMUP="${ZCL_DEV_BENCH_WARMUP:-1}"
ACTIVATE="${ZCL_DEV_BENCH_ACTIVATE:-0}"
HOTSWAP_TARGET_MS="${ZCL_DEV_BENCH_HOTSWAP_TARGET_MS:-1000}"
RELOAD_TARGET_MS="${ZCL_DEV_BENCH_RELOAD_TARGET_MS:-8000}"

TMP_DIR=""
OUTPUT_TMP=""
ANY_FAILURE=0
SOURCE_SUPERSEDED=0
PREREQUISITE_FAILED=0
CAMPAIGN_SOURCE_FINGERPRINT=""
FINAL_SOURCE_FINGERPRINT=""
CAMPAIGN_SOURCE_MUTATION=""
FINAL_SOURCE_MUTATION=""
CAMPAIGN_SOURCE_RECORD=""
FINAL_SOURCE_RECORD=""
BENCHMARK_CONTRACT_FINGERPRINT=""

declare -A CASE_COMMAND CASE_STATUS CASE_CONFIGURED CASE_REQUIRES_ACTIVATION
declare -A CASE_P50 CASE_P95 CASE_SUCCESSES CASE_FAILURES CASE_LAST_RC
declare -A CASE_LOG CASE_SAMPLES

CASES=(no_op one_controller one_service one_header hot_swap process_reload)

log()
{
    printf '[dev-loop-bench] %s\n' "$*"
}

fail()
{
    printf '[dev-loop-bench] FATAL: %s\n' "$*" >&2
    exit 2
}

usage()
{
    printf '%s\n' \
        'Usage: tools/dev/dev-loop-bench.sh [--status|--self-test|--help]' \
        '' \
        'Default: benchmark no-op/controller/service/header check+link paths;' \
        'skip hot-swap and process reload. No service is activated by default.' \
        '' \
        'Activation opt-in (dev lane only):' \
        '  ZCL_DEV_BENCH_ACTIVATE=1' \
        '  ZCL_DEV_BENCH_CMD_HOTSWAP=<resident swap command>' \
        '    (default: make hotswap-apply HANDLER=core.status — the REAL' \
        '    dev-lane activation path against the armed zcl23-dev node)' \
        '  ZCL_DEV_BENCH_CMD_RELOAD=<transactional reload fixture>' \
        '    (process-level generation publication remains contained)' \
        '' \
        'Other controls: ZCL_DEV_BENCH_ITERATIONS, ZCL_DEV_BENCH_WARMUP,' \
        'ZCL_DEV_BENCH_OUTPUT, and ZCL_DEV_BENCH_CMD_<case> overrides.'
}

json_escape()
{
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\b'/\\b}"
    value="${value//$'\f'/\\f}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '%s' "$value"
}

cleanup()
{
    [ -n "$OUTPUT_TMP" ] && rm -f "$OUTPUT_TMP"
    [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"
}

clock_ns()
{
    local now
    now="$(date +%s%N 2>/dev/null || true)"
    if [[ "$now" =~ ^[0-9]+$ ]]; then
        printf '%s' "$now"
    else
        printf '%s000000000' "$(date +%s)"
    fi
}

# Bind every sample to the exact v2 source-identity record used by the build:
# current source bytes plus the host-local mutation token. Git history/object
# ids are absent, and an edit/revert ABA still supersedes the campaign.
capture_source_record()
{
    local tool="$ROOT/tools/dev/source-identity.sh"
    local record source_id clean mutation extra
    [ -x "$tool" ] || return 2
    record="$(cd "$ROOT" && "$tool" capture-record 2>/dev/null)" || return 2
    read -r source_id clean mutation extra <<< "$record"
    [[ "$source_id" =~ ^[0-9a-f]{64}$ ]] &&
        [ "$clean" = "1" ] &&
        [[ "$mutation" =~ ^[0-9a-f]{64}$ ]] &&
        [ -z "${extra:-}" ] || return 2
    printf '%s %s %s\n' "$source_id" "$clean" "$mutation"
}

source_fingerprint_matches_campaign()
{
    local current
    current="$(capture_source_record)" || return 2
    if [ "$current" != "$CAMPAIGN_SOURCE_RECORD" ]; then
        printf '[dev-loop-bench] source superseded expected_record=%s actual_record=%s\n' \
            "$CAMPAIGN_SOURCE_RECORD" "$current" >&2
        return 3
    fi
}

capture_benchmark_contract_fingerprint()
{
    local fingerprint
    fingerprint="$(sha256sum "$SCRIPT_DIR/dev-loop-bench.sh" |
        awk '{print $1}')" || return 2
    [[ "$fingerprint" =~ ^[0-9a-fA-F]{64}$ ]] || return 2
    printf '%s' "${fingerprint,,}"
}

default_safe_watch_command()
{
    local path="$1" state_name
    state_name="$(printf '%s' "$path" | tr '/.' '__')"
    printf '%s' \
        "ZCL_FAST_CACHE=1 ZCL_FAST_COMPILE=strict ZCL_DEV_WATCH_ONCE=1 ZCL_DEV_WATCH_MODE=check ZCL_DEV_WATCH_CHECK_WORKER=1 ZCL_DEV_WATCH_CHECK_SOURCE_RECORD='$CAMPAIGN_SOURCE_RECORD' ZCL_DEV_WATCH_STATE_DIR='$TMP_DIR/watch-state/$state_name' ZCL_DEV_WATCH_ONCE_FILES='$path' tools/dev/watch-dev-lane.sh --once"
}

configure_cases()
{
    CASE_COMMAND[no_op]="${ZCL_DEV_BENCH_CMD_NOOP:-:}"
    CASE_COMMAND[one_controller]="${ZCL_DEV_BENCH_CMD_CONTROLLER:-$(
        default_safe_watch_command cognition/controllers/src/agent_controller.c)}"
    CASE_COMMAND[one_service]="${ZCL_DEV_BENCH_CMD_SERVICE:-$(
        default_safe_watch_command engine/services/src/block_source_policy.c)}"
    CASE_COMMAND[one_header]="${ZCL_DEV_BENCH_CMD_HEADER:-$(
        default_safe_watch_command platform/modules/json/include/json/json.h)}"
    CASE_COMMAND[hot_swap]="${ZCL_DEV_BENCH_CMD_HOTSWAP:-make --no-print-directory hotswap-apply HANDLER=core.status}"
    CASE_COMMAND[process_reload]="${ZCL_DEV_BENCH_CMD_RELOAD:-$(
        default_safe_watch_command cognition/controllers/src/agent_controller.c |
            sed 's/ZCL_DEV_WATCH_MODE=check/ZCL_DEV_WATCH_MODE=reload/')}"

    CASE_CONFIGURED[no_op]=true
    CASE_CONFIGURED[one_controller]=true
    CASE_CONFIGURED[one_service]=true
    CASE_CONFIGURED[one_header]=true
    CASE_CONFIGURED[hot_swap]=true
    CASE_CONFIGURED[process_reload]=true

    CASE_REQUIRES_ACTIVATION[no_op]=false
    CASE_REQUIRES_ACTIVATION[one_controller]=false
    CASE_REQUIRES_ACTIVATION[one_service]=false
    CASE_REQUIRES_ACTIVATION[one_header]=false
    CASE_REQUIRES_ACTIVATION[hot_swap]=true
    CASE_REQUIRES_ACTIVATION[process_reload]=true
}

percentile_nearest_rank()
{
    local samples="$1" percent="$2" count rank
    count="$(sed '/^$/d' "$samples" | wc -l | tr -d ' ')"
    [ "$count" -gt 0 ] || { printf 'null'; return; }
    rank=$(( (count * percent + 99) / 100 ))
    [ "$rank" -gt 0 ] || rank=1
    LC_ALL=C sort -n "$samples" | sed -n "${rank}p"
}

run_case()
{
    local name="$1" command="${CASE_COMMAND[$1]}" total run start end elapsed rc
    local command_rc fingerprint_rc
    local samples="$TMP_DIR/$name.samples" case_log
    local successes=0 failures=0 last_rc=0
    local superseded=false failed=false
    case_log="$(dirname "$OUTPUT")/logs/$name.log"
    mkdir -p "$(dirname "$case_log")"
    : > "$case_log"
    : > "$samples"
    CASE_LOG[$name]="$case_log"
    CASE_SAMPLES[$name]="$samples"

    if [ "${CASE_CONFIGURED[$name]}" != true ]; then
        CASE_STATUS[$name]="not_configured"
        CASE_P50[$name]=null
        CASE_P95[$name]=null
        CASE_SUCCESSES[$name]=0
        CASE_FAILURES[$name]=0
        CASE_LAST_RC[$name]=0
        return
    fi
    if [ "${CASE_REQUIRES_ACTIVATION[$name]}" = true ] &&
       ! is_true "$ACTIVATE"; then
        CASE_STATUS[$name]="skipped_activation_not_opted_in"
        CASE_P50[$name]=null
        CASE_P95[$name]=null
        CASE_SUCCESSES[$name]=0
        CASE_FAILURES[$name]=0
        CASE_LAST_RC[$name]=0
        return
    fi
    if [ "$SOURCE_SUPERSEDED" -eq 1 ]; then
        CASE_STATUS[$name]="skipped_source_superseded"
        CASE_P50[$name]=null
        CASE_P95[$name]=null
        CASE_SUCCESSES[$name]=0
        CASE_FAILURES[$name]=0
        CASE_LAST_RC[$name]=0
        return
    fi
    if [ "$PREREQUISITE_FAILED" -eq 1 ]; then
        CASE_STATUS[$name]="skipped_prior_failure"
        CASE_P50[$name]=null
        CASE_P95[$name]=null
        CASE_SUCCESSES[$name]=0
        CASE_FAILURES[$name]=0
        CASE_LAST_RC[$name]=0
        return
    fi

    # A case is not allowed to start against a source tree different from the
    # campaign epoch. This catches an external edit before paying any build or
    # test cost, even when the child command has no source-CAS of its own.
    source_fingerprint_matches_campaign >> "$case_log" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ]; then
        CASE_SUCCESSES[$name]=0
        CASE_FAILURES[$name]=1
        CASE_LAST_RC[$name]="$rc"
        CASE_P50[$name]=null
        CASE_P95[$name]=null
        if [ "$rc" -eq 3 ]; then
            CASE_STATUS[$name]="superseded"
            SOURCE_SUPERSEDED=1
        else
            CASE_STATUS[$name]="failed"
            ANY_FAILURE=1
            PREREQUISITE_FAILED=1
        fi
        return
    fi

    total=$((WARMUP + ITERATIONS))
    log "case=$name warmup=$WARMUP measured=$ITERATIONS"
    for ((run = 1; run <= total; run++)); do
        source_fingerprint_matches_campaign >> "$case_log" 2>&1
        fingerprint_rc=$?
        if [ "$fingerprint_rc" -ne 0 ]; then
            failures=$((failures + 1))
            last_rc="$fingerprint_rc"
            if [ "$fingerprint_rc" -eq 3 ]; then
                superseded=true
                SOURCE_SUPERSEDED=1
            else
                failed=true
                ANY_FAILURE=1
                PREREQUISITE_FAILED=1
            fi
            break
        fi

        start="$(clock_ns)"
        (cd "$ROOT" && /bin/sh -c "$command") >> "$case_log" 2>&1
        command_rc=$?
        end="$(clock_ns)"
        elapsed=$(( (end - start + 999999) / 1000000 ))

        # An edit during the child invalidates its timing regardless of the
        # child exit code. Check immediately so even the final iteration can
        # never be accepted from a mixed source epoch.
        source_fingerprint_matches_campaign >> "$case_log" 2>&1
        fingerprint_rc=$?
        if [ "$fingerprint_rc" -ne 0 ]; then
            failures=$((failures + 1))
            last_rc="$fingerprint_rc"
            if [ "$fingerprint_rc" -eq 3 ]; then
                superseded=true
                SOURCE_SUPERSEDED=1
            else
                failed=true
                ANY_FAILURE=1
                PREREQUISITE_FAILED=1
            fi
            break
        fi

        last_rc="$command_rc"
        if [ "$command_rc" -ne 0 ]; then
            failures=$((failures + 1))
            if [ "$command_rc" -eq 3 ]; then
                superseded=true
                SOURCE_SUPERSEDED=1
            else
                failed=true
                ANY_FAILURE=1
                PREREQUISITE_FAILED=1
            fi
            break
        fi
        if [ "$run" -le "$WARMUP" ]; then
            continue
        fi
        printf '%s\n' "$elapsed" >> "$samples"
        successes=$((successes + 1))
    done

    CASE_SUCCESSES[$name]="$successes"
    CASE_FAILURES[$name]="$failures"
    CASE_LAST_RC[$name]="$last_rc"
    CASE_P50[$name]="$(percentile_nearest_rank "$samples" 50)"
    CASE_P95[$name]="$(percentile_nearest_rank "$samples" 95)"
    if [ "$superseded" = true ]; then
        CASE_STATUS[$name]="superseded"
    elif [ "$failed" = true ] || [ "$failures" -gt 0 ] ||
         [ "$successes" -ne "$ITERATIONS" ]; then
        CASE_STATUS[$name]="failed"
        ANY_FAILURE=1
        PREREQUISITE_FAILED=1
    else
        CASE_STATUS[$name]="passed"
    fi
}

write_samples_json()
{
    local file="$1" sep="" value
    printf '['
    while IFS= read -r value; do
        [ -n "$value" ] || continue
        printf '%s%s' "$sep" "$value"
        sep=','
    done < "$file"
    printf ']'
}

slo_case_status()
{
    local name="$1" target="$2" status="${CASE_STATUS[$1]}"
    local p95="${CASE_P95[$1]}"
    if [ "$status" != passed ] || [ "$p95" = null ]; then
        case "$status" in
            failed) printf 'error' ;;
            *) printf 'not_measured' ;;
        esac
    elif [ "$p95" -le "$target" ]; then
        printf 'pass'
    else
        printf 'miss'
    fi
}

emit_artifact()
{
    local destination="$1" tmp generated_at epoch hostname kernel cpu_count
    local commit dirty=false worktree_status_fingerprint final_clean
    local hot_status reload_status source_stable=false
    local overall_evaluable=false next_action sep="" name status
    mkdir -p "$(dirname "$destination")"
    tmp="$(mktemp "$(dirname "$destination")/.bench-latest.json.XXXXXX")" ||
        fail 'could not create atomic benchmark staging file'
    OUTPUT_TMP="$tmp"
    generated_at="$(date -u +%FT%TZ)"
    epoch="$(date +%s)"
    hostname="$(hostname 2>/dev/null || printf unknown)"
    kernel="$(uname -sr 2>/dev/null || printf unknown)"
    cpu_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 0)"
    commit="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || printf unknown)"
    if ! git -C "$ROOT" diff-index --quiet HEAD -- 2>/dev/null; then
        dirty=true
    fi
    worktree_status_fingerprint="$(
        git -C "$ROOT" status --porcelain=v1 --untracked-files=normal 2>/dev/null |
        sha256sum | awk '{print $1}')" || worktree_status_fingerprint=unavailable
    FINAL_SOURCE_RECORD="$(capture_source_record 2>/dev/null)" ||
        FINAL_SOURCE_RECORD="unavailable 0 unavailable"
    read -r FINAL_SOURCE_FINGERPRINT final_clean FINAL_SOURCE_MUTATION \
        <<< "$FINAL_SOURCE_RECORD"
    if [ "$FINAL_SOURCE_RECORD" = "$CAMPAIGN_SOURCE_RECORD" ]; then
        source_stable=true
    fi
    hot_status="$(slo_case_status hot_swap "$HOTSWAP_TARGET_MS")"
    reload_status="$(slo_case_status process_reload "$RELOAD_TARGET_MS")"
    if [ "$hot_status" != not_measured ] &&
       [ "$reload_status" != not_measured ]; then
        overall_evaluable=true
    fi
    if [ "$SOURCE_SUPERSEDED" -eq 1 ]; then
        next_action="source epoch changed during the verify-only benchmark; rerun when the workspace is stable or set an isolated ZCL_DEV_BENCH_ROOT"
    elif [ "$ANY_FAILURE" -ne 0 ]; then
        next_action="inspect the first failed case; dependent benchmark cases were skipped instead of retrying the same broken prerequisite"
    elif ! is_true "$ACTIVATE"; then
        next_action="verify-only baseline recorded; rerun with ZCL_DEV_BENCH_ACTIVATE=1 to measure the dev-lane hot-swap SLO against the armed zcl23-dev node (process-level publication remains contained)"
    elif [ "$hot_status" = miss ] || [ "$reload_status" = miss ]; then
        next_action="inspect the per-case logs and optimize the measured miss"
    elif [ "$hot_status" = pass ] && [ "$reload_status" = pass ]; then
        next_action="retain this artifact as the declared reference-host SLO proof"
    else
        next_action="configure every activation case before making SLO claims"
    fi

    {
        printf '{\n'
        printf '  "schema":"zcl.dev_loop_bench.v1",\n'
        if [ "$ANY_FAILURE" -ne 0 ]; then
            status=failed
        elif [ "$SOURCE_SUPERSEDED" -eq 1 ]; then
            status=superseded
        else
            status=ok
        fi
        printf '  "status":"%s",\n' "$status"
        printf '  "generated_at_utc":"%s",\n' "$(json_escape "$generated_at")"
        printf '  "generated_at_epoch":%s,\n' "$epoch"
        printf '  "artifact":"%s",\n' "$(json_escape "$destination")"
        printf '  "host":{"hostname":"%s","kernel":"%s","cpu_count":%s},\n' \
            "$(json_escape "$hostname")" "$(json_escape "$kernel")" "$cpu_count"
        printf '  "source":{"identity_schema":"zcl.dev_source_identity.v2",'
        printf '"freshness_authority":"source_id_sha256_plus_mutation_token",'
        printf '"build_commit":"%s","build_commit_semantics":"display_only_github_trace_metadata","dirty":%s,' \
            "$(json_escape "$commit")" "$dirty"
        printf '"worktree_status_sha256":"%s",' "$worktree_status_fingerprint"
        printf '"campaign_source_sha256":"%s","final_source_sha256":"%s",' \
            "$CAMPAIGN_SOURCE_FINGERPRINT" "$FINAL_SOURCE_FINGERPRINT"
        printf '"campaign_mutation_token":"%s","final_mutation_token":"%s",' \
            "$CAMPAIGN_SOURCE_MUTATION" "$FINAL_SOURCE_MUTATION"
        printf '"source_stable":%s},\n' "$source_stable"
        printf '  "configuration":{"iterations":%s,"warmup":%s,' \
            "$ITERATIONS" "$WARMUP"
        printf '"activation_opt_in":%s,"benchmark_contract_sha256":"%s"},\n' \
            "$(is_true "$ACTIVATE" && printf true || printf false)" \
            "$BENCHMARK_CONTRACT_FINGERPRINT"
        printf '  "cases":[\n'
        for name in "${CASES[@]}"; do
            printf '%s    {' "$sep"
            printf '"name":"%s",' "$name"
            printf '"requires_activation":%s,' "${CASE_REQUIRES_ACTIVATION[$name]}"
            printf '"configured":%s,' "${CASE_CONFIGURED[$name]}"
            printf '"status":"%s",' "${CASE_STATUS[$name]}"
            printf '"command":"%s",' "$(json_escape "${CASE_COMMAND[$name]}")"
            printf '"successful_samples":%s,' "${CASE_SUCCESSES[$name]}"
            printf '"failures":%s,' "${CASE_FAILURES[$name]}"
            printf '"last_exit_code":%s,' "${CASE_LAST_RC[$name]}"
            printf '"samples_ms":'
            write_samples_json "${CASE_SAMPLES[$name]}"
            printf ',"p50_ms":%s,"p95_ms":%s,' \
                "${CASE_P50[$name]}" "${CASE_P95[$name]}"
            printf '"log":"%s"}' "$(json_escape "${CASE_LOG[$name]}")"
            sep=$',\n'
        done
        printf '\n  ],\n'
        printf '  "slo":{"evaluable":%s,' "$overall_evaluable"
        printf '"hot_swap":{"target_p95_ms":%s,"p95_ms":%s,"status":"%s"},' \
            "$HOTSWAP_TARGET_MS" "${CASE_P95[hot_swap]}" "$hot_status"
        printf '"process_reload":{"target_p95_ms":%s,"p95_ms":%s,"status":"%s"}},\n' \
            "$RELOAD_TARGET_MS" "${CASE_P95[process_reload]}" "$reload_status"
        printf '  "agent_next_action":"%s"\n' "$(json_escape "$next_action")"
        printf '}\n'
    } > "$tmp"
    mv -f "$tmp" "$destination"
    OUTPUT_TMP=""
}

run_benchmark()
{
    local name status campaign_clean
    [ -d "$ROOT" ] || fail "repository root does not exist: $ROOT"
    is_uint "$ITERATIONS" && [ "$ITERATIONS" -gt 0 ] ||
        fail 'ZCL_DEV_BENCH_ITERATIONS must be a positive integer'
    is_uint "$WARMUP" || fail 'ZCL_DEV_BENCH_WARMUP must be non-negative'
    is_uint "$HOTSWAP_TARGET_MS" && is_uint "$RELOAD_TARGET_MS" ||
        fail 'SLO targets must be non-negative integers'
    is_true "$ACTIVATE" >/dev/null || true
    ANY_FAILURE=0
    SOURCE_SUPERSEDED=0
    PREREQUISITE_FAILED=0
    FINAL_SOURCE_FINGERPRINT=""
    FINAL_SOURCE_MUTATION=""
    FINAL_SOURCE_RECORD=""
    BENCHMARK_CONTRACT_FINGERPRINT="$(
        capture_benchmark_contract_fingerprint)" ||
        fail 'could not fingerprint benchmark contract'
    CAMPAIGN_SOURCE_RECORD="$(capture_source_record)" ||
        fail 'could not capture exact source-identity v2 record'
    read -r CAMPAIGN_SOURCE_FINGERPRINT campaign_clean CAMPAIGN_SOURCE_MUTATION \
        <<< "$CAMPAIGN_SOURCE_RECORD"

    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zcl-dev-loop-bench.XXXXXX")" ||
        fail 'could not create temporary workspace'
    trap cleanup EXIT
    mkdir -p "$(dirname "$OUTPUT")/logs"
    configure_cases
    for name in "${CASES[@]}"; do
        run_case "$name"
    done
    emit_artifact "$OUTPUT"
    if [ "$ANY_FAILURE" -ne 0 ]; then
        status=failed
    elif [ "$SOURCE_SUPERSEDED" -eq 1 ]; then
        status=superseded
    else
        status=ok
    fi
    log "artifact=$OUTPUT status=$status"
    [ "$ANY_FAILURE" -eq 0 ] || return 1
    [ "$SOURCE_SUPERSEDED" -eq 0 ] || return 3
    return 0
}

self_test()
{
    local sandbox first second third fourth fifth marker rc
    local failure_runs failure_marker fresh_status stale_status legacy_status
    local source_tool source_backup record_before record_after record_aba
    local source_before source_after source_aba clean_before clean_after clean_aba
    local mutation_before mutation_after mutation_aba default_command
    source_tool="$SCRIPT_DIR/source-identity.sh"
    sandbox="$(mktemp -d "${TMPDIR:-/tmp}/zcl-dev-loop-selftest.XXXXXX")" ||
        return 1
    ROOT="$sandbox/repo"
    mkdir -p "$ROOT/tools/dev"
    cp "$source_tool" "$ROOT/tools/dev/source-identity.sh" || {
        rm -rf "$sandbox"
        return 1
    }
    chmod 755 "$ROOT/tools/dev/source-identity.sh"
    git -C "$ROOT" init -q || { rm -rf "$sandbox"; return 1; }
    git -C "$ROOT" config user.name zcl-dev-loop-selftest
    git -C "$ROOT" config user.email dev-loop-selftest@invalid
    printf 'baseline\n' > "$ROOT/source.txt"
    git -C "$ROOT" add source.txt tools/dev/source-identity.sh &&
        git -C "$ROOT" commit -qm baseline || {
            rm -rf "$sandbox"
            return 1
        }

    # Git history is display metadata, not benchmark supersession authority.
    # Conversely, the v2 mutation token must reject an edit/revert ABA even
    # when the exact source bytes (and therefore source ID) are restored.
    record_before="$(capture_source_record)" || {
        rm -rf "$sandbox"
        return 1
    }
    git -C "$ROOT" commit --allow-empty -qm history-only || {
        rm -rf "$sandbox"
        return 1
    }
    record_after="$(capture_source_record)" || {
        rm -rf "$sandbox"
        return 1
    }
    [ "$record_before" = "$record_after" ] || {
        printf '[dev-loop-bench-selftest] FAIL: Git history superseded benchmark source authority\n' >&2
        rm -rf "$sandbox"
        return 1
    }
    source_backup="$sandbox/source.backup"
    cp "$ROOT/source.txt" "$source_backup"
    printf 'transient edit\n' >> "$ROOT/source.txt"
    cp "$source_backup" "$ROOT/source.txt"
    chmod 600 "$ROOT/source.txt"
    chmod 644 "$ROOT/source.txt"
    record_aba="$(capture_source_record)" || {
        rm -rf "$sandbox"
        return 1
    }
    read -r source_before clean_before mutation_before <<< "$record_before"
    read -r source_after clean_after mutation_after <<< "$record_after"
    read -r source_aba clean_aba mutation_aba <<< "$record_aba"
    [ "$source_before" = "$source_after" ] &&
    [ "$source_before" = "$source_aba" ] &&
    [ "$clean_before" = 1 ] && [ "$clean_after" = 1 ] &&
    [ "$clean_aba" = 1 ] &&
    [ "$mutation_before" = "$mutation_after" ] &&
    [ "$mutation_before" != "$mutation_aba" ] || {
        printf '[dev-loop-bench-selftest] FAIL: exact source authority was not history-independent and ABA-safe\n' >&2
        rm -rf "$sandbox"
        return 1
    }
    TMP_DIR="$sandbox/default-state"
    CAMPAIGN_SOURCE_RECORD="$record_after"
    default_command="$(default_safe_watch_command source.txt)"
    case "$default_command" in
        *"ZCL_FAST_COMPILE=strict"*) ;;
        *)
            printf '[dev-loop-bench-selftest] FAIL: default warm proof is not reusable by strict pre-push\n' >&2
            rm -rf "$sandbox"
            return 1
            ;;
    esac
    ITERATIONS=3
    WARMUP=1
    ACTIVATE=0
    ZCL_DEV_BENCH_CMD_NOOP=':'
    ZCL_DEV_BENCH_CMD_CONTROLLER=':'
    ZCL_DEV_BENCH_CMD_SERVICE=':'
    ZCL_DEV_BENCH_CMD_HEADER=':'
    ZCL_DEV_BENCH_CMD_HOTSWAP=':'
    ZCL_DEV_BENCH_CMD_RELOAD=':'
    export ZCL_DEV_BENCH_CMD_NOOP ZCL_DEV_BENCH_CMD_CONTROLLER
    export ZCL_DEV_BENCH_CMD_SERVICE ZCL_DEV_BENCH_CMD_HEADER
    export ZCL_DEV_BENCH_CMD_HOTSWAP ZCL_DEV_BENCH_CMD_RELOAD

    first="$sandbox/no-activation.json"
    OUTPUT="$first"
    ANY_FAILURE=0
    run_benchmark >/dev/null || { rm -rf "$sandbox"; return 1; }
    grep -q '"schema":"zcl.dev_loop_bench.v1"' "$first" &&
    grep -q '"name":"hot_swap".*"status":"skipped_activation_not_opted_in"' "$first" &&
    grep -q '"evaluable":false' "$first" || {
        printf '[dev-loop-bench-selftest] FAIL: safe artifact contract\n' >&2
        rm -rf "$sandbox"
        return 1
    }
    if command -v jq >/dev/null 2>&1; then
        jq -e '.schema == "zcl.dev_loop_bench.v1" and
               (.cases | type == "array") and
               (.cases | length == 6)' "$first" >/dev/null || {
            printf '[dev-loop-bench-selftest] FAIL: safe artifact is not valid contract JSON\n' >&2
            rm -rf "$sandbox"
            return 1
        }
    fi

    cleanup
    TMP_DIR=""
    ACTIVATE=1
    second="$sandbox/activation-opt-in.json"
    OUTPUT="$second"
    ANY_FAILURE=0
    run_benchmark >/dev/null || { rm -rf "$sandbox"; return 1; }
    grep -q '"name":"hot_swap".*"status":"passed"' "$second" &&
    grep -q '"name":"process_reload".*"status":"passed"' "$second" &&
    grep -q '"evaluable":true' "$second" || {
        printf '[dev-loop-bench-selftest] FAIL: opt-in artifact contract\n' >&2
        rm -rf "$sandbox"
        return 1
    }

    cleanup
    TMP_DIR=""
    ACTIVATE=0
    third="$sandbox/superseded.json"
    marker="$sandbox/should-not-run"
    OUTPUT="$third"
    ZCL_DEV_BENCH_CMD_CONTROLLER='exit 3'
    ZCL_DEV_BENCH_CMD_SERVICE="printf ran > '$marker'"
    ZCL_DEV_BENCH_CMD_HEADER="printf ran > '$marker'"
    export ZCL_DEV_BENCH_CMD_CONTROLLER ZCL_DEV_BENCH_CMD_SERVICE
    export ZCL_DEV_BENCH_CMD_HEADER
    run_benchmark >/dev/null
    rc=$?
    [ "$rc" -eq 3 ] && [ ! -e "$marker" ] &&
    grep -q '"status":"superseded"' "$third" &&
    grep -q '"name":"one_service".*"status":"skipped_source_superseded"' "$third" &&
    grep -q '"name":"one_header".*"status":"skipped_source_superseded"' "$third" || {
        printf '[dev-loop-bench-selftest] FAIL: superseded source did not stop redundant cases\n' >&2
        rm -rf "$sandbox"
        return 1
    }
    if command -v jq >/dev/null 2>&1; then
        jq -e '.status == "superseded"' "$third" >/dev/null || {
            printf '[dev-loop-bench-selftest] FAIL: superseded artifact is not valid contract JSON\n' >&2
            rm -rf "$sandbox"
            return 1
        }
    fi

    # A child that returns success after an external source edit must not
    # contribute a timing sample. The post-iteration fingerprint catches the
    # drift and the remaining verify-only cases never execute.
    cleanup
    TMP_DIR=""
    fourth="$sandbox/fingerprint-drift.json"
    marker="$sandbox/drift-later-case-ran"
    OUTPUT="$fourth"
    ZCL_DEV_BENCH_CMD_CONTROLLER="printf 'external edit\\n' >> '$ROOT/source.txt'"
    ZCL_DEV_BENCH_CMD_SERVICE="printf ran > '$marker'"
    ZCL_DEV_BENCH_CMD_HEADER="printf ran > '$marker'"
    export ZCL_DEV_BENCH_CMD_CONTROLLER ZCL_DEV_BENCH_CMD_SERVICE
    export ZCL_DEV_BENCH_CMD_HEADER
    run_benchmark >/dev/null
    rc=$?
    [ "$rc" -eq 3 ] && [ ! -e "$marker" ] &&
    grep -q '"name":"one_controller".*"status":"superseded"' "$fourth" &&
    grep -q '"name":"one_service".*"status":"skipped_source_superseded"' "$fourth" &&
    grep -q '"source_stable":false' "$fourth" || {
        printf '[dev-loop-bench-selftest] FAIL: external source drift was accepted or repeated\n' >&2
        rm -rf "$sandbox"
        return 1
    }
    git -C "$ROOT" restore -- source.txt || {
        rm -rf "$sandbox"
        return 1
    }

    # Any ordinary nonzero result is a broken prerequisite, not a reason to
    # repeat the same compile failure for every sample and later case.
    cleanup
    TMP_DIR=""
    fifth="$sandbox/failure-fast.json"
    failure_runs="$sandbox/failure-runs"
    failure_marker="$sandbox/failure-later-case-ran"
    OUTPUT="$fifth"
    ZCL_DEV_BENCH_CMD_CONTROLLER="printf 'attempt\\n' >> '$failure_runs'; exit 1"
    ZCL_DEV_BENCH_CMD_SERVICE="printf ran > '$failure_marker'"
    ZCL_DEV_BENCH_CMD_HEADER="printf ran > '$failure_marker'"
    export ZCL_DEV_BENCH_CMD_CONTROLLER ZCL_DEV_BENCH_CMD_SERVICE
    export ZCL_DEV_BENCH_CMD_HEADER
    run_benchmark >/dev/null
    rc=$?
    [ "$rc" -eq 1 ] && [ "$(wc -l < "$failure_runs" | tr -d ' ')" -eq 1 ] &&
    [ ! -e "$failure_marker" ] &&
    grep -q '"name":"one_controller".*"status":"failed".*"failures":1' "$fifth" &&
    grep -q '"name":"one_service".*"status":"skipped_prior_failure"' "$fifth" &&
    grep -q '"name":"one_header".*"status":"skipped_prior_failure"' "$fifth" || {
        printf '[dev-loop-bench-selftest] FAIL: nonzero result was retried or later cases ran\n' >&2
        rm -rf "$sandbox"
        return 1
    }
    if command -v jq >/dev/null 2>&1; then
        jq -e '.status == "failed" and .source.source_stable == true' \
            "$fifth" >/dev/null || {
            printf '[dev-loop-bench-selftest] FAIL: fail-fast artifact is invalid JSON\n' >&2
            rm -rf "$sandbox"
            return 1
        }
    fi

    # Status is authoritative only for the exact source and benchmark
    # contract that produced the artifact. A current artifact passes through
    # byte-for-byte; a subsequent source edit yields compact stale metadata.
    fresh_status="$sandbox/status-fresh.json"
    stale_status="$sandbox/status-stale.json"
    OUTPUT="$fifth"
    emit_status > "$fresh_status"
    cmp -s "$fifth" "$fresh_status" || {
        printf '[dev-loop-bench-selftest] FAIL: current status did not preserve fresh artifact\n' >&2
        rm -rf "$sandbox"
        return 1
    }
    printf 'status drift\n' >> "$ROOT/source.txt"
    emit_status > "$stale_status"
    grep -q '"status":"stale"' "$stale_status" &&
    grep -q '"reason":"artifact_source_superseded"' "$stale_status" &&
    grep -q '"artifact_status":"failed"' "$stale_status" &&
    grep -q '"source_stable":false' "$stale_status" || {
        printf '[dev-loop-bench-selftest] FAIL: stale source artifact remained authoritative\n' >&2
        rm -rf "$sandbox"
        return 1
    }
    if command -v jq >/dev/null 2>&1; then
        jq -e '.status == "stale" and
               .reason == "artifact_source_superseded"' \
            "$stale_status" >/dev/null || {
            printf '[dev-loop-bench-selftest] FAIL: stale status is invalid JSON\n' >&2
            rm -rf "$sandbox"
            return 1
        }
    fi
    git -C "$ROOT" restore -- source.txt || {
        rm -rf "$sandbox"
        return 1
    }

    # Pre-binding artifacts from the older benchmark contract fail closed as
    # stale rather than surfacing old cases as if they described this tree.
    legacy_status="$sandbox/status-legacy.json"
    OUTPUT="$sandbox/legacy.json"
    printf '{"schema":"zcl.dev_loop_bench.v1","status":"failed"}\n' > "$OUTPUT"
    emit_status > "$legacy_status"
    grep -q '"status":"stale"' "$legacy_status" &&
    grep -q '"reason":"artifact_missing_source_binding"' "$legacy_status" || {
        printf '[dev-loop-bench-selftest] FAIL: legacy artifact was not marked stale\n' >&2
        rm -rf "$sandbox"
        return 1
    }
    rm -rf "$sandbox"
    TMP_DIR=""
    printf '[dev-loop-bench-selftest] PASS: source-ID v2 authority is history-independent and ABA-safe; valid JSON, fail-fast supersession, safe skips, samples, percentiles\n'
}

emit_status_problem()
{
    local status="$1" reason="$2" artifact_status="$3"
    local age="$4" stored_source="$5" current_source="$6"
    local stored_mutation="$7" current_mutation="$8"
    local stored_contract="$9" current_contract="${10}"
    printf '{"schema":"zcl.dev_loop_bench.v1","status":"%s",' \
        "$(json_escape "$status")"
    printf '"artifact_status":"%s","reason":"%s",' \
        "$(json_escape "$artifact_status")" "$(json_escape "$reason")"
    printf '"artifact":"%s","artifact_age_seconds":%s,' \
        "$(json_escape "$OUTPUT")" "$age"
    printf '"source":{"identity_schema":"zcl.dev_source_identity.v2",'
    printf '"freshness_authority":"source_id_sha256_plus_mutation_token",'
    printf '"artifact_final_source_sha256":"%s",' \
        "$(json_escape "$stored_source")"
    printf '"current_source_sha256":"%s",' \
        "$(json_escape "$current_source")"
    printf '"artifact_final_mutation_token":"%s",' \
        "$(json_escape "$stored_mutation")"
    printf '"current_mutation_token":"%s","source_stable":false},' \
        "$(json_escape "$current_mutation")"
    printf '"configuration":{"artifact_benchmark_contract_sha256":"%s",' \
        "$(json_escape "$stored_contract")"
    printf '"current_benchmark_contract_sha256":"%s"},' \
        "$(json_escape "$current_contract")"
    printf '"slo":{"evaluable":false,'
    printf '"hot_swap":{"target_p95_ms":%s,"p95_ms":null,"status":"not_measured"},' \
        "$HOTSWAP_TARGET_MS"
    printf '"process_reload":{"target_p95_ms":%s,"p95_ms":null,"status":"not_measured"}},' \
        "$RELOAD_TARGET_MS"
    printf '"agent_next_action":"rerun make dev-loop-bench on a stable source epoch; stale or invalid evidence is never authoritative"}\n'
}

emit_status()
{
    if [ -r "$OUTPUT" ]; then
        local artifact_status generated age now reason=""
        local stored_source current_source stored_mutation current_mutation
        local stored_contract current_contract current_record current_clean
        if command -v jq >/dev/null 2>&1 &&
           ! jq -e '.schema == "zcl.dev_loop_bench.v1"' "$OUTPUT" \
                >/dev/null 2>&1; then
            emit_status_problem invalid invalid_artifact_json unknown null \
                unavailable unavailable unavailable unavailable \
                unavailable unavailable
            return 0
        fi
        artifact_status="$(sed -n \
            's/^[[:space:]]*"status":"\([^"]*\)".*/\1/p' \
            "$OUTPUT" | head -1)"
        generated="$(sed -n \
            's/^[[:space:]]*"generated_at_epoch":\([0-9][0-9]*\).*/\1/p' \
            "$OUTPUT" | head -1)"
        stored_source="$(sed -n \
            's/.*"final_source_sha256":"\([0-9a-fA-F]*\)".*/\1/p' \
            "$OUTPUT" | head -1)"
        stored_mutation="$(sed -n \
            's/.*"final_mutation_token":"\([0-9a-fA-F]*\)".*/\1/p' \
            "$OUTPUT" | head -1)"
        stored_contract="$(sed -n \
            's/.*"benchmark_contract_sha256":"\([0-9a-fA-F]*\)".*/\1/p' \
            "$OUTPUT" | head -1)"
        [ -n "$artifact_status" ] || artifact_status=unknown
        now="$(date +%s)"
        if [[ "$generated" =~ ^[0-9]+$ ]] && [ "$now" -ge "$generated" ]; then
            age=$((now - generated))
        else
            age=null
        fi
        current_contract="$(capture_benchmark_contract_fingerprint)" ||
            current_contract=unavailable
        current_record="$(capture_source_record 2>/dev/null)" ||
            current_record="unavailable 0 unavailable"
        read -r current_source current_clean current_mutation \
            <<< "$current_record"
        if [[ ! "$stored_source" =~ ^[0-9a-fA-F]{64}$ ]] ||
           [[ ! "$stored_mutation" =~ ^[0-9a-fA-F]{64}$ ]] ||
           [[ ! "$stored_contract" =~ ^[0-9a-fA-F]{64}$ ]]; then
            reason=artifact_missing_source_binding
        elif [ "$current_contract" = unavailable ] ||
             [ "$current_source" = unavailable ] ||
             [ "$current_mutation" = unavailable ]; then
            reason=current_source_fingerprint_unavailable
        elif [ "${stored_contract,,}" != "$current_contract" ]; then
            reason=benchmark_contract_changed
        elif [ "${stored_source,,}" != "$current_source" ]; then
            reason=artifact_source_superseded
        elif [ "${stored_mutation,,}" != "$current_mutation" ]; then
            reason=artifact_source_mutation_superseded
        fi
        if [ -z "$reason" ]; then
            sed -n '1,$p' "$OUTPUT"
            return 0
        fi
        emit_status_problem stale "$reason" "$artifact_status" "$age" \
            "${stored_source:-unavailable}" "$current_source" \
            "${stored_mutation:-unavailable}" "$current_mutation" \
            "${stored_contract:-unavailable}" "$current_contract"
        return 0
    fi
    printf '{"schema":"zcl.dev_loop_bench.v1","status":"missing",'
    printf '"artifact":"%s","slo":{"evaluable":false,' \
        "$(json_escape "$OUTPUT")"
    printf '"hot_swap":{"target_p95_ms":%s,"p95_ms":null,"status":"not_measured"},' \
        "$HOTSWAP_TARGET_MS"
    printf '"process_reload":{"target_p95_ms":%s,"p95_ms":null,"status":"not_measured"}},' \
        "$RELOAD_TARGET_MS"
    printf '"agent_next_action":"run make dev-loop-bench for a verify-only baseline; ZCL_DEV_BENCH_ACTIVATE=1 measures the armed dev-lane hot-swap SLO"}\n'
}

case "${1:-}" in
    --help|-h) usage ;;
    --status) emit_status ;;
    --self-test|--selftest) self_test ;;
    "") run_benchmark ;;
    *) usage >&2; exit 2 ;;
esac
