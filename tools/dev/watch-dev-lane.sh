#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Save-driven development loop for the isolated zcl23-dev lane.
#
# The loop classifies every save before verification. Runtime publication is
# contained; the separate typed hot-swap command owns eligible leaf activation.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tools/dev/dev_lib.sh
. "$SCRIPT_DIR/dev_lib.sh"  # is_uint, is_true (fail() below satisfies is_true's contract)
DEFAULT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ROOT="${ZCL_DEV_WATCH_ROOT:-$DEFAULT_ROOT}"
MODE="${ZCL_DEV_WATCH_MODE:-verify}"
POLL_MS="${ZCL_DEV_WATCH_POLL_MS:-500}"
DEBOUNCE_MS="${ZCL_DEV_WATCH_DEBOUNCE_MS:-500}"
BACKEND="${ZCL_DEV_WATCH_BACKEND:-auto}"
RUN_ONCE="${ZCL_DEV_WATCH_ONCE:-0}"
RUN_INITIAL="${ZCL_DEV_WATCH_INITIAL:-0}"
WARM_CODEINDEX="${ZCL_DEV_WARM_CODEINDEX:-1}"
CHECK_WORKER="${ZCL_DEV_WATCH_CHECK_WORKER:-0}"
CHECK_SOURCE_RECORD="${ZCL_DEV_WATCH_CHECK_SOURCE_RECORD:-}"

# Test/automation seams.  Empty means use the real in-tree command.
CHECK_COMMAND="${ZCL_DEV_WATCH_CHECK_COMMAND:-}"
REBUILD_COMMAND="${ZCL_DEV_WATCH_REBUILD_COMMAND:-}"
DEPLOY_COMMAND="${ZCL_DEV_WATCH_DEPLOY_COMMAND:-}"
STAGE_COMMAND="${ZCL_DEV_WATCH_STAGE_COMMAND:-}"
DEFAULT_STATE_DIR="$HOME/.local/state/zclassic23-dev"
STATE_DIR="${ZCL_DEV_WATCH_STATE_DIR:-$DEFAULT_STATE_DIR}"
PREACTIVATE_COMMAND="${ZCL_DEV_WATCH_PREACTIVATE_COMMAND:-}"
WATCH_LOCK_REL=".cache/zcl-dev-watch.lock"

STOP_REQUESTED=0
CYCLE=0
WORK=""
NEXT_MANIFEST=""
SETTLED_MANIFEST=""
SELECTED_PATH=""
SELECTED_PROBE=""
SELECTION_REASON=""
CLASSIFIED_PATH=""
CLASSIFICATION_REASON=""
OBSERVED_FILES_FILE=""
IMPACT_PLAN=""
HEARTBEAT="$STATE_DIR/watcher-heartbeat.json"
LAST_CYCLE_RECORD=""
LAST_OUTCOME="starting"

# Per-cycle evidence populated by run_cycle and serialized once on every
# verdict.  Millisecond timings are wall-clock feedback metrics, never
# consensus time.
CYCLE_ID=""
CYCLE_STARTED_MS=0
CLASSIFY_MS=0
CHECK_MS=0
LINK_MS=0
ACTIVATE_MS=0
CANDIDATE_GENERATION=""
RUNNING_GENERATION=""
LAST_GOOD_GENERATION=""
ROLLBACK_STATUS="not_needed"
FAILURE_PHASE=""
FAILURE_DETAIL=""
AGENT_NEXT_ACTION=""
CHECK_RESULT="not_run"
LINK_RESULT="not_run"
ACTIVATION_RESULT="not_run"
SOURCE_ID=""
SOURCE_CLEAN=""
SOURCE_MUTATION=""
SOURCE_GATE_DETAIL=""

log()
{
    printf '[dev-watch] %s\n' "$*"
}

fail()
{
    printf '[dev-watch] FATAL: %s\n' "$*" >&2
    exit 2
}

usage()
{
    cat <<'EOF'
Usage: tools/dev/watch-dev-lane.sh [--once|--self-test|--help]

Watches C/header/build/tool inputs, coalesces editor saves, and runs the
existing verification lane. Every nonempty wake event is conservatively
classified as reload-required with the consensus-parity and sealed-Core gates;
runtime publication is Phase-0 contained.

Environment:
  ZCL_DEV_WATCH_MODE=verify|check      verification only; runtime publication
                                      modes are contained until immutable
                                      epochs and proof receipts are complete
  ZCL_DEV_WATCH_POLL_MS=500           polling interval without inotifywait
  ZCL_DEV_WATCH_DEBOUNCE_MS=500       quiet window used to coalesce saves
  ZCL_DEV_WATCH_BACKEND=auto|poll|inotify
  ZCL_DEV_WATCH_ONCE=1                run one deterministic cycle and exit
  ZCL_DEV_WATCH_ONCE_FILES='a.c b.h'  exact once-mode paths
  ZCL_DEV_WATCH_ONCE_FILES_FILE=path  newline-delimited once-mode paths
  ZCL_DEV_WATCH_INITIAL=1             run one conservative all-input check first
  ZCL_DEV_WATCH_STATE_DIR=path        durable cycles + watcher heartbeat
  ZCL_DEV_WATCH_CHECK_WORKER=1        bounded benchmark worker; requires
                                      --once, check mode and isolated state
  ZCL_DEV_WATCH_CHECK_SOURCE_RECORD=  already captured v2 record for a
                                      bounded check worker; always reverified
  ZCL_DEV_WARM_CODEINDEX=1            warm cognition/modules/codeindex after each green
                                      cycle (default on); set 0 to disable

Examples:
  make dev-watch
  ZCL_DEV_WATCH_MODE=check make dev-watch
  ZCL_DEV_WATCH_ONCE_FILES=core/modules/net/src/msg_tx.c make dev-watch-once
EOF
}

clock_ms()
{
    local value
    value="$(date +%s%3N 2>/dev/null || true)"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        printf '%s' "$value"
    else
        printf '%s000' "$(date +%s)"
    fi
}

json_escape()
{
    # Paths and diagnostics are single-line by construction.  Keep this
    # stock-toolchain implementation independent of jq/python.
    printf '%s' "${1:-}" | sed \
        -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
        -e ':a;N;$!ba;s/\n/\\n/g' -e 's/\r/\\r/g' -e 's/\t/\\t/g'
}

json_array_from_file()
{
    local input="$1" first=1 item
    printf '['
    if [ -r "$input" ]; then
        while IFS= read -r item; do
            [ -n "$item" ] || continue
            [ "$first" -eq 1 ] || printf ','
            printf '"%s"' "$(json_escape "$item")"
            first=0
        done < "$input"
    fi
    printf ']'
}

json_string_field_from_file()
{
    local input="$1" key="$2" token
    [ -r "$input" ] || return 0
    token="$(grep -o "\"${key}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
        "$input" 2>/dev/null | head -1 || true)"
    [ -n "$token" ] || return 0
    printf '%s\n' "$token" |
        sed -n "s/^\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"$/\1/p"
}

write_heartbeat()
{
    local state="${1:-running}" tmp now
    mkdir -p "$STATE_DIR"
    tmp="$(mktemp "$STATE_DIR/.watcher-heartbeat.XXXXXX")" || return 0
    now="$(date -u +%FT%TZ)"
    {
        printf '{"schema":"zcl.dev_watch_heartbeat.v1"'
        printf ',"pid":%s' "$$"
        printf ',"state":"%s"' "$(json_escape "$state")"
        printf ',"updated_at_utc":"%s"' "$(json_escape "$now")"
        printf ',"cycle":%s' "$CYCLE"
        printf ',"current_cycle_id":"%s"' "$(json_escape "$CYCLE_ID")"
        printf ',"last_outcome":"%s"' "$(json_escape "$LAST_OUTCOME")"
        printf ',"last_cycle_record":"%s"' "$(json_escape "$LAST_CYCLE_RECORD")"
        printf '}\n'
    } > "$tmp"
    mv -f "$tmp" "$HEARTBEAT"
}

impact_plan_is_json()
{
    [ -s "$IMPACT_PLAN" ] && grep -q '^[[:space:]]*{' "$IMPACT_PLAN"
}

write_cycle_record()
{
    local changed_file="$1" outcome="$2" total_ms now cycle_dir record tmp latest_tmp
    local persisted_files next_action
    local impact='{"schema":"zcl.agent_fast_plan.v1","status":"unavailable"}'
    local hotswap='{"schema":"zcl.dev_hotswap_result.v1","status":"not_applicable"}'
    local activation_state="${ZCL_DEV_ACTIVATION_RESULT:-$HOME/.zclassic-c23-dev/agent-deploy.json}"

    mkdir -p "$STATE_DIR/cycles" || fail "cannot create cycle state dir: $STATE_DIR/cycles"
    cycle_dir="$STATE_DIR/cycles"
    record="$cycle_dir/$CYCLE_ID.json"
    persisted_files="$cycle_dir/$CYCLE_ID.files"
    cp "$changed_file" "$persisted_files" || fail "cannot persist changed-file list"
    next_action="${AGENT_NEXT_ACTION//$changed_file/$persisted_files}"
    tmp="$(mktemp "$cycle_dir/.cycle.XXXXXX")" || fail "cannot allocate cycle record"
    now="$(date -u +%FT%TZ)"
    total_ms=$(( $(clock_ms) - CYCLE_STARTED_MS ))
    impact_plan_is_json && impact="$(cat "$IMPACT_PLAN")"
    CANDIDATE_GENERATION="$(json_string_field_from_file "$activation_state" candidate_generation)"
    RUNNING_GENERATION="$(json_string_field_from_file "$activation_state" running_generation)"
    LAST_GOOD_GENERATION="$(json_string_field_from_file "$activation_state" last_good_generation)"
    ROLLBACK_STATUS="$(json_string_field_from_file "$activation_state" rollback_status)"
    [ -n "$ROLLBACK_STATUS" ] || ROLLBACK_STATUS="not_needed"

    {
        printf '{\n'
        printf '  "schema":"zcl.dev_cycle.v1",\n'
        printf '  "schema_version":1,\n'
        printf '  "cycle_id":"%s",\n' "$(json_escape "$CYCLE_ID")"
        printf '  "captured_at_utc":"%s",\n' "$(json_escape "$now")"
        printf '  "watcher_pid":%s,\n' "$$"
        printf '  "requested_mode":"%s",\n' "$(json_escape "$MODE")"
        printf '  "source_identity":"%s",\n' "$(json_escape "$SOURCE_ID")"
        printf '  "selected_path":"%s",\n' "$(json_escape "$SELECTED_PATH")"
        printf '  "selected_probe":"%s",\n' "$(json_escape "$SELECTED_PROBE")"
        printf '  "selection_reason":"%s",\n' "$(json_escape "$SELECTION_REASON")"
        printf '  "classified_path":"%s",\n' "$(json_escape "$CLASSIFIED_PATH")"
        printf '  "classification_reason":"%s",\n' "$(json_escape "$CLASSIFICATION_REASON")"
        printf '  "outcome":"%s",\n' "$(json_escape "$outcome")"
        printf '  "observed_files":';
        if [ -n "$OBSERVED_FILES_FILE" ] && [ -r "$OBSERVED_FILES_FILE" ]; then
            json_array_from_file "$OBSERVED_FILES_FILE"
        else
            printf '[]'
        fi
        printf ',\n'
        printf '  "changed_files":'; json_array_from_file "$changed_file"; printf ',\n'
        printf '  "impact_plan":%s,\n' "$impact"
        printf '  "timings_ms":{"classification":%s,"check":%s,"link":%s,"activation":%s,"total":%s},\n' \
            "$CLASSIFY_MS" "$CHECK_MS" "$LINK_MS" "$ACTIVATE_MS" "$total_ms"
        printf '  "candidate_generation":"%s",\n' "$(json_escape "$CANDIDATE_GENERATION")"
        printf '  "running_generation":"%s",\n' "$(json_escape "$RUNNING_GENERATION")"
        printf '  "last_good_generation":"%s",\n' "$(json_escape "$LAST_GOOD_GENERATION")"
        printf '  "tests":{"mapped_source":"impact_plan.test_groups","focused_status":"%s"},\n' \
            "$(json_escape "$CHECK_RESULT")"
        printf '  "probes":{"check":{"status":"%s","elapsed_ms":%s},' \
            "$(json_escape "$CHECK_RESULT")" "$CHECK_MS"
        printf '"link":{"status":"%s","elapsed_ms":%s},' \
            "$(json_escape "$LINK_RESULT")" "$LINK_MS"
        printf '"activation":{"status":"%s","elapsed_ms":%s}},\n' \
            "$(json_escape "$ACTIVATION_RESULT")" "$ACTIVATE_MS"
        printf '  "hotswap":%s,\n' "$hotswap"
        printf '  "rollback":{"status":"%s"},\n' "$(json_escape "$ROLLBACK_STATUS")"
        printf '  "failure_capsule":{"phase":"%s","detail":"%s","replay_command":"%s"},\n' \
            "$(json_escape "$FAILURE_PHASE")" "$(json_escape "$FAILURE_DETAIL")" \
            "$(json_escape "ZCL_DEV_WATCH_ONCE_FILES_FILE=$persisted_files MODE=$MODE make dev-watch-once")"
        printf '  "agent_next_action":"%s"\n' "$(json_escape "$next_action")"
        printf '}\n'
    } > "$tmp"
    mv -f "$tmp" "$record" || fail "cannot publish cycle record"
    latest_tmp="$(mktemp "$STATE_DIR/.latest-cycle.XXXXXX")" || fail "cannot allocate latest-cycle record"
    cp "$record" "$latest_tmp" || fail "cannot copy latest-cycle record"
    mv -f "$latest_tmp" "$STATE_DIR/latest-cycle.json" || fail "cannot publish latest-cycle record"
    LAST_CYCLE_RECORD="$record"
    LAST_OUTCOME="$outcome"
    write_heartbeat running
}

validate_options()
{
    [ -d "$ROOT" ] || fail "repository root does not exist: $ROOT"
    case "$MODE" in
        check|verify) ;;
        auto|apply|hotswap|reload|stage|deploy)
            fail "runtime publication mode '$MODE' is contained; use verify until immutable epochs and proof receipts are transactional"
            ;;
        off) MODE="check" ;;     # compatibility with the bounded watcher MVP
        *) fail "ZCL_DEV_WATCH_MODE must be verify or check (got $MODE)" ;;
    esac
    # These shell-command seams exist solely inside --self-test.  Accepting
    # them in a public watcher would turn an environment variable into an
    # arbitrary publication/proof authority.
    [ -z "${ZCL_DEV_WATCH_CHECK_COMMAND+x}" ] &&
    [ -z "${ZCL_DEV_WATCH_REBUILD_COMMAND+x}" ] &&
    [ -z "${ZCL_DEV_WATCH_DEPLOY_COMMAND+x}" ] &&
    [ -z "${ZCL_DEV_WATCH_STAGE_COMMAND+x}" ] &&
    [ -z "${ZCL_DEV_WATCH_PREACTIVATE_COMMAND+x}" ] ||
        fail "ZCL_DEV_WATCH_*_COMMAND overrides are confined to --self-test"
    case "$BACKEND" in
        auto|poll|inotify) ;;
        *) fail "ZCL_DEV_WATCH_BACKEND must be auto, poll, or inotify (got $BACKEND)" ;;
    esac
    is_uint "$POLL_MS" && [ "$POLL_MS" -gt 0 ] ||
        fail "ZCL_DEV_WATCH_POLL_MS must be a positive integer"
    is_uint "$DEBOUNCE_MS" ||
        fail "ZCL_DEV_WATCH_DEBOUNCE_MS must be a non-negative integer"
    case "$STATE_DIR" in
        /*) ;;
        *) fail "ZCL_DEV_WATCH_STATE_DIR must be absolute (got $STATE_DIR)" ;;
    esac
    is_true "$CHECK_WORKER" >/dev/null || true
    if is_true "$CHECK_WORKER"; then
        is_true "$RUN_ONCE" ||
            fail "ZCL_DEV_WATCH_CHECK_WORKER requires --once"
        [ "$MODE" = "check" ] ||
            fail "ZCL_DEV_WATCH_CHECK_WORKER requires check mode"
        [ "$STATE_DIR" != "$DEFAULT_STATE_DIR" ] ||
            fail "ZCL_DEV_WATCH_CHECK_WORKER requires an isolated ZCL_DEV_WATCH_STATE_DIR"
        if [ -n "$CHECK_SOURCE_RECORD" ]; then
            local check_id check_clean check_mutation check_extra
            read -r check_id check_clean check_mutation check_extra \
                <<< "$CHECK_SOURCE_RECORD"
            [[ "$check_id" =~ ^[0-9a-f]{64}$ ]] &&
            [ "$check_clean" = 1 ] &&
            [[ "$check_mutation" =~ ^[0-9a-f]{64}$ ]] &&
            [ -z "${check_extra:-}" ] ||
                fail "ZCL_DEV_WATCH_CHECK_SOURCE_RECORD must be '<sha256> 1 <sha256>'"
        fi
    elif [ -n "$CHECK_SOURCE_RECORD" ]; then
        fail "ZCL_DEV_WATCH_CHECK_SOURCE_RECORD requires ZCL_DEV_WATCH_CHECK_WORKER=1"
    fi
}

sleep_ms()
{
    local milliseconds="$1" seconds
    [ "$milliseconds" -gt 0 ] || return 0
    seconds="$(awk -v ms="$milliseconds" 'BEGIN { printf "%.3f", ms / 1000 }')"
    sleep "$seconds"
}

refresh_watch_paths()
{
    local candidate
    WATCH_PATHS=()
    for candidate in Makefile README.md AGENTS.md app application adapters \
        config core docs domain lib ports src tools vendor/include; do
        [ -e "$ROOT/$candidate" ] && WATCH_PATHS+=("$candidate")
    done
    [ "${#WATCH_PATHS[@]}" -gt 0 ] ||
        fail "no watchable source paths found below $ROOT"
}

is_relevant_path()
{
    local path="${1#./}"
    case "$path" in
        Makefile|README.md|AGENTS.md|docs/*.md|*.mk) return 0 ;;
        app/*|engine/application/*|platform/adapters/*|config/*|core/*|domain/*|lib/*|platform/ports/*|src/*|tools/*|vendor/include/*)
            case "$path" in
                *.c|*.h|*.def|*.inc|*.md|*.mk|*.service|*.sh|*.css|*.js|*.html|*.tmpl)
                    return 0
                    ;;
            esac
            ;;
    esac
    return 1
}

mode_publishes()
{
    case "$MODE" in
        auto|hotswap|reload|stage) return 0 ;;
        *) return 1 ;;
    esac
}

# A wake-event path list is diagnostic only and may omit pre-existing or
# simultaneous edits. Source authority is the exact SHA-256 identity plus the
# host-local mutation token returned by one capture-record. Git history/object
# ids do not participate. Hidden index flags and inventory races fail closed in
# source-identity.sh; the explicit Core/parity Make gates run separately.
capture_source_epoch()
{
    local record
    SOURCE_ID=""
    SOURCE_CLEAN=""
    SOURCE_MUTATION=""
    SOURCE_GATE_DETAIL=""
    if is_true "$CHECK_WORKER" && [ -n "$CHECK_SOURCE_RECORD" ]; then
        record="$CHECK_SOURCE_RECORD"
    else
        record="$(cd "$ROOT" && "$SCRIPT_DIR/source-identity.sh" capture-record \
            2> "$WORK/source-identity.err")" || {
            SOURCE_GATE_DETAIL="$(tr '\r\n' '  ' < "$WORK/source-identity.err")"
            [ -n "$SOURCE_GATE_DETAIL" ] || SOURCE_GATE_DETAIL="source identity capture failed"
            return 1
        }
    fi
    read -r SOURCE_ID SOURCE_CLEAN SOURCE_MUTATION <<< "$record"
    [[ "$SOURCE_ID" =~ ^[0-9a-f]{64}$ ]] &&
    [ "$SOURCE_CLEAN" = 1 ] &&
    [[ "$SOURCE_MUTATION" =~ ^[0-9a-f]{64}$ ]] || {
        SOURCE_GATE_DETAIL="source capture-record was malformed"
        SOURCE_ID=""
        SOURCE_CLEAN=""
        SOURCE_MUTATION=""
        return 1
    }
}

check_lane_attests_source_epoch()
{
    # agent_fast_ci v3 verifies the frozen record before a cache hit and again
    # before writing a new receipt.  The check lane has no activation or other
    # side effect; its surrounding manifest compare catches a later save.
    [ "$MODE" = "check" ] && [ -z "$CHECK_COMMAND" ]
}

verify_source_epoch()
{
    [ -n "$SOURCE_ID" ] && [ -n "$SOURCE_MUTATION" ] || {
        SOURCE_GATE_DETAIL="source identity was never captured"
        return 1
    }
    if ! (cd "$ROOT" && "$SCRIPT_DIR/source-identity.sh" verify-record \
            "$SOURCE_ID" "$SOURCE_CLEAN" "$SOURCE_MUTATION") \
            > /dev/null 2> "$WORK/source-identity.err"; then
        SOURCE_GATE_DETAIL="$(tr '\r\n' '  ' < "$WORK/source-identity.err")"
        [ -n "$SOURCE_GATE_DETAIL" ] || SOURCE_GATE_DETAIL="source epoch superseded"
        return 1
    fi
    return 0
}

# The manifest is cheap enough to poll: one find and one sort, with a SHA-256
# (or POSIX cksum fallback) over sorted path/mtime/size rows.  It intentionally
# does not hash every source file on every 500 ms tick.
write_manifest()
{
    local output="$1" tmp="$1.tmp"
    (
        cd "$ROOT" || exit 1
        find "${WATCH_PATHS[@]}" -type f \
            \( -name 'Makefile' -o -name '*.mk' -o -name '*.c' -o \
               -name '*.h' -o -name '*.def' -o -name '*.inc' -o \
               -name '*.md' -o -name '*.service' -o \
               -name '*.sh' -o -name '*.css' -o \
               -name '*.js' -o -name '*.html' -o -name '*.tmpl' \) \
            -printf '%T@:%s\t%p\n' 2>/dev/null | LC_ALL=C sort
    ) > "$tmp" || {
        rm -f "$tmp"
        return 1
    }
    mv -f "$tmp" "$output"
}

manifest_digest()
{
    local manifest="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$manifest" | awk '{print $1}'
    else
        cksum "$manifest" | awk '{print $1 ":" $2}'
    fi
}

manifests_equal()
{
    [ "$(manifest_digest "$1")" = "$(manifest_digest "$2")" ]
}

manifest_changed_paths()
{
    local old_manifest="$1" new_manifest="$2" output="$3"
    awk -F '\t' '
        FILENAME == ARGV[1] { old[$2] = $1; next }
        {
            current[$2] = $1
            if (!($2 in old) || old[$2] != $1) print $2
        }
        END {
            for (path in old)
                if (!(path in current)) print path
        }
    ' "$old_manifest" "$new_manifest" | LC_ALL=C sort -u > "$output"
}

append_relevant_path()
{
    local path="${1#./}" output="$2"
    [ -n "$path" ] || return 0
    is_relevant_path "$path" && printf '%s\n' "$path" >> "$output"
}

dirty_relevant_paths()
{
    local output="$1" path inventory="$WORK/conservative-all-inputs"
    : > "$output"
    if [ -n "${ZCL_DEV_WATCH_ONCE_FILES_FILE:-}" ]; then
        [ -r "$ZCL_DEV_WATCH_ONCE_FILES_FILE" ] ||
            fail "once files list is unreadable: $ZCL_DEV_WATCH_ONCE_FILES_FILE"
        while IFS= read -r path; do
            append_relevant_path "$path" "$output"
        done < "$ZCL_DEV_WATCH_ONCE_FILES_FILE"
    fi
    if [ -n "${ZCL_DEV_WATCH_ONCE_FILES:-}" ]; then
        while IFS= read -r path; do
            append_relevant_path "$path" "$output"
        done < <(printf '%s\n' "$ZCL_DEV_WATCH_ONCE_FILES" | tr ' ,' '\n')
    fi
    if [ ! -s "$output" ]; then
        # Without an explicit wake list there is no SHA-1-free changed-set
        # oracle. Check every watched input instead of consulting Git HEAD.
        write_manifest "$inventory" ||
            fail "could not inventory conservative initial/once check"
        while IFS= read -r path; do
            append_relevant_path "$path" "$output"
        done < <(cut -f2- "$inventory")
    fi
    LC_ALL=C sort -u "$output" -o "$output"
}

# Events and once-mode lists are wake hints only. Normalize them for diagnostics
# and focused-check routing, but never promote the list to source or publication
# authority. Classification therefore assumes omitted simultaneous inputs and
# takes the reload+Core/parity boundary for every nonempty event.
normalize_wake_paths()
{
    local input="$1" output="$2" path
    : > "$output"
    while IFS= read -r path; do
        append_relevant_path "$path" "$output"
    done < "$input"
    LC_ALL=C sort -u "$output" -o "$output"
    [ -s "$output" ] || {
        SOURCE_GATE_DETAIL="wake event contained no relevant source path"
        return 1
    }
}

classify_cycle()
{
    local changed_file="$1" started count
    started="$(clock_ms)"
    count="$(sed '/^$/d' "$changed_file" | wc -l | tr -d ' ')"
    SELECTED_PATH="reload"
    SELECTED_PROBE=""
    SELECTION_REASON="reload_required: wake paths are diagnostic-only; exact SHA-1-free changed-set proof is unavailable; sealed-Core and consensus_parity gates required"

    CLASSIFIED_PATH="$SELECTED_PATH"
    CLASSIFICATION_REASON="$SELECTION_REASON"

    case "$MODE" in
        auto|hotswap|reload|stage)
            SELECTED_PATH="rejected"
            SELECTION_REASON="Phase-0 containment: runtime publication is unavailable; verify the reload+consensus_parity candidate only"
            ;;
        check) SELECTED_PATH="check"; SELECTED_PROBE=""; SELECTION_REASON="forced verification-only path; classified_path=$CLASSIFIED_PATH: $CLASSIFICATION_REASON" ;;
        verify) SELECTED_PATH="check"; SELECTED_PROBE=""; SELECTION_REASON="default verify-only execution; classified_path=$CLASSIFIED_PATH: $CLASSIFICATION_REASON; runtime publication is Phase-0 contained" ;;
    esac
    CLASSIFY_MS=$(( $(clock_ms) - started ))
}

capture_impact_plan()
{
    IMPACT_PLAN="$WORK/impact-plan.json"
    if ! (cd "$ROOT" && \
            ZCL_FAST_BUILD_SOURCE_RECORD="$SOURCE_ID $SOURCE_CLEAN $SOURCE_MUTATION" \
            tools/agent_fast_ci.sh plan-json) > "$IMPACT_PLAN" 2>/dev/null; then
        printf '%s\n' '{"schema":"zcl.agent_fast_plan.v1","status":"error","reason":"plan_json_failed"}' > "$IMPACT_PLAN"
    fi
}

resolve_backend()
{
    case "$BACKEND" in
        auto)
            if command -v inotifywait >/dev/null 2>&1; then
                BACKEND="inotify"
            else
                BACKEND="poll"
            fi
            ;;
        inotify)
            command -v inotifywait >/dev/null 2>&1 ||
                fail "inotify backend requested but inotifywait is unavailable"
            ;;
    esac
}

wait_for_possible_change()
{
    local absolute_paths=() path rc
    if [ "$BACKEND" = "poll" ]; then
        sleep_ms "$POLL_MS"
        return 0
    fi

    for path in "${WATCH_PATHS[@]}"; do
        absolute_paths+=("$ROOT/$path")
    done
    inotifywait -q -r -e close_write,create,delete,move,attrib \
        "${absolute_paths[@]}" >/dev/null 2>&1
    rc=$?
    if [ "$rc" -ne 0 ] && [ "$STOP_REQUESTED" -eq 0 ]; then
        log "inotify unavailable after watch start; falling back to polling"
        BACKEND="poll"
        sleep_ms "$POLL_MS"
    fi
}

# Starting with a manifest that is already known to differ, wait until no
# further relevant save arrives for one debounce window.
settle_manifest()
{
    local initial="$1" current="$WORK/settle-current" next="$WORK/settle-next"
    cp "$initial" "$current"
    while [ "$STOP_REQUESTED" -eq 0 ]; do
        sleep_ms "$DEBOUNCE_MS"
        write_manifest "$next" || return 1
        if manifests_equal "$current" "$next"; then
            SETTLED_MANIFEST="$WORK/settled"
            cp "$next" "$SETTLED_MANIFEST"
            return 0
        fi
        cp "$next" "$current"
    done
    return 1
}

wait_for_source_change()
{
    local observed="$1" candidate="$WORK/candidate"
    while [ "$STOP_REQUESTED" -eq 0 ]; do
        wait_for_possible_change
        [ "$STOP_REQUESTED" -eq 0 ] || return 1
        write_manifest "$candidate" || {
            log "manifest read failed; retrying"
            continue
        }
        if ! manifests_equal "$observed" "$candidate"; then
            settle_manifest "$candidate" || return 1
            NEXT_MANIFEST="$SETTLED_MANIFEST"
            return 0
        fi
    done
    return 1
}

run_check_command()
{
    local source_record="$SOURCE_ID $SOURCE_CLEAN $SOURCE_MUTATION"
    if [ -n "$CHECK_COMMAND" ]; then
        # Self-test command seams do not produce a reusable proof receipt, so
        # retain the explicit global gates for them.
        (cd "$ROOT" && make --no-print-directory \
            BUILD_SOURCE_RECORD="$source_record" \
            watcher-safety-gates) || return $?
        (cd "$ROOT" && /bin/sh -c "$CHECK_COMMAND")
    elif [ "$MODE" = "verify" ]; then
        # The ff ladder is deliberately uncached. Neither safety gate may be
        # inferred from its diagnostic wake list.
        (cd "$ROOT" && make --no-print-directory \
            BUILD_SOURCE_RECORD="$source_record" \
            watcher-safety-gates) || return $?
        # Take the checkout lock DIRECTLY here rather than through the `ff`
        # target's own wrapper. The lock tool reports "a foreground build
        # holds this" as exit 99, but GNU make reports *any* failed recipe as
        # exit 2, so reaching the lock through `make ff` collapsed every
        # deferral into a generic failure and left the rc == 99 branch in
        # run_cycle() unreachable from this — the default — mode. With sibling
        # lanes compiling in other checkouts that turned routine, expected
        # contention into a stream of false `rejected` verdicts.
        # checkout-lock.sh exports ZCL_CHECKOUT_LOCK_HELD=1 around the command
        # it runs, so the inner make's own wrapper execs straight through
        # instead of re-acquiring (and self-deadlocking). This mirrors the
        # non-verify branch below, which always had the nesting right.
        (cd "$ROOT" && tools/dev/checkout-lock.sh watcher \
            "$ROOT/build/.checkout.lock" -- \
            env ZCL_DEV_WATCH_LANE=1 make --no-print-directory \
            BUILD_SOURCE_RECORD="$source_record" ff)
    else
        # The check lane's v3 cache receipt is written only after the same
        # global gates pass. Exact-source hits reattach to that proof inside
        # agent_fast_ci instead of rerunning the gates here.
        (cd "$ROOT" && tools/dev/checkout-lock.sh watcher \
            "$ROOT/build/.checkout.lock" -- tools/agent_fast_ci.sh)
    fi
}

run_rebuild_command()
{
    local source_record="$SOURCE_ID $SOURCE_CLEAN $SOURCE_MUTATION"
    if [ -n "$REBUILD_COMMAND" ]; then
        (cd "$ROOT" && /bin/sh -c "$REBUILD_COMMAND")
    else
        (cd "$ROOT" && ZCL_DEV_WATCH_LANE=1 make --no-print-directory \
            BUILD_SOURCE_RECORD="$source_record" fast-rebuild)
    fi
}

run_activation_command()
{
    case "$SELECTED_PATH" in
        check)
            return 0
            ;;
        stage)
            if [ -n "$STAGE_COMMAND" ]; then
                (cd "$ROOT" && /bin/sh -c "$STAGE_COMMAND")
            else
                (cd "$ROOT" && ZCL_DEV_SOURCE_ID="$SOURCE_ID" \
                    ZCL_DEV_DEPLOY_BUILD=fast \
                    ZCL_DEV_USE_PREBUILT=1 \
                    ZCL_DEV_BUILD_ARTIFACT="$ROOT/build/bin/zclassic23-dev" \
                    tools/dev/deploy-dev-lane.sh --stage)
            fi
            ;;
        reload)
            if [ -n "$DEPLOY_COMMAND" ]; then
                (cd "$ROOT" && /bin/sh -c "$DEPLOY_COMMAND")
            else
                (cd "$ROOT" && ZCL_DEV_SOURCE_ID="$SOURCE_ID" \
                    ZCL_DEV_DEPLOY_BUILD=fast \
                    ZCL_DEV_USE_PREBUILT=1 \
                    ZCL_DEV_BUILD_ARTIFACT="$ROOT/build/bin/zclassic23-dev" \
                    tools/dev/deploy-dev-lane.sh)
            fi
            ;;
        rejected)
            return 2
            ;;
        *)
            log "internal classifier error: unsupported path=$SELECTED_PATH"
            return 2
            ;;
    esac
}

schedule_codeindex_warm()
{
    is_true "$WARM_CODEINDEX" || return 0
    command -v flock >/dev/null 2>&1 || return 0
    local bin="$ROOT/build/bin/zclassic23-dev" lock_file="$STATE_DIR/codeindex-warm.lock"
    [ -x "$bin" ] || return 0
    mkdir -p "$STATE_DIR"
    ( nice flock -n "$lock_file" "$bin" code map >/dev/null 2>&1 || true ) &
    log "cycle=$CYCLE scheduled codeindex warm pid=$! lock=$lock_file"
}

source_still_matches()
{
    local expected="$1" probe="$WORK/source-probe"
    write_manifest "$probe" && manifests_equal "$expected" "$probe"
}

elapsed_seconds()
{
    local started="$1" now
    now="$(date +%s)"
    printf '%s' "$((now - started))"
}

# Return: 0 accepted, 1 rejected, 3 superseded by a newer save.
run_cycle()
{
    local observed_file="$1" expected_manifest="$2" started count phase_started rc
    local changed_file="$WORK/cycle-complete-$((CYCLE + 1))"
    CYCLE=$((CYCLE + 1))
    started="$(date +%s)"
    CYCLE_STARTED_MS="$(clock_ms)"
    CYCLE_ID="${CYCLE_STARTED_MS}-$$-${CYCLE}"
    CLASSIFY_MS=0
    CHECK_MS=0
    LINK_MS=0
    ACTIVATE_MS=0
    FAILURE_PHASE=""
    FAILURE_DETAIL=""
    AGENT_NEXT_ACTION=""
    CHECK_RESULT="not_run"
    LINK_RESULT="not_run"
    ACTIVATION_RESULT="not_run"
    SOURCE_ID=""
    SOURCE_CLEAN=""
    SOURCE_MUTATION=""
    SOURCE_GATE_DETAIL=""
    CLASSIFIED_PATH=""
    CLASSIFICATION_REASON=""
    OBSERVED_FILES_FILE="$observed_file"
    ROLLBACK_STATUS="not_needed"
    LAST_OUTCOME="in_progress"
    write_heartbeat checking
    if ! normalize_wake_paths "$observed_file" "$changed_file"; then
        FAILURE_PHASE="wake_set_normalization"
        FAILURE_DETAIL="$SOURCE_GATE_DETAIL"
        AGENT_NEXT_ACTION="save a watched source input or pass an explicit relevant once-mode wake path"
        CLASSIFIED_PATH="unknown"
        CLASSIFICATION_REASON="no relevant wake path was available"
        write_cycle_record "$observed_file" refused
        log "cycle=$CYCLE refused before classification: $SOURCE_GATE_DETAIL"
        return 1
    fi
    count="$(sed '/^$/d' "$changed_file" | wc -l | tr -d ' ')"

    export ZCL_FAST_CHANGED_FILES_FILE="$changed_file"
    export ZCL_FAST_CHANGED_FILES_ONLY=1
    export ZCL_FAST_LIVE=0
    export ZCL_DEV_ACTIVATION_RESULT="${ZCL_DEV_ACTIVATION_RESULT:-$HOME/.zclassic-c23-dev/agent-deploy.json}"
    export ZCL_DEV_CYCLE_ID="$CYCLE_ID"

    classify_cycle "$changed_file"
    log "cycle=$CYCLE check files=$count mode=$MODE path=$SELECTED_PATH"
    log "cycle=$CYCLE reason=$SELECTION_REASON"
    sed 's/^/[dev-watch]   observed: /' "$observed_file"
    sed 's/^/[dev-watch]   classified: /' "$changed_file"

    # Defense in depth for in-process/test callers that bypass validate_options.
    # No event list, environment variable, source id, or Git trace can confer
    # Phase-0 activation authority.
    if mode_publishes; then
        FAILURE_PHASE="phase0_containment"
        FAILURE_DETAIL="runtime publication is Phase-0 contained"
        AGENT_NEXT_ACTION="MODE=verify ZCL_DEV_WATCH_ONCE_FILES_FILE=$changed_file make dev-watch-once"
        write_cycle_record "$changed_file" refused
        log "cycle=$CYCLE refused before checks: runtime publication is Phase-0 contained"
        return 1
    fi

    if [ "$SELECTED_PATH" = "rejected" ]; then
        FAILURE_PHASE="classification"
        FAILURE_DETAIL="$SELECTION_REASON"
        AGENT_NEXT_ACTION="MODE=reload ZCL_DEV_WATCH_ONCE_FILES_FILE=$changed_file make dev-watch-once"
        write_cycle_record "$changed_file" rejected
        log "cycle=$CYCLE rejected phase=classification; running dev service was not touched"
        return 1
    fi

    if ! capture_source_epoch; then
        FAILURE_PHASE="source_epoch_capture"
        FAILURE_DETAIL="$SOURCE_GATE_DETAIL"
        AGENT_NEXT_ACTION="clear hidden Git index bits or repair source inventory, then retry verify"
        write_cycle_record "$changed_file" refused
        log "cycle=$CYCLE refused before checks: $SOURCE_GATE_DETAIL"
        return 1
    fi
    export ZCL_FAST_BUILD_SOURCE_RECORD="$SOURCE_ID $SOURCE_CLEAN $SOURCE_MUTATION"
    capture_impact_plan

    phase_started="$(clock_ms)"
    run_check_command
    rc=$?
    CHECK_MS=$(( $(clock_ms) - phase_started ))
    if [ "$rc" -eq 99 ]; then
        # tools/dev/checkout-lock.sh: a foreground make already holds the
        # per-checkout lock. This is not a check failure — the watcher
        # yields and retries on the next poll instead of racing a
        # foreground build/test run in the same checkout.
        CHECK_RESULT="deferred"
        FAILURE_PHASE="deferred"
        FAILURE_DETAIL="foreground build holds the checkout lock"
        AGENT_NEXT_ACTION="retry after the foreground build/test run finishes"
        write_cycle_record "$changed_file" deferred
        log "cycle=$CYCLE deferred: foreground build holds the lock"
        return 3
    fi
    CHECK_RESULT="$([ "$rc" -eq 0 ] && printf passed || printf failed)"
    if [ "$rc" -ne 0 ]; then
        FAILURE_PHASE="check"
        FAILURE_DETAIL="focused verification failed with exit $rc"
        AGENT_NEXT_ACTION="MODE=check ZCL_DEV_WATCH_ONCE_FILES_FILE=$changed_file make dev-watch-once"
        write_cycle_record "$changed_file" rejected
        log "cycle=$CYCLE rejected phase=check; running dev service was not touched"
        return 1
    fi
    if ! source_still_matches "$expected_manifest"; then
        FAILURE_PHASE="superseded"
        FAILURE_DETAIL="source changed after focused checks"
        AGENT_NEXT_ACTION="MODE=$MODE ZCL_DEV_WATCH_ONCE_FILES_FILE=$changed_file make dev-watch-once"
        write_cycle_record "$changed_file" superseded
        log "cycle=$CYCLE superseded after checks; coalescing newest tree"
        return 3
    fi
    if ! check_lane_attests_source_epoch && ! verify_source_epoch; then
        FAILURE_PHASE="source_epoch_cas"
        FAILURE_DETAIL="$SOURCE_GATE_DETAIL"
        AGENT_NEXT_ACTION="coalesce the newest exact source epoch and rerun verify"
        write_cycle_record "$changed_file" superseded
        log "cycle=$CYCLE superseded after checks: $SOURCE_GATE_DETAIL"
        return 3
    fi

    if [ "$SELECTED_PATH" = "reload" ] || [ "$SELECTED_PATH" = "stage" ]; then
        phase_started="$(clock_ms)"
        run_rebuild_command
        rc=$?
        LINK_MS=$(( $(clock_ms) - phase_started ))
        LINK_RESULT="$([ "$rc" -eq 0 ] && printf passed || printf failed)"
        if [ "$rc" -ne 0 ]; then
            FAILURE_PHASE="link"
            FAILURE_DETAIL="dev binary rebuild failed with exit $rc"
            AGENT_NEXT_ACTION="MODE=reload ZCL_DEV_WATCH_ONCE_FILES_FILE=$changed_file make dev-watch-once"
            write_cycle_record "$changed_file" rejected
            log "cycle=$CYCLE rejected phase=rebuild; running dev service was not touched"
            return 1
        fi
        if ! source_still_matches "$expected_manifest"; then
            FAILURE_PHASE="superseded"
            FAILURE_DETAIL="source changed after dev link"
            AGENT_NEXT_ACTION="MODE=$MODE ZCL_DEV_WATCH_ONCE_FILES_FILE=$changed_file make dev-watch-once"
            write_cycle_record "$changed_file" superseded
            log "cycle=$CYCLE superseded after rebuild; candidate not activated"
            return 3
        fi
    fi

    # Final compare-and-swap: no command that can stage, reload, or commit a
    # resident generation is reached unless the exact source epoch captured
    # before proofs is still byte-identical now.  The test seam mutates here
    # to exercise save/rename/delete races without touching a real lane.
    if [ -n "$PREACTIVATE_COMMAND" ]; then
        (cd "$ROOT" && /bin/sh -c "$PREACTIVATE_COMMAND")
    fi
    if ! check_lane_attests_source_epoch && ! verify_source_epoch; then
        FAILURE_PHASE="source_epoch_cas"
        FAILURE_DETAIL="$SOURCE_GATE_DETAIL"
        AGENT_NEXT_ACTION="coalesce the newest exact source epoch and rerun verify"
        write_cycle_record "$changed_file" superseded
        log "cycle=$CYCLE superseded immediately before activation: $SOURCE_GATE_DETAIL"
        return 3
    fi

    phase_started="$(clock_ms)"
    run_activation_command
    rc=$?
    ACTIVATE_MS=$(( $(clock_ms) - phase_started ))
    if [ "$SELECTED_PATH" = "check" ]; then
        ACTIVATION_RESULT="skipped"
    else
        ACTIVATION_RESULT="$([ "$rc" -eq 0 ] && printf passed || printf failed)"
    fi
    if [ "$rc" -ne 0 ]; then
        FAILURE_PHASE="activation"
        FAILURE_DETAIL="$SELECTED_PATH activation failed with exit $rc"
        if [ "$rc" -eq 75 ]; then
            AGENT_NEXT_ACTION="MODE=$MODE ZCL_DEV_WATCH_ONCE_FILES_FILE=$changed_file make dev-watch-once"
            write_cycle_record "$changed_file" coalesced
            log "cycle=$CYCLE activation lock busy; coalescing newest tree"
            return 3
        fi
        AGENT_NEXT_ACTION="make agent-dev-status ARGS=--json"
        write_cycle_record "$changed_file" rejected
        log "cycle=$CYCLE activation failed path=$SELECTED_PATH; watcher remains alive"
        return 1
    fi

    if [ "$MODE" = "verify" ]; then
        AGENT_NEXT_ACTION="MODE=verify ZCL_DEV_WATCH_ONCE_FILES_FILE=$changed_file make dev-watch-once"
    else
        AGENT_NEXT_ACTION="make agent-dev-status ARGS=--json"
    fi
    write_cycle_record "$changed_file" accepted
    schedule_codeindex_warm
    case "$SELECTED_PATH" in
        reload) log "cycle=$CYCLE ready isolated-dev-lane elapsed_s=$(elapsed_seconds "$started")" ;;
        stage) log "cycle=$CYCLE staged-for-next-dev-restart elapsed_s=$(elapsed_seconds "$started")" ;;
        check) log "cycle=$CYCLE green checks-only elapsed_s=$(elapsed_seconds "$started")" ;;
    esac
    return 0
}

acquire_single_watcher_lock()
{
    local lock_file="$ROOT/$WATCH_LOCK_REL" lock_parent
    if is_true "$CHECK_WORKER"; then
        # A benchmark worker never watches, publishes or activates.  Its
        # compiler work still crosses checkout-lock.sh in run_check_command,
        # while its records and lease stay outside the resident watcher's
        # state.  This lets measurement observe the normal warm service
        # without stopping or impersonating that service.
        lock_file="$STATE_DIR/check-worker.lock"
    fi
    lock_parent="${lock_file%/*}"
    mkdir -p "$lock_parent"
    command -v flock >/dev/null 2>&1 ||
        fail "flock is required for the shared native/shell watcher lease"
    # Open without truncating another owner's diagnostic payload.  Only the
    # successful flock holder may replace it with its own pid/mode.
    exec 9>>"$lock_file"
    flock -n 9 || fail "another dev watcher already owns $lock_file"
    : > "$lock_file"
    printf '%s %s\n' "$$" "$MODE" >&9
    if is_true "$CHECK_WORKER"; then
        log "bounded check worker owns isolated lease $lock_file; resident watcher unchanged"
    fi
}

cleanup()
{
    LAST_OUTCOME="stopped"
    write_heartbeat stopped
    [ -n "$WORK" ] && rm -rf "$WORK"
}

request_stop()
{
    STOP_REQUESTED=1
    log "stop requested; leaving the dev service in its current state"
}

selftest_fail()
{
    printf '[dev-watch-selftest] FAIL: %s\n' "$*" >&2
    return 1
}

# Current Phase-0 contract. Keep this fixture small and authority-focused:
# wake paths are diagnostics, every event crosses the reload/Core/parity
# boundary, source CAS is SHA-256 capture-record/verify-record, and no public or
# in-process mode can reach resident publication.
self_test()
{
    local sandbox old new changed expected command_log latest record
    local source_id source_clean source_mutation rc all_inputs

    [ "$MODE" = "verify" ] ||
        selftest_fail "public watcher default is not verify-only" || return 1
    sandbox="$(mktemp -d "${TMPDIR:-/tmp}/zcl-dev-watch-selftest.XXXXXX")" ||
        return 1
    ROOT="$sandbox/repo"
    WORK="$sandbox/work"
    STATE_DIR="$sandbox/state"
    HEARTBEAT="$STATE_DIR/watcher-heartbeat.json"
    command_log="$sandbox/commands.log"
    export ZCL_WATCH_TEST_LOG="$command_log"
    mkdir -p "$ROOT/app" "$ROOT/core/consensus" "$ROOT/docs" \
        "$ROOT/config" "$ROOT/tools/dev" "$WORK" "$STATE_DIR/cycles"
    printf '%s\n' \
        'all:' \
        $'\t@true' \
        'check-core-seal:' \
        $'\t@echo core >> "$${ZCL_WATCH_TEST_LOG:?}"' \
        $'\t@test ! -e .fail-core' \
        'check-consensus-parity:' \
        $'\t@echo parity >> "$${ZCL_WATCH_TEST_LOG:?}"' \
        $'\t@test ! -e .fail-parity' \
        'watcher-safety-gates: check-core-seal check-consensus-parity' \
        > "$ROOT/Makefile"
    printf '/build/\n/.cache/\n' > "$ROOT/.gitignore"
    printf 'int a;\n' > "$ROOT/app/a.c"
    printf 'int consensus_value;\n' > "$ROOT/core/consensus/value.c"
    printf '# handoff\n' > "$ROOT/docs/HANDOFF.md"
    printf '%s\n' \
        'HOTSWAP_ELIGIBLE("app/a.c") HOTSWAP_PROBE("probe_a")' \
        > "$ROOT/engine/composition/hotswap_eligible.def"
    (
        cd "$ROOT" || exit 1
        git init -q
        git config user.name dev-watch-selftest
        git config user.email dev-watch-selftest@example.invalid
        git add .
        git commit -qm baseline
    ) || { rm -rf "$sandbox"; return 1; }

    # Public activation names and command overrides refuse before source scan,
    # compilation, RPC, or filesystem mutation.
    if ZCL_DEV_WATCH_ROOT="$ROOT" ZCL_DEV_WATCH_MODE=auto \
        "$SCRIPT_DIR/watch-dev-lane.sh" --once \
        >"$sandbox/public-auto.out" 2>&1; then
        selftest_fail "public auto watcher mode was not contained" || {
            rm -rf "$sandbox"; return 1;
        }
    fi
    grep -q 'runtime publication mode' "$sandbox/public-auto.out" ||
        selftest_fail "public auto refusal omitted containment reason" || {
            rm -rf "$sandbox"; return 1;
        }
    if ZCL_DEV_WATCH_ROOT="$ROOT" ZCL_DEV_WATCH_MODE=verify \
        ZCL_DEV_WATCH_CHECK_COMMAND=true \
        "$SCRIPT_DIR/watch-dev-lane.sh" --once \
        >"$sandbox/public-override.out" 2>&1; then
        selftest_fail "public watcher accepted a shell-command override" || {
            rm -rf "$sandbox"; return 1;
        }
    fi
    if ZCL_DEV_WATCH_ROOT="$ROOT" ZCL_DEV_WATCH_MODE=check \
        ZCL_DEV_WATCH_CHECK_SOURCE_RECORD="$(printf '0%.0s' {1..64}) 1 $(printf '1%.0s' {1..64})" \
        "$SCRIPT_DIR/watch-dev-lane.sh" --once \
        >"$sandbox/public-source-record.out" 2>&1; then
        selftest_fail "public watcher accepted a worker source record without the bounded-worker contract" || {
            rm -rf "$sandbox"; return 1;
        }
    fi
    grep -q 'CHECK_SOURCE_RECORD requires.*CHECK_WORKER' \
        "$sandbox/public-source-record.out" ||
        selftest_fail "source-record refusal omitted the bounded-worker reason" || {
            rm -rf "$sandbox"; return 1;
        }
    refresh_watch_paths
    WARM_CODEINDEX=0
    CHECK_COMMAND="printf 'check\\n' >> '$command_log'"
    REBUILD_COMMAND="printf 'rebuild\\n' >> '$command_log'"
    DEPLOY_COMMAND="printf 'deploy\\n' >> '$command_log'"
    STAGE_COMMAND="printf 'stage\\n' >> '$command_log'"
    PREACTIVATE_COMMAND=""

    # The manifest detects modified/deleted/created paths without consulting
    # Git history. Once mode without a hint expands to every watched input.
    old="$WORK/old"
    new="$WORK/new"
    changed="$WORK/changed"
    write_manifest "$old" || { rm -rf "$sandbox"; return 1; }
    printf 'int a = 1;\n' > "$ROOT/app/a.c"
    write_manifest "$new" || { rm -rf "$sandbox"; return 1; }
    manifest_changed_paths "$old" "$new" "$changed"
    grep -qx 'app/a.c' "$changed" ||
        selftest_fail "manifest change detection missed app/a.c" || {
            rm -rf "$sandbox"; return 1;
        }
    ZCL_DEV_WATCH_ONCE_FILES=""
    ZCL_DEV_WATCH_ONCE_FILES_FILE=""
    all_inputs="$WORK/all-inputs"
    dirty_relevant_paths "$all_inputs"
    grep -qx 'core/consensus/value.c' "$all_inputs" ||
        selftest_fail "conservative once inventory omitted sealed Core" || {
            rm -rf "$sandbox"; return 1;
        }

    # Even one manifest-eligible provider is only a diagnostic wake hint. The
    # underlying classification is reload-required and both global gates run.
    expected="$new"
    printf 'app/a.c\n' > "$changed"
    MODE="verify"
    : > "$command_log"
    run_cycle "$changed" "$expected" >/dev/null 2>&1 ||
        selftest_fail "green verify cycle rejected" || {
            rm -rf "$sandbox"; return 1;
        }
    [ "$(tr '\n' ' ' < "$command_log")" = "core parity check " ] ||
        selftest_fail "verify did not run Core/parity gates before focused check" || {
            rm -rf "$sandbox"; return 1;
        }
    latest="$STATE_DIR/latest-cycle.json"
    grep -q '"classified_path":"reload"' "$latest" &&
    grep -q 'consensus_parity gates required' "$latest" &&
    grep -Eq '"source_identity":"[0-9a-f]{64}"' "$latest" ||
        selftest_fail "reload/source-id verification evidence missing" || {
            rm -rf "$sandbox"; return 1;
        }

    # A Git history-only commit cannot supersede the exact current-byte source
    # id. Git object ids remain optional display trace, never watcher authority.
    record="$(cd "$ROOT" && "$SCRIPT_DIR/source-identity.sh" capture-record)" || {
        rm -rf "$sandbox"; return 1;
    }
    read -r source_id source_clean source_mutation <<< "$record"
    (cd "$ROOT" && git commit --allow-empty -qm history-only) || {
        rm -rf "$sandbox"; return 1;
    }
    (cd "$ROOT" && "$SCRIPT_DIR/source-identity.sh" verify-record \
        "$source_id" "$source_clean" "$source_mutation" >/dev/null) ||
        selftest_fail "history-only Git commit changed watcher authority" || {
            rm -rf "$sandbox"; return 1;
        }

    # A parity-gate failure rejects before the mapped check. A source id never
    # bypasses either parity or the sealed-Core gate.
    : > "$ROOT/.fail-parity"
    write_manifest "$new" || { rm -rf "$sandbox"; return 1; }
    expected="$new"
    printf 'docs/HANDOFF.md\n' > "$changed"
    : > "$command_log"
    run_cycle "$changed" "$expected" >/dev/null 2>&1
    rc=$?
    [ "$rc" -eq 1 ] &&
    [ "$(tr '\n' ' ' < "$command_log")" = "core parity " ] ||
        selftest_fail "consensus-parity failure did not stop the cycle" || {
            rm -rf "$sandbox"; return 1;
        }
    rm -f "$ROOT/.fail-parity"

    # Defense in depth: even an in-process caller that skips validate_options
    # cannot turn a wake list or source id into activation authority.
    MODE="auto"
    : > "$command_log"
    run_cycle "$changed" "$expected" >/dev/null 2>&1
    rc=$?
    [ "$rc" -eq 1 ] && [ ! -s "$command_log" ] &&
    grep -q 'phase0_containment' "$STATE_DIR/latest-cycle.json" ||
        selftest_fail "in-process publication path escaped Phase-0 containment" || {
            rm -rf "$sandbox"; return 1;
        }

    # Edit+restore ABA keeps identical bytes but changes the host-local
    # mutation token, so the final exact record CAS supersedes the cycle.
    MODE="verify"
    write_manifest "$new" || { rm -rf "$sandbox"; return 1; }
    expected="$new"
    printf 'app/a.c\n' > "$changed"
    PREACTIVATE_COMMAND="printf 'int a = 2;\\n' > app/a.c; printf 'int a = 1;\\n' > app/a.c"
    : > "$command_log"
    run_cycle "$changed" "$expected" >/dev/null 2>&1
    rc=$?
    [ "$rc" -eq 3 ] &&
    grep -q 'source_epoch_cas' "$STATE_DIR/latest-cycle.json" ||
        selftest_fail "edit/restore ABA was not superseded by record CAS" || {
            rm -rf "$sandbox"; return 1;
        }
    PREACTIVATE_COMMAND=""

    # Hidden index flags fail before gates/checks; they can never conceal a
    # sealed source input from capture-record.
    (
        cd "$ROOT" || exit 1
        git update-index --assume-unchanged app/a.c
    ) || { rm -rf "$sandbox"; return 1; }
    printf 'int a = 3;\n' > "$ROOT/app/a.c"
    write_manifest "$new" || { rm -rf "$sandbox"; return 1; }
    expected="$new"
    : > "$command_log"
    run_cycle "$changed" "$expected" >/dev/null 2>&1
    rc=$?
    [ "$rc" -eq 1 ] && [ ! -s "$command_log" ] &&
    grep -q 'hidden Git index bit' "$STATE_DIR/latest-cycle.json" ||
        selftest_fail "hidden index flag did not fail closed" || {
            rm -rf "$sandbox"; return 1;
        }
    (cd "$ROOT" && git update-index --no-assume-unchanged app/a.c) || true

    unset ZCL_WATCH_TEST_LOG
    rm -rf "$sandbox"
    printf '[dev-watch-selftest] PASS: event-only reload classification, mandatory sealed-Core/consensus parity gates, SHA-256 source-record CAS, history independence, ABA refusal, Phase-0 containment\n'
}

run_once()
{
    local manifest="$WORK/once-manifest" changed="$WORK/once-changed" rc
    write_manifest "$manifest" || fail "could not read source manifest"
    dirty_relevant_paths "$changed"
    if [ ! -s "$changed" ]; then
        log "once: no relevant changed paths; nothing to do"
        return 0
    fi
    run_cycle "$changed" "$manifest"
    rc=$?
    return "$rc"
}

main_loop()
{
    local green="$WORK/green" observed="$WORK/observed"
    local changed="$WORK/changed" candidate post rc pending=0

    write_manifest "$green" || fail "could not read initial source manifest"
    cp "$green" "$observed"
    write_heartbeat watching
    log "watching backend=$BACKEND poll_ms=$POLL_MS debounce_ms=$DEBOUNCE_MS mode=$MODE"
    log "activation target is isolated zcl23-dev only; Ctrl-C stops the watcher"

    if is_true "$RUN_INITIAL"; then
        dirty_relevant_paths "$changed"
        [ -s "$changed" ] && pending=2
    fi

    while [ "$STOP_REQUESTED" -eq 0 ]; do
        write_heartbeat watching
        if [ "$pending" -eq 0 ]; then
            wait_for_source_change "$observed" || break
            candidate="$NEXT_MANIFEST"
            cp "$candidate" "$observed"
            manifest_changed_paths "$green" "$candidate" "$changed"
        elif [ "$pending" -eq 1 ]; then
            write_manifest "$WORK/immediate" || {
                log "manifest read failed; retrying"
                sleep_ms "$POLL_MS"
                continue
            }
            settle_manifest "$WORK/immediate" || break
            candidate="$SETTLED_MANIFEST"
            cp "$candidate" "$observed"
            manifest_changed_paths "$green" "$candidate" "$changed"
        else
            candidate="$observed"
        fi
        pending=0

        [ -s "$changed" ] || continue
        run_cycle "$changed" "$candidate"
        rc=$?

        post="$WORK/post"
        if ! write_manifest "$post"; then
            log "post-cycle manifest read failed; polling again"
            pending=1
            continue
        fi
        if ! manifests_equal "$candidate" "$post"; then
            log "new saves arrived during cycle=$CYCLE; scheduling one coalesced follow-up"
            pending=1
            continue
        fi
        if [ "$rc" -eq 0 ]; then
            cp "$candidate" "$green"
        elif [ "$rc" -eq 3 ]; then
            pending=1
        else
            log "waiting for the next save after rejected cycle=$CYCLE"
        fi
    done
    LAST_OUTCOME="stopped"
    write_heartbeat stopped
    log "stopped"
}

case "${1:-}" in
    --help|-h) usage; exit 0 ;;
    --once) RUN_ONCE=1 ;;
    --self-test|--selftest) self_test; exit $? ;;
    "") ;;
    *) usage >&2; exit 2 ;;
esac

validate_options
refresh_watch_paths
resolve_backend
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-dev-watch.XXXXXX")" ||
    fail "could not create temporary workspace"
mkdir -p "$STATE_DIR/cycles"
trap request_stop INT TERM
trap cleanup EXIT
acquire_single_watcher_lock

if is_true "$RUN_ONCE"; then
    run_once
    exit $?
fi

main_loop
