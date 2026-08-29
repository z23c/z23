#!/usr/bin/env bash
# Read-only agent development doctor.
#
# Combines the fast build/dev-lane status, recent focused-test failures, and a
# single next safe command. It never builds, deploys, or restarts services.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
# shellcheck source=tools/dev/dev_lib.sh
. "$REPO/tools/dev/dev_lib.sh"  # json_escape

MODE="${1:-text}"
SCHEMA="zcl.agent_doctor.v1"
SRC_BIN="${ZCL_AGENT_SRC_BIN:-build/bin/zclassic23-dev}"
DEV_STATUS_CMD="${ZCL_AGENT_DEV_STATUS_CMD:-tools/dev/agent-dev-status.sh --json}"
FAST_PLAN_CMD="${ZCL_AGENT_FAST_PLAN_CMD:-tools/agent_fast_ci.sh plan-json}"

json_string_field() {
    local json="$1" key="$2"
    printf '%s\n' "$json" |
        sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" |
        head -1
}

# baked_source_id() is defined in tools/dev/dev_lib.sh (sourced above) so the
# scheduled drift probe and this doctor share one definition of "what was this
# binary compiled from".

json_number_field() {
    local json="$1" key="$2"
    printf '%s\n' "$json" |
        sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" |
        head -1
}

dev_status_json() {
    local out
    if out="$($DEV_STATUS_CMD 2>/dev/null)"; then
        printf '%s\n' "$out"
    else
        printf '{"schema":"zcl.agent_dev_status.v2","status":"error","next_action":"make agent-dev-status","error":"collector_failed"}\n'
    fi
}

fast_plan_json() {
    local out
    if out="$($FAST_PLAN_CMD 2>/dev/null)"; then
        printf '%s\n' "$out"
    else
        printf '{"schema":"zcl.agent_fast_plan.v1","status":"error","recommended_command":"make fast-ci","error":"collector_failed"}\n'
    fi
}

build_json() {
    local executable="false" source_id="" build_commit="" mtime="" size=""
    local identity="" source_id_valid="false"
    if [ -x "$SRC_BIN" ]; then
        executable="true"
        mtime="$(stat -c '%y' "$SRC_BIN" 2>/dev/null || true)"
        size="$(stat -c '%s' "$SRC_BIN" 2>/dev/null || true)"
        identity="$("$SRC_BIN" agentbuild 2>/dev/null || true)"
        source_id="$(baked_source_id "$SRC_BIN")"
        build_commit="$(printf '%s\n' "$identity" |
            sed -n 's/.*"build_commit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
            head -1 || true)"
        [[ "$source_id" =~ ^[0-9a-f]{64}$ ]] && source_id_valid="true"
    fi
    printf '{"binary":"%s","executable":%s,"size":"%s","mtime":"%s","source_id_sha256":"%s","source_id_valid":%s,"build_commit":"%s","build_commit_semantics":"display_only_github_trace_metadata"}' \
        "$(json_escape "$SRC_BIN")" "$executable" "$(json_escape "$size")" \
        "$(json_escape "$mtime")" "$(json_escape "$source_id")" \
        "$source_id_valid" "$(json_escape "$build_commit")"
}

changed_files_count() {
    git diff --name-only 2>/dev/null | wc -l | tr -d ' '
}

latest_test_artifact_mtime() {
    local latest=0 f mt
    for f in "$SRC_BIN" build/bin/test_parallel_fast build/bin/test_parallel build/bin/test_zcl; do
        mt="$(stat -c '%Y' "$f" 2>/dev/null || printf '0')"
        if [[ "$mt" =~ ^[0-9]+$ ]] && [ "$mt" -gt "$latest" ]; then
            latest="$mt"
        fi
    done
    printf '%s\n' "$latest"
}

latest_failure_log() {
    local f cutoff_mtime="0" log_mtime
    cutoff_mtime="$(latest_test_artifact_mtime)"
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        log_mtime="$(stat -c '%Y' "$f" 2>/dev/null || printf '0')"
        if [[ "$cutoff_mtime" =~ ^[0-9]+$ ]] &&
           [[ "$log_mtime" =~ ^[0-9]+$ ]] &&
           [ "$log_mtime" -lt "$cutoff_mtime" ]; then
            continue
        fi
        if grep -qaE '(^|[.][.][.] )FAIL$|SOME TESTS FAILED|Failed groups:' "$f" 2>/dev/null; then
            printf '%s\n' "$f"
            return 0
        fi
    done <<EOF
$(ls -t test-tmp/test_parallel_*_*.log 2>/dev/null || true)
EOF
}

failure_summary() {
    local log="$1"
    [ -n "$log" ] || return 0
    grep -aE '(^|[.][.][.] )FAIL$|SOME TESTS FAILED|Failed groups:' "$log" 2>/dev/null |
        head -12 |
        tr '\n' '; ' |
        sed 's/[; ][; ]*$//'
}

next_action() {
    local dev_next="$1" fail_log="$2" changed_count="$3" fast_next="$4"
    if [ -n "$dev_next" ] &&
       ! printf '%s' "$dev_next" | grep -q '^z23-dev status$'; then
        printf '%s' "$dev_next"
    elif [ -n "$fail_log" ]; then
        printf 'inspect %s or rerun the focused failing group' "$fail_log"
    elif [ -n "$fast_next" ] && [ "$fast_next" != "make agent-dev-status" ]; then
        printf '%s' "$fast_next"
    elif [ "$changed_count" != "0" ]; then
        printf 'make agent-loop'
    else
        printf 'make agent-dev-status'
    fi
}

# ── Is the CANONICAL live node running this tree? ───────────────────────
#
# Everything else this doctor reports is about the DEV lane. Nothing compared
# the running canonical daemon against the checkout, and the cost of that gap
# is measured, not theoretical: on 2026-07-28 two separate "live defects" were
# diagnosed off this repo, written up, and were in fact already FIXED in the
# tree and merely never shipped. The daemon was running source_id ff29f119…
# from a binary built 04:19 UTC while the fix had landed at 08:42 UTC.
#
# Reading the repo and assuming the running node contains it is the single
# most expensive mistake available here, and it is silent — the node behaves
# exactly like a node with a real bug. One string compare removes it.
#
# Read-only and failure-tolerant by construction: the daemon binary may be
# absent (a fresh clone), unreadable, or slow, and none of that may break a
# doctor whose whole job is to be safe to run. Any failure degrades to
# live="unknown", never to a false "matches".
live_node_json() {
    local bin="${ZCL_AGENT_LIVE_BIN:-$HOME/.local/bin/zclassic23-live}"
    # Compare against the RELEASE artifact, because that is what ship.sh
    # deploys. The dev binary is built with different flags and bakes a
    # different id from the same tree, so comparing the live node against it
    # would report a permanent, meaningless mismatch.
    local rel="${ZCL_AGENT_RELEASE_BIN:-build/bin/zclassic23}"
    local rel_id live_id state="unknown" matches="false"

    rel_id="$(baked_source_id "$rel")"

    if [ ! -x "$bin" ]; then
        printf '{"binary":"%s","present":false,"state":"absent","source_id_sha256":"","tree_source_id_sha256":"%s","matches_tree":false}\n' \
            "$(json_escape "$bin")" "$(json_escape "$rel_id")"
        return 0
    fi

    live_id="$(baked_source_id "$bin")"

    if [ -n "$live_id" ]; then
        state="reporting"
        # Both ids must be present AND equal. An empty release id means the
        # tree has not been built, so nothing is known — never "matches".
        if [ -n "$rel_id" ] && [ "$live_id" = "$rel_id" ]; then
            matches="true"
        fi
    fi

    printf '{"binary":"%s","present":true,"state":"%s","source_id_sha256":"%s","tree_source_id_sha256":"%s","matches_tree":%s}\n' \
        "$(json_escape "$bin")" "$state" "$(json_escape "$live_id")" \
        "$(json_escape "$rel_id")" "$matches"
}

emit_json() {
    local dev_json fast_json build fail_log fail_summary changed dev_next
    local fast_next action live_json
    dev_json="$(dev_status_json)"
    fast_json="$(fast_plan_json)"
    build="$(build_json)"
    live_json="$(live_node_json)"
    fail_log="$(latest_failure_log || true)"
    fail_summary="$(failure_summary "$fail_log" || true)"
    changed="$(json_number_field "$fast_json" "changed_file_count")"
    changed="${changed:-$(changed_files_count)}"
    dev_next="$(json_string_field "$dev_json" "next_action")"
    fast_next="$(json_string_field "$fast_json" "recommended_command")"
    action="$(next_action "$dev_next" "$fail_log" "$changed" "$fast_next")"

    printf '{\n'
    printf '  "schema": "%s",\n' "$SCHEMA"
    printf '  "status": "ok",\n'
    printf '  "build": %s,\n' "$build"
    printf '  "dev_status": %s,\n' "$dev_json"
    printf '  "live_node": %s,\n' "$live_json"
    printf '  "fast_lane": %s,\n' "$fast_json"
    printf '  "changed_file_count": %s,\n' "$changed"
    printf '  "latest_failure_log": "%s",\n' "$(json_escape "$fail_log")"
    printf '  "latest_failure_summary": "%s",\n' "$(json_escape "$fail_summary")"
    printf '  "next_action": "%s"\n' "$(json_escape "$action")"
    printf '}\n'
}

emit_text() {
    local json
    json="$(emit_json)"
    if command -v jq >/dev/null 2>&1; then
        printf '%s\n' "$json" | jq -r '
            "[agent-doctor] build=" + .build.binary +
            " executable=" + (.build.executable|tostring) +
            " source_id=" + .build.source_id_sha256 +
            " commit_display=" + .build.build_commit,
            "[agent-doctor] live_node=" + (.live_node.state // "unknown") +
            " running_this_tree=" + ((.live_node.matches_tree // false)|tostring) +
            (if (.live_node.matches_tree // false) then ""
             else "  ⚠ THE LIVE NODE IS NOT RUNNING THIS TREE — do not diagnose"
                  + " live behaviour from this checkout (running="
                  + ((.live_node.source_id_sha256 // "")[0:12])
                  + "… tree=" + ((.live_node.tree_source_id_sha256 // "")[0:12])
                  + "…); ship first or read the deployed source" end),
            "[agent-doctor] dev=" + (.dev_status.service.active_state // "unknown") +
            " rpc=" + (.dev_status.rpc.status // "unknown") +
            " staged_matches_source=" + ((.dev_status.installed_matches_source // false)|tostring) +
            " deploy_blocker=" + ((.dev_status.deploy_blocker // false)|tostring) +
            " memory_pressure=" + (.dev_status.service.memory_pressure // "unknown"),
            "[agent-doctor] fast compiler=" + (.fast_lane.compiler // "unknown") +
            " cache=" + (.fast_lane.cache_tool // "unknown") +
            " compile=" + (.fast_lane.compile_plan.kind // "unknown") +
            " cache_hit=" + ((.fast_lane.green_input_cache.hit // false)|tostring),
            "[agent-doctor] changed_files=" + (.changed_file_count|tostring) +
            " tests=" + ((.fast_lane.test_groups // [])|join(",")) +
            " unmapped=" + ((.fast_lane.unmapped_code_changes // [])|join(",")),
            "[agent-doctor] native_fresh=" + (.fast_lane.native_shortcuts.fresh_source_tree // "") +
            " native_dev=" + (.fast_lane.native_shortcuts.dev_linger_lane // ""),
            "[agent-doctor] latest_failure_log=" + .latest_failure_log,
            "[agent-doctor] next=" + .next_action'
    else
        printf '%s\n' "$json"
    fi
}

case "$MODE" in
    --json|json)
        emit_json
        ;;
    ""|text)
        emit_text
        ;;
    *)
        echo "usage: tools/dev/agent-doctor.sh [--json]" >&2
        exit 2
        ;;
esac
