#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Plan bounded recovery for NONCANONICAL zclassic23 lanes.
# The planner is observe-only by construction. It contains no snapshot-copy,
# unit-write, header-import, or service-control implementation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

APPLY="${ZCL_LANE_RECOVERY_APPLY:-0}"
FORCE_HEADER_IMPORT="${ZCL_LANE_RECOVERY_IMPORT_HEADERS:-0}"
ALLOW_STALE_HEADER_IMPORT="${ZCL_LANE_RECOVERY_ALLOW_STALE_HEADER_IMPORT:-0}"
JSON=0
LANE="${1:-all}"

usage() {
    cat <<'USAGE'
usage: tools/scripts/lane_recover.sh [dev|soak|all] [--apply] [--json] [--import-headers]

Plans recovery for dev/soak lane lag. `--apply` is a containment probe and
always refuses before reading lane health or changing a unit, datadir,
snapshot, drop-in, block index, or service. ZCL_LANE_RECOVERY_APPLY=1 has the
same fail-closed behavior.

--import-headers adds the documented header-import step to the proposed plan.
It never executes the import. If the loader snapshot is not newer, the step is
omitted unless
ZCL_LANE_RECOVERY_ALLOW_STALE_HEADER_IMPORT=1 is set; stale legacy block-index
imports can make recovery slower without improving the lane.

Canonical/live/main is always refused. Use make lane-health for read-only status.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --apply) APPLY=1 ;;
        --dry-run|--plan) APPLY=0 ;;
        --import-headers) FORCE_HEADER_IMPORT=1 ;;
        --json) JSON=1 ;;
        --selftest) ZCL_LANE_RECOVERY_SELFTEST=1 ;;
        -h|--help)
            usage
            exit 0
            ;;
        dev|soak|all|live|canonical|main) LANE="$1" ;;
        *)
            printf 'lane-recover: unknown arg %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

log() {
    [ "$JSON" = "1" ] && return 0
    printf 'lane-recover: %s\n' "$*"
}

die() {
    printf 'lane-recover: REFUSE: %s\n' "$*" >&2
    exit 1
}

# shellcheck source=tools/scripts/stopwatch_json_lib.sh
. "$REPO_ROOT/tools/scripts/stopwatch_json_lib.sh"  # json_escape

json_bool() {
    case "$1" in
        1|true|TRUE|yes|YES|on|ON) printf true ;;
        *) printf false ;;
    esac
}

is_true() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

refuse_public_apply() {
    is_true "$APPLY" || return 0
    if [ "$JSON" = "1" ]; then
        printf '%s\n' '{"schema":"zcl.lane_recovery_plan.v1","status":"blocked","error":"runtime_recovery_contained","apply":false,"runtime_publication":false,"mutation_contained":true,"apply_authority":"none","safe_next_action":"run the read-only lane recovery plan and obtain separately reviewed activation authority"}'
    fi
    printf '%s\n' \
        'lane-recover: REFUSE: runtime recovery mutation is contained; --apply and ZCL_LANE_RECOVERY_APPLY are not activation authority' >&2
    exit 3
}

json_string_field() {
    local body="$1" key="$2"
    printf '%s\n' "$body" \
        | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" \
        | head -1
}

json_bool_field() {
    local body="$1" key="$2" v
    v="$(printf '%s\n' "$body" \
        | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p" \
        | head -1)"
    case "$v" in
        true) printf 1 ;;
        false) printf 0 ;;
        *) printf 0 ;;
    esac
}

json_number_field() {
    local body="$1" key="$2"
    printf '%s\n' "$body" \
        | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p" \
        | head -1
}

lane_datadir() {
    case "$1" in
        dev) printf '%s/.zclassic-c23-dev' "$HOME" ;;
        soak) printf '%s/.zclassic-c23-soak' "$HOME" ;;
        *) return 1 ;;
    esac
}

health_json() {
    if [ -n "${ZCL_LANE_RECOVERY_HEALTH_JSON:-}" ]; then
        printf '%s\n' "$ZCL_LANE_RECOVERY_HEALTH_JSON"
        return 0
    fi
    "$REPO_ROOT/tools/scripts/lane_health.sh" --json
}

lane_record() {
    local want="$1"
    health_json | grep -E "\"lane\":\"${want}\"" | head -1
}

highest_snapshot_in() {
    local datadir="$1" file base stem best_h best_path
    best_h=""
    best_path=""
    [ -d "$datadir" ] || return 1
    for file in "$datadir"/utxo-seed-*.snapshot; do
        [ -e "$file" ] || continue
        base="${file##*/}"
        stem="${base#utxo-seed-}"
        stem="${stem%.snapshot}"
        case "$stem" in ''|*[!0-9]*) continue ;; esac
        if [ -z "$best_h" ] || [ "$stem" -gt "$best_h" ]; then
            best_h="$stem"
            best_path="$file"
        fi
    done
    [ -n "$best_path" ] || return 1
    printf '%s\n' "$best_path"
}

canonical_seed_snapshot() {
    if [ -n "${ZCL_LANE_RECOVERY_SEED_SOURCE:-}" ]; then
        printf '%s\n' "$ZCL_LANE_RECOVERY_SEED_SOURCE"
        return 0
    fi
    highest_snapshot_in "$HOME/.zclassic-c23"
}

snapshot_height_from_path() {
    local path="$1" base stem
    base="${path##*/}"
    stem="${base#utxo-seed-}"
    stem="${stem%.snapshot}"
    case "$stem" in
        ''|*[!0-9]*) return 1 ;;
        *) printf '%s\n' "$stem" ;;
    esac
}

emit_plan() {
    local lane="$1" action="$2" hint="$3" snapshot="$4" reason="$5" applies="$6"
    local canonical_refused=0
    case "$lane" in live|canonical|main) canonical_refused=1 ;; esac
    if [ "$JSON" = "1" ]; then
        printf '{"schema":"zcl.lane_recovery_plan.v1","lane":"%s","action":"%s","recovery_hint":"%s","snapshot_path":"%s","reason":"%s","apply":%s,"canonical_refused":%s,"runtime_publication":false,"mutation_contained":true,"apply_authority":"none"}\n' \
            "$(json_escape "$lane")" \
            "$(json_escape "$action")" \
            "$(json_escape "$hint")" \
            "$(json_escape "$snapshot")" \
            "$(json_escape "$reason")" \
            "$(json_bool "$applies")" \
            "$(json_bool "$canonical_refused")"
    else
        printf 'lane-recover: lane=%s action=%s hint=%s snapshot=%s reason=%s apply=%s\n' \
            "$lane" "$action" "$hint" "${snapshot:-none}" "$reason" "$applies"
    fi
}

refuse_canonical_lane() {
    case "$1" in
        live|canonical|main)
            emit_plan "$1" "refuse_canonical" "none" "" \
                "canonical lane is observe-only; use lane-health/status tools" 0
            die "canonical/live/main recovery is not supported by this tool"
            ;;
    esac
}

recover_lane() {
    local lane="$1" rec hint role_ready status reason snapshot loader datadir action
    local height snapshot_seed_height
    refuse_canonical_lane "$lane"
    case "$lane" in dev|soak) ;; *) die "unknown lane: $lane" ;; esac

    rec="$(lane_record "$lane")"
    [ -n "$rec" ] || die "no lane-health record found for $lane"

    hint="$(json_string_field "$rec" "recovery_hint")"
    role_ready="$(json_bool_field "$rec" "role_ready")"
    status="$(json_string_field "$rec" "status")"
    reason="$(json_string_field "$rec" "reason")"
    snapshot="$(json_string_field "$rec" "snapshot_path")"
    height="$(json_number_field "$rec" "height")"
    snapshot_seed_height="$(json_number_field "$rec" "snapshot_seed_height")"
    loader="$(json_bool_field "$rec" "snapshot_loader_configured")"
    datadir="$(json_string_field "$rec" "datadir")"
    [ -n "$datadir" ] || datadir="$(lane_datadir "$lane")"

    action="inspect_only"
    if [ "$role_ready" = "1" ] && [ "${hint:-none}" = "none" ]; then
        action="none"
    elif [ "$hint" = "restart_with_load_snapshot_at_own_height" ]; then
        action="install_loader_dropin_restart"
    elif [ "$hint" = "install_tip_seed_snapshot" ]; then
        action="copy_seed_install_loader_restart"
    elif [ "$hint" = "remove_forced_reindex_override" ] && [ "$lane" = "dev" ]; then
        action="remove_dev_reindex_override_restart"
    elif [ "$hint" = "loader_active" ] || [ "$loader" = "1" ]; then
        action="restart_noncanonical_lane"
    fi

    if [ "$action" = "copy_seed_install_loader_restart" ] && [ -z "$snapshot" ]; then
        snapshot="$(canonical_seed_snapshot || true)"
    fi
    if [ -n "$snapshot" ] && [ -z "$snapshot_seed_height" ]; then
        snapshot_seed_height="$(snapshot_height_from_path "$snapshot" || true)"
    fi
    if [ "$FORCE_HEADER_IMPORT" = "1" ] && [ -n "$snapshot" ]; then
        if [ "$ALLOW_STALE_HEADER_IMPORT" != "1" ] &&
           [ -n "$height" ] && [ -n "$snapshot_seed_height" ] &&
           [ "$snapshot_seed_height" -le "$height" ] 2>/dev/null; then
            reason="${reason};header_import_skipped_snapshot_not_newer"
            log "$lane skipping forced header import: snapshot_seed_height=$snapshot_seed_height <= lane_height=$height; set ZCL_LANE_RECOVERY_ALLOW_STALE_HEADER_IMPORT=1 to override"
        else
            case "$action" in
                restart_noncanonical_lane|inspect_only)
                    action="import_headers_restart"
                    ;;
                install_loader_dropin_restart)
                    action="import_headers_install_loader_restart"
                    ;;
                copy_seed_install_loader_restart)
                    action="copy_seed_import_headers_install_loader_restart"
                    ;;
            esac
        fi
    elif [ -n "$height" ] && [ -n "$snapshot_seed_height" ] &&
         [ "$snapshot_seed_height" -gt "$height" ] 2>/dev/null; then
        case "$action" in
            install_loader_dropin_restart)
                action="import_headers_install_loader_restart"
                ;;
            copy_seed_install_loader_restart)
                action="copy_seed_import_headers_install_loader_restart"
                ;;
        esac
    fi

    emit_plan "$lane" "$action" "$hint" "$snapshot" \
        "${status:-unknown}:${reason:-unknown}" 0
}

selftest_case() {
    local name="$1" lane="$2" expect_rc="$3" body="$4"
    local rc=0
    HOME="$ZCL_LANE_SELFTEST_HOME" ZCL_LANE_RECOVERY_HEALTH_JSON="$body" \
        env -u ZCL_LANE_RECOVERY_SELFTEST "$0" "$lane" --json >/dev/null 2>&1 || rc=$?
    if [ "$expect_rc" = "0" ] && [ "$rc" != "0" ]; then
        printf 'lane-recover selftest FAIL expected pass: %s rc=%s\n' "$name" "$rc" >&2
        exit 1
    fi
    if [ "$expect_rc" != "0" ] && [ "$rc" = "0" ]; then
        printf 'lane-recover selftest FAIL expected refusal: %s\n' "$name" >&2
        exit 1
    fi
}

selftest_case_contains() {
    local name="$1" lane="$2" body="$3" needle="$4" out rc
    rc=0
    out="$(HOME="$ZCL_LANE_SELFTEST_HOME" ZCL_LANE_RECOVERY_HEALTH_JSON="$body" \
        env -u ZCL_LANE_RECOVERY_SELFTEST "$0" "$lane" --json --import-headers 2>&1)" || rc=$?
    if [ "$rc" != "0" ]; then
        printf 'lane-recover selftest FAIL expected pass: %s rc=%s out=%s\n' \
            "$name" "$rc" "$out" >&2
        exit 1
    fi
    if ! printf '%s\n' "$out" | grep -F "$needle" >/dev/null; then
        printf 'lane-recover selftest FAIL missing %s: %s out=%s\n' \
            "$needle" "$name" "$out" >&2
        exit 1
    fi
}

selftest_apply_refused() {
    local name="$1" mode="$2" out rc=0
    case "$mode" in
        flag)
            out="$(HOME="$ZCL_LANE_SELFTEST_HOME" \
                env -u ZCL_LANE_RECOVERY_SELFTEST -u ZCL_LANE_RECOVERY_APPLY \
                "$0" dev --json --apply 2>&1)" || rc=$?
            ;;
        env)
            out="$(HOME="$ZCL_LANE_SELFTEST_HOME" \
                ZCL_LANE_RECOVERY_APPLY=1 \
                env -u ZCL_LANE_RECOVERY_SELFTEST \
                "$0" dev --json 2>&1)" || rc=$?
            ;;
        *)
            printf 'lane-recover selftest FAIL unknown refusal mode: %s\n' \
                "$mode" >&2
            exit 1
            ;;
    esac
    [ "$rc" -eq 3 ] || {
        printf 'lane-recover selftest FAIL expected contained exit 3: %s rc=%s out=%s\n' \
            "$name" "$rc" "$out" >&2
        exit 1
    }
    printf '%s\n' "$out" | grep -q 'runtime_recovery_contained' || {
        printf 'lane-recover selftest FAIL missing containment body: %s out=%s\n' \
            "$name" "$out" >&2
        exit 1
    }
    [ -z "$(find "$ZCL_LANE_SELFTEST_HOME" -mindepth 1 -print -quit)" ] || {
        printf 'lane-recover selftest FAIL apply mutated isolated HOME: %s\n' \
            "$name" >&2
        exit 1
    }
}

selftest() {
    local sandbox dev soak live stale_import
    sandbox="$(mktemp -d "${TMPDIR:-/tmp}/zcl-lane-plan-selftest.XXXXXX")"
    ZCL_LANE_SELFTEST_HOME="$sandbox/home"
    mkdir -p "$ZCL_LANE_SELFTEST_HOME"
    dev='{"lane":"dev","unit":"zcl23-dev","datadir":"/tmp/zcl-dev","role_ready":false,"status":"warn","reason":"lag_to_live_99","snapshot_path":"/tmp/zcl-dev/utxo-seed-10.snapshot","snapshot_loader_configured":false,"recovery_hint":"restart_with_load_snapshot_at_own_height"}'
    soak='{"lane":"soak","unit":"z23-soak","datadir":"/tmp/zcl-soak","role_ready":false,"status":"warn","reason":"lag_to_live_99","snapshot_path":"","snapshot_loader_configured":false,"recovery_hint":"install_tip_seed_snapshot"}'
    live='{"lane":"live","unit":"zclassic23","datadir":"/tmp/zcl-live","role_ready":false,"status":"warn","reason":"lag_to_live_99","snapshot_path":"/tmp/zcl-live/utxo-seed-10.snapshot","snapshot_loader_configured":false,"recovery_hint":"restart_with_load_snapshot_at_own_height"}'
    stale_import='{"lane":"dev","unit":"zcl23-dev","datadir":"/tmp/zcl-dev","role_ready":false,"status":"warn","reason":"lag_to_live_99","height":50,"snapshot_seed_height":10,"snapshot_path":"/tmp/zcl-dev/utxo-seed-10.snapshot","snapshot_loader_configured":true,"recovery_hint":"loader_active"}'
    selftest_case "dev loader plan" dev 0 "$dev"
    selftest_case "soak seed plan" soak 0 "$soak"
    selftest_case "canonical refused" live 1 "$live"
    selftest_case_contains "stale forced header import skipped" dev \
        "$stale_import" "header_import_skipped_snapshot_not_newer"
    selftest_apply_refused "public --apply" flag
    selftest_apply_refused "public apply env" env
    rm -rf "$sandbox"
    printf 'lane-recover selftest PASS\n'
}

refuse_public_apply

if [ "${ZCL_LANE_RECOVERY_SELFTEST:-0}" = "1" ]; then
    selftest
    exit 0
fi

case "$LANE" in
    all)
        recover_lane dev
        recover_lane soak
        ;;
    *)
        recover_lane "$LANE"
        ;;
esac
