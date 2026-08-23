#!/usr/bin/env bash
# One-shot first-4/4 evidence writer shared by the referee and its test.

fleet_mesh_capture_first_full() {
    local observed=$1 expected=$2 status_file=$3 evidence_file=$4
    local captured_at=$5 captured_head=$6 evidence_dir status_sha tmp

    FLEET_FIRST_FULL_CAPTURED=no
    [ "$observed" = "$expected" ] || return 0
    [ -e "$evidence_file" ] && return 0

    evidence_dir=$(CDPATH= cd -- "$(dirname -- "$evidence_file")" && pwd)
    status_sha=$(sha256sum "$status_file" | awk '{print $1}')
    tmp=$(mktemp "$evidence_dir/.mesh.first-4of4.XXXXXX")
    {
        printf 'EVIDENCE_KIND=FIRST_MESH_4OF4\n'
        printf 'CAPTURED_AT=%s\n' "$captured_at"
        printf 'CAPTURED_HEAD=%s\n' "$captured_head"
        printf 'MESH_STATUS_SHA256=%s\n' "$status_sha"
        sed -n 'p' "$status_file"
    } >"$tmp"
    mv "$tmp" "$evidence_file"
    FLEET_FIRST_FULL_CAPTURED=yes
}

# Persist one peer's consecutive silence clock across referee cycles. A cycle
# only counts when the caller completed an observation; lock refusals never
# invoke this helper and therefore cannot manufacture silence evidence.
fleet_mesh_silence_observe() {
    local silent=$1 previous_count=$2 previous_since=$3 observed_at=$4
    local previous_epoch=$5 observed_epoch=$6 minimum_interval=$7
    local next_eligible

    case "$previous_count" in
        ''|*[!0-9]*) previous_count=0 ;;
    esac
    case "$previous_epoch" in
        ''|*[!0-9]*) previous_epoch=0 ;;
    esac
    case "$observed_epoch" in
        ''|*[!0-9]*) observed_epoch=0 ;;
    esac
    case "$minimum_interval" in
        ''|*[!0-9]*|0) minimum_interval=240 ;;
    esac
    FLEET_SILENT_COUNT=0
    FLEET_SILENT_SINCE=NONE
    FLEET_SILENT_RECORD="ACTIVE:observed=$observed_at"

    [ "$silent" = yes ] || return 0
    if [ "$previous_count" -gt 0 ] && [ "$previous_since" != NONE ] &&
       [ -n "$previous_since" ]; then
        FLEET_SILENT_SINCE=$previous_since
    else
        FLEET_SILENT_SINCE=$observed_at
    fi

    if [ "$previous_count" -gt 0 ] && [ "$previous_epoch" -gt 0 ] &&
       [ "$observed_epoch" -ge "$previous_epoch" ] &&
       [ $((observed_epoch - previous_epoch)) -lt "$minimum_interval" ]; then
        FLEET_SILENT_COUNT=$previous_count
        next_eligible=$((previous_epoch + minimum_interval))
        if [ "$FLEET_SILENT_COUNT" -ge 2 ]; then
            FLEET_SILENT_RECORD="SILENT_PAST_TWO_CYCLES:since=$FLEET_SILENT_SINCE:observed=$observed_at:cycles=$FLEET_SILENT_COUNT"
        else
            FLEET_SILENT_RECORD="SILENT_PENDING:cycle=1/2:since=$FLEET_SILENT_SINCE:next_eligible_epoch=$next_eligible"
        fi
        return 0
    fi

    FLEET_SILENT_COUNT=$((previous_count + 1))
    if [ "$FLEET_SILENT_COUNT" -ge 2 ]; then
        FLEET_SILENT_RECORD="SILENT_PAST_TWO_CYCLES:since=$FLEET_SILENT_SINCE:confirmed=$observed_at:cycles=$FLEET_SILENT_COUNT"
    else
        FLEET_SILENT_RECORD="SILENT_PENDING:cycle=1/2:since=$FLEET_SILENT_SINCE:next_eligible_epoch=$((observed_epoch + minimum_interval))"
    fi
}
