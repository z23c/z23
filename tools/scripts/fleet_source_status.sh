#!/usr/bin/env bash
# Shared fail-closed source ancestry classifier for the devfleet referee.
#
# SOURCE_SHA remains the byte-authoritative runtime identity.  Git provenance
# is a separate mandatory GIT_SHA field; no runtime hash, including a 40-hex
# legacy value, is ever reinterpreted as a Git commit.
#
# Source this file, then call:
#   fleet_source_status_audit REPO OBSERVED_HEAD SOURCE_SHA GIT_SHA FLOOR
#
# Results are returned in FLEET_SOURCE_* globals.  STATUS is always exactly
# CURRENT or STALE; missing, malformed, foreign, and pre-floor identities are
# STALE rather than an ambiguous third state.

fleet_source_status_reset() {
    FLEET_SOURCE_KIND=invalid
    FLEET_SOURCE_COMMIT=UNKNOWN
    FLEET_SOURCE_STATUS=STALE
    FLEET_SOURCE_COMMIT_DATE=UNKNOWN
    FLEET_SOURCE_BEHIND=UNKNOWN
    FLEET_SOURCE_DETAIL=invalid_source_sha
    FLEET_SOURCE_REQUIRED_FLOOR=no
}

fleet_source_status_audit() {
    local repo=$1 observed_head=$2 source_sha=$3 git_sha=$4 floor=$5
    local commit date behind

    fleet_source_status_reset
    commit=""
    if [[ "$source_sha" =~ ^[0-9a-f]{40}$ ]]; then
        FLEET_SOURCE_KIND=legacy_40hex_source
    elif [[ "$source_sha" =~ ^[0-9a-f]{64}$ ]]; then
        FLEET_SOURCE_KIND=source_id_sha256
    else
        return 0
    fi
    if [[ ! "$git_sha" =~ ^[0-9a-f]{40}$ ]]; then
        FLEET_SOURCE_DETAIL=missing_or_invalid_git_sha
        return 0
    fi
    commit=$git_sha

    FLEET_SOURCE_COMMIT=$commit
    if ! git -C "$repo" cat-file -e "$commit^{commit}" 2>/dev/null; then
        FLEET_SOURCE_DETAIL=source_commit_not_in_repository
        return 0
    fi

    date=$(git -C "$repo" show -s --format=%cI "$commit" 2>/dev/null || true)
    [ -n "$date" ] && FLEET_SOURCE_COMMIT_DATE=$date

    if ! git -C "$repo" merge-base --is-ancestor "$commit" "$observed_head";
    then
        FLEET_SOURCE_DETAIL=source_commit_not_ancestor_of_observed_main
        return 0
    fi

    behind=$(git -C "$repo" rev-list --count "$commit..$observed_head" \
        2>/dev/null || true)
    case "$behind" in
        ''|*[!0-9]*)
            FLEET_SOURCE_DETAIL=source_commit_distance_unavailable
            return 0
            ;;
    esac
    FLEET_SOURCE_BEHIND=$behind

    if [[ "$floor" =~ ^[0-9a-f]{40}$ ]] &&
       git -C "$repo" cat-file -e "$floor^{commit}" 2>/dev/null; then
        if ! git -C "$repo" merge-base --is-ancestor "$floor" "$commit";
        then
            FLEET_SOURCE_REQUIRED_FLOOR=yes
            FLEET_SOURCE_DETAIL="before_required_onion_floor:behind=$behind"
            return 0
        fi
    fi

    FLEET_SOURCE_STATUS=CURRENT
    FLEET_SOURCE_REQUIRED_FLOOR=no
    FLEET_SOURCE_DETAIL="ancestor_of_observed_main:behind=$behind"
    return 0
}
