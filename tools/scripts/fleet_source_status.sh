#!/usr/bin/env bash
# Shared fail-closed source ancestry classifier, plus the one resolver for
# where an operator's LOCAL mesh state lives.
#
# This repository ships no fleet. Anyone may run one box or twenty and have
# them coordinate; no box is privileged, and no box's observations are ever
# committed. Per-box state lives under
#   ${XDG_STATE_HOME:-$HOME/.local/state}/zclassic23/fleet/
# which is outside the checkout on purpose: a clone must look identical to a
# stranger and to someone who happens to run several machines.
#
# SOURCE_SHA remains the byte-authoritative runtime identity.  Git provenance
# is a separate mandatory GIT_SHA field; no runtime hash, including a 40-hex
# legacy value, is ever reinterpreted as a Git commit.
#
# Source this file, then call:
#   fleet_state_dir                                  -> local mesh state path
#   fleet_state_configured                           -> 0 if any box publishes
#   fleet_state_boxes                                -> one box label per line
#   fleet_state_field FILE KEY                       -> one value, "" if absent
#   fleet_source_status_audit REPO OBSERVED_HEAD SOURCE_SHA GIT_SHA FLOOR
#
# Audit results are returned in FLEET_SOURCE_* globals.  STATUS is always
# exactly CURRENT or STALE; missing, malformed, foreign, and pre-floor
# identities are STALE rather than an ambiguous third state.

# The single definition of the local mesh state directory. Everything a box
# observes about itself, or reads about a peer, is a file in here. It is never
# inside the repository: state written into the checkout is exactly how
# operator-specific values ended up in public history, and how a project that
# anyone can join grew the appearance of a designated in-crowd.
fleet_state_dir() {
    if [ -n "${ZCL_FLEET_STATE_DIR:-}" ]; then
        printf '%s' "$ZCL_FLEET_STATE_DIR"
        return 0
    fi
    printf '%s/zclassic23/fleet' "${XDG_STATE_HOME:-$HOME/.local/state}"
}

# No local mesh is the NORMAL state of a fresh clone, not an error. Callers
# use this to report "no local mesh configured" and exit 0 rather than dying.
fleet_state_configured() {
    local dir f
    dir="$(fleet_state_dir)"
    [ -d "$dir" ] || return 1
    # Written as an `if`, not `[ -f "$f" ] && return 0`: a caller running
    # under `set -e` would exit on the failing AND-list of the last iteration
    # instead of reaching the honest `return 1` below.
    for f in "$dir"/*.txt "$dir"/*.identity "$dir"/*.sync; do
        if [ -f "$f" ]; then
            return 0
        fi
    done
    return 1
}

# Box labels this operator publishes locally, one per line, deduplicated.
# A label is whatever the operator named the box; nothing here assumes a
# numbering scheme, a count, or that any particular box exists.
fleet_state_boxes() {
    local dir f b
    dir="$(fleet_state_dir)"
    [ -d "$dir" ] || return 0
    for f in "$dir"/*.txt "$dir"/*.identity "$dir"/*.sync "$dir"/*.status; do
        [ -f "$f" ] || continue
        b="${f##*/}"
        printf '%s\n' "${b%.*}"
    done | LC_ALL=C sort -u
}

# Read one KEY=value field out of a local mesh state file. An absent file and
# an absent key are both "" — an empty state, never a failure. Parsed, never
# sourced: state is data, not code to execute.
fleet_state_field() {
    local file="$1" key="$2"
    [ -f "$file" ] || return 0
    awk -F= -v k="$key" \
        '$0 !~ /^[[:space:]]*#/ && $1==k { sub(/^[^=]*=/, ""); print; exit }' \
        "$file"
}

fleet_source_status_reset() {
    FLEET_SOURCE_KIND=invalid
    FLEET_SOURCE_COMMIT=UNKNOWN
    FLEET_SOURCE_STATUS=STALE
    FLEET_SOURCE_COMMIT_DATE=UNKNOWN
    FLEET_SOURCE_BEHIND=UNKNOWN
    FLEET_SOURCE_DETAIL=invalid_source_sha
    FLEET_SOURCE_REQUIRED_FLOOR=no
}

fleet_source_normalize_commit_date() {
    local stamp=$1

    case "$stamp" in
        ????-??-??T??:??:??Z)
            printf '%s+00:00' "${stamp%Z}"
            ;;
        *)
            printf '%s' "$stamp"
            ;;
    esac
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
    if [ -n "$date" ]; then
        FLEET_SOURCE_COMMIT_DATE=$(fleet_source_normalize_commit_date "$date")
    fi

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

# Report every locally published box's source status against this checkout's
# observed head. Prints one line per box and exits 0 with a single explanatory
# line when there is no local mesh at all, which is what a fresh clone sees.
fleet_source_status_report() {
    local repo="${1:-.}" observed_head="${2:-HEAD}" floor="${3:-}"
    local dir box f src git_sha

    dir="$(fleet_state_dir)"
    if ! fleet_state_configured; then
        printf 'no local mesh configured (%s)\n' "$dir"
        return 0
    fi
    observed_head="$(git -C "$repo" rev-parse "$observed_head" 2>/dev/null \
        || printf '%s' "$observed_head")"
    while read -r box; do
        [ -n "$box" ] || continue
        f="$dir/$box.txt"
        src="$(fleet_state_field "$f" SOURCE_SHA)"
        git_sha="$(fleet_state_field "$f" GIT_SHA)"
        fleet_source_status_audit "$repo" "$observed_head" "$src" \
            "$git_sha" "$floor"
        printf 'box=%s status=%s behind=%s detail=%s\n' \
            "$box" "$FLEET_SOURCE_STATUS" "$FLEET_SOURCE_BEHIND" \
            "$FLEET_SOURCE_DETAIL"
    done <<<"$(fleet_state_boxes)"
    return 0
}
