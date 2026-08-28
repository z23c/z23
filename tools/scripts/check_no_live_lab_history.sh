#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Keep funded transaction-lab history out of the tracked repository.
# Reproducible simnet evidence and public consensus fixtures are allowed in the
# canonical baseline; owner-funded broadcasts and recipient-wallet manifests
# are private local state only.
set -euo pipefail

cd "$(dirname "$0")/../.."

LAB_BASELINE="docs/work/transaction-lab-events.jsonl"
MICRO_BASELINE="docs/work/transaction-micro-lab-events.jsonl"
LAB_NAME="transaction-lab-events.jsonl"
MICRO_NAME="transaction-micro-lab-events.jsonl"
MICRO_HEADER='{"schema":"zcl.transaction_micro_lab_campaign.v1","campaign_id":"mainnet-micro-100-v1","created_at":"2026-08-05T00:00:00Z","target_count":100,"recipient_zat_each":1000,"fee_ceiling_zat_each":10000,"setup_envelope_zat":900000,"campaign_envelope_zat":2000000,"lifetime_lab_cap_zat":5000000,"reserve_floor_zat":25000000}'

fail() {
    echo "check-no-live-lab-history: FAIL — $*" >&2
    return 1
}

check_json_content() {
    local path="$1" content="$2"
    [[ "$content" != *'"schema":"zcl.transaction_micro_lab_recipient_wallet.v1"'* ]] ||
        fail "tracked private recipient-wallet manifest: $path" || return 1
    [[ "$content" != *'"schema":"zcl.transaction_micro_lab_event.v1"'* ]] ||
        fail "tracked funded micro-lab event history: $path" || return 1
    [[ "$content" != *'"proof":"live_confirmed"'* ]] ||
        fail "tracked live-confirmed transaction receipt: $path" || return 1
}

check_paths() {
    local root="$1"
    shift
    local path base content lab_seen=0 micro_seen=0 line_count

    for path in "$@"; do
        base="${path##*/}"
        case "$base" in
            "$LAB_NAME")
                [ "$path" = "$LAB_BASELINE" ] ||
                    fail "tracked duplicate lab ledger: $path" || return 1
                lab_seen=$((lab_seen + 1))
                ;;
            "$MICRO_NAME")
                [ "$path" = "$MICRO_BASELINE" ] ||
                    fail "tracked duplicate micro-lab ledger: $path" || return 1
                micro_seen=$((micro_seen + 1))
                ;;
        esac

        case "$path" in
            *.json|*.jsonl)
                content="$(< "$root/$path")"
                check_json_content "$path" "$content" || return 1
                ;;
        esac
    done

    [ "$lab_seen" -eq 1 ] ||
        fail "canonical lab baseline is missing or duplicated" || return 1
    [ "$micro_seen" -eq 1 ] ||
        fail "canonical micro-lab baseline is missing or duplicated" || return 1

    line_count="$(wc -l < "$root/$MICRO_BASELINE")"
    [ "$line_count" -eq 1 ] ||
        fail "micro-lab baseline must remain an empty one-line campaign template" || return 1
    [ "$(< "$root/$MICRO_BASELINE")" = "$MICRO_HEADER" ] ||
        fail "micro-lab campaign template changed unexpectedly" || return 1
}

check_index() {
    local path content line_count
    git cat-file -e ":$LAB_BASELINE" 2>/dev/null ||
        fail "canonical lab baseline is absent from the Git index" || return 1
    git cat-file -e ":$MICRO_BASELINE" 2>/dev/null ||
        fail "canonical micro-lab baseline is absent from the Git index" || return 1
    for path in "$@"; do
        case "$path" in
            *.json|*.jsonl)
                content="$(git show ":$path")" ||
                    fail "cannot read indexed JSON content: $path" || return 1
                check_json_content "$path (Git index)" "$content" || return 1
                ;;
        esac
    done
    line_count="$(git show ":$MICRO_BASELINE" | wc -l)"
    [ "$line_count" -eq 1 ] ||
        fail "indexed micro-lab baseline must remain a one-line template" || return 1
    [ "$(git show ":$MICRO_BASELINE")" = "$MICRO_HEADER" ] ||
        fail "indexed micro-lab campaign template changed unexpectedly" || return 1
}

selftest() {
    local fixture
    fixture="$(mktemp -d)"
    cleanup_no_live_lab_history_selftest() {
        [ ! -d "$fixture" ] || rm -r -- "$fixture"
    }
    trap cleanup_no_live_lab_history_selftest RETURN
    mkdir -p "$fixture/docs/work" "$fixture/private"
    printf '%s\n' \
        '{"schema":"zcl.transaction_lab_event.v1","proof":"simnet_confirmed"}' \
        > "$fixture/$LAB_BASELINE"
    printf '%s\n' "$MICRO_HEADER" > "$fixture/$MICRO_BASELINE"

    check_paths "$fixture" "$LAB_BASELINE" "$MICRO_BASELINE" ||
        fail "safe baseline fixture was rejected" || return 1

    printf '%s\n' '{"proof":"live_confirmed"}' >> "$fixture/$LAB_BASELINE"
    if check_paths "$fixture" "$LAB_BASELINE" "$MICRO_BASELINE" 2>/dev/null; then
        fail "selftest accepted a tracked live confirmation" || return 1
    fi
    # Drop the last line via rewrite, not GNU `sed -i`: BSD sed takes the
    # next argument as an in-place backup suffix, so `sed -i '$d' FILE`
    # would eat FILE as the script and mutate nothing.
    drop_last_line() { sed '$d' "$1" > "$1.nolid" && mv "$1.nolid" "$1"; }
    drop_last_line "$fixture/$LAB_BASELINE"

    printf '%s\n' '{"schema":"zcl.transaction_micro_lab_event.v1"}' \
        >> "$fixture/$MICRO_BASELINE"
    if check_paths "$fixture" "$LAB_BASELINE" "$MICRO_BASELINE" 2>/dev/null; then
        fail "selftest accepted tracked micro-lab history" || return 1
    fi
    drop_last_line "$fixture/$MICRO_BASELINE"

    cp "$fixture/$LAB_BASELINE" "$fixture/private/$LAB_NAME"
    if check_paths "$fixture" "$LAB_BASELINE" "$MICRO_BASELINE" \
            "private/$LAB_NAME" 2>/dev/null; then
        fail "selftest accepted a duplicate tracked notebook" || return 1
    fi
    rm -- "$fixture/private/$LAB_NAME"

    printf '%s\n' \
        '{"schema":"zcl.transaction_micro_lab_recipient_wallet.v1"}' \
        > "$fixture/private/recipient.json"
    if check_paths "$fixture" "$LAB_BASELINE" "$MICRO_BASELINE" \
            "private/recipient.json" 2>/dev/null; then
        fail "selftest accepted a tracked recipient-wallet manifest" || return 1
    fi

    echo "check-no-live-lab-history selftest: PASS"
}

case "${1:-}" in
    --selftest)
        selftest
        ;;
    "")
        mapfile -t tracked < <(git ls-files)
        check_paths "$PWD" "${tracked[@]}"
        check_index "${tracked[@]}"
        echo "check-no-live-lab-history: PASS — funded receipts remain private local state"
        ;;
    *)
        fail "unknown argument: $1"
        ;;
esac
