#!/usr/bin/env bash
# Append-only, redacted notebook for the 100 x 0.00001000 ZCL live campaign.
# This records evidence only. It cannot plan, sign, authorize, or broadcast.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CATALOG="${ZCL_TRANSACTION_MICRO_CATALOG:-$REPO/tools/dev/transaction_micro_lab_catalog.def}"
ACTION="${1:-status}"
LEDGER_TEMPLATE="$REPO/docs/work/transaction-micro-lab-events.jsonl"
PRIVATE_STATE_ROOT="${XDG_STATE_HOME:-$HOME/.local/state}/zclassic23-transaction-lab"
PRIVATE_LEDGER="$PRIVATE_STATE_ROOT/transaction-micro-lab-events.jsonl"
if [ -n "${ZCL_TRANSACTION_MICRO_LEDGER:-}" ]; then
    LEDGER="$ZCL_TRANSACTION_MICRO_LEDGER"
else
    case "$ACTION" in
        record)
            install -d -m 700 "$PRIVATE_STATE_ROOT"
            if [ ! -e "$PRIVATE_LEDGER" ]; then
                install -m 600 "$LEDGER_TEMPLATE" "$PRIVATE_LEDGER"
            fi
            LEDGER="$PRIVATE_LEDGER"
            ;;
        status)
            if [ -f "$PRIVATE_LEDGER" ]; then
                LEDGER="$PRIVATE_LEDGER"
            else
                LEDGER="$LEDGER_TEMPLATE"
            fi
            ;;
        *) LEDGER="$LEDGER_TEMPLATE" ;;
    esac
fi
LIVE_CATALOG="${ZCL_TRANSACTION_LIVE_CATALOG:-$REPO/tools/dev/transaction_live_catalog.def}"
NATIVE_CATALOG="${ZCL_TRANSACTION_MICRO_NATIVE_CATALOG:-$REPO/engine/controllers/include/controllers/transaction_micro_lab_profiles.def}"
CAMPAIGN_ID=mainnet-micro-100-v1
TARGET_COUNT=100
RECIPIENT_ZAT=1000
FEE_CEILING_ZAT=10000
SETUP_ENVELOPE_ZAT=900000
CAMPAIGN_ENVELOPE_ZAT=2000000
LIFETIME_LAB_CAP_ZAT=5000000
RESERVE_FLOOR_ZAT=25000000

die() {
    echo "transaction-micro-lab: $*" >&2
    exit 2
}

assert_record_ledger_private() {
    local resolved mode owner
    resolved="$(realpath -m -- "$LEDGER")" ||
        die "cannot resolve the private ledger path"
    case "$resolved" in
        "$REPO"|"$REPO"/*)
            die "record ledger must stay outside the repository"
            ;;
    esac
    [ -f "$resolved" ] || die "record ledger must already be a regular file"
    mode="$(stat -c '%a' "$resolved" 2>/dev/null || true)"
    owner="$(stat -c '%u' "$resolved" 2>/dev/null || true)"
    [ "$mode" = 600 ] || die "record ledger must have mode 0600"
    [ "$owner" = "$(id -u)" ] || die "record ledger must be operator-owned"
}

bar() {
    local done="$1" total="$2" width=20 filled=0 empty=0
    [ "$total" -le 0 ] || filled=$((done * width / total))
    [ "$filled" -le "$width" ] || filled="$width"
    empty=$((width - filled))
    printf '%*s' "$filled" '' | tr ' ' '#'
    printf '%*s' "$empty" '' | tr ' ' '-'
}

slot_case() {
    local slot="$1"
    awk -F'|' -v slot="$slot" '
        !/^#/ && NF && (slot + 0) >= ($1 + 0) && (slot + 0) <= ($2 + 0) {
            print $3; found=1; exit
        }
        END { if (!found) exit 1 }
    ' "$CATALOG"
}

check_catalog() {
    awk -F'|' -v target="$TARGET_COUNT" -v recipient="$RECIPIENT_ZAT" \
        -v fee_ceiling="$FEE_CEILING_ZAT" '
        function bad(msg) {
            print "transaction-micro-lab-check: " msg > "/dev/stderr"
            errors++
        }
        !/^#/ && NF {
            if (NF != 8) { bad("catalog line " FNR " must have eight fields"); next }
            if ($1 !~ /^[0-9][0-9][0-9]$/ || $2 !~ /^[0-9][0-9][0-9]$/)
                bad("invalid slot range at catalog line " FNR)
            first=$1 + 0; last=$2 + 0
            if (first != expected) bad("slot range begins at " first ", expected " expected)
            if (last < first || last > target) bad("invalid slot range " $1 ".." $2)
            if ($3 !~ /^[a-z0-9_]+$/) bad("invalid case_id " $3)
            if ($4 !~ /^[a-z0-9_]+$/) bad("invalid variant for " $3)
            if ($5 !~ /^(transparent|sapling|contract)$/) bad("invalid source pool for " $3)
            if ($6 !~ /^[a-z0-9_]+$/) bad("invalid prerequisite for " $3)
            if (($7 + 0) != recipient) bad("recipient value drift for " $3)
            if (($8 + 0) != fee_ceiling) bad("fee ceiling drift for " $3)
            profiles++; slots += last - first + 1; expected=last + 1
        }
        BEGIN { expected=1 }
        END {
            if (slots != target) bad("catalog covers " slots " slots, expected " target)
            if (profiles < 2) bad("campaign must contain multiple transaction types")
            if (errors) exit 1
        }
    ' "$CATALOG"

    local cases case_id
    cases="$(awk -F'|' '!/^#/ && NF { print $3 }' "$CATALOG" | sort -u)"
    while IFS= read -r case_id; do
        [ -n "$case_id" ] || continue
        awk -F'|' -v id="$case_id" '$1 == id && $2 == "mainnet_ready" { found=1 }
            END { exit !found }' "$LIVE_CATALOG" ||
            die "catalog case $case_id is not mainnet_ready"
    done <<< "$cases"

    local shell_rows native_rows
    shell_rows="$(awk -F'|' '!/^#/ && NF { print }' "$CATALOG")"
    native_rows="$(awk '
        /^TX_MICRO_PROFILE[(]/ {
            line=$0
            sub(/^TX_MICRO_PROFILE[(]/, "", line)
            sub(/[)]$/, "", line)
            n=split(line, f, ",")
            if (n != 8) next
            for (i=1; i<=n; i++) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", f[i])
                gsub(/^"|"$/, "", f[i])
            }
            printf "%03d|%03d|%s|%s|%s|%s|%d|%d\n",
                   f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8]
        }
    ' "$NATIVE_CATALOG")"
    [ "$shell_rows" = "$native_rows" ] ||
        die "shell and native C23 micro-lab catalogs differ"
}

check_header() {
    local expected
    expected="{\"schema\":\"zcl.transaction_micro_lab_campaign.v1\",\"campaign_id\":\"$CAMPAIGN_ID\",\"created_at\":\"2026-08-05T00:00:00Z\",\"target_count\":$TARGET_COUNT,\"recipient_zat_each\":$RECIPIENT_ZAT,\"fee_ceiling_zat_each\":$FEE_CEILING_ZAT,\"setup_envelope_zat\":$SETUP_ENVELOPE_ZAT,\"campaign_envelope_zat\":$CAMPAIGN_ENVELOPE_ZAT,\"lifetime_lab_cap_zat\":$LIFETIME_LAB_CAP_ZAT,\"reserve_floor_zat\":$RESERVE_FLOOR_ZAT}"
    [ "$(sed -n '1p' "$LEDGER")" = "$expected" ] ||
        die "ledger campaign header is missing or changed"
}

check_events() {
    local event_ledger="${1:-$LEDGER}"
    awk -F'"' -v catalog="$CATALOG" -v recipient="$RECIPIENT_ZAT" \
        -v fee_ceiling="$FEE_CEILING_ZAT" '
        function bad(msg) {
            print "transaction-micro-lab-check: " msg > "/dev/stderr"
            errors++
        }
        BEGIN {
            while ((getline row < catalog) > 0) {
                if (row ~ /^#/ || row == "") continue
                split(row, f, "[|]")
                for (s=f[1] + 0; s <= f[2] + 0; s++) expected_case[s]=f[3]
            }
            close(catalog)
        }
        NR == 1 { next }
        {
            line=$0
            if (line ~ /"(address|endpoint|datadir|grant_token|private_key|recovery_words|memo|secret|plan_id)"/)
                bad("sensitive field name at ledger line " NR)
            if (NF != 41 || $4 != "zcl.transaction_micro_lab_event.v1") {
                bad("invalid event schema at ledger line " NR); next
            }
            slot_text=line
            sub(/^.*"slot":/, "", slot_text); sub(/,.*/, "", slot_text)
            slot=slot_text + 0; case_id=$14; state=$18; source_commit=$22; txid=$26
            if (slot < 1 || slot > 100) bad("invalid slot at ledger line " NR)
            if (expected_case[slot] != case_id) bad("case mismatch for slot " slot)
            if (state !~ /^(broadcast|confirmed|conflicted|expired|reorged)$/)
                bad("invalid state for slot " slot)
            if (txid !~ /^[0-9a-f]{64}$/) bad("invalid txid for slot " slot)
            if (source_commit !~ /^[0-9a-f]{8,64}$/) bad("invalid source commit for slot " slot)
            value=line; sub(/^.*"recipient_zat":/, "", value); sub(/,.*/, "", value)
            fee=line; sub(/^.*"fee_zat":/, "", fee); sub(/,.*/, "", fee)
            height=line; sub(/^.*"block_height":/, "", height); sub(/,.*/, "", height)
            block_hash=line; sub(/^.*"block_hash":"/, "", block_hash); sub(/".*/, "", block_hash)
            broadcast_unix=line; sub(/^.*"broadcast_unix":/, "", broadcast_unix); sub(/,.*/, "", broadcast_unix)
            confirmed_unix=line; sub(/^.*"confirmed_unix":/, "", confirmed_unix); sub(/}.*/, "", confirmed_unix)
            if ((value + 0) != recipient) bad("recipient value drift for slot " slot)
            if (fee !~ /^[0-9]+$/ || (fee + 0) != fee_ceiling)
                bad("fee differs from the checked campaign fee for slot " slot)
            if (broadcast_unix !~ /^[1-9][0-9]*$/) bad("invalid broadcast time for slot " slot)
            if (state == "broadcast") {
                if (height != "0" || block_hash != "UNAVAILABLE" || confirmed_unix != "0")
                    bad("broadcast event carries confirmation fields for slot " slot)
                if (events[slot] != 0) bad("slot " slot " was broadcast more than once")
            } else {
                if (events[slot] == 0) bad("terminal event precedes broadcast for slot " slot)
                if (first_txid[slot] != txid) bad("txid changed for slot " slot)
                if (first_fee[slot] != fee) bad("fee changed for slot " slot)
                if (state == "confirmed") {
                    if (height !~ /^[1-9][0-9]*$/ || block_hash !~ /^[0-9a-f]{64}$/ ||
                        confirmed_unix !~ /^[1-9][0-9]*$/ || confirmed_unix < broadcast_unix)
                        bad("invalid confirmation identity for slot " slot)
                } else if (height != "0" || block_hash != "UNAVAILABLE" || confirmed_unix != "0") {
                    bad("non-confirmed event carries block identity for slot " slot)
                }
                if ((state == "conflicted" || state == "expired") && closed[slot])
                    bad("slot " slot " has repeated terminal failure")
            }
            if (events[slot] == 0) {
                if (txid_owner[txid] && txid_owner[txid] != slot)
                    bad("txid reused by slots " txid_owner[txid] " and " slot)
                txid_owner[txid]=slot; first_txid[slot]=txid; first_fee[slot]=fee
            }
            # A local node can lose transaction-index/wallet projection
            # coverage while the canonical block body still proves that the
            # exact tx mined.  Keep the ledger append-only and allow that
            # stronger evidence to correct an earlier expired/conflicted
            # observation.  Every other post-terminal transition remains
            # invalid.
            if (closed[slot] && state != "confirmed")
                bad("event follows terminal failure for slot " slot)
            if (state == "conflicted" || state == "expired") closed[slot]=1
            if (state == "reorged" && last_state[slot] != "confirmed")
                bad("reorged must follow confirmed for slot " slot)
            if (state == "confirmed" && last_state[slot] != "broadcast" &&
                last_state[slot] != "reorged" &&
                last_state[slot] != "conflicted" &&
                last_state[slot] != "expired")
                bad("confirmed must follow broadcast, reorged, or a corrected local terminal observation for slot " slot)
            if (state == "confirmed") closed[slot]=0
            if ((state == "conflicted" || state == "expired") &&
                last_state[slot] != "broadcast" && last_state[slot] != "reorged")
                bad(state " must follow broadcast or reorged for slot " slot)
            events[slot]++; last_state[slot]=state
        }
        END { if (errors) exit 1 }
    ' "$event_ledger"
}

check_all() {
    check_catalog
    check_header
    check_events
    echo "transaction-micro-lab-check: PASS"
}

stats() {
    awk -F'"' -v catalog="$CATALOG" '
        BEGIN {
            while ((getline row < catalog) > 0) {
                if (row ~ /^#/ || row == "") continue
                split(row, f, "[|]")
                for (s=f[1] + 0; s <= f[2] + 0; s++) slot_case[s]=f[3]
            }
            close(catalog)
        }
        NR == 1 { next }
        {
            line=$0
            slot_text=line; sub(/^.*"slot":/, "", slot_text); sub(/,.*/, "", slot_text)
            slot=slot_text + 0; state=$18
            fee=line; sub(/^.*"fee_zat":/, "", fee); sub(/,.*/, "", fee)
            broadcast=line; sub(/^.*"broadcast_unix":/, "", broadcast); sub(/,.*/, "", broadcast)
            confirmed=line; sub(/^.*"confirmed_unix":/, "", confirmed); sub(/}.*/, "", confirmed)
            latest[slot]=state
            if (state == "confirmed") {
                confirmed_count[slot]++
                current_fee[slot]=fee + 0
                current_latency[slot]=confirmed - broadcast
            } else if (state == "reorged") {
                confirmed_count[slot]=0; current_fee[slot]=0; current_latency[slot]=0
            }
        }
        END {
            min_fee=-1
            for (slot in latest) {
                if (latest[slot] == "broadcast") inflight++
                else if (latest[slot] == "conflicted") conflicted++
                else if (latest[slot] == "expired") expired++
                else if (latest[slot] == "reorged") reorged++
                if (confirmed_count[slot] > 0) {
                    done++; fee_total += current_fee[slot]
                    latency_total += current_latency[slot]
                    confirmed_type[slot_case[slot]]=1
                    if (min_fee < 0 || current_fee[slot] < min_fee) min_fee=current_fee[slot]
                    if (current_fee[slot] > max_fee) max_fee=current_fee[slot]
                }
            }
            for (type in confirmed_type) type_done++
            if (min_fee < 0) min_fee=0
            avg_fee=done ? int(fee_total / done) : 0
            avg_latency=done ? int(latency_total / done) : 0
            printf "%d %d %d %d %d %d %d %d %d %d %d\n", done, inflight,
                   conflicted, expired, reorged, fee_total, min_fee, max_fee,
                   avg_fee, avg_latency, type_done
        }
    ' "$LEDGER"
}

print_status() {
    local done inflight conflicted expired reorged fee_total min_fee max_fee avg_fee avg_latency type_done
    read -r done inflight conflicted expired reorged fee_total min_fee max_fee avg_fee avg_latency type_done < <(stats)
    local recipient_total=$((done * RECIPIENT_ZAT))
    local planned_recipient=$((TARGET_COUNT * RECIPIENT_ZAT))
    local planned_fee=$((TARGET_COUNT * FEE_CEILING_ZAT))
    local type_count
    type_count="$(awk -F'|' '!/^#/ && NF { seen[$3]=1 } END { for (x in seen) n++; print n+0 }' "$CATALOG")"
    printf 'micro-lab confirmed: [%s] %d/%d transactions\n' "$(bar "$done" "$TARGET_COUNT")" "$done" "$TARGET_COUNT"
    printf 'micro-lab variety:   [%s] %d/%d campaign types confirmed (%d/39 catalog types eligible)\n' \
        "$(bar "$type_done" "$type_count")" "$type_done" "$type_count" "$type_count"
    printf '  amount_each_zat=%d planned_recipient_zat=%d planned_fee_ceiling_zat=%d\n' \
        "$RECIPIENT_ZAT" "$planned_recipient" "$planned_fee"
    printf '  setup_envelope_zat=%d campaign_envelope_zat=%d lifetime_cap_zat=%d\n' \
        "$SETUP_ENVELOPE_ZAT" "$CAMPAIGN_ENVELOPE_ZAT" "$LIFETIME_LAB_CAP_ZAT"
    printf '  confirmed_recipient_zat=%d confirmed_fee_zat=%d fee_min_zat=%d fee_max_zat=%d fee_avg_zat=%d avg_confirmation_seconds=%d\n' \
        "$recipient_total" "$fee_total" "$min_fee" "$max_fee" "$avg_fee" "$avg_latency"
    printf '  inflight=%d conflicted=%d expired=%d reorged=%d\n' "$inflight" "$conflicted" "$expired" "$reorged"
    printf '  fee_policy=current_typed_wallet_default smallest_supported_zat=%d relay_floor_zat=100\n' "$FEE_CEILING_ZAT"
    printf '  mainnet_gate=EXTERNAL_REQUIRED next=evaluate HANDOFF and identity-bound custody gates\n'
}

record_event() {
    local slot='' state='' txid='' fee_zat='' broadcast_unix=''
    local confirmed_unix=0 block_height=0 block_hash=UNAVAILABLE arg case_id observed commit
    local candidate event
    shift
    assert_record_ledger_private
    for arg in "$@"; do
        case "$arg" in
            --slot=*) slot="${arg#*=}" ;;
            --state=*) state="${arg#*=}" ;;
            --txid=*) txid="${arg#*=}" ;;
            --fee-zat=*) fee_zat="${arg#*=}" ;;
            --broadcast-unix=*) broadcast_unix="${arg#*=}" ;;
            --confirmed-unix=*) confirmed_unix="${arg#*=}" ;;
            --block-height=*) block_height="${arg#*=}" ;;
            --block-hash=*) block_hash="${arg#*=}" ;;
            *) die "unknown record argument: $arg" ;;
        esac
    done
    [[ "$slot" =~ ^[0-9]{1,3}$ ]] && [ "$((10#$slot))" -ge 1 ] && [ "$((10#$slot))" -le "$TARGET_COUNT" ] ||
        die "record requires --slot=1..100"
    slot=$((10#$slot))
    case "$state" in broadcast|confirmed|conflicted|expired|reorged) ;; *) die "invalid --state" ;; esac
    [[ "$txid" =~ ^[0-9a-f]{64}$ ]] || die "invalid --txid"
    [[ "$fee_zat" =~ ^[0-9]+$ ]] && [ "$fee_zat" -eq "$FEE_CEILING_ZAT" ] ||
        die "--fee-zat must equal the checked campaign fee $FEE_CEILING_ZAT"
    [[ "$broadcast_unix" =~ ^[1-9][0-9]*$ ]] || die "invalid --broadcast-unix"
    if [ "$state" = confirmed ]; then
        [[ "$confirmed_unix" =~ ^[1-9][0-9]*$ ]] && [ "$confirmed_unix" -ge "$broadcast_unix" ] || die "invalid --confirmed-unix"
        [[ "$block_height" =~ ^[1-9][0-9]*$ ]] || die "invalid --block-height"
        [[ "$block_hash" =~ ^[0-9a-f]{64}$ ]] || die "invalid --block-hash"
    elif [ "$confirmed_unix" != 0 ] || [ "$block_height" != 0 ] || [ "$block_hash" != UNAVAILABLE ]; then
        die "only confirmed events may carry block identity"
    fi
    case_id="$(slot_case "$slot")" || die "slot is not in catalog"
    observed="$(date -u +%FT%TZ)"
    commit="$(git -C "$REPO" rev-parse --short=8 HEAD)"
    check_catalog
    check_header
    printf -v event '{"schema":"zcl.transaction_micro_lab_event.v1","observed_at":"%s","slot":%d,"case_id":"%s","state":"%s","source_commit":"%s","txid":"%s","recipient_zat":%d,"fee_zat":%d,"block_height":%s,"block_hash":"%s","broadcast_unix":%s,"confirmed_unix":%s}' \
        "$observed" "$slot" "$case_id" "$state" "$commit" "$txid" \
        "$RECIPIENT_ZAT" "$fee_zat" "$block_height" "$block_hash" \
        "$broadcast_unix" "$confirmed_unix"
    candidate="$(mktemp)"
    cleanup_transaction_micro_lab_candidate() {
        [ ! -f "$candidate" ] || rm -- "$candidate"
    }
    trap cleanup_transaction_micro_lab_candidate RETURN
    exec 9>>"$LEDGER"
    flock 9
    check_events
    cp "$LEDGER" "$candidate"
    printf '%s\n' "$event" >> "$candidate"
    check_events "$candidate"
    printf '%s\n' "$event" >&9
    flock -u 9
    check_events
}

selftest() {
    local fixture fixture_ledger output
    fixture="$(mktemp -d)"
    fixture_ledger="$fixture/events.jsonl"
    cleanup_transaction_micro_lab_selftest() {
        [ ! -d "$fixture" ] || rm -r -- "$fixture"
    }
    trap cleanup_transaction_micro_lab_selftest RETURN
    if (LEDGER="$REPO/docs/work/forbidden-micro-lab-selftest.jsonl";
        assert_record_ledger_private) >/dev/null 2>&1; then
        die "selftest accepted a record ledger inside the repository"
    fi
    sed -n '1p' "$LEDGER" > "$fixture_ledger"
    chmod 600 "$fixture_ledger"
    chmod 644 "$fixture_ledger"
    if (LEDGER="$fixture_ledger"; assert_record_ledger_private) \
            >/dev/null 2>&1; then
        die "selftest accepted a non-private record ledger"
    fi
    chmod 600 "$fixture_ledger"
    ZCL_TRANSACTION_MICRO_LEDGER="$fixture_ledger" "$0" record \
        --slot=1 --state=broadcast \
        --txid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        --fee-zat=10000 --broadcast-unix=1000 >/dev/null
    ZCL_TRANSACTION_MICRO_LEDGER="$fixture_ledger" "$0" record \
        --slot=1 --state=confirmed \
        --txid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        --fee-zat=10000 --broadcast-unix=1000 --confirmed-unix=1120 \
        --block-height=123456 \
        --block-hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb >/dev/null
    output="$(ZCL_TRANSACTION_MICRO_LEDGER="$fixture_ledger" "$0" status)"
    [[ "$output" == *'1/100 transactions'* ]] || die "selftest status omitted confirmation"
    [[ "$output" == *'confirmed_fee_zat=10000'* ]] || die "selftest status omitted fee"
    [[ "$output" == *'avg_confirmation_seconds=120'* ]] || die "selftest status omitted latency"
    ZCL_TRANSACTION_MICRO_LEDGER="$fixture_ledger" "$0" record \
        --slot=1 --state=reorged \
        --txid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        --fee-zat=10000 --broadcast-unix=1000 >/dev/null
    ZCL_TRANSACTION_MICRO_LEDGER="$fixture_ledger" "$0" record \
        --slot=1 --state=confirmed \
        --txid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        --fee-zat=10000 --broadcast-unix=1000 --confirmed-unix=1180 \
        --block-height=123457 \
        --block-hash=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd >/dev/null
    output="$(ZCL_TRANSACTION_MICRO_LEDGER="$fixture_ledger" "$0" status)"
    [[ "$output" == *'avg_confirmation_seconds=180'* ]] || die "selftest did not reconcile reorg"

    # A canonical block-body proof may correct an earlier local expiry.  The
    # correction is a new append-only event; the old observation is retained.
    ZCL_TRANSACTION_MICRO_LEDGER="$fixture_ledger" "$0" record \
        --slot=2 --state=broadcast \
        --txid=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
        --fee-zat=10000 --broadcast-unix=1000 >/dev/null
    ZCL_TRANSACTION_MICRO_LEDGER="$fixture_ledger" "$0" record \
        --slot=2 --state=expired \
        --txid=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
        --fee-zat=10000 --broadcast-unix=1000 >/dev/null
    ZCL_TRANSACTION_MICRO_LEDGER="$fixture_ledger" "$0" record \
        --slot=2 --state=confirmed \
        --txid=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
        --fee-zat=10000 --broadcast-unix=1000 --confirmed-unix=1190 \
        --block-height=123458 \
        --block-hash=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee >/dev/null
    output="$(ZCL_TRANSACTION_MICRO_LEDGER="$fixture_ledger" "$0" status)"
    [[ "$output" == *'2/100 transactions'* ]] ||
        die "selftest did not accept canonical correction after local expiry"
    if ZCL_TRANSACTION_MICRO_LEDGER="$fixture_ledger" "$0" record \
        --slot=3 --state=broadcast \
        --txid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        --fee-zat=10000 --broadcast-unix=1001 >/dev/null 2>&1; then
        die "selftest accepted a txid reused by two slots"
    fi
    if ZCL_TRANSACTION_MICRO_LEDGER="$fixture_ledger" "$0" record \
        --slot=3 --state=broadcast \
        --txid=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
        --fee-zat=10001 --broadcast-unix=1001 >/dev/null 2>&1; then
        die "selftest accepted a fee different from the checked campaign fee"
    fi
    echo "transaction-micro-lab selftest: PASS"
}

case "${1:-status}" in
    status) check_catalog; check_header; check_events; print_status ;;
    check) check_all ;;
    record) record_event "$@" ;;
    selftest) selftest ;;
    -h|--help)
        echo "usage: tools/dev/transaction-micro-lab.sh {status|check|selftest|record ...}"
        ;;
    *) die "unknown action: $1" ;;
esac
