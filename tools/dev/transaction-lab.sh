#!/usr/bin/env bash
# Redacted, append-only transaction-lab notebook and statistics.
# This tool records evidence only. It cannot build, sign, authorize, or send.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CATALOG="${ZCL_TRANSACTION_LAB_CATALOG:-$REPO/tools/dev/transaction_lab_catalog.def}"
ACTION="${1:-status}"
LEDGER_TEMPLATE="$REPO/docs/work/transaction-lab-events.jsonl"
PRIVATE_STATE_ROOT="${XDG_STATE_HOME:-$HOME/.local/state}/zclassic23-transaction-lab"
PRIVATE_LEDGER="$PRIVATE_STATE_ROOT/transaction-lab-events.jsonl"
if [ -n "${ZCL_TRANSACTION_LAB_LEDGER:-}" ]; then
    LEDGER="$ZCL_TRANSACTION_LAB_LEDGER"
else
    case "$ACTION" in
        record)
            install -d -m 700 "$PRIVATE_STATE_ROOT"
            if [ ! -e "$PRIVATE_LEDGER" ]; then
                install -m 600 "$LEDGER_TEMPLATE" "$PRIVATE_LEDGER"
            fi
            LEDGER="$PRIVATE_LEDGER"
            ;;
        status|json)
            if [ -f "$PRIVATE_LEDGER" ]; then
                LEDGER="$PRIVATE_LEDGER"
            else
                LEDGER="$LEDGER_TEMPLATE"
            fi
            ;;
        *) LEDGER="$LEDGER_TEMPLATE" ;;
    esac
fi
TYPE_CATALOG="${ZCL_TRANSACTION_TYPE_CATALOG:-$REPO/engine/controllers/include/controllers/transaction_types.def}"
SUPPLEMENTAL_TESTS="${ZCL_TRANSACTION_LAB_SUPPLEMENTAL_TESTS:-$REPO/engine/controllers/include/controllers/transaction_type_supplemental_tests.def}"
LIVE_CATALOG="${ZCL_TRANSACTION_LIVE_CATALOG:-$REPO/tools/dev/transaction_live_catalog.def}"

die() {
    echo "transaction-lab: $*" >&2
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

proof_allowed() {
    case "$1" in
        builder_verified|interpreter_verified|projection_verified|\
        consensus_verified|simnet_confirmed|live_confirmed|\
        not_demonstrated) return 0 ;;
        *) return 1 ;;
    esac
}

bar() {
    local done="$1" total="$2" width=20 filled=0 empty=0
    [ "$total" -le 0 ] || filled=$((done * width / total))
    [ "$filled" -le "$width" ] || filled="$width"
    empty=$((width - filled))
    printf '%*s' "$filled" '' | tr ' ' '#'
    printf '%*s' "$empty" '' | tr ' ' '-'
}

catalog_count() {
    awk -F'|' '!/^#/ && NF { n++ } END { print n + 0 }' "$CATALOG"
}

stats() {
    awk -F'"' '
        /"schema":"zcl.transaction_lab_event.v(1|2)"/ {
            id=$12; network[id]=$16; proof[id]=$20; result[id]=$24
            line=$0
            sub(/^.*"recipient_zat":/, "", line); sub(/,.*/, "", line)
            recipient[id]=line + 0
            line=$0
            sub(/^.*"fee_zat":/, "", line); sub(/}.*/, "", line)
            fee[id]=line + 0
        }
        END {
            for (id in result) {
                seen++
                if (result[id] == "PASS") passed++
                else if (result[id] == "FAIL") failed++
                else if (result[id] == "BLOCKED") blocked++
                if (result[id] == "PASS" &&
                    (proof[id] == "simnet_confirmed" ||
                     proof[id] == "live_confirmed")) chain++
                if (result[id] == "PASS" && proof[id] == "live_confirmed" &&
                    network[id] == "mainnet") {
                    live++
                    live_recipient += recipient[id]
                    live_fee += fee[id]
                }
            }
            printf "%d %d %d %d %d %d %.0f %.0f\n", seen, passed, failed,
                   blocked, chain, live, live_recipient, live_fee
        }
    ' "$LEDGER"
}

live_catalog_stats() {
    awk -F'|' '
        !/^#/ && NF {
            total++
            if ($2 == "mainnet_ready") ready++
            else if ($2 == "process_reference") process++
            else if ($2 == "contained") contained++
            else if ($2 == "isolated_only") isolated++
        }
        END { printf "%d %d %d %d %d\n", total, ready, process, contained, isolated }
    ' "$LIVE_CATALOG"
}

check_notebook() {
    local declared_contracts lab_contracts declared_live live_contracts
    awk -F'|' '
        function bad(msg) { print "transaction-lab-check: " msg > "/dev/stderr"; errors++ }
        NR == FNR {
            if ($0 ~ /^#/ || NF == 0) next
            if (NF != 5) { bad("catalog line " FNR " must have five fields"); next }
            if ($1 !~ /^[a-z0-9_]+$/) bad("invalid case_id at catalog line " FNR)
            if (known[$1]++) bad("duplicate case_id " $1)
            if ($4 !~ /^(builder_verified|interpreter_verified|projection_verified|consensus_verified|simnet_confirmed|live_confirmed|not_demonstrated)$/)
                bad("invalid minimum proof for " $1)
            if ($5 !~ /^test_[a-z0-9_]+$/) bad("invalid test group for " $1)
            catalog[$1]=1
            next
        }
        {
            line=$0
            if (line ~ /"(address|endpoint|datadir|grant_token|private_key|recovery_words|memo|secret)"/)
                bad("sensitive field name at ledger line " FNR)
            n=split(line, a, "\"")
            schema=a[4]
            if (n < 37 || schema !~ /^zcl.transaction_lab_event.v(1|2)$/) {
                bad("invalid event schema or field order at ledger line " FNR)
                next
            }
            id=a[12]; network=a[16]; proof=a[20]; result=a[24]
            source=a[28]; commit=a[32]; txid=a[36]
            if (!(id in catalog)) bad("unknown case_id " id)
            seen[id]=1
            if (network !~ /^(isolated|simnet|mainnet)$/) bad("invalid network for " id)
            if (proof !~ /^(builder_verified|interpreter_verified|projection_verified|consensus_verified|simnet_confirmed|live_confirmed|not_demonstrated)$/)
                bad("invalid proof for " id)
            if (result !~ /^(PASS|FAIL|BLOCKED)$/) bad("invalid result for " id)
            if (proof == "not_demonstrated" && result != "BLOCKED")
                bad("not_demonstrated evidence must be BLOCKED for " id)
            if (source !~ /^[A-Za-z0-9_.:-]+$/) bad("invalid source for " id)
            if (commit !~ /^[0-9a-f]{8,64}$/) bad("invalid source commit for " id)
            if (txid != "UNAVAILABLE" && txid !~ /^[0-9a-f]{64}$/)
                bad("invalid txid for " id)
            if (network == "mainnet" && proof == "live_confirmed" &&
                txid == "UNAVAILABLE") bad("live confirmation lacks txid for " id)
            if (network == "mainnet" && proof == "live_confirmed" &&
                schema != "zcl.transaction_lab_event.v2")
                bad("live confirmation requires v2 block identity for " id)
            amount=line
            sub(/^.*"recipient_zat":/, "", amount); sub(/,.*/, "", amount)
            cost=line
            sub(/^.*"fee_zat":/, "", cost); sub(/,.*/, "", cost); sub(/}.*/, "", cost)
            if (amount !~ /^[0-9]+$/ || cost !~ /^[0-9]+$/)
                bad("non-integer money field for " id)
            if (schema == "zcl.transaction_lab_event.v2") {
                height=line
                sub(/^.*"block_height":/, "", height); sub(/,.*/, "", height)
                block_hash=line
                sub(/^.*"block_hash":"/, "", block_hash); sub(/".*/, "", block_hash)
                if (height !~ /^[0-9]+$/)
                    bad("invalid block height for " id)
                if (block_hash != "UNAVAILABLE" &&
                    block_hash !~ /^[0-9a-f]{64}$/)
                    bad("invalid block hash for " id)
                if (network == "mainnet" && proof == "live_confirmed" &&
                    block_hash == "UNAVAILABLE")
                    bad("live confirmation lacks block hash for " id)
            }
        }
        END {
            for (id in catalog) if (!(id in seen)) bad("missing evidence for " id)
            if (errors) exit 1
        }
    ' "$CATALOG" "$LEDGER"
    declared_contracts="$(awk '
        !active && /^TX_TYPE\(/ { record=$0; active=1; next }
        active { record=record " " $0 }
        active && /\)$/ {
            n=split(record, quoted, "\"")
            if (n >= 31)
                print quoted[2] "|" quoted[28] "|" quoted[30]
            record=""; active=0
        }
    ' "$TYPE_CATALOG" | sort)"
    lab_contracts="$(awk -F'|' '!/^#/ && NF {
        print $1 "|" $4 "|" $5
    }' "$CATALOG" | sort)"
    if [ "$declared_contracts" != "$lab_contracts" ]; then
        echo "transaction-lab-check: ids, proofs, or test groups differ from the transaction type catalog" >&2
        diff -u <(printf '%s\n' "$declared_contracts") \
                <(printf '%s\n' "$lab_contracts") >&2 || true
        return 1
    fi
    declared_live="$(awk '
        !active && /^TX_TYPE\(/ { record=$0; active=1; next }
        active { record=record " " $0 }
        active && /\)$/ {
            n=split(record, quoted, "\"")
            id=quoted[2]; availability=quoted[6]; network=quoted[24]
            if (availability == "ready") posture="mainnet_ready"
            else if (availability == "process_only") posture="process_reference"
            else if (availability == "contained" && network == "isolated_non_mainnet_only") posture="isolated_only"
            else if (availability == "contained") posture="contained"
            else posture="INVALID"
            print id "|" posture
            record=""; active=0
        }
    ' "$TYPE_CATALOG" | sort)"
    live_contracts="$(awk -F'|' '
        function bad(msg) {
            print "transaction-lab-check: " msg > "/dev/stderr"
            errors++
        }
        !/^#/ && NF {
            if (NF != 4) { bad("live catalog line " FNR " must have four fields"); next }
            if ($1 !~ /^[a-z0-9_]+$/) bad("invalid live case_id at line " FNR)
            if ($2 !~ /^(mainnet_ready|process_reference|contained|isolated_only)$/)
                bad("invalid live posture for " $1)
            if ($3 !~ /^[a-z0-9_]+$/) bad("invalid live prerequisite for " $1)
            if ($4 !~ /^[a-z0-9_]+$/) bad("invalid live campaign for " $1)
            if (seen[$1]++) bad("duplicate live case_id " $1)
            print $1 "|" $2
        }
        END { if (errors) exit 1 }
    ' "$LIVE_CATALOG" | sort)" || return 1
    if [ "$declared_live" != "$live_contracts" ]; then
        echo "transaction-lab-check: live postures differ from the transaction type catalog" >&2
        diff -u <(printf '%s\n' "$declared_live") \
                <(printf '%s\n' "$live_contracts") >&2 || true
        return 1
    fi
    awk '
        function bad(msg) {
            print "transaction-lab-check: " msg > "/dev/stderr"
            errors++
        }
        NR == FNR {
            if ($0 !~ /^#/ && NF) {
                split($0, catalog_fields, "|")
                cases[catalog_fields[1]]=1
            }
            next
        }
        /^TX_TYPE_SUPPLEMENTAL/ {
            split($0, quoted, "\"")
            id=quoted[2]; group_csv=quoted[4]
            if (id !~ /^[a-z0-9_]+$/)
                bad("invalid supplemental case id " id)
            if (!(id in cases))
                bad("supplemental test names unknown case " id)
            if (supplemental_ids[id]++)
                bad("duplicate supplemental test row for " id)
            group_count=split(group_csv, groups, ",")
            for (i=1; i <= group_count; i++) {
                if (groups[i] !~ /^test_[a-z0-9_]+$/)
                    bad("invalid supplemental test group " groups[i])
            }
        }
        END { if (errors) exit 1 }
    ' "$CATALOG" "$SUPPLEMENTAL_TESTS"
    echo "transaction-lab-check: PASS"
}

print_status() {
    local total seen passed failed blocked chain live live_recipient live_fee
    local live_total live_ready live_process live_contained live_isolated
    total="$(catalog_count)"
    read -r seen passed failed blocked chain live live_recipient live_fee < <(stats)
    printf 'transaction-lab proof:   [%s] %d/%d cases latest=PASS\n' \
        "$(bar "$passed" "$total")" "$passed" "$total"
    printf 'transaction-lab chain:   [%s] %d/%d simulated/live confirmations\n' \
        "$(bar "$chain" "$total")" "$chain" "$total"
    printf 'transaction-lab mainnet: [%s] %d/%d live confirmations\n' \
        "$(bar "$live" "$total")" "$live" "$total"
    read -r live_total live_ready live_process live_contained live_isolated \
        < <(live_catalog_stats)
    printf 'transaction-lab eligible: [%s] %d/%d mainnet-broadcast-capable\n' \
        "$(bar "$live_ready" "$live_total")" "$live_ready" "$live_total"
    printf '  process_reference=%d contained=%d isolated_only=%d\n' \
        "$live_process" "$live_contained" "$live_isolated"
    printf '  latest_events=%d failures=%d blocked=%d\n' "$seen" "$failed" "$blocked"
    printf '  live_recipient_zat=%s live_fee_zat=%s live_total_zat=%s\n' \
        "$live_recipient" "$live_fee" "$((live_recipient + live_fee))"
    printf '  mainnet_gate=EXTERNAL_REQUIRED next=evaluate HANDOFF and identity-bound custody gates\n'
}

print_json() {
    local total seen passed failed blocked chain live live_recipient live_fee
    local live_total live_ready live_process live_contained live_isolated
    total="$(catalog_count)"
    read -r seen passed failed blocked chain live live_recipient live_fee < <(stats)
    printf '{"schema":"zcl.transaction_lab_stats.v1","cases_total":%d,' "$total"
    printf '"latest_events":%d,"passed":%d,"failed":%d,"blocked":%d,' \
        "$seen" "$passed" "$failed" "$blocked"
    printf '"chain_confirmed":%d,"mainnet_confirmed":%d,' "$chain" "$live"
    read -r live_total live_ready live_process live_contained live_isolated \
        < <(live_catalog_stats)
    printf '"mainnet_eligibility":{"total":%d,"broadcast_ready":%d,"process_reference":%d,"contained":%d,"isolated_only":%d},' \
        "$live_total" "$live_ready" "$live_process" "$live_contained" "$live_isolated"
    printf '"live_recipient_zat":%s,"live_fee_zat":%s,"live_total_zat":%s,' \
        "$live_recipient" "$live_fee" "$((live_recipient + live_fee))"
    printf '"mainnet_gate":"EXTERNAL_REQUIRED"}\n'
}

record_event() {
    local case_id='' network='' proof='' result='' source=''
    local txid='UNAVAILABLE' recipient_zat=0 fee_zat=0
    local block_height='' block_hash='' arg observed commit
    shift
    assert_record_ledger_private
    for arg in "$@"; do
        case "$arg" in
            --case=*) case_id="${arg#*=}" ;;
            --network=*) network="${arg#*=}" ;;
            --proof=*) proof="${arg#*=}" ;;
            --result=*) result="${arg#*=}" ;;
            --source=*) source="${arg#*=}" ;;
            --txid=*) txid="${arg#*=}" ;;
            --recipient-zat=*) recipient_zat="${arg#*=}" ;;
            --fee-zat=*) fee_zat="${arg#*=}" ;;
            --block-height=*) block_height="${arg#*=}" ;;
            --block-hash=*) block_hash="${arg#*=}" ;;
            *) die "unknown record argument: $arg" ;;
        esac
    done
    [ -n "$case_id" ] &&
        awk -F'|' -v id="$case_id" '$1 == id { found=1 } END { exit !found }' "$CATALOG" ||
        die "record requires a known --case"
    case "$network" in isolated|simnet|mainnet) ;; *) die "invalid --network" ;; esac
    proof_allowed "$proof" || die "invalid --proof"
    case "$result" in PASS|FAIL|BLOCKED) ;; *) die "invalid --result" ;; esac
    if [ "$proof" = not_demonstrated ] && [ "$result" != BLOCKED ]; then
        die "not_demonstrated evidence must be BLOCKED"
    fi
    [[ "$source" =~ ^[A-Za-z0-9_.:-]+$ ]] || die "invalid --source"
    [[ "$txid" == UNAVAILABLE || "$txid" =~ ^[0-9a-f]{64}$ ]] || die "invalid --txid"
    [[ "$recipient_zat" =~ ^[0-9]+$ ]] || die "invalid --recipient-zat"
    [[ "$fee_zat" =~ ^[0-9]+$ ]] || die "invalid --fee-zat"
    if [ -n "$block_height" ] || [ -n "$block_hash" ]; then
        [[ "$block_height" =~ ^[0-9]+$ ]] || die "invalid --block-height"
        [[ "$block_hash" =~ ^[0-9a-f]{64}$ ]] || die "invalid --block-hash"
    fi
    if [ "$network" = mainnet ] && [ "$proof" = live_confirmed ] &&
       [ "$txid" = UNAVAILABLE ]; then
        die "live_confirmed mainnet evidence requires a public txid"
    fi
    if [ "$network" = mainnet ] && [ "$proof" = live_confirmed ] &&
       { [ -z "$block_height" ] || [ -z "$block_hash" ]; }; then
        die "live_confirmed mainnet evidence requires block height and hash"
    fi
    observed="$(date -u +%FT%TZ)"
    commit="$(git -C "$REPO" rev-parse --short=8 HEAD)"
    exec 9>>"$LEDGER"
    flock 9
    if [ -n "$block_height" ]; then
        printf '{"schema":"zcl.transaction_lab_event.v2","observed_at":"%s","case_id":"%s","network":"%s","proof":"%s","result":"%s","source":"%s","source_commit":"%s","txid":"%s","recipient_zat":%s,"fee_zat":%s,"block_height":%s,"block_hash":"%s"}\n' \
            "$observed" "$case_id" "$network" "$proof" "$result" "$source" \
            "$commit" "$txid" "$recipient_zat" "$fee_zat" \
            "$block_height" "$block_hash" >&9
    else
        printf '{"schema":"zcl.transaction_lab_event.v1","observed_at":"%s","case_id":"%s","network":"%s","proof":"%s","result":"%s","source":"%s","source_commit":"%s","txid":"%s","recipient_zat":%s,"fee_zat":%s}\n' \
            "$observed" "$case_id" "$network" "$proof" "$result" "$source" \
            "$commit" "$txid" "$recipient_zat" "$fee_zat" >&9
    fi
    flock -u 9
    check_notebook
}

selftest() {
    local fixture fixture_ledger fixture_type_catalog fixture_supplemental
    local fixture_live_catalog body
    fixture="$(mktemp -d)"
    fixture_ledger="$fixture/events.jsonl"
    fixture_type_catalog="$fixture/transaction_types.def"
    fixture_supplemental="$fixture/transaction_type_supplemental_tests.def"
    fixture_live_catalog="$fixture/transaction_live_catalog.def"
    cleanup_transaction_lab_selftest() {
        [ ! -d "$fixture" ] || rm -r -- "$fixture"
    }
    trap cleanup_transaction_lab_selftest RETURN
    if (LEDGER="$REPO/docs/work/forbidden-live-lab-selftest.jsonl";
        assert_record_ledger_private) >/dev/null 2>&1; then
        die "selftest accepted a record ledger inside the repository"
    fi
    cp "$LEDGER" "$fixture_ledger"
    chmod 600 "$fixture_ledger"
    chmod 644 "$fixture_ledger"
    if (LEDGER="$fixture_ledger"; assert_record_ledger_private) \
            >/dev/null 2>&1; then
        die "selftest accepted a non-private record ledger"
    fi
    chmod 600 "$fixture_ledger"
    ZCL_TRANSACTION_LAB_CATALOG="$CATALOG" \
    ZCL_TRANSACTION_LAB_LEDGER="$fixture_ledger" \
        "$0" record --case=transparent_t_to_t --network=mainnet \
        --proof=live_confirmed --result=PASS --source=selftest_receipt \
        --txid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        --recipient-zat=1000 --fee-zat=100 --block-height=123456 \
        --block-hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
        >/dev/null
    body="$(ZCL_TRANSACTION_LAB_CATALOG="$CATALOG" \
        ZCL_TRANSACTION_LAB_LEDGER="$fixture_ledger" "$0" json)"
    if [[ "$body" != *'"mainnet_confirmed":1'* ]] ||
       [[ "$body" != *'"live_recipient_zat":1000'* ]] ||
       [[ "$body" != *'"live_fee_zat":100'* ]] ||
       [[ "$body" != *'"live_total_zat":1100'* ]] ||
       [[ "$body" != *'"mainnet_gate":"EXTERNAL_REQUIRED"'* ]]; then
        die "selftest stats did not include the fixture mainnet receipt"
    fi
    if ZCL_TRANSACTION_LAB_CATALOG="$CATALOG" \
       ZCL_TRANSACTION_LAB_LEDGER="$fixture_ledger" \
        "$0" record --case=transparent_t_to_t --network=mainnet \
        --proof=live_confirmed --result=PASS --source=selftest_invalid \
        --txid=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
        --recipient-zat=1 --fee-zat=1 >/dev/null 2>&1; then
        die "selftest accepted a live receipt without block identity"
    fi
    if ZCL_TRANSACTION_LAB_CATALOG="$CATALOG" \
       ZCL_TRANSACTION_LAB_LEDGER="$fixture_ledger" \
        "$0" record --case=market_purchase --network=isolated \
        --proof=not_demonstrated --result=PASS --source=selftest_invalid \
        >/dev/null 2>&1; then
        die "selftest accepted not_demonstrated evidence as PASS"
    fi
    sed '0,/"simnet_confirmed"/s//"builder_verified"/' \
        "$TYPE_CATALOG" > "$fixture_type_catalog"
    if ZCL_TRANSACTION_LAB_CATALOG="$CATALOG" \
       ZCL_TRANSACTION_LAB_LEDGER="$fixture_ledger" \
       ZCL_TRANSACTION_TYPE_CATALOG="$fixture_type_catalog" \
        "$0" check >/dev/null 2>&1; then
        die "selftest accepted proof drift between the API and lab catalogs"
    fi
    cp "$SUPPLEMENTAL_TESTS" "$fixture_supplemental"
    printf '%s\n' \
        'TX_TYPE_SUPPLEMENTAL("htlc_redeem", "test_duplicate_fixture")' \
        >> "$fixture_supplemental"
    if ZCL_TRANSACTION_LAB_CATALOG="$CATALOG" \
       ZCL_TRANSACTION_LAB_LEDGER="$fixture_ledger" \
       ZCL_TRANSACTION_LAB_SUPPLEMENTAL_TESTS="$fixture_supplemental" \
        "$0" check >/dev/null 2>&1; then
        die "selftest accepted duplicate supplemental proof rows"
    fi
    sed '0,/|mainnet_ready|/s//|contained|/' \
        "$LIVE_CATALOG" > "$fixture_live_catalog"
    if ZCL_TRANSACTION_LAB_CATALOG="$CATALOG" \
       ZCL_TRANSACTION_LAB_LEDGER="$fixture_ledger" \
       ZCL_TRANSACTION_LIVE_CATALOG="$fixture_live_catalog" \
        "$0" check >/dev/null 2>&1; then
        die "selftest accepted live posture drift from the API catalog"
    fi
    echo "transaction-lab selftest: PASS"
}

case "${1:-status}" in
    status) check_notebook >/dev/null; print_status ;;
    json) check_notebook >/dev/null; print_json ;;
    check) check_notebook ;;
    record) record_event "$@" ;;
    selftest) selftest ;;
    -h|--help)
        echo "usage: tools/dev/transaction-lab.sh {status|json|check|selftest|record ...}"
        ;;
    *) die "unknown action: $1" ;;
esac
