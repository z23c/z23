#!/usr/bin/env bash
# Read-only custody rollout doctor.
#
# Summarizes source support, dev activation, canonical lane targeting, private
# broker binding presence, and the identity-bound money snapshot. It never
# creates a broker directory, migrates a wallet, restarts a service, or moves
# funds. Endpoint and datadir values are used only for local probes and are
# deliberately absent from output.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
# shellcheck source=tools/dev/dev_lib.sh
. "$REPO/tools/dev/dev_lib.sh"  # json_escape
# shellcheck source=tools/scripts/sh_str.sh
. "$REPO/tools/scripts/sh_str.sh"  # str_contains

JSON=0
# Match custody-bind's owner-private default so the memorable read command
# inspects the binding that the memorable setup command creates.
BROKER_DIR="${ZCL_CUSTODY_BROKER_DIR:-$HOME/.local/state/zclassic23-custody-broker}"
WALLET_SCOPE="portfolio"
while [ $# -gt 0 ]; do
    case "$1" in
        --json) JSON=1 ;;
        --broker-dir=*) BROKER_DIR="${1#*=}" ;;
        --wallet-scope=dev|--wallet-scope=prod)
            WALLET_SCOPE="${1#*=}"
            ;;
        --wallet-scope=*)
            echo "custody-status: --wallet-scope must be dev or prod" >&2
            exit 2
            ;;
        -h|--help)
            cat <<'USAGE'
usage: tools/dev/custody-status.sh [--json] [--broker-dir=ABSOLUTE_DIR] [--wallet-scope=dev|prod]

Read-only rollout status for dev/prod custody. A broker directory may also be
provided through ZCL_CUSTODY_BROKER_DIR. Missing, stale, conflicting, or
unreachable wallets remain UNKNOWN; this command never creates or fixes state.
Without --wallet-scope, readiness means the complete two-wallet portfolio is
current. With an explicit scope, readiness applies only to that target wallet;
the independent portfolio status remains visible and is never inferred.
USAGE
            exit 0
            ;;
        *)
            echo "custody-status: unknown argument '$1'" >&2
            exit 2
            ;;
    esac
    shift
done

BIN="${ZCL_CUSTODY_BIN:-build/bin/zclassic23-dev}"
DEV_DATADIR="${ZCL_CUSTODY_DEV_DATADIR:-$HOME/.zclassic-c23-dev}"
PROD_DATADIR="${ZCL_CUSTODY_PROD_DATADIR:-$HOME/.zclassic-c23}"
DEV_RPCPORT="${ZCL_CUSTODY_DEV_RPCPORT:-18252}"
PROD_RPCPORT="${ZCL_CUSTODY_PROD_RPCPORT:-18232}"
FIXTURE="${ZCL_CUSTODY_FIXTURE:-}"
if [ "${ZCL_CUSTODY_STATUS_SELFTEST:-0}" = 1 ]; then
    # The outer self-test invocation must itself remain hermetic; it reaches
    # the live probes only through the two explicit recursive fixture cases.
    FIXTURE=ready
fi

json_string_field() {
    local body="$1" key="$2"
    printf '%s\n' "$body" |
        sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" |
        head -1
}

json_bool_field() {
    local body="$1" key="$2" value
    value="$(printf '%s\n' "$body" |
        grep -o "\"$key\"[[:space:]]*:[[:space:]]*\\(true\\|false\\)" 2>/dev/null |
        head -1 || true)"
    case "$value" in
        *true) printf 'true' ;;
        *) printf 'false' ;;
    esac
}

fixture_probe() {
    local probe="$1"
    case "$probe:$FIXTURE" in
        schema:*)
            printf '{"path":"metaverse.agent.money"}\n'
            ;;
        dev_status:ready|dev_status:dev-ready)
            printf '%s\n' '{"installed_matches_source":true,"deploy_blocker":false,"next_action":"activate --input={\"id\":\"exact\"}"}'
            ;;
        dev_status:stale-dev)
            printf '%s\n' '{"installed_matches_source":false,"deploy_blocker":false,"next_action":"activate --input={\"id\":\"exact\"}"}'
            ;;
        dev_status:*)
            printf '{"installed_matches_source":false,"deploy_blocker":false}\n'
            ;;
        canonical:ready)
            printf '%s\n' "argv[]=zclassic23 -datadir=$PROD_DATADIR -operator-lane=canonical"
            ;;
        canonical:*)
            printf 'argv[]=zclassic23 -datadir=/private/benchmark -operator-lane=canonical\n'
            ;;
        dev_balance:*)
            printf '{"ok":true,"data":{"total":"0.30000000"}}\n'
            ;;
        prod_balance:ready)
            printf '{"ok":true,"data":{"total":"0.00000000"}}\n'
            ;;
        prod_balance:*)
            return 1
            ;;
        money:ready)
            printf '{"ok":true,"data":{"wallets":[{"wallet_scope":"dev","status":"CURRENT"},{"wallet_scope":"prod","status":"CURRENT"}],"portfolio_total_known":true,"portfolio_confirmed_zcl":"0.30000000"}}\n'
            ;;
        money:dev-ready)
            printf '{"ok":true,"data":{"wallets":[{"wallet_scope":"dev","status":"CURRENT"},{"wallet_scope":"prod","status":"UNKNOWN"}],"portfolio_total_known":false}}\n'
            ;;
        money:*)
            return 1
            ;;
        *) return 1 ;;
    esac
}

probe() {
    local kind="$1"
    if [ -n "$FIXTURE" ]; then
        fixture_probe "$kind"
        return
    fi
    case "$kind" in
        schema)
            "$BIN" discover schema metaverse.agent.money 2>/dev/null
            ;;
        dev_status)
            "$BIN" agentdevstatus 2>/dev/null
            ;;
        canonical)
            systemctl --user show z23-node -p ExecStart --value 2>/dev/null
            ;;
        dev_balance)
            "$BIN" -datadir="$DEV_DATADIR" -rpcport="$DEV_RPCPORT" \
                core wallet balance 2>/dev/null
            ;;
        prod_balance)
            "$BIN" -datadir="$PROD_DATADIR" -rpcport="$PROD_RPCPORT" \
                core wallet balance 2>/dev/null
            ;;
        money)
            "$BIN" metaverse agent money --dir="$BROKER_DIR" 2>/dev/null
            ;;
        *) return 2 ;;
    esac
}

broker_state="absent"
if [ -n "$FIXTURE" ]; then
    case "$FIXTURE" in ready|dev-ready) broker_state="present" ;; esac
elif [ -n "$BROKER_DIR" ] && [ -d "$BROKER_DIR" ]; then
    [ -f "$BROKER_DIR/money-bindings.json" ] && broker_state="present"
fi

# All probes are independent and read-only. Run them together so an
# unreachable dev and an unreachable prod cost one deadline, not two or three
# serial deadlines. The mode-0700 temporary directory contains local probe
# output only and is removed on every exit; none of it is copied to the public
# status document.
PROBE_TMP="$(mktemp -d)"
cleanup_probe_tmp() {
    [ ! -d "$PROBE_TMP" ] || rm -r -- "$PROBE_TMP"
}
trap cleanup_probe_tmp EXIT HUP INT TERM
probe_pids=""
start_probe() {
    local kind="$1"
    (
        if probe "$kind" >"$PROBE_TMP/$kind"; then
            : >"$PROBE_TMP/$kind.ok"
        fi
    ) &
    probe_pids="$probe_pids $!"
}
probe_kinds="schema dev_status"
case "$WALLET_SCOPE" in
    dev) probe_kinds="$probe_kinds dev_balance" ;;
    prod) probe_kinds="$probe_kinds canonical prod_balance" ;;
    portfolio) probe_kinds="$probe_kinds canonical dev_balance prod_balance" ;;
esac
for probe_kind in $probe_kinds; do
    start_probe "$probe_kind"
done
[ "$broker_state" = present ] && start_probe money
for probe_pid in $probe_pids; do
    wait "$probe_pid" || true
done

probe_output() {
    local kind="$1"
    [ -f "$PROBE_TMP/$kind.ok" ] && cat "$PROBE_TMP/$kind" || true
}

source_ready=false
source_body="$(probe_output schema)"
if [ -x "$BIN" ] &&
   str_contains "$source_body" '"path":"metaverse.agent.money"'; then
    source_ready=true
fi

dev_current=false
dev_body="$(probe_output dev_status)"
dev_next_action=""
if command -v jq >/dev/null 2>&1; then
    dev_next_action="$(printf '%s\n' "$dev_body" |
        jq -r '.next_action // empty' 2>/dev/null || true)"
fi
if [ "$(json_bool_field "$dev_body" installed_matches_source)" = true ] &&
   [ "$(json_bool_field "$dev_body" deploy_blocker)" = false ]; then
    dev_current=true
fi

canonical_target="not_required"
canonical_body="$(probe_output canonical)"
if [ "$WALLET_SCOPE" != dev ]; then
    canonical_target="unknown"
fi
if [ "$WALLET_SCOPE" != dev ] && [ -n "$canonical_body" ]; then
    # Compare the complete argv token. A benchmark path such as
    # ~/.zclassic-c23-cold-bench-* deliberately must not match the assigned
    # ~/.zclassic-c23 production wallet by prefix.
    canonical_datadir_token="$(printf '%s' "$canonical_body" | tr ' ' '\n' |
        sed -n '/^-datadir=/p' | head -1)"
    if [ "$canonical_datadir_token" = "-datadir=$PROD_DATADIR" ]; then
        canonical_target="expected_prod"
    else
        canonical_target="mismatch"
    fi
fi

balance_status() {
    local kind="$1" body
    body="$(probe_output "$kind")"
    if str_contains "$body" '"ok":true'; then
        printf 'OBSERVED|%s\n' "$(json_string_field "$body" total)"
    else
        printf 'UNKNOWN|UNKNOWN\n'
    fi
}

dev_balance_status="NOT_REQUESTED"
dev_balance="UNKNOWN"
prod_balance_status="NOT_REQUESTED"
prod_balance="UNKNOWN"
case "$WALLET_SCOPE" in
    dev)
        IFS='|' read -r dev_balance_status dev_balance < <(balance_status dev_balance)
        ;;
    prod)
        IFS='|' read -r prod_balance_status prod_balance < <(balance_status prod_balance)
        ;;
    portfolio)
        IFS='|' read -r dev_balance_status dev_balance < <(balance_status dev_balance)
        IFS='|' read -r prod_balance_status prod_balance < <(balance_status prod_balance)
        ;;
esac

money_status="UNKNOWN"
portfolio_known=false
portfolio_total="UNKNOWN"
current_wallets=0
dev_money_status="UNKNOWN"
prod_money_status="UNKNOWN"
if [ "$broker_state" = present ]; then
    money_body="$(probe_output money)"
    dev_money_status="$(printf '%s' "$money_body" |
        sed -n 's/.*"wallet_scope":"dev"[^}]*"status":"\([^"]*\)".*/\1/p' |
        head -1)"
    prod_money_status="$(printf '%s' "$money_body" |
        sed -n 's/.*"wallet_scope":"prod"[^}]*"status":"\([^"]*\)".*/\1/p' |
        head -1)"
    [ -n "$dev_money_status" ] || dev_money_status="UNKNOWN"
    [ -n "$prod_money_status" ] || prod_money_status="UNKNOWN"
    if [ "$(json_bool_field "$money_body" portfolio_total_known)" = true ]; then
        portfolio_known=true
        portfolio_total="$(json_string_field "$money_body" portfolio_confirmed_zcl)"
        current_wallets="$(printf '%s' "$money_body" |
            grep -o '"status":"CURRENT"' 2>/dev/null | wc -l | tr -d ' ')"
        [ "$current_wallets" = 2 ] && money_status="CURRENT"
    elif [ -n "$money_body" ]; then
        money_status="PARTIAL"
    fi
fi

target_money_status="$money_status"
case "$WALLET_SCOPE" in
    dev) target_money_status="$dev_money_status" ;;
    prod) target_money_status="$prod_money_status" ;;
esac

completed=0
total=5
[ "$source_ready" = true ] && completed=$((completed + 1))
[ "$dev_current" = true ] && completed=$((completed + 1))
if [ "$WALLET_SCOPE" = dev ]; then
    total=4
else
    [ "$canonical_target" = expected_prod ] && completed=$((completed + 1))
fi
[ "$broker_state" = present ] && completed=$((completed + 1))
[ "$target_money_status" = CURRENT ] && completed=$((completed + 1))

status="blocked"
[ "$completed" -eq "$total" ] && status="ready"

if [ "$source_ready" != true ]; then
    next_action="run make dev-bin"
elif [ "$dev_current" != true ]; then
    if [ -n "$dev_next_action" ]; then
        next_action="$dev_next_action"
    else
        next_action="owner-activate the current build on the dev lane"
    fi
elif [ "$WALLET_SCOPE" != dev ] && [ "$canonical_target" != expected_prod ]; then
    next_action="restore canonical to the assigned production datadir"
elif [ "$broker_state" != present ]; then
    next_action="create the owner custody binding for ${WALLET_SCOPE} after the requested wallet identity exists"
elif [ "$target_money_status" != CURRENT ]; then
    next_action="inspect the identity-bound ${WALLET_SCOPE} wallet reader; never substitute zero"
else
    next_action="custody rollout is current; no fund movement is required"
fi

emit_json() {
    printf '{'
    printf '"schema":"zcl.custody_rollout_status.v1",'
    printf '"status":"%s",' "$status"
    printf '"requested_wallet_scope":"%s",' "$WALLET_SCOPE"
    printf '"progress":{"completed":%d,"total":%d},' "$completed" "$total"
    printf '"source":{"ready":%s},' "$source_ready"
    printf '"dev_runtime":{"current":%s},' "$dev_current"
    printf '"canonical":{"target":"%s"},' "$canonical_target"
    printf '"broker":{"state":"%s"},' "$broker_state"
    printf '"money":{"status":"%s","target_status":"%s","dev_status":"%s","prod_status":"%s","portfolio_total_known":%s,"portfolio_confirmed_zcl":"%s","current_wallets":%d},' \
        "$money_status" "$target_money_status" "$dev_money_status" \
        "$prod_money_status" "$portfolio_known" \
        "$(json_escape "$portfolio_total")" "$current_wallets"
    printf '"observed_balances":{"dev":{"status":"%s","zcl":"%s"},"prod":{"status":"%s","zcl":"%s"}},' \
        "$dev_balance_status" "$(json_escape "$dev_balance")" \
        "$prod_balance_status" "$(json_escape "$prod_balance")"
    printf '"next_action":"%s"' "$(json_escape "$next_action")"
    printf '}\n'
}

emit_text() {
    local bar="" i
    for ((i = 0; i < total; i++)); do
        if [ "$i" -lt "$completed" ]; then bar+="#"; else bar+="-"; fi
    done
    printf 'custody-status: [%s] %d/%d status=%s scope=%s\n' \
        "$bar" "$completed" "$total" "$status" "$WALLET_SCOPE"
    printf '  source_support=%s dev_runtime_current=%s canonical_target=%s\n' \
        "$source_ready" "$dev_current" "$canonical_target"
    printf '  broker=%s money=%s target_money=%s dev=%s prod=%s portfolio=%s\n' \
        "$broker_state" "$money_status" "$target_money_status" \
        "$dev_money_status" "$prod_money_status" "$portfolio_total"
    printf '  dev_balance=%s (%s) prod_balance=%s (%s)\n' \
        "$dev_balance" "$dev_balance_status" \
        "$prod_balance" "$prod_balance_status"
    printf '  next=%s\n' "$next_action"
}

custody_status_selftest() {
    local ready dev_ready portfolio_partial blocked stale_dev combined
    ready="$(ZCL_CUSTODY_STATUS_SELFTEST=0 ZCL_CUSTODY_FIXTURE=ready \
        "$0" --json --broker-dir=/fixture)"
    blocked="$(ZCL_CUSTODY_STATUS_SELFTEST=0 ZCL_CUSTODY_FIXTURE=blocked \
        "$0" --json)"
    dev_ready="$(ZCL_CUSTODY_STATUS_SELFTEST=0 ZCL_CUSTODY_FIXTURE=dev-ready \
        "$0" --json --broker-dir=/fixture --wallet-scope=dev)"
    portfolio_partial="$(ZCL_CUSTODY_STATUS_SELFTEST=0 ZCL_CUSTODY_FIXTURE=dev-ready \
        "$0" --json --broker-dir=/fixture)"
    stale_dev="$(ZCL_CUSTODY_STATUS_SELFTEST=0 ZCL_CUSTODY_FIXTURE=stale-dev \
        "$0" --json --wallet-scope=dev)"
    str_contains "$ready" '"status":"ready"' || return 1
    str_contains "$ready" '"completed":5' || return 1
    str_contains "$ready" \
        '"portfolio_confirmed_zcl":"0.30000000"' || return 1
    str_contains "$blocked" '"status":"blocked"' || return 1
    str_contains "$blocked" \
        '"portfolio_confirmed_zcl":"UNKNOWN"' || return 1
    str_contains "$dev_ready" '"status":"ready"' || return 1
    str_contains "$dev_ready" '"completed":4,"total":4' || return 1
    str_contains "$dev_ready" '"requested_wallet_scope":"dev"' || return 1
    str_contains "$dev_ready" '"canonical":{"target":"not_required"}' || return 1
    str_contains "$dev_ready" '"target_status":"CURRENT"' || return 1
    str_contains "$dev_ready" '"prod":{"status":"NOT_REQUESTED"' || return 1
    str_contains "$dev_ready" '"portfolio_total_known":false' || return 1
    [ "$(printf '%s\n' "$dev_ready" | jq -r '.next_action')" = \
        'custody rollout is current; no fund movement is required' ] || return 1
    str_contains "$portfolio_partial" '"status":"blocked"' || return 1
    str_contains "$portfolio_partial" '"requested_wallet_scope":"portfolio"' || return 1
    [ "$(printf '%s\n' "$stale_dev" | jq -r '.next_action')" = \
        'activate --input={"id":"exact"}' ] || return 1
    combined="$ready$dev_ready$portfolio_partial$blocked$stale_dev"
    if str_contains "$combined" '/private/' ||
       str_contains "$combined" 'rpcport' ||
       str_contains "$combined" 'node_datadir'; then
        return 1
    fi
    echo "custody-status selftest: PASS"
}

if [ "${ZCL_CUSTODY_STATUS_SELFTEST:-0}" = 1 ]; then
    custody_status_selftest
elif [ "$JSON" -eq 1 ]; then
    emit_json
else
    emit_text
fi
