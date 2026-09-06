#!/usr/bin/env bash
# Hermetic contract test for the native dev-loop wait surface.  It uses a
# private HOME and a correctly workspace-bound SHA3-sealed verdict; it starts
# no watcher, contacts no node, and has no runtime-publication path.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${ZCL_DEV_LOOP_TEST_BIN:-$ROOT/build/bin/zclassic23-dev}"

if [[ ! -x "$BIN" ]]; then
    echo "native-dev-loop-wait-selftest: missing dev binary: $BIN" >&2
    exit 2
fi

SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/zcl-native-loop-wait.XXXXXX")"
trap 'rm -rf "$SANDBOX"' EXIT HUP INT TERM
umask 077

# Status is an observation through the real dev-only command catalog.  Give
# both lock locations existing parents so the former O_CREAT read path would
# be visible, while keeping every byte in this fixture's private state.
STATUS_REPO="$SANDBOX/status-repo"
STATUS_XDG="$SANDBOX/xdg-state"
WORK_LOCK="$STATUS_REPO/.cache/zcl-dev-watch.lock"
LEGACY_LOCK="$SANDBOX/.local/state/zclassic23-dev/native-watch.lock"
mkdir -p "$STATUS_REPO/.cache" "$(dirname "$LEGACY_LOCK")" "$STATUS_XDG"
set +e
STATUS_OUT="$(HOME="$SANDBOX" XDG_STATE_HOME="$STATUS_XDG" \
    ZCL_DEV_SOURCE_ROOT="$STATUS_REPO" \
    "$BIN" dev loop status --view=summary 2>&1)"
STATUS_RC=$?
set -e
[[ "$STATUS_RC" -eq 0 && "$STATUS_OUT" == *'"active":false'* ]] || {
    echo "native-dev-loop-wait-selftest: inactive status failed" >&2
    exit 1
}
[[ ! -e "$WORK_LOCK" && ! -e "$LEGACY_LOCK" ]] || {
    echo "native-dev-loop-wait-selftest: status created a watcher lock" >&2
    exit 1
}

WORKSPACE="$(
    printf 'domain\0zcl.dev_workspace.v1\0canonical_root\0%s\0' "$ROOT" |
        openssl dgst -sha3-256 | awk '{print $NF}'
)"
CYCLE='{"schema":"zcl.dev_cycle.v1","producer":"selftest","status":"passed","action":"check","reason":"contract_fixture","phase":"verified","runtime_published":false,"elapsed_ms":1,"files":["fixture.c"]}'
EPOCH_VALUE=1
DIGEST="$(
    printf 'domain\0zcl.dev_cycle_record.v1\0workspace_id\0%s\0epoch\0%s\0cycle_json\0%s\0' \
        "$WORKSPACE" "$EPOCH_VALUE" "$CYCLE" |
        openssl dgst -sha3-256 | awk '{print $NF}'
)"
STATE="$SANDBOX/.local/state/zclassic23-dev/workspaces/$WORKSPACE"
mkdir -p "$STATE"
: >"$STATE/cycle-state.lock"
printf '{"schema":"zcl.dev_cycle_record.v1","workspace_id":"%s","epoch":%s,"cycle":%s,"cycle_sha3":"%s"}\n' \
    "$WORKSPACE" "$EPOCH_VALUE" "$CYCLE" "$DIGEST" \
    >"$STATE/native-cycle.json"

OUT="$(HOME="$SANDBOX" ZCL_DEV_SOURCE_ROOT="$ROOT" "$BIN" dev loop wait \
    --input='{"after_epoch":0,"timeout_ms":100}' --view=summary)"

[[ "$OUT" == *'"data_schema":"zcl.dev_cycle.v1"'* ]] || {
    echo "native-dev-loop-wait-selftest: declared data schema drifted" >&2
    exit 1
}
[[ "$OUT" == *'"data":{"schema":"zcl.dev_cycle.v1"'* ]] || {
    echo "native-dev-loop-wait-selftest: verdict is not the direct data object" >&2
    exit 1
}
[[ "$OUT" == *'"reason":"contract_fixture"'* ]] || {
    echo "native-dev-loop-wait-selftest: durable verdict was not returned" >&2
    exit 1
}
[[ "$OUT" == *'"epoch":'* ]] || {
    echo "native-dev-loop-wait-selftest: chaining epoch is missing" >&2
    exit 1
}
[[ "$OUT" != *'"latest_verdict"'* && "$OUT" != *'zcl.dev_loop_status.v1'* ]] || {
    echo "native-dev-loop-wait-selftest: wait leaked the loop-status wrapper" >&2
    exit 1
}
[[ "$OUT" == *'"runtime_published":false'* ]] || {
    echo "native-dev-loop-wait-selftest: fixture lost publication containment" >&2
    exit 1
}

EPOCH="$(sed -n 's/.*"epoch":\([0-9][0-9]*\).*/\1/p' <<<"$OUT")"
[[ -n "$EPOCH" ]] || {
    echo "native-dev-loop-wait-selftest: chaining epoch is not an integer" >&2
    exit 1
}
set +e
TIMEOUT_OUT="$(HOME="$SANDBOX" ZCL_DEV_SOURCE_ROOT="$ROOT" \
    "$BIN" dev loop wait \
    --input="{\"after_epoch\":$EPOCH,\"timeout_ms\":25}" 2>&1)"
TIMEOUT_RC=$?
set -e
[[ "$TIMEOUT_RC" -eq 3 && "$TIMEOUT_OUT" == *'"code":"WAIT_TIMEOUT"'* ]] || {
    echo "native-dev-loop-wait-selftest: returned epoch did not chain to a bounded wait" >&2
    exit 1
}
[[ "$TIMEOUT_OUT" == *"current_epoch=$EPOCH"* ]] || {
    echo "native-dev-loop-wait-selftest: timeout recovery lost the current epoch" >&2
    exit 1
}
[[ "$TIMEOUT_OUT" == *'"next":[{"command":"dev.loop.status"'* &&
    "$TIMEOUT_OUT" != *'"next":[{"command":"dev.loop.wait"'* ]] || {
    echo "native-dev-loop-wait-selftest: timeout emitted an invalid self-loop" >&2
    exit 1
}

echo "native-dev-loop-wait-selftest: PASS"
