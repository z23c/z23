#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: physical, browser-free acceptance for the resident native C23 UI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# The host execs os_proc_exe_path(), which resolves the public binary alias.
NODE_BIN="$(readlink -f "$REPO_ROOT/build/bin/zclassic23")"
DRIVER_BIN="$REPO_ROOT/build/bin/native_ui_driver"
RUN_ROOT="$(mktemp -d /tmp/zcl23-native-ui-alpha.XXXXXX)"
RUNTIME_DIR="$RUN_ROOT/runtime"
LATENCIES="$RUN_ROOT/warm-total-us"
HANDOFFS="$RUN_ROOT/warm-handoff-us"
READY_TIMES="$RUN_ROOT/warm-worker-ready-us"
LOAD_HANDOFFS="$RUN_ROOT/load-handoff-us"
DISPLAY_NAME="${DISPLAY:-}"

fail() {
    echo "native-agent-ui-alpha: $*" >&2
    exit 1
}

host_pids() {
    local proc cmd environment
    for proc in /proc/[0-9]*; do
        [ -r "$proc/cmdline" ] && [ -r "$proc/environ" ] || continue
        cmd="$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true)"
        [ "$cmd" = "$NODE_BIN --ui-present-host " ] || continue
        environment="$(tr '\0' '\n' < "$proc/environ" 2>/dev/null || true)"
        case "$environment" in
            *"XDG_RUNTIME_DIR=$RUNTIME_DIR"*) printf '%s\n' "${proc##*/}" ;;
        esac
    done
    return 0
}

host_parent_pids() {
    local pid children
    while IFS= read -r pid; do
        [ -r "/proc/$pid/task/$pid/children" ] || continue
        children="$(<"/proc/$pid/task/$pid/children")"
        [ -n "$children" ] && printf '%s\n' "$pid"
    done < <(host_pids)
    return 0
}

wait_for_host_exit() {
    local attempt remaining
    for attempt in $(seq 1 100); do
        remaining="$(host_pids)"
        [ -z "$remaining" ] && return 0
        sleep 0.02
    done
    return 1
}

cleanup() {
    local rc="$?" pid
    trap - EXIT INT TERM
    while IFS= read -r pid; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done < <(host_pids)
    case "$RUN_ROOT" in
        /tmp/zcl23-native-ui-alpha.*) rm -rf "$RUN_ROOT" ;;
        *) echo "native-agent-ui-alpha: refusing unsafe cleanup: $RUN_ROOT" >&2 ;;
    esac
    exit "$rc"
}
trap cleanup EXIT INT TERM

[ -n "$DISPLAY_NAME" ] || fail "DISPLAY is unset; physical native-window proof cannot run"
[ -x "$NODE_BIN" ] || fail "missing node binary: $NODE_BIN"
[ -x "$DRIVER_BIN" ] || fail "missing physical driver: $DRIVER_BIN"
mkdir -m 0700 "$RUNTIME_DIR"
export XDG_RUNTIME_DIR="$RUNTIME_DIR"

browser_snapshot() {
    ps -eo pid=,comm= | awk '
        { name=tolower($2) }
        name ~ /^(firefox|chrome|chromium|brave|webkit)/ {
            print $1 ":" $2
        }' | sort
}

json_has() {
    case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac
}

json_int() {
    printf '%s\n' "$1" | sed -n \
        "s/.*\"$2\":[[:space:]]*\([-0-9][0-9]*\).*/\1/p" | tail -1
}

timed_command() {
    local output_name="$1" elapsed_name="$2"
    shift 2
    local started finished command_output command_rc=0
    started="$(date +%s%N)"
    command_output="$("$@")" || command_rc="$?"
    finished="$(date +%s%N)"
    printf -v "$output_name" '%s' "$command_output"
    printf -v "$elapsed_name" '%s' "$(( (finished - started) / 1000 ))"
    [ "$command_rc" -eq 0 ] ||
        fail "typed presentation command failed rc=$command_rc: $command_output"
}

assert_display_reply() {
    local reply="$1"
    json_has "$reply" '"launched":true' ||
        fail "command did not launch a window: $reply"
    json_has "$reply" '"resident_host":true' ||
        fail "resident host was not used: $reply"
    json_has "$reply" '"authority":"display-only"' ||
        fail "visual authority boundary missing: $reply"
}

BEFORE_BROWSERS="$(browser_snapshot)"

# The first request owns an isolated runtime endpoint, so this measures a real
# cold same-binary host start plus the first native software blit.
timed_command QR_REPLY COLD_TOTAL_US \
    "$NODE_BIN" app qr show \
    --input='{"payload":"native-ui-alpha-qr","title":"Alpha QR"}'
assert_display_reply "$QR_REPLY"
[ "$COLD_TOTAL_US" -le 500000 ] ||
    fail "cold native-window latency ${COLD_TOTAL_US}us exceeds 500000us"
"$DRIVER_BIN" --title='Alpha QR' --key=escape --timeout-ms=3000 >/dev/null

STATUS_MODEL='{"kind":"status","request_id":"alpha-status","title":"Alpha node status","summary":"NODE FACT - bounded native status instrument","items":[{"kind":"key-value","status":"green","label":"NODE FACT - presentation host","value":"ready"}]}'
timed_command STATUS_REPLY STATUS_TOTAL_US \
    "$NODE_BIN" app presentation show --input="$STATUS_MODEL"
assert_display_reply "$STATUS_REPLY"
json_has "$STATUS_REPLY" '"presentation_kind":"status"' ||
    fail "status card kind was not returned"
"$DRIVER_BIN" --title='Alpha node status' --key=escape --timeout-ms=3000 >/dev/null

DIFF_MODEL='{"kind":"code-diff","request_id":"alpha-diff","title":"Alpha exact code diff","summary":"AGENT SUMMARY - requested behavior; exact lines remain local observations","exact_root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","items":[{"kind":"diff-remove","label":"LOCAL OBSERVATION - before","value":"return 0;"},{"kind":"diff-add","status":"green","label":"LOCAL OBSERVATION - candidate","value":"return verified;"}]}'
timed_command DIFF_REPLY DIFF_TOTAL_US \
    "$NODE_BIN" app presentation show --input="$DIFF_MODEL"
assert_display_reply "$DIFF_REPLY"
json_has "$DIFF_REPLY" '"presentation_kind":"code-diff"' ||
    fail "code-diff kind was not returned"
"$DRIVER_BIN" --title='Alpha exact code diff' --key=escape --timeout-ms=3000 >/dev/null

# A model larger than one fixed viewport must remain completely reachable by
# keyboard. The host selects only among pre-rendered inert pages; it returns no
# software-authority event for this display-local movement.
SCROLL_ITEMS=''
for row in $(seq 1 12); do
    [ -z "$SCROLL_ITEMS" ] || SCROLL_ITEMS+=','
    SCROLL_ITEMS+="{\"kind\":\"table-row\",\"label\":\"Owner $row\",\"value\":\"Exact row $row\"}"
done
SCROLL_MODEL="{\"kind\":\"table\",\"request_id\":\"alpha-scroll\",\"title\":\"Alpha bounded table\",\"summary\":\"LOCAL OBSERVATION - every bounded row remains reachable\",\"items\":[${SCROLL_ITEMS}]}"
timed_command SCROLL_REPLY SCROLL_TOTAL_US \
    "$NODE_BIN" app presentation show --input="$SCROLL_MODEL"
assert_display_reply "$SCROLL_REPLY"
"$DRIVER_BIN" --title='Alpha bounded table' --key=pagedown \
    --timeout-ms=3000 >/dev/null
"$DRIVER_BIN" --title='Alpha bounded table' --key=escape \
    --timeout-ms=3000 >/dev/null

# Fill the complete resident session table with independently addressable
# display-only instruments. The next request must fail closed at the host
# boundary: it may not escape into the detached cold launcher and become an
# orphan outside the resident host's bounded ownership.
for slot in $(seq 1 16); do
    printf -v SLOT_ID '%02d' "$slot"
    LOAD_MODEL="{\"kind\":\"status\",\"request_id\":\"alpha-load-${SLOT_ID}\",\"title\":\"Alpha load window ${SLOT_ID}\",\"summary\":\"LOCAL OBSERVATION - bounded simultaneous instrument\",\"items\":[{\"kind\":\"key-value\",\"label\":\"LOCAL OBSERVATION - slot\",\"value\":\"${SLOT_ID} of 16\"}]}"
    timed_command LOAD_REPLY LOAD_TOTAL_US \
        "$NODE_BIN" app presentation show --input="$LOAD_MODEL"
    assert_display_reply "$LOAD_REPLY"
    json_has "$LOAD_REPLY" '"host_reused":true' ||
        fail "simultaneous window did not use the warm resident host"
    LOAD_HANDOFF_US="$(json_int "$LOAD_REPLY" launch_handoff_us)"
    [ -n "$LOAD_HANDOFF_US" ] ||
        fail "simultaneous window omitted launch_handoff_us"
    printf '%s\n' "$LOAD_HANDOFF_US" >> "$LOAD_HANDOFFS"
done
"$DRIVER_BIN" --title='Alpha load window' --expect-count=16 \
    --timeout-ms=3000 >/dev/null
set +e
CAPACITY_REPLY="$("$NODE_BIN" app presentation show \
    --input='{"kind":"status","request_id":"alpha-load-17","title":"Alpha load window 17","items":[{"kind":"text","value":"must not escape the resident cap"}]}' 2>&1)"
CAPACITY_RC="$?"
set -e
[ "$CAPACITY_RC" -ne 0 ] ||
    fail "seventeenth simultaneous window escaped the resident capacity"
json_has "$CAPACITY_REPLY" 'presentation host capacity exhausted' ||
    fail "resident capacity refusal was not named: $CAPACITY_REPLY"
json_has "$CAPACITY_REPLY" '"launched":true' &&
    fail "capacity refusal still launched a detached window"
"$DRIVER_BIN" --title='Alpha load window' --expect-count=16 \
    --timeout-ms=1000 >/dev/null
"$DRIVER_BIN" --title='Alpha load window 17' --expect-count=0 \
    --timeout-ms=1000 >/dev/null
for slot in $(seq 1 16); do
    printf -v SLOT_ID '%02d' "$slot"
    "$DRIVER_BIN" --title="Alpha load window ${SLOT_ID}" --key=escape \
        --timeout-ms=3000 >/dev/null
done
"$DRIVER_BIN" --title='Alpha load window' --expect-count=0 \
    --timeout-ms=3000 >/dev/null
LOAD_P50_US="$(sort -n "$LOAD_HANDOFFS" | awk 'NR==8 {print; exit}')"
LOAD_P95_US="$(sort -n "$LOAD_HANDOFFS" | awk 'NR==16 {print; exit}')"
[ -n "$LOAD_P50_US" ] && [ -n "$LOAD_P95_US" ] ||
    fail "simultaneous-window latency sample was incomplete"
[ "$LOAD_P95_US" -le 100000 ] ||
    fail "simultaneous-window p95 ${LOAD_P95_US}us exceeds 100000us"

# Replacing one request identity may change its title and pixels, but it must
# leave exactly one latest screen. The old title becoming unreachable is the
# physical proof that no stale frame survived replacement.
STALE_BEFORE='{"kind":"status","request_id":"alpha-stale","title":"Alpha stale before","items":[{"kind":"text","value":"old frame"}]}'
timed_command STALE_BEFORE_REPLY STALE_BEFORE_US \
    "$NODE_BIN" app presentation show --input="$STALE_BEFORE"
assert_display_reply "$STALE_BEFORE_REPLY"
STALE_LATEST='{"kind":"status","request_id":"alpha-stale","title":"Alpha stale latest","items":[{"kind":"text","value":"latest frame"}]}'
timed_command STALE_LATEST_REPLY STALE_LATEST_US \
    "$NODE_BIN" app presentation show --input="$STALE_LATEST"
assert_display_reply "$STALE_LATEST_REPLY"
json_has "$STALE_LATEST_REPLY" '"view_replaced":true' ||
    fail "latest frame did not replace its exact predecessor"
"$DRIVER_BIN" --title='Alpha stale before' --expect-count=0 \
    --timeout-ms=1000 >/dev/null
"$DRIVER_BIN" --title='Alpha stale latest' --expect-count=1 \
    --timeout-ms=1000 >/dev/null
"$DRIVER_BIN" --title='Alpha stale latest' --key=escape \
    --timeout-ms=3000 >/dev/null

# Reuse one action-bound request identity. Every new inert frame must replace
# its predecessor; the final p95 is edit-to-command-return, not render-only.
for step in $(seq 1 20); do
    PROGRESS_MODEL="{\"kind\":\"progress\",\"request_id\":\"alpha-reproduction\",\"title\":\"Alpha reproduction progress\",\"summary\":\"LOCAL OBSERVATION - independent reproduction\",\"exact_root\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"items\":[{\"kind\":\"progress\",\"status\":\"info\",\"label\":\"LOCAL OBSERVATION - verified stages\",\"value\":\"${step}/20\",\"numerator\":${step},\"denominator\":20}]}"
    timed_command PROGRESS_REPLY PROGRESS_TOTAL_US \
        "$NODE_BIN" app presentation show --input="$PROGRESS_MODEL"
    assert_display_reply "$PROGRESS_REPLY"
    if [ "$step" -eq 11 ]; then
        json_has "$PROGRESS_REPLY" '"host_reused":false' ||
            fail "progress did not cold-resume through a fresh host"
        json_has "$PROGRESS_REPLY" '"view_replaced":false' ||
            fail "fresh host claimed authority over the prior display"
        HOST_RESTART_TOTAL_US="$PROGRESS_TOTAL_US"
        HOST_RESTART_HANDOFF_US="$(json_int "$PROGRESS_REPLY" launch_handoff_us)"
    else
        json_has "$PROGRESS_REPLY" '"host_reused":true' ||
            fail "warm presentation request did not reuse the resident host"
    fi
    if [ "$step" -gt 1 ] && [ "$step" -ne 11 ]; then
        json_has "$PROGRESS_REPLY" '"view_replaced":true' ||
            fail "live progress update did not replace its exact prior view"
    fi
    printf '%s\n' "$PROGRESS_TOTAL_US" >> "$LATENCIES"
    PROGRESS_HANDOFF_US="$(json_int "$PROGRESS_REPLY" launch_handoff_us)"
    PROGRESS_READY_US="$(json_int "$PROGRESS_REPLY" window_ready_us)"
    [ -n "$PROGRESS_HANDOFF_US" ] ||
        fail "progress reply omitted launch_handoff_us"
    [ -n "$PROGRESS_READY_US" ] ||
        fail "progress reply omitted window_ready_us"
    printf '%s\n' "$PROGRESS_HANDOFF_US" >> "$HANDOFFS"
    printf '%s\n' "$PROGRESS_READY_US" >> "$READY_TIMES"
    if [ "$step" -eq 10 ]; then
        HOST_PARENT_PID="$(host_parent_pids)"
        [ -n "$HOST_PARENT_PID" ] ||
            fail "resident presentation parent could not be identified"
        case "$HOST_PARENT_PID" in
            *$'\n'*) fail "multiple resident presentation parents found" ;;
        esac
        echo "native-agent-ui-alpha: stopping resident host $HOST_PARENT_PID" >&2
        kill "$HOST_PARENT_PID" ||
            fail "resident presentation parent could not be stopped"
        echo "native-agent-ui-alpha: resident host signal delivered" >&2
        wait_for_host_exit ||
            fail "display worker survived its resident host"
        echo "native-agent-ui-alpha: resident host and worker exited" >&2
    fi
done
"$DRIVER_BIN" --title='Alpha reproduction progress' --key=escape \
    --timeout-ms=3000 >/dev/null

WARM_P50_US="$(sort -n "$LATENCIES" | awk 'NR==10 {print; exit}')"
WARM_P95_US="$(sort -n "$LATENCIES" | awk 'NR==19 {print; exit}')"
HANDOFF_P50_US="$(sort -n "$HANDOFFS" | awk 'NR==10 {print; exit}')"
HANDOFF_P95_US="$(sort -n "$HANDOFFS" | awk 'NR==19 {print; exit}')"
READY_P50_US="$(sort -n "$READY_TIMES" | awk 'NR==10 {print; exit}')"
READY_P95_US="$(sort -n "$READY_TIMES" | awk 'NR==19 {print; exit}')"
[ -n "$WARM_P50_US" ] && [ -n "$WARM_P95_US" ] &&
    [ -n "$HANDOFF_P50_US" ] && [ -n "$HANDOFF_P95_US" ] &&
    [ -n "$READY_P50_US" ] && [ -n "$READY_P95_US" ] ||
    fail "warm latency sample was incomplete"
[ "$HANDOFF_P95_US" -le 100000 ] ||
    fail "warm resident-host p95 ${HANDOFF_P95_US}us exceeds 100000us"
UPDATE_TOTAL_US="$(tail -1 "$LATENCIES")"
UPDATE_HANDOFF_US="$(tail -1 "$HANDOFFS")"
# One arbitrarily selected final frame is not a stable latency statistic. Keep
# the original 50 ms responsiveness bar on the measured p50, and the explicit
# 100 ms tail bar on p95, so a scheduler outlier cannot hide a slow common path
# or randomly fail an otherwise identical candidate.
[ "$HANDOFF_P50_US" -le 50000 ] ||
    fail "resident progress update p50 ${HANDOFF_P50_US}us exceeds 50000us (worker-ready p50 ${READY_P50_US}us; samples $(tr '\n' ',' < "$HANDOFFS"))"
[ -n "${HOST_RESTART_TOTAL_US:-}" ] &&
    [ -n "${HOST_RESTART_HANDOFF_US:-}" ] ||
    fail "progress host-restart sample was incomplete"
[ "$HOST_RESTART_TOTAL_US" -le 500000 ] ||
    fail "progress host restart ${HOST_RESTART_TOTAL_US}us exceeds 500000us"

# A choice is a closed one-to-one display/action mapping. The first radio is
# the initial visible selection and action focus; Tab must visibly move to the
# second exact option, and Enter returns only that inert action ID.
CHOICE_MODEL='{"kind":"choice","request_id":"alpha-proof-choice","title":"Alpha proof choice","summary":"HUMAN CHOICE - select one bounded proof path","exact_root":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","items":[{"kind":"choice","status":"info","id":"focused-proof","label":"Focused story","value":"fast exact evidence","selected":true},{"kind":"choice","status":"neutral","id":"broad-proof","label":"Broader suite","value":"slower coverage"}],"actions":[{"kind":"select","id":"focused-proof","label":"Focused story"},{"kind":"select","id":"broad-proof","label":"Broader suite"}]}'
CHOICE_REPLY_FILE="$RUN_ROOT/choice.json"
"$NODE_BIN" app presentation show --input="$CHOICE_MODEL" \
    >"$CHOICE_REPLY_FILE" 2>&1 &
CHOICE_PID="$!"
"$DRIVER_BIN" --title='Alpha proof choice' --expect-count=1 \
    --timeout-ms=3000 >/dev/null || {
        kill "$CHOICE_PID" 2>/dev/null || true
        wait "$CHOICE_PID" 2>/dev/null || true
        fail "physical choice window did not appear"
    }
"$DRIVER_BIN" --title='Alpha proof choice' --key=tab \
    --expect-pixels-change --timeout-ms=3000 >/dev/null || {
        kill "$CHOICE_PID" 2>/dev/null || true
        wait "$CHOICE_PID" 2>/dev/null || true
        fail "physical choice focus did not advance"
    }
"$DRIVER_BIN" --title='Alpha proof choice' --key=enter \
    --timeout-ms=3000 >/dev/null || {
        kill "$CHOICE_PID" 2>/dev/null || true
        wait "$CHOICE_PID" 2>/dev/null || true
        fail "physical choice action was not delivered"
    }
wait "$CHOICE_PID" || fail "interactive choice command failed"
CHOICE_REPLY="$(<"$CHOICE_REPLY_FILE")"
assert_display_reply "$CHOICE_REPLY"
json_has "$CHOICE_REPLY" '"event_return":true' ||
    fail "bounded choice event did not return"
json_has "$CHOICE_REPLY" '"action_id":"broad-proof"' ||
    fail "choice returned an action not bound to the visible second row"
json_has "$CHOICE_REPLY" '"exact_root":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"' ||
    fail "choice event lost its exact correlation root"
"$DRIVER_BIN" --title='Alpha proof choice' --expect-count=0 \
    --timeout-ms=3000 >/dev/null

# A form is direct bounded editing, not a decorative card. The first printable
# key must change pixels in the focused field; Tab skips the read-only exact
# root, then reaches harmless Cancel and explicit Submit. Only Submit returns
# the exact ID/value pairs, still correlated to the opening root.
FORM_MODEL='{"kind":"form","request_id":"alpha-release-form","title":"Alpha bounded form","summary":"HUMAN INPUT - describe this exact candidate","exact_root":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","items":[{"kind":"form-field","id":"release-note","label":"Release note","value":"","required":true},{"kind":"form-field","id":"candidate-root","label":"Candidate root","value":"immutable-root","read_only":true}],"actions":[{"kind":"cancel","id":"cancel","label":"Cancel"},{"kind":"submit","id":"submit-release-note","label":"Submit"}]}'
FORM_REPLY_FILE="$RUN_ROOT/form.json"
"$NODE_BIN" app presentation show --input="$FORM_MODEL" \
    >"$FORM_REPLY_FILE" 2>&1 &
FORM_PID="$!"
"$DRIVER_BIN" --title='Alpha bounded form' --expect-count=1 \
    --timeout-ms=3000 >/dev/null || {
        kill "$FORM_PID" 2>/dev/null || true
        wait "$FORM_PID" 2>/dev/null || true
        fail "physical bounded form did not appear"
    }
"$DRIVER_BIN" --title='Alpha bounded form' --key=tab \
    --expect-pixels-change --timeout-ms=3000 >/dev/null || {
        kill "$FORM_PID" 2>/dev/null || true
        wait "$FORM_PID" 2>/dev/null || true
        fail "physical form focus did not reach Cancel"
    }
"$DRIVER_BIN" --title='Alpha bounded form' --key=tab \
    --expect-pixels-change --timeout-ms=3000 >/dev/null || {
        kill "$FORM_PID" 2>/dev/null || true
        wait "$FORM_PID" 2>/dev/null || true
        fail "physical form focus did not reach Submit"
    }
"$DRIVER_BIN" --title='Alpha bounded form' --key=enter \
    --expect-pixels-change --timeout-ms=3000 >/dev/null || {
        kill "$FORM_PID" 2>/dev/null || true
        wait "$FORM_PID" 2>/dev/null || true
        fail "empty required field did not keep Submit local and visible"
    }
"$DRIVER_BIN" --title='Alpha bounded form' --key=tab \
    --expect-pixels-change --timeout-ms=3000 >/dev/null || {
        kill "$FORM_PID" 2>/dev/null || true
        wait "$FORM_PID" 2>/dev/null || true
        fail "physical form focus did not wrap back to its editable field"
    }
"$DRIVER_BIN" --title='Alpha bounded form' --key=1 \
    --expect-pixels-change --timeout-ms=3000 >/dev/null || {
        kill "$FORM_PID" 2>/dev/null || true
        wait "$FORM_PID" 2>/dev/null || true
        fail "physical form keystroke did not change its exact field"
    }
"$DRIVER_BIN" --title='Alpha bounded form' --key=tab \
    --expect-pixels-change --timeout-ms=3000 >/dev/null || {
        kill "$FORM_PID" 2>/dev/null || true
        wait "$FORM_PID" 2>/dev/null || true
        fail "physical form focus did not reach Cancel"
    }
"$DRIVER_BIN" --title='Alpha bounded form' --key=tab \
    --expect-pixels-change --timeout-ms=3000 >/dev/null || {
        kill "$FORM_PID" 2>/dev/null || true
        wait "$FORM_PID" 2>/dev/null || true
        fail "physical form focus did not reach Submit"
    }
"$DRIVER_BIN" --title='Alpha bounded form' --key=enter \
    --timeout-ms=3000 >/dev/null || {
        kill "$FORM_PID" 2>/dev/null || true
        wait "$FORM_PID" 2>/dev/null || true
        fail "physical form submission was not delivered"
    }
wait "$FORM_PID" || fail "interactive bounded form command failed"
FORM_REPLY="$(<"$FORM_REPLY_FILE")"
assert_display_reply "$FORM_REPLY"
json_has "$FORM_REPLY" '"action_id":"submit-release-note"' ||
    fail "form returned the wrong bounded action"
json_has "$FORM_REPLY" '"form_submitted":true' ||
    fail "form submit did not identify an exact value event"
json_has "$FORM_REPLY" '"release-note":"1"' ||
    fail "form submit lost the physically edited value"
json_has "$FORM_REPLY" '"candidate-root":"immutable-root"' ||
    fail "form submit changed its read-only value"
json_has "$FORM_REPLY" '"exact_root":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"' ||
    fail "form event lost its exact correlation root"
"$DRIVER_BIN" --title='Alpha bounded form' --expect-count=0 \
    --timeout-ms=3000 >/dev/null

# A canvas is one exact bounded 2D decision, not arbitrary drawing code. The
# orange point moves locally; immutable reference points remain inert. Submit
# returns only normalized coordinates for the one editable point.
CANVAS_MODEL='{"kind":"canvas","request_id":"alpha-placement-canvas","title":"Alpha bounded canvas","summary":"HUMAN INPUT - place one exact point","exact_root":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","items":[{"kind":"canvas-point","id":"label-origin","label":"Label origin","numerator":250,"denominator":300,"selected":true},{"kind":"canvas-point","status":"info","id":"fixed-anchor","label":"Fixed anchor","numerator":800,"denominator":700,"read_only":true}],"actions":[{"kind":"cancel","id":"cancel","label":"Cancel"},{"kind":"submit","id":"submit-placement","label":"Submit"}]}'
CANVAS_REPLY_FILE="$RUN_ROOT/canvas.json"
"$NODE_BIN" app presentation show --input="$CANVAS_MODEL" \
    >"$CANVAS_REPLY_FILE" 2>&1 &
CANVAS_PID="$!"
"$DRIVER_BIN" --title='Alpha bounded canvas' --expect-count=1 \
    --timeout-ms=3000 >/dev/null || {
        kill "$CANVAS_PID" 2>/dev/null || true
        wait "$CANVAS_PID" 2>/dev/null || true
        fail "physical bounded canvas did not appear"
    }
"$DRIVER_BIN" --title='Alpha bounded canvas' --key=right \
    --expect-pixels-change --timeout-ms=3000 >/dev/null || {
        kill "$CANVAS_PID" 2>/dev/null || true
        wait "$CANVAS_PID" 2>/dev/null || true
        fail "physical canvas arrow did not move the editable point"
    }
"$DRIVER_BIN" --title='Alpha bounded canvas' --key=tab \
    --expect-pixels-change --timeout-ms=3000 >/dev/null || {
        kill "$CANVAS_PID" 2>/dev/null || true
        wait "$CANVAS_PID" 2>/dev/null || true
        fail "physical canvas focus did not reach Cancel"
    }
"$DRIVER_BIN" --title='Alpha bounded canvas' --key=tab \
    --expect-pixels-change --timeout-ms=3000 >/dev/null || {
        kill "$CANVAS_PID" 2>/dev/null || true
        wait "$CANVAS_PID" 2>/dev/null || true
        fail "physical canvas focus did not reach Submit"
    }
"$DRIVER_BIN" --title='Alpha bounded canvas' --key=enter \
    --timeout-ms=3000 >/dev/null || {
        kill "$CANVAS_PID" 2>/dev/null || true
        wait "$CANVAS_PID" 2>/dev/null || true
        fail "physical canvas submission was not delivered"
    }
wait "$CANVAS_PID" || fail "interactive bounded canvas command failed"
CANVAS_REPLY="$(<"$CANVAS_REPLY_FILE")"
assert_display_reply "$CANVAS_REPLY"
json_has "$CANVAS_REPLY" '"action_id":"submit-placement"' ||
    fail "canvas returned the wrong bounded action"
json_has "$CANVAS_REPLY" '"canvas_submitted":true' ||
    fail "canvas submit did not identify an exact coordinate event"
json_has "$CANVAS_REPLY" '"canvas_point_id":"label-origin"' ||
    fail "canvas submit lost the editable point identity"
json_has "$CANVAS_REPLY" '"canvas_x":260' ||
    fail "canvas submit lost the physically moved x coordinate"
json_has "$CANVAS_REPLY" '"canvas_y":300' ||
    fail "canvas submit changed the untouched y coordinate"
json_has "$CANVAS_REPLY" '"exact_root":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' ||
    fail "canvas event lost its exact correlation root"
"$DRIVER_BIN" --title='Alpha bounded canvas' --expect-count=0 \
    --timeout-ms=3000 >/dev/null

# An interactive model blocks only for one bounded action. The physical driver
# clicks inside action zero; the command must return its ID and exact root, but
# performs no publication or other software effect.
CONFIRM_MODEL='{"kind":"confirmation","request_id":"alpha-publish","title":"Alpha local-commit confirmation","summary":"HUMAN DECISION - confirm the exact local commit plan; no network publication is performed","exact_root":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","items":[{"kind":"key-value","label":"LOCAL OBSERVATION - plan root","value":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"actions":[{"kind":"cancel","id":"cancel","label":"Cancel - make no change"},{"kind":"confirm","id":"confirm-exact-local-commit","label":"Confirm exact local commit"}]}'
CONFIRM_REPLY_FILE="$RUN_ROOT/confirmation.json"
"$NODE_BIN" app presentation show --input="$CONFIRM_MODEL" \
    >"$CONFIRM_REPLY_FILE" 2>&1 &
CONFIRM_PID="$!"
"$DRIVER_BIN" --title='Alpha local-commit confirmation' --expect-count=1 \
    --timeout-ms=3000 >/dev/null || {
        kill "$CONFIRM_PID" 2>/dev/null || true
        wait "$CONFIRM_PID" 2>/dev/null || true
        fail "physical confirmation window did not appear"
    }
# A display-only update may not reuse the request identity of an unresolved
# human decision. Refusing the collision keeps the original event channel and
# exact plan root intact instead of replacing or losing the decision.
set +e
COLLISION_REPLY="$("$NODE_BIN" app presentation show \
    --input='{"kind":"status","request_id":"alpha-publish","title":"Alpha decision collision","items":[{"kind":"text","value":"must be refused"}]}' 2>&1)"
COLLISION_RC="$?"
set -e
[ "$COLLISION_RC" -ne 0 ] || {
    kill "$CONFIRM_PID" 2>/dev/null || true
    wait "$CONFIRM_PID" 2>/dev/null || true
    fail "display update replaced an unresolved human decision"
}
json_has "$COLLISION_REPLY" 'request id already owns an active window' ||
    fail "request-identity collision refusal was not named: $COLLISION_REPLY"
"$DRIVER_BIN" --title='Alpha decision collision' --expect-count=0 \
    --timeout-ms=1000 >/dev/null
"$DRIVER_BIN" --title='Alpha local-commit confirmation' --expect-count=1 \
    --timeout-ms=1000 >/dev/null
# Exercise the shared visible focus path rather than the direct numeric
# shortcut: the harmless Cancel action owns initial focus; Tab deliberately
# moves to Confirm, and Enter returns that exact bounded action. The semantic
# human decision remains one.
"$DRIVER_BIN" --title='Alpha local-commit confirmation' --key=tab \
    --expect-pixels-change --timeout-ms=3000 >/dev/null || {
        kill "$CONFIRM_PID" 2>/dev/null || true
        wait "$CONFIRM_PID" 2>/dev/null || true
        fail "physical confirmation focus did not advance"
    }
"$DRIVER_BIN" --title='Alpha local-commit confirmation' --key=enter \
    --timeout-ms=3000 >/dev/null || {
        kill "$CONFIRM_PID" 2>/dev/null || true
        wait "$CONFIRM_PID" 2>/dev/null || true
        fail "physical confirmation action was not delivered"
    }
wait "$CONFIRM_PID" || fail "interactive presentation command failed"
CONFIRM_REPLY="$(<"$CONFIRM_REPLY_FILE")"
assert_display_reply "$CONFIRM_REPLY"
json_has "$CONFIRM_REPLY" '"event_return":true' ||
    fail "bounded confirmation event did not return"
json_has "$CONFIRM_REPLY" '"action_id":"confirm-exact-local-commit"' ||
    fail "confirmation returned the wrong action identity"
json_has "$CONFIRM_REPLY" '"exact_root":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"' ||
    fail "confirmation event lost its exact plan root"
"$DRIVER_BIN" --title='Alpha local-commit confirmation' --expect-count=0 \
    --timeout-ms=3000 >/dev/null

set +e
HEADLESS_REPLY="$(env -u DISPLAY "$NODE_BIN" app qr show \
    --input='{"payload":"headless-refusal"}' 2>&1)"
HEADLESS_RC="$?"
set -e
[ "$HEADLESS_RC" -ne 0 ] || fail "headless QR unexpectedly succeeded"
json_has "$HEADLESS_REPLY" 'HEADLESS_DISPLAY_UNAVAILABLE' ||
    fail "headless refusal was not named"

# The exact same typed instrument has a deterministic, display-independent
# companion. Text delivery must neither require DISPLAY nor wake/replace the
# resident host, and it remains explicitly display-only inert data.
TEXT_HOSTS_BEFORE="$(host_pids)"
QR_TEXT_REPLY="$(env -u DISPLAY "$NODE_BIN" app qr show \
    --input='{"payload":"headless-text-exact","title":"Text QR","output":"text"}')" ||
    fail "headless QR text companion failed"
json_has "$QR_TEXT_REPLY" '"launched":false' ||
    fail "QR text companion claimed a native launch: $QR_TEXT_REPLY"
json_has "$QR_TEXT_REPLY" '"delivery":"text"' ||
    fail "QR text companion lost its delivery identity: $QR_TEXT_REPLY"
json_has "$QR_TEXT_REPLY" 'payload-fragment: headless-text-exact' ||
    fail "QR text companion lost exact payload bytes: $QR_TEXT_REPLY"
json_has "$QR_TEXT_REPLY" '"authority":"display-only"' ||
    fail "QR text companion lost the authority boundary: $QR_TEXT_REPLY"

STATUS_TEXT_MODEL='{"kind":"status","request_id":"alpha-status","title":"Alpha node status","summary":"NODE FACT - bounded native status instrument","items":[{"kind":"key-value","status":"green","label":"NODE FACT - presentation host","value":"ready"}],"output":"text"}'
STATUS_TEXT_REPLY="$(env -u DISPLAY "$NODE_BIN" app presentation show \
    --input="$STATUS_TEXT_MODEL")" ||
    fail "headless status text companion failed"
json_has "$STATUS_TEXT_REPLY" 'kind: status' ||
    fail "status text companion lost its model kind: $STATUS_TEXT_REPLY"
json_has "$STATUS_TEXT_REPLY" 'NODE FACT - presentation host' ||
    fail "status text companion lost its exact item: $STATUS_TEXT_REPLY"
CORPUS_TEXT_REPLY="$(env -u DISPLAY "$NODE_BIN" app presentation corpus \
    --input='{"output":"text"}')" ||
    fail "headless canonical corpus instrument failed"
json_has "$CORPUS_TEXT_REPLY" 'title: 10 Million Exact C23' ||
    fail "corpus instrument lost its product identity: $CORPUS_TEXT_REPLY"
json_has "$CORPUS_TEXT_REPLY" 'CORPUS FACT - Admitted production' ||
    fail "corpus instrument lost canonical status facts: $CORPUS_TEXT_REPLY"
json_has "$CORPUS_TEXT_REPLY" 'CORPUS FACT - Downstream used' ||
    fail "corpus text companion omitted downstream-use status: $CORPUS_TEXT_REPLY"
json_has "$CORPUS_TEXT_REPLY" 'CORPUS FACT - Unique semantic units' ||
    fail "corpus text companion omitted semantic units: $CORPUS_TEXT_REPLY"
json_has "$CORPUS_TEXT_REPLY" 'CORPUS FACT - Packages admitted' ||
    fail "corpus text companion omitted package count: $CORPUS_TEXT_REPLY"
json_has "$CORPUS_TEXT_REPLY" 'CORPUS FACT - Exclusions' ||
    fail "corpus text companion omitted exclusions: $CORPUS_TEXT_REPLY"
json_has "$CORPUS_TEXT_REPLY" 'CORPUS FACT - Velocity' ||
    fail "corpus text companion omitted velocity status: $CORPUS_TEXT_REPLY"
json_has "$CORPUS_TEXT_REPLY" '"text_complete":true' ||
    fail "bounded corpus facts still require multiple agent commands: $CORPUS_TEXT_REPLY"
json_has "$CORPUS_TEXT_REPLY" '"text_page_count":1' ||
    fail "complete corpus text companion reports extra pages: $CORPUS_TEXT_REPLY"
json_has "$CORPUS_TEXT_REPLY" '"global_completeness_claimed":false' ||
    fail "corpus instrument overstated completeness: $CORPUS_TEXT_REPLY"
json_has "$CORPUS_TEXT_REPLY" '"authority":"display-only"' ||
    fail "corpus instrument lost the authority boundary: $CORPUS_TEXT_REPLY"
DIFF_TEXT_MODEL='{"kind":"code-diff","request_id":"alpha-diff-text","title":"Alpha exact code diff","exact_root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","items":[{"kind":"diff-remove","label":"before","value":"return 0;"},{"kind":"diff-add","status":"green","label":"candidate","value":"return verified;"}],"output":"text","page":1}'
DIFF_TEXT_REPLY="$(env -u DISPLAY "$NODE_BIN" app presentation show \
    --input="$DIFF_TEXT_MODEL")" ||
    fail "headless paged code-diff text companion failed"
json_has "$DIFF_TEXT_REPLY" 'page: 2/2' ||
    fail "code-diff text companion lost normalized paging: $DIFF_TEXT_REPLY"
json_has "$DIFF_TEXT_REPLY" 'value: return verified;' ||
    fail "code-diff text companion lost its exact candidate: $DIFF_TEXT_REPLY"
json_has "$DIFF_TEXT_REPLY" 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ||
    fail "code-diff text companion lost its exact root: $DIFF_TEXT_REPLY"
[ "$TEXT_HOSTS_BEFORE" = "$(host_pids)" ] ||
    fail "text-only delivery changed the resident native host set"

DEPENDENCIES="$(ldd "$NODE_BIN" 2>&1 | tr '[:upper:]' '[:lower:]')"
case "$DEPENDENCIES" in
    *gtk*|*webkit*|*javascriptcore*|*libnode*)
        fail "release node acquired a browser/UI-framework dependency" ;;
esac
AFTER_BROWSERS="$(browser_snapshot)"
[ "$BEFORE_BROWSERS" = "$AFTER_BROWSERS" ] ||
    fail "browser process set changed during the native journey"

printf '%s\n' \
    "{\"schema\":\"zcl.native_agent_ui_physical.v1\",\"verdict\":\"PASS\",\"qr_window\":true,\"status_card\":true,\"corpus_status_instrument\":true,\"code_diff\":true,\"deterministic_text_companion\":true,\"headless_text_delivery\":true,\"bounded_keyboard_pagination\":true,\"visible_action_focus\":true,\"tab_enter_actions\":true,\"exact_choice_event\":true,\"exact_form_event\":true,\"exact_canvas_event\":true,\"simultaneous_windows\":16,\"resident_capacity_refusal\":true,\"no_detached_capacity_escape\":true,\"no_stale_screens\":true,\"no_lost_decisions\":true,\"no_orphan_processes_after_restart\":true,\"live_reproduction_progress\":true,\"progress_host_restart_resume\":true,\"exact_confirmation_event\":true,\"display_only_authority\":true,\"headless_named_refusal\":true,\"browser_process_delta\":0,\"release_browser_dependency\":false,\"cold_total_us\":$COLD_TOTAL_US,\"warm_total_p50_us\":$WARM_P50_US,\"warm_total_p95_us\":$WARM_P95_US,\"warm_handoff_p50_us\":$HANDOFF_P50_US,\"warm_handoff_p95_us\":$HANDOFF_P95_US,\"update_total_p50_us\":$WARM_P50_US,\"update_total_p95_us\":$WARM_P95_US,\"update_handoff_p50_us\":$HANDOFF_P50_US,\"update_handoff_p95_us\":$HANDOFF_P95_US,\"worker_ready_p50_us\":$READY_P50_US,\"worker_ready_p95_us\":$READY_P95_US,\"simultaneous_handoff_p50_us\":$LOAD_P50_US,\"simultaneous_handoff_p95_us\":$LOAD_P95_US,\"host_restart_total_us\":$HOST_RESTART_TOTAL_US,\"host_restart_handoff_us\":$HOST_RESTART_HANDOFF_US,\"last_update_total_us\":$UPDATE_TOTAL_US,\"last_update_handoff_us\":$UPDATE_HANDOFF_US}"
