#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# agent_test_runner.sh — backing script for the `agenttest` native contract
# (cognition/controllers/src/agent_test_controller.c / native `dev test run`),
# cloned from the tools/repro_on_copy.sh + agentcopyprove pattern (see that
# script + docs/CODEBASE_MAP.md "copy-prove").
#
# Runs ONE bounded, already-allowlisted test surface in the background and
# writes a JSON status file the caller polls via `z23 dumpstate
# subsystem=agent_test key=<kind>_<name>` instead of holding an RPC thread:
#   - kind=test_group: build/bin/test_parallel --only=<name>
#   - kind=scenario:   build/bin/zclassic23-chaos --scenario=tools/sim/scenarios/<name>.scenario
#
# SAFETY: this script re-validates --kind/--name itself (belt and suspenders
# on top of the C controller's allowlist) and NEVER passes them through a
# nested shell/eval — each is used as exactly one argv word to the target
# binary (--only=$NAME / --scenario=$PATH), never concatenated into an
# interpreted command string. --name is restricted to
# ^[a-z0-9_]{1,64}$ — no slash, no dot, no shell metacharacter of any kind.
set -u

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# atomic_write PATH — reads stdin, writes PATH.tmp then renames onto PATH so
# a concurrent poller never observes a partial file.
atomic_write() {
    path="$1"
    tmp="$path.tmp.$$"
    cat > "$tmp"
    mv -f "$tmp" "$path"
}

tail_text() {
    # Last 40 lines of $1, JSON-escaped, empty string if unreadable.
    if [ -r "$1" ]; then
        json_escape "$(tail -n 40 "$1" 2>/dev/null)"
    else
        printf ''
    fi
}

emit_status() {
    # Args: state verdict exit_code tail_json
    state="$1"; verdict="$2"; rc="$3"; tail_json="$4"
    printf '{"schema":"zcl.agent_test_result.v1","state":"%s",' "$state"
    printf '"kind":"%s","name":"%s","verdict":"%s","exit_code":%s,' \
        "$(json_escape "$KIND")" "$(json_escape "$NAME")" "$verdict" "$rc"
    printf '"log_path":"%s","command":"%s","tail":"%s","generated_at":%s}\n' \
        "$(json_escape "$LOG_FILE")" "$(json_escape "$CMD_DESC")" \
        "$tail_json" "$(date +%s)"
}

KIND=""
NAME=""
STATUS_FILE=""
LOG_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --kind=*)        KIND="${1#--kind=}" ;;
        --name=*)        NAME="${1#--name=}" ;;
        --status-file=*) STATUS_FILE="${1#--status-file=}" ;;
        --log-file=*)    LOG_FILE="${1#--log-file=}" ;;
        --)              shift; break ;;
        *) echo "agent_test_runner: unknown arg $1" >&2; exit 2 ;;
    esac
    shift
done

[ -n "$KIND" ] && [ -n "$NAME" ] && [ -n "$STATUS_FILE" ] || {
    echo "usage: agent_test_runner.sh --kind=test_group|scenario --name=NAME --status-file=PATH [--log-file=PATH]" >&2
    exit 2
}
[ -n "$LOG_FILE" ] || LOG_FILE="$STATUS_FILE.log"

# Re-validate NAME independent of the caller (defense in depth): lowercase
# alnum + underscore only, 1..64 chars. No slash, no dot -> path traversal
# and shell metacharacters are structurally unreachable.
case "$NAME" in
    ''|*[!a-z0-9_]*)
        emit_status "done" "ERROR" 2 "" | atomic_write "$STATUS_FILE"
        echo "agent_test_runner: invalid --name" >&2
        exit 2
        ;;
esac
NAME_LEN=${#NAME}
if [ "$NAME_LEN" -gt 64 ]; then
    emit_status "done" "ERROR" 2 "" | atomic_write "$STATUS_FILE"
    echo "agent_test_runner: --name too long" >&2
    exit 2
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
TEST_PARALLEL_BIN="${ZCL_AGENT_TEST_PARALLEL_BIN:-$REPO_ROOT/build/bin/test_parallel}"
CHAOS_BIN="${ZCL_AGENT_TEST_CHAOS_BIN:-$REPO_ROOT/build/bin/zclassic23-chaos}"
SCENARIOS_DIR="${ZCL_AGENT_TEST_SCENARIOS_DIR:-$REPO_ROOT/tools/sim/scenarios}"

mkdir -p "$(dirname "$STATUS_FILE")" 2>/dev/null || true
: > "$LOG_FILE" 2>/dev/null || true

CMD_DESC=""
emit_status "running" "" 0 "" | atomic_write "$STATUS_FILE"

case "$KIND" in
    test_group)
        CMD_DESC="test_parallel --only=$NAME"
        if [ ! -x "$TEST_PARALLEL_BIN" ]; then
            emit_status "done" "ERROR" 127 \
                "$(json_escape "test_parallel binary not built: $TEST_PARALLEL_BIN")" \
                | atomic_write "$STATUS_FILE"
            exit 1
        fi
        "$TEST_PARALLEL_BIN" "--only=$NAME" > "$LOG_FILE" 2>&1
        rc=$?
        if [ "$rc" -eq 0 ]; then verdict="PASS"
        elif [ "$rc" -eq 2 ]; then verdict="NO_MATCH"
        else verdict="FAIL"
        fi
        ;;
    scenario)
        SCEN_PATH="$SCENARIOS_DIR/$NAME.scenario"
        CMD_DESC="zclassic23-chaos --scenario=$SCEN_PATH"
        if [ ! -f "$SCEN_PATH" ]; then
            emit_status "done" "ERROR" 2 \
                "$(json_escape "scenario file not found: $SCEN_PATH")" \
                | atomic_write "$STATUS_FILE"
            exit 1
        fi
        if [ ! -x "$CHAOS_BIN" ]; then
            emit_status "done" "ERROR" 127 \
                "$(json_escape "zclassic23-chaos binary not built: $CHAOS_BIN")" \
                | atomic_write "$STATUS_FILE"
            exit 1
        fi
        "$CHAOS_BIN" "--scenario=$SCEN_PATH" --verbose > "$LOG_FILE" 2>&1
        rc=$?
        if [ "$rc" -eq 0 ]; then verdict="PASS"; else verdict="FAIL"; fi
        ;;
    *)
        emit_status "done" "ERROR" 2 \
            "$(json_escape "unknown kind: $KIND")" | atomic_write "$STATUS_FILE"
        exit 2
        ;;
esac

emit_status "done" "$verdict" "$rc" "$(tail_text "$LOG_FILE")" \
    | atomic_write "$STATUS_FILE"
exit 0
