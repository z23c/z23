#!/bin/bash
# zclassic23-host-watchdog.sh — SYSTEM-level watchdog ABOVE user@<uid>.
#
# Every zclassic23 unit (node, timers, the slo-probe that watches THEM)
# runs under systemd --user for OPERATOR_USER, and that user manager has
# been OOM-killed before (see the fleet memory note: no-sudo revive via
# linger + a localhost ssh login). This runs one level up, as root, via
# deploy/system/zclassic23-host-watchdog.{service,timer} every 2 min:
#   1. probe user@<uid>.service; if dead, revive it (re-assert linger,
#      then an ssh-localhost no-op run AS OPERATOR_USER — that's whose
#      PAM session needs to open, not root's).
#   2. decide what the canonical node is actually doing (see below).
#   3. append ONE line to LOG_FILE, but ONLY on a verdict change or while
#      unhealthy (quiet when OK, loud on transitions + every failing cycle).
#
# ── Why one missed probe is not a down node ────────────────────────────────
# This used to be a single 5-second HTTP probe: it answered, or the box was
# declared NODE-DOWN. On a 7200rpm box measured under 2 MB/s that is a coin
# flip — an honest node mid-checkpoint can miss a 5s budget and be perfectly
# alive, and the operator gets paged about a machine that is working. Worse,
# it collapsed reachability and speed into one scalar, so "slow" and "gone"
# arrived as the same word.
#
# The verdict now COMPOSES three independently observable things:
#
#   reachability — several probes with ESCALATING patience (5s, 15s, 45s by
#                  default). An answer on a later attempt is an answer; it is
#                  reported as slow, with the attempt that succeeded.
#   existence    — does the canonical node process exist at all? No process
#                  is not slowness, and it is called immediately.
#   progress     — /proc/<MainPID> CPU ticks, I/O bytes and, decisively,
#                  delayacct_blkio_ticks: the counter that climbs while the
#                  process is BLOCKED on a slow disk. A box grinding through
#                  a checkpoint moves it; a wedged process moves nothing.
#
# so the verdicts are kept apart by construction and never share a word:
#
#   OK                — answered on the first probe
#   NODE-SLOW         — answered, but only on a later, more patient probe
#   NODE-BUSY         — no answer this cycle, but the process is demonstrably
#                       still working. Reported, not alarmed.
#   NODE-RPC-WEDGED   — alive and progressing, yet unreachable for many
#                       consecutive cycles. That is an RPC front-door fault,
#                       and it is NOT the same fault as a dead node.
#   NODE-UNRESPONSIVE — the process exists but nothing about it has moved for
#                       a whole cycle. One such cycle is a suspicion.
#   NODE-DOWN         — no process at all, or sustained frozen-process cycles.
#                       Only ever printed with the evidence that justified it.
#
# Idempotent. Read-only except the revive step and the log/state append.
# --dry-run:  decide + print, no systemctl/ssh mutation (probes still run).
# --selftest: hermetic proof of the classifier, no node and no root needed.
set -euo pipefail

OPERATOR_USER="${ZCL_HOST_WATCHDOG_USER:-rhett}"
RPC_HOST="${ZCL_HOST_WATCHDOG_RPC_HOST:-127.0.0.1}"
RPC_PORT="${ZCL_HOST_WATCHDOG_RPC_PORT:-18232}"
LOG_FILE="${ZCL_HOST_WATCHDOG_LOG:-/var/log/zclassic23-host-watchdog.log}"
STATE_FILE="${ZCL_HOST_WATCHDOG_STATE:-/var/lib/zclassic23-host-watchdog/state}"
NODE_UNIT="${ZCL_HOST_WATCHDOG_UNIT:-zclassic23}"

# Escalating probe patience, in seconds, one budget per attempt. The sum must
# stay under the timer period so a slow cycle never overlaps the next one.
PROBE_TIMEOUTS="${ZCL_HOST_WATCHDOG_PROBE_TIMEOUTS:-5 15 45}"
# Consecutive frozen-process cycles before a suspicion becomes NODE-DOWN.
DOWN_CYCLES="${ZCL_HOST_WATCHDOG_DOWN_CYCLES:-2}"
# Consecutive unreachable-but-progressing cycles before we name the RPC front
# door as the fault. Deliberately generous: at a 2-minute timer this is ~10min
# of a node that is demonstrably alive and doing work.
WEDGE_CYCLES="${ZCL_HOST_WATCHDOG_WEDGE_CYCLES:-5}"

# Seams. The selftest injects these; production leaves them unset.
PROBE_HOOK="${ZCL_HOST_WATCHDOG_PROBE_HOOK:-}"
PROGRESS_HOOK="${ZCL_HOST_WATCHDOG_PROGRESS_HOOK:-}"
MANAGER_HOOK="${ZCL_HOST_WATCHDOG_MANAGER_HOOK:-}"

MODE=run
case "${1:-}" in
    --dry-run)  MODE=dry ;;
    --selftest) MODE=selftest ;;
    "")         ;;
    *) echo "usage: $0 [--dry-run|--selftest]" >&2; exit 1 ;;
esac

# ── /proc progress observables (pure parsers, so the selftest can pin them) ──
# Field numbering is post-strip of the "pid (comm) " prefix, so proc(5) fields
# shift down by two: utime(14)/stime(15) -> $12/$13,
# delayacct_blkio_ticks(42) -> $40.
proc_cpu_ticks_from_text() {
    printf '%s\n' "${1:-}" |
        sed 's/^[0-9][0-9]* ([^)]*) //' |
        awk 'NF >= 13 && !seen { printf "%.0f\n", $12 + $13; seen = 1 }
             END { if (!seen) print 0 }'
}

proc_blkio_ticks_from_text() {
    printf '%s\n' "${1:-}" |
        sed 's/^[0-9][0-9]* ([^)]*) //' |
        awk 'NF >= 40 && !seen { printf "%.0f\n", $40; seen = 1 }
             END { if (!seen) print 0 }'
}

proc_io_bytes_from_text() {
    printf '%s\n' "${1:-}" |
        awk '/^(rchar|wchar|read_bytes|write_bytes):[ \t]*[0-9]+$/ { total += $2 }
             END { printf "%.0f\n", total + 0 }'
}

# ── the classifier ──────────────────────────────────────────────────────────
# classify_node <answered-attempt> <node-exists> <progress-moved> \
#               <frozen-streak> <unreachable-streak> <down-cycles> <wedge-cycles>
#
#   answered-attempt   0 = no probe answered, else the attempt that did
#   node-exists        1 if a canonical node process was found
#   progress-moved     1 if any observable changed since the previous cycle
#   frozen-streak      consecutive cycles (INCLUDING this one) with a process
#                      present and nothing moving
#   unreachable-streak consecutive cycles (INCLUDING this one) with no answer
#
# Every branch here is a different sentence about a different machine state.
# Nothing in it is a duration, and nothing collapses "slow" into "down".
classify_node() {
    local answered="$1" exists="$2" moved="$3"
    local frozen_streak="$4" unreachable_streak="$5"
    local down_cycles="$6" wedge_cycles="$7"

    if [ "$answered" -eq 1 ]; then
        echo OK
        return 0
    fi
    if [ "$answered" -gt 1 ]; then
        echo NODE-SLOW
        return 0
    fi
    # No probe answered. Slowness is only a defence if something is there.
    if [ "$exists" -ne 1 ]; then
        echo NODE-DOWN
        return 0
    fi
    if [ "$moved" -eq 1 ]; then
        if [ "$unreachable_streak" -ge "$wedge_cycles" ]; then
            echo NODE-RPC-WEDGED
        else
            echo NODE-BUSY
        fi
        return 0
    fi
    if [ "$frozen_streak" -ge "$down_cycles" ]; then
        echo NODE-DOWN
    else
        echo NODE-UNRESPONSIVE
    fi
}

# verdict_is_alarming <verdict> — decides whether a line is written even when
# the verdict has not changed. NODE-SLOW and NODE-BUSY are reported once per
# transition, not screamed every cycle: a slow box is not an incident.
verdict_is_alarming() {
    case "$1" in
        NODE-DOWN|NODE-UNRESPONSIVE|NODE-RPC-WEDGED|REVIVED-USER-MANAGER) return 0 ;;
        *) return 1 ;;
    esac
}

# ── state file: key=value, tolerant of the old bare-verdict format ──────────
state_get() {
    local key="$1" file="$2" line
    [ -f "$file" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            "$key="*) printf '%s\n' "${line#*=}"; return 0 ;;
        esac
    done < "$file"
    # Legacy format: the whole file was one bare verdict word.
    if [ "$key" = verdict ]; then
        line="$(head -n1 "$file" 2>/dev/null || true)"
        case "$line" in
            *=*) : ;;
            ?*)  printf '%s\n' "$line" ;;
        esac
    fi
}

# ── 1. user manager liveness ────────────────────────────────────────────────
manager_alive() {
    if [ -n "$MANAGER_HOOK" ]; then
        "$MANAGER_HOOK"
        return $?
    fi
    systemctl is-active --quiet "user@${uid}.service"
}

# ── 2. reachability: several probes, escalating patience ────────────────────
# Returns the attempt number that answered, or 0. A late answer is an ANSWER.
probe_rpc_once() {
    local attempt="$1" budget="$2"
    if [ -n "$PROBE_HOOK" ]; then
        "$PROBE_HOOK" "$attempt" "$budget"
        return $?
    fi
    local code
    if command -v curl >/dev/null 2>&1; then
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time "$budget" \
                "http://${RPC_HOST}:${RPC_PORT}/" 2>/dev/null || true)"
        [ -n "$code" ] && [ "$code" != "000" ]
    else
        timeout "$budget" bash -c ": >/dev/tcp/${RPC_HOST}/${RPC_PORT}" 2>/dev/null
    fi
}

probe_rpc() {
    local attempt=0 budget
    for budget in $PROBE_TIMEOUTS; do
        attempt=$((attempt + 1))
        if probe_rpc_once "$attempt" "$budget"; then
            printf '%s\n' "$attempt"
            return 0
        fi
    done
    printf '0\n'
}

# ── 3. existence + progress, straight out of /proc ──────────────────────────
node_main_pid() {
    runuser -u "$OPERATOR_USER" -- \
        systemctl --user show "$NODE_UNIT" -p MainPID --value 2>/dev/null || true
}

# Prints a progress token, or nothing at all when no node process exists.
# Empty output is the ONLY thing that means "there is nothing there".
node_progress_token() {
    if [ -n "$PROGRESS_HOOK" ]; then
        "$PROGRESS_HOOK"
        return $?
    fi
    local pid stat io
    pid="$(node_main_pid)"
    case "$pid" in
        ''|*[!0-9]*|0) return 0 ;;
    esac
    [ -r "/proc/$pid/stat" ] || return 0
    stat="$(cat "/proc/$pid/stat" 2>/dev/null || true)"
    [ -n "$stat" ] || return 0
    io="$(cat "/proc/$pid/io" 2>/dev/null || true)"
    printf 'pid=%s cpu=%s blkio=%s io=%s\n' "$pid" \
        "$(proc_cpu_ticks_from_text "$stat")" \
        "$(proc_blkio_ticks_from_text "$stat")" \
        "$(proc_io_bytes_from_text "$io")"
}

# ── selftest ────────────────────────────────────────────────────────────────
watchdog_selftest() {
    local fails=0
    check() {
        local want="$1"; shift
        local got
        got="$(classify_node "$@")"
        if [ "$got" = "$want" ]; then
            printf '[host-watchdog-selftest] PASS: %s <- %s\n' "$want" "$*"
        else
            printf '[host-watchdog-selftest] FAIL: wanted %s got %s <- %s\n' \
                "$want" "$got" "$*" >&2
            fails=$((fails + 1))
        fi
    }
    # args: answered exists moved frozen_streak unreachable_streak down wedge

    # A first-probe answer is the healthy case and stays silent.
    check OK               1 1 1 0 0 2 5
    # THE DEFECT THIS REPLACES: the probe that needed more patience. Under the
    # old single 5s probe this box was NODE-DOWN. It is answering.
    check NODE-SLOW        2 1 1 0 1 2 5
    check NODE-SLOW        3 1 0 0 1 2 5
    # No answer this cycle, but the process is demonstrably still working:
    # that is a slow box, and it must not be alarmed as a dead one.
    check NODE-BUSY        0 1 1 0 1 2 5
    # ...and it stays NODE-BUSY cycle after cycle while it keeps working.
    check NODE-BUSY        0 1 1 0 4 2 5
    # Alive and working but unreachable for many cycles is a DIFFERENT fault
    # from a dead node, and it gets a different word.
    check NODE-RPC-WEDGED  0 1 1 0 5 2 5
    check NODE-RPC-WEDGED  0 1 1 0 9 2 5
    # A process that exists but has not moved for one cycle is a suspicion,
    # never a verdict.
    check NODE-UNRESPONSIVE 0 1 0 1 1 2 5
    # Sustained frozen cycles earn NODE-DOWN.
    check NODE-DOWN        0 1 0 2 2 2 5
    check NODE-DOWN        0 1 0 7 7 2 5
    # No process at all is not slowness: it is called immediately.
    check NODE-DOWN        0 0 0 1 1 2 5
    # A stricter operator can demand more confirmation; a slower box can be
    # given more. Neither changes what the words mean.
    check NODE-UNRESPONSIVE 0 1 0 2 2 3 5
    check NODE-DOWN         0 1 0 3 3 3 5

    # Alarm policy: slow and busy are reported on transition, never screamed.
    verdict_is_alarming NODE-DOWN         || { echo "FAIL: NODE-DOWN not alarming" >&2; fails=$((fails+1)); }
    verdict_is_alarming NODE-UNRESPONSIVE || { echo "FAIL: NODE-UNRESPONSIVE not alarming" >&2; fails=$((fails+1)); }
    verdict_is_alarming NODE-RPC-WEDGED   || { echo "FAIL: NODE-RPC-WEDGED not alarming" >&2; fails=$((fails+1)); }
    if verdict_is_alarming NODE-SLOW; then echo "FAIL: NODE-SLOW must not alarm every cycle" >&2; fails=$((fails+1)); fi
    if verdict_is_alarming NODE-BUSY; then echo "FAIL: NODE-BUSY must not alarm every cycle" >&2; fails=$((fails+1)); fi
    if verdict_is_alarming OK; then echo "FAIL: OK must not alarm" >&2; fails=$((fails+1)); fi

    # ── /proc parsers ───────────────────────────────────────────────────────
    local st_a st_b
    st_a="1 (z23 node) D 1 1 1 0 -1 0 0 0 0 0 5 5 0 0 20 0 9 0 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1000 0 0"
    st_b="1 (z23 node) D 1 1 1 0 -1 0 0 0 0 0 5 5 0 0 20 0 9 0 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 4000 0 0"
    [ "$(proc_cpu_ticks_from_text "$st_a")" = 10 ] || { echo "FAIL: cpu parse" >&2; fails=$((fails+1)); }
    [ "$(proc_blkio_ticks_from_text "$st_a")" = 1000 ] || { echo "FAIL: blkio parse" >&2; fails=$((fails+1)); }
    # Identical CPU, moving blkio: the slow-disk box that burns no CPU and is
    # nonetheless working. This is the sample the whole mechanism turns on.
    [ "$(proc_blkio_ticks_from_text "$st_a")" != "$(proc_blkio_ticks_from_text "$st_b")" ] ||
        { echo "FAIL: blocked-on-disk progress is invisible" >&2; fails=$((fails+1)); }
    [ "$(proc_cpu_ticks_from_text "")" = 0 ] || { echo "FAIL: empty stat" >&2; fails=$((fails+1)); }
    [ "$(proc_blkio_ticks_from_text "")" = 0 ] || { echo "FAIL: empty blkio" >&2; fails=$((fails+1)); }
    [ "$(proc_io_bytes_from_text 'rchar: 100
wchar: 20
read_bytes: 4096
write_bytes: 8192
cancelled_write_bytes: 999999')" = 12408 ] || { echo "FAIL: io parse" >&2; fails=$((fails+1)); }

    # ── state file: new format, and the legacy bare-verdict file ────────────
    local sandbox
    sandbox="$(mktemp -d "${TMPDIR:-/tmp}/zcl-hostwd-selftest.XXXXXX")"
    printf 'verdict=NODE-BUSY\nfrozen_streak=3\nunreachable_streak=4\ntoken=pid=7 cpu=1 blkio=2 io=3\n' \
        > "$sandbox/new"
    [ "$(state_get verdict "$sandbox/new")" = NODE-BUSY ] || { echo "FAIL: state verdict" >&2; fails=$((fails+1)); }
    [ "$(state_get frozen_streak "$sandbox/new")" = 3 ] || { echo "FAIL: state frozen" >&2; fails=$((fails+1)); }
    [ "$(state_get token "$sandbox/new")" = "pid=7 cpu=1 blkio=2 io=3" ] || { echo "FAIL: state token" >&2; fails=$((fails+1)); }
    printf 'OK\n' > "$sandbox/legacy"
    [ "$(state_get verdict "$sandbox/legacy")" = OK ] || { echo "FAIL: legacy state" >&2; fails=$((fails+1)); }
    [ -z "$(state_get frozen_streak "$sandbox/legacy")" ] || { echo "FAIL: legacy streak" >&2; fails=$((fails+1)); }
    [ -z "$(state_get verdict "$sandbox/absent")" ] || { echo "FAIL: absent state" >&2; fails=$((fails+1)); }

    # ── end-to-end cycle through the real seams ─────────────────────────────
    # A node that answers only on the third, most patient probe. The old code
    # gave this box one 5s chance and wrote NODE-DOWN.
    cat > "$sandbox/probe_late" <<'EOF'
#!/bin/sh
[ "$1" -ge 3 ]
EOF
    cat > "$sandbox/probe_never" <<'EOF'
#!/bin/sh
exit 1
EOF
    # Progress token that moves every call: a box blocked on a slow disk.
    cat > "$sandbox/progress_moving" <<'EOF'
#!/bin/sh
n=$(cat "$COUNTER" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$COUNTER"
echo "pid=9 cpu=0 blkio=$((n * 1000)) io=0"
EOF
    cat > "$sandbox/progress_frozen" <<'EOF'
#!/bin/sh
echo "pid=9 cpu=7 blkio=7 io=7"
EOF
    cat > "$sandbox/progress_gone" <<'EOF'
#!/bin/sh
exit 0
EOF
    cat > "$sandbox/manager_up" <<'EOF'
#!/bin/sh
exit 0
EOF
    chmod +x "$sandbox"/probe_late "$sandbox"/probe_never \
             "$sandbox"/progress_moving "$sandbox"/progress_frozen \
             "$sandbox"/progress_gone "$sandbox"/manager_up

    cycle() { # cycle <probe> <progress> <state> [counter]
        COUNTER="${4:-$sandbox/counter}" \
        ZCL_HOST_WATCHDOG_PROBE_HOOK="$1" \
        ZCL_HOST_WATCHDOG_PROGRESS_HOOK="$2" \
        ZCL_HOST_WATCHDOG_MANAGER_HOOK="$sandbox/manager_up" \
        ZCL_HOST_WATCHDOG_STATE="$3" \
        ZCL_HOST_WATCHDOG_LOG="$sandbox/log" \
        ZCL_HOST_WATCHDOG_PROBE_TIMEOUTS="1 1 1" \
        ZCL_HOST_WATCHDOG_DOWN_CYCLES=2 \
        ZCL_HOST_WATCHDOG_WEDGE_CYCLES=3 \
        ZCL_HOST_WATCHDOG_USER="$OPERATOR_USER" \
            bash "$SELF" 2>&1
    }
    expect_cycle() {
        local want="$1"; shift
        local out
        if ! out="$(cycle "$@")"; then
            printf '[host-watchdog-selftest] FAIL: cycle for %s exited nonzero: %s\n' \
                   "$want" "$out" >&2
            fails=$((fails + 1))
            return 0
        fi
        case "$out" in
            *"$want"*) printf '[host-watchdog-selftest] PASS: cycle -> %s\n' "$want" ;;
            *) printf '[host-watchdog-selftest] FAIL: cycle wanted %s, got: %s\n' \
                   "$want" "$out" >&2; fails=$((fails + 1)) ;;
        esac
    }
    rm -f "$sandbox/state1"
    expect_cycle NODE-SLOW "$sandbox/probe_late" "$sandbox/progress_moving" "$sandbox/state1"
    [ "$(state_get frozen_streak "$sandbox/state1")" = 0 ] ||
        { echo "FAIL: an answering node must have no frozen streak" >&2; fails=$((fails+1)); }

    # Unreachable but working: NODE-BUSY, twice, then the wedge name.
    rm -f "$sandbox/state2" "$sandbox/counter2"
    expect_cycle NODE-BUSY "$sandbox/probe_never" "$sandbox/progress_moving" "$sandbox/state2" "$sandbox/counter2"
    expect_cycle NODE-BUSY "$sandbox/probe_never" "$sandbox/progress_moving" "$sandbox/state2" "$sandbox/counter2"
    expect_cycle NODE-RPC-WEDGED "$sandbox/probe_never" "$sandbox/progress_moving" "$sandbox/state2" "$sandbox/counter2"

    # Frozen process. The FIRST cycle has no previous observation to compare,
    # so it must not convict: a watchdog that has never seen this node before
    # cannot know it is frozen, and opening with NODE-DOWN is exactly the
    # single-sample verdict being removed here.
    rm -f "$sandbox/state3"
    expect_cycle NODE-BUSY "$sandbox/probe_never" "$sandbox/progress_frozen" "$sandbox/state3"
    expect_cycle NODE-UNRESPONSIVE "$sandbox/probe_never" "$sandbox/progress_frozen" "$sandbox/state3"
    expect_cycle NODE-DOWN "$sandbox/probe_never" "$sandbox/progress_frozen" "$sandbox/state3"

    # Recovery clears the streaks rather than carrying a grudge.
    rm -f "$sandbox/state4"
    expect_cycle NODE-BUSY "$sandbox/probe_never" "$sandbox/progress_frozen" "$sandbox/state4"
    expect_cycle NODE-UNRESPONSIVE "$sandbox/probe_never" "$sandbox/progress_frozen" "$sandbox/state4"
    expect_cycle NODE-SLOW "$sandbox/probe_late" "$sandbox/progress_frozen" "$sandbox/state4"
    [ "$(state_get frozen_streak "$sandbox/state4")" = 0 ] ||
        { echo "FAIL: recovery did not clear the frozen streak" >&2; fails=$((fails+1)); }
    expect_cycle NODE-UNRESPONSIVE "$sandbox/probe_never" "$sandbox/progress_frozen" "$sandbox/state4"

    # No process at all: down on the first cycle, no waiting.
    rm -f "$sandbox/state5"
    expect_cycle NODE-DOWN "$sandbox/probe_never" "$sandbox/progress_gone" "$sandbox/state5"

    rm -rf "$sandbox"
    if [ "$fails" -eq 0 ]; then
        echo "host-watchdog-selftest: PASS"
        return 0
    fi
    echo "host-watchdog-selftest: FAIL ($fails case(s))" >&2
    return 1
}

SELF="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"

if [ "$MODE" = selftest ]; then
    watchdog_selftest
    exit $?
fi

if [ -n "$PROBE_HOOK" ] && [ -n "$PROGRESS_HOOK" ] &&
   [ -n "$MANAGER_HOOK" ]; then
    # A fully injected cycle is hermetic: none of its seams consults a real
    # user manager, so requiring the production account would make the
    # classifier selftest host-specific.
    uid=1
else
    uid="$(id -u "$OPERATOR_USER" 2>/dev/null || echo 0)"
fi
[ "$uid" -gt 0 ] || { echo "ERROR: cannot resolve uid for '$OPERATOR_USER'" >&2; exit 1; }

verdict="OK"
detail="user-manager=up"

if ! manager_alive; then
    detail="user-manager=DEAD"
    if [ "$MODE" = dry ]; then
        detail="$detail action=would-revive(enable-linger+ssh-localhost)"
    else
        loginctl enable-linger "$OPERATOR_USER" >/dev/null 2>&1 || true
        runuser -u "$OPERATOR_USER" -- ssh -o BatchMode=yes \
            -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 \
            localhost true >/dev/null 2>&1 || true
        sleep 3
        if manager_alive; then detail="$detail action=revived"
        else detail="$detail action=revive-attempted-still-dead"; fi
    fi
    verdict="REVIVED-USER-MANAGER"
fi

prev_verdict="$(state_get verdict "$STATE_FILE")"
prev_token="$(state_get token "$STATE_FILE")"
prev_frozen="$(state_get frozen_streak "$STATE_FILE")"
prev_unreachable="$(state_get unreachable_streak "$STATE_FILE")"
case "${prev_frozen:-}" in ''|*[!0-9]*) prev_frozen=0 ;; esac
case "${prev_unreachable:-}" in ''|*[!0-9]*) prev_unreachable=0 ;; esac

answered="$(probe_rpc)"
token="$(node_progress_token)"
exists=0
if [ -n "$token" ]; then
    exists=1
fi

# "Moved" is only meaningful against a previous observation. The first ever
# cycle has nothing to compare, so it is credited as moving: a watchdog must
# never open its life by declaring a node it has never seen before to be dead.
moved=0
if [ "$exists" -eq 1 ]; then
    if [ -z "$prev_token" ] || [ "$token" != "$prev_token" ]; then
        moved=1
    fi
fi

if [ "$answered" -eq 0 ]; then
    unreachable_streak=$((prev_unreachable + 1))
else
    unreachable_streak=0
fi
if [ "$exists" -eq 1 ] && [ "$moved" -eq 0 ] && [ "$answered" -eq 0 ]; then
    frozen_streak=$((prev_frozen + 1))
else
    frozen_streak=0
fi

node_verdict="$(classify_node "$answered" "$exists" "$moved" \
                              "$frozen_streak" "$unreachable_streak" \
                              "$DOWN_CYCLES" "$WEDGE_CYCLES")"

case "$node_verdict" in
    OK)   detail="$detail node=up probe=1/1" ;;
    NODE-SLOW)
        detail="$detail node=slow answered_on_probe=$answered budgets=[$PROBE_TIMEOUTS]" ;;
    NODE-BUSY)
        detail="$detail node=unreachable-but-working unreachable_cycles=$unreachable_streak progress=[$token]" ;;
    NODE-RPC-WEDGED)
        detail="$detail node=alive-and-progressing-but-unreachable unreachable_cycles=$unreachable_streak (>=$WEDGE_CYCLES) progress=[$token]" ;;
    NODE-UNRESPONSIVE)
        detail="$detail node=process-present-but-frozen frozen_cycles=$frozen_streak (<$DOWN_CYCLES) progress=[$token]" ;;
    NODE-DOWN)
        if [ "$exists" -eq 1 ]; then
            detail="$detail node=DOWN evidence=frozen_for_${frozen_streak}_cycles(>=$DOWN_CYCLES) last_progress=[$prev_token] now=[$token]"
        else
            detail="$detail node=DOWN evidence=no-canonical-node-process"
        fi
        ;;
esac

# The user-manager revive keeps precedence: it is the thing that was acted on.
if [ "$verdict" = "OK" ]; then
    verdict="$node_verdict"
elif [ "$node_verdict" != "OK" ]; then
    detail="$detail node_verdict=$node_verdict"
fi

if [ "$MODE" = dry ]; then
    echo "HOST-WATCHDOG: $verdict ($detail) [dry-run, prev=${prev_verdict:-(none)}, no side effects taken]"
    exit 0
fi

install -d -m755 "$(dirname "$LOG_FILE")" "$(dirname "$STATE_FILE")" 2>/dev/null || true
# A missing state file (first-ever run) is treated as a prior OK so a healthy
# first cycle stays quiet too — only a genuinely new failure or an actual
# transition writes a line. A slow-but-answering box logs its transition once
# and then goes quiet; only an alarming verdict repeats every cycle.
prev_for_log="${prev_verdict:-OK}"
if verdict_is_alarming "$verdict" || [ "$verdict" != "$prev_for_log" ]; then
    printf '%s HOST-WATCHDOG: %s (%s)\n' "$(date -u +%FT%TZ)" "$verdict" "$detail" >> "$LOG_FILE"
fi
echo "HOST-WATCHDOG: $verdict ($detail)"

{
    printf 'verdict=%s\n' "$verdict"
    printf 'frozen_streak=%s\n' "$frozen_streak"
    printf 'unreachable_streak=%s\n' "$unreachable_streak"
    printf 'token=%s\n' "$token"
} > "$STATE_FILE"
