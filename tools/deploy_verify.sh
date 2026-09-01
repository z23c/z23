#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Post-restart RPC health check for `make deploy`.
#
# The previous `make deploy` printed "Deployed." whenever systemd reported
# the unit active for >2s. That includes binaries that segfault on first
# RPC call. This script replaces that false-positive with a real probe:
# poll RPC every 2s and only succeed when the node answers with an integer
# height and the public-node hardening diagnostics are registered by the
# running daemon.
#
# ── Why there is no "deadline that means failure" any more ─────────────────
# This check used to answer "did the node get ready inside N seconds?", and
# that question has no honest answer: N encodes an assumption about the disk
# under the node. 120s false-FAILed a healthy deploy on 2026-06-10 and the
# bound was widened to 600s, which is the same defect with a bigger number —
# on a 7200rpm box a cold boot of a ~22 GB datadir (block-file scan + pprev
# repair + index reconcile) routinely runs far past ten minutes. Grading that
# box "DEPLOY FAILED" makes `make deploy` roll a perfectly good binary back,
# which is how a network quietly becomes SSD-only.
#
# The property the old deadline was standing in for is "is the candidate
# making progress?", and that is directly observable and costs nothing:
#
#   before RPC opens — /proc/<MainPID>/{io,stat}: bytes moved, CPU ticks
#                      burned, and delayacct_blkio_ticks, which climbs
#                      precisely while the process is BLOCKED on a slow disk.
#   after  RPC opens — the reported height, plus the sticky per-class
#                      verification receipts. A node catching up legitimately
#                      fails `healthy` while its height climbs.
#
# A wedge is SILENCE, not slowness. So the only failure clock is time spent
# with none of those observables changing, and the window is a REPORTING
# window: when it expires while the node is still advancing, that is reported
# as its own outcome and is NOT a failure.
#
# Exit codes:
#   0  — RPC live, block count observed, diagnostic contract present
#   1  — real fault: the candidate stopped making observable progress (or its
#        process did not stay up). Never returned merely because time passed.
#   2  — identity inputs or canonical service binding are malformed
#   3  — UNVERIFIED, STILL PROGRESSING: the reporting window expired while the
#        node was demonstrably still advancing. Not a failure, not a success;
#        `make deploy` leaves the candidate installed and does NOT roll back.
#        Re-run this script, or set ZCL_DEPLOY_VERIFY_WAIT=1, to keep watching.
#
# Knobs:
#   ZCL_DEPLOY_VERIFY_TIMEOUT   reporting window, seconds (default 600)
#   ZCL_DEPLOY_VERIFY_SILENCE   observed silence that means fault (default 300)
#   ZCL_DEPLOY_VERIFY_WAIT=1    never exit 3; wait until ready or silent
#
# Deployment acceptance always requires both environment variables:
#   ZCL_DEPLOY_EXPECT_SOURCE_ID=<64 lowercase hex>
#   ZCL_DEPLOY_EXPECT_ARTIFACT_SHA256=<64 lowercase hex>
# Usage: ./tools/deploy_verify.sh [rpc_tool] [timeout_seconds]
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tools/scripts/source_identity_lib.sh
. "$SCRIPT_DIR/scripts/source_identity_lib.sh"  # zcl_healthcheck_v1_running_source_id, zcl_is_sha256

# The ONE question this script is allowed to ask about source identity:
# "what source tree was the RUNNING daemon's own executable built from?"
# That is a property of the executable behind /proc/<MainPID>/exe, baked in at
# compile time, and it is the same value no matter which directory anything
# here runs from. It is emphatically NOT "what source tree is in the current
# checkout" — a cwd-derived answer would look current on a box whose daemon is
# months stale, which is precisely how a deploy check passes a stale binary.
# See the TWO QUESTIONS block at the top of source_identity_lib.sh.
#
# The reader binds the healthcheck schema and refuses a payload that carries
# two different values under `source_id_sha256`, so this can never silently
# start comparing a working-tree identity. Empty output means "the daemon did
# not state an unambiguous identity", and every caller below treats that as
# STALE DEPLOY, never as a pass.
running_daemon_baked_source_id() {
    zcl_healthcheck_v1_running_source_id "$1"
}

RPC_TOOL="${1:-./build/bin/zclassic-cli}"
# REPORTING window, not a failure window. See the header: expiry while the
# candidate is still advancing exits 3, never 1.
TIMEOUT="${2:-${ZCL_DEPLOY_VERIFY_TIMEOUT:-600}}"
# The one clock that can call a fault: consecutive seconds during which NOTHING
# observable about the candidate changed. Deliberately large relative to any
# honest slow-disk step, because its job is to catch a wedge, not a slow box.
SILENCE_LIMIT="${ZCL_DEPLOY_VERIFY_SILENCE:-300}"
WAIT_FOREVER="${ZCL_DEPLOY_VERIFY_WAIT:-0}"
RPC_CALL_TIMEOUT="${ZCL_DEPLOY_RPC_TIMEOUT:-20}"
INTERVAL=2
RPC_CONNECT="127.0.0.1"
DEPLOY_STAGE="${ZCL_DEPLOY_STAGE:-stable}"

case "$DEPLOY_STAGE" in
    stable|challenger|rollback) ;;
    *)
        echo "deploy_verify: FATAL — ZCL_DEPLOY_STAGE must be stable, challenger, or rollback" >&2
        exit 2
        ;;
esac

# Parse only the explicit -key=value argv form accepted by the service. Values
# containing whitespace are deliberately unsupported: guessing across a quoted
# systemd command line would make endpoint binding ambiguous.
exec_arg_values_from_text() {
    parse_key="$1"
    parse_text="$2"
    printf '%s\n' "$parse_text" |
        tr ' ' '\n' |
        sed -n "s/^-${parse_key}=//p"
}

exec_path_values_from_text() {
    printf '%s\n' "$1" |
        tr ' ' '\n' |
        sed -n 's/^path=//p'
}

exec_argv_values_from_text() {
    # `systemctl show -p ExecStart --value` renders one command as:
    #   { path=/zcl-nodectl ; argv[]=/zcl-nodectl launch /node <args> ; ... }
    # Canonical paths contain no whitespace (the same constraint already used
    # by exec_arg_values_from_text), so split only the argv[] segment.
    printf '%s\n' "$1" |
        sed -n 's/^.*argv\[\]=\([^;]*\);.*$/\1/p' |
        tr ' ' '\n' |
        awk 'NF { print }'
}

single_value_or_empty() {
    single_values="$1"
    single_count=$(printf '%s\n' "$single_values" |
        awk 'NF { count++ } END { print count + 0 }')
    [ "$single_count" -le 1 ] || return 1
    printf '%s\n' "$single_values" | awk 'NF { print; exit }'
}

select_bound_value() {
    bound_exec="$1"
    bound_proc="$2"
    bound_default="$3"
    if [ -n "$bound_exec" ] && [ -n "$bound_proc" ] &&
       [ "$bound_exec" != "$bound_proc" ]; then
        return 1
    fi
    if [ -n "$bound_proc" ]; then
        printf '%s\n' "$bound_proc"
    elif [ -n "$bound_exec" ]; then
        printf '%s\n' "$bound_exec"
    else
        printf '%s\n' "$bound_default"
    fi
}

proc_start_ticks_from_text() {
    printf '%s\n' "$1" |
        sed 's/^[0-9][0-9]* (.*) //' |
        awk 'NF >= 20 && !seen { print $20; seen = 1 }'
}

proc_start_ticks() {
    proc_start_ticks_from_text "$(cat "/proc/$1/stat" 2>/dev/null || true)"
}

# ── observable progress, read from /proc only ───────────────────────────────
# These are pure text parsers so the selftest can pin them without a live node.
# Field numbering is post-`sed`: "pid (comm) " is stripped first, so the kernel
# proc(5) fields shift down by two — utime(14)/stime(15) become $12/$13 and
# delayacct_blkio_ticks(42) becomes $40, matching proc_start_ticks above.
proc_io_bytes_from_text() {
    printf '%s\n' "$1" |
        awk '/^(rchar|wchar|read_bytes|write_bytes):[ \t]*[0-9]+$/ { total += $2 }
             END { printf "%.0f\n", total + 0 }'
}

proc_cpu_ticks_from_text() {
    printf '%s\n' "$1" |
        sed 's/^[0-9][0-9]* (.*) //' |
        awk 'NF >= 13 && !seen { printf "%.0f\n", $12 + $13; seen = 1 }
             END { if (!seen) print 0 }'
}

# delayacct_blkio_ticks is the signal that makes a slow disk legible: it climbs
# while the process is BLOCKED waiting on I/O, i.e. exactly when a 7200rpm box
# is doing honest work and burning almost no CPU. A node wedged on a lock moves
# neither this nor CPU; that difference is the whole verdict.
proc_blkio_ticks_from_text() {
    printf '%s\n' "$1" |
        sed 's/^[0-9][0-9]* (.*) //' |
        awk 'NF >= 40 && !seen { printf "%.0f\n", $40; seen = 1 }
             END { if (!seen) print 0 }'
}

# progress_verdict <previous-token> <current-token> -> advancing | silent
# The ONLY thing that may call a fault is `silent`, sustained for SILENCE_LIMIT.
progress_verdict() {
    if [ "$1" = "$2" ]; then
        echo silent
    else
        echo advancing
    fi
}

# window_outcome <advances-seen> <silent-for> <silence-limit>
#   -> fault | unverified_progressing | unverified_unobserved
#
# What the expiry of the REPORTING window means. Expiry alone decides nothing.
# A fault requires PROVEN silence — the full silence limit with no observable
# change — and nothing else may produce it. If the window is shorter than the
# silence limit and nothing has been observed to move yet, neither verdict has
# been earned, and saying so is the honest third answer rather than picking the
# convenient one. A hang and a slow-but-healthy box never share an exit code.
window_outcome() {
    if [ "$2" -ge "$3" ]; then
        echo fault
    elif [ "$1" -gt 0 ]; then
        echo unverified_progressing
    else
        echo unverified_unobserved
    fi
}

# chain_tip_from_text <getblockchaininfo output> -> at_tip | behind | unknown
#
# Post-RPC silence has one honest innocent explanation the /proc counters
# cannot see: the node caught up with the network and went idle. Its height
# token freezes by design when no block arrives, and an idle synced node burns
# no io/cpu/blkio either — byte-for-byte the same /proc shape as a wedge. The
# signature that separates them is getblockchaininfo's headers vs blocks:
# equal means the node knows every header the network has and is merely
# waiting for the next block. Parsed as plain text so the selftest can pin it
# without a live node, in the same spirit as the /proc parsers above. Anything
# that does not parse as two integers — an RPC timeout, an error envelope, an
# empty answer — is `unknown`, which never green-lights anything.
chain_tip_from_text() {
    chain_tip_headers=$(printf '%s\n' "$1" |
        sed -n 's/.*"headers"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' |
        head -1)
    chain_tip_blocks=$(printf '%s\n' "$1" |
        sed -n 's/.*"blocks"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' |
        head -1)
    if [ -n "$chain_tip_headers" ] && [ -n "$chain_tip_blocks" ]; then
        if [ "$chain_tip_headers" -eq "$chain_tip_blocks" ]; then
            echo at_tip
        else
            echo behind
        fi
    else
        echo unknown
    fi
}

service_pid_is_stable() {
    stable_pid=$(systemctl --user show zclassic23 -p MainPID --value 2>/dev/null || true)
    [ "$stable_pid" = "$SERVICE_MAIN_PID" ] || return 1
    stable_ticks=$(proc_start_ticks "$SERVICE_MAIN_PID" || true)
    [ -n "$stable_ticks" ] && [ "$stable_ticks" = "$SERVICE_START_TICKS" ] || return 1
    stable_exe=$(readlink -f "/proc/$SERVICE_MAIN_PID/exe" 2>/dev/null || true)
    [ -n "$stable_exe" ] && [ "$stable_exe" = "$SERVICE_EXE" ]
}

proc_exec_arg_values() {
    proc_key="$1"
    tr '\000' '\n' < "/proc/$SERVICE_MAIN_PID/cmdline" |
        sed -n "s/^-${proc_key}=//p"
}

# Classify the subversion a running node advertises. Since
# core/modules/net/include/net/version.h, a node states which build it is running by
# appending its baked source prefix: "/ZClassic23:0.1.0(src:<12 hex>)/".
# An unstamped build publishes the bare "/ZClassic23:0.1.0/" instead, and that
# is a normal answer, never a deploy failure. The one failure this can see is
# a node advertising a build that is NOT the one we just deployed.
# Echoes exactly one of: deployed | unstamped | stale | foreign.
advertised_subver_verdict() {
    adv_subver="$1"
    adv_want="$2"
    adv_want_prefix=$(printf '%.12s' "$adv_want")
    if [ "$adv_subver" = "/ZClassic23:0.1.0/" ]; then
        echo unstamped
        return 0
    fi
    if [ "$adv_subver" = "/ZClassic23:0.1.0(src:$adv_want_prefix)/" ] ||
       [ "$adv_subver" = "/ZClassic23:0.1.0(src:$adv_want)/" ]; then
        echo deployed
        return 0
    fi
    adv_id=$(printf '%s\n' "$adv_subver" |
        sed -n 's|^/ZClassic23:0\.1\.0(src:\([0-9a-f]\{12\}\))/$|\1|p')
    if [ -z "$adv_id" ]; then
        adv_id=$(printf '%s\n' "$adv_subver" |
            sed -n 's|^/ZClassic23:0\.1\.0(src:\([0-9a-f]\{64\}\))/$|\1|p')
    fi
    if [ -n "$adv_id" ]; then
        echo stale
        return 0
    fi
    echo foreign
}

deploy_verify_selftest() {
    # Hostile inherited lane selectors must have no role in the result.
    ZCL_DATADIR="/attacker/datadir"
    ZCL_RPCPORT="1"
    ZCL_RPCCONNECT="attacker.invalid"
    fixture_exec='{ path=/canonical/bin/zcl-nodectl ; argv[]=/canonical/bin/zcl-nodectl launch /canonical/bin/z23 -datadir=/canonical/data -rpcport=18232 ; }'
    fixture_datadirs=$(exec_arg_values_from_text datadir "$fixture_exec")
    fixture_ports=$(exec_arg_values_from_text rpcport "$fixture_exec")
    fixture_datadir=$(single_value_or_empty "$fixture_datadirs") || return 1
    fixture_port=$(single_value_or_empty "$fixture_ports") || return 1
    fixture_bound_datadir=$(select_bound_value "$fixture_datadir" "/canonical/data" "/default") || return 1
    fixture_bound_port=$(select_bound_value "$fixture_port" "18232" "9") || return 1
    [ "$fixture_bound_datadir" = "/canonical/data" ] || return 1
    [ "$fixture_bound_port" = "18232" ] || return 1
    [ "$RPC_CONNECT" = "127.0.0.1" ] || return 1
    if select_bound_value "/one" "/two" "/default" >/dev/null; then
        return 1
    fi
    duplicate_values=$(printf '/one\n/two\n')
    if single_value_or_empty "$duplicate_values" >/dev/null; then
        return 1
    fi
    fixture_paths=$(exec_path_values_from_text "$fixture_exec")
    [ "$(single_value_or_empty "$fixture_paths")" = "/canonical/bin/zcl-nodectl" ] || return 1
    fixture_argv=$(exec_argv_values_from_text "$fixture_exec")
    [ "$(printf '%s\n' "$fixture_argv" | sed -n '1p')" = "/canonical/bin/zcl-nodectl" ] || return 1
    [ "$(printf '%s\n' "$fixture_argv" | sed -n '2p')" = "launch" ] || return 1
    [ "$(printf '%s\n' "$fixture_argv" | sed -n '3p')" = "/canonical/bin/z23" ] || return 1
    fixture_direct='{ path=/canonical/bin/zclassic23 ; argv[]=/canonical/bin/zclassic23 -datadir=/canonical/data -rpcport=18232 ; }'
    fixture_direct_paths=$(exec_path_values_from_text "$fixture_direct")
    [ "$(single_value_or_empty "$fixture_direct_paths")" = "/canonical/bin/zclassic23" ] || return 1
    fixture_direct_argv=$(exec_argv_values_from_text "$fixture_direct")
    [ "$(printf '%s\n' "$fixture_direct_argv" | sed -n '1p')" = "/canonical/bin/zclassic23" ] || return 1
    [ "$(printf '%s\n' "$fixture_direct_argv" | sed -n '2p')" = "-datadir=/canonical/data" ] || return 1
    # Published build identity. Both native forms must be accepted — a build
    # that carries no baked identity publishes the bare product string, and
    # refusing it here would turn "unknown" into a failure. The one refusal is
    # a well-formed token naming a build other than the deployed one.
    sv_want=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    sv_other=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
    [ "$(advertised_subver_verdict "/ZClassic23:0.1.0(src:0123456789ab)/" \
        "$sv_want")" = deployed ] || return 1
    [ "$(advertised_subver_verdict "/ZClassic23:0.1.0(src:$sv_want)/" \
        "$sv_want")" = deployed ] || return 1
    [ "$(advertised_subver_verdict "/ZClassic23:0.1.0/" "$sv_want")" \
        = unstamped ] || return 1
    [ "$(advertised_subver_verdict "/ZClassic23:0.1.0(src:fedcba987654)/" \
        "$sv_want")" = stale ] || return 1
    [ "$(advertised_subver_verdict "/ZClassic23:0.1.0(src:$sv_other)/" \
        "$sv_want")" = stale ] || return 1
    [ "$(advertised_subver_verdict "/MagicBean:2.1.2/" "$sv_want")" \
        = foreign ] || return 1
    [ "$(advertised_subver_verdict "" "$sv_want")" = foreign ] || return 1

    # The freshness reader must answer Q1 (the running executable's baked
    # identity) and must refuse rather than guess when a payload offers a
    # second, different value under the same key.
    selftest_baked="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    selftest_worktree="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    # Shape of the real payload: the baked value at the top level, repeated
    # verbatim inside the nested agent block, with runtime_build using its own
    # distinct running_/expected_ names.
    selftest_health='{"schema":"zcl.healthcheck.v1","api_version":"v1","status":"ok","source_id_sha256":"'"$selftest_baked"'","runtime_build":{"running_source_id_sha256":"'"$selftest_baked"'","expected_source_id_sha256":"'"$selftest_worktree"'"},"agent":{"source_id_sha256":"'"$selftest_baked"'"}}'
    [ "$(running_daemon_baked_source_id "$selftest_health")" = "$selftest_baked" ] || return 1
    # The RPC tool may hand back the whole JSON-RPC envelope. Refusing that
    # would fail a FRESH deploy, so the reader must see through it.
    selftest_wrapped='{"result":'"$selftest_health"',"error":null,"id":1}'
    [ "$(running_daemon_baked_source_id "$selftest_wrapped")" = "$selftest_baked" ] || return 1
    if zcl_json_sha256_is_ambiguous "$selftest_health" source_id_sha256; then
        return 1
    fi
    # A nested working-tree (Q2) value published under the SAME key makes the
    # document ambiguous: refuse, do not fall back to a positional pick.
    selftest_conflicted='{"schema":"zcl.healthcheck.v1","api_version":"v1","status":"ok","source_id_sha256":"'"$selftest_baked"'","lane":{"source_id_sha256":"'"$selftest_worktree"'"}}'
    zcl_json_sha256_is_ambiguous "$selftest_conflicted" source_id_sha256 || return 1
    [ -z "$(running_daemon_baked_source_id "$selftest_conflicted")" ] || return 1
    # Wrong schema is not a healthcheck and states nothing about the daemon.
    selftest_foreign='{"schema":"zcl.agent_build.v2","api_version":"v1","status":"ok","source_id_sha256":"'"$selftest_baked"'"}'
    [ -z "$(running_daemon_baked_source_id "$selftest_foreign")" ] || return 1

    # ── progress observables: a slow box must be legible as SLOW, never DOWN ──
    # /proc/<pid>/io — every counted field summed, unknown lines ignored.
    selftest_io='rchar: 100
wchar: 20
syscr: 7
syscw: 3
read_bytes: 4096
write_bytes: 8192
cancelled_write_bytes: 999999'
    [ "$(proc_io_bytes_from_text "$selftest_io")" = "12408" ] || return 1
    # A kernel without task IO accounting yields no readable payload; that must
    # be 0 rather than empty, so the token stays comparable.
    [ "$(proc_io_bytes_from_text "")" = "0" ] || return 1

    # /proc/<pid>/stat with a comm containing spaces and parentheses — the
    # exact shape that makes positional parsing wrong if the prefix is not
    # stripped first. utime=11 stime=22 -> 33; delayacct_blkio_ticks=777.
    selftest_stat="4242 (z23 node) S 1 4242 4242 0 -1 4194560 100 0 0 0 11 22 0 0 20 0 9 0 987654 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 777 0 0"
    [ "$(proc_cpu_ticks_from_text "$selftest_stat")" = "33" ] || return 1
    [ "$(proc_blkio_ticks_from_text "$selftest_stat")" = "777" ] || return 1
    [ "$(proc_start_ticks_from_text "$selftest_stat")" = "987654" ] || return 1

    # A comm containing ')'. The kernel permits it, and a non-greedy strip
    # stops at the FIRST ')' and shifts every field after it. blkio then reads
    # 0 — which is not merely wrong, it is indistinguishable from "made no
    # progress", so a healthy box blocked on a slow platter gets convicted as
    # WEDGED and rolled back. comm is the LAST parenthesised group in
    # /proc/<pid>/stat, so the strip must be greedy. Measured before the fix:
    # this returned 0 instead of 777.
    selftest_paren_stat="4242 (z23) node) S 1 4242 4242 0 -1 4194560 100 0 0 0 11 22 0 0 20 0 9 0 987654 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 777 0 0"
    [ "$(proc_blkio_ticks_from_text "$selftest_paren_stat")" = "777" ] || return 1
    [ "$(proc_cpu_ticks_from_text "$selftest_paren_stat")" = "33" ] || return 1
    [ "$(proc_start_ticks_from_text "$selftest_paren_stat")" = "987654" ] || return 1
    [ "$(proc_cpu_ticks_from_text "")" = "0" ] || return 1
    [ "$(proc_blkio_ticks_from_text "")" = "0" ] || return 1

    # THE CASE THIS WHOLE MECHANISM EXISTS FOR: a box that burns no CPU and
    # answers no RPC, but whose blkio ticks climb, is making progress. Under a
    # duration-only verdict it was indistinguishable from a wedge.
    selftest_blocked_a="1 (z23 node) S 1 1 1 0 -1 0 0 0 0 0 5 5 0 0 20 0 9 0 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1000 0 0"
    selftest_blocked_b="1 (z23 node) S 1 1 1 0 -1 0 0 0 0 0 5 5 0 0 20 0 9 0 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 4000 0 0"
    selftest_slow_a="io=0 cpu=$(proc_cpu_ticks_from_text "$selftest_blocked_a") blkio=$(proc_blkio_ticks_from_text "$selftest_blocked_a")"
    selftest_slow_b="io=0 cpu=$(proc_cpu_ticks_from_text "$selftest_blocked_b") blkio=$(proc_blkio_ticks_from_text "$selftest_blocked_b")"
    [ "$(progress_verdict "$selftest_slow_a" "$selftest_slow_b")" = advancing ] || return 1
    # A genuinely wedged process repeats its token byte for byte.
    [ "$(progress_verdict "$selftest_slow_a" "$selftest_slow_a")" = silent ] || return 1

    # After RPC opens, the observables change: a node whose height climbs while
    # `healthy` is still false is CATCHING UP, not broken.
    [ "$(progress_verdict "height=100 receipts=11000" "height=101 receipts=11000")" = advancing ] || return 1
    # Contract convergence is progress too, even at a frozen height.
    [ "$(progress_verdict "height=100 receipts=11000" "height=100 receipts=11100")" = advancing ] || return 1
    # Neither moving is the only shape that may ever be called a fault.
    [ "$(progress_verdict "height=100 receipts=11000" "height=100 receipts=11000")" = silent ] || return 1

    # ── the window-expiry classifier ────────────────────────────────────────
    # THE CASE THE OLD 600s BOUND GOT WRONG: the window expired while the box
    # was still advancing. That must not be a failure.
    [ "$(window_outcome 42 4 300)" = unverified_progressing ] || return 1
    # Even one observed advance is enough; slowness is not evidence of a wedge.
    [ "$(window_outcome 1 299 300)" = unverified_progressing ] || return 1
    # A fault requires PROVEN silence — the full limit with nothing moving.
    [ "$(window_outcome 0 300 300)" = fault ] || return 1
    [ "$(window_outcome 99 301 300)" = fault ] || return 1
    # A window shorter than the silence limit has earned NEITHER verdict.
    [ "$(window_outcome 0 60 300)" = unverified_unobserved ] || return 1

    # ── the idle-tip discriminator ──────────────────────────────────────────
    # THE CASE THE SILENCE CONVICTION GOT WRONG (seen live twice on
    # 2026-08-29): a synced node at the network tip freezes its height token
    # by design, and its /proc counters go quiet — byte-for-byte the token
    # shape of a wedge. headers==blocks is the signature of an idle tip.
    selftest_tip='{"result":{"chain":"main","blocks":3232594,"headers":3232594,"best_header_height":3232594,"verificationprogress":1}}'
    [ "$(chain_tip_from_text "$selftest_tip")" = at_tip ] || return 1
    # A catch-up node knows more headers than it has blocks: still moving, or
    # a stuck catch-up — either way NOT eligible for the idle-tip acquittal.
    selftest_behind='{"result":{"chain":"main","blocks":3232500,"headers":3232594,"best_header_height":3232594,"verificationprogress":0.999}}'
    [ "$(chain_tip_from_text "$selftest_behind")" = behind ] || return 1
    # Anything unparseable is unknown, and unknown never green-lights: an RPC
    # timeout, an error envelope, or a dead surface must take the conviction
    # path unchanged.
    [ "$(chain_tip_from_text "")" = unknown ] || return 1
    [ "$(chain_tip_from_text "error: connection refused")" = unknown ] || return 1
    # The adjacent key best_header_height must not be mistaken for headers,
    # and initialblockdownload must not satisfy "blocks".
    selftest_trapkeys='{"initialblockdownload":false,"best_header_height":77,"blocks":50,"headers":50}'
    [ "$(chain_tip_from_text "$selftest_trapkeys")" = at_tip ] || return 1

    echo "deploy_verify selftest: PASS"
}

if [ "${ZCL_DEPLOY_VERIFY_SELFTEST:-0}" = "1" ]; then
    deploy_verify_selftest || {
        echo "deploy_verify selftest: FAIL" >&2
        exit 1
    }
    exit 0
fi

fatal_binding() {
    echo "deploy_verify: FATAL — $*" >&2
    exit 2
}

# Operational freshness is exact and SHA-1-independent. `make deploy` passes
# the baked source-tree SHA-256 plus the SHA-256 of the installed executable.
# build_commit remains optional GitHub trace metadata and is never compared.
EXPECT_SOURCE_ID="${ZCL_DEPLOY_EXPECT_SOURCE_ID:-}"
EXPECT_ARTIFACT_SHA256="${ZCL_DEPLOY_EXPECT_ARTIFACT_SHA256:-}"

if ! zcl_is_sha256 "$EXPECT_SOURCE_ID"; then
    fatal_binding "ZCL_DEPLOY_EXPECT_SOURCE_ID must be 64 lowercase hex"
fi
if ! zcl_is_sha256 "$EXPECT_ARTIFACT_SHA256"; then
    fatal_binding "ZCL_DEPLOY_EXPECT_ARTIFACT_SHA256 must be 64 lowercase hex"
fi

if [ ! -x "$RPC_TOOL" ]; then
    alt="./build/bin/zcl-rpc"
    if [ -x "$alt" ]; then
        RPC_TOOL="$alt"
    fi
fi

case "$(basename "$RPC_TOOL")" in
    zclassic-cli|zcl-rpc) ;;
    *) fatal_binding "RPC tool must be zclassic-cli or zcl-rpc so its endpoint can be forced" ;;
esac

command -v systemctl >/dev/null 2>&1 ||
    fatal_binding "systemctl is required to bind proof to the canonical service"
SERVICE_MAIN_PID=$(systemctl --user show zclassic23 -p MainPID --value 2>/dev/null || true)
case "$SERVICE_MAIN_PID" in
    ''|*[!0-9]*|0) fatal_binding "canonical zclassic23 service has no MainPID" ;;
esac
[ -r "/proc/$SERVICE_MAIN_PID/cmdline" ] &&
[ -r "/proc/$SERVICE_MAIN_PID/stat" ] &&
[ -e "/proc/$SERVICE_MAIN_PID/exe" ] ||
    fatal_binding "canonical MainPID $SERVICE_MAIN_PID is not inspectable"

SERVICE_START_TICKS=$(proc_start_ticks "$SERVICE_MAIN_PID" || true)
[ -n "$SERVICE_START_TICKS" ] ||
    fatal_binding "canonical MainPID $SERVICE_MAIN_PID has no stable start identity"
SERVICE_EXE=$(readlink -f "/proc/$SERVICE_MAIN_PID/exe" 2>/dev/null || true)
[ -n "$SERVICE_EXE" ] ||
    fatal_binding "canonical MainPID $SERVICE_MAIN_PID executable cannot be resolved"
SERVICE_EXEC_TEXT=$(systemctl --user show zclassic23 -p ExecStart --value 2>/dev/null || true)
[ -n "$SERVICE_EXEC_TEXT" ] || fatal_binding "canonical service ExecStart is unavailable"
SERVICE_EXEC_PATH_VALUES=$(exec_path_values_from_text "$SERVICE_EXEC_TEXT")
SERVICE_EXEC_PATH=$(single_value_or_empty "$SERVICE_EXEC_PATH_VALUES") ||
    fatal_binding "canonical service ExecStart has an ambiguous executable path"
case "$SERVICE_EXEC_PATH" in
    /*) ;;
    *) fatal_binding "canonical service ExecStart executable path is not absolute" ;;
esac
SERVICE_LAUNCHER_EXE=$(readlink -f "$SERVICE_EXEC_PATH" 2>/dev/null || true)
[ -n "$SERVICE_LAUNCHER_EXE" ] ||
    fatal_binding "canonical service launcher cannot be resolved"
SERVICE_ARGV_VALUES=$(exec_argv_values_from_text "$SERVICE_EXEC_TEXT")
SERVICE_ARGV0=$(printf '%s\n' "$SERVICE_ARGV_VALUES" | sed -n '1p')
SERVICE_NODE_ARG=$(printf '%s\n' "$SERVICE_ARGV_VALUES" | sed -n '2p')
[ -n "$SERVICE_ARGV0" ] ||
    fatal_binding "canonical service ExecStart must name an executable argv"
case "$SERVICE_ARGV0" in
    /*) ;;
    *) fatal_binding "canonical service executable argv is not absolute" ;;
esac
SERVICE_ARGV0_EXE=$(readlink -f "$SERVICE_ARGV0" 2>/dev/null || true)
[ -n "$SERVICE_ARGV0_EXE" ] &&
[ "$SERVICE_ARGV0_EXE" = "$SERVICE_LAUNCHER_EXE" ] ||
    fatal_binding "canonical service path and executable argv disagree"

if [ "$(basename "$SERVICE_LAUNCHER_EXE")" = "zcl-nodectl" ]; then
    [ "$SERVICE_NODE_ARG" = "launch" ] ||
        fatal_binding "canonical zcl-nodectl launcher must use the launch subcommand"
    SERVICE_NODE_ARG=$(printf '%s\n' "$SERVICE_ARGV_VALUES" | sed -n '3p')
fi

# Accept both canonical unit forms while preserving an exact executable bind:
#
#   direct:   ExecStart=/absolute/zclassic23 <flags>
#   launcher: ExecStart=/absolute/zcl-nodectl launch /absolute/z23 <flags>
#
# In direct mode argv[1] is normally the first flag, not another executable.
# A launcher is only accepted when its explicit node argument resolves to the
# executable owned by the stable MainPID captured above.
if [ "$SERVICE_LAUNCHER_EXE" = "$SERVICE_EXE" ]; then
    SERVICE_NODE_EXE="$SERVICE_LAUNCHER_EXE"
else
    [ -n "$SERVICE_NODE_ARG" ] ||
        fatal_binding "canonical launcher must name the node binary"
    case "$SERVICE_NODE_ARG" in
        /*) ;;
        *) fatal_binding "canonical launcher node binary argv is not absolute" ;;
    esac
    SERVICE_NODE_EXE=$(readlink -f "$SERVICE_NODE_ARG" 2>/dev/null || true)
    [ -n "$SERVICE_NODE_EXE" ] && [ "$SERVICE_NODE_EXE" = "$SERVICE_EXE" ] ||
        fatal_binding "canonical MainPID executable does not match launcher node binary"
fi

EXEC_DATADIR_VALUES=$(exec_arg_values_from_text datadir "$SERVICE_EXEC_TEXT")
EXEC_RPCPORT_VALUES=$(exec_arg_values_from_text rpcport "$SERVICE_EXEC_TEXT")
PROC_DATADIR_VALUES=$(proc_exec_arg_values datadir)
PROC_RPCPORT_VALUES=$(proc_exec_arg_values rpcport)
EXEC_DATADIR=$(single_value_or_empty "$EXEC_DATADIR_VALUES") ||
    fatal_binding "canonical service ExecStart has duplicate -datadir values"
EXEC_RPCPORT=$(single_value_or_empty "$EXEC_RPCPORT_VALUES") ||
    fatal_binding "canonical service ExecStart has duplicate -rpcport values"
PROC_DATADIR=$(single_value_or_empty "$PROC_DATADIR_VALUES") ||
    fatal_binding "canonical MainPID has duplicate -datadir values"
PROC_RPCPORT=$(single_value_or_empty "$PROC_RPCPORT_VALUES") ||
    fatal_binding "canonical MainPID has duplicate -rpcport values"
[ -n "$EXEC_DATADIR" ] && [ -n "$EXEC_RPCPORT" ] ||
    fatal_binding "canonical service ExecStart must set -datadir and -rpcport"
[ -n "$PROC_DATADIR" ] && [ -n "$PROC_RPCPORT" ] ||
    fatal_binding "canonical MainPID argv must set -datadir and -rpcport"
RPC_DATADIR=$(select_bound_value "$EXEC_DATADIR" "$PROC_DATADIR" "") ||
    fatal_binding "canonical ExecStart/MainPID -datadir values disagree"
RPCPORT=$(select_bound_value "$EXEC_RPCPORT" "$PROC_RPCPORT" "") ||
    fatal_binding "canonical ExecStart/MainPID -rpcport values disagree"
case "$RPC_DATADIR" in
    /*) ;;
    *) fatal_binding "canonical RPC datadir is not absolute" ;;
esac
case "$RPCPORT" in
    ''|*[!0-9]*) fatal_binding "canonical RPC port is not numeric" ;;
esac
[ "$RPCPORT" -ge 1 ] && [ "$RPCPORT" -le 65535 ] ||
    fatal_binding "canonical RPC port is outside 1..65535"
service_pid_is_stable || fatal_binding "canonical MainPID changed during endpoint capture"

# Never permit an inherited shell lane to redirect any part of this proof.
unset ZCL_DATADIR ZCL_RPCPORT ZCL_RPCCONNECT

rpc_exec() {
    rc=0
    if command -v timeout >/dev/null 2>&1; then
        timeout "${RPC_CALL_TIMEOUT}s" "$@" || rc=$?
        if [ "$rc" -eq 124 ]; then
            echo "rpc timed out after ${RPC_CALL_TIMEOUT}s: $*" >&2
        fi
    else
        "$@" || rc=$?
    fi
    return "$rc"
}

rpc_call() {
    name=$(basename "$RPC_TOOL")
    case "$name" in
        zclassic-cli)
            rpc_exec "$RPC_TOOL" "-datadir=$RPC_DATADIR" "-rpcport=$RPCPORT" \
                "-rpcconnect=$RPC_CONNECT" "$@"
            ;;
        zcl-rpc)
            rpc_exec env "ZCL_DATADIR=$RPC_DATADIR" "ZCL_RPCPORT=$RPCPORT" \
                "ZCL_RPCCONNECT=$RPC_CONNECT" "$RPC_TOOL" "$@"
            ;;
        *) return 2 ;;
    esac
}

START_TS=$(date +%s)
deadline=$(( START_TS + TIMEOUT ))
attempt=0
last_err=""
chain_advance_verified=0
chain_evidence_verified=0
network_verified=0
peer_lifecycle_verified=0
legacy_mirror_verified=0
RPC_READY=0
LAST_HEIGHT=none

# The composed observable this script watches instead of a clock. It reports
# two different regimes because the honest evidence differs between them, and
# collapsing them would put a booting box and a broken contract under one
# verdict:
#
#   RPC_READY=0 — the node has not answered yet. Only the kernel can say
#                 whether it is working: bytes moved, CPU burned, and ticks
#                 spent BLOCKED on the disk. On a 7200rpm box the third of
#                 those is usually the only one moving, and it is enough.
#   RPC_READY=1 — the node is up, so "slow" no longer explains a failing
#                 contract. Progress is now the height it serves plus the
#                 sticky per-class receipts below; a node catching up
#                 legitimately fails `healthy` while its height climbs.
progress_token() {
    if [ "$RPC_READY" -eq 1 ]; then
        printf 'height=%s receipts=%s%s%s%s%s\n' "$LAST_HEIGHT" \
            "$chain_advance_verified" "$chain_evidence_verified" \
            "$network_verified" "$peer_lifecycle_verified" \
            "$legacy_mirror_verified"
        return 0
    fi
    token_stat=$(cat "/proc/$SERVICE_MAIN_PID/stat" 2>/dev/null || true)
    token_io=$(cat "/proc/$SERVICE_MAIN_PID/io" 2>/dev/null || true)
    printf 'io=%s cpu=%s blkio=%s\n' \
        "$(proc_io_bytes_from_text "$token_io")" \
        "$(proc_cpu_ticks_from_text "$token_stat")" \
        "$(proc_blkio_ticks_from_text "$token_stat")"
}

json_has_key() {
    printf '%s\n' "$1" | grep -q "\"$2\"[[:space:]]*:"
}

json_not_has_key() {
    ! json_has_key "$1" "$2"
}

json_key_is_true() {
    printf '%s\n' "$1" | grep -q "\"$2\"[[:space:]]*:[[:space:]]*true"
}

json_key_is_string() {
    printf '%s\n' "$1" |
        grep -q "\"$2\"[[:space:]]*:[[:space:]]*\"$3\""
}

json_top_key_is_true() {
    json_key_is_true "$1" "$2"
}

json_top_has_key() {
    json_has_key "$1" "$2"
}

json_top_key_is_string() {
    json_key_is_string "$1" "$2" "$3"
}

json_health_gap_at_most_one() {
    printf '%s\n' "$1" |
        grep -q '"gap"[[:space:]]*:[[:space:]]*[01]\([^0-9]\|$\)'
}

json_rpc_result() {
    printf '%s\n' "$1"
}

extract_health_height() {
    printf '%s\n' "$1" |
        tr ',' '\n' |
        grep -E '"(log_head|projection_height|local_height)"[[:space:]]*:' |
        grep -oE ':[[:space:]]*[0-9]+' |
        grep -oE '[0-9]+' |
        awk '$1 > 0 { print; exit }'
}

json_key_is_int() {
    printf '%s\n' "$1" |
        grep -q "\"$2\"[[:space:]]*:[[:space:]]*$3\\([^0-9]\\|$\\)"
}

extract_height() {
    height=$(printf '%s' "$1" |
        grep -oE '"result"[[:space:]]*:[[:space:]]*[0-9]+' |
        grep -oE '[0-9]+' | head -1)
    if [ -z "$height" ]; then
        plain=$(printf '%s' "$1" | tr -d '[:space:]')
        case "$plain" in
            [0-9]*) height="$plain" ;;
        esac
    fi
    printf '%s' "$height"
}

extract_build_commit() {
    printf '%s\n' "$1" |
        grep -oE '"build_commit"[[:space:]]*:[[:space:]]*"[^"]*"' |
        head -1 |
        sed -E 's/.*"build_commit"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/'
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | sed -E 's/^.*= //'
    else
        return 1
    fi
}

mainpid_socket_inodes() {
    for socket_fd in "/proc/$SERVICE_MAIN_PID/fd/"*; do
        socket_target=$(readlink "$socket_fd" 2>/dev/null || true)
        case "$socket_target" in
            socket:\[*\])
                printf '%s\n' "$socket_target" |
                    sed -n 's/^socket:\[\([0-9][0-9]*\)\]$/\1/p'
                ;;
        esac
    done
}

mainpid_rpc_listener_inodes() {
    listener_port_hex=$(printf '%04X' "$RPCPORT")
    for socket_table in /proc/net/tcp /proc/net/tcp6; do
        [ -r "$socket_table" ] || continue
        awk -v port="$listener_port_hex" '
            NR > 1 {
                split($2, local, ":")
                if (toupper(local[2]) == port && $4 == "0A")
                    print $10
            }
        ' "$socket_table"
    done
}

mainpid_owns_rpc_listener() {
    owned_inodes=$(mainpid_socket_inodes || true)
    listener_inodes=$(mainpid_rpc_listener_inodes || true)
    [ -n "$owned_inodes" ] && [ -n "$listener_inodes" ] || return 1
    for listener_inode in $listener_inodes; do
        if printf '%s\n' "$owned_inodes" | grep -Fxq "$listener_inode"; then
            return 0
        fi
    done
    return 1
}

running_service_artifact_sha256() {
    service_pid_is_stable || return 1
    sha256_file "/proc/$SERVICE_MAIN_PID/exe"
}

pre_rpc_boot_status() {
    service_pid_is_stable || return 1
    boot_status_out=$("$SERVICE_EXE" core node bootstatus \
        "-datadir=$RPC_DATADIR" 2>/dev/null || true)
    service_pid_is_stable || return 1
    printf '%s\n' "$boot_status_out"
}
rpc_dumpstate() {
    component="$1"
    key="${2:-}"
    # zcl-rpc wraps remaining argv directly into a JSON params array, so its
    # string argument needs JSON quotes. zclassic-cli performs its own string
    # encoding and MUST receive the bare subsystem name. Never retry one
    # client's syntax through the other: that overwrites an honest timeout or
    # partial response with a deterministic "unknown subsystem '\"name\"'".
    case "$(basename "$RPC_TOOL")" in
        zcl-rpc)
            if [ -n "$key" ]; then
                out=$(rpc_call dumpstate "\"$component\"" "\"$key\"" 2>&1 || true)
            else
                out=$(rpc_call dumpstate "\"$component\"" 2>&1 || true)
            fi
            ;;
        *)
            if [ -n "$key" ]; then
                out=$(rpc_call dumpstate "$component" "$key" 2>&1 || true)
            else
                out=$(rpc_call dumpstate "$component" 2>&1 || true)
            fi
            ;;
    esac
    out=$(json_rpc_result "$out")
    printf '%s\n' "$out"
}

verify_contract() {
    height="$1"

    service_pid_is_stable ||
        { last_err="canonical zclassic23 MainPID changed during RPC proof"; return 1; }
    mainpid_owns_rpc_listener ||
        { last_err="canonical MainPID does not own RPC listener port $RPCPORT"; return 1; }

    # Each expensive readiness class is sticky for this exact MainPID.  A
    # booting node can legitimately make a later projection probe miss its
    # deadline; restarting the whole sequence in that case used to enqueue the
    # already-proven database-heavy probes again and again.  The stable PID +
    # start-ticks checks above and below keep these receipts process-bound.
    if [ "$chain_advance_verified" -eq 0 ]; then
        ca=$(rpc_dumpstate chain_advance_coordinator initialized)
        json_key_is_true "$ca" initialized ||
            { last_err="chain_advance_coordinator not initialized: $ca"; return 1; }
        json_key_is_true "$ca" has_connman ||
            { last_err="chain_advance_coordinator missing connman: $ca"; return 1; }
        json_key_is_true "$ca" has_main_state ||
            { last_err="chain_advance_coordinator missing main_state: $ca"; return 1; }
        json_key_is_true "$ca" has_node_db ||
            { last_err="chain_advance_coordinator missing node_db: $ca"; return 1; }
        json_key_is_string "$ca" authority local_consensus_validation ||
            { last_err="chain_advance authority contract missing: $ca"; return 1; }
        json_has_key "$ca" selected_source ||
            { last_err="chain_advance selected_source missing: $ca"; return 1; }
        json_has_key "$ca" candidate_source ||
            { last_err="chain_advance candidate_source missing: $ca"; return 1; }
        json_has_key "$ca" sources ||
            { last_err="chain_advance sources missing: $ca"; return 1; }
        chain_advance_verified=1
    fi

    if [ "$chain_evidence_verified" -eq 0 ]; then
        evidence=$(rpc_dumpstate chain_evidence health_reason)
        json_has_key "$evidence" health_reason ||
            { last_err="chain_evidence diagnostics missing health_reason: $evidence"; return 1; }
        printf '%s\n' "$evidence" | grep -q '"health_reason"[[:space:]]*:[[:space:]]*"chain_evidence_gap"' &&
            { last_err="chain_evidence reports generic gap: $evidence"; return 1; }
        printf '%s\n' "$evidence" | grep -q '"health_reason"[[:space:]]*:[[:space:]]*"[^"]' &&
            { last_err="chain_evidence is frozen/degraded: $evidence"; return 1; }
        chain_evidence_verified=1
    fi

    if [ "$network_verified" -eq 0 ]; then
        net=$(rpc_call getnetworkinfo 2>&1 || true)
        net=$(json_rpc_result "$net")
        for key in advertised_subver advertised_services inbound_connections outbound_connections handshaked_connections \
                   inbound_handshake_seen remote_handshake_seen legacy_compatible_peers legacy_magicbean_peers magicbean_peers \
                   zclassic23_peers zclassic_c23_peers peer_lifecycle; do
            json_has_key "$net" "$key" ||
                { last_err="getnetworkinfo missing $key: $net"; return 1; }
        done
        net_subver=$(printf '%s\n' "$net" |
            sed -n 's/.*"advertised_subver"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
            sed -n '1p')
        case "$(advertised_subver_verdict "$net_subver" "$EXPECT_SOURCE_ID")" in
            deployed|unstamped) ;;
            stale)
                last_err="STALE DEPLOY: node advertises build '$net_subver', not the deployed source id '$EXPECT_SOURCE_ID'"
                return 1 ;;
            *)
                last_err="node is not advertising native ZClassic23 subver: $net"
                return 1 ;;
        esac
        network_verified=1
    fi

    if [ "$peer_lifecycle_verified" -eq 0 ]; then
        peer=$(rpc_dumpstate peer_lifecycle summary)
        json_has_key "$peer" summary ||
            { last_err="peer_lifecycle summary missing: $peer"; return 1; }
        json_has_key "$peer" sources ||
            { last_err="peer_lifecycle sources missing: $peer"; return 1; }
        json_has_key "$peer" legacy_magicbean_handshakes ||
            { last_err="peer_lifecycle missing legacy handshake canary: $peer"; return 1; }
        json_has_key "$peer" legacy_compatible_handshakes ||
            { last_err="peer_lifecycle missing legacy handshake alias: $peer"; return 1; }
        json_has_key "$peer" zclassic23_handshakes ||
            { last_err="peer_lifecycle missing zclassic23 handshake canary: $peer"; return 1; }
        json_has_key "$peer" zclassic_c23_handshakes ||
            { last_err="peer_lifecycle missing zclassic_c23 compatibility canary: $peer"; return 1; }
        json_has_key "$peer" pre_handshake_disconnects ||
            { last_err="peer_lifecycle missing pre-handshake disconnect counter: $peer"; return 1; }
        if ! printf '%s\n' "$peer" | grep -q '"legacy_magicbean_handshakes"[[:space:]]*:[[:space:]]*[1-9]'; then
            printf '%s\n' "$peer" | grep -q '"attempted"[[:space:]]*:[[:space:]]*0' ||
                { last_err="no legacy MagicBean handshake observed and peers were reachable: $peer"; return 1; }
        fi
        peer_lifecycle_verified=1
    fi

    if [ "$legacy_mirror_verified" -eq 0 ]; then
        mirror=$(rpc_dumpstate legacy_mirror consensus_authority)
        json_has_key "$mirror" consensus_authority ||
            { last_err="legacy_mirror authority missing: $mirror"; return 1; }
        json_key_is_string "$mirror" consensus_authority local_consensus_validation ||
            { last_err="legacy_mirror must not claim zclassicd authority: $mirror"; return 1; }
        json_not_has_key "$mirror" mirror_authorization_enabled ||
            { last_err="legacy_mirror exposes deleted mirror_authorization_enabled: $mirror"; return 1; }
        json_not_has_key "$mirror" mirror_consensus_authority ||
            { last_err="legacy_mirror exposes deleted mirror_consensus_authority: $mirror"; return 1; }
        json_has_key "$mirror" candidate_source ||
            { last_err="legacy_mirror candidate_source missing: $mirror"; return 1; }
        json_key_is_string "$mirror" candidate_source legacy_advisory ||
            { last_err="legacy_mirror must expose advisory candidate source: $mirror"; return 1; }
        json_has_key "$mirror" legacy_advisory_gated_by_native_retries ||
            { last_err="legacy_mirror advisory/native retry gate missing: $mirror"; return 1; }
        json_has_key "$mirror" blockers_total ||
            { last_err="legacy_mirror blockers_total missing: $mirror"; return 1; }
        json_has_key "$mirror" stalls_total ||
            { last_err="legacy_mirror stalls_total missing: $mirror"; return 1; }
        json_has_key "$mirror" unsafe_overrides_total ||
            { last_err="legacy_mirror unsafe_overrides_total missing: $mirror"; return 1; }
        json_key_is_int "$mirror" unsafe_overrides_total 0 ||
            { last_err="legacy_mirror unsafe overrides are unhealthy: $mirror"; return 1; }
        json_has_key "$mirror" last_override_safe ||
            { last_err="legacy_mirror last_override_safe missing: $mirror"; return 1; }
        json_has_key "$mirror" last_override_scope ||
            { last_err="legacy_mirror last_override_scope missing: $mirror"; return 1; }
        legacy_mirror_verified=1
    fi

    health=$(rpc_call healthcheck 2>&1 || true)
    health=$(json_rpc_result "$health")
    json_top_key_is_string "$health" consensus_authority local_consensus_validation ||
        { last_err="healthcheck authority contract missing: $health"; return 1; }
    json_not_has_key "$health" mirror_authorization_enabled ||
        { last_err="healthcheck exposes deleted mirror_authorization_enabled: $health"; return 1; }
    json_not_has_key "$health" mirror_consensus_authority ||
        { last_err="healthcheck exposes deleted mirror_consensus_authority: $health"; return 1; }
    json_top_has_key "$health" candidate_source ||
        { last_err="healthcheck candidate_source missing: $health"; return 1; }
    json_top_has_key "$health" candidate_trust ||
        { last_err="healthcheck candidate_trust missing: $health"; return 1; }
    if [ "$DEPLOY_STAGE" = "stable" ]; then
        json_top_key_is_true "$health" healthy ||
            { last_err="healthcheck is not healthy: $health"; return 1; }
    else
        # Challenger staging and rollback recovery are deliberately weaker
        # than stable promotion: they prove exact bytes, process identity,
        # RPC/P2P readiness, evidence consistency, and a <=1 tip gap.  Neither
        # claims PROVEN or baseline equivalence merely because the process came
        # back; named health blockers remain visible for owner review.
        json_top_has_key "$health" healthy ||
            { last_err="challenger healthcheck omitted healthy verdict: $health"; return 1; }
        json_health_gap_at_most_one "$health" ||
            { last_err="challenger tip gap is not <=1: $health"; return 1; }
    fi
    printf '%s\n' "$health" | grep -q '"degraded_reason"[[:space:]]*:[[:space:]]*"chain_evidence_gap"' &&
        { last_err="healthcheck reports generic evidence gap: $health"; return 1; }
    health_height=$(extract_health_height "$health" || true)
    if [ -n "$health_height" ]; then
        height="$health_height"
    fi
    case "$height" in
        ''|0)
            last_err="healthcheck is healthy but no positive verified height was available: $health"
            return 1
            ;;
    esac

    # Staleness guard: require both the exact SHA-256 source identity reported
    # by RPC and the exact SHA-256 of /proc/<MainPID>/exe. The second check
    # distinguishes two compiler outputs built from the same source bytes.
    # Git commit metadata is deliberately excluded from both decisions.
    running_source_id=$(running_daemon_baked_source_id "$health" || true)
    running_commit=$(extract_build_commit "$health" || true)
    if ! zcl_is_sha256 "$running_source_id"; then
        if zcl_json_sha256_is_ambiguous "$health" source_id_sha256; then
            last_err="STALE DEPLOY: healthcheck reports more than one source_id_sha256 — the payload is answering two different questions under one key and no freshness verdict can be drawn from it: $health"
        else
            last_err="STALE DEPLOY: running daemon exposes no valid baked source_id_sha256"
        fi
        return 1
    fi
    if [ "$running_source_id" != "$EXPECT_SOURCE_ID" ]; then
        last_err="STALE DEPLOY: running source_id_sha256 '$running_source_id' != expected '$EXPECT_SOURCE_ID'"
        return 1
    fi

    service_pid_is_stable ||
        { last_err="canonical zclassic23 MainPID changed after RPC identity proof"; return 1; }
    mainpid_owns_rpc_listener ||
        { last_err="canonical MainPID lost ownership of RPC listener port $RPCPORT"; return 1; }
    running_artifact_sha256=$(running_service_artifact_sha256 || true)
    if ! zcl_is_sha256 "$running_artifact_sha256"; then
        last_err="STALE DEPLOY: could not hash the running zclassic23 MainPID executable"
        return 1
    fi
    if [ "$running_artifact_sha256" != "$EXPECT_ARTIFACT_SHA256" ]; then
        last_err="STALE DEPLOY: running artifact SHA-256 '$running_artifact_sha256' != expected '$EXPECT_ARTIFACT_SHA256'"
        return 1
    fi

    if [ "$DEPLOY_STAGE" = "challenger" ]; then
        echo "CHALLENGER_ACTIVE (unqualified): RPC live at block $height (source_id $running_source_id, artifact_sha256 $running_artifact_sha256, build_commit ${running_commit:-unknown} display-only); canonical diagnostics ready; stable health promotion not claimed."
    elif [ "$DEPLOY_STAGE" = "rollback" ]; then
        echo "ROLLBACK_VERIFIED: prior RPC live at block $height (source_id $running_source_id, artifact_sha256 $running_artifact_sha256, build_commit ${running_commit:-unknown} display-only); canonical diagnostics ready."
    else
        echo "Deployed + RPC live at block $height (source_id $running_source_id, artifact_sha256 $running_artifact_sha256, build_commit ${running_commit:-unknown} display-only); canonical diagnostics ready."
    fi
    return 0
}

report_evidence() {
    if [ -n "$last_err" ]; then
        echo "last error: $last_err"
    fi
    echo "progress evidence: samples=$progress_advances attempts=$attempt" \
         "elapsed=${elapsed}s silent_for=${silent_for}s" \
         "first_token=[$first_token] last_token=[$prev_token]"
    boot_status=$(pre_rpc_boot_status || true)
    if [ -n "$boot_status" ]; then
        echo "typed boot status: $boot_status"
    else
        echo "typed boot status: unavailable (captured service process changed)"
    fi
}

prev_token=$(progress_token)
first_token="$prev_token"
last_progress_ts="$START_TS"
progress_advances=0
elapsed=0
silent_for=0
pid_unstable=0
PID_CONFIRM_SAMPLES="${ZCL_DEPLOY_VERIFY_PID_SAMPLES:-3}"

while :; do
    attempt=$((attempt + 1))
    if out=$(rpc_call getblockcount 2>&1); then
        # Accept either a plain integer (zclassic-cli) or a JSON
        # envelope with "result":<integer> (build/bin/zcl-rpc). Any other
        # output keeps the loop polling.
        height=$(extract_height "$out")
        if [ -n "$height" ]; then
            LAST_HEIGHT="$height"
            if [ "$RPC_READY" -eq 0 ]; then
                # Regime change. The observable set is now a different one, so
                # the silence clock restarts rather than comparing tokens that
                # were never comparable.
                RPC_READY=1
                prev_token=$(progress_token)
                last_progress_ts=$(date +%s)
                progress_advances=$((progress_advances + 1))
            fi
            if verify_contract "$height"; then
                exit 0
            fi
        else
            last_err="$out"
        fi
    else
        last_err="$out"
    fi

    now=$(date +%s)
    elapsed=$(( now - START_TS ))

    # A candidate that crashed and was restarted underneath us is a FAULT, and
    # it is one no amount of waiting fixes. Naming it here keeps it out of the
    # slowness verdict entirely: it has its own message and its own latency.
    #
    # Confirmed across consecutive samples, never on one. This check shells out
    # to `systemctl show`, and a single hiccup there — an empty answer under
    # load on a busy box — is not evidence that a process died. Convicting on
    # one sample is the same defect as the deadline this file just removed.
    if service_pid_is_stable; then
        pid_unstable=0
    else
        pid_unstable=$(( pid_unstable + 1 ))
        if [ "$pid_unstable" -ge "$PID_CONFIRM_SAMPLES" ]; then
            silent_for=$(( now - last_progress_ts ))
            echo "DEPLOY FAILED: the candidate process did not stay up —" \
                 "canonical MainPID/executable/start-time changed and stayed" \
                 "changed across $pid_unstable consecutive samples," \
                 "${elapsed}s into verification (attempts=$attempt)." \
                 "This is a crash or a restart loop, NOT a slow machine."
            report_evidence
            exit 1
        fi
    fi

    cur_token=$(progress_token)
    if [ "$(progress_verdict "$prev_token" "$cur_token")" = advancing ]; then
        prev_token="$cur_token"
        last_progress_ts="$now"
        progress_advances=$((progress_advances + 1))
    fi
    silent_for=$(( now - last_progress_ts ))

    # The ONLY clock allowed to call a fault.
    if [ "$silent_for" -ge "$SILENCE_LIMIT" ]; then
        # Before convicting, give post-RPC silence its one honest innocent
        # explanation: a node parked at the network tip. Its height token
        # freezes by design when no block arrives, and an idle synced node
        # moves no io/cpu/blkio — indistinguishable from a wedge to the token.
        # Ask the node where it stands. at_tip + a live answer is an idle tip,
        # not a wedge: unverified (exit 3, candidate stays), never a rollback.
        # A node that no longer answers, or that is behind its headers with
        # nothing moving, is exactly the wedge this limit exists to catch.
        if [ "$RPC_READY" -eq 1 ]; then
            tip_verdict=$(chain_tip_from_text "$(rpc_call getblockchaininfo 2>/dev/null || true)")
            case "$tip_verdict" in
                at_tip)
                    echo "DEPLOY UNVERIFIED (idle at tip): the frozen height token" \
                         "coincides with headers==blocks and a live getblockchaininfo" \
                         "answer — the candidate is synced and waiting for the next" \
                         "block, not wedged. ${silent_for}s of idle after ${elapsed}s" \
                         "and $attempt attempts. Candidate stays installed; NOTHING" \
                         "is rolled back. Re-run with ZCL_DEPLOY_VERIFY_WAIT=1 to" \
                         "keep watching, or investigate why the deploy contract did" \
                         "not pass on a healthy node."
                    report_evidence
                    exit 3
                    ;;
                behind)
                    echo "note: silence conviction on a node still behind its" \
                         "headers — a catch-up loop that stopped moving" >&2
                    ;;
                unknown)
                    echo "note: silence conviction with getblockchaininfo" \
                         "unanswerable — the RPC surface died" >&2
                    ;;
            esac
        fi
        echo "DEPLOY FAILED: the candidate stopped making observable progress —" \
             "nothing changed for ${silent_for}s (limit ${SILENCE_LIMIT}s)" \
             "after ${elapsed}s and $attempt attempts." \
             "A wedge is silence; slowness alone never reaches this line."
        report_evidence
        exit 1
    fi

    if [ "$WAIT_FOREVER" != "1" ] && [ "$now" -ge "$deadline" ]; then
        case "$(window_outcome "$progress_advances" "$silent_for" "$SILENCE_LIMIT")" in
            unverified_progressing)
                echo "DEPLOY UNVERIFIED (still progressing): the ${TIMEOUT}s reporting" \
                     "window expired while the node was demonstrably still advancing" \
                     "($progress_advances observed advances, last change ${silent_for}s ago)." \
                     "This is NOT a deploy failure and NOT a reason to roll back;" \
                     "the candidate is installed and working. Keep watching with" \
                     "ZCL_DEPLOY_VERIFY_WAIT=1 ./tools/deploy_verify.sh, or raise" \
                     "ZCL_DEPLOY_VERIFY_TIMEOUT for this box."
                report_evidence
                exit 3
                ;;
            unverified_unobserved)
                echo "DEPLOY UNVERIFIED (no verdict earned): the ${TIMEOUT}s reporting" \
                     "window expired with no observed progress, but silence has only" \
                     "been established for ${silent_for}s of the ${SILENCE_LIMIT}s" \
                     "needed to call a fault. Refusing to guess either way."
                report_evidence
                exit 3
                ;;
        esac
    fi

    sleep "$INTERVAL"
done
