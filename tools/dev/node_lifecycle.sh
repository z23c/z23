#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# node_lifecycle.sh — the single owner of isolated-node process lifecycle for
# acceptance harnesses. SOURCE it; do not run it.
#
# WHY THIS IS A LIBRARY. Spawning a real node is the easy part. Owning it is
# not: every harness needs the same fail-closed rules about which process
# groups it may signal, which ports it may bind, that a killed group is
# really gone, and that its ports rebind immediately so the next run is not
# contaminated by the last one. That logic grew inside the seven-daemon DHT
# acceptance and was correct there. A second harness that reimplemented it
# would be a second state machine to keep honest, which is exactly the way
# these proofs go quietly wrong.
#
# The dht_ prefix is historical. It is kept because four hooks and a 1000-line
# harness call these names, and churning them would risk the acceptance that
# guards consensus-adjacent work for no behavior change.
#
# A caller must set DHT_WORK_PARENT (or accept the default) and may override
# ZCL_NODE_BIN / ZCL_RPC_BIN / DHT_ACCEPTANCE_C23. The EXIT trap installed
# here kills every group this library spawned.


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"
DHT_ACCEPTANCE_C23="${DHT_ACCEPTANCE_C23:-$REPO_ROOT/build/bin/arena_product_journey_c23}"
PROCESS_GROUP_EXEC="${ZCL_PROCESS_GROUP_EXEC:-$REPO_ROOT/build/bin/process-group-exec}"
PROCESS_START_TOKEN="${ZCL_PROCESS_START_TOKEN:-$REPO_ROOT/tools/dev/process-start-token.sh}"

DHT_LIVE_PORTS="8023 8033 8034 8035 8043 8044 8045 8046 8232 8443 \
18034 18232 18234 18243 18244 18245 18246"
# P2P reconnects pass the production reachable-port policy; use two of its
# explicit test-safe ports rather than arbitrary high ports that only the
# initial operator-directed -connect dial may bypass.
DEAD_SINK=39999
DHT_WAIT="${DHT_WAIT:-90}"
DHT_PACKAGEHOST="${DHT_PACKAGEHOST:-0}"
DHT_BUILDWORKERS="${DHT_BUILDWORKERS:-0}"
DHT_AFTER_SPARSE_HOOK="${DHT_AFTER_SPARSE_HOOK:-}"
DHT_WORK_PARENT="${DHT_WORK_PARENT:-$REPO_ROOT/test-tmp}"
DHT_PARAMS_DIR="${DHT_PARAMS_DIR:-}"
# The node these helpers mine on. A caller with more than one node names it.
DHT_MINE_DD=""; DHT_MINE_RPC=""
DHT_WORK_PREFIX=""
DHT_WORK=""; DHT_DD_A=""; DHT_DD_B=""; DHT_DD_C=""; DHT_PGID_A=""; DHT_PGID_B=""; DHT_PGID_C=""
declare -A DHT_OWNED_PGIDS=()
declare -A DHT_OWNED_START=()
DHT_OWNED_PORTS=()
DHT_CLEANED=0
DHT_KEEP="${DHT_KEEP:-0}"
case "$(uname -s 2>/dev/null)" in
    Darwin) DHT_GC_SECTIONS_LDFLAGS=(-Wl,-dead_strip) ;;
    *) DHT_GC_SECTIONS_LDFLAGS=(-Wl,--gc-sections) ;;
esac
# ── remote node operation (multi-host acceptances) ───────────────────────
# Default: every node is a local process, these maps stay empty, and every
# function below takes exactly its historical local path. A multi-host
# caller registers an ssh destination per RPC port (dht_register_remote_node)
# after shipping sha3-verified binaries there; dht_rpc / dht_native /
# dht_spawn / dht_kill_group and the wait probes then operate on that host
# through the same fail-closed ownership rules. Argument quoting goes
# through printf %q so JSON --input payloads survive ssh re-joining.
DHT_SSH="${DHT_SSH:-ssh}"
# Enabled by the Linux two-host and three-host acceptance. Remote native workers must
# inherit the receiving host's scheduler admission and resource scope.
DHT_REMOTE_DEVBUILD=0
# Queue admission is separate from the RPC readiness budget of an admitted node.
DHT_REMOTE_ADMISSION_WAIT="${DHT_REMOTE_ADMISSION_WAIT:-900}"
# Remote fixture compiler children inherit their host scheduler admission.
# The shared scheduler owns CPU and memory bounds; do not add a nested scope.
DHT_SCP="${DHT_SCP:-scp}"
# Remote-lease supervision, in whole seconds. A remote fixture must survive
# the one ssh call that spawned it (its parent is gone by design) yet never
# outlive a driver that lost the host: the driver refreshes a lease file on
# the fixture's host, and the shipped launcher terminates its own group when
# that file goes missing or stale. The stale window must comfortably exceed
# the refresh period; the default tolerates eight consecutive missed
# refreshes (network churn, scheduler lag) before reaping.
DHT_LEASE_STALE_S="${DHT_LEASE_STALE_S:-180}"
DHT_LEASE_REFRESH_S="${DHT_LEASE_REFRESH_S:-20}"
declare -A DHT_REMOTE_HOST=()   # rpc port -> ssh destination
declare -A DHT_REMOTE_DIR=()    # rpc port -> remote base dir (bin/, datadirs)
declare -A DHT_PGID_RPC=()      # owned pgid -> rpc port (remote routing)
declare -A DHT_OWNED_PORT_RPC=() # claimed port -> rpc port of its host
declare -A DHT_LEASE_REFRESH_PGID=() # "host:dir" -> local refresher pgid

dht_register_remote_node() {
    local rpc="$1" host="$2" dir="$3"
    [ -n "$rpc" ] && [ -n "$host" ] && [ -n "$dir" ] ||
        dht_die "dht_register_remote_node needs rpc port, ssh host, remote dir"
    DHT_REMOTE_HOST[$rpc]="$host"
    DHT_REMOTE_DIR[$rpc]="$dir"
}

# dht_ensure_remote_lease RPC — make one host:dir's lease live and fresh,
# and keep it fresh for as long as this driver lives. Called before the
# first supervised spawn on that host: the lease must already be fresh when
# the launcher's supervisor takes its first reading. The refresher is a
# local group under the launcher's own parent-death supervision, so a
# driver killed without its EXIT trap still stops refreshing, the lease
# goes stale, and the remote fixture reaps itself. The refresher only ever
# touches a file over ssh; what dies and when stays owned by the remote
# launcher, so no PPID, port or pid heuristic ever authorizes a kill.
dht_ensure_remote_lease() {
    local rpc="$1" host dir key refresher_pid
    host="${DHT_REMOTE_HOST[$rpc]}"
    dir="${DHT_REMOTE_DIR[$rpc]}"
    key="$host:$dir"
    [ -z "${DHT_LEASE_REFRESH_PGID[$key]:-}" ] || return 0
    [[ "$DHT_LEASE_STALE_S" =~ ^[0-9]+$ && "$DHT_LEASE_REFRESH_S" =~ ^[0-9]+$ ]] ||
        dht_die "lease knobs must be whole seconds: stale='$DHT_LEASE_STALE_S' refresh='$DHT_LEASE_REFRESH_S'"
    [ "$DHT_LEASE_STALE_S" -gt $((DHT_LEASE_REFRESH_S * 2)) ] ||
        dht_die "lease stale window ($DHT_LEASE_STALE_S s) must exceed two refresh periods ($DHT_LEASE_REFRESH_S s)"
    [ -n "$DHT_WORK" ] && [ -d "$DHT_WORK" ] ||
        dht_die "remote lease supervision needs dht_make_work first"
    # Synchronous first touch: a lease that never existed must never be
    # observed fresh-by-absence by a racing supervisor.
    "$DHT_SSH" -o BatchMode=yes -o ConnectTimeout=5 "$host" -- \
        "$(printf '%q ' touch "$dir/lease")" ||
        dht_die "cannot create the supervision lease on $host"
    dht_spawn_owned_command refresher_pid "$DHT_WORK/lease-refresh-$rpc.log" \
        bash -c 'r=$1; host=$2; file=$3; shift 3
                 while sleep "$r"; do
                     "$@" "$host" -- "touch $(printf "%q" "$file")" || :
                 done' \
        lease-refresh "$DHT_LEASE_REFRESH_S" "$host" "$dir/lease" \
        "$DHT_SSH" -o BatchMode=yes -o ConnectTimeout=5
    DHT_LEASE_REFRESH_PGID[$key]="$refresher_pid"
}

# Run one command where this RPC port's node lives. Local when unregistered.
dht_node_exec() {
    local rpc="$1" host; shift
    host="${DHT_REMOTE_HOST[$rpc]:-}"
    if [ -z "$host" ]; then "$@";
    else "$DHT_SSH" -o BatchMode=yes "$host" -- "$(printf '%q ' "$@")"; fi
}

# Copy one local file to the node's host. Local when unregistered.
dht_node_put() {
    local rpc="$1" src="$2" dst="$3" host
    host="${DHT_REMOTE_HOST[$rpc]:-}"
    if [ -z "$host" ]; then cp "$src" "$dst";
    else "$DHT_SCP" -o BatchMode=yes "$src" "$host:$dst"; fi
}

# -f probe where this RPC port's node lives.
dht_node_file_exists() {
    local rpc="$1" path="$2"
    if [ -z "${DHT_REMOTE_HOST[$rpc]:-}" ]; then [ -f "$path" ];
    else dht_node_exec "$rpc" test -f "$path"; fi
}
# Throwaway passphrases for the wallet-custody recipe (never argv: they
# ride the wallet-passphrase credential file and --input=- stdin only).
DHT_WALLET_PASS="zcode-dht-acceptance-wallet-pass"
DHT_BACKUP_PASS="zcode-dht-acceptance-backup-pass"

dht_die() {
    echo "zcode-dht-acceptance: FATAL: $*" >&2
    if [ -n "$DHT_WORK" ] && [ -d "$DHT_WORK" ]; then
        printf '%s\n' "$*" >"$DHT_WORK/FAILURE"
    fi
    exit 2
}
dht_note() { echo "zcode-dht-acceptance: $*"; }

dht_start_token() {
    "$PROCESS_START_TOKEN" "$1" 2>/dev/null
}

dht_require_start_token() {
    local start
    [ -f "$PROCESS_START_TOKEN" ] && [ -x "$PROCESS_START_TOKEN" ] ||
        { dht_die "PROCESS_START_TOKEN_UNAVAILABLE: helper must be a regular executable file"; return 1; }
    start="$(dht_start_token "$$")" && [ -n "$start" ] ||
        { dht_die "PROCESS_START_TOKEN_UNAVAILABLE: helper cannot identify this driver"; return 1; }
}

dht_process_group_exec() {
    if [ -x "$PROCESS_GROUP_EXEC" ]; then
        # Local fixtures die with this driver: a crashed or killed
        # harness must not strand a regtest daemon on the shared
        # test-safe ports. Remote legs cannot use parent death (their
        # parent is one short ssh session of many); they take
        # --die-with-lease on their own host instead.
        exec "$PROCESS_GROUP_EXEC" --die-with-parent "$@"
    elif command -v setsid >/dev/null 2>&1; then
        printf '%s\n' "node_lifecycle: compiled launcher absent; fixture parent-death supervision unavailable (setsid fallback)" >&2
        exec setsid "$@"
    else
        dht_die "no process-group launcher; run make process-group-exec"
    fi
}

dht_make_work() {
    local prefix="$1" parent
    mkdir -p "$DHT_WORK_PARENT"
    parent="$(cd "$DHT_WORK_PARENT" && pwd -P)"
    [ "$parent" != / ] || dht_die "DHT_WORK_PARENT must not be /"
    DHT_WORK_PARENT="$parent"
    DHT_WORK="$(mktemp -d "$DHT_WORK_PARENT/$prefix-XXXXXX")" ||
        dht_die "could not create isolated work directory under $parent"
    # Remember what WE created. Cleanup used to match a hardcoded list of this
    # harness's own prefixes, so a second harness silently leaked its scratch
    # directory on every run while still reporting PASS.
    DHT_WORK_PREFIX="$prefix"
}

dht_assert_port() {
    local p="$1" owner_rpc="${2:-}" live owned
    for live in $DHT_LIVE_PORTS; do
        [ "$p" = "$live" ] && dht_die "port $p is in the live refuse-set"
    done
    if [ -n "$owner_rpc" ] && [ -n "${DHT_REMOTE_HOST[$owner_rpc]:-}" ]; then
        # Probe on the node's host with the already shipped native helper.
        # A missing helper or unreachable host cannot establish a free port.
        if ! dht_node_exec "$owner_rpc" \
                "${DHT_REMOTE_DIR[$owner_rpc]}/bin/arena_product_journey_c23" \
                ports-rebind "$p"; then
            # Same honesty as the local branch: name the holder when the
            # host can, and say "holder unknown" — never "port free" —
            # when it cannot. lsof is the one listener-identity source
            # that exists on both supported platforms; the probe runs on
            # the port's own host through sh so the answer describes that
            # host, not this one.
            local remote_holder
            remote_holder="$(dht_node_exec "$owner_rpc" sh -c '
                if command -v lsof >/dev/null 2>&1; then
                    hp=$(lsof -nP -iTCP:"$1" -sTCP:LISTEN -Fp 2>/dev/null |
                        sed -n "s/^p\([0-9]*\)$/\1/p" | head -1)
                    if [ -n "$hp" ]; then
                        hc=$(ps -o command= -p "$hp" 2>/dev/null | cut -c1-160)
                        printf "pid %s: %s" "$hp" "${hc:-<command unreadable>}"
                    fi
                fi' probe-port "$p" 2>/dev/null || true)"
            if [ -n "$remote_holder" ]; then
                dht_die "port $p unavailable on ${DHT_REMOTE_HOST[$owner_rpc]}: held by $remote_holder"
            fi
            dht_die "port $p unavailable or probe failed on ${DHT_REMOTE_HOST[$owner_rpc]} (no listener identity source on that host; holder unknown)"
        fi
    else
        if ! "$DHT_ACCEPTANCE_C23" ports-rebind "$p"; then
            # Name the holder so an orphaned fixture from a dead session is
            # a one-line reap instead of a forensic exercise. lsof is the
            # one listener-identity source that exists on both supported
            # hosts; a host without it, or a probe failure with no visible
            # listener, still gets an explicit refusal - just an unnamed
            # one.
            local holder_pid holder_cmd
            if command -v lsof >/dev/null 2>&1; then
                holder_pid="$(lsof -nP -iTCP:"$p" -sTCP:LISTEN -Fp 2>/dev/null |
                    sed -n 's/^p\([0-9]*\)$/\1/p' | head -1)"
            fi
            if [ -n "$holder_pid" ]; then
                holder_cmd="$(ps -o command= -p "$holder_pid" 2>/dev/null |
                    cut -c1-160)"
                dht_die "port $p unavailable on this host: held by pid $holder_pid ${holder_cmd:-(command unreadable)}"
            fi
            dht_die "port $p unavailable or probe failed on this host (no listener identity found)"
        fi
    fi
    for owned in "${DHT_OWNED_PORTS[@]:-}"; do
        [ "$owned" = "$p" ] && return 0
    done
    DHT_OWNED_PORTS+=("$p")
    [ -z "$owner_rpc" ] || DHT_OWNED_PORT_RPC[$p]="$owner_rpc"
    return 0
}

# Graceful-stop grace. The node's own shutdown is staged and budgeted in
# engine/composition/src/boot_services_shutdown.c (worker-drain 60 s, then
# runtime-persist 45 s containing a 30 s wallet flush, plus the other stages),
# and systemd allows TimeoutStopSec=300. A driver that escalates sooner than
# that kills a node that is still shutting down normally and manufactures an
# unclean stop. 300 s covers the whole budget; a clean exit returns as soon as
# the group is gone because the poll interval is DHT_STOP_POLL_S.
# DHT_STOP_GRACE_S / DHT_STOP_POLL_S exist so a selftest can scale both down.
: "${DHT_STOP_GRACE_S:=300}"
: "${DHT_STOP_POLL_S:=0.2}"
# Hard kills wait this long (seconds) for the kernel to reap the group.
DHT_HARD_KILL_REAP_S=10
DHT_UNCLEAN_STOPS=0

# dht_group_gone PGID RPC : succeeds when the process group no longer runs.
dht_group_gone() {
    local pgid="$1" rpc="$2" state
    if [ -n "$rpc" ]; then
        dht_node_exec "$rpc" kill -0 "-$pgid" 2>/dev/null && return 1
        return 0
    fi
    kill -0 "-$pgid" 2>/dev/null || return 0
    # A leader that is a zombie has exited; only its reaping is pending.
    state="$(LC_ALL=C ps -p "$pgid" -o stat= 2>/dev/null |
        awk 'NR == 1 { print $1 }' || true)"
    case "$state" in Z*) return 0 ;; esac
    return 1
}

# dht_kill_group PGID [SIG]
#   SIG omitted or TERM: GRACEFUL stop. Signal, then wait up to
#     DHT_STOP_GRACE_S for the group to exit on its own; only then escalate to
#     KILL, and say so loudly ("unclean stop: killed after Ns").
#   SIG=KILL: deliberate HARD kill (an intentional disappearance). SIGKILL is
#     sent immediately, labelled as such, and never counts as unclean.
dht_kill_group() {
    local pgid="$1" sig="${2:-TERM}" rpc="" start polls max hard=0
    [ -n "$pgid" ] || return 0
    [ "${DHT_OWNED_PGIDS[$pgid]:-0}" = 1 ] || return 0
    rpc="${DHT_PGID_RPC[$pgid]:-}"
    if [ -z "$rpc" ] || [ -z "${DHT_REMOTE_HOST[$rpc]:-}" ]; then rpc=""; fi
    start="$SECONDS"
    if [ "$sig" = KILL ]; then
        hard=1
        echo "zcode-dht-acceptance: hard kill (deliberate): SIGKILL to group $pgid" >&2
        max="$DHT_HARD_KILL_REAP_S"
    else
        max="$DHT_STOP_GRACE_S"
    fi
    if [ -n "$rpc" ]; then
        dht_node_exec "$rpc" kill "-$sig" "-$pgid" 2>/dev/null || true
    else
        kill -"$sig" "-$pgid" 2>/dev/null || true
    fi
    # Poll on wall time, not iteration count, so ssh latency cannot stretch
    # the grace.
    polls=0
    while ! dht_group_gone "$pgid" "$rpc"; do
        if [ $((SECONDS - start)) -ge "$max" ]; then
            if [ "$hard" = 0 ]; then
                DHT_UNCLEAN_STOPS=$((DHT_UNCLEAN_STOPS + 1))
                echo "zcode-dht-acceptance: unclean stop: killed after $((SECONDS - start))s (group $pgid ignored $sig for the ${max}s grace)" >&2
            fi
            if [ -n "$rpc" ]; then
                dht_node_exec "$rpc" kill -KILL "-$pgid" 2>/dev/null || true
            else
                kill -KILL "-$pgid" 2>/dev/null || true
            fi
            break
        fi
        sleep "$DHT_STOP_POLL_S"
    done
    if [ -z "$rpc" ]; then wait "$pgid" 2>/dev/null || true; fi
    unset "DHT_OWNED_PGIDS[$pgid]" "DHT_PGID_RPC[$pgid]"
    # After SIGKILL the last members may be zombies for an instant; give the
    # reaper a short bounded window before calling the group still alive.
    for polls in 1 2 3 4 5 6 7 8 9 10; do
        dht_group_gone "$pgid" "$rpc" && return 0
        sleep "$DHT_STOP_POLL_S"
    done
    return 1
}

dht_register_owned_group() {
    local pid="$1" start
    start="$(dht_start_token "$pid" || true)"
    if [ -z "$start" ]; then
        wait "$pid" 2>/dev/null || true
        dht_die "spawned process group $pid exited before ownership registration"
    fi
    DHT_OWNED_PGIDS[$pid]=1
    DHT_OWNED_START[$pid]="$start"
}

dht_assert_no_owned_processes() {
    local pid expected current rpc
    for pid in "${!DHT_OWNED_START[@]}"; do
        rpc="${DHT_PGID_RPC[$pid]:-}"
        [ -n "$rpc" ] && [ -n "${DHT_REMOTE_HOST[$rpc]:-}" ] && continue
        expected="${DHT_OWNED_START[$pid]}"
        current="$(dht_start_token "$pid" || true)"
        [ -z "$current" ] || [ "$current" != "$expected" ] ||
            dht_die "owned process $pid remained after cleanup"
    done
}

dht_assert_ports_rebindable() {
    [ "${#DHT_OWNED_PORTS[@]}" -gt 0 ] || return 0
    local p rpc local_ports=()
    for p in "${DHT_OWNED_PORTS[@]}"; do
        rpc="${DHT_OWNED_PORT_RPC[$p]:-}"
        if [ -n "$rpc" ] && [ -n "${DHT_REMOTE_HOST[$rpc]:-}" ]; then
            # Same proof on the owning host with the shipped helper.
            dht_node_exec "$rpc" \
                "${DHT_REMOTE_DIR[$rpc]}/bin/arena_product_journey_c23" \
                ports-rebind "$p" ||
                dht_die "port $p on ${DHT_REMOTE_HOST[$rpc]} could not rebind immediately after cleanup"
        else
            local_ports+=("$p")
        fi
    done
    [ "${#local_ports[@]}" -eq 0 ] && return 0
    if ! "$DHT_ACCEPTANCE_C23" ports-rebind "${local_ports[@]}"
    then
        dht_die "owned ports could not be rebound immediately after cleanup"
    fi
}

dht_cleanup() {
    [ "$DHT_CLEANED" = 1 ] && return 0
    DHT_CLEANED=1
    local pgid failed=0
    for pgid in "${!DHT_OWNED_PGIDS[@]}"; do
        dht_kill_group "$pgid" || failed=1
    done
    # Remote scratch dirs we registered are ours to remove; anything else is
    # not, and the guard pattern keeps an rm -rf from ever leaving /tmp.
    local rpc rdir
    for rpc in "${!DHT_REMOTE_HOST[@]}"; do
        rdir="${DHT_REMOTE_DIR[$rpc]:-}"
        case "$rdir" in
            /tmp/z23-mh-*)
                if [ "$DHT_KEEP" = 1 ]; then
                    dht_note "preserved remote artifacts on ${DHT_REMOTE_HOST[$rpc]}: $rdir"
                else
                    dht_node_exec "$rpc" rm -rf -- "$rdir" || failed=1
                fi ;;
            "") ;;
            *) dht_note "WARN refusing to remove non-scratch remote $rdir" ;;
        esac
    done
    if [ "$DHT_KEEP" = 1 ] && [ -n "$DHT_WORK" ]; then
        dht_note "preserved acceptance artifacts: $DHT_WORK"
    elif [ -n "$DHT_WORK" ] && [ -d "$DHT_WORK" ]; then
        # Remove only the directory this process made, under the parent it
        # made it in. Anything else is not ours to delete.
        case "$DHT_WORK" in
            "$DHT_WORK_PARENT"/"$DHT_WORK_PREFIX"-??????)
                [ -n "$DHT_WORK_PREFIX" ] && rm -rf "$DHT_WORK"
                ;;
            *) dht_note "WARN refusing to remove non-scratch $DHT_WORK" ;;
        esac
    fi
    [ "$failed" -eq 0 ]
}

dht_exit() {
    local rc="$?"
    trap - EXIT INT TERM
    if ! dht_cleanup && [ "$rc" -eq 0 ]; then rc=2; fi
    exit "$rc"
}
trap dht_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

dht_rpc() {
    local dd="$1" port="$2"; shift 2
    if [ -n "${DHT_REMOTE_HOST[$port]:-}" ]; then
        dht_node_exec "$port" env ZCL_DATADIR="$dd" ZCL_RPCPORT="$port" \
            "${DHT_REMOTE_DIR[$port]}/bin/zcl-rpc" "$@" 2>/dev/null
        return
    fi
    ZCL_DATADIR="$dd" ZCL_RPCPORT="$port" "$RPC_BIN" "$@" 2>/dev/null
}
dht_result() {
    "$DHT_ACCEPTANCE_C23" rpc-result
}
dht_jget() {
    "$DHT_ACCEPTANCE_C23" json-get "$@"
}
dht_native() {
    local dd="$1" rpc="$2"; shift 2
    if [ -n "${DHT_REMOTE_HOST[$rpc]:-}" ]; then
        dht_node_exec "$rpc" "${DHT_REMOTE_DIR[$rpc]}/bin/zclassic23" \
            "-datadir=$dd" "-rpcport=$rpc" "$@" 2>/dev/null | tail -1
        return
    fi
    "$NODE_BIN" -datadir="$dd" -rpcport="$rpc" "$@" 2>/dev/null | tail -1
}
dht_status() { dht_native "$1" "$2" zcode network status; }

dht_remote_scheduled_pid() {
    local rpc="$1" dd="$2" admission_wait; shift 2
    case "$DHT_REMOTE_ADMISSION_WAIT" in
        ''|*[!0-9]*) dht_die "invalid remote scheduler admission wait" ;;
    esac
    [ "$DHT_REMOTE_ADMISSION_WAIT" -ge 1 ] &&
        [ "$DHT_REMOTE_ADMISSION_WAIT" -le 3600 ] ||
        dht_die "remote scheduler admission wait must be 1..3600 seconds"
    admission_wait=$((10#$DHT_REMOTE_ADMISSION_WAIT))
    # This is fixture startup, not a remote job executor. The only scheduled
    # process is the native node, whose compiler children inherit its scope.
    dht_node_exec "$rpc" bash -c '
        set -eu
        dd=$1; limit=$2; shift 2
        mkdir -p "$dd-worker/.zvcs"
        cd "$dd-worker"
        pidfile="$dd/scheduled-node.pid"
        rm -f "$pidfile"
        setsid "$HOME/.local/bin/devbuild" --wait --project z23 \
            setsid bash -c '\''
                pidfile=$1; shift
                printf "%s\n" "$$" > "$pidfile"
                exec "$@"
            '\'' scheduled-node "$pidfile" "$@" \
            >>"$dd/node.log" 2>&1 </dev/null &
        launcher=$!
        end=$((SECONDS + limit))
        while [ "$SECONDS" -lt "$end" ]; do
            if [ -s "$pidfile" ]; then cat "$pidfile"; exit 0; fi
            kill -0 "$launcher" 2>/dev/null || { wait "$launcher"; exit 1; }
            sleep 0.2
        done
        kill -TERM -- "-$launcher" 2>/dev/null || true
        if [ -s "$pidfile" ]; then
            pid=$(cat "$pidfile")
            case "$pid" in ""|*[!0-9]*) ;; *) kill -TERM -- "-$pid" 2>/dev/null || true ;; esac
        fi
        printf "remote scheduler admission timed out\n" >&2
        exit 75
    ' remote-scheduled-node "$dd" "$admission_wait" "$@"
}

dht_record_started_arguments() {
    # /proc observations belong to the opt-in Linux admitted remote lanes.
    [ "$DHT_REMOTE_DEVBUILD" = 1 ] || return 0
    local dd="$1" rpc="$2" pid="$3" expected
    expected="$(sha256sum "$NODE_BIN" | awk '{print $1}')"
    dht_node_exec "$rpc" bash -c '
        set -eu
        dd=$1; pid=$2; expected=$3
        for attempt in $(seq 1 50); do
            if tr "\0" "\n" < "/proc/$pid/cmdline" | grep -q "^-datadir="; then
                actual=$(sha256sum "/proc/$pid/exe" | awk '\''{print $1}'\'')
                [ "$actual" = "$expected" ] || exit 75
                {
                    printf "started_utc=%s pid=%s\n" "$(date -u +%FT%TZ)" "$pid"
                    sha256sum "/proc/$pid/exe"
                    tr "\0" "\n" < "/proc/$pid/cmdline"
                } >> "$dd/observed-start-arguments.txt"
                exit 0
            fi
            sleep 0.1
        done
        exit 75
    ' observe-start "$dd" "$pid" "$expected" || dht_die "could not verify started node image and arguments"
}

dht_spawn() {
    local out_name="$1" dd="$2" p2p="$3" rpc="$4" fs="$5" https="$6"
    shift 6
    dht_require_start_token || return 1
    local args=() connect pid
    for connect in "$@"; do args+=("-connect=$connect"); done
    [ "${#args[@]}" -gt 0 ] || args+=("-connect=127.0.0.1:$DEAD_SINK")
    # No -allow-plaintext-wallet: the ZID anchor's overlay-intent custody
    # gate refuses a plaintext-at-rest wallet. The wallet-passphrase
    # credential (CREDENTIALS_DIRECTORY, exported below) encrypts key
    # writes at rest (WKS1); -operator-lane=dev arms the dev wallet scope.
    case "$DHT_PACKAGEHOST" in 0|1) ;; *) dht_die "DHT_PACKAGEHOST must be 0 or 1" ;; esac
    case "$DHT_BUILDWORKERS" in 0|1) ;; *) dht_die "DHT_BUILDWORKERS must be 0 or 1" ;; esac
    local worker_args=() params_args=()
    [ "$DHT_BUILDWORKERS" = 1 ] && worker_args+=("-buildworker=1")
    [ -z "$DHT_PARAMS_DIR" ] || params_args+=("-paramsdir=$DHT_PARAMS_DIR")
    if [ -n "${DHT_REMOTE_HOST[$rpc]:-}" ]; then
        # Same flags, on the node's own host. The native launcher detaches the
        # group from the ssh session; the echoed pid IS the remote pgid. The
        # group stays supervised by lease: the launcher terminates it when
        # this driver stops refreshing the lease on that host, so a killed
        # driver cannot strand a fixture daemon holding the shared test-safe
        # ports. The remote credential directory must already hold
        # wallet-passphrase.
        local cmd=(env
            "CREDENTIALS_DIRECTORY=${DHT_REMOTE_DIR[$rpc]}/cred"
            "${DHT_REMOTE_DIR[$rpc]}/bin/zclassic23"
            "-datadir=$dd" -regtest "-port=$p2p" "-rpcport=$rpc"
            "-fsport=$fs" "-httpsport=$https")
        cmd+=("${args[@]}" "-packagehost=$DHT_PACKAGEHOST" -noisetransport)
        [ "${#worker_args[@]}" -eq 0 ] || cmd+=("${worker_args[@]}")
        # The params dir is per-host: the remote node gets its own.
        [ -z "$DHT_PARAMS_DIR" ] ||
            cmd+=("-paramsdir=${DHT_REMOTE_DIR[$rpc]}/no-zk-params")
        cmd+=(-operator-lane=dev -wallet-no-phrase-backup
              -nobgvalidation -nolegacyimport -showmetrics=0)
        if [ "$DHT_REMOTE_DEVBUILD" = 1 ]; then
            pid="$(dht_remote_scheduled_pid "$rpc" "$dd" "${cmd[@]}")" ||
                dht_die "scheduled remote spawn failed"
        else
            dht_ensure_remote_lease "$rpc"
            pid="$("$DHT_SSH" -o BatchMode=yes "${DHT_REMOTE_HOST[$rpc]}" -- \
                "$(printf '%q' "${DHT_REMOTE_DIR[$rpc]}/bin/process-group-exec") --die-with-lease=$(printf '%q' "${DHT_REMOTE_DIR[$rpc]}/lease:$DHT_LEASE_STALE_S") $(printf '%q ' "${cmd[@]}")>>$(printf '%q' "$dd/node.log") 2>&1 </dev/null & echo \$!" </dev/null)" ||
                dht_die "remote spawn on ${DHT_REMOTE_HOST[$rpc]} failed"
        fi
        case "$pid" in ''|*[!0-9]*) dht_die "remote spawn returned no pid: $pid" ;; esac
        DHT_OWNED_PGIDS[$pid]=1
        DHT_PGID_RPC[$pid]="$rpc"
        if [ "$DHT_REMOTE_DEVBUILD" = 1 ]; then
            local expected_exe
            expected_exe="$(openssl dgst -sha3-256 "$NODE_BIN" | awk '{print $NF}')"
            dht_node_exec "$rpc" bash -c '
                set -eu
                pid=$1; dd=$2; expected=$3; limit=$4
                # Startup PID publication precedes exec. Preserve that raw
                # sample, then require the actual frozen image before a receipt.
                openssl dgst -sha3-256 "/proc/$pid/exe" >> "$dd/scheduled-starts.raw.txt" 2>&1 || true
                end=$((SECONDS + limit))
                actual=""
                while [ "$SECONDS" -lt "$end" ]; do
                    kill -0 "$pid" 2>/dev/null || exit 1
                    actual=$(openssl dgst -sha3-256 "/proc/$pid/exe" 2>/dev/null | awk '\''{print $NF}'\'' || true)
                    [ "$actual" != "$expected" ] || break
                    sleep 0.1
                done
                [ "$actual" = "$expected" ] || exit 75
                cg=$(awk -F: '\''$1 == "0" { print $3 }'\'' "/proc/$pid/cgroup")
                case "$cg" in */development.slice/*) ;; *) exit 75 ;; esac
                {
                    printf "pid=%s cgroup=%s\n" "$pid" "$cg"
                    printf "mapped_binary_sha3=%s\n" "$actual"
                    grep "^Cpus_allowed_list:" "/proc/$pid/status"
                    printf "memory.max="; cat "/sys/fs/cgroup$cg/memory.max"
                    printf "cpu.max="; cat "/sys/fs/cgroup$cg/cpu.max"
                } >> "$dd/scheduled-starts.txt"
            ' verify-scheduled-node "$pid" "$dd" "$expected_exe" "$DHT_WAIT" ||
                dht_die "remote worker did not inherit its scheduled scope"
        fi
        printf -v "$out_name" '%s' "$pid"
        dht_record_started_arguments "$dd" "$rpc" "$pid"
        return 0
    fi
    dht_process_group_exec "$NODE_BIN" -datadir="$dd" -regtest -port="$p2p" \
        -rpcport="$rpc" -fsport="$fs" -httpsport="$https" \
        "${args[@]}" -packagehost="$DHT_PACKAGEHOST" -noisetransport \
        "${worker_args[@]}" "${params_args[@]}" \
        -operator-lane=dev -wallet-no-phrase-backup \
        -nobgvalidation -nolegacyimport -showmetrics=0 \
        >>"$dd/node.log" 2>&1 &
    pid="$!"
    dht_register_owned_group "$pid"
    printf -v "$out_name" '%s' "$pid"
    dht_record_started_arguments "$dd" "$rpc" "$pid"
}

dht_spawn_owned_command() {
    local out_name="$1" log="$2" pid
    shift 2
    dht_require_start_token || return 1
    dht_process_group_exec "$@" >>"$log" 2>&1 &
    pid="$!"
    dht_register_owned_group "$pid"
    printf -v "$out_name" '%s' "$pid"
}

dht_wait_owned_exit() {
    local pid="$1" expected="$2" label="$3" rc
    if wait "$pid"; then rc=0; else rc="$?"; fi
    unset "DHT_OWNED_PGIDS[$pid]"
    [ "$rc" -eq "$expected" ] ||
        dht_die "$label exited $rc (expected $expected)"
}

dht_wait_file() {
    local path="$1" owner="$2" deadline
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        [ -s "$path" ] && return 0
        kill -0 "$owner" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

dht_process_identity_alive() {
    local pid="$1" expected="$2" current
    current="$(dht_start_token "$pid" || true)"
    [ -n "$current" ] && [ "$current" = "$expected" ]
}

dht_height() {
    dht_rpc "$1" "$2" getblockcount | dht_result
}
dht_wait_rpc() {
    local dd="$1" rpc="$2" pid="$3" deadline
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ -n "${DHT_REMOTE_HOST[$rpc]:-}" ]; then
            # A remote spawn's pid can race the first kill -0: ssh returns
            # as soon as echo $! runs, before setsid is visible. Retry until
            # the deadline instead of treating one miss as a dead node.
            if dht_node_exec "$rpc" kill -0 "-$pid" 2>/dev/null; then
                dht_node_file_exists "$rpc" "$dd/.cookie" &&
                    dht_height "$dd" "$rpc" >/dev/null 2>&1 && return 0
            fi
        else
            kill -0 "$pid" 2>/dev/null || return 1
            [ -f "$dd/.cookie" ] &&
                dht_height "$dd" "$rpc" >/dev/null 2>&1 && return 0
        fi
        sleep 0.5
    done
    if [ -n "${DHT_REMOTE_HOST[$rpc]:-}" ]; then
        echo "dht_wait_rpc: remote $dd/node.log:" >&2
        dht_node_exec "$rpc" tail -n 40 "$dd/node.log" >&2 || true
    fi
    return 1
}
dht_wait_height() {
    local dd="$1" rpc="$2" target="$3" deadline h
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        h="$(dht_height "$dd" "$rpc" 2>/dev/null || true)"
        [ "$h" = "$target" ] && return 0
        sleep 0.5
    done
    return 1
}


# The regtest miner stamps blocks from whole-second wall time.  More than six
# consecutive blocks with one timestamp becomes <= the peer's 11-block MTP
# even though the local submission path accepted the batch.  Mine in groups
# of five with a wall-clock step so the second node validates the same chain.
dht_mine_to_address() {
    local count="$1" address="$2" chunk reply rpc_exit decode_exit
    while [ "$count" -gt 0 ]; do
        chunk=5
        [ "$count" -lt "$chunk" ] && chunk="$count"
        rpc_exit=0; decode_exit=0
        reply="$(dht_rpc "$DHT_MINE_DD" "$DHT_MINE_RPC" generatetoaddress \
                    "$chunk" "\"$address\"")" || rpc_exit=$?
        printf '%s' "$reply" | dht_result >/dev/null || decode_exit=$?
        if [ "$rpc_exit" -ne 0 ] || [ "$decode_exit" -ne 0 ]; then
            if [ -n "$DHT_WORK" ]; then
                printf '%s\n' "$reply" >"$DHT_WORK/funding-rpc-failure.json"
            fi
            printf 'funding RPC failed: remaining=%s chunk=%s rpc_exit=%s decoder_exit=%s response=%s\n' \
                "$count" "$chunk" "$rpc_exit" "$decode_exit" "${reply:0:4096}" >&2
            [ "$rpc_exit" -eq 0 ] || return "$rpc_exit"
            return "$decode_exit"
        fi
        count=$((count - chunk))
        [ "$count" -eq 0 ] || sleep 1
    done
}
dht_mine_empty() {
    local count="$1" chunk
    while [ "$count" -gt 0 ]; do
        chunk=5
        [ "$count" -lt "$chunk" ] && chunk="$count"
        dht_rpc "$DHT_MINE_DD" "$DHT_MINE_RPC" generate "$chunk" | dht_result >/dev/null
        count=$((count - chunk))
        [ "$count" -eq 0 ] || sleep 1
    done
}
dht_wait_auth() {
    local dd="$1" rpc="$2" want="${3:-1}" deadline out enabled auth accepted
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        out="$(dht_status "$dd" "$rpc" 2>/dev/null || true)"
        enabled="$(printf '%s' "$out" | dht_jget data.enabled False 2>/dev/null || true)"
        auth="$(printf '%s' "$out" | dht_jget data.connected_authenticated 0 2>/dev/null || true)"
        accepted="$(printf '%s' "$out" | dht_jget data.frames_accepted 0 2>/dev/null || true)"
        [ "$enabled" = True ] && [ "${auth:-0}" -ge "$want" ] &&
            [ "${accepted:-0}" -ge "$want" ] && return 0
        sleep 0.5
    done
    return 1
}
dht_wait_cold_load() {
    local dd="$1" rpc="$2" want="${3:-1}" deadline out loaded cold
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        out="$(dht_status "$dd" "$rpc" 2>/dev/null || true)"
        loaded="$(printf '%s' "$out" | dht_jget data.persistence_loaded False 2>/dev/null || true)"
        cold="$(printf '%s' "$out" | dht_jget data.cold_contacts 0 2>/dev/null || true)"
        [ "$loaded" = True ] && [ "${cold:-0}" -ge "$want" ] && return 0
        sleep 0.5
    done
    return 1
}

# ── Wallet-custody helpers (the ZID anchor's overlay-intent gate) ─────
# The anchor's custody gate requires the wallet encrypted at rest (the
# wallet-passphrase credential armed at first boot), unlocked, and covered
# by a current-key encrypted backup; its money gate requires an OUTBOUND
# peer with a live sync state and a positive vault spendable. This is the
# metaverse-tour recipe (tools/dev/metaverse_tour.sh) adapted to dht_*
# style; passphrases ride --input=- stdin only, never argv.
dht_wait_connected() {
    local dd="$1" rpc="$2" deadline n
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        n="$(dht_rpc "$dd" "$rpc" getconnectioncount 2>/dev/null | dht_result 2>/dev/null || true)"
        [ "${n:-0}" -ge 1 ] 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}
# The money freshness classifier fails closed on finding_peers; the sync
# FSM only leaves it behind a peer it can sync FROM (outbound).
dht_wait_sync_live() {
    local dd="$1" rpc="$2" deadline state
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        state="$(dht_rpc "$dd" "$rpc" downloadstats 2>/dev/null \
            | dht_jget result.sync_state 2>/dev/null || true)"
        case "$state" in
            blocks_download|connecting_blocks|at_tip) return 0 ;;
        esac
        sleep 0.5
    done
    return 1
}
# The money gate reads the REDUCER pipeline, not the active chain: the
# authoritative coins tip AND H* must both reach the mined height.
dht_wait_fold() {
    local dd="$1" rpc="$2" tip="$3" deadline dump coins hstar
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        dump="$(dht_native "$dd" "$rpc" dumpstate reducer_frontier || true)"
        coins="$(printf '%s' "$dump" | dht_jget state.coins_best_height 2>/dev/null || true)"
        hstar="$(printf '%s' "$dump" | dht_jget state.hstar 2>/dev/null || true)"
        [ "$coins" = "$tip" ] && [ "$hstar" = "$tip" ] && return 0
        sleep 1
    done
    echo "zcode-dht-acceptance: reducer_frontier at stall: $dump" >&2
    return 1
}
# RPC-ready != chain-loaded: the anchor's runtime gate needs the active
# chain index, which loads after the RPC starts serving.
dht_wait_chain_loaded() {
    local dd="$1" rpc="$2" tip="$3" deadline loaded
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        loaded="$(dht_rpc "$dd" "$rpc" getblockchaininfo 2>/dev/null |
            "$DHT_ACCEPTANCE_C23" chain-loaded "$tip" 2>/dev/null || true)"
        [ "$loaded" = "True" ] && return 0
        sleep 1
    done
    return 1
}
# The fee-reserve rung reads the vault read model's zcl_spendable, which
# lags the reducer fold while the wallet re-derives its spendable coins.
dht_wait_spendable() {
    local dd="$1" rpc="$2" deadline spend
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        spend="$(dht_native "$dd" "$rpc" dumpstate vault 2>/dev/null \
            | dht_jget state.zcl.spendable 2>/dev/null || true)"
        case "$spend" in
            ''|*[!0-9]*) ;;
            *) [ "$spend" -gt 0 ] && return 0 ;;
        esac
        sleep 1
    done
    return 1
}
dht_unlock_wallet() {
    local dd="$1" rpc="$2" status unlock
    status="$(dht_native "$dd" "$rpc" core wallet security status || true)"
    [ "$(printf '%s' "$status" | dht_jget ok False 2>/dev/null || true)" = "True" ] || {
        printf '%s\n' "$status" >&2; return 1; }
    if [ "$(printf '%s' "$status" | dht_jget data.unlocked 2>/dev/null || true)" != "True" ]; then
        unlock="$(printf '%s' "{\"passphrase\":\"$DHT_WALLET_PASS\",\"timeout_seconds\":3600}" \
            | dht_native "$dd" "$rpc" core wallet security unlock --input=- || true)"
        [ "$(printf '%s' "$unlock" | dht_jget data.unlocked 2>/dev/null || true)" = "True" ] || {
            printf '%s\n' "$unlock" >&2; return 1; }
    fi
    return 0
}
dht_backup_wallet() {
    local dd="$1" rpc="$2" out
    out="$(printf '%s' "{\"confirm\":true,\"password\":\"$DHT_BACKUP_PASS\"}" \
        | dht_native "$dd" "$rpc" core wallet backup now --input=- || true)"
    [ "$(printf '%s' "$out" | dht_jget ok False 2>/dev/null || true)" = "True" ] || {
        printf '%s\n' "$out" >&2; return 1; }
}
# Plan (retrying ONLY the transient OVERLAY_INTENT_REFUSED money-currency
# skew — the idempotency key makes a repeated plan safe), then commit the
# returned plan_id. Prints the commit reply; nonzero on any refusal.
dht_anchor() {
    local dd="$1" rpc="$2" pubkey="$3" key="$4" plan plan_id commit try
    plan=""
    for try in $(seq 1 20); do
        plan="$(dht_native "$dd" "$rpc" core identity anchor \
            --input="{\"wallet_scope\":\"dev\",\"pubkey\":\"$pubkey\",\"idempotency_key\":\"$key\"}" || true)"
        case "$plan" in
            *OVERLAY_INTENT_REFUSED*) sleep 1 ;;
            *) break ;;
        esac
    done
    [ "$(printf '%s' "$plan" | dht_jget ok False 2>/dev/null || true)" = "True" ] &&
    [ "$(printf '%s' "$plan" | dht_jget data.stage 2>/dev/null || true)" = "plan" ] || {
        printf '%s\n' "$plan" >&2; return 1; }
    plan_id="$(printf '%s' "$plan" | dht_jget data.plan_id 2>/dev/null)" || return 1
    commit="$(dht_native "$dd" "$rpc" core identity anchor \
        --input="{\"wallet_scope\":\"dev\",\"plan_id\":\"$plan_id\",\"confirm\":true}" || true)"
    [ "$(printf '%s' "$commit" | dht_jget ok False 2>/dev/null || true)" = "True" ] &&
    [ "$(printf '%s' "$commit" | dht_jget data.stage 2>/dev/null || true)" = "committed" ] || {
        printf '%s\n' "$commit" >&2; return 1; }
    printf '%s\n' "$commit"
}
