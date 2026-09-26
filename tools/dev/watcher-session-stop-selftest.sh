#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# purpose: Drive dev begin/status/stop in the dev binary against recorded
# watcher stand-ins: a launch refuses beside a killed watcher's surviving
# worker, a bound stop leaves no process of the session, and a leaderless
# session is retired only by its exact birth.
#
# usage: watcher-session-stop-selftest.sh [dev-binary [holder-fixture.c]]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
bin="${1:-$here/build/bin/z23-dev}"
fixture="${2:-$here/tools/dev/fixtures/watcher_session_holder.c}"
[[ -x "$bin" ]] || { printf 'missing dev binary: %s\n' "$bin" >&2; exit 2; }
scratch="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/z23-watch-session.XXXXXX")" && pwd -P)"
holders=()
endpoints=()
cleanup()
{
    local pid path
    for pid in "${holders[@]}"; do
        kill -KILL -- "-$pid" 2>/dev/null || true
    done
    # A killed holder cannot remove its own stop endpoint.
    for path in "${endpoints[@]}"; do
        rm -f -- "$path"
    done
    rm -rf -- "$scratch"
}
trap cleanup EXIT

cc -std=c23 -O2 -Wall -Wextra -Werror -pedantic "$fixture" -o "$scratch/z23-dev"

fail()
{
    printf 'watcher session selftest: %s\n' "$1" >&2
    exit 1
}

new_root()
{
    local root="$scratch/$1"
    mkdir -p "$root/.cache"
    chmod 0700 "$root/.cache"
    : > "$root/Makefile"
    printf '%s\n' "$root"
}

# start MODE ROOT -> sets pid worker born session
start()
{
    local mode="$1" root="$2" ready="$2/holder.ready"
    # Detached as the launcher detaches a watcher, so init reaps it.
    ( cd "$root" && exec "$scratch/z23-dev" "$mode" "$root" "$ready" & )
    for ((i = 0; i < 300; i++)); do
        [[ -s "$ready" ]] && break
        sleep 0.01
    done
    [[ -s "$ready" ]] || fail "$mode holder did not become ready"
    read -r pid worker born session < "$ready"
    holders+=("$pid")
    endpoints+=("/tmp/z23-watch-stop-$(id -u)-$session")
}

run()
{
    local root="$1"
    shift
    (cd "$root" && HOME="$scratch" ZCL_DEV_SOURCE_ROOT="$root" "$bin" "$@") 2>&1 || true
}

# Running, not a zombie waiting for its reaper.
alive()
{
    local stat
    stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
    [[ "$stat" != *") Z "* ]]
}

gone()
{
    for ((i = 0; i < 300; i++)); do
        alive "$1" || return 0
        sleep 0.01
    done
    return 1
}

# (a) A killed watcher's worker still runs: begin refuses, never forks.
root="$(new_root begin)"
start orphan "$root"
kill -KILL "$pid"
gone "$pid" || fail 'orphan leader did not die'
out="$(run "$root" dev begin --input="{\"root\":\"$root\"}")"
grep -q '"WATCHER_RETIRING"' <<<"$out" || fail "begin beside an orphan: $out"
alive "$worker" || fail 'begin touched the orphaned worker'

# (c) The orphan is listed by pid and born, and retired only by that birth.
out="$(run "$root" dev loop status)"
grep -q "\"pid\":$pid,\"born\":$born" <<<"$out" ||
    fail "status does not list the orphan: $out"
out="$(run "$root" dev loop stop --input="{\"watcher_id\":$pid,\"watcher_born\":$((born + 1))}")"
grep -q '"WATCHER_ID_MISMATCH"' <<<"$out" || fail "another birth accepted: $out"
alive "$worker" || fail 'a refused stop signalled the worker'
out="$(run "$root" dev loop stop --input="{\"watcher_id\":$pid,\"watcher_born\":$born}")"
grep -q '"session_retired":"retired"' <<<"$out" || fail "orphan not retired: $out"
gone "$worker" || fail 'orphaned worker survived its stop'

# (b) A bound stop reaches the exact session and leaves none of it.
root="$(new_root stop)"
start fifo "$root"
out="$(run "$root" dev loop stop --input="{\"watcher_id\":$pid,\"watcher_session\":\"$session\"}")"
grep -q '"stopped":true' <<<"$out" || fail "bound stop failed: $out"
grep -q '"session_retired":"retired"' <<<"$out" ||
    fail "leaked worker not retired: $out"
gone "$pid" || fail 'leader survived its stop'
gone "$worker" || fail 'worker survived its session stop'

printf 'watcher session stop: begin refuses beside an orphan; orphan retired only by its birth; bound stop leaves no process\n'
