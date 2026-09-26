#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# purpose: Prove Linux watcher stop refuses a watcher-looking non-owner.
set -euo pipefail

root="$(mktemp -d "${TMPDIR:-/tmp}/z23-watch-stop.XXXXXX")"
make -j"$(getconf _NPROCESSORS_ONLN)" dev-bin >/dev/null
bin="$(pwd -P)/build/bin/z23-dev"
fixture="$(pwd -P)/tools/dev/fixtures/watcher_stop_holder.c"
idle_pid=0
holder_pid=0
cleanup()
{
    if (( holder_pid > 1 )); then kill -TERM "$holder_pid" 2>/dev/null || true; wait "$holder_pid" 2>/dev/null || true; fi
    if (( idle_pid > 1 )); then kill -TERM "$idle_pid" 2>/dev/null || true; wait "$idle_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT

mkdir "$root/.cache"
: > "$root/Makefile"
cc -std=c23 -O2 -Wall -Wextra -Werror -pedantic "$fixture" -o "$root/z23-dev"

wait_ready()
{
    local marker="$1"
    for ((i=0; i<200; i++)); do
        [[ -f "$marker" ]] && return 0
        sleep 0.01
    done
    printf 'fixture did not become ready: %s\n' "$marker" >&2
    return 1
}

"$root/z23-dev" idle "$root" none "$root/idle.ready" &
idle_pid=$!
wait_ready "$root/idle.ready"
"$root/z23-dev" hold "$root" "$idle_pid" "$root/forged.ready" &
holder_pid=$!
wait_ready "$root/forged.ready"
forged_session="$(awk '{print $6}' "$root/.cache/zcl-dev-watch.lock")"
if (cd "$root" && ZCL_DEV_SOURCE_ROOT="$root" "$bin" dev loop stop --input="{\"watcher_id\":$idle_pid,\"watcher_session\":\"$forged_session\"}") > "$root/forged.json" 2>&1; then
    printf 'stop accepted a PID that did not own the lock\n' >&2
    exit 1
fi
grep -q 'WATCHER_STOP_TIMEOUT' "$root/forged.json"
kill -0 "$idle_pid"
kill -0 "$holder_pid"
kill -TERM "$holder_pid"
wait "$holder_pid"
holder_pid=0

"$root/z23-dev" hold "$root" self "$root/owner.ready" &
holder_pid=$!
wait_ready "$root/owner.ready"
owner_session="$(awk '{print $6}' "$root/.cache/zcl-dev-watch.lock")"
stale_session="$(printf '%064d' 0)"
if (cd "$root" && ZCL_DEV_SOURCE_ROOT="$root" "$bin" dev loop stop --input="{\"watcher_id\":$holder_pid,\"watcher_session\":\"$stale_session\"}") > "$root/stale.json" 2>&1; then
    printf 'stop accepted a stale watcher session\n' >&2
    exit 1
fi
grep -q 'WATCHER_ID_MISMATCH' "$root/stale.json"
kill -0 "$holder_pid"
(cd "$root" && ZCL_DEV_SOURCE_ROOT="$root" "$bin" dev loop stop --input="{\"watcher_id\":$holder_pid,\"watcher_session\":\"$owner_session\"}") > "$root/owner.json" 2>&1
grep -q '"stopped":true' "$root/owner.json"
wait "$holder_pid"
holder_pid=0
kill -TERM "$idle_pid"
wait "$idle_pid"
idle_pid=0
printf 'watcher stop identity: forged PID and stale session refused; exact lock owner stopped\n'
