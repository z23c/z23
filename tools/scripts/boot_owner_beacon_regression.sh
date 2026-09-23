#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# A refused second node must not replace the datadir owner's boot beacon.

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"
if [ "$(uname -s)" != Linux ]; then
    echo 'boot-owner-beacon: Linux native acceptance requires GNU flock' >&2
    exit 2
fi

ISO_KIND=boot-owner-beacon
ISO_PORT_BASE=${ISO_PORT_BASE:-39820}
ISO_NODE_BIN=${ISO_NODE_BIN:-./build/bin/z23}
ISO_RPC_BIN=${ISO_RPC_BIN:-./build/bin/zcl-rpc}
ISO_JSONQ_BIN=${ISO_JSONQ_BIN:-./build/bin/jsonq}
source "$repo_root/tools/scripts/isolated_node_env.sh"
iso_init

holder_pid=''
owner_cleanup() {
    if [ -n "$holder_pid" ]; then
        kill "$holder_pid" 2>/dev/null || true
        wait "$holder_pid" 2>/dev/null || true
    fi
    iso_cleanup
}
# Preserve isolated_node_env's cleanup while also releasing the fixture lock.
trap owner_cleanup EXIT INT TERM

beacon="$ISO_DD/boot_status.json"
pidfile="$ISO_DD/zclassic23.pid"
now=$(date +%s)
printf '{"schema":"zcl.boot_status.v1","phase":"serving","stage":"ready","stage_ordinal":9,"height":0,"rpc_bound":true,"serving":true,"started_unix":%s,"updated_unix":%s,"elapsed_s":0}\n' \
    "$now" "$now" > "$beacon"
before=$(sha256sum "$beacon" | cut -d' ' -f1)

# GNU flock's no-fork mode makes the lock holder itself the background PID,
# so cleanup can stop it without leaving a child that still holds the file.
flock -F "$pidfile" sleep 60 \
    </dev/null >"$ISO_DD/owner.log" 2>&1 &
holder_pid=$!
held=0
for ((attempt=0; attempt<50; attempt++)); do
    kill -0 "$holder_pid" 2>/dev/null || break
    if ! flock -n "$pidfile" true; then
        held=1
        break
    fi
    sleep 0.1
done
if [ "$held" -ne 1 ]; then
    echo 'boot-owner-beacon: fixture could not hold the datadir lock' >&2
    cat "$ISO_DD/owner.log" >&2
    exit 1
fi

set +e
timeout --signal=TERM --kill-after=5s 40s "$ISO_NODE_BIN" \
    -datadir="$ISO_DD" -regtest \
    -port="$ISO_PORT" -rpcport="$ISO_RPCPORT" \
    -fsport="$ISO_FSPORT" -httpsport="$ISO_HTTPSPORT" \
    -connect=127.0.0.1:"$ISO_CONNECT_SINK" \
    -nobgvalidation -nolegacyimport -nofilesync -showmetrics=0 \
    </dev/null >"$ISO_DD/second.log" 2>&1
second_rc=$?
set -e

after=$(sha256sum "$beacon" | cut -d' ' -f1)
if [ "$second_rc" -eq 0 ] || [ "$second_rc" -eq 124 ] ||
   ! rg -q 'BOOT_DATADIR_LOCKED' "$ISO_DD/second.log" ||
   [ "$before" != "$after" ] ||
   flock -n "$pidfile" true; then
    echo "boot-owner-beacon: FAIL exit=$second_rc before=$before after=$after" >&2
    tail -n 12 "$ISO_DD/second.log" >&2
    exit 1
fi

echo 'boot-owner-beacon: PASS refused second node preserved the owner beacon'
