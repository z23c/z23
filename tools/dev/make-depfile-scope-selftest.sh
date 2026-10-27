#!/bin/sh
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# Build and run the native real-Makefile depfile fixture in disposable scratch.
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-depfile-scope.XXXXXX")"
child=
cleanup()
{
    if [ -n "$child" ]; then
        kill "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
    rm -rf -- "$WORK"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
make -C "$ROOT" --no-print-directory ZCL_STANDALONE_CLEAN=1 \
    BIN_DIR="$WORK/bin" "$WORK/bin/make-depfile-scope-selftest" &
child=$!
wait "$child"
child=
"$WORK/bin/make-depfile-scope-selftest" "$ROOT" "$WORK" &
child=$!
wait "$child"
child=
