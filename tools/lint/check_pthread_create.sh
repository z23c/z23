#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_pthread_create.sh — raw pthread_create outside thread_registry
# (Makefile `check-pthread-create` gate). Every long-running thread goes
# through thread_registry_spawn{,_ex}. Short-burst workers joined within the
# same function, and pthread_attr-using detached-helper wrappers, opt out with
# a `raw-pthread-ok` marker on the call line or the line immediately above.
# The registry's own implementation in lib/util/src/thread_registry.c is
# implicitly skipped. Extracted verbatim from the former inline Makefile
# recipe for tools/lint/run_lint.sh + standalone use.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

HITS=$(grep -rn 'pthread_create\s*(' lib/ app/ tools/ config/ --include='*.c' \
    | grep -v 'lib/test/' \
    | grep -v 'lib/util/src/thread_registry.c' \
    | grep -v 'thread_registry_spawn\|thread_registry_trampoline' \
    | grep -v 'raw-pthread-ok' \
    | while read -r line; do
        f=$(echo "$line" | cut -d: -f1)
        n=$(echo "$line" | cut -d: -f2)
        prev=$((n - 1))
        if [ "$prev" -gt 0 ] && \
           grep -q 'raw-pthread-ok' <<<"$(sed -n "${prev}p" "$f")"; then
            continue
        fi
        echo "$line"
    done || true)
if [ -n "$HITS" ]; then
    echo "$HITS"
    echo "FAIL: raw pthread_create in production code (use thread_registry_spawn{,_ex} or mark // raw-pthread-ok: <reason>)"
    exit 1
fi
echo "  OK: all pthread_create call sites accounted for"
