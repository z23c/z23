#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_malloc.sh — bare malloc/calloc/realloc in app/tools code (Makefile
# `check-malloc` gate). Every allocation must go through zcl_malloc/zcl_calloc/
# zcl_realloc (platform/modules/util safe_alloc) or carry a `raw-alloc-ok` marker. Extracted
# verbatim from the former inline Makefile recipe so the gate can run under
# tools/lint/run_lint.sh (and standalone in ~ms without a Make parse).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

HITS=$(grep -rn '[^_]malloc\s*(' app/ tools/ --include='*.c' --include='*.h' \
    | grep -v 'zcl_malloc\|zcl_calloc\|zcl_realloc\|raw-alloc-ok\|safe_alloc\|".*malloc\|LOG_\|fprintf' || true)
if [ -n "$HITS" ]; then
    echo "$HITS"
    echo "FAIL: bare malloc in app/tools code (use zcl_malloc or mark // raw-alloc-ok)"
    exit 1
fi
HITS=$(grep -rn '[^_]calloc\s*(' app/ tools/ --include='*.c' --include='*.h' \
    | grep -v 'zcl_calloc\|raw-alloc-ok\|safe_alloc\|".*calloc\|LOG_\|fprintf' || true)
if [ -n "$HITS" ]; then
    echo "$HITS"
    echo "FAIL: bare calloc in app/tools code (use zcl_calloc or mark // raw-alloc-ok)"
    exit 1
fi
HITS=$(grep -rn '[^_]realloc\s*(' app/ tools/ --include='*.c' --include='*.h' \
    | grep -v 'zcl_realloc\|raw-alloc-ok\|safe_alloc\|".*realloc\|LOG_\|fprintf' || true)
if [ -n "$HITS" ]; then
    echo "$HITS"
    echo "FAIL: bare realloc in app/tools code (use zcl_realloc or mark // raw-alloc-ok)"
    exit 1
fi
echo "  OK: no raw allocations"
