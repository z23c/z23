#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
#
# Prove docs/CAPABILITY_INVENTORY.jsonl is exactly what the C23 source scanner
# derives from this checkout.  The report is evidence, never authored prose.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

DOC="docs/CAPABILITY_INVENTORY.jsonl"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/zcl-capability-inventory.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

SOURCES=(
    tools/gen_capability_inventory.c
    lib/codeindex/src/codeindex_inventory.c
    lib/codeindex/src/codeindex_inventory_scan.c
    lib/codeindex/src/codeindex_inventory_body.c
    lib/codeindex/src/codeindex_scan.c
    lib/codeindex/src/codeindex_scan_doc.c
    lib/base/src/safe_alloc.c
    lib/base/src/log_level.c
    lib/sha3/src/sha3.c
)

if [ ! -f "$DOC" ]; then
    echo "check_capability_inventory_generated: FATAL — missing $DOC" >&2
    echo "  Fix: make docs-capability-inventory" >&2
    exit 2
fi

CC_BIN="${CC:-cc}"
if ! "$CC_BIN" -std=c23 -D_POSIX_C_SOURCE=200809L -O2 -Wall -Wextra \
        -Werror -pedantic -Ilib/codeindex/include -Ilib/codeindex/src \
        -Ilib/base/include -Ilib/util/include -Ilib/sha3/include \
        -Ilib/crypto/include -Ilib/platform/include \
        -o "$TMP/gen_capability_inventory" "${SOURCES[@]}" \
        2>"$TMP/cc.log"; then
    echo "check_capability_inventory_generated: FATAL — generator compile failed" >&2
    sed 's/^/    /' "$TMP/cc.log" >&2
    exit 2
fi

if ! "$TMP/gen_capability_inventory" "$TMP/expected.jsonl" . \
        2>"$TMP/gen.log"; then
    echo "check_capability_inventory_generated: FATAL — derivation failed" >&2
    sed 's/^/    /' "$TMP/gen.log" >&2
    exit 2
fi

meta="$(head -n 1 "$TMP/expected.jsonl")"
capabilities="$(printf '%s\n' "$meta" | sed -n 's/.*"capabilities":\([0-9][0-9]*\).*/\1/p')"
roots_found="$(printf '%s\n' "$meta" | sed -n 's/.*"registered_test_roots_found":\([0-9][0-9]*\).*/\1/p')"
roots_missing="$(printf '%s\n' "$meta" | sed -n 's/.*"registered_test_roots_missing":\([0-9][0-9]*\).*/\1/p')"
if [ "${capabilities:-0}" -lt 1000 ] || [ "${roots_found:-0}" -lt 500 ] ||
   [ "${roots_missing:-1}" -ne 0 ]; then
    echo "check_capability_inventory_generated: FATAL — census floor/refusal failed" >&2
    echo "  capabilities=${capabilities:-missing} roots_found=${roots_found:-missing} roots_missing=${roots_missing:-missing}" >&2
    exit 2
fi

compare_doc() {
    local candidate="$1"
    diff -u "$candidate" "$TMP/expected.jsonl" >"$TMP/diff.log" 2>&1
}

if [ "${1:-}" = "--selftest" ]; then
    if ! compare_doc "$DOC"; then
        echo "check_capability_inventory_generated selftest: FATAL — baseline is stale" >&2
        echo "  Fix: make docs-capability-inventory" >&2
        exit 2
    fi
    cp "$DOC" "$TMP/tampered.jsonl"
    printf '%s\n' '{"record":"handwritten_finding"}' >>"$TMP/tampered.jsonl"
    if compare_doc "$TMP/tampered.jsonl"; then
        echo "check_capability_inventory_generated selftest: FAIL — a hand edit passed" >&2
        exit 1
    fi
    echo "check_capability_inventory_generated selftest: PASS — clean output passes and a hand edit fails"
    exit 0
fi

if ! compare_doc "$DOC"; then
    echo "FAIL: $DOC is stale or hand-edited." >&2
    echo "  Regenerate only with: make docs-capability-inventory" >&2
    head -60 "$TMP/diff.log" | sed 's/^/    /' >&2
    exit 1
fi

echo "check_capability_inventory_generated: clean — $capabilities capabilities; $roots_found registered roots resolved"
