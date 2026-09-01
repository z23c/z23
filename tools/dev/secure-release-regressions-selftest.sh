#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Prove the physical gate and canonical release-intent manifest name one exact set.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MAKE_GROUPS="${1:-}"
MANIFEST="$ROOT/contexts/commons/modules/vcs/src/build_release_regressions.c"
CATALOG="$ROOT/tools/dev/test_group_catalog.def"

fail()
{
    printf 'secure-release-regressions-selftest: FAIL: %s\n' "$*" >&2
    exit 1
}

[ -n "$MAKE_GROUPS" ] || fail 'expected the Makefile exact group set'
MANIFEST_GROUPS="$(sed -n \
    '/^    "runner=/d; s/^    "[a-z_]*=\(test_[^"]*\)\\n"[,;]*$/\1/p' \
    "$MANIFEST" |
    paste -sd, -)"
[ -n "$MANIFEST_GROUPS" ] || fail 'canonical manifest group set is empty'
[ "$MANIFEST_GROUPS" = "$MAKE_GROUPS" ] ||
    fail "Makefile/manifest drift: make=$MAKE_GROUPS manifest=$MANIFEST_GROUPS"

EXPECTED_CASES="stale_wal_ownership,lease_takeover,mempool_generation,provider_reconnect,utxo_mirror_storm,diagnostic_teardown,rollback"
MANIFEST_CASES="$(sed -n \
    '/^    "runner=/d; s/^    "\([a-z_]*\)=test_[^"]*\\n"[,;]*$/\1/p' \
    "$MANIFEST" | paste -sd, -)"
[ "$MANIFEST_CASES" = "$EXPECTED_CASES" ] ||
    fail "historical case drift: expected=$EXPECTED_CASES actual=$MANIFEST_CASES"

IFS=',' read -r -a groups <<<"$MANIFEST_GROUPS"
declare -A seen=()
for group in "${groups[@]}"; do
    [[ "$group" =~ ^test_[a-z0-9_]+$ ]] ||
        fail "noncanonical group id: $group"
    [ -z "${seen[$group]:-}" ] || fail "duplicate group id: $group"
    seen[$group]=1
    symbol="${group#test_}"
    grep -Fxq "ZCL_TEST_GROUP($symbol)" "$CATALOG" ||
        fail "group is absent from the exact test catalog: $group"
done

printf 'secure-release-regressions-selftest: PASS cases=7 groups=%d exact=true\n' \
    "${#groups[@]}"
