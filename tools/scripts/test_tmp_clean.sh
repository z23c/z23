#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# test-tmp scratch reclaimer (environment hygiene).
#
# The parallel test runner creates ./test-tmp/ and per-run captures
# (tests/harness/src/test_parallel.c:465-477) and the fixtures leave scratch dirs
# behind (anchor_selfmint_*, ...); nothing ever deletes them — 5,463 entries
# / ~1.4 G at last measure. This script removes entries older than --days N
# (default 2, find -mtime semantics).
#
# NOTE: this is the janitor, not the fix. The STRUCTURAL fix — test_parallel
# deleting each child's scratch on success — is a separate change and is
# deliberately NOT done here.
#
# DRY-RUN BY DEFAULT: prints the per-entry table and the reclaimable total.
# Nothing is removed unless --apply is passed explicitly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DAYS=2
APPLY=0
TARGET="$REPO_ROOT/test-tmp"

usage() {
    cat <<'USAGE'
usage: tools/scripts/test_tmp_clean.sh [--days N] [--apply] [--dry-run] [path]

Remove test-tmp scratch entries older than N days (default 2, by mtime).
Default path is <repo>/test-tmp; an explicit path is accepted only if its
basename is literally "test-tmp" (guard against rm -rf on the wrong tree).

Default is DRY-RUN: report only. --apply executes the removal.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --days)
            [ $# -ge 2 ] || { echo "test-tmp-clean: --days needs a value" >&2; exit 2; }
            DAYS="$2"
            shift
            ;;
        --days=*) DAYS="${1#--days=}" ;;
        --apply) APPLY=1 ;;
        --dry-run|--plan) APPLY=0 ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            printf 'test-tmp-clean: unknown arg %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
        *) TARGET="$1" ;;
    esac
    shift
done

case "$DAYS" in
    ''|*[!0-9]*)
        echo "test-tmp-clean: --days must be a non-negative integer (got '$DAYS')" >&2
        exit 2
        ;;
esac

if [ ! -d "$TARGET" ]; then
    echo "test-tmp-clean: nothing to do — $TARGET does not exist"
    exit 0
fi
if [ "$(basename "$TARGET")" != "test-tmp" ]; then
    echo "test-tmp-clean: REFUSING — target basename is not 'test-tmp': $TARGET" >&2
    exit 2
fi

human() {
    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec --suffix=B "$1" 2>/dev/null || printf '%s' "$1"
    else
        printf '%s' "$1"
    fi
}

mode="DRY-RUN"
[ "$APPLY" = "1" ] && mode="APPLY"
printf 'test-tmp-clean: %s (target: %s, older than %s days)\n' "$mode" "$TARGET" "$DAYS"
if [ "$APPLY" != "1" ]; then
    echo "test-tmp-clean: dry-run default — pass --apply to execute"
fi
echo

printf '%-12s %10s  %-24s  %s\n' ACTION BYTES MTIME ENTRY
n=0
bytes_total=0
rc=0
while IFS= read -r -d '' entry; do
    sz="$(du -sb -- "$entry" 2>/dev/null | awk '{print $1}')"
    sz="${sz:-0}"
    mtime="$(stat -c '%y' -- "$entry" 2>/dev/null | cut -c1-19)"
    n=$((n + 1))
    bytes_total=$((bytes_total + sz))
    if [ "$APPLY" = "1" ]; then
        if rm -rf -- "$entry"; then
            printf '%-12s %10s  %-24s  %s\n' REMOVED "$(human "$sz")" "$mtime" "$entry"
        else
            printf '%-12s %10s  %-24s  %s\n' FAILED "$(human "$sz")" "$mtime" "$entry" >&2
            rc=1
        fi
    else
        printf '%-12s %10s  %-24s  %s\n' WOULD-REMOVE "$(human "$sz")" "$mtime" "$entry"
    fi
done < <(find "$TARGET" -mindepth 1 -maxdepth 1 -mtime +"$DAYS" -print0 | sort -z)

echo
printf 'TOTAL: %d entries, %s reclaimable%s\n' \
    "$n" "$(human "$bytes_total")" \
    "$([ "$APPLY" = "1" ] && echo ' (removed)' || echo ' (dry-run — nothing removed)')"

exit "$rc"
