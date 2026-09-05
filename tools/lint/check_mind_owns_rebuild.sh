#!/usr/bin/env bash
# check-mind-owns-rebuild — exactly one process rebuilds a checkout's index.
#
# WHAT IT PROVES. codeindex_rebuild() is called only from the codeindex module
# that implements it, from the resident that owns rebuilding (tools/mind/), and
# from the codeindex module's own tests. Any other caller is a second writer:
# it races the resident's publication, and it pays the rebuild inside whatever
# it was doing — measured at 6,750 to 12,301 ms, three of four runs ending
# fail-closed because the tree moved underneath the build.
#
# WHAT IT DOES NOT PROVE. It is a source-level fact, not a runtime one. It says
# nothing about who holds the owner marker at any moment; that is
# codeindex_owner_is_live()'s job, and docs/MIND.md states the rule.
#
# Comments and prose naming the function are not calls. The scan matches a
# call site — the name immediately followed by `(` — and then drops matches
# whose line is a `//` or `*` comment, so a file may explain the rule without
# tripping it.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

GATE="check-mind-owns-rebuild"
CALL='codeindex_rebuild[[:space:]]*\('

# The three homes a call may have, each for a stated reason:
#   the module that defines and publishes the build;
#   the resident that owns rebuilding for the node;
#   that module's own tests, which drive the build directly on a fixture.
ALLOWED_RE='^(cognition/modules/codeindex/(src|include)/|tools/mind/|tests/harness/src/test_codeindex)'

if [[ "${1:-}" == "--selftest" ]]; then
    [[ 'cognition/modules/codeindex/src/codeindex_build.c' =~ $ALLOWED_RE ]] || exit 1
    [[ 'tools/mind/mind_resident.c' =~ $ALLOWED_RE ]] || exit 1
    [[ 'tests/harness/src/test_codeindex.c' =~ $ALLOWED_RE ]] || exit 1
    [[ 'tools/command/native_code_command.c' =~ $ALLOWED_RE ]] && exit 1
    [[ 'cognition/services/src/zcode_goal_context_service.c' =~ $ALLOWED_RE ]] && exit 1
    [[ '    if (!codeindex_rebuild(ci))' =~ $CALL ]] || exit 1
    [[ ' * Explicit codeindex_rebuild() remains a forced recompute' =~ $CALL ]] || exit 1
    printf '%s selftest: OK\n' "$GATE"
    exit 0
fi

# Every tracked C source or header naming the call, comment lines removed.
hits="$(gate_grep -n -E "$CALL" -- \
    $(git ls-files -- '*.c' '*.h') || true)"
call_lines="$(printf '%s\n' "$hits" | grep -v '^[[:space:]]*$' \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(/\*|\*|//)' || true)"

scanned=0
[[ -z "$call_lines" ]] || scanned="$(printf '%s\n' "$call_lines" | wc -l)"
# The definition itself, its declaration, and the module's own internal calls
# are always present. A scan that finds fewer than four call lines has lost
# the file that defines the function, not proved the tree clean.
gate_require_scanned "$scanned" 4 "$GATE" \
    "codeindex_rebuild's own module should always appear; check the pathspec."

violations=""
while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    path="${line%%:*}"
    [[ "$path" =~ $ALLOWED_RE ]] || violations+="$line"$'\n'
done <<< "$call_lines"

if [[ -n "$violations" ]]; then
    printf '%s: FAIL — codeindex_rebuild called outside the mind and the codeindex module\n' "$GATE" >&2
    printf '%s' "$violations" >&2
    printf '  A query that rebuilds is a second writer racing the node resident.\n' >&2
    printf '  Read the published generation with codeindex_open_readonly() and\n' >&2
    printf '  refuse a stale one; the mind rebuilds. See docs/MIND.md.\n' >&2
    exit 1
fi

printf '%s: PASS — %s call site(s), all inside the codeindex module, tools/mind/, or that module'"'"'s own tests\n' \
    "$GATE" "$scanned"
