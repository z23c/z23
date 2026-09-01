#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_json_value_init.sh — a `struct json_value` local must be zeroed
# (`= {0}`) or json_init()ed before any json_set_*() / json_free() touches it.
#
# WHY THIS GATE EXISTS. json_set_object()/json_set_array()/json_set_str() and
# friends all call json_free(v) FIRST, to release what the value held before
# (platform/modules/json/src/json.c). On an uninitialised stack local that "release" reads
# garbage type/num_children/children and frees or walks it. The contract is
# already stated in platform/modules/json/include/json/json.h ("Stack values must be
# zero-initialized or passed through json_init()") — this gate is what makes
# the statement true.
#
# It was written after zid_domain_dump_state_json() did exactly this and
# segfaulted a serving node every ~15 minutes:
#     json_free+0x43 <- zid_domain_dump_state_json+0x1b9 <- debug_bundle_write
# Whether it faults depends on what the previous frame left behind, so the
# same binary can look fine for hours and then kill a node mid-sync.
#
# SCOPE — the unambiguous, purely local pattern only:
#     struct json_value NAME;      <- no initialiser
#     ... first mention of NAME is json_set_*(&NAME) or json_free(&NAME)
# Indirection through a helper that takes &NAME is NOT flagged; helpers own
# their out-param (see core/math/src/core_io.c, which json_init()s first).
# Every file under the repo is scanned, tests included — the UB is identical
# there and a test that corrupts its own stack is not a passing test.
#
# ZERO baseline on purpose: the class was empty when this gate landed, so
# there is nothing to grandfather and no allowlist to erode.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || exit 1

SELFTEST=0
[ "${1:-}" = "--self-test" ] && SELFTEST=1

# scan_one <file> — emit "file:line: NAME -> <offending line>" per violation.
scan_one() {
    awk -v F="$1" '
        # A bare local declaration: no initialiser, no pointer, not a prototype.
        /^[ \t]*struct json_value[ \t]+[A-Za-z_][A-Za-z_0-9]*[ \t]*;[ \t]*$/ {
            name = $0
            sub(/^[ \t]*struct json_value[ \t]+/, "", name)
            sub(/[ \t]*;.*$/, "", name)
            pend[name] = NR
            next
        }
        {
            for (n in pend) {
                if ($0 ~ ("[^A-Za-z_0-9]" n "[^A-Za-z_0-9]") ||
                    $0 ~ ("[^A-Za-z_0-9]" n "$")) {
                    if ($0 !~ ("json_init\\([ \t]*&" n "[ \t]*\\)") &&
                        ($0 ~ ("json_set_(object|array|str|int|bool|real|null)\\([ \t]*&" n "[,)]") ||
                         $0 ~ ("json_free\\([ \t]*&" n "[ \t]*\\)"))) {
                        printf "%s:%d: %s -> %s\n", F, pend[n], n, $0
                    }
                    delete pend[n]
                }
            }
        }
    ' "$1"
}

if [ "$SELFTEST" = "1" ]; then
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/jsoninit-selftest-XXXXXX")"
    trap 'rm -rf "$tmp"' EXIT
    cat >"$tmp/bad.c" <<'EOF'
void f(void) {
    struct json_value arr;
    json_set_array(&arr);
}
EOF
    cat >"$tmp/good.c" <<'EOF'
void g(void) {
    struct json_value arr = {0};
    json_set_array(&arr);
    struct json_value obj;
    json_init(&obj); json_set_object(&obj);
}
EOF
    bad_n="$(scan_one "$tmp/bad.c" | grep -c . || true)"
    good_n="$(scan_one "$tmp/good.c" | grep -c . || true)"
    if [ "$bad_n" != "1" ] || [ "$good_n" != "0" ]; then
        echo "FAIL: check_json_value_init self-test (bad=$bad_n want 1, good=$good_n want 0)"
        exit 1
    fi
    echo "OK: check_json_value_init self-test (detects the bad shape, passes both good shapes)"
    exit 0
fi

violations=""
while IFS= read -r f; do
    out="$(scan_one "$f")"
    [ -n "$out" ] && violations="${violations}${out}"$'\n'
done < <(git ls-files '*.c')

if [ -n "${violations//[[:space:]]/}" ]; then
    echo "$violations"
    echo "FAIL: struct json_value used before it was initialised"
    echo "  json_set_*() and json_free() release the value's PREVIOUS contents"
    echo "  first, so on an uninitialised local they free/walk stack garbage."
    echo "  Declare it 'struct json_value x = {0};' or call json_init(&x) first"
    echo "  (contract: platform/modules/json/include/json/json.h)."
    exit 1
fi

echo "OK: check_json_value_init - every struct json_value local is initialised before use"
exit 0
