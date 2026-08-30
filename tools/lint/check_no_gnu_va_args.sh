#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_no_gnu_va_args.sh — ban the GNU comma-swallowing extension
# `, ##__VA_ARGS__` in favour of the C23 standard `__VA_OPT__`
# (Makefile `check-no-gnu-va-args` gate).
#
# Why this is a gate and not a style note: the tree is built by exactly one
# compiler, so a GNU-only idiom is invisible until someone builds with a second
# one. A single `, ##__VA_ARGS__` in a header that is included nearly
# everywhere -- lib/util/include/util/log_macros.h is included by ~1100
# translation units -- produced 7,141 diagnostics under
# `clang -std=c23 -pedantic`, which is enough noise to bury real findings.
#
# The C23 replacement is exact:
#     ..., __func__, ##__VA_ARGS__      ->  ..., __func__ __VA_OPT__(,) __VA_ARGS__
#     snprintf(buf, cap, fmt, ##__VA_ARGS__) -> snprintf(buf, cap, fmt __VA_OPT__(,) __VA_ARGS__)
# Both forms emit the comma only when the variadic list is non-empty, and the
# resulting token streams are identical on gcc and clang for the zero-vararg,
# one-vararg, n-vararg, and macro-valued-argument cases.
#
# Opt out on the call line or the line immediately above with a
# `gnu-va-args-ok:` marker plus a reason, for a site that genuinely needs the
# GNU behaviour (there are none today).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

# `,` then optional whitespace then `##` then `__VA_ARGS__`.
HITS=$(grep -rn ',[[:space:]]*##[[:space:]]*__VA_ARGS__' \
        app/ config/ core/ lib/ domain/ application/ adapters/ ports/ src/ tools/ \
        --include='*.c' --include='*.h' \
    | grep -v 'gnu-va-args-ok' \
    | while IFS= read -r line; do
        f=${line%%:*}
        rest=${line#*:}
        n=${rest%%:*}
        prev=$((n - 1))
        if [ "$prev" -gt 0 ] && \
           grep -q 'gnu-va-args-ok' <<<"$(sed -n "${prev}p" "$f" 2>/dev/null)"; then
            continue
        fi
        echo "$line"
    done || true)

if [ -n "$HITS" ]; then
    echo "$HITS"
    echo "FAIL: GNU ', ##__VA_ARGS__' extension in C23 source."
    echo "      Use '__VA_OPT__(,) __VA_ARGS__' instead, or mark the line"
    echo "      // gnu-va-args-ok: <reason>"
    exit 1
fi
echo "  OK: no GNU comma-swallowing __VA_ARGS__ (C23 __VA_OPT__ everywhere)"
