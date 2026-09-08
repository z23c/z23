#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1
work="$(mktemp -d "${TMPDIR:-/tmp}/tor-compiler.XXXXXX")" || exit 1
trap 'rm -f "$work/positive.log" "$work/negative.log"; rmdir "$work"' EXIT

# CC is the same trusted command prefix Make executes, including wrappers
# and quoted paths. Forward fixture arguments separately without re-parsing.
compiler_run() {
    bash -c 'exec '"${CC:-cc}"' "$@"' compiler \
        -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
        -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE \
        -Icontexts/commons/packages/zsha256/include \
        -Iplatform/modules/platform/include \
        -fsyntax-only tools/tor_provenance.c "$@"
}
if compiler_run -Iplatform/modules/base/include > "$work/positive.log" 2>&1; then
    positive=0
else
    positive=$?
fi
if compiler_run > "$work/negative.log" 2>&1; then
    negative=0
else
    negative=$?
fi
# The native C23 helper owns acceptance of statuses and bounded diagnostics.
"$ROOT/build/bin/z23-tor-provenance" check-compiler-results \
    "$positive" "$negative" "$work/positive.log" "$work/negative.log" || exit 1
"$ROOT/build/bin/z23-tor-provenance" --selftest || exit 1
commit="$(git -C "$ROOT/vendor/tor" rev-parse --verify HEAD)" || exit 1
"$ROOT/build/bin/z23-tor-provenance" check "$ROOT/vendor/tor" --tor-commit "$commit"
