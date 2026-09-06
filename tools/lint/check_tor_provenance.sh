#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# The pre-Make helper must keep the same hex include directory as
# $(TOR_PROVENANCE_BIN). Omitting it is how a fresh `make setup` failed
# to compile tools/tor_provenance.c after digest formatting moved to
# base/hex.h.
LIB="$ROOT/tools/scripts/tor_provenance_lib.sh"
grep -F 'platform/modules/base/include' "$LIB" >/dev/null || {
    echo "check-tor-provenance: tor_provenance_lib.sh is missing the hex.h include path the Makefile already has" >&2
    exit 1
}
# Born-red: compiling the shipped source without that -I must still fail
# on base/hex.h, so the grep is guarding a real compile rather than a comment.
red_out="$(mktemp "${TMPDIR:-/tmp}/tor-prov-red.XXXXXX")" || exit 1
red_obj="$(mktemp "${TMPDIR:-/tmp}/tor-prov-red.XXXXXX.o")" || exit 1
trap 'rm -f "$red_out" "$red_obj"' EXIT
if "${CC:-cc}" -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
        -D_POSIX_C_SOURCE=200809L \
        -I"$ROOT/contexts/commons/packages/zsha256/include" \
        -c "$ROOT/tools/tor_provenance.c" -o "$red_obj" \
        >"$red_out" 2>&1; then
    echo "check-tor-provenance: compile without the hex include unexpectedly succeeded" >&2
    exit 1
fi
# Apple Clang quotes the include (`'base/hex.h' file not found`);
# Linux gcc/clang says `fatal error: base/hex.h: No such file`.
# Match the header token, not one compiler's wording.
grep -F 'base/hex.h' "$red_out" >/dev/null || {
    echo "check-tor-provenance: omitting the hex include did not fail on base/hex.h" >&2
    cat "$red_out" >&2
    exit 1
}
echo "check-tor-provenance: omitting hex include fails on base/hex.h (born-red)"
"$ROOT/build/bin/z23-tor-provenance" --selftest &&
exec "$ROOT/build/bin/z23-tor-provenance" check "$ROOT/vendor/tor" --tor-commit "$(git -C "$ROOT/vendor/tor" rev-parse HEAD)"
