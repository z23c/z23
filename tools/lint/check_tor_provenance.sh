#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck source=tools/scripts/tor_provenance_lib.sh
. "$ROOT/tools/scripts/tor_provenance_lib.sh"
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
# The REAL gate: judge compiler_id and configure_args_sha256 too, not just
# archive_sha256/tor_commit. Derived the SAME way tor_archives_ready.sh's
# have_all() derives it (zcl_tor_compiler_identity_for_cc, shared via
# tor_provenance_lib.sh) so writer and every reader can never drift apart.
tor_effective_cc="$(zcl_tor_effective_cc "$ROOT/vendor/tor" "")" || exit 1
tor_compiler_id="$(zcl_tor_compiler_identity_for_cc "$ROOT" "$tor_effective_cc")" || {
    echo "check-tor-provenance: could not derive a compiler identity for $tor_effective_cc" >&2
    exit 1
}
"$ROOT/build/bin/z23-tor-provenance" check "$ROOT/vendor/tor" \
    --tor-commit "$commit" --compiler-id "$tor_compiler_id"
