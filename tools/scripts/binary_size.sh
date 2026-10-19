#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# binary_size.sh — the DERIVED source of truth for "how big is the binary".
#
# Dev-UX counterpart to the check-no-stale-pinned-facts lint gate. That gate
# forbids hand-pinning a "<N> MB binary" claim in the docs (a stale "~15 MB"
# survived long after the real binary grew past 20 MB). The sovereign-doctrine
# fix is DERIVE-OR-GATE: instead of pinning a number, a doc author (or agent)
# runs THIS and quotes the live value, and a reviewer re-runs it to confirm.
#
# DESIGN DECISION (step 2 of the anti-stale lane): the binary size is NOT baked
# into the machine-checked DOC-COUNTS block in docs/dev/CODEBASE_MAP.md. That block
# is build-free by contract (check_doc_counts.sh is "filesystem + grep only, no
# build"), whereas a binary size only exists after a whole-program LTO link and
# depends on the flag profile (release vs test, portable vs ZCL_NATIVE, Tor stub
# vs real libtor). Pinning it into a build-free doc gate would either break that
# contract or flake. So the answer is: forbid hand-pinned sizes (the gate) +
# size-agnostic prose ("compact self-contained C23 binary") + this on-demand
# derived helper for anyone who genuinely needs the current number.
#
# Usage:
#   tools/scripts/binary_size.sh            # human line for the default binary
#   tools/scripts/binary_size.sh --bytes    # just the byte count (scriptable)
#   tools/scripts/binary_size.sh path/to/bin
#
# Exit 0 with the size when the artifact exists; exit 1 (to stderr) when it has
# not been built yet — so callers can distinguish "unbuilt" from a real size.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

bytes_only=0
bin=""
for arg in "$@"; do
    case "$arg" in
        --bytes) bytes_only=1 ;;
        -*)      echo "binary_size.sh: unknown flag '$arg'" >&2; exit 2 ;;
        *)       bin="$arg" ;;
    esac
done
[[ -n "$bin" ]] || bin="$ROOT/build/bin/zclassic23"

if [[ ! -f "$bin" ]]; then
    echo "binary_size.sh: '$bin' not built yet — run 'make -j\$(nproc)' (or 'make build-only')." >&2
    exit 1
fi

size_bytes=$(stat -c%s "$bin" 2>/dev/null || stat -f%z "$bin")
if (( bytes_only )); then
    printf '%s\n' "$size_bytes"
    exit 0
fi

mb=$(awk -v b="$size_bytes" 'BEGIN { printf "%.1f", b / 1048576 }')
printf '%s bytes (~%s MB)  %s\n' "$size_bytes" "$mb" "$bin"
