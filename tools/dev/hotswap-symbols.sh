#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# hotswap-symbols.sh — will this module actually MOUNT?
#
#   tools/dev/hotswap-symbols.sh <module.so> [node-binary]
#   tools/dev/hotswap-symbols.sh --all [node-binary]
#
# WHY THIS EXISTS. A hot-swap module carries undefined symbols on purpose: the
# kernel entry points it calls (json_*, node_rpc_call_*, zcl_native_bridge_run,
# ...) live in the resident node and bind at dlopen against its -rdynamic
# export table. Whether they ALL resolve is the difference between a module
# that mounts and one that does not.
#
# Nothing checked that. The two existing checks each miss it from a different
# side:
#
#   tools/dev/hotswap-verify.sh proves the module's MANIFEST is admissible --
#   real symbol, right ABI, well-formed leaf table, allowlist match, probe and
#   self-test pass. But it dlopens a copy RE-LINKED with -Wl,-z,lazy, because
#   the small verifier process does not export the node's symbols and a -z now
#   dlopen would fail there for reasons that say nothing about the module. Lazy
#   binding defers every unresolved symbol to first call, so an unresolvable
#   one sails straight through admission.
#
#   The shipped artifact is linked -Wl,-z,now (Makefile HARDEN/module link), so
#   the real dlopen resolves everything up front and fails loudly.
#
# Verification is therefore strictly LOOSER than production in exactly the
# dimension that decides whether the thing loads -- a false-pass direction. It
# is not hypothetical: a module that built and verified cleanly failed at
# `dlopen: undefined symbol: zcl_native_policy_resident_booted` against a
# stale resident, and nothing before the attempt said the resident was behind.
#
# This script closes that gap WITHOUT needing a running node, by answering the
# same question the loader asks: is every strong undefined symbol in the module
# provided by the node binary or by one of the libraries the node itself links?
#
# WHAT IT PROVES: every strong undefined symbol has a definition in the
# resolution set, so a -z now dlopen against THIS node build will not fail for
# a missing symbol.
#
# WHAT IT DOES NOT PROVE: that the definition found is the RIGHT one (ABI or
# semantics), that the module is admissible (hotswap-verify.sh owns that), or
# anything about a different node build. It is a pre-mount check bound to one
# specific binary, which is why the report names that binary.
#
# Weak undefined symbols (__gmon_start__, the _ITM_* clone-table pair) are
# excluded: by definition they may resolve to zero, and the dynamic linker does
# not fail on them.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

SCRATCH="${ZCL_HOTSWAP_SYMBOLS_DIR:-$HOME/.local/state/zclassic23/scratch/hotswap-symbols}"
mkdir -p "$SCRATCH" || { echo "hotswap-symbols: cannot create $SCRATCH" >&2; exit 2; }

usage() {
    echo "usage: tools/dev/hotswap-symbols.sh <module.so> [node-binary]" >&2
    echo "       tools/dev/hotswap-symbols.sh --all [node-binary]" >&2
}

command -v nm >/dev/null 2>&1 || {
    echo "hotswap-symbols: nm not found; cannot read dynamic symbol tables" >&2
    exit 2
}

# ── the resolution set: the node's own exports, plus every library it links ──
#
# Built once per run and reused. `ldd` is the honest source for the library
# list: it is the same set the dynamic linker will have mapped when the module
# is dlopen'd into that process.
build_resolution_set() {
    local node="$1" out="$2" lib
    : > "$out"
    nm -D --defined-only "$node" 2>/dev/null |
        awk 'NF >= 2 { print $NF }' | sed 's/@.*//' >> "$out"
    local n_node
    n_node="$(wc -l < "$out")"
    if [ "$n_node" -lt 1000 ]; then
        # A node built without -rdynamic exports almost nothing, and every
        # module would then look broken. Refuse rather than report a flood of
        # false unresolved symbols.
        echo "hotswap-symbols: FATAL — $node exports only $n_node dynamic symbol(s)." >&2
        echo "  A dev node is linked -rdynamic and exports tens of thousands." >&2
        echo "  Refusing to judge any module against an export table this small." >&2
        return 2
    fi
    while IFS= read -r lib; do
        [ -n "$lib" ] && [ -r "$lib" ] || continue
        nm -D --defined-only "$lib" 2>/dev/null |
            awk 'NF >= 2 { print $NF }' | sed 's/@.*//' >> "$out"
    done < <(ldd "$node" 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i ~ /^\//) { print $i; break }}')
    LC_ALL=C sort -u -o "$out" "$out"
    return 0
}

# Strong undefined symbols only. `nm -D` prints the type in the field before
# the name; 'U' is a strong undefined, 'w' a weak one that may resolve to zero.
module_needs() {
    nm -D "$1" 2>/dev/null |
        awk 'NF >= 2 && $(NF - 1) == "U" { print $NF }' | sed 's/@.*//' |
        LC_ALL=C sort -u
}

NODE_ARG=""
TARGETS=()
case "${1:-}" in
    -h|--help|"") usage; exit 2 ;;
    --all)
        NODE_ARG="${2:-}"
        mapfile -t TARGETS < <(ls -1 build/hotswap/*.so 2>/dev/null)
        if [ "${#TARGETS[@]}" -eq 0 ]; then
            echo "hotswap-symbols: FATAL — no modules in build/hotswap/." >&2
            echo "  Refusing to report success with nothing checked." >&2
            exit 2
        fi
        ;;
    *)
        TARGETS=("$1")
        NODE_ARG="${2:-}"
        ;;
esac

NODE="${NODE_ARG:-${ZCL_HOTSWAP_NODE_BINARY:-build/bin/zclassic23-dev}}"
if [ ! -r "$NODE" ]; then
    echo "hotswap-symbols: node binary '$NODE' not readable." >&2
    echo "  Build it with 'make fast-rebuild', or pass one explicitly." >&2
    exit 2
fi

RESOLVE="$SCRATCH/resolution-set.txt"
build_resolution_set "$NODE" "$RESOLVE" || exit 2

echo "══ hot-swap module symbol resolution (${#TARGETS[@]} module(s)) ══"
echo "   against : $NODE"
echo "   provides: $(wc -l < "$RESOLVE") symbol(s) (node + linked libraries)"

pass=0
fail=0
failed=""
for so in "${TARGETS[@]}"; do
    [ -n "$so" ] || continue
    if [ ! -r "$so" ]; then
        echo "  MISSING  $so"
        fail=$((fail + 1)); failed="${failed}  $so (unreadable)"$'\n'
        continue
    fi
    needs="$SCRATCH/needs.txt"
    module_needs "$so" > "$needs"
    n_needs="$(wc -l < "$needs")"
    if [ "$n_needs" -eq 0 ]; then
        # A module with zero strong undefined symbols never calls the kernel.
        # That is not a pass, it is a sign the symbol table was not read.
        echo "  FATAL    ${so##*/}: zero strong undefined symbols" >&2
        echo "           A leaf that calls nothing in the node is not a module." >&2
        fail=$((fail + 1)); failed="${failed}  $so (no undefined symbols)"$'\n'
        continue
    fi
    unresolved="$(LC_ALL=C comm -23 "$needs" "$RESOLVE")"
    if [ -n "$unresolved" ]; then
        echo "  UNRESOLVED  ${so##*/}"
        printf '%s\n' "$unresolved" | sed 's/^/                /'
        fail=$((fail + 1)); failed="${failed}  $so"$'\n'
    else
        echo "  MOUNTABLE   ${so##*/}  ($n_needs symbol(s) all resolved)"
        pass=$((pass + 1))
    fi
done

echo
if [ "$fail" -ne 0 ]; then
    echo "FAIL: $fail of $((pass + fail)) module(s) would fail a -z now dlopen against $NODE:"
    printf '%s' "$failed"
    echo "  A module is built against the node it will be loaded into. If the node"
    echo "  is behind the module, rebuild it: make fast-rebuild"
    exit 1
fi
echo "OK: $pass module(s) resolve every strong undefined symbol against $NODE"
exit 0
