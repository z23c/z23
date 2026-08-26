#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# hotswap-verify.sh — prove a hot-swap module allowlist row is actually
# LOADABLE, not merely listed.
#
#   tools/dev/hotswap-verify.sh app/controllers/src/status_native_handlers.c
#   tools/dev/hotswap-verify.sh --all
#
# For each row of config/hotswap_swappable.def this:
#   1. builds the module .so via `make hotswap-module-so FILE=<tu>` (the exact
#      shipping recipe: same compiler, same DEV_LIVE_CFLAGS, same
#      -DZCL_HOTSWAP_MODULE_GEN, same island unity-include);
#   2. re-links the resulting object with -Wl,-z,lazy into a scratch,
#      verification-only artifact (see the LAZY-BINDING NOTE in
#      tools/dev/hotswap_verify_so.c for why this is sound and what it costs);
#   3. dlopens it and runs the REAL hotswap_module_admit() gauntlet.
#
# Exit 0 only if every requested row is ADMITTED. This is deliberately NOT the
# activation path: no registry commit, no live probe, no datadir, no node.
#
# Scratch lives under ZCL_HOTSWAP_VERIFY_DIR (default
# ~/.local/state/zclassic23/scratch/hotswap-verify), never /tmp, and never in
# build/ — a lazily-bound artifact must not be mistakable for a shippable one.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

SCRATCH="${ZCL_HOTSWAP_VERIFY_DIR:-$HOME/.local/state/zclassic23/scratch/hotswap-verify}"
mkdir -p "$SCRATCH" || { echo "hotswap-verify: cannot create $SCRATCH" >&2; exit 2; }

MANIFEST="${ZCL_HOTSWAP_SWAPPABLE_MANIFEST:-config/hotswap_swappable.def}"
FLAGS_ENV="build/hotswap/fast/flags.env"

# Rows of the swappable manifest, one source_tu per line. Same COLUMN-1,
# paren-depth, string-literal-aware walk the lint gates use, so the macro
# signature spelled out in the manifest's header comment is never a row.
manifest_sources() {
    awk -v TOK='HOTSWAP_SWAPPABLE(' '
    { buf = buf $0 "\n" }
    END {
        n = length(buf); L = length(TOK); i = 1
        while (i <= n) {
            if (substr(buf, i, L) != TOK || (i > 1 && substr(buf, i - 1, 1) != "\n")) {
                i++; continue
            }
            j = i + L; depth = 1; in_str = 0; esc = 0; spec = ""
            while (j <= n && depth > 0) {
                c = substr(buf, j, 1)
                if (in_str) {
                    if (esc) { esc = 0 }
                    else if (c == "\\") { esc = 1 }
                    else if (c == "\"") { in_str = 0 }
                } else {
                    if (c == "\"") { in_str = 1 }
                    else if (c == "(") { depth++ }
                    else if (c == ")") { depth-- }
                }
                if (depth > 0) spec = spec c
                j++
            }
            if (match(spec, /"[^"]*"/)) print substr(spec, RSTART + 1, RLENGTH - 2)
            i = j
        }
    }' "$MANIFEST"
}

TARGETS=()
if [ "$#" -eq 0 ] || [ "${1:-}" = "--all" ]; then
    mapfile -t TARGETS < <(manifest_sources)
    if [ "${#TARGETS[@]}" -eq 0 ]; then
        echo "hotswap-verify: FATAL — $MANIFEST parsed to zero rows." >&2
        echo "  Refusing to report success with nothing verified." >&2
        exit 2
    fi
else
    TARGETS=("$@")
fi

# The verifier itself is built once, against the real lib/hotswap admission
# code. --gc-sections drops hotswap_activate()'s dlopen core and its json /
# sha256 / logging imports, which the admit path never reaches; without it the
# link would drag most of the node in for a pure predicate.
build_verifier() {
    [ -r "$FLAGS_ENV" ] || {
        echo "hotswap-verify: $FLAGS_ENV missing — run 'make hotswap-module-so FILE=<tu>' once first." >&2
        return 2
    }
    local cc cflags
    cc="$(sed -n 's/^CC=//p' "$FLAGS_ENV")"
    cflags="$(sed -n 's/^DEV_CFLAGS=//p' "$FLAGS_ENV")"
    [ -n "$cc" ] && [ -n "$cflags" ] || {
        echo "hotswap-verify: could not parse CC/DEV_CFLAGS from $FLAGS_ENV" >&2
        return 2
    }
    # shellcheck disable=SC2086
    $cc $cflags -ffunction-sections -fdata-sections \
        -o "$SCRATCH/hotswap_verify_so" \
        tools/dev/hotswap_verify_so.c \
        lib/hotswap/src/hotswap_activate.c \
        lib/hotswap/src/hotswap_islands.c \
        -Wl,--gc-sections -ldl || return 1
    return 0
}

echo "══ hot-swap module load verification (${#TARGETS[@]} row(s)) ══"
build_verifier || { echo "hotswap-verify: verifier build failed" >&2; exit 2; }

pass=0
fail=0
failed_rows=""
for tu in "${TARGETS[@]}"; do
    [ -n "$tu" ] || continue
    echo
    echo "── $tu"

    if ! make hotswap-module-so FILE="$tu" > "$SCRATCH/build.log" 2>&1; then
        echo "  FAIL: module build failed"
        tail -15 "$SCRATCH/build.log" | sed 's/^/    /'
        fail=$((fail + 1)); failed_rows="${failed_rows}  $tu (build)"$'\n'
        continue
    fi

    safe="$(printf '%s' "$tu" | tr -c 'A-Za-z0-9_.-' '_')"
    obj="build/hotswap/fast/$safe.o"
    if [ ! -f "$obj" ]; then
        echo "  FAIL: expected cached object $obj not produced"
        fail=$((fail + 1)); failed_rows="${failed_rows}  $tu (no object)"$'\n'
        continue
    fi

    cc="$(sed -n 's/^CC=//p' "$FLAGS_ENV")"
    lazy_so="$SCRATCH/$safe.verify.so"
    # Same object, same -Bsymbolic; only -z now becomes -z lazy.
    # shellcheck disable=SC2086
    if ! $cc -shared -Wl,--build-id=none -Wl,-z,relro -Wl,-z,lazy \
             -Wl,-z,noexecstack -Wl,-Bsymbolic \
             -o "$lazy_so" "$obj" 2>"$SCRATCH/link.log"; then
        echo "  FAIL: verification re-link failed"
        sed 's/^/    /' "$SCRATCH/link.log"
        fail=$((fail + 1)); failed_rows="${failed_rows}  $tu (relink)"$'\n'
        continue
    fi

    if "$SCRATCH/hotswap_verify_so" "$lazy_so" "$tu" 2>&1 | sed 's/^/    /'; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1)); failed_rows="${failed_rows}  $tu (admit)"$'\n'
    fi
done

echo
if [ "$fail" -ne 0 ]; then
    echo "FAIL: $fail of $((pass + fail)) swappable row(s) are NOT loadable:"
    printf '%s' "$failed_rows"
    exit 1
fi
if [ "$pass" -eq 0 ]; then
    echo "hotswap-verify: FATAL — zero rows verified; refusing to report success." >&2
    exit 2
fi
echo "OK: $pass swappable row(s) dlopen'd and ADMITTED by hotswap_module_admit()"
exit 0
