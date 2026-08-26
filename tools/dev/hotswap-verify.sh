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
#      verification-only artifact. The small verifier process does not export
#      the node kernel symbols a module binds against, so a -z now dlopen
#      would fail there for reasons that say nothing about the module. Lazy
#      binding defers those to first call, which is what lets the manifest be
#      judged at all -- and is also its cost: an UNRESOLVABLE symbol sails
#      through. The shipped artifact links -z now, so this check is LOOSER
#      than production in exactly the dimension that decides whether the
#      module loads. tools/dev/hotswap-symbols.sh closes that gap against a
#      real node binary, and step 4 runs it whenever one is built;
#   3. dlopens it and runs the REAL hotswap_module_admit() gauntlet;
#   4. when a dev node binary exists, resolves the SHIPPED artifact's strong
#      undefined symbols against it, which is the check step 2 cannot make.
#      Absent a node this step reports that it did not run -- it never counts
#      as a pass, and it never fails a row for the node's absence.
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
# The node a module will be dlopen'd into. Step 4 resolves against it.
SYMBOL_NODE="${ZCL_HOTSWAP_NODE_BINARY:-build/bin/zclassic23-dev}"

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
# logging imports, which the admit path never reaches; without it the link
# would drag most of the node in for a pure predicate. The SHA-256 and
# SHA3-256 hashers deliberately survive: the verify path fd-pins and records
# both artifact digests, so lib/sha3 is linked in on purpose, not by accident.
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
        lib/hotswap/src/hotswap_artifact_digest.c \
        lib/sha3/src/sha3.c \
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

    # A row passes only if BOTH checks pass, and is counted exactly once.
    row_ok=1
    if ! "$SCRATCH/hotswap_verify_so" "$lazy_so" "$tu" 2>&1 | sed 's/^/    /'; then
        row_ok=0; failed_rows="${failed_rows}  $tu (admit)"$'\n'
    fi

    # Step 4. The admit check above ran against the LAZY re-link; the artifact
    # that actually ships is this one, linked -z now. Resolve its symbols
    # against a real node so an unresolvable one cannot reach a mount attempt.
    # NOT `tail -1`: make appends its own "Leaving directory" line after the
    # recipe's output, so the artifact path is not last.
    shipped="$(LC_ALL=C grep -oE '^build/hotswap/[^ ]+\.so$' "$SCRATCH/build.log" | tail -1)"
    if [ -z "$shipped" ] || [ ! -f "$shipped" ]; then
        echo "    symbols     : REFUSED (shipped artifact path absent)"
        row_ok=0
        failed_rows="${failed_rows}  $tu (shipped artifact absent)"$'\n'
    else
        if [ -r "$SYMBOL_NODE" ]; then
            if ! tools/dev/hotswap-symbols.sh "$shipped" "$SYMBOL_NODE" 2>&1 |
                    sed -n 's/^  /    /p'; then
                row_ok=0; failed_rows="${failed_rows}  $tu (symbols)"$'\n'
            fi
        else
            echo "    symbols     : NOT CHECKED (no node at $SYMBOL_NODE; make fast-rebuild)"
        fi
    fi

    if [ "$row_ok" -eq 1 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
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
if [ -r "$SYMBOL_NODE" ]; then
    echo "OK: $pass swappable row(s) ADMITTED by hotswap_module_admit(), and every"
    echo "    shipped artifact resolves its symbols against $SYMBOL_NODE"
else
    echo "OK: $pass swappable row(s) dlopen'd and ADMITTED by hotswap_module_admit()"
    echo "    NOTE: symbol resolution was NOT checked -- no node at $SYMBOL_NODE."
    echo "    Admission runs against a -z lazy re-link, so an unresolvable symbol"
    echo "    is not caught here. Build a node (make fast-rebuild) for that leg."
fi
exit 0
