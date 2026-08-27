#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Fast MULTI-LEAF module rebuild for the observable hot-swap loop
# (`make hotswap-try` / `make hotswap-apply`). Bypasses the whole-program make
# parse by replaying cached compile metadata (build/hotswap/fast/flags.env)
# written by the authoritative `make hotswap-module-so` recipe.
#
# FAIL-SAFE CONTRACT: whenever any input is newer than the cached metadata, or
# anything the fast path needs is missing/stale/suspicious, this script execs
# the authoritative `make hotswap-module-so` (which also refreshes the cache).
# It never silently skips a needed rebuild.
#
# Replicated semantics from the make recipe (Makefile: hotswap-module-so):
#   - per-FILE allowlist resolution from config/hotswap_swappable.def (a leaf
#     given as HANDLER= is resolved to the one file that owns it)
#   - exact DEV_CFLAGS + `-fPIC -DZCL_HOTSWAP_MODULE_GEN
#     -DZCL_HOTSWAP_MODULE_SOURCE_TU="<tu>"` compile
#   - link with HOTSWAP_MODULE_LDFLAGS, including the LOAD-BEARING
#     -Wl,-Bsymbolic (ELF interposition guard; refused if absent from cache)
#   - mutation guard: source/header mtimes verified unchanged across the build
#     (module-scope analogue of the make path's verify-record)
#   - content-addressed, read-only artifacts published via hardlink-or-verify
#     (REFUSE on byte mismatch), printed as the LAST stdout line
#
# Artifact naming uses a module-input digest (flags + compiler + source/header
# bytes) instead of the whole-tree source identity. The runtime never parses
# the name; it pins and hashes the artifact bytes itself. Only the directory
# (build/hotswap/) is contract — see lib/hotswap/src/hotswap_loader.c.

set -euo pipefail

HANDLER=""
FILE=""
for arg in "$@"; do
    case "$arg" in
        HANDLER=*) HANDLER="${arg#HANDLER=}" ;;
        FILE=*) FILE="${arg#FILE=}" ;;
        *) echo "hotswap-module-fast: unknown argument: $arg" >&2; exit 2 ;;
    esac
done
[ -n "$HANDLER" ] || [ -n "$FILE" ] || {
    echo "usage: tools/dev/hotswap-module-fast.sh FILE=app/controllers/src/status_native_handlers.c" >&2
    echo "   or: tools/dev/hotswap-module-fast.sh HANDLER=core.status" >&2
    exit 2
}

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 2
ROOT="$(cd "$SELF_DIR/../.." && pwd)" || exit 2
cd "$ROOT" || exit 2

fallback() {
    echo "hotswap-module-fast: $* — falling back to make hotswap-module-so" >&2
    # Capture the source identity exactly once here and hand it to the nested
    # make on the command line (the escape hatch at Makefile:~90 gives
    # command-line-origin BUILD_SOURCE_RECORD absolute precedence). Without
    # this, make's own parse-time `$(shell tools/dev/source-identity.sh
    # capture-record)` would redo the identical ~2s scan from scratch — a
    # second full capture paid back-to-back with this one for no reason, on
    # top of the recipe's own post-compile verify-record. If the capture
    # itself fails here, fall through to letting make capture it instead of
    # masking the failure.
    local record selector
    if [ -n "$FILE" ]; then selector="FILE=$FILE"; else selector="HANDLER=$HANDLER"; fi
    if record="$(tools/dev/source-identity.sh capture-record 2>/dev/null)"; then
        exec make --no-print-directory hotswap-module-so \
            "$selector" "BUILD_SOURCE_RECORD=$record"
    fi
    exec make --no-print-directory hotswap-module-so "$selector"
}

# Leaf names are command-leaf paths and FILE is a repo-relative .c; anything
# outside these charsets is for the authoritative make path to diagnose.
case "$HANDLER" in
    *[!A-Za-z0-9_.-]*) fallback "leaf name outside safe charset" ;;
esac
case "$FILE" in
    *[!A-Za-z0-9_./-]*) fallback "FILE outside safe charset" ;;
esac

DEF=config/hotswap_swappable.def
ISLAND_DEF=config/hotswap_islands.def
# Rows are per-FILE and span lines: flatten, then match only complete
# HOTSWAP_SWAPPABLE("<src>", "<leaves>") invocations (the header comment spells
# the signature without quotes, so it can never match).
rows="$(tr '\n' ' ' < "$DEF" \
    | grep -oE 'HOTSWAP_SWAPPABLE\("[^"]*"[[:space:]]*,[[:space:]]*"[^"]*"\)')" ||
    fallback "no HOTSWAP_SWAPPABLE rows parsed from $DEF"
[ -n "$rows" ] || fallback "no HOTSWAP_SWAPPABLE rows parsed from $DEF"

if [ -n "$FILE" ]; then
    src="$FILE"
    printf '%s\n' "$rows" | grep -Fq "HOTSWAP_SWAPPABLE(\"$src\"" ||
        fallback "'$src' is not a row in $DEF"
else
    src="$(printf '%s\n' "$rows" | awk -v leaf="$HANDLER" -F '"' \
        '{ n = split($4, L, " "); for (i = 1; i <= n; i++) if (L[i] == leaf) { print $2; exit } }')"
    [ -n "$src" ] || fallback "leaf '$HANDLER' not resolved by $DEF"
fi
[ -f "$src" ] || fallback "source does not exist: $src"

FAST_DIR=build/hotswap/fast
FLAGS_ENV="$FAST_DIR/flags.env"
HOTSWAP_OBJ_DIR=build/hotswap-obj
HOTSWAP_SO_DIR=build/hotswap
safe="$(printf '%s' "$src" | tr -c 'A-Za-z0-9_.-' '_')"

# ── Cached metadata must be present and fresher than everything that could
# invalidate it: the Makefile (flag definitions), the allowlist (handler ->
# TU mapping), and this script (fast-path semantics).
[ -f "$FLAGS_ENV" ] || fallback "no cached flags.env (run make hotswap-module-so once)"
for ref in Makefile "$DEF" "$ISLAND_DEF" "$SELF_DIR/$(basename "${BASH_SOURCE[0]}")"; do
    [ "$ref" -nt "$FLAGS_ENV" ] && fallback "$ref newer than cached flags.env"
done

# ── Generated view headers are compiler inputs. Missing or template-stale
# ones are regenerated by make rules the fast path does not own.
VH1=app/views/include/views/wallet_templates_gen.h
VH2=app/views/include/views/site_css.h
for vh in "$VH1" "$VH2"; do
    [ -f "$vh" ] || fallback "generated view header missing: $vh"
done
if [ "$(find app/views/templates app/views/css -type f -newer "$VH1" 2>/dev/null | head -1)" ]; then
    fallback "view template newer than $VH1"
fi
[ app/views/src/site.css -nt "$VH2" ] && fallback "site.css newer than $VH2"

# ── Parse the cached flags. Strict KEY=VALUE lines only; never sourced.
F_CC="" F_CFLAGS="" F_LDFLAGS=""
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
        CC=*) F_CC="${line#CC=}" ;;
        DEV_CFLAGS=*) F_CFLAGS="${line#DEV_CFLAGS=}" ;;
        HOTSWAP_MODULE_LDFLAGS=*) F_LDFLAGS="${line#HOTSWAP_MODULE_LDFLAGS=}" ;;
        \#* | "") ;;
        *) fallback "unrecognized line in flags.env: $line" ;;
    esac
done < "$FLAGS_ENV"
[ -n "$F_CC" ] && [ -n "$F_CFLAGS" ] && [ -n "$F_LDFLAGS" ] ||
    fallback "flags.env is incomplete"
case "$F_LDFLAGS" in
    *-Bsymbolic*) ;;
    *) fallback "cached link flags lack -Bsymbolic (interposition guard); refusing fast link" ;;
esac
case "$F_LDFLAGS" in
    *-nostartfiles*) ;;
    *) fallback "cached link flags lack -nostartfiles (zero-constructor guard); refusing fast link" ;;
esac
# Word-splitting below mirrors how make expands these flag strings on its own
# recipe lines; the values are toolchain flags, never shell code.
# shellcheck disable=SC2086
command -v $F_CC >/dev/null 2>&1 || fallback "cached compiler not found: $F_CC"

# ── Per-handler module cache.
cache_o="$FAST_DIR/$safe.o"
cache_d="$FAST_DIR/$safe.d"
cache_cmd="$FAST_DIR/$safe.cmd"
cache_ptr="$FAST_DIR/$safe.so-path"

deps_from_depfile() {
    # gcc -MD output: "target: dep1 dep2 \" continued lines. No filenames with
    # spaces exist in this tree.
    tr '\n' ' ' < "$1" | tr -d '\\' | cut -d: -f2- | tr ' ' '\n' | sed '/^$/d'
}

want_cc="$F_CC $F_CFLAGS"

fresh=0
if [ -f "$cache_o" ] && [ -f "$cache_d" ] && [ -f "$cache_cmd" ] && [ -f "$cache_ptr" ] &&
   [ "$(cat "$cache_cmd")" = "$want_cc" ]; then
    so_cached="$(cat "$cache_ptr")"
    if [ -n "$so_cached" ] && [ -f "$so_cached" ] && [ ! "$src" -nt "$cache_o" ]; then
        fresh=1
        while IFS= read -r dep_file; do
            [ -f "$dep_file" ] || { fresh=0; break; }
            [ "$dep_file" -nt "$cache_o" ] && { fresh=0; break; }
        done < <(deps_from_depfile "$cache_d")
    fi
fi

if [ "$fresh" = 1 ]; then
    printf '%s\n' "$so_cached"
    exit 0
fi

# ── Fast rebuild: compile + link with the cached command lines.
echo "hotswap-module-fast: rebuilding module for $HANDLER ($src)" >&2
mkdir -p "$FAST_DIR" "$HOTSWAP_OBJ_DIR" "$HOTSWAP_SO_DIR"
tmp_o="$(mktemp "$FAST_DIR/.module.XXXXXX.o")"
tmp_d="$(mktemp "$FAST_DIR/.module.XXXXXX.d")"
tmp_so="$(mktemp "$HOTSWAP_SO_DIR/.module.XXXXXX.so")"
trap 'rm -f "$tmp_o" "$tmp_d" "$tmp_so"' EXIT HUP INT TERM

# Mutation guard (module-scope analogue of the make path's verify-record):
# snapshot the source and its previously-known headers before compiling...
pre_snapshot="$( { [ -f "$cache_d" ] && deps_from_depfile "$cache_d"; printf '%s\n' "$src"; } | LC_ALL=C sort -u | xargs -r stat -c '%n %i:%s:%y' 2>/dev/null || true )"

# shellcheck disable=SC2086
$F_CC $F_CFLAGS -fPIC -DZCL_HOTSWAP_MODULE_GEN \
    "-DZCL_HOTSWAP_MODULE_SOURCE_TU=\"$src\"" \
    -MD -MF "$tmp_d" -c -o "$tmp_o" "$src" >&2 ||
    fallback "compile failed under cached flags"
mapfile -t new_deps < <(deps_from_depfile "$tmp_d")
[ "${#new_deps[@]}" -gt 0 ] || fallback "depfile from cached compile is empty"

# shellcheck disable=SC2086
$F_CC $F_LDFLAGS -o "$tmp_so" "$tmp_o" >&2 ||
    fallback "link failed under cached flags"

# ...and require the source set observed after the build to be unchanged.
post_snapshot="$(printf '%s\n' "${new_deps[@]}" | LC_ALL=C sort -u | xargs -r stat -c '%n %i:%s:%y' 2>/dev/null || true)"
if [ -n "$pre_snapshot" ]; then
    while IFS= read -r rec; do
        [ -n "$rec" ] || continue
        printf '%s\n' "$post_snapshot" | grep -Fqx "$rec" ||
            fallback "input mutated during fast build: ${rec%% *}"
    done <<< "$pre_snapshot"
fi

# Content-addressed publish, same discipline as the make recipe: hardlink into
# place, or verify byte-identity with any existing artifact and REFUSE on
# mismatch (a digest collision with different bytes must never publish).
digest="$( { printf '%s\n' 'zcl.hotswap_module_fast.v1' "$F_CC" "$F_CFLAGS" "$F_LDFLAGS"; \
             sha256sum -- "$src" "${new_deps[@]}"; } | sha256sum | awk '{print $1}' )"
case "$digest" in
    *[!0-9a-f]* | '') fallback "invalid module digest" ;;
esac
final_o="$HOTSWAP_OBJ_DIR/mod-$safe-$digest.o"
final_so="$HOTSWAP_SO_DIR/$safe-$digest.so"

publish_exact() {
    local src_f="$1" dst="$2"
    if ln -- "$src_f" "$dst" 2>/dev/null; then rm -f -- "$src_f"; return 0; fi
    [ -f "$dst" ] && [ ! -L "$dst" ] && cmp -s "$src_f" "$dst" || return 1
    rm -f -- "$src_f"
}
publish_exact "$tmp_o" "$final_o" || {
    echo "hotswap-module-fast: REFUSING mismatched existing object $final_o" >&2
    exit 3
}
publish_exact "$tmp_so" "$final_so" || {
    echo "hotswap-module-fast: REFUSING mismatched existing candidate $final_so" >&2
    exit 3
}
chmod a-w "$final_o" "$final_so"

# Cache update (last-writer-wins; a torn cache only forces a later rebuild,
# never a stale print: the .o/dep/cmd/ptr set is revalidated on every run).
# The cached .o must be an independent copy, not a hardlink: publish_exact
# keeps a pre-existing identical artifact with its ORIGINAL mtime, and the
# freshness check compares source/header mtimes against the cached .o — a
# hardlink would inherit that stale mtime and the happy path would never hit.
mv -f -- "$tmp_d" "$cache_d"
rm -f -- "$cache_o"
cp -- "$final_o" "$cache_o"
chmod u+w "$cache_o"
printf '%s\n' "$want_cc" > "$cache_cmd"
printf '%s\n' "$final_so" > "$cache_ptr"
trap - EXIT HUP INT TERM

echo "hotswap-module-fast: linked multi-leaf module candidate $final_so ($src)" >&2
printf '%s\n' "$final_so"
