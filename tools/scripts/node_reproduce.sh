#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# node_reproduce.sh — build the node artifact ONCE on THIS machine and emit a
# zcl.node_repro_receipt.v1 describing exactly what came out.
#
# This is the "produce bytes" half of `z23 zcode node verify`. It deliberately
# does no comparing: the verdict belongs to the pure comparator in
# lib/vcs/src/node_reproduce.c, which cannot be talked into accepting a
# publisher's own hash as evidence. Keeping the two apart is the same split
# lib/vcs already keeps between package_recipe (declare), package_verify
# (compile), and package_reproduce (judge) — nothing that builds also decides.
#
# WHY THE RECEIPT NAMES WHAT IT COULD NOT REBUILD. The node binary is
# reproducible; several of its inputs are not rebuilt here at all. A receipt
# that listed only the artifact would let a green verdict quietly cover
# vendored static archives this run merely consumed. Every such component is
# emitted as an `unverified` row with a reason, the comparator carries them
# into the report, and the presence of even one turns MATCH into PARTIAL.
#
# Usage:
#   tools/scripts/node_reproduce.sh --out=PATH [options]
#
#   --out=PATH        where to write the receipt (required)
#   --source=DIR      source tree to build (default: this script's repo root)
#   --scratch=DIR     isolated build root (default: a mktemp dir, removed)
#   --jobs=N          build parallelism (default: nproc)
#   --profile=NAME    default | release   (default: default)
#                     `default` is what `make z23` and `make repro-verify`
#                     build. `release` resolves the exact tools/release.sh
#                     flag profile through tools/scripts/repro_build_vars.sh.
#   --keep            leave the scratch build tree in place
#
# Exit: 0 receipt written; 2 usage/prerequisite refusal; 1 build failure.
set -euo pipefail

export LC_ALL=C
export TZ=UTC
# Reproduction consumes already-acquired, checksum-pinned inputs; a cache miss
# must never become network activity. Same contract repro-verify.sh forces.
export ZCL_VENDOR_OFFLINE=1
export ZCL_USE_CCACHE=0

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SELF_DIR/../.." && pwd)"

OUT=""
SOURCE_DIR="$REPO_ROOT"
SCRATCH=""
JOBS=""
PROFILE="default"
KEEP=0

die() { printf 'node-reproduce: %s\n' "$*" >&2; exit 2; }

for arg in "$@"; do
    case "$arg" in
        --out=*)     OUT="${arg#--out=}" ;;
        --source=*)  SOURCE_DIR="${arg#--source=}" ;;
        --scratch=*) SCRATCH="${arg#--scratch=}" ;;
        --jobs=*)    JOBS="${arg#--jobs=}" ;;
        --profile=*) PROFILE="${arg#--profile=}" ;;
        --keep)      KEEP=1 ;;
        -h|--help)   sed -n '1,35p' "$0"; exit 0 ;;
        *)           die "unknown argument: $arg" ;;
    esac
done

[ -n "$OUT" ] || die "--out=PATH is required"
[ -d "$SOURCE_DIR" ] || die "--source is not a directory: $SOURCE_DIR"
[ -f "$SOURCE_DIR/Makefile" ] || die "no Makefile under $SOURCE_DIR"
case "$PROFILE" in
    default|release) ;;
    *) die "--profile must be 'default' or 'release'" ;;
esac
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
case "$JOBS" in
    ''|*[!0-9]*) die "--jobs must be a positive integer" ;;
esac
[ "$JOBS" -ge 1 ] || die "--jobs must be a positive integer"

for t in make openssl; do
    command -v "$t" >/dev/null 2>&1 || die "missing required tool: $t"
done
openssl dgst -sha3-256 /dev/null >/dev/null 2>&1 \
    || die "this host's openssl has no SHA3-256; the receipt would have to \
change hash algorithm mid-flight, so it refuses instead"

SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"

OWN_SCRATCH=0
if [ -z "$SCRATCH" ]; then
    SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/zcl-node-repro.XXXXXX")"
    OWN_SCRATCH=1
else
    mkdir -p "$SCRATCH"
    SCRATCH="$(cd "$SCRATCH" && pwd -P)"
fi
cleanup() {
    if [ "$KEEP" = "1" ] || [ "$OWN_SCRATCH" = "0" ]; then
        return
    fi
    chmod -R u+w "$SCRATCH" 2>/dev/null || true
    rm -rf "$SCRATCH"
}
trap cleanup EXIT HUP INT TERM

BUILD_DIR="$SCRATCH/build"
BUILD_LOG="$SCRATCH/build.log"

sha3() { openssl dgst -sha3-256 "$1" | awk '{print $NF}'; }
filesize() { stat -c%s "$1" 2>/dev/null || stat -f%z "$1"; }

# ── source identity ─────────────────────────────────────────────────────
# "What source tree is in THIS DIRECTORY right now" — the checkout-shaped
# question (tools/scripts/source_identity_lib.sh TWO QUESTIONS block). It is
# the right one here: we are about to build this directory. The receipt for
# the artifact the user RECEIVED answers the other one, from the constant
# baked into that executable, and the comparator only calls it a match when
# the two agree.
SOURCE_ID=""
if [ -x "$SOURCE_DIR/tools/dev/source-identity.sh" ]; then
    SOURCE_ID="$( cd "$SOURCE_DIR" && ./tools/dev/source-identity.sh capture 2>/dev/null || true )"
fi
case "$SOURCE_ID" in
    *[!0-9a-f]*|'') SOURCE_ID="" ;;
    *) [ "${#SOURCE_ID}" -eq 64 ] || SOURCE_ID="" ;;
esac

# ── build ───────────────────────────────────────────────────────────────
MAKE_ARGS=( -C "$SOURCE_DIR" -j"$JOBS" "BUILD_DIR=$BUILD_DIR" )
PROFILE_DESC="make default profile (the same flags make z23 and make repro-verify use)"
if [ "$PROFILE" = release ]; then
    # shellcheck source=tools/scripts/repro_build_vars.sh
    ( cd "$SOURCE_DIR" && . tools/scripts/repro_build_vars.sh ) >/dev/null 2>&1 \
        || die "could not resolve the release flag profile"
    cd "$SOURCE_DIR"
    # shellcheck source=tools/scripts/repro_build_vars.sh
    . tools/scripts/repro_build_vars.sh
    [ -n "${REL_CFLAGS:-}" ] || die "REL_CFLAGS resolved empty"
    MAKE_ARGS+=( "CFLAGS=$REL_CFLAGS" "LDFLAGS=$REL_LDFLAGS" )
    PROFILE_DESC="tools/release.sh release profile, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
fi

printf 'node-reproduce: building z23 in %s (profile=%s jobs=%s)\n' \
    "$BUILD_DIR" "$PROFILE" "$JOBS" >&2
if ! make "${MAKE_ARGS[@]}" z23 >"$BUILD_LOG" 2>&1; then
    printf 'node-reproduce: BUILD FAILED — no receipt written. Tail:\n' >&2
    tail -30 "$BUILD_LOG" >&2
    exit 1
fi

ARTIFACT="$BUILD_DIR/bin/z23"
[ -f "$ARTIFACT" ] || { printf 'node-reproduce: build produced no %s\n' "$ARTIFACT" >&2; exit 1; }

# ── receipt ─────────────────────────────────────────────────────────────
tmp_out="$OUT.tmp.$$"
mkdir -p "$(dirname "$OUT")"
{
    printf 'zcl.node_repro_receipt.v1\n'
    printf 'producer local-rebuild\n'
    [ -n "$SOURCE_ID" ] && printf 'source_id %s\n' "$SOURCE_ID"
    printf 'toolchain_desc %s\n' "$PROFILE_DESC"
    printf 'artifact %s %s %s\n' "$(sha3 "$ARTIFACT")" "$(filesize "$ARTIFACT")" 'bin/z23'

    # ── the named gaps ──────────────────────────────────────────────────
    # Anything below was NOT produced by this build and therefore is NOT
    # covered by a byte match on the artifact above. Naming each one is the
    # difference between a verdict that means something and a green light.
    for a in "$SOURCE_DIR"/vendor/lib/*.a; do
        [ -f "$a" ] || continue
        base="$(basename "$a")"
        if [ -f "$SOURCE_DIR/vendor/provenance/${base%.a}.manifest" ]; then
            printf 'unverified vendor/lib/%s prebuilt static archive committed to the source tree and linked as-is; its own manifest under vendor/provenance/ records the provenance this build did not re-derive\n' "$base"
        else
            printf 'unverified vendor/lib/%s static archive already present on this host and linked as-is; this run rebuilt none of it from vendored source\n' "$base"
        fi
    done
    printf 'unverified lto-intermediate-objects gcc streams absolute paths into the compressed LTO intermediate representation and -ffile-prefix-map cannot reach inside it, so per-translation-unit objects are not byte-stable across build directories; only the final linked artifact above is compared\n'
    printf 'unverified host-toolchain the compiler, assembler, linker and archiver were used, not rebuilt from source; their identity is recorded from the artifact ELF .comment section and compared, which is weaker than reproducing them\n'
} >"$tmp_out"
mv -f "$tmp_out" "$OUT"

printf 'node-reproduce: receipt written to %s\n' "$OUT" >&2
exit 0
