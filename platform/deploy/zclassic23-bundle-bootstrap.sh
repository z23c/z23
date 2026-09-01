#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# zclassic23-bundle-bootstrap.sh — BYTE DELIVERY ONLY: stage a
# release-shipped consensus-state bundle into <datadir>/bundles/ so a fresh
# node's zero-flag cold-boot autodetect
# (boot_autodetect_consensus_bundle, engine/composition/src/boot_auto_install_bundle.c)
# finds it with NO operator action at boot time — "instant-on" for a brand
# new datadir instead of a 15-20h from-genesis fold or the legacy two-step
# --importblockindex recipe.
#
# SOVEREIGNTY: this script is a courier, not a trust boundary. It never
# opens, parses, or validates the bundle's consensus content, and staging a
# bundle here does not make it trusted. The ONE trust boundary is exactly
# where it already is: the RECEIPT / CHECKPOINT_ROM / CHECKPOINT_CONTENT
# authority resolved at INSTALL time
# (engine/composition/src/consensus_state_snapshot_install_checkpoint_authority.c), which
# independently re-derives the bundle's content digests (coins, Sapling/
# Sprout anchor history, nullifier history) against the compiled-in
# checkpoint (core/chainparams/src/checkpoints.c) before ever lifting
# admission containment. A bundle staged by this script is exactly as
# untrusted, until that gate passes, as one fetched cold from a stranger
# over ROM delivery (docs/ROM_DELIVERY.md) — see docs/ROM_DELIVERY.md
# "Local bundle bootstrap" for the full write-up of why that is fine.
#
# Usage:
#   zclassic23-bundle-bootstrap.sh --source=PATH_TO_consensus-state-bundle-*.sqlite \
#       [--datadir=DIR] [--sha3-tool=PATH]
#
# DIR defaults to $ZCL_DATADIR or ~/.zclassic-c23 (the node's own default —
# see CLAUDE.md "Running" / -datadir=).
#
# Idempotent / fail-safe, safe to run on every boot (systemd ExecStartPre=-):
#   - <datadir>/bundles/ already holds a *.sqlite  -> no-op, exit 0 (never
#     overwrites, never duplicates; the autodetect's own lexicographic
#     tie-break among multiple staged bundles is left exactly as-is)
#   - the durable consensus-bundle-installed.marker already exists in
#     <datadir> -> no-op, exit 0 (this datadir already holds sovereign,
#     installed state; never stage bytes over/alongside it)
#   - --source missing/empty/unreadable, or the post-copy digest does not
#     match the source -> fail closed (exit 1), nothing left half-written
#     (copy lands via temp name + atomic rename inside <datadir>/bundles/,
#     never at the final name until content is proven byte-identical to
#     the source)
#
# Exit codes: 0 = staged (or already present/installed — nothing to do),
#             1 = copy/verify failure, 2 = usage error.
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"

SOURCE=""
DATADIR="${ZCL_DATADIR:-$HOME/.zclassic-c23}"
SHA3_TOOL="$REPO_ROOT/build/bin/rom_bundle_sha3"

MARKER_NAME="consensus-bundle-installed.marker"

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --source=*)   SOURCE="${1#--source=}" ;;
        --datadir=*)  DATADIR="${1#--datadir=}" ;;
        --sha3-tool=*) SHA3_TOOL="${1#--sha3-tool=}" ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "zclassic23-bundle-bootstrap: unknown option $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

log() { printf '[bundle-bootstrap] %s\n' "$*" >&2; }

if [ -z "$SOURCE" ]; then
    log "no --source given (and none configured) — nothing to stage, exiting cleanly"
    log "point --source=PATH at a checkpoint bundle to enable zero-flag instant-on;"
    log "see docs/ROM_DELIVERY.md 'Local bundle bootstrap' for where to get one"
    exit 0
fi

BUNDLES_DIR="$DATADIR/bundles"

# ── fast no-op guards (never clobber existing sovereign or staged state) ──

if [ -f "$DATADIR/$MARKER_NAME" ]; then
    log "already installed: $DATADIR/$MARKER_NAME exists — nothing to do"
    exit 0
fi

if [ -d "$BUNDLES_DIR" ]; then
    existing="$(find "$BUNDLES_DIR" -maxdepth 1 -type f -name '*.sqlite' -print -quit 2>/dev/null || true)"
    if [ -n "$existing" ]; then
        log "already staged: $existing exists — nothing to do"
        exit 0
    fi
fi

# ── validate the source ────────────────────────────────────────────────

[ -s "$SOURCE" ] || { log "FAIL: --source not found or empty: $SOURCE"; exit 1; }
case "$SOURCE" in
    *.sqlite) ;;
    *) log "FAIL: --source must end in .sqlite (the autodetect suffix filter): $SOURCE"; exit 1 ;;
esac

sha3_of() {
    local path="$1"
    if [ -x "$SHA3_TOOL" ]; then
        "$SHA3_TOOL" "$path" | awk '{print $1}'
        return
    fi
    if command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha3-256 "$path" | awk '{print $NF}'
        return
    fi
    if command -v sha3sum >/dev/null 2>&1; then
        sha3sum -a 256 "$path" | awk '{print $1}'
        return
    fi
    log "FAIL: no SHA3-256 tool available (build one: make tools/rom_bundle_sha3)"
    exit 1
}

BASENAME="$(basename -- "$SOURCE")"
DEST="$BUNDLES_DIR/$BASENAME"
TMP="$DEST.tmp.$$"

cleanup() { rm -f "$TMP"; }
trap cleanup EXIT INT TERM

mkdir -p "$BUNDLES_DIR"

log "staging $SOURCE -> $DEST"
src_sha3="$(sha3_of "$SOURCE")"

cp -- "$SOURCE" "$TMP"
# Read-only before it is ever visible at the final name: the installer's
# immutable-admission check (engine/composition/src/consensus_state_snapshot_install.c)
# refuses any bundle with a write bit set for anyone, so this is required for
# the auto-install to ever accept the staged file, not just defense in depth.
chmod 0444 "$TMP"

dest_sha3="$(sha3_of "$TMP")"
if [ "$dest_sha3" != "$src_sha3" ]; then
    log "FAIL: copy digest mismatch: staged=$dest_sha3 want=$src_sha3"
    exit 1
fi

mv -f -- "$TMP" "$DEST"
# Directory entry durability best-effort (a crash between mv and the next
# boot's autodetect just repeats the (idempotent) no-op guard above rather
# than double-staging).
sync 2>/dev/null || true

log "PASS: staged $DEST (sha3 $dest_sha3)"
log "the next zero-flag boot's cold-boot autodetect will find it; the"
log "RECEIPT/CHECKPOINT_ROM/CHECKPOINT_CONTENT authority at install time"
log "decides whether it is ever trusted — this script never does"
exit 0
