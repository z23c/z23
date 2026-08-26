#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# repro_build.sh — the standing proof that a second builder gets the same
# bytes. A node announces which source it runs (`src:<64 hex>` in the version
# handshake); that announcement is only checkable if anyone holding the same
# source can rebuild the same binary. This script is what makes it checkable.
#
# It builds the node THREE times and reports FOUR separate properties, each
# named exactly, so a reader never has to guess how much was actually proven:
#
#   P1  shipped binary, two builders     build/bin/z23 built in two DIFFERENT
#       (ASSERTED)                       absolute directories is byte-identical.
#                                        This is the property a verifier needs.
#   P2  debug sidecar, two builders      build/bin/z23.debug (unstripped) is
#       (ASSERTED)                       byte-identical across the same two.
#   P3  objects, one directory           every per-TU object of the shipped
#       (ASSERTED)                       profile is byte-identical when the
#                                        same directory builds twice. This is
#                                        what the pinned $(ZCL_TU_RANDOM_SEED)
#                                        buys; without it GCC seeds itself from
#                                        the object's temporary staging name
#                                        and NO object repeats.
#   N1  objects, two directories         NOT byte-identical, and this script
#       (REPORTED, NOT ASSERTED)         says so out loud with the measured
#                                        count. GCC streams absolute source and
#                                        header paths into the .gnu.lto_* IR
#                                        and -ffile-prefix-map does not reach
#                                        inside it; there is no GCC 14 flag for
#                                        this. It does not touch P1/P2 because
#                                        that IR is consumed at link time and
#                                        never reaches the output.
#
# N1 is printed on success as well as on failure. A gate that quietly narrows
# its own scope to whatever passes is not evidence.
#
# Usage:   make repro-build            (or)   tools/scripts/repro_build.sh
# Env:     ZCL_REPRO_JOBS=<n>          parallelism per build (default: nproc)
#          ZCL_REPRO_BUILD_DIR=<dir>   working root (default: the XDG state
#                                      scratch dir; never /tmp)
#          ZCL_REPRO_KEEP=1            keep the trees for inspection
set -uo pipefail

# Reproduction consumes already-pinned inputs. It must never turn a cache miss
# into network traffic, and it must never be answered out of a compile cache:
# a cached object would make both builds trivially agree and prove nothing.
export ZCL_VENDOR_OFFLINE=1
export ZCL_USE_CCACHE=0
export ZCC_DIR=/nonexistent/zcc-disabled-for-repro
export LC_ALL=C
export TZ=UTC
umask 022

TOKEN_PASS='repro-build: PASS'
TOKEN_FAIL='repro-build: FAIL'

say() { printf 'repro-build: %s\n' "$*"; }
die() { printf '%s — %s\n' "$TOKEN_FAIL" "$*" >&2; exit 1; }

for t in rsync cmp sha256sum git make; do
    command -v "$t" >/dev/null 2>&1 || die "missing required tool: $t"
done

SRC="$(git rev-parse --show-toplevel 2>/dev/null)" ||
    die 'not inside a git worktree'

JOBS="${ZCL_REPRO_JOBS:-$(nproc 2>/dev/null || echo 4)}"
STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"
ROOT="${ZCL_REPRO_BUILD_DIR:-$STATE_HOME/zclassic23/scratch/repro-build}"
mkdir -p "$ROOT" || die "cannot create working root $ROOT"
WORK="$(mktemp -d "$ROOT/run.XXXXXX")" || die "cannot create a run dir under $ROOT"

# Two source roots whose absolute paths differ in BOTH value and length: an
# equal-length pair would hide a padding-sensitive divergence.
DIR_ONE="$WORK/one"
DIR_TWO="$WORK/builder-two-deliberately-longer-path"

cleanup() {
    if [ "${ZCL_REPRO_KEEP:-0}" = "1" ]; then
        say "trees kept at $WORK"
    else
        chmod -R u+w "$WORK" 2>/dev/null
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT HUP INT TERM

snapshot() {
    local dst="$1"
    mkdir -p "$dst" || return 1
    rsync -a --delete \
        --exclude='/build' --exclude='/.git' --exclude='/.zvcs' \
        --exclude='/.claude/worktrees' --exclude='/test-tmp' \
        "$SRC"/./ "$dst"/ || return 1
    # The build reads its own source identity through git; give each snapshot
    # its own throwaway repository so neither can see the other's.
    ( cd "$dst" &&
      git init -q >/dev/null 2>&1 &&
      git add -A >/dev/null 2>&1 &&
      git -c user.email=repro@localhost -c user.name=repro \
          commit -q -m 'repro-build snapshot' >/dev/null 2>&1 ) || return 1
}

# build <source dir> <BUILD_DIR> <log>
#
# BUILD_DIR is always OUTSIDE the source tree, and that is load-bearing rather
# than tidy: the build verifies at publish time that the source it hashed at
# parse time has not moved underneath it, and a build directory written INSIDE
# the tree moves it. Building the same directory a second time then fails with
# "source build superseded" — a correct refusal, and the reason this script
# keeps every output root next to the source rather than in it.
build() {
    local dir="$1" bdir="$2" log="$3" t0 t1
    t0=$(date +%s)
    if ! ( cd "$dir" && make z23 -j"$JOBS" BUILD_DIR="$bdir" ) >"$log" 2>&1; then
        say "build FAILED in $dir (BUILD_DIR=$bdir); tail of $log:"
        tail -30 "$log" >&2
        return 1
    fi
    t1=$(date +%s)
    printf '%s' "$((t1 - t0))"
}

# Hash every per-TU object of one build tree into a sorted path+digest list.
# Paths are recorded relative to the object root so two trees compare directly.
object_manifest() {
    local bdir="$1" out="$2"
    ( cd "$bdir" && find . -name '*.o' -type f -print0 |
        LC_ALL=C sort -z |
        xargs -0 -r sha256sum ) > "$out" || return 1
    [ -s "$out" ] || return 1
}

say "source tree   = $SRC"
say "working root  = $WORK"
say "jobs          = $JOBS"
say "compile cache = disabled (ZCC_DIR points at an unusable path)"
say "vendor network= denied"
say "snapshotting two independent source trees ..."
snapshot "$DIR_ONE" || die "could not snapshot $DIR_ONE"
snapshot "$DIR_TWO" || die "could not snapshot $DIR_TWO"

OUT_ONE="$WORK/out-one"
OUT_TWO="$WORK/out-two"
OUT_AGAIN="$WORK/out-one-again"

say "build 1/3: builder ONE  (this is ~1x a full node build) ..."
T1="$(build "$DIR_ONE" "$OUT_ONE" "$WORK/build-one.log")" || exit 1
say "build 2/3: builder TWO  (different absolute path) ..."
T2="$(build "$DIR_TWO" "$OUT_TWO" "$WORK/build-two.log")" || exit 1
say "build 3/3: builder ONE again, a second output root (same directory) ..."
T3="$(build "$DIR_ONE" "$OUT_AGAIN" "$WORK/build-one-again.log")" || exit 1
say "build times: one=${T1}s two=${T2}s one-again=${T3}s"

# ── the artifacts ────────────────────────────────────────────────────────
# build/bin/zclassic23 is a SYMLINK to z23 (a migration alias). Compare the
# real files, so the printed sizes describe the artifact and not a 3-byte
# link target.
BIN_ONE="$OUT_ONE/bin/z23"
BIN_TWO="$OUT_TWO/bin/z23"
DBG_ONE="$OUT_ONE/bin/z23.debug"
DBG_TWO="$OUT_TWO/bin/z23.debug"

for f in "$BIN_ONE" "$BIN_TWO"; do
    [ -f "$f" ] || die "a shipped node binary is missing: $f"
done

h() { sha256sum "$1" | awk '{print $1}'; }
sz() { stat -Lc%s "$1"; }

H1="$(h "$BIN_ONE")"; H2="$(h "$BIN_TWO")"
say "P1 builder ONE  build/bin/z23  sha256=$H1  size=$(sz "$BIN_ONE")"
say "P1 builder TWO  build/bin/z23  sha256=$H2  size=$(sz "$BIN_TWO")"

FAILED=0
P1=FAIL
if [ "$H1" = "$H2" ] && cmp -s "$BIN_ONE" "$BIN_TWO"; then
    P1=PASS
else
    FAILED=1
fi

P2=SKIP
if [ -f "$DBG_ONE" ] && [ -f "$DBG_TWO" ]; then
    D1="$(h "$DBG_ONE")"; D2="$(h "$DBG_TWO")"
    say "P2 builder ONE  build/bin/z23.debug  sha256=$D1  size=$(sz "$DBG_ONE")"
    say "P2 builder TWO  build/bin/z23.debug  sha256=$D2  size=$(sz "$DBG_TWO")"
    if [ "$D1" = "$D2" ] && cmp -s "$DBG_ONE" "$DBG_TWO"; then P2=PASS; else P2=FAIL; FAILED=1; fi
fi

# ── the intermediates ────────────────────────────────────────────────────
MAN_ONE="$WORK/objects-one.txt"
MAN_AGAIN="$WORK/objects-one-again.txt"
MAN_TWO="$WORK/objects-two.txt"
object_manifest "$OUT_ONE/node-obj" "$MAN_ONE" ||
    die 'could not hash builder ONE objects'
object_manifest "$OUT_AGAIN/node-obj" "$MAN_AGAIN" ||
    die 'could not hash the second same-directory build objects'
object_manifest "$OUT_TWO/node-obj" "$MAN_TWO" ||
    die 'could not hash builder TWO objects'

# The epoch directory name is part of the object path and is stable for a
# fixed flag set, so the manifests line up by path. Compare digests only.
digests() { awk '{print $1}' "$1"; }
count() { wc -l < "$1" | tr -d ' '; }

OBJ_N="$(count "$MAN_ONE")"
SAME_DIFF="$(diff <(digests "$MAN_ONE") <(digests "$MAN_AGAIN") | grep -c '^<')"
CROSS_DIFF="$(diff <(digests "$MAN_ONE") <(digests "$MAN_TWO") | grep -c '^<')"

P3=PASS
say "P3 same-directory objects: $((OBJ_N - SAME_DIFF))/$OBJ_N byte-identical"
if [ "$SAME_DIFF" != 0 ]; then P3=FAIL; FAILED=1; fi

# ── the honest residual ──────────────────────────────────────────────────
say ""
say "STILL NOT REPRODUCIBLE (named, not hidden):"
say "  N1  per-TU objects across two build directories:"
say "      $CROSS_DIFF of $OBJ_N differ."
say "      Cause: GCC streams absolute source/header paths into the"
say "      .gnu.lto_* IR and -ffile-prefix-map does not reach inside it."
say "      No GCC 14 flag fixes this. It does not affect P1/P2: that IR is"
say "      consumed at link time and never reaches the shipped output, which"
say "      is exactly what P1 above measures rather than assumes."
say ""

say "P1 shipped binary,  two builders : $P1"
say "P2 debug sidecar,   two builders : $P2"
say "P3 per-TU objects,  one directory: $P3"
say "N1 per-TU objects,  two builders : NOT ASSERTED (see above)"

if [ "$FAILED" != 0 ]; then
    if [ "$P1" != PASS ]; then
        say "first differing byte offsets in build/bin/z23 (hex):"
        cmp -l "$BIN_ONE" "$BIN_TWO" 2>/dev/null |
            awk '{printf "  0x%x\n",$1-1}' | head -20
        if command -v readelf >/dev/null 2>&1 &&
           command -v objcopy >/dev/null 2>&1; then
            say "differing ELF sections:"
            for s in $(readelf -SW "$BIN_ONE" |
                       sed -n 's/.*\] \(\.[^ ]*\).*/\1/p' | LC_ALL=C sort -u); do
                a="$(objcopy -O binary --only-section="$s" "$BIN_ONE" /dev/stdout 2>/dev/null | sha256sum)"
                b="$(objcopy -O binary --only-section="$s" "$BIN_TWO" /dev/stdout 2>/dev/null | sha256sum)"
                [ "$a" = "$b" ] || say "  DIFF $s"
            done
        fi
    fi
    if [ "$P3" != PASS ]; then
        say "same-directory objects that differ (first 10):"
        diff "$MAN_ONE" "$MAN_AGAIN" | grep '^<' | head -10
    fi
    say "re-run with ZCL_REPRO_KEEP=1 to inspect $WORK"
    printf '%s\n' "$TOKEN_FAIL"
    exit 1
fi

printf '%s — build/bin/z23 is byte-identical across two builders (sha256=%s)\n' \
    "$TOKEN_PASS" "$H1"
exit 0
