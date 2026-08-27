#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# hotswap-shelf-selftest.sh — build three REAL modules from ONE swappable TU
# and drive the hot-swap shelf end to end (activate, supersede, roll back,
# roll back again, supersede again, refuse).
#
#   make t-hotswap-shelf
#   tools/dev/hotswap-shelf-selftest.sh --driver=<bin> --cc=... (make does this)
#
# WHY A SCRIPT AND NOT A TEST GROUP. The shelf only ever holds an image put
# there by the dlopen activation path, so proving it needs compiled module .so
# files, a genuine supersede, and live-activation authority at the moment of
# the rollback. test_parallel's module mode activates ONE module in the parent
# before any group forks and cannot express a second one. See the header of
# tools/dev/hotswap_shelf_drive.c.
#
# THE THREE MODULES. All three are compiled from
# app/controllers/src/policy_native_handlers.c — a row of
# config/hotswap_swappable.def — with its island member from
# config/hotswap_islands.def, using the SAME compiler, the SAME DEV_CFLAGS and
# the SAME module link flags the shipping `make hotswap-module-so` recipe uses
# (read from build/hotswap/fast/flags.env, the frozen action plan). B and C are
# built from a SCRATCH COPY of the island member with one integer constant
# changed — the NEW_USER row's queue_priority. That is exactly the edit an
# agent makes in the dev loop, done to a copy so this harness never writes to a
# file in the repository. The change is observable in the leaf's rendered
# reply, which is what lets dispatch tell the three apart.
#
# WHY THAT TU. Its body answers from `args` plus compiled-in constants — no
# RPC, no datadir, no wall-clock, no filesystem — so probe-before-publish and
# the harness's own dispatch both run in-process with no node.
#
# HERMETIC. Everything the run creates lives under
# ~/.local/state/zclassic23/scratch/hotswap-shelf (never /tmp) except the
# module .so files, which MUST live under a build/hotswap directory because
# hotswap_path_is_acceptable() confines module artifacts to /tmp or
# build/hotswap; they are removed at the end. The driver runs under a scratch
# HOME, so the "exact dev datadir" hotswap_datadir_is_dev() demands is a
# throwaway directory inside scratch. The real ~/.zclassic-c23-dev, the
# canonical ~/.zclassic-c23, and the devfleet datadir are never opened.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || { echo "hotswap-shelf: cannot cd to $ROOT" >&2; exit 2; }

TU="app/controllers/src/policy_native_handlers.c"
LEAF="zcode.package.policy.limits"
MARKER_KEY="queue_priority"
PATCH_MEMBER="lib/vcs/src/package_policy.c"
# A second row of config/hotswap_swappable.def, never activated by this run:
# the "nothing shelved" refusal has to be asked of a source the loader knows.
UNSHELVED_TU="app/controllers/src/status_native_handlers.c"

FLAGS_ENV="build/hotswap/fast/flags.env"
SCRATCH="${ZCL_HOTSWAP_SHELF_DIR:-$HOME/.local/state/zclassic23/scratch/hotswap-shelf}"
SO_DIR="$ROOT/build/hotswap/shelf-drive"
DRIVER=""
KEEP=0

for arg in "$@"; do
    case "$arg" in
        --driver=*) DRIVER="${arg#--driver=}" ;;
        --keep)     KEEP=1 ;;
        *) echo "hotswap-shelf: unknown argument '$arg'" >&2; exit 2 ;;
    esac
done

[ -n "$DRIVER" ] || { echo "hotswap-shelf: --driver=<binary> is required" >&2; exit 2; }
[ -x "$DRIVER" ] || { echo "hotswap-shelf: driver '$DRIVER' is not executable" >&2; exit 2; }
[ -r "$FLAGS_ENV" ] || {
    echo "hotswap-shelf: $FLAGS_ENV missing — run 'make hotswap-module-so FILE=$TU' once first." >&2
    exit 2
}

CC="$(sed -n 's/^CC=//p' "$FLAGS_ENV")"
CFLAGS="$(sed -n 's/^DEV_CFLAGS=//p' "$FLAGS_ENV")"
MODULE_LDFLAGS="$(sed -n 's/^HOTSWAP_MODULE_LDFLAGS=//p' "$FLAGS_ENV")"
[ -n "$CC" ] && [ -n "$CFLAGS" ] && [ -n "$MODULE_LDFLAGS" ] || {
    echo "hotswap-shelf: could not parse CC/DEV_CFLAGS/HOTSWAP_MODULE_LDFLAGS from $FLAGS_ENV" >&2
    exit 2
}

# ── the swappable row and its island, read from the manifests ──────────────
LC_ALL=C grep -Fq "HOTSWAP_SWAPPABLE(\"$TU\"" config/hotswap_swappable.def || {
    echo "hotswap-shelf: $TU is not a row of config/hotswap_swappable.def" >&2
    exit 2
}
MEMBERS="$(tr '\n' ' ' < config/hotswap_islands.def \
    | LC_ALL=C grep -oE 'HOTSWAP_ISLAND\("[^"]*"[[:space:]]*,[[:space:]]*"[^"]*"\)' \
    | awk -v owner="$TU" -F '"' '$2 == owner { print $4; exit }')"
[ -n "$MEMBERS" ] || {
    echo "hotswap-shelf: $TU declares no island in config/hotswap_islands.def;" >&2
    echo "  this harness varies an island member, so it cannot proceed." >&2
    exit 2
}
case " $MEMBERS " in
    *" $PATCH_MEMBER "*) : ;;
    *) echo "hotswap-shelf: island of $TU no longer contains $PATCH_MEMBER (members: $MEMBERS)" >&2
       exit 2 ;;
esac

mkdir -p "$SCRATCH" "$SO_DIR" || { echo "hotswap-shelf: cannot create scratch dirs" >&2; exit 2; }
RUN_HOME="$SCRATCH/run-home"
DEV_DATADIR="$RUN_HOME/.zclassic-c23-dev"

# Defensive: this harness must never be able to name a real datadir.
case "$DEV_DATADIR" in
    "$HOME/.zclassic-c23-dev"|"$HOME/.zclassic-c23"|"$HOME/.zclassic-c23-devfleet")
        echo "hotswap-shelf: REFUSING — the scratch datadir resolved to a real one" >&2
        exit 2 ;;
esac

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        echo "hotswap-shelf: --keep: leaving $SCRATCH and $SO_DIR in place"
        return
    fi
    rm -rf -- "$RUN_HOME" "$SCRATCH/build" 2>/dev/null
    rm -rf -- "$SO_DIR" 2>/dev/null
}
trap cleanup EXIT HUP INT TERM

rm -rf -- "$RUN_HOME" "$SCRATCH/build"
mkdir -p "$DEV_DATADIR" "$SCRATCH/build" || {
    echo "hotswap-shelf: cannot create the scratch datadir" >&2; exit 2; }

# ── patch one integer constant on a COPY of the island member ──────────────
# The NEW_USER row's queue_priority. Renders into the leaf's reply, so the
# three modules are distinguishable by dispatch alone.
patch_member() {
    local value="$1" dest="$2"
    awk -v val="$value" '
        BEGIN { done = 0 }
        done == 0 && /queue_priority/ && /^[[:space:]]*0u,/ {
            sub(/0u,/, val "u,"); done = 1
        }
        { print }
        END { if (done == 0) exit 3 }
    ' "$PATCH_MEMBER" > "$dest"
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "hotswap-shelf: FATAL — could not find the NEW_USER queue_priority" >&2
        echo "  constant in $PATCH_MEMBER. Refusing to build three modules that" >&2
        echo "  might be byte-identical: the drive would assert nothing." >&2
        return 1
    fi
    LC_ALL=C grep -q "^[[:space:]]*${value}u,.*queue_priority" "$dest" || {
        echo "hotswap-shelf: FATAL — patched copy does not carry ${value}u" >&2
        return 1
    }
    # A no-op edit is the one way this harness could build three modules that
    # behave identically and still look busy. Distinct DIGESTS do not rule it
    # out — the variants are compiled from differently-named scratch files, so
    # their debug info differs even when their code does not. Compare the
    # SOURCE against the original instead.
    if cmp -s "$PATCH_MEMBER" "$dest"; then
        echo "hotswap-shelf: FATAL — patching $PATCH_MEMBER with ${value}u changed" >&2
        echo "  nothing. Three identical modules would make dispatch unable to" >&2
        echo "  tell them apart, so the drive would assert nothing. Refusing." >&2
        return 1
    fi
    return 0
}

build_variant() {
    local name="$1" member_src="$2"
    local unity="$SCRATCH/build/$name.unity.c"
    local obj="$SCRATCH/build/$name.o"
    local so="$SO_DIR/$name.so"
    : > "$unity"
    local m
    for m in $MEMBERS; do
        if [ "$m" = "$PATCH_MEMBER" ]; then
            printf '#include "%s"\n' "$member_src" >> "$unity"
        else
            printf '#include "%s/%s"\n' "$ROOT" "$m" >> "$unity"
        fi
    done
    printf '#include "%s/%s"\n' "$ROOT" "$TU" >> "$unity"

    rm -f -- "$obj" "$so"
    # shellcheck disable=SC2086
    $CC $CFLAGS -fPIC -DZCL_HOTSWAP_MODULE_GEN \
        -DZCL_HOTSWAP_MODULE_SOURCE_TU="\"$TU\"" \
        -c -o "$obj" "$unity" > "$SCRATCH/build/$name.compile.log" 2>&1
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "hotswap-shelf: compile of module $name FAILED" >&2
        tail -25 "$SCRATCH/build/$name.compile.log" >&2
        return 1
    fi
    # shellcheck disable=SC2086
    $CC $MODULE_LDFLAGS -o "$so" "$obj" > "$SCRATCH/build/$name.link.log" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "hotswap-shelf: link of module $name FAILED" >&2
        tail -25 "$SCRATCH/build/$name.link.log" >&2
        return 1
    fi
    [ -s "$so" ] || { echo "hotswap-shelf: module $name produced no artifact" >&2; return 1; }
    return 0
}

echo "══ hot-swap shelf: building three real modules from one swappable TU ══"
echo "  source_tu       $TU"
echo "  island member   $PATCH_MEMBER (varied: NEW_USER $MARKER_KEY)"
echo "  compiler        $CC"
echo

patch_member 7 "$SCRATCH/build/member-b.c" || exit 2
patch_member 9 "$SCRATCH/build/member-c.c" || exit 2

build_variant module-a "$ROOT/$PATCH_MEMBER"      || exit 2
build_variant module-b "$SCRATCH/build/member-b.c" || exit 2
build_variant module-c "$SCRATCH/build/member-c.c" || exit 2

for v in module-a module-b module-c; do
    printf '  built %-10s %s\n' "$v" "$(sha256sum "$SO_DIR/$v.so" | awk '{print $1}')"
done

DISTINCT="$(sha256sum "$SO_DIR"/module-*.so | awk '{print $1}' | sort -u | wc -l)"
if [ "$DISTINCT" -ne 3 ]; then
    echo "hotswap-shelf: FATAL — the three modules are not three distinct artifacts" >&2
    echo "  ($DISTINCT distinct digests). The drive would prove nothing." >&2
    exit 2
fi

echo
echo "  scratch HOME    $RUN_HOME"
echo "  dev datadir     $DEV_DATADIR (created empty; the real"
echo "                  \$HOME/.zclassic-c23-dev is never opened)"
echo

RUN_LOG="$SCRATCH/drive.log"
HOME="$RUN_HOME" ZCL_HOTSWAP_ACTIVATE=1 "$DRIVER" \
    --datadir="$DEV_DATADIR" \
    --source-tu="$TU" \
    --leaf="$LEAF" \
    --marker-key="$MARKER_KEY" \
    --module-a="$SO_DIR/module-a.so" \
    --module-b="$SO_DIR/module-b.so" \
    --module-c="$SO_DIR/module-c.so" \
    --unshelved-source="$UNSHELVED_TU" > "$RUN_LOG" 2>&1
DRIVE_EXIT=$?
cat "$RUN_LOG"

if [ "$DRIVE_EXIT" -ne 0 ]; then
    echo
    echo "hotswap-shelf: SHELF DRIVE FAILED (exit $DRIVE_EXIT)" >&2
    KEEP=1
    echo "hotswap-shelf: artifacts kept for inspection: $SCRATCH, $SO_DIR" >&2
    exit 1
fi
# Gate on the PASS token as well as the exit status: a driver that exited 0
# without reaching its verdict line has proven nothing.
if ! LC_ALL=C grep -q '^  SHELF DRIVE PASSED$' "$RUN_LOG"; then
    echo
    echo "hotswap-shelf: exit 0 but the PASSED verdict line is absent — refusing" >&2
    KEEP=1
    exit 1
fi
if LC_ALL=C grep -q '    FAIL  ' "$RUN_LOG"; then
    echo
    echo "hotswap-shelf: a FAIL line is present despite exit 0 — refusing" >&2
    KEEP=1
    exit 1
fi

echo
echo "hotswap-shelf: OK — the shelf was driven end to end against three real"
echo "               module artifacts. The scratch datadir, the build scratch"
echo "               and the module .so files are removed; the transcript"
echo "               stays at $RUN_LOG."
exit 0
