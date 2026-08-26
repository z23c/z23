#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Two-builder reproducible-build gate for the zclassic23 node binary.
#
# Builds build/bin/z23 TWICE from the current working tree, in two
# isolated build directories whose absolute paths differ in both value AND
# length (to expose any embedded absolute-path or padding nondeterminism), then
# SHA3-256- and byte-compares the two shipped (stripped) binaries.
#
# The shipped binary is stripped (`strip -s`), so .text/.rodata/.data carry no
# debug metadata. This gate compares the shipped artifacts AS SHIPPED — it does
# NOT strip anything itself. Byte identity is therefore proven over exactly the
# bytes a user would receive. If a future toolchain change reintroduces a
# divergence, the gate reports the exact differing ELF sections and byte
# offsets rather than papering over them with aggressive stripping; a residual
# diff is printed in full so the operator sees precisely what is not yet proven.
#
# Determinism is supplied by REPRO_CFLAGS in the Makefile (behavior-identical
# -ffile-prefix-map + -gno-record-gcc-switches). See
# docs/SECURITY_AND_INTEGRITY.md "Reproducible build gate".
#
# Cost: two full whole-program LTO builds (~2x a normal `make zclassic23`).
# This is intentionally NOT on the default lint/ci path — run it on demand.
#
# Usage:  make repro-verify            (or)   tools/scripts/repro-verify.sh
# Env:    ZCL_REPRO_JOBS=<n>   parallelism for each build (default: nproc)
#         ZCL_REPRO_KEEP=1     keep the two build trees for inspection
#         ZCL_REPRO_REFERENCE_BIN=<path>  require an exact reference match
# Sovereign mode additionally requires ZCL_SOVEREIGN_SOURCE_ROOT and
# ZCL_SOVEREIGN_VERIFY_BIN. Its snapshots contain neither .git nor .zvcs.
set -euo pipefail

# Reproduction consumes already-acquired, checksum-pinned inputs.  It must not
# turn a cache miss into network activity.  Force this here as well as in the
# Makefile so direct script invocation has the identical deny-by-default
# contract.  Compiler caches are host state and are excluded from this lane.
export ZCL_VENDOR_OFFLINE=1
export ZCL_USE_CCACHE=0
export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin
export HOME=/nonexistent
umask 022

JOBS="${ZCL_REPRO_JOBS:-$(nproc 2>/dev/null || echo 4)}"
if [ -n "${ZCL_SOVEREIGN_SOURCE_ROOT:-}" ]; then
    SRC="$(pwd -P)"
    SOURCE_MODE=sovereign-zvcs
else
    SRC="$(git rev-parse --show-toplevel 2>/dev/null)" || {
        echo "repro-verify: not inside a git worktree and no sovereign ZVCS root was supplied" >&2
        exit 2
    }
    SOURCE_MODE=git-worktree
fi

for t in rsync openssl cmp readelf; do
    command -v "$t" >/dev/null 2>&1 || { echo "repro-verify: missing required tool: $t" >&2; exit 2; }
done
if [ "$SOURCE_MODE" = git-worktree ]; then
    command -v git >/dev/null 2>&1 || {
        echo "repro-verify: missing required tool: git" >&2
        exit 2
    }
fi

BASE="$(mktemp -d "${TMPDIR:-/tmp}/zcl-repro.XXXXXX")"
# Two build roots with DIFFERENT absolute-path values and lengths.
A="$BASE/a"
B="$BASE/builder-two-deliberately-longer-path"

cleanup() {
    if [ "${ZCL_REPRO_KEEP:-0}" = "1" ]; then
        echo "repro-verify: build trees kept at $BASE" >&2
    else
        # Some tests deliberately create read-only fixtures.  They should not
        # make a successful byte comparison fail during trap cleanup.
        chmod -R u+w "$BASE" 2>/dev/null || true
        rm -rf "$BASE"
    fi
}
trap cleanup EXIT HUP INT TERM

snapshot() {
    # Copy source plus offline/generated vendor inputs. Sovereign mode leaves
    # the snapshots Git-free and re-verifies their exact ZVCS authority through
    # the trusted bootstrap binary. Legacy worktree mode retains the throwaway
    # repository used by the existing identity adapter.
    local dst="$1"
    mkdir -p "$dst"
    rsync -a --delete \
        --exclude='/build' --exclude='/.git' --exclude='/.zvcs' \
        --exclude='/.claude/worktrees' \
        --exclude='/test-tmp' \
        "$SRC"/./ "$dst"/
    if [ "$SOURCE_MODE" = git-worktree ]; then
        ( cd "$dst"
          git init -q >/dev/null 2>&1
          git add -A >/dev/null 2>&1 || true
          git -c user.email=repro@localhost -c user.name=repro \
              commit -q -m 'repro-verify snapshot' >/dev/null 2>&1 || true )
    fi
}

build_one() {
    local dst="$1" log="$2"
    if ! ( cd "$dst" && make zclassic23 -j"$JOBS" ) >"$log" 2>&1; then
        echo "repro-verify: build FAILED in $dst (tail of log):" >&2
        tail -25 "$log" >&2
        return 1
    fi
}

echo "repro-verify: source tree     = $SRC"
echo "repro-verify: source mode     = $SOURCE_MODE"
echo "repro-verify: build root A     = $A"
echo "repro-verify: build root B     = $B"
echo "repro-verify: jobs             = $JOBS"
echo "repro-verify: vendor network   = denied"
echo "repro-verify: snapshotting ..."
snapshot "$A"
snapshot "$B"
if [ "$SOURCE_MODE" = sovereign-zvcs ]; then
    [ ! -e "$A/.git" ] && [ ! -e "$B/.git" ] &&
        [ ! -e "$A/.zvcs" ] && [ ! -e "$B/.zvcs" ] || {
        echo "repro-verify: FAIL — sovereign snapshot inherited repository metadata" >&2
        exit 1
    }
fi

echo "repro-verify: building A (this is ~1x a full node build) ..."
build_one "$A" "$BASE/build-a.log"
echo "repro-verify: building B ..."
build_one "$B" "$BASE/build-b.log"

# build/bin/zclassic23 is a SYMLINK to the real artifact, build/bin/z23 (a
# migration alias, see the Makefile). cmp and openssl follow it, so the
# verdict was always about the real bytes — but `stat -c%s` does not, and this
# gate spent its life printing "size=3", the length of the string "z23".
# Compare the real file by name and dereference for the reported size.
BA="$A/build/bin/z23"
BB="$B/build/bin/z23"
[ -f "$BA" ] && [ -f "$BB" ] || { echo "repro-verify: FAIL — a node binary is missing" >&2; exit 1; }

HA="$(openssl dgst -sha3-256 "$BA" | awk '{print $NF}')"
HB="$(openssl dgst -sha3-256 "$BB" | awk '{print $NF}')"
SA="$(stat -Lc%s "$BA")"; SB="$(stat -Lc%s "$BB")"

echo "repro-verify: A  sha3-256=$HA  size=$SA"
echo "repro-verify: B  sha3-256=$HB  size=$SB"

if cmp -s "$BA" "$BB"; then
    if [ -n "${ZCL_REPRO_REFERENCE_BIN:-}" ]; then
        REFERENCE="$(realpath "$ZCL_REPRO_REFERENCE_BIN" 2>/dev/null)" || {
            echo "repro-verify: FAIL — reference binary does not resolve" >&2
            exit 1
        }
        [ -f "$REFERENCE" ] || {
            echo "repro-verify: FAIL — reference binary is not a regular file" >&2
            exit 1
        }
        HR="$(openssl dgst -sha3-256 "$REFERENCE" | awk '{print $NF}')"
        SR="$(stat -c%s "$REFERENCE")"
        echo "repro-verify: reference sha3-256=$HR  size=$SR"
        cmp -s "$BA" "$REFERENCE" || {
            echo "repro-verify: FAIL — rebuilt binary differs from the accepted reference" >&2
            exit 1
        }
    fi
    echo "repro-verify: github_contacted=false"
    echo "repro-verify: PASS — build/bin/z23 is byte-identical across two builders (sha3-256=$HA)"
    exit 0
fi

# ── Residual-diff report (honest; no aggressive stripping) ────────────────
echo "repro-verify: FAIL — the two node binaries are NOT byte-identical" >&2
echo "repro-verify: differing byte count = $(cmp -l "$BA" "$BB" | wc -l)" >&2
echo "repro-verify: first differing offsets (hex):" >&2
cmp -l "$BA" "$BB" | awk '{printf "  0x%x\n",$1-1}' | head -20 >&2
echo "repro-verify: differing ELF sections:" >&2
for s in $(readelf -SW "$BA" | sed -n 's/.*\] \(\.[^ ]*\).*/\1/p' | sort -u); do
    ha="$(objcopy -O binary --only-section="$s" "$BA" /dev/stdout 2>/dev/null | sha256sum | awk '{print $1}')"
    hb="$(objcopy -O binary --only-section="$s" "$BB" /dev/stdout 2>/dev/null | sha256sum | awk '{print $1}')"
    [ "$ha" = "$hb" ] || echo "  DIFF section $s" >&2
done
echo "repro-verify: (re-run with ZCL_REPRO_KEEP=1 to inspect $BASE)" >&2
exit 1
