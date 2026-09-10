#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Executable regression for tools/scripts/host_gc.sh. Every check runs the
# real script against a throwaway fixture tree built under ./test-tmp — NEVER
# against $HOME, the real /proc, or the real repo checkout — by overriding
# every ZCL_HOST_GC_* indirection seam the script reads. --apply is exercised
# ONLY against this fixture tree; a bare `host_gc.sh --dry-run` against the
# live host (no overrides) is the caller's job, not this selftest's.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTGC="$SELF_DIR/host_gc.sh"
mkdir -p -- "${TMPDIR:-./test-tmp}"
WORK="$(cd "${TMPDIR:-./test-tmp}" && pwd)/host_gc_selftest.$$"
mkdir -p -- "$WORK"
FAIL=0

cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

fail() { printf 'host_gc_selftest: FAIL: %s\n' "$*" >&2; FAIL=1; }
pass() { printf 'host_gc_selftest: ok: %s\n' "$*"; }

# ------------------------------------------------------------- fixture root
HOME_FX="$WORK/home"
REPO_FX="$HOME_FX/github/zclassic23"
TMP_FX="$WORK/tmp"
PROC_FX="$WORK/proc"
STATE_FX="$HOME_FX/.local/state/server-cleanup"
UNITS_FX="$HOME_FX/.z23/units"
LANES_FX="$HOME_FX/.z23/lanes"
TRAINS_FX="$HOME_FX/.z23/trains"
SCRATCH_FX="$HOME_FX/.local/state/zclassic23/scratch"
ZCCDIR_FX="$HOME_FX/.cache/zcc"
Z23P_FX="$HOME_FX/github/.z23p"

mkdir -p -- "$TMP_FX" "$PROC_FX" "$STATE_FX" "$UNITS_FX" "$LANES_FX" \
    "$TRAINS_FX" "$SCRATCH_FX" "$ZCCDIR_FX" "$Z23P_FX"

# A real git repo stands in for GC_REPO so `git cherry`, `worktree add` and
# `worktree remove` behave exactly as they do on the live host.
git -C "$WORK" init -q -b main "$REPO_FX"
git -C "$REPO_FX" config user.email "selftest@example.invalid"
git -C "$REPO_FX" config user.name "host_gc_selftest"
echo base > "$REPO_FX/base.txt"
# *.pid/*.lock are gitignored so a z23p creator marker (an untracked file a
# real dev-proof generation drops next to its content) never makes
# worktree_clean() see a provably-dead generation as dirty.
printf '*.pid\n*.lock\n' > "$REPO_FX/.gitignore"
git -C "$REPO_FX" add base.txt .gitignore
git -C "$REPO_FX" commit -q -m base

# run_hostgc CAT MODE [EXTRA_ENV...] — invokes host_gc.sh --only CAT in the
# given MODE (dry-run|apply) against the fixture tree, capturing output.
run_hostgc() {
    local cat="$1" mode="$2"; shift 2
    env \
        ZCL_HOST_GC_HOME="$HOME_FX" \
        ZCL_HOST_GC_TMP="$TMP_FX" \
        ZCL_HOST_GC_PROC="$PROC_FX" \
        ZCL_HOST_GC_STATE="$STATE_FX" \
        ZCL_HOST_GC_REPO="$REPO_FX" \
        ZCL_HOST_GC_UNITS_DIR="$UNITS_FX" \
        ZCL_HOST_GC_LANES_DIR="$LANES_FX" \
        ZCL_HOST_GC_TRAINS_DIR="$TRAINS_FX" \
        ZCL_HOST_GC_SCRATCH_DIR="$SCRATCH_FX" \
        ZCL_HOST_GC_ZCC_DIR="$ZCCDIR_FX" \
        ZCL_HOST_GC_Z23P="$Z23P_FX" \
        ZCL_HOST_GC_UNITS_MIN_AGE_H=0 \
        ZCL_HOST_GC_SCRATCH_MIN_AGE_D=0 \
        ZCL_HOST_GC_Z23P_MIN_AGE_H=0 \
        ZCL_HOST_GC_TMPLITTER_MIN_AGE_D=0 \
        "$@" \
        "$HOSTGC" --only "$cat" "--$mode"
}

assert_contains() {
    local haystack="$1" needle="$2" label="$3"
    case "$haystack" in
        *"$needle"*) pass "$label" ;;
        *) fail "$label — expected to see '$needle'" ;;
    esac
}
assert_not_contains() {
    local haystack="$1" needle="$2" label="$3"
    case "$haystack" in
        *"$needle"*) fail "$label — did not expect to see '$needle'" ;;
        *) pass "$label" ;;
    esac
}

[ -x "$HOSTGC" ] || { echo "host_gc_selftest: $HOSTGC is not executable" >&2; exit 2; }

# ---------------------------------------------------------------- tmplitter
touch_old() { touch -d '3 days ago' -- "$1"; }
mkdir -p -- "$TMP_FX/orphan-fixture"
touch_old "$TMP_FX/orphan-fixture"
mkdir -p -- "$TMP_FX/claude-keepme"   # matches the standing exemption prefix
touch_old "$TMP_FX/claude-keepme"

out="$(run_hostgc tmplitter dry-run)"
log="$(cat -- "$STATE_FX/host_gc.log" 2>/dev/null || true)"
assert_contains "$log" "orphan-fixture" "tmplitter dry-run logs the unregistered entry as reapable"
assert_not_contains "$log" "claude-keepme" "tmplitter dry-run never logs an exempt entry"
assert_contains "$out" "1 reapable" "tmplitter dry-run summary counts the reapable entry"

out="$(run_hostgc tmplitter apply)"
[ -e "$TMP_FX/orphan-fixture" ] && fail "tmplitter apply left the unregistered entry behind" \
    || pass "tmplitter apply removed the unregistered entry"
[ -e "$TMP_FX/claude-keepme" ] || fail "tmplitter apply removed an exempt entry"

# -------------------------------------------------------------------- z23p
# z23p only ever looks at entries `git worktree list` reports for GC_REPO,
# so each pool "generation" here must be a real detached worktree.
git -C "$REPO_FX" worktree add -q --detach "$Z23P_FX/gen-dead" main >/dev/null
touch_old "$Z23P_FX/gen-dead"
printf '999999999\n' > "$Z23P_FX/gen-dead/creator.pid"

git -C "$REPO_FX" worktree add -q --detach "$Z23P_FX/gen-alive" main >/dev/null
touch_old "$Z23P_FX/gen-alive"
mkdir -p -- "$PROC_FX/$$"
printf '%s\n' "$$" > "$Z23P_FX/gen-alive/creator.pid"

out="$(run_hostgc z23p dry-run)"
log="$(cat -- "$STATE_FX/host_gc.log" 2>/dev/null || true)"
assert_contains "$log" "gen-dead" "z23p dry-run logs the dead-creator generation as reapable"
assert_contains "$out" "KEEP (creating process still alive)" \
    "z23p dry-run reports the alive-creator generation as kept"

out="$(run_hostgc z23p apply)"
[ -e "$Z23P_FX/gen-dead" ] && fail "z23p apply left a dead-creator generation behind" \
    || pass "z23p apply removed the dead-creator generation"
[ -e "$Z23P_FX/gen-alive" ] || fail "z23p apply removed a live-creator generation"

# --------------------------------------------------------------------- zcc
out="$(ZCL_HOST_GC_ZCC_BIN="$WORK/no-such-zcc" PATH="/usr/bin:/bin" \
    run_hostgc zcc dry-run)"
assert_contains "$out" "evictor not built" "zcc dry-run reports why no evictor was found"
assert_contains "$out" "$WORK/no-such-zcc" "zcc dry-run names every path it tried"

# zcc apply must measure the cache by reading the evictor's own report line
# — NEVER by walking the tree itself before and/or after the trim (the
# 2026-09-10 HDD incident: three du -sb walks of a multi-million-file cache
# per hourly run, one alone 27 minutes in D state). A fake evictor proves
# (a) held/freed come straight from its report line, (b) it is invoked
# exactly once, and (c) du is never invoked on the zcc dir in the apply
# path; a PATH-shadowed `du` records every call it would have made.
ZCC_STUB_OK="$WORK/zcc-stub-ok"
cat > "$ZCC_STUB_OK" <<'STUBEOF'
#!/usr/bin/env bash
set -euo pipefail
: "${ZCC_STUB_COUNT_FILE:?}"
printf 'x' >> "$ZCC_STUB_COUNT_FILE"
cap="${2:-0}"
echo "zcc: 42 MB held, ${cap} MB ceiling, 7 MB freed"
STUBEOF
chmod +x -- "$ZCC_STUB_OK"

ZCC_STUB_GARBAGE="$WORK/zcc-stub-garbage"
cat > "$ZCC_STUB_GARBAGE" <<'STUBEOF'
#!/usr/bin/env bash
echo "not a trim report"
STUBEOF
chmod +x -- "$ZCC_STUB_GARBAGE"

DU_SHADOW_DIR="$WORK/du-shadow"
mkdir -p -- "$DU_SHADOW_DIR"
DU_CALL_LOG="$WORK/du-calls.log"
: > "$DU_CALL_LOG"
cat > "$DU_SHADOW_DIR/du" <<DUEOF
#!/usr/bin/env bash
printf 'du-called %s\n' "\$*" >> "$DU_CALL_LOG"
printf '0\t%s\n' "\${*: -1}"
DUEOF
chmod +x -- "$DU_SHADOW_DIR/du"

ZCC_STUB_COUNT="$WORK/zcc-stub-count"
: > "$ZCC_STUB_COUNT"
out="$(ZCL_HOST_GC_ZCC_BIN="$ZCC_STUB_OK" ZCC_STUB_COUNT_FILE="$ZCC_STUB_COUNT" \
    PATH="$DU_SHADOW_DIR:$PATH" run_hostgc zcc apply)"
log="$(cat -- "$STATE_FX/host_gc.log" 2>/dev/null || true)"
assert_contains "$out" "reclaimed 7" \
    "zcc apply reports the freed amount straight from the evictor's report line"
assert_contains "$log" "zcc-trim" "zcc apply logs a zcc-trim row"
calls="$(wc -c < "$ZCC_STUB_COUNT")"
[ "$calls" = 1 ] || fail "zcc apply invoked the evictor $calls time(s), expected exactly 1"
if [ -s "$DU_CALL_LOG" ]; then
    fail "zcc apply called du, which the one-walk invariant forbids: $(cat -- "$DU_CALL_LOG")"
else
    pass "zcc apply never calls du — held/freed come from the evictor's report alone"
fi

# A cache FREEZE (free space under the freeze floor — the state a proof
# generation on a full tmpfs is always in) must not buy the second walk
# back: the apply path records the freeze from the evictor's held figure
# instead of measuring first.
: > "$DU_CALL_LOG"
: > "$ZCC_STUB_COUNT"
out="$(ZCL_HOST_GC_ZCC_BIN="$ZCC_STUB_OK" ZCC_STUB_COUNT_FILE="$ZCC_STUB_COUNT" \
    ZCL_HOST_GC_CACHE_FREEZE_GB=1000000 \
    PATH="$DU_SHADOW_DIR:$PATH" run_hostgc zcc apply)"
assert_contains "$out" "FREEZE active" "zcc apply under a cache freeze says so"
assert_contains "$out" "reclaimed 7" \
    "zcc apply under a cache freeze still reports the evictor's freed amount"
calls="$(wc -c < "$ZCC_STUB_COUNT")"
[ "$calls" = 1 ] || fail "zcc apply under a freeze invoked the evictor $calls time(s), expected exactly 1"
if [ -s "$DU_CALL_LOG" ]; then
    fail "zcc apply under a cache freeze called du, which the one-walk invariant forbids: $(cat -- "$DU_CALL_LOG")"
else
    pass "zcc apply under a cache freeze never calls du — the freeze is recorded from the evictor's held figure"
fi

# A stub that prints garbage must fail loudly (zcc-trim-failed), never a
# silent 0-freed success row.
: > "$DU_CALL_LOG"
out="$(ZCL_HOST_GC_ZCC_BIN="$ZCC_STUB_GARBAGE" PATH="$DU_SHADOW_DIR:$PATH" \
    run_hostgc zcc apply)"
log="$(cat -- "$STATE_FX/host_gc.log" 2>/dev/null || true)"
assert_contains "$log" "zcc-trim-failed" \
    "zcc apply with an unparsable evictor report logs zcc-trim-failed, not a success"
assert_not_contains "$out" "reclaimed" \
    "zcc apply with an unparsable evictor report never claims a reclaim"

# -------------------------------------------------------------------- units
land_a_unit() {
    local name="$1" land="$2" dir
    dir="$UNITS_FX/$name"
    git -C "$REPO_FX" worktree add -q --detach "$dir" main >/dev/null
    echo "$name" > "$dir/change.txt"
    git -C "$dir" add change.txt
    git -C "$dir" commit -q -m "unit $name"
    if [ "$land" = 1 ]; then
        git -C "$REPO_FX" cherry-pick "$(git -C "$dir" rev-parse HEAD)" >/dev/null
    fi
    touch_old "$dir"
}
land_a_unit landed-unit 1
land_a_unit unlanded-unit 0

out="$(run_hostgc units dry-run)"
assert_contains "$out" "landed-unit" "units dry-run names the patch-equivalent worktree"
assert_contains "$out" "KEEP (unlanded commits" "units dry-run keeps the unlanded worktree"

out="$(run_hostgc units apply)"
[ -d "$UNITS_FX/landed-unit" ] && fail "units apply left the landed worktree behind" \
    || pass "units apply removed the landed worktree"
[ -d "$UNITS_FX/unlanded-unit" ] || fail "units apply removed the unlanded worktree"

# ------------------------------------------------------------------ scratch
mkdir -p -- "$SCRATCH_FX/orphaned-lane"
touch_old "$SCRATCH_FX/orphaned-lane"
mkdir -p -- "$SCRATCH_FX/pinned-lane"
touch_old "$SCRATCH_FX/pinned-lane"
printf 'pinned-lane\n' > "$SCRATCH_FX/.gc_keep"
mkdir -p -- "$LANES_FX/still-here"
mkdir -p -- "$SCRATCH_FX/still-here"
touch_old "$SCRATCH_FX/still-here"

out="$(run_hostgc scratch dry-run)"
assert_contains "$out" "orphaned-lane" "scratch dry-run names the orphaned scratch dir"
assert_contains "$out" "KEEP (.gc_keep)" "scratch dry-run honors .gc_keep"
assert_contains "$out" "KEEP (worktree still exists)" "scratch dry-run keeps a dir with a live worktree"

out="$(run_hostgc scratch apply)"
[ -d "$SCRATCH_FX/orphaned-lane" ] && fail "scratch apply left the orphaned dir in place" \
    || pass "scratch apply quarantined the orphaned dir (moved, not deleted)"
found=0
for d in "$STATE_FX"/quarantine/*/scratch/orphaned-lane; do
    [ -d "$d" ] && found=1
done
[ "$found" = 1 ] || fail "scratch apply did not move the orphaned dir into quarantine"
[ -d "$SCRATCH_FX/pinned-lane" ] || fail "scratch apply removed a .gc_keep-pinned dir"
[ -d "$SCRATCH_FX/still-here" ] || fail "scratch apply removed a dir with a live worktree"

# ----------------------------------------------------------------- pressure
out="$(ZCL_HOST_GC_PRESSURE_MIN_FREE_PCT=101 ZCL_HOST_GC_PRESSURE_CRITICAL_FREE_PCT=101 \
    run_hostgc worktree dry-run)"
assert_contains "$out" "PRESSURE" "an impossible pressure floor is always reported"
assert_contains "$out" "CRITICAL" "an impossible critical floor is always reported"
assert_contains "$out" "largest dirs under" "critical pressure names the largest directories"

# --------------------------------------------------------------- protection
out="$(env ZCL_HOST_GC_HOME="$HOME_FX" ZCL_HOST_GC_REPO="$REPO_FX" \
    "$HOSTGC" --check-protected "$REPO_FX/base.txt")"
[ "$out" = "PROTECTED" ] || fail "the fixture's own repo is not seen as protected: $out"
out="$(env ZCL_HOST_GC_HOME="$HOME_FX" ZCL_HOST_GC_REPO="$REPO_FX" \
    "$HOSTGC" --check-protected "$TMP_FX/orphan-fixture")"
[ "$out" = "UNPROTECTED" ] || fail "an ordinary fixture path reads as protected: $out"

if [ "$FAIL" = 1 ]; then
    echo "host_gc_selftest: FAILED" >&2
    exit 1
fi
echo "host_gc_selftest: PASS"
