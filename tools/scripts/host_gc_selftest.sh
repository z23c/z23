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

# All Git operations, including host_gc's children, must use the fixture repo.
unset GIT_DIR GIT_COMMON_DIR GIT_WORK_TREE GIT_INDEX_FILE \
    GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTGC="$SELF_DIR/host_gc.sh"
mkdir -p -- "${TMPDIR:-./test-tmp}"
# pwd -P, not pwd: on macOS TMPDIR usually sits behind a symlink (/tmp ->
# /private/tmp, /var -> /private/var), and git registers worktree paths
# physically — a logical WORK path makes every `case "$wt" in "$pool"/*`
# filter in host_gc.sh see zero worktrees on a Mac and pass on a Linux box.
WORK="$(cd "${TMPDIR:-./test-tmp}" && pwd -P)/host_gc_selftest.$$"
mkdir -p -- "$WORK"
FAIL=0

cleanup() { chmod -R u+w -- "$WORK" 2>/dev/null || true; rm -rf -- "$WORK"; }
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
# The tmpfs twin of the proof pool, and the node binary the z23p sweep
# prefers for it. BOTH are pinned to the fixture here on purpose: left at
# their production defaults this selftest would point a real `z23 ops host
# gc --apply` at the real /dev/shm/z23p of whatever box it runs on.
RAM_FX="$WORK/shm/z23p"
Z23_STUB="$WORK/z23-stub"
Z23_STUB_CALLS="$WORK/z23-stub-calls.log"

mkdir -p -- "$TMP_FX" "$PROC_FX" "$STATE_FX" "$UNITS_FX" "$LANES_FX" \
    "$TRAINS_FX" "$SCRATCH_FX" "$ZCCDIR_FX" "$Z23P_FX" "$RAM_FX"

# FREE SPACE IS INJECTED, NEVER READ LIVE. host_gc.sh measures free space
# with `df -P` on its home; this stub answers for the fixture instead, so a
# verdict here never depends on how full the box running the selftest is.
# HGT_DF_AVAIL_KB (1 KiB blocks free) defaults to roughly 1 TB on a 2 TB
# filesystem: comfortably above every floor. A test that needs low disk
# sets it for one call.
DF_STUB_DIR="$WORK/df-stub"
mkdir -p -- "$DF_STUB_DIR"
cat > "$DF_STUB_DIR/df" <<'STUBEOF'
#!/usr/bin/env bash
avail="${HGT_DF_AVAIL_KB:-1000000000}"
total=2000000000
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
printf 'fixture %s %s %s 50%% /\n' "$total" "$(( total - avail ))" "$avail"
STUBEOF
chmod +x "$DF_STUB_DIR/df"

# systemctl, stubbed so no category ever reads this box's real user units.
# One unit, whose ExecStart is whatever $UNITS_EXEC_FILE names (empty = no
# unit points anywhere).
SYSTEMCTL_STUB="$WORK/systemctl-stub"
UNITS_EXEC_FILE="$WORK/unit-exec.txt"
: > "$UNITS_EXEC_FILE"
cat > "$SYSTEMCTL_STUB" <<STUBEOF
#!/usr/bin/env bash
case "\$*" in
    *list-unit-files*) printf 'fx-svc.service enabled enabled\n' ;;
    *ExecStart*) p="\$(cat -- "$UNITS_EXEC_FILE")"
        [ -n "\$p" ] && printf '{ path=%s ; argv[]=%s ; }\n' "\$p" "\$p" ;;
esac
exit 0
STUBEOF
chmod +x "$SYSTEMCTL_STUB"

# The dev binary the low-disk warning posts through. It sits next to the
# z23 stub (host_gc.sh looks beside its z23 binary before PATH), so a
# selftest run can never reach a real z23-dev and post real mail.
DEV_STUB="$WORK/z23-dev"
DEV_STUB_CALLS="$WORK/z23-dev-calls.log"
cat > "$DEV_STUB" <<STUBEOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$DEV_STUB_CALLS"
printf '{"schema":"zcl.result.v1","ok":true,"status":"passed"}\n'
STUBEOF
chmod +x "$DEV_STUB"
: > "$DEV_STUB_CALLS"

cat > "$Z23_STUB" <<'STUBEOF'
#!/usr/bin/env bash
set -euo pipefail
: "${Z23_STUB_CALL_LOG:?}"
printf '%s\n' "$*" >> "$Z23_STUB_CALL_LOG"
printf '{"schema":"zcl.host_gc.v1","status":"passed","data":{"apply":true,'
printf '"classes":[{"class":"z23p","bytes_reclaimed":7},'
printf '{"class":"z23p-ram","bytes_reclaimed":40953}],'
printf '"totals":{"registered":2,"bytes_reclaimed":40960},"refusals":[]}}\n'
STUBEOF
chmod +x "$Z23_STUB"
: > "$Z23_STUB_CALLS"

# A real git repo stands in for GC_REPO so `git cherry`, `worktree add` and
# `worktree remove` behave exactly as they do on the live host.
git -C "$WORK" init -q -b main "$REPO_FX"
git -C "$REPO_FX" config user.email "selftest@example.invalid"
git -C "$REPO_FX" config user.name "host_gc_selftest"
echo base > "$REPO_FX/base.txt"
# *.pid/*.lock are gitignored so a z23p creator marker (an untracked file a
# real dev-proof generation drops next to its content) never makes
# worktree_clean() see a provably-dead generation as dirty.
# build/ and test-tmp/ are ignored exactly as in the real repository, so a
# fixture worktree carrying build output and test scratch is still clean.
printf '*.pid\n*.lock\nbuild/\ntest-tmp/\n' > "$REPO_FX/.gitignore"
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
        ZCL_HOST_GC_RAM_ROOT="$RAM_FX" \
        ZCL_HOST_GC_Z23_BIN="${ZCL_HOST_GC_Z23_BIN:-$Z23_STUB}" \
        Z23_STUB_CALL_LOG="$Z23_STUB_CALLS" \
        ZCL_HOST_GC_UNITS_MIN_AGE_H=0 \
        ZCL_HOST_GC_SCRATCH_MIN_AGE_D=0 \
        ZCL_HOST_GC_Z23P_MIN_AGE_H=0 \
        ZCL_HOST_GC_TMPLITTER_MIN_AGE_D=0 \
        ZCL_HOST_GC_REPOTMP_MIN_AGE_D=0 \
        ZCL_HOST_GC_SYSTEMCTL_BIN="${ZCL_HOST_GC_SYSTEMCTL_BIN:-$SYSTEMCTL_STUB}" \
        PATH="$DF_STUB_DIR:$PATH" \
        "$@" \
        "$HOSTGC" --only "$cat" "--$mode" ${HGT_EXTRA_ARGS:-}
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
# A fixed 2000-01-01 stamp, not `touch -d '3 days ago'`: GNU touch's -d does
# not exist on macOS, and every age floor this selftest exercises is set to 0
# by run_hostgc, so any old timestamp satisfies each check portably.
touch_old() { touch -t 200001010000 -- "$1"; }
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

# ------------------------------------------------------------- z23p (tmpfs)
# The tmpfs twin of the pool is the half nobody swept: it grew to 34 GB of
# RAM in one unattended day while this category reported the disk pool
# clean. The sweep must reach it every run, hand the native verb the apply
# flag and the age floor THIS run is using, and log one row carrying the
# byte total the report itself gave — not a number this script invented.
log_lines_before="$(wc -l < "$STATE_FX/host_gc.log" 2>/dev/null || echo 0)"
: > "$Z23_STUB_CALLS"
out="$(run_hostgc z23p dry-run)"
assert_contains "$(cat -- "$Z23_STUB_CALLS")" "ops host gc --apply=false --floor_hours=0" \
    "z23p dry-run asks the native sweep for a dry run at this run's age floor"
: > "$Z23_STUB_CALLS"
out="$(run_hostgc z23p apply)"
new_log="$(tail -n "+$(( log_lines_before + 1 ))" -- "$STATE_FX/host_gc.log" 2>/dev/null || true)"
assert_contains "$(cat -- "$Z23_STUB_CALLS")" "ops host gc --apply=true --floor_hours=0" \
    "z23p apply asks the native sweep to apply"
assert_contains "$out" "$RAM_FX" "z23p apply names the tmpfs pool it swept"
assert_contains "$new_log" "z23p-ram" "z23p apply logs one z23p-ram row"
assert_contains "$new_log" "40960" \
    "the z23p-ram row carries bytes_reclaimed straight from the report's totals"
calls="$(wc -l < "$Z23_STUB_CALLS" | tr -d '[:space:]')"
[ "$calls" = 1 ] || fail "z23p apply invoked the native sweep $calls time(s), expected exactly 1"

# No binary anywhere: the sweep must still LOOK at the tmpfs pool, using
# this script's own classifier, rather than skip the half of the pool it
# cannot reach the preferred way.
git -C "$REPO_FX" worktree add -q --detach "$RAM_FX/gen-ram-dead" main >/dev/null
touch_old "$RAM_FX/gen-ram-dead"
printf '999999999\n' > "$RAM_FX/gen-ram-dead/creator.pid"
out="$(ZCL_HOST_GC_Z23_BIN="$WORK/no-such-z23" PATH="/usr/bin:/bin" \
    run_hostgc z23p apply)"
assert_contains "$out" "no z23 binary" "z23p says why it fell back to its own classifier"
[ -e "$RAM_FX/gen-ram-dead" ] && fail "the fallback classifier left a dead tmpfs generation behind" \
    || pass "the fallback classifier reaps a dead tmpfs generation"

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
chmod +x "$ZCC_STUB_OK"

ZCC_STUB_GARBAGE="$WORK/zcc-stub-garbage"
cat > "$ZCC_STUB_GARBAGE" <<'STUBEOF'
#!/usr/bin/env bash
echo "not a trim report"
STUBEOF
chmod +x "$ZCC_STUB_GARBAGE"

DU_SHADOW_DIR="$WORK/du-shadow"
mkdir -p -- "$DU_SHADOW_DIR"
DU_CALL_LOG="$WORK/du-calls.log"
: > "$DU_CALL_LOG"
cat > "$DU_SHADOW_DIR/du" <<DUEOF
#!/usr/bin/env bash
printf 'du-called %s\n' "\$*" >> "$DU_CALL_LOG"
printf '0\t%s\n' "\${*: -1}"
DUEOF
chmod +x "$DU_SHADOW_DIR/du"

# A stand-in for GNU `timeout` on a box that ships none (stock macOS has no
# coreutils). Its directory is APPENDED to PATH below, so a real GNU timeout
# always wins where one exists and this stub only serves boxes that would
# otherwise have no budget mechanism to assert against at all. It implements
# exactly the form host_gc.sh uses — timeout --foreground SECS CMD... —
# exiting 124 when the budget expires and the child's own status otherwise,
# the two outcomes the assertions distinguish.
TIMEOUT_STUB_DIR="$WORK/timeout-stub"
mkdir -p -- "$TIMEOUT_STUB_DIR"
cat > "$TIMEOUT_STUB_DIR/timeout" <<'TIMEOUTEOF'
#!/usr/bin/env bash
# Poll, do not orphan a watcher: a `( sleep N && kill ) &` watcher holds this
# stub's captured stdout pipe open after its subshell dies, and the caller's
# command substitution then blocks for the whole budget.
secs="$2"
shift 2
"$@" &
child=$!
t=0
while kill -0 "$child" 2>/dev/null; do
    if [ "$t" -ge "$secs" ]; then
        kill -TERM "$child" 2>/dev/null
        wait "$child" 2>/dev/null
        exit 124
    fi
    sleep 1
    t=$(( t + 1 ))
done
wait "$child"
exit $?
TIMEOUTEOF
chmod +x "$TIMEOUT_STUB_DIR/timeout"

ZCC_STUB_COUNT="$WORK/zcc-stub-count"
: > "$ZCC_STUB_COUNT"
out="$(ZCL_HOST_GC_ZCC_BIN="$ZCC_STUB_OK" ZCC_STUB_COUNT_FILE="$ZCC_STUB_COUNT" \
    PATH="$DU_SHADOW_DIR:$PATH:$TIMEOUT_STUB_DIR" run_hostgc zcc apply)"
log="$(cat -- "$STATE_FX/host_gc.log" 2>/dev/null || true)"
assert_contains "$out" "reclaimed 7" \
    "zcc apply reports the freed amount straight from the evictor's report line"
assert_contains "$log" "zcc-trim" "zcc apply logs a zcc-trim row"
calls="$(wc -c < "$ZCC_STUB_COUNT" | tr -d '[:space:]')"
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
    PATH="$DU_SHADOW_DIR:$PATH:$TIMEOUT_STUB_DIR" run_hostgc zcc apply)"
assert_contains "$out" "FREEZE active" "zcc apply under a cache freeze says so"
assert_contains "$out" "reclaimed 7" \
    "zcc apply under a cache freeze still reports the evictor's freed amount"
calls="$(wc -c < "$ZCC_STUB_COUNT" | tr -d '[:space:]')"
[ "$calls" = 1 ] || fail "zcc apply under a freeze invoked the evictor $calls time(s), expected exactly 1"
if [ -s "$DU_CALL_LOG" ]; then
    fail "zcc apply under a cache freeze called du, which the one-walk invariant forbids: $(cat -- "$DU_CALL_LOG")"
else
    pass "zcc apply under a cache freeze never calls du — the freeze is recorded from the evictor's held figure"
fi

# A stub that prints garbage must fail loudly (zcc-trim-failed), never a
# silent 0-freed success row.
: > "$DU_CALL_LOG"
out="$(ZCL_HOST_GC_ZCC_BIN="$ZCC_STUB_GARBAGE" PATH="$DU_SHADOW_DIR:$PATH:$TIMEOUT_STUB_DIR" \
    run_hostgc zcc apply)"
log="$(cat -- "$STATE_FX/host_gc.log" 2>/dev/null || true)"
assert_contains "$log" "zcc-trim-failed" \
    "zcc apply with an unparsable evictor report logs zcc-trim-failed, not a success"
assert_not_contains "$out" "reclaimed" \
    "zcc apply with an unparsable evictor report never claims a reclaim"

# A stub that outruns its wall-clock budget must be given up on
# (zcc-trim-timeout), never left to block the rest of the run — the
# 2026-09-10 HDD incident: the evictor's own walk alone ran past the unit's
# 30-minute TimeoutStartSec and systemd SIGKILLed the whole sweep mid-walk,
# so nothing after zcc ever ran that hour.
ZCC_STUB_SLOW="$WORK/zcc-stub-slow"
cat > "$ZCC_STUB_SLOW" <<'STUBEOF'
#!/usr/bin/env bash
exec sleep 5
echo "zcc: 42 MB held, 0 MB ceiling, 0 MB freed"
STUBEOF
chmod +x "$ZCC_STUB_SLOW"

: > "$DU_CALL_LOG"
log_lines_before="$(wc -l < "$STATE_FX/host_gc.log" 2>/dev/null || echo 0)"
set +e
out="$(ZCL_HOST_GC_ZCC_BIN="$ZCC_STUB_SLOW" ZCL_HOST_GC_ZCC_BUDGET_S=1 \
    PATH="$DU_SHADOW_DIR:$PATH:$TIMEOUT_STUB_DIR" run_hostgc zcc apply)"
rc_zcc=$?
set -e
# Only the log rows THIS call appended — the fixture's log file accumulates
# across every section in this script, and an earlier section already
# logged a real zcc-trim success row.
new_log="$(tail -n "+$(( log_lines_before + 1 ))" -- "$STATE_FX/host_gc.log" 2>/dev/null || true)"
assert_contains "$out" "trim gave up after 1s" \
    "zcc apply past its budget says it gave up, not that it failed silently"
assert_contains "$new_log" "zcc-trim-timeout" \
    "zcc apply past its budget logs zcc-trim-timeout"
assert_not_contains "$new_log" "$(printf 'zcc-trim\t')" \
    "zcc apply past its budget never logs a zcc-trim success row"
assert_not_contains "$out" "reclaimed" \
    "zcc apply past its budget never claims a reclaim"
[ "$rc_zcc" -eq 0 ] || fail "zcc apply past its budget changed the run's own exit status to $rc_zcc"

# A full run (no --only) must run every OTHER category before zcc, so a
# slow zcc walk can never again starve them the way it did on 2026-09-10.
# --only runs a single category in isolation (see run_hostgc above), and a
# real full --apply run here would call the REAL ccache/journalctl/systemctl
# binaries against this box's actual state unless every one of the sweeps'
# own binary-seam flags were separately stubbed out — more fixture surface
# than this invariant is worth touching live-host-adjacent tools for. The
# invariant itself ("sweep_zcc is the last call in the driver, right before
# the summary") is a static property of host_gc.sh's own driver section
# (search for "^sweep_" calls between "^report_pressure$" and
# '^hdr "summary"$'), so assert it there directly instead of executing it.
driver_calls="$(awk '/^report_pressure$/{p=1} p && /^sweep_[a-z0-9_]+$/{print} /^hdr "summary"$/{exit}' "$HOSTGC")"
assert_contains "$driver_calls" "sweep_zcc" \
    "the driver still calls sweep_zcc somewhere in its sweep list"
last_call="$(printf '%s\n' "$driver_calls" | tail -1)"
[ "$last_call" = "sweep_zcc" ] \
    && pass "sweep_zcc is the LAST sweep call in the driver — a slow zcc walk can no longer starve any other category" \
    || fail "sweep_zcc is not the last sweep call in the driver (last call is '$last_call') — a slow zcc walk would again starve whatever runs after it"

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

# ---------------------------------------------------------- z23p (donors)
# The newest complete generation per build identity is the next proof's
# warm donor and is kept; every other generation is reaped as before. The
# keep is bounded: across the whole pool at most two donors survive.
make_donor() {
    local name="$1" ident="$2" completed="$3" dir="$Z23P_FX/$1"
    git -C "$REPO_FX" worktree add -q --detach "$dir" main >/dev/null
    mkdir -p -- "$dir/build/obj"
    printf 'object\n' > "$dir/build/obj/a.o"
    printf 'zcl.proof_build_complete.v1\nroot=%s\nlocal=%s\nbase=%s\ncompleted=%s\ncompiler=%s\nflags=%s\nenvironment=%s\nbuild_graph=%s\n' \
        "$REPO_FX" "$name" base "$completed" "$ident" "$ident" "$ident" "$ident" \
        > "$dir/build/.proof-build-complete"
    find "$dir" -exec touch -t 200001010000 {} + 2>/dev/null || true
}
make_donor gen-donor-a-old aaaa 100
make_donor gen-donor-a-new aaaa 400
make_donor gen-donor-b bbbb 300
make_donor gen-donor-c cccc 200

out="$(run_hostgc z23p dry-run)"
assert_contains "$out" "KEEP (newest warm donor" "z23p dry-run names the kept warm donor"
out="$(run_hostgc z23p apply)"
[ -d "$Z23P_FX/gen-donor-a-new" ] && pass "z23p keeps the newest donor of an identity" \
    || fail "z23p reaped the newest complete generation of its build identity"
[ -d "$Z23P_FX/gen-donor-b" ] && pass "z23p keeps the newest donor of a second identity" \
    || fail "z23p reaped the newest complete generation of a second identity"
[ -d "$Z23P_FX/gen-donor-a-old" ] && fail "z23p kept a superseded donor of the same identity" \
    || pass "z23p reaps a superseded generation of the same identity"
[ -d "$Z23P_FX/gen-donor-c" ] && fail "z23p kept a third donor past the two-donor bound" \
    || pass "z23p bounds the donor keep to two generations"

# A pool other than the default one (a lane's own proof pool, or the
# landing worktree's) is discovered from git's worktree list and swept by
# the same classifier.
OTHER_POOL="$HOME_FX/.z23/lanes/.z23p"
mkdir -p -- "$OTHER_POOL"
git -C "$REPO_FX" worktree add -q --detach "$OTHER_POOL/gen-lane-dead" main >/dev/null
touch_old "$OTHER_POOL/gen-lane-dead"
out="$(run_hostgc z23p dry-run)"
assert_contains "$out" "$OTHER_POOL" "z23p discovers a proof pool outside the default location"
out="$(run_hostgc z23p apply)"
[ -e "$OTHER_POOL/gen-lane-dead" ] && fail "z23p left a dead generation in a discovered pool" \
    || pass "z23p reaps a dead generation in a discovered pool"

# ------------------------------------------------------------------ wtbuild
# build/ output inside idle registered worktrees: the 230 GB that filled
# this host while every other category reported nothing to do.
touch_tree_old() { find "$1" -exec touch -t 200001010000 {} + 2>/dev/null || true; }
# touch_hours_ago PATH H — an mtime H hours in the past, GNU or BSD date.
touch_hours_ago() {
    local when
    when=$(( $(date +%s) - $2 * 3600 ))
    touch -t "$(date -d "@$when" +%Y%m%d%H%M 2>/dev/null || date -r "$when" +%Y%m%d%H%M)" -- "$1"
}
WT_FX="$HOME_FX/work"
mkdir -p -- "$WT_FX"
make_build_wt() {
    local dir="$WT_FX/$1"
    git -C "$REPO_FX" worktree add -q --detach "$dir" main >/dev/null
    mkdir -p -- "$dir/build/obj" "$dir/build/bin" "$dir/build/scratch" \
        "$dir/build/handoff" "$dir/build/devverify" "$dir/build/clang-facts" \
        "$dir/build/lane-stopwatch" "$dir/build/proof-receipts" \
        "$dir/build/acceptance-run" "$dir/build/evidence" "$dir/test-tmp/case1"
    printf 'object\n' > "$dir/build/obj/a.o"
    printf 'binary\n' > "$dir/build/bin/tool"
    printf 'lock\n' > "$dir/build/.session.lock"
    for sub in scratch handoff devverify clang-facts lane-stopwatch proof-receipts acceptance-run evidence; do
        printf 'kept\n' > "$dir/build/$sub/f"
    done
    printf 'scratch\n' > "$dir/test-tmp/case1/f"
    touch_tree_old "$dir"
}
make_build_wt wt-idle
make_build_wt wt-live
make_build_wt wt-recent
make_build_wt wt-mid
make_build_wt wt-unit
touch -- "$WT_FX/wt-recent/build/obj/a.o"
# A hand cleanup (or this sweep) removing entries bumps the build/ directory's
# own mtime; that alone is not recent build activity.
make_build_wt wt-emptied
touch -- "$WT_FX/wt-emptied/build" "$WT_FX/wt-emptied/build/obj"
# A proof generation (a direct child of a .z23p pool) belongs to z23p, but a
# worktree nested under a generation's test-tmp (a proof running this very
# selftest) is an ordinary worktree and must still be swept.
POOL_GEN="$HOME_FX/lanes/.z23p/gen1"
WT_FX="$HOME_FX/lanes/.z23p" make_build_wt gen1
WT_FX="$POOL_GEN/test-tmp" make_build_wt wt-nest
touch_hours_ago "$WT_FX/wt-mid/build/obj/a.o" 5
mkdir -p -- "$PROC_FX/4242424"
ln -s "$WT_FX/wt-live/build" "$PROC_FX/4242424/cwd"
printf '%s\n' "$WT_FX/wt-unit/build/bin/tool" > "$UNITS_EXEC_FILE"

out="$(run_hostgc wtbuild dry-run)"
assert_contains "$out" "KEEP (live process inside): $WT_FX/wt-live" "wtbuild keeps a worktree a live process sits in"
assert_contains "$out" "KEEP (built within" "wtbuild keeps a worktree built recently"
assert_contains "$out" "$WT_FX/wt-idle/build/obj" "wtbuild dry-run names an idle build output"
assert_contains "$out" "$POOL_GEN/test-tmp/wt-nest/build/obj" "wtbuild names a worktree nested inside a proof generation"
[ -d "$WT_FX/wt-idle/build/obj" ] && pass "wtbuild dry-run removes nothing" \
    || fail "wtbuild dry-run removed build output"

out="$(run_hostgc wtbuild apply)"
log="$(cat -- "$STATE_FX/host_gc.log" 2>/dev/null || true)"
[ -e "$WT_FX/wt-idle/build/obj" ] && fail "wtbuild apply left idle build output behind" \
    || pass "wtbuild apply removes idle build output"
[ -e "$WT_FX/wt-idle/build/bin" ] && fail "wtbuild apply left an idle build/bin no unit runs from" \
    || pass "wtbuild apply removes a build/bin no unit runs from"
for sub in scratch handoff devverify clang-facts lane-stopwatch proof-receipts acceptance-run evidence; do
    [ -f "$WT_FX/wt-idle/build/$sub/f" ] || fail "wtbuild apply removed evidence-bearing build/$sub"
done
pass "wtbuild apply keeps every evidence-bearing build/ child"
[ -f "$WT_FX/wt-idle/build/.session.lock" ] || fail "wtbuild apply removed hidden build state"
[ -e "$WT_FX/wt-idle/test-tmp/case1" ] && fail "wtbuild apply left idle test scratch behind" \
    || pass "wtbuild apply removes idle test scratch"
[ -e "$WT_FX/wt-emptied/build/obj" ] && fail "wtbuild read a freshly emptied build/ directory as recent work" \
    || pass "wtbuild ignores directory mtimes when judging recent work"
[ -f "$WT_FX/wt-live/build/obj/a.o" ] || fail "wtbuild apply removed output from a worktree in use"
[ -f "$WT_FX/wt-recent/build/obj/a.o" ] || fail "wtbuild apply removed output built recently"
[ -f "$WT_FX/wt-mid/build/obj/a.o" ] || fail "wtbuild apply ignored the 12h idle floor with disk to spare"
[ -f "$WT_FX/wt-unit/build/bin/tool" ] || fail "wtbuild apply removed a build/bin a systemd unit runs from"
[ -e "$WT_FX/wt-unit/build/obj" ] && fail "wtbuild apply kept the rest of a unit-bearing build/" \
    || pass "wtbuild apply keeps only the unit's build/bin"
assert_contains "$log" "$(printf 'wtbuild-remove\t%s' "$WT_FX/wt-idle/build/obj")" \
    "wtbuild apply logs each removal with its path"
[ -d "$REPO_FX" ] || fail "wtbuild touched the main checkout"
[ -f "$POOL_GEN/build/obj/a.o" ] || fail "wtbuild reached into a proof generation that z23p owns"
[ -e "$POOL_GEN/test-tmp/wt-nest/build/obj" ] && fail "wtbuild skipped a worktree nested inside a proof generation" \
    || pass "wtbuild sweeps a nested worktree and leaves the proof generation to z23p"

# Below the low-disk floor the idle window drops to two hours.
out="$(HGT_DF_AVAIL_KB=1048576 run_hostgc wtbuild apply)"
[ -e "$WT_FX/wt-mid/build/obj" ] && fail "wtbuild under low disk kept output idle for 5h" \
    || pass "wtbuild under low disk reclaims output idle for more than 2h"
[ -f "$WT_FX/wt-recent/build/obj/a.o" ] || fail "wtbuild under low disk removed output built just now"
# The live occupant of wt-live stays for the landed section below.

# --------------------------------------------------------------- repotmp
# The main checkout's own test-tmp: z23_lane_worktrees skips GC_REPO and
# is_protected shields the whole tree, so without this category the one
# scratch dir every developer shares grows without bound (measured 207k
# entries on 2026-09-29). The sweep reaps stale ENTRIES under it; the
# checkout itself, its tracked content and fresh entries stay put.
mkdir -p -- "$REPO_FX/test-tmp/stale-rig" "$REPO_FX/test-tmp/fresh-rig"
printf 'stale\n' > "$REPO_FX/test-tmp/stale-rig/f"
printf 'fresh\n' > "$REPO_FX/test-tmp/fresh-rig/f"
touch_old "$REPO_FX/test-tmp/stale-rig/f"
touch_old "$REPO_FX/test-tmp/stale-rig"

out="$(run_hostgc repotmp dry-run)"
assert_contains "$out" "stale-rig" "repotmp dry-run names a stale main-checkout scratch entry"
assert_not_contains "$out" "fresh-rig" "repotmp dry-run never names a fresh entry"
[ -d "$REPO_FX/test-tmp/stale-rig" ] || fail "repotmp dry-run removed scratch"
# The summary table is fed by cat_totals' own category list; a category that
# runs, reaps, and logs but is missing from that list reports TOTAL 0B while
# doing real work — exactly the silent drop this row assertion exists for.
grep -Eq '^  repotmp +[1-9][0-9]* item\(s\)' <<<"$out" \
    && pass "repotmp appears in the summary table with its count" \
    || fail "repotmp missing from the summary table (cat_totals category list)"

out="$(run_hostgc repotmp apply)"
[ -e "$REPO_FX/test-tmp/stale-rig" ] && fail "repotmp apply left stale main-checkout scratch behind" \
    || pass "repotmp apply removed the stale entry"
[ -e "$REPO_FX/test-tmp/fresh-rig" ] || fail "repotmp apply removed a fresh entry"
[ -f "$REPO_FX/base.txt" ] || fail "repotmp removed tracked main-checkout content"

# The batch cap bounds one run's work and reports the backlog it left.
mkdir -p -- "$REPO_FX/test-tmp/cap-a" "$REPO_FX/test-tmp/cap-b"
touch_old "$REPO_FX/test-tmp/cap-a"
touch_old "$REPO_FX/test-tmp/cap-b"
out="$(ZCL_HOST_GC_REPOTMP_BATCH_MAX=1 run_hostgc repotmp apply)"
assert_contains "$out" "of 2 stale entries" "repotmp batch run reports the remaining backlog"
left="$(find "$REPO_FX/test-tmp" -mindepth 1 -maxdepth 1 -name 'cap-*' | wc -l)"
[ "$left" = 1 ] || fail "repotmp batch cap reaped $left entries, expected exactly 1"
out="$(ZCL_HOST_GC_REPOTMP_BATCH_MAX=1 run_hostgc repotmp apply)"
left="$(find "$REPO_FX/test-tmp" -mindepth 1 -maxdepth 1 -name 'cap-*' | wc -l)"
[ "$left" = 0 ] || fail "repotmp second batch left $left entries, expected 0"

# --------------------------------------------------------------- landtmp
# The landing worktree's test scratch: reclaimed only when the land queue
# is provably idle.
LAND_FX="$HOME_FX/.local/state/z23/dev/land"
mkdir -p -- "$LAND_FX/wt/test-tmp/run1" "$LAND_FX/wt/test-tmp/ro/inner"
printf 'x\n' > "$LAND_FX/wt/test-tmp/run1/f"
printf 'x\n' > "$LAND_FX/wt/test-tmp/ro/inner/f"
chmod -R a-w "$LAND_FX/wt/test-tmp/ro"
: > "$LAND_FX/step.lock"
printf '{"seq":1,"state":"proving"}\n' > "$LAND_FX/queue.jsonl"

out="$(run_hostgc landtmp apply)"
assert_contains "$out" "SKIP (land queue has" "landtmp skips while the land queue holds a row"
[ -d "$LAND_FX/wt/test-tmp/run1" ] || fail "landtmp removed test scratch with a landing in flight"

: > "$LAND_FX/queue.jsonl"
if command -v flock >/dev/null 2>&1; then
    exec 9>"$LAND_FX/step.lock"
    flock -x 9
    out="$(run_hostgc landtmp apply)"
    exec 9>&-
    assert_contains "$out" "SKIP (step.lock is held" "landtmp skips while a land step holds step.lock"
    [ -d "$LAND_FX/wt/test-tmp/run1" ] || fail "landtmp removed test scratch while step.lock was held"

    out="$(run_hostgc landtmp dry-run)"
    log="$(cat -- "$STATE_FX/host_gc.log" 2>/dev/null || true)"
    assert_contains "$out" "would remove 2 entr(y/ies) under $LAND_FX/wt/test-tmp" \
        "landtmp dry-run summarizes the scratch it would remove"
    assert_contains "$log" "$(printf 'landtmp-remove\t%s' "$LAND_FX/wt/test-tmp/run1")" \
        "landtmp dry-run logs each entry it would remove"
    [ -d "$LAND_FX/wt/test-tmp/run1" ] || fail "landtmp dry-run removed test scratch"
    out="$(run_hostgc landtmp apply)"
    [ -e "$LAND_FX/wt/test-tmp/run1" ] && fail "landtmp apply left idle landing scratch behind" \
        || pass "landtmp apply removes idle landing scratch"
    [ -e "$LAND_FX/wt/test-tmp/ro" ] && fail "landtmp apply left a read-only scratch dir behind" \
        || pass "landtmp apply removes read-only scratch (chmod first)"
    [ -d "$LAND_FX/wt/test-tmp" ] || fail "landtmp apply removed test-tmp itself"
else
    out="$(run_hostgc landtmp apply)"
    assert_contains "$out" "SKIP (no flock" "landtmp without flock cannot prove step.lock free and skips"
    chmod -R u+w "$LAND_FX/wt/test-tmp"
fi

# ------------------------------------------------------------------ landed
# Clean, fully landed, idle worktrees: opt-in only, and recorded before
# removal so each one can be recreated at its exact commit.
make_landed_wt() {
    local name="$1" land="$2" dir="$WT_FX/$1"
    git -C "$REPO_FX" worktree add -q -b "lane/$name" "$dir" main >/dev/null
    echo "$name" > "$dir/$name.txt"
    git -C "$dir" add "$name.txt"
    git -C "$dir" commit -q -m "lane $name"
    if [ "$land" = 1 ]; then
        git -C "$REPO_FX" cherry-pick "$(git -C "$dir" rev-parse HEAD)" >/dev/null
    fi
    touch_tree_old "$dir"
}
make_landed_wt lane-landed 1
make_landed_wt lane-unlanded 0
make_landed_wt lane-dirty 1
echo wip > "$WT_FX/lane-dirty/wip.txt"
touch_tree_old "$WT_FX/lane-dirty"
landed_sha="$(git -C "$WT_FX/lane-landed" rev-parse HEAD)"

out="$(run_hostgc landed apply)"
assert_contains "$out" "opt-in" "landed without --reap-landed-worktrees says it is opt-in"
[ -d "$WT_FX/lane-landed" ] || fail "landed removed a worktree without the opt-in flag"

out="$(HGT_EXTRA_ARGS=--reap-landed-worktrees run_hostgc landed dry-run)"
assert_contains "$out" "$WT_FX/lane-landed" "landed dry-run names the fully landed worktree"
assert_contains "$out" "KEEP (unlanded commits" "landed dry-run keeps a worktree with unlanded commits"
assert_contains "$out" "KEEP (dirty" "landed dry-run keeps a dirty worktree"
[ -d "$WT_FX/lane-landed" ] || fail "landed dry-run removed a worktree"

out="$(HGT_EXTRA_ARGS=--reap-landed-worktrees run_hostgc landed apply)"
[ -e "$WT_FX/lane-landed" ] && fail "landed apply left a fully landed idle worktree" \
    || pass "landed apply removes a fully landed idle worktree"
[ -d "$WT_FX/lane-unlanded" ] || fail "landed apply removed a worktree with unlanded commits"
[ -f "$WT_FX/lane-dirty/wip.txt" ] || fail "landed apply removed a dirty worktree"
[ -d "$WT_FX/wt-live" ] || fail "landed apply removed a worktree a live process sits in"
[ -d "$WT_FX/wt-recent" ] || fail "landed apply removed a worktree touched within a day"
[ -d "$Z23P_FX/gen-alive" ] || fail "landed apply reached into a proof pool"
rm -f -- "$PROC_FX/4242424/cwd"
record="$(cat -- "$STATE_FX/landed_worktrees.tsv" 2>/dev/null || true)"
assert_contains "$record" "$(printf '%s\t%s' "$WT_FX/lane-landed" "$landed_sha")" \
    "landed apply records path and commit before removing"
[ -d "$UNITS_FX/unlanded-unit" ] || fail "landed reached into the units directory"

# ---------------------------------------------------------------- lowdisk
# Below the low-disk floor after a sweep: one line of agent mail naming the
# largest consumers, rate limited to one per six hours, never an absolute
# path in the body.
: > "$DEV_STUB_CALLS"
out="$(HGT_DF_AVAIL_KB=1048576 run_hostgc lowdisk dry-run)"
assert_contains "$out" "would post" "lowdisk dry-run says it would post and does not"
[ -s "$DEV_STUB_CALLS" ] && fail "lowdisk dry-run posted mail" || pass "lowdisk dry-run posts nothing"

out="$(run_hostgc lowdisk apply)"
[ -s "$DEV_STUB_CALLS" ] && fail "lowdisk posted mail with disk to spare" \
    || pass "lowdisk is silent above the floor"

out="$(HGT_DF_AVAIL_KB=1048576 run_hostgc lowdisk apply)"
calls="$(cat -- "$DEV_STUB_CALLS")"
assert_contains "$calls" "dev agent mail --action=post --to=oauth --kind=problem --ref=host-gc" \
    "lowdisk posts one problem row to the dev agent mail leaf"
body="$(printf '%s\n' "$calls" | sed -n 's/.*--body=//p' | head -1)"
assert_contains "$body" "top:" "lowdisk names the largest consumers"
case "$body" in
    */[A-Za-z]*) fail "lowdisk body carries a path the mail filter refuses: $body" ;;
    *) pass "lowdisk body carries no absolute path" ;;
esac
[ "${#body}" -le 4096 ] || fail "lowdisk body is over 4 KiB"
out="$(HGT_DF_AVAIL_KB=1048576 run_hostgc lowdisk apply)"
assert_contains "$out" "rate limited" "lowdisk says why it stayed quiet"
n="$(wc -l < "$DEV_STUB_CALLS" | tr -d '[:space:]')"
[ "$n" = 1 ] && pass "lowdisk posts at most once per six hours" \
    || fail "lowdisk posted $n times inside its rate-limit window"

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
for p in "$HOME_FX/github/qedc/build" "$HOME_FX/github/qedc-lanes/x" "$HOME_FX/work/.qedc/data" \
    "/tmp/claude-1000/session" "/private/tmp/claude-1000/session" \
    "$HOME_FX/.zclassic-c23/blocks"; do
    out="$(env ZCL_HOST_GC_HOME="$HOME_FX" ZCL_HOST_GC_REPO="$REPO_FX" \
        "$HOSTGC" --check-protected "$p")"
    [ "$out" = "PROTECTED" ] || fail "$p is not protected: $out"
done

if [ "$FAIL" = 1 ]; then
    echo "host_gc_selftest: FAILED" >&2
    exit 1
fi
echo "host_gc_selftest: PASS"
