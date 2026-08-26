#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Execute ship.sh's exact remote activation heredoc against a fake user service.
# This is a behavioral transaction test: success must activate exact process
# bytes, identity, and both package-verify workers staged beside the executable,
# while failures after either identity reload or executable replacement must
# restore all three files and restart the outgoing process.
#
# It also proves the half that decides WHEN a rollback is allowed to happen at
# all. That used to be a 300s stopwatch, and a remote box booting a ~22 GB
# datadir on a 7200rpm disk exceeds it routinely — so a correctly-shipped
# binary got restored on every slow host at once. The transaction now asks
# whether the candidate process is MOVING (tools/scripts/ship_progress_lib.sh:
# /proc io bytes, CPU ticks, delayacct_blkio_ticks) and only PROVEN silence or
# a process that will not stay up reaches the restore. Both directions are
# exercised below against real processes: still-progressing must NOT roll
# back, and wedged MUST.
#
# tools/ship_selftest.sh covers the classifier, the /proc parsers and the
# local polling loop (which has no host to talk to) hermetically; this gate
# runs it first, then exercises the shipped heredocs themselves.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${ZCL_SCRATCH_DIR:-${TMPDIR:-/tmp}}/zcl-ship-remote-test.XXXXXX")"
pidfile="$tmp/service.pid"

"$ROOT/tools/ship_selftest.sh"

cleanup() {
    if [ -s "$pidfile" ]; then
        kill "$(cat "$pidfile")" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM

awk '
    /<<'\''REMOTE_SCRIPT'\''$/ { copying=1; next }
    copying && /^REMOTE_SCRIPT$/ { exit }
    copying { print }
' "$ROOT/tools/ship.sh" > "$tmp/activate.body"
awk '
    /<<'\''ROLLBACK_SCRIPT'\''/ { copying=1; next }
    copying && /^ROLLBACK_SCRIPT$/ { exit }
    copying { print }
' "$ROOT/tools/ship.sh" > "$tmp/rollback.body"
[ -s "$tmp/activate.body" ] || { echo "check_ship_remote_transaction: REMOTE_SCRIPT heredoc did not extract" >&2; exit 1; }
[ -s "$tmp/rollback.body" ] || { echo "check_ship_remote_transaction: ROLLBACK_SCRIPT heredoc did not extract" >&2; exit 1; }

# THE WIRE FORMAT. ship.sh sends the health library ahead of each script on
# the same stdin, because the target box has no checkout to source it from.
# Reconstructing it here rather than stubbing it is what keeps this gate
# testing the bytes that actually run on a remote host.
cat "$ROOT/tools/scripts/ship_progress_lib.sh" "$tmp/activate.body" > "$tmp/activate.sh"
cat "$ROOT/tools/scripts/ship_progress_lib.sh" "$tmp/rollback.body" > "$tmp/rollback.sh"
bash -n "$tmp/activate.sh" "$tmp/rollback.sh"

# Three daemons, because the transaction now distinguishes three machine
# states that the old stopwatch collapsed into one:
#   answers `status`            -> qualifies
#   never answers, moves I/O    -> a slow box doing work. MUST NOT roll back.
#   never answers, moves nothing-> a wedge. MUST roll back.
# An EMPTY environment variable is still a SET one, so STATUS_OK is a compile
# -time constant here rather than a getenv the fixture could get wrong.
cat > "$tmp/node.c" <<'EOF'
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifndef VERSION
#define VERSION "unset"
#endif
#ifndef STATUS_OK
#define STATUS_OK 1
#endif
#ifndef BUSY
#define BUSY 0
#endif
static volatile const char *version = VERSION;
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "status") == 0)
        return STATUS_OK ? (version[0] == '\0') : 1;
    if (BUSY) {
        for (;;) {
            FILE *f = fopen("/dev/null", "w");
            if (f) { fprintf(f, "working %d\n", (int)getpid()); fclose(f); }
            usleep(20000);
        }
    }
    for (;;) pause();
}
EOF
cc -O0 -DVERSION='"old"' "$tmp/node.c" -o "$tmp/old"
cc -O0 -DVERSION='"new"' "$tmp/node.c" -o "$tmp/new"
cc -O0 -DVERSION='"slow"' -DSTATUS_OK=0 -DBUSY=1 "$tmp/node.c" -o "$tmp/newslow"
cc -O0 -DVERSION='"wedge"' -DSTATUS_OK=0 -DBUSY=0 "$tmp/node.c" -o "$tmp/newwedge"
old_sha="$(sha256sum < "$tmp/old" | awk '{print $1}')"
new_sha="$(sha256sum < "$tmp/new" | awk '{print $1}')"
slow_sha="$(sha256sum < "$tmp/newslow" | awk '{print $1}')"
wedge_sha="$(sha256sum < "$tmp/newwedge" | awk '{print $1}')"
[ "$old_sha" != "$new_sha" ]
[ "$slow_sha" != "$new_sha" ]
[ "$wedge_sha" != "$slow_sha" ]

mkdir -p "$tmp/mockbin" "$tmp/home/.config/systemd/user/zclassic23.service.d"
cat > "$tmp/mockbin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = --user ]; then shift; fi
case "${1:-}" in
    show)
        cat "$ZCL_SHIP_TEST_PIDFILE"
        ;;
    daemon-reload)
        if [ "${ZCL_SHIP_TEST_FAIL_ONCE:-}" = reload ] &&
           [ ! -e "$ZCL_SHIP_TEST_FAIL_MARKER" ]; then
            : > "$ZCL_SHIP_TEST_FAIL_MARKER"
            exit 1
        fi
        ;;
    restart)
        if [ "${ZCL_SHIP_TEST_FAIL_ALWAYS:-}" = restart ]; then
            exit 1
        fi
        if [ "${ZCL_SHIP_TEST_FAIL_ONCE:-}" = restart ] &&
           [ ! -e "$ZCL_SHIP_TEST_FAIL_MARKER" ]; then
            : > "$ZCL_SHIP_TEST_FAIL_MARKER"
            exit 1
        fi
        old_pid="$(cat "$ZCL_SHIP_TEST_PIDFILE" 2>/dev/null || true)"
        [ -z "$old_pid" ] || kill "$old_pid" 2>/dev/null || true
        ZCL_AGENT_EXPECT_SOURCE_ID="$ZCL_SHIP_TEST_WANT_SOURCE" \
        ZCL_AGENT_EXPECT_BUILD_COMMIT="$ZCL_SHIP_TEST_WANT_COMMIT" \
        ZCL_AGENT_EXPECT_BUILD_SOURCE=ship \
            "$ZCL_SHIP_TEST_TARGET" >/dev/null 2>&1 &
        echo $! > "$ZCL_SHIP_TEST_PIDFILE"
        ;;
    *) exit 2 ;;
esac
EOF
chmod +x "$tmp/mockbin/systemctl"

target="$tmp/zclassic23"
worker_v="$tmp/zclassic23-package-verify"
worker_d="$tmp/zclassic23-package-verify-dev"
dropin="$tmp/home/.config/systemd/user/zclassic23.service.d/90-build-identity.conf"

start_old() {
    install -m 755 "$tmp/old" "$target"
    install -m 755 "$tmp/old" "$worker_v"
    install -m 755 "$tmp/old" "$worker_d"
    "$target" >/dev/null 2>&1 &
    echo $! > "$pidfile"
}

stop_current() {
    if [ -s "$pidfile" ]; then
        kill "$(cat "$pidfile")" 2>/dev/null || true
        : > "$pidfile"
    fi
}

# invoke [fail_once] [fail_always] [want_sha] [window] [silence]
#
# The health knobs are POSITIONAL now, exactly as ship.sh passes them: ssh
# forwards no environment, so an env-only knob would be silently ignored on
# every real host — the same class of bug as a systemd unit expanding ${VAR}
# outside Exec*. Order: window, silence, rollback window, rollback silence,
# crash samples, unknown samples, rpc budgets.
invoke() {
    HOME="$tmp/home" PATH="$tmp/mockbin:$PATH" \
    ZCL_SHIP_TEST_PIDFILE="$pidfile" \
    ZCL_SHIP_TEST_TARGET="$target" \
    ZCL_SHIP_TEST_WANT_SOURCE="$(printf 'a%.0s' {1..64})" \
    ZCL_SHIP_TEST_WANT_COMMIT=candidate-commit \
    ZCL_SHIP_TEST_FAIL_MARKER="$tmp/fail.marker" \
    ZCL_SHIP_TEST_FAIL_ONCE="${1:-}" \
    ZCL_SHIP_TEST_FAIL_ALWAYS="${2:-}" \
        bash "$tmp/activate.sh" "$target" "${3:-$new_sha}" \
            "$(printf 'a%.0s' {1..64})" candidate-commit \
            "${3:-$new_sha}" "${3:-$new_sha}" \
            "${4:-20}" "${5:-20}" 20 20 3 5 "1 1 1"
}

stage_incoming() {
    install -m 755 "$1" "${target}.incoming"
    install -m 755 "$1" "${worker_v}.incoming"
    install -m 755 "$1" "${worker_d}.incoming"
}

reset_fixture() {
    stop_current
    rm -f "$tmp/fail.marker" "${target}.incoming" \
        "${target}.rollback" "${dropin}.ship.rollback" "${dropin}.ship.absent" \
        "${worker_v}.incoming" "${worker_d}.incoming" \
        "${worker_v}.ship.rollback" "${worker_d}.ship.rollback" \
        "${worker_v}.ship.absent" "${worker_d}.ship.absent"
    printf 'old identity\n' > "$dropin"
    start_old
}

assert_rolled_back() {
    [ "$(sha256sum < "$target" | awk '{print $1}')" = "$old_sha" ]
    [ "$(sha256sum < "$worker_v" | awk '{print $1}')" = "$old_sha" ]
    [ "$(sha256sum < "$worker_d" | awk '{print $1}')" = "$old_sha" ]
    grep -qx 'old identity' "$dropin"
    live_pid="$(cat "$pidfile")"
    [ "$(sha256sum < "/proc/$live_pid/exe" | awk '{print $1}')" = "$old_sha" ]
}

for fault in reload restart; do
    reset_fixture
    stage_incoming "$tmp/new"
    if invoke "$fault" >/dev/null 2>&1; then
        echo "check_ship_remote_transaction: activation unexpectedly survived $fault fault" >&2
        exit 1
    fi
    assert_rolled_back
done

# A rollback restart that also fails must never print a success claim. The
# outgoing process is deliberately left alive by this injected systemctl
# failure, allowing the test to prove the files were restored while the
# transaction reports the rollback as unverified.
reset_fixture
stage_incoming "$tmp/new"
if out="$(invoke "" restart 2>&1)"; then
    echo "check_ship_remote_transaction: activation survived persistent restart fault" >&2
    exit 1
fi
case "$out" in
    *'CRITICAL — rollback could not be process-qualified'*) ;;
    *) echo "check_ship_remote_transaction: missing activation rollback alarm" >&2; exit 1 ;;
esac
assert_rolled_back

# ── THE SLOW BOX ── the candidate is up with the exact right bytes and the
# exact right identity, but it does not answer `status` and it is not going to
# any time soon: it is a node grinding through a cold datadir. It IS moving —
# /proc/<pid>/io climbs the whole time. The reporting window closes first.
#
# The old code called this `healthy=0` and restored the previous binary, on
# every slow host in the fleet, in one command. It must now exit 3 and leave
# the candidate exactly where it is. If this assertion ever flips, ship is
# back to grading a machine by its disk speed.
reset_fixture
stage_incoming "$tmp/newslow"
slow_rc=0
#                      fault  always  want_sha      window silence
slow_out="$(invoke ""  ""     "$slow_sha" 2 600 2>&1)" || slow_rc=$?
if [ "$slow_rc" -ne 3 ]; then
    echo "check_ship_remote_transaction: a still-progressing candidate exited $slow_rc, wanted 3" >&2
    echo "$slow_out" >&2
    exit 1
fi
case "$slow_out" in
    *'UNVERIFIED (still progressing)'*) ;;
    *) echo "check_ship_remote_transaction: slow candidate did not say why it was unverified" >&2
       echo "$slow_out" >&2; exit 1 ;;
esac
case "$slow_out" in
    *'SLOW after'*|*'UNVERIFIED after'*) ;;
    *) echo "check_ship_remote_transaction: slow candidate printed no verdict evidence" >&2
       echo "$slow_out" >&2; exit 1 ;;
esac
# NOTHING was rolled back: the candidate bytes, its workers and its identity
# are all still in place.
[ "$(sha256sum < "$target" | awk '{print $1}')" = "$slow_sha" ] || {
    echo "check_ship_remote_transaction: a slow box had its binary ROLLED BACK" >&2; exit 1; }
[ "$(sha256sum < "$worker_v" | awk '{print $1}')" = "$slow_sha" ]
[ "$(sha256sum < "$worker_d" | awk '{print $1}')" = "$slow_sha" ]
grep -q '^Environment="ZCL_AGENT_EXPECT_SOURCE_ID=a\{64\}"$' "$dropin"

# ── THE WEDGE ── same shape, but NOTHING about the process moves: no bytes,
# no CPU, no blocked-on-disk ticks. That is proven silence, and it must still
# roll back. A fix that never rolls back is not a fix.
reset_fixture
stage_incoming "$tmp/newwedge"
wedge_rc=0
#                        fault always want_sha       window silence
wedge_out="$(invoke ""   ""    "$wedge_sha" 600 3 2>&1)" || wedge_rc=$?
if [ "$wedge_rc" -ne 1 ]; then
    echo "check_ship_remote_transaction: a wedged candidate exited $wedge_rc, wanted 1" >&2
    echo "$wedge_out" >&2
    exit 1
fi
case "$wedge_out" in
    *'WEDGED after'*) ;;
    *) echo "check_ship_remote_transaction: wedge rollback printed no WEDGED verdict" >&2
       echo "$wedge_out" >&2; exit 1 ;;
esac
case "$wedge_out" in
    *'last observation:'*) ;;
    *) echo "check_ship_remote_transaction: wedge rollback printed no evidence" >&2
       echo "$wedge_out" >&2; exit 1 ;;
esac
assert_rolled_back

reset_fixture
stage_incoming "$tmp/new"
invoke "" >/dev/null
[ "$(sha256sum < "$target" | awk '{print $1}')" = "$new_sha" ]
[ "$(sha256sum < "$worker_v" | awk '{print $1}')" = "$new_sha" ]
[ "$(sha256sum < "$worker_d" | awk '{print $1}')" = "$new_sha" ]
live_pid="$(cat "$pidfile")"
[ "$(sha256sum < "/proc/$live_pid/exe" | awk '{print $1}')" = "$new_sha" ]
grep -q '^Environment="ZCL_AGENT_EXPECT_SOURCE_ID=a\{64\}"$' "$dropin"
grep -qx 'Environment="ZCL_AGENT_EXPECT_BUILD_COMMIT=candidate-commit"' "$dropin"

# Exercise the exact post-activation fallback heredoc too — the leg ship.sh
# reaches from HERE when the local re-check proves a fault. Same positional
# knob order as the activation script: window, silence, crash samples,
# unknown samples, rpc budgets.
run_fallback() {
    HOME="$tmp/home" PATH="$tmp/mockbin:$PATH" \
    ZCL_SHIP_TEST_PIDFILE="$pidfile" ZCL_SHIP_TEST_TARGET="$target" \
    ZCL_SHIP_TEST_WANT_SOURCE="$(printf 'a%.0s' {1..64})" \
    ZCL_SHIP_TEST_WANT_COMMIT=candidate-commit \
    ZCL_SHIP_TEST_FAIL_ONCE="${1:-}" ZCL_SHIP_TEST_FAIL_ALWAYS="${2:-}" \
        bash "$tmp/rollback.sh" "$target" "${3:-20}" "${4:-20}" 3 5 "1 1 1"
}

run_fallback >/dev/null
assert_rolled_back

# ── BAR 3 ── A SLOW RESTORE MUST NOT BE MISREAD AS A FAILED RESTORE. This is
# the worst possible moment to get the verdict wrong: the prior binary has
# just been put back and an operator reading "CRITICAL — rollback restart did
# not qualify the old process" will start hunting a fault that does not exist
# while a healthy node boots underneath them.
#
# The rollback copy is swapped for a binary that never answers `status` and is
# demonstrably working, and the reporting window is made to close first.
reset_fixture
stage_incoming "$tmp/new"
invoke "" >/dev/null
install -m 755 "$tmp/newslow" "${target}.rollback"
slow_rb_rc=0
slow_rb_out="$(run_fallback "" "" 2 600 2>&1)" || slow_rb_rc=$?
if [ "$slow_rb_rc" -ne 3 ]; then
    echo "check_ship_remote_transaction: a slow restore exited $slow_rb_rc, wanted 3" >&2
    echo "$slow_rb_out" >&2
    exit 1
fi
case "$slow_rb_out" in
    *'Slow, not failed.'*) ;;
    *) echo "check_ship_remote_transaction: slow restore was not named as slow" >&2
       echo "$slow_rb_out" >&2; exit 1 ;;
esac
case "$slow_rb_out" in
    *CRITICAL*) echo "check_ship_remote_transaction: a slow restore was alarmed as CRITICAL" >&2
       echo "$slow_rb_out" >&2; exit 1 ;;
esac

# ...while a restore that is genuinely still IS loud. The alarm still exists.
reset_fixture
stage_incoming "$tmp/new"
invoke "" >/dev/null
install -m 755 "$tmp/newwedge" "${target}.rollback"
wedge_rb_rc=0
wedge_rb_out="$(run_fallback "" "" 600 3 2>&1)" || wedge_rb_rc=$?
if [ "$wedge_rb_rc" -ne 1 ]; then
    echo "check_ship_remote_transaction: a wedged restore exited $wedge_rb_rc, wanted 1" >&2
    echo "$wedge_rb_out" >&2
    exit 1
fi
case "$wedge_rb_out" in
    *'CRITICAL — rollback restart did not qualify the old process'*) ;;
    *) echo "check_ship_remote_transaction: wedged restore lost its alarm" >&2
       echo "$wedge_rb_out" >&2; exit 1 ;;
esac

# Re-activate new bytes, then deny the fallback restart. The fallback must
# return nonzero and call the rollback unqualified rather than claiming it.
reset_fixture
stage_incoming "$tmp/new"
invoke "" >/dev/null
if out="$(run_fallback "" restart 2>&1)"; then
    echo "check_ship_remote_transaction: fallback survived persistent restart fault" >&2
    exit 1
fi
case "$out" in
    *'CRITICAL — rollback restart'*) ;;
    *) echo "check_ship_remote_transaction: missing fallback rollback alarm" >&2; exit 1 ;;
esac

echo "check_ship_remote_transaction: PASS (activation/fallback faults rollback bytes+identity+workers; success and rollback process-qualified; a still-progressing candidate and a slow restore are NOT rolled back, a wedged one still is)"
