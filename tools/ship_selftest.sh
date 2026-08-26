#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# ship_selftest.sh — hermetic proof that tools/ship.sh never rolls a good
# binary off a slow machine, and still rolls a broken one back.
#
# tools/ship.sh had NO selftest of any kind, and the loop it needed one for
# spans two machines: an inline ssh heredoc that runs on the target box plus a
# local polling loop that re-checks it from here. A botched edit there rolls
# back good binaries across the whole fleet in one command, so the seam came
# first and the behaviour change second.
#
# THE SEAM is ZCL_SHIP_REMOTE_EXEC (tools/scripts/ship_progress_lib.sh,
# ship_remote_sh / ship_remote_script). When it is set it replaces ssh
# entirely and receives exactly what ssh would have: for `sh`, the one-shot
# observer program text; for `script`, the activation/rollback script on stdin
# plus its arguments. A fixture can therefore
#
#   * EXECUTE the program it was handed, in a sandbox with a mocked systemctl
#     and a real fixture process, so the whole chain — observer program text ->
#     ship_observe -> /proc -> observation line -> classifier — is exercised
#     with no host anywhere; or
#   * script a canned answer, so states a sandbox cannot manufacture (a kernel
#     with no CONFIG_TASK_DELAY_ACCT, a box wedged for ten minutes) are still
#     covered in seconds; or
#   * refuse to answer at all, which is the case the old code got backwards.
#
# Everything here runs in a mktemp sandbox, needs no node, no root, no
# network, and writes nothing tracked.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tools/scripts/ship_progress_lib.sh
. "$ROOT/tools/scripts/ship_progress_lib.sh"
SHIP_LIB_TEXT="$(cat "$ROOT/tools/scripts/ship_progress_lib.sh")"

SANDBOX="$(mktemp -d "${ZCL_SCRATCH_DIR:-${TMPDIR:-/tmp}}/zcl-ship-selftest.XXXXXX")"
FAILS=0
cleanup() {
    if [ -s "$SANDBOX/fixture.pid" ]; then
        kill "$(cat "$SANDBOX/fixture.pid")" 2>/dev/null || true
    fi
    rm -rf "$SANDBOX"
}
trap cleanup EXIT HUP INT TERM

pass() { printf 'ship-selftest:   ok  %s\n' "$*"; }
fail() { printf 'ship-selftest: FAIL %s\n' "$*" >&2; FAILS=$((FAILS + 1)); }

WANT_SHA="$(printf 'a%.0s' {1..64})"

# ── 1. the classifier ───────────────────────────────────────────────────────
# args: qualified observed exists silent silence unstable crash unknown
#       unknown_n window_expired advances
check_verdict() {
    local want="$1"; shift
    local got; got="$(ship_verdict "$@")"
    if [ "$got" = "$want" ]; then
        pass "verdict $want <- $*"
    else
        fail "verdict wanted $want got $got <- $*"
    fi
}

printf '\nship-selftest: 1. the classifier — five machine states, five words\n'
# Exact bytes + identity + an answer. Nothing else can produce this word.
check_verdict QUALIFIED  1 1 1 0 300 0 3 0 5 0 0
# THE DEFECT THIS REPLACES. The reporting window has expired on a box that is
# demonstrably still moving. Under the old code this was `healthy=0`, which
# meant ROLL BACK. It must be SLOW, and SLOW must never share an exit code
# with a fault.
check_verdict SLOW       0 1 1 10 300 0 3 0 5 1 7
# Window expired, nothing observed either way, silence not yet established.
# Refusing to guess is its own answer.
check_verdict UNVERIFIED 0 1 1 10 300 0 3 0 5 1 0
# Proven stillness. This is the only slowness-shaped input that convicts, and
# it is not slowness at all: nothing moved for the entire silence limit.
check_verdict WEDGED     0 1 1 300 300 0 3 0 5 0 0
check_verdict WEDGED     0 1 1 999 300 0 3 0 5 1 4
# A process that will not stay up. Not a slow machine.
check_verdict CRASHED    0 1 0 0 300 3 3 0 5 0 0
# One absent sample is a suspicion, never a verdict.
check_verdict WATCHING   0 1 0 0 300 1 3 0 5 0 0
check_verdict WATCHING   0 1 0 0 300 2 3 0 5 0 0
# No evidence at all. An unreachable host is UNKNOWN, and UNKNOWN is not a
# failed deploy — this is the fail-safe direction that matters most here.
check_verdict UNKNOWN    0 0 0 0 300 0 3 5 5 0 0
# ...and one unanswered probe is not that either.
check_verdict WATCHING   0 0 0 0 300 0 3 1 5 0 0
# Ordering: a positive crash observation outranks missing evidence, and
# missing evidence outranks a silence claim (a box we cannot see has not been
# proven still).
check_verdict CRASHED    0 1 0 999 300 3 3 5 5 1 0
check_verdict UNKNOWN    0 0 0 999 300 0 3 5 5 1 0
# Silence cannot be claimed from a sample that observed nothing.
check_verdict WATCHING   0 0 0 999 300 0 3 1 5 0 0

printf '\nship-selftest: 2. the exit-code contract\n'
for pair in "QUALIFIED 0" "CRASHED 1" "WEDGED 1" "SLOW 3" "UNVERIFIED 3" "UNKNOWN 4"; do
    set -- $pair
    got="$(ship_verdict_code "$1")"
    if [ "$got" = "$2" ]; then pass "$1 -> exit $2"; else fail "$1 -> exit $got, wanted $2"; fi
done
# No two verdicts that mean different things may share an exit code, and the
# two non-failures must never collide with the fault code.
if [ "$(ship_verdict_code SLOW)" = "$(ship_verdict_code WEDGED)" ]; then
    fail "SLOW and WEDGED share an exit code"
else
    pass "SLOW and WEDGED cannot be confused by exit code"
fi
if [ "$(ship_verdict_code UNKNOWN)" = "$(ship_verdict_code CRASHED)" ]; then
    fail "UNKNOWN and CRASHED share an exit code"
else
    pass "UNKNOWN and CRASHED cannot be confused by exit code"
fi
for v in SLOW UNVERIFIED UNKNOWN QUALIFIED; do
    if ship_verdict_is_destructive "$v"; then
        fail "$v is allowed to trigger a rollback"
    else
        pass "$v can never trigger a rollback"
    fi
done
for v in WEDGED CRASHED; do
    if ship_verdict_is_destructive "$v"; then
        pass "$v is allowed to trigger a rollback"
    else
        fail "$v cannot trigger a rollback — a fix that never rolls back is not a fix"
    fi
done

# ── 3. the /proc parsers ────────────────────────────────────────────────────
printf '\nship-selftest: 3. /proc parsers — the slow-disk signal must be legible\n'
# proc(5) after the "pid (comm) " strip: utime $12, stime $13, starttime $20,
# delayacct_blkio_ticks $40.
STAT_A="1 (z23 node) D 1 1 1 0 -1 0 0 0 0 0 11 22 0 0 20 0 9 0 4242 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 777 0 0"
STAT_B="1 (z23 node) D 1 1 1 0 -1 0 0 0 0 0 11 22 0 0 20 0 9 0 4242 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 9999 0 0"
[ "$(ship_cpu_ticks_from_text "$STAT_A")" = 33 ]    && pass "cpu ticks"    || fail "cpu ticks"
[ "$(ship_start_ticks_from_text "$STAT_A")" = 4242 ] && pass "start ticks"  || fail "start ticks"
[ "$(ship_blkio_ticks_from_text "$STAT_A")" = 777 ]  && pass "blkio ticks"  || fail "blkio ticks"
# THE SAMPLE THE WHOLE MECHANISM TURNS ON: identical CPU, identical I/O bytes,
# moving delayacct_blkio_ticks. That is a process blocked on a spinning
# platter, burning no CPU, and it is WORKING. If these two compared equal the
# slow box would be indistinguishable from a wedged one.
if [ "$(ship_blkio_ticks_from_text "$STAT_A")" != "$(ship_blkio_ticks_from_text "$STAT_B")" ]; then
    pass "blocked-on-disk progress is visible with flat CPU"
else
    fail "blocked-on-disk progress is INVISIBLE — a slow box reads as wedged"
fi
# A comm containing spaces and parentheses must not shift the field numbering.
STAT_UGLY="7 (z23 (node) x) D 1 1 1 0 -1 0 0 0 0 0 11 22 0 0 20 0 9 0 4242 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 777 0 0"
[ "$(ship_blkio_ticks_from_text "$STAT_UGLY")" = 777 ] && pass "comm with spaces/parens" \
    || fail "comm with spaces/parens shifts the fields"
# Kernels without CONFIG_TASK_DELAY_ACCT: the field is short or zero. It must
# read 0 rather than aborting, and CPU + I/O then carry the signal (proved
# end-to-end in scenario `io-only-kernel` below).
STAT_SHORT="1 (z23) S 1 1 1 0 -1 0 0 0 0 0 11 22 0 0 20 0 9 0 4242"
[ "$(ship_blkio_ticks_from_text "$STAT_SHORT")" = 0 ] && pass "no delayacct -> 0, not an error" \
    || fail "no delayacct did not degrade to 0"
[ "$(ship_cpu_ticks_from_text "")" = 0 ] && pass "empty stat -> 0" || fail "empty stat"
[ "$(ship_blkio_ticks_from_text "")" = 0 ] && pass "empty blkio -> 0" || fail "empty blkio"
IOTXT='rchar: 100
wchar: 20
read_bytes: 4096
write_bytes: 8192
cancelled_write_bytes: 999999
syscr: 5'
[ "$(ship_io_bytes_from_text "$IOTXT")" = 12408 ] && pass "io bytes (counted fields only)" \
    || fail "io bytes"

printf '\nship-selftest: 4. observation-line field extraction\n'
LINE="observed=1 exists=1 pid=9 start=5 sha=$WANT_SHA ident=yes rpc=no cpu=0 blkio=5000 io=12"
# `io` is a substring of `blkio` — the leading-space anchor is what stops the
# slow-disk counter from being read as the I/O byte count.
[ "$(ship_field "$LINE" io)" = 12 ]      && pass "io is not read out of blkio" || fail "io/blkio confusion"
[ "$(ship_field "$LINE" blkio)" = 5000 ] && pass "blkio"  || fail "blkio field"
[ "$(ship_field "$LINE" pid)" = 9 ]      && pass "pid"    || fail "pid field"
[ -z "$(ship_field "$LINE" nosuch)" ]    && pass "absent field is empty" || fail "absent field"
[ "$(ship_field_num "$LINE" nosuch)" = 0 ] && pass "absent numeric field is 0" || fail "absent numeric"
[ "$(ship_field_num "garbage" observed)" = 0 ] && pass "garbled transcript reads as no-evidence" \
    || fail "garbled transcript"
# Escalating patience: a late answer is an ANSWER, and the list sticks rather
# than growing without bound.
[ "$(ship_rpc_budget 1 "5 20 60")" = 5 ]  && pass "rpc budget 1" || fail "rpc budget 1"
[ "$(ship_rpc_budget 2 "5 20 60")" = 20 ] && pass "rpc budget 2" || fail "rpc budget 2"
[ "$(ship_rpc_budget 9 "5 20 60")" = 60 ] && pass "rpc budget sticks at the last" || fail "rpc budget sticks"

# ── 5. scripted observers driven through the real loop ──────────────────────
# Each writes ONE observation line per call, exactly as the box would.
mk_observer() {
    local name="$1"; shift
    cat > "$SANDBOX/$name"
    chmod +x "$SANDBOX/$name"
}

mk_observer fast-healthy <<EOF
#!/bin/sh
echo "observed=1 exists=1 pid=9 start=5 sha=$WANT_SHA ident=yes rpc=ok cpu=1 blkio=1 io=1"
EOF

# A node answering only on a later, more patient probe. A late answer is an
# answer; under a single fixed timeout this box was a failed deploy.
mk_observer late-answer <<EOF
#!/bin/sh
n=\$(cat "\$COUNTER" 2>/dev/null || echo 0); n=\$((n + 1)); echo "\$n" > "\$COUNTER"
if [ "\$n" -ge 3 ]; then rpc=ok; else rpc=no; fi
echo "observed=1 exists=1 pid=9 start=5 sha=$WANT_SHA ident=yes rpc=\$rpc cpu=\$n blkio=0 io=0"
EOF

# THE CASE THIS LANE EXISTS FOR: a box blocked on a 7200rpm disk. It answers
# no RPC at all, burns NO CPU and moves NO I/O bytes — only
# delayacct_blkio_ticks climbs. It is working the entire time.
mk_observer blocked-on-disk <<EOF
#!/bin/sh
n=\$(cat "\$COUNTER" 2>/dev/null || echo 0); n=\$((n + 1)); echo "\$n" > "\$COUNTER"
echo "observed=1 exists=1 pid=9 start=5 sha=$WANT_SHA ident=yes rpc=no cpu=7 blkio=\$((n * 1000)) io=3"
EOF

# The same box on a kernel with no CONFIG_TASK_DELAY_ACCT: blkio is stuck at
# 0 forever and the I/O byte counter has to carry the signal on its own.
mk_observer io-only-kernel <<EOF
#!/bin/sh
n=\$(cat "\$COUNTER" 2>/dev/null || echo 0); n=\$((n + 1)); echo "\$n" > "\$COUNTER"
echo "observed=1 exists=1 pid=9 start=5 sha=$WANT_SHA ident=yes rpc=no cpu=7 blkio=0 io=\$((n * 65536))"
EOF

# A genuinely wedged process: it exists, and NOTHING about it moves.
mk_observer wedged <<EOF
#!/bin/sh
echo "observed=1 exists=1 pid=9 start=5 sha=$WANT_SHA ident=yes rpc=no cpu=7 blkio=7 io=7"
EOF

# A crash loop: a new incarnation every time we look.
mk_observer restart-loop <<EOF
#!/bin/sh
n=\$(cat "\$COUNTER" 2>/dev/null || echo 0); n=\$((n + 1)); echo "\$n" > "\$COUNTER"
echo "observed=1 exists=1 pid=\$((100 + n)) start=\$((500 + n)) sha=$WANT_SHA ident=yes rpc=no cpu=1 blkio=1 io=1"
EOF

# The service is up but its MainPID is gone: the box looked and found nothing.
mk_observer no-process <<'EOF'
#!/bin/sh
echo "observed=1 exists=0 pid=0 start=0 sha=- ident=no rpc=no cpu=0 blkio=0 io=0"
EOF

# Nobody answered at all. Distinct from no-process by construction.
mk_observer no-evidence <<'EOF'
#!/bin/sh
exit 1
EOF

# Right bytes, right identity, answering — but the WRONG bytes. Qualification
# is still exact; nothing here loosened it.
mk_observer wrong-bytes <<'EOF'
#!/bin/sh
echo "observed=1 exists=1 pid=9 start=5 sha=deadbeef ident=yes rpc=ok cpu=7 blkio=7 io=7"
EOF

# Right bytes and answering, but the deploy identity is not in its environment.
mk_observer no-identity <<EOF
#!/bin/sh
echo "observed=1 exists=1 pid=9 start=5 sha=$WANT_SHA ident=no rpc=ok cpu=7 blkio=7 io=7"
EOF

# run_await <want-verdict> <want-rc> <observer> <window> <silence> <crash-n>
#           <unknown-n> [poll]
run_await() {
    local want_v="$1" want_rc="$2" obs="$3"
    local rc=0 out
    rm -f "$SANDBOX/counter"
    out="$(COUNTER="$SANDBOX/counter" \
        SHIP_AWAIT_WINDOW="$4" SHIP_AWAIT_SILENCE="$5" \
        SHIP_AWAIT_CRASH_SAMPLES="$6" SHIP_AWAIT_UNKNOWN_SAMPLES="$7" \
        SHIP_AWAIT_POLL="${8:-1}" SHIP_AWAIT_RPC_BUDGETS="1 1 1" \
        bash -c '. "$1"; ship_await fixture "$2" "$3"' _ \
            "$ROOT/tools/scripts/ship_progress_lib.sh" "$SANDBOX/$obs" "$WANT_SHA" 2>&1)" || rc=$?
    # NEVER judge through a pipe, and never grep a captured transcript for a
    # decision: str_contains is a case pattern and cannot invert under pipefail.
    if [ "$rc" = "$want_rc" ] && str_contains "$out" ": $want_v after"; then
        pass "$obs -> $want_v (exit $rc)"
    else
        fail "$obs wanted $want_v/exit $want_rc, got exit $rc: $out"
    fi
    # Evidence must accompany EVERY verdict, not only the destructive ones.
    if str_lacks "$out" "last observation:"; then
        fail "$obs printed a verdict with no observation to justify it"
    fi
}

# str_contains / str_lacks: `printf | grep -q` under pipefail returns 141 on a
# match once the payload outgrows the pipe buffer, which inverts the decision.
# shellcheck source=tools/scripts/sh_str.sh
. "$ROOT/tools/scripts/sh_str.sh"

printf '\nship-selftest: 5. the loop, end to end, through the observer seam\n'
#          verdict     rc  observer          window silence crash unknown poll
run_await  QUALIFIED   0   fast-healthy         30     10      3     5     1
run_await  QUALIFIED   0   late-answer          30     10      3     5     1
# ── BAR 1 ── a slow-but-progressing box must NEVER be rolled back. The window
# expires at 3s while blkio climbs; the verdict is SLOW and the exit code is
# 3, which no destructive branch in ship.sh reads.
run_await  SLOW        3   blocked-on-disk       3     60      3     5     1
run_await  SLOW        3   io-only-kernel        3     60      3     5     1
# ── BAR 2 ── a genuinely wedged box must STILL be rolled back. Same observer
# shape, nothing moving: WEDGED, exit 1.
run_await  WEDGED      1   wedged               60      3      3     5     1
# A crash loop and a vanished process are both faults, and both are named.
run_await  CRASHED     1   restart-loop         60     60      3     5     1
run_await  CRASHED     1   no-process           60     60      3     5     1
# ── BAR 5 ── evidence unavailable must NOT default to rolling back.
run_await  UNKNOWN     4   no-evidence          60     60      3     3     1
# Window expired with nothing observed either way: refuse to guess, and still
# do not roll back.
run_await  UNVERIFIED  3   wedged                3    600      3     5     1
# Qualification stayed exact: wrong bytes or a missing identity never pass.
run_await  UNVERIFIED  3   wrong-bytes           3    600      3     5     1
run_await  UNVERIFIED  3   no-identity           3    600      3     5     1

# ── 6. the two-machine loop, with no second machine ─────────────────────────
# This is the leg that had a hard-coded 300 and no override: ship.sh polling a
# remote box over ssh. The fixture below stands in for ssh at the
# ZCL_SHIP_REMOTE_EXEC seam and either EXECUTES the observer program it was
# handed (full chain, real /proc, real classifier) or refuses to answer.
printf '\nship-selftest: 6. the local polling loop, no remote host\n'

mkdir -p "$SANDBOX/mockbin"
cat > "$SANDBOX/mockbin/systemctl" <<'EOF'
#!/bin/sh
# Mock user manager: MainPID comes from a file the fixture controls.
case "${3:-}" in
    -p) cat "$ZCL_SHIP_TEST_PIDFILE" 2>/dev/null || exit 1 ;;
esac
cat "$ZCL_SHIP_TEST_PIDFILE" 2>/dev/null || exit 1
EOF
chmod +x "$SANDBOX/mockbin/systemctl"

# A fixture "daemon". It has to be a COMPILED binary, not a shell script:
# ship_observe reads /proc/<pid>/exe both to hash the running bytes and to
# re-invoke the daemon as `<exe> status`, and for a script that symlink points
# at the interpreter — the hash would be /bin/sh's and the status probe would
# run `sh status`. A script fixture would therefore prove nothing about the
# path being tested.
#
# `status` succeeds only when ZCL_SHIP_TEST_STATUS_OK is in the PROBE's
# environment, so one binary plays both a healthy node and a node whose RPC
# front door has not opened yet. ZCL_SHIP_TEST_BUSY, read once at startup,
# decides whether it moves I/O — that is the difference between a box working
# through a cold datadir and a box that is wedged.
cat > "$SANDBOX/node.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* An EMPTY environment variable is still a SET one: getenv returns a non-NULL
 * pointer to "". Testing the pointer alone made `FOO= ./node status` succeed,
 * so the fixture answered RPC in every scenario and three slow/wedged cases
 * silently qualified instead of testing what they were written for. */
static int flag(const char *name)
{
    const char *v = getenv(name);
    return v != NULL && *v != '\0';
}
int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "status") == 0)
        return flag("ZCL_SHIP_TEST_STATUS_OK") ? 0 : 1;
    if (flag("ZCL_SHIP_TEST_BUSY")) {
        for (;;) {
            FILE *f = fopen("/dev/null", "w");
            if (f) { fprintf(f, "working %d\n", (int)getpid()); fclose(f); }
            usleep(20000);
        }
    }
    for (;;) pause();
}
EOF
if ! cc -O0 "$SANDBOX/node.c" -o "$SANDBOX/node" 2>"$SANDBOX/cc.err"; then
    fail "could not build the fixture daemon: $(cat "$SANDBOX/cc.err")"
fi

# The ssh stand-in. $1 is the mode ship_remote_sh/ship_remote_script passes.
cat > "$SANDBOX/fake-ssh" <<'EOF'
#!/bin/bash
mode="$1"; shift
case "${FIXTURE_TRANSPORT:-up}" in
    down) exit 255 ;;          # ssh could not connect at all
    empty) exit 0 ;;           # connected, said nothing — also not evidence
esac
if [ "$mode" = sh ]; then
    # Run the exact program text ssh would have run, on this box, with the
    # mocked systemctl in front. This is the whole chain under test.
    PATH="$FIXTURE_MOCKBIN:$PATH" \
    ZCL_SHIP_TEST_PIDFILE="$FIXTURE_PIDFILE" \
    ZCL_SHIP_TEST_STATUS_OK="${FIXTURE_STATUS_OK:-}" \
        sh -c "$1"
    exit $?
fi
exit 0
EOF
chmod +x "$SANDBOX/fake-ssh"

# start_fixture_daemon [busy]
start_fixture_daemon() {
    ZCL_SHIP_TEST_BUSY="${1:-}" "$SANDBOX/node" >/dev/null 2>&1 &
    echo $! > "$SANDBOX/fixture.pid"
    printf '%s\n' "$!" > "$SANDBOX/mainpid"
}
stop_fixture_daemon() {
    if [ -s "$SANDBOX/fixture.pid" ]; then
        kill "$(cat "$SANDBOX/fixture.pid")" 2>/dev/null || true
        : > "$SANDBOX/fixture.pid"
    fi
}

# run_remote_await <want-verdict> <want-rc> <transport> <window> <silence>
#                  <crash-n> <unknown-n>
run_remote_await() {
    local want_v="$1" want_rc="$2" transport="$3"
    local rc=0 out
    out="$(FIXTURE_TRANSPORT="$transport" \
        FIXTURE_MOCKBIN="$SANDBOX/mockbin" \
        FIXTURE_PIDFILE="$SANDBOX/mainpid" \
        FIXTURE_STATUS_OK="${FIXTURE_STATUS_OK:-}" \
        ZCL_SHIP_REMOTE_EXEC="$SANDBOX/fake-ssh" \
        SHIP_LIB_TEXT="$SHIP_LIB_TEXT" \
        SHIP_OBS_UNIT=zclassic23 SHIP_OBS_SHA="$8" \
        SHIP_OBS_SRC= SHIP_OBS_COMMIT= \
        SHIP_SSH_OPTS= SHIP_REMOTE_HOST=fixture-host \
        SHIP_AWAIT_WINDOW="$4" SHIP_AWAIT_SILENCE="$5" \
        SHIP_AWAIT_CRASH_SAMPLES="$6" SHIP_AWAIT_UNKNOWN_SAMPLES="$7" \
        SHIP_AWAIT_POLL=1 SHIP_AWAIT_RPC_BUDGETS="1 2 3" \
        bash -c '. "$1"; ship_await fixture-host ship_remote_observe "$2"' _ \
            "$ROOT/tools/scripts/ship_progress_lib.sh" "$8" 2>&1)" || rc=$?
    if [ "$rc" = "$want_rc" ] && str_contains "$out" ": $want_v after"; then
        pass "remote leg / transport=$transport -> $want_v (exit $rc)"
    else
        fail "remote leg / transport=$transport wanted $want_v/exit $want_rc, got exit $rc: $out"
    fi
}

# The observer program really does travel over the seam and really is executed
# on the far side, against a real process and a real /proc: a live fixture
# daemon whose exact bytes match and which answers `status` QUALIFIES.
FIXTURE_SHA="$(sha256sum < "$SANDBOX/node" | awk '{print $1}')"
stop_fixture_daemon
start_fixture_daemon
FIXTURE_STATUS_OK=1 run_remote_await QUALIFIED 0 up 30 20 3 5 "$FIXTURE_SHA"

# ── BAR 5, over the wire ── ssh cannot connect. The old code read that as
# "did not come back healthy" and ROLLED BACK. It is UNKNOWN, and UNKNOWN is
# not a failed deploy.
FIXTURE_STATUS_OK= run_remote_await UNKNOWN 4 down 60 60 3 3 "$FIXTURE_SHA"
# Connected but silent is also not evidence.
FIXTURE_STATUS_OK= run_remote_await UNKNOWN 4 empty 60 60 3 3 "$FIXTURE_SHA"

# ── BAR 1, over the wire, against a REAL process ── the far side is up, has
# the right bytes, is moving I/O, and its `status` never answers — a node
# working through a cold datadir with its RPC front door still shut. The old
# local loop timed out on exactly this and rolled the fleet back. It is SLOW.
stop_fixture_daemon
start_fixture_daemon busy
FIXTURE_STATUS_OK= run_remote_await SLOW 3 up 4 600 3 5 "$FIXTURE_SHA"

# The same box with nothing moving at all, judged before silence is
# established: the window produces UNVERIFIED, which is still not a rollback.
stop_fixture_daemon
start_fixture_daemon
FIXTURE_STATUS_OK= run_remote_await UNVERIFIED 3 up 4 600 3 5 "$FIXTURE_SHA"

# ── BAR 2, over the wire ── nothing moving for the whole silence limit on a
# process that demonstrably exists. That is a wedge and it MUST roll back.
stop_fixture_daemon
start_fixture_daemon
FIXTURE_STATUS_OK= run_remote_await WEDGED 1 up 600 4 3 5 "$FIXTURE_SHA"

# The service names a MainPID that no longer exists: the far side LOOKED and
# found no process. That is a fault, and it is reachable over the seam.
stop_fixture_daemon
printf '999999\n' > "$SANDBOX/mainpid"
FIXTURE_STATUS_OK= run_remote_await CRASHED 1 up 60 600 3 5 "$FIXTURE_SHA"

# ── 7. the shipped script text ──────────────────────────────────────────────
# ship.sh's two remote scripts are extracted the same way
# tools/lint/check_ship_remote_transaction.sh extracts them, and must still
# parse once the library is prepended — that concatenation IS the wire format.
printf '\nship-selftest: 7. the wire format\n'
awk '
    /<<'\''REMOTE_SCRIPT'\''$/ { copying=1; next }
    copying && /^REMOTE_SCRIPT$/ { exit }
    copying { print }
' "$ROOT/tools/ship.sh" > "$SANDBOX/activate.sh"
awk '
    /<<'\''ROLLBACK_SCRIPT'\''/ { copying=1; next }
    copying && /^ROLLBACK_SCRIPT$/ { exit }
    copying { print }
' "$ROOT/tools/ship.sh" > "$SANDBOX/rollback.sh"
for f in activate rollback; do
    if [ ! -s "$SANDBOX/$f.sh" ]; then
        fail "$f heredoc did not extract — the gate that runs it is now vacuous"
        continue
    fi
    cat "$ROOT/tools/scripts/ship_progress_lib.sh" "$SANDBOX/$f.sh" > "$SANDBOX/$f.full.sh"
    if bash -n "$SANDBOX/$f.full.sh" 2>"$SANDBOX/$f.err"; then
        pass "$f heredoc parses with the library prepended"
    else
        fail "$f heredoc does not parse over the wire: $(cat "$SANDBOX/$f.err")"
    fi
done
# The observer program is exactly the library plus one call, and it must run
# on a plain /bin/sh — the target box's shell is not ours to choose.
PROG="$(ship_observer_program "$SHIP_LIB_TEXT" zclassic23 abc '' '' 5)"
printf '%s' "$PROG" > "$SANDBOX/observer.sh"
if sh -n "$SANDBOX/observer.sh"; then
    pass "observer program parses under POSIX sh"
else
    fail "observer program is not POSIX sh"
fi
if sh -n "$ROOT/tools/scripts/ship_progress_lib.sh"; then
    pass "library parses under POSIX sh"
else
    fail "library is not POSIX sh — the remote leg cannot run it"
fi
# No duration may decide a health verdict in ship.sh any more. All four sites
# were `deadline=$(( $(date +%s) + N ))` followed by a `while ... -lt
# "$deadline"` poll whose expiry meant ROLL BACK; the shape is named here by
# construction so a fifth one cannot be added quietly. Counting is done with
# grep -c into a variable, never with a status-carrying pipeline.
SHIP_TEXT="$(cat "$ROOT/tools/ship.sh")"
deadline_sites="$(grep -c 'deadline=\$(( \$(date +%s)' "$ROOT/tools/ship.sh" || true)"
if [ "$deadline_sites" = 0 ]; then
    pass "no health verdict in ship.sh is decided by a countdown"
else
    fail "ship.sh has $deadline_sites countdown-deadline health loops left"
fi
# ...and every one of the four subjects is judged by ship_await instead. Two
# on the remote leg (candidate, restore-inside-the-transaction), one on the
# local leg, one in the fallback rollback script.
await_sites="$(grep -c 'ship_await ' "$ROOT/tools/ship.sh" || true)"
if [ "$await_sites" -ge 4 ]; then
    pass "all four health sites go through ship_await ($await_sites call sites)"
else
    fail "only $await_sites ship_await call sites in ship.sh, expected at least 4"
fi
# The old `|| true` that turned an ssh failure into "not healthy" — and
# therefore into a fleet-wide rollback — must not come back. There is exactly
# one place allowed to decide what an unanswered host means, and it is
# ship_remote_observe in the library.
if str_contains "$SHIP_TEXT" 'remote did not come back healthy'; then
    fail "ship.sh still collapses an unanswered host into a failed deploy"
else
    pass "an unanswered host is no longer a failed deploy"
fi

printf '\n'
if [ "$FAILS" -eq 0 ]; then
    echo "ship-selftest: PASS (slow never rolls back; wedged and crashed still do; unknown is neither)"
    exit 0
fi
echo "ship-selftest: FAIL ($FAILS checks)" >&2
exit 1
