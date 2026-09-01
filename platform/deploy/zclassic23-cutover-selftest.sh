#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# zclassic23-cutover-selftest.sh — hermetic proof of zclassic23-cutover.sh's
# preflight comparison, its progress-based readiness verdict, and its
# auto-rollback. NO live nodes, NO real systemd:
#   * SYSTEMCTL=echo turns unit stop/start into visible no-ops,
#   * CUTOVER_HSTAR_READER points at a mock that returns injected H* per role,
#   * CUTOVER_PROGRESS_READER points at a mock pre-RPC progress observable,
#   * two throwaway fixture datadirs stand in for canonical + candidate.
# Every case asserts the exit code, the verdict line, AND the on-disk datadir
# layout (promotion actually swaps; rollback actually restores).
#
# The cases that matter most are the SLOW ones (10-13): a promoted node that
# is still catching up, or still booting behind a slow disk, must keep its
# promotion. Only observed SILENCE may reverse a live datadir promotion.
#
# Emits a final "cutover-selftest: PASS" line iff every case passed.
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CUTOVER="$SCRIPT_DIR/zclassic23-cutover.sh"
# str_contains: pipeline-free substring test. `printf | grep -q` under
# pipefail reports a MATCH as 141 when printf takes SIGPIPE, which inverts the
# assertion — and this selftest's captured output grew when the cutover script
# started printing progress heartbeats.
# shellcheck source=tools/scripts/sh_str.sh
. "$SCRIPT_DIR/../../tools/scripts/sh_str.sh"
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/zcl-cutover-selftest.XXXXXX")"
trap 'rm -rf "$SANDBOX"' EXIT

fails=0
fail() { printf '[cutover-selftest] FAIL: %s\n' "$*" >&2; fails=$((fails + 1)); }
ok()   { printf '[cutover-selftest] PASS: %s\n' "$*"; }

# ── mock H* reader: returns $MOCK_H_<ROLE> or -1 ────────────────────────────
# With $MOCK_H_<ROLE>_STEP set it returns base + call_number * step instead, so
# a case can model a node whose height CLIMBS between polls — the slow-box
# shape the old 300s stopwatch could not tell apart from a wedge.
MOCK_READER="$SANDBOX/mock_hstar.sh"
cat > "$MOCK_READER" <<'EOF'
#!/bin/sh
role="$1"
var="MOCK_H_$(printf '%s' "$role" | tr 'a-z-' 'A-Z_')"
eval "val=\${$var:-}"
eval "step=\${${var}_STEP:-}"
if [ -n "$step" ]; then
    counter="$MOCK_COUNTER_DIR/$var"
    n="$(cat "$counter" 2>/dev/null || echo 0)"
    n=$((n + 1))
    echo "$n" > "$counter"
    printf '%s\n' "$(( ${val:-0} + n * step ))"
    exit 0
fi
[ -n "$val" ] && printf '%s\n' "$val" || printf '%s\n' "-1"
EOF
chmod +x "$MOCK_READER"

# ── mock progress readers: the pre-RPC observable ───────────────────────────
# MOVING stands for a node blocked on a slow disk — blkio ticks climbing while
# it burns no CPU and answers no RPC. FROZEN stands for a genuine wedge. The
# whole point of the mechanism under test is that these two are different.
MOCK_PROGRESS_MOVING="$SANDBOX/mock_progress_moving.sh"
cat > "$MOCK_PROGRESS_MOVING" <<'EOF'
#!/bin/sh
counter="$MOCK_COUNTER_DIR/progress"
n="$(cat "$counter" 2>/dev/null || echo 0)"
n=$((n + 1))
echo "$n" > "$counter"
printf 'pid=9 cpu=0 blkio=%s io=0\n' "$((n * 1000))"
EOF
MOCK_PROGRESS_FROZEN="$SANDBOX/mock_progress_frozen.sh"
cat > "$MOCK_PROGRESS_FROZEN" <<'EOF'
#!/bin/sh
printf 'pid=9 cpu=7 blkio=7 io=7\n'
EOF
chmod +x "$MOCK_PROGRESS_MOVING" "$MOCK_PROGRESS_FROZEN"

# Fresh fixture datadirs: canonical/ (marker CANON), candidate/ (marker CAND).
setup_fixtures() {
    local root="$1"
    rm -rf "$root"
    mkdir -p "$root/canonical" "$root/candidate" "$root/counters"
    echo CANON > "$root/canonical/marker"
    echo CAND  > "$root/candidate/marker"
}

marker_of() { cat "$1/marker" 2>/dev/null || echo MISSING; }

# run_cutover <case-root> <extra cutover args...> — invokes the script with the
# mock wired in; per-case MOCK_H_* + knobs come from the caller's environment.
run_cutover() {
    local root="$1"; shift
    SYSTEMCTL="${SYSTEMCTL_MOCK:-echo}" \
    CANONICAL_DATADIR="$root/canonical" \
    CANONICAL_RPCPORT=19998 \
    CANDIDATE_RPCPORT=19999 \
    CUTOVER_HSTAR_READER="$MOCK_READER" \
    CUTOVER_PROGRESS_READER="${PROGRESS_MOCK:-$MOCK_PROGRESS_FROZEN}" \
    MOCK_COUNTER_DIR="$root/counters" \
    POLL_INTERVAL=1 STOP_GRACE=0 \
    READY_STALL_TIMEOUT="${STALL_MOCK:-2}" READY_HEARTBEAT=1 \
    sh "$CUTOVER" --candidate="$root/candidate" "$@"
}

# ── case 1: preflight REFUSE — candidate behind canonical ───────────────────
c1() {
    local r="$SANDBOX/c1"; setup_fixtures "$r"
    local out rc
    out="$(MOCK_H_CANONICAL_PRE=100 MOCK_H_CANDIDATE_PRE=90 \
           run_cutover "$r" --yes 2>&1)"; rc=$?
    [ "$rc" = 2 ] || fail "c1: expected exit 2 (behind), got $rc"
    str_contains "$out" "BEHIND canonical" || fail "c1: no BEHIND message"
    [ "$(marker_of "$r/canonical")" = CANON ] || fail "c1: canonical datadir touched"
    [ "$(marker_of "$r/candidate")" = CAND ] || fail "c1: candidate datadir touched"
    [ "$rc" = 2 ] && [ "$(marker_of "$r/canonical")" = CANON ] && ok "case1 refuses a candidate behind canonical, touches nothing"
}

# ── case 2: preflight REFUSE — no --yes (owner gate) ────────────────────────
c2() {
    local r="$SANDBOX/c2"; setup_fixtures "$r"
    local out rc
    out="$(MOCK_H_CANONICAL_PRE=100 MOCK_H_CANDIDATE_PRE=105 \
           run_cutover "$r" 2>&1)"; rc=$?
    [ "$rc" = 2 ] || fail "c2: expected exit 2 (no --yes), got $rc"
    str_contains "$out" "owner action" || fail "c2: no owner-gate message"
    [ "$(marker_of "$r/canonical")" = CANON ] || fail "c2: canonical datadir touched without --yes"
    ls -d "$r"/canonical.pre-cutover-* >/dev/null 2>&1 && fail "c2: a swap happened without --yes"
    [ "$rc" = 2 ] && ok "case2 refuses without --yes (owner gate), touches nothing"
}

# ── case 3: PROMOTE — candidate ahead, reaches the bar ──────────────────────
c3() {
    local r="$SANDBOX/c3"; setup_fixtures "$r"
    local out rc
    out="$(MOCK_H_CANONICAL_PRE=100 MOCK_H_CANDIDATE_PRE=105 \
           MOCK_H_CANDIDATE_POSTSTOP=-1 MOCK_H_CANONICAL_POST=105 \
           run_cutover "$r" --yes --timeout=5 2>&1)"; rc=$?
    [ "$rc" = 0 ] || fail "c3: expected exit 0 (promoted), got $rc"
    str_contains "$out" "CUTOVER: PROMOTED" || fail "c3: no PROMOTED verdict"
    [ "$(marker_of "$r/canonical")" = CAND ] || fail "c3: candidate not promoted into canonical path"
    [ -e "$r/candidate" ] && fail "c3: candidate dir still present after promote"
    local dem; dem="$(ls -d "$r"/canonical.pre-cutover-* 2>/dev/null | head -1)"
    [ -n "$dem" ] && [ "$(marker_of "$dem")" = CANON ] || fail "c3: old canonical not preserved as pre-cutover backup"
    [ "$rc" = 0 ] && [ "$(marker_of "$r/canonical")" = CAND ] && ok "case3 promotes candidate, preserves old canonical, verdict PROMOTED"
}

# ── case 4: ROLLBACK — promoted node goes silent below the bar ──────────────
c4() {
    local r="$SANDBOX/c4"; setup_fixtures "$r"
    local out rc
    # H* frozen at 42 AND a frozen progress token: nothing about this node
    # moves. That, and only that, may reverse a promotion.
    out="$(MOCK_H_CANONICAL_PRE=100 MOCK_H_CANDIDATE_PRE=105 \
           MOCK_H_CANDIDATE_POSTSTOP=-1 MOCK_H_CANONICAL_POST=42 \
           run_cutover "$r" --yes --timeout=1 2>&1)"; rc=$?
    [ "$rc" = 1 ] || fail "c4: expected exit 1 (rolled back), got $rc"
    str_contains "$out" "CUTOVER: ROLLED-BACK" || fail "c4: no ROLLED-BACK verdict"
    str_contains "$out" "went SILENT" || fail "c4: rollback did not name silence as the cause"
    # Datadir layout must be fully restored.
    [ "$(marker_of "$r/canonical")" = CANON ] || fail "c4: old canonical NOT restored (got $(marker_of "$r/canonical"))"
    [ "$(marker_of "$r/candidate")" = CAND ] || fail "c4: candidate NOT restored (got $(marker_of "$r/candidate"))"
    ls -d "$r"/canonical.pre-cutover-* >/dev/null 2>&1 && fail "c4: pre-cutover backup left behind after rollback"
    [ "$rc" = 1 ] && [ "$(marker_of "$r/canonical")" = CANON ] && [ "$(marker_of "$r/candidate")" = CAND ] \
        && ok "case4 rolls back cleanly, restores BOTH datadirs, verdict ROLLED-BACK"
}

# ── case 5: REFUSE — candidate unhealthy/unreadable (H*=-1) ──────────────────
c5() {
    local r="$SANDBOX/c5"; setup_fixtures "$r"
    local out rc
    out="$(MOCK_H_CANONICAL_PRE=100 \
           run_cutover "$r" --yes 2>&1)"; rc=$?   # candidate-pre unset -> -1
    [ "$rc" = 2 ] || fail "c5: expected exit 2 (unhealthy candidate), got $rc"
    str_contains "$out" "not healthy/readable" || fail "c5: no unhealthy-candidate message"
    [ "$(marker_of "$r/canonical")" = CANON ] || fail "c5: canonical touched on unhealthy candidate"
    [ "$rc" = 2 ] && ok "case5 refuses an unreadable/unhealthy candidate"
}

# ── case 6: FAILOVER — canonical DOWN, candidate healthy, promotes ──────────
c6() {
    local r="$SANDBOX/c6"; setup_fixtures "$r"
    local out rc
    # canonical-pre unset -> -1 (down). Bar becomes candidate H*.
    out="$(MOCK_H_CANDIDATE_PRE=200 \
           MOCK_H_CANDIDATE_POSTSTOP=-1 MOCK_H_CANONICAL_POST=200 \
           run_cutover "$r" --yes --timeout=5 2>&1)"; rc=$?
    [ "$rc" = 0 ] || fail "c6: expected exit 0 (failover promote), got $rc"
    str_contains "$out" "FAILOVER" || fail "c6: no FAILOVER warning"
    str_contains "$out" "CUTOVER: PROMOTED" || fail "c6: no PROMOTED verdict"
    [ "$(marker_of "$r/canonical")" = CAND ] || fail "c6: candidate not promoted in failover"
    [ "$rc" = 0 ] && ok "case6 promotes on failover when canonical is down"
}

# ── case 7: REFUSE pre-swap — candidate still running after stop ─────────────
c7() {
    local r="$SANDBOX/c7"; setup_fixtures "$r"
    local out rc
    # poststop still answers (105) -> refuse to rename a live datadir.
    out="$(MOCK_H_CANONICAL_PRE=100 MOCK_H_CANDIDATE_PRE=105 \
           MOCK_H_CANDIDATE_POSTSTOP=105 MOCK_H_CANONICAL_POST=105 \
           run_cutover "$r" --yes --timeout=5 2>&1)"; rc=$?
    [ "$rc" = 2 ] || fail "c7: expected exit 2 (candidate not stopped), got $rc"
    str_contains "$out" "refusing to rename a live datadir" || fail "c7: no live-datadir refusal"
    [ "$(marker_of "$r/canonical")" = CANON ] || fail "c7: canonical touched despite live candidate"
    [ "$(marker_of "$r/candidate")" = CAND ] || fail "c7: candidate touched despite being live"
    [ "$rc" = 2 ] && ok "case7 refuses to rename a candidate that is still running"
}

# ── case 8: ROLLBACK on start failure — new canonical won't start ────────────
c8() {
    local r="$SANDBOX/c8"; setup_fixtures "$r"
    # Mock systemctl that FAILS `start zclassic23` (the canonical unit) but
    # succeeds everything else, forcing the start-failure rollback branch.
    local mc="$SANDBOX/mock_systemctl_c8.sh"
    cat > "$mc" <<'EOF'
#!/bin/sh
if [ "$1" = start ] && [ "$2" = zclassic23 ]; then
    echo "mock systemctl: refusing to start $2" >&2
    exit 1
fi
echo "mock systemctl: $*"
exit 0
EOF
    chmod +x "$mc"
    local out rc
    out="$(SYSTEMCTL_MOCK="$mc" \
           MOCK_H_CANONICAL_PRE=100 MOCK_H_CANDIDATE_PRE=105 \
           MOCK_H_CANDIDATE_POSTSTOP=-1 MOCK_H_CANONICAL_POST=105 \
           run_cutover "$r" --yes --timeout=5 2>&1)"; rc=$?
    [ "$rc" = 1 ] || fail "c8: expected exit 1 (start-failure rollback), got $rc"
    str_contains "$out" "CUTOVER: ROLLED-BACK" || fail "c8: no ROLLED-BACK verdict on start failure"
    [ "$(marker_of "$r/canonical")" = CANON ] || fail "c8: old canonical NOT restored after start-failure rollback"
    [ "$(marker_of "$r/candidate")" = CAND ] || fail "c8: candidate NOT restored after start-failure rollback"
    [ "$rc" = 1 ] && [ "$(marker_of "$r/canonical")" = CANON ] \
        && ok "case8 rolls back and restores datadirs when the promoted unit won't start"
}

# ── case 9: a failing promote-mv itself triggers rollback (not a bare exit) ──
c9() {
    local r="$SANDBOX/c9"; setup_fixtures "$r"
    local shim="$SANDBOX/c9-shim"; mkdir -p "$shim"
    cat > "$shim/mv" <<'EOF'
#!/bin/sh
if [ -n "${MV_FAIL_SRC:-}" ] && [ "$1" = "$MV_FAIL_SRC" ]; then
    echo "mv shim: injected failure moving $1" >&2
    exit 1
fi
exec /bin/mv "$@"
EOF
    chmod +x "$shim/mv"
    local out rc
    out="$(PATH="$shim:$PATH" MV_FAIL_SRC="$r/candidate" \
           MOCK_H_CANONICAL_PRE=100 MOCK_H_CANDIDATE_PRE=105 \
           MOCK_H_CANDIDATE_POSTSTOP=-1 MOCK_H_CANONICAL_POST=105 \
           run_cutover "$r" --yes --timeout=5 2>&1)"; rc=$?
    [ "$rc" = 1 ] || fail "c9: expected exit 1 (promote-mv rollback), got $rc"
    str_contains "$out" "CUTOVER: ROLLED-BACK" || fail "c9: no ROLLED-BACK verdict on promote-mv failure"
    [ "$(marker_of "$r/canonical")" = CANON ] || fail "c9: old canonical NOT restored after promote-mv failure"
    [ "$(marker_of "$r/candidate")" = CAND ] || fail "c9: candidate datadir lost after promote-mv failure"
    [ "$rc" = 1 ] && [ "$(marker_of "$r/canonical")" = CANON ] \
        && ok "case9 rolls back when the promote rename itself fails"
}

# ── case 10: SLOW BOX — window expires while H* is still CLIMBING ───────────
# THE CASE THE OLD 300s BOUND GOT WRONG. The promoted node is catching up and
# has not reached the bar; under a stopwatch its live datadir promotion was
# REVERSED for having a slow disk. It must keep the promotion and say so.
c10() {
    local r="$SANDBOX/c10"; setup_fixtures "$r"
    local out rc
    out="$(MOCK_H_CANONICAL_PRE=100 MOCK_H_CANDIDATE_PRE=105 \
           MOCK_H_CANDIDATE_POSTSTOP=-1 \
           MOCK_H_CANONICAL_POST=1 MOCK_H_CANONICAL_POST_STEP=1 \
           STALL_MOCK=4 \
           run_cutover "$r" --yes --timeout=1 2>&1)"; rc=$?
    [ "$rc" = 3 ] || fail "c10: expected exit 3 (catching up), got $rc"
    str_contains "$out" "CUTOVER: PROMOTED-CATCHING-UP" || fail "c10: no PROMOTED-CATCHING-UP verdict"
    str_lacks "$out" "ROLLED-BACK" || fail "c10: a still-advancing node was ROLLED BACK"
    str_contains "$out" "STILL ADVANCING" || fail "c10: did not report why it stopped waiting"
    [ "$(marker_of "$r/canonical")" = CAND ] || fail "c10: promotion did not stand (canonical is $(marker_of "$r/canonical"))"
    [ -e "$r/candidate" ] && fail "c10: candidate dir restored — promotion was reversed"
    local dem; dem="$(ls -d "$r"/canonical.pre-cutover-* 2>/dev/null | head -1)"
    [ -n "$dem" ] && [ "$(marker_of "$dem")" = CANON ] || fail "c10: old canonical backup missing"
    [ "$rc" = 3 ] && [ "$(marker_of "$r/canonical")" = CAND ] \
        && ok "case10 keeps the promotion when the window expires while H* is still climbing"
}

# ── case 11: SLOW BOX — reaches the bar LATE, long after a 1s stopwatch ─────
# Lateness alone is not failure. Same inputs, more patience, exit 0.
c11() {
    local r="$SANDBOX/c11"; setup_fixtures "$r"
    local out rc
    out="$(MOCK_H_CANONICAL_PRE=100 MOCK_H_CANDIDATE_PRE=105 \
           MOCK_H_CANDIDATE_POSTSTOP=-1 \
           MOCK_H_CANONICAL_POST=100 MOCK_H_CANONICAL_POST_STEP=1 \
           STALL_MOCK=15 \
           run_cutover "$r" --yes --timeout=1 2>&1)"; rc=$?
    [ "$rc" = 0 ] || fail "c11: expected exit 0 (promoted late), got $rc"
    str_contains "$out" "CUTOVER: PROMOTED" || fail "c11: no PROMOTED verdict"
    str_lacks "$out" "ROLLED-BACK" || fail "c11: a node that reached the bar was rolled back"
    [ "$(marker_of "$r/canonical")" = CAND ] || fail "c11: promotion did not stand"
    [ "$rc" = 0 ] && ok "case11 promotes a node that reaches the bar long after the old stopwatch would have fired"
}

# ── case 12: SLOW BOX PRE-RPC — H* is -1 the whole time, but /proc moves ────
# A cold boot behind a 7200rpm disk answers no RPC for a long time. H* alone
# cannot tell that apart from a wedge; the blocked-on-disk observable can.
c12() {
    local r="$SANDBOX/c12"; setup_fixtures "$r"
    local out rc
    out="$(MOCK_H_CANONICAL_PRE=100 MOCK_H_CANDIDATE_PRE=105 \
           MOCK_H_CANDIDATE_POSTSTOP=-1 \
           PROGRESS_MOCK="$MOCK_PROGRESS_MOVING" STALL_MOCK=3 \
           run_cutover "$r" --yes --timeout=1 2>&1)"; rc=$?
    [ "$rc" = 3 ] || fail "c12: expected exit 3 (booting, still progressing), got $rc"
    str_contains "$out" "CUTOVER: PROMOTED-CATCHING-UP" || fail "c12: no PROMOTED-CATCHING-UP verdict"
    str_lacks "$out" "ROLLED-BACK" || fail "c12: a booting-but-working node was ROLLED BACK"
    [ "$(marker_of "$r/canonical")" = CAND ] || fail "c12: promotion did not stand during a slow boot"
    [ "$rc" = 3 ] && ok "case12 keeps the promotion while the node is pre-RPC but demonstrably working"
}

# ── case 13: a real WEDGE pre-RPC — nothing moves at all ────────────────────
# Same H*=-1 as case 12, but every observable is frozen. This is the fault the
# rollback exists for, and it must still fire — with its evidence printed.
c13() {
    local r="$SANDBOX/c13"; setup_fixtures "$r"
    local out rc
    out="$(MOCK_H_CANONICAL_PRE=100 MOCK_H_CANDIDATE_PRE=105 \
           MOCK_H_CANDIDATE_POSTSTOP=-1 \
           PROGRESS_MOCK="$MOCK_PROGRESS_FROZEN" STALL_MOCK=2 \
           run_cutover "$r" --yes --timeout=1 2>&1)"; rc=$?
    [ "$rc" = 1 ] || fail "c13: expected exit 1 (wedge rollback), got $rc"
    str_contains "$out" "CUTOVER: ROLLED-BACK" || fail "c13: a real wedge did not roll back"
    str_contains "$out" "went SILENT" || fail "c13: rollback did not name silence"
    str_contains "$out" "last progress token=" || fail "c13: rollback printed no evidence"
    [ "$(marker_of "$r/canonical")" = CANON ] || fail "c13: old canonical NOT restored after wedge rollback"
    [ "$(marker_of "$r/candidate")" = CAND ] || fail "c13: candidate NOT restored after wedge rollback"
    [ "$rc" = 1 ] && ok "case13 still rolls back a genuine wedge, and prints the evidence that justified it"
}

# ── case 14: --help states every exit code, including the non-failure one ───
c14() {
    local out rc
    out="$(sh "$CUTOVER" --help 2>&1)"; rc=$?
    [ "$rc" = 0 ] || fail "c14: --help exited $rc"
    str_contains "$out" "PROMOTED-CATCHING-UP" || fail "c14: --help omits exit 3"
    str_contains "$out" "--stall-timeout" || fail "c14: --help omits --stall-timeout"
    [ "$rc" = 0 ] && ok "case14 --help documents the catching-up exit code and the stall knob"
}

c1; c2; c3; c4; c5; c6; c7; c8; c9; c10; c11; c12; c13; c14

if [ "$fails" -eq 0 ]; then
    echo "cutover-selftest: PASS"
    exit 0
fi
echo "cutover-selftest: FAIL ($fails case(s))"
exit 1
