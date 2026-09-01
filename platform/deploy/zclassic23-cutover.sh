#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# zclassic23-cutover.sh — promote a warm-standby (or any healthy candidate
# datadir) to the canonical serving identity (ports 8033/18232, datadir
# ~/.zclassic-c23), with a hard preflight and an AUTO-ROLLBACK that can never
# strand you with no running canonical.
#
# Invoked by `make cutover CANDIDATE_DATADIR=<path>`. Canonical cutover is an
# OWNER action: this script refuses to touch the canonical unit until you pass
# --yes, and it prints a side-by-side height comparison first.
#
# ── Why a directory-rename swap and not a symlink ──────────────────────────
# The node opens its datadir with open(O_DIRECTORY|O_NOFOLLOW)
# (engine/composition/src/boot_datadir_lock.c) and mint/anchor preflight does the same.
# O_NOFOLLOW makes a SYMLINKED datadir root fail at boot with ELOOP, so a
# `~/.zclassic-c23 -> real-dir` convention is UNSAFE — the promoted node would
# refuse to start. systemd ALSO cannot expand $ENV in ReadWritePaths /
# StandardOutput, so an env-indirected datadir would break the canonical
# unit's sandbox + log paths. Both rule out symlink/env swaps.
#
# Instead we keep the canonical unit COMPLETELY UNTOUCHED (it always points at
# the literal ~/.zclassic-c23) and swap the DATADIRS underneath it with two
# renames while both units are stopped:
#     mv ~/.zclassic-c23        -> ~/.zclassic-c23.pre-cutover-<ts>   (demote)
#     mv <candidate>            -> ~/.zclassic-c23                    (promote)
# Rollback is exactly those two renames reversed. Ports, sandbox paths, log
# path and core dir all stay correct because the promoted data literally IS
# ~/.zclassic-c23 afterward. The candidate and ~/.zclassic-c23's parent must be
# on the same filesystem (checked) so each rename is atomic and instant.
#
# ── What it does NOT do ────────────────────────────────────────────────────
# No file inside any datadir is modified; it only RENAMES whole directories.
# It never deletes a datadir. The demoted old-canonical dir is preserved
# (~/.zclassic-c23.pre-cutover-<ts>) for manual inspection/rollback.
#
# ── Why the readiness bar is not a stopwatch ───────────────────────────────
# This used to auto-roll-back the promotion if the new canonical had not
# reached the pre-cutover H* within 300 seconds. That is the most damaging
# form of a duration verdict in this tree: on a 7200rpm box measured under
# 2 MB/s, opening a ~22 GB datadir and replaying to tip takes far longer than
# 300s, so a slow-but-perfectly-healthy machine got its promotion REVERSED —
# the datadirs swapped back, both units bounced — for the sole offence of
# having a cheap disk. Repeat that across a fleet and only fast-storage boxes
# can ever hold the canonical identity.
#
# Nothing about the promoted node's HEALTH is knowable from elapsed time. What
# the 300s was standing in for is "is it coming up, or is it wedged?", and
# that is directly observable: H* climbing, H* becoming readable at all, or —
# before RPC opens — the process burning CPU and, decisively, accumulating
# delayacct_blkio_ticks, which climbs precisely while it is BLOCKED on the
# disk. A wedge is SILENCE, not slowness.
#
# So the ONLY thing that can trigger the automatic rollback is a stretch of
# OBSERVED SILENCE (READY_STALL_TIMEOUT, default 900s with nothing moving),
# and the rollback message always prints the evidence that justified firing.
# The old READY_TIMEOUT survives as a REPORTING window: when it expires while
# the node is still advancing, the promotion STANDS and the script says so.
# The candidate already proved H* >= bar at preflight, so a promoted node
# still climbing is finishing a job whose inputs were verified, not failing.
#
# Exit codes: 0 PROMOTED, 1 ROLLED-BACK, 2 REFUSED (preflight / usage),
#             3 PROMOTED-CATCHING-UP (promotion stands; not yet at the bar,
#               still demonstrably advancing — NOT a failure).
set -eu

# ── knobs (all overridable; the test suite injects mocks through these) ─────
SYSTEMCTL="${SYSTEMCTL:-systemctl --user}"
CANONICAL_UNIT="${CANONICAL_UNIT:-zclassic23}"
STANDBY_UNIT="${STANDBY_UNIT:-zclassic23-standby}"
CANONICAL_DATADIR="${CANONICAL_DATADIR:-$HOME/.zclassic-c23}"
CANONICAL_RPCPORT="${CANONICAL_RPCPORT:-18232}"
CANDIDATE_DATADIR="${CANDIDATE_DATADIR:-}"
CANDIDATE_RPCPORT="${CANDIDATE_RPCPORT:-18272}"   # standby default RPC port
# REPORTING window: after this the script stops waiting and SAYS what it saw.
# It is not a failure bound and never triggers the rollback.
READY_TIMEOUT="${READY_TIMEOUT:-300}"
# The one clock that may fire the automatic rollback: consecutive seconds with
# NOTHING observable about the promoted node changing. Deliberately enormous
# relative to any honest slow-disk step, because its job is to catch a wedge.
READY_STALL_TIMEOUT="${READY_STALL_TIMEOUT:-900}"
# How often to print a "still catching up" line while waiting.
READY_HEARTBEAT="${READY_HEARTBEAT:-60}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"
STOP_GRACE="${STOP_GRACE:-10}"                    # wait for a stopped node to release its datadir
ALLOW_CROSS_FS="${ALLOW_CROSS_FS:-0}"
ASSUME_YES=0

# Seams the fixture selftest overrides. The real readers just talk to zcl-rpc.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
RPC_BIN="${ZCL_RPC_BIN:-$SCRIPT_DIR/build/bin/zcl-rpc}"
HSTAR_READER="${CUTOVER_HSTAR_READER:-_hstar_read_rpc}"
PROGRESS_READER="${CUTOVER_PROGRESS_READER:-_progress_read_proc}"

log()  { printf '[cutover] %s\n' "$*" >&2; }
die()  { printf '[cutover] ERROR: %s\n' "$*" >&2; exit 2; }

usage() {
    # Everything from the copyright line to the exit-code block, so --help
    # always states what each exit code means. Anchored on the text, not on
    # frozen line numbers, which is how this drifted before.
    sed -n '2,/^# *Exit codes:/p' "$0" | sed 's/^# \{0,1\}//'
    sed -n '/^# *Exit codes:/,/^set -eu$/p' "$0" |
        sed '/^set -eu$/d; 1d' | sed 's/^# \{0,1\}//'
    printf '\nOptions: --yes --candidate=<dir> --candidate-rpcport=<n>\n'
    printf '         --timeout=<s> (reporting window) --stall-timeout=<s> (silence before rollback)\n'
    printf '         --allow-cross-fs\n'
}

# ── H* reader ───────────────────────────────────────────────────────────────
# _hstar_read_rpc <role> <rpcport> <datadir> -> prints an integer H* on stdout,
# or -1 if the node is unreachable / the answer is not a non-negative integer.
# <role> lets a mock distinguish call sites (pre/post/poststop); the real
# reader ignores it. getblockcount serves H* (the provable frontier tip).
_hstar_read_rpc() {
    _role="$1"; _port="$2"; _dd="$3"
    _resp="$(ZCL_DATADIR="$_dd" ZCL_RPCPORT="$_port" "$RPC_BIN" getblockcount 2>/dev/null || true)"
    _val="$(printf '%s\n' "$_resp" | \
        sed -n 's/.*"result"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -1)"
    case "${_val:-}" in
        ''|*[!0-9]*) printf '%s\n' "-1" ;;
        *)           printf '%s\n' "$_val" ;;
    esac
}

hstar() { "$HSTAR_READER" "$1" "$2" "$3"; }

# ── pre-RPC progress reader ─────────────────────────────────────────────────
# A promoted node that has not opened its RPC port yet reports H*=-1, which is
# indistinguishable from "wedged" if H* is the only thing you look at. The
# kernel already knows the difference. delayacct_blkio_ticks (proc(5) field 42)
# climbs while the process is BLOCKED on I/O, so a box crawling through a
# block-file scan on a 7200rpm disk is visibly working even though it burns
# almost no CPU and answers nothing. A wedged process moves none of these.
#
# Prints an opaque token; ANY change between polls is progress. Empty output
# means "nothing observable", which is silence, not a fault on its own.
_progress_read_proc() {
    _pr_pid="$($SYSTEMCTL show "$CANONICAL_UNIT" -p MainPID --value 2>/dev/null || true)"
    case "${_pr_pid:-}" in
        ''|*[!0-9]*|0) return 0 ;;
    esac
    [ -r "/proc/$_pr_pid/stat" ] || return 0
    _pr_stat="$(cat "/proc/$_pr_pid/stat" 2>/dev/null || true)"
    [ -n "$_pr_stat" ] || return 0
    _pr_io="$(cat "/proc/$_pr_pid/io" 2>/dev/null || true)"
    # Fields are numbered AFTER the "pid (comm) " prefix is stripped, so
    # proc(5) utime(14)/stime(15) become $12/$13 and blkio(42) becomes $40.
    _pr_cpu="$(printf '%s\n' "$_pr_stat" | sed 's/^[0-9][0-9]* ([^)]*) //' |
        awk 'NF >= 13 && !seen { printf "%.0f\n", $12 + $13; seen = 1 }
             END { if (!seen) print 0 }')"
    _pr_blk="$(printf '%s\n' "$_pr_stat" | sed 's/^[0-9][0-9]* ([^)]*) //' |
        awk 'NF >= 40 && !seen { printf "%.0f\n", $40; seen = 1 }
             END { if (!seen) print 0 }')"
    _pr_bytes="$(printf '%s\n' "$_pr_io" |
        awk '/^(rchar|wchar|read_bytes|write_bytes):[ \t]*[0-9]+$/ { total += $2 }
             END { printf "%.0f\n", total + 0 }')"
    printf 'pid=%s cpu=%s blkio=%s io=%s\n' \
        "$_pr_pid" "$_pr_cpu" "$_pr_blk" "$_pr_bytes"
}

progress_token() { "$PROGRESS_READER"; }

# ── unit control (SYSTEMCTL=echo in tests makes these visible no-ops) ────────
unit_stop()  { log "stopping $1"; $SYSTEMCTL stop "$1" >/dev/null 2>&1 || $SYSTEMCTL stop "$1" || true; }
unit_start() { log "starting $1"; $SYSTEMCTL start "$1"; }

# ── argument parsing ────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --yes)                ASSUME_YES=1 ;;
        --candidate=*)        CANDIDATE_DATADIR="${1#--candidate=}" ;;
        --candidate-rpcport=*) CANDIDATE_RPCPORT="${1#--candidate-rpcport=}" ;;
        --timeout=*)          READY_TIMEOUT="${1#--timeout=}" ;;
        --stall-timeout=*)    READY_STALL_TIMEOUT="${1#--stall-timeout=}" ;;
        --allow-cross-fs)     ALLOW_CROSS_FS=1 ;;
        -h|--help)            usage; exit 0 ;;
        --*)                  die "unknown option $1 (see --help)" ;;
        *) [ -z "$CANDIDATE_DATADIR" ] && CANDIDATE_DATADIR="$1" || die "unexpected arg $1" ;;
    esac
    shift
done

# ── validation ──────────────────────────────────────────────────────────────
[ -n "$CANDIDATE_DATADIR" ] || die "CANDIDATE_DATADIR is required (make cutover CANDIDATE_DATADIR=<path>)"
[ -d "$CANDIDATE_DATADIR" ] || die "candidate datadir not found: $CANDIDATE_DATADIR"
# Canonicalize to catch a candidate that IS the canonical datadir.
_cand_abs="$(CDPATH= cd -- "$CANDIDATE_DATADIR" && pwd -P)" || die "cannot resolve $CANDIDATE_DATADIR"
if [ -d "$CANONICAL_DATADIR" ]; then
    _canon_abs="$(CDPATH= cd -- "$CANONICAL_DATADIR" && pwd -P)" || die "cannot resolve $CANONICAL_DATADIR"
    [ "$_cand_abs" != "$_canon_abs" ] || die "candidate == canonical datadir; nothing to promote"
fi

# Same-filesystem is required for atomic instant renames (a cross-fs mv is a
# slow, non-atomic copy that can half-fail mid-incident).
if [ "$ALLOW_CROSS_FS" != "1" ]; then
    _cand_dev="$(stat -c %d "$_cand_abs" 2>/dev/null || echo x)"
    _canon_parent_dev="$(stat -c %d "$(dirname "$CANONICAL_DATADIR")" 2>/dev/null || echo y)"
    [ "$_cand_dev" = "$_canon_parent_dev" ] || \
        die "candidate and $(dirname "$CANONICAL_DATADIR") are on different filesystems; a rename swap would not be atomic. Move the candidate onto the same fs, or pass --allow-cross-fs to accept a slow copy."
fi

# ══ PRE-FLIGHT ══════════════════════════════════════════════════════════════
log "PRE-FLIGHT: reading heights"
CANON_H="$(hstar canonical-pre  "$CANONICAL_RPCPORT" "$CANONICAL_DATADIR")"
CAND_H="$(hstar  candidate-pre  "$CANDIDATE_RPCPORT" "$CANDIDATE_DATADIR")"

printf '\n'
printf '  ┌─ cutover preflight ───────────────────────────────────────────\n'
printf '  │ canonical  unit=%-20s rpc=%-6s  H*=%s\n' "$CANONICAL_UNIT" "$CANONICAL_RPCPORT" "$CANON_H"
printf '  │ candidate  dir =%-20s rpc=%-6s  H*=%s\n' "$_cand_abs" "$CANDIDATE_RPCPORT" "$CAND_H"
printf '  └───────────────────────────────────────────────────────────────\n\n'

# The candidate MUST be readable + healthy; you never promote what you cannot
# verify. (A negative H* means unreachable rpc or a non-integer answer.)
[ "$CAND_H" -ge 0 ] 2>/dev/null || \
    { log "REFUSED: candidate is not healthy/readable on rpc $CANDIDATE_RPCPORT (H*=$CAND_H). Start the standby unit first."; exit 2; }

# If canonical is readable, the candidate must not be BEHIND it — promoting a
# node that serves a lower tip would regress the network's view. If canonical
# is DOWN (H*=-1) this is exactly the failover case: allow it, but the operator
# still has to pass --yes with eyes open.
if [ "$CANON_H" -ge 0 ] 2>/dev/null; then
    BAR="$CANON_H"
    if [ "$CAND_H" -lt "$CANON_H" ] 2>/dev/null; then
        log "REFUSED: candidate H*=$CAND_H is BEHIND canonical H*=$CANON_H. Let the standby catch up, then retry."
        exit 2
    fi
    log "preflight OK: candidate H*=$CAND_H >= canonical H*=$CANON_H"
else
    BAR="$CAND_H"
    log "WARNING: canonical is unreachable on rpc $CANONICAL_RPCPORT (H*=$CANON_H) — treating this as a FAILOVER. The promoted node must reach candidate H*=$CAND_H."
fi

if [ "$ASSUME_YES" != "1" ]; then
    log "REFUSED: canonical cutover is an owner action. Re-run with --yes to promote (heights above)."
    exit 2
fi

# ══ EXECUTE ═════════════════════════════════════════════════════════════════
TS="$(date +%Y%m%d%H%M%S)"
DEMOTED_DIR="$CANONICAL_DATADIR.pre-cutover-$TS"
DEMOTED_DONE=0
PROMOTED_DONE=0

# Rollback is defined BEFORE we mutate anything so it is always reachable. It
# reverses exactly the renames that actually happened and ALWAYS leaves a
# running canonical on the OLD datadir.
rollback() {
    _reason="$1"
    log "AUTO-ROLLBACK: $_reason"
    unit_stop "$CANONICAL_UNIT"
    if [ "$PROMOTED_DONE" = "1" ]; then
        # undo promote: the candidate's data is currently at CANONICAL_DATADIR
        if [ -e "$CANDIDATE_DATADIR" ]; then
            log "FATAL: cannot restore candidate — $CANDIDATE_DATADIR reappeared; leaving promoted data at $CANONICAL_DATADIR for manual repair"
        else
            mv "$CANONICAL_DATADIR" "$CANDIDATE_DATADIR"
            log "restored candidate datadir -> $CANDIDATE_DATADIR"
            PROMOTED_DONE=0
        fi
    fi
    if [ "$DEMOTED_DONE" = "1" ]; then
        # undo demote: move the old canonical back into place
        if [ -e "$CANONICAL_DATADIR" ]; then
            log "FATAL: cannot restore old canonical — $CANONICAL_DATADIR is occupied; old data preserved at $DEMOTED_DIR"
        else
            mv "$DEMOTED_DIR" "$CANONICAL_DATADIR"
            log "restored old canonical datadir <- $DEMOTED_DIR"
            DEMOTED_DONE=0
        fi
    fi
    # Best-effort restarts — a failure here must NOT abort rollback before the
    # verdict prints (the old datadir is already restored above, which is the
    # part that matters). Loudly flag a genuinely un-startable canonical.
    unit_start "$CANONICAL_UNIT" || log "FATAL: old canonical did NOT restart — data is safe at $CANONICAL_DATADIR but no canonical is running; investigate NOW"
    unit_start "$STANDBY_UNIT" || log "note: could not restart $STANDBY_UNIT (candidate datadir may have been the standby's)"
    printf 'CUTOVER: ROLLED-BACK  canonical_H*=%s candidate_H*=%s bar=%s\n' "$CANON_H" "$CAND_H" "$BAR"
    exit 1
}

log "EXECUTE: stopping both units before the datadir swap"
unit_stop "$STANDBY_UNIT"
unit_stop "$CANONICAL_UNIT"

# The candidate datadir must be RELEASED (its node fully stopped) before we can
# safely rename it — moving a datadir with a live writer corrupts it. Poll its
# rpc until it stops answering.
_waited=0
while [ "$_waited" -lt "$STOP_GRACE" ]; do
    _live="$(hstar candidate-poststop "$CANDIDATE_RPCPORT" "$CANDIDATE_DATADIR")"
    [ "$_live" -lt 0 ] 2>/dev/null && break
    sleep 1
    _waited=$((_waited + 1))
done
_live="$(hstar candidate-poststop "$CANDIDATE_RPCPORT" "$CANDIDATE_DATADIR")"
if [ "$_live" -ge 0 ] 2>/dev/null; then
    log "REFUSED (pre-swap): candidate still answering rpc $CANDIDATE_RPCPORT after stop+${STOP_GRACE}s — it is not stopped; refusing to rename a live datadir. Both units left stopped? Restarting canonical."
    unit_start "$CANONICAL_UNIT" || log "FATAL: canonical did NOT restart after refusal — data untouched at $CANONICAL_DATADIR but no canonical is running; start it manually NOW"
    exit 2
fi

# demote: preserve the old canonical (only if it exists — a failover from a
# canonical that never had a datadir is valid).
if [ -e "$CANONICAL_DATADIR" ]; then
    # Guarded: an unguarded mv under `set -e` would exit WITHOUT rollback,
    # leaving the canonical unit stopped (or the datadir missing) — the
    # stranding class this script exists to prevent.
    mv "$CANONICAL_DATADIR" "$DEMOTED_DIR" || rollback "demote rename failed ($CANONICAL_DATADIR -> $DEMOTED_DIR)"
    DEMOTED_DONE=1
    log "demoted old canonical -> $DEMOTED_DIR"
fi
# promote: candidate becomes the canonical datadir.
mv "$CANDIDATE_DATADIR" "$CANONICAL_DATADIR" || rollback "promote rename failed ($CANDIDATE_DATADIR -> $CANONICAL_DATADIR)"
PROMOTED_DONE=1
log "promoted candidate -> $CANONICAL_DATADIR"

unit_start "$CANONICAL_UNIT" || rollback "canonical unit failed to start on the promoted datadir"

# ── verify: new canonical becomes ready AND reaches the pre-cutover bar ──────
# The reporting window never ends before the stall detector has had its full
# chance to fire; otherwise a short --timeout could exit while silence was
# still unproven, and neither answer would have been earned.
_report_window="$READY_TIMEOUT"
_minimum_report_window=$(( READY_STALL_TIMEOUT + POLL_INTERVAL ))
if [ "$_report_window" -lt "$_minimum_report_window" ]; then
    _report_window="$_minimum_report_window"
    # The first observation establishes the baseline; it does not prove
    # elapsed silence. Reserve one complete poll beyond the stall threshold
    # so second-granularity wall-clock rounding cannot let the reporting
    # verdict race ahead of the rollback verdict.
    log "note: reporting window widened to ${_report_window}s so the ${READY_STALL_TIMEOUT}s stall detector gets a baseline plus one full poll"
fi
log "verifying promoted canonical reaches H* >= $BAR"
log "  rollback fires ONLY on ${READY_STALL_TIMEOUT}s of observed silence, never on elapsed time"
_start="$(date +%s)"
_report_deadline=$(( _start + _report_window ))
NEW_H=-1
_last_h=-2                       # -2 so the first reading always counts as news
_last_token=""
_last_progress="$_start"
_advances=0
_next_heartbeat=$(( _start + READY_HEARTBEAT ))
while :; do
    NEW_H="$(hstar canonical-post "$CANONICAL_RPCPORT" "$CANONICAL_DATADIR")"
    if [ "$NEW_H" -ge "$BAR" ] 2>/dev/null; then
        printf 'CUTOVER: PROMOTED  old_canonical_H*=%s candidate_H*=%s new_canonical_H*=%s (bar=%s, demoted=%s)\n' \
            "$CANON_H" "$CAND_H" "$NEW_H" "$BAR" "$DEMOTED_DIR"
        exit 0
    fi

    _token="$(progress_token || true)"
    _now="$(date +%s)"
    # Progress is ANY of: H* moved, H* became readable, or the kernel says the
    # process is still doing work. Each is independently sufficient.
    if [ "$NEW_H" != "$_last_h" ] || [ "$_token" != "$_last_token" ]; then
        _last_h="$NEW_H"
        _last_token="$_token"
        _last_progress="$_now"
        _advances=$(( _advances + 1 ))
    fi
    _silent_for=$(( _now - _last_progress ))
    _elapsed=$(( _now - _start ))

    if [ "$_now" -ge "$_next_heartbeat" ]; then
        log "still catching up: H*=$NEW_H bar=$BAR elapsed=${_elapsed}s advances=$_advances last_change=${_silent_for}s ago progress=[$_last_token]"
        _next_heartbeat=$(( _now + READY_HEARTBEAT ))
    fi

    # The ONLY path to an automatic rollback, and it prints its evidence.
    if [ "$_silent_for" -ge "$READY_STALL_TIMEOUT" ]; then
        rollback "promoted canonical went SILENT — nothing observable changed for ${_silent_for}s (limit ${READY_STALL_TIMEOUT}s) after ${_elapsed}s and $_advances observed advances; last H*=$NEW_H (bar=$BAR), last progress token=[$_last_token]. Slowness alone never reaches this line."
    fi

    if [ "$_now" -ge "$_report_deadline" ]; then
        # Silence was NOT established (that branch is above), so the node is
        # demonstrably still advancing. Reversing a live datadir promotion on
        # this evidence is the damage; the promotion stands.
        log "reporting window (${_report_window}s) expired while the promoted canonical was STILL ADVANCING — leaving the promotion in place. This is not a failure."
        log "  watch it finish with: ZCL_DATADIR=$CANONICAL_DATADIR ZCL_RPCPORT=$CANONICAL_RPCPORT $RPC_BIN getblockcount"
        log "  roll back by hand if you decide to: stop $CANONICAL_UNIT, mv $CANONICAL_DATADIR $CANDIDATE_DATADIR, mv $DEMOTED_DIR $CANONICAL_DATADIR, start $CANONICAL_UNIT"
        printf 'CUTOVER: PROMOTED-CATCHING-UP  old_canonical_H*=%s candidate_H*=%s new_canonical_H*=%s (bar=%s, demoted=%s, elapsed=%ss, advances=%s, last_change=%ss ago)\n' \
            "$CANON_H" "$CAND_H" "$NEW_H" "$BAR" "$DEMOTED_DIR" \
            "$_elapsed" "$_advances" "$_silent_for"
        exit 3
    fi

    sleep "$POLL_INTERVAL"
done
