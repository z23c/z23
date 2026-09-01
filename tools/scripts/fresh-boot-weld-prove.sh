#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# fresh-boot-weld-prove.sh — copy-prove that the ZERO-FLAG cold-boot "weld"
# (engine/composition/src/boot_auto_install_bundle.c: boot_maybe_auto_install_consensus_bundle,
# the 1b passive autodetect of <datadir>/bundles/<name>.sqlite) actually welds a
# verified `zcl.consensus_state_bundle.v1` checkpoint bundle onto a WIPED/empty
# temp datadir with a completely ordinary boot — no `-install-consensus-bundle=`
# verb, no sync-assist flags — then proves the reducer folds FORWARD from the
# checkpoint so H* CLIMBS strictly past it (real progress, not just "booted").
# A companion NEGATIVE leg proves a one-byte-tampered bundle is REFUSED at
# admission: nothing installs, no state is borrowed, and the node still boots
# cleanly (never-stuck) rather than wedging or crash-looping.
#
# Gate is H* CLIMB (dumpstate reducer_frontier's "hstar" field), never "the
# node stayed up" or "no FATAL in the log" — see docs/HANDOFF.md and
# tools/scripts/fresh-boot-proof.sh for the same doctrine applied to the
# flagless from-genesis path this script's positive leg is the install-first
# sibling of.
#
# ─────────────────────────────────────────────────────────────────────────────
# WHAT "ZERO-FLAG" MEANS HERE, PRECISELY
# The node is launched with ONLY harness-isolation flags (-datadir -port
# -rpcport -fsport -httpsport -connect=<dead sink by default> -nolegacyimport
# -nofilesync -nobgvalidation) — never `-install-consensus-bundle=PATH`. The
# bundle is staged at <work-datadir>/bundles/<name>.sqlite BEFORE the node is
# launched; boot_autodetect_consensus_bundle() finds it there on its own. This
# is deliberately a DIFFERENT (and stricter) proof than
# tools/scripts/instant-on-copy-prove.sh, which drives the explicit terminal
# verb: that script proves the INSTALL PIPELINE; this one proves the BOOT
# WIRING that makes the pipeline fire with no operator action at all.
#
# ─────────────────────────────────────────────────────────────────────────────
# SUBSTRATE REALITY — READ BEFORE ASSUMING A LITERAL-BLANK DATADIR PASSES THE
# POSITIVE LEG TODAY. consensus_state_chain_binding_service.c's -3/-4/-11
# predicates (engine/composition/src/consensus_state_install_runtime.c calls them "ALWAYS
# target-derived / checkpoint authority never relaxes") require the target's
# OWN durable served height to already be >= the bundle height and its
# selected frontier to be an established, durable, consistent one — properties
# a truly-empty datadir does not have (no tip_finalize_log, served H*
# undefined). This is a state-REPLACEMENT precondition, not a from-zero
# bootstrap one; making the zero-flag weld work on a LITERAL blank datadir is
# exactly the "instant-on" gap the wf/instant-on-weld lane is closing (relaxing
# -4 the way wf/instant-on-header-bootstrap already relaxed it for the header
# case). This script's DEFAULT invocation (no --src) still runs the ideal
# scenario against whatever binary you point it at — that is the point: point
# ZCL_NODE_BIN at an integrated build that closes the gap and this script
# proves it; against a binary that hasn't landed the relaxation yet, the
# positive leg reports BLOCKED-CHAIN-BINDING (not a false PASS, not an opaque
# FAIL — a distinct, honest, actionable verdict) while the negative leg still
# runs and must still PASS unconditionally (tamper is caught at admission,
# strictly before any chain-binding decision, on ANY datadir shape).
#
# Supplying --src=DIR (a synced copy already at/past the checkpoint, with
# validated headers + on-disk bodies past it) satisfies -3/-4/-11 against
# TODAY's predicates too, so the positive leg can be proven against the
# current tree as an interim check — but note a --src datadir that itself
# already ran `-mint-anchor`/an install (i.e. already carries
# consensus-bundle-installed.marker, or whose OWN fold already covers the
# checkpoint) makes the weld's autodetect a same-day no-op
# (boot_maybe_auto_install_consensus_bundle's FIRST check short-circuits on a
# pre-existing marker) — that would prove nothing. Use a substrate that has
# validated headers/bodies past the checkpoint but NOT yet the checkpoint's
# UTXO/anchor/nullifier fold, or accept that --src is a mechanics check of the
# harness, not a proof of the weld, and prefer the flagless (no --src) leg
# against an integrated build for the real proof.
#
# SAFETY: the node is NEVER launched with -datadir set to a live/known
# datadir (see DENYLIST below). --src may point at one (read-only rsync copy,
# same pattern as tools/repro_on_copy.sh / instant-on-copy-prove.sh) but is
# never run against directly. Isolated ports, isolated HOME, dead-sink
# -connect by default (override with --connect=IP:PORT to fetch the tail from
# a live peer instead of relying on on-disk bodies).
#
# Usage:
#   # ideal: wiped/empty datadir, zero flags, point at an integrated build:
#   ZCL_NODE_BIN=/path/to/integrated/build/bin/zclassic23 \
#       tools/scripts/fresh-boot-weld-prove.sh --deadline=1800
#
#   # fail-closed proof only (fast; no substrate, no chain-binding gap to hit):
#   tools/scripts/fresh-boot-weld-prove.sh --negative-only
#
#   # interim positive proof against today's chain-binding predicates:
#   tools/scripts/fresh-boot-weld-prove.sh \
#       --src=$HOME/.zclassic-c23-some-pre-checkpoint-synced-copy --deadline=1800
#
# Exit codes: 0 PASS (or SKIP: no bundle found) · 1 FAIL ·
#             2 INVALID (environment/usage) · 3 BLOCKED (see per-leg verdict)
set -u

# ── Resolve repo root + binaries (env-overridable so the orchestrator can aim
#    this at an integrated build without touching this worktree) ───────────
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "$SELF_DIR/../.." && pwd)
if command -v git >/dev/null 2>&1; then
    _gr=$(git -C "$SELF_DIR" rev-parse --show-toplevel 2>/dev/null || true)
    [ -n "$_gr" ] && REPO_ROOT="$_gr"
fi
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"

# ── Defaults ────────────────────────────────────────────────────────────────
CHECKPOINT=3056758                 # REDUCER_FRONTIER_TRUSTED_ANCHOR (mainnet)
EXPECT_CLIMB_PAST=""               # default filled to CHECKPOINT after parse
BUNDLE=""
SRC=""
WORK_BASE=""                       # default: $TMPDIR (or /tmp)
RPCPORT=39640
P2PPORT=39641
FSPORT=39642
HTTPSPORT=39643
CONNECT="127.0.0.1:39999"          # dead sink -> offline fold from on-disk bodies
DEADLINE=1800
NEGATIVE_DEADLINE=90               # tamper refusal is fast; no fold to wait for
NEGATIVE_ONLY=0
POSITIVE_ONLY=0
CLEAN=0
SAMPLE_SECS=5
# ── MIN_SAMPLES — why a deadline may never cut the observation short ───────
# The POSITIVE predicate is a TWO-POINT observation: H* must be seen landing
# exactly at the checkpoint, and then seen ABOVE it. Fewer than two successful
# samples cannot decide it either way. So a deadline that expires before two
# samples have been taken is not measuring the node at all — it is measuring
# how much spare capacity the box had, and on a saturated or 7200rpm-disk box
# it manufactures a FAIL out of a perfectly healthy node. This floor makes the
# loop take its samples FIRST and consult the clock second: the deadline
# bounds how long we are willing to WAIT, never how much we are willing to
# OBSERVE. Same reasoning applies to the negative leg's marker poll below.
MIN_SAMPLES=2

DENYLIST="$HOME/.zclassic-c23 $HOME/.zclassic-c23-prod2 $HOME/.zclassic-c23-dev \
$HOME/.zclassic-c23-serve1 $HOME/.zclassic-c23-soak $HOME/.zclassic \
$HOME/.zclassic-c23-serve1-BACKUP-preflip"

usage() { sed -n '2,75p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }

for arg in "$@"; do
    case "$arg" in
        --bundle=*)            BUNDLE=${arg#*=} ;;
        --src=*)                SRC=${arg#*=} ;;
        --work-base=*)          WORK_BASE=${arg#*=} ;;
        --checkpoint=*)         CHECKPOINT=${arg#*=} ;;
        --expect-climb-past=*)  EXPECT_CLIMB_PAST=${arg#*=} ;;
        --rpcport=*)            RPCPORT=${arg#*=} ;;
        --port=*)               P2PPORT=${arg#*=} ;;
        --fsport=*)             FSPORT=${arg#*=} ;;
        --httpsport=*)          HTTPSPORT=${arg#*=} ;;
        --connect=*)            CONNECT=${arg#*=} ;;
        --deadline=*)           DEADLINE=${arg#*=} ;;
        --negative-deadline=*)  NEGATIVE_DEADLINE=${arg#*=} ;;
        --negative-only)        NEGATIVE_ONLY=1 ;;
        --positive-only)        POSITIVE_ONLY=1 ;;
        --clean)                CLEAN=1 ;;
        -h|--help)              usage 0 ;;
        *) echo "fresh-boot-weld-prove: unknown arg: $arg" >&2; usage 2 ;;
    esac
done
[ -n "$EXPECT_CLIMB_PAST" ] || EXPECT_CLIMB_PAST="$CHECKPOINT"

fail_env() { echo "fresh-boot-weld-prove: $1" >&2; exit 2; }

[ -x "$NODE_BIN" ] || fail_env "node binary not built/executable at $NODE_BIN (run 'make' or set ZCL_NODE_BIN)"

# ── Path helpers ────────────────────────────────────────────────────────────
resolve() { # best-effort absolute path (dir need not exist)
    _p=$1
    if command -v realpath >/dev/null 2>&1; then
        realpath -m -- "$_p" 2>/dev/null && return 0
    fi
    case "$_p" in
        /*) printf '%s\n' "$_p" ;;
        *)  printf '%s/%s\n' "$(pwd)" "$_p" ;;
    esac
}

is_denylisted() { # true if $1 equals or sits under any denylisted live datadir
    _cand=$(resolve "$1")
    for d in $DENYLIST; do
        _dr=$(resolve "$d")
        [ "$_cand" = "$_dr" ] && return 0
        case "$_cand/" in "$_dr"/*) return 0 ;; esac
    done
    return 1
}

# ── Bundle discovery (mirrors instant-on-copy-prove.sh's convention) ───────
is_sqlite_bundle() {
    [ -f "$1" ] || return 1
    head -c 16 -- "$1" 2>/dev/null | grep -q 'SQLite format 3' || return 1
    case "$(basename -- "$1")" in
        consensus-state-bundle-*.sqlite|*bundle*.sqlite) return 0 ;;
        *.sqlite) return 0 ;;
        *) return 1 ;;
    esac
}

discover_bundle() {
    if [ -n "$BUNDLE" ]; then
        is_sqlite_bundle "$BUNDLE" && { printf '%s\n' "$BUNDLE"; return 0; }
        return 1
    fi
    if [ -n "$SRC" ]; then
        for c in "$SRC"/bundles/consensus-state-bundle-*.sqlite \
                 "$SRC"/consensus-state-bundle-*.sqlite; do
            is_sqlite_bundle "$c" && { printf '%s\n' "$c"; return 0; }
        done
    fi
    _found=$(find "$HOME" -maxdepth 3 -type f -name 'consensus-state-bundle-*.sqlite' \
                 -printf '%T@\t%p\n' 2>/dev/null | sort -rn | cut -f2-)
    for c in $_found; do
        is_sqlite_bundle "$c" && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}

# ── Staging: an installable bundle must be read-only. Stage a 0444 copy under
#    a scratch dir so the discovered source stays untouched and both legs
#    (good + tampered) derive from the same byte-identical baseline. ────────
STAGE_DIR="${TMPDIR:-/tmp}/fresh-boot-weld-stage.$$"
stage_readonly() { # stage_readonly SRCFILE DSTNAME -> echoes staged path or ""
    _dst="$STAGE_DIR/$2"
    cp -f -- "$1" "$_dst" 2>/dev/null || return 1
    chmod 0444 -- "$_dst" 2>/dev/null || return 1
    printf '%s\n' "$_dst"
}

WORK_DIRS_TO_CLEAN=""
cleanup() {
    [ -n "$STAGE_DIR" ] && [ -d "$STAGE_DIR" ] && chmod -R u+w "$STAGE_DIR" 2>/dev/null && rm -rf "$STAGE_DIR"
    if [ "$CLEAN" = "1" ] && [ -n "$WORK_DIRS_TO_CLEAN" ]; then
        for d in $WORK_DIRS_TO_CLEAN; do rm -rf "$d"; done
    fi
}
trap cleanup EXIT INT TERM

# ── H* reader — reuses the SAME binary as its own RPC client, identical
#    convention to tools/scripts/fresh-boot-proof.sh. ───────────────────────
ISO_HOME=""
rpc_frontier() {
    _dd="$1"; _rp="$2"
    _out=""
    _try=0
    while [ "$_try" -lt 4 ]; do
        _out=$(HOME="$ISO_HOME" "$NODE_BIN" -rpcport="$_rp" -datadir="$_dd" \
                   dumpstate reducer_frontier 2>/dev/null)
        printf '%s' "$_out" | grep -q '"hstar"' && { printf '%s' "$_out"; return 0; }
        _try=$((_try + 1))
        sleep 1
    done
    printf '%s' "$_out"
}
jget() { # jget JSON KEY -> integer or empty
    printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*-?[0-9]+" | head -1 |
        grep -oE -- '-?[0-9]+$'
}

# ── Wall time is REPORTED, never asserted on ──────────────────────────────
# Every leg below prints how long it took and what the machine load looked
# like. Nothing branches on either number. The point is that when a leg does
# report a problem, the reader can tell "this node is broken" from "this box
# was saturated" in one glance instead of guessing.
loadavg_now() { cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo "unknown"; }
report_timing() { # report_timing LABEL START_EPOCH
    echo "  timing: $1 took $(( $(date +%s) - $2 ))s  (loadavg $(loadavg_now), $(nproc 2>/dev/null || echo '?') cpus) — reported, not asserted"
}

# ── NEGATIVE case: a one-byte-tampered bundle must fail closed on ANY datadir
#    shape (a fresh empty one included) — the digest/manifest check runs at
#    admission, strictly before the chain-binding decision, so it needs no
#    substrate at all. ───────────────────────────────────────────────────────
NEG_VERDICT="NOT_RUN"
run_negative() {
    echo "── NEGATIVE: one-byte-tampered bundle must be refused, no borrowed state ──"
    NEG_DD="${WORK_BASE:-${TMPDIR:-/tmp}}/zcl-weld-NEG-$$"
    if is_denylisted "$NEG_DD"; then
        echo "  NEGATIVE INVALID — computed work dir is denylisted: $NEG_DD"; NEG_VERDICT=INVALID; return
    fi
    rm -rf "$NEG_DD"; mkdir -p "$NEG_DD/bundles" || { NEG_VERDICT=INVALID; return; }
    WORK_DIRS_TO_CLEAN="$WORK_DIRS_TO_CLEAN $NEG_DD"
    ISO_HOME="$NEG_DD/.isohome"; mkdir -p "$ISO_HOME"
    [ -e "$HOME/.zcash-params" ] && ln -sfn "$HOME/.zcash-params" "$ISO_HOME/.zcash-params"

    FLIP=$(stage_readonly "$BUNDLE_STAGED" "bundle_flipped.sqlite")
    [ -n "$FLIP" ] && [ -f "$FLIP" ] || { echo "  could not stage tampered copy"; NEG_VERDICT=INVALID; return; }
    _size=$(wc -c < "$FLIP" 2>/dev/null | tr -d ' ')
    _off=$(( _size / 2 ))
    chmod u+w -- "$FLIP"
    perl -e '
        my ($f,$off)=@ARGV; open(my $fh,"+<",$f) or die "open: $!"; binmode $fh;
        seek($fh,$off,0); my $b=""; read($fh,$b,1); die "short read" if length($b)!=1;
        my $x=chr((ord($b)^0xFF)&0xFF); seek($fh,$off,0); print $fh $x; close $fh;
        printf("    byte at offset %d: 0x%02x -> 0x%02x\n",$off,ord($b),ord($x));
    ' "$FLIP" "$_off" 2>/dev/null
    echo "  flipped 1 byte at offset $_off of $_size"
    chmod 0444 -- "$FLIP"
    if cmp -s -- "$BUNDLE_STAGED" "$FLIP"; then
        echo "  tamper no-op (files identical) — cannot prove fail-closed"; NEG_VERDICT=INVALID; return
    fi

    NEG_BUNDLE_NAME="consensus-state-bundle-$CHECKPOINT.sqlite"
    cp -f -- "$FLIP" "$NEG_DD/bundles/$NEG_BUNDLE_NAME"
    chmod 0444 -- "$NEG_DD/bundles/$NEG_BUNDLE_NAME"

    NEG_LOG="$NEG_DD/neg_node.log"
    echo "  zero-flag boot on a FRESH empty datadir with the tampered bundle staged at"
    echo "  $NEG_DD/bundles/$NEG_BUNDLE_NAME (deadline=${NEGATIVE_DEADLINE}s)"
    HOME="$ISO_HOME" timeout "${NEGATIVE_DEADLINE}s" \
        "$NODE_BIN" -datadir="$NEG_DD" -rpcport="$RPCPORT" -port="$P2PPORT" \
        -fsport="$FSPORT" -httpsport="$HTTPSPORT" -connect="$CONNECT" \
        -nolegacyimport -nofilesync -nobgvalidation \
        > "$NEG_LOG" 2>&1 &
    NEG_PID=$!

    # Poll for the .failed never-stuck marker OR deadline; the node keeps
    # running normally throughout (never-stuck property under test too).
    # MIN_SAMPLES polls happen unconditionally (see MIN_SAMPLES above): a
    # busy box must not be able to skip the observation entirely and have
    # that scored as a refusal failure.
    NEG_STARTED=$(date +%s)
    _deadline=$(( NEG_STARTED + NEGATIVE_DEADLINE ))
    failed_marker=0
    _polls=0
    while [ "$_polls" -lt "$MIN_SAMPLES" ] || [ "$(date +%s)" -lt "$_deadline" ]; do
        _polls=$((_polls + 1))
        if [ -f "$NEG_DD/bundles/$NEG_BUNDLE_NAME.failed" ]; then
            failed_marker=1; break
        fi
        # An INSTALLED marker is a decision too — the wrong one. Waiting out
        # the rest of the window after the node has already decided buys no
        # information and just makes the run longer on every box. Leave on
        # the EVENT, not on the clock.
        [ -f "$NEG_DD/consensus-bundle-installed.marker" ] && break
        kill -0 "$NEG_PID" 2>/dev/null || break
        sleep 2
    done
    # Give the node a moment more to finish writing logs, then stop it.
    sleep 2
    if kill -0 "$NEG_PID" 2>/dev/null; then
        kill "$NEG_PID" 2>/dev/null
        for _ in $(seq 1 10); do kill -0 "$NEG_PID" 2>/dev/null || break; sleep 0.5; done
        kill -9 "$NEG_PID" 2>/dev/null
    fi
    wait "$NEG_PID" 2>/dev/null

    marker=0
    [ -f "$NEG_DD/consensus-bundle-installed.marker" ] && marker=1
    refusal_line=$(grep -am1 'did not install (marked .failed' "$NEG_LOG" 2>/dev/null || true)
    fj=$(rpc_frontier "$NEG_DD" "$RPCPORT")
    hs=$(jget "$fj" hstar); [ -z "$hs" ] && hs="-1"

    echo "  failed_marker=$failed_marker marker=$marker hstar=$hs polls=$_polls"
    [ -n "$refusal_line" ] && echo "    log: $refusal_line"
    report_timing "negative leg" "$NEG_STARTED"

    if [ "$failed_marker" = "1" ] && [ "$marker" = "0" ] && \
       { [ "$hs" = "-1" ] || [ "$hs" -lt "$CHECKPOINT" ] 2>/dev/null; }; then
        echo "  NEGATIVE PASS — tamper REFUSED, marked .failed, no state installed,"
        echo "                  H* never reached the checkpoint on borrowed state."
        NEG_VERDICT=PASS
    elif [ "$failed_marker" = "0" ] && [ "$marker" = "0" ] && [ -z "$refusal_line" ]; then
        # The node produced NO admission decision at all: no .failed, no
        # installed marker, no refusal line. That is not evidence the tamper
        # was accepted — it is evidence we stopped watching too early. A
        # saturated or slow-disk box lands here, and calling it FAIL would be
        # grading the machine instead of the code. It is still NOT a pass.
        echo "  NEGATIVE INCONCLUSIVE — the node never reached a bundle-admission"
        echo "  decision within ${NEGATIVE_DEADLINE}s ($_polls polls): no .failed marker, no"
        echo "  installed marker, no refusal line. Nothing here says the tamper was"
        echo "  accepted; it says the observation window closed first. Re-run with a"
        echo "  larger --negative-deadline on a slow/loaded box. See $NEG_LOG."
        NEG_VERDICT=INCONCLUSIVE
    else
        echo "  NEGATIVE FAIL — tamper was not cleanly rejected (see $NEG_LOG)."
        echo "  (failed_marker=$failed_marker marker=$marker hstar=$hs — the node reached an"
        echo "   admission decision and it was the wrong one; this is a code verdict,"
        echo "   not a timing one.)"
        grep -aE 'REFUSED|admission/validation failed|mismatch|chain binding' "$NEG_LOG" 2>/dev/null | \
            tail -5 | sed 's/^/    /'
        NEG_VERDICT=FAIL
    fi
}

# ── POSITIVE case: zero-flag boot, weld auto-installs, H*==checkpoint, then
#    H* CLIMBS. Uses --src if given (copied read-only, never run against);
#    otherwise a genuinely wiped/empty datadir — the ideal scenario. ────────
POS_VERDICT="NOT_RUN"
POS_FIRST=-1; POS_MAX=-1
run_positive() {
    echo "── POSITIVE: zero-flag boot installs checkpoint $CHECKPOINT, then H* CLIMBS ──"
    WORK="${WORK_BASE:-${TMPDIR:-/tmp}}/zcl-weld-POS-$$"
    if is_denylisted "$WORK"; then
        echo "  POSITIVE INVALID — computed work dir is denylisted: $WORK"; POS_VERDICT=INVALID; return
    fi
    rm -rf "$WORK"

    if [ -n "$SRC" ]; then
        [ -d "$SRC" ] || { echo "  POSITIVE INVALID — --src not a directory: $SRC"; POS_VERDICT=INVALID; return; }
        echo "  copying substrate $SRC -> $WORK (read-only source; never run against)"
        mkdir -p "$WORK" || { POS_VERDICT=INVALID; return; }
        if command -v rsync >/dev/null 2>&1; then
            rsync -a --delete \
                --exclude 'zclassic23.pid' --exclude '.cookie' --exclude '*.lock' \
                --exclude 'bundles' --exclude 'install_bundle_request' \
                --exclude 'consensus-bundle-installed.marker' \
                -- "$SRC"/ "$WORK"/ || { echo "  copy failed"; POS_VERDICT=INVALID; return; }
        else
            cp -a -- "$SRC"/. "$WORK"/ || { echo "  copy failed"; POS_VERDICT=INVALID; return; }
            rm -f "$WORK/zclassic23.pid" "$WORK/.cookie" "$WORK/install_bundle_request" \
                  "$WORK/consensus-bundle-installed.marker" 2>/dev/null
            rm -rf "$WORK/bundles" 2>/dev/null
        fi
        if [ -f "$WORK/consensus-bundle-installed.marker" ]; then
            echo "  POSITIVE INVALID — --src already carries the installed marker;"
            echo "                     the weld would short-circuit as a no-op. Use a"
            echo "                     pre-install substrate (see the script header)."
            POS_VERDICT=INVALID; return
        fi
    else
        echo "  no --src supplied: using a genuinely WIPED/EMPTY datadir (the ideal scenario)"
        mkdir -p "$WORK" || { POS_VERDICT=INVALID; return; }
    fi
    WORK_DIRS_TO_CLEAN="$WORK_DIRS_TO_CLEAN $WORK"
    mkdir -p "$WORK/bundles"
    ISO_HOME="$WORK/.isohome"; mkdir -p "$ISO_HOME"
    [ -e "$HOME/.zcash-params" ] && ln -sfn "$HOME/.zcash-params" "$ISO_HOME/.zcash-params"

    POS_BUNDLE_NAME="consensus-state-bundle-$CHECKPOINT.sqlite"
    cp -f -- "$BUNDLE_STAGED" "$WORK/bundles/$POS_BUNDLE_NAME"
    chmod 0444 -- "$WORK/bundles/$POS_BUNDLE_NAME"
    echo "  staged bundle at $WORK/bundles/$POS_BUNDLE_NAME"

    NODE_LOG="$WORK/pos_node.log"
    echo "  zero-flag boot (no -install-consensus-bundle=): $NODE_BIN -datadir=$WORK ..."
    HOME="$ISO_HOME" \
        "$NODE_BIN" -datadir="$WORK" -rpcport="$RPCPORT" -port="$P2PPORT" \
        -fsport="$FSPORT" -httpsport="$HTTPSPORT" -connect="$CONNECT" \
        -nolegacyimport -nofilesync -nobgvalidation \
        > "$NODE_LOG" 2>&1 &
    NODE_PID=$!

    POS_STARTED=$(date +%s)
    _deadline=$(( POS_STARTED + DEADLINE ))
    seen_checkpoint=0; climbed=0; seen_rpc=0; chain_binding_blocked=0; _samples=0
    # MIN_SAMPLES iterations run unconditionally before the clock is allowed
    # to end the loop — see MIN_SAMPLES at the top of this file. Without that
    # floor the deadline can expire between the node coming up and the first
    # dumpstate, and a healthy node scores INCONCLUSIVE purely because the box
    # was busy.
    while [ "$_samples" -lt "$MIN_SAMPLES" ] || [ "$(date +%s)" -lt "$_deadline" ]; do
        _samples=$((_samples + 1))
        kill -0 "$NODE_PID" 2>/dev/null || { echo "  node exited early (see $NODE_LOG)"; break; }
        fj=$(rpc_frontier "$WORK" "$RPCPORT")
        hs=$(jget "$fj" hstar)
        if [ -n "$hs" ]; then
            seen_rpc=1
            [ "$POS_FIRST" -lt 0 ] && POS_FIRST="$hs" && echo "  first H*: $hs"
            [ "$hs" -gt "$POS_MAX" ] 2>/dev/null && POS_MAX="$hs"
            [ "$hs" -eq "$CHECKPOINT" ] 2>/dev/null && seen_checkpoint=1
            if [ "$hs" -gt "$EXPECT_CLIMB_PAST" ] 2>/dev/null && [ "$seen_checkpoint" = "1" ]; then
                climbed=1
                echo "  H* CLIMBED to $hs (> $EXPECT_CLIMB_PAST, having landed at the checkpoint)"
                break
            fi
        fi
        if grep -aq 'selected-chain binding failed' "$NODE_LOG" 2>/dev/null; then
            chain_binding_blocked=1
        fi
        sleep "$SAMPLE_SECS"
    done
    kill "$NODE_PID" 2>/dev/null
    for _ in $(seq 1 10); do kill -0 "$NODE_PID" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$NODE_PID" 2>/dev/null
    wait "$NODE_PID" 2>/dev/null

    echo "  first=$POS_FIRST max=$POS_MAX seen_rpc=$seen_rpc seen_checkpoint=$seen_checkpoint climbed=$climbed samples=$_samples"
    report_timing "positive leg" "$POS_STARTED"
    if [ "$seen_rpc" = "0" ]; then
        echo "  POSITIVE INCONCLUSIVE — node never answered RPC across $_samples samples in"
        echo "  ${DEADLINE}s (see $NODE_LOG). INCONCLUSIVE, not FAIL: a node that never"
        echo "  answered told us nothing about the weld. On a slow/loaded box raise"
        echo "  --deadline; the sample count above says how many chances it got."
        POS_VERDICT=INCONCLUSIVE
    elif [ "$climbed" = "1" ]; then
        echo "  POSITIVE PASS — zero-flag boot welded the checkpoint bundle and H* CLIMBED"
        echo "                  past $EXPECT_CLIMB_PAST."
        POS_VERDICT=PASS
    elif [ "$chain_binding_blocked" = "1" ]; then
        echo "  POSITIVE BLOCKED-CHAIN-BINDING — the target's selected-chain binding"
        echo "  (consensus_state_chain_binding_service.c -3/-4/-11) refused the install:"
        echo "  this datadir does not (yet) satisfy the ALWAYS-target-derived predicates"
        echo "  (durable served H* / consistent selected frontier at/above the checkpoint)."
        echo "  This is the known from-zero-bootstrap gap wf/instant-on-weld /"
        echo "  wf/instant-on-header-bootstrap are closing, NOT a harness or weld"
        echo "  regression. Re-run with --src=<pre-checkpoint synced copy> for an interim"
        echo "  proof against today's predicates, or point ZCL_NODE_BIN at the integrated"
        echo "  build once the relaxation lands."
        grep -am1 'selected-chain binding failed' "$NODE_LOG" | sed 's/^/    log: /'
        POS_VERDICT=BLOCKED_CHAIN_BINDING
    elif [ "$seen_checkpoint" != "1" ]; then
        echo "  POSITIVE FAIL — never observed H*==$CHECKPOINT (the weld did not install)."
        grep -aE 'REFUSED|did not install|admission/validation failed' "$NODE_LOG" 2>/dev/null | \
            tail -5 | sed 's/^/    /'
        POS_VERDICT=FAIL
    elif [ "$POS_MAX" -gt "$CHECKPOINT" ] 2>/dev/null; then
        # It IS climbing — it just has not reached the (raised) target yet.
        # Grading that FAIL would be grading the machine: a 7200rpm box climbs
        # the same heights, slower. Progress across samples is the load-free
        # signal, and it says "moving", so the honest verdict is INCONCLUSIVE.
        echo "  POSITIVE INCONCLUSIVE — H* landed at the checkpoint and IS climbing"
        echo "  ($CHECKPOINT -> $POS_MAX over $_samples samples) but had not passed"
        echo "  $EXPECT_CLIMB_PAST when the ${DEADLINE}s window closed. Progress is the"
        echo "  load-free signal and it is positive; this is a short window, not a"
        echo "  stuck node. Re-run with a larger --deadline."
        POS_VERDICT=INCONCLUSIVE
    else
        echo "  POSITIVE FAIL — landed at the checkpoint and NEVER moved: H* read"
        echo "  $POS_MAX on every one of $_samples samples across ${DEADLINE}s. Zero"
        echo "  progress over N samples is a load-free observation — a slow box still"
        echo "  advances, it just advances slowly — so this is a stuck node, not a"
        echo "  busy one. (Ensure --src carries block bodies above the checkpoint, or"
        echo "  pass --connect=IP:PORT to fetch the tail live.)"
        POS_VERDICT=FAIL
    fi
    echo "  work copy left at $WORK (remove with: rm -rf '$WORK')"
}

# ── Main ────────────────────────────────────────────────────────────────────
echo "========================================================================"
echo "  fresh-boot-weld-prove   checkpoint=$CHECKPOINT  climb-past=$EXPECT_CLIMB_PAST"
echo "  node=$NODE_BIN"
echo "========================================================================"

BUNDLE_RESOLVED=$(discover_bundle || true)
if [ -z "$BUNDLE_RESOLVED" ]; then
    echo "  VERDICT: SKIP — no usable zcl.consensus_state_bundle.v1 found."
    echo "  Produce one (offline, on a datadir folded to EXACTLY $CHECKPOINT):"
    echo "    <bin> -datadir=<producer-dd> -mint-anchor         # fold genesis->checkpoint"
    echo "    <bin> -datadir=<producer-dd> -export-consensus-bundle"
    echo "  -> writes <producer-dd>/consensus-state-bundle-$CHECKPOINT.sqlite"
    exit 0
fi
echo "  bundle: $BUNDLE_RESOLVED ($(wc -c < "$BUNDLE_RESOLVED" 2>/dev/null) bytes)"
mkdir -p "$STAGE_DIR" || fail_env "cannot create stage dir $STAGE_DIR"
BUNDLE_STAGED=$(stage_readonly "$BUNDLE_RESOLVED" "bundle.sqlite")
[ -n "$BUNDLE_STAGED" ] && [ -f "$BUNDLE_STAGED" ] || fail_env "could not stage a read-only bundle copy under $STAGE_DIR"

[ "$POSITIVE_ONLY" = "1" ] || run_negative
[ "$NEGATIVE_ONLY" = "1" ] || run_positive

echo "========================================================================"
echo "  SUMMARY   negative=$NEG_VERDICT   positive=$POS_VERDICT"

if [ "$NEGATIVE_ONLY" = "1" ]; then
    case "$NEG_VERDICT" in
        PASS)          echo "  VERDICT: PASS — fail-closed proven (negative-only)."; exit 0 ;;
        INCONCLUSIVE)  echo "  VERDICT: FAIL — negative leg INCONCLUSIVE (observation window"
                       echo "           closed before the node decided; NOT evidence of a bad"
                       echo "           refusal). Never a pass, but do not read it as a defect."
                       exit 1 ;;
        *)             echo "  VERDICT: FAIL — negative leg did not pass."; exit 1 ;;
    esac
fi
if [ "$POSITIVE_ONLY" = "1" ]; then
    case "$POS_VERDICT" in
        PASS)                  echo "  VERDICT: PASS — zero-flag weld install+climb proven (positive-only)."; exit 0 ;;
        BLOCKED_CHAIN_BINDING)  echo "  VERDICT: BLOCKED — see chain-binding diagnosis above."; exit 3 ;;
        INCONCLUSIVE)          echo "  VERDICT: FAIL — positive leg INCONCLUSIVE (see the diagnosis"
                               echo "           above for whether the window or the node was short)."
                               exit 1 ;;
        *)                      echo "  VERDICT: FAIL — positive leg did not pass."; exit 1 ;;
    esac
fi
if [ "$NEG_VERDICT" = "PASS" ] && [ "$POS_VERDICT" = "PASS" ]; then
    echo "  VERDICT: PASS — H* CLIMB proven from a zero-flag boot AND tamper fails closed."
    exit 0
elif [ "$NEG_VERDICT" = "PASS" ] && [ "$POS_VERDICT" = "BLOCKED_CHAIN_BINDING" ]; then
    echo "  VERDICT: BLOCKED — fail-closed proven, but the zero-flag install+climb needs"
    echo "           either --src=<pre-checkpoint synced copy> or an integrated build"
    echo "           carrying the from-zero chain-binding relaxation. Not a full PASS."
    exit 3
else
    echo "  VERDICT: FAIL — see per-leg output above."
    exit 1
fi
