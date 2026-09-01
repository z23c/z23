#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# instant-on-copy-prove.sh — the copy-prove that GATES the sovereign "instant-on"
# cutover switch. It proves, on a THROWAWAY datadir (never the live chain), that
# a `zcl.consensus_state_bundle.v1` bundle at the compiled checkpoint height
# (REDUCER_FRONTIER_TRUSTED_ANCHOR = 3,056,758) installs via the terminal
# `-install-consensus-bundle=PATH` verb, brings H* to the checkpoint, folds the
# tail so H* CLIMBS strictly past the checkpoint, AND that a one-byte-tampered
# bundle FAILS CLOSED (REFUSED, nothing committed). Gate is H* CLIMB, never
# "the install printed INSTALLED".
#
# ─────────────────────────────────────────────────────────────────────────────
# SUBSTRATE PRECONDITION — READ THIS BEFORE ASSUMING A LITERAL-BLANK DATADIR
# WORKS. The `-install-consensus-bundle` path is a state-REPLACEMENT cure, not a
# from-zero bootstrap. Its selected-chain binding
# (engine/services/src/consensus_state_chain_binding_service.c
# consensus_state_chain_binding_decide) enforces three predicates the comment
# there marks "ALWAYS target-derived / checkpoint authority never relaxes":
#   -3  the target's own selected frontier must be durable + consistent;
#   -4  the target's durable served H* must ALREADY be >= the bundle height
#       (>= 3,056,758);
#   -11 the target must own a validated selected header at/above the bundle
#       height with nonzero work.
# A truly EMPTY datadir has no tip_finalize_log and served H* = 0, so the GOOD
# bundle is REFUSED at binding ("-3 selected frontier changed or is not durable")
# LONG BEFORE the header-independent CHECKPOINT_ROM authority is ever consulted.
# (Verified empirically 2026-07-21 with build/bin/zclassic23 on a blank datadir.)
#
# Therefore the positive proof needs a SUBSTRATE datadir that is already
# at/past the checkpoint WITH its validated header chain and on-disk block
# bodies above the checkpoint (so the tail fold is offline-reproducible). Supply
# it with --src=DIR; the harness COPIES it into a fresh throwaway work datadir
# and never writes the source. This is "fresh" in the copy-prove sense (a
# brand-new datadir that never touched the live chain), not literally empty.
# Without --src the positive leg reports BLOCKED (the negative fail-closed leg
# still runs and must pass).
# ─────────────────────────────────────────────────────────────────────────────
#
# SAFETY / DENYLIST (enforced below): the node is NEVER launched with -datadir
# set to a live/existing datadir. The work datadir must be one THIS script
# creates fresh and must not equal or sit under any of:
#   ~/.zclassic-c23  ~/.zclassic-c23-prod2  ~/.zclassic-c23-dev  ~/.zclassic
# --src may point at one of those (it is copied read-only, exactly as
# tools/repro_on_copy.sh copies the live datadir) but is never run against.
#
# Isolated ports, isolated HOME, -connect to a dead sink by default (the tail
# fold then climbs only from ON-DISK bodies — supply --connect=IP:PORT to fetch
# from a live peer). The work copy is left on disk for analysis unless --clean.
#
# Usage:
#   # full proof (positive install+climb + negative fail-closed):
#   tools/scripts/instant-on-copy-prove.sh \
#       --src=$HOME/.zclassic-c23-some-synced-copy \
#       --operator-lane=dev \
#       --expect-climb-past=3056758 --deadline=3600
#
#   # fail-closed proof only (fast; no substrate needed):
#   tools/scripts/instant-on-copy-prove.sh --negative-only
#
#   # explicit bundle + auto-discovery otherwise:
#   tools/scripts/instant-on-copy-prove.sh --bundle=/path/consensus-state-bundle-3056758.sqlite --src=...
#
# Exit codes: 0 PASS (or SKIP: no bundle / negative-only pass) · 1 FAIL ·
#             2 INVALID (environment/usage) · 3 BLOCKED (positive needs --src).

set -u

# ── Resolve repo root + binaries ────────────────────────────────────────────
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "$SELF_DIR/../.." && pwd)
if command -v git >/dev/null 2>&1; then
    _gr=$(git -C "$SELF_DIR" rev-parse --show-toplevel 2>/dev/null || true)
    [ -n "$_gr" ] && REPO_ROOT="$_gr"
fi
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"

# ── Defaults ────────────────────────────────────────────────────────────────
CHECKPOINT=3056758                 # REDUCER_FRONTIER_TRUSTED_ANCHOR (mainnet)
EXPECT_CLIMB_PAST=""               # default filled to CHECKPOINT after parse
BUNDLE=""
SRC=""
OPERATOR_LANE=""                   # auto-read from --src wallet identity
WORK_BASE=""                       # default: alongside --src's parent, else $HOME
RPCPORT=39610
P2PPORT=39611
FSPORT=39612
HTTPSPORT=39613
CONNECT="127.0.0.1:39999"          # dead sink → offline; override to fetch tail
DEADLINE=3600
NEGATIVE_ONLY=0
POSITIVE_ONLY=0
CLEAN=0
FLIP_OFFSET=200000000              # lands in the bundle's anchor payload region

DENYLIST="$HOME/.zclassic-c23 $HOME/.zclassic-c23-prod2 $HOME/.zclassic-c23-dev $HOME/.zclassic"

usage() { sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }

for arg in "$@"; do
    case "$arg" in
        --bundle=*)            BUNDLE=${arg#*=} ;;
        --src=*)               SRC=${arg#*=} ;;
        --operator-lane=*)     OPERATOR_LANE=${arg#*=} ;;
        --work-base=*)         WORK_BASE=${arg#*=} ;;
        --checkpoint=*)        CHECKPOINT=${arg#*=} ;;
        --expect-climb-past=*) EXPECT_CLIMB_PAST=${arg#*=} ;;
        --rpcport=*)           RPCPORT=${arg#*=} ;;
        --port=*)              P2PPORT=${arg#*=} ;;
        --fsport=*)            FSPORT=${arg#*=} ;;
        --httpsport=*)         HTTPSPORT=${arg#*=} ;;
        --connect=*)           CONNECT=${arg#*=} ;;
        --deadline=*)          DEADLINE=${arg#*=} ;;
        --flip-offset=*)       FLIP_OFFSET=${arg#*=} ;;
        --negative-only)       NEGATIVE_ONLY=1 ;;
        --positive-only)       POSITIVE_ONLY=1 ;;
        --clean)               CLEAN=1 ;;
        -h|--help)             usage 0 ;;
        *) echo "instant-on-copy-prove: unknown arg: $arg" >&2; usage 2 ;;
    esac
done
[ -n "$EXPECT_CLIMB_PAST" ] || EXPECT_CLIMB_PAST="$CHECKPOINT"

fail_env() { echo "instant-on-copy-prove: $1" >&2; exit 2; }

[ -x "$NODE_BIN" ] || fail_env "node binary not built at $NODE_BIN (run 'make' or set ZCL_NODE_BIN)"
[ -x "$RPC_BIN" ]  || fail_env "rpc binary not built at $RPC_BIN (run 'make zcl-rpc' or set ZCL_RPC_BIN)"

# A work copy retains its persistent wallet identity, including its operator
# lane. Preserve that lane so the identity guard can distinguish a valid
# isolated copy from an accidental lane reassignment. An explicit option wins;
# otherwise read only the non-secret lane field from the source database.
if [ -z "$OPERATOR_LANE" ] && [ -n "$SRC" ] && [ -f "$SRC/node.db" ]; then
    command -v sqlite3 >/dev/null 2>&1 ||
        fail_env "sqlite3 is required to detect the source operator lane; pass --operator-lane explicitly"
    OPERATOR_LANE=$(sqlite3 "$SRC/node.db" \
        'SELECT operator_lane FROM wallet_identity WHERE id=1;' 2>/dev/null || true)
fi
[ -n "$OPERATOR_LANE" ] || OPERATOR_LANE=copy
case "$OPERATOR_LANE" in
    canonical|dev|test|soak|copy) ;;
    *) fail_env "unsupported --operator-lane (expected canonical, dev, test, soak, or copy)" ;;
esac

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

# ── Bundle discovery ────────────────────────────────────────────────────────
is_sqlite_bundle() { # $1 looks like a SQLite file whose name is a bundle
    [ -f "$1" ] || return 1
    head -c 16 -- "$1" 2>/dev/null | grep -q 'SQLite format 3' || return 1
    case "$(basename -- "$1")" in
        consensus-state-bundle-*.sqlite|*bundle*.sqlite) return 0 ;;
        *.sqlite) return 0 ;;
        *) return 1 ;;
    esac
}

discover_bundle() {
    # Explicit wins.
    if [ -n "$BUNDLE" ]; then
        is_sqlite_bundle "$BUNDLE" && { printf '%s\n' "$BUNDLE"; return 0; }
        return 1
    fi
    # A bundle carried inside the substrate's bundles/ dir or datadir root.
    if [ -n "$SRC" ]; then
        for c in "$SRC"/bundles/consensus-state-bundle-*.sqlite \
                 "$SRC"/consensus-state-bundle-*.sqlite; do
            is_sqlite_bundle "$c" && { printf '%s\n' "$c"; return 0; }
        done
    fi
    # Known producer/candidate locations, newest first.
    _found=$(find "$HOME" -maxdepth 3 -type f -name 'consensus-state-bundle-*.sqlite' \
                 -printf '%T@\t%p\n' 2>/dev/null | sort -rn | cut -f2-)
    for c in $_found; do
        is_sqlite_bundle "$c" && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}

# ── Staging: install requires an IMMUTABLE (read-only) bundle file. Stage a
#    0444 copy under the scratch base so the source stays untouched and we can
#    also derive the tampered copy from a byte-identical baseline. ────────────
# STAGE_DIR is created once in main (a deterministic path from the parent PID)
# so it survives command-substitution subshells and the EXIT trap can clean it.
STAGE_DIR="${TMPDIR:-/tmp}/instant-on-stage.$$"
stage_readonly() { # stage_readonly SRCFILE DSTNAME → echoes staged path, or ""
    _dst="$STAGE_DIR/$2"
    cp -f -- "$1" "$_dst" 2>/dev/null || return 1
    chmod 0444 -- "$_dst" 2>/dev/null || return 1
    printf '%s\n' "$_dst"
}

cleanup() {
    [ -n "$STAGE_DIR" ] && [ -d "$STAGE_DIR" ] && chmod -R u+w "$STAGE_DIR" 2>/dev/null && rm -rf "$STAGE_DIR"
}
trap cleanup EXIT INT TERM

# ── Tip (H*) reader — identical parse to tools/repro_on_copy.sh ─────────────
ISO_HOME=""
rpc() { HOME="$ISO_HOME" ZCL_DATADIR="$1" ZCL_RPCPORT="$2" "$RPC_BIN" getblockcount 2>/dev/null || true; }
parse_tip() {
    resp=$1
    case "$resp" in
        *\"result\"*)
            printf '%s\n' "$resp" | sed -n 's/.*"result"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -1 ;;
        *)
            printf '%s\n' "$resp" | sed -n 's/^[[:space:]]*\(-\{0,1\}[0-9][0-9]*\)[[:space:]]*$/\1/p' | head -1 ;;
    esac
}

# ── NEGATIVE case: a one-byte-tampered bundle MUST fail closed ───────────────
# Caught at admission (semantic revalidation) before any state write — so it is
# provable on a fresh blank datadir (no substrate needed). Asserts REFUSED +
# no state committed + (if the cutover was ever reached) a restorable
# consensus.db.preinstall.* image.
NEG_VERDICT="NOT_RUN"
run_negative() {
    echo "── NEGATIVE: one-byte-tampered bundle must fail closed ──────────────"
    NEG_DD="${WORK_BASE:-$HOME}/.zclassic-c23-INSTANTON-neg-$$"
    if is_denylisted "$NEG_DD"; then
        echo "  NEGATIVE INVALID — computed work dir is denylisted: $NEG_DD"; NEG_VERDICT=INVALID; return
    fi
    rm -rf "$NEG_DD"; mkdir -p "$NEG_DD" || { NEG_VERDICT=INVALID; return; }
    ISO_HOME="$NEG_DD/.isohome"; mkdir -p "$ISO_HOME"
    [ -e "$HOME/.zcash-params" ] && ln -sfn "$HOME/.zcash-params" "$ISO_HOME/.zcash-params"

    FLIP=$(stage_readonly "$BUNDLE_STAGED" "bundle_flipped.sqlite")
    [ -n "$FLIP" ] && [ -f "$FLIP" ] || { echo "  could not stage tampered copy"; NEG_VERDICT=INVALID; return; }
    # perl in-place single-byte XOR flip, then re-assert read-only.
    chmod u+w -- "$FLIP"
    perl -e '
        my ($f,$off)=@ARGV; open(my $fh,"+<",$f) or die "open: $!"; binmode $fh;
        seek($fh,$off,0); my $b=""; read($fh,$b,1); die "short read" if length($b)!=1;
        my $x=chr((ord($b)^0xFF)&0xFF); seek($fh,$off,0); print $fh $x; close $fh;
        printf("  flipped byte at offset %d: 0x%02x -> 0x%02x\n",$off,ord($b),ord($x));
    ' "$FLIP" "$FLIP_OFFSET" || { echo "  perl byte-flip failed"; NEG_VERDICT=INVALID; return; }
    chmod 0444 -- "$FLIP"
    if cmp -s -- "$BUNDLE_STAGED" "$FLIP"; then
        echo "  tamper no-op (files identical) — cannot prove fail-closed"; NEG_VERDICT=INVALID; return
    fi

    NEG_LOG="$NEG_DD/neg_install.log"
    echo "  installing TAMPERED bundle onto fresh datadir $NEG_DD"
    neg_rc=0
    HOME="$ISO_HOME" ZCL_MIRROR_SYNC=0 timeout "${DEADLINE}s" \
        "$NODE_BIN" -datadir="$NEG_DD" -rpcport="$RPCPORT" -port="$P2PPORT" \
        -fsport="$FSPORT" -httpsport="$HTTPSPORT" -connect="$CONNECT" \
        -operator-lane="$OPERATOR_LANE" \
        -nolegacyimport -nofilesync -nobgvalidation \
        -install-consensus-bundle="$FLIP" > "$NEG_LOG" 2>&1 || neg_rc=$?

    refused=0; installed=0
    grep -aq '^REFUSED: -install-consensus-bundle:' "$NEG_LOG" && refused=1
    grep -aq '^INSTALLED: -install-consensus-bundle:' "$NEG_LOG" && installed=1
    # No sovereign state may have been committed by a refused install.
    marker=0
    ls "$NEG_DD"/*consensus-bundle-installed* >/dev/null 2>&1 && marker=1
    [ -f "$NEG_DD/consensus_bundle_installed" ] && marker=1
    preinstall=$(ls "$NEG_DD"/consensus.db.preinstall.* 2>/dev/null | head -1 || true)

    echo "  rc=$neg_rc refused=$refused installed=$installed marker=$marker preinstall=${preinstall:-none}"
    grep -aE '^REFUSED:|validation failed|mismatch|not immutable' "$NEG_LOG" | tail -3 | sed 's/^/    /'

    # Fail-closed contract: refused, NOT installed, and no committed sovereign
    # state. A preinstall image is acceptable ONLY paired with a restore (the
    # cutover was reached then rolled back); admission-stage refusal — the
    # normal tamper path — never reaches the cutover, so there must be none.
    if [ "$refused" = "1" ] && [ "$installed" = "0" ] && [ "$neg_rc" != "0" ] && [ "$marker" = "0" ]; then
        if [ -z "$preinstall" ]; then
            echo "  NEGATIVE PASS — tamper REFUSED at admission; no state committed, no marker."
            NEG_VERDICT=PASS
        elif grep -aqi 'restore' "$NEG_LOG"; then
            echo "  NEGATIVE PASS — tamper reached cutover then ROLLED BACK to $preinstall."
            NEG_VERDICT=PASS
        else
            echo "  NEGATIVE FAIL — a consensus.db.preinstall.* image exists with no restore evidence."
            NEG_VERDICT=FAIL
        fi
    else
        echo "  NEGATIVE FAIL — tamper was not cleanly rejected (see $NEG_LOG)."
        NEG_VERDICT=FAIL
    fi
    [ "$CLEAN" = "1" ] && rm -rf "$NEG_DD"
}

# ── POSITIVE case: install the GOOD bundle, assert H*==checkpoint, then CLIMB ─
POS_VERDICT="NOT_RUN"
POS_FIRST=-1; POS_MIN=-1; POS_MAX=-1
run_positive() {
    echo "── POSITIVE: install good bundle, H*==checkpoint, then H* CLIMB ─────"
    if [ -z "$SRC" ]; then
        echo "  POSITIVE BLOCKED — no --src substrate."
        echo "  The -install-consensus-bundle path REQUIRES a datadir already at/past"
        echo "  the checkpoint (durable served H* >= $CHECKPOINT) with a validated header"
        echo "  chain + on-disk bodies above the checkpoint. Re-run with"
        echo "  --src=<a synced copy> (never a live datadir; it is copied read-only)."
        POS_VERDICT=BLOCKED; return
    fi
    [ -d "$SRC" ] || { echo "  POSITIVE INVALID — --src not a directory: $SRC"; POS_VERDICT=INVALID; return; }
    if [ "$(resolve "$SRC")" = "$(resolve "$HOME/.zclassic-c23")" ] &&
       [ "$(systemctl --user show zclassic23 -p ActiveState --value 2>/dev/null || true)" = active ]; then
        echo "  POSITIVE INVALID — canonical source wallet is active; stop it before copying so one wallet identity is never active at two endpoints."
        POS_VERDICT=INVALID; return
    fi

    WORK="${WORK_BASE:-$(dirname -- "$(resolve "$SRC")")}/.zclassic-c23-INSTANTON-$$"
    if is_denylisted "$WORK"; then
        echo "  POSITIVE INVALID — computed work dir is denylisted (would run against a live datadir): $WORK"
        POS_VERDICT=INVALID; return
    fi
    if [ -e "$WORK" ]; then
        echo "  POSITIVE INVALID — work dir already exists (must be fresh): $WORK"; POS_VERDICT=INVALID; return
    fi
    echo "  copying substrate $SRC -> $WORK (read-only source; full copy incl. blocks/)"
    mkdir -p "$WORK" || { POS_VERDICT=INVALID; return; }
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete \
            --exclude 'zclassic23.pid' --exclude '.cookie' --exclude '*.lock' \
            --exclude 'bundles' --exclude 'install_bundle_request' \
            -- "$SRC"/ "$WORK"/ || { echo "  copy failed"; POS_VERDICT=INVALID; return; }
    else
        cp -a -- "$SRC"/. "$WORK"/ || { echo "  copy failed"; POS_VERDICT=INVALID; return; }
        rm -f "$WORK/zclassic23.pid" "$WORK/.cookie" "$WORK/install_bundle_request" 2>/dev/null
        rm -rf "$WORK/bundles" 2>/dev/null
    fi
    ISO_HOME="$WORK/.isohome"; mkdir -p "$ISO_HOME"
    [ -e "$HOME/.zcash-params" ] && ln -sfn "$HOME/.zcash-params" "$ISO_HOME/.zcash-params"

    # Phase 1 — terminal install. Require exit 0 AND the typed INSTALLED banner.
    INSTALL_LOG="$WORK/pos_install.log"
    echo "  phase 1: -install-consensus-bundle=$BUNDLE_STAGED (timeout ${DEADLINE}s)"
    ins_rc=0
    HOME="$ISO_HOME" ZCL_MIRROR_SYNC=0 timeout "${DEADLINE}s" \
        "$NODE_BIN" -datadir="$WORK" -rpcport="$RPCPORT" -port="$P2PPORT" \
        -fsport="$FSPORT" -httpsport="$HTTPSPORT" -connect="$CONNECT" \
        -operator-lane="$OPERATOR_LANE" \
        -nolegacyimport -nofilesync -nobgvalidation \
        -install-consensus-bundle="$BUNDLE_STAGED" > "$INSTALL_LOG" 2>&1 || ins_rc=$?
    if [ "$ins_rc" != "0" ] || ! grep -aq '^INSTALLED: -install-consensus-bundle:' "$INSTALL_LOG"; then
        echo "  POSITIVE FAIL — phase-1 install did not report INSTALLED (rc=$ins_rc)."
        grep -aE '^REFUSED:|chain binding|selected frontier|durable' "$INSTALL_LOG" | tail -3 | sed 's/^/    /'
        POS_VERDICT=FAIL; return
    fi
    echo "  phase-1 INSTALLED; booting normally to fold the tail and prove H* CLIMB"

    # Phase 2 — normal boot; watch H*. Assert we OBSERVE the checkpoint anchor
    # (usable at H*==checkpoint) THEN a strict climb past --expect-climb-past.
    NODE_LOG="$WORK/pos_node.log"
    HOME="$ISO_HOME" ZCL_MIRROR_SYNC=0 \
        "$NODE_BIN" -datadir="$WORK" -rpcport="$RPCPORT" -port="$P2PPORT" \
        -fsport="$FSPORT" -httpsport="$HTTPSPORT" -connect="$CONNECT" \
        -operator-lane="$OPERATOR_LANE" \
        -nolegacyimport -nofilesync -nobgvalidation \
        > "$NODE_LOG" 2>&1 &
    NODE_PID=$!

    deadline=$(( $(date +%s) + DEADLINE ))
    seen_checkpoint=0; climbed=0; seen_rpc=0
    while [ "$(date +%s)" -lt "$deadline" ]; do
        kill -0 "$NODE_PID" 2>/dev/null || { echo "  node exited early (see $NODE_LOG)"; break; }
        t=$(parse_tip "$(rpc "$WORK" "$RPCPORT")"); t=${t:--1}
        if [ "$t" -ge 0 ] 2>/dev/null; then
            seen_rpc=1
            [ "$POS_FIRST" -lt 0 ] && POS_FIRST="$t" && echo "  first H*: $t"
            [ "$POS_MIN" -lt 0 ] || [ "$t" -lt "$POS_MIN" ] && POS_MIN="$t"
            [ "$t" -gt "$POS_MAX" ] && POS_MAX="$t"
            [ "$t" -le "$CHECKPOINT" ] 2>/dev/null && seen_checkpoint=1
            if [ "$t" -gt "$EXPECT_CLIMB_PAST" ] 2>/dev/null && [ "$seen_checkpoint" = "1" ]; then
                climbed=1; echo "  H* CLIMBED to $t (> $EXPECT_CLIMB_PAST, first seen at/below $CHECKPOINT)"; break
            fi
        fi
        sleep 3
    done
    kill "$NODE_PID" 2>/dev/null; wait "$NODE_PID" 2>/dev/null

    echo "  first=$POS_FIRST min=$POS_MIN max=$POS_MAX seen_rpc=$seen_rpc seen_checkpoint=$seen_checkpoint climbed=$climbed"
    if [ "$seen_rpc" = "0" ]; then
        echo "  POSITIVE INCONCLUSIVE — node never answered RPC in ${DEADLINE}s (see $NODE_LOG)."
        POS_VERDICT=INCONCLUSIVE
    elif [ "$seen_checkpoint" != "1" ]; then
        echo "  POSITIVE FAIL — never observed H* at/below the checkpoint $CHECKPOINT (install did not reset to the anchor)."
        POS_VERDICT=FAIL
    elif [ "$climbed" != "1" ]; then
        echo "  POSITIVE FAIL — H* did not climb strictly past $EXPECT_CLIMB_PAST within ${DEADLINE}s."
        echo "                  (offline default: ensure --src carries block bodies above the checkpoint,"
        echo "                   or pass --connect=IP:PORT to fetch the tail from a live peer.)"
        POS_VERDICT=FAIL
    else
        echo "  POSITIVE PASS — installed at checkpoint $CHECKPOINT and H* climbed past $EXPECT_CLIMB_PAST."
        POS_VERDICT=PASS
    fi
    echo "  work copy left at $WORK (remove with: rm -rf '$WORK')"
    [ "$CLEAN" = "1" ] && rm -rf "$WORK"
}

# ── Main ────────────────────────────────────────────────────────────────────
echo "========================================================================"
echo "  instant-on-copy-prove   checkpoint=$CHECKPOINT  climb-past=$EXPECT_CLIMB_PAST"
echo "  node=$NODE_BIN"
echo "  operator_lane=$OPERATOR_LANE"
echo "========================================================================"

BUNDLE_RESOLVED=$(discover_bundle || true)
if [ -z "$BUNDLE_RESOLVED" ]; then
    echo "  VERDICT: SKIP — no usable zcl.consensus_state_bundle.v1 found."
    echo "  Produce one (offline, on a datadir folded to EXACTLY $CHECKPOINT):"
    echo "    <bin> -datadir=<producer-dd> -mint-anchor         # fold genesis→checkpoint, then export"
    echo "    # OR, on a datadir already folded to the checkpoint:"
    echo "    <bin> -datadir=<producer-dd> -export-consensus-bundle"
    echo "  → writes <producer-dd>/consensus-state-bundle-$CHECKPOINT.sqlite"
    exit 0
fi
echo "  bundle: $BUNDLE_RESOLVED ($(wc -c < "$BUNDLE_RESOLVED" 2>/dev/null) bytes)"
# Stage an immutable (0444) baseline so both legs share one byte-identical file.
mkdir -p "$STAGE_DIR" || fail_env "cannot create stage dir $STAGE_DIR"
BUNDLE_STAGED=$(stage_readonly "$BUNDLE_RESOLVED" "bundle.sqlite")
[ -n "$BUNDLE_STAGED" ] && [ -f "$BUNDLE_STAGED" ] || fail_env "could not stage a read-only bundle copy under $STAGE_DIR"

[ "$POSITIVE_ONLY" = "1" ] || run_negative
[ "$NEGATIVE_ONLY" = "1" ] || run_positive

echo "========================================================================"
echo "  SUMMARY   negative=$NEG_VERDICT   positive=$POS_VERDICT"

# Overall verdict / exit code.
if [ "$NEGATIVE_ONLY" = "1" ]; then
    [ "$NEG_VERDICT" = "PASS" ] && { echo "  VERDICT: PASS — fail-closed proven (negative-only)."; echo "======"; exit 0; }
    echo "  VERDICT: FAIL — negative leg did not pass."; echo "======"; exit 1
fi
if [ "$POSITIVE_ONLY" = "1" ]; then
    case "$POS_VERDICT" in
        PASS)    echo "  VERDICT: PASS — install→checkpoint→climb proven (positive-only)."; exit 0 ;;
        BLOCKED) echo "  VERDICT: BLOCKED — supply --src (see above)."; exit 3 ;;
        *)       echo "  VERDICT: FAIL — positive leg did not pass."; exit 1 ;;
    esac
fi
if [ "$NEG_VERDICT" = "PASS" ] && [ "$POS_VERDICT" = "PASS" ]; then
    echo "  VERDICT: PASS — H* CLIMB proven AND tamper fails closed. Switch is gated OPEN."
    exit 0
elif [ "$NEG_VERDICT" = "PASS" ] && [ "$POS_VERDICT" = "BLOCKED" ]; then
    echo "  VERDICT: BLOCKED — fail-closed proven, but the positive install+climb"
    echo "           needs --src (a synced copy at/past the checkpoint). Not a full PASS."
    exit 3
else
    echo "  VERDICT: FAIL — see per-leg output above."
    exit 1
fi
