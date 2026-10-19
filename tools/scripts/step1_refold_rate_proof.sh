#!/usr/bin/env bash
# step1_refold_rate_proof.sh — un-fakeable win-proof for the incremental-H*
# frontier change ("Step 1: kill the per-block O(delta) rescan").
#
# THE claim under test: with the rescan removed, H* (the reducer fold frontier)
# climbs the from-anchor refold span at a FLAT rate — constant blocks/second,
# independent of how far it has already climbed. The unfixed O(delta) path
# instead DECAYS: each applied block costs more as the span grows, so the
# per-sample climb shrinks over wall time. This harness boots the binary on a
# datadir COPY armed for the from-anchor refold, samples H* on a fixed wall-time
# cadence, and rules on the shape of the climb.
#
# Honesty rules (mirrors the cure proof idiom):
#   * H* is read ONLY from `dumpstate reducer_frontier` (the SELECT-only fold),
#     never getblockcount/getblockhash.
#   * The verdict math is a pure awk function fed the sample log; --selftest
#     drives it with synthetic fixtures so the ruling itself is testable and
#     cannot silently drift.
#   * Exit 0 is reserved for RATE=FLAT. DECAYING and NO_CLIMB exit non-zero.
#
# Verdict (computed over the CLIMB region — the samples from the last global-min
# H* onward, which drops the one-time post-install anchor dip):
#   NO_CLIMB   — H* never advanced past its floor (nothing to measure).
#   FLAT       — mean per-interval rate of the LAST third >= RATIO x that of the
#                FIRST third, AND the overall rate >= MIN_RATE blk/s.
#   DECAYING   — anything else with a climb (rate faded, or too slow overall).
#
# Live safety: refuses to touch the live node datadir (~/.zclassic-c23) or the
# oracle datadir (~/.zclassic). Always run against a COPY.
#
# Non-interactive; every artifact lands under --workdir so it runs clean as a
# systemd --user oneshot (linger) unit. bash + awk only.
set -uo pipefail

# ── defaults / contract knobs ────────────────────────────────────────────────
BIN=""
DATADIR=""
WORKDIR=""
RPCBIN=""
CONNECT=""
BUDGET_SECS=12600           # total sampling budget (default 3.5h)
SAMPLE_SECS=45              # wall-time between H* samples
READY_GRACE_SECS=2400       # network-ready must appear within this of launch
PORT_BASE=39240             # rpc=base, p2p=base+1, fs=base+2, https=base+3
MIN_RATE=100                # overall floor for FLAT (blocks/second)
RATIO="0.6"                 # last-third / first-third rate floor for FLAT
TARGET_HSTAR=""             # optional early-stop tip; empty = run to budget
DO_SELFTEST=0
REAL_HOME="${ZCL_REAL_HOME:-$HOME}"

usage() {
    cat <<'EOF'
Usage:
  step1_refold_rate_proof.sh --bin <zclassic23> --datadir <datadir-COPY> \
      [--workdir DIR] [--budget-secs N] [--sample-secs N] [--connect IP:PORT] \
      [--rpcbin PATH] [--target-hstar N] [--port-base N] [--min-rate N] [--ratio F]

  step1_refold_rate_proof.sh --selftest        # hermetic verdict-math check

Refuses any datadir whose final path component is `.zclassic` or `.zclassic-c23`
(the oracle / live node), or that resolves to $HOME/.zclassic[-c23]. Exit 0 only
on RATE=FLAT.
EOF
}

die() { printf 'step1-refold-proof: FATAL %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --bin)         BIN="${2:-}"; shift 2 ;;
        --datadir)     DATADIR="${2:-}"; shift 2 ;;
        --workdir)     WORKDIR="${2:-}"; shift 2 ;;
        --rpcbin)      RPCBIN="${2:-}"; shift 2 ;;
        --connect)     CONNECT="${2:-}"; shift 2 ;;
        --budget-secs) BUDGET_SECS="${2:-}"; shift 2 ;;
        --sample-secs) SAMPLE_SECS="${2:-}"; shift 2 ;;
        --ready-grace-secs) READY_GRACE_SECS="${2:-}"; shift 2 ;;
        --port-base)   PORT_BASE="${2:-}"; shift 2 ;;
        --min-rate)    MIN_RATE="${2:-}"; shift 2 ;;
        --ratio)       RATIO="${2:-}"; shift 2 ;;
        --target-hstar) TARGET_HSTAR="${2:-}"; shift 2 ;;
        --selftest)    DO_SELFTEST=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             die "unknown arg: $1 (see --help)" ;;
    esac
done

# ── the verdict math — the ONLY judge, exercised by --selftest ────────────────
# Reads a proof log ({"ts":..,"hstar":..,"delta":..} per line), prints one
# "VERDICT <token> ..." line, and returns 0=FLAT 2=DECAYING 3=NO_CLIMB.
compute_verdict() {  # $1 = proof-log path
    awk -v MINRATE="$MIN_RATE" -v RATIO="$RATIO" '
    function jget(line, key,   s) {
        if (match(line, "\"" key "\"[[:space:]]*:[[:space:]]*-?[0-9]+")) {
            s = substr(line, RSTART, RLENGTH)
            sub(/.*:[[:space:]]*/, "", s)
            return s + 0
        }
        return "NA"
    }
    /^[[:space:]]*($|#)/ { next }
    {
        ts = jget($0, "ts"); hs = jget($0, "hstar")
        if (ts == "NA" || hs == "NA") next
        n++; T[n] = ts + 0; H[n] = hs + 0
    }
    END {
        if (n < 2) {
            printf "VERDICT NO_CLIMB samples=%d reason=insufficient_samples\n", n+0
            exit 3
        }
        # last occurrence of the global-min H*: the from-anchor refold drops H*
        # to the anchor once post-install, then climbs; start measuring at the
        # bottom so the one-time dip (and any pre-climb stall) is excluded.
        minv = H[1]; m = 1
        for (i = 1; i <= n; i++) if (H[i] <= minv) { minv = H[i]; m = i }
        climb = H[n] - H[m]
        if (climb <= 0) {
            printf "VERDICT NO_CLIMB samples=%d climb=%d reason=hstar_never_advanced\n", n, climb
            exit 3
        }
        k = 0
        for (i = m + 1; i <= n; i++) {
            dt = T[i] - T[i-1]; if (dt <= 0) dt = 1
            k++; R[k] = (H[i] - H[i-1]) / dt
        }
        if (k < 3) {
            printf "VERDICT DECAYING samples=%d intervals=%d reason=insufficient_intervals\n", n, k
            exit 2
        }
        tot_dt = T[n] - T[m]; if (tot_dt <= 0) tot_dt = 1
        overall = climb / tot_dt
        third = int(k / 3); if (third < 1) third = 1
        fs = 0; for (i = 1; i <= third; i++) fs += R[i]; fmean = fs / third
        ls = 0; for (i = k - third + 1; i <= k; i++) ls += R[i]; lmean = ls / third
        ratio_ok = (lmean >= RATIO * fmean)
        rate_ok  = (overall >= MINRATE)
        flat = (ratio_ok && rate_ok)
        printf "VERDICT %s samples=%d intervals=%d climb=%d overall_rate=%.2f first_third_rate=%.2f last_third_rate=%.2f last_over_first=%.3f min_rate=%s ratio_floor=%s min_at=%d\n", \
            (flat ? "FLAT" : "DECAYING"), n, k, climb, overall, fmean, lmean, \
            (fmean > 0 ? lmean / fmean : 1), MINRATE, RATIO, m
        exit (flat ? 0 : 2)
    }
    ' "$1"
}

# ── hermetic selftest ─────────────────────────────────────────────────────────
selftest() {
    local sd rc fails=0 line
    sd="$(mktemp -d "${TMPDIR:-/tmp}/step1-refold-selftest.XXXXXX")" || die "mktemp"
    trap 'rm -rf "$sd"' RETURN

    # Fixture writer: append a sample line with an explicit delta field.
    _s() { printf '{"ts": %s, "hstar": %s, "delta": %s}\n' "$1" "$2" "$3" >>"$4"; }

    local got vtok rc
    _check() { # $1 label  $2 fixture  $3 expect-token  $4 expect-rc
        got="$(compute_verdict "$2")"; rc=$?
        vtok="$(printf '%s' "$got" | awk '{print $2}')"
        if [ "$vtok" = "$3" ] && [ "$rc" = "$4" ]; then
            printf '  selftest OK   %-28s -> %s (rc=%s)\n' "$1" "$vtok" "$rc"
        else
            printf '  selftest FAIL %-28s -> got %s rc=%s, want %s rc=%s\n' \
                "$1" "$vtok" "$rc" "$3" "$4"
            printf '        line: %s\n' "$got"
            fails=$((fails + 1))
        fi
    }

    # (1) FLAT: constant +5000 H* every 45s (~111 blk/s), no decay, >=100.
    local f_flat="$sd/flat.jsonl" ts=1000 h=3056758 i
    for i in $(seq 0 30); do _s "$ts" "$h" 5000 "$f_flat"; ts=$((ts+45)); h=$((h+5000)); done

    # (2) DECAYING: per-sample climb shrinks 9000 -> ~300 over the run.
    local f_dec="$sd/decay.jsonl" d=9000
    ts=1000; h=3056758
    for i in $(seq 0 30); do
        _s "$ts" "$h" "$d" "$f_dec"
        ts=$((ts+45)); h=$((h+d))
        d=$(( d>400 ? d-300 : 300 ))
    done

    # (3) DECAYING via overall floor: flat shape but only ~44 blk/s (<100).
    local f_slow="$sd/slow.jsonl"
    ts=1000; h=3056758
    for i in $(seq 0 30); do _s "$ts" "$h" 2000 "$f_slow"; ts=$((ts+45)); h=$((h+2000)); done

    # (4) NO_CLIMB: H* pinned at the anchor the whole run.
    local f_none="$sd/none.jsonl"
    ts=1000
    for i in $(seq 0 10); do _s "$ts" 3056758 0 "$f_none"; ts=$((ts+45)); done

    # (5) NO_CLIMB: a single sample (cannot measure).
    local f_one="$sd/one.jsonl"
    _s 1000 3056758 0 "$f_one"

    # (6) FLAT after the install dip: high H*, drop to anchor, then fast flat
    #     climb. The dip MUST be excluded (min-anchored window) or it false-fails.
    local f_dip="$sd/dip.jsonl"
    ts=1000
    _s "$ts" 3176000 0 "$f_dip"; ts=$((ts+45))       # pre-install served tip
    _s "$ts" 3056758 -119242 "$f_dip"; ts=$((ts+45)) # post-install drop to anchor
    h=3056758
    for i in $(seq 0 20); do _s "$ts" "$h" 6000 "$f_dip"; ts=$((ts+45)); h=$((h+6000)); done

    # (7) DECAYING: climbs then stalls (rate -> 0 in the last third).
    local f_stall="$sd/stall.jsonl"
    ts=1000; h=3056758
    for i in $(seq 0 20); do _s "$ts" "$h" 6000 "$f_stall"; ts=$((ts+45)); h=$((h+6000)); done
    for i in $(seq 0 15); do _s "$ts" "$h" 0 "$f_stall"; ts=$((ts+45)); done

    echo "step1-refold-proof: --selftest (verdict math)"
    _check "constant-fast-climb"      "$f_flat"  FLAT     0
    _check "decaying-climb"           "$f_dec"   DECAYING 2
    _check "flat-but-below-min-rate"  "$f_slow"  DECAYING 2
    _check "pinned-no-climb"          "$f_none"  NO_CLIMB 3
    _check "single-sample"            "$f_one"   NO_CLIMB 3
    _check "install-dip-then-flat"    "$f_dip"   FLAT     0
    _check "climb-then-stall"         "$f_stall" DECAYING 2

    if [ "$fails" -eq 0 ]; then
        echo "step1-refold-proof: SELFTEST PASSED (7/7)"
        return 0
    fi
    echo "step1-refold-proof: SELFTEST FAILED ($fails case(s))"
    return 1
}

if [ "$DO_SELFTEST" = 1 ]; then
    selftest
    exit $?
fi

# ── live run: preflight ───────────────────────────────────────────────────────
[ -n "$BIN" ]     || die "missing --bin (see --help)"
[ -n "$DATADIR" ] || die "missing --datadir (a COPY; never the live datadir)"
[ -x "$BIN" ]     || die "binary not executable: $BIN"
[ -d "$DATADIR" ] || die "datadir not a directory: $DATADIR"

canon() { realpath -m -- "$1" 2>/dev/null; }
dd_canon="$(canon "$DATADIR")" || \
    die "cannot canonicalize datadir: $DATADIR"
dd_base="$(basename "$dd_canon")"
case "$dd_base" in
    .zclassic|.zclassic-c23)
        die "refusing: datadir final component '$dd_base' is a LIVE/ORACLE datadir name — pass a COPY" ;;
esac
live_canon="$(canon "$REAL_HOME/.zclassic-c23")" || \
    die "cannot canonicalize live datadir path: $REAL_HOME/.zclassic-c23"
oracle_canon="$(canon "$REAL_HOME/.zclassic")" || \
    die "cannot canonicalize oracle datadir path: $REAL_HOME/.zclassic"
[ "$dd_canon" != "$live_canon" ] || \
    die "refusing: datadir resolves to a LIVE/ORACLE path ($dd_canon)"
[ "$dd_canon" != "$oracle_canon" ] || \
    die "refusing: datadir resolves to a LIVE/ORACLE path ($dd_canon)"

[ "$BUDGET_SECS" -gt 0 ] 2>/dev/null || die "--budget-secs must be a positive integer"
[ "$SAMPLE_SECS" -gt 0 ] 2>/dev/null || die "--sample-secs must be a positive integer"

if [ -z "$WORKDIR" ]; then
    WORKDIR="$PWD/step1-refold-proof-$(date -u +%Y%m%d-%H%M%S)"
fi
mkdir -p "$WORKDIR" || die "cannot create workdir: $WORKDIR"
ISO_HOME="$WORKDIR/.iso-home"
mkdir -p "$ISO_HOME"
ln -sfn "$REAL_HOME/.zcash-params" "$ISO_HOME/.zcash-params" 2>/dev/null || true

PROOFLOG="$WORKDIR/proof.log"
NODELOG="$WORKDIR/node.log"
VERDICTF="$WORKDIR/verdict.jsonl"
: >"$PROOFLOG"

# RPC client: default to the same binary (it doubles as a client, exactly as
# network_disruption_recovery_stopwatch.sh drives it). --rpcbin may point at a
# standalone zcl-rpc, which is fed via ZCL_DATADIR/ZCL_RPCPORT env instead of
# flags (the import-copy-prove idiom). read_hstar tries both dumpstate arg forms
# so either client resolves.
[ -n "$RPCBIN" ] || RPCBIN="$BIN"

RPCPORT=$PORT_BASE
P2PPORT=$((PORT_BASE + 1))
FSPORT=$((PORT_BASE + 2))
HTTPSPORT=$((PORT_BASE + 3))

log() { printf '[%s] step1-refold-proof: %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$WORKDIR/run.log"; }

rpc() {
    if [ "$RPCBIN" = "$BIN" ]; then
        HOME="$ISO_HOME" "$RPCBIN" -datadir="$DATADIR" -rpcport="$RPCPORT" "$@" 2>/dev/null || true
    else
        HOME="$ISO_HOME" ZCL_DATADIR="$DATADIR" ZCL_RPCPORT="$RPCPORT" "$RPCBIN" "$@" 2>/dev/null || true
    fi
}

_hstar_from() {  # $1 = dumpstate output
    local h
    h="$(printf '%s' "$1" | grep -oE '"hstar"[[:space:]]*:[[:space:]]*-?[0-9]+' | grep -oE '\-?[0-9]+' | head -1)"
    if [ -z "$h" ] || [ "$h" = "-1" ]; then
        h="$(printf '%s' "$1" | grep -oE '"cached_provable_tip"[[:space:]]*:[[:space:]]*-?[0-9]+' | grep -oE '\-?[0-9]+' | head -1)"
    fi
    printf '%s' "$h"
}

read_hstar() {
    local h
    h="$(_hstar_from "$(rpc dumpstate reducer_frontier)")"       # native-CLI form
    [ -z "$h" ] && h="$(_hstar_from "$(rpc dumpstate '"reducer_frontier"')")"  # zcl-rpc JSON form
    printf '%s' "$h"
}

emit_verdict() { # $1 token  $2 rc  $3 maxH(or empty)  $4 note
    local hs="${3:-}"; [ -z "$hs" ] && hs=null
    printf '{"unit":"step1_refold_rate_proof","verdict":"%s","rc":%s,"h_star_max":%s,"budget_secs":%s,"sample_secs":%s,"min_rate":%s,"ratio":"%s","finished_at":"%s","workdir":"%s","note":"%s"}\n' \
        "$1" "$2" "$hs" "$BUDGET_SECS" "$SAMPLE_SECS" "$MIN_RATE" "$RATIO" \
        "$(date -u +%FT%TZ)" "$WORKDIR" "$4" >>"$VERDICTF"
    log "VERDICT=$1 rc=$2 hstar_max=${3:-none} note=$4"
}

PID=""
cleanup() { [ -n "$PID" ] && kill -TERM "$PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# ── boot the node on the COPY, armed for the from-anchor refold ───────────────
log "boot bin=$BIN datadir=$dd_canon ports=$RPCPORT/$P2PPORT/$FSPORT/$HTTPSPORT refold-from-anchor"
CONNECT_ARG=()
[ -n "$CONNECT" ] && CONNECT_ARG=(-connect="$CONNECT")
HOME="$ISO_HOME" "$BIN" -datadir="$DATADIR" \
    -rpcport="$RPCPORT" -port="$P2PPORT" -fsport="$FSPORT" -httpsport="$HTTPSPORT" \
    -refold-from-anchor -nolegacyimport -nobgvalidation "${CONNECT_ARG[@]}" \
    >>"$NODELOG" 2>&1 &
PID=$!
log "node pid=$PID"

PROC_START=$(date +%s)
BUDGET_START=0
DEADLINE=0
PREV_H=""
MAXH=""
SAMPLES=0

while :; do
    NOW=$(date +%s)

    if ! kill -0 "$PID" 2>/dev/null; then
        sleep 3
        if ! kill -0 "$PID" 2>/dev/null; then
            log "node exited — ruling on collected samples ($SAMPLES)"
            break
        fi
    fi

    if [ "$BUDGET_START" = 0 ] && grep -aq 'P2P listening on' "$NODELOG" 2>/dev/null; then
        BUDGET_START="$NOW"; DEADLINE=$((NOW + BUDGET_SECS))
        log "NETWORK_READY — sampling budget starts (${BUDGET_SECS}s @ ${SAMPLE_SECS}s cadence)"
    fi
    if [ "$BUDGET_START" = 0 ] && [ $((NOW - PROC_START)) -ge "$READY_GRACE_SECS" ]; then
        emit_verdict NO_CLIMB 3 "" "never_network_ready within ${READY_GRACE_SECS}s"
        exit 3
    fi

    if [ "$BUDGET_START" != 0 ]; then
        H="$(read_hstar)"
        if [ -n "$H" ] && [ "$H" -ge 0 ] 2>/dev/null; then
            SAMPLES=$((SAMPLES + 1))
            local_delta=0
            [ -n "$PREV_H" ] && local_delta=$((H - PREV_H))
            printf '{"ts": %s, "hstar": %s, "delta": %s}\n' "$NOW" "$H" "$local_delta" >>"$PROOFLOG"
            PREV_H="$H"
            { [ -z "$MAXH" ] || [ "$H" -gt "$MAXH" ]; } 2>/dev/null && MAXH="$H"
            log "sample #$SAMPLES H*=$H delta=$local_delta maxH=$MAXH"
            if [ -n "$TARGET_HSTAR" ] && [ "$H" -ge "$TARGET_HSTAR" ] 2>/dev/null; then
                log "reached target H*=$H >= $TARGET_HSTAR — ruling"
                break
            fi
        fi
    fi

    if [ "$DEADLINE" != 0 ] && [ "$NOW" -ge "$DEADLINE" ] 2>/dev/null; then
        log "budget deadline reached — ruling"
        break
    fi
    sleep "$SAMPLE_SECS"
done

# ── rule ──────────────────────────────────────────────────────────────────────
VERDICT_LINE="$(compute_verdict "$PROOFLOG")"
VRC=$?
log "$VERDICT_LINE"
VTOK="$(printf '%s' "$VERDICT_LINE" | awk '{print $2}')"
emit_verdict "${VTOK:-DECAYING}" "$VRC" "$MAXH" "$(printf '%s' "$VERDICT_LINE" | sed 's/^VERDICT [A-Z_]* //')"
exit "$VRC"
