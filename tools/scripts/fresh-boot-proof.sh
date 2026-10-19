#!/usr/bin/env bash
# fresh-boot-proof.sh — flagless fresh-datadir boot proof (TASK K1).
#
# Product bar: a user runs plain `zclassic23` on a BRAND-NEW empty datadir with
# ONLY harness-isolation flags (datadir + ports), no sync assistance (no
# -addnode, no snapshot/import flags), and the node must reach a climbing,
# self-driving sync where every stall is a NAMED blocker with an automatic
# remedy — never a quiet stop and never a required flag.
#
# This harness:
#   1. Wipes + recreates an isolated empty datadir.
#   2. Launches the locally-built binary via nohup with ONLY isolation flags,
#      writing a verdict log into the datadir.
#   3. Samples `dumpstate reducer_frontier` (header_admit + H* cursors) and the
#      blocker list every SAMPLE_SECS for WINDOW_SECS.
#   4. Emits a verdict:
#        CLIMBING        — header_admit or H* strictly rose across the window.
#        STALLED-NAMED   — no rise, but >=1 active blocker present (printed).
#        STALLED-SILENT  — no rise AND no active blocker (the FAILURE class).
#   5. Kills its node and prints the verdict + evidence table at exit.
#
# The datadir/ports below are OWNED by this harness exclusively. It NEVER
# touches any live datadir/service.
#
# Manual operator tool — intentionally no in-repo caller (no doc/Makefile
# wiring): run by hand when re-proving the flagless cold-boot bar. Owning
# runbook: docs/quality/MVP.md criterion 3 ("Cold-start sync to tip") is the product
# claim this harness verifies live against a real fresh datadir; see also
# docs/agent/HANDOFF.md for the current live sync state before running it.
set -u

# ── configuration (env-overridable) ────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${BIN:-$REPO_ROOT/build/bin/zclassic23}"
DATADIR="${DATADIR:-$HOME/.zclassic-c23-freshproof}"
PORT="${PORT:-39672}"
RPCPORT="${RPCPORT:-39673}"
FSPORT="${FSPORT:-39674}"
HTTPSPORT="${HTTPSPORT:-39675}"
WINDOW_SECS="${WINDOW_SECS:-1200}"   # default 20 min
SAMPLE_SECS="${SAMPLE_SECS:-60}"

VERDICT_LOG="$DATADIR/fresh-boot-verdict.log"
NODE_LOG="$DATADIR/fresh-boot-node.out"

# Isolated HOME so the node sees a genuine FRESH MACHINE: no co-located
# ~/.zclassic legacy zclassicd datadir to auto-import headers/UTXOs from (the
# node's default header source is $HOME/.zclassic — see boot_cold_start.c /
# utxo_recovery_restore.c). This is the faithful "no legacy dir available to
# it" condition AND it guarantees the real protected ~/.zclassic is never even
# read. HOME is process environment, not a node sync flag. We provision ONLY
# the proving-params dir (~/.zcash-params, keys — NOT chain state) into the
# isolated home so proof validation is not a false blocker.
ISO_HOME="${ISO_HOME:-$DATADIR-home}"
REAL_PARAMS="${REAL_PARAMS:-$HOME/.zcash-params}"

# ── guard: refuse to run against any live/known datadir ─────────────────────
case "$DATADIR" in
  "$HOME/.zclassic-c23"|"$HOME/.zclassic-c23-serve1"|"$HOME/.zclassic-c23-dev"|\
  "$HOME/.zclassic-c23-soak"|"$HOME/.zclassic"|"$HOME/.zclassic-c23-serve1-BACKUP-preflip")
    echo "REFUSE: $DATADIR is a protected live datadir" >&2
    exit 3 ;;
esac

if [ ! -x "$BIN" ]; then
  echo "REFUSE: binary not found/executable: $BIN" >&2
  exit 3
fi

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$VERDICT_LOG"; }

NODE_PID=""
cleanup() {
  if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then
    log "cleanup: stopping node pid=$NODE_PID"
    kill "$NODE_PID" 2>/dev/null
    for _ in $(seq 1 20); do
      kill -0 "$NODE_PID" 2>/dev/null || break
      sleep 0.5
    done
    kill -9 "$NODE_PID" 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

rpc() {
  # $1.. = subcommand args; prints raw output
  "$BIN" -rpcport="$RPCPORT" -datadir="$DATADIR" "$@" 2>/dev/null
}

# Dumpstate with retry: during heavy header import the progress_store is
# briefly busy and dumpstate can return empty/partial. Retry a few times so a
# transient read miss is not mistaken for a stall. Prints the frontier JSON.
rpc_frontier() {
  local out=""
  for _ in 1 2 3 4; do
    out="$(rpc dumpstate reducer_frontier)"
    if printf '%s' "$out" | grep -q '"hstar"'; then
      printf '%s' "$out"; return 0
    fi
    sleep 1
  done
  printf '%s' "$out"
}

# Extract an integer field from a flat-ish JSON blob by key name.
jget() {
  # $1 = json, $2 = key -> prints integer value or empty
  printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*-?[0-9]+" | head -1 |
    grep -oE -- '-?[0-9]+$'
}

# Extract the header_admit stage cursor from the frontier JSON.
jget_header_admit() {
  printf '%s' "$1" | tr -d '\n' |
    grep -oE '"stage"[[:space:]]*:[[:space:]]*"header_admit"[^}]*"cursor"[[:space:]]*:[[:space:]]*-?[0-9]+' |
    head -1 | grep -oE -- '-?[0-9]+$'
}

# Node-log-derived progress. The reducer drive holds the progress_store lock
# during from-genesis header import, so dumpstate reducer_frontier frequently
# returns progress_store_busy (a read miss, not a stall). The P2P header path
# logs "... (header tip=N, chain tip=M ...)" on every batch — a reliable,
# lock-free corroborating progress signal. Print the MAX seen so far.
log_max() {
  # $1 = regex capturing "<label>=<int>" -> prints max int (or empty)
  grep -oE "$1=[0-9]+" "$NODE_LOG" 2>/dev/null | grep -oE '[0-9]+$' |
    sort -n | tail -1
}

# ── 1. wipe + recreate the datadir + isolated home ──────────────────────────
rm -rf "$DATADIR"
mkdir -p "$DATADIR"

# Build the isolated fresh-machine home: empty except for a proving-params
# symlink. Crucially it has NO .zclassic (legacy datadir) so the node cannot
# auto-import chain state from anywhere.
rm -rf "$ISO_HOME"
mkdir -p "$ISO_HOME"
if [ -d "$REAL_PARAMS" ]; then
  ln -s "$REAL_PARAMS" "$ISO_HOME/.zcash-params"
fi
export HOME="$ISO_HOME"

: > "$VERDICT_LOG"
log "=== fresh-boot-proof START ==="
log "binary:   $BIN ($("$BIN" --version 2>/dev/null | head -1))"
log "datadir:  $DATADIR (freshly wiped, empty)"
log "iso-home: $ISO_HOME (fresh machine: NO .zclassic legacy dir; params-only)"
log "ports:    p2p=$PORT rpc=$RPCPORT fs=$FSPORT https=$HTTPSPORT"
log "window:   ${WINDOW_SECS}s, sampling every ${SAMPLE_SECS}s"
log "flags:    ONLY -datadir -port -rpcport -fsport -httpsport (no sync assist)"

# ── 2. launch the node (ONLY isolation flags) ───────────────────────────────
nohup "$BIN" \
  -datadir="$DATADIR" \
  -port="$PORT" \
  -rpcport="$RPCPORT" \
  -fsport="$FSPORT" \
  -httpsport="$HTTPSPORT" \
  > "$NODE_LOG" 2>&1 &
NODE_PID=$!
log "launched node pid=$NODE_PID (nohup, log=$NODE_LOG)"

# Wait for RPC to answer (up to 90s) before the sampling window.
rpc_up=0
for _ in $(seq 1 90); do
  if ! kill -0 "$NODE_PID" 2>/dev/null; then
    log "FATAL: node exited during startup (see $NODE_LOG)"
    log "=== last 30 lines of node output ==="
    tail -30 "$NODE_LOG" | tee -a "$VERDICT_LOG"
    log "VERDICT: STALLED-SILENT (node did not stay up)"
    exit 2
  fi
  if rpc dumpstate reducer_frontier >/dev/null 2>&1; then
    rpc_up=1
    break
  fi
  sleep 1
done
if [ "$rpc_up" = 1 ]; then
  log "RPC is answering"
else
  log "WARN: RPC not answering after 90s; sampling anyway (node still up)"
fi

# ── 3. sampling window ──────────────────────────────────────────────────────
printf '%-8s %-12s %-8s %-9s %-10s %-9s %s\n' \
  "t(s)" "header_admit" "hstar" "net_tip" "log_htip" "log_ctip" "blockers" \
  | tee -a "$VERDICT_LOG"
printf '%-8s %-12s %-8s %-9s %-10s %-9s %s\n' \
  "----" "------------" "-----" "-------" "--------" "--------" "--------" \
  | tee -a "$VERDICT_LOG"

# Track first VALID (non-read-miss) reading and the monotonic MAX seen. The
# on-disk stage cursors never regress, so a max > first-valid across the window
# is strictly-rising forward progress; a mid-window -1 is a read miss, not a
# regression. log_htip/log_ctip are the lock-free node-log corroboration.
first_ha=""; first_hstar=""; first_htip=""
max_ha="-1"; max_hstar="-1"; max_htip="-1"; max_ctip="-1"
# First-half vs second-half maxima: SUSTAINED climbing requires the second
# half to reach strictly higher than the first half's ceiling. This tells a
# genuinely climbing node apart from one that climbed early then plateaued
# (climb-then-wedge reads as STALLED-NAMED, not CLIMBING).
fh_ha="-1"; fh_hstar="-1"; fh_htip="-1"
sh_ha="-1"; sh_hstar="-1"; sh_htip="-1"
half="$((WINDOW_SECS / 2))"
last_blocker_ids=""
last_blocker_count="0"
samples=0

t=0
while [ "$t" -le "$WINDOW_SECS" ]; do
  if ! kill -0 "$NODE_PID" 2>/dev/null; then
    log "FATAL: node exited mid-window at t=${t}s (see $NODE_LOG)"
    tail -30 "$NODE_LOG" | tee -a "$VERDICT_LOG"
    break
  fi

  fj="$(rpc_frontier)"
  bj="$(rpc dumpstate blocker)"

  ha="$(jget_header_admit "$fj")";      [ -z "$ha" ] && ha="-1"
  hs="$(jget "$fj" hstar)";             [ -z "$hs" ] && hs="-1"
  nt="$(jget "$fj" network_tip)";       [ -z "$nt" ] && nt="-1"
  # lock-free node-log progress (max seen so far)
  htip="$(log_max 'header tip')";       [ -z "$htip" ] && htip="-1"
  ctip="$(log_max 'chain tip')";        [ -z "$ctip" ] && ctip="-1"
  bc="$(jget "$bj" active_count)";      [ -z "$bc" ] && bc="0"
  bids="$(printf '%s' "$bj" | tr -d '\n' |
          grep -oE '"id"[[:space:]]*:[[:space:]]*"[^"]*"' |
          sed -E 's/.*"id"[[:space:]]*:[[:space:]]*"([^"]*)"/\1/' | paste -sd, -)"
  [ -z "$bids" ] && bids="-"

  printf '%-8s %-12s %-8s %-9s %-10s %-9s %s\n' \
    "$t" "$ha" "$hs" "$nt" "$htip" "$ctip" "b=$bc:$bids" | tee -a "$VERDICT_LOG"

  # first valid readings (skip read-misses)
  if [ "$ha" != "-1" ] && [ -z "$first_ha" ]; then first_ha="$ha"; fi
  if [ "$hs" != "-1" ] && [ -z "$first_hstar" ]; then first_hstar="$hs"; fi
  if [ "$htip" != "-1" ] && [ -z "$first_htip" ]; then first_htip="$htip"; fi
  # monotonic maxima
  if [ "$ha" -gt "$max_ha" ] 2>/dev/null; then max_ha="$ha"; fi
  if [ "$hs" -gt "$max_hstar" ] 2>/dev/null; then max_hstar="$hs"; fi
  if [ "$htip" -gt "$max_htip" ] 2>/dev/null; then max_htip="$htip"; fi
  if [ "$ctip" -gt "$max_ctip" ] 2>/dev/null; then max_ctip="$ctip"; fi
  # first-half / second-half maxima (sustained-progress split)
  if [ "$t" -le "$half" ]; then
    if [ "$ha" -gt "$fh_ha" ] 2>/dev/null; then fh_ha="$ha"; fi
    if [ "$hs" -gt "$fh_hstar" ] 2>/dev/null; then fh_hstar="$hs"; fi
    if [ "$htip" -gt "$fh_htip" ] 2>/dev/null; then fh_htip="$htip"; fi
  else
    if [ "$ha" -gt "$sh_ha" ] 2>/dev/null; then sh_ha="$ha"; fi
    if [ "$hs" -gt "$sh_hstar" ] 2>/dev/null; then sh_hstar="$hs"; fi
    if [ "$htip" -gt "$sh_htip" ] 2>/dev/null; then sh_htip="$htip"; fi
  fi

  last_blocker_ids="$bids"; last_blocker_count="$bc"
  samples=$((samples + 1))

  [ "$t" -ge "$WINDOW_SECS" ] && break
  sleep "$SAMPLE_SECS"
  t=$((t + SAMPLE_SECS))
done

# ── 4. verdict ──────────────────────────────────────────────────────────────
[ -z "$first_ha" ] && first_ha="-1"
[ -z "$first_hstar" ] && first_hstar="-1"
[ -z "$first_htip" ] && first_htip="-1"
log "=== sampling complete: $samples samples ==="
log "header_admit (dumpstate): first_valid=$first_ha max=$max_ha  1st-half=$fh_ha 2nd-half=$sh_ha"
log "hstar        (dumpstate): first_valid=$first_hstar max=$max_hstar  1st-half=$fh_hstar 2nd-half=$sh_hstar"
log "header tip   (node log):  first_valid=$first_htip max=$max_htip  1st-half=$fh_htip 2nd-half=$sh_htip"
log "chain tip    (node log):  max=$max_ctip"

# CLIMBING requires SUSTAINED forward progress: the second half of the window
# must reach strictly higher than the first half's ceiling, on the header
# frontier OR H*. The dumpstate header_admit/hstar cursors are primary; the
# lock-free node-log header tip is corroborating (it survives progress_store_busy
# read misses). A node that climbs early then plateaus/wedges fails this test
# (2nd-half == 1st-half) and falls to STALLED-NAMED — the honest verdict.
climbed=0
if [ "$sh_ha" -gt "$fh_ha" ] 2>/dev/null && [ "$fh_ha" != "-1" ]; then
  climbed=1
fi
if [ "$sh_hstar" -gt "$fh_hstar" ] 2>/dev/null && [ "$fh_hstar" != "-1" ]; then
  climbed=1
fi
if [ "$sh_htip" -gt "$fh_htip" ] 2>/dev/null && [ "$fh_htip" != "-1" ]; then
  climbed=1
fi

VERDICT=""
if [ "$climbed" = 1 ]; then
  VERDICT="CLIMBING"
elif [ "${last_blocker_count:-0}" -gt 0 ] 2>/dev/null; then
  VERDICT="STALLED-NAMED"
else
  VERDICT="STALLED-SILENT"
fi

log ""
log "############################################################"
log "# VERDICT: $VERDICT"
if [ "$VERDICT" = "STALLED-NAMED" ]; then
  log "# named blocker(s): $last_blocker_ids"
  log "# --- blocker detail ---"
  rpc dumpstate blocker 2>/dev/null | tee -a "$VERDICT_LOG"
elif [ "$VERDICT" = "STALLED-SILENT" ]; then
  log "# NO forward progress AND NO named blocker — this is the FAILURE class."
fi
log "############################################################"

cleanup
NODE_PID=""

case "$VERDICT" in
  CLIMBING)       exit 0 ;;
  STALLED-NAMED)  exit 0 ;;   # named-with-remedy is an acceptable terminal state
  *)              exit 1 ;;   # STALLED-SILENT is failure
esac
