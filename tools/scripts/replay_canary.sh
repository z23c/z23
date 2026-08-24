#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# replay_canary.sh — the standing full-history replay canary.
#
# Replays the REAL chain through one frozen, content-bound binary's reducer in an
# isolated scratch datadir on isolated ports, then asserts:
#   (a) zero consensus rejects (bg_validation reaches COMPLETE, never
#       FAILED, and getsyncdiag headers.total_rejected == 0),
#   (b) the node's recomputed SHA3 UTXO commitment passed through the
#       compiled checkpoint at anchor 3,056,758 without an integrity
#       FATAL (the boot gate refuses otherwise),
#   (c) coarse UTXO stats (bestblock/txouts/total_amount) at the node's
#       tip == co-located zclassicd `gettxoutsetinfo` (read-only, 8232),
#   (d) BYTE-EXACT: the node's served SHA3-256 UTXO commitment ==
#       `--legacy-utxo-commitment`'s SHA3 over zclassicd's OWN chainstate
#       serialization (skipped only on mid-run height skew, never silently;
#       coarse agreement is NOT set equality — two nodes can share height,
#       count, and supply while holding different UTXO sets).
#
# The AUTHORITATIVE verdict is a sentinel FILE written atomically
# (tmp + fsync + rename) ONLY after every assertion passes. The shell
# exit code is advisory (it drives systemd OnFailure=); proof requires a
# *positive* fresh PASS record, never the absence of a non-zero exit.
# This is the "never exit-0-as-proof" guarantee, made REAL two ways:
#   1. reset_verdict() removes ANY prior sentinel as the FIRST thing every
#      run does (live AND self-test), so a crashed/killed/OOM/timed-out run
#      leaves NO sentinel at all — not a stale PASS — and an absence-of-
#      fresh-PASS reader resolves FAIL by construction.
#   2. The sentinel carries "started_ts" and the run drops a
#      $VERDICT_DIR/.run_started_<from> stamp, so an external freshness
#      check (the `make replay-canary-*` guard's marker + `-nt` test; a
#      live-node Condition) can REJECT a stale PASS that somehow survives.
# Together: a stale PASS can never be read as the current run's proof.
#
# Variants (one --from flag, same harness):
#   --from=anchor  : the PROVEN cold recipe — --importblockindex (headers,
#                    read-only) then a NORMAL boot with legacy auto-import ON
#                    (auto-links read-only ~/.zclassic, seeds the anchor
#                    3,056,758 UTXO set), a shielded-history interlude
#                    (wait staged-seed floor → stop node →
#                    -import-complete-shielded from the read-only zd →
#                    respawn, so post-seed SPEND blocks pass the
#                    fail-closed preflight), then bg-validation walks the
#                    connected extent toward tip (~45 min + import). Dials
#                    the co-located zclassicd P2P (8034) via -connect for
#                    post-seed tip blocks (2026-08-01 fix — the dead-sink
#                    variant could never satisfy crossnode tip equality).
#                    (The -snapshot=+-nolegacyimport combo FATALs at HEAD —
#                    see iso_spawn_mainnet_node.)
#   --from=genesis : -nolegacyimport (no anchor seed); replay genesis->tip
#                    with bg-validation ON (~6 h). Dials the co-located
#                    zclassicd P2P (8034) via -connect (NOT -addnode — see
#                    2026-07-20 fix note at the iso_spawn_mainnet_node call
#                    below) for bodies — the one real peer, read-only, and
#                    the ONLY outbound peer this run can ever reach.
#
# Usage:
#   replay_canary.sh --from=anchor|genesis [--src-datadir=DIR]
#                    [--budget-sec=N] [--zclassicd-rpc=PORT]
#                    [--zclassicd-p2p=PORT]
#
# Hidden self-test mode (drives the hermetic verdict-logic gate; injects
# synthetic RPC outputs from a fixture dir, never spawns a node):
#   replay_canary.sh --self-test=pass|fail-rejects|fail-sha3|\
#                    fail-crossnode|fail-timeout
#       reads $ZCL_CANARY_SELFTEST_DIR/{getsyncdetail,getsyncdiag,
#       getutxocommitment,gettxoutsetinfo,zd_gettxoutsetinfo}.json

set -euo pipefail

# ── Defaults / arg parse ───────────────────────────────────────────
FROM="anchor"
SRC_DATADIR="${HOME:-/root}/.zclassic"
BUDGET_SEC=""
ZD_RPC="8232"
ZD_P2P="8034"
SELFTEST=""

for arg in "$@"; do
    case "$arg" in
        --from=*)          FROM="${arg#--from=}" ;;
        --src-datadir=*)   SRC_DATADIR="${arg#--src-datadir=}" ;;
        --budget-sec=*)    BUDGET_SEC="${arg#--budget-sec=}" ;;
        --zclassicd-rpc=*) ZD_RPC="${arg#--zclassicd-rpc=}" ;;
        --zclassicd-p2p=*) ZD_P2P="${arg#--zclassicd-p2p=}" ;;
        --self-test=*)     SELFTEST="${arg#--self-test=}" ;;
        *) echo "replay-canary: unknown arg '$arg'" >&2; exit 2 ;;
    esac
done

# The expected checkpoint SHA3 + anchor (lib/chain/src/checkpoints.c:86-104,
# mirrored by REDUCER_FRONTIER_TRUSTED_ANCHOR). The canary asserts the node
# passed through this without an integrity FATAL; for the local commitment
# path the value is the recompute target.
ANCHOR_HEIGHT=3056758
EXPECTED_SHA3="5817f0ec66738db6989cf881cf37b2148d07b978fd69e5a334855b4991ac5f85"

# ── Elapsed-time band (the named-defect guard) ─────────────────────
# A from-anchor run that silently DEGRADES to a from-genesis-scale replay
# is the named I5 defect. The band makes that degrade a typed FAIL, not an
# accidental green: a from-anchor full-history replay through the reducer
# legitimately takes ~45 min, so a COMPLETE that arrives implausibly FAST
# (the seed never applied / the node only replayed a stub) blows the FLOOR,
# and a COMPLETE that takes ~genesis-scale time (~6 h, the silent degrade)
# blows the CEILING. The anchor band is centred on ~45 min, NOT ~6 h; the
# genesis band is the ~6 h replay. Bounds in seconds:
#   anchor : floor 300 (5 min — a real anchor replay can never be near-
#            instant), ceiling 7200 (120 min == the hard budget; a 6 h
#            from-anchor degrade blows this long before genesis scale).
#            The ceiling grew 5400 -> 7200 on 2026-08-02 when the
#            shielded-history import interlude (stop → import → respawn)
#            joined the anchor track: the ~45-min replay plus the import
#            and a second boot still sit far under 2 h.
#   genesis: floor 3600 (1 h), ceiling 28800 (8 h == the hard budget).
ANCHOR_ELAPSED_MIN=300
ANCHOR_ELAPSED_MAX=7200
GENESIS_ELAPSED_MIN=3600
GENESIS_ELAPSED_MAX=28800

# The verdict probes call heavyweight read-only audit RPCs whose cost scales
# with the UTXO set, not with the walk: getutxocommitment recomputes the
# SHA3-256 fold over ~1.35M UTXOs on EVERY call (~10.5 s on the 2026-08-01
# anchor run, while the node was simultaneously folding post-seed tip blocks
# from the 8034 oracle and running the bg-validation walk). The RPC server's
# per-request watchdog (ZCL_RPC_TIMEOUT_MS, default 10000 ms — see
# lib/rpc/include/rpc/rpc_timeout.h) shutdown()s the socket at the deadline:
# the client then reads an EMPTY reply while the worker keeps computing and
# logs its span OK ~0.5 s later — surfacing here as the false
# rpc_unreachable_getutxocommitment FAIL (observed 2026-08-01, elapsed=383 s,
# UC span duration_us=10538872 status=OK). Raise the deadline for canary
# nodes only; the production default is untouched. 120 s covers the UC
# recompute plus gettxoutsetinfo on a loaded box with 10x headroom.
export ZCL_RPC_TIMEOUT_MS="${ZCL_RPC_TIMEOUT_MS:-120000}"

# REPO_ROOT: the harness knows where it lives (like soak_assert.sh).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VERDICT_DIR="${ZCL_CANARY_VERDICT_DIR:-${HOME:-/root}/.local/state/zclassic23-canary}"
mkdir -p "$VERDICT_DIR"

# Verdict identity is captured ONCE from the exact immutable executable used
# by this run. It is never re-read from build/bin at verdict time: that path
# may be atomically replaced during a 90-minute/8-hour replay.
CANARY_SOURCE_ID_SHA256=""
CANARY_ARTIFACT_SHA256=""
CANARY_BUILD_COMMIT="unknown"       # optional GitHub trace, display only

capture_binary_identity() {
    local binary="$1" before after identity_json source_id trace
    [ -x "$binary" ] || return 1
    before="$(sha256sum -- "$binary" 2>/dev/null | awk '{print $1}')"
    [[ "$before" =~ ^[0-9a-f]{64}$ ]] || return 1
    identity_json="$("$binary" agentbuild 2>/dev/null)" || return 1
    after="$(sha256sum -- "$binary" 2>/dev/null | awk '{print $1}')"
    [ "$before" = "$after" ] || return 1
    source_id="$(printf '%s\n' "$identity_json" |
        sed -n 's/.*"source_id_sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{64\}\)".*/\1/p' |
        head -1)"
    [[ "$source_id" =~ ^[0-9a-f]{64}$ ]] || return 1
    trace="$(printf '%s\n' "$identity_json" |
        sed -n 's/.*"build_commit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
        head -1)"
    CANARY_SOURCE_ID_SHA256="$source_id"
    CANARY_ARTIFACT_SHA256="$before"
    CANARY_BUILD_COMMIT="${trace:-unknown}"
}

freeze_live_binaries() {
    local source="$REPO_ROOT/build/bin/zclassic23"
    local frozen="$ISO_DD/zclassic23-replay-canary"
    local tmp="$frozen.tmp.$$"
    local rpc_source="$REPO_ROOT/build/bin/zcl-rpc"
    local rpc_frozen="$ISO_DD/zcl-rpc-replay-canary"
    local rpc_tmp="$rpc_frozen.tmp.$$"
    local rpc_before rpc_after rpc_frozen_hash
    rm -f -- "$tmp" "$frozen"
    cp -- "$source" "$tmp" || return 1
    chmod 0500 "$tmp" || { rm -f -- "$tmp"; return 1; }
    mv -- "$tmp" "$frozen" || { rm -f -- "$tmp"; return 1; }
    capture_binary_identity "$frozen" || return 1

    rpc_before="$(sha256sum -- "$rpc_source" 2>/dev/null | awk '{print $1}')"
    [[ "$rpc_before" =~ ^[0-9a-f]{64}$ ]] || return 1
    rm -f -- "$rpc_tmp" "$rpc_frozen"
    cp -- "$rpc_source" "$rpc_tmp" || return 1
    chmod 0500 "$rpc_tmp" || { rm -f -- "$rpc_tmp"; return 1; }
    mv -- "$rpc_tmp" "$rpc_frozen" || { rm -f -- "$rpc_tmp"; return 1; }
    rpc_after="$(sha256sum -- "$rpc_source" 2>/dev/null | awk '{print $1}')"
    rpc_frozen_hash="$(sha256sum -- "$rpc_frozen" 2>/dev/null | awk '{print $1}')"
    [ "$rpc_before" = "$rpc_after" ] &&
        [ "$rpc_before" = "$rpc_frozen_hash" ] || return 1
    ISO_NODE_BIN="$frozen"
    ISO_RPC_BIN="$rpc_frozen"
}

# START_TS is fixed at the very top of the process so reset_verdict,
# write_verdict, and the elapsed band all share one run-start epoch.
START_TS="$(date +%s)"; STARTED_TS="$START_TS"; ELAPSED=0

# ── Sentinel path (one place, used by reset + write) ───────────────
sentinel_path() { printf '%s/replay_canary_%s.json' "$VERDICT_DIR" "$FROM"; }

# ── Sentinel reset (FIRST thing every run does) ────────────────────
# Remove ANY prior sentinel before the run does any work. This is the
# load-bearing half of "never exit-0-as-proof": after this point a
# killed/OOM/timed-out harness leaves NO sentinel at all (not a stale
# PASS), so an absence-of-fresh-PASS reader resolves FAIL by construction.
# A fresh PASS can therefore only appear if THIS run reaches write_verdict
# PASS after every assertion. We also stamp $VERDICT_DIR/.run_started_<from>
# with the run-start epoch so an external reader (the Makefile guard, a
# live-node Condition) can band-check the sentinel's freshness against the
# run it is judging — a stale sentinel that somehow survives is still read
# as not-fresh => FAIL.
reset_verdict() {
    local f; f="$(sentinel_path)"
    rm -f "$f" "$f".tmp.* 2>/dev/null || true
    printf '%s\n' "$STARTED_TS" > "$VERDICT_DIR/.run_started_${FROM}" 2>/dev/null || true
    sync 2>/dev/null || true
}

# ── Sentinel writer (atomic: tmp + fsync + rename) ─────────────────
# The PASS sentinel exists ONLY after every assertion passed AND after
# reset_verdict removed any prior one. write_verdict is the single place a
# sentinel is produced; it is called exactly once per run, at the very end,
# with the already-decided verdict. The "started_ts" field lets a reader
# band-check freshness without a second stamp file.
write_verdict() {
    local verdict="$1" reason="$2"
    local f; f="$(sentinel_path)"
    local tmp="$f.tmp.$$"
    local now; now="$(date +%s)"
    {
        printf '{"verdict":"%s","from":"%s","ts":%s,"started_ts":%s,' \
            "$verdict" "$FROM" "$now" "${STARTED_TS:-$now}"
        printf '"source_id_sha256":"%s","artifact_sha256":"%s",' \
            "${CANARY_SOURCE_ID_SHA256:-unknown}" \
            "${CANARY_ARTIFACT_SHA256:-unknown}"
        printf '"build_commit":"%s",' "${CANARY_BUILD_COMMIT:-unknown}"
        printf '"tip":%s,"verified_height":%s,"bg_state":"%s",' \
            "${R_TIP:-0}" "${R_VERIFIED:-0}" "${R_BGSTATE:-unknown}"
        printf '"consensus_rejects":%s,"local_sha3":"%s","expected_sha3":"%s",' \
            "${R_REJECTS:-0}" "${R_LOCAL_SHA3:-}" "$EXPECTED_SHA3"
        printf '"legacy_sha3":"%s","exact_tier":"%s",' \
            "${R_LEGACY_SHA3:-}" "${R_EXACT_TIER:-not_run}"
        printf '"txouts":%s,"zd_txouts":%s,"supply":"%s","zd_supply":"%s",' \
            "${R_TXOUTS:-0}" "${R_ZD_TXOUTS:-0}" "${R_SUPPLY:-}" "${R_ZD_SUPPLY:-}"
        printf '"reason":"%s","elapsed_sec":%s}\n' \
            "$reason" "${ELAPSED:-0}"
    } > "$tmp"
    # fsync the file contents, then atomically rename into place, then
    # fsync the directory so the rename is durable. `sync` flushes the
    # whole fs; a targeted fdatasync would be tighter but `sync` keeps
    # this dependency-free (no python, no helper binary — roadmap rule).
    sync
    mv -f "$tmp" "$f"
    sync
}

# ── Single-line operator-greppable verdict + page ──────────────────
# Three verdict values, mirroring the sibling evidence lane's vocabulary
# (tools/scripts/sticky_matrix.sh's PASS/FAIL/BLOCKED VERDICT= convention):
#   PASS    — the replay ran to completion and every assertion held.
#   FAIL    — the replay ran and something about the CHAIN/BUILD under test
#             is wrong (consensus reject, sha3 mismatch, cross-node
#             disagreement, a crash mid-replay, ...) — a consensus-grade
#             alarm. This is the only value the in-node
#             `replay_canary_failed` Condition pages on (see
#             app/services/include/services/canary_sentinel_watch.h:
#             "only an explicit verdict==\"FAIL\" field pages").
#   BLOCKED — the harness could not even ATTEMPT a replay (missing binary,
#             an unusable source datadir, insufficient disk, ...) — an
#             operational/environmental alarm, distinct from a replay
#             mismatch. The node-side watcher already treats any verdict
#             other than the exact strings "FAIL"/"PASS" as an untrusted
#             unknown verdict that never crashes, never pages, and never
#             clears a real FAIL latch (see canary_sentinel_watch.c
#             `is_fail`/`is_pass`) — so BLOCKED is safely inert there by
#             construction, no node-side change required.
emit_verdict_line() {
    local verdict="$1" reason="$2"
    case "$verdict" in
        FAIL)
            echo "replay-canary: VERDICT=FAIL from=$FROM reason=$reason tip=${R_TIP:-?} bg=${R_BGSTATE:-?} elapsed=${ELAPSED:-?}s"
            # OnFailure systemd notification (File 7) is the page channel; we
            # also log to the journal here so `journalctl` greps VERDICT=FAIL.
            logger -t replay-canary "VERDICT=FAIL from=$FROM reason=$reason" 2>/dev/null || true
            ;;
        BLOCKED)
            echo "replay-canary: VERDICT=BLOCKED from=$FROM reason=$reason elapsed=${ELAPSED:-?}s"
            # Loud but NOT a page channel — `journalctl -t replay-canary` still
            # surfaces it, and the sentinel keeps it distinct from a FAIL an
            # operator would otherwise have to triage as a consensus alarm.
            logger -t replay-canary "VERDICT=BLOCKED from=$FROM reason=$reason — canary could not attempt a replay (not a consensus alarm)" 2>/dev/null || true
            ;;
        *)
            echo "replay-canary: VERDICT=PASS from=$FROM tip=${R_TIP:-?} verified=${R_VERIFIED:-?} elapsed=${ELAPSED:-?}s"
            ;;
    esac
}

# fail <reason>: write FAIL sentinel + line, exit non-zero. The sentinel
# is the authority; the exit code only drives systemd OnFailure=.
fail() {
    local reason="$1"
    write_verdict "FAIL" "$reason"
    emit_verdict_line "FAIL" "$reason"
    # Preserve forensics BEFORE the exit trap rm -rf's the scratch datadir:
    # the isolated node's log tail is the only post-mortem for an
    # unattended (02:30 nightly) FAIL. Tail-bounded so the verdict dir
    # stays small; tmp+mv so a reader never sees a torn copy. Quietly
    # skipped in selftest/fixture mode (no ISO_DD / no node.log).
    if [ -n "${ISO_DD:-}" ] && [ -f "${ISO_DD}/node.log" ]; then
        local flog="$VERDICT_DIR/lastfail_${FROM}_node.log"
        { echo "# preserved by fail(reason=$reason) ts=$(date -u +%s) elapsed=${ELAPSED:-?}s"; \
          tail -n 400 "${ISO_DD}/node.log"; } > "${flog}.tmp" 2>/dev/null \
            && mv -f "${flog}.tmp" "$flog" 2>/dev/null || true
    fi
    exit 1
}

# blocked <reason>: write a BLOCKED sentinel + line, exit non-zero (distinct
# exit code from fail's, though the durable signal is the sentinel's
# "verdict" field, not the exit code).
#
# Use this whenever the run produced NO parity evidence, so there is nothing
# to report either way. Two kinds qualify:
#   1. could not attempt a replay at all, caught before any node/RPC evidence
#      exists — missing binary, unusable source datadir, no disk, isolation
#      refusal;
#   2. attempted but did not COMPLETE — the budget timeout. Nothing was
#      compared: no sha3, no cross-node equality, no reject count.
#
# Once the isolated node HAS been probed and returned real evidence
# (bg_validation FAILED, a consensus reject, a mismatched sha3 or cross-node
# stat), stay on fail() — those ARE consensus-grade findings.
#
# The line to hold: a verdict may report what was MEASURED. It may never
# convert "we ran out of time on this hardware" into "the chain disagrees".
blocked() {
    local reason="$1"
    write_verdict "BLOCKED" "$reason"
    emit_verdict_line "BLOCKED" "$reason"
    exit 2
}

# pass: write PASS sentinel + line, exit 0.
pass() {
    write_verdict "PASS" ""
    emit_verdict_line "PASS" ""
    exit 0
}

# ── JSON field extraction (no python — grep/sed only) ──────────────
# Pulls "key":<number-or-"string"> out of a flat-ish JSON blob. Returns
# empty on a miss so the caller can detect rpc_unreachable / missing field
# (never silently treat a missing field as 0/pass).
json_num() {  # $1=json $2=key
    printf '%s' "$1" | grep -o "\"$2\"[[:space:]]*:[[:space:]]*-\?[0-9]\+" \
        | head -1 | grep -o -- '-\?[0-9]\+$' || true
}
json_str() {  # $1=json $2=key
    printf '%s' "$1" | grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
        | head -1 | sed 's/.*:[[:space:]]*"\([^"]*\)"/\1/' || true
}
# total_amount tolerance: zclassic23 emits it QUOTED ("10364137.94674881")
# but zclassicd emits it UNQUOTED as a JSON number (10395235.80748115).
# Extract either form as a bare token so the two can be string-compared
# directly (both nodes use 8-decimal fixed-point at the same height).
json_amount() {  # $1=json $2=key
    local v
    v="$(json_str "$1" "$2")"
    if [ -n "$v" ]; then printf '%s' "$v"; return 0; fi
    printf '%s' "$1" | grep -o "\"$2\"[[:space:]]*:[[:space:]]*[0-9.]\+" \
        | head -1 | sed 's/.*:[[:space:]]*\([0-9.]*\)/\1/' || true
}

# TCP liveness of one 127.0.0.1 port. The C8 genesis replay cannot start
# without a co-located zclassicd; probing here (timeout + /dev/tcp) names
# that host gap in milliseconds without a local binary, iso_init, or the
# 30s curl wait zcl-rpc would spend on a closed port.
oracle_tcp_open() {
    local port="$1"
    command -v timeout >/dev/null 2>&1 || return 1
    timeout 3 bash -c 'exec 3<>"/dev/tcp/127.0.0.1/$1"' -- "$port" \
        >/dev/null 2>&1
}

# Host-oracle preflight: no local binary required. A missing zclassicd is
# the C8 gap; a missing worktree binary must not hide it. Port-number
# validation, then TCP on RPC then P2P (same order the later getblockcount
# / -connect= checks use). First failure wins, typed BLOCKED.
preflight_host_oracle() {
    case "$ZD_RPC" in
        ''|*[!0-9]*) ELAPSED=$(( $(date +%s) - START_TS )); blocked "oracle_rpc_port_invalid" ;;
    esac
    case "$ZD_P2P" in
        ''|*[!0-9]*) ELAPSED=$(( $(date +%s) - START_TS )); blocked "oracle_p2p_port_invalid" ;;
    esac
    if [ "$ZD_RPC" -lt 1 ] || [ "$ZD_RPC" -gt 65535 ]; then
        ELAPSED=$(( $(date +%s) - START_TS )); blocked "oracle_rpc_port_invalid"
    fi
    if [ "$ZD_P2P" -lt 1 ] || [ "$ZD_P2P" -gt 65535 ]; then
        ELAPSED=$(( $(date +%s) - START_TS )); blocked "oracle_p2p_port_invalid"
    fi
    if ! command -v timeout >/dev/null 2>&1; then
        echo "replay-canary: timeout(1) missing — cannot probe zclassicd RPC/P2P liveness" >&2
        ELAPSED=$(( $(date +%s) - START_TS )); blocked "oracle_p2p_probe_unavailable"
    fi
    if ! oracle_tcp_open "$ZD_RPC"; then
        echo "replay-canary: zclassicd RPC 127.0.0.1:$ZD_RPC unreachable — C8 genesis replay needs a co-located zclassicd (default RPC 8232, P2P 8034, datadir $SRC_DATADIR)" >&2
        ELAPSED=$(( $(date +%s) - START_TS )); blocked "oracle_rpc_unreachable"
    fi
    if ! oracle_tcp_open "$ZD_P2P"; then
        echo "replay-canary: zclassicd P2P 127.0.0.1:$ZD_P2P unreachable — genesis replay -connect= needs the co-located oracle (default 8034)" >&2
        ELAPSED=$(( $(date +%s) - START_TS )); blocked "oracle_p2p_unreachable"
    fi
}

# ── Result vars (populated as we probe; consumed by write_verdict) ─
# START_TS / STARTED_TS / ELAPSED are fixed earlier (with the sentinel
# helpers) so reset_verdict and the elapsed band share the same run-start.
R_TIP=0; R_VERIFIED=0; R_BGSTATE="unknown"; R_REJECTS=0
R_LOCAL_SHA3=""; R_TXOUTS=0; R_ZD_TXOUTS=0; R_SUPPLY=""; R_ZD_SUPPLY=""
R_LEGACY_SHA3=""; R_EXACT_TIER="not_run"

# ── Raw RPC blobs consumed by evaluate_verdict ─────────────────────
# Defaulted to "" here (not left to first-assignment in run_live/run_self_test)
# so `set -u` can NEVER trip an "unbound variable" on one of these under ANY
# code path — including one a future edit adds and forgets to populate on
# every branch. A real defect: run_live's budget-timeout branch (the "record
# a synthetic timeout bg_state" block) populated SD/DIAG/TX/ZD but not UC,
# so a from-anchor run that ran past its budget crashed with
# "replay_canary.sh: line NNN: UC: unbound variable" INSIDE evaluate_verdict,
# before write_verdict/fail() ever ran — leaving no sentinel at all (silently
# indistinguishable, to an operator reading the journal, from any other
# uncaught crash). evaluate_verdict's own `[ -n "$UC" ] || fail ...` check
# was written to turn a missing blob into a clean, sentinel-backed FAIL; an
# unbound reference defeats that check before it can run. This default is
# the general fix; the timeout branch also now populates UC explicitly (see
# run_live) for defense in depth.
# LEG: stdout of `--legacy-utxo-commitment` (the byte-exact tier — SHA3 over
# zclassicd's OWN chainstate serialization). Empty means "tier did not run";
# evaluate_verdict treats that as a hard FAIL in live mode (the gate must
# never silently degrade to the coarse height/stats tier) and as skip in
# self-test fixtures that predate the tier.
SD=""; DIAG=""; UC=""; TX=""; ZD=""; LEG=""

# ── Verdict logic: evaluate already-collected RPC blobs ────────────
# Inputs (set by run_live or run_self_test): SD (getsyncdetail),
# DIAG (getsyncdiag), UC (getutxocommitment), TX (node gettxoutsetinfo),
# ZD (zclassicd gettxoutsetinfo). First failure wins.
evaluate_verdict() {
    # ELAPSED is the wall-clock the run took. The self-test injects a
    # synthetic value (SELFTEST_ELAPSED) so the band can be exercised
    # hermetically without a 45-min wait; live mode measures the clock.
    if [ -n "${SELFTEST_ELAPSED:-}" ]; then ELAPSED="$SELFTEST_ELAPSED"
    else ELAPSED=$(( $(date +%s) - START_TS )); fi

    # rpc_unreachable: any required blob empty => FAIL (never a silent pass).
    [ -n "$SD" ]   || fail "rpc_unreachable_getsyncdetail"
    [ -n "$DIAG" ] || fail "rpc_unreachable_getsyncdiag"
    [ -n "$UC" ]   || fail "rpc_unreachable_getutxocommitment"
    [ -n "$TX" ]   || fail "rpc_unreachable_gettxoutsetinfo"
    [ -n "$ZD" ]   || fail "rpc_unreachable_zd_gettxoutsetinfo"

    R_BGSTATE="$(json_str "$SD" state)"
    R_VERIFIED="$(json_num "$SD" verified_height)"; : "${R_VERIFIED:=0}"
    R_TIP="$(json_num "$TX" height)"; : "${R_TIP:=0}"
    local skipped; skipped="$(json_num "$SD" script_verif_skipped_no_undo)"; : "${skipped:=0}"
    R_REJECTS="$(json_num "$DIAG" total_rejected)"; : "${R_REJECTS:=0}"
    R_TXOUTS="$(json_num "$TX" txouts)"; : "${R_TXOUTS:=0}"
    local tx_best; tx_best="$(json_str "$TX" bestblock)"
    R_SUPPLY="$(json_amount "$TX" total_amount)"
    R_ZD_TXOUTS="$(json_num "$ZD" txouts)"; : "${R_ZD_TXOUTS:=0}"
    local zd_best; zd_best="$(json_str "$ZD" bestblock)"
    R_ZD_SUPPLY="$(json_amount "$ZD" total_amount)"
    local zd_height; zd_height="$(json_num "$ZD" height)"; : "${zd_height:=0}"
    # (a) bg_validation must reach COMPLETE.
    #
    #     FAILED => FAIL: a consensus reject during replay surfaces here, and
    #     that IS a consensus-grade finding.
    #
    #     timeout (caller records bg_state=timeout) => BLOCKED, not FAIL. The
    #     run did not diverge; it did not FINISH. bg_validation never reached
    #     COMPLETE, so no sha3, no cross-node equality and no reject count was
    #     ever compared — there is no parity evidence to report either way.
    #     Typing it FAIL made mvp_gate.sh raise C8 "full-history parity alarm"
    #     (held 7 days) out of a stopwatch: measured 2026-08-24, a from-genesis
    #     replay sustained 33 blk/s against the ~112 blk/s the 8 h budget
    #     assumes, so an honest slow box reported a divergence it never found.
    #     A budget encodes an assumption about hardware, never a fact about
    #     consensus. BLOCKED still earns C8 nothing (mvp_gate has no BLOCKED
    #     branch for genesis, so it falls through to "unearned"), which is the
    #     correct outcome: unproven, not proven-bad.
    case "$R_BGSTATE" in
        complete|COMPLETE) : ;;
        timeout)  blocked "budget_exceeded_incomplete_no_parity_evidence" ;;
        failed|FAILED) fail "bg_validation_failed" ;;
        *) fail "bg_state_${R_BGSTATE:-empty}" ;;
    esac

    # (a cont.) elapsed-time band — the named-defect guard for THIS track.
    # A COMPLETE that is too FAST (the from-anchor seed never applied, so
    # the node "completed" a stub) or too SLOW (the from-anchor run silently
    # degraded to a genesis-scale replay) both FAIL with a typed reason,
    # BEFORE the cross-node equality can mask a degraded-but-matching tip.
    local emin emax
    if [ "$FROM" = "genesis" ]; then emin="$GENESIS_ELAPSED_MIN"; emax="$GENESIS_ELAPSED_MAX"
    else emin="$ANCHOR_ELAPSED_MIN"; emax="$ANCHOR_ELAPSED_MAX"; fi
    [ "${ELAPSED:-0}" -ge "$emin" ] || fail "elapsed_too_fast"
    [ "${ELAPSED:-0}" -le "$emax" ] || fail "elapsed_too_slow"

    # (a cont.) header-admit rejects must be zero.
    [ "${R_REJECTS:-0}" -eq 0 ] || fail "consensus_rejects"

    # (b) local commitment. For from=anchor the node seeds AT the anchor
    #     and the commitment is computed at the TIP (not the anchor), so
    #     we assert it is a 64-hex value (a real recompute, not an error
    #     string) and rely on the boot integrity gate at h=3056758 for the
    #     checkpoint-sha3 proof. For from=genesis the replay crosses the
    #     anchor and the same boot gate proves the checkpoint; if the UC
    #     blob carries the anchor-height commitment it must equal EXPECTED.
    R_LOCAL_SHA3="$(json_str "$UC" sha3_hash)"
    local uc_h; uc_h="$(json_num "$UC" height)"; : "${uc_h:=0}"
    [ -n "$R_LOCAL_SHA3" ] || fail "sha3_unreadable"
    [[ "$R_LOCAL_SHA3" =~ ^[0-9a-f]{64}$ ]] || fail "sha3_malformed"
    # If the commitment was taken exactly at the anchor height, it must
    # equal the compiled checkpoint hash exactly.
    if [ "$uc_h" = "$ANCHOR_HEIGHT" ] && [ "$R_LOCAL_SHA3" != "$EXPECTED_SHA3" ]; then
        fail "sha3_mismatch"
    fi

    # (b cont.) from=genesis must verify EVERY script (no post-snapshot
    #     skips). from=anchor legitimately skips post-snapshot script
    #     verification, so do not assert it there.
    if [ "$FROM" = "genesis" ] && [ "${skipped:-0}" -ne 0 ]; then
        fail "script_verif_skipped_no_undo"
    fi

    # (c) cross-node coarse stats at the node's tip vs zclassicd.
    [ "${R_TIP:-0}" = "${zd_height:-0}" ] || fail "crossnode_height"
    [ -n "$tx_best" ] && [ "$tx_best" = "$zd_best" ] || fail "crossnode_bestblock"
    [ "${R_TXOUTS:-0}" = "${R_ZD_TXOUTS:-0}" ] || fail "crossnode_txouts"
    [ -n "$R_SUPPLY" ] && [ "$R_SUPPLY" = "$R_ZD_SUPPLY" ] || fail "crossnode_supply"

    # (d) BYTE-EXACT tier (2026-08-01 review): heights/counts/supply agreeing
    #     is NOT UTXO-set equality — two nodes can agree on every coarse stat
    #     while holding different sets. `--legacy-utxo-commitment` hashes
    #     zclassicd's OWN chainstate serialization through the canonical
    #     SHA3-256 fold the node serves via getutxocommitment, so this is a
    #     true byte-level set comparison. Height skew (the oracle advanced
    #     mid-run) is reported as exact_tier=skew and skipped — never read
    #     as drift and never as proof; only best_block equality unlocks the
    #     comparison. In LIVE mode an empty LEG is a hard FAIL: the gate
    #     must never silently degrade to the coarse tier. In SELF-TEST mode
    #     a missing legacy_utxo_commitment.json fixture skips the tier for
    #     backward compatibility with pre-tier fixtures.
    if [ -n "${LEG}" ]; then
        local leg_sha3 leg_best
        leg_sha3="$(json_str "$LEG" legacy_utxo_sha3)"
        leg_best="$(json_str "$LEG" best_block)"
        R_LEGACY_SHA3="$leg_sha3"
        if [ -z "$leg_sha3" ]; then
            R_EXACT_TIER="unreadable"; fail "exact_reference_unreadable"
        fi
        if [ "$leg_best" != "$tx_best" ]; then
            R_EXACT_TIER="skew"
            echo "replay-canary: exact tier SKIPPED — legacy best_block ${leg_best:-?} != node tip ${tx_best:-?} (oracle advanced mid-run); coarse tier already passed"
        elif [ "$leg_sha3" != "$R_LOCAL_SHA3" ]; then
            R_EXACT_TIER="mismatch"; fail "crossnode_utxo_sha3"
        else
            R_EXACT_TIER="match"
            echo "replay-canary: exact tier MATCH — UTXO SHA3 ${leg_sha3} identical over zclassicd chainstate and c23 coins at ${tx_best}"
        fi
    elif [ -z "${SELFTEST}" ] && [ "${ZCL_CANARY_NO_EXACT:-0}" != "1" ]; then
        R_EXACT_TIER="unusable"; fail "exact_reference_unusable"
    fi

    pass
}

# ── Self-test mode: feed fixture JSON, run the SAME verdict logic ──
# Drives the hermetic test_replay_canary_verdict gate. Reads fixture
# blobs from $ZCL_CANARY_SELFTEST_DIR. No node, no zclassicd, no network.
run_self_test() {
    local dir="${ZCL_CANARY_SELFTEST_DIR:-}"
    [ -n "$dir" ] && [ -d "$dir" ] || { echo "replay-canary: self-test needs ZCL_CANARY_SELFTEST_DIR" >&2; exit 2; }
    # Reset FIRST so even the self-test path proves the no-stale-sentinel
    # contract: any prior sentinel for this --from is removed before we
    # decide, and the run-start stamp is laid down.
    reset_verdict
    local selftest_binary="${ZCL_CANARY_SELFTEST_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
    if ! capture_binary_identity "$selftest_binary"; then
        ELAPSED=0
        blocked "source_identity_capture_failed"
    fi
    # Test-only mid-run pause: if ZCL_CANARY_SELFTEST_BLOCK_FIFO is set, block
    # on a read of that FIFO AFTER reset_verdict (so the stale sentinel is
    # already gone) but BEFORE evaluate_verdict (so no fresh sentinel is yet
    # written). The hermetic kill-mid-run test SIGKILLs us here and asserts
    # the post-kill read resolves FAIL (no fresh PASS) — proving the kill
    # lands inside a real run, not before the harness ever started.
    if [ -n "${ZCL_CANARY_SELFTEST_BLOCK_FIFO:-}" ]; then
        read -r _ < "$ZCL_CANARY_SELFTEST_BLOCK_FIFO" || true
    fi
    read_fixture() { [ -f "$dir/$1.json" ] && cat "$dir/$1.json" || printf ''; }
    SD="$(read_fixture getsyncdetail)"
    DIAG="$(read_fixture getsyncdiag)"
    UC="$(read_fixture getutxocommitment)"
    TX="$(read_fixture gettxoutsetinfo)"
    ZD="$(read_fixture zd_gettxoutsetinfo)"
    # Byte-exact tier fixture; absent => tier skipped (pre-tier fixtures).
    LEG="$(read_fixture legacy_utxo_commitment)"
    # Optional elapsed.json (a bare integer) drives the elapsed band
    # hermetically. Absent => default to an in-band value for the active
    # --from so the baseline pass fixtures stay green without one.
    local fx_elapsed; fx_elapsed="$(read_fixture elapsed | tr -dc '0-9')"
    if [ -n "$fx_elapsed" ]; then SELFTEST_ELAPSED="$fx_elapsed"
    elif [ "$FROM" = "genesis" ]; then SELFTEST_ELAPSED=$(( GENESIS_ELAPSED_MIN + 1 ))
    else SELFTEST_ELAPSED=$(( ANCHOR_ELAPSED_MIN + 1 )); fi
    # The self-test mode name is informational; the verdict is decided
    # purely by the fixture content, so a mislabeled fixture cannot lie.
    evaluate_verdict
}

# ── Live mode: spawn the isolated mainnet node, replay, probe ──────
run_live() {
    # Reset FIRST — before importing headers, spawning the node, or any
    # other abortable step. From here on a killed/OOM/timed-out harness
    # leaves NO sentinel (not a stale PASS), so absence-of-fresh-PASS is a
    # construction-level FAIL.
    reset_verdict

    cd "$REPO_ROOT"

    # Missing-prerequisite checks below are self-describing (name the exact
    # missing thing AND the fix) and durable (BLOCKED sentinel, not just a
    # stderr line + bare exit) — a canary that cannot run must leave a
    # verdict an operator/ops-surface reader can distinguish from a replay
    # MISMATCH (see blocked()'s doc comment).
    #
    # Order is load-bearing for C8: probe the co-located zclassicd FIRST.
    # A missing worktree binary used to win, so `make replay-canary-genesis`
    # on an unbuilt tree named binary_missing_zclassic23 and hid the actual
    # acceptance gap (no oracle on 8232/8034). The hermetic
    # test_blocked_on_oracle_rpc_unreachable contract also depends on this
    # order: `--zclassicd-rpc=1` must resolve oracle_rpc_unreachable even
    # when build/bin/zclassic23 is absent.
    preflight_host_oracle

    # from=genesis byte-exact tier hashes zclassicd's OWN chainstate via
    # --legacy-utxo-commitment. Missing chainstate used to burn the 8 h
    # budget and then FAIL exact_reference_unusable (a consensus-grade
    # alarm) for an environmental gap. BLOCKED here, after the oracle TCP
    # probe so a closed RPC port still wins the hermetic port-1 test.
    if [ "$FROM" = "genesis" ] && [ ! -d "$SRC_DATADIR/chainstate" ]; then
        echo "replay-canary: --src-datadir=$SRC_DATADIR has no chainstate/ — byte-exact C8 (--legacy-utxo-commitment) cannot run (expected the zclassicd datadir, default \$HOME/.zclassic)" >&2
        ELAPSED=$(( $(date +%s) - START_TS )); blocked "src_datadir_missing"
    fi

    if [ ! -x build/bin/zclassic23 ]; then
        echo "replay-canary: build/bin/zclassic23 missing — run 'make' in $REPO_ROOT" >&2
        ELAPSED=0; blocked "binary_missing_zclassic23"
    fi
    if [ ! -x build/bin/zcl-rpc ]; then
        echo "replay-canary: build/bin/zcl-rpc missing — run 'make zcl-rpc' in $REPO_ROOT" >&2
        ELAPSED=0; blocked "binary_missing_zcl_rpc"
    fi

    # Default budgets: anchor 7200 s (120 min — ~45-min replay + the
    # shielded-import interlude + a second boot, 1.6x headroom); genesis
    # 28800 s (8 h, ~1.3x the ~6-h expectation).
    local budget
    if [ -n "$BUDGET_SEC" ]; then budget="$BUDGET_SEC"
    elif [ "$FROM" = "genesis" ]; then budget=28800
    else budget=7200; fi

    # Distinct port bases so a nightly + a (rare) overlapping weekly cannot
    # collide. anchor=39050, genesis=39060. crash-soak (item 7) reserves 39070.
    if [ "$FROM" = "genesis" ]; then export ISO_PORT_BASE=39060
    else export ISO_PORT_BASE=39050; fi
    export ISO_KIND=replay

    # shellcheck source=tools/scripts/isolated_mainnet_env.sh
    . tools/scripts/isolated_mainnet_env.sh
    iso_init
    if ! freeze_live_binaries; then
        ELAPSED=$(( $(date +%s) - START_TS ))
        blocked "source_identity_capture_failed"
    fi

    # TCP already proved the oracle ports are open (preflight_host_oracle).
    # getblockcount still has to answer: an open port that is reindexing,
    # unauthenticated, or not actually zclassicd must stay typed BLOCKED,
    # never a spawned 8 h replay that FAILs as if consensus diverged.
    local oracle_height
    oracle_height="$(json_num "$(ZCL_DATADIR="$SRC_DATADIR" \
        ZCL_RPCPORT="$ZD_RPC" "$ISO_RPC_BIN" getblockcount 2>/dev/null || true)" result)"
    if [ -z "$oracle_height" ]; then
        echo "replay-canary: zclassicd RPC 127.0.0.1:$ZD_RPC is open but getblockcount did not return a height (reindexing, auth, or not zclassicd)" >&2
        ELAPSED=$(( $(date +%s) - START_TS )); blocked "oracle_rpc_unreachable"
    fi

    # Disk preflight follows the tiny immutable executable capture so every
    # verdict, including this refusal, remains bound to exact executed bytes.
    local avail_kb; avail_kb="$(df -Pk /tmp | awk 'NR==2{print $4}')"
    if [ "${avail_kb:-0}" -lt 83886080 ]; then   # < 80 GiB
        echo "replay-canary: REFUSE — /tmp has $((avail_kb/1024/1024)) GiB free, need >= 80 GiB" >&2
        ELAPSED=0; blocked "insufficient_disk"
    fi

    if [ "$FROM" = "anchor" ]; then
        if [ ! -d "$SRC_DATADIR/blocks/index" ]; then
            echo "replay-canary: --src-datadir=$SRC_DATADIR has no blocks/index — not a node datadir (expected the zclassicd datadir, default \$HOME/.zclassic)" >&2
            ELAPSED=$(( $(date +%s) - START_TS )); blocked "src_datadir_missing"
        fi
        echo "replay-canary: importing headers from $SRC_DATADIR (read-only)"
        if ! iso_import_blockindex "$SRC_DATADIR"; then
            ELAPSED=$(( $(date +%s) - START_TS )); blocked "blockindex_import_failed"
        fi
        # PROVEN cold recipe (empirically verified at HEAD 2026-06-12):
        # NORMAL boot with legacy auto-import ON (NO -nolegacyimport, NO
        # -snapshot). Boot auto-links the read-only ~/.zclassic, seeds the
        # anchor UTXO set, reconciles, and serves; bg-validation walks the
        # connected extent (omit -nobgvalidation). The -snapshot=$SRC +
        # -nolegacyimport combo the spec proposed FATALs at HEAD
        # (torn-anchor: utxos present, coins_best unset, heal refused) — do
        # NOT use it. NOTE: legacy auto-import is hardcoded to read
        # ~/.zclassic, so for the anchor variant the source IS ~/.zclassic
        # regardless of --src-datadir (the default).
        #
        # 2026-08-01 fix: this used to dial the DEAD -connect sink
        # (127.0.0.1:$ISO_CONNECT_SINK) to keep peer_count 0 — but that
        # freezes the node at boot-tip while the co-located zclassicd keeps
        # mining, so the crossnode_height gate (node tip == zd tip, exact
        # equality) structurally FAILed (~22-block skew on the 2026-08-01
        # run) and the byte-exact --legacy-utxo-commitment tier could never
        # see matching heights. Dial the read-only co-located zclassicd
        # (127.0.0.1:8034) instead — the same peer the from=genesis track
        # already sanctions as "the ONE place a real peer is dialed": the
        # trust posture is unchanged (zd is already the sole body source
        # via the disk link; P2P here only supplies post-link tip blocks),
        # and -connect= still enforces the no-public-peer contract. The
        # node now tracks tip to verdict, making both the crossnode
        # equality gate and the exact byte-tier achievable.
        iso_spawn_mainnet_node "-connect=127.0.0.1:$ZD_P2P"
    else
        # from=genesis: -nolegacyimport so boot does NOT seed to the anchor;
        # dial the co-located zclassicd for bodies. This is the ONE place a
        # real peer is dialed — the read-only co-located zclassicd.
        #
        # 2026-07-20 fix: this used to pass -addnode=127.0.0.1:8034, which
        # only ADDS zclassicd as a candidate — it does NOT disable the
        # node's normal DNS-seed/addrman outbound discovery (that requires
        # -connect=, which sets g_connect_only, the exact mechanism the
        # from-anchor variant already relies on for its dead sink — see
        # iso_spawn_mainnet_node's Peer-policy doc comment below). The "ONE
        # place a real peer is dialed" invariant above was therefore
        # violated in practice: a live weekly run (2026-07-19) dialed four
        # real mainnet IPs alongside zclassicd. -connect= (like -addnode=)
        # still adds the given host as a peer (src/main.c's argv loop
        # applies app_add_node() to BOTH flags identically), so switching
        # to -connect= keeps fetching bodies from zclassicd while actually
        # enforcing the "no public peer" contract.
        iso_spawn_mainnet_node "-nolegacyimport -connect=127.0.0.1:$ZD_P2P"
    fi

    # 600 s: a fresh-import boot walks 3.1M-header restore phases before the
    # RPC listener starts; 180 s false-FAILed (rpc_never_ready) on a loaded
    # box (first live RED run, 2026-06-13). The hard budget still bounds the
    # whole run; this only lets the node finish booting.
    if ! iso_wait_rpc_ready 600; then
        ELAPSED=$(( $(date +%s) - START_TS )); fail "rpc_never_ready"
    fi

    # ── from=anchor shielded-history import interlude ─────────────────
    # The cold-import staged seed borrows the anchor-tier shielded frontier
    # but the shielded ACTIVATION cursors stay >0, and the shielded
    # preflight (app/jobs/src/utxo_apply_nullifiers.c) fail-closed-HOLDs any
    # post-seed block carrying a shielded SPEND (canary FAIL#5, 2026-08-02:
    # fold resumed after the memo-clear fix, then pinned at seed+25 on the
    # first spend block — no auto-remedy can cure it BY DESIGN; the cursors
    # are the node's own "my shielded history below the seed is unproven"
    # marker). The -import-complete-shielded verb fills exactly that gap:
    # it streams the co-located zclassicd's chainstate through a
    # WAL-inclusive stable copy, verifies the tip anchor BY ROOT against
    # the target's own header-derived sapling root, and folds the verified
    # anchors/nullifiers in, zeroing the cursors. It needs the node STOPPED
    # (it opens the target datadir's node.db itself) and the seed floor
    # landed (the tip bind keys off it). Sequence: wait seed floor → wait
    # header coverage past it → settle → stop → import → respawn → the
    # shared bg-wait/convergence/probe flow below. from=genesis needs none
    # of this — its fold is from genesis, so the cursors flip to 0 on their
    # own.
    if [ "$FROM" = "anchor" ]; then
        # (1) Wait for the staged seed. It lands AFTER rpc-ready (the
        # reducer seeds on its first ticks); node.log carries
        # "cold-import staged-sync seed ... H*=<height>". Cap 600 s.
        local seed_h="" seed_deadline=$(( $(date +%s) + 600 ))
        while [ "$(date +%s)" -lt "$seed_deadline" ]; do
            if [ -n "${ISO_NODE_PID:-}" ] && ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
                ELAPSED=$(( $(date +%s) - START_TS )); R_BGSTATE="exited"; fail "node_exited_unexpectedly"
            fi
            seed_h="$(grep -aoE 'H\*=[0-9]+' "$ISO_DD/node.log" 2>/dev/null | head -1 | grep -oE '[0-9]+' || true)"
            [ -n "$seed_h" ] && break
            sleep 5
        done
        if [ -z "$seed_h" ]; then
            ELAPSED=$(( $(date +%s) - START_TS )); fail "seed_never_landed"
        fi
        echo "replay-canary: staged seed landed at H*=$seed_h — waiting for header coverage"

        # (2) The import's tip bind keys off the target's OWN seed floor /
        # coins_best, and its by-root verify reads the target's header at
        # that height. The --importblockindex copy ends well below the seed
        # floor (the disk copy lags the live zd tip), so wait until P2P
        # header sync from zd covers H* before stopping. Then a 20 s
        # projection settle so node.db writers are quiescent before the
        # importer opens the datadir.
        local h_now="" cov_deadline=$(( $(date +%s) + 600 ))
        while [ "$(date +%s)" -lt "$cov_deadline" ]; do
            if [ -n "${ISO_NODE_PID:-}" ] && ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
                ELAPSED=$(( $(date +%s) - START_TS )); R_BGSTATE="exited"; fail "node_exited_unexpectedly"
            fi
            h_now="$(json_num "$(iso_rpc getblockcount)" result)"
            if [ -n "$h_now" ] && [ "$h_now" -ge "$seed_h" ]; then break; fi
            sleep 5
        done
        if [ -z "$h_now" ] || [ "$h_now" -lt "$seed_h" ]; then
            ELAPSED=$(( $(date +%s) - START_TS )); fail "header_coverage_timeout_seed_$seed_h"
        fi
        echo "replay-canary: header coverage $h_now >= seed $seed_h — settling 20 s, then stopping for import"
        sleep 20

        # (3) Stop the node (the importer opens the target datadir's
        # node.db itself). TERM the process group, wait, KILL stragglers —
        # iso_cleanup's discipline, minus the datadir removal. The wait is
        # 120 s, NOT iso_cleanup's 10 s: the graceful shutdown's
        # persist-fast-restart-state step rewrites block_index.bin (the
        # ~550 MB flat + its embedded SHA3), and the importer's tip-bind
        # root read REQUIRES that save — a SIGKILL preempting it leaves the
        # flat at its boot-time state, below the P2P header tip, and the
        # verb refuses "no row at height" (canary FAIL#7 ran exactly this
        # stop at 10 s).
        kill -TERM "-$ISO_PGID" 2>/dev/null || true
        local i
        for i in $(seq 1 600); do
            kill -0 "-$ISO_PGID" 2>/dev/null || break
            sleep 0.2
        done
        kill -KILL "-$ISO_PGID" 2>/dev/null || true
        ISO_NODE_PID=""; ISO_PGID=""
        # node.log is TRUNCATED on respawn, so keep boot1's (seed-floor +
        # shutdown evidence) for the post-mortem trail. The copy must run
        # AFTER the stop — the shutdown's own prints land in node.log only
        # once the TERM is delivered (FAIL#8: copying BEFORE the TERM and
        # then grepping the copy for the shutdown lines false-FAILed a
        # node that had shut down perfectly).
        cp "$ISO_DD/node.log" "$ISO_DD/node.boot1.log"
        # Belt-and-suspenders: the flat save announces itself on stdout.
        # Its absence after a graceful stop means the shutdown sequence
        # never reached persist-fast-restart-state — the import below
        # would refuse on a stale flat, so name it now instead.
        if ! grep -aq 'fast restart state persisted' "$ISO_DD/node.boot1.log"; then
            ELAPSED=$(( $(date +%s) - START_TS )); fail "shutdown_flat_save_missing"
        fi

        # (4) Run the importer against the read-only zd source; its output
        # goes to node.import.log (the respawn truncates node.log). One
        # retry after 60 s covers a lagging projection write; a second
        # failure is a real refusal (bind mismatch, missing boundaries) —
        # FAIL named, never silently skip the interlude.
        echo "replay-canary: importing complete shielded history from $SRC_DATADIR (read-only)"
        if ! "$ISO_NODE_BIN" -datadir="$ISO_DD" -import-complete-shielded="$SRC_DATADIR" >"$ISO_DD/node.import.log" 2>&1; then
            echo "replay-canary: shielded import failed once — retrying in 60 s (projection-lag insurance)" >&2
            sleep 60
            if ! "$ISO_NODE_BIN" -datadir="$ISO_DD" -import-complete-shielded="$SRC_DATADIR" >>"$ISO_DD/node.import.log" 2>&1; then
                ELAPSED=$(( $(date +%s) - START_TS )); fail "shielded_import_failed"
            fi
        fi
        grep -a 'IMPORT COMPLETE' "$ISO_DD/node.import.log" | tail -1 || true
        echo "replay-canary: shielded history import complete — respawning node"

        # (5) Respawn with the same flags; boot2 folds post-seed bodies
        # with activation cursors now 0, so spend blocks pass preflight.
        iso_spawn_mainnet_node "-connect=127.0.0.1:$ZD_P2P"
        if ! iso_wait_rpc_ready 600; then
            ELAPSED=$(( $(date +%s) - START_TS )); fail "rpc_never_ready_after_import"
        fi
    fi

    # Poll until bg_validation reaches a terminal state or the budget blows.
    local deadline=$(( START_TS + budget ))
    while :; do
        # Node-death check FIRST. A node that CRASHED (e.g. a SIGSEGV in a
        # recovery/boot path) answers every RPC empty, so without this the loop
        # would poll until the budget blows and then mislabel a crash as
        # rpc_unreachable_getsyncdiag / bg_state=timeout (observed 2026-06-13,
        # masking a real signal 11 in chain_restore_finalize). Detect the dead
        # PID and FAIL FAST with the actual signal from node.log.
        if [ -n "${ISO_NODE_PID:-}" ] && ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
            ELAPSED=$(( $(date +%s) - START_TS ))
            local sig=""
            if [ -f "$ISO_DD/node.log" ]; then
                sig="$(grep -aoE 'signal[^0-9]*[0-9]+' "$ISO_DD/node.log" \
                        | grep -oE '[0-9]+' | tail -1)"
            fi
            if [ -n "$sig" ]; then
                R_BGSTATE="crashed"; fail "node_crashed_signal_${sig}"
            else
                R_BGSTATE="exited"; fail "node_exited_unexpectedly"
            fi
        fi
        local sd; sd="$(iso_rpc getsyncdetail)"
        local st; st="$(json_str "$sd" state)"
        case "$st" in
            complete|COMPLETE|failed|FAILED) break ;;
        esac
        if [ "$(date +%s)" -ge "$deadline" ]; then
            # Record a synthetic timeout bg_state so evaluate_verdict pages
            # budget_exceeded — never silently pass on a stuck RUNNING.
            # evaluate_verdict's leading "every blob present" gate checks ALL
            # FIVE of SD/DIAG/UC/TX/ZD unconditionally (it runs before the
            # bg_state case statement gets a chance to short-circuit on
            # "timeout"), so every one of them must be populated here even
            # though only SD/DIAG/TX/ZD are otherwise meaningful for a
            # timeout verdict — UC was missing here (a real defect: it
            # crashed the harness with an unbound-variable error instead of
            # reaching fail("budget_exceeded"); see the SD="" ... default
            # block above for the general-case fix).
            R_BGSTATE="timeout"
            SD="{\"bg_validation\":{\"state\":\"timeout\"}}"
            DIAG="$(iso_rpc getsyncdiag)"; UC="$(iso_rpc getutxocommitment)"
            TX="$(iso_rpc gettxoutsetinfo)"
            ZD_DATADIR="$SRC_DATADIR" ZD="$(ZCL_DATADIR="$SRC_DATADIR" ZCL_RPCPORT="$ZD_RPC" "$ISO_RPC_BIN" gettxoutsetinfo 2>/dev/null || true)"
            evaluate_verdict
        fi
        sleep 30
    done

    # Tip-convergence wait (live tracks): bg COMPLETE only proves the
    # re-verification walk finished over the locally-derived extent — with a
    # live oracle peer dialed, the node can still be folding post-seed
    # bodies when the walk ends (2026-08-01 anchor run: bg started at the
    # seed floor 3202072 while the oracle tip was ~3204600; the walk
    # completed over a ~2-block extent and the verdict would have FAILed
    # crossnode_height had the UC-probe watchdog not fired first). The
    # crossnode gate demands EXACT tip equality, so wait until the node has
    # caught the oracle's tip before probing. node_tip >= zd_tip (not ==):
    # the oracle keeps mining and the node chases via P2P within seconds,
    # so "caught up at sample time" is the achievable condition. Same hard
    # budget as the bg wait; a node that never converges pages
    # budget_exceeded, never a silent pass.
    #
    # BOTH sides are sampled via gettxoutsetinfo height, NOT getblockcount:
    # the node's public tip is finalize-lagged — it reports exactly one
    # block below its coins tip PERSISTENTLY (a block is only exposed after
    # the next block's finalize), so getblockcount(node) >=
    # getblockcount(zd) is structurally impossible against a still-mining
    # oracle (2026-08-02 anchor run: node getblockcount=3202299 vs
    # zd=3202300 held for 60+s while gettxoutsetinfo on BOTH reported
    # height=3202300 with identical bestblock — the node WAS at tip, the
    # probe was lying). gettxoutsetinfo height is the coins tip (==
    # reducer_frontier hstar) and the commitment is cached: ~1 s per call
    # on both sides, cheap enough to poll.
    while :; do
        if [ -n "${ISO_NODE_PID:-}" ] && ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
            ELAPSED=$(( $(date +%s) - START_TS ))
            R_BGSTATE="exited"; fail "node_exited_unexpectedly"
        fi
        local n_tip z_raw z_tip
        n_tip="$(json_num "$(iso_rpc gettxoutsetinfo)" height)"
        z_raw="$(ZCL_DATADIR="$SRC_DATADIR" ZCL_RPCPORT="$ZD_RPC" "$ISO_RPC_BIN" gettxoutsetinfo 2>/dev/null || true)"
        # Both RPCs return the gettxoutsetinfo object; "height" is unique
        # enough to grep flat in both.
        z_tip="$(json_num "$z_raw" height)"
        if [ -n "$n_tip" ] && [ -n "$z_tip" ] && [ "$n_tip" -ge "$z_tip" ]; then
            break
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            R_BGSTATE="timeout"
            SD="{\"bg_validation\":{\"state\":\"timeout\"}}"
            DIAG="$(iso_rpc getsyncdiag)"; UC="$(iso_rpc getutxocommitment)"
            TX="$(iso_rpc gettxoutsetinfo)"
            ZD_DATADIR="$SRC_DATADIR" ZD="$(ZCL_DATADIR="$SRC_DATADIR" ZCL_RPCPORT="$ZD_RPC" "$ISO_RPC_BIN" gettxoutsetinfo 2>/dev/null || true)"
            evaluate_verdict
        fi
        sleep 15
    done

    # Terminal state reached — collect every probe blob, then evaluate.
    # Probe binding: the verdict's crossnode tier compares TX (node
    # gettxoutsetinfo) against ZD (oracle gettxoutsetinfo) and the exact
    # tier compares UC (node commitment) against LEG (oracle chainstate
    # hashed through this binary's frozen fold) — so TX, ZD and UC must be
    # sampled at the SAME tip. The old fixed order (SD,DIAG,UC,TX,ZD,LEG)
    # spread them ~5+ s apart; with a live oracle mining 36-137 s blocks a
    # fresh block could land between UC and TX/ZD and false-FAIL the
    # height binds. Sample TX→ZD→UC→LEG back-to-back (~1 s each,
    # commitment-cached) in a retry loop until the three heights agree —
    # that window fits inside any single block gap. LEG skew (its best
    # block lags the live tip between compactions) remains a SKIP of the
    # exact tier by design, not a FAIL. SD/DIAG are diagnostic-only and
    # unbound — taken once, after the loop.
    while :; do
        if [ -n "${ISO_NODE_PID:-}" ] && ! kill -0 "$ISO_NODE_PID" 2>/dev/null; then
            ELAPSED=$(( $(date +%s) - START_TS ))
            R_BGSTATE="exited"; fail "node_exited_unexpectedly"
        fi
        TX="$(iso_rpc gettxoutsetinfo)"
        # zclassicd is read-only: gettxoutsetinfo only, never stop/generate.
        ZD="$(ZCL_DATADIR="$SRC_DATADIR" ZCL_RPCPORT="$ZD_RPC" "$ISO_RPC_BIN" gettxoutsetinfo 2>/dev/null || true)"
        UC="$(iso_rpc getutxocommitment)"
        # Byte-exact tier: hash the oracle's OWN chainstate through the
        # frozen binary's canonical SHA3 fold (read-only WAL-inclusive
        # stable copy; the daemon keeps running). stderr is preserved for
        # post-mortem, stdout is the JSON blob.
        LEG="$("$ISO_NODE_BIN" --legacy-utxo-commitment "$SRC_DATADIR" \
            2>"$ISO_DD/legacy_utxo_commitment.stderr" || true)"
        local tx_h zd_h uc_h
        tx_h="$(json_num "$TX" height)"
        zd_h="$(json_num "$ZD" height)"
        uc_h="$(json_num "$UC" height)"
        if [ -n "$tx_h" ] && [ "$tx_h" = "$zd_h" ] && [ "$tx_h" = "$uc_h" ]; then
            break
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            # Same synthetic-timeout shape as the wait loops above:
            # evaluate_verdict pages budget_exceeded, never a silent pass.
            R_BGSTATE="timeout"
            SD="{\"bg_validation\":{\"state\":\"timeout\"}}"
            DIAG="$(iso_rpc getsyncdiag)"
            evaluate_verdict
        fi
        sleep 10
    done
    # The bg_validation section is nested in getsyncdetail under
    # "bg_validation"; evaluate_verdict reads state/verified_height/
    # script_verif_skipped_no_undo which are unique enough to grep flat.
    SD="$(iso_rpc getsyncdetail)"
    DIAG="$(iso_rpc getsyncdiag)"

    evaluate_verdict
}

# ── Dispatch ───────────────────────────────────────────────────────
case "$FROM" in
    anchor|genesis) : ;;
    *) echo "replay-canary: --from must be anchor|genesis (got '$FROM')" >&2; exit 2 ;;
esac

if [ -n "$SELFTEST" ]; then
    run_self_test
else
    run_live
fi
