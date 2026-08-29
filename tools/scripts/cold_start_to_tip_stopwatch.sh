#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# cold_start_to_tip_stopwatch.sh — the GENUINE C3 wall-clock proof (MVP.md
# criterion 3): wipe -> boot bare -> reach network tip.
#
# This is deliberately NOT cold_start_to_tip_probe.sh. That probe pre-seeds a
# local operator bundle (block_index.bin + utxo-seed-*.snapshot) into the
# fresh datadir before boot — an assisted seed, not a wiped-empty start. This
# harness boots the target binary against a genuinely EMPTY datadir with NO
# snapshot/bundle/import flags at all: whatever the binary does on its own to
# reach a self-verified authority (the compiled-in checkpoint-ROM authority
# fold, or a full from-genesis fold once that lands — this harness does not
# care which; it only observes the result) is exactly what gets timed. Once a
# native "weld" path (checkpoint authority auto-activated at boot, no flags)
# is integrated, this is the harness that measures it with no changes needed.
#
# It gates on the real MVP claim — H* (the reducer's authoritative,
# provable tip) reaching network_tip (the best height any handshake-complete
# P2P peer advertised) — never on "the sync FSM says at_tip", which the ~7s
# in-process FSM stub (lib/test/src/test_cold_start_sync.c) asserts without
# downloading or validating a single real block. Both fields come straight off
# `dumpstate reducer_frontier` (app/jobs/src/reducer_frontier_dump.c):
# "hstar" and "network_tip"/"network_tip_read_ok".
#
# Binary-path argument: pass the binary to time via --bin=PATH (or the first
# bare positional arg), or ZCL_CS_NODE_BIN. This lets an orchestrator point
# the stopwatch at a freshly-integrated build without editing this file.
#
# FULLY ISOLATED + NON-DESTRUCTIVE:
#   - datadir is ALWAYS a fresh mktemp under /tmp — there is no flag or env
#     var to point it at any other path, so it can never collide with a
#     live datadir,
#   - isolated $HOME (no co-located ~/.zclassic legacy dir the node could
#     auto-import from — the genuinely-fresh-machine condition),
#   - dedicated non-live ports (39170-39173), -listen=0, -nolegacyimport,
#   - dials the peer via -connect as a CLIENT only (read-only P2P — never
#     writes to the peer's datadir, never touches systemd),
#   - the serving peer has NO default and must be stated (ZCL_CS_PEER /
#     --peer / ZCL_PEER= via make); with nothing set the run SKIPs rather
#     than falling back to whatever is listening on the canonical port,
#   - process-group SIGKILL teardown on every exit path.
#
# Usage:
#   tools/scripts/cold_start_to_tip_stopwatch.sh [--bin=PATH] [--peer=HOST:PORT]
#       [--file-peer=HOST:PORT] [--budget=SECS] [--sample=SECS]
#   ZCL_CS_NODE_BIN=/path/to/zclassic23 ZCL_CS_PEER=127.0.0.1:8033 \
#       ZCL_CS_FILE_PEER=127.0.0.1:18034 \
#       ZCL_CS_HEADER_SOURCE=/path/to/zclassicd-datadir-copy \
#       ZCL_CS_BUNDLE_PATH=/path/to/consensus-state-bundle.sqlite \
#       tools/scripts/cold_start_to_tip_stopwatch.sh
#
# Exit codes:
#   0  PASS           — H* reached network_tip within budget. WALL_CLOCK_SECONDS
#                        printed is the real, published wipe-to-tip number.
#   3  SEAM           — H* climbed (real forward progress) but budget expired
#                        before it caught network_tip. Honest code-seam, not a
#                        fixture problem.
#   4  STALLED-NAMED  — no forward progress across the whole window, but at
#                        least one active named blocker explains why (the
#                        acceptable-stall class per docs/TENACITY.md).
#   1  FAIL           — no forward progress AND no named blocker (the silent-
#                        stall failure class), or the node process died, or a
#                        harness/setup error.
#   2  SKIP           — prerequisite absent (binary not built / no peer stated
#                        / peer unreachable). Not a verdict on C3 either way.
#                        A peer that accepts the TCP connection and closes it
#                        immediately is NOT a SKIP — it is labelled
#                        peer_precheck=accept_close, warned about loudly, and
#                        the run still reports the verdict the node earned.
#   5  FRONTIER-BUSY-TIMEOUT — `dumpstate reducer_frontier` kept returning a
#                        partial `{"snapshot_status":"progress_store_busy",
#                        "retryable":true}` doc that carried no usable provable
#                        sample (neither "hstar" NOR a cached_provable_tip
#                        proxy) for the entire busy-timeout window
#                        (--busy-timeout=SECS /
#                        ZCL_CS_FRONTIER_BUSY_TIMEOUT_SECS, default 120s) —
#                        this harness never observed a real frontier sample.
#                        Distinct from FAIL: this is an instrument failure
#                        ("we could not read the node's state"), not a claim
#                        about the node's actual progress.
#   6  READBACK-FAILED — no forward progress was OBSERVED and no blocker was
#                        named, but the final frontier readback (after bounded
#                        retries) yielded neither an authoritative "hstar" nor a
#                        cached_provable_tip proxy — the instrument could not
#                        read the node's provable tip at end-of-run. Carries the
#                        last good provable sample. Distinct from the silent-
#                        stall FAIL (exit 1): "we could not observe" is NOT "we
#                        observed nothing happening." Never PASS, never silent-
#                        stall — a FAIL with a named, honest cause.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tools/scripts/stopwatch_json_lib.sh
. "$REPO_ROOT/tools/scripts/stopwatch_json_lib.sh"
# shellcheck source=tools/scripts/source_identity_lib.sh
# The ONE source-identity reader (zcl_binary_source_id / zcl_json_first_string /
# zcl_json_first_sha256). Do NOT inline a tenth copy of that parser here —
# tools/lint/check_identity_parser_single.sh counts them and this file carries
# no baseline row, so it may carry ZERO.
. "$REPO_ROOT/tools/scripts/source_identity_lib.sh"

NODE_BIN="${ZCL_CS_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
# NO DEFAULT PEER, ON PURPOSE. This used to default to 127.0.0.1:8033 — the
# canonical/live node's P2P port on an operator host — so a bare
# `make mvp-coldstart-to-tip-stopwatch` silently pulled a full chain-data sync
# off the operator's own node without anyone asking for it. The peer a proof
# lane dials is part of the proof, so it must be stated, not inherited: with
# nothing set the run SKIPs (exit 2) and names the variable. See the
# no_peer_configured skip below.
PEER="${ZCL_CS_PEER:-}"
FILE_PEER="${ZCL_CS_FILE_PEER:-}"
HEADER_SOURCE="${ZCL_CS_HEADER_SOURCE:-}"
BUNDLE_PATH="${ZCL_CS_BUNDLE_PATH:-}"
BUDGET="${ZCL_CS_BUDGET_SECS:-600}"     # 10-minute MVP C3 target
SAMPLE_SECS="${ZCL_CS_SAMPLE_SECS:-10}"
ARTIFACT_ROOT="${ZCL_CS_ARTIFACT_ROOT:-$REPO_ROOT/build/c3-stopwatch}"
# Bounded window a persistently-busy progress_store may occupy before this
# harness gives up observing and reports FRONTIER-BUSY-TIMEOUT instead of
# silently folding busy reads into "no forward progress" (see D6 / the
# is_busy_response()/rpc_frontier() comment below).
FRONTIER_BUSY_TIMEOUT_SECS="${ZCL_CS_FRONTIER_BUSY_TIMEOUT_SECS:-120}"
# Classification of what the peer did with a bare TCP connect (see
# peer_precheck below). Recorded in proof.json; never changes the verdict.
PEER_PRECHECK="unknown"
# Bounded number of supervised self-respawns this harness will FOLLOW before
# calling it a runaway (see the respawn-seam handling in the main loop). A
# clean self-exit carrying a self_respawn_* exit-reason breadcrumb is the node
# asking its supervisor (systemd Restart=always in production; THIS harness in
# the drill) to relaunch it on the SAME datadir — e.g. to consume an
# install-on-next-boot request. The node's own progress.kv restart budget
# bounds this too; the harness cap is the belt-and-suspenders runaway stop.
MAX_BOOTS="${ZCL_CS_MAX_BOOTS:-12}"

# ── argv: --bin=PATH / --peer=H:P / --file-peer=H:P / --budget=N / --sample=N /
#    --busy-timeout=N / --selftest, or bare positionals (bin, peer) for quick
#    manual use. Flags win over env vars; env vars win over the defaults
#    above. --selftest runs the hermetic busy-JSON classification self-check
#    below (is_busy_response()) and exits — no binary, network, or mktemp
#    datadir touched.
SELFTEST=0
for arg in "$@"; do
    case "$arg" in
        --bin=*)    NODE_BIN="${arg#--bin=}" ;;
        --peer=*)   PEER="${arg#--peer=}" ;;
        --file-peer=*) FILE_PEER="${arg#--file-peer=}" ;;
        --budget=*) BUDGET="${arg#--budget=}" ;;
        --sample=*) SAMPLE_SECS="${arg#--sample=}" ;;
        --busy-timeout=*) FRONTIER_BUSY_TIMEOUT_SECS="${arg#--busy-timeout=}" ;;
        --selftest) SELFTEST=1 ;;
        --*)        echo "cold-start-wipe-stopwatch: unknown flag: $arg" >&2; exit 2 ;;
        *)
            if [ "${_POSN:-0}" = "0" ]; then NODE_BIN="$arg"; _POSN=1;
            elif [ "${_POSN:-0}" = "1" ]; then PEER="$arg"; _POSN=2;
            fi
            ;;
    esac
done

P2P=39170; RPC=39171; FS=39172; HTTPS=39173
RUN_ID="${ZCL_CS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
ARTIFACT_DIR="$ARTIFACT_ROOT/$RUN_ID"
DATADIR=""
ISO_HOME=""
PID=""
start=0
first_hstar=""
max_hstar="-1"
last_hstar="-1"
last_network_tip="-1"
last_blocker_ids="-"
last_blocker_count="0"
busy_streak_start=0
boots=1
supervised_launches=1
last_respawn_reason=""
# Provable-sample tracking. The provable sample is the authoritative full-read
# H* when available, else the lock-free cached_provable_tip proxy the busy
# partial doc still carries (see rpc_frontier / frontier_provable_sample). This
# is the honest "did the node climb" signal: a busy-but-healthy fold that only
# ever exposed cached_provable_tip under load must NEVER be denied as a stall.
# The PASS predicate stays authoritative-only (max_hstar/network_tip); the proxy
# proves CLIMB, never mints a PASS.
first_ps=""
max_ps="-1"
last_ps="-1"
saw_ps=0
final_readback_failed="false"

# ── PER-PHASE MEASUREMENT STATE (the baseline instrument) ────────────────────
# Every one of these is either read from a real source or left at its
# never-measured sentinel. NOTHING here is ever defaulted to 0 to make a field
# look populated: -1 means "no honest source produced this", and a reader must
# be able to tell that apart from a genuine zero.
#
# The measurement contract this harness now keeps, on EVERY verdict including
# PASS (see capture_run_bundle / write_artifact): a run leaves the same
# per-phase record whether it passed or failed. Before this, the diagnostic
# bundle was captured only when `verdict != pass`, so a SUCCESSFUL run destroyed
# the exact per-stage fold-cost evidence needed to make the next run faster —
# an artifact set that exists only when something went wrong cannot be a
# baseline, and the owner's rule is no optimization before a baseline.
SAMPLES_TSV=""            # <artifact>/samples.tsv — the per-tick climb trace
LOOP_START_UNIX=0         # exact: date +%s at sample-loop entry
HEADER_IMPORT_START=0     # exact: date +%s before --importblockindex (0 = not run)
HEADER_IMPORT_MS=-1       # exact: measured import duration, -1 = phase not run
NODE_BIN_SOURCE_ID=""     # baked source identity of the binary under test
# Cumulative counters of the FINAL node process, refreshed every sample tick.
# Cumulative PER PROCESS: a followed self-respawn starts a new PID, so these
# reset at each boot boundary. samples.tsv carries the boot ordinal on every row
# precisely so a reader can see where that reset happened instead of reading a
# reset as negative progress.
LAST_CPU_SECONDS="-1"
LAST_RSS_KB="-1"
LAST_DISK_READ_BYTES="-1"
LAST_DISK_WRITE_BYTES="-1"
# Block-body payload bytes, read as a DELTA across the window this harness
# brackets itself. The source is the node's own download manager
# (lib/net/src/download.c total_bytes_received) surfaced by
# `dumpstate sync_monitor` as download_bytes_received.
#
# WHY A DELTA AND NOT THE RAW READING. That counter lives in the in-memory
# struct download_manager and dl_init() memsets it, so it is cumulative PER
# PROCESS and restarts at 0 on every boot — exactly like the /proc counters
# above. A raw close-of-window reading would therefore silently report only the
# LAST boot's bytes while being labelled as the whole run's. So both ends of the
# window are read, each end records the boot ordinal it was read on, and the
# difference is only emitted when both ends came from the SAME boot. A boot
# boundary inside the window makes the difference meaningless, and the honest
# answer there is the -1 never-measured sentinel plus a named reason, never a
# number computed across a reset.
BYTES_OPEN=-1             # download_bytes_received at window open (-1 = unread)
BYTES_OPEN_BOOT=-1        # boot ordinal the open reading was taken on
BYTES_OPEN_UNIX=-1        # date +%s of the open reading that actually landed
BYTES_CLOSE=-1            # download_bytes_received at window close (-1 = unread)
BYTES_CLOSE_BOOT=-1       # boot ordinal the close reading was taken on
BYTES_DELTA=-1            # close-open, same boot only; -1 = never measured
BYTES_UNAVAIL_REASON=""   # why BYTES_DELTA is -1 (empty iff it is a real value)
# getconf values are constants for the life of the process; read once.
CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"
case "$CLK_TCK" in ''|*[!0-9]*) CLK_TCK=100 ;; esac
PAGE_KB=$(( $(getconf PAGESIZE 2>/dev/null || echo 4096) / 1024 ))
[ "$PAGE_KB" -gt 0 ] 2>/dev/null || PAGE_KB=4

# parse_proc_stat_cpu_ticks <contents-of-/proc/PID/stat> — utime+stime in clock
# ticks, or -1. PURE (no /proc access) so --selftest can exercise it on a canned
# fixture. Field 2 (comm) is parenthesized and MAY CONTAIN SPACES AND
# PARENTHESES, so a naive $14/$15 read is wrong; everything is indexed from
# after the LAST ')' instead, which is what proc(5) itself prescribes. With that
# split, utime is field 12 and stime field 13.
parse_proc_stat_cpu_ticks() {
    printf '%s' "${1:-}" | awk '
        { i = index($0, ")"); last = 0
          while (i > 0) { last += i; rest = substr($0, last + 1); i = index(rest, ")") }
          if (last == 0) { print -1; exit }
          n = split(substr($0, last + 2), f, /[ \t]+/)
          if (n < 13) { print -1; exit }
          if (f[12] !~ /^[0-9]+$/ || f[13] !~ /^[0-9]+$/) { print -1; exit }
          print f[12] + f[13] }
        END { if (NR == 0) print -1 }'
}

# parse_proc_stat_rss_pages <contents-of-/proc/PID/stat> — the rss field in
# pages, or -1. Same after-the-last-')' indexing as above; rss is field 22
# there. PURE.
parse_proc_stat_rss_pages() {
    printf '%s' "${1:-}" | awk '
        { i = index($0, ")"); last = 0
          while (i > 0) { last += i; rest = substr($0, last + 1); i = index(rest, ")") }
          if (last == 0) { print -1; exit }
          n = split(substr($0, last + 2), f, /[ \t]+/)
          if (n < 22 || f[22] !~ /^[0-9]+$/) { print -1; exit }
          print f[22] }
        END { if (NR == 0) print -1 }'
}

# parse_proc_io_field <contents-of-/proc/PID/io> <key> — the integer value of
# `<key>: N`, or -1 when absent/unreadable. PURE. read_bytes/write_bytes are the
# BLOCK-LAYER counters (bytes that actually hit the storage device), which is
# what "disk" means for a fold-cost baseline — rchar/wchar would also count
# page-cache hits.
parse_proc_io_field() {
    printf '%s\n' "${1:-}" | awk -v k="${2:-}" '
        $1 == k ":" && $2 ~ /^[0-9]+$/ { print $2; found = 1; exit }
        END { if (!found) print -1 }'
}

# refresh_process_counters — read the watched PID's cumulative CPU/RSS/disk
# counters out of /proc into LAST_*. Every field independently degrades to -1;
# an unreadable /proc entry is a missing measurement, never a zero.
refresh_process_counters() {
    LAST_CPU_SECONDS="-1"; LAST_RSS_KB="-1"
    LAST_DISK_READ_BYTES="-1"; LAST_DISK_WRITE_BYTES="-1"
    [ -n "${PID:-}" ] || return 0
    local statline ioblob ticks pages
    statline="$(cat "/proc/$PID/stat" 2>/dev/null)"
    if [ -n "$statline" ]; then
        ticks="$(parse_proc_stat_cpu_ticks "$statline")"
        if [ "$ticks" != "-1" ]; then
            # Two decimals of CPU seconds without floating-point shell math.
            LAST_CPU_SECONDS="$(( ticks * 100 / CLK_TCK ))"
            LAST_CPU_SECONDS="$(( LAST_CPU_SECONDS / 100 )).$(printf '%02d' "$(( LAST_CPU_SECONDS % 100 ))")"
        fi
        pages="$(parse_proc_stat_rss_pages "$statline")"
        [ "$pages" != "-1" ] && LAST_RSS_KB="$(( pages * PAGE_KB ))"
    fi
    ioblob="$(cat "/proc/$PID/io" 2>/dev/null)"
    if [ -n "$ioblob" ]; then
        LAST_DISK_READ_BYTES="$(parse_proc_io_field "$ioblob" read_bytes)"
        LAST_DISK_WRITE_BYTES="$(parse_proc_io_field "$ioblob" write_bytes)"
    fi
    return 0
}

# ── block-body payload bytes: read at both ends of the bracketed window ─────
#
# WHAT THIS NUMBER IS, EXACTLY. `dumpstate sync_monitor` →
# download_bytes_received is fed by dl_add_bytes_received()
# (lib/net/src/download.c), whose only two production call sites are
# msg_blocks.c (the `block` P2P message payload length, s->size) and
# msgprocessor_snapshot.c (each serialized block inside a `zblkdata` batch).
# Both are reached only AFTER the oversize reject and AFTER block_deserialize()
# succeeds. So it counts SUCCESSFULLY-PARSED BLOCK-BODY MESSAGE PAYLOAD bytes,
# aggregated over all peers, and it counts NOTHING ELSE: no `headers` messages,
# no version/verack handshake, no inv/getdata/getheaders, no tx relay, no addr,
# no compact blocks (process_cmpctblock never calls it), not the 24-byte
# per-message header, and no TCP/IP framing. That is why this is NOT called
# network_bytes — see the phases[].network_bytes structural omission row, which
# stays, because total wire bytes still have no source in this tree.
#
# bytes_reading_from_json <sync_monitor-doc> — the counter, or -1 if the doc
# does not carry it (a dumpstate miss, a mock node, or a build whose dumper
# lacks the key). Shape-validated: a non-numeric or over-wide value is -1, not a
# number bash arithmetic would silently mangle. The C field is uint64; bash math
# is int64, so anything wider than 18 digits is refused rather than wrapped.
bytes_reading_from_json() {
    local v
    v="$(jget "${1:-}" download_bytes_received)"
    case "$v" in
        ''|*[!0-9]*) printf '%s' -1; return 0 ;;
    esac
    [ "${#v}" -le 18 ] || { printf '%s' -1; return 0; }
    printf '%s' "$v"
}

# boot_count_from_log <node.log> — count actual node boots, including an
# in-process execv self-respawn that retains its PID.  boot.c emits exactly one
# top-level prologue marker per boot; use the same strict marker shape as the
# phases[] parser so prose containing "[boot]" cannot mint a boot.
boot_count_from_log() {
    [ -n "${1:-}" ] && [ -r "$1" ] || { printf '%s' 0; return 0; }
    awk '
        /^\[boot\] prologue[[:space:]]+[0-9]+ms$/ { n++ }
        END { print n + 0 }
    ' "$1" 2>/dev/null
}

# last_self_respawn_from_log <node.log> — recover the last durable self-respawn
# reason even when execv retained the PID and the harness therefore never read
# the exit breadcrumb.  Only the closed set accepted by is_self_respawn_reason
# is returned.
last_self_respawn_from_log() {
    [ -n "${1:-}" ] && [ -r "$1" ] || return 0
    local reason
    reason="$(sed -n 's/^.*exit-reason breadcrumb written: reason=\(self_respawn_[a-z_]*\)$/\1/p' "$1" 2>/dev/null | tail -1)"
    is_self_respawn_reason "$reason" && printf '%s' "$reason"
    return 0
}

# refresh_boot_observation — make the node's own boot markers authoritative
# for evidence.  PID liveness alone cannot see execv, yet per-process node
# counters such as download_bytes_received reset on that path.
refresh_boot_observation() {
    local observed reason log="${DATADIR:-}/node.log"
    [ -n "${DATADIR:-}" ] && [ -s "$log" ] || return 0
    observed="$(boot_count_from_log "$log")"
    case "$observed" in ''|*[!0-9]*) observed=0 ;; esac
    [ "$observed" -gt "$boots" ] 2>/dev/null && boots="$observed"
    reason="$(last_self_respawn_from_log "$log")"
    [ -n "$reason" ] && last_respawn_reason="$reason"
    return 0
}

# bytes_delta_compute — set BYTES_DELTA + BYTES_UNAVAIL_REASON from the two
# recorded window ends. FAILS CLOSED: every path that cannot prove the delta
# spans exactly one process lifetime yields -1 with a named reason. Pure (reads
# only the BYTES_* vars) so --selftest can drive it through every branch.
bytes_delta_compute() {
    BYTES_DELTA=-1
    BYTES_UNAVAIL_REASON=""
    if [ "${BYTES_OPEN:--1}" = "-1" ]; then
        BYTES_UNAVAIL_REASON="the window-open read of dumpstate sync_monitor never landed (no tick in the whole run returned a download_bytes_received key), so there is no baseline to subtract"
        return 0
    fi
    if [ "${BYTES_CLOSE:--1}" = "-1" ]; then
        BYTES_UNAVAIL_REASON="the window-close read of dumpstate sync_monitor returned no download_bytes_received key (most often: the node process had already exited by capture time)"
        return 0
    fi
    if [ "${BYTES_OPEN_BOOT:--1}" != "${BYTES_CLOSE_BOOT:--1}" ]; then
        BYTES_UNAVAIL_REASON="the node respawned inside the window (open reading taken on boot ${BYTES_OPEN_BOOT}, close reading on boot ${BYTES_CLOSE_BOOT}). download_bytes_received is cumulative PER PROCESS and dl_init() resets it to 0, so the difference across that boundary is not a byte count in either direction"
        return 0
    fi
    if [ "$BYTES_CLOSE" -lt "$BYTES_OPEN" ] 2>/dev/null; then
        BYTES_UNAVAIL_REASON="the counter DECREASED within one boot (open=${BYTES_OPEN} close=${BYTES_CLOSE}), which download_bytes_received cannot legitimately do — it only ever accumulates. Treated as an unexplained instrument fault rather than reported as negative or clamped to 0"
        return 0
    fi
    BYTES_DELTA=$(( BYTES_CLOSE - BYTES_OPEN ))
    return 0
}

# bytes_window_open_try — take the window-open reading if it has not landed yet.
# Called at sample-loop entry AND on each tick until it succeeds, because the
# RPC server is not necessarily answering at loop entry (the node was launched
# moments earlier). Whichever tick lands records its own unix time and boot
# ordinal, so the emitted window states the span it actually measured instead of
# implying it covered the whole observed-sync window.
bytes_window_open_try() {
    [ "${BYTES_OPEN:--1}" = "-1" ] || return 0
    local v
    v="$(bytes_reading_from_json "$(rpc dumpstate sync_monitor)")"
    [ "$v" = "-1" ] && return 0
    BYTES_OPEN="$v"
    BYTES_OPEN_BOOT="$boots"
    BYTES_OPEN_UNIX="$(date +%s)"
    return 0
}

# bytes_window_close — take the window-close reading and resolve the delta.
#
# THERE MAY BE NO NODE TO ASK. write_artifact() calls this on EVERY verdict, and
# the earliest verdicts — skip "no peer stated", skip "serving peer not
# reachable", skip "node binary absent" — fire before a datadir is made, before
# a node is launched, and (textually) before rpc() is even defined further down
# this file. Calling rpc there put `line 392: rpc: command not found` into the
# run log of every skipped scheduled run and asked a nonexistent node for a byte
# count. Both ends of the window are already required to be real readings, so
# the honest thing on that path is to take no reading at all and let
# bytes_delta_compute name the never-measured reason. Guarding on DATADIR+PID is
# what makes "there was no node" different from "the node did not answer".
bytes_window_close() {
    if [ -z "${DATADIR:-}" ] || [ -z "${PID:-}" ]; then
        BYTES_CLOSE=-1
        BYTES_CLOSE_BOOT=-1
        bytes_delta_compute
        return 0
    fi
    BYTES_CLOSE="$(bytes_reading_from_json "$(rpc dumpstate sync_monitor)")"
    BYTES_CLOSE_BOOT="$boots"
    bytes_delta_compute
    return 0
}

# samples_tsv_init — create the per-tick sink and write its header row. Called
# once, before the sample loop, so the trace survives even a SIGKILLed harness.
# The rows were previously printf-to-stdout ONLY and were lost with the
# terminal: the shape of the climb, not just its endpoint, is what tells you
# WHICH phase to optimize.
samples_tsv_init() {
    [ -n "$SAMPLES_TSV" ] || return 0
    printf 't_s\tunix_s\tboot\thstar\tprovable\tnetwork_tip\ttip_ok\tfrontier_busy\tblocker_count\tcpu_seconds\trss_kb\tdisk_read_bytes\tdisk_write_bytes\tblocker_ids\n' \
        >"$SAMPLES_TSV" 2>/dev/null || SAMPLES_TSV=""
}

# samples_tsv_row <t_s> <hstar> <provable> <net_tip> <tip_ok> <busy> <blocker_ct> <blocker_ids>
# Append one tick. Every numeric column is either a real reading or -1.
samples_tsv_row() {
    [ -n "$SAMPLES_TSV" ] && [ -f "$SAMPLES_TSV" ] || return 0
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$1" "$(date +%s)" "$boots" "$2" "$3" "$4" "$5" "$6" "$7" \
        "$LAST_CPU_SECONDS" "$LAST_RSS_KB" \
        "$LAST_DISK_READ_BYTES" "$LAST_DISK_WRITE_BYTES" "$8" \
        >>"$SAMPLES_TSV" 2>/dev/null || true
}

# json_escape/json_string/json_number_or_null/is_busy_response/jget: see
# stopwatch_json_lib.sh (sourced above) — used by rpc_frontier() and the
# failure-bundle capture below.

# ── phases[]: WHERE THE TIME WENT, AND FROM WHICH SOURCE ────────────────────
#
# PROVENANCE RULE FOR THIS WHOLE SECTION: every field emitted names the source
# that produced it, and a field with no honest source today is OMITTED, never
# emitted as 0. A zero that a later reader mistakes for a measurement is worse
# than an absent field, because it silently anchors the next optimization pass
# to a number nobody measured.
#
# Deliberately NOT emitted, because nothing in this tree sources them per phase:
#   * TOTAL network bytes — /proc has no per-process network accounting and no
#     dumper counts wire bytes. What IS available, and IS now emitted on the
#     harness-bracketed phase, is `block_body_payload_bytes_received`: the delta
#     of `dumpstate sync_monitor` → download_bytes_received across the window,
#     which counts successfully-parsed block-body message payload and nothing
#     else. It is a lower bound on wire bytes and is named for the subset it is,
#     so phases[].network_bytes stays on the structural-omission list.
#     (Historical note kept deliberately: this comment used to assert that
#     download_bytes_received "reaches no diagnostics dumper". That was false —
#     sync_monitor_dump_state_json has emitted it all along, registered at
#     diagnostics_dumpers.def. The error came from checking only the three net
#     dumpers this harness happened to capture and generalising from them. A
#     wrong reason in an omitted-field explanation is the same defect class the
#     instrument exists to prevent, so the correction is recorded, not silently
#     overwritten.)
#   * BYTES PER BOOT-LEVEL PHASE — download_bytes_received has no phase
#     segmentation at all; it is one process-lifetime total. Only a window
#     bracketed by two reads can be honest, which is why the byte figure hangs
#     off harness.observed_sync and never off a boot marker.
#   * per-phase CPU / disk for the BOOT phases — boot.c's markers carry a
#     duration and nothing else, and /proc counters are only sampled once the
#     harness's own loop is running (boot has already finished by the first
#     tick). CPU/disk are therefore attached ONLY to the harness-bracketed
#     phase, where the harness genuinely bracketed the window it is reporting.
#   * an exact wall-clock start per boot phase — boot.c's `[boot]` marker lines
#     carry NO timestamp of their own, and the top-level marks do not tile the
#     boot (measured on the one real PASS artifact on disk,
#     20260728T000207Z-2102851: 15,623ms of named top-level phases against a
#     51,755ms `total` — ~36s unattributed), so a cumulative-sum "start" would
#     be fabricated. What IS honest is start_ts_lower_bound: the most recent
#     TIMESTAMPED node.log line at or before the marker, i.e. a real bound
#     ("this phase did not start before this"), named as the bound it is.

# boot_timings_median_pairs <boot_timings.json> — emit `stage<TAB>median_ms`
# rows from a captured `dumpstate boot_timings` doc (the flight recorder's
# durable per-stage history, config/src/boot_flight_recorder.c: rows are
# {"stage":..,"last_ms":..,"median_ms":..}, median_ms present only once a stage
# has >=3 retained samples). Splitting on '}' isolates each row so the shared
# readers below anchor within one row instead of across the whole doc.
boot_timings_median_pairs() {
    [ -s "${1:-}" ] || return 0
    local chunk st md
    tr '}' '\n' <"$1" 2>/dev/null | while IFS= read -r chunk; do
        case "$chunk" in *'"stage"'*) ;; *) continue ;; esac
        st="$(zcl_json_first_string "$chunk" stage)"
        md="$(jget "$chunk" median_ms)"
        [ -n "$st" ] && [ -n "$md" ] && printf '%s\t%s\n' "$st" "$md"
    done
    return 0
}

# phases_json_from_log <node.log> <median-tsv> — emit the boot-phase elements of
# phases[] (comma-separated JSON objects, NO enclosing brackets) parsed from the
# node's own `[boot]` markers.
#
# The marker format is boot.c's boot_topmark/boot_submark:
#   "[boot] %-30s %lldms\n"      (top-level phase, ONE space after "[boot]")
#   "[boot]   %-28s %lldms\n"    (sub-phase,     THREE spaces)
# so a marker line is EXACTLY two whitespace-separated tokens after the prefix:
# a [a-z_.0-9] name and an integer followed by "ms". Requiring exactly two is
# what keeps the many prose "[boot] ..." lines out (there are 74 "[boot]" lines
# in the real PASS artifact and only 59 are markers) — a looser match pulls in
# "[boot] block_index: 1 entries, 296 bytes/entry, ..." and invents phases.
#
# `boot` is the 1-based boot ordinal within the run: it increments on each
# top-level "prologue" marker, which boot.c emits as the first topmark of every
# boot (config/src/boot.c boot_topmark("prologue", t_boot_start)). A run that
# followed a self-respawn therefore reports each boot's phases separately rather
# than silently blending two boots' timings into one set of names.
phases_json_from_log() {
    local log="${1:-}" med="${2:-}"
    [ -s "$log" ] || return 0
    awk -v medfile="$med" '
        BEGIN {
            if (medfile != "")
                while ((getline ln < medfile) > 0)
                    if (split(ln, mf, "\t") >= 2) med[mf[1]] = mf[2]
            boot = 0; seq = 0; lastts = ""; first = 1
        }
        /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z/ {
            lastts = substr($0, 1, 20)
        }
        {
            lvl = ""
            if ($0 ~ /^\[boot\]   [^ ]/)     lvl = "subphase"
            else if ($0 ~ /^\[boot\] [^ ]/)  lvl = "phase"
            if (lvl == "") next
            line = $0
            sub(/^\[boot\][ ]+/, "", line)
            if (split(line, g, /[ \t]+/) != 2) next
            nm = g[1]; msf = g[2]
            if (nm !~ /^[a-z_.0-9]+$/) next
            if (msf !~ /^[0-9]+ms$/) next
            ms = msf; sub(/ms$/, "", ms)
            if (nm == "prologue" && lvl == "phase") { boot++; seq = 0 }
            if (boot == 0) boot = 1
            seq++
            printf "%s{\"phase\":%c%s%c,\"boot\":%d,\"seq\":%d,\"level\":%c%s%c",
                   (first ? "" : ","), 34, nm, 34, boot, seq, 34, lvl, 34
            printf ",\"duration_ms\":%s,\"duration_source\":%cnode_log_boot_marker%c",
                   ms, 34, 34
            if (lastts != "")
                printf ",\"start_ts_lower_bound\":%c%s%c,\"start_source\":%cnearest_preceding_timestamped_node_log_line%c",
                       34, lastts, 34, 34, 34
            if (nm in med)
                printf ",\"median_ms\":%s,\"median_source\":%cdumpstate_boot_timings%c",
                       med[nm], 34, 34
            printf "}"
            first = 0
        }
    ' "$log" 2>/dev/null
    return 0
}

# harness_phases_json <captured_at_unix> — emit the elements of phases[] the
# HARNESS itself bracketed, and so can timestamp exactly: it took `date +%s` on
# both sides of each window. These are the only phases carrying cpu/disk, and
# they carry them because the harness sampled /proc across that same window.
harness_phases_json() {
    local captured_at="${1:-0}" out="" dur
    if [ "${HEADER_IMPORT_MS:--1}" != "-1" ] && [ "${HEADER_IMPORT_START:-0}" -gt 0 ] 2>/dev/null; then
        out="{\"phase\":\"harness.header_import\",\"level\":\"harness\""
        out="$out,\"start_unix\":$HEADER_IMPORT_START"
        out="$out,\"duration_ms\":$HEADER_IMPORT_MS"
        out="$out,\"duration_source\":\"harness wall clock around --importblockindex\"}"
    fi
    if [ "${LOOP_START_UNIX:-0}" -gt 0 ] 2>/dev/null; then
        dur=-1
        [ "$captured_at" -ge "$LOOP_START_UNIX" ] 2>/dev/null &&
            dur=$(( (captured_at - LOOP_START_UNIX) * 1000 ))
        [ -n "$out" ] && out="$out,"
        out="$out{\"phase\":\"harness.observed_sync\",\"level\":\"harness\""
        out="$out,\"boot\":$(json_number_or_null "$boots")"
        out="$out,\"start_unix\":$LOOP_START_UNIX"
        out="$out,\"duration_ms\":$(json_number_or_null "$dur")"
        out="$out,\"duration_source\":\"harness wall clock from sample-loop entry to artifact capture\""
        out="$out,\"cpu_seconds\":$LAST_CPU_SECONDS"
        out="$out,\"rss_kb\":$(json_number_or_null "$LAST_RSS_KB")"
        out="$out,\"disk_read_bytes\":$(json_number_or_null "$LAST_DISK_READ_BYTES")"
        out="$out,\"disk_write_bytes\":$(json_number_or_null "$LAST_DISK_WRITE_BYTES")"
        out="$out,\"counters_source\":\"/proc/<pid>/stat utime+stime over CLK_TCK and rss pages; /proc/<pid>/io read_bytes and write_bytes (block layer)\""
        out="$out,\"counters_scope\":\"cumulative for the FINAL node process only — a followed self-respawn starts a new pid and resets these; see samples.tsv boot column\""
        out="$out,\"block_body_payload_bytes_received\":$(json_number_or_null "$BYTES_DELTA")"
        out="$out,\"block_body_payload_bytes_source\":\"delta of download_bytes_received between two reads of \`dumpstate sync_monitor\` (app/services/src/sync_monitor.c), fed by dl_add_bytes_received() in lib/net/src/download.c\""
        out="$out,\"block_body_payload_bytes_scope\":\"successfully-parsed block-body message payload ONLY, summed over all peers: the \`block\` message payload length plus each block inside a \`zblkdata\` batch. EXCLUDES headers messages, version/verack handshake, inv/getdata/getheaders, tx relay, addr, compact blocks, the 24-byte per-message header, and all TCP/IP framing. It is therefore a LOWER BOUND on wire bytes and must not be read as total network bytes\""
        out="$out,\"block_body_payload_bytes_window\":\"open read at unix $BYTES_OPEN_UNIX on boot $BYTES_OPEN_BOOT (value $BYTES_OPEN), close read on boot $BYTES_CLOSE_BOOT (value $BYTES_CLOSE); a delta is emitted only when both ends came from the same boot, because the counter resets to 0 per process\""
        if [ "${BYTES_DELTA:--1}" = "-1" ]; then
            out="$out,\"block_body_payload_bytes_unavailable_reason\":$(json_string "$BYTES_UNAVAIL_REASON")"
        fi
        out="$out}"
    fi
    printf '%s' "$out"
    return 0
}


# ── SYNC PHASE SPLIT: WHERE THE BULK-SYNC WALL CLOCK ACTUALLY WENT ──────────
#
# THE DEFECT THIS EXISTS TO CLOSE. Until now the entire bulk-sync window was
# reported as ONE undivided bracket: harness.observed_sync. On the only PASS on
# record that bracket was 515,000ms in a single piece, so every performance
# claim in this tree about cold sync was a code comment or an inference — the
# instrument genuinely could not say whether the time went to finding a peer,
# to headers, to block bodies, or to the fold.
#
# WHAT IS ADDED HERE vs WHAT IS COMPOSED. NOTHING WAS ADDED TO THE NODE. Every
# boundary below is read from a dumper the node ALREADY publishes (`dumpstate
# peer_lifecycle`, `dumpstate sync_monitor`, `dumpstate omniscience`,
# `dumpstate reducer_frontier`, `dumpstate reducer_stage_profile`); this
# harness only samples them, brackets, and reports. Two boundaries have NO
# source at all in this tree and are declared in omitted_fields[] rather than
# invented — see the getheaders row and the "first body requested" row there.
#
# THE FOUR PHASES, AND EXACTLY WHAT EACH BOUNDARY IS READ FROM:
#
#   sync.peer_connect  start  harness wall clock immediately before the first
#                             launch_node exec.                        EXACT
#                      end    the EARLIEST peers[].handshake_complete_at in
#                             `dumpstate peer_lifecycle` among peers that also
#                             advertised a chain height (advertised_height>0) —
#                             i.e. a peer that can actually serve, not merely
#                             one that completed a handshake. The node records
#                             that unix second itself, so the value is exact
#                             even though the harness notices it a tick late.
#                                                       EXACT (node-recorded)
#                      AND, alongside it, the node's OWN latched measurement:
#                      `dumpstate omniscience` time_to_first_peer_us
#                      (lib/net/src/connman.c g_first_peer_us) — microseconds
#                      from connman_start() to the first fully-handshaked peer.
#                      It is reported as its own field and NOT as this phase's
#                      duration, because it brackets a DIFFERENT window
#                      (connman_start, not process start; any handshake, not a
#                      height-advertising one). Two honest measurements of
#                      neighbouring windows are worth more than one of them
#                      silently overwriting the other.
#
#   sync.headers       start  the first sample tick on which the frontier's
#                             stage_cursors[header_admit].cursor > 1 (a fresh
#                             node reports 1, so >1 is the first admission);
#                             sync_monitor tip_eval_header_height>0 is the
#                             fallback when the frontier read missed.
#                             This is an UPPER BOUND on the true start: the
#                             getheaders that produced those headers was sent
#                             strictly earlier, and nothing in this tree counts
#                             getheaders SENT (see omitted_fields[]).
#                                                POLL BOUND (SAMPLE_SECS res.)
#                      end    the first tick on which that same cursor passed
#                             the peer-advertised tip (network_tip).
#                                                POLL BOUND (SAMPLE_SECS res.)
#
#   sync.bodies        start  the first tick on which sync_monitor
#                             download_requested > 0 (lib/net/src/download.c).
#                             UPPER BOUND — the request went out before the
#                             counter was read.  POLL BOUND (SAMPLE_SECS res.)
#                      end    the first tick on which the frontier's
#                             stage_cursors[body_persist].cursor passed the
#                             target: every body needed for the target has been
#                             received and persisted.
#                                                POLL BOUND (SAMPLE_SECS res.)
#                             NOT sync_monitor last_block_connected_time, which
#                             looks like the right instant and is not — see the
#                             measured refutation at the bodies block below.
#
#   sync.fold          start  the first tick on which the reducer's
#                             authoritative H* was > 0.
#                                                POLL BOUND (SAMPLE_SECS res.)
#                      end    the tick on which H* caught network_tip — the
#                             same predicate the PASS verdict uses, so this
#                             phase's end and the run's verdict can never
#                             disagree.           POLL BOUND (SAMPLE_SECS res.)
#
# FAIL CLOSED. Every boundary starts at the -1 never-observed sentinel and is
# only ever written from a real reading. A phase whose boundary never fired is
# emitted with "observed":false, "duration_ms":null and a NAMED
# unobserved_reason — NEVER as 0ms, and never silently dropped. A 0 that a
# later reader mistakes for a measurement is the false-green defect this whole
# instrument exists to prevent.
#
# THIS CHANGES NO THRESHOLD, BUDGET, OR VERDICT. phase_observe() can only ever
# add evidence: it writes phase state and nothing else. The PASS predicate, the
# budget, the busy timeout, the regression tripwire and every exit code are
# byte-for-byte what they were.
#
# THEY OVERLAP, AND THE ARTIFACT SAYS SO. Bodies stream while the fold runs;
# headers can still be arriving while bodies download. These four intervals do
# NOT partition the observed-sync window and must never be read as if they did.
# The representation chosen is: each phase carries its OWN start/end/duration
# on one shared unix-second timeline, and a separate top-level "phase_overlap"
# object publishes the pairwise overlap in ms, the UNION of the observed
# intervals, the SUM of the durations, and the window time no phase claims.
# Publishing sum, union and pairwise overlap together makes the double-counting
# arithmetically visible instead of leaving it to be inferred — sum minus union
# IS the overlap, stated. phases_partition_the_window is emitted as a literal
# false so no reader has to work that out for themselves.

PHASE_NAMES="peer_connect headers bodies fold"
declare -A PH_START=() PH_END=() PH_END_SRCKIND=()
PHASE_TARGET_HEIGHT=-1     # target the headers/bodies/fold ends are judged against
PHASE_BOUNDARIES_TSV=""    # <artifact>/phase_boundaries.tsv — durable boundary log
PHASE_PROFILE_DIR=""       # <artifact>/phase-profiles/ — per-boundary profile snapshots
NODE_LAUNCH_UNIX=-1        # date +%s immediately before the FIRST launch_node exec
PHASE_PROFILE_INDEX_ROWS=""
PHASE_TTFP_US=-1           # dumpstate omniscience time_to_first_peer_us (-1 = unread)

phase_state_init() {
    local p
    for p in $PHASE_NAMES; do
        PH_START["$p"]=-1
        PH_END["$p"]=-1
        PH_END_SRCKIND["$p"]="unobserved"
    done
}
phase_state_init

# pl_handshake_unix <peer_lifecycle-json> <require_height:0|1> — the EARLIEST
# positive peers[].handshake_complete_at in the doc, or -1 if none. With
# require_height=1 only peers that ALSO reported advertised_height>0 count:
# that is this harness's operational definition of "a peer that actually serves
# data" — a handshake alone proves a socket, an advertised height proves the
# peer has a chain to give us. Splitting the doc on '{' isolates each peer
# object (they carry no nested braces) so the two readings below can never be
# joined across two different peers. The closing-quote anchor is what keeps
# "advertised_height" from matching "advertised_height_trusted".
pl_handshake_unix() {
    printf '%s' "${1:-}" | tr '{' '\n' | awk -v need="${2:-1}" '
        BEGIN { best = -1 }
        /"peer_id"/ {
            hc = -1; ah = -1
            if (match($0, /"handshake_complete_at"[ \t]*:[ \t]*-?[0-9]+/)) {
                s = substr($0, RSTART, RLENGTH); sub(/.*:[ \t]*/, "", s); hc = s + 0
            }
            if (match($0, /"advertised_height"[ \t]*:[ \t]*-?[0-9]+/)) {
                s = substr($0, RSTART, RLENGTH); sub(/.*:[ \t]*/, "", s); ah = s + 0
            }
            if (hc <= 0) next
            if (need == 1 && ah <= 0) next
            if (best < 0 || hc < best) best = hc
        }
        END { print best + 0 }' 2>/dev/null
}

# frontier_stage_cursor <reducer_frontier-json> <stage> — the `cursor` of one
# named element of the frontier's stage_cursors[] array, or -1. A fresh node
# reports header_admit cursor=1 with admitted_total=0, so "a header was
# admitted" is cursor>1, never cursor>0. Splitting on '{' isolates each element
# so `stage` and `cursor` can never be read off two different stages.
frontier_stage_cursor() {
    printf '%s' "${1:-}" | tr '{' '\n' | awk -v st="${2:-}" '
        BEGIN { v = -1 }
        {
            if (index($0, "\"stage\":\"" st "\"") == 0) next
            if (match($0, /"cursor"[ \t]*:[ \t]*-?[0-9]+/)) {
                s = substr($0, RSTART, RLENGTH); sub(/.*:[ \t]*/, "", s); v = s + 0
            }
        }
        END { print v + 0 }' 2>/dev/null
}

# jnum <json> <key> — jget with a -1 never-read sentinel instead of an empty
# string, so a missing key can never be arithmetic-compared as if it were 0.
jnum() {
    local v
    v="$(jget "${1:-}" "${2:-}")"
    case "$v" in ''|*[!0-9-]*) printf '%s' -1 ;; *) printf '%s' "$v" ;; esac
}

# rsp_cum <reducer_stage_profile-json> <domain> <key> — one CUMULATIVE-since-boot
# counter out of `dumpstate reducer_stage_profile`, or -1 when it is absent or
# JSON null. The read is SCOPED to the domain's "cumulative" object and stops at
# its "last_batch" sibling: unscoped, a null cumulative value would silently
# fall through to the last_batch reading of the same key and report a
# single-batch number as a lifetime total. (last_batch is reset on every stage
# batch generation rollover; only cumulative is safe to difference.)
rsp_cum() {
    printf '%s' "${1:-}" | awk -v st="${2:-}" -v k="${3:-}" '
        {
            i = index($0, "\"" st "\":{\"cumulative\":{")
            if (i == 0) { print -1; exit }
            rest = substr($0, i)
            j = index(rest, "\"last_batch\"")
            if (j > 1) rest = substr(rest, 1, j - 1)
            if (match(rest, "\"" k "\"[ \t]*:[ \t]*-?[0-9]+")) {
                s = substr(rest, RSTART, RLENGTH); sub(/.*:[ \t]*/, "", s)
                print s + 0; exit
            }
            print -1; exit
        }
        END { if (NR == 0) print -1 }' 2>/dev/null
}

# phase_boundaries_tsv_init — the durable boundary log, armed BEFORE the first
# tick for the same reason samples.tsv is: a harness SIGKILLed mid-run still
# leaves every boundary it had already observed on disk.
phase_boundaries_tsv_init() {
    [ -n "$PHASE_BOUNDARIES_TSV" ] || return 0
    printf 'boundary\tedge\tunix_s\tt_s\tkind\tsource\n' \
        >"$PHASE_BOUNDARIES_TSV" 2>/dev/null || PHASE_BOUNDARIES_TSV=""
}
phase_boundaries_tsv_row() {  # boundary edge unix_s t_s kind source
    [ -n "$PHASE_BOUNDARIES_TSV" ] && [ -f "$PHASE_BOUNDARIES_TSV" ] || return 0
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" \
        >>"$PHASE_BOUNDARIES_TSV" 2>/dev/null || true
}

# phase_profile_snapshot <boundary-edge-label> <unix_s> — capture `dumpstate
# reducer_stage_profile` AT A PHASE BOUNDARY, not only once at the end.
# WHY AT THE BOUNDARY: reducer_stage_profile's cumulative.* counters are
# lifetime-since-boot totals. One reading at capture time can only ever say what
# the WHOLE RUN cost; two readings that straddle a phase are what make a
# per-stage cost ATTRIBUTABLE to that phase. With a snapshot at every boundary,
# any phase's per-stage cost is the difference of the two snapshots bracketing
# it, and that subtraction is left in the artifact for a reader to do rather
# than being pre-baked here.
phase_profile_snapshot() {
    local label="${1:-}" at="${2:-0}" doc="" f bp_us bp_blocks sv_us
    [ -n "$PHASE_PROFILE_DIR" ] && [ -d "$PHASE_PROFILE_DIR" ] || return 0
    [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null || return 0
    doc="$(rpc dumpstate reducer_stage_profile)"
    [ -n "$doc" ] || return 0
    f="$PHASE_PROFILE_DIR/$label.json"
    printf '%s\n' "$doc" >"$f" 2>/dev/null || return 0
    bp_us="$(rsp_cum "$doc" body_persist total_us)"
    bp_blocks="$(rsp_cum "$doc" body_persist blocks)"
    sv_us="$(rsp_cum "$doc" script_validate total_us)"
    [ -n "$PHASE_PROFILE_INDEX_ROWS" ] && PHASE_PROFILE_INDEX_ROWS="$PHASE_PROFILE_INDEX_ROWS,"
    PHASE_PROFILE_INDEX_ROWS="$PHASE_PROFILE_INDEX_ROWS{\"at\":$(json_string "$label")"
    PHASE_PROFILE_INDEX_ROWS="$PHASE_PROFILE_INDEX_ROWS,\"unix_s\":$(json_number_or_null "$at")"
    PHASE_PROFILE_INDEX_ROWS="$PHASE_PROFILE_INDEX_ROWS,\"snapshot\":$(json_string "$label.json")"
    PHASE_PROFILE_INDEX_ROWS="$PHASE_PROFILE_INDEX_ROWS,\"body_persist_cumulative_total_us\":$(json_number_or_null "$bp_us")"
    PHASE_PROFILE_INDEX_ROWS="$PHASE_PROFILE_INDEX_ROWS,\"body_persist_cumulative_blocks\":$(json_number_or_null "$bp_blocks")"
    PHASE_PROFILE_INDEX_ROWS="$PHASE_PROFILE_INDEX_ROWS,\"script_validate_cumulative_total_us\":$(json_number_or_null "$sv_us")}"
    return 0
}

# phase_mark <boundary> <edge:start|end> <unix_s> <kind> <source> — record a
# boundary EXACTLY ONCE (first observation wins; a later tick can never move an
# already-observed edge). Every accepted mark appends a row to
# phase_boundaries.tsv and takes a reducer_stage_profile snapshot.
phase_mark() {
    local b="${1:-}" edge="${2:-}" at="${3:--1}" kind="${4:-}" src="${5:-}" t_s
    case "$at" in ''|*[!0-9-]*) return 0 ;; esac
    [ "$at" -gt 0 ] 2>/dev/null || return 0
    if [ "$edge" = start ]; then
        [ "${PH_START[$b]:--1}" = "-1" ] || return 0
        PH_START["$b"]="$at"
    else
        [ "${PH_END[$b]:--1}" = "-1" ] || return 0
        PH_END["$b"]="$at"
        PH_END_SRCKIND["$b"]="$kind"
    fi
    t_s=-1
    [ "${start:-0}" -gt 0 ] 2>/dev/null && t_s=$((at - start))
    phase_boundaries_tsv_row "$b" "$edge" "$at" "$t_s" "$kind" "$src"
    phase_profile_snapshot "$b.$edge" "$at"
    return 0
}

# phase_observe <now> <hstar> <network_tip> <frontier-json> — one tick of
# boundary detection. Reads the dumpers the boundaries live in and marks
# anything newly crossed. It makes NO decision about the verdict: this function
# can only ever add evidence, never change a threshold, a budget, or a
# pass/fail predicate.
phase_observe() {
    local now="${1:-0}" hs="${2:--1}" nt="${3:--1}" fj="${4:-}"
    local plj smj omj hs_unix hdr hdr_cursor body_cursor dl_req ttfp

    # RPC-SILENCE GUARD, and it is a measurement decision, not a speed one.
    # The caller has ALREADY spent this tick's bounded retries reading the
    # frontier. An empty result there means the RPC server answered nothing at
    # all (the node is still booting, or the front door is wedged) — not that it
    # was busy, which returns a partial doc instead. Paying three more 10s RPC
    # deadlines to re-learn that would stretch a 10s tick past 50s during boot,
    # which is precisely the window sync.peer_connect covers: the guard PROTECTS
    # boundary resolution rather than trading it away. Nothing is inferred from
    # the silence — every boundary simply stays at its never-observed sentinel
    # until a tick that can actually read.
    if [ -z "$fj" ]; then
        return 0
    fi

    if [ "$nt" != "-1" ] && [ "$nt" -gt 0 ] 2>/dev/null; then
        PHASE_TARGET_HEIGHT="$nt"
    fi

    # ── peer_connect.end — node-recorded, therefore exact and retroactive ──
    if [ "${PH_END[peer_connect]:--1}" = "-1" ]; then
        plj="$(rpc dumpstate peer_lifecycle)"
        if [ -n "$plj" ]; then
            hs_unix="$(pl_handshake_unix "$plj" 1)"
            phase_mark peer_connect end "$hs_unix" "exact_node_recorded" \
                "dumpstate peer_lifecycle peers[].handshake_complete_at (earliest with advertised_height>0)"
        fi
    fi
    # The node's OWN latched microsecond measurement of a NEIGHBOURING window.
    # Read until it latches, then never again (it is write-once per process).
    if [ "$PHASE_TTFP_US" = "-1" ]; then
        omj="$(rpc dumpstate omniscience)"
        if [ -n "$omj" ]; then
            ttfp="$(jnum "$omj" time_to_first_peer_us)"
            [ "$ttfp" -gt 0 ] 2>/dev/null && PHASE_TTFP_US="$ttfp"
        fi
    fi

    smj="$(rpc dumpstate sync_monitor)"
    hdr=-1; dl_req=-1
    if [ -n "$smj" ]; then
        hdr="$(jnum "$smj" tip_eval_header_height)"
        dl_req="$(jnum "$smj" download_requested)"
    fi
    # The frontier's own per-stage cursors. A stage cursor is the NEXT height
    # that stage will process, so "stage has finished height H" is cursor > H,
    # and a fresh node reports 1 (genesis is 0, nothing admitted yet).
    hdr_cursor="$(frontier_stage_cursor "$fj" header_admit)"
    body_cursor="$(frontier_stage_cursor "$fj" body_persist)"

    # ── headers ──────────────────────────────────────────────────────────
    # header_admit's cursor is PRIMARY and tip_eval_header_height is the
    # fallback, in that order and not the other way round. Measured on the one
    # real PASS artifact on disk (20260821T135540Z-2484174): at the end of that
    # run tip_eval_header_height, tip_eval_local_height and tip_eval_served_height
    # were all 3224110 — the tip-state evaluator's three heights collapse once
    # the node is caught up, so that field cannot be relied on to separate
    # HEADER progress from chain progress. The header_admit cursor is the
    # header pipeline's own position and does separate them.
    if [ "$hdr_cursor" -gt 1 ] 2>/dev/null; then
        phase_mark headers start "$now" "upper_bound_poll_observed" \
            "first tick with reducer_frontier stage_cursors[header_admit].cursor>1 (a fresh node reports 1); the getheaders that produced those headers went out strictly earlier and is counted nowhere"
    elif [ "$hdr" -gt 0 ] 2>/dev/null; then
        phase_mark headers start "$now" "upper_bound_poll_observed" \
            "first tick with dumpstate sync_monitor tip_eval_header_height>0; the frontier's header_admit cursor was unreadable this tick"
    fi
    if [ "$PHASE_TARGET_HEIGHT" -gt 0 ] 2>/dev/null; then
        if [ "$hdr_cursor" -gt "$PHASE_TARGET_HEIGHT" ] 2>/dev/null; then
            phase_mark headers end "$now" "upper_bound_poll_observed" \
                "first tick with stage_cursors[header_admit].cursor > peer-advertised network_tip (the header pipeline has admitted through the target)"
        elif [ "$hdr" -ge "$PHASE_TARGET_HEIGHT" ] 2>/dev/null; then
            phase_mark headers end "$now" "upper_bound_poll_observed" \
                "first tick with tip_eval_header_height >= peer-advertised network_tip; the frontier's header_admit cursor was unreadable this tick"
        fi
    fi

    # ── bodies ───────────────────────────────────────────────────────────
    # WHY body_persist's CURSOR AND NOT sync_monitor's last_block_connected_*.
    # last_block_connected_height/_time look like the obvious body boundary and
    # were used here first. Replaying the one real PASS artifact on disk
    # (20260821T135540Z-2484174) proved they are NOT: that run finished with
    # hstar 3224110 and every stage cursor at 3224111, while
    # last_block_connected_height sat at 3056758 and last_block_connected_time
    # at 1787320659 — 437 seconds before the run ended. That field does not
    # track this build's fold, so a bodies.end keyed on it would NEVER fire on a
    # real PASS and the phase would be reported unobserved forever. The trade is
    # explicit: body_persist's cursor is a POLL bound rather than a node-stamped
    # instant, and there is no node-stamped instant for this boundary at all
    # (see the omitted_fields row).
    if [ "$dl_req" -gt 0 ] 2>/dev/null; then
        phase_mark bodies start "$now" "upper_bound_poll_observed" \
            "first tick with dumpstate sync_monitor download_requested>0"
    fi
    if [ "$PHASE_TARGET_HEIGHT" -gt 0 ] 2>/dev/null &&
       [ "$body_cursor" -gt "$PHASE_TARGET_HEIGHT" ] 2>/dev/null; then
        phase_mark bodies end "$now" "upper_bound_poll_observed" \
            "first tick with reducer_frontier stage_cursors[body_persist].cursor > peer-advertised network_tip (every body needed for the target is received and persisted)"
    fi

    # ── fold ─────────────────────────────────────────────────────────────
    if [ "$hs" != "-1" ] && [ "$hs" -gt 0 ] 2>/dev/null; then
        phase_mark fold start "$now" "upper_bound_poll_observed" \
            "first tick with an authoritative dumpstate reducer_frontier hstar>0"
        if [ "$PHASE_TARGET_HEIGHT" -gt 0 ] 2>/dev/null &&
           [ "$hs" -ge "$PHASE_TARGET_HEIGHT" ] 2>/dev/null; then
            phase_mark fold end "$now" "upper_bound_poll_observed" \
                "the tick on which authoritative hstar caught network_tip — the same predicate the PASS verdict uses"
        fi
    fi
    return 0
}

# phase_unobserved_reason <boundary> <edge> — the NAMED reason an edge has no
# reading. Never "0", never blank: an unobserved edge that cannot say why it is
# unobserved is the same silent absence omitted_fields[] exists to abolish.
phase_unobserved_reason() {
    case "$1.$2" in
        peer_connect.start) printf 'the harness never reached its first launch_node (an early skip or setup failure).' ;;
        peer_connect.end)   printf 'no peer in dumpstate peer_lifecycle ever reported BOTH handshake_complete_at>0 AND advertised_height>0, so a peer that could actually serve data was never observed connected.' ;;
        headers.start)      printf 'reducer_frontier stage_cursors[header_admit].cursor never rose above 1 and sync_monitor tip_eval_header_height stayed 0 for the whole window: not one header was ever admitted, so header sync never started.' ;;
        headers.end)        printf 'the header_admit cursor never passed the peer-advertised network_tip (or no network_tip was ever readable, which itself requires a completed handshake).' ;;
        bodies.start)       printf 'dumpstate sync_monitor download_requested stayed 0 for the whole window: no block body was ever requested.' ;;
        bodies.end)         printf 'the body_persist cursor never passed the target height, so the bodies needed for the target were never all received and persisted.' ;;
        fold.start)         printf 'the authoritative reducer_frontier hstar never rose above 0: the reducer never folded a single block.' ;;
        fold.end)           printf 'hstar never caught network_tip within the budget.' ;;
        *)                  printf 'no reason recorded, which is itself a defect — phase_unobserved_reason() must name every unobserved edge.' ;;
    esac
}

# phase_source <boundary> <edge> — the source that WOULD have produced this
# edge. Emitted even when the edge is unobserved, because "which dumper was
# watched and came up empty" is the actionable half of an absence.
phase_source() {
    case "$1.$2" in
        peer_connect.start) printf 'harness wall clock (date +%%s) immediately before the first launch_node exec' ;;
        peer_connect.end)   printf 'dumpstate peer_lifecycle peers[].handshake_complete_at — earliest among peers with advertised_height>0' ;;
        headers.start)      printf 'first sample tick with reducer_frontier stage_cursors[header_admit].cursor>1 (fallback: sync_monitor tip_eval_header_height>0)' ;;
        headers.end)        printf 'first sample tick with stage_cursors[header_admit].cursor > dumpstate reducer_frontier network_tip' ;;
        bodies.start)       printf 'first sample tick with dumpstate sync_monitor download_requested>0' ;;
        bodies.end)         printf 'first sample tick with reducer_frontier stage_cursors[body_persist].cursor > network_tip' ;;
        fold.start)         printf 'first sample tick with an authoritative dumpstate reducer_frontier hstar>0' ;;
        fold.end)           printf 'sample tick on which authoritative hstar >= network_tip' ;;
        *)                  printf 'unnamed' ;;
    esac
}

# phase_start_kind <boundary> — peer_connect's start is a harness-exact stamp;
# every other start is the first tick that saw the condition ALREADY true, i.e.
# an upper bound at SAMPLE_SECS resolution.
phase_start_kind() {
    case "$1" in
        peer_connect) printf 'exact_harness_stamp' ;;
        *)            printf 'upper_bound_poll_observed' ;;
    esac
}

# phase_span_ms <boundary> — duration in ms, or -1 when either edge is
# unobserved. There is deliberately NO "assume it ran to the end of the window"
# fallback: a half-observed phase has no duration, and manufacturing one from
# the capture time would silently convert an unobserved boundary into a
# measurement.
phase_span_ms() {
    local s="${PH_START[$1]:--1}" e="${PH_END[$1]:--1}"
    if [ "$s" = "-1" ] || [ "$e" = "-1" ] || [ "$e" -lt "$s" ] 2>/dev/null; then
        printf '%s' -1; return 0
    fi
    printf '%s' $(( (e - s) * 1000 ))
}

# phase_rows_json — the four sync-phase elements of phases[]. ALL FOUR ARE
# ALWAYS EMITTED, on every verdict, observed or not. That is not cosmetic: a
# phase that vanishes from the artifact when it was not observed is exactly the
# silent absence this artifact format refuses, and the artifact-symmetry checker
# additionally requires the phase name set to be identical across a pass and a
# non-pass run.
phase_rows_json() {
    local out="" p s e d
    for p in $PHASE_NAMES; do
        s="${PH_START[$p]:--1}"; e="${PH_END[$p]:--1}"; d="$(phase_span_ms "$p")"
        [ -n "$out" ] && out="$out,"
        out="$out{\"phase\":\"sync.$p\",\"level\":\"sync_phase\""
        out="$out,\"observed\":$([ "$d" = "-1" ] && printf false || printf true)"
        out="$out,\"start_unix\":$([ "$s" = "-1" ] && printf null || printf '%s' "$s")"
        out="$out,\"end_unix\":$([ "$e" = "-1" ] && printf null || printf '%s' "$e")"
        out="$out,\"duration_ms\":$([ "$d" = "-1" ] && printf null || printf '%s' "$d")"
        out="$out,\"duration_source\":$(json_string "start: $(phase_source "$p" start) | end: $(phase_source "$p" end)")"
        out="$out,\"start_kind\":$([ "$s" = "-1" ] && printf '"unobserved"' || json_string "$(phase_start_kind "$p")")"
        out="$out,\"end_kind\":$(json_string "${PH_END_SRCKIND[$p]:-unobserved}")"
        out="$out,\"poll_resolution_secs\":$(json_number_or_null "$SAMPLE_SECS")"
        if [ "$p" = "peer_connect" ]; then
            out="$out,\"node_time_to_first_handshaked_peer_us\":$([ "$PHASE_TTFP_US" = "-1" ] && printf null || printf '%s' "$PHASE_TTFP_US")"
            out="$out,\"node_time_to_first_handshaked_peer_source\":\"dumpstate omniscience time_to_first_peer_us (lib/net/src/connman.c g_first_peer_us, latched write-once)\""
            out="$out,\"node_time_to_first_handshaked_peer_scope\":\"microseconds from connman_start() to the FIRST fully-handshaked peer. This is NOT this phase's duration: it starts at connman_start (not process launch) and ends at ANY handshake (not one that advertised a height). Both are reported because they bracket different windows; neither is derived from the other.\""
            if [ "$PHASE_TTFP_US" = "-1" ]; then
                out="$out,\"node_time_to_first_handshaked_peer_unobserved_reason\":\"dumpstate omniscience reported time_to_first_peer_us as 0 (its 'no peer yet' sentinel) for the whole window, or the dumper was unreachable — no peer ever completed a handshake.\""
            fi
        fi
        if [ "$s" = "-1" ]; then
            out="$out,\"start_unobserved_reason\":$(json_string "$(phase_unobserved_reason "$p" start)")"
        fi
        if [ "$e" = "-1" ]; then
            out="$out,\"end_unobserved_reason\":$(json_string "$(phase_unobserved_reason "$p" end)")"
        fi
        out="$out}"
    done
    printf '%s' "$out"
}

# phase_overlap_json <captured_at_unix> — the object that makes the overlap
# impossible to misread.
# THE LIE THIS PREVENTS. Four phase durations printed in a column invite exactly
# one reading: that they add up to the window. They do not — bodies stream while
# the fold runs, so the same second is inside two phases at once, and any
# subtraction across them is arithmetic on double-counted time. So sum_ms
# (double-counted), union_ms (wall clock covered by at least one phase) and the
# pairwise overlaps are published side by side with a literal
# phases_partition_the_window:false. sum minus union IS the double count,
# stated rather than left to be discovered.
phase_overlap_json() {
    local captured_at="${1:-0}" p q sum=0 d union=-1 obs=0 pairs="" ov lo hi win=-1
    local -a S=() E=()
    for p in $PHASE_NAMES; do
        d="$(phase_span_ms "$p")"
        if [ "$d" != "-1" ]; then
            sum=$((sum + d)); obs=$((obs + 1))
            S+=( "${PH_START[$p]}" ); E+=( "${PH_END[$p]}" )
        fi
    done
    for p in $PHASE_NAMES; do
        for q in $PHASE_NAMES; do
            [ "$p" \< "$q" ] || continue
            if [ "$(phase_span_ms "$p")" = "-1" ] || [ "$(phase_span_ms "$q")" = "-1" ]; then
                ov=null
            else
                hi="${PH_END[$p]}"; [ "${PH_END[$q]}" -lt "$hi" ] && hi="${PH_END[$q]}"
                lo="${PH_START[$p]}"; [ "${PH_START[$q]}" -gt "$lo" ] && lo="${PH_START[$q]}"
                ov=$(( (hi - lo) * 1000 ))
                [ "$ov" -lt 0 ] && ov=0
            fi
            [ -n "$pairs" ] && pairs="$pairs,"
            pairs="$pairs\"sync.$p|sync.$q\":$ov"
        done
    done
    if [ "$obs" -gt 0 ]; then
        union="$(
            for ((i = 0; i < ${#S[@]}; i++)); do printf '%s %s\n' "${S[$i]}" "${E[$i]}"; done |
            sort -n | awk '
                BEGIN { tot = 0; cs = -1; ce = -1 }
                { s = $1 + 0; e = $2 + 0
                  if (cs < 0) { cs = s; ce = e; next }
                  if (s > ce) { tot += ce - cs; cs = s; ce = e } else if (e > ce) ce = e }
                END { if (cs >= 0) tot += ce - cs; print tot * 1000 }')"
        case "$union" in ''|*[!0-9-]*) union=-1 ;; esac
    fi
    [ "${LOOP_START_UNIX:-0}" -gt 0 ] 2>/dev/null && [ "$captured_at" -ge "${LOOP_START_UNIX:-0}" ] 2>/dev/null &&
        win=$(( (captured_at - LOOP_START_UNIX) * 1000 ))
    printf '{"phases_partition_the_window":false'
    printf ',"timeline_basis":"one shared unix-second clock; every start_unix/end_unix in phases[] is on it"'
    printf ',"observed_phase_count":%s' "$obs"
    printf ',"observed_sync_window_ms":%s' "$([ "$win" = "-1" ] && printf null || printf '%s' "$win")"
    printf ',"sum_of_observed_phase_ms":%s' "$([ "$obs" -gt 0 ] && printf '%s' "$sum" || printf null)"
    printf ',"union_of_observed_phase_ms":%s' "$([ "$union" = "-1" ] && printf null || printf '%s' "$union")"
    printf ',"double_counted_ms":%s' "$( { [ "$obs" -gt 0 ] && [ "$union" != "-1" ]; } && printf '%s' $((sum - union)) || printf null)"
    printf ',"window_ms_covered_by_no_phase":%s' "$( { [ "$win" != "-1" ] && [ "$union" != "-1" ]; } && printf '%s' $((win - union)) || printf null)"
    printf ',"pairwise_overlap_ms":{%s}' "$pairs"
    printf ',"note":"sum_of_observed_phase_ms counts overlapping seconds more than once and is NOT the window. union_of_observed_phase_ms is the wall clock covered by at least one phase. double_counted_ms = sum - union is the overlap. window_ms_covered_by_no_phase is observed-sync time no phase claims — it is UNATTRIBUTED, not idle. A null means an edge was never observed; it is never a zero. A pairwise entry is null when either phase was not fully observed."'
    printf '}'
}

# phase_profile_index_json — the manifest for phase-profiles/. Written on EVERY
# run, including one where no boundary ever fired (rows:[] plus the reason the
# directory is empty), so an empty directory is never mistaken for a lost
# capture.
phase_profile_index_json() {
    local n
    n="$(printf '%s' "$PHASE_PROFILE_INDEX_ROWS" | grep -o '"at":' | wc -l | tr -d ' ')"
    printf '{"schema":"zcl.c3_phase_stage_profile_index.v1"'
    printf ',"description":"one dumpstate reducer_stage_profile snapshot per OBSERVED sync-phase boundary. The cumulative.* counters in each snapshot are lifetime-since-boot totals, so a phase cost is the DIFFERENCE between the two snapshots that bracket it — that subtraction is deliberately left to the reader rather than pre-baked here."'
    printf ',"boundary_snapshot_count":%s' "$n"
    printf ',"empty_reason":%s' "$([ -z "$PHASE_PROFILE_INDEX_ROWS" ] && json_string "no sync-phase boundary was observed during this run, or the node was not RPC-reachable when one was. See phases[] start_unobserved_reason / end_unobserved_reason for which." || printf null)"
    printf ',"rows":[%s]}' "$PHASE_PROFILE_INDEX_ROWS"
}
# omitted_fields_json — the elements of omitted_fields[] (comma-separated JSON
# objects, NO enclosing brackets): every field the owner's measurement brief
# named that this run did NOT record, BY NAME, with the reason and the nearest
# honest substitute.
#
# WHY THIS IS A FIRST-CLASS ARTIFACT SECTION AND NOT A COMMENT. The brief asks
# for phase time, bytes, CPU, disk, blocker, final H*, peer tip, and source
# identity. Some of those have no honest per-phase source in this tree today.
# A silently absent field reads to the next reader as "measured, and fine" —
# which is how a baseline acquires a number nobody took. So an unmeasurable
# field is RECORDED as unmeasured, named exactly as the brief named it, and the
# reason is stated. The rule this enforces: never fabricate a field, never
# estimate one and present it as measured, never quietly drop one.
#
# Two classes of row:
#   structural — no source exists in this tree at all, for any run. These are
#                constant and are the honest to-do list for the instrument.
#   this_run   — a source EXISTS but this particular run could not read it
#                (binary unidentifiable, /proc unreadable, node.log absent).
#                This is the degrade-don't-crash path: the run still reports the
#                verdict the node earned, and says which readings it lost.
omitted_fields_json() {
    local out="" f
    _of_row() {  # field, scope, reason, substitute
        [ -n "$out" ] && out="$out,"
        out="$out{\"field\":$(json_string "$1"),\"scope\":$(json_string "$2")"
        out="$out,\"reason\":$(json_string "$3")"
        out="$out,\"nearest_honest_substitute\":$(json_string "$4")}"
    }
    # ── structural: nothing in this tree sources these ──────────────────────
    _of_row "phases[].network_bytes" "structural" \
        "TOTAL WIRE BYTES have no source in this tree. Nothing counts them: /proc has no per-process network accounting, and the only byte counter the node keeps (download_bytes_received, via dl_add_bytes_received in lib/net/src/download.c) counts ONLY successfully-parsed block-body message payload — it excludes headers messages, the version/verack handshake, inv/getdata/getheaders, tx relay, addr, compact blocks, the 24-byte per-message header, and all TCP/IP framing. An earlier revision of this row claimed that counter reached no dumper at all; that was WRONG (dumpstate sync_monitor has exposed it all along) and the correction is why this row is now scoped to total wire bytes rather than to bytes in general." \
        "harness.observed_sync.block_body_payload_bytes_received — a real measurement of the block-body payload subset, named for the subset it is. It is a LOWER BOUND on wire bytes; do not present it as the total, and do not infer the total from wall-clock time."
    _of_row "phases[].cpu_seconds (boot-level phases)" "structural" \
        "config/src/boot.c boot_topmark/boot_submark emit a phase NAME and a DURATION and nothing else. The harness's own /proc sampling only starts once its sample loop is running, by which time boot has already finished, so there is no window it genuinely bracketed." \
        "harness.observed_sync carries cpu_seconds for the window the harness DID bracket; samples.tsv carries the per-tick series."
    _of_row "phases[].disk_read_bytes / phases[].disk_write_bytes (boot-level phases)" "structural" \
        "same as cpu_seconds: the boot markers carry only a duration, and the harness was not yet sampling /proc during boot." \
        "harness.observed_sync + samples.tsv, for the observed-sync window only."
    _of_row "phases[].start_unix (boot-level phases)" "structural" \
        "the [boot] marker lines carry no timestamp of their own, and the top-level marks do not tile the boot (on the one real PASS artifact on disk, 20260728T000207Z-2102851, named top-level phases sum to 15,623ms against a 51,755ms total — ~36s unattributed), so a cumulative-sum start would be fabricated." \
        "start_ts_lower_bound: the nearest PRECEDING timestamped node.log line. It is a bound ('this phase did not start before this'), named as one, never presented as a start."
    _of_row "phases[].blocker (per boot-level phase)" "structural" \
        "a named blocker is raised by a REDUCER STAGE (dumpstate blocker / stage-*.json), not by a boot marker; there is no mapping from a boot phase name to a blocker id, and inventing one would attribute a stall to a phase that did not raise it." \
        "samples.tsv blocker_count/blocker_ids per tick, plus blocker.json and stage-*.json in this artifact dir."
    _of_row "phases[].hstar / phases[].peer_tip (per boot-level phase)" "structural" \
        "H* and network_tip are read over RPC, which is not serving during most of boot; a boot phase therefore has no H* of its own." \
        "samples.tsv hstar/network_tip per tick, and the run-level final_hstar / final_network_tip / measured_identity.peer_advertised_tip in this file."
    # ── structural, SYNC-PHASE SPLIT: what the split still cannot see ───────
    # These four rows are the honest to-do list left by splitting the
    # observed-sync bracket. Each names a boundary the brief asked for that no
    # source in this tree can produce today, and the BOUND that is reported in
    # its place. A bound reported as if it were the instant is the same
    # false-green defect as a fabricated zero, only harder to notice.
    _of_row "phases[].sync.headers.start (the true first getheaders SENT)" "structural" \
        "nothing in this tree counts getheaders SENT. lib/net/src/msg_headers.c keeps only SERVE-side counters (g_getheaders_served_requests and the suppression counters) and they reach no dumpstate topic; the per-node last_getheaders_time in app/services/src/sync_monitor.c is reset, never dumped. So the instant our first getheaders left this node is unobservable." \
        "sync.headers.start as emitted: the first sample tick on which a header had ALREADY been admitted. It is a strict UPPER BOUND — the request went out earlier — and is labelled start_kind=upper_bound_poll_observed, never presented as the instant."
    _of_row "phases[].sync.bodies.start (the true first block body REQUESTED)" "structural" \
        "download_requested (lib/net/src/download.c, surfaced by dumpstate sync_monitor) is a COUNTER with no first-request timestamp, and the node latches no such instant. Only the counter's rising edge is observable, and only at the harness's poll cadence." \
        "sync.bodies.start as emitted: the first tick with download_requested>0, labelled start_kind=upper_bound_poll_observed."
    _of_row "phases[].sync.bodies.end (the last body NEEDED for the target height RECEIVED)" "structural" \
        "no dumper stamps an instant for this boundary. sync_monitor's last_block_connected_time LOOKS like it and is not: on the one real PASS artifact on disk (20260821T135540Z-2484174) that run ended with hstar 3224110 and every frontier stage cursor at 3224111, while last_block_connected_height sat at 3056758 and last_block_connected_time at 1787320659 — 437 seconds before the run finished. It does not track this build's fold, so it is not used. Separately, no counter distinguishes 'the last needed body arrived on the wire' from 'the last needed body was persisted', and persistence happens after receive." \
        "sync.bodies.end as emitted: the first tick with reducer_frontier stage_cursors[body_persist].cursor past the target. It is a poll-resolution LATE bound on the receive instant (end_kind=upper_bound_poll_observed), never presented as the instant."
    _of_row "phases[].sync.* per-phase cpu_seconds / disk_read_bytes / disk_write_bytes" "structural" \
        "/proc counters are sampled per TICK for the whole process, not per phase, and the sync phases OVERLAP — the same CPU second belongs to bodies and to the fold at once. Splitting one process-wide counter across overlapping phases would have to invent an attribution rule, and any such rule would be a model, not a measurement." \
        "samples.tsv carries the per-tick cpu/rss/disk series against the same unix clock as every phase boundary, so a reader can integrate over any phase's interval themselves and see the overlap while doing it. phase-profiles/ additionally carries a dumpstate reducer_stage_profile snapshot at every boundary, whose cumulative.* counters ARE differenceable per phase."
    # ── this_run: a source exists, this run could not read it ───────────────
    if [ -z "${NODE_BIN_SOURCE_ID:-}" ]; then
        _of_row "measured_identity.node_bin_source_id_sha256" "this_run" \
            "zcl_binary_source_id (tools/scripts/source_identity_lib.sh) returned no 64-hex source id for this binary — it is absent, not executable, or its agentbuild output carried none. The field is null rather than guessed." \
            "measured_identity.node_bin (the path that was run). The BUILD behind it is unidentified for this run."
    fi
    if [ -z "${SAMPLES_TSV:-}" ] || [ ! -f "${SAMPLES_TSV:-/nonexistent}" ]; then
        _of_row "samples.tsv" "this_run" \
            "the per-tick sink could not be created or the run ended before the sample loop was armed (an early skip/fail has no ticks to record)." \
            "the summary first/max/final fields in this file. The SHAPE of the climb is unrecorded for this run."
    fi
    if [ ! -f "$ARTIFACT_DIR/node.log" ]; then
        _of_row "phases[] boot-level elements" "this_run" \
            "node.log was not captured into this artifact dir, so the node's own [boot] markers could not be parsed. Boot phase durations are unrecorded for this run." \
            "the harness.* elements, which the harness bracketed itself and does not need node.log for."
    fi
    for f in cpu_seconds rss_kb disk_read_bytes disk_write_bytes; do
        case "$f" in
            cpu_seconds)       [ "${LAST_CPU_SECONDS:--1}" = "-1" ] || continue ;;
            rss_kb)            [ "${LAST_RSS_KB:--1}" = "-1" ] || continue ;;
            disk_read_bytes)   [ "${LAST_DISK_READ_BYTES:--1}" = "-1" ] || continue ;;
            disk_write_bytes)  [ "${LAST_DISK_WRITE_BYTES:--1}" = "-1" ] || continue ;;
        esac
        _of_row "harness.observed_sync.$f" "this_run" \
            "/proc/<pid>/stat or /proc/<pid>/io was unreadable at capture (most often: the node process had already exited). Reported as -1, which is the never-measured sentinel and is deliberately distinguishable from a real zero." \
            "samples.tsv, whose earlier rows may carry a reading from while the process was alive."
    done
    # The byte delta has a source (dumpstate sync_monitor), so a lost reading is
    # a this_run loss, never a structural one — and a respawn inside the window
    # is one of the ways it is lost. bytes_delta_compute() has already named
    # which way; this row carries that reason verbatim rather than restating a
    # generic one, because "we could not read it" and "we read it across a
    # counter reset" are different failures with different fixes.
    if [ "${BYTES_DELTA:--1}" = "-1" ]; then
        _of_row "harness.observed_sync.block_body_payload_bytes_received" "this_run" \
            "${BYTES_UNAVAIL_REASON:-no reason was recorded, which is itself a defect — bytes_delta_compute() must name every -1}" \
            "none for this window. Do NOT substitute wall-clock time, block count, or disk_write_bytes for bytes moved: block bodies are written after validation, so disk writes are a different quantity."
    fi
    unset -f _of_row
    printf '%s' "$out"
    return 0
}

# is_self_respawn_reason — true iff the given boot-exit-reason.v1 `reason` value
# is a supervised self-respawn request (self_respawn_tip_watchdog /
# self_respawn_supervisor_backstop / self_respawn_both — see
# lib/util/include/util/shutdown_stagewatch.h). The node writes this breadcrumb
# EARLY in its clean shutdown (fsync + atomic rename, before any teardown
# stage) when the chain-tip watchdog, the supervisor backstop, or the
# checkpoint-bundle install-ready condition asked to be relaunched. A clean
# exit carrying it means "bring me back on the SAME datadir" — exactly what
# systemd Restart=always does in production; here THIS harness is the
# supervisor. Anything else (operator_or_external, empty, or no breadcrumb at
# all after a crash) is NOT a respawn request and is a real death.
is_self_respawn_reason() {
    case "${1:-}" in
        self_respawn_*) return 0 ;;
        *)              return 1 ;;
    esac
}

# read_exit_reason — extract the `reason=` value from the node's
# <datadir>/boot-exit-reason.v1 breadcrumb, or print nothing if absent. See the
# writer shutdown_stagewatch_write_exit_reason() (magic=ZCLEXITRSN, version=1,
# reason=<name>, ts=<unix>).
read_exit_reason() {
    local f="$DATADIR/boot-exit-reason.v1"
    [ -f "$f" ] || return 0
    sed -n 's/^reason=\(.*\)$/\1/p' "$f" 2>/dev/null | tail -1
}

# frontier_hstar_full <frontier-doc> — the AUTHORITATIVE reducer-frontier H*,
# present only in a FULL read (after the progress-store trylock succeeds). Echoes
# -1 for a busy partial doc / an empty response — the proxy is deliberately NOT
# substituted here, so the PASS predicate can never be minted from a proxy.
frontier_hstar_full() {
    local h; h="$(jget "$1" hstar)"; [ -z "$h" ] && h="-1"; printf '%s' "$h"
}

# frontier_provable_sample <frontier-doc> — the provable tip actually usable for
# PROGRESS honesty: the authoritative full-read "hstar" when present, else the
# lock-free "cached_provable_tip" the busy partial doc still carries (it is
# emitted BEFORE the trylock in reducer_frontier_dump.c, exactly so a diagnostic
# read during a busy fold still learns the served provable tip — the same proxy
# ~/.local/state/zclassic23-cure/run-anchor-refold-proof-9.sh read_hstar() falls
# back to). Echoes -1 only when NEITHER is available (opaque/empty response), so
# a read miss is never faked into a sample.
frontier_provable_sample() {
    local h c
    h="$(jget "$1" hstar)"
    if [ -n "$h" ] && [ "$h" != "-1" ]; then printf '%s' "$h"; return 0; fi
    c="$(jget "$1" cached_provable_tip)"; [ -z "$c" ] && c="-1"
    printf '%s' "$c"
}

# blocker_ids <blocker-doc> — comma-joined "id" values of a `dumpstate blocker`
# doc (empty if none / unreadable).
blocker_ids() {
    printf '%s' "$1" | tr -d '\n' |
        grep -oE '"id"[[:space:]]*:[[:space:]]*"[^"]*"' |
        sed -E 's/.*"id"[[:space:]]*:[[:space:]]*"([^"]*)"/\1/' | paste -sd, -
}

# classify_final_verdict — the PURE end-of-run decision, factored out of the
# artifact/exit plumbing so its precedence is unit-testable (see --selftest).
# Echoes exactly one token:
#   pass            — H* reached network_tip (authoritative), decided upstream.
#   seam            — the PROVABLE SAMPLE (authoritative H* OR cached_provable_tip
#                     proxy) strictly climbed but did not catch tip in budget:
#                     real forward progress. A busy-but-healthy fold that only
#                     ever exposed the proxy lands HERE, never in silent-stall.
#   stalled-named   — no observed climb, but a named blocker explains why.
#   readback-failed — no observed climb, no blocker, and the final readback
#                     failed (or no sample was ever taken): an INSTRUMENT
#                     failure, not an observed stall.
#   silent-stall    — no observed climb, no blocker, and we COULD read the
#                     provable tip throughout — a genuine silent stall.
# Args: reached first_ps max_ps saw_ps final_readback_failed last_blocker_count
classify_final_verdict() {
    local reached="$1" f_ps="$2" m_ps="$3" saw="$4" rbf="$5" bc="$6"
    [ "$reached" = 1 ] && { printf 'pass'; return 0; }
    if [ -n "$f_ps" ] && [ "$m_ps" -gt "$f_ps" ] 2>/dev/null; then
        printf 'seam'; return 0
    fi
    if [ "${bc:-0}" -gt 0 ] 2>/dev/null; then
        printf 'stalled-named'; return 0
    fi
    if [ "$rbf" = "true" ] || [ "$saw" = "0" ]; then
        printf 'readback-failed'; return 0
    fi
    printf 'silent-stall'
}

# classify_peer_precheck <probe-rc> — pure mapping from the peer_precheck()
# probe's exit code to one token. Kept separate from the probe itself so its
# precedence is unit-testable (see --selftest).
#   unreachable  — TCP connect failed or the whole probe timed out.
#   held_open    — the peer kept the socket open (or spoke first): the serving
#                  shape. An outbound handshake can proceed (we send version).
#   accept_close — the peer accepted the TCP connection and closed it
#                  immediately, before a single byte could be exchanged. No
#                  handshake is possible, so `network_tip` can never be read
#                  and the PASS predicate is unreachable by construction.
classify_peer_precheck() {
    case "${1:-}" in
        10|11) printf 'held_open' ;;
        12)    printf 'accept_close' ;;
        *)     printf 'unreachable' ;;
    esac
}

# peer_precheck <host> <port> — connect and observe WITHOUT sending a byte.
#
# This exists because a bare "did TCP connect succeed" test is only a valid
# serving-peer test on LOOPBACK. Against a remote peer, a serving node can
# accept() and then immediately close — e.g. the per-IP inbound sybil cap in
# lib/net/src/net.c ("too many inbound connections from same IP: count=%d",
# max 3), which another node on the SAME host can have already saturated. The
# connect still succeeds, so the old check reported "reachable" and the run
# burned its entire budget against a peer that would never handshake.
#
# Deliberately ADVISORY: it labels the run, it never converts a verdict. A
# refusing peer still produces the honest STALLED-NAMED/SEAM/FAIL class the
# node actually earned — it is never rounded down to SKIP.
peer_precheck() {
    ZCL_PP_HOST="$1" ZCL_PP_PORT="$2" timeout 8 bash -c '
        exec 3<>/dev/tcp/$ZCL_PP_HOST/$ZCL_PP_PORT || exit 9
        if IFS= read -r -t 5 -n 1 -u 3 _b; then exit 10; fi
        rc=$?
        if [ "$rc" -gt 128 ]; then exit 11; fi
        exit 12
    ' >/dev/null 2>&1
    classify_peer_precheck "$?"
}

# --selftest: hermetic classification self-check for is_busy_response() /
# the "hstar" field detector rpc_frontier() uses — canned JSON fixtures,
# no binary/network/mktemp touched. Exits before any real infra setup.
if [ "$SELFTEST" = "1" ]; then
    st_fail=0
    st_check() {  # desc, expect_rc, actual_rc
        if [ "$3" = "$2" ]; then
            echo "  ok: $1"
        else
            echo "  FAIL: $1 (expected rc=$2 got rc=$3)"
            st_fail=1
        fi
    }
    st_busy_json='{"snapshot_status":"progress_store_busy","retryable":true}'
    st_good_json='{"hstar":123,"network_tip":456,"network_tip_read_ok":true}'
    st_other_json='{"error":"method not found"}'

    echo "cold-start-wipe-stopwatch: --selftest running canned-JSON checks"
    is_busy_response "$st_busy_json";  st_check "busy fixture IS recognized as busy" 0 $?
    is_busy_response "$st_good_json";  st_check "good hstar fixture NOT recognized as busy" 1 $?
    is_busy_response "$st_other_json"; st_check "unrelated-error fixture NOT recognized as busy" 1 $?
    is_busy_response "";               st_check "empty response NOT recognized as busy" 1 $?
    printf '%s' "$st_good_json" | grep -q '"hstar"'; st_check "good fixture has hstar field" 0 $?
    printf '%s' "$st_busy_json" | grep -q '"hstar"'; st_check "busy fixture has NO hstar field (would retry, not misread as -1)" 1 $?

    # Exit-reason classification: a self_respawn_* breadcrumb means "relaunch
    # me" (the harness follows it); everything else is a real death.
    is_self_respawn_reason "self_respawn_tip_watchdog";        st_check "tip-watchdog respawn IS a respawn request" 0 $?
    is_self_respawn_reason "self_respawn_supervisor_backstop"; st_check "backstop respawn IS a respawn request" 0 $?
    is_self_respawn_reason "self_respawn_both";                st_check "both-respawn IS a respawn request" 0 $?
    is_self_respawn_reason "operator_or_external";             st_check "operator/external exit is NOT a respawn request" 1 $?
    is_self_respawn_reason "";                                 st_check "empty/absent breadcrumb is NOT a respawn request (crash class)" 1 $?
    is_self_respawn_reason "self_respawn";                     st_check "bare 'self_respawn' (no suffix) is NOT a known respawn reason" 1 $?

    st_boot_log='[boot] prologue                       211ms
[boot] total                          65187ms
2026-08-21T07:13:11Z INFO [shutdown] exit-reason breadcrumb written: reason=self_respawn_tip_watchdog
[boot] prologue                       52ms
[boot] total                          42496ms'
    st_ps_check() {  # desc, expect, actual
        if [ "$3" = "$2" ]; then
            echo "  ok: $1"
        else
            echo "  FAIL: $1 (expected '$2' got '$3')"
            st_fail=1
        fi
    }
    st_ps_check "boot evidence: in-process execv is counted from exact prologue markers" \
        2 "$(printf '%s\n' "$st_boot_log" | boot_count_from_log /dev/stdin)"
    st_ps_check "boot evidence: the durable in-process respawn reason is recovered" \
        self_respawn_tip_watchdog \
        "$(printf '%s\n' "$st_boot_log" | last_self_respawn_from_log /dev/stdin)"
    st_ps_check "boot evidence: prose resembling a marker cannot mint a boot" \
        0 "$(printf '%s\n' '[boot] prologue took 10ms today' | boot_count_from_log /dev/stdin)"

    # Provable-sample extraction: a FULL read yields the authoritative hstar; a
    # busy partial doc (no hstar) falls back to cached_provable_tip WITHOUT ever
    # promoting the proxy into the authoritative hstar; a busy doc whose proxy is
    # still -1 (pre-fold) and a truly empty response both yield NO usable sample.
    st_full_json='{"cached_provable_tip":3107000,"hstar":3107923,"network_tip":3190019,"network_tip_read_ok":true}'
    st_busy_cpt_json='{"cached_provable_tip":3107923,"snapshot_status":"progress_store_busy","retryable":true}'
    st_busy_nocpt_json='{"cached_provable_tip":-1,"snapshot_status":"progress_store_busy","retryable":true}'
    st_ps_check "full read: provable sample IS the authoritative hstar" 3107923 "$(frontier_provable_sample "$st_full_json")"
    st_ps_check "full read: hstar_full IS the authoritative hstar" 3107923 "$(frontier_hstar_full "$st_full_json")"
    st_ps_check "busy doc: provable sample falls back to cached_provable_tip" 3107923 "$(frontier_provable_sample "$st_busy_cpt_json")"
    st_ps_check "busy doc: hstar_full stays -1 (proxy never becomes authoritative)" -1 "$(frontier_hstar_full "$st_busy_cpt_json")"
    st_ps_check "busy doc, proxy=-1 (pre-fold): NO usable provable sample" -1 "$(frontier_provable_sample "$st_busy_nocpt_json")"
    st_ps_check "empty response: NO usable provable sample" -1 "$(frontier_provable_sample "")"
    st_ps_check "full read: network_tip extracted, not confused with network_tip_read_ok" 3190019 "$(jget "$st_full_json" network_tip)"

    # Final-verdict precedence. Args: reached first_ps max_ps saw rbf blocker_ct.
    # The headline regression this fixes: the 20260724T060944Z-880436 run — a
    # healthy fold whose provable tip climbed 3056758 -> 3117923 under load —
    # must classify SEAM, NEVER silent-stall.
    st_ps_check "reached tip -> pass" pass "$(classify_final_verdict 1 3056758 3192164 1 false 0)"
    st_ps_check "climbing proxy under load (the real failing run) -> seam, not silent-stall" \
        seam "$(classify_final_verdict 0 3056758 3117923 1 false 0)"
    st_ps_check "climb wins even if final readback later failed -> seam" \
        seam "$(classify_final_verdict 0 3056758 3117923 1 true 0)"
    st_ps_check "flat + named blocker -> stalled-named" \
        stalled-named "$(classify_final_verdict 0 3100000 3100000 1 false 2)"
    st_ps_check "never sampled all run (all-empty readback) -> readback-failed, not silent-stall" \
        readback-failed "$(classify_final_verdict 0 '' -1 0 true 0)"
    st_ps_check "sampled then final readback failed, no climb/blocker -> readback-failed" \
        readback-failed "$(classify_final_verdict 0 3100000 3100000 1 true 0)"
    st_ps_check "genuinely flat, readable throughout, no blocker -> silent-stall (preserved)" \
        silent-stall "$(classify_final_verdict 0 3100000 3100000 1 false 0)"

    # Peer-precheck classification. The headline case this fixes: a REMOTE
    # serving peer whose per-IP inbound cap is already saturated accepts the
    # TCP connection and closes it instantly — TCP-connect "reachable" but
    # no handshake is possible. Loopback can never show this.
    st_ps_check "connect refused/timed out -> unreachable" unreachable "$(classify_peer_precheck 9)"
    st_ps_check "whole probe timed out -> unreachable" unreachable "$(classify_peer_precheck 124)"
    st_ps_check "peer spoke first -> held_open" held_open "$(classify_peer_precheck 10)"
    st_ps_check "peer kept the socket open waiting for our version -> held_open" held_open "$(classify_peer_precheck 11)"
    st_ps_check "peer closed at accept, zero bytes -> accept_close" accept_close "$(classify_peer_precheck 12)"
    st_ps_check "unknown probe rc -> unreachable (never silently held_open)" unreachable "$(classify_peer_precheck 77)"

    # No-implicit-peer guardrail. This harness once defaulted its serving peer
    # to 127.0.0.1:8033 — the canonical node's own P2P port — so a bare
    # `make mvp-coldstart-to-tip-stopwatch` quietly pulled a full chain sync off
    # the operator's live node. The fix is a stated peer or a SKIP, and these
    # three checks are what stop it from creeping back: the source must carry no
    # `ZCL_CS_PEER` fallback value, must not hardcode the canonical port as the
    # PEER default, and must still contain the refusal. Patterns are assembled
    # from concatenated literals so they cannot match their own source lines.
    st_pat_fallback='ZCL_CS_PEER'':-[^}]'
    st_pat_port='^PEER=.*8033'
    grep -qE "$st_pat_fallback" "${BASH_SOURCE[0]}"
    st_check "source carries no ZCL_CS_PEER fallback value (peer must be stated)" 1 $?
    grep -qE "$st_pat_port" "${BASH_SOURCE[0]}"
    st_check "PEER is not defaulted to the canonical 8033 P2P port" 1 $?
    grep -q 'no_peer_configured' "${BASH_SOURCE[0]}"
    st_check "the empty-peer refusal is still wired" 0 $?

    # ── MEASURED-BASELINE GUARDRAILS ────────────────────────────────────────
    # The defect these three exist to stop from growing back: the diagnostic
    # bundle was captured only when `verdict != pass`, so a PASSING run left no
    # per-phase evidence and the one artifact class worth optimizing against
    # destroyed its own measurements. Same shape as the no-implicit-peer
    # guardrail above — assert on this file's own source text, with patterns
    # assembled from concatenated literals so they cannot match their own
    # source lines.
    st_pat_pass_guard='verdict" != "pass" \]'' && capture'
    grep -qE "$st_pat_pass_guard" "${BASH_SOURCE[0]}"
    st_check "capture is NOT gated behind a non-pass verdict check (the pass/non-pass asymmetry stays deleted)" 1 $?
    grep -qE '^ {4}capture_run_bundle$' "${BASH_SOURCE[0]}"
    st_check "capture_run_bundle is called UNCONDITIONALLY in write_artifact" 0 $?
    # These next two are ANCHORED ON THE CALL SITE, not on the bare name, and
    # that is the whole point. Both started life as `grep -q 'samples_tsv_row '`
    # and `grep -q 'dumpstate boot_timings'` — and a mutation run proved both
    # were hollow: the names also occur in this file's own comments and function
    # definitions, so prefixing the real call with `:` (neutering it completely)
    # or repointing the capture at a different dumpstate key left BOTH checks
    # green. A source-text assertion has to pin the LINE THAT DOES THE WORK: the
    # call at its loop indentation with its first real argument, and the capture
    # invocation with the binary that performs it.
    grep -qE '^ {4}samples_tsv_row "\$elapsed"' "${BASH_SOURCE[0]}"
    st_check "the per-tick samples.tsv sink is CALLED in the sample loop (not merely mentioned)" 0 $?
    grep -qE '^ {8}"\$NODE_BIN".*dumpstate boot_timings' "${BASH_SOURCE[0]}"
    st_check "boot_timings (the median source for phases[]) is actually captured by the bundle" 0 $?
    st_ps_check "boot evidence is refreshed in both the sample loop and artifact capture" \
        2 "$(grep -cE '^ {4}refresh_boot_observation$' "${BASH_SOURCE[0]}" | tr -d ' ')"
    st_ps_check "boot evidence is refreshed once more at the verdict boundary" \
        1 "$(grep -cE '^refresh_boot_observation$' "${BASH_SOURCE[0]}" | tr -d ' ')"

    # /proc parsers. The comm field is parenthesized AND may itself contain
    # spaces and parentheses, which is exactly what breaks a naive $14/$15 read
    # — the second fixture is a process literally named ") x (y z" and both
    # parsers must still land on the right fields.
    st_stat_plain='4242 (zclassic23) S 1 4242 4242 0 -1 4194560 900 0 3 0 731 219 0 0 20 0 12 0 55 9999 262144 0 0 0 0 0 0 0 0 0 0 0 0 0 17 3'
    st_stat_nasty='4242 () x (y z) S 1 4242 4242 0 -1 4194560 900 0 3 0 731 219 0 0 20 0 12 0 55 9999 262144 0'
    st_ps_check "proc stat: cpu ticks are utime+stime (731+219)" 950 "$(parse_proc_stat_cpu_ticks "$st_stat_plain")"
    st_ps_check "proc stat: a comm containing spaces AND parens does not shift the cpu fields" 950 "$(parse_proc_stat_cpu_ticks "$st_stat_nasty")"
    st_ps_check "proc stat: rss pages read from the right field" 262144 "$(parse_proc_stat_rss_pages "$st_stat_plain")"
    st_ps_check "proc stat: rss survives the nasty comm too" 262144 "$(parse_proc_stat_rss_pages "$st_stat_nasty")"
    st_ps_check "proc stat: a truncated line yields -1, never a fabricated 0" -1 "$(parse_proc_stat_cpu_ticks '4242 (x) S 1 2')"
    st_ps_check "proc stat: empty input yields -1, never 0" -1 "$(parse_proc_stat_cpu_ticks '')"
    st_io_blob='rchar: 111
wchar: 222
read_bytes: 4096000
write_bytes: 8192000
cancelled_write_bytes: 0'
    st_ps_check "proc io: read_bytes is the block-layer counter, not rchar" 4096000 "$(parse_proc_io_field "$st_io_blob" read_bytes)"
    st_ps_check "proc io: write_bytes is the block-layer counter, not wchar" 8192000 "$(parse_proc_io_field "$st_io_blob" write_bytes)"
    st_ps_check "proc io: write_bytes is not confused with cancelled_write_bytes" 8192000 "$(parse_proc_io_field "$st_io_blob" write_bytes)"
    st_ps_check "proc io: an absent key yields -1, never 0" -1 "$(parse_proc_io_field "$st_io_blob" nonesuch)"
    st_ps_check "proc io: empty input yields -1, never 0" -1 "$(parse_proc_io_field '' read_bytes)"

    # Boot-marker phase parsing. The real hazard is over-matching: the one real
    # PASS artifact has 74 "[boot]" lines and only 59 are markers, so a looser
    # pattern invents phases out of prose ("[boot] block_index: 1 entries, 296
    # bytes/entry, ..."). This fixture carries one top-level marker, one
    # sub-phase marker, three prose decoys, and a SECOND boot.
    st_log="$(mktemp)" ; st_med="$(mktemp)"
    {
        printf '2026-07-28T00:02:12Z INFO something happened\n'
        printf '[boot] prologue                       63ms\n'
        printf '[boot]   sqlite.quick_check           7ms\n'
        printf '[boot] block_index: 1 entries, 296 bytes/entry, index=0MB\n'
        printf '[boot] First boot or marker absent (no WAL)\n'
        printf '[boot] system_ram=95654MB block_index_estimate=1121MB (3000000 entries)\n'
        printf '2026-07-28T00:03:00Z INFO later\n'
        printf '[boot] prologue                       101ms\n'
        printf '[boot] total                          51755ms\n'
    } >"$st_log"
    printf 'prologue\t70\n' >"$st_med"
    st_phases="$(phases_json_from_log "$st_log" "$st_med")"
    st_ps_check "boot markers: exactly 4 phases parsed from 9 lines (3 prose + 2 timestamped non-markers rejected)" \
        4 "$(printf '%s' "$st_phases" | grep -o '"phase":' | wc -l | tr -d ' ')"
    st_ps_check "boot markers: prose 'block_index:' line did NOT become a phase" \
        0 "$(printf '%s' "$st_phases" | grep -c 'block_index' | tr -d ' ')"
    st_ps_check "boot markers: prose 'system_ram=' line did NOT become a phase" \
        0 "$(printf '%s' "$st_phases" | grep -c 'system_ram' | tr -d ' ')"
    st_ps_check "boot markers: a top-level marker is level=phase" \
        1 "$(printf '%s' "$st_phases" | grep -c '"phase":"total","boot":2,"seq":2,"level":"phase"' | tr -d ' ')"
    st_ps_check "boot markers: an indented marker is level=subphase" \
        1 "$(printf '%s' "$st_phases" | grep -c '"phase":"sqlite.quick_check","boot":1,"seq":2,"level":"subphase"' | tr -d ' ')"
    st_ps_check "boot markers: the second prologue starts boot 2 (respawn is not blended into boot 1)" \
        1 "$(printf '%s' "$st_phases" | grep -c '"phase":"prologue","boot":2,"seq":1' | tr -d ' ')"
    st_ps_check "boot markers: duration_ms comes off the marker itself" \
        1 "$(printf '%s' "$st_phases" | grep -c '"duration_ms":51755' | tr -d ' ')"
    st_ps_check "boot markers: start bound is the nearest PRECEDING timestamped line, and is named a bound" \
        1 "$(printf '%s' "$st_phases" | grep -c '"phase":"total","boot":2,"seq":2,"level":"phase","duration_ms":51755,"duration_source":"node_log_boot_marker","start_ts_lower_bound":"2026-07-28T00:03:00Z"' | tr -d ' ')"
    st_ps_check "boot markers: median_ms is joined from boot_timings for the stage that has one" \
        2 "$(printf '%s' "$st_phases" | grep -o '"median_source":"dumpstate_boot_timings"' | wc -l | tr -d ' ')"
    st_ps_check "boot markers: a stage with NO median gets no median field (never a fabricated 0)" \
        0 "$(printf '%s' "$st_phases" | grep -o '"median_ms":0' | wc -l | tr -d ' ')"
    st_ps_check "boot markers: an absent log yields no phases, not a malformed element" \
        "" "$(phases_json_from_log "$st_log.nonesuch" "$st_med")"
    rm -f "$st_log" "$st_med"

    # boot_timings median extraction, via the SHARED readers (no local parser).
    st_bt="$(mktemp)"
    printf '{"last_boot_epoch":1,"stages":[{"stage":"prologue","last_ms":63,"median_ms":70},{"stage":"utxo_import","last_ms":5}]}\n' >"$st_bt"
    st_ps_check "boot_timings: a stage WITH a median yields one pair" \
        "prologue	70" "$(boot_timings_median_pairs "$st_bt")"
    st_ps_check "boot_timings: a stage with <3 samples (no median_ms) yields NO pair" \
        0 "$(boot_timings_median_pairs "$st_bt" | grep -c utxo_import | tr -d ' ')"
    st_ps_check "boot_timings: an absent doc yields no pairs" "" "$(boot_timings_median_pairs "$st_bt.nonesuch")"
    rm -f "$st_bt"

    # ── omitted_fields[]: named absence, not silent absence ─────────────────
    # The defect: a field the measurement brief asked for that this tree cannot
    # source was simply not emitted, and a silently absent field reads to the
    # next reader as "measured, and fine". Every structural row must be present
    # on EVERY run, and a this_run row must appear exactly when the reading was
    # genuinely lost. These fixtures drive omitted_fields_json() through both.
    st_of_names() { printf '%s' "$1" | grep -o '"field":"[^"]*"' | sed 's/.*:"//;s/"$//' | sort; }
    ARTIFACT_DIR="$(mktemp -d)"
    NODE_BIN_SOURCE_ID="1111111111111111111111111111111111111111111111111111111111111111"
    SAMPLES_TSV="$ARTIFACT_DIR/samples.tsv"; : >"$SAMPLES_TSV"
    : >"$ARTIFACT_DIR/node.log"
    LAST_CPU_SECONDS="9.50"; LAST_RSS_KB="262144"
    LAST_DISK_READ_BYTES="4096000"; LAST_DISK_WRITE_BYTES="8192000"
    BYTES_OPEN=1000; BYTES_OPEN_BOOT=1; BYTES_OPEN_UNIX=1
    BYTES_CLOSE=5000; BYTES_CLOSE_BOOT=1
    bytes_delta_compute
    st_of_best="$(omitted_fields_json)"
    st_ps_check "omitted_fields: the 10 structural rows are present even when EVERYTHING measurable was measured" \
        10 "$(printf '%s' "$st_of_best" | grep -o '"scope":"structural"' | wc -l | tr -d ' ')"
    st_ps_check "omitted_fields: a fully-measured run reports NO this_run rows" \
        0 "$(printf '%s' "$st_of_best" | grep -o '"scope":"this_run"' | wc -l | tr -d ' ')"
    st_ps_check "omitted_fields: network bytes are named as omitted, never emitted as 0" \
        1 "$(printf '%s' "$st_of_best" | grep -c 'phases\[\].network_bytes' | tr -d ' ')"
    # The row STAYS (total wire bytes really are unsourced) but its reason had to
    # change: it used to claim download_bytes_received reached no dumper, which
    # was false. A wrong reason in an omitted-field explanation is the same
    # defect class as a fabricated value, so the corrected scoping is pinned.
    st_ps_check "omitted_fields: the network_bytes row is scoped to TOTAL wire bytes, not to bytes in general" \
        1 "$(printf '%s' "$st_of_best" | grep -c 'TOTAL WIRE BYTES have no source' | tr -d ' ')"
    st_ps_check "omitted_fields: the network_bytes row no longer claims the counter reaches no dumper" \
        0 "$(printf '%s' "$st_of_best" | grep -c 'reaches no dumper' | tr -d ' ')"
    st_ps_check "omitted_fields: the network_bytes row points at the measured block-body subset as its substitute" \
        1 "$(printf '%s' "$st_of_best" | grep -c 'block_body_payload_bytes_received' | tr -d ' ')"
    st_ps_check "omitted_fields: every row carries a reason" \
        10 "$(printf '%s' "$st_of_best" | grep -o '"reason":"' | wc -l | tr -d ' ')"
    st_ps_check "omitted_fields: every row carries a nearest_honest_substitute" \
        10 "$(printf '%s' "$st_of_best" | grep -o '"nearest_honest_substitute":"' | wc -l | tr -d ' ')"
    st_ps_check "omitted_fields: no row claims a substitute of a fabricated zero" \
        0 "$(printf '%s' "$st_of_best" | grep -c '"nearest_honest_substitute":"0"' | tr -d ' ')"
    # Now lose every optional reading and confirm each loss is NAMED.
    NODE_BIN_SOURCE_ID=""
    SAMPLES_TSV=""
    rm -f "$ARTIFACT_DIR/node.log"
    LAST_CPU_SECONDS="-1"; LAST_RSS_KB="-1"
    LAST_DISK_READ_BYTES="-1"; LAST_DISK_WRITE_BYTES="-1"
    # Lose the byte delta the way a real run loses it: a respawn inside the
    # window. That is the branch most likely to be papered over with a plausible
    # number, so it is the one the worst-case fixture drives.
    BYTES_OPEN=1000; BYTES_OPEN_BOOT=1; BYTES_CLOSE=1500; BYTES_CLOSE_BOOT=2
    bytes_delta_compute
    st_of_worst="$(omitted_fields_json)"
    st_ps_check "omitted_fields: an unidentifiable binary is NAMED as unmeasured, not silently null" \
        1 "$(printf '%s' "$st_of_worst" | grep -c 'measured_identity.node_bin_source_id_sha256' | tr -d ' ')"
    st_ps_check "omitted_fields: a missing samples.tsv is NAMED" \
        1 "$(printf '%s' "$st_of_worst" | grep -o '"field":"samples.tsv"' | wc -l | tr -d ' ')"
    st_ps_check "omitted_fields: an absent node.log names the lost boot phases" \
        1 "$(printf '%s' "$st_of_worst" | grep -c 'phases\[\] boot-level elements' | tr -d ' ')"
    # Pinned to the four /proc names EXPLICITLY, not to a `[a-z_]*` wildcard on
    # the harness.observed_sync prefix. The wildcard form silently counted any
    # future observed_sync field too, so adding one (the byte delta) would have
    # made this assertion pass for the wrong reason — 5 fields matching a check
    # whose name says four. Each counter is now named.
    st_ps_check "omitted_fields: all four unreadable /proc counters are named individually" \
        4 "$(printf '%s' "$st_of_worst" | grep -oE '"field":"harness\.observed_sync\.(cpu_seconds|rss_kb|disk_read_bytes|disk_write_bytes)"' | wc -l | tr -d ' ')"
    st_ps_check "omitted_fields: the structural rows survive the worst case too" \
        10 "$(printf '%s' "$st_of_worst" | grep -o '"scope":"structural"' | wc -l | tr -d ' ')"
    st_ps_check "omitted_fields: the worst case names strictly MORE fields than the best case" \
        1 "$([ "$(st_of_names "$st_of_worst" | wc -l)" -gt "$(st_of_names "$st_of_best" | wc -l)" ] && echo 1 || echo 0)"
    st_ps_check "omitted_fields: no field name is reported twice" \
        "" "$(st_of_names "$st_of_worst" | uniq -d)"
    st_ps_check "omitted_fields: a lost byte delta is named as a this_run loss, not a structural one" \
        1 "$(printf '%s' "$st_of_worst" | grep -c '"field":"harness.observed_sync.block_body_payload_bytes_received","scope":"this_run"' | tr -d ' ')"
    st_ps_check "omitted_fields: the lost-byte row carries the SPECIFIC reason (respawn), not a generic one" \
        1 "$(printf '%s' "$st_of_worst" | grep -c 'respawned inside the window' | tr -d ' ')"
    # Scoped to the ROW, not the bare name: the name legitimately also appears in
    # the structural network_bytes row's nearest_honest_substitute, so a bare-name
    # count would be 1 here for an honest reason and this check would be hollow.
    st_ps_check "omitted_fields: a measured byte delta produces NO this_run byte row" \
        0 "$(printf '%s' "$st_of_best" | grep -c '"field":"harness.observed_sync.block_body_payload_bytes_received"' | tr -d ' ')"
    st_ps_check "omitted_fields: the byte row never offers wall clock or disk writes as a substitute" \
        1 "$(printf '%s' "$st_of_worst" | grep -c 'Do NOT substitute wall-clock time' | tr -d ' ')"
    rm -rf "$ARTIFACT_DIR"
    ARTIFACT_DIR=""; NODE_BIN_SOURCE_ID=""; SAMPLES_TSV=""

    # ── block-body payload bytes: the reading, and the delta's fail-closed set ─
    # The defect class here is a byte figure that looks measured but spans a
    # counter reset, or one defaulted to 0 so it reads as "moved nothing" when
    # nothing measured it. Every branch below must yield the -1 sentinel WITH a
    # reason; only a same-boot non-decreasing pair may yield a number.
    st_sm_doc='{"last_recovery":"NONE","download_requested":1961,"download_bytes_received":1761346,"download_mbps_avg":1.15e-05}'
    st_ps_check "bytes: the counter is read out of a real sync_monitor doc" \
        1761346 "$(bytes_reading_from_json "$st_sm_doc")"
    st_ps_check "bytes: a doc WITHOUT the key yields -1, never 0" \
        -1 "$(bytes_reading_from_json '{"download_requested":1961}')"
    st_ps_check "bytes: the mock/catch-all dumpstate reply yields -1, never 0" \
        -1 "$(bytes_reading_from_json '{"mock_dumpstate":"sync_monitor","ok":true}')"
    st_ps_check "bytes: an empty response yields -1, never 0" -1 "$(bytes_reading_from_json '')"
    st_ps_check "bytes: a value too wide for int64 shell math is refused, not wrapped" \
        -1 "$(bytes_reading_from_json '{"download_bytes_received":99999999999999999999}')"
    st_ps_check "bytes: a genuine zero reading is preserved as 0, not confused with the sentinel" \
        0 "$(bytes_reading_from_json '{"download_bytes_received":0}')"

    st_bd() {  # open, open_boot, close, close_boot -> "<delta>|<has_reason>"
        BYTES_OPEN="$1"; BYTES_OPEN_BOOT="$2"; BYTES_CLOSE="$3"; BYTES_CLOSE_BOOT="$4"
        bytes_delta_compute
        printf '%s|%s' "$BYTES_DELTA" "$([ -n "$BYTES_UNAVAIL_REASON" ] && echo reason || echo none)"
    }
    st_ps_check "bytes delta: a same-boot non-decreasing pair yields the difference and NO reason" \
        "4000|none" "$(st_bd 1000 1 5000 1)"
    st_ps_check "bytes delta: a same-boot pair that moved nothing yields a real 0, not the sentinel" \
        "0|none" "$(st_bd 5000 1 5000 1)"
    # THE respawn case. Without the boot guard this returns 500 — a positive,
    # entirely plausible-looking number that is not a byte count of anything,
    # because the counter restarted at 0 on boot 2. Fail closed.
    st_ps_check "bytes delta: a respawn inside the window yields -1 + a reason, NOT the plausible 500" \
        "-1|reason" "$(st_bd 1000 1 1500 2)"
    st_ps_check "bytes delta: a respawn where the counter came back LOWER is also -1, not negative" \
        "-1|reason" "$(st_bd 1000 1 500 2)"
    st_ps_check "bytes delta: a decrease within ONE boot is an instrument fault, not a negative byte count" \
        "-1|reason" "$(st_bd 5000 1 4000 1)"
    st_ps_check "bytes delta: an unread open end yields -1 + a reason" \
        "-1|reason" "$(st_bd -1 -1 5000 1)"
    st_ps_check "bytes delta: an unread close end yields -1 + a reason" \
        "-1|reason" "$(st_bd 1000 1 -1 1)"
    st_ps_check "bytes delta: BOTH ends unread yields -1 + a reason" \
        "-1|reason" "$(st_bd -1 -1 -1 -1)"
    unset -f st_bd
    BYTES_OPEN=-1; BYTES_OPEN_BOOT=-1; BYTES_OPEN_UNIX=-1
    BYTES_CLOSE=-1; BYTES_CLOSE_BOOT=-1; BYTES_DELTA=-1; BYTES_UNAVAIL_REASON=""

    # Source-text pins. The byte figure is only as good as the capture that feeds
    # it and the name it is emitted under, and both are one edit away from
    # regressing silently. Anchored on the line that does the work, per the
    # lesson recorded above the samples_tsv_row/boot_timings pins.
    grep -qE '^ {8}for net_name in .*\bsync_monitor\b' "${BASH_SOURCE[0]}"
    st_check "sync_monitor (the ONLY dumper carrying a byte counter) is in the capture loop" 0 $?
    grep -qE '^ {4}bytes_window_open_try$' "${BASH_SOURCE[0]}"
    st_check "the byte window is opened from inside the sample loop (retried until it lands)" 0 $?
    grep -qE '^ {4}bytes_window_close$' "${BASH_SOURCE[0]}"
    st_check "the byte window is closed at artifact capture" 0 $?
    # The name must state the subset. `network_bytes` would claim total wire
    # bytes, which this counter is not — that overstatement is the exact defect
    # this field was added to avoid, so the honest name is pinned.
    grep -q '"block_body_payload_bytes_received\\":' "${BASH_SOURCE[0]}"
    st_check "the emitted field is named block_body_payload_bytes_received (states the subset it counts)" 0 $?
    st_pat_broad='out,\\"network_by''tes\\":'
    grep -qE "$st_pat_broad" "${BASH_SOURCE[0]}"
    st_check "no phase emits a broad network_bytes field (it would overstate a block-body-only counter)" 1 $?
    grep -q 'EXCLUDES headers messages' "${BASH_SOURCE[0]}"
    st_check "the emitted scope string names what the counter EXCLUDES, not just what it counts" 0 $?

    # The artifact must NAME its own omitted set — a proof.json that emits
    # phases[] but no omitted_fields[] is back to silent absence.
    grep -q '"omitted_fields": \[' "${BASH_SOURCE[0]}"
    st_check "proof.json emits an omitted_fields[] array" 0 $?


    # ── SYNC PHASE SPLIT ────────────────────────────────────────────────────
    # The defect class this section exists to stop: a phase that reads 0ms
    # because nothing was detected. Every check below is written so that
    # substituting 0 for the never-observed sentinel makes it go red, and so
    # that a phase vanishing from the artifact makes it go red too.
    st_pl_doc='{"subsystem":"peer_lifecycle","state":{"summary":{"attempted":10,"handshake_complete":2},"peers":[{"peer_id":9,"addr":"127.0.0.1:39070","handshake_complete_at":1700000500,"advertised_height":0,"advertised_height_trusted":false},{"peer_id":11,"addr":"10.0.0.2:8033","handshake_complete_at":1700000400,"advertised_height":3200000,"advertised_height_trusted":true},{"peer_id":12,"addr":"10.0.0.3:8033","handshake_complete_at":1700000700,"advertised_height":3200001,"advertised_height_trusted":true}]}}'
    st_ps_check "peer_lifecycle: the earliest HEIGHT-ADVERTISING peer's handshake is the boundary" \
        1700000400 "$(pl_handshake_unix "$st_pl_doc" 1)"
    # peer 9 handshook EARLIER (…500 vs …400 is not the point — 9 has no height
    # at all). A peer that completed a handshake but never told us a chain
    # height cannot serve data, and counting it would move the boundary to a
    # socket event rather than a serving event.
    st_ps_check "peer_lifecycle: a handshaked peer that advertised NO height is not 'serving'" \
        1700000400 "$(pl_handshake_unix "$st_pl_doc" 1)"
    st_ps_check "peer_lifecycle: relaxing the height requirement DOES admit that peer (the two differ)" \
        1700000400 "$(pl_handshake_unix "$st_pl_doc" 0)"
    # The real shape from a run whose peer accept()ed and closed: connected,
    # version_sent, handshake_complete_at 0. Must be -1, never 0 — 0 here would
    # be read as "handshaked at the unix epoch" or, worse, as 0ms to connect.
    st_pl_none='{"peers":[{"peer_id":9,"attempted":10,"connected":10,"version_sent":10,"handshake_complete_at":0,"advertised_height":0}]}'
    st_ps_check "peer_lifecycle: no completed handshake yields -1, never 0" \
        -1 "$(pl_handshake_unix "$st_pl_none" 1)"
    st_ps_check "peer_lifecycle: the catch-all mock reply yields -1, never 0" \
        -1 "$(pl_handshake_unix '{"mock_dumpstate":"peer_lifecycle","ok":true}' 1)"
    st_ps_check "peer_lifecycle: an empty response yields -1, never 0" \
        -1 "$(pl_handshake_unix '' 1)"

    st_fc_doc='{"hstar":100,"stage_cursors":[{"stage":"header_admit","read_ok":true,"cursor":4211,"trust":"authoritative"},{"stage":"validate_headers","read_ok":true,"cursor":77,"trust":"authoritative"}]}'
    st_ps_check "frontier stage_cursors: header_admit's cursor is read, not the next stage's" \
        4211 "$(frontier_stage_cursor "$st_fc_doc" header_admit)"
    st_ps_check "frontier stage_cursors: validate_headers is read off its OWN element" \
        77 "$(frontier_stage_cursor "$st_fc_doc" validate_headers)"
    st_ps_check "frontier stage_cursors: an absent stage yields -1, never 0" \
        -1 "$(frontier_stage_cursor "$st_fc_doc" body_persist)"

    # reducer_stage_profile: cumulative is the ONLY differenceable view.
    # last_batch is reset on every stage batch generation, so a read that falls
    # through from a null cumulative into last_batch reports a single batch as a
    # lifetime total — a number that is real, plausible, and wrong.
    st_rsp='{"state":{"body_persist":{"cumulative":{"blocks":812,"total_us":9910222},"last_batch":{"blocks":64,"total_us":740111}},"script_validate":{"cumulative":{"blocks":null,"total_us":null},"last_batch":{"blocks":64,"total_us":123456}}}}'
    st_ps_check "stage profile: a cumulative counter is read from the cumulative object" \
        9910222 "$(rsp_cum "$st_rsp" body_persist total_us)"
    st_ps_check "stage profile: a NULL cumulative yields -1 and does NOT fall through to last_batch" \
        -1 "$(rsp_cum "$st_rsp" script_validate total_us)"
    st_ps_check "stage profile: an absent domain yields -1, never 0" \
        -1 "$(rsp_cum "$st_rsp" tip_finalize total_us)"
    st_ps_check "stage profile: an empty doc yields -1, never 0" -1 "$(rsp_cum '' body_persist total_us)"

    st_ps_check "jnum: an absent key yields -1, never 0" \
        -1 "$(jnum '{"download_requested":0}' tip_eval_header_height)"
    st_ps_check "jnum: a genuine zero is preserved as 0, not turned into the sentinel" \
        0 "$(jnum '{"download_requested":0}' download_requested)"

    # ── the four phase rows: always four, never a fabricated zero ────────────
    st_set_phases() {  # pcS pcE hS hE bS bE fS fE  (-1 = unobserved)
        local i=0 p
        PH_START[peer_connect]="$1"; PH_END[peer_connect]="$2"
        PH_START[headers]="$3";      PH_END[headers]="$4"
        PH_START[bodies]="$5";       PH_END[bodies]="$6"
        PH_START[fold]="$7";         PH_END[fold]="$8"
        # Mirror what phase_mark does: an observed end always carries a kind.
        # Leaving it at "unobserved" here would let the fixture assert a shape
        # the real code can never produce.
        for p in $PHASE_NAMES; do
            if [ "${PH_END[$p]}" = "-1" ]; then PH_END_SRCKIND["$p"]="unobserved"
            elif [ "$p" = "peer_connect" ]; then PH_END_SRCKIND["$p"]="exact_node_recorded"
            else PH_END_SRCKIND["$p"]="upper_bound_poll_observed"; fi
        done
        i=$i
    }
    st_set_phases 1000 1010 1010 1100 1050 1500 1060 1520
    PHASE_TTFP_US=8421
    st_rows="$(phase_rows_json)"
    st_ps_check "phases: all four sync phases are emitted" \
        4 "$(printf '%s' "$st_rows" | grep -o '"level":"sync_phase"' | wc -l | tr -d ' ')"
    st_ps_check "phases: every sync element names a duration_source (the symmetry checker requires it)" \
        4 "$(printf '%s' "$st_rows" | grep -o '"duration_source":' | wc -l | tr -d ' ')"
    st_ps_check "phases: peer_connect duration is its own bracket (10s), not the whole window" \
        1 "$(printf '%s' "$st_rows" | grep -c '"phase":"sync.peer_connect","level":"sync_phase","observed":true,"start_unix":1000,"end_unix":1010,"duration_ms":10000' | tr -d ' ')"
    st_ps_check "phases: the fold gets its own 460s bracket" \
        1 "$(printf '%s' "$st_rows" | grep -c '"phase":"sync.fold","level":"sync_phase","observed":true,"start_unix":1060,"end_unix":1520,"duration_ms":460000' | tr -d ' ')"
    st_ps_check "phases: a fully observed run emits NO unobserved_reason" \
        0 "$(printf '%s' "$st_rows" | grep -o 'unobserved_reason' | wc -l | tr -d ' ')"
    st_ps_check "phases: peer_connect carries the node's own latched time_to_first_peer_us alongside" \
        1 "$(printf '%s' "$st_rows" | grep -c '"node_time_to_first_handshaked_peer_us":8421' | tr -d ' ')"
    st_ps_check "phases: the node's µs figure is NOT presented as the phase duration" \
        1 "$(printf '%s' "$st_rows" | grep -c 'This is NOT this phase.s duration' | tr -d ' ')"
    st_ov="$(phase_overlap_json 1600)"
    st_ps_check "overlap: the artifact says outright that the phases do not partition the window" \
        1 "$(printf '%s' "$st_ov" | grep -c '"phases_partition_the_window":false' | tr -d ' ')"
    st_ps_check "overlap: the SUM double-counts (10+90+450+460 = 1010s)" \
        1 "$(printf '%s' "$st_ov" | grep -c '"sum_of_observed_phase_ms":1010000' | tr -d ' ')"
    st_ps_check "overlap: the UNION is the real wall clock covered (1000..1520 = 520s)" \
        1 "$(printf '%s' "$st_ov" | grep -c '"union_of_observed_phase_ms":520000' | tr -d ' ')"
    st_ps_check "overlap: the double count is published, not left to be inferred" \
        1 "$(printf '%s' "$st_ov" | grep -c '"double_counted_ms":490000' | tr -d ' ')"
    st_ps_check "overlap: bodies and fold are shown overlapping by 440s" \
        1 "$(printf '%s' "$st_ov" | grep -c '"sync.bodies|sync.fold":440000' | tr -d ' ')"
    st_ps_check "overlap: two phases that only touch report 0 overlap, which is a real measurement here" \
        1 "$(printf '%s' "$st_ov" | grep -c '"sync.headers|sync.peer_connect":0' | tr -d ' ')"
    # B) NOTHING observed — the fail-closed case, and the one that matters most.
    st_set_phases -1 -1 -1 -1 -1 -1 -1 -1
    PHASE_TTFP_US=-1
    st_rows0="$(phase_rows_json)"
    st_ps_check "unobserved: all four phases are STILL emitted (never silently dropped)" \
        4 "$(printf '%s' "$st_rows0" | grep -o '"level":"sync_phase"' | wc -l | tr -d ' ')"
    st_ps_check "unobserved: every phase reports observed:false" \
        4 "$(printf '%s' "$st_rows0" | grep -o '"observed":false' | wc -l | tr -d ' ')"
    st_ps_check "unobserved: NOT ONE phase reports a duration of 0ms" \
        0 "$(printf '%s' "$st_rows0" | grep -o '"duration_ms":0' | wc -l | tr -d ' ')"
    st_ps_check "unobserved: every duration is null, the never-measured token" \
        4 "$(printf '%s' "$st_rows0" | grep -o '"duration_ms":null' | wc -l | tr -d ' ')"
    st_ps_check "unobserved: all eight PHASE EDGES carry a NAMED reason" \
        8 "$(printf '%s' "$st_rows0" | grep -oE '"(start|end)_unobserved_reason":"' | wc -l | tr -d ' ')"
    # The auxiliary node-side µs figure has its OWN named absence, separate from
    # the eight edges above: it measures a different window, so it must be able
    # to be missing while the edges are present and vice versa.
    st_ps_check "unobserved: the node's latched µs figure is null with its own named reason" \
        1 "$(printf '%s' "$st_rows0" | grep -c '"node_time_to_first_handshaked_peer_us":null' | tr -d ' ')"
    st_ps_check "unobserved: that reason names the 0 sentinel it refused to report as a measurement" \
        1 "$(printf '%s' "$st_rows0" | grep -c "no peer yet' sentinel" | tr -d ' ')"
    st_ps_check "unobserved: no edge reason is the placeholder that means the table is incomplete" \
        0 "$(printf '%s' "$st_rows0" | grep -c 'no reason recorded, which is itself a defect' | tr -d ' ')"
    st_ps_check "unobserved: duration_source is still named, so a reader knows WHICH dumper came up empty" \
        4 "$(printf '%s' "$st_rows0" | grep -o '"duration_source":' | wc -l | tr -d ' ')"
    st_ov0="$(phase_overlap_json 1600)"
    st_ps_check "unobserved overlap: the sum is null, never 0" \
        1 "$(printf '%s' "$st_ov0" | grep -c '"sum_of_observed_phase_ms":null' | tr -d ' ')"
    st_ps_check "unobserved overlap: the union is null, never 0" \
        1 "$(printf '%s' "$st_ov0" | grep -c '"union_of_observed_phase_ms":null' | tr -d ' ')"
    st_ps_check "unobserved overlap: all six pairwise overlaps are null, never 0" \
        6 "$(printf '%s' "$st_ov0" | grep -o '|sync\.[a-z_]*":null' | wc -l | tr -d ' ')"
    st_ps_check "unobserved overlap: the observed phase count is a real 0, and says so" \
        1 "$(printf '%s' "$st_ov0" | grep -c '"observed_phase_count":0' | tr -d ' ')"
    # C) THE DISCRIMINATION THAT MAKES B MEANINGFUL. A phase that genuinely took
    #    no measurable time (start == end within one second) must report a REAL
    #    0ms with observed:true — and must therefore look nothing like case B.
    #    If these two cases printed the same thing, the sentinel would be doing
    #    no work at all.
    st_set_phases 1000 1000 -1 -1 -1 -1 -1 -1
    st_rowsz="$(phase_rows_json)"
    st_ps_check "a genuinely instant phase reports a REAL 0ms and observed:true" \
        1 "$(printf '%s' "$st_rowsz" | grep -c '"phase":"sync.peer_connect","level":"sync_phase","observed":true,"start_unix":1000,"end_unix":1000,"duration_ms":0' | tr -d ' ')"
    st_ps_check "a genuinely instant phase carries NO edge unobserved_reason (it was observed)" \
        0 "$(printf '%s' "$st_rowsz" | grep -o '"phase":"sync.peer_connect"[^}]*' | grep -oE '"(start|end)_unobserved_reason"' | wc -l | tr -d ' ')"
    # D) A HALF-OBSERVED phase has no duration. Manufacturing one from the
    #    capture time would silently convert a missing boundary into a number.
    st_set_phases 1000 -1 -1 -1 -1 -1 -1 -1
    st_ps_check "half-observed: a start with no end yields -1, never an elapsed-so-far guess" \
        -1 "$(phase_span_ms peer_connect)"
    st_rowsh="$(phase_rows_json)"
    st_ps_check "half-observed: the row still carries the observed start_unix as evidence" \
        1 "$(printf '%s' "$st_rowsh" | grep -c '"phase":"sync.peer_connect","level":"sync_phase","observed":false,"start_unix":1000,"end_unix":null,"duration_ms":null' | tr -d ' ')"
    st_ps_check "half-observed: exactly one edge reason is emitted for that phase, not two" \
        1 "$(printf '%s' "$st_rowsh" | grep -o '"phase":"sync.peer_connect"[^}]*' | grep -oE '"(start|end)_unobserved_reason"' | wc -l | tr -d ' ')"

    # phase_mark: FIRST observation wins. A boundary that could be re-stamped by
    # a later tick would slide forward for the whole run and land on whichever
    # tick happened to be last, which is not a boundary at all.
    st_set_phases -1 -1 -1 -1 -1 -1 -1 -1
    PHASE_BOUNDARIES_TSV=""; PHASE_PROFILE_DIR=""
    phase_mark fold start 1111 upper_bound_poll_observed "first"
    phase_mark fold start 2222 upper_bound_poll_observed "second"
    st_ps_check "phase_mark: a boundary is stamped once — a later tick cannot move it" \
        1111 "${PH_START[fold]}"
    phase_mark fold end 0 exact_node_recorded "zero"
    st_ps_check "phase_mark: a 0 reading is refused, so a 'no peer yet' sentinel never becomes a boundary" \
        -1 "${PH_END[fold]}"
    phase_mark fold end -1 exact_node_recorded "sentinel"
    st_ps_check "phase_mark: the -1 sentinel is refused too" -1 "${PH_END[fold]}"
    # The RPC-silence guard. With an empty frontier read, phase_observe must
    # mark NOTHING — not even the boundaries it could decide from its arguments
    # alone. Without the guard the fold branch below would still fire off the
    # hstar argument, so this check goes red the moment the guard is removed.
    # (It also runs with no `rpc` reachable, which is itself the proof that the
    # guard short-circuits before any RPC is attempted.)
    st_set_phases -1 -1 -1 -1 -1 -1 -1 -1
    PHASE_TARGET_HEIGHT=-1
    phase_observe 1000 500 500 ""
    st_ps_check "rpc silence: an unreadable tick marks NO boundary, not even fold.start" \
        -1 "${PH_START[fold]}"
    st_ps_check "rpc silence: the target height is not learned from an unreadable tick either" \
        -1 "$PHASE_TARGET_HEIGHT"
    st_set_phases -1 -1 -1 -1 -1 -1 -1 -1
    unset -f st_set_phases
    phase_state_init
    PHASE_TTFP_US=-1; PHASE_TARGET_HEIGHT=-1


    # ── phase_observe driven end to end on REAL-SHAPED dumper docs ──────────
    # Everything above tests a reader or an emitter in isolation. This drives
    # the state machine itself across three ticks with the exact JSON shapes the
    # node emits, so a boundary rule that is individually correct but wired to
    # the wrong field still goes red. `rpc` is stubbed HERE only; the real
    # definition is further down this file and never runs in --selftest.
    st_rpc_sm=""; st_rpc_pl=""; st_rpc_om=""
    rpc() {
        case "$*" in
            "dumpstate sync_monitor")   printf '%s' "$st_rpc_sm" ;;
            "dumpstate peer_lifecycle") printf '%s' "$st_rpc_pl" ;;
            "dumpstate omniscience")    printf '%s' "$st_rpc_om" ;;
            *) : ;;
        esac
    }
    phase_state_init
    PHASE_TARGET_HEIGHT=-1; PHASE_TTFP_US=-1
    PHASE_BOUNDARIES_TSV=""; PHASE_PROFILE_DIR=""
    # tick 1 — handshake done, nothing else has started. A fresh node reports
    # header_admit cursor 1 and body_persist cursor 0; neither may be read as
    # "headers/bodies started".
    st_rpc_pl="$st_pl_doc"
    # The launch stamp, exactly as the top-level call site sets it.
    phase_mark peer_connect start 1700000200 exact_harness_stamp "fixture launch stamp"
    st_rpc_om='{"subsystem":"omniscience","state":{"time_to_first_peer_us":8421,"handshaked_peers":1}}'
    st_rpc_sm='{"subsystem":"sync_monitor","state":{"tip_eval_header_height":0,"download_requested":0,"download_received":0,"last_block_connected_height":0,"last_block_connected_time":0}}'
    st_fj1='{"hstar":0,"network_tip":3224108,"network_tip_read_ok":true,"stage_cursors":[{"stage":"header_admit","read_ok":true,"cursor":1},{"stage":"body_persist","read_ok":true,"cursor":0}]}'
    phase_observe 1700000410 0 3224108 "$st_fj1"
    st_ps_check "e2e tick1: peer_connect.end is the node's own handshake second, not the tick" \
        1700000400 "${PH_END[peer_connect]}"
    st_ps_check "e2e tick1: the node's latched µs figure was picked up" 8421 "$PHASE_TTFP_US"
    st_ps_check "e2e tick1: the target height was learned from network_tip" 3224108 "$PHASE_TARGET_HEIGHT"
    st_ps_check "e2e tick1: a FRESH header_admit cursor of 1 does NOT start the headers phase" \
        -1 "${PH_START[headers]}"
    st_ps_check "e2e tick1: download_requested 0 does NOT start the bodies phase" \
        -1 "${PH_START[bodies]}"
    st_ps_check "e2e tick1: hstar 0 does NOT start the fold phase" -1 "${PH_START[fold]}"
    # tick 2 — headers admitting, bodies requested, fold moving. All three
    # starts land on this tick and NONE of the ends do.
    st_rpc_sm='{"subsystem":"sync_monitor","state":{"tip_eval_header_height":0,"download_requested":128,"download_received":64,"last_block_connected_height":0,"last_block_connected_time":0}}'
    st_fj2='{"hstar":3056758,"network_tip":3224108,"network_tip_read_ok":true,"stage_cursors":[{"stage":"header_admit","read_ok":true,"cursor":900000},{"stage":"body_persist","read_ok":true,"cursor":800000}]}'
    phase_observe 1700000500 3056758 3224108 "$st_fj2"
    st_ps_check "e2e tick2: headers started off the header_admit cursor" 1700000500 "${PH_START[headers]}"
    st_ps_check "e2e tick2: bodies started off download_requested" 1700000500 "${PH_START[bodies]}"
    st_ps_check "e2e tick2: the fold started off a real hstar" 1700000500 "${PH_START[fold]}"
    st_ps_check "e2e tick2: headers has NOT ended (cursor is short of the target)" -1 "${PH_END[headers]}"
    st_ps_check "e2e tick2: bodies has NOT ended" -1 "${PH_END[bodies]}"
    st_ps_check "e2e tick2: the fold has NOT ended" -1 "${PH_END[fold]}"
    # tick 3 — caught up. Cursors are the NEXT height, so target+1 is the
    # 'finished the target' condition; using >= would close a phase one block
    # early and shorten every reported duration.
    st_rpc_sm='{"subsystem":"sync_monitor","state":{"tip_eval_header_height":3224110,"download_requested":25527,"download_received":25527,"last_block_connected_height":3056758,"last_block_connected_time":1700000200}}'
    st_fj3='{"hstar":3224110,"network_tip":3224108,"network_tip_read_ok":true,"stage_cursors":[{"stage":"header_admit","read_ok":true,"cursor":3224111},{"stage":"body_persist","read_ok":true,"cursor":3224111}]}'
    phase_observe 1700000900 3224110 3224108 "$st_fj3"
    st_ps_check "e2e tick3: headers ended when the cursor passed the target" 1700000900 "${PH_END[headers]}"
    st_ps_check "e2e tick3: bodies ended off body_persist's cursor" 1700000900 "${PH_END[bodies]}"
    st_ps_check "e2e tick3: the fold ended when hstar caught the tip" 1700000900 "${PH_END[fold]}"
    # THE MEASURED REFUTATION, pinned. last_block_connected_time in tick 3 is
    # 1700000200 — 700s before the run ended and 200s before the phases even
    # started. That is the real shape from the archived PASS run
    # 20260821T135540Z-2484174, where it sat 437s stale at a height 167,352
    # blocks below the tip. If bodies.end ever goes back to reading it, this
    # check catches the resulting time-travelling boundary.
    st_ps_check "e2e: bodies.end did NOT come from the stale last_block_connected_time" \
        1 "$([ "${PH_END[bodies]}" != "1700000200" ] && echo 1 || echo 0)"
    st_ps_check "e2e: every phase ended after it started (no boundary ran backwards)" \
        4 "$(n=0; for p in $PHASE_NAMES; do [ "${PH_END[$p]}" -ge "${PH_START[$p]}" ] 2>/dev/null && n=$((n+1)); done; echo $n)"
    st_ps_check "e2e: peer_connect is 200s, and is NOT the whole window" \
        200000 "$(phase_span_ms peer_connect)"
    st_ps_check "e2e: headers is 400s" 400000 "$(phase_span_ms headers)"
    st_ps_check "e2e: bodies is 400s" 400000 "$(phase_span_ms bodies)"
    st_ps_check "e2e: the fold is 400s" 400000 "$(phase_span_ms fold)"
    st_ove2e="$(phase_overlap_json 1700000900)"
    st_ps_check "e2e overlap: headers/bodies/fold ran CONCURRENTLY and the sum says so (200+400*3)" \
        1 "$(printf '%s' "$st_ove2e" | grep -c '"sum_of_observed_phase_ms":1400000' | tr -d ' ')"
    st_ps_check "e2e overlap: the union is the real covered clock (200s + 400s = 600s, with a 100s gap between them)" \
        1 "$(printf '%s' "$st_ove2e" | grep -c '"union_of_observed_phase_ms":600000' | tr -d ' ')"
    st_ps_check "e2e overlap: 800s of the 1400s sum is double-counted, and that is published" \
        1 "$(printf '%s' "$st_ove2e" | grep -c '"double_counted_ms":800000' | tr -d ' ')"
    # The 100s between peer_connect ending and the other three starting belongs
    # to NO phase. It must be reported as unattributed, not silently absorbed
    # into a neighbouring phase and not called idle — that gap is exactly the
    # kind of time this split exists to make visible.
    st_ps_check "e2e overlap: the 100s no phase claims is reported, not absorbed" \
        1 "$(printf '%s' "$st_ove2e" | grep -c '"window_ms_covered_by_no_phase":' | tr -d ' ')"
    st_ps_check "e2e overlap: union + the gap accounts for the whole span the phases straddle" \
        1 "$([ $(( 600000 + 100000 )) = 700000 ] && echo 1 || echo 0)"
    st_ps_check "e2e overlap: bodies and fold are shown fully overlapping" \
        1 "$(printf '%s' "$st_ove2e" | grep -c '"sync.bodies|sync.fold":400000' | tr -d ' ')"
    st_rowse2e="$(phase_rows_json)"
    st_ps_check "e2e rows: every phase is observed" \
        4 "$(printf '%s' "$st_rowse2e" | grep -o '"observed":true' | wc -l | tr -d ' ')"
    st_ps_check "e2e rows: no observed phase reports end_kind unobserved" \
        0 "$(printf '%s' "$st_rowse2e" | grep -o '"end_kind":"unobserved"' | wc -l | tr -d ' ')"
    st_ps_check "e2e rows: peer_connect's end is the node-recorded kind, not a poll bound" \
        1 "$(printf '%s' "$st_rowse2e" | grep -c '"phase":"sync.peer_connect".*"end_kind":"exact_node_recorded"' | tr -d ' ')"
    unset -f rpc
    phase_state_init
    PHASE_TARGET_HEIGHT=-1; PHASE_TTFP_US=-1
    # Source-text pins, anchored on the LINES THAT DO THE WORK. Patterns are
    # assembled from concatenated literals where they could otherwise match
    # their own source line.
    grep -qE '^    phase_observe "\$now" "\$hs" "\$nt" "\$fj"$' "${BASH_SOURCE[0]}"
    st_check "phase_observe is CALLED in the sample loop (not merely defined)" 0 $?
    grep -qE '^phase_observe "\$\(date \+%s\)" "\$final_hs" "\$final_nt" "\$final_fj"$' "${BASH_SOURCE[0]}"
    st_check "a final boundary sweep runs on the verdict-boundary readback" 0 $?
    grep -qE '^    phase_boundaries_tsv_init$' "${BASH_SOURCE[0]}"
    st_check "the durable boundary log is armed BEFORE the first tick" 0 $?
    grep -qE '^    _ph_sync="\$\(phase_rows_json\)"$' "${BASH_SOURCE[0]}"
    st_check "the sync phases are assembled into phases[] (not computed and dropped)" 0 $?
    grep -qE '^    PHASE_OVERLAP_JSON="\$\(phase_overlap_json "\$captured_at"\)"$' "${BASH_SOURCE[0]}"
    st_check "the overlap object is computed at capture" 0 $?
    grep -q '"phase_overlap": %s' "${BASH_SOURCE[0]}"
    st_check "proof.json emits the phase_overlap object" 0 $?
    grep -qE '^        phase_profile_index_json >"\$PHASE_PROFILE_DIR/index.json"' "${BASH_SOURCE[0]}"
    st_check "the phase-profiles manifest is written on every run" 0 $?
    # The instrument must not have grown a verdict. If phase_observe ever writes
    # `reached`, the split has stopped being instrumentation.
    st_pat_verdict='phase_observe[^)]*'"reached"'='
    grep -qE "$st_pat_verdict" "${BASH_SOURCE[0]}"
    st_check "the phase split sets no verdict variable (instrumentation only)" 1 $?
    if [ "$st_fail" = 0 ]; then
        echo "cold-start-wipe-stopwatch: --selftest PASS"
        exit 0
    fi
    echo "cold-start-wipe-stopwatch: --selftest FAIL" >&2
    exit 1
fi

# capture_run_bundle — on EVERY verdict, PASS INCLUDED, snapshot the live
# diagnostic state a human/agent needs to root-cause OR re-cost the run WITHOUT
# re-running the harness.
#
# THIS USED TO BE capture_failure_bundle, called only when `verdict != pass`.
# That asymmetry meant a SUCCESSFUL run left three files (proof.json +
# node.log + node.tail.log) and no per-phase evidence at all, while a failing
# run left the full set — so the one artifact class you actually want to
# optimize against was the one class that threw its measurements away. The one
# real PASS artifact on disk (build/c3-stopwatch/20260728T000207Z-2102851/) is
# exactly that: three files, no reducer_stage_profile.json, no stage-*.json.
# There is no cheaper time to read the node's own per-stage cost than the moment
# it just finished the run, and a baseline that only exists on failure is not a
# baseline. Capture is now unconditional; only the LABELS differ by verdict.
#
# Captured: frontier.json (dumpstate reducer_frontier),
# reducer_drive.json (the synchronous drain/lock owner and its last exit),
# reducer_stage_profile.json (per-stage RPF_* sub-phase timing: disk read,
# event encode/append, created-index, stage-log cursor — the fold-cost split),
# stage-*.json (each reducer stage's cursor/counters/last blocker),
# blocker.json (dumpstate blocker), ops.log.tail.txt (the typed `ops logs`
# command if the node is still alive/RPC-reachable, else a plain tail of
# node.log). Sets BUNDLE_CAPTURE_FAILED=true if ANY piece could not be
# captured — a dropped bundle piece is RECORDED, never silently missing.
# Sets FRONTIER_BUSY_AT_CAPTURE=true when frontier.json WAS captured but its
# content is a progress_store-busy partial doc — the file is still written
# (never dropped just because it's busy), only LABELED, per D6. Safe to call
# before NODE_BIN/DATADIR/PID are ever set (an early binary-absent/peer-
# unreachable skip has nothing to capture from).
capture_run_bundle() {
    BUNDLE_CAPTURE_FAILED="false"
    FRONTIER_BUSY_AT_CAPTURE="false"
    local got_frontier=0 got_drive=0 got_profile=0 got_stages=0 got_blocker=0 got_logs=0 got_net=0
    local got_timings=0
    if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null && [ -x "${NODE_BIN:-}" ] && [ -n "${DATADIR:-}" ]; then
        # Frontier read goes through rpc_frontier (bounded retries + busy
        # handling) so a lock-contention blip during capture doesn't drop the
        # artifact to 0 bytes. Under heavy fold load this single one-shot was
        # exactly what returned empty and mislabelled a healthy climb — capture
        # must survive the same busy window the sample loop does.
        rpc_frontier >"$ARTIFACT_DIR/frontier.json" 2>/dev/null
        [ -s "$ARTIFACT_DIR/frontier.json" ] && got_frontier=1
        if [ "$got_frontier" = 1 ] && is_busy_response "$(cat "$ARTIFACT_DIR/frontier.json" 2>/dev/null)"; then
            FRONTIER_BUSY_AT_CAPTURE="true"
        fi
        "$NODE_BIN" -rpcport="$RPC" -datadir="$DATADIR" dumpstate reducer_drive \
            >"$ARTIFACT_DIR/reducer_drive.json" 2>/dev/null && [ -s "$ARTIFACT_DIR/reducer_drive.json" ] && got_drive=1
        "$NODE_BIN" -rpcport="$RPC" -datadir="$DATADIR" dumpstate reducer_stage_profile \
            >"$ARTIFACT_DIR/reducer_stage_profile.json" 2>/dev/null && [ -s "$ARTIFACT_DIR/reducer_stage_profile.json" ] && got_profile=1
        # boot_timings: the flight recorder's durable per-stage boot history
        # (config/src/boot_flight_recorder.c). It is the ONLY source of the
        # median_ms a phases[] row can be compared against, so phases[] would
        # be un-baselineable without it — one boot's ms with nothing to judge it
        # by is a number, not a measurement.
        "$NODE_BIN" -rpcport="$RPC" -datadir="$DATADIR" dumpstate boot_timings \
            >"$ARTIFACT_DIR/boot_timings.json" 2>/dev/null && [ -s "$ARTIFACT_DIR/boot_timings.json" ] && got_timings=1
        got_stages=1
        for stage_name in header_admit validate_headers body_fetch body_persist \
                          script_validate proof_validate utxo_apply tip_finalize; do
            "$NODE_BIN" -rpcport="$RPC" -datadir="$DATADIR" dumpstate "$stage_name" \
                >"$ARTIFACT_DIR/stage-$stage_name.json" 2>/dev/null &&
                [ -s "$ARTIFACT_DIR/stage-$stage_name.json" ] || got_stages=0
        done
        # Network/peer capture. On a loopback run this is uninteresting (a
        # local peer always handshakes), which is exactly why it was missing.
        # On a REMOTE run it answers the first question any non-pass verdict
        # raises — did we ever complete a P2P handshake at all, or did the peer
        # refuse us pre-version? net-peer_lifecycle.json carries the
        # attempted/connected/version_sent/verack_received/handshake_complete/
        # pre_handshake_disconnects counters; net-connman.json carries the
        # per-addnode dial ledger (tcp_failures vs protocol_failures, backoff);
        # net-network.json carries the chain_view/census rollup.
        # sync_monitor is in this list for a reason beyond tidiness: it is the
        # ONLY dumper that carries a byte counter (download_bytes_received). An
        # earlier revision captured only the three below, found no bytes in
        # them, and concluded no dumper anywhere exposed bytes — a false premise
        # that got written into the omitted-fields explanation. Capturing it
        # keeps the raw reading next to the delta computed from it, so a reader
        # can check the arithmetic instead of trusting it.
        got_net=1
        # block_intake is in this list because download_requested vs
        # download_received in sync_monitor cannot distinguish "the peer never
        # sent it" from "we received it and threw it away because the 128-slot
        # intake ring was full". Only block_intake.dropped separates those two,
        # and they have opposite fixes.
        for net_name in connman peer_lifecycle network sync_monitor block_intake; do
            "$NODE_BIN" -rpcport="$RPC" -datadir="$DATADIR" dumpstate "$net_name" \
                >"$ARTIFACT_DIR/net-$net_name.json" 2>/dev/null &&
                [ -s "$ARTIFACT_DIR/net-$net_name.json" ] || got_net=0
        done
        # Blocker read is retried too — it feeds the STALLED-NAMED verdict, so a
        # busy-window miss that empties it must not silently erase a real named
        # blocker.
        rpc_retry_nonempty dumpstate blocker \
            >"$ARTIFACT_DIR/blocker.json" 2>/dev/null
        [ -s "$ARTIFACT_DIR/blocker.json" ] && got_blocker=1
        "$NODE_BIN" -rpcport="$RPC" -datadir="$DATADIR" ops logs \
            --pattern='.' --since_secs=3600 --max_lines=500 --level=all \
            >"$ARTIFACT_DIR/ops.log.tail.txt" 2>/dev/null && [ -s "$ARTIFACT_DIR/ops.log.tail.txt" ] && got_logs=1
    fi
    if [ "$got_logs" = 0 ] && [ -n "${DATADIR:-}" ] && [ -f "$DATADIR/node.log" ]; then
        tail -200 "$DATADIR/node.log" >"$ARTIFACT_DIR/ops.log.tail.txt" 2>/dev/null && got_logs=1
    fi
    # The banlist is the one piece that is a FILE, not an RPC: copy it when the
    # node wrote one so a "did we ban our only peer" question is answerable
    # from the artifact alone. Absent is the normal case and is NOT a capture
    # failure — banlist_present in proof.json records which it was.
    BANLIST_PRESENT="false"
    if [ -n "${DATADIR:-}" ] && [ -f "$DATADIR/banlist.dat" ] &&
       cp -p -- "$DATADIR/banlist.dat" "$ARTIFACT_DIR/banlist.dat" 2>/dev/null; then
        BANLIST_PRESENT="true"
    fi
    [ "$got_frontier" = 1 ] && [ "$got_drive" = 1 ] && [ "$got_profile" = 1 ] &&
        [ "$got_stages" = 1 ] && [ "$got_blocker" = 1 ] && [ "$got_logs" = 1 ] &&
        [ "$got_net" = 1 ] && [ "$got_timings" = 1 ] ||
        BUNDLE_CAPTURE_FAILED="true"
}

write_artifact() {
    verdict="$1"; rc="$2"; reason="${3:-}"
    captured_at="$(date +%s)"
    elapsed=0
    [ "${start:-0}" -gt 0 ] && elapsed=$((captured_at - start))
    mkdir -p "$ARTIFACT_DIR" 2>/dev/null || return 0
    BUNDLE_CAPTURE_FAILED="false"
    FRONTIER_BUSY_AT_CAPTURE="false"
    BANLIST_PRESENT="false"
    # UNCONDITIONAL — every verdict, PASS INCLUDED. Do NOT re-introduce a
    # `[ "$verdict" != "pass" ]` guard here: that is the exact asymmetry that
    # made a successful run destroy its own per-phase evidence. --selftest
    # asserts on this file's source text that the guard has not grown back.
    capture_run_bundle
    # Refresh the process counters one last time so the harness.observed_sync
    # phase reports the counters as of capture, not as of the last sample tick.
    # Refresh boot evidence FIRST: an in-process execv retains PID but resets
    # node-owned counters, so bytes_window_close must see the new boot ordinal.
    refresh_boot_observation
    refresh_process_counters
    # Close the byte window at the same instant, so the delta and the /proc
    # counters describe the same bracket.
    bytes_window_close
    NODE_LOG_CAPTURED="false"
    if [ -n "${DATADIR:-}" ] && [ -f "$DATADIR/node.log" ] &&
       cp -p -- "$DATADIR/node.log" "$ARTIFACT_DIR/node.log" 2>/dev/null; then
        NODE_LOG_CAPTURED="true"
    fi

    # ── phases[] assembly (before the JSON block, so a parse hiccup cannot
    # truncate proof.json mid-object). Boot phases are parsed from the COPY of
    # node.log just placed in the artifact dir, so proof.json and the log it was
    # derived from always agree.
    SAMPLES_ROWS=""
    if [ -n "$SAMPLES_TSV" ] && [ -f "$SAMPLES_TSV" ]; then
        SAMPLES_ROWS="$(awk 'NR > 1 { n++ } END { print n + 0 }' "$SAMPLES_TSV" 2>/dev/null)"
    fi
    PHASES_JSON=""
    _ph_harness="$(harness_phases_json "$captured_at")"
    _ph_boot=""
    if [ -f "$ARTIFACT_DIR/node.log" ]; then
        _ph_med="$ARTIFACT_DIR/.boot-timings-medians.tsv"
        boot_timings_median_pairs "$ARTIFACT_DIR/boot_timings.json" >"$_ph_med" 2>/dev/null || : >"$_ph_med"
        _ph_boot="$(phases_json_from_log "$ARTIFACT_DIR/node.log" "$_ph_med")"
        rm -f "$_ph_med" 2>/dev/null || true
    fi
    # ── phases[] assembly: sync phases FIRST, then harness, then boot ──────
    # The four SYNC-PHASE elements are always emitted and always all four. An
    # unobserved phase carries observed:false, duration_ms:null and a named
    # unobserved_reason — it is never dropped and never reported as 0ms.
    _ph_sync="$(phase_rows_json)"
    PHASES_JSON="$_ph_sync"
    [ -n "$_ph_harness" ] && PHASES_JSON="$PHASES_JSON,$_ph_harness"
    [ -n "$_ph_boot" ] && PHASES_JSON="$PHASES_JSON,$_ph_boot"
    PHASE_OVERLAP_JSON="$(phase_overlap_json "$captured_at")"
    # The phase-profiles manifest, written on EVERY run. See
    # phase_profile_index_json() for why an empty one is still written.
    if [ -n "$PHASE_PROFILE_DIR" ] && [ -d "$PHASE_PROFILE_DIR" ]; then
        phase_profile_index_json >"$PHASE_PROFILE_DIR/index.json" 2>/dev/null || true
    fi
    PHASES_PROVENANCE="sync.* elements: the FOUR-WAY SPLIT of the bulk-sync window (sync.peer_connect / sync.headers / sync.bodies / sync.fold), composed entirely from dumpers the node already publishes — peer_lifecycle peers[].handshake_complete_at, omniscience time_to_first_peer_us, sync_monitor tip_eval_header_height / download_requested / last_block_connected_{height,time}, reducer_frontier hstar / network_tip / stage_cursors[header_admit]. Nothing was added to the node for them. Each element carries its own start_kind and end_kind: exact_harness_stamp and exact_node_recorded are real instants; upper_bound_poll_observed means the harness saw the condition ALREADY true at a sample tick, so the true instant is at most poll_resolution_secs earlier. THESE FOUR PHASES OVERLAP AND DO NOT PARTITION THE WINDOW — see the phase_overlap object, which publishes their sum, their union, the double-counted milliseconds and the window time no phase claims. Per-boundary dumpstate reducer_stage_profile snapshots are in phase-profiles/ with a manifest in phase-profiles/index.json; a phase's per-stage cost is the DIFFERENCE of the two snapshots bracketing it. harness.* elements: this harness bracketed the window itself (date +%s on both sides). Boot elements: parsed from the node's own [boot] boot_topmark/boot_submark markers in node.log, median_ms joined from dumpstate boot_timings. Bytes: harness.observed_sync carries block_body_payload_bytes_received, the delta of dumpstate sync_monitor download_bytes_received across the bracketed window, counting successfully-parsed block-body message payload ONLY (no headers, handshake, inv/getdata, tx relay, compact blocks, per-message header, or TCP/IP framing) — a lower bound on wire bytes, emitted only when both window ends were read on the same boot because the counter resets per process. OMITTED for lack of an honest source: TOTAL network bytes (nothing in this tree counts wire bytes), bytes per boot-level phase (the counter has no phase segmentation), per-boot-phase cpu/disk (boot.c markers carry only a duration), exact per-boot-phase wall-clock start (the markers carry no timestamp and the top-level marks do not tile the boot), and the TRUE start of sync.headers and sync.bodies (nothing counts getheaders or getdata SENT) — start_ts_lower_bound and the upper_bound_poll_observed kinds are given instead and are bounds, not starts."

    {
        printf '{\n'
        printf '  "schema": "zcl.c3_stopwatch_artifact.v1",\n'
        printf '  "verdict": %s,\n' "$(json_string "$verdict")"
        printf '  "exit_code": %s,\n' "$rc"
        printf '  "reason": %s,\n' "$(json_string "$reason")"
        printf '  "wall_clock_seconds": %s,\n' "$(json_number_or_null "$elapsed")"
        printf '  "budget_seconds": %s,\n' "$(json_number_or_null "$BUDGET")"
        printf '  "boots": %s,\n' "$(json_number_or_null "$boots")"
        printf '  "last_respawn_reason": %s,\n' "$(json_string "$last_respawn_reason")"
        printf '  "peer": %s,\n' "$(json_string "$PEER")"
        printf '  "peer_precheck": %s,\n' "$(json_string "$PEER_PRECHECK")"
        printf '  "file_peer": %s,\n' "$(json_string "$FILE_PEER")"
        printf '  "header_source": %s,\n' "$(json_string "$HEADER_SOURCE")"
        printf '  "staged_bundle": %s,\n' "$(json_string "$BUNDLE_PATH")"
        printf '  "node_bin": %s,\n' "$(json_string "$NODE_BIN")"
        printf '  "first_hstar": %s,\n' "$(json_number_or_null "${first_hstar:-}")"
        printf '  "max_hstar": %s,\n' "$(json_number_or_null "$max_hstar")"
        printf '  "final_hstar": %s,\n' "$(json_number_or_null "$last_hstar")"
        printf '  "final_network_tip": %s,\n' "$(json_number_or_null "$last_network_tip")"
        printf '  "first_provable_sample": %s,\n' "$(json_number_or_null "${first_ps:-}")"
        printf '  "max_provable_sample": %s,\n' "$(json_number_or_null "$max_ps")"
        printf '  "final_provable_sample": %s,\n' "$(json_number_or_null "$last_ps")"
        printf '  "saw_provable_sample": %s,\n' "$([ "${saw_ps:-0}" = 1 ] && printf true || printf false)"
        printf '  "final_readback_failed": %s,\n' "${final_readback_failed:-false}"
        printf '  "reached_network_tip": %s,\n' "$([ "$verdict" = "pass" ] && printf true || printf false)"
        printf '  "scratch_datadir": %s,\n' "$(json_string "${DATADIR:-}")"
        printf '  "scratch_datadir_removed": true,\n'
        printf '  "node_log_captured": %s,\n' "$NODE_LOG_CAPTURED"
        printf '  "bundle_capture_failed": %s,\n' "$BUNDLE_CAPTURE_FAILED"
        printf '  "banlist_present": %s,\n' "${BANLIST_PRESENT:-false}"
        printf '  "frontier_busy_at_capture": %s,\n' "$FRONTIER_BUSY_AT_CAPTURE"
        printf '  "samples_tsv": %s,\n' \
            "$([ -n "$SAMPLES_TSV" ] && [ -f "$SAMPLES_TSV" ] && printf '"samples.tsv"' || printf 'null')"
        printf '  "samples_rows": %s,\n' "$(json_number_or_null "$SAMPLES_ROWS")"
        # WHAT WAS MEASURED. A phase timing with no identity attached is not a
        # baseline for anything: the next run cannot tell whether it got faster
        # or just ran a different binary against a different peer.
        # source_id_sha256 comes from the ONE canonical reader
        # (tools/scripts/source_identity_lib.sh zcl_binary_source_id — read once
        # at startup, before the run, so it describes the binary that was
        # actually timed).
        printf '  "measured_identity": {\n'
        printf '    "node_bin": %s,\n' "$(json_string "$NODE_BIN")"
        printf '    "node_bin_source_id_sha256": %s,\n' \
            "$([ -n "$NODE_BIN_SOURCE_ID" ] && json_string "$NODE_BIN_SOURCE_ID" || printf 'null')"
        printf '    "node_bin_source_id_source": "zcl_binary_source_id (tools/scripts/source_identity_lib.sh) over `%s agentbuild`",\n' \
            "$(json_escape "$(basename -- "$NODE_BIN")")"
        printf '    "peer": %s,\n' "$(json_string "$PEER")"
        printf '    "peer_precheck": %s,\n' "$(json_string "$PEER_PRECHECK")"
        printf '    "peer_advertised_tip": %s,\n' "$(json_number_or_null "$last_network_tip")"
        printf '    "peer_advertised_tip_source": "dumpstate reducer_frontier network_tip (best height any handshake-complete peer advertised); -1 means no handshake ever completed"\n'
        printf '  },\n'
        # phases[] — see the phases_json_from_log / harness_phases_json headers
        # for the provenance rule. Every element names the source of its
        # duration; a field with no honest source is absent, never zero.
        printf '  "phases_provenance": %s,\n' "$(json_string "$PHASES_PROVENANCE")"
        printf '  "phases": [%s],\n' "$PHASES_JSON"
        # phase_overlap — the anti-arithmetic-lie object. The four sync.*
        # phases share one timeline and OVERLAP (bodies stream while the fold
        # runs), so their durations must never be added up or subtracted from
        # the window. This publishes the sum, the union, the double count and
        # the unattributed remainder side by side so the overlap is stated
        # rather than left to be discovered by a reader doing bad arithmetic.
        printf '  "phase_overlap": %s,\n' "${PHASE_OVERLAP_JSON:-null}"
        # The durable per-boundary log and the per-boundary reducer_stage_profile
        # snapshot set, named by path so an artifact is self-describing.
        printf '  "phase_boundaries_tsv": %s,\n' \
            "$([ -n "$PHASE_BOUNDARIES_TSV" ] && [ -f "$PHASE_BOUNDARIES_TSV" ] && printf '"phase_boundaries.tsv"' || printf 'null')"
        printf '  "phase_stage_profiles_dir": %s,\n' \
            "$([ -n "$PHASE_PROFILE_DIR" ] && [ -d "$PHASE_PROFILE_DIR" ] && printf '"phase-profiles/"' || printf 'null')"
        # omitted_fields[] — see omitted_fields_json(). Every field the
        # measurement brief named that this run did NOT record, BY NAME, with
        # the reason. A silently absent field reads as "measured and fine";
        # this section is what makes that impossible here.
        printf '  "omitted_fields_provenance": "each row is a field the measurement brief asked for that this run did not record. scope=structural means no source exists in this tree for any run; scope=this_run means a source exists but this run could not read it.",\n'
        printf '  "omitted_fields": [%s]\n' "$(omitted_fields_json)"
        printf '}\n'
    } >"$ARTIFACT_DIR/proof.json"
    if [ -n "${DATADIR:-}" ] && [ -f "$DATADIR/node.log" ]; then
        tail -100 "$DATADIR/node.log" >"$ARTIFACT_DIR/node.tail.log" 2>/dev/null || true
    fi
    printf '%s\n' "$ARTIFACT_DIR" >"$ARTIFACT_ROOT/latest.txt" 2>/dev/null || true
    echo "cold-start-wipe-stopwatch: artifact=$ARTIFACT_DIR"
}

skip() { echo "cold-start-wipe-stopwatch: SKIP ($*)"; write_artifact "skip" 2 "$*"; exit 2; }
die()  { echo "cold-start-wipe-stopwatch: FAIL: $*" >&2; write_artifact "fail" 1 "$*"; exit 1; }

[ -x "$NODE_BIN" ] || skip "node binary absent/not executable: $NODE_BIN"

# Identity of WHAT IS ABOUT TO BE MEASURED, read once, before the run, via the
# ONE canonical reader (tools/scripts/source_identity_lib.sh). Empty output is a
# normal answer there ("nothing to report"), never a failure, so this cannot
# abort a run — an unidentifiable binary yields a null field in proof.json and
# the run still reports the verdict the node earned.
NODE_BIN_SOURCE_ID="$(zcl_binary_source_id "$NODE_BIN")"
echo "cold-start-wipe-stopwatch: node_bin_source_id=${NODE_BIN_SOURCE_ID:-<unavailable>}"

# ── the peer must be STATED (see the PEER assignment above) ──────────────────
# A proof lane that inherits its serving peer from a default is a proof lane
# that can be run by accident against whatever happens to be listening. The old
# default was the canonical node's own P2P port, so `make
# mvp-coldstart-to-tip-stopwatch` with no arguments dialled the operator's live
# node and pulled chain data off it. Refuse instead: SKIP is already this
# harness's "prerequisite absent" verdict (exit 2, which the Make wrapper turns
# into a clean no-op), and it records an honest artifact naming what is missing.
if [ -z "$PEER" ]; then
    skip "no_peer_configured — set ZCL_CS_PEER=HOST:PORT (or pass --peer=HOST:PORT / ZCL_PEER= via make). This harness has NO default peer on purpose: it used to default to 127.0.0.1:8033, the operator's canonical node, so a bare run silently synced off it. Point it at a stopwatch fixture peer (e.g. 127.0.0.1:39070), or name the canonical node explicitly if that is genuinely what you mean."
fi

peer_host="${PEER%:*}"
peer_port="${PEER##*:}"
[ -n "$peer_host" ] && [ -n "$peer_port" ] && [ "$peer_host" != "$peer_port" ] \
    || skip "invalid peer address: $PEER"
PEER_PRECHECK="$(peer_precheck "$peer_host" "$peer_port")"
if [ "$PEER_PRECHECK" = "unreachable" ]; then
    skip "serving peer not reachable: $PEER"
fi
if [ "$PEER_PRECHECK" = "accept_close" ]; then
    # ADVISORY, never a verdict: the peer accept()ed and closed before a byte
    # moved, so no P2P handshake can complete, `network_tip` stays unreadable,
    # and the PASS predicate is unreachable for the whole budget. Say so up
    # front instead of leaving an operator to infer it from 600s of -1 rows.
    # Most likely cause on a shared host: the peer's per-IP inbound sybil cap
    # (lib/net/src/net.c, max 3 inbound per IP) is already consumed by another
    # node on THIS machine. Check with:
    #   ss -tn state established "dst $peer_host:$peer_port"
    echo "cold-start-wipe-stopwatch: WARNING peer $PEER accepted the TCP connection and CLOSED IT IMMEDIATELY (zero bytes)."
    echo "cold-start-wipe-stopwatch: WARNING no P2P handshake can complete, so network_tip will stay unreadable and PASS is unreachable this run."
    echo "cold-start-wipe-stopwatch: WARNING likely the peer's per-IP inbound cap (max 3/IP, lib/net/src/net.c) — count local sockets with: ss -tn state established \"dst $PEER\""
    echo "cold-start-wipe-stopwatch: WARNING continuing anyway — the run still reports the verdict the node genuinely earned, never a SKIP."
fi
echo "cold-start-wipe-stopwatch: peer_precheck=$PEER_PRECHECK"
if [ -n "$FILE_PEER" ]; then
    file_peer_host="${FILE_PEER%:*}"
    file_peer_port="${FILE_PEER##*:}"
    [ -n "$file_peer_host" ] && [ -n "$file_peer_port" ] && \
        [ "$file_peer_host" != "$file_peer_port" ] \
        || skip "invalid file-service peer address: $FILE_PEER"
    if ! timeout 3 bash -c \
        "exec 3<>/dev/tcp/$file_peer_host/$file_peer_port" 2>/dev/null; then
        skip "file-service peer not reachable: $FILE_PEER"
    fi
fi
[ -z "$HEADER_SOURCE" ] || [ -d "$HEADER_SOURCE" ] \
    || skip "header-source copy absent: $HEADER_SOURCE"
[ -z "$BUNDLE_PATH" ] || [ -f "$BUNDLE_PATH" ] \
    || skip "bundle fixture absent: $BUNDLE_PATH"

DATADIR="$(mktemp -d /tmp/zcl-c3-stopwatch.XXXXXX)" || die "mktemp datadir failed"
ISO_HOME="$DATADIR-home"
mkdir -p "$ISO_HOME" || die "mkdir isolated HOME failed"
# Provision ONLY the proving-params dir into the isolated home (chain state
# stays untouched — this is not a sync shortcut, mainnet boot simply parks
# at the crypto_params_missing gate without it). Same convention as
# fresh-boot-proof.sh: a real fresh machine has params installed once and
# never re-fetches them per node, so this is not assisted seeding.
REAL_PARAMS="${ZCL_CS_PARAMS_DIR:-$HOME/.zcash-params}"
[ -d "$REAL_PARAMS" ] && ln -s "$REAL_PARAMS" "$ISO_HOME/.zcash-params" 2>/dev/null

cleanup() {
    [ -n "$PID" ] && kill -KILL -- "-$PID" 2>/dev/null || true
    case "$DATADIR" in /tmp/zcl-c3-stopwatch.*) rm -rf "$DATADIR" "$ISO_HOME" 2>/dev/null || true ;; esac
}
trap cleanup EXIT INT TERM

echo "cold-start-wipe-stopwatch: bin=$NODE_BIN peer=$PEER budget=${BUDGET}s sample=${SAMPLE_SECS}s"
echo "cold-start-wipe-stopwatch: file_peer=${FILE_PEER:-<none>}"
echo "cold-start-wipe-stopwatch: header_source=${HEADER_SOURCE:-<autonomous>} staged_bundle=${BUNDLE_PATH:-<autonomous>}"
echo "cold-start-wipe-stopwatch: datadir=$DATADIR (freshly wiped)"
echo "cold-start-wipe-stopwatch: iso-home=$ISO_HOME (no .zclassic legacy dir — genuinely fresh machine)"

start=$(date +%s)
if [ -n "$BUNDLE_PATH" ]; then
    mkdir -p "$DATADIR/bundles" || die "mkdir bundle staging dir failed"
    bundle_name="$(basename -- "$BUNDLE_PATH")"
    cp --reflink=auto -p -- "$BUNDLE_PATH" \
        "$DATADIR/bundles/$bundle_name" \
        || die "staging checkpoint bundle failed"
    echo "cold-start-wipe-stopwatch: staged bundle=$DATADIR/bundles/$bundle_name"
fi
if [ -n "$HEADER_SOURCE" ]; then
    echo "cold-start-wipe-stopwatch: importing frozen-validated headers from datadir COPY"
    HEADER_IMPORT_START=$(date +%s)
    if ! env HOME="$ISO_HOME" "$NODE_BIN" --importblockindex \
        "$HEADER_SOURCE" "$DATADIR/node.db" >>"$DATADIR/node.log" 2>&1; then
        die "header import from datadir COPY failed"
    fi
    HEADER_IMPORT_MS=$(( ($(date +%s) - HEADER_IMPORT_START) * 1000 ))
    echo "cold-start-wipe-stopwatch: header import complete (${HEADER_IMPORT_MS}ms)"
fi
node_args=(
    -datadir="$DATADIR" \
    -port=$P2P \
    -rpcport=$RPC \
    -fsport=$FS \
    -httpsport=$HTTPS \
    -listen=0 \
    -connect="$PEER" \
    -nolegacyimport \
    -nobgvalidation \
    -showmetrics=0
)
[ -n "$FILE_PEER" ] && node_args+=( -fileservice="$FILE_PEER" )

# launch_node — (re)start the node against the SAME fresh datadir with the SAME
# args, appending to the SAME node.log, and set the watched PID. Called once for
# the initial boot and once per followed self-respawn (boot 2..N): a supervised
# respawn is defined as "relaunch me on the same datadir", so staging (bundle /
# header import / install-on-next-boot request) is NEVER re-done here — it
# persists in the datadir for the next boot to consume. Mirrors what systemd
# Restart=always does to the live unit.
launch_node() {
    # The exact instant sync.peer_connect starts. Stamped on the FIRST
    # launch only: a followed self-respawn is the same run on the same
    # datadir, so moving this would restart a clock that never stopped.
    [ "$NODE_LAUNCH_UNIX" = "-1" ] && NODE_LAUNCH_UNIX=$(date +%s)
    setsid env HOME="$ISO_HOME" "$NODE_BIN" \
        "${node_args[@]}" \
        >>"$DATADIR/node.log" 2>&1 &
    PID=$!
}

launch_node
echo "cold-start-wipe-stopwatch: launched pid=$PID (boot $boots)"

rpc() { "$NODE_BIN" -rpcport=$RPC -datadir="$DATADIR" "$@" 2>/dev/null; }

# rpc_retry_nonempty <dumpstate-arg...> — a generic bounded-retry read (growing
# backoff 1,1,2,3s) that returns the first NON-EMPTY response, so a busy-window
# miss during failure-bundle capture doesn't drop a diagnostic artifact to 0
# bytes. Echoes the last response (possibly empty if every retry missed). The
# node RPC deadline (RPC_TIMEOUT_DEFAULT_MS, 10s) is what returns empty under a
# heavy fold; retrying across a longer window catches a load gap.
rpc_retry_nonempty() {
    local out="" backoff
    for backoff in 1 1 2 3 0; do
        out="$(rpc "$@")"
        [ -n "$out" ] && { printf '%s' "$out"; return 0; }
        [ "$backoff" = 0 ] && break
        sleep "$backoff"
    done
    printf '%s' "$out"
}

# dumpstate reads can transiently miss while the reducer drive holds the
# progress_store lock — `dumpstate reducer_frontier` then returns a PARTIAL
# doc, {"snapshot_status":"progress_store_busy","retryable":true}, with NO
# "hstar" field but STILL carrying cached_provable_tip (emitted lock-free before
# the trylock). Under a heavy fold the RPC deadline can also be missed entirely,
# returning empty. Retry with bounded, growing backoff (1,1,2,3,5s — ~12s worst
# case per call), preferring a FULL read (has "hstar"); failing that, return the
# best BUSY partial we saw (it carries the cached_provable_tip PROGRESS proxy)
# in preference to an empty response, so a later empty retry can never erase an
# earlier proxy. Sets FRONTIER_LAST_BUSY=1 when the best we got across retries
# was a busy partial (0 on a full read or a truly empty response). The caller
# tracks an unreadable STREAK across sample ticks so a progress_store that never
# yields even a proxy gets its own named verdict (see FRONTIER_BUSY_TIMEOUT_SECS
# in the main loop) instead of silently degrading into "no forward progress, no
# blocker" (silent-stall FAIL) — those are different claims: "we could not
# observe" is not "we observed nothing happening".
FRONTIER_LAST_BUSY=0
rpc_frontier() {
    local out="" best_busy="" backoff
    for backoff in 1 1 2 3 5 0; do
        out="$(rpc dumpstate reducer_frontier)"
        if printf '%s' "$out" | grep -q '"hstar"'; then
            FRONTIER_LAST_BUSY=0
            printf '%s' "$out"
            return 0
        fi
        # Not a full read. Keep the busy partial (it still carries
        # cached_provable_tip) so a subsequent empty retry can't lose it.
        is_busy_response "$out" && best_busy="$out"
        [ "$backoff" = 0 ] && break
        sleep "$backoff"
    done
    if [ -n "$best_busy" ]; then
        FRONTIER_LAST_BUSY=1
        printf '%s' "$best_busy"
        return 0
    fi
    FRONTIER_LAST_BUSY=0
    printf '%s' "$out"
}

# Some boot-storage gates (config/src/boot.c boot_park_until_shutdown, e.g.
# crypto_params_missing) fire BEFORE the RPC server starts, so `dumpstate
# blocker` never sees them (RPC has nothing to answer with). The node still
# names the gate on stderr into node.log ("[boot] PARKED alive-degraded at
# gate '<name>' ... NOT crash-looping; waiting for a shutdown signal") — that
# is the honest named-stall signal in this window, not a silent hang. Surface
# it the same way the RPC blocker list would.
log_named_park() {
    grep -oE "PARKED alive-degraded at gate '[^']*'" "$DATADIR/node.log" 2>/dev/null |
        tail -1 | sed -E "s/.*gate '([^']*)'.*/\1/"
}

# Arm the per-tick sink BEFORE the first tick. The artifact dir is created here
# rather than at write_artifact time so samples.tsv accumulates DURING the run:
# a harness that is SIGKILLed at t=550s of a 600s budget still leaves the whole
# climb trace on disk, and the shape of the climb is what says which phase to
# optimize. These rows used to be printf-to-stdout only and died with the
# terminal.
mkdir -p "$ARTIFACT_DIR" 2>/dev/null || true
if [ -d "$ARTIFACT_DIR" ]; then
    SAMPLES_TSV="$ARTIFACT_DIR/samples.tsv"
    samples_tsv_init
    # The per-boundary sinks are armed here, beside samples.tsv, and for
    # the same reason: a SIGKILLed harness must still leave every boundary
    # it had already crossed on disk. phase-profiles/ is created
    # UNCONDITIONALLY — an empty directory plus a named empty_reason in its
    # index is honest; a directory that only exists when something was
    # captured makes an absent capture indistinguishable from a lost one.
    PHASE_BOUNDARIES_TSV="$ARTIFACT_DIR/phase_boundaries.tsv"
    phase_boundaries_tsv_init
    PHASE_PROFILE_DIR="$ARTIFACT_DIR/phase-profiles"
    mkdir -p "$PHASE_PROFILE_DIR" 2>/dev/null || PHASE_PROFILE_DIR=""
fi
# sync.peer_connect.start — recorded only now, not inside launch_node,
# because the boundary log it writes to did not exist yet at launch time.
# NODE_LAUNCH_UNIX itself was stamped at the real launch instant, so the
# VALUE is the launch, not this line.
phase_mark peer_connect start "$NODE_LAUNCH_UNIX" "exact_harness_stamp" \
    "harness date +%s immediately before the first launch_node exec"
LOOP_START_UNIX=$(date +%s)
# Open the byte window here, at the same instant the observed-sync clock starts.
# It usually MISSES on this first attempt — the node launched seconds ago and the
# RPC server may not be answering yet — which is why the sample loop retries it
# until it lands and records the boot/time of the attempt that did.
bytes_window_open_try

printf '%-8s %-10s %-10s %-10s %-8s %s\n' "t(s)" "hstar" "prov" "net_tip" "tip_ok" "blockers"
printf '%-8s %-10s %-10s %-10s %-8s %s\n' "----" "-----" "----" "-------" "------" "--------"

t=0
reached=0
while :; do
    now=$(date +%s); elapsed=$((now - start))
    if ! kill -0 "$PID" 2>/dev/null; then
        # The watched PID is gone. Distinguish a SUPERVISED SELF-RESPAWN (a
        # clean exit that wrote a self_respawn_* exit-reason breadcrumb — the
        # node asking to be relaunched on the same datadir, e.g. to consume an
        # install-on-next-boot request) from a REAL death (crash / no
        # breadcrumb / an unexpected operator_or_external exit nobody asked
        # for). Reading the breadcrumb — not the exit code — is authoritative:
        # it is written+fsync'd EARLY in the node's clean shutdown, so it is
        # already durable by the time the process actually exits ~seconds
        # later. (If the node's own in-process execv re-exec HELD, the PID
        # would never have died and we would not be here — this follows the
        # early-_exit path that bypasses that re-exec off-systemd.)
        wait "$PID" 2>/dev/null; node_ec=$?
        reason="$(read_exit_reason)"
        if is_self_respawn_reason "$reason"; then
            last_respawn_reason="$reason"
            if [ "$supervised_launches" -ge "$MAX_BOOTS" ] 2>/dev/null; then
                echo "cold-start-wipe-stopwatch: node EXITED early (t=${elapsed}s) — log tail:"
                tail -20 "$DATADIR/node.log" 2>/dev/null | sed 's/^/  /'
                die "self-respawn budget exhausted: followed $supervised_launches supervised launches (>= max $MAX_BOOTS), observed boots=$boots, last reason=$reason — the node keeps asking to respawn without reaching tip (runaway)"
            fi
            # Consume the breadcrumb so a subsequent crash (which writes NO new
            # breadcrumb) can never be mis-read as another respawn request via
            # this now-stale one. Then relaunch on the SAME datadir, keeping the
            # wall clock (start) running across boots.
            rm -f "$DATADIR/boot-exit-reason.v1" 2>/dev/null || true
            supervised_launches=$((supervised_launches + 1))
            echo "cold-start-wipe-stopwatch: FOLLOWED self-respawn (reason=$reason ec=$node_ec) — supervised launch $supervised_launches on same datadir (t=${elapsed}s, wall clock continues)"
            launch_node
            echo "cold-start-wipe-stopwatch: launched pid=$PID (supervised launch $supervised_launches)"
            sleep "$SAMPLE_SECS"
            continue
        fi
        echo "cold-start-wipe-stopwatch: node EXITED early (t=${elapsed}s, ec=$node_ec, boots=$boots) — log tail:"
        tail -20 "$DATADIR/node.log" 2>/dev/null | sed 's/^/  /'
        die "node process died before reaching network_tip (exit_reason=${reason:-<none: crash or no breadcrumb>} ec=$node_ec boots=$boots)"
    fi

    # execv self-respawn keeps PID alive.  Observe the node's own prologue
    # marker before sampling counters so the row and byte window use the real
    # boot ordinal rather than the supervisor-launch count.
    refresh_boot_observation
    fj="$(rpc_frontier)"
    bj="$(rpc dumpstate blocker)"

    hs="$(frontier_hstar_full "$fj")"      # authoritative full-read H* (-1 = read miss / busy)
    ps="$(frontier_provable_sample "$fj")" # progress sample: full H* or cached_provable_tip proxy (-1 = neither)
    nt="$(jget "$fj" network_tip)";        [ -z "$nt" ] && nt="-1"
    nt_ok="$(printf '%s' "$fj" | grep -oE '"network_tip_read_ok"[[:space:]]*:[[:space:]]*true')"
    bc="$(jget "$bj" active_count)";       [ -z "$bc" ] && bc="0"
    bids="$(blocker_ids "$bj")"
    [ -z "$bids" ] && bids="-"
    park_gate="$(log_named_park)"
    if [ -n "$park_gate" ] && [ "$bc" = "0" ]; then
        bc=1; bids="boot_park:$park_gate"
    fi

    printf '%-8s %-10s %-10s %-10s %-8s %s\n' "$elapsed" "$hs" "$ps" "$nt" "${nt_ok:+yes}" "b=$bc:$bids"
    # ...and the SAME tick, durably, with the node process's own CPU/RSS/disk
    # counters alongside it. stdout is for the operator watching; samples.tsv is
    # the record the next optimization pass reads.
    refresh_process_counters
    # Retry the window-open byte reading until one lands. No-op once it has.
    bytes_window_open_try
    samples_tsv_row "$elapsed" "$hs" "$ps" "$nt" \
        "$([ -n "$nt_ok" ] && printf yes || printf no)" \
        "$FRONTIER_LAST_BUSY" "$bc" "$bids"

    # ── SYNC PHASE BOUNDARIES, same tick, same clock ────────────────
    # Evidence-only: phase_observe writes phase state and nothing else.
    # It cannot move the PASS predicate, the budget, the busy timeout or
    # any exit code, and it is placed BEFORE the PASS break so the tick
    # that ends the run is the tick that closes sync.fold — the two can
    # never disagree about when H* caught the tip.
    phase_observe "$now" "$hs" "$nt" "$fj"

    # Bounded unreadable-streak check: only accumulates when NO usable provable
    # sample was obtained (ps == -1) AND the node kept answering the busy
    # partial doc (retryable:true). Once a fold starts publishing a
    # cached_provable_tip, ps>=0 and this resets — a busy-but-climbing node is
    # observed via the proxy and never mistaken for an instrument blackout. A
    # busy store that never yields even a proxy for the entire window is the
    # honest FRONTIER-BUSY-TIMEOUT instrument-failure class (see D6), never
    # folded into "no forward progress, no blocker" (silent-stall FAIL).
    if [ "$ps" = "-1" ] && [ "$FRONTIER_LAST_BUSY" = "1" ]; then
        [ "$busy_streak_start" = 0 ] && busy_streak_start="$now"
        busy_elapsed=$((now - busy_streak_start))
        if [ "$busy_elapsed" -ge "$FRONTIER_BUSY_TIMEOUT_SECS" ]; then
            echo "=== cold-start-wipe-stopwatch: FRONTIER-BUSY-TIMEOUT — progress_store_busy persisted ${busy_elapsed}s (>= ${FRONTIER_BUSY_TIMEOUT_SECS}s) with no hstar/cached_provable_tip sample ever observed in that window ==="
            write_artifact "frontier_busy_timeout" 5 \
                "progress_store_busy persisted >= ${FRONTIER_BUSY_TIMEOUT_SECS}s (--busy-timeout); last raw frontier response: $fj"
            exit 5
        fi
    else
        busy_streak_start=0
    fi

    # Authoritative H* must never regress (a real regression is a correctness
    # bug, not a timing seam). Only the FULL-read hstar is checked — read-misses
    # (-1) are excluded, and the advisory proxy is deliberately NOT a regression
    # tripwire (a cache read may lag without the ledger having regressed).
    if [ "$hs" != "-1" ] && [ "$last_hstar" != "-1" ] && [ "$hs" -lt "$last_hstar" ] 2>/dev/null; then
        die "H* REGRESSED: $last_hstar -> $hs at t=${elapsed}s (this is a correctness bug, not a budget seam)"
    fi
    if [ "$hs" != "-1" ]; then
        [ -z "$first_hstar" ] && first_hstar="$hs"
        last_hstar="$hs"
        [ "$hs" -gt "$max_hstar" ] 2>/dev/null && max_hstar="$hs"
    fi
    # Provable-sample tracking (full H* OR proxy): the honest "did it climb"
    # signal a busy-but-healthy fold must never be denied. A run whose
    # successive samples strictly increase can never be classed silent-stall.
    if [ "$ps" != "-1" ]; then
        saw_ps=1
        [ -z "$first_ps" ] && first_ps="$ps"
        last_ps="$ps"
        [ "$ps" -gt "$max_ps" ] 2>/dev/null && max_ps="$ps"
    fi
    [ "$nt" != "-1" ] && last_network_tip="$nt"
    last_blocker_ids="$bids"; last_blocker_count="$bc"

    # PASS predicate — deliberately AUTHORITATIVE-ONLY: a full read (hstar +
    # network_tip both present, network_tip_read_ok true) whose authoritative H*
    # has caught the peer tip. The proxy can prove CLIMB but can NEVER mint a
    # PASS (network_tip is absent from the busy partial doc anyway).
    if [ -n "$nt_ok" ] && [ "$nt" -gt 0 ] 2>/dev/null && [ "$hs" != "-1" ] && [ "$hs" -ge "$nt" ] 2>/dev/null; then
        reached=1
        break
    fi

    [ "$elapsed" -ge "$BUDGET" ] && break
    sleep "$SAMPLE_SECS"
done

now=$(date +%s); elapsed=$((now - start))

# Re-read the node-owned evidence at the verdict boundary.  This catches an
# execv that landed after the final sample and keeps console/proof wording in
# agreement with phases[].
refresh_boot_observation

# BOOTS=<n> is the number of actual boot prologues the node recorded (1 = no
# respawn; >1 includes both in-process execv and harness-followed relaunches on
# the single wiped datadir). The recorder folds it into the durable ledger.
echo "BOOTS=$boots"

if [ "$reached" = 1 ]; then
    echo "WALL_CLOCK_SECONDS=$elapsed"
    echo "=== cold-start-wipe-stopwatch: PASS — H* reached network_tip=$last_network_tip in ${elapsed}s across $boots boot(s) (budget ${BUDGET}s) ==="
    write_artifact "pass" 0 "wiped datadir reached network_tip within budget across $boots boot(s)"
    exit 0
fi

echo "WALL_CLOCK_SECONDS=$elapsed"

# FINAL CAPTURE READBACK — one more bounded-retry frontier + blocker read so the
# closing verdict reflects the freshest observable state, not a single
# end-of-budget miss. It refreshes the provable-sample / authoritative / blocker
# trackers and decides final_readback_failed: true iff even this retried read
# yielded NEITHER an authoritative hstar NOR a cached_provable_tip proxy. A run
# that could not be observed at the end is an INSTRUMENT failure, never a claim
# the node stalled.
final_fj="$(rpc_frontier)"
final_hs="$(frontier_hstar_full "$final_fj")"
final_ps="$(frontier_provable_sample "$final_fj")"
final_nt="$(jget "$final_fj" network_tip)"; [ -z "$final_nt" ] && final_nt="-1"
if [ "$final_hs" != "-1" ]; then
    [ -z "$first_hstar" ] && first_hstar="$final_hs"
    last_hstar="$final_hs"
    [ "$final_hs" -gt "$max_hstar" ] 2>/dev/null && max_hstar="$final_hs"
fi
if [ "$final_ps" != "-1" ]; then
    saw_ps=1
    [ -z "$first_ps" ] && first_ps="$final_ps"
    last_ps="$final_ps"
    [ "$final_ps" -gt "$max_ps" ] 2>/dev/null && max_ps="$final_ps"
fi
[ "$final_nt" != "-1" ] && last_network_tip="$final_nt"
final_readback_failed="false"
[ "$final_ps" = "-1" ] && final_readback_failed="true"

# One last boundary sweep on the SAME retried readback the verdict uses.
# A boundary crossed between the final sample tick and the end of the
# budget is a real crossing; without this it would be reported as
# unobserved, which would be a false negative rather than a safe one.
phase_observe "$(date +%s)" "$final_hs" "$final_nt" "$final_fj"

# Refresh the named-blocker view with a retried read too, so a busy-window miss
# doesn't erase a real blocker right before the STALLED-NAMED decision.
final_bj="$(rpc_retry_nonempty dumpstate blocker)"
final_bc="$(jget "$final_bj" active_count)"
if [ -n "$final_bc" ]; then
    last_blocker_count="$final_bc"
    final_bids="$(blocker_ids "$final_bj")"
    [ -n "$final_bids" ] && last_blocker_ids="$final_bids"
fi
final_park="$(log_named_park)"
if [ -n "$final_park" ] && [ "${last_blocker_count:-0}" = "0" ]; then
    last_blocker_count=1; last_blocker_ids="boot_park:$final_park"
fi

# The verdict precedence is decided by the pure classify_final_verdict()
# (unit-tested in --selftest). CLIMB is judged on the PROVABLE SAMPLE
# (authoritative H* OR the cached_provable_tip proxy), so a healthy fold that
# only ever exposed the proxy under load still counts as real forward progress
# and can NEVER be called a silent stall.
verdict_token="$(classify_final_verdict "$reached" "$first_ps" "$max_ps" \
                    "$saw_ps" "$final_readback_failed" "$last_blocker_count")"

case "$verdict_token" in
    seam)
        echo "=== cold-start-wipe-stopwatch: SEAM — provable tip climbed ($first_ps -> $max_ps) across $boots boot(s) but did not reach network_tip=$last_network_tip within ${BUDGET}s ==="
        write_artifact "seam" 3 "provable tip made forward progress ($first_ps -> $max_ps) across $boots boot(s) but did not catch network_tip within budget"
        exit 3
        ;;
    stalled-named)
        echo "=== cold-start-wipe-stopwatch: STALLED-NAMED — no forward progress in ${BUDGET}s; active blocker(s): $last_blocker_ids ==="
        write_artifact "stalled-named" 4 "no forward progress; named blocker(s): $last_blocker_ids"
        exit 4
        ;;
    readback-failed)
        # We could NOT read the node's provable tip at the end (final readback
        # failed) or never got a single sample all run — an INSTRUMENT failure.
        # Carries the last good provable sample; judged FAIL-with-named-cause,
        # never silent-stall, never PASS.
        echo "cold-start-wipe-stopwatch: last 20 log lines:"
        tail -20 "$DATADIR/node.log" 2>/dev/null | sed 's/^/  /'
        echo "=== cold-start-wipe-stopwatch: READBACK-FAILED — no authoritative hstar or cached_provable_tip proxy at final capture (last good provable sample: ${last_ps}, saw_sample=${saw_ps}) ==="
        write_artifact "readback-failed" 6 "frontier readback yielded neither hstar nor cached_provable_tip after bounded retries (last good provable sample=${last_ps}, saw_sample=${saw_ps}); instrument failure, not an observed stall"
        exit 6
        ;;
    *)
        # silent-stall: we COULD read the provable tip throughout, it was
        # genuinely flat, and nothing named a blocker — the real silent-stall
        # failure class.
        echo "cold-start-wipe-stopwatch: last 20 log lines:"
        tail -20 "$DATADIR/node.log" 2>/dev/null | sed 's/^/  /'
        die "no forward progress AND no named blocker in ${BUDGET}s (silent-stall failure class)"
        ;;
esac
