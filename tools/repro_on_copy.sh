#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# repro_on_copy.sh — snapshot the live datadir to a NEW labelled COPY and run
# build/bin/zclassic23 against the COPY on an isolated port, so consensus-critical and
# recovery experiments are validated BEFORE they can touch the live chain.
#
# This is the guardrail that makes the catastrophic tail structurally
# impossible: a reducer/recovery fix that would have collapsed the public tip
# (the real 3,130,701 -> 47,279 reset; the import-reset to ~199) is caught here
# on a throwaway copy instead of on the live node. The harness is also a
# TIP-REGRESSION DETECTOR: it boots the copy, watches the public tip for a
# window, and FAILS LOUD if the tip ever drops (a reset) — the exact symptom
# the import-reset (#10) and write-ordering (#7) tracks must reproduce safely.
# When --expect-climb-past=H is supplied it is also an H* CLIMB gate: a run
# that boots and holds flat at or below H is a FAIL, not a false-green PASS.
#
# SAFETY (enforced below):
#   - copies to a brand-new $HOME/.zclassic-c23-COPY-<ts>-<slug> dir that must
#     not exist and must not equal --src; the live datadir is never written.
#   - runs the copy node with an isolated HOME plus isolated --rpcport /
#     --p2p-port / --fs-port / --https-port. It forces -connect to a dead sink,
#     -nolegacyimport, and -nofilesync unless the peer is explicitly overridden
#     with --connect. It never uses live ports or reads ~/.zclassic.
#   - leaves the copy on disk afterwards for further analysis (print its path).
#
# Usage:
#   make repro-on-copy SLUG=import-reset ARGS='-nobgvalidation'
#   tools/repro_on_copy.sh import-reset --port=18299 -- -nobgvalidation
#
# Options (before the `--` passthrough):
#   <slug>            required first arg; labels the copy + manifest
#   --src=DIR         source datadir (default $HOME/.zclassic-c23)
#   --port=N          isolated rpcport (default 18299)
#   --p2p-port=N      isolated p2p port (default 18933)
#   --fs-port=N       isolated file-service port (default 18934)
#   --https-port=N    isolated HTTPS port (default 18935)
#   --connect=ADDR    isolated -connect peer (default 127.0.0.1:39999 dead sink)
#   --full            copy the WHOLE datadir incl. blocks/ + consensus_snapshot
#                     (default is --light: node.db + the kernel store
#                     (consensus.db, or the legacy progress.kv on a pre-flip
#                     datadir) + block_index + projections; skips the 14G
#                     blocks/ + 2.3G snapshot)
#   --like-live       DEPLOY GATE mode. Reconstruct the effective live systemd
#                     ExecStart on the COPY: read the merged drop-in ExecStart +
#                     Environment from the running `zclassic23` user unit
#                     (READ-ONLY), strip only network/port identity
#                     (-port/-rpcport/-externalip/-addnode/-connect and the
#                     $ZCL_EXTERNALIP_FLAG/$ZCL_ADDNODE_FLAGS refs), rewrite
#                     -datadir and -load-snapshot-at-own-height onto the COPY,
#                     and pass EVERYTHING else verbatim (-txindex -tor
#                     -nobgvalidation -nolegacyimport -showmetrics=0 …). Forces
#                     --full so the snapshot-loader path is reachable, replicates
#                     the service Environment=/EnvironmentFile vars (net-identity
#                     stripped, live-datadir paths rewritten onto the COPY,
#                     ZCL_AGENT_EXPECT_SOURCE_ID set to the candidate binary's
#                     exact baked source SHA-256; build_commit is copied only
#                     as optional GitHub/display trace metadata), and
#                     makes ~/.zcash-params and ~/.zclassic (zclassicd chainstate
#                     for the tier-1b Sapling-frontier borrow) reachable in the
#                     isolated HOME. The generic default mode is NOT sufficient
#                     to clear a live deploy; `ebfe4c207` added this mode after
#                     a real flag-parity miss.
#   --deadline=SECS   how long to watch the tip (default 180)
#   --expect-climb-past=H
#                     require the served/provable tip (H*) to climb strictly
#                     above H before the deadline
#   --expect-static-spend-ready
#                     after any requested H* climb, require the copy's offline
#                     sovereignty fold to report wallet_spend_static_allowed.
#                     This is still only the static half of spend readiness;
#                     an identity-bound current money snapshot remains required.
#   --no-run          snapshot + manifest only; do not launch the node
#   --json            emit ONE JSON summary object on stdout instead of the
#                      human banner (progress/log lines move to stderr).
#                      Default human-text mode is unchanged byte-for-byte.
#                      Schema: zcl.copy_prove_result.v1. No jq dependency.
#   --status-file=PATH
#                      write the same JSON result to PATH (atomically),
#                      first as {"state":"running",...} right after the
#                      node launches, then overwritten with the final
#                      {"state":"done",...} result. Lets an out-of-process
#                      caller poll a long run without holding a pipe open.
#                      Independent of --json (works in text mode too).
#   --install-consensus-bundle=PATH
#                     ALTERNATE cutover mode to -refold-from-anchor, for the v1
#                     consensus-state bundle consumer (-install-consensus-bundle
#                     on build/bin/zclassic23, config/src/boot_install_consensus_bundle.c).
#                     Two-phase on the COPY: (1) run the node ONCE with
#                     `-install-consensus-bundle=PATH` and nothing else — this
#                     call is TERMINAL (it _exit()s after installing or a typed
#                     refusal, never starts P2P/RPC services) — and require it
#                     to print "INSTALLED: -install-consensus-bundle:" and exit
#                     0; (2) only on that success, boot the COPY NORMALLY (no
#                     -install-consensus-bundle flag) and enforce the existing
#                     --expect-climb-past=H tip-watch gate, so the fold forward
#                     past the bundle height is the thing actually proven, not
#                     the install call's own exit code. PATH may be an absolute
#                     path (used verbatim, e.g. a bundle staged outside any
#                     datadir) or a path under --src (auto-rewritten onto the
#                     COPY, e.g. <src>/consensus-state-bundle-<anchor>.sqlite
#                     the mint producer wrote inside its own datadir). Requires
#                     --full + --expect-climb-past=H; refuses to combine with a
#                     -refold-from-anchor pass-through (alternate cutover
#                     modes, pick one). This mode never sets
#                     ZCL_DEPLOY_ALLOW_CANONICAL — the COPY is never the
#                     canonical datadir, so the install call's canonical-lane
#                     gate is not exercised here; the live cutover run sets
#                     that env var itself (see
#                     docs/work/sovereign-cutover-runbook.md).
#   --                everything after is passed verbatim to build/bin/zclassic23
#
# Refold-specific rule:
#   If pass-through args include -refold-from-anchor, this harness requires
#   --full, --expect-climb-past=H, and a reachable anchor snapshot candidate
#   at $ZCL_MINT_ANCHOR_OUT or <src>/utxo-anchor.snapshot. The node still owns
#   the SHA3/count verification at boot; this preflight only catches missing
#   artifacts and invalid light-copy proofs cheaply.
#
# Bundle-install-specific rule:
#   --install-consensus-bundle=PATH requires --full and --expect-climb-past=H
#   for the same reason as -refold-from-anchor (the forward fold reads block
#   bodies, and a flat/failed boot must not false-pass). The resolved PATH must
#   exist and be non-empty on the COPY before the install call runs; the node
#   still owns bundle admission, publication-CAS gating, and the atomic
#   activate-install itself — this preflight only catches a missing/misnamed
#   artifact and an incompatible copy mode cheaply, before spending a boot.
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=tools/scripts/source_identity_lib.sh
. "$SCRIPT_DIR/scripts/source_identity_lib.sh"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"

# ── --json / --status-file support (additive; default text mode is
# untouched byte-for-byte — see json_escape()/emit_*_json() below, only
# invoked when JSON=1 or STATUS_FILE is set). No jq: hand-rolled printf.
json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# num_or_null VALUE — VALUE of -1 (our "unset" sentinel) prints as JSON
# null; any other integer prints verbatim.
num_or_null() {
    if [ "$1" = "-1" ]; then printf 'null'; else printf '%s' "$1"; fi
}

bool_json() {
    if [ "$1" = "1" ]; then printf 'true'; else printf 'false'; fi
}

is_sha256_hex() {
    [ "${#1}" -eq 64 ] || return 1
    case "$1" in
        *[!0-9a-f]*) return 1 ;;
        *) return 0 ;;
    esac
}

# atomic_write PATH — reads stdin, writes PATH.tmp then renames onto PATH
# so a concurrent poller never observes a partial file.
atomic_write() {
    path="$1"
    tmp="$path.tmp.$$"
    cat > "$tmp"
    mv -f "$tmp" "$path"
}

emit_running_json() {
    printf '{"schema":"zcl.copy_prove_result.v1","state":"running",'\
'"slug":"%s","copy_path":"%s","src":"%s","node_pid":%s,'\
'"expect_climb_past":%s,"expect_static_spend_ready":%s,'\
'"generated_at":%s}\n' \
        "$(json_escape "$SLUG")" "$(json_escape "$DEST")" \
        "$(json_escape "$SRC")" "${NODE_PID:-0}" \
        "$(num_or_null "${EXPECT_CLIMB_PAST:--1}")" \
        "$(bool_json "${EXPECT_STATIC_SPEND_READY:-0}")" "$(date +%s)"
}

emit_done_json() {
    # Args: verdict rc h_before h_after h_max duration log_path
    verdict="$1"; rc="$2"; h_before="$3"; h_after="$4"; h_max="$5"
    dur="$6"; log_path="$7"
    printf '{"schema":"zcl.copy_prove_result.v1","state":"done",'\
'"verdict":"%s","exit_code":%s,"slug":"%s","copy_path":"%s",'\
'"src":"%s","h_star_before":%s,"h_star_after":%s,"max_tip":%s,'\
'"expect_climb_past":%s,"climbed_past":%s,"tip_regression":%s,'\
'"expect_static_spend_ready":%s,"static_spend_ready":%s,'\
'"body_read_fails":%s,"refold_requested":%s,'\
'"refold_snapshot_loaded":%s,"duration_secs":%s,'\
'"log_path":"%s","node_pid":%s,"generated_at":%s}\n' \
        "$verdict" "$rc" \
        "$(json_escape "$SLUG")" "$(json_escape "$DEST")" \
        "$(json_escape "$SRC")" \
        "$(num_or_null "$h_before")" "$(num_or_null "$h_after")" \
        "$(num_or_null "$h_max")" \
        "$(num_or_null "${EXPECT_CLIMB_PAST:--1}")" \
        "$(bool_json "${climbed_past:-0}")" \
        "$(bool_json "${regressed:-0}")" \
        "$(bool_json "${EXPECT_STATIC_SPEND_READY:-0}")" \
        "$(bool_json "${static_spend_ready:-0}")" \
        "${body_read_fails:-0}" \
        "$(bool_json "${REFOLD_REQUESTED:-0}")" \
        "$(bool_json "${refold_snapshot_loaded:-0}")" \
        "$dur" "$(json_escape "$log_path")" "${NODE_PID:-0}" "$(date +%s)"
}

SLUG=""
SRC="$HOME/.zclassic-c23"
RPCPORT=18299
P2PPORT=18933
FSPORT=18934
HTTPSPORT=18935
CONNECT="127.0.0.1:39999"
LIGHT=1
DEADLINE=180
EXPECT_CLIMB_PAST=""
EXPECT_STATIC_SPEND_READY=0
RUN=1
PASS=""
JSON=0
STATUS_FILE=""
LIKE_LIVE=0
LIKE_LIVE_FLAGS=""
LIKE_LIVE_ENV=""
LIKE_LIVE_SNAP=""
LIKE_LIVE_SOURCE_ID=""
LIKE_LIVE_BUILD_COMMIT=""
INSTALL_BUNDLE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --src=*)       SRC="${1#--src=}" ;;
        --port=*)      RPCPORT="${1#--port=}" ;;
        --p2p-port=*)  P2PPORT="${1#--p2p-port=}" ;;
        --fs-port=*)   FSPORT="${1#--fs-port=}" ;;
        --https-port=*) HTTPSPORT="${1#--https-port=}" ;;
        --connect=*)   CONNECT="${1#--connect=}" ;;
        --full)        LIGHT=0 ;;
        --light)       LIGHT=1 ;;
        --like-live)   LIKE_LIVE=1; LIGHT=0 ;;
        --deadline=*)  DEADLINE="${1#--deadline=}" ;;
        --expect-climb-past=*) EXPECT_CLIMB_PAST="${1#--expect-climb-past=}" ;;
        --expect-static-spend-ready) EXPECT_STATIC_SPEND_READY=1 ;;
        --no-run)      RUN=0 ;;
        --json)        JSON=1 ;;
        --status-file=*) STATUS_FILE="${1#--status-file=}" ;;
        --install-consensus-bundle=*) INSTALL_BUNDLE="${1#--install-consensus-bundle=}" ;;
        --)            shift; PASS="$*"; break ;;
        --*)           echo "repro_on_copy: unknown option $1" >&2; exit 2 ;;
        *)             if [ -z "$SLUG" ]; then SLUG="$1"; else
                           echo "repro_on_copy: unexpected arg $1" >&2; exit 2; fi ;;
    esac
    shift
done

[ -n "$SLUG" ] || { echo "usage: tools/repro_on_copy.sh <slug> [--src=DIR] [--port=N] [--full] [-- <node args>]" >&2; exit 2; }
[ -d "$SRC" ]  || { echo "repro_on_copy: source datadir not found: $SRC" >&2; exit 1; }
if [ "$RUN" = "1" ]; then
    [ -x "$NODE_BIN" ] || { echo "repro_on_copy: $NODE_BIN not built (run make)" >&2; exit 1; }
    [ -x "$RPC_BIN" ] || { echo "repro_on_copy: $RPC_BIN not built (run make zcl-rpc)" >&2; exit 1; }
fi
case "$EXPECT_CLIMB_PAST" in
    ""|*[!0-9]*)
        if [ -n "$EXPECT_CLIMB_PAST" ]; then
            echo "repro_on_copy: --expect-climb-past must be a non-negative height" >&2
            exit 2
        fi
        ;;
esac

REFOLD_REQUESTED=0
case " $PASS " in
    *" -refold-from-anchor "*) REFOLD_REQUESTED=1 ;;
esac
ANCHOR_CANDIDATE=""
if [ "$REFOLD_REQUESTED" = "1" ]; then
    if [ "$LIGHT" = "1" ]; then
        echo "repro_on_copy: -refold-from-anchor requires --full because the fold reads block bodies" >&2
        exit 2
    fi
    if [ -z "$EXPECT_CLIMB_PAST" ]; then
        echo "repro_on_copy: -refold-from-anchor requires --expect-climb-past=H so a flat boot cannot pass" >&2
        exit 2
    fi
    ANCHOR_CANDIDATE="${ZCL_MINT_ANCHOR_OUT:-$SRC/utxo-anchor.snapshot}"
    if [ ! -s "$ANCHOR_CANDIDATE" ]; then
        echo "repro_on_copy: -refold-from-anchor requires an anchor snapshot candidate at $ANCHOR_CANDIDATE" >&2
        echo "repro_on_copy: mint/stage one first with zclassic23 -mint-anchor or ZCL_ANCHOR_SNAPSHOT_SRC=<file> make seed-anchor-snapshot" >&2
        exit 2
    fi
fi

if [ -n "$INSTALL_BUNDLE" ]; then
    if [ "$REFOLD_REQUESTED" = "1" ]; then
        echo "repro_on_copy: --install-consensus-bundle and -refold-from-anchor are alternate cutover modes; pass only one" >&2
        exit 2
    fi
    if [ "$LIGHT" = "1" ]; then
        echo "repro_on_copy: --install-consensus-bundle requires --full because the post-install forward fold reads block bodies" >&2
        exit 2
    fi
    if [ -z "$EXPECT_CLIMB_PAST" ]; then
        echo "repro_on_copy: --install-consensus-bundle requires --expect-climb-past=H so a flat/failed boot cannot pass" >&2
        exit 2
    fi
    if [ "$RUN" = "0" ]; then
        echo "repro_on_copy: --install-consensus-bundle requires a run (incompatible with --no-run)" >&2
        exit 2
    fi
fi

refuse_live_port() {
    p="$1"
    label="$2"
    case "$p" in
        8023|8033|8034|8232|8233|8443|18034|18232)
            echo "repro_on_copy: refusing live $label port $p" >&2
            exit 1
            ;;
    esac
}

refuse_live_port "$RPCPORT" "rpc"
refuse_live_port "$P2PPORT" "p2p"
refuse_live_port "$FSPORT" "file-service"
refuse_live_port "$HTTPSPORT" "https"
case "$CONNECT" in
    *:*) refuse_live_port "${CONNECT##*:}" "connect" ;;
esac

case " $PASS " in
    *" -addnode="*|*" -connect="*|*" -rpcport="*|*" -port="*|*" -fsport="*|*" -httpsport="*|*" -install-consensus-bundle="*)
        echo "repro_on_copy: pass-through may not override network ports/peers/bundle-install; use script options" >&2
        exit 2
        ;;
esac

# All input validation is done. From here on, --json redirects the
# script's normal progress/log output to stderr and reserves fd 3 (a
# duplicate of the original stdout) for the ONE JSON result object, so a
# caller parsing stdout never has to separate JSON from prose. Default
# (JSON=0) mode is completely untouched: fd 1 keeps meaning stdout, byte
# for byte identical to before this feature existed.
RUN_START_EPOCH="$(date +%s)"
if [ "$JSON" = "1" ]; then
    exec 3>&1 1>&2
fi
if [ -n "$STATUS_FILE" ]; then
    mkdir -p "$(dirname "$STATUS_FILE")" 2>/dev/null || true
fi

TS="$(date +%Y%m%d-%H%M%S)"
DEST="$HOME/.zclassic-c23-COPY-$TS-$SLUG"
# Refuse to clobber / alias the source.
[ ! -e "$DEST" ] || { echo "repro_on_copy: dest already exists: $DEST" >&2; exit 1; }
case "$DEST" in "$SRC"|"$SRC"/*) echo "repro_on_copy: dest must not be inside src" >&2; exit 1 ;; esac

# ── --like-live: reconstruct the effective live systemd ExecStart on the COPY.
# READ-ONLY reads of the running `zclassic23` user unit; the COPY destination is
# still the fixed <HOME>/.zclassic-c23-COPY-<ts>-<slug> path computed above (no
# caller-controlled dest), and every port/peer/-datadir the live unit carries is
# stripped here — the harness OWNS ports, peers, and the datadir. This is the
# flag-parity invariant locked by `ebfe4c207`.
process_env_kv() {
    _kv="$1"; _key="${_kv%%=*}"; _val="${_kv#*=}"
    [ -n "$_key" ] || return 0
    case "$_key" in
        ZCL_EXTERNALIP_FLAG|ZCL_ADDNODE_FLAGS) return 0 ;;           # net identity
        ZCL_AGENT_EXPECT_SOURCE_ID|ZCL_AGENT_EXPECT_BUILD_COMMIT|ZCL_AGENT_EXPECT_BUILD_SOURCE)
            return 0 ;;                                              # set to candidate below
        HOME|ZCL_MIRROR_SYNC) return 0 ;;                            # owned by the harness
    esac
    case "$_val" in *[!-A-Za-z0-9_/.:=]*) return 0 ;; esac           # single safe token only
    case "$_val" in                                                 # live datadir -> COPY
        "$SRC"/*) _val="$DEST/${_val#"$SRC"/}" ;;
        "$SRC")   _val="$DEST" ;;
    esac
    LIKE_LIVE_ENV="$LIKE_LIVE_ENV $_key=$_val"
}
derive_like_live_flags() {
    _exec="$(systemctl --user show zclassic23 -p ExecStart --value 2>/dev/null || true)"
    [ -n "$_exec" ] || { echo "repro_on_copy: --like-live: cannot read ExecStart for zclassic23 (unit installed?)" >&2; exit 1; }
    _argv="$(printf '%s\n' "$_exec" | sed -n 's/.*argv\[\]=\(.*\) ; ignore_errors=.*/\1/p')"
    [ -n "$_argv" ] || { echo "repro_on_copy: --like-live: could not parse argv from ExecStart" >&2; exit 1; }
    _first=1
    # shellcheck disable=SC2086
    for _tok in $_argv; do
        if [ "$_first" = 1 ]; then _first=0; continue; fi            # drop argv[0] (binary path)
        case "$_tok" in
            -datadir=*|-port=*|-rpcport=*|-fsport=*|-httpsport=*) continue ;;
            -externalip=*|-addnode=*|-connect=*)                  continue ;;
            \$*)                                                  continue ;; # unexpanded net-identity env refs
            -load-snapshot-at-own-height=*)
                LIKE_LIVE_SNAP="$(basename "${_tok#-load-snapshot-at-own-height=}")"
                continue ;;
            *) LIKE_LIVE_FLAGS="$LIKE_LIVE_FLAGS $_tok" ;;
        esac
    done
    # Defensive: the harness OWNS ports/peers/datadir — a passthrough flag must never carry them.
    case " $LIKE_LIVE_FLAGS " in
        *" -port="*|*" -rpcport="*|*" -addnode="*|*" -connect="*|*" -externalip="*|*" -datadir="*)
            echo "repro_on_copy: --like-live: refused to pass a network/port/datadir flag through" >&2
            exit 1 ;;
    esac
}
if [ "$LIKE_LIVE" = "1" ]; then
    LIGHT=0                                                          # snapshot-loader path must be reachable
    derive_like_live_flags
    # Replicate Environment= (via systemctl show) + EnvironmentFile vars.
    for _kv in $(systemctl --user show zclassic23 -p Environment --value 2>/dev/null); do
        process_env_kv "$_kv"
    done
    _envfile="$HOME/.config/zclassic23/env"
    if [ -f "$_envfile" ]; then
        while IFS= read -r _line; do
            case "$_line" in ''|\#*) continue ;; *=*) : ;; *) continue ;; esac
            process_env_kv "$_line"
        done < "$_envfile"
    fi
    if command -v timeout >/dev/null 2>&1; then
        _identity="$(timeout 10 "$NODE_BIN" agentbuild 2>/dev/null || true)"
    else
        _identity="$("$NODE_BIN" agentbuild 2>/dev/null || true)"
    fi
    # Bind only the top-level zcl.agent_build.v2 identity. The response also
    # contains nested background-lane source_id_sha256/build_commit fields;
    # a greedy `.*field` parser selects the LAST nested occurrence and can
    # bind a copy proof to an unrelated stale artifact.
    LIKE_LIVE_SOURCE_ID="$(zcl_agentbuild_v2_top_source_id "$_identity")"
    is_sha256_hex "$LIKE_LIVE_SOURCE_ID" || {
        echo "repro_on_copy: --like-live: candidate agentbuild omitted a valid source_id_sha256" >&2
        exit 1
    }
    LIKE_LIVE_BUILD_COMMIT="$(zcl_agentbuild_v2_top_build_commit "$_identity")"
    case "$LIKE_LIVE_BUILD_COMMIT" in
        ''|*[!A-Za-z0-9._-]*) LIKE_LIVE_BUILD_COMMIT="unknown" ;;
    esac
    LIKE_LIVE_ENV="$LIKE_LIVE_ENV ZCL_AGENT_EXPECT_SOURCE_ID=$LIKE_LIVE_SOURCE_ID ZCL_AGENT_EXPECT_BUILD_COMMIT=$LIKE_LIVE_BUILD_COMMIT ZCL_AGENT_EXPECT_BUILD_SOURCE=like-live"
    LIKE_LIVE_ENV="${LIKE_LIVE_ENV# }"
    # Rewrite the snapshot loader onto the COPY, then assemble PASS: live flags
    # first, then any explicit `-- <args>` the caller added last (override wins).
    if [ -n "$LIKE_LIVE_SNAP" ]; then
        LIKE_LIVE_FLAGS="$LIKE_LIVE_FLAGS -load-snapshot-at-own-height=$DEST/$LIKE_LIVE_SNAP"
    fi
    PASS="$(printf '%s' "$LIKE_LIVE_FLAGS ${PASS:-}" | sed 's/^ *//; s/ *$//')"
    echo "[repro] --like-live derived node args: $PASS"
    echo "[repro] --like-live derived env:       $LIKE_LIVE_ENV"
fi

# Disk precheck: need ~110% of what we are about to copy.
if [ "$LIGHT" = "1" ]; then
    NEED_KB=$( { du -sk "$SRC/node.db" "$SRC/consensus.db" "$SRC/progress.kv" \
                 "$SRC/block_index.bin" 2>/dev/null; \
                 du -sk "$SRC"/*_projection.db 2>/dev/null; } | awk '{s+=$1} END{print s+0}')
else
    NEED_KB=$(du -sk "$SRC" 2>/dev/null | awk '{print $1}')
fi
AVAIL_KB=$(df -Pk "$SRC" 2>/dev/null | awk 'NR==2{print $4}')
case "$AVAIL_KB" in
    ''|*[!0-9]*) echo "[repro] WARN: could not read free space for $SRC; skipping disk precheck" ;;
    *) if [ "$((NEED_KB + NEED_KB/10))" -gt "$AVAIL_KB" ]; then
           echo "repro_on_copy: not enough disk: need ~$((NEED_KB/1024))M (+10%), avail $((AVAIL_KB/1024))M" >&2
           exit 1
       fi ;;
esac

echo "[repro] snapshotting $SRC -> $DEST ($([ "$LIGHT" = 1 ] && echo light || echo full), ~$((NEED_KB/1024))M)"
mkdir -p "$DEST"
if [ "$LIGHT" = "1" ]; then
    # Copy the cursor/tip working set; SQLite -wal/-shm copied alongside each db
    # so the copy is self-consistent on open. Skip blocks/ (14G) + snapshot (2.3G).
    # consensus.db is the kernel store post-flip (coins/anchors/nullifiers/stage
    # cursors); progress.kv is copied too — either it's the legacy kernel store
    # on a pre-flip datadir, or the post-flip projections file (address_index/
    # txindex) — both cases need it on the copy.
    for f in node.db node.db-wal node.db-shm consensus.db consensus.db-wal \
             consensus.db-shm progress.kv progress.kv-wal progress.kv-shm \
             block_index.bin block_index.bin.sha3; do
        [ -e "$SRC/$f" ] && cp -a "$SRC/$f" "$DEST/" || true
    done
    for f in "$SRC"/*_projection.db "$SRC"/*_projection.db-wal "$SRC"/*_projection.db-shm; do
        [ -e "$f" ] && cp -a "$f" "$DEST/" || true
    done
    # control/marker files that influence boot, all tiny
    for f in last_reimport_attempted file_manifest.bin sapling_tree_ckpt.dat; do
        [ -e "$SRC/$f" ] && cp -a "$SRC/$f" "$DEST/" || true
    done
else
    cp -a "$SRC"/. "$DEST"/
fi

# Full copies inherit the live runtime identity and lock markers. They are not
# chain state, and leaving them in the throwaway datadir makes the isolated
# node correctly refuse to boot because it believes the live PID owns the copy.
rm -f "$DEST/zclassic23.pid" "$DEST/.cookie" "$DEST/.lock" 2>/dev/null || true

# --install-consensus-bundle=PATH: resolve PATH onto the COPY. A path under
# --src is rewritten the same way the --like-live env rewrite handles live
# datadir paths (e.g. <src>/consensus-state-bundle-<anchor>.sqlite the mint
# producer wrote inside its own datadir); any other path is used verbatim
# (e.g. a bundle staged outside any datadir). Must exist and be non-empty on
# the COPY before the terminal install call runs below.
INSTALL_BUNDLE_RESOLVED=""
if [ -n "$INSTALL_BUNDLE" ]; then
    case "$INSTALL_BUNDLE" in
        "$SRC"/*) INSTALL_BUNDLE_RESOLVED="$DEST/${INSTALL_BUNDLE#"$SRC"/}" ;;
        "$SRC")   INSTALL_BUNDLE_RESOLVED="$DEST" ;;
        *)        INSTALL_BUNDLE_RESOLVED="$INSTALL_BUNDLE" ;;
    esac
    if [ ! -s "$INSTALL_BUNDLE_RESOLVED" ]; then
        echo "repro_on_copy: --install-consensus-bundle candidate not found or empty: $INSTALL_BUNDLE_RESOLVED" >&2
        exit 2
    fi
fi

# Manifest for provenance.
{
    echo "slug:        $SLUG"
    echo "created:     $TS"
    echo "src:         $SRC"
    echo "mode:        $([ "$LIGHT" = 1 ] && echo light || echo full)"
    echo "like_live:   $([ "$LIKE_LIVE" = 1 ] && echo yes || echo no)"
    [ "$LIKE_LIVE" = 1 ] && echo "like_live_env: $LIKE_LIVE_ENV"
    echo "candidate_source_id_sha256: ${LIKE_LIVE_SOURCE_ID:-none}"
    echo "candidate_build_commit_display: ${LIKE_LIVE_BUILD_COMMIT:-none}"
    echo "git_head:    $(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "git_head_semantics: display_only_github_trace_metadata"
    echo "node_args:   $PASS"
    echo "rpcport:     $RPCPORT"
    echo "p2p_port:    $P2PPORT"
    echo "fs_port:     $FSPORT"
    echo "https_port:  $HTTPSPORT"
    echo "connect:     $CONNECT"
    echo "climb_past:  ${EXPECT_CLIMB_PAST:-none}"
    echo "static_spend_ready_required: $([ "$EXPECT_STATIC_SPEND_READY" = 1 ] && echo yes || echo no)"
    echo "refold:      $([ "$REFOLD_REQUESTED" = 1 ] && echo yes || echo no)"
    echo "anchor_snapshot_candidate: ${ANCHOR_CANDIDATE:-none}"
    echo "install_consensus_bundle: ${INSTALL_BUNDLE_RESOLVED:-none}"
} > "$DEST/REPRO_MANIFEST.txt"
echo "[repro] manifest: $DEST/REPRO_MANIFEST.txt"

if [ "$RUN" = "0" ]; then
    echo "[repro] --no-run: snapshot ready at $DEST"
    if [ "$JSON" = "1" ]; then
        NODE_PID=0
        emit_done_json NO_RUN 0 -1 -1 -1 \
            "$(( $(date +%s) - RUN_START_EPOCH ))" "" >&3
    fi
    [ -n "$STATUS_FILE" ] && { NODE_PID=0
        emit_done_json NO_RUN 0 -1 -1 -1 \
            "$(( $(date +%s) - RUN_START_EPOCH ))" "" |
            atomic_write "$STATUS_FILE"; }
    exit 0
fi

NODE_PID=""
cleanup() {
    [ -n "$NODE_PID" ] && kill -TERM "$NODE_PID" 2>/dev/null || true
    [ -n "$NODE_PID" ] && wait "$NODE_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ISO_HOME="$DEST/.isolated-home"
mkdir -p "$ISO_HOME"
NODE_ISO_ARGS="-fsport=$FSPORT -httpsport=$HTTPSPORT -connect=$CONNECT -nolegacyimport -nofilesync"

# --like-live: the node runs with HOME=$ISO_HOME, so the real ~/.zcash-params
# (Sapling proving/verifying keys) and ~/.zclassic (zclassicd chainstate, read
# by the tier-1b Sapling-frontier borrow at $HOME/.zclassic/chainstate) are not
# reachable unless we bridge them into the isolated HOME. Both are symlinked
# READ-ONLY (the borrow copies chainstate OUT into the COPY datadir, never
# writes back). Missing params otherwise parks the node before the code under
# test; a missing chainstate silently disables the tier-1b borrow the gate
# checks for.
# Params are read-only and mainnet always needs them — link them in EVERY
# mode (a --light run otherwise parks at crypto_params_missing before the
# code under test ever runs). The zclassicd-chainstate borrow bridge stays
# like-live-only: light runs should not silently exercise the tier-1b borrow.
[ -e "$HOME/.zcash-params" ] && ln -sfn "$HOME/.zcash-params" "$ISO_HOME/.zcash-params"
if [ "$LIKE_LIVE" = "1" ]; then
    [ -e "$HOME/.zclassic" ]     && ln -sfn "$HOME/.zclassic"     "$ISO_HOME/.zclassic"
fi

# --install-consensus-bundle=PATH: phase 1 — the terminal install call. Run
# SYNCHRONOUSLY (not backgrounded — this call never binds RPC and always
# exits on its own) with -install-consensus-bundle and nothing else; $PASS is
# reserved for phase 2's normal boot. A timeout guard (reuses --deadline)
# catches an unexpected hang defensively; the call is documented terminal
# either way. Acceptance requires BOTH exit 0 AND the typed INSTALLED banner
# — an exit-0 without the banner is not trusted. On any failure this exits
# the harness immediately: nothing further is booted, and the verdict is FAIL
# (never a false PASS from skipping straight to a flat/absent tip-watch).
if [ -n "$INSTALL_BUNDLE_RESOLVED" ]; then
    INSTALL_LOG="$DEST/repro_install_bundle.log"
    echo "[repro] terminal install pass: -install-consensus-bundle=$INSTALL_BUNDLE_RESOLVED (timeout ${DEADLINE}s)"
    install_rc=0
    if command -v timeout >/dev/null 2>&1; then
        HOME="$ISO_HOME" timeout "${DEADLINE}s" \
            "$NODE_BIN" -datadir="$DEST" -rpcport="$RPCPORT" -port="$P2PPORT" \
            $NODE_ISO_ARGS -install-consensus-bundle="$INSTALL_BUNDLE_RESOLVED" \
            > "$INSTALL_LOG" 2>&1 || install_rc=$?
    else
        HOME="$ISO_HOME" \
            "$NODE_BIN" -datadir="$DEST" -rpcport="$RPCPORT" -port="$P2PPORT" \
            $NODE_ISO_ARGS -install-consensus-bundle="$INSTALL_BUNDLE_RESOLVED" \
            > "$INSTALL_LOG" 2>&1 || install_rc=$?
    fi
    if [ "$install_rc" != "0" ] || ! grep -q '^INSTALLED: -install-consensus-bundle:' "$INSTALL_LOG"; then
        echo "========================================================================"
        echo "  repro-on-copy [$SLUG]"
        echo "  copy:      $DEST"
        echo "  VERDICT:   FAIL — the terminal -install-consensus-bundle pass did not"
        echo "             report INSTALLED (exit=$install_rc). Inspect $INSTALL_LOG"
        echo "             before trusting this run; nothing further was booted."
        echo "========================================================================"
        DURATION_SECS=$(( $(date +%s) - RUN_START_EPOCH ))
        if [ "$JSON" = "1" ]; then
            emit_done_json FAIL "$install_rc" -1 -1 -1 "$DURATION_SECS" "$INSTALL_LOG" >&3
        fi
        if [ -n "$STATUS_FILE" ]; then
            emit_done_json FAIL "$install_rc" -1 -1 -1 "$DURATION_SECS" "$INSTALL_LOG" |
                atomic_write "$STATUS_FILE"
        fi
        exit 1
    fi
    echo "[repro] install pass reported INSTALLED — booting normally to fold forward and prove H* CLIMB"
fi

echo "[repro] launching $NODE_BIN on the COPY (rpcport=$RPCPORT p2p=$P2PPORT fs=$FSPORT https=$HTTPSPORT connect=$CONNECT) args: $PASS"
# shellcheck disable=SC2086
# `env $LIKE_LIVE_ENV` replicates the live service Environment=/EnvironmentFile
# vars in --like-live mode (empty string otherwise → a no-op env wrapper that
# just forwards HOME/ZCL_MIRROR_SYNC unchanged).
HOME="$ISO_HOME" ZCL_MIRROR_SYNC=0 \
env $LIKE_LIVE_ENV \
"$NODE_BIN" -datadir="$DEST" -rpcport="$RPCPORT" -port="$P2PPORT" \
    $NODE_ISO_ARGS $PASS \
    > "$DEST/repro_node.log" 2>&1 &
NODE_PID=$!
[ -n "$STATUS_FILE" ] && emit_running_json | atomic_write "$STATUS_FILE"

cookie="$DEST/.cookie"
rpc() { HOME="$ISO_HOME" ZCL_DATADIR="$DEST" ZCL_RPCPORT="$RPCPORT" "$RPC_BIN" "$@" 2>/dev/null || true; }
tip()  {
    resp="$(rpc getblockcount)"
    case "$resp" in
        *\"result\"*)
            printf '%s\n' "$resp" |
                sed -n 's/.*"result"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' |
                head -1
            ;;
        *)
            printf '%s\n' "$resp" |
                sed -n 's/^[[:space:]]*\(-\{0,1\}[0-9][0-9]*\)[[:space:]]*$/\1/p' |
                head -1
            ;;
    esac
}

static_spend_ready_now() {
    _static_input="{\"datadir\":\"$(json_escape "$DEST")\"}"
    _static_out="$("$NODE_BIN" core sync frontier offline \
        --input="$_static_input" 2>/dev/null || true)"
    printf '%s\n' "$_static_out" |
        grep -q '"wallet_spend_static_allowed":true'
}

# Wait for RPC, then watch the tip for regressions over the deadline window.
deadline=$(( $(date +%s) + DEADLINE ))
max_tip=-1
first_tip=-1
regressed=0
seen_rpc=0
climbed_past=0
seen_at_or_below_climb=0
static_spend_ready=0
proof_gate_requested=0
[ -n "$EXPECT_CLIMB_PAST" ] && proof_gate_requested=1
[ "$EXPECT_STATIC_SPEND_READY" = "1" ] && proof_gate_requested=1
while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! kill -0 "$NODE_PID" 2>/dev/null; then
        echo "[repro] node exited early (see $DEST/repro_node.log)"; break
    fi
    if [ -f "$cookie" ]; then
        t="$(tip)"; t="${t:--1}"
        if [ "$t" -ge 0 ] 2>/dev/null; then
            seen_rpc=1
            [ "$first_tip" -lt 0 ] && first_tip="$t" && echo "[repro] first tip: $t"
            if [ "$t" -gt "$max_tip" ]; then max_tip="$t"; fi
            if [ -n "$EXPECT_CLIMB_PAST" ] &&
               [ "$t" -le "$EXPECT_CLIMB_PAST" ] 2>/dev/null; then
                seen_at_or_below_climb=1
            fi
            if [ -n "$EXPECT_CLIMB_PAST" ] &&
               [ "$t" -gt "$EXPECT_CLIMB_PAST" ] 2>/dev/null; then
                if [ "$REFOLD_REQUESTED" != "1" ] ||
                   [ "$seen_at_or_below_climb" = "1" ]; then
                    climbed_past=1
                    echo "[repro] H* CLIMBED to $t (> $EXPECT_CLIMB_PAST)"
                fi
            fi
            climb_gate_ready=1
            if [ -n "$EXPECT_CLIMB_PAST" ] && [ "$climbed_past" != "1" ]; then
                climb_gate_ready=0
            fi
            if [ "$climb_gate_ready" = "1" ] &&
               [ "$EXPECT_STATIC_SPEND_READY" = "1" ] &&
               static_spend_ready_now; then
                static_spend_ready=1
                echo "[repro] static wallet-spend predicate READY"
            fi
            if [ "$proof_gate_requested" = "1" ] &&
               [ "$climb_gate_ready" = "1" ] &&
               { [ "$EXPECT_STATIC_SPEND_READY" = "0" ] ||
                 [ "$static_spend_ready" = "1" ]; }; then
                break
            fi
            # Regression = tip dropped meaningfully below the high-water mark.
            if [ "$max_tip" -ge 0 ] && [ "$t" -lt "$((max_tip - 5))" ]; then
                echo "[repro] !! TIP REGRESSION: $max_tip -> $t (height dropped)"
                regressed=1
                break
            fi
        fi
    fi
    sleep 3
done

post_tip="$(tip)"; post_tip="${post_tip:--1}"
# A --light copy has no blocks/ — any consensus/repair path that reads bodies
# silently degrades into read-error spam and the proof is environmentally
# invalid, not evidence about the binary. Detect and refuse the verdict.
body_read_fails=0
refold_snapshot_loaded=0
if [ -f "$DEST/repro_node.log" ]; then
    # `grep -c` prints the valid count "0" while returning status 1 for no
    # matches.  Appending `|| echo 0` therefore produced "0\n0", corrupting
    # the otherwise machine-readable result JSON on a clean proof.  Preserve
    # grep's count and normalize only a genuine read/tool failure.
    body_read_fails="$(grep -ac 'cannot open .*/blocks/blk' "$DEST/repro_node.log" 2>/dev/null)" ||
        body_read_fails="${body_read_fails:-0}"
    if grep -aq '\[boot\] -refold-from-anchor: loaded .* coins from the MINTED snapshot' "$DEST/repro_node.log" 2>/dev/null; then
        refold_snapshot_loaded=1
    fi
fi
echo "========================================================================"
echo "  repro-on-copy [$SLUG]"
echo "  copy:      $DEST"
echo "  first_tip: $first_tip   max_tip: $max_tip   post_tip: $post_tip"
if [ -n "$EXPECT_CLIMB_PAST" ]; then
    echo "  climb_past: $EXPECT_CLIMB_PAST   climbed: $climbed_past"
fi
if [ "$EXPECT_STATIC_SPEND_READY" = "1" ]; then
    echo "  static_spend_ready: $static_spend_ready"
fi
if [ "$REFOLD_REQUESTED" = "1" ]; then
    echo "  refold_snapshot_loaded: $refold_snapshot_loaded"
fi
if [ -n "$INSTALL_BUNDLE_RESOLVED" ]; then
    echo "  install_consensus_bundle: $INSTALL_BUNDLE_RESOLVED (phase-1 INSTALLED; see repro_install_bundle.log)"
    echo "  phase-2 boot (this tip watch) is the H* CLIMB proof, not the install call's exit code."
fi
if [ "$LIGHT" = "1" ] && [ "$body_read_fails" -gt 0 ]; then
    echo "  VERDICT:   INVALID — $body_read_fails block-body read failures on a"
    echo "             --light copy (no blocks/). Re-run with --full; this run"
    echo "             proves nothing about the binary."
    RC=2
    VERDICT_WORD=INVALID
elif [ "$seen_rpc" = "0" ]; then
    echo "  VERDICT:   INCONCLUSIVE — node never answered RPC within ${DEADLINE}s"
    echo "             (inspect $DEST/repro_node.log)"
    RC=2
    VERDICT_WORD=INCONCLUSIVE
elif [ "$regressed" = "1" ]; then
    echo "  VERDICT:   FAIL — public tip REGRESSED on the copy (reset reproduced)"
    RC=1
    VERDICT_WORD=FAIL
elif [ "$REFOLD_REQUESTED" = "1" ] && [ "$refold_snapshot_loaded" != "1" ]; then
    echo "  VERDICT:   FAIL — -refold-from-anchor did not prove that the"
    echo "             SHA3-verified MINTED anchor snapshot was loaded."
    echo "             Inspect $DEST/repro_node.log before trusting this run."
    RC=1
    VERDICT_WORD=FAIL
elif [ -n "$EXPECT_CLIMB_PAST" ] && [ "$climbed_past" != "1" ]; then
    echo "  VERDICT:   FAIL — H* did not climb strictly past $EXPECT_CLIMB_PAST"
    echo "             within ${DEADLINE}s (first=$first_tip max=$max_tip)."
    if [ "$REFOLD_REQUESTED" = "1" ] &&
       [ "$seen_at_or_below_climb" != "1" ]; then
        echo "             Refold proofs require observing H* at/below the gate first;"
        echo "             starting above it is not accepted as a climb proof."
    fi
    RC=1
    VERDICT_WORD=FAIL
elif [ "$EXPECT_STATIC_SPEND_READY" = "1" ] &&
     [ "$static_spend_ready" != "1" ]; then
    echo "  VERDICT:   FAIL — the copied frontier never reached the exact"
    echo "             static wallet-spend-ready predicate within ${DEADLINE}s."
    echo "             A current identity-bound money snapshot would still be"
    echo "             required even if this static predicate had passed."
    RC=1
    VERDICT_WORD=FAIL
else
    echo "  VERDICT:   PASS — required proof reached within ${DEADLINE}s;"
    echo "             no tip regression occurred while observed."
    RC=0
    VERDICT_WORD=PASS
fi
echo "  copy left on disk for analysis. remove with: rm -rf '$DEST'"
echo "========================================================================"

DURATION_SECS=$(( $(date +%s) - RUN_START_EPOCH ))
LOG_PATH="$DEST/repro_node.log"
if [ "$JSON" = "1" ]; then
    emit_done_json "$VERDICT_WORD" "$RC" "$first_tip" "$post_tip" "$max_tip" \
        "$DURATION_SECS" "$LOG_PATH" >&3
fi
if [ -n "$STATUS_FILE" ]; then
    emit_done_json "$VERDICT_WORD" "$RC" "$first_tip" "$post_tip" "$max_tip" \
        "$DURATION_SECS" "$LOG_PATH" | atomic_write "$STATUS_FILE"
fi
exit $RC
