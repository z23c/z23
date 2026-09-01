# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# science_acceptance.sh — the v1 acceptance proof for the ZCODE
# scientific-metaverse slice (S3 science store, S4 closed executors,
# S5 discovery projection), per /tmp/acceptance-proof-plan.md:
#
#   two clean nodes, no GitHub, preregister and run a C23 benchmark,
#   reproduce it, publish findings/review, rank it locally, restart both
#   nodes, and reconstruct every object and receipt from hashes.
#
# Topology (two disjoint isolated nodes sharing NO datadir, loopback only):
#
#   Node A (author/executor): listens on $A_PORT, dead -connect sink; its
#       package store is seeded (real vcs_package_store_put_* APIs) with a
#       small content.v2 package, and its workspace CAS with the execution
#       context (the context objects have NO command-leaf admission path —
#       the landed tests seed them with vcs_object_put_addressed; the
#       fixture tool does exactly that, field-for-field).
#   Node B (second clean node): -connect=127.0.0.1:$A_PORT only. Same
#       lifecycle with an independent study (different fixture salt).
#
# What this script PROVES (each step asserts before proceeding):
#   [1] two-node loopback topology, exactly A<->B, nothing off-host.
#   [2] A: study plan -> commit -> show/list; workspace CAS holds the wire.
#   [3] A: confined c23.benchmark.v1 execute (sandbox self-check gate) ->
#       COMMITTED receipt; work.receipt re-verifies the row against CAS.
#   [4] A: reproduction via the v1 mirror (the executor refuses non-v1
#       originals by name; the S4 test hand-builds its v1 original the
#       same way) -> reproduction.v1 COMMITTED; roots differ, same
#       study/task/candidate binding (action equality enforced inside the
#       executor: executor-action-mismatch).
#   [5] A: findings -> review.submit (a stale review predating findings is
#       REFUSED with science-review-predates-findings) -> curation vote.
#   [6] A: zcode.science.discover renders with explanation (mass,
#       direct_citations, seed_weight), corpus/graph/seed-set roots,
#       truncation flag; rank.snapshot agrees.
#   [7] B: the SAME lifecycle independently (proves a second clean node).
#   [8] GAP ASSERTIONS: A's science objects never reached B (CAS absent,
#       projection found=false, B's execute against A's study refuses
#       executor-study-not-in-cas) — see NAMED GAPS below.
#   [9] PACKAGE LEG: B fetches A's package over the zpkgswm swarm
#       (download record pre-seeded via the one-shot fetch leaf, the
#       node's own resume path). Bounded wait; either it completes
#       (verified byte-for-byte against the root) or it stalls in
#       WANT_MANIFEST — see NAMED GAPS.
#   [10] SIGTERM both nodes, cold boot same datadirs, topology re-forms.
#   [11] HEADLINE: on both nodes — snapshot the science projection, run
#        zcode.science.rebuild (drop + re-derive from CAS), snapshot again:
#        byte-identical. Then DELETE the six projection tables directly
#        (scratch C23 sqlite wiper, never touching .zvcs/objects), prove study.show
#        goes found=false, rebuild again, byte-identical once more. CAS
#        object count unchanged throughout.
#
# NAMED GAPS (asserted, not worked around — a named gap is a deliverable):
#   G1  CLOSED. Science CAS objects had no node-to-node path; the carrier
#       is now the blob swarm (vcs/blob_store.h): zcode.science.publish
#       mirrors a committed wire into the package store as a one-chunk
#       content.v2 blob, the clock-driven swarm announces and delivers it,
#       and zcode.science.fetch re-derives the science root FROM THE BYTES
#       and admits it into the receiver's CAS + projection. This proof
#       ships A's study to B below. Honest limit, by design: the receiver
#       learns the blob root OUT OF BAND (this script passes it) —
#       automatic provider/root discovery is S7 DHT territory; S6 finds
#       authenticated node IDs only.
#   G2  CLOSED. The fresh-node package fetch stalled for three stacked
#       reasons, each fixed and covered by this proof's package leg:
#       (a) the frozen policy table gave NEW_USER 0 announces/hour, so the
#           receiver flood-refused the very first ANNOUNCE — now a 4/hour
#           bootstrap quota (VCS_POLICY_FREE_ANNOUNCE_PER_HOUR);
#       (b) announces were only queued when a peer was first added, so
#           content published after the handshake never propagated — the
#           per-sync membership sweep now re-announces to every known
#           peer, deduped per peer in the engine;
#       (c) the swarm tick only fired from the per-peer message cycle,
#           so an idle-but-healthy connection got ZERO ticks — no sync, no
#           announce, no WANT, no drain. The swarm is now clock-driven by
#           a supervisor child (net.zcode_swarm, 1 s period) registered in
#           boot_zcode_swarm_wire; the message-cycle hook survives only as
#           a send-latency fast path.
#   G3  zcode_science_rebuild had no operator surface (test-only
#       callers); this proof lands the zcode.science.rebuild leaf as the
#       sanctioned additive glue.
#   G4  CLOSED 2026-08-03: findings.v1 now has command-leaf admission —
#       zcode.science.findings.plan|commit (the fixture only composes the
#       deterministic wire via mkfindings-emit; the leaves store it to CAS
#       and project it). The remaining fixture-seeded objects are the
#       execution-context documents (env policy, workload, task,
#       candidate, method), which are content roots, not ledger objects.
#       Historical: the deterministic now_unix pin (and the science int
#       keys) had no input-validator rule, so the leaves were uninvokable
#       from the shell — fixed in engine/modules/kernel/src/command_registry.c as
#       sanctioned glue.
#
# SAFETY: mirrors isolated_node_env.sh / two_node_peer_tip.sh —
#   test-tmp/-only datadirs (mktemp -d), 39xxx isolation ports probed with
#   ss(8) against the live refuse-set AND the LISTEN table, setsid process
#   groups killed on EXIT/INT/TERM, never near 8033/18232.
#
# Run:  make test-science-acceptance   (opt-in; NOT in `make ci` — spawns
# two real node processes and needs the host Landlock/seccomp confinement
# backend, same opt-in class as test-two-node-peer-tip.)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"
JSONQ="${JSONQ:-$REPO_ROOT/build/bin/jsonq}"

SA_LIVE_PORTS="8023 8033 8034 8035 8043 8044 8045 8046 8232 8443 \
18034 18232 18234 18243 18244 18245 18246"

# Controlled reconnects pass the production reachable-port policy. Use the
# same explicit test-safe P2P pair as the S6 DHT acceptance; arbitrary 39xxx
# P2P ports are valid only for the first operator-directed connect.
A_PORT=20022; A_RPC=39111; A_FS=39112; A_HTTPS=39113
B_PORT=18033; B_RPC=39121; B_FS=39122; B_HTTPS=39123
DEAD_SINK=39999
RPC_WARMUP="${RPC_WARMUP:-90}"     # per-node RPC warmup budget (s)
PKG_WAIT="${PKG_WAIT:-75}"         # swarm fetch budget (s)

# Deterministic submission pins (fixture windows: study 1000..5000,
# findings 1800, stale review 1700, fresh review 1900, vote expires 5000).
NOW_STUDY=1500
NOW_REPRO=1600
NOW_REVIEW=1900

SA_DD_A=""; SA_DD_B=""; SA_WORK=""
SA_PGID_A=""; SA_PGID_B=""
SA_CLEANED=0
SA_KEEP="${SCIENCE_KEEP:-0}"
# Throwaway passphrases for the wallet-custody recipe (never argv: they
# ride the wallet-passphrase credential file and --input=- stdin only).
SA_WALLET_PASS="science-acceptance-wallet-pass"
SA_BACKUP_PASS="science-acceptance-backup-pass"
SA_STEP_START=$(date +%s)

sa_die() { echo "science-acceptance: FATAL: $*" >&2; exit 2; }
sa_step() {
    local now; now=$(date +%s)
    echo "science-acceptance: [$1] (t+$((now - SA_STEP_START))s) $2"
    SA_STEP_START=$now
}

sa_assert_not_live_port() {
    local p="$1" lp
    for lp in $SA_LIVE_PORTS; do
        [ "$p" = "$lp" ] && sa_die "port $p is in the live refuse-set — refusing"
    done
    return 0
}
sa_assert_port_free() {
    local p="$1"
    if [ -n "$(ss -tlnH "sport = :$p" 2>/dev/null)" ]; then
        sa_die "port $p is already LISTENING — refusing (operator port math is wrong)"
    fi
    return 0
}

sa_kill_group() {
    local pgid="$1" sig="${2:-TERM}"
    [ -n "$pgid" ] || return 0
    kill -"$sig" "-$pgid" 2>/dev/null || true
    local i
    for i in $(seq 1 50); do
        kill -0 "-$pgid" 2>/dev/null || break
        sleep 0.2
    done
    kill -KILL "-$pgid" 2>/dev/null || true
}
sa_rm_dir() {
    local dd="$1"
    [ -n "$dd" ] && [ -d "$dd" ] || return 0
    case "$dd" in
        "$REPO_ROOT"/test-tmp/zcl23-sciacc-*) rm -rf "$dd" 2>/dev/null || true ;;
        *) echo "science-acceptance: WARN: refusing to rm non-scratch dir '$dd'" >&2 ;;
    esac
}
sa_cleanup() {
    [ "$SA_CLEANED" = "1" ] && return 0
    SA_CLEANED=1
    sa_kill_group "$SA_PGID_A"
    sa_kill_group "$SA_PGID_B"
    [ -n "$SA_DD_A" ] && pkill -KILL -f -- "-datadir=$SA_DD_A" 2>/dev/null || true
    [ -n "$SA_DD_B" ] && pkill -KILL -f -- "-datadir=$SA_DD_B" 2>/dev/null || true
    if [ "$SA_KEEP" = "1" ]; then
        echo "science-acceptance: preserved A=$SA_DD_A B=$SA_DD_B work=$SA_WORK"
        return 0
    fi
    sa_rm_dir "$SA_DD_A"
    sa_rm_dir "$SA_DD_B"
    sa_rm_dir "$SA_WORK"
}

sa_rpc() { # $1=datadir $2=rpcport $3.. = method/args
    local dd="$1" rp="$2"; shift 2
    ZCL_DATADIR="$dd" ZCL_RPCPORT="$rp" "$RPC_BIN" "$@" 2>/dev/null || true
}
sa_result() { "$JSONQ" unwrap; }
a_rpc() { sa_rpc "$SA_DD_A" "$A_RPC" "$@"; }
b_rpc() { sa_rpc "$SA_DD_B" "$B_RPC" "$@"; }

sa_peer_count() { # $1=datadir $2=rpcport → integer peer count
    local n
    n="$(sa_rpc "$1" "$2" getpeerinfo | "$JSONQ" count result 2>/dev/null)" || n=-1
    printf '%s\n' "${n:--1}"
}

sa_wait_topology() { # wait for the one permitted A<->B peer on both sides
    local deadline pc_a pc_b
    deadline=$(( $(date +%s) + 60 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        pc_a="$(sa_peer_count "$SA_DD_A" "$A_RPC")"
        pc_b="$(sa_peer_count "$SA_DD_B" "$B_RPC")"
        [ "$pc_a" = "1" ] && [ "$pc_b" = "1" ] && return 0
        sleep 0.5
    done
    return 1
}

sa_spawn() { # $1=datadir $2=p2p $3=rpc $4=fs $5=https $6=connect-target $7=mode
    local dd="$1" p2p="$2" rpc="$3" fs="$4" https="$5" conn="$6"
    local mode="${7:-hosting}" service_args=(-packagehost=1 -nofilesync)
    [ "$mode" = "bootstrap" ] && service_args=(-packagehost=0)
    # No -allow-plaintext-wallet: the ZID anchor's overlay-intent custody
    # gate refuses a plaintext-at-rest wallet. The wallet-passphrase
    # credential (CREDENTIALS_DIRECTORY, exported below) encrypts key
    # writes at rest (WKS1); -operator-lane=dev arms the dev wallet scope.
    setsid "$NODE_BIN" \
        -datadir="$dd" -regtest \
        -port="$p2p" -rpcport="$rpc" -fsport="$fs" -httpsport="$https" \
        -connect="$conn" "${service_args[@]}" -noisetransport \
        -operator-lane=dev -wallet-no-phrase-backup \
        -nobgvalidation -nolegacyimport -showmetrics=0 \
        >"$dd/node.log" 2>&1 &
    echo "$!"   # PID == PGID (setsid leader)
}

sa_mine_to() {
    local count="$1" address="$2" chunk
    while [ "$count" -gt 0 ]; do
        chunk=5; [ "$count" -lt 5 ] && chunk="$count"
        a_rpc generatetoaddress "$chunk" "\"$address\"" | sa_result >/dev/null
        count=$((count - chunk)); [ "$count" -eq 0 ] || sleep 1
    done
}
sa_mine_empty() {
    local count="$1" chunk
    while [ "$count" -gt 0 ]; do
        chunk=5; [ "$count" -lt 5 ] && chunk="$count"
        a_rpc generate "$chunk" | sa_result >/dev/null
        count=$((count - chunk)); [ "$count" -eq 0 ] || sleep 1
    done
}
sa_wait_height() {
    local dd="$1" rpc="$2" want="$3" i h
    for i in $(seq 1 180); do
        h="$(sa_rpc "$dd" "$rpc" getblockcount | sa_result 2>/dev/null || true)"
        [ "${h:-0}" -ge "$want" ] && return 0
        sleep 0.5
    done
    return 1
}

sa_wait_identity_active() { # $1=datadir $2=master pubkey
    local dd="$1" pub="$2" out
    for _ in $(seq 1 120); do
        out="$(sa_sci "$dd" core.identity.resolve "{\"pubkey\":\"$pub\"}")"
        [ "$(sa_jget "$out" ok 2>/dev/null || true)" = "true" ] &&
        [ "$(sa_jget "$out" data.status 2>/dev/null || true)" = "active" ] && return 0
        sleep 0.5
    done
    echo "science-acceptance: identity ACTIVE wait last reply: $out" >&2
    return 1
}

sa_wait_rpc() { # $1=dd $2=rpc $3=pid $4=secs
    local dd="$1" rp="$2" pid="$3" secs="$4" deadline t
    deadline=$(( $(date +%s) + secs ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "science-acceptance: node (pid $pid) exited during warmup (see $dd/node.log)" >&2
            return 1
        fi
        if [ -f "$dd/.cookie" ]; then
            t="$(sa_rpc "$dd" "$rp" getblockcount | tr -dc '0-9-')"
            [ -n "$t" ] && return 0
        fi
        sleep 0.5
    done
    return 1
}

# ── wallet-custody helpers (the ZID anchor's overlay-intent gate) ─────
# The anchor's custody gate requires the wallet encrypted at rest (the
# wallet-passphrase credential armed at first boot), unlocked, and covered
# by a current-key encrypted backup; its money gate requires an OUTBOUND
# peer with a live sync state and a positive vault spendable. This is the
# metaverse-tour recipe (tools/dev/metaverse_tour.sh) adapted to sa_*
# style; passphrases ride --input=- stdin only, never argv.
sa_native() { # $1=datadir $2.. = argv (no --input appended)
    local dd="$1"; shift
    local rpc="$A_RPC"
    [ "$dd" = "$SA_DD_B" ] && rpc="$B_RPC"
    "$NODE_BIN" -datadir="$dd" -rpcport="$rpc" "$@" 2>/dev/null | tail -1 || true
}
sa_sci_stdin() { # $1=datadir $2=leaf; the JSON input rides stdin
    local dd="$1" leaf="$2"
    local rpc="$A_RPC"
    [ "$dd" = "$SA_DD_B" ] && rpc="$B_RPC"
    "$NODE_BIN" -datadir="$dd" -rpcport="$rpc" "$leaf" --input=- 2>/dev/null | tail -1 || true
}
sa_wait_connected() { # $1=datadir $2=rpcport
    local deadline n
    deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        n="$(sa_rpc "$1" "$2" getconnectioncount | sa_result 2>/dev/null || true)"
        [ "${n:-0}" -ge 1 ] 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}
# The money freshness classifier fails closed on finding_peers; the sync
# FSM only leaves it behind a peer it can sync FROM (outbound).
sa_wait_sync_live() { # $1=datadir $2=rpcport
    local deadline state
    deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        state="$(sa_rpc "$1" "$2" downloadstats \
            | jget result.sync_state 2>/dev/null || true)"
        case "$state" in
            blocks_download|connecting_blocks|at_tip) return 0 ;;
        esac
        sleep 0.5
    done
    return 1
}
# The money gate reads the REDUCER pipeline, not the active chain: the
# authoritative coins tip AND H* must both reach the mined height.
sa_wait_fold() { # $1=datadir $2=tip
    local deadline dump coins hstar
    deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        dump="$(sa_native "$1" dumpstate reducer_frontier)"
        coins="$(sa_jget "$dump" state.coins_best_height 2>/dev/null || true)"
        hstar="$(sa_jget "$dump" state.hstar 2>/dev/null || true)"
        [ "$coins" = "$2" ] && [ "$hstar" = "$2" ] && return 0
        sleep 1
    done
    echo "science-acceptance: reducer_frontier at stall: $dump" >&2
    return 1
}
# RPC-ready != chain-loaded: the anchor's runtime gate needs the active
# chain index, which loads after the RPC starts serving.
sa_wait_chain_loaded() { # $1=datadir $2=rpcport $3=tip
    local deadline info blocks ibd
    deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        info="$(sa_rpc "$1" "$2" getblockchaininfo 2>/dev/null || true)"
        blocks="$(printf '%s' "$info" | "$JSONQ" get result.blocks 2>/dev/null || true)"
        ibd="$(printf '%s' "$info" | "$JSONQ" get result.initialblockdownload 2>/dev/null || true)"
        [ "$blocks" = "$3" ] && [ "$ibd" != "true" ] && [ -n "$blocks" ] && return 0
        sleep 1
    done
    return 1
}
# The fee-reserve rung reads the vault read model's zcl_spendable, which
# lags the reducer fold while the wallet re-derives its spendable coins.
sa_wait_spendable() { # $1=datadir
    local deadline spend
    deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        spend="$(sa_native "$1" dumpstate vault \
            | jget state.zcl.spendable 2>/dev/null || true)"
        case "$spend" in
            ''|*[!0-9]*) ;;
            *) [ "$spend" -gt 0 ] && return 0 ;;
        esac
        sleep 1
    done
    return 1
}
sa_unlock_wallet() { # $1=datadir
    local status unlock
    status="$(sa_native "$1" core.wallet.security.status)"
    [ "$(sa_jget "$status" ok 2>/dev/null || true)" = "true" ] || {
        printf '%s\n' "$status" >&2; return 1; }
    if [ "$(sa_jget "$status" data.unlocked 2>/dev/null || true)" != "true" ]; then
        unlock="$(printf '%s' "{\"passphrase\":\"$SA_WALLET_PASS\",\"timeout_seconds\":3600}" \
            | sa_sci_stdin "$1" core.wallet.security.unlock)"
        [ "$(sa_jget "$unlock" data.unlocked 2>/dev/null || true)" = "true" ] || {
            printf '%s\n' "$unlock" >&2; return 1; }
    fi
    return 0
}
sa_backup_wallet() { # $1=datadir
    local out
    out="$(printf '%s' "{\"confirm\":true,\"password\":\"$SA_BACKUP_PASS\"}" \
        | sa_sci_stdin "$1" core.wallet.backup.now)"
    [ "$(sa_jget "$out" ok 2>/dev/null || true)" = "true" ] || {
        printf '%s\n' "$out" >&2; return 1; }
}
# Plan (retrying ONLY the transient OVERLAY_INTENT_REFUSED money-currency
# skew — the idempotency key makes a repeated plan safe), then commit the
# returned plan_id. Prints the commit reply; nonzero on any refusal.
sa_anchor() { # $1=datadir $2=pubkey $3=idempotency-key
    local dd="$1" pubkey="$2" key="$3" plan plan_id commit try
    plan=""
    for try in $(seq 1 20); do
        plan="$(sa_sci "$dd" core.identity.anchor \
            "{\"wallet_scope\":\"dev\",\"pubkey\":\"$pubkey\",\"idempotency_key\":\"$key\"}")"
        case "$plan" in
            *OVERLAY_INTENT_REFUSED*) sleep 1 ;;
            *) break ;;
        esac
    done
    [ "$(sa_jget "$plan" ok 2>/dev/null || true)" = "true" ] &&
    [ "$(sa_jget "$plan" data.stage 2>/dev/null || true)" = "plan" ] || {
        printf '%s\n' "$plan" >&2; return 1; }
    plan_id="$(sa_jget "$plan" data.plan_id 2>/dev/null)" || return 1
    commit="$(sa_sci "$dd" core.identity.anchor \
        "{\"wallet_scope\":\"dev\",\"plan_id\":\"$plan_id\",\"confirm\":true}")"
    [ "$(sa_jget "$commit" ok 2>/dev/null || true)" = "true" ] &&
    [ "$(sa_jget "$commit" data.stage 2>/dev/null || true)" = "committed" ] || {
        printf '%s\n' "$commit" >&2; return 1; }
    printf '%s\n' "$commit"
}

# ── science leaf driver + assertions ──────────────────────────────────
# sa_sci <datadir> <leaf> <json> → prints the reply's one JSON line.
sa_sci() {
    local dd="$1" leaf="$2" input="$3"
    local rpc="$A_RPC"
    [ "$dd" = "$SA_DD_B" ] && rpc="$B_RPC"
    # The CLI exits non-zero whenever the reply is ok:false — expected for
    # the refusal assertions (stale review, B-against-A's-study). Always
    # return 0; every reply is asserted on its JSON content.
    "$NODE_BIN" -datadir="$dd" -rpcport="$rpc" "$leaf" \
        --input="$input" 2>/dev/null | tail -1 || true
}
# jget PATH — jsonq get over one JSON document on stdin.
jget() { "$JSONQ" get "$1"; }
sa_jget() { printf '%s' "$1" | "$JSONQ" get "$2"; }

# ── fixture tool compile ───────────────────────────────────────────────
sa_build_fixture() {
    cc -std=c23 -O1 -w -D_GNU_SOURCE \
        -I"$REPO_ROOT/contexts/commons/modules/vcs/include" -I"$REPO_ROOT/platform/modules/base/include" \
        -I"$REPO_ROOT/platform/modules/sha3/include" -I"$REPO_ROOT/core/modules/crypto/include" \
        -I"$REPO_ROOT/platform/modules/json/include" -I"$REPO_ROOT/platform/modules/codec/include" \
        -I"$REPO_ROOT/platform/modules/util/include" -I"$REPO_ROOT/platform/modules/platform/include" \
        -I"$REPO_ROOT/platform/modules/support/include" \
        -o "$SA_WORK/zcode_science_fixture" \
        "$REPO_ROOT/tools/zcode_science_fixture.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/zcode_science.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/zcode_dev.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/zcode_benchmark_receipt.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/vcs_object.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/package_store.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/package_store_io.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/package_manifest.c" \
        "$REPO_ROOT/contexts/commons/modules/vcs/src/build_action.c" \
        "$REPO_ROOT/platform/modules/codec/src/cursor.c" \
        "$REPO_ROOT/platform/modules/sha3/src/sha3.c" \
        "$REPO_ROOT/core/modules/crypto/src/ed25519.c" \
        "$REPO_ROOT/core/modules/crypto/src/sha512.c" \
        "$REPO_ROOT/core/modules/crypto/src/sha256.c" \
        "$REPO_ROOT/core/modules/crypto/src/chacha20poly1305.c" \
        "$REPO_ROOT/platform/modules/support/src/log_throttle.c" \
        "$REPO_ROOT/platform/modules/base/src/safe_alloc.c" \
        "$REPO_ROOT/platform/modules/base/src/log_level.c" \
        "$REPO_ROOT/platform/modules/base/src/result.c" \
        "$REPO_ROOT/platform/modules/base/src/cleanse.c" \
        "$REPO_ROOT/platform/modules/platform/src/clock.c" \
        "$REPO_ROOT/platform/modules/json/src/json.c" \
        "$REPO_ROOT/platform/modules/util/src/hw_profile.c" \
        "$REPO_ROOT/platform/modules/util/src/spawn.c" \
        "$REPO_ROOT/platform/modules/util/src/cpu_topology.c" 2>/dev/null \
        || sa_die "fixture tool compile failed"
}

FIX=""   # fixture tool path
CH_HASH="abababababababababababababababababababababababababababababababab"
REPRO_PUB="cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

# Full single-node science lifecycle. $1=datadir $2=salt $3=label.
# Sets globals: L_STUDY L_TASK L_CAND L_METHOD L_RA L_V1 L_PA L_RB L_FR L_RR L_VID
run_lifecycle() {
    local dd="$1" salt="$2" label="$3" out
    eval "$("$FIX" seed-context "$dd/zcode" "$salt" | grep -E 'ROOT=|WIRE=')"
    L_STUDY="$STUDY_ROOT"; L_TASK="$TASK_ROOT"; L_CAND="$CANDIDATE_ROOT"
    L_METHOD="$METHOD_ROOT"

    # study plan -> commit -> show/list
    out="$(sa_sci "$dd" zcode.science.study.plan \
        "{\"wire_hex\":\"$STUDY_WIRE\",\"now_unix\":$NOW_STUDY}")"
    [ "$(sa_jget "$out" ok)" = "true" ] || sa_die "$label study.plan refused: $out"
    out="$(sa_sci "$dd" zcode.science.study.commit \
        "{\"wire_hex\":\"$STUDY_WIRE\",\"confirm\":true,\"now_unix\":$NOW_STUDY}")"
    [ "$(sa_jget "$out" ok)" = "true" ] || sa_die "$label study.commit refused: $out"
    [ "$(sa_jget "$out" data.study_root)" = "$L_STUDY" ] \
        || sa_die "$label study root drifted"
    out="$(sa_sci "$dd" zcode.science.study.show \
        "{\"study_root\":\"$L_STUDY\"}")"
    [ "$(sa_jget "$out" data.found)" = "true" ] \
        || sa_die "$label study.show found=false after commit"
    [ "$("$FIX" cas-has "$dd/zcode" "$L_STUDY" | grep -c 'PRESENT=1')" = "1" ] \
        || sa_die "$label study wire absent from CAS after commit"
    echo "science-acceptance:     $label study committed: ${L_STUDY:0:16}…"

    # confined benchmark execute (the sandbox self-check gate is inside)
    out="$(sa_sci "$dd" zcode.science.work.execute \
        "{\"study_root\":\"$L_STUDY\",\"task_root\":\"$L_TASK\",\"candidate_root\":\"$L_CAND\",\"method_root\":\"$L_METHOD\",\"challenge_block_height\":3200000,\"challenge_block_hash\":\"$CH_HASH\",\"confirm\":true,\"now_unix\":$NOW_STUDY}")"
    [ "$(sa_jget "$out" ok)" = "true" ] \
        || sa_die "$label work.execute refused (confinement gate?): $out"
    [ "$(sa_jget "$out" data.state)" = "COMMITTED" ] \
        || sa_die "$label execute did not commit"
    L_RA="$(sa_jget "$out" data.result_root)"
    local raw_root payload_root ev_root
    raw_root="$(sa_jget "$out" data.raw_sample_root)"
    payload_root="$(sa_jget "$out" data.sample_payload_root)"
    ev_root="$(sa_jget "$out" data.evidence_root)"
    out="$(sa_sci "$dd" zcode.science.work.receipt "{\"root\":\"$L_RA\"}")"
    [ "$(sa_jget "$out" data.cas_verified)" = "true" ] \
        || sa_die "$label receipt failed CAS verification"
    [ "$(sa_jget "$out" data.study_root)" = "$L_STUDY" ] \
        || sa_die "$label receipt bound the wrong study"
    echo "science-acceptance:     $label benchmark committed: ${L_RA:0:16}… (samples ${raw_root:0:12}… payload ${payload_root:0:12}… evidence ${ev_root:0:12}…)"

    # reproduction against the v1 mirror of the real observation
    eval "$("$FIX" v1mirror "$dd/zcode" "$L_RA")"
    L_V1="$V1_ROOT"
    out="$(sa_sci "$dd" zcode.science.work.execute \
        "{\"method_root\":\"$L_METHOD\",\"original_result_root\":\"$L_V1\",\"reproducer_pubkey\":\"$REPRO_PUB\",\"action_kind\":\"c23.benchmark.reproduce.v1\",\"challenge_block_height\":3200000,\"challenge_block_hash\":\"$CH_HASH\",\"confirm\":true,\"now_unix\":$NOW_REPRO}")"
    [ "$(sa_jget "$out" ok)" = "true" ] \
        || sa_die "$label reproduction execute refused: $out"
    L_PA="$(sa_jget "$out" data.reproduction_root)"
    L_RB="$(sa_jget "$out" data.reproduced_result_root)"
    local verdict
    verdict="$(sa_jget "$out" data.verdict)"
    [ "$L_RB" != "$L_RA" ] || sa_die "$label reproduced root equals original root"
    out="$(sa_sci "$dd" zcode.science.work.status "{\"root\":\"$L_PA\"}")"
    [ "$(sa_jget "$out" data.study_root)" = "$L_STUDY" ] \
        || sa_die "$label reproduction bound the wrong study"
    [ "$(sa_jget "$out" data.link_root)" = "$L_V1" ] \
        || sa_die "$label reproduction bound the wrong original"
    [ "$(sa_jget "$out" data.aux_root)" = "$L_RB" ] \
        || sa_die "$label reproduction bound the wrong reproduced root"
    echo "science-acceptance:     $label reproduction committed: ${L_PA:0:16}… verdict=$verdict (1=replicated 2=contradicted 3=inconclusive; any is a valid observation)"

    # findings -> stale review REFUSED -> fresh review -> vote
    # G4: findings are admitted through the plan|commit leaves (the fixture
    # only composes the wire; it no longer touches the CAS).
    eval "$("$FIX" mkfindings-emit "$L_STUDY" "$L_TASK" "$L_CAND" "$L_RA" 1800 "$salt")"
    L_FR="$FINDINGS_ROOT"
    sa_sci "$dd" zcode.science.findings.plan \
        "{\"wire_hex\":\"$FINDINGS_WIRE_HEX\",\"now_unix\":$NOW_REVIEW}" >/dev/null
    out="$(sa_sci "$dd" zcode.science.findings.commit \
        "{\"wire_hex\":\"$FINDINGS_WIRE_HEX\",\"confirm\":true,\"now_unix\":$NOW_REVIEW}")"
    [ "$(sa_jget "$out" ok)" = "true" ] || sa_die "$label findings commit refused: $out"
    [ "$(sa_jget "$out" data.findings_root)" = "$L_FR" ] \
        || sa_die "$label findings root drifted through plan/commit: $out"
    eval "$("$FIX" mkreview "$L_TASK" "$L_CAND" "$L_FR" 1700 1 "$salt")"
    sa_sci "$dd" zcode.science.review.submit \
        "{\"wire_hex\":\"$REVIEW_WIRE\",\"now_unix\":$NOW_REVIEW}" >/dev/null
    out="$(sa_sci "$dd" zcode.science.review.submit \
        "{\"wire_hex\":\"$REVIEW_WIRE\",\"confirm\":true,\"now_unix\":$NOW_REVIEW}")"
    [ "$(sa_jget "$out" ok)" = "false" ] \
        || sa_die "$label stale review was ACCEPTED — the freshness rule is broken"
    [ "$(sa_jget "$out" error.message)" = "science-review-predates-findings" ] \
        || sa_die "$label stale review refused with the wrong rule: $out"
    echo "science-acceptance:     $label stale review refused by name (science-review-predates-findings)"
    eval "$("$FIX" mkreview "$L_TASK" "$L_CAND" "$L_FR" 1900 1 "$salt")"
    sa_sci "$dd" zcode.science.review.submit \
        "{\"wire_hex\":\"$REVIEW_WIRE\",\"now_unix\":$NOW_REVIEW}" >/dev/null
    out="$(sa_sci "$dd" zcode.science.review.submit \
        "{\"wire_hex\":\"$REVIEW_WIRE\",\"confirm\":true,\"now_unix\":$NOW_REVIEW}")"
    [ "$(sa_jget "$out" ok)" = "true" ] || sa_die "$label fresh review refused: $out"
    L_RR="$(sa_jget "$out" data.review_root)"
    eval "$("$FIX" mkvote "$L_STUDY" 5000 "$salt")"
    sa_sci "$dd" zcode.science.vote.submit \
        "{\"wire_hex\":\"$VOTE_WIRE\",\"now_unix\":$NOW_STUDY,\"network_genesis_root\":\"$GENESIS_ROOT\",\"voter_zid_root\":\"$VOTER_ZID_ROOT\",\"signer_pubkey\":\"$SIGNER_PUBKEY\"}" >/dev/null
    out="$(sa_sci "$dd" zcode.science.vote.submit \
        "{\"wire_hex\":\"$VOTE_WIRE\",\"confirm\":true,\"now_unix\":$NOW_STUDY,\"network_genesis_root\":\"$GENESIS_ROOT\",\"voter_zid_root\":\"$VOTER_ZID_ROOT\",\"signer_pubkey\":\"$SIGNER_PUBKEY\"}")"
    [ "$(sa_jget "$out" ok)" = "true" ] || sa_die "$label vote refused: $out"
    L_VID="$(sa_jget "$out" data.vote_id)"
    echo "science-acceptance:     $label findings ${L_FR:0:12}… review ${L_RR:0:12}… vote ${L_VID:0:12}… committed"

    # local discovery over the committed corpus
    out="$(sa_sci "$dd" zcode.science.discover \
        "{\"category\":\"active\",\"max\":16,\"now_unix\":$NOW_STUDY}")"
    [ "$(sa_jget "$out" ok)" = "true" ] || sa_die "$label discover failed: $out"
    [ "$(sa_jget "$out" data.count)" -ge 1 ] \
        || sa_die "$label discover rendered an empty corpus over a committed study"
    local corpus graph seedset trunc trunc_t count noun k
    corpus="$(printf '%s' "$out" | "$JSONQ" get data.corpus_root)" \
        || sa_die "$label discover output lacks explanation/roots/truncation"
    graph="$(printf '%s' "$out" | "$JSONQ" get data.graph_root)" \
        || sa_die "$label discover output lacks explanation/roots/truncation"
    seedset="$(printf '%s' "$out" | "$JSONQ" get data.seed_set_root)" \
        || sa_die "$label discover output lacks explanation/roots/truncation"
    [ -n "$corpus" ] && [ "$corpus" != "null" ] &&
    [ -n "$graph" ] && [ "$graph" != "null" ] &&
    [ -n "$seedset" ] && [ "$seedset" != "null" ] \
        || sa_die "$label discover output lacks explanation/roots/truncation"
    trunc="$(printf '%s' "$out" | "$JSONQ" get data.truncated)" \
        || sa_die "$label discover output lacks explanation/roots/truncation"
    trunc_t="$(printf '%s' "$out" | "$JSONQ" type data.truncated)" \
        || sa_die "$label discover output lacks explanation/roots/truncation"
    [ "$trunc_t" = "bool" ] \
        || sa_die "$label discover output lacks explanation/roots/truncation"
    for k in property_root mass mass_share_millionths direct_citations seed_weight; do
        printf '%s' "$out" | "$JSONQ" has "data.entries[0].$k" >/dev/null \
            || sa_die "$label discover output lacks explanation/roots/truncation"
    done
    count="$(printf '%s' "$out" | "$JSONQ" get data.count)"
    if [ "$count" = "1" ]; then noun=y; else noun=ies; fi
    echo "science-acceptance:     $label discover: $count entr$noun, corpus ${corpus:0:16}…, truncated=$trunc"
}

# Projection snapshot for the rebuild-equivalence proof. $1=datadir
# $2=study $3=ra $4=pa $5=outfile
snap_projection() {
    local dd="$1" study="$2" ra="$3" pa="$4" outfile="$5"
    local raw line cmd data
    raw="$(mktemp)"
    {
        sa_sci "$dd" zcode.science.study.list '{"max":32}'
        sa_sci "$dd" zcode.science.study.show "{\"study_root\":\"$study\"}"
        sa_sci "$dd" zcode.science.work.status "{\"root\":\"$ra\"}"
        sa_sci "$dd" zcode.science.work.status "{\"root\":\"$pa\"}"
        sa_sci "$dd" zcode.science.work.receipt "{\"root\":\"$ra\"}"
        sa_sci "$dd" zcode.science.work.receipt "{\"root\":\"$pa\"}"
        sa_sci "$dd" zcode.science.discover "{\"category\":\"active\",\"max\":16,\"now_unix\":$NOW_STUDY}"
        sa_sci "$dd" zcode.science.rank.snapshot "{\"workspace\":\"$dd/zcode\",\"now_unix\":$NOW_STUDY}"
    } > "$raw"
    : > "$outfile"
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        case "$line" in
            \{*)
                cmd="$(printf '%s' "$line" | "$JSONQ" get command 2>/dev/null || true)"
                if printf '%s' "$line" | "$JSONQ" has data >/dev/null 2>&1; then
                    data="$(printf '%s' "$line" | "$JSONQ" get data)"
                else
                    data="null"
                fi
                printf '%s %s\n' "$cmd" "$data" >> "$outfile"
                ;;
        esac
    done < "$raw"
    rm -f "$raw"
}

cas_object_count() { # $1=datadir
    find "$1/zcode/.zvcs/objects" -type f -not -path "*/tmp/*" | wc -l
}

sql_wipe_projection() { # $1=datadir — the six rebuildable tables ONLY.
    local db="$1/node.db"
    if [ ! -x "$SA_WORK/wipe_projection" ]; then
        cat > "$SA_WORK/wipe_projection.c" <<'EOF'
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include <sqlite3.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fputs("usage: wipe_projection <node.db>\n", stderr);
        return 2;
    }
    sqlite3 *db = NULL;
    if (sqlite3_open(argv[1], &db) != SQLITE_OK) {
        fprintf(stderr, "wipe_projection: open failed: %s\n",
                db ? sqlite3_errmsg(db) : "oom");
        sqlite3_close(db);
        return 1;
    }
    sqlite3_busy_timeout(db, 30000);
    const char *sql =
        "DELETE FROM zcode_science_studies;"
        "DELETE FROM zcode_science_results;"
        "DELETE FROM zcode_science_reproductions;"
        "DELETE FROM zcode_science_findings;"
        "DELETE FROM zcode_science_votes;"
        "DELETE FROM zcode_science_reviews;";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "wipe_projection: %s\n", err ? err : "exec failed");
        sqlite3_free(err);
        sqlite3_close(db);
        return 1;
    }
    sqlite3_close(db);
    return 0;
}
EOF
        cc -std=c23 -O2 -I"$REPO_ROOT/vendor/include" \
            -o "$SA_WORK/wipe_projection" "$SA_WORK/wipe_projection.c" \
            -L"$REPO_ROOT/vendor/lib" -l:libsqlite3.a -lpthread -ldl -lm \
            || sa_die "projection wiper compile failed"
    fi
    "$SA_WORK/wipe_projection" "$db" || sa_die "SQL projection wipe failed"
}

# Rebuild + wipe + rebuild proof on one node. $1=datadir $2=label
# $3=study $4=ra $5=pa
rebuild_proof() {
    local dd="$1" label="$2" study="$3" ra="$4" pa="$5" out
    local before after
    before="$(mktemp)"; after="$(mktemp)"
    snap_projection "$dd" "$study" "$ra" "$pa" "$before"
    out="$(sa_sci "$dd" zcode.science.rebuild "{\"now_unix\":$NOW_STUDY}")"
    [ "$(sa_jget "$out" ok)" = "true" ] || sa_die "$label rebuild failed: $out"
    echo "science-acceptance:     $label rebuild counts: $(sa_jget "$out" data)"
    snap_projection "$dd" "$study" "$ra" "$pa" "$after"
    diff -q "$before" "$after" >/dev/null \
        || { diff "$before" "$after" | head -10; sa_die "$label projection changed across rebuild"; }
    echo "science-acceptance:     $label rebuild-equivalence: projection byte-identical after drop+rebuild"

    # The projection is disposable: wipe the six tables directly, prove the
    # reads go empty, rebuild from the CAS again, byte-identical again.
    local objs_before objs_after
    objs_before="$(cas_object_count "$dd")"
    sql_wipe_projection "$dd"
    out="$(sa_sci "$dd" zcode.science.study.show "{\"study_root\":\"$study\"}")"
    [ "$(sa_jget "$out" data.found)" = "false" ] \
        || sa_die "$label study.show still served after the SQL wipe"
    echo "science-acceptance:     $label SQL projection wiped (6 tables; .zvcs/objects untouched): study.show found=false"
    out="$(sa_sci "$dd" zcode.science.rebuild "{\"now_unix\":$NOW_STUDY}")"
    [ "$(sa_jget "$out" ok)" = "true" ] || sa_die "$label rebuild after wipe failed: $out"
    snap_projection "$dd" "$study" "$ra" "$pa" "$after"
    diff -q "$before" "$after" >/dev/null \
        || { diff "$before" "$after" | head -10; sa_die "$label projection did not reconstruct identically from CAS"; }
    objs_after="$(cas_object_count "$dd")"
    [ "$objs_before" = "$objs_after" ] \
        || sa_die "$label CAS object count changed ($objs_before -> $objs_after) across wipe+rebuild"
    echo "science-acceptance:     $label reconstructed from hashes: byte-identical after SQL wipe; CAS object count stable at $objs_after"
    rm -f "$before" "$after"
}

# ── preflight ──────────────────────────────────────────────────────────
command -v ss      >/dev/null 2>&1 || sa_die "ss(8) not found (need iproute2)"
command -v mktemp  >/dev/null 2>&1 || sa_die "mktemp not found"
command -v cc      >/dev/null 2>&1 || sa_die "cc not found (fixture tool compile)"
[ -x "$JSONQ" ]    || sa_die "build/bin/jsonq is missing — run make jsonq"
[ -x "$NODE_BIN" ] || sa_die "$NODE_BIN not built — run make first"
[ -x "$RPC_BIN" ]  || sa_die "$RPC_BIN not built — run make zcl-rpc"

for p in "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" \
         "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "$DEAD_SINK"; do
    sa_assert_not_live_port "$p"
done

SA_DD_A="$(mktemp -d "$REPO_ROOT/test-tmp/zcl23-sciacc-A-XXXXXX")" || sa_die "mktemp A failed"
SA_DD_B="$(mktemp -d "$REPO_ROOT/test-tmp/zcl23-sciacc-B-XXXXXX")" || sa_die "mktemp B failed"
SA_WORK="$(mktemp -d "$REPO_ROOT/test-tmp/zcl23-sciacc-W-XXXXXX")" || sa_die "mktemp W failed"
case "$SA_DD_A" in "$REPO_ROOT"/test-tmp/zcl23-sciacc-A-*) : ;; *) sa_die "bad A datadir $SA_DD_A" ;; esac
case "$SA_DD_B" in "$REPO_ROOT"/test-tmp/zcl23-sciacc-B-*) : ;; *) sa_die "bad B datadir $SA_DD_B" ;; esac
if [ -n "${HOME:-}" ]; then
    case "$SA_DD_A" in "$HOME"/.zclassic-c23*) sa_die "A datadir under live tree — refusing" ;; esac
    case "$SA_DD_B" in "$HOME"/.zclassic-c23*) sa_die "B datadir under live tree — refusing" ;; esac
fi

trap sa_cleanup EXIT INT TERM

for p in "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" \
         "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS"; do
    sa_assert_port_free "$p"
done

sa_build_fixture
FIX="$SA_WORK/zcode_science_fixture"
SEED_A=1111111111111111111111111111111111111111111111111111111111111111
SEED_B=2222222222222222222222222222222222222222222222222222222222222222
install -m 600 /dev/null "$SA_WORK/master-a.hex"
install -m 600 /dev/null "$SA_WORK/master-b.hex"
printf '%s\n' "$SEED_A" >"$SA_WORK/master-a.hex"
printf '%s\n' "$SEED_B" >"$SA_WORK/master-b.hex"
eval "$("$FIX" pubkey "$SEED_A")"; PUB_A="$PUBKEY"
eval "$("$FIX" pubkey "$SEED_B")"; PUB_B="$PUBKEY"
echo "science-acceptance: A{dd=$SA_DD_A p2p=$A_PORT rpc=$A_RPC} B{dd=$SA_DD_B p2p=$B_PORT rpc=$B_RPC}"

# ── [1] boot A and B on the loopback-only provisioning link ─────────
sa_step 1 "boot isolated pre-delegation A<->B link"
# Wallet custody: boot every node with a passphrase credential so key
# writes encrypt at rest (WKS1) — the ZID anchor's overlay-intent custody
# gate refuses a plaintext-at-rest wallet. The current-key encrypted
# backup itself happens after mining below, once the spend key exists.
SA_CRED_DIR="$SA_WORK/cred"
install -d -m 700 "$SA_CRED_DIR"
install -m 600 /dev/null "$SA_CRED_DIR/wallet-passphrase"
printf '%s\n' "$SA_WALLET_PASS" >"$SA_CRED_DIR/wallet-passphrase"
export CREDENTIALS_DIRECTORY="$SA_CRED_DIR"
SA_PGID_A="$(sa_spawn "$SA_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" "127.0.0.1:$DEAD_SINK" bootstrap)"
sa_wait_rpc "$SA_DD_A" "$A_RPC" "$SA_PGID_A" "$RPC_WARMUP" \
    || { tail -20 "$SA_DD_A/node.log" >&2; sa_die "A RPC never came up"; }
SA_PGID_B="$(sa_spawn "$SA_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$A_PORT" bootstrap)"
sa_wait_rpc "$SA_DD_B" "$B_RPC" "$SA_PGID_B" "$RPC_WARMUP" \
    || { tail -20 "$SA_DD_B/node.log" >&2; sa_die "B RPC never came up"; }
# Provision two independent, finality-delayed DHT delegations on the same
# isolated regtest chain. S7 publication must never fall back to an unsigned
# or process-local identity merely to make this harness convenient.
sa_step 1b "anchor two ZID masters and enable their Noise-bound DHT delegations"
ADDR="$(a_rpc getnewaddress | sa_result)"
sa_mine_to 101 "$ADDR"
sa_wait_height "$SA_DD_B" "$B_RPC" 101 || sa_die "B did not sync funding chain"
sa_wait_fold "$SA_DD_A" 101 || sa_die "A reducer fold did not reach the funding tip"

# The ZID anchor's overlay-intent custody gate requires the wallet
# encrypted at rest, unlocked, and covered by a current-key encrypted
# backup; its money gate requires A to hold an OUTBOUND peer with a live
# sync state (the money-freshness classifier fails closed on
# finding_peers, and the sync FSM only leaves it behind an outbound peer).
# Mirror the metaverse-tour recipe: bounce B onto the dead sink so the
# pair's only post-restart link is A's outbound onetry below (B's own
# redial-backoff was measured >60s — deterministic, no already-connected
# skip), then restart A so the forward-folded coins set stamps its
# authority (the coins_kv authority stamps land only at boot).
sa_kill_group "$SA_PGID_B"; SA_PGID_B=""
SA_PGID_B="$(sa_spawn "$SA_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$DEAD_SINK" bootstrap)"
sa_wait_rpc "$SA_DD_B" "$B_RPC" "$SA_PGID_B" "$RPC_WARMUP" || sa_die "B dead-sink bounce failed"
sa_kill_group "$SA_PGID_A"; SA_PGID_A=""
SA_PGID_A="$(sa_spawn "$SA_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" "127.0.0.1:$DEAD_SINK" bootstrap)"
sa_wait_rpc "$SA_DD_A" "$A_RPC" "$SA_PGID_A" "$RPC_WARMUP" || sa_die "A custody restart failed"
sa_wait_fold "$SA_DD_A" 101 || sa_die "A reducer fold did not survive the restart"
# Operator-directed onetry: bypasses the reachable-port policy and lands
# immediately — B is up, listening, and not connected to us.
a_rpc addnode "\"127.0.0.1:$B_PORT\"" "\"onetry\"" >/dev/null || true
sa_wait_connected "$SA_DD_A" "$A_RPC" || sa_die "A never connected outbound to B"
sa_wait_sync_live "$SA_DD_A" "$A_RPC" || sa_die "A sync never left finding_peers"
sa_wait_chain_loaded "$SA_DD_A" "$A_RPC" 101 || sa_die "A active chain index did not load"

# The restart re-locks the encrypted-at-rest wallet; the anchor's
# funding-input build draws from the key pool, which a locked wallet
# refuses. Unlock explicitly (passphrase via --input=- only), re-top the
# RAM-only keypool bookkeeping with one getnewaddress, then take the
# current-key encrypted backup the custody gate demands (AFTER the top-up,
# so the backup covers the key the anchor spends from).
sa_unlock_wallet "$SA_DD_A" || sa_die "A wallet unlock failed"
a_rpc getnewaddress | sa_result >/dev/null || sa_die "post-restart keypool top-up failed"
sa_backup_wallet "$SA_DD_A" || sa_die "A custody backup failed"
sa_wait_spendable "$SA_DD_A" || sa_die "A vault spendable never became positive"

out="$(sa_anchor "$SA_DD_A" "$PUB_A" "science-anchor-a")" || sa_die "A identity anchor failed"
[ "$(sa_jget "$out" data.status 2>/dev/null || true)" = "broadcast" ] || sa_die "A identity anchor was not broadcast: $out"
sa_mine_empty 1
sa_wait_height "$SA_DD_B" "$B_RPC" 102 || sa_die "B did not fold A's anchor block"
out="$(sa_anchor "$SA_DD_A" "$PUB_B" "science-anchor-b")" || sa_die "B identity anchor failed"
[ "$(sa_jget "$out" data.status 2>/dev/null || true)" = "broadcast" ] || sa_die "B identity anchor was not broadcast: $out"
sa_mine_empty 1
sa_wait_height "$SA_DD_B" "$B_RPC" 103 || sa_die "B did not fold its anchor block"
sa_mine_empty 22
sa_wait_height "$SA_DD_B" "$B_RPC" 125 || sa_die "B did not sync final beacon chain"
sa_wait_identity_active "$SA_DD_A" "$PUB_A" || sa_die "A master did not project ACTIVE"
sa_wait_identity_active "$SA_DD_B" "$PUB_B" || sa_die "B master did not project ACTIVE"
out="$(sa_sci "$SA_DD_A" zcode.network.delegate "{\"seed_file\":\"$SA_WORK/master-a.hex\"}")"
[ "$(sa_jget "$out" ok)" = "true" ] || sa_die "A DHT delegation failed: $out"
out="$(sa_sci "$SA_DD_B" zcode.network.delegate "{\"seed_file\":\"$SA_WORK/master-b.hex\"}")"
[ "$(sa_jget "$out" ok)" = "true" ] || sa_die "B DHT delegation failed: $out"

# Every discovery/content/execution action is locally denied by default.
# The proof opts each sovereign node into exactly the generic `science`
# service before the authenticated restart that loads the atomic policy.
for tuple in "$SA_DD_A:A" "$SA_DD_B:B"; do
    dd="${tuple%:*}"; label="${tuple##*:}"
    out="$(sa_sci "$dd" zcode.network.policy.mutate \
        '{"mode":"plan","operation":"add","source":"local","effect":"allow","scope":"service_type","action_mask":127,"value":"science"}')"
    [ "$(sa_jget "$out" ok)" = "true" ] || sa_die "$label science policy plan failed: $out"
    token="$(sa_jget "$out" data.plan_token)"
    out="$(sa_sci "$dd" zcode.network.policy.mutate \
        "{\"mode\":\"commit\",\"operation\":\"add\",\"source\":\"local\",\"effect\":\"allow\",\"scope\":\"service_type\",\"action_mask\":127,\"value\":\"science\",\"plan_token\":\"$token\"}")"
    [ "$(sa_jget "$out" ok)" = "true" ] || sa_die "$label science policy commit failed: $out"
done

# The isolated pre-delegation boot learns and persists v2 capability while the
# funding/anchor chain is prepared. Restart both nodes with their independent
# delegations before accepting any discovery frame or publishing any record.
sa_kill_group "$SA_PGID_B"; SA_PGID_B=""
sa_kill_group "$SA_PGID_A"; SA_PGID_A=""

sa_step 1c "seed package stores during the node-down hosting boundary"
eval "$("$FIX" seed-package "$SA_DD_A" 7)"
PKG_ROOT="$PACKAGE_ROOT"
[ "$COMPLETE" = "1" ] || sa_die "seeded package not tracked-complete on A"
echo "science-acceptance:     A serves package ${PKG_ROOT:0:16}… (tracked+complete)"
# B's swarm download record is persisted while no node owns the store; the
# live engine replays it at B's first package-hosting boot below.
out="$(sa_sci "$SA_DD_B" zcode.package.fetch "{\"root\":\"$PKG_ROOT\"}")"
[ "$(sa_jget "$out" ok)" = "true" ] || sa_die "B download-record seed failed: $out"
[ "$(sa_jget "$out" data.live)" = "false" ] \
    || sa_die "B one-shot fetch claimed a live engine"

SA_PGID_A="$(sa_spawn "$SA_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" "127.0.0.1:$DEAD_SINK")"
sa_wait_rpc "$SA_DD_A" "$A_RPC" "$SA_PGID_A" "$RPC_WARMUP" || sa_die "A authenticated restart failed"
SA_PGID_B="$(sa_spawn "$SA_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$A_PORT")"
sa_wait_rpc "$SA_DD_B" "$B_RPC" "$SA_PGID_B" "$RPC_WARMUP" || sa_die "B authenticated restart failed"
en_a=false; en_b=false; auth_a=0; auth_b=0; fr_a=0; fr_b=0
for _ in $(seq 1 180); do
    da="$(sa_sci "$SA_DD_A" zcode.network.status '{}')"
    db="$(sa_sci "$SA_DD_B" zcode.network.status '{}')"
    en_a="$(sa_jget "$da" data.enabled 2>/dev/null || true)"; en_a="${en_a:-false}"
    en_b="$(sa_jget "$db" data.enabled 2>/dev/null || true)"; en_b="${en_b:-false}"
    auth_a="$(sa_jget "$da" data.connected_authenticated 2>/dev/null || true)"; auth_a="${auth_a:-0}"
    auth_b="$(sa_jget "$db" data.connected_authenticated 2>/dev/null || true)"; auth_b="${auth_b:-0}"
    fr_a="$(sa_jget "$da" data.frames_accepted 2>/dev/null || true)"; fr_a="${fr_a:-0}"
    fr_b="$(sa_jget "$db" data.frames_accepted 2>/dev/null || true)"; fr_b="${fr_b:-0}"
    [ "$en_a" = "true" ] && [ "$en_b" = "true" ] &&
    [ "$auth_a" -ge 1 ] && [ "$auth_b" -ge 1 ] &&
    [ "$fr_a" -ge 1 ] && [ "$fr_b" -ge 1 ] && break
    sleep 0.5
done
[ "$en_a" = "true" ] || sa_die "A DHT did not enable"
[ "$en_b" = "true" ] || sa_die "B DHT did not enable"
[ "$auth_a" -ge 1 ] \
    || sa_die "A never authenticated B over DHT: A=$da B=$db"
[ "$auth_b" -ge 1 ] \
    || sa_die "B never authenticated A over DHT: A=$da B=$db"

# ── [2..6] A's science lifecycle ──────────────────────────────────────
sa_wait_topology || sa_die "authenticated A<->B topology did not settle"
pc_a="$(sa_peer_count "$SA_DD_A" "$A_RPC")"
pc_b="$(sa_peer_count "$SA_DD_B" "$B_RPC")"
[ "$pc_a" = "1" ] || sa_die "A peer count is $pc_a, expected exactly 1 (B)"
[ "$pc_b" = "1" ] || sa_die "B peer count is $pc_b, expected exactly 1 (A)"
echo "science-acceptance:     authenticated topology exactly A<->B (peers: A=$pc_a B=$pc_b; regtest, no DNS seeds, no GitHub, -nofilesync)"

sa_step "2-6" "A: preregister -> confined execute -> reproduce -> findings/review/vote -> discover"
run_lifecycle "$SA_DD_A" 11 "A"
A_STUDY="$L_STUDY"; A_RA="$L_RA"; A_PA="$L_PA"; A_V1="$L_V1"

# ── [7] B's independent lifecycle ─────────────────────────────────────
sa_step 7 "B: the same lifecycle independently (second clean node)"
run_lifecycle "$SA_DD_B" 29 "B"
B_STUDY="$L_STUDY"; B_RA="$L_RA"; B_PA="$L_PA"
[ "$B_STUDY" != "$A_STUDY" ] || sa_die "A and B minted the same study root"

# ── [8] No-automatic-carrier assertions: nothing crosses unpublished ──
sa_step 8 "no automatic carrier: A's science objects have not reached B"
[ "$("$FIX" cas-has "$SA_DD_B/zcode" "$A_STUDY" | grep -c 'PRESENT=0')" = "1" ] \
    || sa_die "A's study wire unexpectedly present in B's CAS"
[ "$("$FIX" cas-has "$SA_DD_B/zcode" "$A_RA" | grep -c 'PRESENT=0')" = "1" ] \
    || sa_die "A's result wire unexpectedly present in B's CAS"
out="$(sa_sci "$SA_DD_B" zcode.science.study.show "{\"study_root\":\"$A_STUDY\"}")"
[ "$(sa_jget "$out" data.found)" = "false" ] \
    || sa_die "B's projection unexpectedly knows A's study"
out="$(sa_sci "$SA_DD_B" zcode.science.work.execute \
    "{\"study_root\":\"$A_STUDY\",\"task_root\":\"$L_TASK\",\"candidate_root\":\"$L_CAND\",\"method_root\":\"$L_METHOD\",\"challenge_block_height\":3200000,\"challenge_block_hash\":\"$CH_HASH\",\"confirm\":true,\"now_unix\":$NOW_STUDY}")"
[ "$(sa_jget "$out" ok)" = "false" ] \
    || sa_die "B executed against A's study — distribution happened out of band?!"
case "$(sa_jget "$out" error.message)" in
    executor-study-not-in-cas*) : ;;
    *) sa_die "B's refusal named the wrong rule: $out" ;;
esac
echo "science-acceptance:     no automatic carrier confirmed: B refuses A's study with executor-study-not-in-cas; nothing crosses unpublished"

# ── [9] PACKAGE LEG: B's swarm fetch of A's package ───────────────────
sa_step 9 "package leg: poll B's store for the swarm fetch (budget ${PKG_WAIT}s)"
PKG_COMPLETE=0
deadline=$(( $(date +%s) + PKG_WAIT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    eval "$("$FIX" verify-package "$SA_DD_B" "$PKG_ROOT")"
    [ "$COMPLETE" = "1" ] && { PKG_COMPLETE=1; break; }
    sleep 3
done
if [ "$PKG_COMPLETE" = "1" ]; then
    [ "$ROOT_MATCH" = "1" ] && [ "$CHUNKS_OK" = "1" ] \
        || sa_die "B fetched bytes that do not re-derive the package root"
    echo "science-acceptance:     package leg PROVEN: B fetched $CHUNKS_CHECKED chunks node-to-node; rederived root == address"
else
    out="$(sa_sci "$SA_DD_B" zcode.package.fetch "{\"root\":\"$PKG_ROOT\"}")"
    dl_state="$(sa_jget "$out" data.download.state 2>/dev/null || true)"
    dl_ads="$(sa_jget "$out" data.download.advertisers 2>/dev/null || true)"
    dl_bytes="$(sa_jget "$out" data.download.present_bytes 2>/dev/null || true)"
    echo "science-acceptance:     G2 REGRESSION: fetch stalled (state=$dl_state advertisers=$dl_ads present_bytes=$dl_bytes)" >&2
    echo "science-acceptance:     the package leg is gated CLOSED (announce bootstrap quota + deduped" >&2
    echo "science-acceptance:     per-sync re-announce + supervisor clock-driven swarm) — a stall is a bug." >&2
    grep -am5 -i "zcode swarm\|announce" "$SA_DD_B/node.log" 2>/dev/null | sed 's/^/science-acceptance:       B log: /' >&2 || true
    sa_die "package leg stalled: G2 regressed"
fi

# ── [9b] G1 CARRIER, publish side: A mirrors its study into a blob ────
sa_step 9b "G1 carrier: A publishes its study as a swarm blob"
out="$(sa_sci "$SA_DD_A" zcode.science.publish "{\"root\":\"$A_STUDY\"}")"
[ "$(sa_jget "$out" ok)" = "true" ] || sa_die "A science publish failed: $out"
BLOB_ROOT="$(sa_jget "$out" data.blob_root)"
[ "$(sa_jget "$out" data.kind)" = "study" ] \
    || sa_die "publish reported the wrong kind: $out"
echo "science-acceptance:     A published study ${A_STUDY:0:16}… as blob ${BLOB_ROOT:0:16}… (one-shot store persist; A announces it from its next store open)"
# B starts from only the semantic science root. The signed POINTER is carried
# over the same authenticated DHT session; once admitted locally it resolves
# the transport root and schedules the download (one-shot persists it).
# the [10] restart lets A's store rescan announce the blob and B's live
# engine resume the record and pull it.
for _ in $(seq 1 20); do
    out="$(sa_sci "$SA_DD_B" zcode.science.fetch "{\"root\":\"$A_STUDY\",\"now_unix\":$NOW_STUDY}")"
    [ "$(sa_jget "$out" ok)" = "true" ] && break
    sleep 1
done
[ "$(sa_jget "$out" ok)" = "true" ] || sa_die "B root-only science discovery/fetch schedule failed: $out"
[ "$(sa_jget "$out" data.admitted)" = "false" ] \
    || sa_die "B admitted a blob it could not have downloaded yet"

# ── [10] restart both nodes (SIGTERM, cold boot, same datadirs) ───────
sa_step 10 "SIGTERM both nodes; cold boot same datadirs; topology re-forms"
sa_kill_group "$SA_PGID_A" TERM
sa_kill_group "$SA_PGID_B" TERM
SA_PGID_A=""; SA_PGID_B=""
sleep 1
SA_PGID_A="$(sa_spawn "$SA_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" "127.0.0.1:$DEAD_SINK")"
sa_wait_rpc "$SA_DD_A" "$A_RPC" "$SA_PGID_A" "$RPC_WARMUP" \
    || { tail -20 "$SA_DD_A/node.log" >&2; sa_die "A never came back after SIGTERM restart"; }
SA_PGID_B="$(sa_spawn "$SA_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$A_PORT")"
sa_wait_rpc "$SA_DD_B" "$B_RPC" "$SA_PGID_B" "$RPC_WARMUP" \
    || { tail -20 "$SA_DD_B/node.log" >&2; sa_die "B never came back after SIGTERM restart"; }
sleep 3
pc_a="$(sa_peer_count "$SA_DD_A" "$A_RPC")"
pc_b="$(sa_peer_count "$SA_DD_B" "$B_RPC")"
[ "$pc_a" = "1" ] && [ "$pc_b" = "1" ] \
    || sa_die "topology did not re-form after restart (A=$pc_a B=$pc_b)"
echo "science-acceptance:     both nodes cold-booted; topology A<->B restored"

# ── [10b] G1 CARRIER, receive side: B admits A's study from the blob ──
sa_step 10b "G1 carrier: poll B's admit of A's study (budget ${PKG_WAIT}s)"
ADMITTED=0
deadline=$(( $(date +%s) + PKG_WAIT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    out="$(sa_sci "$SA_DD_B" zcode.science.fetch "{\"root\":\"$A_STUDY\",\"now_unix\":$NOW_STUDY}")"
    [ "$(sa_jget "$out" ok)" = "true" ] \
        && [ "$(sa_jget "$out" data.admitted)" = "true" ] \
        && { ADMITTED=1; break; }
    sleep 3
done
[ "$ADMITTED" = "1" ] \
    || { echo "science-acceptance:     G1 REGRESSION: B never admitted A's study blob (last reply: $out)" >&2
         grep -am5 -i "zcode swarm\|blob" "$SA_DD_B/node.log" 2>/dev/null | sed 's/^/science-acceptance:       B log: /' >&2 || true
         sa_die "G1 carrier stalled"; }
[ "$(sa_jget "$out" data.science_root)" = "$A_STUDY" ] \
    || sa_die "B admitted the wrong science root: $out"
[ "$(sa_jget "$out" data.kind)" = "study" ] \
    || sa_die "B admitted the wrong kind: $out"
out="$(sa_sci "$SA_DD_B" zcode.science.study.show "{\"study_root\":\"$A_STUDY\"}")"
[ "$(sa_jget "$out" data.found)" = "true" ] \
    || sa_die "B study.show does not serve A's admitted study"
echo "science-acceptance:     G1 carrier PROVEN: A's study crossed node-to-node as blob ${BLOB_ROOT:0:16}…; B re-derived the science root from the bytes and projected it"

# ── [11] HEADLINE: reconstruct every object and receipt from hashes ────
sa_step 11 "rebuild-equivalence + SQL-wipe reconstruction on BOTH nodes"
rebuild_proof "$SA_DD_A" "A" "$A_STUDY" "$A_RA" "$A_PA"
rebuild_proof "$SA_DD_B" "B" "$B_STUDY" "$B_RA" "$B_PA"

# ── verdict ────────────────────────────────────────────────────────────
echo "science-acceptance: ─────────────────────────────────────────────"
echo "science-acceptance: NAMED GAPS (asserted, not worked around):"
echo "science-acceptance:   G1/S7 CLOSED (gated): B starts with only A's science root —"
echo "science-acceptance:       signed POINTER + PROVIDER over S6, then zcode.science.fetch"
echo "science-acceptance:       (swarm download → root re-derived from bytes → CAS + projection)."
echo "science-acceptance:       no out-of-band blob root; bytes still re-derive the semantic root before admission."
echo "science-acceptance:   G2 CLOSED (gated): fresh-node swarm fetch proven node-to-node —"
echo "science-acceptance:       NEW_USER bootstrap announce quota (4/h) + deduped per-sync re-announce"
echo "science-acceptance:       + supervisor clock-driven swarm (net.zcode_swarm, 1 s)"
echo "science-acceptance:   G3 rebuild had no operator surface — glued: zcode.science.rebuild leaf"
echo "science-acceptance:   G4 CLOSED (gated): findings admitted via zcode.science.findings.plan|commit"
echo "science-acceptance:       (fixture composes the wire, never touches CAS; review.submit binds"
echo "science-acceptance:       the CLI-admitted findings). Context objects stay fixture-seeded."
echo "science-acceptance: PASS"
exit 0
