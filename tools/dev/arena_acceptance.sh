# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# arena_acceptance.sh — the THREE-NODE physical proof for the zdogfight
# arena alpha: a fresh node pulls the exact published arena packages over
# the zpkgswm swarm from a second node, installs them through the confined
# build+test worker, builds its own pilot binaries, and then both nodes
# independently run the same arena match to BYTE-IDENTICAL replays and
# identical roots. Failure/alteration legs prove the evidence chain
# refuses tampering and that a killed build worker cannot change results.
#
# Template: tools/dev/science_acceptance.sh (same guard/cleanup
# discipline: live-port refuse-set + LISTEN probes, setsid process
# groups, datadir-scoped pkill, mktemp scratch datadirs under test-tmp/).
#
# Topology (three disjoint isolated regtest nodes, loopback only):
#
#   Node A (publisher): booted on a BYTE-EXACT cp -a of the quarantine
#       store pair member ~/.zclassic-c23-commons-arena-a (an ordinary
#       datadir whose zcode/ store holds the four published arena
#       packages, all installed). `z23 join` writes its hosting flags;
#       dead-sink -connect means A dials nobody real and only serves.
#   Node B (fresh node): empty mktemp datadir. Its four download records
#       are seeded ONE-SHOT while B is down (the fetch leaf persists a
#       resumable record under <dd>/zcode/downloads and reports
#       live:false — the exact science-acceptance pattern), then B boots
#       after `z23 join`, with -connect=127.0.0.1:$A_PORT; its swarm engine
#       resumes the records and pulls every chunk from A.
#   Node C (late replica): empty mktemp datadir joined through the public
#       command. After A stops it connects only to B and fetches one exact
#       package without DHT, identity, wallet transaction, block, or fee.
#
# MINIMAL BOOT, NO ZID IDENTITY — resolved empirically: the zpkgswm
# package swarm needs no DHT delegation or identity anchor between two
# scratch regtest nodes. The science script anchored identities because
# its proof covered S6/S7 DHT discovery; the package swarm announces to
# every known peer on the membership sweep (G2 fixes, see
# science_acceptance.sh) over the plain authenticated-transport P2P
# link. This script boots with plain sa_spawn-style flags and nothing
# else; if a future change makes the swarm refuse anonymous peers this
# script fails loudly at [2], which is the intended signal.
#
# What this script PROVES (each step asserts before proceeding):
#   [1] `z23 join` writes the hosting/worker flags into clean scratch
#       datadirs; daemons boot without either flag on their command lines.
#       A then serves all four arena packages (tracked+complete).
#   [2] B fetches zprng + zdogfight + zdogdrone + zdogace over the swarm
#       from A (per-package fetch seconds recorded), then installs each
#       through `zcode package add plan|commit` (confined build+test
#       worker, receipt-bound; per-package install seconds recorded).
#   [2b] A is stopped; a third clean joined node fetches exact inert bytes
#       from B alone, with no DHT, ZID, wallet transaction, block or fee.
#   [3] A and B each build BOTH pilot binaries from their own datadir
#       (verified `zcode package checkout` of the app source + the
#       installed static archives; -static is REQUIRED — the sandbox's
#       W^X denies the dynamic loader). Cross-node: the pilot binaries
#       and the installed archives are BYTE-IDENTICAL.
#   [4] challenge/accept: A writes the match definition (arena root,
#       pilot roots, seed 4242, 3v3, rules zdogfight-0.1.0) into the run
#       dir; B reads the same file (same-host alpha — the transport
#       under test is the package swarm, not this JSON). Both nodes
#       verify the roots against their own installed trees before
#       proceeding. NOT carried via
#       zcode.commons.reproduction.challenge.plan|commit: those leaves
#       take a pre-composed signed `request_hex` wire (schema
#       zcl.zcode_reproduction_challenge.input.v1: workspace,
#       request_hex, now_unix) with no shell-composable path — forcing
#       the match definition through them would need a fixture tool, not
#       "cheap" carriage. Documented, not forced, per the mission.
#   [5] both nodes run arena_runner independently (seed 4242, 3v3,
#       their own pilots), each writing its own replay.
#   [6] COMPARE: replays byte-identical (cmp); replay_root,
#       final_state_root, state_root_chain, winner, ticks all equal —
#       and equal to the independently proven M5 reference (the
#       published-pilot seed-4242 3v3 match is a 36000-tick 0:0 draw:
#       published zdogace 0.1.0 carries the known steering-sign quirk,
#       fixed in the unpublished 0.1.1; it is still exact and
#       deterministic, so nothing here is "fixed").
#   [7] ALTERATION: one byte flipped in a copy of B's replay ctl stream;
#       `arena_runner --verify-replay` exits 1 with a NAMED mismatch.
#       Control: the intact replay verifies ok with the same roots.
#   [8] WORKER FAILURE: a third scratch datadir (copy of B's fetched
#       store WITHOUT installed/) starts `add commit`, the confined
#       worker's process group is SIGKILLed mid-build, and the identical
#       retry runs to completion. The resulting archives are
#       byte-identical to B's and the rerun match reproduces the [6]
#       roots exactly: failure/retry cannot change the result.
#   [9] KPIs: runner ticks/sec (the 36000-tick published-pilot match, a
#       36000-tick dead-pilot pure-sim run, and the 11941-tick reference
#       match — seed 7, repo-source dev pilots carrying the unpublished
#       sign-fixed zdogace, asserted against the M3b reference roots),
#       replay bytes, pilot binary sizes, per-package fetch+install
#       seconds, total cross-node reproduction wall time.
#
# NAMED GAPS (asserted/documented, not worked around silently — a named
# gap is a deliverable, same convention as science_acceptance.sh):
#   G-A1  ANNOUNCE BOOTSTRAP QUOTA. A NEW_USER receiver flood-refuses the
#         5th+ announce within a one-hour window
#         (VCS_POLICY_FREE_ANNOUNCE_PER_HOUR=4,
#         VCS_SWARM_ANNOUNCE_WINDOW_TICKS=3600), and the sender's per-peer
#         dedupe never re-announces within the session — so a store
#         serving MORE than four complete packages cannot introduce the
#         excess roots to a fresh peer (4 offences << the 100-offence
#         disconnect threshold: the link survives, the extra roots are
#         simply never learned, and "zero advertisers is not a failure"
#         so the download honestly waits). Observed empirically on this
#         host 2026-08-16: the quarantine store carries 8 tracked
#         packages (4 arena + 4 stale); B completed exactly the two arena
#         packages whose announces fit the quota and stalled on the two
#         whose announces were refused. This script therefore prunes A's
#         SCRATCH COPY to exactly the four arena manifests before boot —
#         store recovery re-derives tracking from manifests/ and GCs the
#         unreferenced CAS chunks at open, so the prune is clean and the
#         live tree is untouched. A multi-package seeder serving a fresh
#         node needs a tier-earned quota or a per-root provider route
#         (S7 DHT territory); that is a real product gap this proof names
#         rather than papers over.
#   G-A2  RELEASE-ENVELOPE IMPORT IS DHT-GATED. The raw zpkgswm swarm
#         delivers the exact package CONTENT (manifest + CAS chunks,
#         re-derived against the root — B needs no identity for that, as
#         this run proves). But the carrier import that persists the
#         signed release envelope + recipe wires into releases/ and
#         recipes/ (vcs_package_transport_import) is only invoked from
#         the authenticated-DHT provider route
#         (boot_zcode_package_import_render via the zcode_dht_provider_route
#         RPC, namespace "zclassic23.package"), and `zcode package add
#         plan` resolves a root THROUGH that envelope
#         (pkgl_release_for_root over <dd>/zcode/releases). Without ZID
#         anchoring + DHT delegation there is no command path that fires
#         the import. Minimal in-script fix (same-host alpha): A hands the
#         four signed release envelopes + recipe wires to B over the same
#         out-of-band channel as the match definition (the exact bytes
#         from A's store; the envelope is self-verifying signed metadata
#         and the add commit's VERIFIED gate re-hashes every fetched CAS
#         chunk, so B trusts nothing about these files beyond their own
#         signatures and hashes). This mirrors science-acceptance G1: the
#         receiver learns the root/binding out of band; automatic
#         provider/root discovery is S7 DHT territory.
#
# SAFETY: three live production nodes share this host. This script never
# touches them: the live-port refuse-set is asserted for every port it
# uses, every port is probe-free before bind, datadirs are mktemp
# scratch under test-tmp/ only, cleanup is setsid group kills plus
# datadir-scoped pkill -f -- "-datadir=<scratch>" only, and the guarded
# rm -rf accepts only test-tmp/zcl23-arenaacc-* paths.
#
# Run: bash tools/dev/arena_acceptance.sh   (opt-in; spawns three real
# node processes and needs the host Landlock/seccomp confinement
# backend, same opt-in class as test-science-acceptance.)
#   ARENA_KEEP=1 preserves the scratch datadirs for inspection.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"
ARENA_BIN="${ZCL_ARENA_BIN:-$REPO_ROOT/build/bin/arena_runner}"
JSONQ="${JSONQ:-$REPO_ROOT/build/bin/jsonq}"

# ── CONFIG ────────────────────────────────────────────────────────────
# Exact published arena package roots (quarantine store pair member a).
ARENA_SOURCE_STORE="${ARENA_SOURCE_STORE:-$HOME/.zclassic-c23-commons-arena-a}"
ZPRNG_ROOT=91e9406a1016bcc224bb5e229377b1841e21c8ede1e0a00bc0d45d1989c41563
ZDOGFIGHT_ROOT=3ea608b29cdee1df15d560a930455faa264b3ac9ded8b557efc28e3e720ef40a
ZDOGDRONE_ROOT=10568ebc2876a6e3ecded390b012b0b8983613f3717949db1c9144ede2d78cf8
ZDOGACE_ROOT=ea4bda864dc08eb67afed16445469242d621eaec3da3beb9137b03ceddb68c07
# Dependency install/build order (target last).
PKG_ORDER="zprng zdogfight zdogdrone zdogace"

MATCH_SEED=4242
MATCH_PLANES=3
MATCH_RULES="zdogfight-0.1.0"
# The published-pilot seed-4242 3v3 match, proven on this host (M5
# reference): a full-length 36000-tick 0:0 draw (zdogace 0.1.0 steering
# quirk). These roots are the cross-check, not just cross-node equality.
M5_TICKS=36000
M5_WINNER=draw
M5_REPLAY_ROOT=681956eb17678dc9289fdff693825fd22282d086ef3bf8f0f3082e632bccb4c8
M5_FINAL_STATE_ROOT=f7c6ac02d6c251263756efe37583cb8f163db653c9938369012d6179b4fc1cbb
M5_STATE_ROOT_CHAIN=c39939a4e5e02bdeba9a0ed770263795981c373d886cbe3628eb719111bc6ce2
# The 11941-tick KPI reference: seed 7, 3v3, repo-source dev pilots with
# the UNPUBLISHED sign-fixed zdogace (packages/ tree, not the published
# package). M3b reference roots, proven byte-identical on this host.
REF_SEED=7
REF_TICKS=11941
REF_REPLAY_ROOT=05ed352dbb2213aad289cdf403d424d18d9ae075db57252a52c4e745a25e8396
REF_FINAL_STATE_ROOT=e4b37a9b94547cead91a7d4ae2a63b0385b29a99bb603bd0ac3519cebd270ebd
REF_STATE_ROOT_CHAIN=657cbc598e8cfff4e3a67e0b11de17a6b576be686ae924149614eca3e156f87b

# Ports. P2P uses the same explicit test-safe pair as science_acceptance
# (controlled reconnects pass the production reachable-port policy;
# arbitrary 39xxx P2P ports are valid only for the first
# operator-directed connect). RPC/FS/HTTPS ride the 39xxx isolation
# range. Every port is checked against the live refuse-set AND the
# LISTEN table before any bind.
A_PORT=20022; A_RPC=39211; A_FS=39212; A_HTTPS=39213
B_PORT=18033; B_RPC=39221; B_FS=39222; B_HTTPS=39223
C_PORT=20023; C_RPC=39231; C_FS=39232; C_HTTPS=39233
DEAD_SINK=39999
RPC_WARMUP="${RPC_WARMUP:-90}"     # per-node RPC warmup budget (s)
FETCH_BUDGET="${FETCH_BUDGET:-180}" # swarm fetch budget for all 4 pkgs (s)
KILL_WAIT=30                        # worker-kill leg: evidence window (s)

AA_LIVE_PORTS="8023 8033 8034 8035 8043 8044 8045 8046 8232 8443 \
18034 18232 18234 18243 18244 18245 18246"

AA_DD_A=""; AA_DD_B=""; AA_DD_C=""; AA_WORK=""
AA_PGID_A=""; AA_PGID_B=""; AA_PGID_C=""
AA_CLEANED=0
AA_KEEP="${ARENA_KEEP:-0}"
AA_STEP_START=$(date +%s)
AA_T0=$(date +%s%3N)

aa_die() {
    echo "arena-acceptance: FATAL: $*" >&2
    for dd in "$AA_DD_A" "$AA_DD_B" "$AA_DD_C"; do
        if [ -n "$dd" ] && [ -f "$dd/node.log" ]; then
            echo "arena-acceptance: last 30 lines of $dd/node.log:" >&2
            tail -30 "$dd/node.log" | sed 's/^/arena-acceptance:   /' >&2
        fi
    done
    exit 2
}
aa_step() {
    local now; now=$(date +%s)
    echo "arena-acceptance: [$1] (t+$((now - AA_STEP_START))s) $2"
    AA_STEP_START=$now
}
now_ms() { date +%s%3N; }

aa_assert_not_live_port() {
    local p="$1" lp
    for lp in $AA_LIVE_PORTS; do
        [ "$p" = "$lp" ] && aa_die "port $p is in the live refuse-set — refusing"
    done
    return 0
}
aa_assert_port_free() {
    local p="$1"
    if ss -tlnH "sport = :$p" 2>/dev/null | grep -q .; then
        aa_die "port $p is already LISTENING — refusing (operator port math is wrong)"
    fi
    return 0
}

aa_kill_group() {
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
aa_rm_dir() {
    local dd="$1"
    [ -n "$dd" ] && [ -d "$dd" ] || return 0
    case "$dd" in
        "$REPO_ROOT"/test-tmp/zcl23-arenaacc-*) rm -rf "$dd" 2>/dev/null || true ;;
        *) echo "arena-acceptance: WARN: refusing to rm non-scratch dir '$dd'" >&2 ;;
    esac
}
aa_cleanup() {
    [ "$AA_CLEANED" = "1" ] && return 0
    AA_CLEANED=1
    aa_kill_group "$AA_PGID_A"
    aa_kill_group "$AA_PGID_B"
    aa_kill_group "$AA_PGID_C" KILL
    [ -n "$AA_DD_A" ] && pkill -KILL -f -- "-datadir=$AA_DD_A" 2>/dev/null || true
    [ -n "$AA_DD_B" ] && pkill -KILL -f -- "-datadir=$AA_DD_B" 2>/dev/null || true
    [ -n "$AA_DD_C" ] && pkill -KILL -f -- "-datadir=$AA_DD_C" 2>/dev/null || true
    if [ "$AA_KEEP" = "1" ]; then
        echo "arena-acceptance: preserved A=$AA_DD_A B=$AA_DD_B C=$AA_DD_C work=$AA_WORK"
        return 0
    fi
    aa_rm_dir "$AA_DD_A"
    aa_rm_dir "$AA_DD_B"
    aa_rm_dir "$AA_DD_C"
    aa_rm_dir "$AA_WORK"
}

aa_rpc() { # $1=datadir $2=rpcport $3.. = method/args
    local dd="$1" rp="$2"; shift 2
    ZCL_DATADIR="$dd" ZCL_RPCPORT="$rp" "$RPC_BIN" "$@" 2>/dev/null || true
}
aa_result() { "$JSONQ" unwrap; }
# One-shot native leaf against a datadir whose node is DOWN (never open a
# store one-shot against a live datadir). JSON input rides stdin.
aa_leaf() { # $1=datadir $2=leaf  (stdin = input JSON)
    local dd="$1" leaf="$2"
    "$NODE_BIN" -datadir="$dd" "$leaf" --input=- 2>/dev/null | tail -1 || true
}
# Live-daemon query: dumpstate <subsystem> [key] via the cookie RPC.
aa_dump() { # $1=datadir $2=rpcport $3=subsystem [$4=key]
    local dd="$1" rp="$2" sub="$3" key="${4:-}"
    if [ -n "$key" ]; then
        "$NODE_BIN" -datadir="$dd" -rpcport="$rp" dumpstate "$sub" "$key" 2>/dev/null | tail -1 || true
    else
        "$NODE_BIN" -datadir="$dd" -rpcport="$rp" dumpstate "$sub" 2>/dev/null | tail -1 || true
    fi
}
aa_jget() { printf '%s' "$1" | "$JSONQ" get "$2"; }

aa_peer_count() { # $1=datadir $2=rpcport → integer peer count
    local n
    n="$(aa_rpc "$1" "$2" getpeerinfo | "$JSONQ" count result 2>/dev/null)" || n=-1
    printf '%s\n' "${n:--1}"
}
aa_wait_topology() { # wait for the one permitted A<->B peer on both sides
    local deadline pc_a pc_b
    deadline=$(( $(date +%s) + 60 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        pc_a="$(aa_peer_count "$AA_DD_A" "$A_RPC")"
        pc_b="$(aa_peer_count "$AA_DD_B" "$B_RPC")"
        [ "$pc_a" = "1" ] && [ "$pc_b" = "1" ] && return 0
        sleep 0.5
    done
    return 1
}
aa_wait_pair() { # $1=left-dd $2=left-rpc $3=right-dd $4=right-rpc
    local deadline left right
    deadline=$(( $(date +%s) + 60 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        left="$(aa_peer_count "$1" "$2")"
        right="$(aa_peer_count "$3" "$4")"
        [ "$left" -ge 1 ] 2>/dev/null && [ "$right" -ge 1 ] 2>/dev/null &&
            return 0
        sleep 0.5
    done
    return 1
}
aa_wait_rpc() { # $1=dd $2=rpc $3=pid $4=secs
    local dd="$1" rp="$2" pid="$3" secs="$4" deadline t
    deadline=$(( $(date +%s) + secs ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "arena-acceptance: node (pid $pid) exited during warmup (see $dd/node.log)" >&2
            return 1
        fi
        if [ -f "$dd/.cookie" ]; then
            t="$(aa_rpc "$dd" "$rp" getblockcount | tr -dc '0-9-')"
            [ -n "$t" ] && return 0
        fi
        sleep 0.5
    done
    return 1
}
aa_spawn() { # $1=datadir $2=p2p $3=rpc $4=fs $5=https $6=connect-target
    local dd="$1" p2p="$2" rpc="$3" fs="$4" https="$5" conn="$6"
    setsid "$NODE_BIN" \
        -datadir="$dd" -regtest \
        -port="$p2p" -rpcport="$rpc" -fsport="$fs" -httpsport="$https" \
        -connect="$conn" -nofilesync \
        -v2transport \
        -nobgvalidation -nolegacyimport -showmetrics=0 \
        >"$dd/node.log" 2>&1 &
    echo "$!"   # PID == PGID (setsid leader)
}

aa_join() { # $1=clean-or-scratch datadir
    local dd="$1" out config
    out="$(printf '%s' '{}' | aa_leaf "$dd" zcode.node.join)"
    [ "$(aa_jget "$out" ok 2>/dev/null || true)" = "true" ] ||
        aa_die "z23 join failed for $dd: $out"
    [ "$(aa_jget "$out" data.swarm_member 2>/dev/null || true)" = "true" ] ||
        aa_die "z23 join did not establish swarm membership: $out"
    config="$(aa_jget "$out" data.config_file 2>/dev/null || true)"
    [ "$config" = "$dd/z23.conf" ] && grep -qx 'packagehost=1' "$config" ||
        aa_die "z23 join did not write packagehost=1 to $dd/z23.conf"
    grep -qx 'buildworker=1' "$config" ||
        aa_die "z23 join did not admit the C23 compiler available to this harness"
}

# dumpstate zcode_store <root> on a LIVE node → "tracked complete" booleans.
aa_store_state() { # $1=datadir $2=rpcport $3=root → "true true" etc.
    local out tracked complete present total
    out="$(aa_dump "$1" "$2" zcode_store "$3")"
    tracked="$(printf '%s' "$out" | "$JSONQ" get state.tracked 2>/dev/null || true)"
    complete="$(printf '%s' "$out" | "$JSONQ" get state.complete 2>/dev/null || true)"
    present="$(printf '%s' "$out" | "$JSONQ" get state.present_chunks 2>/dev/null || true)"
    total="$(printf '%s' "$out" | "$JSONQ" get state.total_chunks 2>/dev/null || true)"
    printf '%s %s %s %s\n' "${tracked:-false}" "${complete:-false}" "${present:--1}" "${total:--1}"
}

# arena_runner output <file> → KEY=VALUE lines evaluated by the caller.
aa_run_match() { # $1=red $2=blue $3=seed $4=planes $5=replay-out $6=stdout-file
    "$ARENA_BIN" --seed "$3" --planes-per-team "$4" \
        --pilot-red "$1" --pilot-blue "$2" \
        --replay-out "$5" >"$6" 2>&1
}
# Fields ride space-separated key=value tokens, several per line
# (seed/planes/ticks share line 1). The .out files are <1 KiB — no
# pipefail/SIGPIPE hazard.
aa_match_field() { # $1=out file $2=key
    tr ' ' '\n' <"$1" | awk -v k="$2" 'index($0, k "=") == 1 { print substr($0, length(k) + 2); exit }'
}
# ── preflight ──────────────────────────────────────────────────────────
command -v ss      >/dev/null 2>&1 || aa_die "ss(8) not found (need iproute2)"
command -v mktemp  >/dev/null 2>&1 || aa_die "mktemp not found"
command -v cc      >/dev/null 2>&1 || aa_die "cc not found (pilot builds)"
command -v cmp     >/dev/null 2>&1 || aa_die "cmp not found"
[ -x "$JSONQ" ]     || aa_die "build/bin/jsonq is missing — run make jsonq"
[ -x "$NODE_BIN" ]  || aa_die "$NODE_BIN not built — run make first"
[ -x "$RPC_BIN" ]   || aa_die "$RPC_BIN not built — run make zcl-rpc"
[ -x "$ARENA_BIN" ] || aa_die "$ARENA_BIN not built — run make tools/arena-runner"
[ -d "$ARENA_SOURCE_STORE/zcode" ] \
    || aa_die "quarantine store $ARENA_SOURCE_STORE missing (need the published arena packages)"

for p in "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" \
         "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" \
         "$C_PORT" "$C_RPC" "$C_FS" "$C_HTTPS" "$DEAD_SINK"; do
    aa_assert_not_live_port "$p"
done

AA_DD_A="$(mktemp -d "$REPO_ROOT/test-tmp/zcl23-arenaacc-A-XXXXXX")" || aa_die "mktemp A failed"
AA_DD_B="$(mktemp -d "$REPO_ROOT/test-tmp/zcl23-arenaacc-B-XXXXXX")" || aa_die "mktemp B failed"
AA_DD_C="$(mktemp -d "$REPO_ROOT/test-tmp/zcl23-arenaacc-C-XXXXXX")" || aa_die "mktemp C failed"
AA_WORK="$(mktemp -d "$REPO_ROOT/test-tmp/zcl23-arenaacc-W-XXXXXX")" || aa_die "mktemp W failed"
for dd in "$AA_DD_A" "$AA_DD_B" "$AA_DD_C" "$AA_WORK"; do
    case "$dd" in "$REPO_ROOT"/test-tmp/zcl23-arenaacc-*) : ;; *) aa_die "bad scratch dir $dd" ;; esac
    if [ -n "${HOME:-}" ]; then
        case "$dd" in "$HOME"/.zclassic-c23*) aa_die "scratch dir under live tree — refusing" ;; esac
    fi
done

trap aa_cleanup EXIT INT TERM

for p in "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" \
         "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" \
         "$C_PORT" "$C_RPC" "$C_FS" "$C_HTTPS"; do
    aa_assert_port_free "$p"
done

root_of() { # $1=short package name → its published root
    case "$1" in
        zprng)     echo "$ZPRNG_ROOT" ;;
        zdogfight) echo "$ZDOGFIGHT_ROOT" ;;
        zdogdrone) echo "$ZDOGDRONE_ROOT" ;;
        zdogace)   echo "$ZDOGACE_ROOT" ;;
        *) aa_die "unknown package $1" ;;
    esac
}

echo "arena-acceptance: A{dd=$AA_DD_A p2p=$A_PORT rpc=$A_RPC} B{dd=$AA_DD_B p2p=$B_PORT rpc=$B_RPC}"
echo "arena-acceptance: C{dd=$AA_DD_C p2p=$C_PORT rpc=$C_RPC} work=$AA_WORK"

# B and C begin genuinely empty. The product command, not this harness's
# daemon argv, grants their package-host/build-worker posture.
[ "$(find "$AA_DD_B" -mindepth 1 -maxdepth 1 | wc -l)" -eq 0 ] ||
    aa_die "B datadir was not clean before join"
[ "$(find "$AA_DD_C" -mindepth 1 -maxdepth 1 | wc -l)" -eq 0 ] ||
    aa_die "C datadir was not clean before join"
aa_join "$AA_DD_B"
aa_join "$AA_DD_C"
echo "arena-acceptance:     clean B/C joined through z23.conf; daemon argv carries no packagehost/buildworker override"

# ── [1] byte-exact store copy; boot A; A serves all four ─────────────
aa_step 1 "copy quarantine store byte-exact; boot A (hosting, dead sink)"
cp -a "$ARENA_SOURCE_STORE/." "$AA_DD_A/" \
    || aa_die "cp -a of the quarantine store failed"
aa_join "$AA_DD_A"
# G-A1: prune A's scratch copy to exactly the four arena manifests, so A's
# announce set fits the receiver's NEW_USER bootstrap quota (4/hour).
# Recovery re-derives tracking from manifests/ and GCs unreferenced CAS
# chunks at open; the live quarantine store is never touched.
PRUNED=0
for f in "$AA_DD_A/zcode/manifests/"*; do
    [ -e "$f" ] || continue
    case " $ZPRNG_ROOT $ZDOGFIGHT_ROOT $ZDOGDRONE_ROOT $ZDOGACE_ROOT " in
        *" $(basename "$f") "*) : ;;
        *) rm -f "$f"; PRUNED=$((PRUNED + 1)) ;;
    esac
done
echo "arena-acceptance:     G-A1 prune: dropped $PRUNED non-arena manifests from A's scratch copy (announce set == the 4 arena roots)"
# Sanity: the copy carries the four packages, all installed.
for name in $PKG_ORDER; do
    root="$(root_of "$name")"
    [ -f "$AA_DD_A/zcode/installed/$root/build-report" ] \
        || aa_die "A copy lacks installed build-report for $name ($root)"
    [ -f "$AA_DD_A/zcode/installed/$root/lib/lib$name.a" ] \
        || aa_die "A copy lacks installed archive for $name"
done
echo "arena-acceptance:     store copy carries all four packages, installed, byte-exact"

AA_PGID_A="$(aa_spawn "$AA_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" "127.0.0.1:$DEAD_SINK")"
aa_wait_rpc "$AA_DD_A" "$A_RPC" "$AA_PGID_A" "$RPC_WARMUP" \
    || aa_die "A RPC never came up"
for name in $PKG_ORDER; do
    root="$(root_of "$name")"
    set -- $(aa_store_state "$AA_DD_A" "$A_RPC" "$root")
    [ "${1:-false}" = "true" ] && [ "${2:-false}" = "true" ] \
        || aa_die "A does not serve $name (tracked=${1:-?} complete=${2:-?})"
done
a_tracked="$(aa_dump "$AA_DD_A" "$A_RPC" zcode_store | "$JSONQ" get state.tracked_packages 2>/dev/null || true)"
a_tracked="${a_tracked:--1}"
[ "$a_tracked" = "4" ] \
    || aa_die "A announces $a_tracked packages, not exactly 4 — G-A1 prune incomplete (would overflow B's NEW_USER announce quota)"
echo "arena-acceptance:     A live store: exactly 4 packages tracked+complete (serving; announce set fits B's bootstrap quota)"

# ── [2] B: seed fetch records one-shot, boot hosting, swarm pull ─────
aa_step 2 "B: seed 4 download records one-shot, boot hosting, swarm fetch from A"
for name in $PKG_ORDER; do
    root="$(root_of "$name")"
    out="$(printf '%s' "{\"root\":\"$root\",\"maximum_bytes\":268435456}" \
        | aa_leaf "$AA_DD_B" zcode.package.fetch)"
    [ "$(aa_jget "$out" ok 2>/dev/null || true)" = "true" ] \
        || aa_die "B fetch-record seed for $name refused: $out"
    live="$(aa_jget "$out" data.live 2>/dev/null || true)"; live="${live:-true}"
    [ "$live" = "false" ] \
        || aa_die "B fetch-record seed for $name claimed a live engine: $out"
done
echo "arena-acceptance:     4 resumable download records persisted under B's zcode/downloads (live:false, node down)"

T_FETCH_START=$(now_ms)
AA_PGID_B="$(aa_spawn "$AA_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$A_PORT")"
aa_wait_rpc "$AA_DD_B" "$B_RPC" "$AA_PGID_B" "$RPC_WARMUP" \
    || aa_die "B RPC never came up"
aa_wait_topology || aa_die "A<->B topology did not settle"
echo "arena-acceptance:     topology exactly A<->B (regtest, no DNS seeds, -nofilesync)"

# Poll B's LIVE store (dumpstate is answered by the daemon; no one-shot
# store open against a live datadir) until every root is complete. All
# four are re-checked each pass, so completion order never misattributes
# per-package times.
FETCH_DEADLINE=$(( $(date +%s) + FETCH_BUDGET ))
declare -A FETCH_SECS=()
remaining="$PKG_ORDER"
while [ -n "$remaining" ] && [ "$(date +%s)" -lt "$FETCH_DEADLINE" ]; do
    next=""
    for name in $remaining; do
        root="$(root_of "$name")"
        set -- $(aa_store_state "$AA_DD_B" "$B_RPC" "$root")
        if [ "${1:-false}" = "true" ] && [ "${2:-false}" = "true" ]; then
            FETCH_SECS[$name]=$(( $(now_ms) - T_FETCH_START ))
            echo "arena-acceptance:     B fetched $name over the swarm: complete at +$(( FETCH_SECS[$name] / 1000 )).$(( FETCH_SECS[$name] % 1000 ))s"
        else
            next="$next $name"
        fi
    done
    remaining="${next# }"
    [ -n "$remaining" ] && sleep 1
done
if [ -n "$remaining" ]; then
    echo "arena-acceptance:     stall detail (tracked complete present/total chunks):" >&2
    for name in $remaining; do
        echo "arena-acceptance:       $name: $(aa_store_state "$AA_DD_B" "$B_RPC" "$(root_of "$name")")" >&2
    done
    grep -m8 -i "swarm\|announce\|download" "$AA_DD_B/node.log" 2>/dev/null \
        | sed 's/^/arena-acceptance:       B log: /' >&2 || true
    grep -m8 -i "swarm\|announce" "$AA_DD_A/node.log" 2>/dev/null \
        | sed 's/^/arena-acceptance:       A log: /' >&2 || true
    aa_die "B swarm fetch stalled past ${FETCH_BUDGET}s: $remaining"
fi
T_FETCH_DONE=$(now_ms)

# ── [2b] the no-coin onboarding claim, over real daemons ─────────────
# B has only verified package bytes from A. Stop A completely, then let a
# clean `z23 join`-configured C fetch one exact root from B. No DHT discovery
# is involved: the ordinary NODE_ZCL23 inventory announces the root.
aa_step 2b "publisher down; clean joined C fetches exact inert bytes from replica B"
[ ! -e "$AA_DD_B/zcode/installed" ] ||
    aa_die "B built or installed fetched source before explicit admission"
aa_kill_group "$AA_PGID_A"; AA_PGID_A=""
sleep 1

out="$(printf '%s' "{\"root\":\"$ZPRNG_ROOT\",\"maximum_bytes\":268435456}" \
    | aa_leaf "$AA_DD_C" zcode.package.fetch)"
[ "$(aa_jget "$out" ok 2>/dev/null || true)" = "true" ] ||
    aa_die "C no-coin fetch-record seed refused: $out"
[ "$(aa_jget "$out" data.live 2>/dev/null || true)" = "false" ] ||
    aa_die "C down-node fetch seed claimed a live engine: $out"

AA_PGID_C="$(aa_spawn "$AA_DD_C" "$C_PORT" "$C_RPC" "$C_FS" \
    "$C_HTTPS" "127.0.0.1:$B_PORT")"
aa_wait_rpc "$AA_DD_C" "$C_RPC" "$AA_PGID_C" "$RPC_WARMUP" ||
    aa_die "C RPC never came up after z23 join"
aa_wait_pair "$AA_DD_B" "$B_RPC" "$AA_DD_C" "$C_RPC" ||
    aa_die "B<->C ordinary P2P topology did not settle after A stopped"

deadline=$(( $(date +%s) + FETCH_BUDGET ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    set -- $(aa_store_state "$AA_DD_C" "$C_RPC" "$ZPRNG_ROOT")
    [ "${1:-false}" = "true" ] && [ "${2:-false}" = "true" ] && break
    sleep 1
done
set -- $(aa_store_state "$AA_DD_C" "$C_RPC" "$ZPRNG_ROOT")
[ "${1:-false}" = "true" ] && [ "${2:-false}" = "true" ] ||
    aa_die "C did not fetch zprng from replica B after publisher A stopped"
[ ! -e "$AA_DD_C/zcode/installed" ] ||
    aa_die "C's fetched bytes gained build/install authority"

cmp -s "$AA_DD_B/zcode/manifests/$ZPRNG_ROOT" \
    "$AA_DD_C/zcode/manifests/$ZPRNG_ROOT" ||
    aa_die "C's relayed manifest is not byte-identical to B's verified root"
for node in "B:$AA_DD_B:$B_RPC" "C:$AA_DD_C:$C_RPC"; do
    label="${node%%:*}"; rest="${node#*:}"; dd="${rest%:*}"; rpc="${rest##*:}"
    [ "$(aa_rpc "$dd" "$rpc" getblockcount | aa_result)" = "0" ] ||
        aa_die "$label wrote a chain block during no-coin onboarding"
    [ "$(aa_rpc "$dd" "$rpc" getrawmempool | "$JSONQ" count result 2>/dev/null)" = "0" ] ||
        aa_die "$label created or relayed a fee transaction"
    [ "$(aa_rpc "$dd" "$rpc" listtransactions | "$JSONQ" count result 2>/dev/null)" = "0" ] ||
        aa_die "$label wrote a wallet transaction during no-coin onboarding"
    dht_enabled="$(aa_dump "$dd" "$rpc" zcode_dht | \
        "$JSONQ" get state.enabled 2>/dev/null || true)"
    [ "$dht_enabled" = "false" ] ||
        aa_die "$label unexpectedly enabled the ZID-gated DHT: $dht_enabled"
done
echo "arena-acceptance:     PASS join config -> ordinary inventory -> replica fetch; A down, exact bytes inert, height=0, mempool=0, DHT=false"
aa_kill_group "$AA_PGID_C"; AA_PGID_C=""
sleep 1

# Nodes down: every further store operation is one-shot per datadir, never
# racing a live daemon.
aa_kill_group "$AA_PGID_B"; AA_PGID_B=""
aa_kill_group "$AA_PGID_A"; AA_PGID_A=""
sleep 1
echo "arena-acceptance:     both nodes SIGTERM'd after the swarm leg; installs are one-shot, node down"

# The swarm delivered exact content: assert B persisted each manifest and
# the tracked chunk sets are complete on disk.
for name in $PKG_ORDER; do
    root="$(root_of "$name")"
    [ -f "$AA_DD_B/zcode/manifests/$root" ] \
        || aa_die "B fetched $name but manifests/$root is missing"
done
# G-A2: hand B the signed release envelopes + recipe wires out of band
# (the DHT-gated carrier import is the only in-node path; see the header).
install -d -m 700 "$AA_DD_B/zcode/releases" "$AA_DD_B/zcode/recipes"
cp -a "$AA_DD_A/zcode/releases/." "$AA_DD_B/zcode/releases/" \
    || aa_die "G-A2 release-envelope handoff failed"
cp -a "$AA_DD_A/zcode/recipes/." "$AA_DD_B/zcode/recipes/" \
    || aa_die "G-A2 recipe-wire handoff failed"
echo "arena-acceptance:     G-A2 handoff: signed release envelopes + recipe wires A->B out of band (swarm carried the content; the import path is DHT-gated)"

# B installs each package through the confined build+test worker.
declare -A INSTALL_SECS=()
declare -A RECEIPT=()
for name in $PKG_ORDER; do
    root="$(root_of "$name")"
    t0=$(now_ms)
    out="$(printf '%s' "{\"name_or_root\":\"$root\"}" | aa_leaf "$AA_DD_B" zcode.package.add.plan)"
    [ "$(aa_jget "$out" ok 2>/dev/null || true)" = "true" ] \
        || aa_die "B add plan for $name refused: $out"
    plan_id="$(aa_jget "$out" data.plan_id 2>/dev/null)" \
        || aa_die "B add plan for $name returned no plan_id: $out"
    out="$(printf '%s' "{\"plan_id\":\"$plan_id\"}" | aa_leaf "$AA_DD_B" zcode.package.add.commit)"
    [ "$(aa_jget "$out" ok 2>/dev/null || true)" = "true" ] \
        || aa_die "B add commit for $name refused: $out"
    [ "$(aa_jget "$out" data.installed 2>/dev/null || true)" = "true" ] \
        || aa_die "B add commit for $name did not install: $out"
    [ "$(aa_jget "$out" data.active_root 2>/dev/null || true)" = "$root" ] \
        || aa_die "B add commit for $name activated the wrong root: $out"
    INSTALL_SECS[$name]=$(( $(now_ms) - t0 ))
    n_steps="$(printf '%s' "$out" | "$JSONQ" count data.steps 2>/dev/null || true)"
    n_steps="${n_steps:-0}"
    RECEIPT[$name]=""
    i=0
    while [ "$i" -lt "$n_steps" ]; do
        sroot="$(printf '%s' "$out" | "$JSONQ" get "data.steps[$i].root" 2>/dev/null || true)"
        if [ "$sroot" = "$root" ]; then
            RECEIPT[$name]="$(printf '%s' "$out" | "$JSONQ" get "data.steps[$i].build_receipt_id" 2>/dev/null || true)"
            break
        fi
        i=$((i + 1))
    done
    [ -f "$AA_DD_B/zcode/installed/$root/build-report" ] \
        || aa_die "B installed $name but the build-report is missing"
    [ -f "$AA_DD_B/zcode/installed/$root/lib/lib$name.a" ] \
        || aa_die "B installed $name but lib$name.a is missing"
    echo "arena-acceptance:     B installed $name via confined worker in $(( INSTALL_SECS[$name] / 1000 )).$(( INSTALL_SECS[$name] % 1000 ))s (receipt ${RECEIPT[$name]:0:16}…)"
done
T_INSTALL_DONE=$(now_ms)

# A runs the same lifecycle against its byte-exact copy: every step must
# report already-installed (the publisher side installed at publish time).
for name in $PKG_ORDER; do
    root="$(root_of "$name")"
    out="$(printf '%s' "{\"name_or_root\":\"$root\"}" | aa_leaf "$AA_DD_A" zcode.package.add.plan)"
    [ "$(aa_jget "$out" ok 2>/dev/null || true)" = "true" ] \
        || aa_die "A add plan for $name refused: $out"
    plan_id="$(aa_jget "$out" data.plan_id)"
    out="$(printf '%s' "{\"plan_id\":\"$plan_id\"}" | aa_leaf "$AA_DD_A" zcode.package.add.commit)"
    [ "$(aa_jget "$out" ok 2>/dev/null || true)" = "true" ] \
        || aa_die "A add commit for $name refused: $out"
    [ "$(aa_jget "$out" data.active_root 2>/dev/null || true)" = "$root" ] \
        || aa_die "A add commit for $name activated the wrong root: $out"
done
echo "arena-acceptance:     A lifecycle re-check: all four already installed, correct active roots"

# ── [3] both nodes build both pilots independently ────────────────────
aa_step 3 "checkout + pilot builds on both nodes; cross-node byte equality"
build_pilot() { # $1=datadir $2=pilot pkg name $3=checkout dest $4=out binary
    local dd="$1" pkg="$2" dest="$3" out="$4"
    local pkg_root fight_root prng_root
    pkg_root="$(root_of "$pkg")"; fight_root="$ZDOGFIGHT_ROOT"; prng_root="$ZPRNG_ROOT"
    # The checkout refuses unless the destination's PARENT already exists
    # (and the destination itself does not).
    mkdir -p "$(dirname "$dest")"
    local reply
    reply="$(printf '%s' "{\"root\":\"$pkg_root\",\"destination\":\"$dest\",\"datadir\":\"$dd\"}" \
        | aa_leaf "$dd" zcode.package.checkout)"
    [ "$(aa_jget "$reply" ok 2>/dev/null || true)" = "true" ] \
        || aa_die "$dd checkout of $pkg refused: $reply"
    [ -f "$dest/app/main.c" ] || aa_die "$dd checkout of $pkg lacks app/main.c"
    cc -std=c23 -O1 -static -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L \
        -I "$dd/zcode/installed/$pkg_root/include" \
        -I "$dd/zcode/installed/$fight_root/include" \
        -I "$dd/zcode/installed/$prng_root/include" \
        "$dest/app/main.c" \
        "$dd/zcode/installed/$pkg_root/lib/lib$pkg.a" \
        "$dd/zcode/installed/$fight_root/lib/libzdogfight.a" \
        "$dd/zcode/installed/$prng_root/lib/libzprng.a" \
        -o "$out" || aa_die "$dd pilot build for $pkg failed"
    [ -x "$out" ] || aa_die "$dd pilot build for $pkg produced no binary"
}
build_pilot "$AA_DD_A" zdogace   "$AA_WORK/checkout-A/zdogace"   "$AA_WORK/pilot-A-red"
build_pilot "$AA_DD_A" zdogdrone "$AA_WORK/checkout-A/zdogdrone" "$AA_WORK/pilot-A-blue"
build_pilot "$AA_DD_B" zdogace   "$AA_WORK/checkout-B/zdogace"   "$AA_WORK/pilot-B-red"
build_pilot "$AA_DD_B" zdogdrone "$AA_WORK/checkout-B/zdogdrone" "$AA_WORK/pilot-B-blue"
echo "arena-acceptance:     pilots built: A(red=zdogace blue=zdogdrone) B(red=zdogace blue=zdogdrone), static, from each node's own datadir"

cmp "$AA_WORK/pilot-A-red"  "$AA_WORK/pilot-B-red"  \
    || aa_die "RED: A's and B's zdogace pilot binaries differ — build not reproduced"
cmp "$AA_WORK/pilot-A-blue" "$AA_WORK/pilot-B-blue" \
    || aa_die "RED: A's and B's zdogdrone pilot binaries differ — build not reproduced"
for name in $PKG_ORDER; do
    root="$(root_of "$name")"
    cmp "$AA_DD_A/zcode/installed/$root/lib/lib$name.a" \
        "$AA_DD_B/zcode/installed/$root/lib/lib$name.a" \
        || aa_die "RED: installed lib$name.a differs between A and B"
done
echo "arena-acceptance:     cross-node reproduction: pilot binaries AND all four installed archives byte-identical"

# ── [4] match definition: A writes, B reads, both verify ─────────────
aa_step 4 "match definition (A writes, B reads; both verify installed roots)"
MATCH_DEF="$AA_WORK/match-definition.json"
cat >"$MATCH_DEF" <<EOF
{"arena_root":"$ZDOGFIGHT_ROOT","pilot_red_root":"$ZDOGACE_ROOT","pilot_blue_root":"$ZDOGDRONE_ROOT","seed":$MATCH_SEED,"planes_per_team":$MATCH_PLANES,"rules":"$MATCH_RULES"}
EOF
verify_match_def() { # $1=datadir $2=label
    local dd="$1"
    [ "$("$JSONQ" get arena_root <"$MATCH_DEF")" = "$ZDOGFIGHT_ROOT" ] || return 1
    [ "$("$JSONQ" get pilot_red_root <"$MATCH_DEF")" = "$ZDOGACE_ROOT" ] || return 1
    [ "$("$JSONQ" get pilot_blue_root <"$MATCH_DEF")" = "$ZDOGDRONE_ROOT" ] || return 1
    [ "$("$JSONQ" get seed <"$MATCH_DEF")" = "$MATCH_SEED" ] || return 1
    [ "$("$JSONQ" get planes_per_team <"$MATCH_DEF")" = "$MATCH_PLANES" ] || return 1
    [ "$("$JSONQ" get rules <"$MATCH_DEF")" = "$MATCH_RULES" ] || return 1
    [ -f "$dd/zcode/installed/$ZDOGFIGHT_ROOT/build-report" ] || return 1
    [ -f "$dd/zcode/installed/$ZDOGACE_ROOT/build-report" ] || return 1
    [ -f "$dd/zcode/installed/$ZDOGDRONE_ROOT/build-report" ] || return 1
    return 0
}
verify_match_def "$AA_DD_A" A || aa_die "A cannot stand behind the match definition roots"
verify_match_def "$AA_DD_B" B || aa_die "B cannot stand behind the match definition roots"
echo "arena-acceptance:     match definition committed to run dir; both nodes verified all three roots against their own installed trees"

# ── [5] both nodes run the match independently ────────────────────────
aa_step 5 "arena_runner on both nodes (seed $MATCH_SEED, ${MATCH_PLANES}v${MATCH_PLANES}, own pilots)"
T_MATCH_A_0=$(now_ms)
aa_run_match "$AA_WORK/pilot-A-red" "$AA_WORK/pilot-A-blue" "$MATCH_SEED" "$MATCH_PLANES" \
    "$AA_WORK/replay-A.bin" "$AA_WORK/match-A.out" \
    || { cat "$AA_WORK/match-A.out" >&2; aa_die "A arena_runner failed"; }
T_MATCH_A_1=$(now_ms)
aa_run_match "$AA_WORK/pilot-B-red" "$AA_WORK/pilot-B-blue" "$MATCH_SEED" "$MATCH_PLANES" \
    "$AA_WORK/replay-B.bin" "$AA_WORK/match-B.out" \
    || { cat "$AA_WORK/match-B.out" >&2; aa_die "B arena_runner failed"; }
T_MATCH_B_1=$(now_ms)
echo "arena-acceptance:     A match: $(grep -o 'ticks=[^ ]*' "$AA_WORK/match-A.out") $(grep -o 'winner=[^ ]*' "$AA_WORK/match-A.out") in $(( (T_MATCH_A_1 - T_MATCH_A_0) ))ms"
echo "arena-acceptance:     B match: $(grep -o 'ticks=[^ ]*' "$AA_WORK/match-B.out") $(grep -o 'winner=[^ ]*' "$AA_WORK/match-B.out")"

# ── [6] COMPARE: the core invariant ───────────────────────────────────
aa_step 6 "COMPARE: replays byte-identical; roots equal; equal to the M5 reference"
if ! cmp "$AA_WORK/replay-A.bin" "$AA_WORK/replay-B.bin"; then
    echo "arena-acceptance: RED: replay divergence (cmp above)" >&2
    aa_die "RED: A and B produced different replays — cross-node reproduction FAILED"
fi
for f in replay_root final_state_root state_root_chain winner ticks score_red score_blue; do
    va="$(aa_match_field "$AA_WORK/match-A.out" "$f")"
    vb="$(aa_match_field "$AA_WORK/match-B.out" "$f")"
    [ "$va" = "$vb" ] || aa_die "RED: match field $f diverged: A=$va B=$vb"
done
M_TICKS="$(aa_match_field "$AA_WORK/match-A.out" ticks)"
M_REPLAY_ROOT="$(aa_match_field "$AA_WORK/match-A.out" replay_root)"
M_FINAL="$(aa_match_field "$AA_WORK/match-A.out" final_state_root)"
M_CHAIN="$(aa_match_field "$AA_WORK/match-A.out" state_root_chain)"
M_WINNER="$(aa_match_field "$AA_WORK/match-A.out" winner)"
[ "$M_TICKS" = "$M5_TICKS" ] && [ "$M_WINNER" = "$M5_WINNER" ] \
    || aa_die "RED: match drifted from the proven reference: ticks=$M_TICKS winner=$M_WINNER (want $M5_TICKS/$M5_WINNER)"
[ "$M_REPLAY_ROOT" = "$M5_REPLAY_ROOT" ] \
    || aa_die "RED: replay_root $M_REPLAY_ROOT != M5 reference $M5_REPLAY_ROOT"
[ "$M_FINAL" = "$M5_FINAL_STATE_ROOT" ] \
    || aa_die "RED: final_state_root drifted from the M5 reference"
[ "$M_CHAIN" = "$M5_STATE_ROOT_CHAIN" ] \
    || aa_die "RED: state_root_chain drifted from the M5 reference"
echo "arena-acceptance:     CORE INVARIANT PROVEN: byte-identical replays; replay_root=$M_REPLAY_ROOT"
echo "arena-acceptance:       final_state_root=$M_FINAL state_root_chain=$M_CHAIN winner=$M_WINNER ticks=$M_TICKS (== M5 reference)"

# ── [7] ALTERATION: one flipped byte must be named ────────────────────
aa_step 7 "alteration leg: flip one ctl byte in a copy of B's replay"
cp "$AA_WORK/replay-B.bin" "$AA_WORK/replay-B-altered.bin"
f="$AA_WORK/replay-B-altered.bin"
off=$((21 + 7 * 13 + 3))          # inside the 14th ctl frame
b=$(od -An -tu1 -N1 -j "$off" "$f" | tr -d ' \n')
[ -n "$b" ] || aa_die "alteration: could not read byte at offset $off"
nb=$((b ^ 1))
printf "\\$(printf '%03o' "$nb")" | dd of="$f" bs=1 seek="$off" conv=notrunc status=none
echo "arena-acceptance:     flipped byte at offset $off (ctl stream)"
set +e
verr="$("$ARENA_BIN" --verify-replay "$AA_WORK/replay-B-altered.bin" 2>&1)"
vrc=$?
set -e
[ "$vrc" = "1" ] || aa_die "altered replay verify exited $vrc, want 1: $verr"
case "$verr" in
    *"verify=MISMATCH "*) : ;;
    *) aa_die "altered replay refused without a NAMED mismatch: $verr" ;;
esac
echo "arena-acceptance:     altered replay refused: $(echo "$verr" | grep -o 'verify=MISMATCH [a-z-]*')"
vok="$("$ARENA_BIN" --verify-replay "$AA_WORK/replay-A.bin" 2>&1)" \
    || aa_die "intact replay failed verify: $vok"
case "$vok" in *"verify=ok"*) : ;; *) aa_die "intact replay verify not ok: $vok" ;; esac
[ "$(echo "$vok" | grep -o '^replay_root=[^ ]*' | cut -d= -f2)" = "$M_REPLAY_ROOT" ] \
    || aa_die "verify-replay recomputed a different replay_root"
echo "arena-acceptance:     control: intact replay verifies ok, recomputed roots match"

# ── [8] WORKER FAILURE: kill mid-build, retry, same result ───────────
aa_step 8 "worker-failure leg: SIGKILL the confined worker mid-build on C, retry, same roots"
# C starts from B's fetched store with the installed/ tree AND the filed
# build receipts/plans REMOVED, so the add commit genuinely rebuilds
# (zprng -> zdogfight -> zdogdrone) instead of reusing a receipt.
rm -rf "$AA_DD_C/zcode"
cp -a "$AA_DD_B/zcode" "$AA_DD_C/zcode" || aa_die "C store copy failed"
rm -rf "$AA_DD_C/zcode/installed" "$AA_DD_C/zcode/buildwork" \
       "$AA_DD_C/zcode/staging" "$AA_DD_C/zcode/receipts" \
       "$AA_DD_C/zcode/addplans"
out="$(printf '%s' "{\"name_or_root\":\"$ZDOGDRONE_ROOT\"}" | aa_leaf "$AA_DD_C" zcode.package.add.plan)"
[ "$(aa_jget "$out" ok 2>/dev/null || true)" = "true" ] \
    || aa_die "C add plan refused: $out"
C_PLAN="$(aa_jget "$out" data.plan_id)"
printf '%s' "{\"plan_id\":\"$C_PLAN\"}" > "$AA_WORK/c-commit-input.json"
setsid "$NODE_BIN" -datadir="$AA_DD_C" zcode.package.add.commit --input=- \
    <"$AA_WORK/c-commit-input.json" >"$AA_WORK/c-commit-1.out" 2>&1 &
AA_PGID_C=$!
# Kill as soon as the confined build shows on disk (bounded window).
kill_evidence=""
deadline=$(( $(date +%s) + KILL_WAIT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! kill -0 "$AA_PGID_C" 2>/dev/null; then
        break
    fi
    if [ -n "$(find "$AA_DD_C/zcode/buildwork" "$AA_DD_C/zcode/staging" -type f 2>/dev/null | head -1)" ]; then
        kill_evidence="buildwork/staging"
        break
    fi
    sleep 0.05
done
if [ -n "$kill_evidence" ]; then
    kill -KILL "-$AA_PGID_C" 2>/dev/null || true
    sleep 0.3
    pkill -KILL -f -- "-datadir=$AA_DD_C" 2>/dev/null || true
    wait "$AA_PGID_C" 2>/dev/null || true
    echo "arena-acceptance:     SIGKILLed the add-commit process group mid-build (evidence: $kill_evidence)"
else
    wait "$AA_PGID_C" 2>/dev/null || true
    aa_die "worker-kill leg: the first add commit finished before any buildwork appeared — cannot prove interruption"
fi
AA_PGID_C=""
[ ! -e "$AA_DD_C/zcode/installed/$ZDOGDRONE_ROOT/build-report" ] \
    || aa_die "worker-kill leg: zdogdrone fully installed despite the SIGKILL — interruption not proven"
echo "arena-acceptance:     interrupted state confirmed: zdogdrone (target, built last) not installed"

# Retry the identical install to completion.
t0=$(now_ms)
out="$(printf '%s' "{\"name_or_root\":\"$ZDOGDRONE_ROOT\"}" | aa_leaf "$AA_DD_C" zcode.package.add.plan)"
[ "$(aa_jget "$out" ok 2>/dev/null || true)" = "true" ] \
    || aa_die "C retry add plan refused: $out"
C_PLAN2="$(aa_jget "$out" data.plan_id)"
out="$(printf '%s' "{\"plan_id\":\"$C_PLAN2\"}" | aa_leaf "$AA_DD_C" zcode.package.add.commit)"
[ "$(aa_jget "$out" ok 2>/dev/null || true)" = "true" ] \
    || aa_die "C retry add commit refused: $out"
[ "$(aa_jget "$out" data.active_root 2>/dev/null || true)" = "$ZDOGDRONE_ROOT" ] \
    || aa_die "C retry activated the wrong root: $out"
C_RETRY_MS=$(( $(now_ms) - t0 ))
echo "arena-acceptance:     retry completed in $(( C_RETRY_MS / 1000 )).$(( C_RETRY_MS % 1000 ))s; active_root == zdogdrone"

for name in zprng zdogfight zdogdrone; do
    root="$(root_of "$name")"
    cmp "$AA_DD_B/zcode/installed/$root/lib/lib$name.a" \
        "$AA_DD_C/zcode/installed/$root/lib/lib$name.a" \
        || aa_die "RED: C's rebuilt lib$name.a differs from B's — failure/retry changed the bytes"
done
echo "arena-acceptance:     C's post-kill rebuild: archives byte-identical to B's"
build_pilot "$AA_DD_C" zdogdrone "$AA_WORK/checkout-C/zdogdrone" "$AA_WORK/pilot-C-blue"
aa_run_match "$AA_WORK/pilot-A-red" "$AA_WORK/pilot-C-blue" "$MATCH_SEED" "$MATCH_PLANES" \
    "$AA_WORK/replay-C.bin" "$AA_WORK/match-C.out" \
    || { cat "$AA_WORK/match-C.out" >&2; aa_die "C rerun match failed"; }
cmp "$AA_WORK/replay-C.bin" "$AA_WORK/replay-A.bin" \
    || aa_die "RED: post-failure rerun replay differs from the proven replay"
[ "$(aa_match_field "$AA_WORK/match-C.out" replay_root)" = "$M_REPLAY_ROOT" ] \
    || aa_die "RED: post-failure rerun replay_root drifted"
echo "arena-acceptance:     WORKER-FAILURE LEG PROVEN: kill+retry cannot change the result (replay byte-identical, same roots)"

# ── [9] KPIs ──────────────────────────────────────────────────────────
aa_step 9 "KPIs"
# (a) published-pilot 36000-tick match: A's leg-5 timing.
KPI_MATCH_MS=$(( T_MATCH_A_1 - T_MATCH_A_0 ))
# (b) dead-pilot pure-sim 36000-tick run (immediate-EOF pilots -> neutral
# controls -> full-length draw; deterministic, no seed luck).
printf 'int main(void){return 0;}\n' > "$AA_WORK/dead.c"
cc -std=c23 -O1 -static -o "$AA_WORK/dead_pilot" "$AA_WORK/dead.c" \
    || aa_die "dead pilot build failed"
k0=$(now_ms)
aa_run_match "$AA_WORK/dead_pilot" "$AA_WORK/dead_pilot" "$MATCH_SEED" "$MATCH_PLANES" \
    "$AA_WORK/replay-dead.bin" "$AA_WORK/match-dead.out" \
    || aa_die "dead-pilot KPI run failed"
k1=$(now_ms)
DEAD_TICKS="$(aa_match_field "$AA_WORK/match-dead.out" ticks)"
[ "$DEAD_TICKS" = "36000" ] || aa_die "dead-pilot run did not go the distance: ticks=$DEAD_TICKS"
# (c) 11941-tick reference: repo-source dev pilots (UNPUBLISHED sign-fixed
# zdogace; packages/ tree — explicitly outside the published-package
# proof), asserted against the M3b reference roots.
for f in packages/zdogace/src/zdogace.c packages/zdogdrone/src/zdogdrone.c \
         packages/zdogfight/src/zdogfight.c packages/zdogfight/src/zdogfix.c \
         packages/zprng/src/zprng.c; do
    [ -f "$REPO_ROOT/$f" ] || aa_die "missing $f for the dev-pilot KPI build"
done
cc -std=c23 -O1 -static -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L \
    -I "$REPO_ROOT/packages/zdogace/include" -I "$REPO_ROOT/packages/zdogfight/include" \
    -I "$REPO_ROOT/packages/zprng/include" \
    "$REPO_ROOT/packages/zdogace/app/main.c" "$REPO_ROOT/packages/zdogace/src/zdogace.c" \
    "$REPO_ROOT/packages/zdogfight/src/zdogfight.c" "$REPO_ROOT/packages/zdogfight/src/zdogfix.c" \
    "$REPO_ROOT/packages/zprng/src/zprng.c" -o "$AA_WORK/pilot-dev-red" || aa_die "dev ace pilot build failed"
cc -std=c23 -O1 -static -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L \
    -I "$REPO_ROOT/packages/zdogdrone/include" -I "$REPO_ROOT/packages/zdogfight/include" \
    -I "$REPO_ROOT/packages/zprng/include" \
    "$REPO_ROOT/packages/zdogdrone/app/main.c" "$REPO_ROOT/packages/zdogdrone/src/zdogdrone.c" \
    "$REPO_ROOT/packages/zdogfight/src/zdogfight.c" "$REPO_ROOT/packages/zdogfight/src/zdogfix.c" \
    "$REPO_ROOT/packages/zprng/src/zprng.c" -o "$AA_WORK/pilot-dev-blue" || aa_die "dev drone pilot build failed"
k2=$(now_ms)
aa_run_match "$AA_WORK/pilot-dev-red" "$AA_WORK/pilot-dev-blue" "$REF_SEED" "$MATCH_PLANES" \
    "$AA_WORK/replay-dev.bin" "$AA_WORK/match-dev.out" \
    || aa_die "dev-pilot KPI run failed"
k3=$(now_ms)
[ "$(aa_match_field "$AA_WORK/match-dev.out" ticks)" = "$REF_TICKS" ] \
    || aa_die "dev-pilot reference match drifted: ticks=$(aa_match_field "$AA_WORK/match-dev.out" ticks), want $REF_TICKS"
[ "$(aa_match_field "$AA_WORK/match-dev.out" replay_root)" = "$REF_REPLAY_ROOT" ] \
    || aa_die "dev-pilot reference replay_root drifted from the M3b reference"

REPLAY_BYTES="$(stat -c %s "$AA_WORK/replay-A.bin")"
PILOT_RED_BYTES="$(stat -c %s "$AA_WORK/pilot-A-red")"
PILOT_BLUE_BYTES="$(stat -c %s "$AA_WORK/pilot-A-blue")"
TOTAL_MS=$(( T_MATCH_B_1 - T_FETCH_START ))

echo "arena-acceptance: ══ KPIs ══"
awk -v m="$KPI_MATCH_MS" -v dead="$(( k1 - k0 ))" -v ref="$(( k3 - k2 ))" '
function rate(ticks, ms) {
    if (ms + 0 == 0) return "inf"
    return sprintf("%.0f", ticks * 1000.0 / ms)
}
function commify(n,    s, out, i, c) {
    s = n ""
    if (s == "inf") return s
    out = ""
    c = 0
    for (i = length(s); i >= 1; i--) {
        c++
        out = substr(s, i, 1) out
        if (c == 3 && i > 1) { out = "," out; c = 0 }
    }
    return out
}
BEGIN {
    printf "arena-acceptance:   runner ticks/sec: %s (36000-tick published-pilot match, %s ms wall incl. 6 confined pilots)\n", commify(rate(36000, m)), m
    printf "arena-acceptance:                     %s (36000-tick dead-pilot pure-sim, %s ms)\n", commify(rate(36000, dead)), dead
    printf "arena-acceptance:                     %s (11941-tick dev-pilot reference match, %s ms)\n", commify(rate(11941, ref)), ref
}'
echo "arena-acceptance:   replay bytes: $REPLAY_BYTES (36000-tick 3v3 canonical stream)"
echo "arena-acceptance:   pilot binary sizes: red(zdogace)=$PILOT_RED_BYTES blue(zdogdrone)=$PILOT_BLUE_BYTES bytes (static)"
for name in $PKG_ORDER; do
    printf 'arena-acceptance:   fetch+install: %-10s fetch=+%d.%03ds install=%d.%03ds\n' \
        "$name" \
        $(( FETCH_SECS[$name] / 1000 )) $(( FETCH_SECS[$name] % 1000 )) \
        $(( INSTALL_SECS[$name] / 1000 )) $(( INSTALL_SECS[$name] % 1000 ))
done
echo "arena-acceptance:   fetch total (B boot -> all four complete): $(( (T_FETCH_DONE - T_FETCH_START) / 1000 )).$(( (T_FETCH_DONE - T_FETCH_START) % 1000 ))s"
echo "arena-acceptance:   cross-node reproduction wall time (B fetch start -> B replay done): $(( TOTAL_MS / 1000 )).$(( TOTAL_MS % 1000 ))s"
echo "arena-acceptance:   whole-proof wall time: $(( ( $(now_ms) - AA_T0 ) / 1000 ))s"

aa_step done "ALL LEGS GREEN"
echo "arena-acceptance: PROOF COMPLETE — two-node swarm fetch, independent install, byte-identical match, tamper refusal, kill-safe retry."
