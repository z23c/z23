#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Moderation acceptance: two isolated regtest daemons apply DIFFERENT
# moderation profiles to the SAME signed market offer. A (seller,
# -externalip + file service) commits one signed paid offer; it gossips
# to B (buyer) over the loopback P2P link. The proof then walks the
# per-node moderation surface (schema v65 review_state):
#   1. B's boot-default general-audience.v1 profile HIDES the offer from
#      `app market list` (it ingested as unreviewed) with an honest
#      hidden_count >= 1, and `app market moderation status` names the
#      active profile and the unreviewed count.
#   2. The explicit per-request opt-in (`profile:"open"`) shows the same
#      offer annotated review_state=unreviewed.
#   3. Switching B's node default to open-view (plan/commit with the
#      leaf's plan_token) shows it on the default list.
#   4. Back on general-audience, B's OWN review marks drive visibility:
#      reviewed_ok shows, sensitive hides; the open view always shows
#      the current annotation.
#   5. A (never touched by moderation) keeps its own view of the same
#      offer_id: the two nodes legitimately disagree — B shows the
#      reviewed_ok offer while A's default list hides it. Hidden is not
#      rejected: file_offers holds exactly one row on BOTH nodes.
#   6. Protocol-validity separation: the signed wire columns
#      (auth_version, endpoint, ids, pubkeys, signature, expiry) are
#      byte-identical on A and B and unchanged on B across every
#      moderation action — review_state never enters the wire and never
#      leaves the node (the review-set reply says local_only=true,
#      gossiped=false).
# No purchase is planned or paid: this is a VISIBILITY acceptance, not
# a trade.
#
# Modelled on tools/dev/market_acceptance.sh: same setsid isolation,
# port refuse-set discipline, wallet-custody recipe, mining cadence,
# pgid cleanup, phase banners. Tor is deliberately absent — moderation
# is independent of transport, so this uses the clearnet sibling's
# cheaper boot.
#
# Knobs: MKT_WAIT (chain/sync/gossip gate budget, s), MKT_KEEP=1
# preserves the scratch tree.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"
JSONQ="${JSONQ:-$REPO_ROOT/build/bin/jsonq}"

MKT_LIVE_PORTS="8023 8033 8034 8035 8043 8044 8045 8046 8232 8443 \
18034 18232 18234 18243 18244 18245 18246"
# Fresh block vs the siblings (market: 395xx quads + 20030/20031 + 39999,
# onion: 396xx quads + 20040/20041 + 39998, dht: 29211-29273, science:
# 39111-39123, p2p 20022-20027 + 18033) and vs this host's
# zclassic23-live instance (39311/39312).
A_PORT=20050; A_RPC=39711; A_FS=39712; A_HTTPS=39713
B_PORT=20051; B_RPC=39721; B_FS=39722; B_HTTPS=39723
DEAD_SINK=39997
MKT_WAIT="${MKT_WAIT:-90}"
MKT_WORK=""; MKT_DD_A=""; MKT_DD_B=""; MKT_PGID_A=""; MKT_PGID_B=""
MKT_EXTRA_FLAGS=()
MKT_CLEANED=0
MKT_KEEP="${MKT_KEEP:-0}"
# Throwaway passphrases for the wallet-custody recipe (never argv: they
# ride the wallet-passphrase credential file and --input=- stdin only).
MKT_WALLET_PASS="market-moderation-acceptance-wallet-pass"
MKT_BACKUP_PASS="market-moderation-acceptance-backup-pass"

# One small one-chunk fixture: the trade itself is out of scope, so the
# fixture only has to give the offer a real committed root and price.
PRICE_PER_MB_ZAT=30000
FIXTURE_BYTES=$((150 * 1024))
EXPECTED_CHUNKS=1

# The signed-wire columns moderation must NEVER touch (last_seen/ttl are
# gossip-refresh metadata, not wire; review_state is the local-only v65
# column under test). Snapshot-compared across every moderation action.
WIRE_SQL="SELECT auth_version,endpoint_type,peer_port,nonce,issued_unix,expires_unix,hex(root_hash),hex(offer_id),hex(seller_pubkey),hex(seller_signature),filename,size_bytes,num_chunks,price_per_mb FROM file_offers"

mkt_die() {
    echo "market-moderation-acceptance: FATAL: $*" >&2
    if [ -n "$MKT_WORK" ] && [ -d "$MKT_WORK" ]; then
        printf '%s\n' "$*" >"$MKT_WORK/FAILURE"
    fi
    exit 2
}
mkt_note() { echo "market-moderation-acceptance: $*"; }

mkt_assert_port() {
    local p="$1" live
    for live in $MKT_LIVE_PORTS; do
        [ "$p" = "$live" ] && mkt_die "port $p is in the live refuse-set"
    done
    ss -tlnH "sport = :$p" 2>/dev/null | grep -q . &&
        mkt_die "port $p is already listening"
    return 0
}

mkt_kill_group() {
    local pgid="$1" sig="${2:-TERM}" i
    [ -n "$pgid" ] || return 0
    kill -"$sig" "-$pgid" 2>/dev/null || true
    for i in $(seq 1 50); do
        kill -0 "-$pgid" 2>/dev/null || return 0
        sleep 0.2
    done
    kill -KILL "-$pgid" 2>/dev/null || true
}

mkt_cleanup() {
    [ "$MKT_CLEANED" = 1 ] && return 0
    MKT_CLEANED=1
    mkt_kill_group "$MKT_PGID_A"
    mkt_kill_group "$MKT_PGID_B"
    if [ "$MKT_KEEP" = 1 ] && [ -n "$MKT_WORK" ]; then
        mkt_note "preserved acceptance artifacts: $MKT_WORK"
    elif [ -n "$MKT_WORK" ] && [ -d "$MKT_WORK" ]; then
        case "$MKT_WORK" in
            "$REPO_ROOT"/test-tmp/zcl23-modacc-*) rm -rf "$MKT_WORK" ;;
            *) mkt_note "WARN refusing to remove non-scratch $MKT_WORK" ;;
        esac
    fi
}
trap mkt_cleanup EXIT INT TERM

mkt_rpc() {
    local dd="$1" port="$2"; shift 2
    ZCL_DATADIR="$dd" ZCL_RPCPORT="$port" "$RPC_BIN" "$@" 2>/dev/null
}
a_rpc() { mkt_rpc "$MKT_DD_A" "$A_RPC" "$@"; }
b_rpc() { mkt_rpc "$MKT_DD_B" "$B_RPC" "$@"; }
mkt_result() {
    "$JSONQ" unwrap
}
mkt_jget() {
    "$JSONQ" get "$1"
}
mkt_hex64() {
    local h="$1"
    [ "${#h}" -eq 64 ] || return 1
    case "$h" in
        *[!0-9a-fA-F]*) return 1 ;;
        *[!0]*) return 0 ;;
        *) return 1 ;;
    esac
}
mkt_native() {
    local dd="$1" rpc="$2"; shift 2
    "$NODE_BIN" -datadir="$dd" -rpcport="$rpc" "$@" 2>/dev/null | tail -1
}

mkt_spawn() {
    local dd="$1" p2p="$2" rpc="$3" fs="$4" https="$5"; shift 5
    local args=() connect
    for connect in "$@"; do args+=("-connect=$connect"); done
    [ "${#args[@]}" -gt 0 ] || args+=("-connect=127.0.0.1:$DEAD_SINK")
    # No -allow-plaintext-wallet: the wallet-passphrase credential
    # (CREDENTIALS_DIRECTORY, exported below) encrypts key writes at rest
    # (WKS1); -operator-lane=dev arms the dev wallet scope. -regtestshielded
    # activates Overwinter+Sapling from genesis on BOTH nodes (the zcashd
    # -nuparams equivalent; regtest otherwise pins them NO_ACTIVATION).
    # No -tor: moderation is transport-independent, so the seller carries
    # the clearnet -externalip endpoint opt-in instead.
    setsid "$NODE_BIN" -datadir="$dd" -regtest -port="$p2p" \
        -rpcport="$rpc" -fsport="$fs" -httpsport="$https" \
        "${args[@]}" -packagehost=0 -regtestshielded \
        -operator-lane=dev -wallet-no-phrase-backup \
        -nobgvalidation -nolegacyimport -showmetrics=0 \
        "${MKT_EXTRA_FLAGS[@]}" \
        >>"$dd/node.log" 2>&1 &
    echo "$!"
}

mkt_height() {
    mkt_rpc "$1" "$2" getblockcount | mkt_result
}
mkt_wait_rpc() {
    local dd="$1" rpc="$2" pid="$3" deadline
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        kill -0 "$pid" 2>/dev/null || return 1
        [ -f "$dd/.cookie" ] && mkt_height "$dd" "$rpc" >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    return 1
}
mkt_wait_height() {
    local dd="$1" rpc="$2" target="$3" deadline h
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        h="$(mkt_height "$dd" "$rpc" 2>/dev/null || true)"
        [ "$h" = "$target" ] && return 0
        sleep 0.5
    done
    return 1
}

# The regtest miner stamps blocks from whole-second wall time.  More than six
# consecutive blocks with one timestamp becomes <= the peer's 11-block MTP
# even though the local submission path accepted the batch.  Mine in groups
# of five with a wall-clock step so the second node validates the same chain.
mkt_mine_to_address() {
    local rpc_fn="$1" count="$2" address="$3" chunk
    while [ "$count" -gt 0 ]; do
        chunk=5
        [ "$count" -lt "$chunk" ] && chunk="$count"
        "$rpc_fn" generatetoaddress "$chunk" "\"$address\"" | mkt_result >/dev/null
        count=$((count - chunk))
        [ "$count" -eq 0 ] || sleep 1
    done
}

mkt_wait_connected() {
    local dd="$1" rpc="$2" deadline n
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        n="$(mkt_rpc "$dd" "$rpc" getconnectioncount 2>/dev/null | mkt_result 2>/dev/null || true)"
        [ "${n:-0}" -ge 1 ] 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}
# A listen-only node never leaves finding_peers: each node needs its own
# outbound link before its sync FSM can walk to at_tip.
mkt_wait_at_tip() {
    local dd="$1" rpc="$2" deadline state
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        state="$(mkt_rpc "$dd" "$rpc" downloadstats 2>/dev/null \
            | mkt_jget result.sync_state 2>/dev/null || true)"
        [ "$state" = "at_tip" ] && return 0
        sleep 0.5
    done
    return 1
}
mkt_unlock_wallet() {
    local dd="$1" rpc="$2" status unlock
    status="$(mkt_native "$dd" "$rpc" core wallet security status || true)"
    [ "$(printf '%s' "$status" | mkt_jget ok 2>/dev/null || true)" = "true" ] || {
        printf '%s\n' "$status" >&2; return 1; }
    if [ "$(printf '%s' "$status" | mkt_jget data.unlocked 2>/dev/null || true)" != "true" ]; then
        unlock="$(printf '%s' "{\"passphrase\":\"$MKT_WALLET_PASS\",\"timeout_seconds\":3600}" \
            | mkt_native "$dd" "$rpc" core wallet security unlock --input=- || true)"
        [ "$(printf '%s' "$unlock" | mkt_jget data.unlocked 2>/dev/null || true)" = "true" ] || {
            printf '%s\n' "$unlock" >&2; return 1; }
    fi
    return 0
}
mkt_backup_wallet() {
    local dd="$1" rpc="$2" out
    out="$(printf '%s' "{\"confirm\":true,\"password\":\"$MKT_BACKUP_PASS\"}" \
        | mkt_native "$dd" "$rpc" core wallet backup now --input=- || true)"
    [ "$(printf '%s' "$out" | mkt_jget ok 2>/dev/null || true)" = "true" ] || {
        printf '%s\n' "$out" >&2; return 1; }
}

# One node's signed-wire row set for the moderated offer (WIRE_SQL
# excludes last_seen/ttl/review_state by construction), printed as a
# canonical JSON string for byte comparison.
mod_wire_rows() {
    local dd="$1" rpc="$2" out
    out="$(mkt_native "$dd" "$rpc" core storage query \
        --input="{\"sql\":\"$WIRE_SQL\"}" || true)"
    printf '%s' "$out" | mkt_jget data.rows 2>/dev/null
}
# The node's local-only review_state column for the one stored offer.
mod_review_col() {
    local dd="$1" rpc="$2" out
    out="$(mkt_native "$dd" "$rpc" core storage query \
        --input='{"sql":"SELECT review_state FROM file_offers"}' || true)"
    printf '%s' "$out" | mkt_jget data.rows[0][0] 2>/dev/null
}
# The `app market list` body, optionally with a per-request profile
# override ({"profile":"open"} is the explicit opt-in view).
mod_list() {
    local dd="$1" rpc="$2" profile="${3:-}"
    if [ -n "$profile" ]; then
        printf '%s' "{\"profile\":\"$profile\"}" \
            | mkt_native "$dd" "$rpc" app market list --input=- 2>/dev/null
    else
        mkt_native "$dd" "$rpc" app market list 2>/dev/null
    fi
}
# Assert one default (no per-request override) list body hides the offer:
# absent from offers, an honest hidden_count, and the expected profile
# name. $3 = expected profile.
mod_assert_hidden() {
    local body="$1" profile="$3" n i oid hidden count
    printf '%s' "$body" | "$JSONQ" eq ok true ||
        mkt_die "default list did not hide the $profile offer: $body"
    [ "$(printf '%s' "$body" | "$JSONQ" get data.profile)" = "$profile" ] ||
        mkt_die "default list did not hide the $profile offer: $body"
    printf '%s' "$body" | "$JSONQ" eq data.profile_override false ||
        mkt_die "default list did not hide the $profile offer: $body"
    n="$(printf '%s' "$body" | "$JSONQ" count data.offers)" ||
        mkt_die "default list did not hide the $profile offer: $body"
    i=0
    while [ "$i" -lt "$n" ]; do
        oid="$(printf '%s' "$body" | "$JSONQ" get "data.offers[$i].offer_id")" ||
            mkt_die "default list did not hide the $profile offer: $body"
        [ "$oid" != "$OFFER_ID" ] ||
            mkt_die "default list did not hide the $profile offer: $body"
        i=$((i + 1))
    done
    hidden="$(printf '%s' "$body" | "$JSONQ" get data.hidden_count)" ||
        mkt_die "default list did not hide the $profile offer: $body"
    [ "$hidden" -ge 1 ] ||
        mkt_die "default list did not hide the $profile offer: $body"
    count="$(printf '%s' "$body" | "$JSONQ" get data.offer_count)" ||
        mkt_die "default list did not hide the $profile offer: $body"
    [ "$count" = "$n" ] ||
        mkt_die "default list did not hide the $profile offer: $body"
}
# Assert one list body shows the offer with an exact review_state. $3 =
# expected review_state, $4 = expected profile name.
mod_assert_shown() {
    local body="$1" expect_state="$3" profile="$4" n i oid match
    printf '%s' "$body" | "$JSONQ" eq ok true ||
        mkt_die "list did not show the offer as $expect_state ($profile): $body"
    [ "$(printf '%s' "$body" | "$JSONQ" get data.profile)" = "$profile" ] ||
        mkt_die "list did not show the offer as $expect_state ($profile): $body"
    n="$(printf '%s' "$body" | "$JSONQ" count data.offers)" ||
        mkt_die "list did not show the offer as $expect_state ($profile): $body"
    match=0
    i=0
    while [ "$i" -lt "$n" ]; do
        oid="$(printf '%s' "$body" | "$JSONQ" get "data.offers[$i].offer_id")" ||
            mkt_die "list did not show the offer as $expect_state ($profile): $body"
        if [ "$oid" = "$OFFER_ID" ]; then
            match=$((match + 1))
            printf '%s' "$body" | "$JSONQ" eq "data.offers[$i].review_state" "$expect_state" ||
                mkt_die "list did not show the offer as $expect_state ($profile): $body"
        fi
        i=$((i + 1))
    done
    [ "$match" = 1 ] ||
        mkt_die "list did not show the offer as $expect_state ($profile): $body"
    printf '%s' "$body" | "$JSONQ" eq data.hidden_count 0 ||
        mkt_die "list did not show the offer as $expect_state ($profile): $body"
}
# Switch one node's active profile through the leaf's plan/commit idiom:
# mode=plan mints a plan_token bound to the current active profile and
# the target; mode=commit requires that exact token.
mod_profile_set() {
    local dd="$1" rpc="$2" target="$3" expect_prev="$4" plan token commit
    plan="$(printf '%s' "{\"profile\":\"$target\",\"mode\":\"plan\"}" \
        | mkt_native "$dd" "$rpc" app market moderation profile set --input=- || true)"
    printf '%s' "$plan" | "$JSONQ" eq ok true ||
        mkt_die "profile set plan refused: $plan"
    printf '%s' "$plan" | "$JSONQ" eq data.mode plan ||
        mkt_die "profile set plan refused: $plan"
    printf '%s' "$plan" | "$JSONQ" eq data.committed false ||
        mkt_die "profile set plan refused: $plan"
    printf '%s' "$plan" | "$JSONQ" eq data.profile "$target" ||
        mkt_die "profile set plan refused: $plan"
    token="$(printf '%s' "$plan" | "$JSONQ" get data.plan_token)" ||
        mkt_die "profile set plan refused: $plan"
    [ "$(printf '%s' "$plan" | "$JSONQ" type data.plan_token)" = "string" ] ||
        mkt_die "profile set plan refused: $plan"
    [ -n "$token" ] || mkt_die "profile set plan refused: $plan"
    commit="$(printf '%s' "{\"profile\":\"$target\",\"mode\":\"commit\",\"plan_token\":\"$token\"}" \
        | mkt_native "$dd" "$rpc" app market moderation profile set --input=- || true)"
    printf '%s' "$commit" | "$JSONQ" eq ok true ||
        mkt_die "profile set commit refused: $commit"
    printf '%s' "$commit" | "$JSONQ" eq data.mode commit ||
        mkt_die "profile set commit refused: $commit"
    printf '%s' "$commit" | "$JSONQ" eq data.committed true ||
        mkt_die "profile set commit refused: $commit"
    printf '%s' "$commit" | "$JSONQ" eq data.profile "$target" ||
        mkt_die "profile set commit refused: $commit"
    printf '%s' "$commit" | "$JSONQ" eq data.previous_profile "$expect_prev" ||
        mkt_die "profile set commit refused: $commit"
}
# Mark the offer's local review_state on one node and assert the reply
# proves the mark is local-only and never gossiped.
mod_review_set() {
    local dd="$1" rpc="$2" state="$3" expect_prev="$4" out
    out="$(printf '%s' "{\"offer_id\":\"$OFFER_ID\",\"review_state\":\"$state\"}" \
        | mkt_native "$dd" "$rpc" app market moderation review set --input=- || true)"
    printf '%s' "$out" | "$JSONQ" eq ok true ||
        mkt_die "review set $state refused: $out"
    printf '%s' "$out" | "$JSONQ" eq data.offer_id "$OFFER_ID" ||
        mkt_die "review set $state refused: $out"
    printf '%s' "$out" | "$JSONQ" eq data.review_state "$state" ||
        mkt_die "review set $state refused: $out"
    printf '%s' "$out" | "$JSONQ" eq data.previous_review_state "$expect_prev" ||
        mkt_die "review set $state refused: $out"
    printf '%s' "$out" | "$JSONQ" eq data.local_only true ||
        mkt_die "review set $state refused: $out"
    printf '%s' "$out" | "$JSONQ" eq data.gossiped false ||
        mkt_die "review set $state refused: $out"
}

for port in $A_PORT $A_RPC $A_FS $A_HTTPS $B_PORT $B_RPC $B_FS $B_HTTPS; do
    mkt_assert_port "$port"
done
[ -x "$NODE_BIN" ] && [ -x "$RPC_BIN" ] || mkt_die "build node and RPC binaries first"
[ -x "$JSONQ" ] || mkt_die "build/bin/jsonq is missing — run make jsonq"
mkdir -p "$REPO_ROOT/test-tmp"
MKT_WORK="$(mktemp -d "$REPO_ROOT/test-tmp/zcl23-modacc-XXXXXX")"
MKT_DD_A="$MKT_WORK/a"; MKT_DD_B="$MKT_WORK/b"
MKT_CONTENT="$MKT_WORK/content"
mkdir -p "$MKT_DD_A" "$MKT_DD_B" "$MKT_CONTENT"
FIXTURE="$MKT_CONTENT/seller-fixture.bin"
FIXTURE_GEN="$MKT_WORK/fixture_gen"

# Deterministic one-chunk fixture, plus the exact manifest root the offer
# must commit (sha3-256 over the concatenated per-chunk sha3-256 digests)
# and the exact total price.
cat >"$MKT_WORK/fixture_gen.c" <<'C'
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { CHUNK = 50 * 1024 * 1024, BLOCK = 65536 };

static void die(const char *m)
{
    fprintf(stderr, "fixture_gen: %s\n", m);
    exit(1);
}

static void digest_hex(const unsigned char d[32], char out[65])
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2] = hex[d[i] >> 4];
        out[i * 2 + 1] = hex[d[i] & 15];
    }
    out[64] = '\0';
}

static uint64_t parse_u64(const char *s)
{
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (!s || !s[0] || !end || *end) die("invalid integer");
    return (uint64_t)v;
}

static uint64_t price_total(uint64_t written, uint64_t price)
{
    uint64_t mb = 1024ull * 1024ull;
    uint64_t whole = written / mb, rem = written % mb;
    uint64_t pw = price / mb, pr = price % mb;
    return whole * price + rem * pw + (rem * pr + mb - 1ull) / mb;
}

static int hash_chunk_stream(FILE *f, uint64_t size,
                             unsigned char *digests, int *nchunks)
{
    unsigned char buf[BLOCK];
    unsigned char digest[32];
    uint64_t written = 0;
    *nchunks = 0;
    while (written < size) {
        uint64_t n = size - written;
        if (n > (uint64_t)CHUNK) n = (uint64_t)CHUNK;
        struct sha3_256_ctx ctx;
        sha3_256_init(&ctx);
        uint64_t off = 0;
        while (off < n) {
            size_t take = (n - off) > (uint64_t)BLOCK
                ? (size_t)BLOCK : (size_t)(n - off);
            for (size_t i = 0; i < take; i++)
                buf[i] = (unsigned char)((written +
                    (off + (uint64_t)i) * 11ull) & 0xFFull);
            if (fwrite(buf, 1, take, f) != take) return -1;
            sha3_256_write(&ctx, buf, take);
            off += take;
        }
        sha3_256_finalize(&ctx, digest);
        memcpy(digests + (*nchunks) * 32, digest, 32);
        (*nchunks)++;
        written += n;
    }
    return 0;
}

int main(int argc, char **argv)
{
    unsigned char digests[64 * 32];
    int nchunks = 0;
    uint64_t price, size;
    FILE *f;
    unsigned char root[32];
    char hex[65];

    if (argc != 4) die("usage: fixture_gen PATH PRICE SIZE");
    price = parse_u64(argv[2]);
    size = parse_u64(argv[3]);
    if (size == 0 ||
        (size + (uint64_t)CHUNK - 1ull) / (uint64_t)CHUNK > 64ull)
        die("size out of range");
    f = fopen(argv[1], "wb");
    if (!f) die("open write failed");
    if (hash_chunk_stream(f, size, digests, &nchunks) != 0) {
        fclose(f);
        die("write failed");
    }
    fclose(f);
    sha3_256(digests, (size_t)nchunks * 32u, root);
    digest_hex(root, hex);
    printf("%llu %s %llu\n",
           (unsigned long long)size, hex,
           (unsigned long long)price_total(size, price));
    return 0;
}
C
cc -std=c23 -O2 -I"$REPO_ROOT/lib/sha3/include" -I"$REPO_ROOT/lib/base/include" \
    -o "$FIXTURE_GEN" "$MKT_WORK/fixture_gen.c" \
    "$REPO_ROOT/lib/sha3/src/sha3.c" || mkt_die "fixture_gen compile failed"
read -r FIXTURE_SIZE EXPECT_ROOT EXPECT_TOTAL_ZAT \
    <<<"$("$FIXTURE_GEN" "$FIXTURE" "$PRICE_PER_MB_ZAT" "$FIXTURE_BYTES")" \
    || mkt_die "fixture build failed"

# Wallet custody: boot both nodes with a passphrase credential so key writes
# encrypt at rest (WKS1). The seller-key envelope (metadata DEK) refuses a
# locked or plaintext wallet.
MKT_CRED_DIR="$MKT_WORK/cred"
install -d -m 700 "$MKT_CRED_DIR"
install -m 600 /dev/null "$MKT_CRED_DIR/wallet-passphrase"
printf '%s\n' "$MKT_WALLET_PASS" >"$MKT_CRED_DIR/wallet-passphrase"
export CREDENTIALS_DIRECTORY="$MKT_CRED_DIR"

mkt_note "booting seller A (-externalip + file service) and buyer B (no Tor: moderation is transport-independent)"
MKT_EXTRA_FLAGS=("-externalip=127.0.0.1")
MKT_PGID_A="$(mkt_spawn "$MKT_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" "127.0.0.1:$DEAD_SINK")"
mkt_wait_rpc "$MKT_DD_A" "$A_RPC" "$MKT_PGID_A" || mkt_die "seller A RPC warmup failed"
MKT_EXTRA_FLAGS=()
MKT_PGID_B="$(mkt_spawn "$MKT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$A_PORT")"
mkt_wait_rpc "$MKT_DD_B" "$B_RPC" "$MKT_PGID_B" || mkt_die "buyer B RPC warmup failed"
! grep -qaF "unrecognized flag" "$MKT_DD_A/node.log" "$MKT_DD_B/node.log" ||
    mkt_die "a boot flag was not recognized"

mkt_note "mining 101 spendable regtest blocks to the buyer"
BUYER_ADDR="$(b_rpc getnewaddress | mkt_result)"
mkt_mine_to_address b_rpc 101 "$BUYER_ADDR"
mkt_wait_height "$MKT_DD_A" "$A_RPC" 101 || mkt_die "A did not sync the funding chain"

# Symmetric one-shot link so BOTH nodes own an outbound peer and walk to
# at_tip (B dialed A at boot; A is on the dead sink until this onetry).
a_rpc addnode "\"127.0.0.1:$B_PORT\"" "\"onetry\"" >/dev/null || true
mkt_wait_connected "$MKT_DD_A" "$A_RPC" || mkt_die "A never connected outbound to B"
mkt_wait_at_tip "$MKT_DD_A" "$A_RPC" || mkt_die "A sync never reached at_tip"
mkt_wait_at_tip "$MKT_DD_B" "$B_RPC" || mkt_die "B sync never reached at_tip"

# The offer's payee gate refuses an unseeded Sapling keystore and a locked
# wallet: unlock both, re-top the RAM-only keypool bookkeeping, mint the
# seller's first z-address, take the current-key encrypted backups.
mkt_note "unlocking both wallets and taking current-key encrypted backups"
mkt_unlock_wallet "$MKT_DD_A" "$A_RPC" || mkt_die "A wallet unlock failed"
mkt_unlock_wallet "$MKT_DD_B" "$B_RPC" || mkt_die "B wallet unlock failed"
a_rpc getnewaddress | mkt_result >/dev/null || mkt_die "A keypool top-up failed"
b_rpc getnewaddress | mkt_result >/dev/null || mkt_die "B keypool top-up failed"
a_rpc z_getnewaddress | mkt_result >/dev/null || mkt_die "A sapling keystore seeding failed"
mkt_backup_wallet "$MKT_DD_A" "$A_RPC" || mkt_die "A custody backup failed"
mkt_backup_wallet "$MKT_DD_B" "$B_RPC" || mkt_die "B custody backup failed"

# ── Phase 1: seller offer plan (non-mutating) then commit ────────────
mkt_note "seller plans the offer (non-mutating preview)"
OFFER_PLAN="$(printf '%s' "{\"filepath\":\"$FIXTURE\",\"price_per_mb_zat\":$PRICE_PER_MB_ZAT}" \
    | mkt_native "$MKT_DD_A" "$A_RPC" app market offer --input=- || true)"
printf '%s' "$OFFER_PLAN" | "$JSONQ" eq ok true ||
    mkt_die "offer plan preview mismatch: $OFFER_PLAN"
printf '%s' "$OFFER_PLAN" | "$JSONQ" eq data.stage plan ||
    mkt_die "offer plan preview mismatch: $OFFER_PLAN"
printf '%s' "$OFFER_PLAN" | "$JSONQ" eq data.committed false ||
    mkt_die "offer plan preview mismatch: $OFFER_PLAN"
printf '%s' "$OFFER_PLAN" | "$JSONQ" eq data.spends_funds false ||
    mkt_die "offer plan preview mismatch: $OFFER_PLAN"
printf '%s' "$OFFER_PLAN" | "$JSONQ" eq data.root_hash "$EXPECT_ROOT" ||
    mkt_die "offer plan preview mismatch: $OFFER_PLAN"
printf '%s' "$OFFER_PLAN" | "$JSONQ" eq data.size_bytes "$FIXTURE_SIZE" ||
    mkt_die "offer plan preview mismatch: $OFFER_PLAN"
printf '%s' "$OFFER_PLAN" | "$JSONQ" eq data.num_chunks "$EXPECTED_CHUNKS" ||
    mkt_die "offer plan preview mismatch: $OFFER_PLAN"
printf '%s' "$OFFER_PLAN" | "$JSONQ" eq data.total_zat "$EXPECT_TOTAL_ZAT" ||
    mkt_die "offer plan preview mismatch: $OFFER_PLAN"
price="$(printf '%s' "$OFFER_PLAN" | "$JSONQ" get data.price_per_mb_zat)" ||
    mkt_die "offer plan preview mismatch: $OFFER_PLAN"
[ "$price" -gt 0 ] || mkt_die "offer plan preview mismatch: $OFFER_PLAN"
printf '%s' "$OFFER_PLAN" | "$JSONQ" has data.commit_input ||
    mkt_die "offer plan preview mismatch: $OFFER_PLAN"
if printf '%s' "$OFFER_PLAN" | "$JSONQ" has data.offer_id; then
    mkt_die "offer plan preview mismatch: $OFFER_PLAN"
fi
if printf '%s' "$OFFER_PLAN" | "$JSONQ" has data.seller_pubkey; then
    mkt_die "offer plan preview mismatch: $OFFER_PLAN"
fi
OFFER_COUNT="$(mkt_native "$MKT_DD_A" "$A_RPC" core storage query \
    --input='{"sql":"SELECT COUNT(*) AS n FROM file_offers"}' || true)"
[ "$(printf '%s' "$OFFER_COUNT" | mkt_jget data.rows[0][0] 2>/dev/null || true)" = "0" ] ||
    mkt_die "offer plan mutated seller storage: $OFFER_COUNT"

mkt_note "seller commits the offer (seal, persist, bind, flood)"
OFFER_COMMIT="$(printf '%s' "{\"filepath\":\"$FIXTURE\",\"price_per_mb_zat\":$PRICE_PER_MB_ZAT,\"confirm\":true}" \
    | mkt_native "$MKT_DD_A" "$A_RPC" app market offer --input=- || true)"
printf '%s' "$OFFER_COMMIT" | "$JSONQ" eq ok true ||
    mkt_die "offer commit refused: $OFFER_COMMIT"
printf '%s' "$OFFER_COMMIT" | "$JSONQ" eq data.stage committed ||
    mkt_die "offer commit refused: $OFFER_COMMIT"
printf '%s' "$OFFER_COMMIT" | "$JSONQ" eq data.committed true ||
    mkt_die "offer commit refused: $OFFER_COMMIT"
printf '%s' "$OFFER_COMMIT" | "$JSONQ" eq data.idempotent_replay false ||
    mkt_die "offer commit refused: $OFFER_COMMIT"
printf '%s' "$OFFER_COMMIT" | "$JSONQ" eq data.announced true ||
    mkt_die "offer commit refused: $OFFER_COMMIT"
printf '%s' "$OFFER_COMMIT" | "$JSONQ" eq data.root_hash "$EXPECT_ROOT" ||
    mkt_die "offer commit refused: $OFFER_COMMIT"
OFFER_ID="$(printf '%s' "$OFFER_COMMIT" | "$JSONQ" get data.offer_id)" ||
    mkt_die "offer commit refused: $OFFER_COMMIT"
mkt_hex64 "$OFFER_ID" || mkt_die "offer commit refused: $OFFER_COMMIT"
seller_pubkey="$(printf '%s' "$OFFER_COMMIT" | "$JSONQ" get data.seller_pubkey)" ||
    mkt_die "offer commit refused: $OFFER_COMMIT"
[ "${#seller_pubkey}" -eq 64 ] || mkt_die "offer commit refused: $OFFER_COMMIT"
mkt_note "seller offer committed: offer_id=$OFFER_ID"

# The seller's pre-gossip wire row: the reference every later comparison
# must reproduce byte-for-byte.
A_WIRE_PRE="$(mod_wire_rows "$MKT_DD_A" "$A_RPC")"
[ -n "$A_WIRE_PRE" ] || mkt_die "seller wire row snapshot failed"
[ "$(mod_review_col "$MKT_DD_A" "$A_RPC")" = "unreviewed" ] ||
    mkt_die "seller's own offer did not ingest as unreviewed"

# ── Phase 2: the offer gossips to the buyer ──────────────────────────
# The default profile HIDES unreviewed offers, so the gossip wait polls
# the explicit open view — the offer being listed there is itself the
# first ingest proof (hidden != absent).
mkt_note "waiting for the signed offer to gossip to the buyer"
LIST_DEADLINE=$(( $(date +%s) + MKT_WAIT ))
while :; do
    BUYER_OPEN="$(mod_list "$MKT_DD_B" "$B_RPC" open || true)"
    case "$BUYER_OPEN" in
        *"$OFFER_ID"*) break ;;
    esac
    [ "$(date +%s)" -lt "$LIST_DEADLINE" ] ||
        mkt_die "offer never gossiped to the buyer: $BUYER_OPEN"
    sleep 1
done
B_WIRE_PRE="$(mod_wire_rows "$MKT_DD_B" "$B_RPC")"
[ -n "$B_WIRE_PRE" ] || mkt_die "buyer wire row snapshot failed"
[ "$B_WIRE_PRE" = "$A_WIRE_PRE" ] ||
    mkt_die "gossiped wire row differs from the seller's: A=$A_WIRE_PRE B=$B_WIRE_PRE"
[ "$(mod_review_col "$MKT_DD_B" "$B_RPC")" = "unreviewed" ] ||
    mkt_die "buyer did not ingest the offer as unreviewed"

# ── Phase 3: the boot-default profile HIDES the unreviewed offer ─────
mkt_note "buyer default profile (general-audience.v1) must hide the unreviewed offer"
B_DEFAULT="$(mod_list "$MKT_DD_B" "$B_RPC" || true)"
mod_assert_hidden "$B_DEFAULT" x "general-audience.v1"

mkt_note "buyer moderation status names the active profile and the unreviewed count"
B_STATUS="$(mkt_native "$MKT_DD_B" "$B_RPC" app market moderation status || true)"
printf '%s' "$B_STATUS" | "$JSONQ" eq ok true ||
    mkt_die "moderation status mismatch: $B_STATUS"
printf '%s' "$B_STATUS" | "$JSONQ" eq data.active_profile general-audience.v1 ||
    mkt_die "moderation status mismatch: $B_STATUS"
prof_n="$(printf '%s' "$B_STATUS" | "$JSONQ" count data.available_profiles)" ||
    mkt_die "moderation status mismatch: $B_STATUS"
prof_found=0
prof_i=0
while [ "$prof_i" -lt "$prof_n" ]; do
    prof="$(printf '%s' "$B_STATUS" | "$JSONQ" get "data.available_profiles[$prof_i]")" ||
        mkt_die "moderation status mismatch: $B_STATUS"
    [ "$prof" = "open-view" ] && prof_found=1
    prof_i=$((prof_i + 1))
done
[ "$prof_found" = 1 ] || mkt_die "moderation status mismatch: $B_STATUS"
unreviewed="$(printf '%s' "$B_STATUS" | "$JSONQ" get data.review_counts.unreviewed 2>/dev/null || true)"
[ "${unreviewed:-0}" -ge 1 ] || mkt_die "moderation status mismatch: $B_STATUS"
printf '%s' "$B_STATUS" | "$JSONQ" eq data.view_filter_only true ||
    mkt_die "moderation status mismatch: $B_STATUS"
printf '%s' "$B_STATUS" | "$JSONQ" eq data.review_counts_live true ||
    mkt_die "moderation status mismatch: $B_STATUS"

# ── Phase 4: the explicit per-request opt-in shows it, annotated ─────
mkt_note "buyer open override must show the same offer annotated unreviewed"
B_OPEN="$(mod_list "$MKT_DD_B" "$B_RPC" open || true)"
mod_assert_shown "$B_OPEN" x unreviewed open-view

# ── Phase 5: switch B's node default to open-view ────────────────────
mkt_note "switching the buyer node default to open-view (plan/commit)"
mod_profile_set "$MKT_DD_B" "$B_RPC" open-view general-audience.v1
B_DEFAULT_OPEN="$(mod_list "$MKT_DD_B" "$B_RPC" || true)"
mod_assert_shown "$B_DEFAULT_OPEN" x unreviewed open-view
[ -f "$MKT_DD_B/market/moderation.v1" ] ||
    mkt_die "profile commit did not persist market/moderation.v1"
POLICY_BODY="$(cat "$MKT_DD_B/market/moderation.v1")"
case "$POLICY_BODY" in
    *"profile=open-view"*) : ;;
    *) mkt_die "persisted policy does not name open-view: $POLICY_BODY" ;;
esac

# ── Phase 6: back to general-audience — hidden again ─────────────────
mkt_note "switching the buyer node default back to general-audience.v1"
mod_profile_set "$MKT_DD_B" "$B_RPC" general-audience.v1 open-view
B_DEFAULT_GA="$(mod_list "$MKT_DD_B" "$B_RPC" || true)"
mod_assert_hidden "$B_DEFAULT_GA" x "general-audience.v1"

# ── Phase 7: B's own review mark drives visibility; A disagrees ──────
mkt_note "buyer marks the offer reviewed_ok: B shows it, A's default still hides the SAME offer_id"
mod_review_set "$MKT_DD_B" "$B_RPC" reviewed_ok unreviewed
B_REVIEWED="$(mod_list "$MKT_DD_B" "$B_RPC" || true)"
mod_assert_shown "$B_REVIEWED" x reviewed_ok general-audience.v1
# The two-node disagreement proof: A never marked anything, so A's own
# default list hides the same offer_id while B's shows it. Moderation is
# per-node view filtering, not a network-wide verdict.
A_DEFAULT="$(mod_list "$MKT_DD_A" "$A_RPC" || true)"
mod_assert_hidden "$A_DEFAULT" x "general-audience.v1"
A_OPEN="$(mod_list "$MKT_DD_A" "$A_RPC" open || true)"
mod_assert_shown "$A_OPEN" x unreviewed open-view
mkt_note "disagreement proven: B lists $OFFER_ID as reviewed_ok, A hides it as unreviewed"

# ── Phase 8: sensitive hides again; the open view keeps showing ──────
mkt_note "buyer marks the offer sensitive: default hides, open view shows it annotated"
mod_review_set "$MKT_DD_B" "$B_RPC" sensitive reviewed_ok
B_SENSITIVE="$(mod_list "$MKT_DD_B" "$B_RPC" || true)"
mod_assert_hidden "$B_SENSITIVE" x "general-audience.v1"
B_SENSITIVE_OPEN="$(mod_list "$MKT_DD_B" "$B_RPC" open || true)"
mod_assert_shown "$B_SENSITIVE_OPEN" x sensitive open-view

# ── Phase 9: hidden != rejected; the wire round-tripped unchanged ────
mkt_note "verifying gossip storage and protocol-validity separation"
A_COUNT="$(mkt_native "$MKT_DD_A" "$A_RPC" core storage query \
    --input='{"sql":"SELECT COUNT(*) AS n FROM file_offers"}' || true)"
[ "$(printf '%s' "$A_COUNT" | mkt_jget data.rows[0][0] 2>/dev/null || true)" = "1" ] ||
    mkt_die "seller file_offers row count is not 1: $A_COUNT"
B_COUNT="$(mkt_native "$MKT_DD_B" "$B_RPC" core storage query \
    --input='{"sql":"SELECT COUNT(*) AS n FROM file_offers"}' || true)"
[ "$(printf '%s' "$B_COUNT" | mkt_jget data.rows[0][0] 2>/dev/null || true)" = "1" ] ||
    mkt_die "buyer file_offers row count is not 1 (hidden != rejected): $B_COUNT"
# review_state is the ONLY column the two nodes may disagree on.
[ "$(mod_review_col "$MKT_DD_A" "$A_RPC")" = "unreviewed" ] ||
    mkt_die "seller review_state moved — moderation must be buyer-local here"
[ "$(mod_review_col "$MKT_DD_B" "$B_RPC")" = "sensitive" ] ||
    mkt_die "buyer review_state is not the sensitive mark just set"
# The signed wire columns are byte-identical on both nodes and unchanged
# on each across every profile switch and review mark.
A_WIRE_POST="$(mod_wire_rows "$MKT_DD_A" "$A_RPC")"
B_WIRE_POST="$(mod_wire_rows "$MKT_DD_B" "$B_RPC")"
[ "$A_WIRE_POST" = "$A_WIRE_PRE" ] ||
    mkt_die "seller wire columns changed across the acceptance: pre=$A_WIRE_PRE post=$A_WIRE_POST"
[ "$B_WIRE_POST" = "$B_WIRE_PRE" ] ||
    mkt_die "moderation altered the buyer's signed wire columns: pre=$B_WIRE_PRE post=$B_WIRE_POST"
[ "$A_WIRE_POST" = "$B_WIRE_POST" ] ||
    mkt_die "signed wire diverged between nodes: A=$A_WIRE_POST B=$B_WIRE_POST"

mkt_note "PASS: two-daemon moderation acceptance — one signed offer, two profiles: general-audience hides the unreviewed offer with an honest hidden_count, the open opt-in and the open-view node default show it annotated, reviewed_ok/sensitive marks drive per-node visibility, A and B legitimately disagree about the same offer_id, the offer stays gossip-stored on both (hidden != rejected), and the signed wire columns are byte-identical and untouched by every moderation action (review_state never leaves the node)"
