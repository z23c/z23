#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# B5 acceptance (docs/work/MARKET_ONION_DELIVERY.md): two isolated regtest
# daemons, BOTH booted with -tor and NEITHER with -externalip, run the full
# P2P file-market trade with the DELIVERY leg routed over the seller's
# ephemeral onion service. A (seller) commits a signed paid offer whose v2
# wire names endpoint_type=onion; it gossips to B (buyer) over the clearnet
# loopback P2P link (the P2P link is not the leg under test); B plans and
# commits a real Sapling payment, is refused delivery before confirmation
# (authorize-before-read — served THROUGH the onion route), then, after one
# mined block, retrieves the file as 60 KiB slices over real Tor circuits
# via GET /market/chunk/<signed-request-hex>?slice=k. The proof that no
# clearnet file-service connection was used: the onion offer carries no
# usable clearnet endpoint (peer_ip zero, peer_port 0), and both tor.log
# files name the /market/chunk traffic. The negative half restarts B
# WITHOUT -tor before any successful retrieve and asserts the named
# ONION_DELIVERY_UNAVAILABLE refusal — there is never a clearnet fallback
# against a signed onion offer.
#
# Modelled on tools/dev/market_acceptance.sh: same setsid isolation, port
# refuse-set discipline, wallet-custody recipe, mining cadence, pgid
# cleanup, phase banners. Public Tor network reachability is REQUIRED: if
# neither node can bootstrap, the script FAILS with a named reason — it
# never silently passes.
#
# Knobs: MKT_WAIT (chain/sync gate budget, s), ONI_TOR_WAIT (Tor bootstrap
# + onion address budget, s), ONI_RETRIEVE_WAIT (onion retrieval budget,
# s — per-slice real Tor round trips plus seller-projection retries),
# MKT_KEEP=1 preserves the scratch tree.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NODE_BIN="${ZCL_NODE_BIN:-$REPO_ROOT/build/bin/zclassic23}"
RPC_BIN="${ZCL_RPC_BIN:-$REPO_ROOT/build/bin/zcl-rpc}"
JSONQ="${JSONQ:-$REPO_ROOT/build/bin/jsonq}"

MKT_LIVE_PORTS="8023 8033 8034 8035 8043 8044 8045 8046 8232 8443 \
18034 18232 18234 18243 18244 18245 18246"
# Fresh block vs the siblings (market: 395xx quads + 20030/20031 + 39999,
# dht: 29211-29273, science: 39111-39123, p2p 20022-20027 + 18033) and vs
# this host's zclassic23-live instance (39311/39312). The +11966 Tor
# bootstrap SocksPorts land at 32006/32007 and are asserted too.
A_PORT=20040; A_RPC=39611; A_FS=39612; A_HTTPS=39613
B_PORT=20041; B_RPC=39621; B_FS=39622; B_HTTPS=39623
DEAD_SINK=39998
MKT_WAIT="${MKT_WAIT:-90}"
ONI_TOR_WAIT="${ONI_TOR_WAIT:-420}"
ONI_RETRIEVE_WAIT="${ONI_RETRIEVE_WAIT:-600}"
MKT_WORK=""; MKT_DD_A=""; MKT_DD_B=""; MKT_PGID_A=""; MKT_PGID_B=""
MKT_EXTRA_FLAGS=()
MKT_CLEANED=0
MKT_KEEP="${MKT_KEEP:-0}"
# Throwaway passphrases for the wallet-custody recipe (never argv: they
# ride the wallet-passphrase credential file and --input=- stdin only).
MKT_WALLET_PASS="market-onion-acceptance-wallet-pass"
MKT_BACKUP_PASS="market-onion-acceptance-backup-pass"

# Trade terms: a ONE-chunk 150 KiB fixture. Onion delivery slices a chunk
# into 60 KiB pieces (the dynhost webserver response cap is 64 KiB), so
# 150 KiB = 3 slices over real Tor round trips — the clearnet script's
# 100 MiB fixture would be ~1700 Tor fetches. chunks_paid is num_chunks.
PRICE_PER_MB_ZAT=30000
FIXTURE_BYTES=$((150 * 1024))
EXPECTED_CHUNKS=1
EXPECTED_SLICES=3
IDEMPOTENCY_KEY="market-onion-acceptance-purchase-1"

mkt_die() {
    echo "market-onion-acceptance: FATAL: $*" >&2
    if [ -n "$MKT_WORK" ] && [ -d "$MKT_WORK" ]; then
        printf '%s\n' "$*" >"$MKT_WORK/FAILURE"
    fi
    exit 2
}
mkt_note() { echo "market-onion-acceptance: $*"; }

mkt_assert_port() {
    local p="$1" live
    for live in $MKT_LIVE_PORTS; do
        [ "$p" = "$live" ] && mkt_die "port $p is in the live refuse-set"
    done
    [ -n "$(ss -tlnH "sport = :$p" 2>/dev/null)" ] &&
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
            "$REPO_ROOT"/test-tmp/zcl23-oniacc-*) rm -rf "$MKT_WORK" ;;
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
hexrev() {
    local h="$1" i=${#1} out=""
    while [ "$i" -gt 0 ]; do
        i=$((i-2))
        out="${out}${h:$i:2}"
    done
    printf '%s\n' "$out"
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
    # (WKS1); -operator-lane=dev arms the dev wallet scope the purchase
    # plan/commit leaves require. -regtestshielded activates
    # Overwinter+Sapling from genesis on BOTH nodes. -tor runs the real
    # embedded Tor (vendor/tor/libtor.a is linked in this build); its
    # DataDirectory is <datadir>/tor_data and its bootstrap SocksPort is
    # p2p_port+11966, so the two nodes never collide. -externalip is
    # DELIBERATELY ABSENT on both: it is the explicit public-endpoint
    # opt-in that would pin offer commits to the clearnet v1 wire.
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

# Tor bootstrap to the PUBLIC network takes ~10-60 s per node (warm
# tor_data is faster) and can be impossible on a host without Tor
# reachability. Poll the explorer dumpstate subsystem for the node's
# ephemeral onion address (`core status` does NOT carry it — the
# `health.checks.onion_address` surface is the in-process health
# projection; over RPC the address lives at
# `ops state --subsystem=explorer` → data.state.onion_address, fed by
# explorer_dump_state_json). On timeout, FAIL with the last bootstrap
# line — never silently skip the onion proof.
oni_onion_address() {
    local json addr
    json="$(mkt_native "$1" "$2" ops state --subsystem=explorer 2>/dev/null || true)"
    addr="$(printf '%s' "$json" | "$JSONQ" get data.state.onion_address 2>/dev/null || true)"
    [ -n "$addr" ] ||
        addr="$(printf '%s' "$json" | "$JSONQ" get state.onion_address 2>/dev/null || true)"
    [ -n "$addr" ] ||
        addr="$(printf '%s' "$json" | "$JSONQ" get data.onion_address 2>/dev/null || true)"
    printf '%s\n' "$addr"
}
oni_bootstrap_tail() {
    grep -a "Bootstrapped" "$1/tor.log" 2>/dev/null | tail -1
}
oni_wait_onion_address() {
    local dd="$1" rpc="$2" label="$3" deadline addr
    deadline=$(( $(date +%s) + ONI_TOR_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        addr="$(oni_onion_address "$dd" "$rpc" || true)"
        case "$addr" in
            *.onion) printf '%s\n' "$addr"; return 0 ;;
        esac
        sleep 2
    done
    mkt_die "$label never published an onion address within ${ONI_TOR_WAIT}s \
— host may lack public Tor network reachability (last bootstrap line: \
$(oni_bootstrap_tail "$dd" || echo none))"
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
# The money freshness classifier fails closed on finding_peers; the sync
# FSM only leaves it behind a peer it can sync FROM (outbound).
mkt_wait_sync_live() {
    local dd="$1" rpc="$2" deadline state
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        state="$(mkt_rpc "$dd" "$rpc" downloadstats 2>/dev/null \
            | mkt_jget result.sync_state 2>/dev/null || true)"
        case "$state" in
            blocks_download|connecting_blocks|at_tip) return 0 ;;
        esac
        sleep 0.5
    done
    return 1
}
# The seller's market payment gate (market_payment_claim_ingest /
# market_payment_authorize_chunk) reads sync_get_state()==SYNC_AT_TIP as
# "chain current" and persists UNKNOWN otherwise; a node whose only links
# are inbound never leaves finding_peers, so the seller needs its own
# outbound link AND the full walk to at_tip before any payment arrives.
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
# The money gate reads the REDUCER pipeline, not the active chain: the
# authoritative coins tip AND H* must both reach the mined height.
mkt_wait_fold() {
    local dd="$1" rpc="$2" tip="$3" deadline dump coins hstar
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        dump="$(mkt_native "$dd" "$rpc" dumpstate reducer_frontier || true)"
        coins="$(printf '%s' "$dump" | mkt_jget state.coins_best_height 2>/dev/null || true)"
        hstar="$(printf '%s' "$dump" | mkt_jget state.hstar 2>/dev/null || true)"
        [ "$coins" = "$tip" ] && [ "$hstar" = "$tip" ] && return 0
        sleep 1
    done
    echo "market-onion-acceptance: reducer_frontier at stall: $dump" >&2
    return 1
}
# RPC-ready != chain-loaded: the money gate needs the active chain index,
# which loads after the RPC starts serving.
mkt_wait_chain_loaded() {
    local dd="$1" rpc="$2" tip="$3" deadline chain blocks ibd
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        chain="$(mkt_rpc "$dd" "$rpc" getblockchaininfo 2>/dev/null || true)"
        blocks="$(printf '%s' "$chain" | mkt_jget result.blocks 2>/dev/null || true)"
        ibd="$(printf '%s' "$chain" | mkt_jget result.initialblockdownload 2>/dev/null || true)"
        [ "$blocks" = "$tip" ] && [ "$ibd" != "true" ] && return 0
        sleep 1
    done
    return 1
}
# The purchase plan's reservation reads the vault read model's confirmed
# custody, which lags the reducer fold while the wallet re-derives its
# spendable coins.
mkt_wait_spendable() {
    local dd="$1" rpc="$2" deadline spend
    deadline=$(( $(date +%s) + MKT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        spend="$(mkt_native "$dd" "$rpc" dumpstate vault 2>/dev/null \
            | mkt_jget state.zcl.spendable 2>/dev/null || true)"
        case "$spend" in
            ''|*[!0-9]*) ;;
            *) [ "$spend" -gt 0 ] && return 0 ;;
        esac
        sleep 1
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

for port in $A_PORT $A_RPC $A_FS $A_HTTPS $B_PORT $B_RPC $B_FS $B_HTTPS \
    $((A_PORT + 11966)) $((B_PORT + 11966)); do
    mkt_assert_port "$port"
done
[ -x "$NODE_BIN" ] && [ -x "$RPC_BIN" ] || mkt_die "build node and RPC binaries first"
[ -x "$JSONQ" ] || mkt_die "build/bin/jsonq is missing — run make jsonq"
mkdir -p "$REPO_ROOT/test-tmp"
MKT_WORK="$(mktemp -d "$REPO_ROOT/test-tmp/zcl23-oniacc-XXXXXX")"
MKT_DD_A="$MKT_WORK/a"; MKT_DD_B="$MKT_WORK/b"
MKT_CONTENT="$MKT_WORK/content"
MKT_DOWNLOADS="$MKT_WORK/downloads"
mkdir -p "$MKT_DD_A" "$MKT_DD_B" "$MKT_CONTENT" "$MKT_DOWNLOADS"
FIXTURE="$MKT_CONTENT/seller-fixture.bin"
DESTINATION="$MKT_DOWNLOADS/bought-copy.bin"
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

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
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

static int hash_chunk_stream(FILE *f, int writing, uint64_t size,
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
            if (writing) {
                for (size_t i = 0; i < take; i++)
                    buf[i] = (unsigned char)((written +
                        (off + (uint64_t)i) * 11ull) & 0xFFull);
                if (fwrite(buf, 1, take, f) != take) return -1;
            } else {
                if (fread(buf, 1, take, f) != take) return -1;
            }
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

static void cmd_write(const char *path, uint64_t price, uint64_t size)
{
    unsigned char digests[64 * 32];
    int nchunks = 0;
    FILE *f = fopen(path, "wb");
    if (!f) die("open write failed");
    if (size == 0 ||
        (size + (uint64_t)CHUNK - 1ull) / (uint64_t)CHUNK > 64ull) {
        fclose(f);
        die("size out of range");
    }
    if (hash_chunk_stream(f, 1, size, digests, &nchunks) != 0) {
        fclose(f);
        die("write failed");
    }
    fclose(f);
    unsigned char root[32];
    char hex[65];
    sha3_256(digests, (size_t)nchunks * 32u, root);
    digest_hex(root, hex);
    printf("%llu %s %llu\n",
           (unsigned long long)size, hex,
           (unsigned long long)price_total(size, price));
}

static void cmd_root(const char *path)
{
    unsigned char digests[64 * 32];
    int nchunks = 0;
    FILE *f = fopen(path, "rb");
    if (!f) die("open read failed");
    if (fseek(f, 0, SEEK_END) != 0) die("seek failed");
    long sz = ftell(f);
    if (sz < 0) die("tell failed");
    if (fseek(f, 0, SEEK_SET) != 0) die("seek failed");
    uint64_t size = (uint64_t)sz;
    if (size == 0 ||
        (size + (uint64_t)CHUNK - 1ull) / (uint64_t)CHUNK > 64ull) {
        fclose(f);
        die("size out of range");
    }
    if (hash_chunk_stream(f, 0, size, digests, &nchunks) != 0) {
        fclose(f);
        die("read failed");
    }
    fclose(f);
    unsigned char root[32];
    char hex[65];
    sha3_256(digests, (size_t)nchunks * 32u, root);
    digest_hex(root, hex);
    printf("%s\n", hex);
}

static void b32encode(const unsigned char *in, size_t inlen, char *out)
{
    static const char alph[] = "abcdefghijklmnopqrstuvwxyz234567";
    uint64_t buf = 0;
    int bits = 0;
    size_t j = 0;
    for (size_t i = 0; i < inlen; i++) {
        buf = (buf << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[j++] = alph[(buf >> bits) & 31];
        }
    }
    if (bits)
        out[j++] = alph[(buf << (5 - bits)) & 31];
    out[j] = '\0';
}

static void cmd_onion(const char *hex)
{
    unsigned char pub[32];
    if (!hex || strlen(hex) != 64) die("onion pubkey must be 64 hex chars");
    for (int i = 0; i < 32; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) die("onion pubkey is not hex");
        pub[i] = (unsigned char)((hi << 4) | lo);
    }
    unsigned char msg[15 + 32 + 1];
    memcpy(msg, ".onion checksum", 15);
    memcpy(msg + 15, pub, 32);
    msg[47] = 0x03;
    unsigned char digest[32];
    sha3_256(msg, 48, digest);
    unsigned char raw[35];
    memcpy(raw, pub, 32);
    raw[32] = digest[0];
    raw[33] = digest[1];
    raw[34] = 0x03;
    char addr[57];
    b32encode(raw, 35, addr);
    printf("%s.onion\n", addr);
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "write") == 0 && argc == 5) {
        cmd_write(argv[2], parse_u64(argv[3]), parse_u64(argv[4]));
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "root") == 0 && argc == 3) {
        cmd_root(argv[2]);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "onion") == 0 && argc == 3) {
        cmd_onion(argv[2]);
        return 0;
    }
    die("usage: fixture_gen write PATH PRICE SIZE | root PATH | onion PUBKEY_HEX");
}
C
cc -std=c23 -O2 -I"$REPO_ROOT/platform/modules/sha3/include" -I"$REPO_ROOT/platform/modules/base/include" \
    -o "$FIXTURE_GEN" "$MKT_WORK/fixture_gen.c" \
    "$REPO_ROOT/platform/modules/sha3/src/sha3.c" || mkt_die "fixture_gen compile failed"
read -r FIXTURE_SIZE EXPECT_ROOT EXPECT_TOTAL_ZAT \
    <<<"$("$FIXTURE_GEN" write "$FIXTURE" "$PRICE_PER_MB_ZAT" "$FIXTURE_BYTES")" \
    || mkt_die "fixture build failed"

# Wallet custody: boot both nodes with a passphrase credential so key writes
# encrypt at rest (WKS1). The seller-key envelope (metadata DEK) and the
# buyer's money gate both refuse a locked or plaintext wallet.
MKT_CRED_DIR="$MKT_WORK/cred"
install -d -m 700 "$MKT_CRED_DIR"
install -m 600 /dev/null "$MKT_CRED_DIR/wallet-passphrase"
printf '%s\n' "$MKT_WALLET_PASS" >"$MKT_CRED_DIR/wallet-passphrase"
export CREDENTIALS_DIRECTORY="$MKT_CRED_DIR"

mkt_note "booting seller A and buyer B (both -tor, neither -externalip)"
MKT_EXTRA_FLAGS=("-tor")
MKT_PGID_A="$(mkt_spawn "$MKT_DD_A" "$A_PORT" "$A_RPC" "$A_FS" "$A_HTTPS" "127.0.0.1:$DEAD_SINK")"
mkt_wait_rpc "$MKT_DD_A" "$A_RPC" "$MKT_PGID_A" || mkt_die "seller A RPC warmup failed"
MKT_PGID_B="$(mkt_spawn "$MKT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$A_PORT")"
mkt_wait_rpc "$MKT_DD_B" "$B_RPC" "$MKT_PGID_B" || mkt_die "buyer B RPC warmup failed"
! grep -qaF "unrecognized flag" "$MKT_DD_A/node.log" "$MKT_DD_B/node.log" ||
    mkt_die "a boot flag was not recognized"

# ── Phase 0: both nodes bootstrap Tor to the public network ──────────
# No reachability is a named FAIL, never a silent pass (see
# oni_wait_onion_address).
mkt_note "waiting for both embedded Tor instances to publish onion addresses"
A_ONION="$(oni_wait_onion_address "$MKT_DD_A" "$A_RPC" "seller A")"
mkt_note "seller A onion service: $A_ONION"
B_ONION="$(oni_wait_onion_address "$MKT_DD_B" "$B_RPC" "buyer B")"
mkt_note "buyer B onion service: $B_ONION"

mkt_note "mining 101 spendable regtest blocks to the buyer"
BUYER_ADDR="$(b_rpc getnewaddress | mkt_result)"
mkt_mine_to_address b_rpc 101 "$BUYER_ADDR"
mkt_wait_height "$MKT_DD_A" "$A_RPC" 101 || mkt_die "A did not sync the funding chain"
mkt_wait_fold "$MKT_DD_B" "$B_RPC" 101 || mkt_die "B reducer fold did not reach the funding tip"

# The buyer's purchase money gate reads the forward-folded coins set, whose
# authority stamps land only at boot: restart B (the funded node) so they
# stamp, then re-link with an operator-directed onetry so B owns the
# OUTBOUND peer the money-freshness classifier demands (it fails closed on
# finding_peers). A stays up on the dead sink the whole time, so no
# already-connected skip can delay the link. B's tor_data is warm, so this
# bootstrap is the fast one.
mkt_note "restarting B so the forward-folded coins set stamps its authority"
mkt_kill_group "$MKT_PGID_B"; MKT_PGID_B=""
MKT_PGID_B="$(mkt_spawn "$MKT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$DEAD_SINK")"
mkt_wait_rpc "$MKT_DD_B" "$B_RPC" "$MKT_PGID_B" || mkt_die "B custody restart failed"
B_ONION="$(oni_wait_onion_address "$MKT_DD_B" "$B_RPC" "buyer B (custody restart)")"
mkt_wait_fold "$MKT_DD_B" "$B_RPC" 101 || mkt_die "B reducer fold did not survive the restart"
b_rpc addnode "\"127.0.0.1:$A_PORT\"" "\"onetry\"" >/dev/null || true
mkt_wait_connected "$MKT_DD_B" "$B_RPC" || mkt_die "B never connected outbound to A"
mkt_wait_sync_live "$MKT_DD_B" "$B_RPC" || mkt_die "B sync never left finding_peers"
mkt_wait_chain_loaded "$MKT_DD_B" "$B_RPC" 101 || mkt_die "B active chain index did not load"

# Symmetric one-shot link: the seller's paid-chunk gate reads
# sync_get_state()==SYNC_AT_TIP, which a listen-only node never reaches.
a_rpc addnode "\"127.0.0.1:$B_PORT\"" "\"onetry\"" >/dev/null || true
mkt_wait_connected "$MKT_DD_A" "$A_RPC" || mkt_die "A never connected outbound to B"
mkt_wait_at_tip "$MKT_DD_A" "$A_RPC" || mkt_die "A sync never reached at_tip"

# The restart re-locks the encrypted-at-rest wallet (and A booted locked):
# unlock both (passphrase via --input=- only), re-top the RAM-only keypool
# bookkeeping, take the current-key encrypted backup, then wait for the
# buyer's spendable custody to turn positive.
mkt_note "unlocking both wallets and taking current-key encrypted backups"
mkt_unlock_wallet "$MKT_DD_A" "$A_RPC" || mkt_die "A wallet unlock failed"
mkt_unlock_wallet "$MKT_DD_B" "$B_RPC" || mkt_die "B wallet unlock failed"
a_rpc getnewaddress | mkt_result >/dev/null || mkt_die "A keypool top-up failed"
b_rpc getnewaddress | mkt_result >/dev/null || mkt_die "B keypool top-up failed"
# The offer's payee gate refuses an unseeded Sapling keystore; minting the
# seller's first z-address generates + persists the seed it checks for.
a_rpc z_getnewaddress | mkt_result >/dev/null || mkt_die "A sapling keystore seeding failed"
mkt_backup_wallet "$MKT_DD_A" "$A_RPC" || mkt_die "A custody backup failed"
mkt_backup_wallet "$MKT_DD_B" "$B_RPC" || mkt_die "B custody backup failed"
mkt_wait_spendable "$MKT_DD_B" "$B_RPC" || mkt_die "B vault spendable never became positive"

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
[ "$(a_rpc zmarket_list | mkt_result)" = "[]" ] ||
    mkt_die "offer plan touched the seller gossip cache"

mkt_note "seller commits the offer — Tor ready + no -externalip must select the v2 onion endpoint"
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
printf '%s' "$OFFER_COMMIT" | "$JSONQ" eq data.endpoint_source onion ||
    mkt_die "offer commit refused: $OFFER_COMMIT"
OFFER_ID="$(printf '%s' "$OFFER_COMMIT" | "$JSONQ" get data.offer_id)" ||
    mkt_die "offer commit refused: $OFFER_COMMIT"
mkt_hex64 "$OFFER_ID" || mkt_die "offer commit refused: $OFFER_COMMIT"
seller_pubkey="$(printf '%s' "$OFFER_COMMIT" | "$JSONQ" get data.seller_pubkey)" ||
    mkt_die "offer commit refused: $OFFER_COMMIT"
[ "${#seller_pubkey}" -eq 64 ] || mkt_die "offer commit refused: $OFFER_COMMIT"
mkt_note "seller offer committed on the onion endpoint: offer_id=$OFFER_ID"

# The committed offer must name A's OWN onion service: endpoint_type=1,
# peer_port=0, and onion_pubkey must re-derive the exact onion address the
# health projection published (Tor v3: base32(pubkey || sha3-256(".onion
# checksum" || pubkey || 0x03)[:2] || 0x03) + ".onion").
A_OFFER_ROW="$(mkt_native "$MKT_DD_A" "$A_RPC" core storage query \
    --input='{"sql":"SELECT endpoint_type, peer_port, hex(onion_pubkey) FROM file_offers"}' || true)"
printf '%s' "$A_OFFER_ROW" | "$JSONQ" eq ok true ||
    mkt_die "seller offer endpoint row mismatch: $A_OFFER_ROW"
[ "$(printf '%s' "$A_OFFER_ROW" | "$JSONQ" count data.rows)" = "1" ] ||
    mkt_die "seller offer endpoint row mismatch: $A_OFFER_ROW"
printf '%s' "$A_OFFER_ROW" | "$JSONQ" eq data.rows[0][0] 1 ||
    mkt_die "seller offer endpoint row mismatch: $A_OFFER_ROW"
printf '%s' "$A_OFFER_ROW" | "$JSONQ" eq data.rows[0][1] 0 ||
    mkt_die "seller offer endpoint row mismatch: $A_OFFER_ROW"
onion_pub="$(printf '%s' "$A_OFFER_ROW" | "$JSONQ" get data.rows[0][2])" ||
    mkt_die "seller offer endpoint row mismatch: $A_OFFER_ROW"
[ "$("$FIXTURE_GEN" onion "$onion_pub")" = "$A_ONION" ] ||
    mkt_die "seller offer endpoint row mismatch: $A_OFFER_ROW"

# ── Phase 2: the offer gossips to the buyer ──────────────────────────
mkt_note "waiting for the signed v2 offer to gossip to the buyer"
LIST_DEADLINE=$(( $(date +%s) + MKT_WAIT ))
while :; do
    BUYER_LIST="$(mkt_native "$MKT_DD_B" "$B_RPC" app market list 2>/dev/null || true)"
    case "$BUYER_LIST" in
        *"$OFFER_ID"*) break ;;
    esac
    [ "$(date +%s)" -lt "$LIST_DEADLINE" ] ||
        mkt_die "offer never gossiped to the buyer: $BUYER_LIST"
    sleep 1
done
BUYER_ENTRY="$(b_rpc zmarket_list | mkt_result)"
buyer_kind="$(printf '%s' "$BUYER_ENTRY" | "$JSONQ" type .)" ||
    mkt_die "buyer market list entry mismatch: $BUYER_ENTRY"
if [ "$buyer_kind" = "array" ]; then
    buyer_n="$(printf '%s' "$BUYER_ENTRY" | "$JSONQ" count .)" ||
        mkt_die "buyer market list entry mismatch: $BUYER_ENTRY"
    buyer_pref=""
else
    buyer_n="$(printf '%s' "$BUYER_ENTRY" | "$JSONQ" count offers)" ||
        mkt_die "buyer market list entry mismatch: $BUYER_ENTRY"
    buyer_pref="offers"
fi
buyer_match=0
buyer_i=0
while [ "$buyer_i" -lt "$buyer_n" ]; do
    if [ -n "$buyer_pref" ]; then
        buyer_at="${buyer_pref}[$buyer_i]"
    else
        buyer_at="[$buyer_i]"
    fi
    buyer_oid="$(printf '%s' "$BUYER_ENTRY" | "$JSONQ" get "$buyer_at.offer_id")" ||
        mkt_die "buyer market list entry mismatch: $BUYER_ENTRY"
    if [ "$buyer_oid" = "$OFFER_ID" ]; then
        buyer_match=$((buyer_match + 1))
        printf '%s' "$BUYER_ENTRY" | "$JSONQ" eq "$buyer_at.root_hash" "$EXPECT_ROOT" ||
            mkt_die "buyer market list entry mismatch: $BUYER_ENTRY"
        printf '%s' "$BUYER_ENTRY" | "$JSONQ" eq "$buyer_at.price_per_mb_zat" "$PRICE_PER_MB_ZAT" ||
            mkt_die "buyer market list entry mismatch: $BUYER_ENTRY"
        printf '%s' "$BUYER_ENTRY" | "$JSONQ" eq "$buyer_at.num_chunks" "$EXPECTED_CHUNKS" ||
            mkt_die "buyer market list entry mismatch: $BUYER_ENTRY"
        printf '%s' "$BUYER_ENTRY" | "$JSONQ" eq "$buyer_at.total_cost_zat" "$EXPECT_TOTAL_ZAT" ||
            mkt_die "buyer market list entry mismatch: $BUYER_ENTRY"
        # The onion endpoint carries NO usable clearnet address: the buyer
        # physically cannot open a clearnet file-service connection to the seller.
        printf '%s' "$BUYER_ENTRY" | "$JSONQ" eq "$buyer_at.authenticated" true ||
            mkt_die "buyer market list entry mismatch: $BUYER_ENTRY"
        printf '%s' "$BUYER_ENTRY" | "$JSONQ" eq "$buyer_at.peer_port" 0 ||
            mkt_die "buyer market list entry mismatch: $BUYER_ENTRY"
    fi
    buyer_i=$((buyer_i + 1))
done
[ "$buyer_match" = 1 ] || mkt_die "buyer market list entry mismatch: $BUYER_ENTRY"
B_OFFER_ROW="$(mkt_native "$MKT_DD_B" "$B_RPC" core storage query \
    --input="{\"sql\":\"SELECT endpoint_type, peer_port FROM file_offers WHERE offer_id=x'$OFFER_ID'\"}" || true)"
[ "$(printf '%s' "$B_OFFER_ROW" | "$JSONQ" count data.rows 2>/dev/null || true)" = "1" ] &&
    printf '%s' "$B_OFFER_ROW" | "$JSONQ" eq data.rows[0][0] 1 &&
    printf '%s' "$B_OFFER_ROW" | "$JSONQ" eq data.rows[0][1] 0 ||
    mkt_die "buyer stored the offer with a non-onion endpoint: $B_OFFER_ROW"

# ── Phase 3: buyer purchase plan + commit (real Sapling payment) ─────
mkt_note "buyer plans the full-file purchase"
PLAN=""
for try in $(seq 1 20); do
    PLAN="$(printf '%s' "{\"wallet_scope\":\"dev\",\"offer_id\":\"$OFFER_ID\",\"source_address\":\"$BUYER_ADDR\",\"chunk_start\":0,\"chunks_paid\":$EXPECTED_CHUNKS,\"idempotency_key\":\"$IDEMPOTENCY_KEY\"}" \
        | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase plan --input=- || true)"
    case "$PLAN" in
        *MONEY_STATE_NOT_CURRENT*|*MONEY_SNAPSHOT_CHANGED*) sleep 1 ;;
        *) break ;;
    esac
done
printf '%s' "$PLAN" | "$JSONQ" eq ok true ||
    mkt_die "purchase plan refused: $PLAN"
printf '%s' "$PLAN" | "$JSONQ" eq data.stage plan ||
    mkt_die "purchase plan refused: $PLAN"
printf '%s' "$PLAN" | "$JSONQ" eq data.committed false ||
    mkt_die "purchase plan refused: $PLAN"
printf '%s' "$PLAN" | "$JSONQ" eq data.spends_funds false ||
    mkt_die "purchase plan refused: $PLAN"
printf '%s' "$PLAN" | "$JSONQ" eq data.offer_id "$OFFER_ID" ||
    mkt_die "purchase plan refused: $PLAN"
printf '%s' "$PLAN" | "$JSONQ" eq data.amount_zat "$EXPECT_TOTAL_ZAT" ||
    mkt_die "purchase plan refused: $PLAN"
fee="$(printf '%s' "$PLAN" | "$JSONQ" get data.maximum_fee_zat)" ||
    mkt_die "purchase plan refused: $PLAN"
reserved="$(printf '%s' "$PLAN" | "$JSONQ" get data.reserved_zat)" ||
    mkt_die "purchase plan refused: $PLAN"
amount="$(printf '%s' "$PLAN" | "$JSONQ" get data.amount_zat)" ||
    mkt_die "purchase plan refused: $PLAN"
[ "$fee" -gt 0 ] && [ "$reserved" = "$((amount + fee))" ] ||
    mkt_die "purchase plan refused: $PLAN"
printf '%s' "$PLAN" | "$JSONQ" eq data.chunk_start 0 ||
    mkt_die "purchase plan refused: $PLAN"
chunks_paid="$(printf '%s' "$PLAN" | "$JSONQ" get data.chunks_paid)" ||
    mkt_die "purchase plan refused: $PLAN"
[ "$chunks_paid" -gt 0 ] || mkt_die "purchase plan refused: $PLAN"
printf '%s' "$PLAN" | "$JSONQ" eq data.state planned ||
    mkt_die "purchase plan refused: $PLAN"
printf '%s' "$PLAN" | "$JSONQ" eq data.idempotent_replay false ||
    mkt_die "purchase plan refused: $PLAN"
PLAN_ID="$(printf '%s' "$PLAN" | "$JSONQ" get data.plan_id)" ||
    mkt_die "purchase plan refused: $PLAN"
mkt_hex64 "$PLAN_ID" || mkt_die "purchase plan refused: $PLAN"
printf '%s' "$PLAN" | "$JSONQ" has data.commit_input ||
    mkt_die "purchase plan refused: $PLAN"
mkt_note "buyer purchase planned: plan_id=$PLAN_ID"

mkt_note "buyer commits the purchase (broadcasts the Sapling payment)"
COMMIT="$(printf '%s' "{\"wallet_scope\":\"dev\",\"plan_id\":\"$PLAN_ID\",\"confirm\":true}" \
    | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase commit --input=- || true)"
printf '%s' "$COMMIT" | "$JSONQ" eq ok true ||
    mkt_die "purchase commit refused: $COMMIT"
printf '%s' "$COMMIT" | "$JSONQ" eq data.stage committed ||
    mkt_die "purchase commit refused: $COMMIT"
printf '%s' "$COMMIT" | "$JSONQ" eq data.committed true ||
    mkt_die "purchase commit refused: $COMMIT"
printf '%s' "$COMMIT" | "$JSONQ" eq data.spends_funds true ||
    mkt_die "purchase commit refused: $COMMIT"
printf '%s' "$COMMIT" | "$JSONQ" eq data.idempotent_replay false ||
    mkt_die "purchase commit refused: $COMMIT"
printf '%s' "$COMMIT" | "$JSONQ" eq data.payment_notification_queued true ||
    mkt_die "purchase commit refused: $COMMIT"
printf '%s' "$COMMIT" | "$JSONQ" eq data.state mempool_accepted ||
    mkt_die "purchase commit refused: $COMMIT"
TXID="$(printf '%s' "$COMMIT" | "$JSONQ" get data.txid)" ||
    mkt_die "purchase commit refused: $COMMIT"
mkt_hex64 "$TXID" || mkt_die "purchase commit refused: $COMMIT"
claim_id="$(printf '%s' "$COMMIT" | "$JSONQ" get data.claim_id)" ||
    mkt_die "purchase commit refused: $COMMIT"
[ "${#claim_id}" -eq 64 ] || mkt_die "purchase commit refused: $COMMIT"
mkt_note "purchase payment broadcast: txid=$TXID"

# ── Phase 4: authorize-before-read — refused pre-confirmation, via onion ──
# The early retrieve dials A's onion service and the /market/chunk handler
# answers with the payment-gate refusal status: the onion route serves the
# authorize-before-read boundary, not just the happy path.
mkt_note "buyer retrieves before confirmation: the onion route must refuse"
EARLY_RETRIEVE="$(printf '%s' "{\"plan_id\":\"$PLAN_ID\",\"destination_path\":\"$DESTINATION\"}" \
    | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase retrieve --input=- || true)"
printf '%s' "$EARLY_RETRIEVE" | "$JSONQ" eq ok false ||
    mkt_die "pre-confirmation retrieve was not refused: $EARLY_RETRIEVE"
printf '%s' "$EARLY_RETRIEVE" | "$JSONQ" eq error.code DELIVERY_NOT_READY ||
    mkt_die "pre-confirmation retrieve was not refused: $EARLY_RETRIEVE"
early_msg="$(printf '%s' "$EARLY_RETRIEVE" | "$JSONQ" get error.message 2>/dev/null || true)"
case "$early_msg" in
    *PENDING*|*UNKNOWN*) ;;
    *) mkt_die "pre-confirmation retrieve was not refused: $EARLY_RETRIEVE" ;;
esac
[ ! -e "$DESTINATION" ] ||
    mkt_die "destination published before payment confirmation"

# Mempool relay is trickle, not instant: mining the confirmation before A
# has the payment produces a coinbase-only block and the purchase never
# confirms. Wait until A's mempool names the exact txid (either hex order).
mkt_note "waiting for the seller mempool to hold the payment"
TXID_REV="$(hexrev "$TXID")"
MEMPOOL_DEADLINE=$(( $(date +%s) + MKT_WAIT ))
while :; do
    MEMPOOL="$(a_rpc getrawmempool 2>/dev/null | mkt_result 2>/dev/null || true)"
    case "$MEMPOOL" in
        *"$TXID"*|*"$TXID_REV"*) break ;;
    esac
    [ "$(date +%s)" -lt "$MEMPOOL_DEADLINE" ] ||
        mkt_die "payment never reached the seller mempool: $MEMPOOL"
    sleep 1
done

# ── Phase 5: mine the confirmation; both sides reconcile ─────────────
mkt_note "mining the payment confirmation block"
SELLER_ADDR="$(a_rpc getnewaddress | mkt_result)"
mkt_mine_to_address a_rpc 1 "$SELLER_ADDR"
mkt_wait_height "$MKT_DD_B" "$B_RPC" 102 || mkt_die "B did not sync the confirmation block"
mkt_wait_fold "$MKT_DD_A" "$A_RPC" 102 || mkt_die "A reducer fold did not reach the confirmation tip"
mkt_wait_fold "$MKT_DD_B" "$B_RPC" 102 || mkt_die "B reducer fold did not reach the confirmation tip"

# The market purchase status leaf is a dumb durable read by design; the
# vault controller's reconcile (triggered here by vault_intent_status) is
# what advances mempool_accepted -> confirmed against the canonical chain.
mkt_note "polling the buyer purchase status until confirmed"
STATUS_DEADLINE=$(( $(date +%s) + MKT_WAIT ))
while :; do
    VI_REFRESH="$(b_rpc vault_intent_status "{\"plan_id\":\"$PLAN_ID\"}" 2>&1 || true)"
    STATUS="$(printf '%s' "{\"plan_id\":\"$PLAN_ID\"}" \
        | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase status --input=- || true)"
    state="$(printf '%s' "$STATUS" | mkt_jget data.state 2>/dev/null || true)"
    [ "$state" = "confirmed" ] && break
    [ "$(date +%s)" -lt "$STATUS_DEADLINE" ] ||
        mkt_die "purchase never confirmed: $STATUS"
    sleep 1
done
printf '%s' "$STATUS" | "$JSONQ" eq ok true ||
    mkt_die "confirmed purchase status mismatch: $STATUS"
printf '%s' "$STATUS" | "$JSONQ" eq data.state confirmed ||
    mkt_die "confirmed purchase status mismatch: $STATUS"
printf '%s' "$STATUS" | "$JSONQ" eq data.txid "$TXID" ||
    mkt_die "confirmed purchase status mismatch: $STATUS"
status_claim="$(printf '%s' "$STATUS" | "$JSONQ" get data.claim_id)" ||
    mkt_die "confirmed purchase status mismatch: $STATUS"
[ "${#status_claim}" -eq 64 ] ||
    mkt_die "confirmed purchase status mismatch: $STATUS"

# The seller wallet must trial-decrypt its exact payment note at the
# confirmation height before the chunk gate can bind against it.
mkt_note "waiting for the seller wallet to decrypt its exact payment note"
NOTE_DEADLINE=$(( $(date +%s) + MKT_WAIT ))
while :; do
    NOTE="$(mkt_native "$MKT_DD_A" "$A_RPC" core storage query \
        --input="{\"sql\":\"SELECT COUNT(*) FROM wallet_sapling_notes WHERE value=$EXPECT_TOTAL_ZAT AND block_height=102\"}" || true)"
    ncount="$(printf '%s' "$NOTE" | mkt_jget data.rows[0][0] 2>/dev/null || true)"
    [ "$ncount" = "1" ] && break
    [ "$(date +%s)" -lt "$NOTE_DEADLINE" ] ||
        mkt_die "seller never decrypted its payment note: $NOTE"
    sleep 1
done

# ── Phase 6 (negative): retrieve without Tor refuses by name ─────────
# A completed retrieve replays idempotently without touching the transport
# gate, so the no-Tor refusal must be proven BEFORE the successful
# retrieve: kill B, bring the same datadir up WITHOUT -tor, and the signed
# onion offer must refuse with ONION_DELIVERY_UNAVAILABLE — never a
# clearnet fallback.
mkt_note "restarting B WITHOUT -tor: the onion offer must refuse retrieval by name"
mkt_kill_group "$MKT_PGID_B"; MKT_PGID_B=""
MKT_EXTRA_FLAGS=()
MKT_PGID_B="$(mkt_spawn "$MKT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$DEAD_SINK")"
mkt_wait_rpc "$MKT_DD_B" "$B_RPC" "$MKT_PGID_B" || mkt_die "B no-Tor restart failed"
mkt_unlock_wallet "$MKT_DD_B" "$B_RPC" || mkt_die "B no-Tor wallet unlock failed"
NOTOR_RETRIEVE="$(printf '%s' "{\"plan_id\":\"$PLAN_ID\",\"destination_path\":\"$DESTINATION\"}" \
    | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase retrieve --input=- || true)"
printf '%s' "$NOTOR_RETRIEVE" | "$JSONQ" eq ok false ||
    mkt_die "retrieve without Tor was not refused by name: $NOTOR_RETRIEVE"
printf '%s' "$NOTOR_RETRIEVE" | "$JSONQ" eq error.code ONION_DELIVERY_UNAVAILABLE ||
    mkt_die "retrieve without Tor was not refused by name: $NOTOR_RETRIEVE"
[ ! -e "$DESTINATION" ] ||
    mkt_die "destination published by a no-Tor retrieve"
mkt_note "no-Tor retrieve refused with ONION_DELIVERY_UNAVAILABLE"

# ── Phase 7: authorized onion retrieval + verified publication ───────
# Retry on DELIVERY_NOT_READY: the seller's per-chunk authorization
# reconciles the claim live, and a real Tor circuit to a freshly published
# onion service can fail transiently — both are transient refusals, not
# verdicts. Each slice is one blocking embedded-Tor fetch, so this phase
# gets its own generous budget.
mkt_note "restarting B WITH -tor for the onion retrieval"
mkt_kill_group "$MKT_PGID_B"; MKT_PGID_B=""
MKT_EXTRA_FLAGS=("-tor")
MKT_PGID_B="$(mkt_spawn "$MKT_DD_B" "$B_PORT" "$B_RPC" "$B_FS" "$B_HTTPS" "127.0.0.1:$DEAD_SINK")"
mkt_wait_rpc "$MKT_DD_B" "$B_RPC" "$MKT_PGID_B" || mkt_die "B onion-retrieve restart failed"
B_ONION="$(oni_wait_onion_address "$MKT_DD_B" "$B_RPC" "buyer B (onion-retrieve restart)")"
mkt_unlock_wallet "$MKT_DD_B" "$B_RPC" || mkt_die "B onion-retrieve wallet unlock failed"

mkt_note "buyer retrieves the file over the seller onion service (60 KiB slices)"
RETRIEVE_DEADLINE=$(( $(date +%s) + ONI_RETRIEVE_WAIT ))
while :; do
    RETRIEVE="$(printf '%s' "{\"plan_id\":\"$PLAN_ID\",\"destination_path\":\"$DESTINATION\"}" \
        | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase retrieve --input=- || true)"
    rok="$(printf '%s' "$RETRIEVE" | mkt_jget ok 2>/dev/null || true)"
    [ "$rok" = "true" ] && break
    case "$RETRIEVE" in
        *DELIVERY_NOT_READY*) ;;
        *) mkt_die "retrieve failed with a non-delivery error: $RETRIEVE" ;;
    esac
    [ "$(date +%s)" -lt "$RETRIEVE_DEADLINE" ] ||
        mkt_die "retrieve never authorized over onion: $RETRIEVE"
    sleep 2
done
printf '%s' "$RETRIEVE" | "$JSONQ" eq ok true ||
    mkt_die "retrieve failed: $RETRIEVE"
printf '%s' "$RETRIEVE" | "$JSONQ" eq data.stage retrieved ||
    mkt_die "retrieve failed: $RETRIEVE"
printf '%s' "$RETRIEVE" | "$JSONQ" eq data.download_state complete ||
    mkt_die "retrieve failed: $RETRIEVE"
printf '%s' "$RETRIEVE" | "$JSONQ" eq data.destination_published true ||
    mkt_die "retrieve failed: $RETRIEVE"
printf '%s' "$RETRIEVE" | "$JSONQ" eq data.chunks_received "$EXPECTED_CHUNKS" ||
    mkt_die "retrieve failed: $RETRIEVE"
printf '%s' "$RETRIEVE" | "$JSONQ" eq data.num_chunks "$EXPECTED_CHUNKS" ||
    mkt_die "retrieve failed: $RETRIEVE"
printf '%s' "$RETRIEVE" | "$JSONQ" eq data.bytes_received "$FIXTURE_SIZE" ||
    mkt_die "retrieve failed: $RETRIEVE"
printf '%s' "$RETRIEVE" | "$JSONQ" eq data.size_bytes "$FIXTURE_SIZE" ||
    mkt_die "retrieve failed: $RETRIEVE"
cmp -s "$FIXTURE" "$DESTINATION" ||
    mkt_die "delivered bytes differ from the seller fixture"
DELIVERED_ROOT="$("$FIXTURE_GEN" root "$DESTINATION")"
[ "$DELIVERED_ROOT" = "$EXPECT_ROOT" ] ||
    mkt_die "delivered bytes re-derive a different content root"

# ── Phase 8: the onion-transport witnesses ────────────────────────────
# The delivery leg is witnessed on BOTH tor.log files (the dynhost
# webserver and client log every request at notice level, which the
# generated torrc writes to <datadir>/tor.log): the seller logged the
# /market/chunk GETs (one per slice fetch, including the pre-confirmation
# refusal), the buyer logged the matching client fetches to the .onion.
# Combined with the signed offer carrying no usable clearnet endpoint
# (peer_port=0, asserted above) and B never dialling A's file service,
# this is the proof the bytes crossed the Tor network.
mkt_note "verifying the /market/chunk traffic crossed both Tor instances"
A_CHUNK_GETS="$(grep -ac "HTTP GET /market/chunk/" "$MKT_DD_A/tor.log" 2>/dev/null || true)"
[ "${A_CHUNK_GETS:-0}" -ge "$EXPECTED_SLICES" ] ||
    mkt_die "seller tor.log shows only ${A_CHUNK_GETS:-0} /market/chunk GETs (need $EXPECTED_SLICES)"
B_CHUNK_FETCHES="$(grep -ac "initiated fetch to .*\.onion/market/chunk/" "$MKT_DD_B/tor.log" 2>/dev/null || true)"
[ "${B_CHUNK_FETCHES:-0}" -ge "$EXPECTED_SLICES" ] ||
    mkt_die "buyer tor.log shows only ${B_CHUNK_FETCHES:-0} onion chunk fetches (need $EXPECTED_SLICES)"
mkt_note "onion witness: seller served $A_CHUNK_GETS chunk GETs, buyer initiated $B_CHUNK_FETCHES"

# The authorized delivery above made the seller reconcile the claim against
# its exact canonical note; the durable row must now read CONFIRMED.
mkt_note "verifying the seller-side payment claim is confirmed"
CLAIM="$(mkt_native "$MKT_DD_A" "$A_RPC" core storage query \
    --input='{"sql":"SELECT status, status_reason, confirmations, block_height FROM market_payment_claims"}' || true)"
printf '%s' "$CLAIM" | "$JSONQ" eq ok true ||
    mkt_die "seller claim row mismatch: $CLAIM"
[ "$(printf '%s' "$CLAIM" | "$JSONQ" count data.rows)" = "1" ] ||
    mkt_die "seller claim row mismatch: $CLAIM"
claim_ncols="$(printf '%s' "$CLAIM" | "$JSONQ" count data.columns)" ||
    mkt_die "seller claim row mismatch: $CLAIM"
claim_status=""; claim_conf=""; claim_height=""
claim_i=0
while [ "$claim_i" -lt "$claim_ncols" ]; do
    claim_col="$(printf '%s' "$CLAIM" | "$JSONQ" get "data.columns[$claim_i]")" ||
        mkt_die "seller claim row mismatch: $CLAIM"
    claim_val="$(printf '%s' "$CLAIM" | "$JSONQ" get "data.rows[0][$claim_i]")" ||
        mkt_die "seller claim row mismatch: $CLAIM"
    case "$claim_col" in
        status) claim_status="$claim_val" ;;
        confirmations) claim_conf="$claim_val" ;;
        block_height) claim_height="$claim_val" ;;
    esac
    claim_i=$((claim_i + 1))
done
[ "$claim_status" = "CONFIRMED" ] && [ "${claim_conf:-0}" -ge 1 ] &&
    [ "$claim_height" = "102" ] ||
    mkt_die "seller claim row mismatch: $CLAIM"
FINAL_STATUS="$(printf '%s' "{\"plan_id\":\"$PLAN_ID\"}" \
    | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase status --input=- || true)"
[ "$(printf '%s' "$FINAL_STATUS" | mkt_jget data.destination_published 2>/dev/null || true)" = "true" ] ||
    mkt_die "purchase status does not show the completed download: $FINAL_STATUS"

# ── Phase 9: idempotent replays ──────────────────────────────────────
mkt_note "re-committing the same purchase plan (idempotent replay, no double-spend)"
RECOMMIT="$(printf '%s' "{\"wallet_scope\":\"dev\",\"plan_id\":\"$PLAN_ID\",\"confirm\":true}" \
    | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase commit --input=- || true)"
printf '%s' "$RECOMMIT" | "$JSONQ" eq ok true ||
    mkt_die "purchase re-commit was not an exact replay: $RECOMMIT"
printf '%s' "$RECOMMIT" | "$JSONQ" eq data.idempotent_replay true ||
    mkt_die "purchase re-commit was not an exact replay: $RECOMMIT"
printf '%s' "$RECOMMIT" | "$JSONQ" eq data.txid "$TXID" ||
    mkt_die "purchase re-commit was not an exact replay: $RECOMMIT"
REPLAN="$(printf '%s' "{\"wallet_scope\":\"dev\",\"offer_id\":\"$OFFER_ID\",\"source_address\":\"$BUYER_ADDR\",\"chunk_start\":0,\"chunks_paid\":$EXPECTED_CHUNKS,\"idempotency_key\":\"$IDEMPOTENCY_KEY\"}" \
    | mkt_native "$MKT_DD_B" "$B_RPC" app market purchase plan --input=- || true)"
printf '%s' "$REPLAN" | "$JSONQ" eq ok true ||
    mkt_die "purchase re-plan was not an exact replay: $REPLAN"
printf '%s' "$REPLAN" | "$JSONQ" eq data.idempotent_replay true ||
    mkt_die "purchase re-plan was not an exact replay: $REPLAN"
printf '%s' "$REPLAN" | "$JSONQ" eq data.plan_id "$PLAN_ID" ||
    mkt_die "purchase re-plan was not an exact replay: $REPLAN"

mkt_note "seller re-commits the same offer (content-addressed idempotent)"
REOFFER="$(printf '%s' "{\"filepath\":\"$FIXTURE\",\"price_per_mb_zat\":$PRICE_PER_MB_ZAT,\"confirm\":true}" \
    | mkt_native "$MKT_DD_A" "$A_RPC" app market offer --input=- || true)"
printf '%s' "$REOFFER" | "$JSONQ" eq ok true ||
    mkt_die "offer re-commit was not an exact replay: $REOFFER"
printf '%s' "$REOFFER" | "$JSONQ" eq data.stage committed ||
    mkt_die "offer re-commit was not an exact replay: $REOFFER"
printf '%s' "$REOFFER" | "$JSONQ" eq data.idempotent_replay true ||
    mkt_die "offer re-commit was not an exact replay: $REOFFER"
printf '%s' "$REOFFER" | "$JSONQ" eq data.offer_id "$OFFER_ID" ||
    mkt_die "offer re-commit was not an exact replay: $REOFFER"
printf '%s' "$REOFFER" | "$JSONQ" eq data.endpoint_source onion ||
    mkt_die "offer re-commit was not an exact replay: $REOFFER"

mkt_note "PASS: two-daemon onion market trade — v2 onion-endpoint offer gossip, Sapling payment, authorize-before-read refusal served through the onion route, no-Tor retrieve refused by name (ONION_DELIVERY_UNAVAILABLE), 3-slice 60 KiB onion delivery byte-identical to the offer root, /market/chunk traffic witnessed in both tor.log files, idempotent replays"
