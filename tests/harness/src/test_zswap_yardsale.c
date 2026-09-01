/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zswap_yardsale — the zswap YARDSALE: zswapquote P2P gossip ingress
 * (msgprocessor dispatch row + handler), the local expiry-pruned yardsale
 * cache (contexts/market/modules/zswap/zswap_yardsale.*), and its rebuildable AR projection
 * (models/zswap_ad.*, table zswap_ads).
 *
 * Covers: dispatch-row flags; handler accepts a valid sealed ad and stores
 * it (plus save callback + relay eligibility); byte-identical re-gossip
 * dedups on the quote root; expired / tampered / cross-network / early ads
 * dropped at ingress and never stored; per-peer new-ad clamp; best-price
 * browse ordering with integer-only math (including the 128-bit
 * overflow-sensitive case); lazy expiry pruning with the "verify evidence
 * valid when created" principle preserved in storage; the AR projection
 * roundtrip; and the dumpstate counters. */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "core/serialize.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "models/database.h"
#include "models/zswap_ad.h"
#include "net/msgprocessor.h"
#include "platform/time_compat.h"
#include "util/util.h"
#include "validation/main_state.h"
#include "zswap/zswap_quote.h"
#include "zswap/zswap_yardsale.h"

#include <stdio.h>
#include <string.h>

#define ZYS_CHECK(name, expr) do {                                    \
    if (expr) { printf("  zswap_yardsale: %s... OK\n", (name)); }    \
    else { printf("  zswap_yardsale: %s... FAIL\n", (name));         \
        failures++; }                                                 \
} while (0)

static void zys_token(uint8_t token_id[32])
{
    for (size_t i = 0; i < 32; i++) token_id[i] = (uint8_t)(0x40u + i);
}

/* Build + seal + encode one ad wire. seed_fill picks the seller key. */
static bool zys_wire(uint8_t wire[ZSWAP_QUOTE_WIRE_BYTES],
                     const uint8_t net[32], uint8_t seed_fill,
                     uint64_t nonce, const uint8_t token_id[32],
                     uint64_t token_amount, uint64_t zcl_amount,
                     int64_t issued, int64_t expires)
{
    uint8_t seed[32], pk[32], sk[32];
    memset(seed, seed_fill, sizeof(seed));
    ed25519_keypair(pk, sk, seed);

    struct zswap_quote_v1 q;
    memset(&q, 0, sizeof(q));
    q.schema_version = ZSWAP_QUOTE_VERSION;
    memcpy(q.network_genesis_root, net, 32);
    memcpy(q.seller_pubkey, pk, 32);
    q.nonce = nonce;
    memcpy(q.token_id, token_id, 32);
    q.token_amount = token_amount;
    q.zcl_amount = zcl_amount;
    q.issued_unix = issued;
    q.expires_unix = expires;
    if (zswap_quote_seal(&q, seed) != ZSWAP_QUOTE_OK)
        return false;
    return zswap_quote_encode(&q, wire) == ZSWAP_QUOTE_OK;
}

/* A currently-valid ad wire (real wall clock: issued just now, +45s). */
static bool zys_wire_now(uint8_t wire[ZSWAP_QUOTE_WIRE_BYTES],
                         const uint8_t net[32], uint8_t seed_fill,
                         uint64_t nonce, const uint8_t token_id[32],
                         uint64_t token_amount, uint64_t zcl_amount)
{
    int64_t now = (int64_t)platform_time_wall_time_t();
    return zys_wire(wire, net, seed_fill, nonce, token_id,
                    token_amount, zcl_amount, now - 1, now + 45);
}

/* ── Handler driver (dispatch-table entry + stub mp/node/stream) ── */

struct zys_capture {
    int calls;
    struct zswap_yardsale_ad last;
};

static bool zys_save_hook(const struct zswap_yardsale_ad *ad, void *ctx)
{
    struct zys_capture *cap = ctx;
    cap->calls++;
    cap->last = *ad;
    return true;
}

/* The handler reaches the yardsale through the injected ingest port (the
 * module-order seam); wire it to the real thing, as boot does. */
static int zys_ingest_hook(const uint8_t *wire, size_t wire_len,
                           const uint8_t expected_network_genesis[32],
                           int64_t peer_id, int64_t now_unix,
                           struct zswap_yardsale_ad *out_ad, void *ctx)
{
    (void)ctx;
    return (int)zswap_yardsale_ingest_wire(wire, wire_len,
                                           expected_network_genesis,
                                           peer_id, now_unix, out_ad);
}

static const struct msg_dispatch_entry *zys_entry(void)
{
    const struct msg_dispatch_entry *e = msg_get_dispatch_table();
    for (; e->handler; e++) {
        if (strcmp(e->command, ZSWAP_MSG_QUOTE) == 0)
            return e;
    }
    return NULL;
}

static bool zys_drive(const struct msg_dispatch_entry *e,
                      struct msg_processor *mp, int64_t peer_id,
                      const uint8_t *payload, size_t payload_len)
{
    struct p2p_node node;
    memset(&node, 0, sizeof(node));
    snprintf(node.addr_name, sizeof(node.addr_name),
             "203.0.113.%d:8033", (int)(peer_id & 0xff));
    node.id = peer_id;
    struct byte_stream s;
    stream_init(&s, payload_len);
    stream_write(&s, payload, payload_len);
    bool ok = e->handler(mp, &node, &s);
    stream_free(&s);
    return ok;
}

/* ── Sub-tests ──────────────────────────────────────────────────── */

static int t_dispatch_row(void)
{
    int failures = 0;
    const struct msg_dispatch_entry *e = zys_entry();
    ZYS_CHECK("dispatch: zswapquote row exists", e != NULL);
    if (e) {
        ZYS_CHECK("dispatch: command <= 12 bytes",
                  strlen(e->command) <= 12);
        /* Same flags as the ZCL Market z-messages (zfilelist): handshake
         * required + zcl23-only (NODE_ZCL23 service bit), "market" domain. */
        ZYS_CHECK("dispatch: handshake-required + zcl23-only",
                  e->requires_handshake && e->zcl23_only);
        ZYS_CHECK("dispatch: market domain",
                  e->service_name &&
                      strcmp(e->service_name, "market") == 0);
    }
    return failures;
}

static int t_handler_accept_store(struct msg_processor *mp,
                                  const uint8_t net[32],
                                  struct zys_capture *cap)
{
    int failures = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    uint8_t token[32], wire[ZSWAP_QUOTE_WIRE_BYTES];
    zys_token(token);
    ZYS_CHECK("accept: fixture seals",
              zys_wire_now(wire, net, 0x11, 1, token, 500000, 125000000));

    const struct msg_dispatch_entry *e = zys_entry();
    ZYS_CHECK("accept: dispatch entry", e != NULL);
    if (!e) return failures + 1;

    ZYS_CHECK("accept: handler returns true",
              zys_drive(e, mp, 77, wire, sizeof(wire)));
    ZYS_CHECK("accept: ad stored in yardsale",
              zswap_yardsale_count(now) == 1);
    ZYS_CHECK("accept: save callback fired once", cap->calls == 1);

    struct zswap_yardsale_counters c;
    zswap_yardsale_counters_snapshot(&c);
    ZYS_CHECK("accept: counters wires_seen=1 ads_stored=1",
              c.wires_seen == 1 && c.ads_stored == 1 &&
                  c.ads_dropped_invalid == 0);

    /* The persisted projection row carries the dedup id + the ad fields. */
    uint8_t root[32];
    struct zswap_quote_v1 q;
    bool rooted = zswap_quote_decode(wire, sizeof(wire), &q) ==
                      ZSWAP_QUOTE_OK &&
                  zswap_quote_root(&q, root) == ZSWAP_QUOTE_OK;
    ZYS_CHECK("accept: saved row keyed by quote root",
              rooted && cap->calls == 1 &&
                  memcmp(cap->last.quote_root, root, 32) == 0 &&
                  cap->last.seen_count == 1);
    return failures;
}

static int t_dedup(struct msg_processor *mp, const uint8_t net[32],
                   struct zys_capture *cap)
{
    int failures = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    uint8_t token[32], wire[ZSWAP_QUOTE_WIRE_BYTES];
    zys_token(token);
    ZYS_CHECK("dedup: fixture seals",
              zys_wire_now(wire, net, 0x11, 2, token, 500000, 125000000));
    const struct msg_dispatch_entry *e = zys_entry();
    if (!e) return failures + 1;

    ZYS_CHECK("dedup: first gossip stores",
              zys_drive(e, mp, 77, wire, sizeof(wire)));
    /* Byte-identical re-gossip (possibly via a different relay). */
    ZYS_CHECK("dedup: re-gossip accepted-and-ignored",
              zys_drive(e, mp, 78, wire, sizeof(wire)) &&
              zys_drive(e, mp, 79, wire, sizeof(wire)));

    ZYS_CHECK("dedup: single cache entry",
              zswap_yardsale_count(now) == 1);

    struct zswap_quote_v1 q;
    uint8_t root[32];
    bool ok = zswap_quote_decode(wire, sizeof(wire), &q) == ZSWAP_QUOTE_OK &&
              zswap_quote_root(&q, root) == ZSWAP_QUOTE_OK;
    struct zswap_yardsale_ad ad;
    ZYS_CHECK("dedup: seen_count bumped, single row",
              ok && zswap_yardsale_find(root, &ad) &&
              ad.seen_count == 3 && ad.first_seen_unix > 0);

    struct zswap_yardsale_counters c;
    zswap_yardsale_counters_snapshot(&c);
    ZYS_CHECK("dedup: counters stored=1 deduped=2",
              c.ads_stored == 1 && c.ads_deduped == 2);
    /* The dedup bump is persisted too (upsert), once per gossip. */
    ZYS_CHECK("dedup: save callback fired per gossip", cap->calls == 3);
    return failures;
}

static int t_drops(struct msg_processor *mp, const uint8_t net[32],
                   struct zys_capture *cap)
{
    int failures = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    uint8_t token[32], wire[ZSWAP_QUOTE_WIRE_BYTES];
    zys_token(token);
    const struct msg_dispatch_entry *e = zys_entry();
    if (!e) return failures + 1;

    /* Expired at ingress: well-formed and signed, window already closed. */
    ZYS_CHECK("drop: expired fixture seals",
              zys_wire(wire, net, 0x11, 3, token, 100, 1000,
                       now - 50, now - 10));
    ZYS_CHECK("drop: expired ad rejected",
              zys_drive(e, mp, 77, wire, sizeof(wire)) &&
              zswap_yardsale_count(now) == 0);
    struct zswap_yardsale_counters c;
    zswap_yardsale_counters_snapshot(&c);
    ZYS_CHECK("drop: expired counted, not stored, not saved",
              c.ads_dropped_expired == 1 && c.ads_stored == 0 &&
                  cap->calls == 0);

    /* Tampered signature: flips a byte inside the 64-byte signature
     * (wire offset 146..209). Decode passes; verify fails. */
    ZYS_CHECK("drop: tampered fixture seals",
              zys_wire_now(wire, net, 0x11, 4, token, 100, 1000));
    wire[200] ^= 0x01;
    ZYS_CHECK("drop: tampered ad rejected",
              zys_drive(e, mp, 77, wire, sizeof(wire)) &&
              zswap_yardsale_count(now) == 0);
    zswap_yardsale_counters_snapshot(&c);
    ZYS_CHECK("drop: tamper counted invalid",
              c.ads_dropped_invalid == 1 && c.ads_stored == 0);

    /* Cross-network: validly sealed for a DIFFERENT genesis root. */
    uint8_t other_net[32];
    for (size_t i = 0; i < 32; i++) other_net[i] = (uint8_t)(0xb0u + i);
    ZYS_CHECK("drop: cross-network fixture seals",
              zys_wire_now(wire, other_net, 0x11, 5, token, 100, 1000));
    ZYS_CHECK("drop: cross-network ad rejected",
              zys_drive(e, mp, 77, wire, sizeof(wire)) &&
              zswap_yardsale_count(now) == 0);
    zswap_yardsale_counters_snapshot(&c);
    ZYS_CHECK("drop: cross-network counted invalid",
              c.ads_dropped_invalid == 2 && c.ads_stored == 0);

    /* Not yet valid: issued in the future. */
    ZYS_CHECK("drop: early fixture seals",
              zys_wire(wire, net, 0x11, 6, token, 100, 1000,
                       now + 20, now + 50));
    ZYS_CHECK("drop: not-yet-valid ad rejected",
              zys_drive(e, mp, 77, wire, sizeof(wire)) &&
              zswap_yardsale_count(now) == 0);
    zswap_yardsale_counters_snapshot(&c);
    ZYS_CHECK("drop: early counted invalid, nothing ever stored",
              c.ads_dropped_invalid == 3 && c.ads_stored == 0 &&
                  cap->calls == 0);
    return failures;
}

static int t_clamp(struct msg_processor *mp, const uint8_t net[32])
{
    int failures = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    uint8_t token[32], wire[ZSWAP_QUOTE_WIRE_BYTES];
    zys_token(token);
    const struct msg_dispatch_entry *e = zys_entry();
    if (!e) return failures + 1;

    /* ZSWAP_YARDSALE_PEER_WINDOW_MAX_ADS distinct fresh ads from one peer
     * inside one window all store; the next one is capped. */
    bool all_ok = true;
    for (uint64_t n = 1; n <= ZSWAP_YARDSALE_PEER_WINDOW_MAX_ADS + 1; n++) {
        all_ok = all_ok &&
            zys_wire_now(wire, net, 0x11, 100 + n, token, 100, 1000) &&
            zys_drive(e, mp, 77, wire, sizeof(wire));
    }
    ZYS_CHECK("clamp: N+1 ads all parse", all_ok);
    ZYS_CHECK("clamp: cache capped at window max",
              zswap_yardsale_count(now) == ZSWAP_YARDSALE_PEER_WINDOW_MAX_ADS);
    struct zswap_yardsale_counters c;
    zswap_yardsale_counters_snapshot(&c);
    ZYS_CHECK("clamp: (max) stored, 1 dropped by rate cap",
              c.ads_stored == ZSWAP_YARDSALE_PEER_WINDOW_MAX_ADS &&
                  c.ads_dropped_rate == 1);

    /* The clamp is PER PEER: the same ad volume from another peer is fine. */
    ZYS_CHECK("clamp: second-peer fixture seals",
              zys_wire_now(wire, net, 0x22, 200, token, 100, 1000));
    ZYS_CHECK("clamp: different peer unaffected",
              zys_drive(e, mp, 78, wire, sizeof(wire)) &&
              zswap_yardsale_count(now) ==
                  ZSWAP_YARDSALE_PEER_WINDOW_MAX_ADS + 1);
    return failures;
}

static int t_unit_price(void)
{
    int failures = 0;
    /* Plain ordering. */
    ZYS_CHECK("price: cheaper first",
              zswap_quote_unit_price_cmp(500, 100, 1000, 100) == -1 &&
              zswap_quote_unit_price_cmp(1000, 100, 500, 100) == 1);
    ZYS_CHECK("price: equal ratios tie",
              zswap_quote_unit_price_cmp(2, 4, 3, 6) == 0);
    /* The overflow-sensitive case: 3/2 = 1.5 vs (2^63+1)/2^62 ≈ 2.0 — the
     * true ordering is a < b, but the 64-bit cross products are
     * 3*2^62 (fits) vs (2^63+1)*2 = 2^64+2 (wraps to 2), which a 64-bit
     * implementation reads as a > b. The 128-bit compare must not flip. */
    ZYS_CHECK("price: 128-bit cross product does not overflow",
              zswap_quote_unit_price_cmp(3, 2, (1ULL << 63) + 1,
                                         1ULL << 62) == -1);
    /* Full-range amounts still order exactly. */
    ZYS_CHECK("price: huge amounts order exactly",
              zswap_quote_unit_price_cmp((1ULL << 40), (1ULL << 40),
                                         (1ULL << 40) + (1ULL << 20),
                                         1ULL << 40) == -1);
    return failures;
}

static int t_best_price(const uint8_t net[32])
{
    int failures = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    uint8_t token[32], wire[ZSWAP_QUOTE_WIRE_BYTES];
    zys_token(token);

    /* Five ads for one token, unit prices 10 / 5 / 20 / 1 / ~1.0000009. */
    struct { uint64_t token_amt, zcl; uint64_t nonce; } ads[5] = {
        { 100, 1000, 301 },                 /* 10 sats/unit */
        { 100, 500, 302 },                  /* 5  */
        { 100, 2000, 303 },                 /* 20 */
        { 1ULL << 40, 1ULL << 40, 304 },    /* exactly 1 */
        { 1ULL << 40, (1ULL << 40) + (1ULL << 20), 305 }, /* ~1.0000009 */
    };
    bool all_ok = true;
    for (size_t i = 0; i < 5; i++) {
        all_ok = all_ok &&
            zys_wire(wire, net, 0x11, ads[i].nonce, token,
                     ads[i].token_amt, ads[i].zcl, now - 1, now + 45) &&
            zswap_yardsale_ingest_wire(wire, sizeof(wire), net,
                                       90 + (int64_t)i, now, NULL) ==
                ZSWAP_YARDSALE_INGEST_NEW;
    }
    ZYS_CHECK("best: five ads ingested", all_ok);
    ZYS_CHECK("best: cache holds five", zswap_yardsale_count(now) == 5);

    struct zswap_yardsale_ad out[8];
    int n = zswap_yardsale_best_for_token(token, now, out, 8);
    ZYS_CHECK("best: all five returned", n == 5);
    bool ordered = n == 5 &&
        out[0].quote.zcl_amount == (1ULL << 40) &&
        out[1].quote.zcl_amount == (1ULL << 40) + (1ULL << 20) &&
        out[2].quote.zcl_amount == 500 &&
        out[3].quote.zcl_amount == 1000 &&
        out[4].quote.zcl_amount == 2000;
    ZYS_CHECK("best: ascending unit price (incl. huge amounts)", ordered);

    /* Bounded result count. */
    n = zswap_yardsale_best_for_token(token, now, out, 2);
    ZYS_CHECK("best: bounded to max", n == 2 &&
              out[0].quote.zcl_amount == (1ULL << 40) &&
              out[1].quote.zcl_amount == (1ULL << 40) + (1ULL << 20));

    /* A different token browses empty. */
    uint8_t other_token[32];
    for (size_t i = 0; i < 32; i++) other_token[i] = (uint8_t)(0x60u + i);
    ZYS_CHECK("best: unknown token empty",
              zswap_yardsale_best_for_token(other_token, now, out, 8) == 0);
    return failures;
}

static int t_lazy_prune(const uint8_t net[32])
{
    int failures = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    uint8_t token[32], wire[ZSWAP_QUOTE_WIRE_BYTES];
    zys_token(token);

    /* Valid at ingress (verify evidence valid when created); the window
     * closes 5 seconds later. */
    ZYS_CHECK("prune: fixture seals",
              zys_wire(wire, net, 0x11, 401, token, 100, 1000,
                       now - 1, now + 5));
    ZYS_CHECK("prune: stored while valid",
              zswap_yardsale_ingest_wire(wire, sizeof(wire), net, 91,
                                         now, NULL) ==
                  ZSWAP_YARDSALE_INGEST_NEW);

    struct zswap_yardsale_ad out[4];
    ZYS_CHECK("prune: browseable inside window",
              zswap_yardsale_best_for_token(token, now, out, 4) == 1);
    /* Queries filter by now: past expiry the cache prunes the sign. */
    ZYS_CHECK("prune: expired ad gone from query and cache",
              zswap_yardsale_best_for_token(token, now + 10, out, 4) == 0 &&
              zswap_yardsale_count(now + 10) == 0);
    struct zswap_yardsale_counters c;
    zswap_yardsale_counters_snapshot(&c);
    ZYS_CHECK("prune: prune counted", c.ads_pruned >= 1);
    return failures;
}

static int t_ar_projection(const uint8_t net[32])
{
    int failures = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    uint8_t token[32], wire[ZSWAP_QUOTE_WIRE_BYTES];
    zys_token(token);

    /* Two live-cache ads (prices 10 and 5) become the rows under test. */
    struct zswap_yardsale_ad ad10, ad5;
    bool ok =
        zys_wire(wire, net, 0x11, 501, token, 100, 1000, now - 1, now + 45) &&
        zswap_yardsale_ingest_wire(wire, sizeof(wire), net, 92, now,
                                   &ad10) == ZSWAP_YARDSALE_INGEST_NEW &&
        zys_wire(wire, net, 0x22, 502, token, 100, 500, now - 1, now + 45) &&
        zswap_yardsale_ingest_wire(wire, sizeof(wire), net, 93, now,
                                   &ad5) == ZSWAP_YARDSALE_INGEST_NEW;
    ZYS_CHECK("ar: fixture ads ingested", ok);

    struct node_db ndb;
    ZYS_CHECK("ar: in-memory node_db opens",
              node_db_open(&ndb, ":memory:"));
    if (!ndb.open) return failures + 1;

    ZYS_CHECK("ar: save both ads",
              db_zswap_ad_save(&ndb, &ad10) && db_zswap_ad_save(&ndb, &ad5));

    struct zswap_yardsale_ad back;
    ZYS_CHECK("ar: find by quote root",
              db_zswap_ad_find(&ndb, ad10.quote_root, &back) &&
              back.quote.zcl_amount == 1000 && back.seen_count == 1);

    /* Byte-identical re-gossip: the upsert bumps seen_count and keeps
     * first_seen — one row, never two. */
    struct zswap_yardsale_ad bump = ad10;
    bump.seen_count = 2;
    bump.last_seen_unix = now + 1;
    ZYS_CHECK("ar: dedup upsert", db_zswap_ad_save(&ndb, &bump));
    ZYS_CHECK("ar: dedup bumped in place",
              db_zswap_ad_find(&ndb, ad10.quote_root, &back) &&
              back.seen_count == 2 &&
              back.first_seen_unix == ad10.first_seen_unix);

    /* Best-price browse: ascending unit price, expired filtered. */
    struct zswap_yardsale_ad out[4];
    int n = db_zswap_ad_best_for_token(&ndb, token, now, out, 4);
    ZYS_CHECK("ar: best-price order", n == 2 &&
              out[0].quote.zcl_amount == 500 &&
              out[1].quote.zcl_amount == 1000);

    /* "Verify evidence valid when created": past expiry the query filters
     * the rows but storage still holds exactly what verified at ingress. */
    ZYS_CHECK("ar: expired filtered from query",
              db_zswap_ad_best_for_token(&ndb, token, now + 100, out, 4) == 0);
    ZYS_CHECK("ar: expired evidence preserved in storage",
              db_zswap_ad_find(&ndb, ad10.quote_root, &back) &&
              db_zswap_ad_find(&ndb, ad5.quote_root, &back));

    ZYS_CHECK("ar: explicit expiry prune reclaims",
              db_zswap_ad_prune_expired(&ndb, now + 100) == 2 &&
              !db_zswap_ad_find(&ndb, ad10.quote_root, &back));
    node_db_close(&ndb);
    return failures;
}

static int t_dump_state(const uint8_t net[32])
{
    int failures = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    uint8_t token[32], wire[ZSWAP_QUOTE_WIRE_BYTES];
    zys_token(token);

    bool ok =
        zys_wire_now(wire, net, 0x11, 601, token, 100, 1000) &&
        zswap_yardsale_ingest_wire(wire, sizeof(wire), net, 94, now,
                                   NULL) == ZSWAP_YARDSALE_INGEST_NEW &&
        /* one dedup */
        zswap_yardsale_ingest_wire(wire, sizeof(wire), net, 95, now,
                                   NULL) == ZSWAP_YARDSALE_INGEST_DEDUP &&
        /* one expired drop */
        zys_wire(wire, net, 0x11, 602, token, 100, 1000,
                 now - 50, now - 10) &&
        zswap_yardsale_ingest_wire(wire, sizeof(wire), net, 96, now,
                                   NULL) == ZSWAP_YARDSALE_INGEST_EXPIRED;
    ZYS_CHECK("dump: fixture traffic", ok);

    struct json_value j;
    json_init(&j);
    ZYS_CHECK("dump: state json builds", zswap_dump_state_json(&j, NULL));
    const struct json_value *cache_size = json_get(&j, "cache_size");
    const struct json_value *stored = json_get(&j, "ads_stored");
    const struct json_value *deduped = json_get(&j, "ads_deduped");
    const struct json_value *expired = json_get(&j, "ads_dropped_expired");
    const struct json_value *newest = json_get(&j, "newest_expiry_unix");
    ZYS_CHECK("dump: counters + expiry fields",
              cache_size && json_get_int(cache_size) == 1 &&
              stored && json_get_int(stored) == 1 &&
              deduped && json_get_int(deduped) == 1 &&
              expired && json_get_int(expired) == 1 &&
              newest && json_get_int(newest) > now);
    json_free(&j);
    return failures;
}

int test_zswap_yardsale(void)
{
    printf("\n=== zswap_yardsale: yardsale gossip + cache + projection ===\n");
    int failures = 0;

    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();
    const uint8_t *net = cp->consensus.hashGenesisBlock.data;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "zswap_yardsale", "main");
    SetDataDir(dir);

    struct main_state ms;
    main_state_init(&ms);
    struct net_manager nm;
    net_manager_init(&nm);
    struct msg_processor mp;
    msg_processor_init(&mp, &ms, NULL, NULL, cp, dir, &nm, NULL);

    struct zys_capture cap;
    memset(&cap, 0, sizeof(cap));
    msg_processor_set_zswap_ad_save(&mp, zys_save_hook, &cap);
    msg_processor_set_zswap_ad_ingest(&mp, zys_ingest_hook, NULL);

    failures += t_dispatch_row();

    zswap_yardsale_reset();
    memset(&cap, 0, sizeof(cap));
    failures += t_handler_accept_store(&mp, net, &cap);

    zswap_yardsale_reset();
    memset(&cap, 0, sizeof(cap));
    failures += t_dedup(&mp, net, &cap);

    zswap_yardsale_reset();
    memset(&cap, 0, sizeof(cap));
    failures += t_drops(&mp, net, &cap);

    zswap_yardsale_reset();
    failures += t_clamp(&mp, net);

    failures += t_unit_price();

    zswap_yardsale_reset();
    failures += t_best_price(net);

    zswap_yardsale_reset();
    failures += t_lazy_prune(net);

    zswap_yardsale_reset();
    failures += t_ar_projection(net);

    zswap_yardsale_reset();
    failures += t_dump_state(net);

    printf("=== zswap_yardsale complete: %d failure(s) ===\n", failures);
    return failures;
}
