/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the zswap YARDSALE — the local cache of "for sale by owner"
 * signed ZSLP-token/ZCL ads (zswap_quote.v1 wires) heard on P2P gossip.
 *
 * Every sign is for-sale-by-owner and always will be: any node may pin up a
 * signed, expiring yard-sale sign — "I'll sell token_amount of token_id for
 * zcl_amount sats" — peers gossip the signs, intermediaries relay but can
 * never alter them (Ed25519-signed, see zswap/zswap_quote.h), and settlement
 * is always bilateral P2P. This module is only the remembering layer: a
 * bounded, expiry-pruned cache of the signs this node has seen, plus the
 * ingress policy (verify-at-ingress, dedup-on-root, per-peer flood clamp)
 * and the best-price browse query. It is NOT a market or a matching engine.
 *
 * Persistence: the cache is process-lifetime working memory (gossip ads are
 * ephemeral by nature — 60 s structural lifetime cap). A rebuildable AR
 * projection (models/zswap_ad.h, table zswap_ads) mirrors every accepted
 * ad through the msgprocessor save callback so a restart keeps the signs
 * that are still inside their validity window.
 */

#ifndef ZCL_ZSWAP_ZSWAP_YARDSALE_H
#define ZCL_ZSWAP_ZSWAP_YARDSALE_H

#include "zswap/zswap_quote.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* P2P message command (max 12 bytes). One message carries exactly one
 * signed ad: payload = the exact 210-byte zswap_quote.v1 wire. The wire has
 * no TTL field — a relay must never alter signed bytes — so gossip loops
 * are bounded by dedup-on-root instead: a node forwards a given quote root
 * at most once (the zfilelist TTL-decrement idiom's equivalent for signed
 * content), and fresh-ad floods are bounded by the per-peer clamp below. */
#define ZSWAP_MSG_QUOTE "zswapquote"

/* Cache + ingress limits. */
#define ZSWAP_YARDSALE_MAX_ADS 256 /* per-node yardsale cache */
#define ZSWAP_YARDSALE_PEER_SLOTS 64        /* per-peer clamp table */
#define ZSWAP_YARDSALE_PEER_WINDOW_SECS 10  /* clamp window */
#define ZSWAP_YARDSALE_PEER_WINDOW_MAX_ADS 8 /* new ads per peer per window */
#define ZSWAP_YARDSALE_QUERY_CAP 64  /* rows fetched for one best-price query */

/* One remembered sign: the verified quote, its dedup id, and the local
 * gossip bookkeeping (first/last time this exact wire was seen, and how
 * many times it arrived). */
struct zswap_yardsale_ad {
    struct zswap_quote_v1 quote;
    uint8_t quote_root[32];
    int64_t first_seen_unix;
    int64_t last_seen_unix;
    uint64_t seen_count;
};

enum zswap_yardsale_ingest {
    ZSWAP_YARDSALE_INGEST_NEW = 0,     /* verified + stored; forward + persist */
    ZSWAP_YARDSALE_INGEST_DEDUP,       /* known root; seen bump only, no forward */
    ZSWAP_YARDSALE_INGEST_INVALID,     /* decode/verify/network/tamper/not-yet-valid */
    ZSWAP_YARDSALE_INGEST_EXPIRED,     /* well-formed but expired at now_unix */
    ZSWAP_YARDSALE_INGEST_RATE_LIMITED,/* per-peer new-ad clamp fired */
};

struct zswap_yardsale_counters {
    uint64_t wires_seen;         /* every zswapquote payload offered to us */
    uint64_t ads_stored;         /* accepted as new into the cache */
    uint64_t ads_deduped;        /* byte-identical re-gossip (seen bump) */
    uint64_t ads_dropped_invalid;
    uint64_t ads_dropped_expired;
    uint64_t ads_dropped_rate;   /* per-peer clamp */
    uint64_t ads_pruned;         /* expired entries evicted from the cache */
    uint64_t ads_evicted;        /* live entries evicted at the cache cap */
};

/* Unit-price ordering for the browse query, integer math only — never a
 * float. Compares a_zcl/a_token against b_zcl/b_token (sats per whole
 * token_amount) via 128-bit cross-multiplication, so ad amounts anywhere in
 * the full uint64 range order correctly (a 64-bit cross product overflows
 * long before the amounts do). Returns -1/0/+1. */
int zswap_quote_unit_price_cmp(uint64_t a_zcl, uint64_t a_token,
                               uint64_t b_zcl, uint64_t b_token);

/* Ingress: decode the exact 210-byte wire, verify it at now_unix against
 * the expected network genesis root (cross-network, tampered, early, and
 * expired ads are dropped-and-ignored, never stored), dedup on the quote
 * root (a byte-identical re-gossip bumps seen_count/last_seen only), clamp
 * fresh ads per peer per window, and store. On NEW/DEDUP, out_ad (when
 * non-NULL) receives the cache entry so the caller can persist it and, for
 * NEW only, relay it onward. */
enum zswap_yardsale_ingest zswap_yardsale_ingest_wire(
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_network_genesis[32],
    int64_t peer_id, int64_t now_unix,
    struct zswap_yardsale_ad *out_ad);

/* Current cache occupancy (expired entries pruned lazily first). */
int zswap_yardsale_count(int64_t now_unix);

/* Evict every ad whose validity window has closed (expires_unix <= now).
 * Returns the number pruned. Called lazily by count/query/ingest. */
int zswap_yardsale_prune(int64_t now_unix);

/* Browse the yardsale: the best CURRENT signs for one token — ads still
 * inside [issued, expires) at now_unix — sorted by ascending unit price
 * (zswap_quote_unit_price_cmp), bounded to max results. Expired ads stay in
 * neither result nor cache: the "verify evidence valid when created"
 * principle lives in the AR projection's stored row, not in a stale cache
 * entry. Returns the number written to out. */
int zswap_yardsale_best_for_token(const uint8_t token_id[32],
                                  int64_t now_unix,
                                  struct zswap_yardsale_ad *out, size_t max);

/* Look up one remembered sign by quote root. */
bool zswap_yardsale_find(const uint8_t quote_root[32],
                         struct zswap_yardsale_ad *out);

/* Consistent snapshot of the ingress/cache counters. */
void zswap_yardsale_counters_snapshot(struct zswap_yardsale_counters *out);

/* Test hook: clear the cache, the clamp table, and all counters. */
void zswap_yardsale_reset(void);

struct json_value;
/* See AGENTS.md "Adding state introspection". Reentrant-safe. */
bool zswap_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_ZSWAP_ZSWAP_YARDSALE_H */
