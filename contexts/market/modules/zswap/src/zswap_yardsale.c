/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the zswap YARDSALE implementation — the local, expiry-pruned
 * cache of signed "for sale by owner" ZSLP/ZCL ads (zswap_quote.v1) plus
 * the gossip ingress policy. See zswap/zswap_yardsale.h for the design
 * framing: remembered signs, never a market, matching engine, or book.
 *
 * All state is static (no allocation): the cache is bounded at
 * ZSWAP_YARDSALE_MAX_ADS entries and the per-peer clamp table at
 * ZSWAP_YARDSALE_PEER_SLOTS, so gossip can never grow memory. Mirrors the
 * file_market.c idiom: one mutex, brief critical sections, crypto verify
 * OUTSIDE the lock. */

#include "zswap/zswap_yardsale.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Cache state ────────────────────────────────────────────────── */

static struct zswap_yardsale_ad g_ads[ZSWAP_YARDSALE_MAX_ADS];
static int g_ad_count = 0;

struct zswap_peer_window {
    bool used;
    int64_t peer_id;
    int64_t window_start_unix;
    uint64_t new_ads_in_window;
};
static struct zswap_peer_window g_peers[ZSWAP_YARDSALE_PEER_SLOTS];

static struct zswap_yardsale_counters g_counters;

static pthread_mutex_t g_yardsale_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── Unit price (integer math only) ─────────────────────────────── */

int zswap_quote_unit_price_cmp(uint64_t a_zcl, uint64_t a_token,
                               uint64_t b_zcl, uint64_t b_token)
{
    /* a_zcl/a_token ? b_zcl/b_token  <=>  a_zcl*b_token ? b_zcl*a_token.
     * Both products need up to 128 bits; amounts are uint64, so a 64-bit
     * cross product would overflow and silently mis-order large ads.
     * __int128 is the project's portable 128-bit idiom (see
     * core/modules/sapling/src/bls12_381.c for the same pragma). */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    unsigned __int128 lhs = (unsigned __int128)a_zcl * (unsigned __int128)b_token;
    unsigned __int128 rhs = (unsigned __int128)b_zcl * (unsigned __int128)a_token;
#pragma GCC diagnostic pop
    if (lhs < rhs) return -1;
    if (lhs > rhs) return 1;
    return 0;
}

/* qsort comparator over full cache entries: ascending unit price, then
 * ascending zcl_amount, then quote-root bytes — total, deterministic. */
static int ad_price_qsort_cmp(const void *pa, const void *pb)
{
    const struct zswap_yardsale_ad *a = pa;
    const struct zswap_yardsale_ad *b = pb;
    int c = zswap_quote_unit_price_cmp(a->quote.zcl_amount,
                                       a->quote.token_amount,
                                       b->quote.zcl_amount,
                                       b->quote.token_amount);
    if (c != 0) return c;
    if (a->quote.zcl_amount < b->quote.zcl_amount) return -1;
    if (a->quote.zcl_amount > b->quote.zcl_amount) return 1;
    return memcmp(a->quote_root, b->quote_root, 32);
}

/* ── Prune ──────────────────────────────────────────────────────── */

/* Caller holds g_yardsale_mutex. */
static int yardsale_prune_locked(int64_t now_unix)
{
    int pruned = 0;
    for (int i = 0; i < g_ad_count; ) {
        if (g_ads[i].quote.expires_unix <= now_unix) {
            g_ads[i] = g_ads[g_ad_count - 1];
            g_ad_count--;
            pruned++;
        } else {
            i++;
        }
    }
    g_counters.ads_pruned += (uint64_t)pruned;
    return pruned;
}

int zswap_yardsale_prune(int64_t now_unix)
{
    pthread_mutex_lock(&g_yardsale_mutex);
    int pruned = yardsale_prune_locked(now_unix);
    pthread_mutex_unlock(&g_yardsale_mutex);
    return pruned;
}

int zswap_yardsale_count(int64_t now_unix)
{
    pthread_mutex_lock(&g_yardsale_mutex);
    yardsale_prune_locked(now_unix);
    int count = g_ad_count;
    pthread_mutex_unlock(&g_yardsale_mutex);
    return count;
}

/* ── Per-peer flood clamp ───────────────────────────────────────── */

/* Caller holds g_yardsale_mutex. Returns true when the peer may offer
 * another NEW ad inside its current window. Unknown peers are slotted in
 * (evicting the stalest window when the table is full). */
static bool peer_window_admit_locked(int64_t peer_id, int64_t now_unix)
{
    struct zswap_peer_window *slot = NULL;
    struct zswap_peer_window *stalest = &g_peers[0];
    for (size_t i = 0; i < ZSWAP_YARDSALE_PEER_SLOTS; i++) {
        if (!g_peers[i].used) { slot = &g_peers[i]; break; }
        if (g_peers[i].peer_id == peer_id) { slot = &g_peers[i]; break; }
        if (g_peers[i].window_start_unix < stalest->window_start_unix)
            stalest = &g_peers[i];
    }
    if (!slot) slot = stalest; /* table full: reuse the stalest window */

    if (!slot->used || slot->peer_id != peer_id ||
        now_unix - slot->window_start_unix >= ZSWAP_YARDSALE_PEER_WINDOW_SECS) {
        slot->used = true;
        slot->peer_id = peer_id;
        slot->window_start_unix = now_unix;
        slot->new_ads_in_window = 0;
    }
    if (slot->new_ads_in_window >= ZSWAP_YARDSALE_PEER_WINDOW_MAX_ADS)
        return false;
    slot->new_ads_in_window++;
    return true;
}

/* ── Ingress ────────────────────────────────────────────────────── */

enum zswap_yardsale_ingest zswap_yardsale_ingest_wire(
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_network_genesis[32],
    int64_t peer_id, int64_t now_unix,
    struct zswap_yardsale_ad *out_ad)
{
    if (!wire || !expected_network_genesis)
        LOG_RETURN(ZSWAP_YARDSALE_INGEST_INVALID, "zswap",
                   "ingest_wire: NULL wire=%d net=%d",
                   !wire, !expected_network_genesis);

    pthread_mutex_lock(&g_yardsale_mutex);
    g_counters.wires_seen++;
    pthread_mutex_unlock(&g_yardsale_mutex);

    /* A yardsale sign is exactly one 210-byte signed wire — no framing, no
     * count prefix, no trailing bytes. */
    if (wire_len != ZSWAP_QUOTE_WIRE_BYTES) {
        pthread_mutex_lock(&g_yardsale_mutex);
        g_counters.ads_dropped_invalid++;
        pthread_mutex_unlock(&g_yardsale_mutex);
        return ZSWAP_YARDSALE_INGEST_INVALID;
    }

    struct zswap_quote_v1 quote;
    if (zswap_quote_decode(wire, wire_len, &quote) != ZSWAP_QUOTE_OK) {
        pthread_mutex_lock(&g_yardsale_mutex);
        g_counters.ads_dropped_invalid++;
        pthread_mutex_unlock(&g_yardsale_mutex);
        return ZSWAP_YARDSALE_INGEST_INVALID;
    }

    /* Verify at ingress, outside the lock: the sign must be for THIS chain,
     * inside its validity window right now, and carry a seller signature
     * that verifies — a relay can forward bytes but can never alter them. */
    enum zswap_quote_error verr =
        zswap_quote_verify_at(&quote, expected_network_genesis, now_unix);
    if (verr == ZSWAP_QUOTE_ERR_EXPIRED) {
        pthread_mutex_lock(&g_yardsale_mutex);
        g_counters.ads_dropped_expired++;
        pthread_mutex_unlock(&g_yardsale_mutex);
        return ZSWAP_YARDSALE_INGEST_EXPIRED;
    }
    if (verr != ZSWAP_QUOTE_OK) {
        pthread_mutex_lock(&g_yardsale_mutex);
        g_counters.ads_dropped_invalid++;
        pthread_mutex_unlock(&g_yardsale_mutex);
        return ZSWAP_YARDSALE_INGEST_INVALID;
    }

    uint8_t root[32];
    if (zswap_quote_root(&quote, root) != ZSWAP_QUOTE_OK)
        LOG_RETURN(ZSWAP_YARDSALE_INGEST_INVALID, "zswap",
                   "ingest_wire: verified quote has no root");

    pthread_mutex_lock(&g_yardsale_mutex);
    yardsale_prune_locked(now_unix);

    /* Dedup on the quote root: a byte-identical re-gossip bumps
     * seen_count/last_seen only — same wire, same id, never a second row. */
    for (int i = 0; i < g_ad_count; i++) {
        if (memcmp(g_ads[i].quote_root, root, 32) == 0) {
            g_ads[i].seen_count++;
            g_ads[i].last_seen_unix = now_unix;
            g_counters.ads_deduped++;
            if (out_ad) *out_ad = g_ads[i];
            pthread_mutex_unlock(&g_yardsale_mutex);
            return ZSWAP_YARDSALE_INGEST_DEDUP;
        }
    }

    /* Fresh ad: per-peer clamp. A flooding seller/relay hits the window cap;
     * honest re-gossip of known ads above never reaches this check. */
    if (!peer_window_admit_locked(peer_id, now_unix)) {
        g_counters.ads_dropped_rate++;
        pthread_mutex_unlock(&g_yardsale_mutex);
        return ZSWAP_YARDSALE_INGEST_RATE_LIMITED;
    }

    /* Store: at capacity, prefer evicting the stalest sign (oldest
     * last_seen) — expired ones were already pruned above. */
    struct zswap_yardsale_ad ad;
    memset(&ad, 0, sizeof(ad));
    ad.quote = quote;
    memcpy(ad.quote_root, root, 32);
    ad.first_seen_unix = now_unix;
    ad.last_seen_unix = now_unix;
    ad.seen_count = 1;
    if (g_ad_count >= ZSWAP_YARDSALE_MAX_ADS) {
        int stalest = 0;
        for (int i = 1; i < g_ad_count; i++) {
            if (g_ads[i].last_seen_unix < g_ads[stalest].last_seen_unix)
                stalest = i;
        }
        g_counters.ads_evicted++;
        g_ads[stalest] = ad;
    } else {
        g_ads[g_ad_count++] = ad;
    }
    g_counters.ads_stored++;
    if (out_ad) *out_ad = ad;
    pthread_mutex_unlock(&g_yardsale_mutex);

    printf("yardsale: new ad (token_amount=%llu zcl_amount=%llu sats) "
           "seen_count=1\n",
           (unsigned long long)quote.token_amount,
           (unsigned long long)quote.zcl_amount);
    return ZSWAP_YARDSALE_INGEST_NEW;
}

/* ── Queries ────────────────────────────────────────────────────── */

bool zswap_yardsale_find(const uint8_t quote_root[32],
                         struct zswap_yardsale_ad *out)
{
    if (!quote_root || !out)
        LOG_FAIL("zswap", "yardsale_find: NULL root=%d out=%d",
                 !quote_root, !out);
    pthread_mutex_lock(&g_yardsale_mutex);
    for (int i = 0; i < g_ad_count; i++) {
        if (memcmp(g_ads[i].quote_root, quote_root, 32) == 0) {
            *out = g_ads[i];
            pthread_mutex_unlock(&g_yardsale_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&g_yardsale_mutex);
    return false;
}

int zswap_yardsale_best_for_token(const uint8_t token_id[32],
                                  int64_t now_unix,
                                  struct zswap_yardsale_ad *out, size_t max)
{
    if (!token_id || (!out && max > 0))
        LOG_RETURN(0, "zswap",
                   "yardsale_best_for_token: NULL token=%d out=%d",
                   !token_id, !out);

    struct zswap_yardsale_ad match[ZSWAP_YARDSALE_QUERY_CAP];
    size_t n = 0;
    pthread_mutex_lock(&g_yardsale_mutex);
    yardsale_prune_locked(now_unix);
    for (int i = 0; i < g_ad_count && n < ZSWAP_YARDSALE_QUERY_CAP; i++) {
        if (memcmp(g_ads[i].quote.token_id, token_id, 32) == 0)
            match[n++] = g_ads[i];
    }
    pthread_mutex_unlock(&g_yardsale_mutex);

    qsort(match, n, sizeof(match[0]), ad_price_qsort_cmp);
    if (n > max) n = max;
    memcpy(out, match, n * sizeof(match[0]));
    return (int)n;
}

/* ── Counters + introspection ───────────────────────────────────── */

void zswap_yardsale_counters_snapshot(struct zswap_yardsale_counters *out)
{
    if (!out) return;
    pthread_mutex_lock(&g_yardsale_mutex);
    *out = g_counters;
    pthread_mutex_unlock(&g_yardsale_mutex);
}

void zswap_yardsale_reset(void)
{
    pthread_mutex_lock(&g_yardsale_mutex);
    memset(g_ads, 0, sizeof(g_ads));
    g_ad_count = 0;
    memset(g_peers, 0, sizeof(g_peers));
    memset(&g_counters, 0, sizeof(g_counters));
    pthread_mutex_unlock(&g_yardsale_mutex);
}

bool zswap_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    int64_t now = (int64_t)platform_time_wall_time_t();

    pthread_mutex_lock(&g_yardsale_mutex);
    yardsale_prune_locked(now);
    int cache_size = g_ad_count;
    int64_t oldest_expiry = 0, newest_expiry = 0;
    for (int i = 0; i < g_ad_count; i++) {
        int64_t e = g_ads[i].quote.expires_unix;
        if (oldest_expiry == 0 || e < oldest_expiry) oldest_expiry = e;
        if (e > newest_expiry) newest_expiry = e;
    }
    struct zswap_yardsale_counters c = g_counters;
    pthread_mutex_unlock(&g_yardsale_mutex);

    json_push_kv_int(out, "cache_size", (int64_t)cache_size);
    json_push_kv_int(out, "cache_cap", (int64_t)ZSWAP_YARDSALE_MAX_ADS);
    json_push_kv_int(out, "wires_seen", (int64_t)c.wires_seen);
    json_push_kv_int(out, "ads_stored", (int64_t)c.ads_stored);
    json_push_kv_int(out, "ads_deduped", (int64_t)c.ads_deduped);
    json_push_kv_int(out, "ads_dropped_invalid", (int64_t)c.ads_dropped_invalid);
    json_push_kv_int(out, "ads_dropped_expired", (int64_t)c.ads_dropped_expired);
    json_push_kv_int(out, "ads_dropped_rate", (int64_t)c.ads_dropped_rate);
    json_push_kv_int(out, "ads_pruned", (int64_t)c.ads_pruned);
    json_push_kv_int(out, "ads_evicted", (int64_t)c.ads_evicted);
    json_push_kv_int(out, "oldest_expiry_unix", oldest_expiry);
    json_push_kv_int(out, "newest_expiry_unix", newest_expiry);
    json_push_kv_int(out, "peer_window_secs",
                     (int64_t)ZSWAP_YARDSALE_PEER_WINDOW_SECS);
    json_push_kv_int(out, "peer_window_max_ads",
                     (int64_t)ZSWAP_YARDSALE_PEER_WINDOW_MAX_ADS);
    return true;
}
