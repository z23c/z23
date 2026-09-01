/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Market: Crypto-incentivized P2P file sharing.
 *
 * In-memory offer cache + serialization. SQLite persistence lives in the
 * FileOffer model; gossip logic receives offers, decrements TTL, and
 * re-broadcasts. */

#include "platform/time_compat.h"
#include "net/file_market.h"
#include "core/serialize.h"
#include "util/log_macros.h"
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <pthread.h>

/* ── In-Memory Offer Cache ──────────────────────────────────────── */

static struct file_offer g_offers[FILE_MARKET_MAX_OFFERS];
static int g_offer_count = 0;
static pthread_mutex_t g_market_mutex = PTHREAD_MUTEX_INITIALIZER;

struct file_market_peer_window {
    bool used;
    int64_t peer_id;
    int64_t window_start_unix;
    unsigned attempts;
    unsigned new_offers;
};
static struct file_market_peer_window g_offer_peers[FILE_MARKET_PEER_SLOTS];

/* ── Size Validation ────────────────────────────────────────────── */

bool file_market_num_chunks_for_size(uint64_t size_bytes,
                                     uint32_t *out_chunks)
{
    if (!out_chunks) {
        LOG_FAIL("market",
                 "num_chunks_for_size: NULL out_chunks");
        return false;
    }
    /* Reject sizes that would make num_chunks overflow u32. Max
     * accepted = UINT32_MAX * CHUNK_SIZE (~225 PB) — way above any
     * plausible real file. This also implicitly caps the
     * (size + CHUNK_SIZE - 1) u64 arithmetic far below UINT64_MAX. */
    const uint64_t max_size =
        (uint64_t)UINT32_MAX * (uint64_t)FILE_MARKET_CHUNK_SIZE;
    if (size_bytes > max_size) {
        LOG_FAIL("market",
                 "num_chunks_for_size: size_bytes too large for u32 "
                 "chunk count");
        return false;
    }
    *out_chunks = (uint32_t)((size_bytes + FILE_MARKET_CHUNK_SIZE - 1)
                              / FILE_MARKET_CHUNK_SIZE);
    return true;
}

/* ── Serialization ──────────────────────────────────────────────── */

bool file_offer_serialize(const struct file_offer *offer,
                          struct byte_stream *s)
{
    bool ok = true;
    ok &= stream_write(s, offer->root_hash, 32);

    /* filename: length-prefixed, max 255 bytes */
    size_t namelen = strlen(offer->filename);
    if (namelen > 255) namelen = 255;
    ok &= stream_write_u8(s, (uint8_t)namelen);
    ok &= stream_write(s, offer->filename, namelen);

    ok &= stream_write_u64_le(s, offer->size_bytes);
    ok &= stream_write_u32_le(s, offer->num_chunks);
    ok &= stream_write_i64_le(s, offer->price_per_mb);
    ok &= stream_write(s, offer->z_addr, 43);
    ok &= stream_write(s, offer->peer_ip, 16);
    ok &= stream_write_u16_le(s, offer->peer_port);
    ok &= stream_write_u8(s, offer->ttl);
    return ok;
}

bool file_offer_deserialize(struct file_offer *offer,
                            struct byte_stream *s)
{
    memset(offer, 0, sizeof(*offer));
    bool ok = true;

    ok &= stream_read(s, offer->root_hash, 32);

    uint8_t namelen = 0;
    ok &= stream_read_u8(s, &namelen);
    if (!ok) LOG_FAIL("market", "file_offer_deserialize: read namelen failed");
    ok &= stream_read(s, offer->filename, namelen);
    offer->filename[namelen] = '\0';

    ok &= stream_read_u64_le(s, &offer->size_bytes);
    ok &= stream_read_u32_le(s, &offer->num_chunks);
    ok &= stream_read_i64_le(s, &offer->price_per_mb);
    ok &= stream_read(s, offer->z_addr, 43);
    ok &= stream_read(s, offer->peer_ip, 16);
    ok &= stream_read_u16_le(s, &offer->peer_port);
    ok &= stream_read_u8(s, &offer->ttl);

    if (ok) offer->last_seen = (int64_t)platform_time_wall_time_t();
    return ok;
}

bool file_challenge_serialize(const struct file_challenge *chal,
                              struct byte_stream *s)
{
    bool ok = true;
    ok &= stream_write(s, chal->root_hash, 32);
    ok &= stream_write_u32_le(s, chal->chunk_index);
    return ok;
}

bool file_challenge_deserialize(struct file_challenge *chal,
                                struct byte_stream *s)
{
    memset(chal, 0, sizeof(*chal));
    bool ok = true;
    ok &= stream_read(s, chal->root_hash, 32);
    ok &= stream_read_u32_le(s, &chal->chunk_index);
    return ok;
}

bool file_proof_serialize(const struct file_proof *proof,
                          struct byte_stream *s)
{
    bool ok = true;
    ok &= stream_write(s, proof->root_hash, 32);
    ok &= stream_write_u32_le(s, proof->chunk_index);
    ok &= stream_write(s, proof->chunk_hash, 32);
    return ok;
}

bool file_proof_deserialize(struct file_proof *proof,
                            struct byte_stream *s)
{
    memset(proof, 0, sizeof(*proof));
    bool ok = true;
    ok &= stream_read(s, proof->root_hash, 32);
    ok &= stream_read_u32_le(s, &proof->chunk_index);
    ok &= stream_read(s, proof->chunk_hash, 32);
    return ok;
}

/* ── Offer Cache ────────────────────────────────────────────────── */

bool file_market_offer_can_replace(const struct file_offer *existing,
                                   const struct file_offer *candidate)
{
    if (!existing || !candidate)
        return false;
    if (existing->auth_version >= FILE_MARKET_OFFER_VERSION &&
        candidate->auth_version >= FILE_MARKET_OFFER_VERSION)
        return memcmp(existing->seller_pubkey, candidate->seller_pubkey,
                      sizeof(existing->seller_pubkey)) == 0 &&
            (memcmp(existing->offer_id, candidate->offer_id,
                    sizeof(existing->offer_id)) == 0 ||
             candidate->issued_unix > existing->issued_unix ||
             (candidate->issued_unix == existing->issued_unix &&
              candidate->nonce > existing->nonce));
    return existing->auth_version == 0 && candidate->auth_version == 0 &&
        memcmp(existing->root_hash, candidate->root_hash,
               sizeof(existing->root_hash)) == 0 &&
        strcmp(existing->filename, candidate->filename) == 0 &&
        existing->size_bytes == candidate->size_bytes &&
        existing->num_chunks == candidate->num_chunks &&
        existing->price_per_mb == candidate->price_per_mb &&
        memcmp(existing->z_addr, candidate->z_addr,
               sizeof(existing->z_addr)) == 0 &&
        memcmp(existing->peer_ip, candidate->peer_ip,
               sizeof(existing->peer_ip)) == 0 &&
        existing->endpoint_type == candidate->endpoint_type &&
        memcmp(existing->onion_pubkey, candidate->onion_pubkey,
               sizeof(existing->onion_pubkey)) == 0 &&
        memcmp(existing->network_genesis, candidate->network_genesis,
               sizeof(existing->network_genesis)) == 0 &&
        memcmp(existing->seller_pubkey, candidate->seller_pubkey,
               sizeof(existing->seller_pubkey)) == 0 &&
        existing->nonce == candidate->nonce &&
        existing->issued_unix == candidate->issued_unix &&
        existing->expires_unix == candidate->expires_unix &&
        memcmp(existing->seller_signature, candidate->seller_signature,
               sizeof(existing->seller_signature)) == 0 &&
        memcmp(existing->offer_id, candidate->offer_id,
               sizeof(existing->offer_id)) == 0;
}

bool file_market_add_offer(const struct file_offer *offer)
{
    if (!offer || offer->ttl == 0 || offer->num_chunks == 0)
        LOG_FAIL("market", "add_offer: null offer or ttl=0 or num_chunks=0");
    /* Unsigned paid gossip is never admissible. The only auth_version=0
     * compatibility path is the price-zero ROM artifact catalog. */
    if (offer->price_per_mb > 0) {
        int64_t now_unix = (int64_t)platform_time_wall_time_t();
        if (file_offer_auth_validate_at(offer, now_unix) !=
                FILE_OFFER_AUTH_OK ||
            file_offer_auth_verify_signature(offer) != FILE_OFFER_AUTH_OK)
            LOG_FAIL("market", "add_offer: paid offer is invalid or expired");
    }

    pthread_mutex_lock(&g_market_mutex);

    /* Check for existing offer with same root_hash — update if newer */
    for (int i = 0; i < g_offer_count; i++) {
        if (memcmp(g_offers[i].root_hash, offer->root_hash, 32) == 0) {
            if (!file_market_offer_can_replace(&g_offers[i], offer)) {
                pthread_mutex_unlock(&g_market_mutex);
                LOG_FAIL("market",
                         "add_offer: listing takeover refused on root conflict");
            }
            g_offers[i] = *offer;
            g_offers[i].last_seen = (int64_t)platform_time_wall_time_t();
            pthread_mutex_unlock(&g_market_mutex);
            return false; /* updated, not new */
        }
    }

    /* Add new offer */
    if (g_offer_count >= FILE_MARKET_MAX_OFFERS) {
        /* Evict oldest */
        int oldest = 0;
        for (int i = 1; i < g_offer_count; i++) {
            if (g_offers[i].last_seen < g_offers[oldest].last_seen)
                oldest = i;
        }
        g_offers[oldest] = *offer;
        g_offers[oldest].last_seen = (int64_t)platform_time_wall_time_t();
        pthread_mutex_unlock(&g_market_mutex);
        return true;
    }

    g_offers[g_offer_count] = *offer;
    g_offers[g_offer_count].last_seen = (int64_t)platform_time_wall_time_t();
    g_offer_count++;
    pthread_mutex_unlock(&g_market_mutex);
    return true;
}

/* Caller holds g_market_mutex. One bounded window covers cheap admission
 * attempts and the smaller fresh-offer quota. This prevents forged signatures
 * from buying unlimited Ed25519/Sapling verification work. */
static struct file_market_peer_window *offer_peer_slot_locked(
    int64_t peer_id, int64_t now_unix)
{
    struct file_market_peer_window *slot = NULL;
    struct file_market_peer_window *oldest = &g_offer_peers[0];
    for (size_t i = 0; i < FILE_MARKET_PEER_SLOTS; i++) {
        if (!g_offer_peers[i].used) {
            slot = &g_offer_peers[i];
            break;
        }
        if (g_offer_peers[i].peer_id == peer_id) {
            slot = &g_offer_peers[i];
            break;
        }
        if (g_offer_peers[i].window_start_unix < oldest->window_start_unix)
            oldest = &g_offer_peers[i];
    }
    if (!slot)
        slot = oldest;
    if (!slot->used || slot->peer_id != peer_id ||
        now_unix < slot->window_start_unix ||
        now_unix - slot->window_start_unix >=
            FILE_MARKET_PEER_WINDOW_SECS) {
        memset(slot, 0, sizeof(*slot));
        slot->used = true;
        slot->peer_id = peer_id;
        slot->window_start_unix = now_unix;
    }
    return slot;
}

static bool offer_peer_attempt_locked(int64_t peer_id, int64_t now_unix)
{
    struct file_market_peer_window *slot = offer_peer_slot_locked(
        peer_id, now_unix);
    if (slot->attempts >= FILE_MARKET_PEER_WINDOW_MAX_ATTEMPTS)
        return false;
    slot->attempts++;
    return true;
}

static bool offer_peer_admit_locked(int64_t peer_id, int64_t now_unix)
{
    struct file_market_peer_window *slot = offer_peer_slot_locked(
        peer_id, now_unix);
    if (slot->new_offers >= FILE_MARKET_PEER_WINDOW_MAX_OFFERS)
        return false;
    slot->new_offers++;
    return true;
}

enum file_market_offer_ingest file_market_ingest_offer_wire_persist(
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_network_genesis[32],
    int64_t peer_id, int64_t now_unix, struct file_offer *out_offer,
    file_market_offer_persist_fn persist, void *persist_ctx)
{
    struct file_offer offer;
    pthread_mutex_lock(&g_market_mutex);
    bool attempt_allowed = offer_peer_attempt_locked(peer_id, now_unix);
    pthread_mutex_unlock(&g_market_mutex);
    if (!attempt_allowed)
        return FILE_MARKET_INGEST_RATE_LIMITED;

    enum file_offer_auth_error error = file_offer_auth_decode(
        wire, wire_len, &offer);
    if (error != FILE_OFFER_AUTH_OK)
        return FILE_MARKET_INGEST_INVALID;
    error = file_offer_auth_verify_at(&offer, expected_network_genesis,
                                      now_unix);
    if (error == FILE_OFFER_AUTH_ERR_EXPIRED)
        return FILE_MARKET_INGEST_EXPIRED;
    if (error != FILE_OFFER_AUTH_OK)
        return FILE_MARKET_INGEST_INVALID;
    offer.last_seen = now_unix;
    offer.ttl = FILE_MARKET_MAX_TTL;

    pthread_mutex_lock(&g_market_mutex);
    for (int i = 0; i < g_offer_count; i++) {
        if (file_offer_auth_version_supported(g_offers[i].auth_version) &&
            memcmp(g_offers[i].offer_id, offer.offer_id, 32) == 0) {
            if (persist && !persist(&offer, persist_ctx)) {
                pthread_mutex_unlock(&g_market_mutex);
                return FILE_MARKET_INGEST_PERSIST_FAILED;
            }
            g_offers[i].last_seen = now_unix;
            if (out_offer)
                *out_offer = g_offers[i];
            pthread_mutex_unlock(&g_market_mutex);
            return FILE_MARKET_INGEST_DEDUP;
        }
    }
    /* One seller owns the live contract for a content root. A fresh contract
     * from that seller may replace its stale terms; another seller cannot
     * enter cache, persistence, or relay state. */
    for (int i = 0; i < g_offer_count; i++) {
        if (memcmp(g_offers[i].root_hash, offer.root_hash, 32) == 0) {
            if (!file_market_offer_can_replace(&g_offers[i], &offer)) {
                pthread_mutex_unlock(&g_market_mutex);
                return FILE_MARKET_INGEST_CONFLICT;
            }
            if (!offer_peer_admit_locked(peer_id, now_unix)) {
                pthread_mutex_unlock(&g_market_mutex);
                return FILE_MARKET_INGEST_RATE_LIMITED;
            }
            if (persist && !persist(&offer, persist_ctx)) {
                pthread_mutex_unlock(&g_market_mutex);
                return FILE_MARKET_INGEST_PERSIST_FAILED;
            }
            g_offers[i] = offer;
            if (out_offer)
                *out_offer = offer;
            pthread_mutex_unlock(&g_market_mutex);
            return FILE_MARKET_INGEST_NEW;
        }
    }
    if (!offer_peer_admit_locked(peer_id, now_unix)) {
        pthread_mutex_unlock(&g_market_mutex);
        return FILE_MARKET_INGEST_RATE_LIMITED;
    }
    if (persist && !persist(&offer, persist_ctx)) {
        pthread_mutex_unlock(&g_market_mutex);
        return FILE_MARKET_INGEST_PERSIST_FAILED;
    }
    if (g_offer_count >= FILE_MARKET_MAX_OFFERS) {
        int oldest = 0;
        for (int i = 1; i < g_offer_count; i++) {
            if (g_offers[i].last_seen < g_offers[oldest].last_seen)
                oldest = i;
        }
        g_offers[oldest] = offer;
    } else {
        g_offers[g_offer_count++] = offer;
    }
    if (out_offer)
        *out_offer = offer;
    pthread_mutex_unlock(&g_market_mutex);
    return FILE_MARKET_INGEST_NEW;
}

enum file_market_offer_ingest file_market_ingest_offer_wire(
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_network_genesis[32],
    int64_t peer_id, int64_t now_unix, struct file_offer *out_offer)
{
    return file_market_ingest_offer_wire_persist(
        wire, wire_len, expected_network_genesis, peer_id, now_unix,
        out_offer, NULL, NULL);
}

int file_market_get_offers(struct file_offer *out, size_t max)
{
    pthread_mutex_lock(&g_market_mutex);
    int count = g_offer_count;
    if ((size_t)count > max) count = (int)max;
    memcpy(out, g_offers, count * sizeof(struct file_offer));
    pthread_mutex_unlock(&g_market_mutex);
    return count;
}

bool file_market_find_offer(const uint8_t root_hash[32],
                            struct file_offer *out)
{
    pthread_mutex_lock(&g_market_mutex);
    for (int i = 0; i < g_offer_count; i++) {
        if (memcmp(g_offers[i].root_hash, root_hash, 32) == 0) {
            *out = g_offers[i];
            pthread_mutex_unlock(&g_market_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&g_market_mutex);
    return false;
}

int file_market_prune(int64_t max_age)
{
    int64_t cutoff = (int64_t)platform_time_wall_time_t() - max_age;
    int pruned = 0;

    pthread_mutex_lock(&g_market_mutex);
    for (int i = 0; i < g_offer_count; ) {
        if (g_offers[i].last_seen < cutoff) {
            g_offers[i] = g_offers[g_offer_count - 1];
            g_offer_count--;
            pruned++;
        } else {
            i++;
        }
    }
    pthread_mutex_unlock(&g_market_mutex);
    return pruned;
}

int file_market_count(void)
{
    pthread_mutex_lock(&g_market_mutex);
    int c = g_offer_count;
    pthread_mutex_unlock(&g_market_mutex);
    return c;
}

/* ── Download Sessions ──────────────────────────────────────────── */

#define MAX_DOWNLOADS 16
static struct file_download g_downloads[MAX_DOWNLOADS];
static int g_download_count = 0;

int file_market_start_download(const uint8_t root_hash[32],
                               const char *output_path)
{
    struct file_offer offer;
    if (!file_market_find_offer(root_hash, &offer))
        LOG_ERR("market", "start_download: offer not found for root_hash");

    pthread_mutex_lock(&g_market_mutex);
    if (g_download_count >= MAX_DOWNLOADS) {
        pthread_mutex_unlock(&g_market_mutex);
        LOG_ERR("market", "start_download: max downloads %d reached", MAX_DOWNLOADS);
    }

    int idx = g_download_count++;
    memset(&g_downloads[idx], 0, sizeof(g_downloads[idx]));
    g_downloads[idx].offer = offer;
    g_downloads[idx].state = FDL_CHALLENGING;
    if (output_path)
        snprintf(g_downloads[idx].output_path, sizeof(g_downloads[idx].output_path),
                 "%s", output_path);
    pthread_mutex_unlock(&g_market_mutex);
    return idx;
}

bool file_market_get_download(const uint8_t root_hash[32],
                              struct file_download *out)
{
    pthread_mutex_lock(&g_market_mutex);
    for (int i = 0; i < g_download_count; i++) {
        if (memcmp(g_downloads[i].offer.root_hash, root_hash, 32) == 0) {
            *out = g_downloads[i];
            pthread_mutex_unlock(&g_market_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&g_market_mutex);
    return false;
}

bool file_market_update_download(const uint8_t root_hash[32],
                                 enum file_download_state state,
                                 uint32_t chunks_received,
                                 uint32_t chunks_paid_through)
{
    pthread_mutex_lock(&g_market_mutex);
    for (int i = 0; i < g_download_count; i++) {
        if (memcmp(g_downloads[i].offer.root_hash, root_hash, 32) == 0) {
            g_downloads[i].state = state;
            g_downloads[i].chunks_received = chunks_received;
            g_downloads[i].chunks_paid_through = chunks_paid_through;
            pthread_mutex_unlock(&g_market_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&g_market_mutex);
    return false;
}

bool file_market_download_challenge_passed(const uint8_t root_hash[32])
{
    pthread_mutex_lock(&g_market_mutex);
    for (int i = 0; i < g_download_count; i++) {
        if (memcmp(g_downloads[i].offer.root_hash, root_hash, 32) == 0) {
            g_downloads[i].challenges_passed++;
            pthread_mutex_unlock(&g_market_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&g_market_mutex);
    return false;
}
