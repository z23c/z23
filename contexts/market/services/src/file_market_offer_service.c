/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact, owner-signed, idempotent file-market seller offers. */

#include "services/file_market_offer_service.h"

#include "models/file_offer.h"
#include "models/market_content.h"
#include "models/market_seller_key.h"
#include "net/file_market.h"
#include "services/file_market_content_service.h"
#include "support/cleanse.h"
#include "util/log_macros.h"

#include <openssl/rand.h>
#include <limits.h>
#include <string.h>

enum market_offer_error {
    MARKET_OFFER_ERR_ARGS = -1,
    MARKET_OFFER_ERR_CONTENT_UNAVAILABLE = -2,
    MARKET_OFFER_ERR_CONTENT_INVALID = -3,
    MARKET_OFFER_ERR_CONTENT_TOO_LARGE = -4,
    MARKET_OFFER_ERR_CONTENT_UNSTABLE = -5,
    MARKET_OFFER_ERR_PRICE = -6,
    MARKET_OFFER_ERR_ENDPOINT = -7,
    MARKET_OFFER_ERR_PAYEE = -8,
    MARKET_OFFER_ERR_SELLER_KEY = -9,
    MARKET_OFFER_ERR_SEAL = -10,
    MARKET_OFFER_ERR_SAVE = -11,
    MARKET_OFFER_ERR_CONTENT_BIND = -12,
    MARKET_OFFER_ERR_WIRE = -13,
    MARKET_OFFER_ERR_ONION_ENDPOINT = -14,
};

static struct zcl_result offer_runtime_validate(
    const struct market_offer_runtime *rt, bool committing)
{
    static const uint8_t zero32[32] = {0};
    if (!rt || !rt->node_db || !rt->node_db->open || rt->now_unix <= 0 ||
        memcmp(rt->network_genesis, zero32, 32) == 0)
        return ZCL_ERR(MARKET_OFFER_ERR_ARGS,
                       "open market database, network genesis, and observation time are required");
    if (committing && (!rt->endpoint || !rt->payee || !rt->announce))
        return ZCL_ERR(MARKET_OFFER_ERR_ARGS,
                       "offer commit requires endpoint, payee, and announce ports");
    if (committing && rt->prefer_onion && !rt->onion_endpoint)
        return ZCL_ERR(MARKET_OFFER_ERR_ARGS,
                       "onion-endpoint offer commit requires the onion endpoint port");
    return ZCL_OK;
}

static struct zcl_result offer_request_validate(
    const struct market_offer_request *req)
{
    if (!req || !req->filepath || !req->filepath[0])
        return ZCL_ERR(MARKET_OFFER_ERR_ARGS,
                       "a private content filepath is required");
    if (req->price_per_mb_zat <= 0)
        return ZCL_ERR(MARKET_OFFER_ERR_PRICE,
                       "paid offers require a positive price per MB; free files use romseed_register");
    return ZCL_OK;
}

/* Map the content manifest builder's refusal onto the offer vocabulary. */
static struct zcl_result offer_manifest(
    const struct market_offer_request *req,
    char canonical[MARKET_CONTENT_PATH_MAX], uint64_t *size_out,
    uint32_t *chunks_out, uint8_t root_out[32])
{
    struct zcl_result r = file_market_content_manifest_build(
        req->filepath, canonical, NULL, size_out, chunks_out, root_out);
    if (r.ok)
        return r;
    switch (r.code) {
    case -4: /* MARKET_CONTENT_ERR_TYPE */
        return ZCL_ERR(MARKET_OFFER_ERR_CONTENT_INVALID, "%s", r.message);
    case -5: /* MARKET_CONTENT_ERR_SIZE */
    case -6: /* MARKET_CONTENT_ERR_LIMIT */
        return ZCL_ERR(MARKET_OFFER_ERR_CONTENT_TOO_LARGE, "%s", r.message);
    case -7: /* MARKET_CONTENT_ERR_IO */
        return ZCL_ERR(MARKET_OFFER_ERR_CONTENT_UNSTABLE, "%s", r.message);
    default:
        return ZCL_ERR(MARKET_OFFER_ERR_CONTENT_UNAVAILABLE, "%s", r.message);
    }
}

static struct zcl_result offer_filename(const char *canonical,
                                        char out[256])
{
    const char *base = strrchr(canonical, '/');
    base = base ? base + 1 : canonical;
    size_t len = strlen(base);
    if (len == 0 || len > 255)
        return ZCL_ERR(MARKET_OFFER_ERR_CONTENT_INVALID,
                       "content basename exceeds the signed offer filename limit");
    memcpy(out, base, len + 1);
    return ZCL_OK;
}

static struct zcl_result offer_total(uint64_t size_bytes,
                                     int64_t price_per_mb, int64_t *total_out)
{
    struct file_offer pricing;
    memset(&pricing, 0, sizeof(pricing));
    pricing.size_bytes = size_bytes;
    pricing.price_per_mb = price_per_mb;
    if (!file_market_offer_total_zat(&pricing, total_out))
        return ZCL_ERR(MARKET_OFFER_ERR_PRICE,
                       "size times price overflows the exact money bound");
    return ZCL_OK;
}

static void offer_view_fill(const struct file_offer *offer, int64_t total_zat,
                            struct market_offer_view *out)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->offer_id, offer->offer_id, 32);
    memcpy(out->root_hash, offer->root_hash, 32);
    memcpy(out->seller_pubkey, offer->seller_pubkey, 32);
    snprintf(out->filename, sizeof(out->filename), "%s", offer->filename);
    out->size_bytes = offer->size_bytes;
    out->num_chunks = offer->num_chunks;
    out->price_per_mb = offer->price_per_mb;
    out->total_zat = total_zat;
    out->expires_unix = offer->expires_unix;
    out->endpoint_type = offer->endpoint_type;
}

struct zcl_result file_market_offer_plan(
    const struct market_offer_runtime *rt,
    const struct market_offer_request *req,
    struct market_offer_view *out)
{
    ZCL_CHECK(offer_runtime_validate(rt, false));
    ZCL_CHECK(offer_request_validate(req));
    if (!out)
        return ZCL_ERR(MARKET_OFFER_ERR_ARGS, "plan output is required");
    memset(out, 0, sizeof(*out));

    char canonical[MARKET_CONTENT_PATH_MAX];
    ZCL_CHECK(offer_manifest(req, canonical, &out->size_bytes,
                             &out->num_chunks, out->root_hash));
    ZCL_CHECK(offer_filename(canonical, out->filename));
    ZCL_CHECK(offer_total(out->size_bytes, req->price_per_mb_zat,
                          &out->total_zat));
    out->price_per_mb = req->price_per_mb_zat;
    out->expires_unix = rt->now_unix + FILE_MARKET_OFFER_MAX_LIFETIME_SECS;
    return ZCL_OK;
}

/* A live replay exists only when the durable offer for this exact content is
 * still valid, prices identically, belongs to this owner's seller key,
 * commits the same endpoint kind, and its private content binding survived.
 * The endpoint-kind clause is what keeps an onion-preferring node from
 * silently replaying a stale clearnet offer (or vice versa). */
static bool offer_replay(struct node_db *ndb,
                         const struct market_offer_runtime *rt,
                         const uint8_t root[32], int64_t price_per_mb,
                         const uint8_t seller_pubkey[32],
                         struct file_offer *existing)
{
    uint8_t want_endpoint = rt->prefer_onion
        ? FILE_MARKET_ENDPOINT_ONION : FILE_MARKET_ENDPOINT_CLEARNET;
    struct market_content_chunk_record binding;
    return db_file_offer_find(ndb, root, existing) &&
        file_offer_auth_version_supported(existing->auth_version) &&
        existing->endpoint_type == want_endpoint &&
        existing->price_per_mb == price_per_mb &&
        memcmp(existing->seller_pubkey, seller_pubkey, 32) == 0 &&
        file_offer_auth_verify_at(existing, rt->network_genesis,
                                  rt->now_unix) == FILE_OFFER_AUTH_OK &&
        db_market_content_find_chunk(ndb, existing->offer_id, 0, &binding);
}

struct zcl_result file_market_offer_commit(
    const struct market_offer_runtime *rt,
    const struct market_offer_request *req,
    struct market_offer_view *out)
{
    ZCL_CHECK(offer_runtime_validate(rt, true));
    ZCL_CHECK(offer_request_validate(req));
    if (!out)
        return ZCL_ERR(MARKET_OFFER_ERR_ARGS, "commit output is required");
    memset(out, 0, sizeof(*out));

    char canonical[MARKET_CONTENT_PATH_MAX];
    uint64_t size_bytes = 0;
    uint32_t num_chunks = 0;
    uint8_t root[32];
    ZCL_CHECK(offer_manifest(req, canonical, &size_bytes, &num_chunks, root));
    char filename[256];
    ZCL_CHECK(offer_filename(canonical, filename));
    int64_t total_zat = 0;
    ZCL_CHECK(offer_total(size_bytes, req->price_per_mb_zat, &total_zat));

    uint8_t seed[32], seller_pubkey[32];
    if (!db_market_seller_key_ensure(rt->node_db, seed, seller_pubkey,
                                     rt->now_unix))
        return ZCL_ERR(MARKET_OFFER_ERR_SELLER_KEY,
                       "owner seller signing key is unavailable (wallet locked or metadata DEK missing)");

    struct file_offer existing;
    if (offer_replay(rt->node_db, rt, root, req->price_per_mb_zat,
                     seller_pubkey, &existing)) {
        memory_cleanse(seed, sizeof(seed));
        offer_view_fill(&existing, total_zat, out);
        out->idempotent_replay = true;
        return ZCL_OK;
    }

    uint8_t peer_ip[16];
    uint16_t peer_port = 0;
    uint8_t onion_pubkey[32];
    memset(peer_ip, 0, sizeof(peer_ip));
    memset(onion_pubkey, 0, sizeof(onion_pubkey));
    if (rt->prefer_onion) {
        /* The node-level default chose onion (see the runtime contract):
         * sign a v2 onion-endpoint offer or refuse — never downgrade. */
        struct zcl_result onion = rt->onion_endpoint(
            rt->onion_endpoint_ctx, onion_pubkey);
        if (!onion.ok) {
            memory_cleanse(seed, sizeof(seed));
            return ZCL_ERR(MARKET_OFFER_ERR_ONION_ENDPOINT,
                           "own onion endpoint is unavailable: %s",
                           onion.message);
        }
    } else {
        struct zcl_result endpoint = rt->endpoint(rt->endpoint_ctx, peer_ip,
                                                  &peer_port);
        if (!endpoint.ok) {
            memory_cleanse(seed, sizeof(seed));
            return ZCL_ERR(MARKET_OFFER_ERR_ENDPOINT,
                           "own reachable file endpoint is unknown: %s",
                           endpoint.message);
        }
    }
    uint8_t z_addr[43];
    struct zcl_result payee = rt->payee(rt->payee_ctx, z_addr);
    if (!payee.ok) {
        memory_cleanse(seed, sizeof(seed));
        return ZCL_ERR(MARKET_OFFER_ERR_PAYEE,
                       "owner payee address is unavailable: %s", payee.message);
    }

    struct file_offer offer;
    memset(&offer, 0, sizeof(offer));
    memcpy(offer.root_hash, root, 32);
    memcpy(offer.network_genesis, rt->network_genesis, 32);
    memcpy(offer.seller_pubkey, seller_pubkey, 32);
    snprintf(offer.filename, sizeof(offer.filename), "%s", filename);
    offer.size_bytes = size_bytes;
    offer.num_chunks = num_chunks;
    offer.price_per_mb = req->price_per_mb_zat;
    memcpy(offer.z_addr, z_addr, sizeof(offer.z_addr));
    memcpy(offer.peer_ip, peer_ip, sizeof(offer.peer_ip));
    offer.peer_port = peer_port;
    if (rt->prefer_onion) {
        offer.auth_version = FILE_MARKET_OFFER_VERSION_V2;
        offer.endpoint_type = FILE_MARKET_ENDPOINT_ONION;
        memcpy(offer.onion_pubkey, onion_pubkey,
               sizeof(offer.onion_pubkey));
    } else {
        /* Clearnet stays on the v1 wire so pre-v2 nodes keep relaying and
         * buying these offers unchanged. */
        offer.auth_version = FILE_MARKET_OFFER_VERSION;
        offer.endpoint_type = FILE_MARKET_ENDPOINT_CLEARNET;
    }
    offer.last_seen = rt->now_unix;
    offer.ttl = FILE_MARKET_MAX_TTL;
    uint8_t nonce_bytes[8];
    if (RAND_bytes(nonce_bytes, sizeof(nonce_bytes)) != 1) {
        memory_cleanse(seed, sizeof(seed));
        return ZCL_ERR(MARKET_OFFER_ERR_SEAL,
                       "could not mint the offer nonce");
    }
    uint64_t nonce = 0;
    memcpy(&nonce, nonce_bytes, sizeof(nonce));
    offer.nonce = nonce & (uint64_t)INT64_MAX;
    if (offer.nonce == 0)
        offer.nonce = 1;
    struct file_offer previous;
    if (db_file_offer_find(rt->node_db, offer.root_hash, &previous) &&
        previous.auth_version >= FILE_MARKET_OFFER_VERSION &&
        memcmp(previous.seller_pubkey, offer.seller_pubkey,
               sizeof(previous.seller_pubkey)) == 0 &&
        previous.issued_unix == rt->now_unix &&
        offer.nonce <= previous.nonce) {
        if (previous.nonce == (uint64_t)INT64_MAX) {
            memory_cleanse(seed, sizeof(seed));
            return ZCL_ERR(MARKET_OFFER_ERR_SEAL,
                           "same-second offer sequence is exhausted");
        }
        offer.nonce = previous.nonce + 1;
    }
    offer.issued_unix = rt->now_unix;
    offer.expires_unix = rt->now_unix + FILE_MARKET_OFFER_MAX_LIFETIME_SECS;

    enum file_offer_auth_error sealed = file_offer_auth_seal(&offer, seed);
    memory_cleanse(seed, sizeof(seed));
    if (sealed != FILE_OFFER_AUTH_OK)
        return ZCL_ERR(MARKET_OFFER_ERR_SEAL,
                       "offer sealing failed: %s",
                       file_offer_auth_error_string(sealed));

    if (!db_file_offer_save(rt->node_db, &offer))
        return ZCL_ERR(MARKET_OFFER_ERR_SAVE,
                       "signed offer could not be persisted");

    struct market_content_public_record binding;
    struct zcl_result bound = file_market_content_register(
        rt->node_db, offer.offer_id, canonical, rt->now_unix, &binding);
    if (!bound.ok) {
        if (!db_file_offer_delete(rt->node_db, offer.root_hash))
            LOG_ERROR("market",
                      "compensating offer delete failed after content bind refusal");
        return ZCL_ERR(MARKET_OFFER_ERR_CONTENT_BIND,
                       "private content binding failed; offer rolled back: %s",
                       bound.message);
    }
    (void)file_market_add_offer(&offer);

    uint8_t wire[FILE_MARKET_OFFER_WIRE_BYTES_MAX];
    size_t wire_len = 0;
    if (file_offer_auth_encode_into(&offer, wire, sizeof(wire),
                                    &wire_len) != FILE_OFFER_AUTH_OK ||
        wire_len == 0)
        return ZCL_ERR(MARKET_OFFER_ERR_WIRE,
                       "persisted offer failed its own wire encoding");

    offer_view_fill(&offer, total_zat, out);
    out->announced = rt->announce(rt->announce_ctx, wire, wire_len);
    return ZCL_OK;
}
