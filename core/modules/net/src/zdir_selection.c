/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZDIR selection — see net/zdir_selection.h for the design contract.
 * Pure: no clock, no allocation, no I/O, no globals, no locks. */

#include "net/zdir_selection.h"

#include "net/addrman.h"   /* ADDRMAN_REPUTATION_MAX_MULT — bound parity only */
#include "crypto/sha3.h"
#include "base/log_macros.h"

#include <string.h>

/* The weight ceiling here must BE addrman's ceiling. If someone widens one,
 * this stops the build rather than letting the directory outgrow the dial
 * that is supposed to bound it. */
_Static_assert(ZDIR_WEIGHT_MAX_MILLI ==
                   (uint32_t)ADDRMAN_REPUTATION_MAX_MULT * 1000u,
               "ZDIR weight ceiling must equal ADDRMAN_REPUTATION_MAX_MULT");
_Static_assert(ZDIR_WEIGHT_NEUTRAL_MILLI == 1000u,
               "ZDIR neutral weight must be exactly 1.0x");
_Static_assert(ZDIR_PREFERRED_MAX == ANCHOR_PEERS_MAX,
               "ZDIR preferred cap must track the anchor/outbound slot cap");

/* ── domain-separated hashing ───────────────────────────────────────── */

static void zdir_hash_begin(struct sha3_256_ctx *ctx, uint8_t domain)
{
    sha3_256_init(ctx);
    sha3_256_write(ctx, &domain, 1);
    sha3_256_write(ctx, (const unsigned char *)ZDIR_SELECTION_TAG,
                   ZDIR_SELECTION_TAG_LEN);
}

bool zdir_client_key(uint8_t out[32], const uint8_t node_secret[32])
{
    if (!out || !node_secret)
        LOG_FAIL("zdir", "client_key: null argument (out=%p secret=%p)",
                 (const void *)out, (const void *)node_secret);

    struct sha3_256_ctx ctx;
    zdir_hash_begin(&ctx, ZDIR_DOMAIN_CLIENT_KEY);
    sha3_256_write(&ctx, node_secret, 32);
    sha3_256_finalize(&ctx, out);
    return true;
}

bool zdir_epoch_seed(uint8_t out[32], const uint8_t block_hash[32],
                     const uint8_t client_key[32])
{
    if (!out || !block_hash || !client_key)
        LOG_FAIL("zdir", "epoch_seed: null argument (out=%p block=%p key=%p)",
                 (const void *)out, (const void *)block_hash,
                 (const void *)client_key);

    struct sha3_256_ctx ctx;
    zdir_hash_begin(&ctx, ZDIR_DOMAIN_SEED);
    sha3_256_write(&ctx, block_hash, 32);
    sha3_256_write(&ctx, client_key, 32);
    sha3_256_finalize(&ctx, out);
    return true;
}

bool zdir_candidate_score(uint8_t out[32], const uint8_t seed[32],
                          const uint8_t candidate_id[32])
{
    if (!out || !seed || !candidate_id)
        LOG_FAIL("zdir", "candidate_score: null argument (out=%p seed=%p id=%p)",
                 (const void *)out, (const void *)seed,
                 (const void *)candidate_id);

    struct sha3_256_ctx ctx;
    zdir_hash_begin(&ctx, ZDIR_DOMAIN_CANDIDATE);
    sha3_256_write(&ctx, seed, 32);
    sha3_256_write(&ctx, candidate_id, 32);
    sha3_256_finalize(&ctx, out);
    return true;
}

bool zdir_endpoint_id(uint8_t out[32], const struct net_addr *addr,
                      uint16_t port)
{
    if (!out || !addr)
        LOG_FAIL("zdir", "endpoint_id: null argument (out=%p addr=%p)",
                 (const void *)out, (const void *)addr);

    uint8_t flag = addr->has_torv3 ? 1u : 0u;
    uint8_t port_le[2] = { (uint8_t)(port & 0xffu), (uint8_t)(port >> 8) };

    struct sha3_256_ctx ctx;
    zdir_hash_begin(&ctx, ZDIR_DOMAIN_ENDPOINT);
    sha3_256_write(&ctx, addr->ip, 16);
    sha3_256_write(&ctx, addr->torv3, TORV3_ADDR_SIZE);
    sha3_256_write(&ctx, &flag, 1);
    sha3_256_write(&ctx, port_le, 2);
    sha3_256_finalize(&ctx, out);
    return true;
}

/* ── weighting ──────────────────────────────────────────────────────── */

uint16_t zdir_weight_milli(uint8_t bandwidth_score, uint32_t age_blocks,
                           uint32_t seniority_full_blocks)
{
    /* Seniority, scaled 0..255. seniority_full_blocks == 0 means the caller
     * has opted out of seniority entirely, which is full credit — never a
     * division by zero. */
    uint32_t seniority = 255u;
    if (seniority_full_blocks > 0u) {
        uint64_t age = age_blocks < seniority_full_blocks
                           ? (uint64_t)age_blocks
                           : (uint64_t)seniority_full_blocks;
        seniority = (uint32_t)((age * 255u) / (uint64_t)seniority_full_blocks);
    }

    /* Bandwidth gated by seniority: a brand-new relay claiming 255 earns 0. */
    uint32_t combined = ((uint32_t)bandwidth_score * seniority) / 255u;
    uint32_t span = ZDIR_WEIGHT_MAX_MILLI - ZDIR_WEIGHT_NEUTRAL_MILLI;
    return (uint16_t)(ZDIR_WEIGHT_NEUTRAL_MILLI + (span * combined) / 255u);
}

double zdir_weight_multiplier(uint16_t weight_milli)
{
    uint32_t w = weight_milli;
    if (w < ZDIR_WEIGHT_NEUTRAL_MILLI)
        w = ZDIR_WEIGHT_NEUTRAL_MILLI;
    if (w > ZDIR_WEIGHT_MAX_MILLI)
        w = ZDIR_WEIGHT_MAX_MILLI;
    return (double)w / 1000.0;
}

/* ── ranking ────────────────────────────────────────────────────────── */

/* Top 52 bits of the score digest, big-endian. 52 bits (not 64) so that
 * rank × weight_milli (< 2^12) always fits in a uint64_t and the
 * cross-multiplied comparison below needs no 128-bit arithmetic. */
static uint64_t zdir_rank_key(const uint8_t score[32])
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | score[i];
    return v >> 12;
}

/* Weighted rendezvous order: smaller rank/weight sorts first, so a heavier
 * weight pulls a candidate forward. Compared as rank_a × weight_b vs
 * rank_b × weight_a — integer only, no floating point, no platform drift.
 * Total order: ties fall through to the full digest, then the identity. */
static bool zdir_better(const uint8_t score_a[32], uint16_t weight_a,
                        const uint8_t id_a[32],
                        const uint8_t score_b[32], uint16_t weight_b,
                        const uint8_t id_b[32])
{
    uint64_t lhs = zdir_rank_key(score_a) * (uint64_t)weight_b;
    uint64_t rhs = zdir_rank_key(score_b) * (uint64_t)weight_a;
    if (lhs != rhs)
        return lhs < rhs;
    int c = memcmp(score_a, score_b, 32);
    if (c != 0)
        return c < 0;
    return memcmp(id_a, id_b, 32) < 0;
}

static uint32_t zdir_candidate_age(const struct zdir_params *params,
                                   const struct zdir_candidate *c)
{
    if (params->chain_height <= c->registration_height)
        return 0u;
    return params->chain_height - c->registration_height;
}

/* ── selection ──────────────────────────────────────────────────────── */

bool zdir_select(const struct zdir_params *params,
                 const struct zdir_candidate *candidates, size_t count,
                 uint16_t *weight_milli_out, struct zdir_selection *out)
{
    if (!params || !out)
        LOG_FAIL("zdir", "select: null argument (params=%p out=%p)",
                 (const void *)params, (const void *)out);
    if (count > 0 && !candidates)
        LOG_FAIL("zdir", "select: null candidate array with count=%zu", count);
    if (count > (size_t)ZDIR_CANDIDATES_MAX)
        LOG_FAIL("zdir", "select: candidate count %zu exceeds cap %u", count,
                 (unsigned)ZDIR_CANDIDATES_MAX);

    memset(out, 0, sizeof(*out));
    if (!zdir_epoch_seed(out->seed, params->block_hash, params->client_key))
        LOG_FAIL("zdir", "select: epoch seed derivation failed");

    /* Neutral first: any candidate this function never prefers keeps the
     * exact behaviour of a node with no directory. Non-exclusion is the
     * default state of the output buffer, not a branch we must remember. */
    if (weight_milli_out) {
        for (size_t i = 0; i < count; i++)
            weight_milli_out[i] = (uint16_t)ZDIR_WEIGHT_NEUTRAL_MILLI;
    }

    uint32_t want = params->want;
    if (want > (uint32_t)ZDIR_PREFERRED_MAX)
        want = (uint32_t)ZDIR_PREFERRED_MAX;
    uint32_t owner_cap = params->per_owner_cap ? params->per_owner_cap : 1u;

    for (uint32_t slot = 0; slot < want; slot++) {
        bool have_best = false;
        size_t best_idx = 0;
        uint8_t best_score[32] = { 0 };
        uint16_t best_weight = (uint16_t)ZDIR_WEIGHT_NEUTRAL_MILLI;

        for (size_t i = 0; i < count; i++) {
            /* Already preferred? (preferred_count <= 8, so this stays cheap.) */
            bool taken = false;
            uint32_t owner_used = 0;
            for (uint32_t k = 0; k < out->preferred_count; k++) {
                size_t p = (size_t)out->preferred[k];
                if (p == i) { taken = true; break; }
                if (memcmp(candidates[p].owner_id, candidates[i].owner_id,
                           32) == 0)
                    owner_used++;
            }
            if (taken || owner_used >= owner_cap)
                continue;

            uint8_t score[32];
            if (!zdir_candidate_score(score, out->seed, candidates[i].id))
                LOG_FAIL("zdir", "select: score derivation failed at index %zu",
                         i);
            uint16_t weight =
                zdir_weight_milli(candidates[i].bandwidth_score,
                                  zdir_candidate_age(params, &candidates[i]),
                                  params->seniority_full_blocks);

            if (!have_best ||
                zdir_better(score, weight, candidates[i].id, best_score,
                            best_weight, candidates[best_idx].id)) {
                have_best = true;
                best_idx = i;
                best_weight = weight;
                memcpy(best_score, score, 32);
            }
        }

        if (!have_best)
            break;   /* fewer eligible candidates than slots — not an error */

        out->preferred[out->preferred_count] = (uint32_t)best_idx;
        memcpy(out->score[out->preferred_count], best_score, 32);
        out->preferred_count++;
        if (weight_milli_out)
            weight_milli_out[best_idx] = best_weight;
    }

    return true;
}

/* ── anchors.dat adapter ────────────────────────────────────────────── */

bool zdir_candidates_from_anchors(const struct anchor_peer_set *set,
                                  struct zdir_candidate *out, size_t out_cap,
                                  size_t *out_count)
{
    if (!set || !out || !out_count)
        LOG_FAIL("zdir", "from_anchors: null argument (set=%p out=%p n=%p)",
                 (const void *)set, (const void *)out, (const void *)out_count);

    *out_count = 0;
    size_t n = set->count;
    if (n > ANCHOR_PEERS_MAX)
        LOG_FAIL("zdir", "from_anchors: anchor count %zu exceeds %d", n,
                 ANCHOR_PEERS_MAX);
    if (n > out_cap)
        n = out_cap;

    for (size_t i = 0; i < n; i++) {
        const struct anchor_peer *a = &set->peers[i];
        memset(&out[i], 0, sizeof(out[i]));
        if (!zdir_endpoint_id(out[i].id, &a->addr, a->port))
            LOG_FAIL("zdir", "from_anchors: endpoint id failed at index %zu", i);
        /* An anchor vouches for itself: it is a peer we personally proved
         * healthy, not a directory claim, so it is its own owner and the
         * per-owner cap never collapses the set. */
        memcpy(out[i].owner_id, out[i].id, 32);
        out[i].registration_height =
            a->last_height > 0 ? (uint32_t)a->last_height : 0u;
        out[i].bandwidth_score = 0;   /* unmeasured → NEUTRAL weight */
    }

    *out_count = n;
    return true;
}
