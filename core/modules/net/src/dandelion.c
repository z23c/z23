/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Dandelion++ transaction propagation — stem/fluff relay for tx origin
 * privacy. See dandelion.h for protocol overview.
 *
 * Thread safety: all public functions acquire ds->cs. The caller must
 * NOT hold ds->cs when calling these functions. The caller MAY hold
 * net_manager->cs_nodes when calling dandelion_maybe_rotate_epoch()
 * (it acquires cs_nodes internally only if not rotating). */

#include "platform/time_compat.h"
#include "net/dandelion.h"
#include "crypto/random_secret.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ── Lifecycle ─────────────────────────────────────────────────── */

void dandelion_init(struct dandelion_state *ds)
{
    memset(ds, 0, sizeof(*ds));
    zcl_mutex_init(&ds->cs);
    ds->epoch_start = 0;
    ds->num_stem_peers = 0;
    ds->stempool_count = 0;
    ds->stem_rr_index = 0;
    ds->enabled = true;
    for (int i = 0; i < DANDELION_NUM_STEM_PEERS; i++)
        ds->stem_peers[i] = DANDELION_NODE_ID_NONE;
}

void dandelion_free(struct dandelion_state *ds)
{
    zcl_mutex_destroy(&ds->cs);
    memset(ds, 0, sizeof(*ds));
}

/* ── Cryptographic RNG for stem decisions ───────────────────
 *
 * Dandelion's stem-peer selection (Fisher-Yates) and per-tx fluff
 * coin-flip MUST be unpredictable to the network. these ran
 * on an xorshift64 PRNG seeded from `platform_time_wall_time_t() ^ const` — ~31 bits
 * of effective entropy. An attacker who knows rough boot time and
 * epoch cadence could replay the stream and predict (a) which
 * outbound peers we use for stem relay this epoch and (b) every
 * fluff outcome — defeating Dandelion's origin-privacy property.
 *
 * Both decisions now route through `zcl_random_secret_bytes`, the
 * same source used for esk / Sapling rcm/rcv / Groth16 blinding.
 * On RNG failure (open(/dev/urandom) failure or all-zero output —
 * both extremely rare) callers safe-fail by aborting stem-peer
 * selection (leaves num_stem_peers=0 → next dandelion_should_stem
 * returns false → tx fluffs via normal relay) or returning false
 * from the coin-flip directly (tx fluffs).
 *
 * If a future "performance" refactor wants to swap this back to a
 * cheap PRNG: don't. The seed must be unpredictable to the network,
 * and fetching fresh per-call entropy is the simplest way to
 * guarantee that. Dandelion is not a hot path — the per-tx cost of
 * a /dev/urandom read is negligible compared to script verification.
 */

static bool dandelion_secret_u64(uint64_t *out, const char *label)
{
    uint8_t buf[8];
    if (!zcl_random_secret_bytes(buf, sizeof buf, label))
        return false;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)buf[i] << (i * 8);
    *out = v;
    return true;
}

/* ── Epoch management ──────────────────────────────────────────── */

void dandelion_maybe_rotate_epoch(struct dandelion_state *ds,
                                  struct net_manager *nm)
{
    if (!ds || !nm)
        return;

    int64_t now = (int64_t)platform_time_wall_time_t();

    zcl_mutex_lock(&ds->cs);

    if (ds->epoch_start != 0 &&
        (now - ds->epoch_start) < DANDELION_EPOCH_SECS) {
        zcl_mutex_unlock(&ds->cs);
        return;
    }

    /* New epoch — pick stem relay peers from connected outbound peers */
    ds->epoch_start = now;
    ds->num_stem_peers = 0;
    for (int i = 0; i < DANDELION_NUM_STEM_PEERS; i++)
        ds->stem_peers[i] = DANDELION_NODE_ID_NONE;

    /* Collect eligible peer IDs (outbound, handshake complete, relays tx) */
    node_id_t candidates[MAX_OUTBOUND_CONNECTIONS];
    int num_candidates = 0;

    zcl_mutex_lock(&nm->cs_nodes);
    for (size_t i = 0; i < nm->num_nodes && num_candidates < MAX_OUTBOUND_CONNECTIONS; i++) {
        struct p2p_node *peer = nm->nodes[i];
        if (!peer->inbound &&
            peer->state >= PEER_HANDSHAKE_COMPLETE &&
            !peer->disconnect &&
            peer->relay_txes) {
            candidates[num_candidates++] = peer->id;
        }
    }
    zcl_mutex_unlock(&nm->cs_nodes);

    /* Fisher-Yates shuffle backed by the cryptographic RNG. On RNG
     * failure: leave num_stem_peers=0 so dandelion_should_stem returns
     * false and txs fluff via normal relay (safer than picking with a
     * compromised RNG). */
    bool rng_ok = true;
    for (int i = num_candidates - 1; i > 0; i--) {
        uint64_t r;
        if (!dandelion_secret_u64(&r, "dandelion-stem-shuffle")) {
            rng_ok = false;
            break;
        }
        int j = (int)(r % (uint64_t)(i + 1));
        node_id_t tmp = candidates[i];
        candidates[i] = candidates[j];
        candidates[j] = tmp;
    }

    if (!rng_ok) {
        fprintf(stderr, "[dandelion] stem-peer RNG failed; deferring "  // obs-ok:helper-context-logged
                        "selection (txs will fluff this epoch)\n");
        ds->num_stem_peers = 0;
        ds->stem_rr_index = 0;
        for (int i = 0; i < DANDELION_NUM_STEM_PEERS; i++)
            ds->stem_peers[i] = DANDELION_NODE_ID_NONE;
        zcl_mutex_unlock(&ds->cs);
        return;
    }

    int pick = num_candidates < DANDELION_NUM_STEM_PEERS
             ? num_candidates : DANDELION_NUM_STEM_PEERS;
    for (int i = 0; i < pick; i++)
        ds->stem_peers[i] = candidates[i];
    ds->num_stem_peers = pick;
    ds->stem_rr_index = 0;

    if (pick > 0) {
        fprintf(stderr, "[dandelion] new epoch: %d stem peer(s) selected\n", pick);  // obs-ok:helper-context-logged
    }

    zcl_mutex_unlock(&ds->cs);
}

/* ── Core routing ──────────────────────────────────────────────── */

bool dandelion_should_stem(struct dandelion_state *ds, node_id_t from_peer)
{
    (void)from_peer;

    if (!ds)
        return false;

    zcl_mutex_lock(&ds->cs);

    if (!ds->enabled || ds->num_stem_peers == 0) {
        zcl_mutex_unlock(&ds->cs);
        return false;
    }

    /* Each hop independently decides to fluff with DANDELION_FLUFF_PROB%.
     * On RNG failure: fluff (safer than stemming with a compromised
     * RNG; matches the safe-fail policy in maybe_rotate_epoch). */
    uint64_t r;
    if (!dandelion_secret_u64(&r, "dandelion-fluff-coin")) {
        zcl_mutex_unlock(&ds->cs);
        return false;
    }
    bool stem = ((r % 100) >= DANDELION_FLUFF_PROB);

    zcl_mutex_unlock(&ds->cs);
    return stem;
}

node_id_t dandelion_get_stem_peer(struct dandelion_state *ds,
                                  node_id_t from_peer)
{
    if (!ds)
        return DANDELION_NODE_ID_NONE;

    zcl_mutex_lock(&ds->cs);

    if (ds->num_stem_peers == 0) {
        zcl_mutex_unlock(&ds->cs);
        return DANDELION_NODE_ID_NONE;
    }

    /* Round-robin among stem peers, skipping from_peer */
    node_id_t chosen = DANDELION_NODE_ID_NONE;
    for (int attempt = 0; attempt < ds->num_stem_peers; attempt++) {
        int idx = (ds->stem_rr_index + attempt) % ds->num_stem_peers;
        if (ds->stem_peers[idx] != from_peer) {
            chosen = ds->stem_peers[idx];
            ds->stem_rr_index = (idx + 1) % ds->num_stem_peers;
            break;
        }
    }

    zcl_mutex_unlock(&ds->cs);
    return chosen;
}

/* ── Stem pool (embargo queue) ─────────────────────────────────── */

void dandelion_stempool_add(struct dandelion_state *ds,
                            const struct uint256 *txhash,
                            node_id_t from_peer)
{
    if (!ds || !txhash)
        return;

    zcl_mutex_lock(&ds->cs);

    /* Check for duplicate */
    for (int i = 0; i < DANDELION_MAX_STEMPOOL; i++) {
        if (ds->stempool[i].active &&
            uint256_eq(&ds->stempool[i].txhash, txhash)) {
            zcl_mutex_unlock(&ds->cs);
            return;
        }
    }

    /* Find empty slot, or evict oldest */
    int slot = -1;
    int64_t oldest_time = INT64_MAX;
    int oldest_slot = 0;

    for (int i = 0; i < DANDELION_MAX_STEMPOOL; i++) {
        if (!ds->stempool[i].active) {
            slot = i;
            break;
        }
        if (ds->stempool[i].embargo_time < oldest_time) {
            oldest_time = ds->stempool[i].embargo_time;
            oldest_slot = i;
        }
    }

    if (slot < 0) {
        /* Evict oldest — it should have been fluffed already */
        slot = oldest_slot;
        ds->stempool_count--;
    }

    ds->stempool[slot].txhash = *txhash;
    ds->stempool[slot].embargo_time = (int64_t)platform_time_wall_time_t() + DANDELION_EMBARGO_SECS;
    ds->stempool[slot].from_peer = from_peer;
    ds->stempool[slot].active = true;
    ds->stempool_count++;

    zcl_mutex_unlock(&ds->cs);
}

bool dandelion_stempool_remove(struct dandelion_state *ds,
                               const struct uint256 *txhash)
{
    if (!ds || !txhash)
        return false;

    zcl_mutex_lock(&ds->cs);

    for (int i = 0; i < DANDELION_MAX_STEMPOOL; i++) {
        if (ds->stempool[i].active &&
            uint256_eq(&ds->stempool[i].txhash, txhash)) {
            ds->stempool[i].active = false;
            ds->stempool_count--;
            zcl_mutex_unlock(&ds->cs);
            return true;
        }
    }

    zcl_mutex_unlock(&ds->cs);
    return false;
}

int dandelion_stempool_check_embargo(struct dandelion_state *ds,
                                     struct uint256 *out_hashes,
                                     int max_out)
{
    if (!ds || !out_hashes || max_out <= 0)
        return 0;

    int64_t now = (int64_t)platform_time_wall_time_t();
    int count = 0;

    zcl_mutex_lock(&ds->cs);

    for (int i = 0; i < DANDELION_MAX_STEMPOOL && count < max_out; i++) {
        if (ds->stempool[i].active &&
            now >= ds->stempool[i].embargo_time) {
            out_hashes[count++] = ds->stempool[i].txhash;
            ds->stempool[i].active = false;
            ds->stempool_count--;
            ds->stat_embargo_fluff++;
        }
    }

    zcl_mutex_unlock(&ds->cs);
    return count;
}

bool dandelion_stempool_contains(struct dandelion_state *ds,
                                 const struct uint256 *txhash)
{
    if (!ds || !txhash)
        return false;

    zcl_mutex_lock(&ds->cs);

    for (int i = 0; i < DANDELION_MAX_STEMPOOL; i++) {
        if (ds->stempool[i].active &&
            uint256_eq(&ds->stempool[i].txhash, txhash)) {
            zcl_mutex_unlock(&ds->cs);
            return true;
        }
    }

    zcl_mutex_unlock(&ds->cs);
    return false;
}

#ifdef ZCL_TESTING
/* acceptance hooks. These exercise the same RNG-driven shuffle
 * and coin-flip used by dandelion_maybe_rotate_epoch and
 * dandelion_should_stem, in a form that doesn't require a populated
 * net_manager. NOT for production callers. */

bool dandelion_test_shuffle(node_id_t *inout, int n)
{
    if (!inout || n < 0)
        return false;
    for (int i = n - 1; i > 0; i--) {
        uint64_t r;
        if (!dandelion_secret_u64(&r, "dandelion-test-shuffle"))
            return false;
        int j = (int)(r % (uint64_t)(i + 1));
        node_id_t tmp = inout[i];
        inout[i] = inout[j];
        inout[j] = tmp;
    }
    return true;
}

bool dandelion_test_should_stem_coin(bool *out_stem)
{
    if (!out_stem)
        return false;
    uint64_t r;
    if (!dandelion_secret_u64(&r, "dandelion-test-coin"))
        return false;
    *out_stem = ((r % 100) >= DANDELION_FLUFF_PROB);
    return true;
}
#endif
