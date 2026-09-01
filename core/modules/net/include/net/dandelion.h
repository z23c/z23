/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Dandelion++ Transaction Propagation (BIP 156 variant)
 *
 * Hides the origin of transactions by splitting relay into two phases:
 *
 *   Stem phase — forward tx to exactly 1 random peer (the "stem relay").
 *                Each node picks 2 stem relay peers per epoch (~10 min).
 *                A tx entering stem is forwarded along a random path.
 *
 *   Fluff phase — broadcast tx to all peers (normal inv relay).
 *                 Triggered by: (a) probabilistic fluff decision at each
 *                 hop (10% chance), (b) stem embargo timeout (~30s),
 *                 or (c) stem relay failure.
 *
 * The stem-to-fluff transition is probabilistic (each hop independently
 * decides), so the originator is hidden behind multiple stem hops.
 *
 * Wire protocol: uses standard "tx" and "inv" messages. Stem relay
 * sends the full tx directly (not inv) to the stem peer. No new P2P
 * commands needed — Dandelion++ is purely routing logic.
 *
 * Reference: Fanti et al., "Dandelion++: Lightweight Cryptocurrency
 * Networking with Formal Anonymity Guarantees" (SIGMETRICS 2018).
 */

#ifndef ZCL_DANDELION_H
#define ZCL_DANDELION_H

#include "core/uint256.h"
#include "net/net.h"
#include "util/sync.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* ── Constants ─────────────────────────────────────────────────── */

/* Epoch duration: stem relay peers rotate every ~10 minutes */
#define DANDELION_EPOCH_SECS      600

/* Embargo timeout: if a stemmed tx isn't seen back as fluff within
 * this many seconds, the node fluffs it (fail-safe). */
#define DANDELION_EMBARGO_SECS    30

/* Probability of transitioning from stem to fluff at each hop.
 * Stored as percent (0-100). Dandelion++ paper recommends ~10%. */
#define DANDELION_FLUFF_PROB      10

/* Maximum number of transactions in the stem pool (embargo queue).
 * Oldest entries are fluffed when this limit is reached. */
#define DANDELION_MAX_STEMPOOL    1024

/* Number of outbound stem relay peers per epoch */
#define DANDELION_NUM_STEM_PEERS  2

/* ── Stem pool entry ───────────────────────────────────────────── */

struct dandelion_stem_entry {
    struct uint256 txhash;       /* tx hash */
    int64_t        embargo_time; /* unix timestamp when embargo expires */
    node_id_t      from_peer;    /* peer that sent this tx (for loop detect) */
    bool           active;       /* slot in use */
};

/* ── Dandelion state ───────────────────────────────────────────── */

struct dandelion_state {
    /* Epoch management */
    int64_t    epoch_start;                            /* unix time */
    node_id_t  stem_peers[DANDELION_NUM_STEM_PEERS];   /* chosen stem relays */
    int        num_stem_peers;

    /* Stem pool (embargo queue): txs in stem phase awaiting fluff */
    struct dandelion_stem_entry stempool[DANDELION_MAX_STEMPOOL];
    int        stempool_count;

    /* Round-robin index for distributing among stem peers */
    int        stem_rr_index;

    /* Thread safety */
    zcl_mutex_t cs;

    /* Enabled flag (can be toggled at runtime) */
    bool       enabled;

    /* Stats */
    uint64_t   stat_stem_sent;     /* txs forwarded in stem phase */
    uint64_t   stat_fluffed;       /* txs transitioned to fluff */
    uint64_t   stat_embargo_fluff; /* txs fluffed due to embargo timeout */
};

/* ── Lifecycle ─────────────────────────────────────────────────── */

void dandelion_init(struct dandelion_state *ds);
void dandelion_free(struct dandelion_state *ds);

/* ── Epoch management ──────────────────────────────────────────── */

/* Check if epoch has expired and rotate stem peers if needed.
 * Must be called periodically (e.g., from message send loop).
 * nm is used to enumerate connected peers for stem selection. */
void dandelion_maybe_rotate_epoch(struct dandelion_state *ds,
                                  struct net_manager *nm);

/* ── Core routing ──────────────────────────────────────────────── */

/* Decide how to relay a newly received/created transaction.
 *
 * Returns true if the tx should be stemmed (caller should send full tx
 * to the stem peer via dandelion_get_stem_peer()).
 * Returns false if the tx should be fluffed (caller should broadcast
 * via normal inv relay to all peers).
 *
 * from_peer: the peer that sent us this tx (NODE_ID_NONE for local).
 *            Used for loop detection (won't stem back to sender). */
bool dandelion_should_stem(struct dandelion_state *ds, node_id_t from_peer);

/* Get the stem peer to relay a tx to. Returns the peer node_id,
 * or -1 if no suitable stem peer is available (caller should fluff).
 * from_peer is excluded to avoid sending back to the originator. */
node_id_t dandelion_get_stem_peer(struct dandelion_state *ds,
                                  node_id_t from_peer);

/* Add a tx to the stem pool (embargo queue). The tx will be fluffed
 * if not seen back within DANDELION_EMBARGO_SECS. */
void dandelion_stempool_add(struct dandelion_state *ds,
                            const struct uint256 *txhash,
                            node_id_t from_peer);

/* Remove a tx from the stem pool (called when we see it fluffed).
 * Returns true if the tx was in the stem pool. */
bool dandelion_stempool_remove(struct dandelion_state *ds,
                               const struct uint256 *txhash);

/* Check for expired embargo entries. Returns the number of txhashes
 * written to out_hashes (up to max_out). Caller should fluff these. */
int dandelion_stempool_check_embargo(struct dandelion_state *ds,
                                     struct uint256 *out_hashes,
                                     int max_out);

/* ── Helpers ───────────────────────────────────────────────────── */

/* Check if a tx is currently in the stem pool. */
bool dandelion_stempool_contains(struct dandelion_state *ds,
                                 const struct uint256 *txhash);

/* Sentinel value for "no peer" / "local origin" */
#define DANDELION_NODE_ID_NONE  ((node_id_t)-1)

#endif
