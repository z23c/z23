/* Copyright (c) 2012 Pieter Wuille
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_ADDRMAN_H
#define ZCL_ADDRMAN_H

#include "net/netaddr.h"
#include "core/uint256.h"
#include "util/sync.h"
#include <stdbool.h>
#include <stdint.h>

#define ADDRMAN_TRIED_BUCKET_COUNT 256
#define ADDRMAN_NEW_BUCKET_COUNT 1024
#define ADDRMAN_BUCKET_SIZE 64
#define ADDRMAN_TRIED_BUCKETS_PER_GROUP 8
#define ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP 64
#define ADDRMAN_NEW_BUCKETS_PER_ADDRESS 8
#define ADDRMAN_HORIZON_DAYS 30
#define ADDRMAN_RETRIES 3
#define ADDRMAN_MAX_FAILURES 10
#define ADDRMAN_MIN_FAIL_DAYS 7
#define ADDRMAN_GETADDR_MAX_PCT 23
#define ADDRMAN_GETADDR_MAX 2500

#define ADDRMAN_MAX_ENTRIES (ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE)

struct addr_info {
    struct net_address addr;
    struct net_addr source;
    int64_t last_success;
    int64_t last_try;
    int attempts;
    int ref_count;
    bool in_tried;
    int random_pos;
    bool used;
    /* NO per-entry reputation weight. An address's dial-preference
     * multiplier is NOT a property of its addrman entry — it lives in the
     * published weight table below, and an address absent from that table
     * reads exactly 1.0. See "the published weight table". */
};

/* Maximum dial-preference multiplier a banked-fast peer can earn (bounded so
 * reputation can nudge, never dominate, address selection). */
#define ADDRMAN_REPUTATION_MAX_MULT 4.0

/* ── the published weight table ─────────────────────────────────────────
 *
 * The advisory dial-preference multiplier used to be a `double` stored on
 * each addr_info and written one address at a time. That made it a SECOND
 * WRITABLE COPY of a fact whose only authority is the per-epoch weighting
 * computation, and the two drifted: a peer boosted to 2.5x in one epoch that
 * recomputed to 1.0 in the next was simply never written again (the producer
 * returned early on "no opinion"), so it carried the dead 2.5x for the life
 * of the process. Worse, the producer never enumerated addrman at all, so an
 * address that stopped appearing in either input feed was never revisited.
 *
 * The copy is gone. The weighting computation publishes ONE immutable table
 * per ranking epoch and it is swapped in whole. There is deliberately NO
 * "clear one address's weight" entry point, because a clear path is exactly
 * what rotted: an address ABSENT from the published table reads 1.0 BY
 * CONSTRUCTION, so a weight disappears by not being republished.
 *
 * The table can only ever RAISE a candidate's dial chance (every multiplier
 * is clamped into [1.0, ADDRMAN_REPUTATION_MAX_MULT]) and can never remove
 * an address from selection.
 *
 * Concurrency: the table is immutable once published, and both the swap and
 * every read happen under `am->cs`. That gives reclamation for free — a
 * publisher holding `cs` knows no reader can still be inside the old table —
 * so there is no publish list to grow and no snapshot to leak. */

/* One published row: an address and the multiplier this epoch computed for
 * it. `ip` is addrman's own 16-byte address identity (ports are not part of
 * it — see net_addr_eq), IPv4 in its IPv4-mapped form. */
struct addrman_weight_row {
    uint8_t ip[16];
    double  multiplier;
};

/* One epoch's publication: immutable, sorted, opaque. Defined in addrman.c. */
struct addrman_weights;

/* O(1) address→entry-id index slot. Defined privately in addrman.c;
 * struct addr_man holds only a pointer, so a forward declaration is
 * enough here. See "address index" in addrman.c. */
struct addr_index_slot;

struct addr_man {
    zcl_mutex_t cs;
    struct uint256 nKey;

    struct addr_info *entries;
    size_t entries_cap;
    int id_count;

    /* In-memory O(1) net_addr→id index (open addressing, tombstoned).
     * NOT serialized — rebuilt from `entries` on load. Keeps addrman_add's
     * per-address dedup off the old O(id_count) linear scan. */
    struct addr_index_slot *idx;
    size_t idx_slots;   /* capacity, power of 2 */
    size_t idx_live;    /* live slots == number of used entries */
    size_t idx_tombs;   /* tombstoned slots */

    int *random_order;
    size_t random_size;
    size_t random_cap;

    int tried_count;
    int vvTried[ADDRMAN_TRIED_BUCKET_COUNT][ADDRMAN_BUCKET_SIZE];

    int new_count;
    int vvNew[ADDRMAN_NEW_BUCKET_COUNT][ADDRMAN_BUCKET_SIZE];

    /* The current epoch's published weight table, or NULL when nothing has
     * been published — in which case every address reads exactly 1.0.
     * Replaced whole under `cs`; never mutated in place. */
    struct addrman_weights *weights;
};

void addrman_init(struct addr_man *am);
void addrman_free(struct addr_man *am);
void addrman_clear(struct addr_man *am);
size_t addrman_size(const struct addr_man *am);

/* How many stored addresses this node has actually completed a connection
 * with at least once (last_success != 0).
 *
 * This is deliberately NOT addrman_size(). The table also holds hearsay —
 * addresses other peers told us about — and the hardcoded seed list, which
 * seed_from_fixed() injects on a cold boot and which then persists in
 * peers.dat forever. Only last_success distinguishes "a peer I have spoken
 * to" from "an address somebody handed me", and the bootstrap decision (do I
 * still need the shipped seed list?) must be made on the former. Takes `cs`. */
size_t addrman_proven_count(struct addr_man *am);

bool addrman_add(struct addr_man *am, const struct net_address *addr,
                 const struct net_addr *source, int64_t time_penalty);

void addrman_good(struct addr_man *am, const struct net_service *addr,
                  int64_t nTime);

void addrman_attempt(struct addr_man *am, const struct net_service *addr,
                     int64_t nTime);

/* Copy the exact endpoint's durable dial ledger. O(1) through addrman's
 * address index; false means the endpoint is absent or its port differs.
 * The caller never receives an internal pointer, so concurrent writers may
 * safely update the entry after this snapshot returns. */
bool addrman_find_info(struct addr_man *am, const struct net_service *addr,
                       struct addr_info *out);

bool addrman_select(struct addr_man *am, bool new_only,
                    struct addr_info *result);

void addrman_connected(struct addr_man *am, const struct net_service *addr,
                       int64_t nTime);

size_t addrman_get_addr(struct addr_man *am, struct net_address *out,
                        size_t max_out);

int addr_info_get_tried_bucket(const struct addr_info *info,
                               const struct uint256 *nKey);

int addr_info_get_new_bucket(const struct addr_info *info,
                             const struct uint256 *nKey,
                             const struct net_addr *src);

int addr_info_get_bucket_position(const struct addr_info *info,
                                  const struct uint256 *nKey,
                                  bool fNew, int nBucket);

bool addr_info_is_terrible(const struct addr_info *info, int64_t nNow);

/* The dial chance for one entry, including its published weight multiplier.
 *
 * CALL WITH `am->cs` HELD — that is where addrman_select calls it from, and
 * the published table is read under the same lock the publisher swaps it
 * under. `am` may be NULL, which reads the plain unweighted chance; that is
 * the form a caller scoring a detached struct addr_info uses. */
double addr_info_get_chance(const struct addr_man *am,
                            const struct addr_info *info, int64_t nNow);

/* Publish this epoch's whole dial-preference table, replacing whatever was
 * published before. `rows` is copied (the caller keeps ownership), clamped
 * into [1.0, ADDRMAN_REPUTATION_MAX_MULT], sorted, and de-duplicated keeping
 * the highest multiplier per address; rows at or below 1.0 are dropped
 * because absence already means 1.0. `n == 0` publishes an empty table,
 * which returns every address to the plain baseline — that is the intended
 * way a boost expires, and the only one.
 *
 * `epoch` is recorded for observation only; nothing here interprets it.
 *
 * Returns false WITHOUT replacing the live table when a registered
 * directory-influence policy is withholding influence
 * (net/directory_influence_port.h) — degraded mode while SUSPECTED_NETSPLIT
 * stands. The previously published table keeps working, exactly as before:
 * the refusal denies NEW influence, never existing preference, and never
 * makes selection exclusionary. Also false on an allocation failure, again
 * leaving the live table untouched. */
bool addrman_publish_reputation_weights(struct addr_man *am,
                                        const struct addrman_weight_row *rows,
                                        size_t n, int32_t epoch);

/* The published multiplier for one address, or exactly 1.0 when the address
 * is absent from the table or nothing has been published. Takes `cs`; do not
 * call from a path that already holds it. */
double addrman_reputation_weight(struct addr_man *am,
                                 const struct net_addr *addr);

/* Rows in the currently published table, and the epoch it was published for
 * (INT32_MIN when nothing has been published). Both take `cs`. */
size_t addrman_reputation_weight_count(struct addr_man *am);
int32_t addrman_reputation_weight_epoch(struct addr_man *am);

/* Verify internal consistency of bucket tables.
 * Returns 0 on success, negative on error.
 * err_buf (if non-NULL) receives a description of the first error found. */
int addrman_consistency_check(const struct addr_man *am,
                              char *err_buf, size_t err_cap);

/* Verify the in-memory address index agrees with a brute-force scan of
 * `entries` (find-by-index == find-by-scan for every used entry, live-slot
 * count matches, every live slot points at a matching used entry).
 * Returns 0 on success, -1 on the first discrepancy (described in err_buf).
 * A NULL index (OOM fallback to linear scan) verifies trivially. */
int addrman_index_verify(const struct addr_man *am,
                         char *err_buf, size_t err_cap);

/* Bucket distribution stats for monitoring/debugging. */
struct addrman_bucket_stats {
    int new_occupied;           /* total occupied slots in new table */
    int tried_occupied;         /* total occupied slots in tried table */
    int new_buckets_nonempty;   /* buckets with >= 1 entry */
    int tried_buckets_nonempty;
    int max_new_bucket_fill;    /* most-full new bucket */
    int max_tried_bucket_fill;  /* most-full tried bucket */
};

void addrman_get_bucket_stats(const struct addr_man *am,
                              struct addrman_bucket_stats *stats);

struct byte_stream;
bool addrman_serialize(const struct addr_man *am, struct byte_stream *s);
bool addrman_deserialize(struct addr_man *am, struct byte_stream *s);

#endif
