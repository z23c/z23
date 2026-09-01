/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Consensus Reject Index — hash-keyed ring of recent rejections.
 *
 * Motivation
 * ----------
 * When a block or transaction is rejected by `check_block` /
 * `check_transaction`, the emitters fire `EV_CONSENSUS_REJECT_BLOCK`
 * and `EV_CONSENSUS_REJECT_TX` events whose payloads include the
 * rejected hash. Those events feed `z23 core consensus report` metrics
 * endpoint, but metrics alone can't answer the single most important
 * diagnostic question operators ask:
 *
 *     "Why was block / tx <HASH> rejected?"
 *
 * Answering that question with the event ring buffer is O(N)
 * plus a string-parse, plus the global ring gets filled with
 * unrelated events so the recent rejections age out fast. This
 * service is the purpose-built index: it subscribes to the two
 * consensus reject events, parses the payload into a typed
 * entry, and stores the most recent N entries in a fixed-size
 * ring keyed by hash. `consensus_reject_index_lookup()` is O(N)
 * over the small ring (default N=256) and returns the reason,
 * dos score, type, and timestamp for any hash that is still
 * present.
 *
 * The service backs a future native reject-explanation command, which should
 * wrap `consensus_reject_index_lookup()` rather than duplicate this state.
 *
 * Design
 * ------
 * - Fixed-size ring, power-of-two capacity (default 256).
 * - Newest writes overwrite oldest slots (true ring, O(1) write).
 * - Lookup is a linear scan backward from the write head — newest
 *   matches win when the same hash is rejected twice (valuable:
 *   the operator typically wants the *latest* rejection reason).
 * - Single mutex guards the ring. Writes happen on the event
 *   emit thread (currently the validation thread), reads on
 *   operator threads (RPC / native). Contention is negligible.
 * - Registered as a synchronous observer on both reject events
 *   so there's no latency window between emission and index
 *   update — `lookup()` is consistent the instant the emitter
 *   returns.
 *
 * Lifecycle
 * ---------
 * Operators call `consensus_reject_index_start(capacity)` once
 * at boot. Tests can call start/stop freely — stop clears
 * observers and frees the ring. Calling start twice without
 * stop in between is a no-op (idempotent) so the service can
 * be initialised from multiple boot entry points safely.
 *
 * Thread safety
 * -------------
 * All public functions are safe from any thread. Writes take
 * the mutex; reads take the mutex. The ring is not lock-free
 * because rejections are rare enough (they're an error path)
 * that the complexity of a lock-free design isn't warranted.
 */

#ifndef ZCL_SERVICES_CONSENSUS_REJECT_INDEX_H
#define ZCL_SERVICES_CONSENSUS_REJECT_INDEX_H

#include "core/uint256.h"
#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Tunables ─────────────────────────────────────────────── */

#define CRI_DEFAULT_CAPACITY   256
#define CRI_MAX_CAPACITY      4096
#define CRI_REASON_MAX          80

enum cri_kind {
    CRI_KIND_TX    = 0,
    CRI_KIND_BLOCK = 1,
};

struct cri_entry {
    struct uint256 hash;
    enum cri_kind  kind;
    int32_t        dos;
    int64_t        ts_us;              /* microseconds since epoch */
    char           reason[CRI_REASON_MAX];
};

/* ── Lifecycle ────────────────────────────────────────────── */

/* Start the index with the given ring capacity. capacity=0 picks
 * the default (256). Capacity is clamped to [8, CRI_MAX_CAPACITY]
 * and rounded up to the next power of two. Idempotent — calling
 * start while already running is a no-op that returns ZCL_OK.
 * Returns a non-ok zcl_result on allocation failure. */
struct zcl_result consensus_reject_index_start(size_t capacity);

/* Stop the index and free the ring. Unregisters observers.
 * Safe to call when not running. */
void consensus_reject_index_stop(void);

/* Is the service currently running? */
bool consensus_reject_index_running(void);

/* Drop every entry but keep the ring allocated and observers
 * registered. Used by tests between assertions. */
void consensus_reject_index_clear(void);

/* ── Queries (all O(N) over the ring) ─────────────────────── */

/* Total rejections observed since start (not the ring size —
 * this keeps counting past the ring capacity). */
uint64_t consensus_reject_index_total(void);

/* Current number of entries in the ring (bounded by capacity). */
size_t consensus_reject_index_count(void);

/* Ring capacity. */
size_t consensus_reject_index_capacity(void);

/* Look up the most recent rejection for the given hash. The
 * optional `kind` argument, if non-null, restricts the search to
 * entries of that kind (use for "was this block rejected?" vs
 * "was this txid rejected?"). Pass NULL to match either kind.
 * Returns ZCL_OK and fills *out if found; a non-ok zcl_result names
 * the bad input or that no matching entry is present (a cache miss
 * is the common, expected case for an unrejected hash). */
struct zcl_result consensus_reject_index_lookup(const struct uint256 *hash,
                                                 const enum cri_kind *kind,
                                                 struct cri_entry *out);

/* Copy up to `cap` most recent entries (newest first) into
 * `out`. Returns the number actually copied. */
size_t consensus_reject_index_recent(struct cri_entry *out, size_t cap);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool consensus_reject_index_dump_state_json(struct json_value *out,
                                            const char *key);

/* ── Internal hook (for tests / manual feeding) ───────────── */

/* Record an entry directly without going through the event
 * system. Tests use this to assert ring/eviction behaviour
 * without having to craft failing transactions. The service
 * must be running. */
void consensus_reject_index_record(const struct cri_entry *e);

#endif /* ZCL_SERVICES_CONSENSUS_REJECT_INDEX_H */
