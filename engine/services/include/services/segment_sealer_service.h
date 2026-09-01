/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Segment Sealer Service — the supervised background organ that turns finalized
 * block history into the sealed ROM substrate (engine/modules/storage/chain_segment). As
 * finality deepens, it seals completed CHAIN_SEGMENT_BLOCKS_PER_SEG (10k) ranges
 * that sit fully below the finalized frontier into <datadir>/segments and
 * rebuilds the manifest — one segment per tick, so it never competes with the
 * reducer drive for IO.
 *
 * It reads block bodies through the ordinary disk read path (active_chain_at +
 * read_block_from_disk_index_pread), never through reducer internals, so it
 * takes no csr->lock and honors the reducer drive lock-order law.
 *
 * OFF BY DEFAULT: sealing only runs when ZCL_SEGMENT_SEALER=1 (or start() is
 * called with force_enable, as tests do). When disabled the thread still ticks
 * its supervision heartbeat but seals nothing, so a default node's on-disk state
 * is unchanged.
 *
 * PRUNE-AFTER-SEAL: after a segment seals successfully, this service
 * immediately re-opens it (a full mmap + whole-segment SHA3 re-verify off
 * disk — not trusting the writer's own digest) and, only when that verify
 * passes AND an optional block_pruning_service has been wired via
 * segment_sealer_set_prune_service(), prunes the now-redundant blk*.dat range
 * strictly below the just-verified segment's top via
 * block_pruning_prune_sealed_range(). A verify failure never prunes — the
 * blk*.dat bodies remain the only copy until a later seal attempt succeeds.
 * prune_svc defaults to NULL (prune-after-seal disabled) so a caller that
 * never wires it sees byte-for-byte unchanged sealer behavior.
 *
 * API
 * ---
 *   segment_sealer_init(svc, ms, datadir)  — init struct (reads env flag)
 *   segment_sealer_set_prune_service(svc, prune_svc) — wire prune-after-seal
 *   segment_sealer_start(svc)              — launch background thread
 *   segment_sealer_stop(svc)               — join thread
 *   segment_sealer_run_catchup(svc, n, force) — seal up to n segments (tests)
 *   segment_sealer_dump_state_json — `z23 dumpstate segment_sealer`
 */

#ifndef ZCL_SERVICES_SEGMENT_SEALER_SERVICE_H
#define ZCL_SERVICES_SEGMENT_SEALER_SERVICE_H

#include "storage/chain_segment.h"
#include "util/result.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* Depth below the active tip that a block must reach before its segment is
 * eligible to seal. Sealed history is immutable, so this is a conservative
 * finality margin against a shallow reorg re-writing a body we already froze. */
#define SEGMENT_SEALER_DEFAULT_FINALITY_DEPTH 1000
#define SEGMENT_SEALER_DEFAULT_TICK_SECONDS   30

/* Boundary backfill catch-up: how many oldest-unsealed segments the sealer may
 * seal in a SINGLE tick. A node booting with existing history has a backlog of
 * finalized-but-unsealed segments below the frontier; this lets it walk that
 * backlog forward a bounded batch per tick (never O(chain) in one tick) instead
 * of a single segment every tick_seconds. Kept small so the sealer never races
 * the reducer drive for disk. */
#define SEGMENT_SEALER_DEFAULT_CATCHUP_BATCH  4

struct block_pruning_service;

struct segment_sealer_service {
    /* References (not owned) */
    struct main_state *ms;
    const char *datadir;

    /* Optional: prune-after-seal target. NULL (the segment_sealer_init
     * default) disables prune-after-seal entirely — wire it explicitly via
     * segment_sealer_set_prune_service(). Not owned. */
    struct block_pruning_service *prune_svc;

    /* Config */
    bool    enabled;         /* ZCL_SEGMENT_SEALER=1 or forced on */
    int     finality_depth;
    int     tick_seconds;
    int     catchup_batch;   /* max segments sealed per tick (bounded backfill) */

    /* Thread management */
    pthread_t    thread;
    bool         thread_started;
    _Atomic bool stop_requested;
    pthread_mutex_t ready_mutex;
    pthread_cond_t  ready_cond;
    bool            ready;

    /* Progress (atomics for lock-free reads) */
    _Atomic int     state;              /* 0 idle, 1 running, 2 stopped */
    _Atomic int64_t segments_sealed;    /* segments sealed this process */
    _Atomic int64_t seal_failures;      /* seal attempts that returned !ok */
    _Atomic int64_t last_sealed_first;  /* first_height of the last sealed seg */
    _Atomic int64_t frontier;           /* last computed finalized frontier */
    _Atomic int     last_status;        /* enum cseg_status of last attempt */

    /* Prune-after-seal observability (all zero when prune_svc is NULL) */
    _Atomic int64_t segments_verified;    /* post-seal re-verify succeeded */
    _Atomic int64_t verify_failures;      /* post-seal re-verify failed (never pruned) */
    _Atomic int64_t sealed_prune_files;   /* files pruned via the seal-triggered path */
};

/* Global pointer for dumpstate access. Set by boot, NULL before init. */
extern struct segment_sealer_service *g_segment_sealer;

void segment_sealer_init(struct segment_sealer_service *svc,
                         struct main_state *ms, const char *datadir);

/* Wire (or clear, with prune_svc=NULL) the optional prune-after-seal target.
 * Not owned; the caller keeps prune_svc alive for as long as this service
 * may seal. Safe to call before or after start(). */
void segment_sealer_set_prune_service(struct segment_sealer_service *svc,
                                      struct block_pruning_service *prune_svc);

struct zcl_result segment_sealer_start(struct segment_sealer_service *svc);
void segment_sealer_stop(struct segment_sealer_service *svc);

/* Bounded backfill catch-up: seal up to `max_segments` oldest-unsealed,
 * fully-below-frontier, 10k-aligned segments this pass. Returns the count
 * sealed (>=0), or -1 when the FIRST attempt errored before any segment was
 * sealed (partial progress on a later error is kept and returned as the count).
 * Bounded: one call is O(max_segments) segment writes, never O(chain). Ignores
 * the enabled flag when `force` is true. */
int segment_sealer_run_catchup(struct segment_sealer_service *svc,
                               uint32_t max_segments, bool force);

/* Pure single-seal primitive (no service state): seal the single oldest
 * unsealed, fully-below-`frontier_incl`, 10k-aligned segment in `dir` via
 * `body`. Returns 1 (sealed; *out_first = its first height when non-NULL), 0
 * (nothing eligible at/below the frontier — no file written), or -1 (store/seal
 * error, message in err). Never seals a segment whose top height exceeds
 * `frontier_incl`. Exposed for unit testing with a synthetic body source; the
 * service wires the ordinary disk body reader. */
int segment_sealer_seal_next(const char *dir, uint32_t frontier_incl,
                             chain_segment_body_fn body, void *user,
                             uint32_t *out_first, char *err, size_t errlen);

/* Pure range selector: the first unsealed, fully-below-frontier, 10k-aligned
 * segment. `frontier_incl` is the highest height safe to seal (inclusive).
 * Returns true and fills first/count when there is a segment to seal. The
 * store may be NULL (nothing sealed yet). Exposed for unit testing. */
struct chain_segment_store;
bool segment_sealer_next_range(uint32_t frontier_incl,
                               const struct chain_segment_store *store,
                               uint32_t *first, uint32_t *count);

struct json_value;
bool segment_sealer_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_SEGMENT_SEALER_SERVICE_H */
