/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * parity_sample — bounded, retained history of the mirror's per-tick
 * consensus-parity comparison against the co-located zclassicd oracle.
 * One row per legacy_mirror_sync comparison outcome (see
 * engine/services/src/legacy_mirror_sync_service.c: lms_cache_comparison),
 * covering every branch the comparator can land in: a clean agreeing
 * sample, a same-height hash disagreement, an unreachable-oracle sample,
 * and the "no common height available yet" sample. This turns the mirror's
 * ad-hoc rpc-unreachable / hash-disagreement blockers into a trendable time
 * series so a breach that only ever fires transiently (never long enough to
 * page) is still visible in a bounded window, not just as a point-in-time
 * blocker snapshot.
 *
 * Purely observational: never consulted by consensus. Bounded retention —
 * pruned to the newest N rows (see parity_slo_breach condition for the
 * detector that reads the *live* mirror stats directly; this table is the
 * durable trend record, not the detector's input). */

#ifndef ZCL_DB_MODEL_PARITY_SAMPLE_H
#define ZCL_DB_MODEL_PARITY_SAMPLE_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

/* One retained parity comparison sample. heights_equal_at is the common
 * height the comparator actually verified at, or -1 when no common height
 * was available yet (still catching up / neither side had a usable hash).
 * hash_equal is meaningful only when heights_equal_at >= 0; it is stored 0
 * for an unresolved comparison so a query never has to special-case NULL. */
struct db_parity_sample {
    int64_t ts;                 /* observed_at, unix seconds */
    int64_t our_height;         /* local chain height at sample time */
    int64_t oracle_height;      /* zclassicd-reported height (last known) */
    int64_t heights_equal_at;   /* common height compared, or -1 */
    int     hash_equal;         /* 0/1 */
    int     oracle_reachable;   /* 0/1 */
};

/* Lazily-initialized before/after-save callback registry for the model. */
struct ar_callbacks *db_parity_sample_callbacks(void);

/* Populate errors with any validation failures. Returns true iff valid. */
bool db_parity_sample_validate(const struct db_parity_sample *s,
                               struct ar_errors *errors);

/* Insert one sample row. Runs the AR lifecycle (validate + hooks). Stamps
 * ts if unset. Returns false on bad args / veto / DB error. */
bool db_parity_sample_save(struct node_db *ndb,
                           const struct db_parity_sample *s);

/* Bounded retention: delete all but the newest keep_rows rows (by id).
 * Returns true on success (including nothing-to-delete). */
bool db_parity_sample_prune(struct node_db *ndb, int keep_rows);

/* Total retained rows. Returns 0 on bad args / empty. */
int db_parity_sample_count(struct node_db *ndb);

/* Load up to max most-recent samples (newest first) into out.
 * Returns the number of rows written, or 0 on bad args / empty. */
int db_parity_sample_recent(struct node_db *ndb,
                            struct db_parity_sample *out, size_t max);

#endif /* ZCL_DB_MODEL_PARITY_SAMPLE_H */
