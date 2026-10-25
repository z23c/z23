/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_turnstile_seed - background seeder for the ZIP-209 pool-totals
 * table (storage/shielded_pool_kv.h).
 *
 * The table is one contiguous run [0..M]; the stage writes row h only when
 * row h-1 exists, so a node that synced before the turnstile existed has no
 * rows and nothing is ever checked. After each drain (including idle ticks
 * at tip) this fills the run up to cursor-1 from the block bodies, at most
 * 1024 heights and ~100 ms of reads per call, then writes the slice in one
 * short BEGIN IMMEDIATE txn. It never refuses, holds or delays a block and
 * touches no table but shielded_pool_totals. */

#ifndef ZCL_JOBS_UTXO_APPLY_TURNSTILE_SEED_H
#define ZCL_JOBS_UTXO_APPLY_TURNSTILE_SEED_H

#include <stdbool.h>
#include <stdint.h>

struct block;
struct block_index;
struct main_state;
struct sqlite3;

#define UA_TURNSTILE_SEED_MAX_ROWS 1024
#define UA_TURNSTILE_SEED_READ_BUDGET_US 100000

struct utxo_apply_turnstile_seed_stats {
    int64_t seeded_through;   /* highest height this process wrote, -1 none */
    uint64_t rows_written;
    uint64_t slices;
    int64_t last_slice_us;    /* wall time of the last Phase B txn */
    uint64_t read_us_total;   /* Phase A body read + parse time */
    const char *hold;         /* "none", "body" or "negative_total" */
};

/* Body reader: same shape as the stage reader seam. NULL reads the block
 * file directly (never the parse cache). */
typedef bool (*utxo_apply_turnstile_seed_reader_fn)(
    struct block *out, const struct block_index *bi, const char *datadir,
    void *user);

/* One seeding slice on `db`. True when at least one row was written. */
bool utxo_apply_turnstile_seed_run(
    struct sqlite3 *db, struct main_state *ms, const char *datadir,
    utxo_apply_turnstile_seed_reader_fn reader, void *reader_user);

/* Drain hook: seeds from the stage's own main_state, datadir and reader.
 * Skips while the stage is unbound, catch-up cadence or a reducer drive is
 * active. Call with no progress_store lock held. */
bool utxo_apply_turnstile_seed_post_commit(void);

void utxo_apply_turnstile_seed_stats_get(
    struct utxo_apply_turnstile_seed_stats *out);

/* Test seams: a callback between Phase A and Phase B, and a state reset. */
void utxo_apply_turnstile_seed_set_gap_hook_for_test(void (*fn)(void *),
                                                     void *user);
void utxo_apply_turnstile_seed_reset_for_test(void);

#endif
