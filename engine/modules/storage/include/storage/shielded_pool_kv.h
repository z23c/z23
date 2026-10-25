/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * shielded_pool_kv -- cumulative Sprout/Sapling pool totals per height in
 * progress.kv, the durable half of the ZIP-209 turnstile
 * (docs/work/reducer-shielded-consensus-plan.md (c)).
 *
 * One row per applied height holds the pool totals AFTER that block. A
 * missing row means "unknown" (zclassicd's optional semantics), never zero.
 * Writes join the caller's transaction; the reducer writes the row inside
 * the stage txn and every rewind deletes abandoned-branch rows in the same
 * transaction. A deterministic recompute must agree with a stored row. */

#ifndef STORAGE_SHIELDED_POOL_KV_H
#define STORAGE_SHIELDED_POOL_KV_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

/* Create shielded_pool_totals (additive; touches no other table). */
bool shielded_pool_kv_ensure_schema(struct sqlite3 *db);

/* Read the row at `height`. *found_out says whether it exists. */
bool shielded_pool_kv_get(struct sqlite3 *db, int64_t height,
                          int64_t *sprout_out, int64_t *sapling_out,
                          bool *found_out);

/* Store the totals at `height`. An existing row with the same values is ok;
 * different values return false (a recompute must agree). */
bool shielded_pool_kv_put(struct sqlite3 *db, int64_t height,
                          int64_t sprout, int64_t sapling);

/* Highest stored height; *found_out false (and *height_out -1) when empty. */
bool shielded_pool_kv_max_height(struct sqlite3 *db, int64_t *height_out,
                                 bool *found_out);

/* Delete rows with from <= height <= to. */
bool shielded_pool_kv_delete_range(struct sqlite3 *db, int64_t from,
                                   int64_t to);

#endif
