/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: per-height block census that lets self-heal conditions find blocks
 * at tip+1 without scanning the whole block map on every poll. */

#ifndef ZCL_CONDITIONS_BLOCK_HEIGHT_CENSUS_H
#define ZCL_CONDITIONS_BLOCK_HEIGHT_CENSUS_H

#include <stdbool.h>

struct block_index;
struct main_state;

typedef bool (*block_height_pred_fn)(const struct block_index *p, void *ctx);
/* First block in `ms->map_block_index` (bucket order) at `height` for which
 * `pred` is true, or NULL.
 *
 * Equivalent to scanning the whole block map, which costs one reader-lock
 * round trip and one cache miss per bucket (about 3 million at the tip).
 * The set of blocks at one height is gathered by a single scan and reused
 * until the map gains an entry, the active tip moves, the best header
 * changes, or 30 seconds pass. Each call re-reads `nHeight` and passes the
 * block to `pred`, which reads its live status, so a flag set or a height
 * rewritten after the scan is observed. `nHeight` is assigned or rewritten
 * after insertion (header relink, height repair), so a block that gains
 * `height` after the scan can stay unseen for up to 30 seconds. Block index
 * entries are never removed from the map. Heights holding more blocks than
 * the census can store use the full scan. */
struct block_index *block_height_find(struct main_state *ms, int height,
                                      block_height_pred_fn pred, void *ctx);

#ifdef ZCL_TESTING
#include <stdint.h>
/* Full scans performed since the last reset, for cache-hit assertions. */
unsigned long block_height_census_test_scans(void);
/* Replace the seconds clock the 30 s expiry reads; reset restores it. */
void block_height_census_test_set_clock(int64_t (*fn)(void));
void block_height_census_test_reset(void);
#endif

#endif /* ZCL_CONDITIONS_BLOCK_HEIGHT_CENSUS_H */
