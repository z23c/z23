/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

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
 * until the map gains an entry, the active tip moves or the best header
 * changes, or after 30 seconds. `pred` still reads each block's live status,
 * so a flag set after the scan is observed. Heights holding more blocks than the census can
 * store fall back to the full scan. Block index entries are never removed
 * from the map and `nHeight` never changes after insertion. */
struct block_index *block_height_find(struct main_state *ms, int height,
                                      block_height_pred_fn pred, void *ctx);

#ifdef ZCL_TESTING
/* Full scans performed since the last reset, for cache-hit assertions. */
unsigned long block_height_census_test_scans(void);
void block_height_census_test_reset(void);
#endif

#endif /* ZCL_CONDITIONS_BLOCK_HEIGHT_CENSUS_H */
