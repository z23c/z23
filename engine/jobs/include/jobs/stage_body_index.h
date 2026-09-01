/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Resolve the canonical block-index entry that owns a stage body. */

#ifndef ZCL_JOBS_STAGE_BODY_INDEX_H
#define ZCL_JOBS_STAGE_BODY_INDEX_H

struct block_index;
struct main_state;

/* Resolve the block_index object that actually owns the body for the
 * canonical active/best-header block at height. Same-hash duplicates are a
 * storage identity detail, never a distinct consensus candidate. */
struct block_index *stage_body_index_at(struct main_state *ms, int height);

#endif /* ZCL_JOBS_STAGE_BODY_INDEX_H */
