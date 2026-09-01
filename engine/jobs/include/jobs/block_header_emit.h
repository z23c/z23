/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared EV_BLOCK_HEADER / EV_BLOCK_STATUS emitters for the reducer stages.
 *
 * block_index_emit_header_event() is for FIRST ADMIT (header_admit_stage) and
 * genuine repair/heal corrections: it carries the full header, including the
 * up-to-1344-byte Equihash solution, so block_index_projection can construct
 * a brand-new row.
 *
 * block_index_emit_status_event() is for a PURE status bump on an entry that
 * ALREADY has a durable row (body_persist raising BLOCK_HAVE_DATA,
 * script_validate raising BLOCK_VALID_SCRIPTS): it carries only the mutable
 * fields (hash + nStatus/nFile/nDataPos/nUndoPos/nTx, 52 bytes fixed) instead
 * of re-serializing the immutable header fields + solution on every advance
 * (measured ~1.4KB/block/bump saved on the fold's hot path — the projection
 * patches its stored blob's mutable fields off that hot path, during its own
 * catch_up; see storage/block_index_projection.c).
 *
 * Both source scalars from the in-memory `struct block_index` (not the
 * disk_block_index that engine/modules/storage/block_index_db.c serializes). hashPrev is
 * the parent's phashBlock (all-zero for genesis). Best-effort/counted, never
 * fatal — exactly the block_index_db.c semantics. Counters are caller-owned
 * (per-stage observability via `z23 dumpstate`); pass NULL to skip. */

#ifndef ZCL_JOBS_BLOCK_HEADER_EMIT_H
#define ZCL_JOBS_BLOCK_HEADER_EMIT_H

#include "chain/chain.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/event_log_singleton.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

static inline bool block_index_emit_header_event(
        const struct block_index *bi, const char *tag,
        _Atomic uint64_t *emit_ok, _Atomic uint64_t *emit_fail)
{
    if (!bi || !bi->phashBlock)
        return false;

    event_log_t *log = event_log_singleton();
    if (!log) {
        /* Not wired yet (very early boot, or tests). The projection catches
         * up once boot completes — not a hard failure, not counted. */
        return false;
    }

    if (bi->nSolutionSize > EV_BLOCK_HEADER_MAX_SOLUTION) {
        LOG_WARN(tag, "[%s] header emit: solution size %zu > max %u for h=%d; "
                 "skipping", tag, bi->nSolutionSize,
                 (unsigned)EV_BLOCK_HEADER_MAX_SOLUTION, bi->nHeight);
        if (emit_fail)
            atomic_fetch_add_explicit(emit_fail, 1, memory_order_relaxed);
        return false;
    }

    struct ev_block_header h;
    memset(&h, 0, sizeof(h));
    memcpy(h.hash, bi->phashBlock->data, 32);
    if (bi->pprev && bi->pprev->phashBlock)
        memcpy(h.hashPrev, bi->pprev->phashBlock->data, 32);
    /* else: genesis — hashPrev stays all-zero (memset above) */
    h.height        = bi->nHeight;
    h.nStatus       = block_index_status_load(bi);
    h.nFile         = block_index_file_load(bi);
    h.nDataPos      = block_index_data_pos_load(bi);
    h.nUndoPos      = block_index_undo_pos_load(bi);
    h.nTime         = bi->nTime;
    h.nBits         = bi->nBits;
    memcpy(h.nNonce, bi->nNonce.data, 32);
    memcpy(h.hashMerkleRoot, bi->hashMerkleRoot.data, 32);
    memcpy(h.hashFinalSaplingRoot, bi->hashFinalSaplingRoot.data, 32);
    h.nVersion      = bi->nVersion;
    h.nTx           = bi->nTx;
    h.nSolutionSize = (uint16_t)bi->nSolutionSize;

    size_t bufcap = ev_block_header_wire_size(h.nSolutionSize);
    uint8_t stackbuf[256 + 1344];  /* fixed 200 + max solution 1344 */
    if (bufcap > sizeof(stackbuf)) {
        if (emit_fail)
            atomic_fetch_add_explicit(emit_fail, 1, memory_order_relaxed);
        return false;
    }
    size_t written = 0;
    if (!ev_block_header_serialize(&h, bi->nSolution, stackbuf, bufcap,
                                   &written)) {
        LOG_WARN(tag, "[%s] header emit: serialize failed h=%d",
                 tag, bi->nHeight);
        if (emit_fail)
            atomic_fetch_add_explicit(emit_fail, 1, memory_order_relaxed);
        return false;
    }

    uint64_t off = event_log_append(log, EV_BLOCK_HEADER, stackbuf, written);
    if (off == UINT64_MAX) {
        if (emit_fail)
            atomic_fetch_add_explicit(emit_fail, 1, memory_order_relaxed);
        return false;
    }
    if (emit_ok)
        atomic_fetch_add_explicit(emit_ok, 1, memory_order_relaxed);
    return true;
}

/* Lightweight counterpart of block_index_emit_header_event() above — see the
 * file header comment for when to use which. Requires a prior EV_BLOCK_HEADER
 * row for this hash to already exist in the projection (first admit always
 * runs upstream of body_persist/script_validate in the reducer pipeline); a
 * status event for a hash the projection has never folded is a durable-log
 * ordering defect, logged and counted by the projection's catch_up, never
 * fatal (the cursor still advances — see block_index_projection.c). */
static inline void block_index_emit_status_event(
        const struct block_index *bi, const char *tag,
        _Atomic uint64_t *emit_ok, _Atomic uint64_t *emit_fail)
{
    if (!bi || !bi->phashBlock)
        return;

    event_log_t *log = event_log_singleton();
    if (!log) {
        /* Not wired yet (very early boot, or tests). The projection catches
         * up once boot completes — not a hard failure, not counted. */
        return;
    }

    struct ev_block_status s;
    memset(&s, 0, sizeof(s));
    memcpy(s.hash, bi->phashBlock->data, 32);
    s.nStatus  = block_index_status_load(bi);
    s.nFile    = block_index_file_load(bi);
    s.nDataPos = block_index_data_pos_load(bi);
    s.nUndoPos = block_index_undo_pos_load(bi);
    s.nTx      = bi->nTx;

    uint8_t buf[EV_BLOCK_STATUS_WIRE_LEN];
    if (!ev_block_status_serialize(&s, buf)) {
        LOG_WARN(tag, "[%s] status emit: serialize failed h=%d",
                 tag, bi->nHeight);
        if (emit_fail)
            atomic_fetch_add_explicit(emit_fail, 1, memory_order_relaxed);
        return;
    }

    uint64_t off = event_log_append(log, EV_BLOCK_STATUS, buf, sizeof(buf));
    if (off == UINT64_MAX) {
        if (emit_fail)
            atomic_fetch_add_explicit(emit_fail, 1, memory_order_relaxed);
        return;
    }
    if (emit_ok)
        atomic_fetch_add_explicit(emit_ok, 1, memory_order_relaxed);
}

#endif /* ZCL_JOBS_BLOCK_HEADER_EMIT_H */
