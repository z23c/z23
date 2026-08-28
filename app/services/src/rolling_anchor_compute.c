// one-result-type-ok:state-free-window-predicates — every export here is a
// TOTAL predicate over caller-supplied inputs, not a fallible service
// surface: ra_snapshot_equal is snapshot equality, ra_quorum_allows_commit
// is a verdict that deliberately fails OPEN (an unprobeable oracle means
// "allowed"), and ra_compute_window_hash already threads its one
// distinguishable reason out through *out_failure_height — the same
// contract-bool-with-in/out shape E2 accepts elsewhere in this shape dir.
// The fallible surfaces of this service (init, start, window_hash_ending_at)
// return struct zcl_result and stay in rolling_anchor_service.c.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the rolling anchor's state-free computations — compile-time
 * prefix arithmetic, on-disk file-integrity helpers, window hashing from
 * disk, and the quorum commit predicate.
 *
 * Split out of app/services/src/rolling_anchor_service.c when that file
 * passed the 800-line shape ceiling. The seam is module state: not one
 * function here reads or writes g_ra or takes its lock, so this TU can be
 * reasoned about (and tested) without the service's lifecycle. The ring,
 * its mutex, persistence, the supervisor contract, and every public entry
 * point stay in rolling_anchor_service.c; the shared declarations are in
 * rolling_anchor_internal.h.
 */

#include "rolling_anchor_internal.h"

#include "chain/chain.h"
#include "chain/sha3_windows.h"
#include "core/serialize.h"
#include "crypto/sha3.h"
#include "primitives/block.h"
#include "services/quorum_oracle_service.h"
#include "storage/disk_block_io.h"
#include "validation/chainstate.h"

int ra_compile_time_end(void)
{
    if (g_sha3_windows_count == 0) return -1; // raw-return-ok:sentinel-no-compile-time-windows
    return (int)(g_sha3_windows_count * SHA3_WINDOW_SIZE) - 1;
}

/* Compute the file-level SHA3 over the on-disk body (everything before
 * the trailing 32-byte digest). Caller passes the body bytes + length. */
void ra_file_digest(const uint8_t *body, size_t body_len,
                     uint8_t out[32])
{
    sha3_256(body, body_len, out);
}

bool ra_snapshot_equal(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a->size == b->size &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds &&
           a->volume == b->volume && a->file_low == b->file_low &&
           a->file_high == b->file_high;
}

/* Caller holds lock. Compute SHA3 over heights [start_h..start_h+999]
 * by reading each block from disk via active_chain. Returns true if
 * every block was read; false on any I/O failure. */
bool ra_compute_window_hash(struct main_state *ms,
                             const char *datadir,
                             int start_h,
                             uint8_t out_hash[32],
                             int *out_failure_height)
{
    *out_failure_height = -1;
    if (!ms || !datadir || !datadir[0])
        return false;

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);

    struct byte_stream s;
    stream_init(&s, 4096);

    bool ok = true;
    for (int h = start_h; h < start_h + (int)SHA3_WINDOW_SIZE; h++) {
        struct block_index *bi = active_chain_at(&ms->chain_active, h);
        if (!bi || bi->nFile < 0 ||
            !(bi->nStatus & BLOCK_HAVE_DATA)) {
            *out_failure_height = h;
            ok = false;
            break;
        }
        struct block blk;
        block_init(&blk);
        if (!read_block_from_disk_index_pread(&blk, bi, datadir)) {
            block_free(&blk);
            *out_failure_height = h;
            ok = false;
            break;
        }
        s.size = 0;
        s.read_pos = 0;
        s.error = false;
        if (!block_serialize(&blk, &s)) {
            block_free(&blk);
            *out_failure_height = h;
            ok = false;
            break;
        }
        sha3_256_write(&ctx, s.data, s.size);
        block_free(&blk);
    }
    stream_free(&s);
    if (ok) sha3_256_finalize(&ctx, out_hash);
    return ok;
}

bool ra_quorum_allows_commit(int height)
{
    struct quorum_oracle_result qr;
    int present = 0;

    if (!quorum_oracle_probe(height, &qr).ok)
        return true;
    for (int i = 0; i < QO_SRC_NUM; i++) {
        if (qr.by_source[i].present && !qr.by_source[i].error &&
            qr.by_source[i].hash_hex[0] != '\0')
            present++;
    }
    if (present <= 1)
        return true;
    return qr.verdict == QO_VERDICT_QUORUM_MATCH &&
           qr.agreeing_sources >= 2;
}
