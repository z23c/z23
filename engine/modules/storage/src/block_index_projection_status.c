/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * block_index_projection_status — the EV_BLOCK_STATUS catch_up consumer,
 * split out of block_index_projection.c to keep that file under the
 * file-size ceiling (the same "_internal.h" sibling-split convention
 * engine/jobs/src/ already uses). Shares struct catch_up_ctx / batch_begin /
 * batch_commit with block_index_projection.c via
 * block_index_projection_internal.h. */

#include "block_index_projection_internal.h"

#include "storage/event_log_payloads.h"
#include "util/boot_scan.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/* Apply one EV_BLOCK_STATUS event: read the existing row's blob (written by
 * the prior EV_BLOCK_HEADER first-admit — see event_log.h's EV_BLOCK_STATUS
 * doc), patch the mutable fields (nStatus/nFile/nDataPos/nUndoPos/nTx), and
 * re-serialize + INSERT OR REPLACE the SAME columns the EV_BLOCK_HEADER path
 * in block_index_projection.c's catch_up_cb writes. This is the only place
 * the header/solution bytes get re-copied for a status bump, and it happens
 * HERE — off the reducer fold's hot path, on the projection's own catch_up
 * consumer.
 *
 * A hash with no prior row is a durable-log ordering defect (first admit
 * must always precede a status bump in this node's own log): logged and
 * counted via c->status_orphans, never fatal — the event is fully consumed
 * (the cursor still advances) so a single malformed/out-of-order row cannot
 * wedge the whole projection. Returns false only on a hard SQL error. */
bool catch_up_apply_status(struct catch_up_ctx *c,
                           const void *payload, size_t len)
{
    struct ev_block_status st;
    if (!ev_block_status_parse(payload, len, &st)) {
        fprintf(stderr,  // obs-ok:block-index-projection-catch-up-failure
                "[block_index_projection] status parse failed (len=%zu)\n",
                len);
        c->error = true;
        return false;
    }

    /* Look up the prior row BEFORE opening/extending a transaction: an
     * orphan (no prior row) must be a true no-op — batch_begin() and
     * batch_count are only touched once we know an INSERT will follow, so a
     * trailing run of orphan events never leaves a transaction open with
     * nothing to commit it (batch_commit only fires when batch_count > 0). */
    sqlite3_reset(c->blob_stmt);
    sqlite3_clear_bindings(c->blob_stmt);
    sqlite3_bind_blob(c->blob_stmt, 1, st.hash, 32, SQLITE_TRANSIENT);
    int sel_rc = sqlite3_step(c->blob_stmt);  // raw-sql-ok:kernel-primitive
    if (sel_rc != SQLITE_ROW) {
        c->status_orphans++;
        return true;
    }
    const void *blob = sqlite3_column_blob(c->blob_stmt, 0);
    int blob_len = sqlite3_column_bytes(c->blob_stmt, 0);
    /* Copy out — sqlite3_column_blob's buffer is invalidated by the next
     * step/reset on this same statement, and prior EV_BLOCK_HEADER blobs
     * never exceed EV_BLOCK_HEADER_FIXED_BYTES + EV_BLOCK_HEADER_MAX_SOLUTION. */
    uint8_t old[256 + 1344];
    if (!blob || blob_len <= 0 || (size_t)blob_len > sizeof(old)) {
        c->status_orphans++;
        return true;
    }
    memcpy(old, blob, (size_t)blob_len);

    struct ev_block_header h;
    const uint8_t *solution = NULL;
    if (!ev_block_header_parse(old, (size_t)blob_len, &h, &solution)) {
        fprintf(stderr,  // obs-ok:block-index-projection-catch-up-failure
                "[block_index_projection] status-update: prior blob parse "
                "failed (len=%d)\n", blob_len);
        c->error = true;
        return false;
    }

    if (c->batch_count == 0) {
        if (!batch_begin(c)) {
            c->error = true;
            return false;
        }
    }

    h.nStatus  = st.nStatus;
    h.nFile    = st.nFile;
    h.nDataPos = st.nDataPos;
    h.nUndoPos = st.nUndoPos;
    h.nTx      = st.nTx;

    uint8_t newbuf[256 + 1344];
    size_t written = 0;
    if (!ev_block_header_serialize(&h, solution, newbuf, sizeof(newbuf),
                                   &written)) {
        fprintf(stderr,  // obs-ok:block-index-projection-catch-up-failure
                "[block_index_projection] status-update: re-serialize "
                "failed h=%d\n", h.height);
        c->error = true;
        return false;
    }

    sqlite3_reset(c->ins_stmt);
    sqlite3_clear_bindings(c->ins_stmt);
    sqlite3_bind_blob (c->ins_stmt, 1, h.hash, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(c->ins_stmt, 2, (sqlite3_int64)h.height);
    sqlite3_bind_int64(c->ins_stmt, 3, (sqlite3_int64)h.nStatus);
    sqlite3_bind_int64(c->ins_stmt, 4, (sqlite3_int64)h.nFile);
    sqlite3_bind_int64(c->ins_stmt, 5, (sqlite3_int64)h.nDataPos);
    sqlite3_bind_int64(c->ins_stmt, 6, (sqlite3_int64)h.nUndoPos);
    sqlite3_bind_int64(c->ins_stmt, 7, (sqlite3_int64)h.nTime);
    sqlite3_bind_int64(c->ins_stmt, 8, (sqlite3_int64)h.nBits);
    sqlite3_bind_int64(c->ins_stmt, 9, (sqlite3_int64)h.nVersion);
    sqlite3_bind_int64(c->ins_stmt,10, (sqlite3_int64)h.nTx);
    sqlite3_bind_blob (c->ins_stmt,11, newbuf, (int)written, SQLITE_TRANSIENT);

    int rc = sqlite3_step(c->ins_stmt);  // raw-sql-ok:kernel-primitive
    if (rc != SQLITE_DONE) {
        fprintf(stderr,  // obs-ok:block-index-projection-catch-up-failure
                "[block_index_projection] status-update INSERT step rc=%d "
                "(%s)\n", rc, sqlite3_errstr(rc));
        char *err = NULL;
        sqlite3_exec(c->p->db, "ROLLBACK", NULL, NULL, &err);
        if (err) sqlite3_free(err);
        c->batch_count = 0;
        c->collisions = 0;
        c->error = true;
        return false;
    }
    if (!block_index_projection_mark_dirty(c, h.hash)) {
        fprintf(stderr,  // obs-ok:block-index-projection-catch-up-failure
                "[block_index_projection] dirty mark failed for status "
                "height=%d: %s\n", h.height, sqlite3_errmsg(c->p->db));
        char *err = NULL;
        sqlite3_exec(c->p->db, "ROLLBACK", NULL, NULL, &err);
        if (err) sqlite3_free(err);
        c->batch_count = 0;
        c->collisions = 0;
        c->error = true;
        return false;
    }
    c->batch_count++;
    c->collisions++;   /* a status update is always a replace by definition */
    boot_scan_bump(c->scan_ctr);

    if (c->batch_count >= BIP_BATCH_EVENTS) {
        if (!batch_commit(c)) {
            c->error = true;
            return false;
        }
    }
    return true;
}
