/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Live (serving-node) consensus-state bundle exporter entry: prove + copy from
 * a PRIVATE read-only WAL snapshot of progress.kv so the reducer is never
 * stalled for the multi-second proof/copy. Split from
 * consensus_state_snapshot_export.c along the file-size ceiling seam; the
 * offline-mint entry lives there and both share the internal contract. */

#include "config/consensus_state_snapshot_export.h"
#include "base/bytes.h"
#include "consensus_state_snapshot_export_internal.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


/* Open a PRIVATE read-only connection to the owned progress.kv and pin a
 * consistent WAL read snapshot. The process lock is held ONLY across the pin
 * (open + BEGIN + one probe read) so the reducer cannot advance the durable tip
 * mid-pin; it is released before the caller runs the (slow) proof/copy against
 * the returned handle. Returns the pinned handle or NULL (with *result filled). */
static sqlite3 *export_open_pinned_snapshot(
    struct consensus_state_export_result *result)
{
    char path[PROGRESS_STORE_PATH_MAX];
    if (!progress_store_path(path, sizeof(path))) {
        (void)consensus_export_fail(result, CONSENSUS_EXPORT_REFUSED,
                                    "progress store not open for snapshot");
        return NULL;
    }
    sqlite3 *snap = NULL;
    if (sqlite3_open_v2(path, &snap,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK) {
        const char *m = snap ? sqlite3_errmsg(snap) : "open failed";
        (void)consensus_export_fail(result, CONSENSUS_EXPORT_STORE_ERROR,
                                    "read-only snapshot open failed: %s", m);
        if (snap)
            sqlite3_close(snap);
        return NULL;
    }
    char *err = NULL;
    bool ok = sqlite3_exec(snap,
                  "PRAGMA query_only=ON;PRAGMA busy_timeout=5000;", NULL, NULL,
                  &err) == SQLITE_OK;
    if (err) {
        sqlite3_free(err);
        err = NULL;
    }
    /* Pin the WAL read snapshot under the process lock: BEGIN + a probe read
     * establish a consistent view that the reducer's concurrent writes cannot
     * disturb; the reducer cannot commit a new durable tip while we hold the
     * lock, so the pinned H* equals the tip the caller just finalized against. */
    if (ok) {
        progress_store_tx_lock();
        sqlite3_stmt *probe = NULL;
        ok = sqlite3_exec(snap, "BEGIN", NULL, NULL, NULL) == SQLITE_OK &&
             sqlite3_prepare_v2(snap, "SELECT count(*) FROM stage_cursor", -1,
                                &probe, NULL) == SQLITE_OK &&
             sqlite3_step(probe) == SQLITE_ROW; // raw-sql-ok:progress-kv-kernel-store
        if (probe)
            sqlite3_finalize(probe);
        progress_store_tx_unlock();
    }
    if (!ok) {
        (void)consensus_export_fail(result, CONSENSUS_EXPORT_STORE_ERROR,
                                    "read-only snapshot pin failed");
        sqlite3_close(snap);
        return NULL;
    }
    return snap;
}

bool consensus_state_snapshot_export_from_progress_snapshot(
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_export_result *result)
{
    if (result)
        memset(result, 0, sizeof(*result));
    if (!request)
        return consensus_export_fail(result, CONSENSUS_EXPORT_REFUSED,
                                     "NULL request");
    if (request->expected_height < 0 ||
        request->expected_height >= INT32_MAX ||
        !zcl_bytes_any_set(request->expected_block_hash, 32))
        return consensus_export_fail(result, CONSENSUS_EXPORT_REFUSED,
                                     "invalid expected source height/hash");

    struct consensus_export_output_binding *output = zcl_calloc(
        1, sizeof(*output), "consensus_export_output_binding");
    if (!output)
        return consensus_export_fail(result, CONSENSUS_EXPORT_OUTPUT_ERROR,
                                     "output binding allocation failed");
    consensus_export_output_init(output);
    if (!consensus_export_output_open(request, output, result)) {
        free(output);
        return false;
    }
    consensus_export_run_after_bind_hook();

    sqlite3 *snap = export_open_pinned_snapshot(result);
    if (!snap) {
        consensus_export_output_close(output);
        if (!output->abandon_on_close)
            free(output);
        return false;
    }

    struct consensus_state_bundle_manifest manifest;
    memset(&manifest, 0, sizeof(manifest));
    /* The snapshot's BEGIN read transaction (a private handle, no process lock)
     * spans the whole proof + copy for a consistent view; the reducer writes
     * concurrently on the primary handle without contention. */
    bool ok = consensus_export_prove_write(snap, request, output, &manifest, result);
    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(snap, finish, NULL, NULL, NULL) != SQLITE_OK && ok) {
        (void)consensus_export_fail(result, CONSENSUS_EXPORT_STORE_ERROR,
                                    "snapshot read transaction close failed");
        ok = false;
        sqlite3_exec(snap, "ROLLBACK", NULL, NULL, NULL);
    }
    sqlite3_close(snap);

    if (ok)
        ok = consensus_export_finalize_temp(output, &manifest, result);
    if (!ok) {
        consensus_export_output_close(output);
        if (!output->abandon_on_close)
            free(output);
        return false;
    }
    consensus_export_fill_success(&manifest, result);
    consensus_export_output_close(output);
    if (!output->abandon_on_close)
        free(output);
    return true;
}
