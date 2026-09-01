/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared snapshot import implementation for the pre-restore probe in boot.c
 * and the post-services receive path in boot_services.c. The function takes
 * `struct node_db *` directly (not boot_svc_ctx) so it can run before
 * services have been composed. See engine/composition/include/config/boot_snapshot_import.h.
 */

#include "config/boot_snapshot_import.h"
#include "chain/checkpoints.h"
#include "coins/utxo_commitment.h"
#include "models/database.h"
#include "services/reindex_epilogue.h"
#include "util/ar_step_readonly.h"
#include "util/boot_progress.h"
#include "util/log_macros.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <sqlite3.h>

/* SQLite calls this only after executing more virtual-machine instructions.
 * Unlike a timer thread, it cannot claim progress while a disk operation is
 * hung. Returning zero preserves the statement; the callback records only a
 * cheap lock-free liveness timestamp. */
static int snapshot_import_progress(void *unused)
{
    (void)unused;
    boot_progress_tick("snapshot_import_bulk_insert");
    return 0;
}

bool boot_import_snapshot_db(struct node_db *ndb,
                              const char *snapshot_path,
                              int64_t *out_utxo_count,
                              int64_t *out_snap_height,
                              uint8_t out_best_hash[32])
{
    if (!ndb || !ndb->open || !ndb->db || !snapshot_path)
        LOG_FAIL("boot_snapshot_import", "null inputs");

    struct stat st;
    if (stat(snapshot_path, &st) != 0)
        LOG_FAIL("boot_snapshot_import", "stat %s: %s",
                 snapshot_path, strerror(errno));
    if (st.st_size < (off_t)(10 * 1024 * 1024))
        LOG_FAIL("boot_snapshot_import",
                 "snapshot too small (%lld bytes) — likely truncated",
                 (long long)st.st_size);

    sqlite3 *src = NULL;
    if (sqlite3_open_v2(snapshot_path, &src,
                        SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        const char *m = src ? sqlite3_errmsg(src) : "n/a";
        if (src) sqlite3_close(src);
        LOG_FAIL("boot_snapshot_import", "open ro %s: %s",
                 snapshot_path, m);
    }

    bool integrity_ok = false;
    {
        sqlite3_stmt *ck = NULL;
        if (sqlite3_prepare_v2(src, "PRAGMA integrity_check",
                               -1, &ck, NULL) == SQLITE_OK && ck) {
            if (sqlite3_step(ck) == SQLITE_ROW) {  // raw-sql-ok:integrity-pragma
                const unsigned char *r = sqlite3_column_text(ck, 0);
                integrity_ok = r && strcmp((const char *)r, "ok") == 0;
            }
            sqlite3_finalize(ck);
        }
    }
    if (!integrity_ok) {
        sqlite3_close(src);
        LOG_FAIL("boot_snapshot_import",
                 "integrity_check failed for %s", snapshot_path);
    }

    int64_t snap_height = -1;
    {
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(src,
                "SELECT value FROM _snapshot_meta WHERE key='height'",
                -1, &q, NULL) == SQLITE_OK && q) {
            if (sqlite3_step(q) == SQLITE_ROW) {  // raw-sql-ok:read-only-snapshot
                const unsigned char *v = sqlite3_column_text(q, 0);
                if (v) snap_height = strtoll((const char *)v, NULL, 10);
            }
            sqlite3_finalize(q);
        }
    }
    if (snap_height < 1) {
        sqlite3_close(src);
        LOG_FAIL("boot_snapshot_import",
                 "missing/invalid _snapshot_meta.height");
    }

    /* PROVENANCE GATE (defense-in-depth for the peer-served path):
     * this importer installs a `consensus_snapshot.db` that arrived over the
     * unauthenticated file_service (file_index=254) — the per-chunk SHA3 only
     * proves the bytes match the SERVING PEER's manifest, not that the coin set
     * is the real consensus set. We only have an in-binary cryptographic ground
     * truth AT the single compiled checkpoint (the WRITE-TIME SHA3 reject
     * below). ABOVE the checkpoint there is no in-binary root and no anchor
     * binding here, so a forged snapshot at an arbitrary height would otherwise
     * be installed as ground truth (forged-money / consensus divergence).
     * REFUSE to promote an above-checkpoint peer snapshot — fall back to safe
     * P2P IBD. The assisted operator bundle path
     * (boot_load_snapshot_at_own_height_reset, which checks that the snapshot
     * anchor names a validated block_index location) is the supported way to
     * seed above the checkpoint; that location check does not authenticate
     * UTXO/shielded contents, and the path does NOT use this function. */
    {
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        if (cp && snap_height > (int64_t)cp->height) {
            sqlite3_close(src);
            LOG_FAIL("boot_snapshot_import",
                     "REFUSING peer snapshot at h=%lld (above compiled "
                     "checkpoint h=%llu): no in-binary root to consensus-verify "
                     "it against — falling back to P2P IBD / operator bundle",
                     (long long)snap_height,
                     (unsigned long long)cp->height);
        }
    }

    uint8_t best_hash[32] = {0};
    bool best_found = false;
    {
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(src,
                "SELECT hash FROM blocks WHERE height=?",
                -1, &q, NULL) == SQLITE_OK && q) {
            sqlite3_bind_int64(q, 1, snap_height);
            if (sqlite3_step(q) == SQLITE_ROW) {  // raw-sql-ok:read-only-snapshot
                const void *b = sqlite3_column_blob(q, 0);
                int n = sqlite3_column_bytes(q, 0);
                if (b && n == 32) {
                    memcpy(best_hash, b, 32);
                    best_found = true;
                }
            }
            sqlite3_finalize(q);
        }
    }
    if (!best_found) {
        sqlite3_close(src);
        LOG_FAIL("boot_snapshot_import",
                 "no blocks row at h=%lld", (long long)snap_height);
    }

    int64_t snap_utxos = 0;
    {
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(src,
                "SELECT COUNT(*) FROM utxos",
                -1, &q, NULL) == SQLITE_OK && q) {
            if (sqlite3_step(q) == SQLITE_ROW)  // raw-sql-ok:read-only-snapshot
                snap_utxos = sqlite3_column_int64(q, 0);
            sqlite3_finalize(q);
        }
    }
    sqlite3_close(src);
    if (snap_utxos < 1000)
        LOG_FAIL("boot_snapshot_import",
                 "implausible utxo count %lld", (long long)snap_utxos);

    /* Stash prior coins_best_block so we can restore on failure
     * after the bulk-copy has committed. */
    uint8_t prior_cb[32] = {0};
    size_t prior_cb_len = 0;
    bool prior_cb_present = node_db_state_get(ndb, "coins_best_block",
                                              prior_cb, sizeof(prior_cb),
                                              &prior_cb_len);

    char attach_sql[640];
    snprintf(attach_sql, sizeof(attach_sql),
             "ATTACH DATABASE '%s' AS snapsrc", snapshot_path);
    char *err = NULL;
    if (sqlite3_exec(ndb->db, attach_sql, NULL, NULL, &err) != SQLITE_OK) {
        char msg[256] = "?";
        if (err) { snprintf(msg, sizeof(msg), "%s", err); sqlite3_free(err); }
        LOG_FAIL("boot_snapshot_import", "ATTACH failed: %s", msg);
    }

    bool ok = true;
    if (sqlite3_exec(ndb->db, "BEGIN IMMEDIATE", NULL, NULL, &err)
        != SQLITE_OK) {
        char msg[256] = "?";
        if (err) { snprintf(msg, sizeof(msg), "%s", err); sqlite3_free(err); }
        sqlite3_exec(ndb->db, "DETACH DATABASE snapsrc", NULL, NULL, NULL);
        LOG_FAIL("boot_snapshot_import", "BEGIN failed: %s", msg);
    }
    /* Report only measured SQLite VM progress while the bulk copy and
     * commitment scan run. A timer-based pump falsely kept a genuinely hung
     * INSERT alive forever once watchdog progress exemptions became active. */
    sqlite3_progress_handler(ndb->db, 50000,
                             snapshot_import_progress, NULL);
    if (ok && ar_exec_write_sql(ndb->db, "DELETE FROM main.utxos")
                  != SQLITE_OK) {
        fprintf(stderr, "[boot_snapshot_import] clear utxos: %s\n",  // obs-ok:bulk-import-failure
                sqlite3_errmsg(ndb->db));
        ok = false;
    }
    if (ok && ar_exec_write_sql(ndb->db,
            "INSERT INTO main.utxos SELECT * FROM snapsrc.utxos")
                  != SQLITE_OK) {
        fprintf(stderr, "[boot_snapshot_import] copy utxos: %s\n",  // obs-ok:bulk-import-failure
                sqlite3_errmsg(ndb->db));
        ok = false;
    }
    /* WRITE-TIME VERIFICATION (mirrors utxo_recovery_restore.c):
     * before COMMIT, recompute the SHA3 over the just-installed set. At the
     * compiled checkpoint height there is a cryptographic ground truth, so
     * REJECT unless (root,count) byte-match it — a peer's per-chunk transport
     * SHA3 only proves the file matches the SERVING PEER's manifest, NOT that
     * the coin set is the real consensus set. Runs while the SQLite progress
     * handler remains active (the walk is O(set)). Above the checkpoint there
     * is no
     * compiled root to verify against; that non-checkpoint provenance gap (the
     * snapshot path writes no cold-import seed, so the boot torn-gate cannot
     * see it) is a documented follow-up — the checkpoint reject is the
     * load-bearing half and closes the fabricate-at-the-checkpoint hole. */
    if (ok) {
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        if (cp && snap_height == (int64_t)cp->height) {
            uint8_t root[32]; uint64_t cnt = 0;
            utxo_commitment_sha3_compute(ndb->db, root, &cnt);
            if (cnt != cp->utxo_count || memcmp(root, cp->sha3_hash, 32) != 0) {
                LOG_WARN("boot_snapshot_import",
                         "checkpoint SHA3 MISMATCH at h=%lld (count=%llu "
                         "want=%llu) — snapshot REJECTED, not installed as "
                         "ground truth",
                         (long long)snap_height, (unsigned long long)cnt,
                         (unsigned long long)cp->utxo_count);
                ok = false;
            } else {
                printf("[boot_snapshot_import] checkpoint SHA3 verified at "
                       "h=%lld (%llu UTXOs)\n", (long long)snap_height,
                       (unsigned long long)cnt);
            }
        }
    }
    if (ok) {
        /* A failed COMMIT (SQLITE_FULL / IO error) leaves the bulk-copy txn
         * uncommitted — we must NOT then stamp coins_best_block at the
         * snapshot tip (that is the snapshot-path coin-tear class). Capture
         * the rc, roll back, and propagate failure so the caller falls back
         * to normal sync instead of trusting a half-installed set. */
        if (sqlite3_exec(ndb->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
            LOG_WARN("boot_snapshot_import",
                     "COMMIT failed (%s) — rolling back snapshot install",
                     sqlite3_errmsg(ndb->db));
            sqlite3_exec(ndb->db, "ROLLBACK", NULL, NULL, NULL);
            ok = false;
        }
    } else {
        sqlite3_exec(ndb->db, "ROLLBACK", NULL, NULL, NULL);
    }
    sqlite3_exec(ndb->db, "DETACH DATABASE snapsrc", NULL, NULL, NULL);
    sqlite3_progress_handler(ndb->db, 0, NULL, NULL);

    if (!ok) {
        LOG_FAIL("boot_snapshot_import",
                 "snapshot install failed; node.db rolled back");
        return false;
    }

    /* CACHE-REFRESH (wave 2): 'coins_best_block' is a projection key —
     * authority = reducer_frontier_derive_coins_best over coins_kv. */
    if (!node_db_state_set(ndb, "coins_best_block",
                           best_hash, sizeof(best_hash))) {
        /* utxos already committed; restore prior anchor so the next
         * boot doesn't try to CSR-commit to a snapshot we lost. */
        if (prior_cb_present && prior_cb_len == 32)
            node_db_state_set(ndb, "coins_best_block",
                              prior_cb, prior_cb_len);
        LOG_FAIL("boot_snapshot_import", "set coins_best_block failed");
    }

    /* Verified-install epilogue: a snapshot import is only a fast rebuild if
     * it seeds the same durable authority surface as a full reindex. Reuse the
     * reindex epilogue so both paths derive coins_kv, coins_applied_height,
     * utxo_sha3, trusted cursors, and H* with one implementation. */
    const char *main_db_path = sqlite3_db_filename(ndb->db, "main");
    if (!reindex_epilogue_derive_imported_snapshot(
            ndb, main_db_path, (int)snap_height, best_hash)) {
        LOG_WARN("boot_snapshot_import",
                 "snapshot imported into node.db but authority epilogue failed "
                 "at h=%lld; refusing fast-rebuild success",
                 (long long)snap_height);
        return false;
    }

    if (out_utxo_count)  *out_utxo_count  = snap_utxos;
    if (out_snap_height) *out_snap_height = snap_height;
    if (out_best_hash)   memcpy(out_best_hash, best_hash, 32);
    return true;
}
