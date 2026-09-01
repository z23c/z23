/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Enforce exact BLOB hash bindings before reducer state can serve. */

#include "reducer_frontier_evidence.h"

#include "jobs/mint_skip_crypto.h"
#include "jobs/reducer_frontier.h"
#include "platform/time_compat.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Fetch a 32-byte hash column from a stage-log row. A missing, NULL, or
 * non-BLOB hash is not evidence and reports found=false. */
static bool log_hash_at(sqlite3 *db, const char *log_table,
                        const char *hash_col, int32_t height,
                        uint8_t out[32], bool *found)
{
    *found = false;
    char sql[160];
    int n = snprintf(sql, sizeof(sql),
                     "SELECT %s FROM %s WHERE height = ?",
                     hash_col, log_table);
    if (n < 0 || n >= (int)sizeof(sql))
        LOG_FAIL("reducer", "log_hash_at sql overflow for %s.%s",
                 log_table, hash_col);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("reducer", "prepare %s.%s failed: %s",
                 log_table, hash_col, sqlite3_errmsg(db));
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);

    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        int type = sqlite3_column_type(st, 0);
        const void *blob = type == SQLITE_BLOB
            ? sqlite3_column_blob(st, 0) : NULL;
        int blen = blob ? sqlite3_column_bytes(st, 0) : 0;
        if (blob && blen == 32) {
            memcpy(out, blob, 32);
            *found = true;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("reducer", "step %s.%s at h=%d failed: %s",
                 log_table, hash_col, height, sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

static void hash_prefix(sqlite3_stmt *st, int column, uint8_t out[4])
{
    memset(out, 0, 4);
    if (sqlite3_column_type(st, column) != SQLITE_BLOB ||
        sqlite3_column_bytes(st, column) != 32)
        return;
    const void *blob = sqlite3_column_blob(st, column);
    if (blob)
        memcpy(out, blob, 4);
}

/* True iff `table` currently carries a column named `col`. Schema generations
 * differ: the nullable per-stage hash witnesses (script_validate_log.block_hash,
 * proof_validate_log.block_hash) were ADDED after the reducer shipped, so a
 * pre-flip / pre-migration datadir has proof rows with NO block_hash column at
 * all (see proof_validate_null_hash_rearm.c). Enumerate the actual columns via
 * pragma_table_info — a LIMIT-0 SELECT probe is unsafe here because SQLite's
 * legacy double-quoted-identifier fallback silently reads an absent "col" as a
 * STRING LITERAL and prepares fine, wrongly reporting the column present.
 * table/col here are compile-time constants (no injection surface). */
static bool column_exists(sqlite3 *db, const char *table, const char *col)
{
    char sql[160];
    int n = snprintf(sql, sizeof(sql),
                     "SELECT 1 FROM pragma_table_info('%s') WHERE name='%s'",
                     table, col);
    if (n < 0 || n >= (int)sizeof(sql))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool found = sqlite3_step(st) == SQLITE_ROW;  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_finalize(st);
    return found;
}

/* Clamp H* below the first missing, malformed, or mixed-fork binding.  Every
 * serving height must name one exact selected header in header_admit,
 * validate_headers, script validation, proof validation, and the
 * transactionally co-written UTXO delta.  ZClassic headers do not commit
 * state, so an independent ok=1 row is never sufficient authority.  The
 * caller holds progress_store_tx_lock(). */
bool reducer_frontier_apply_hash_agreement(sqlite3 *db, int32_t anchor,
                                           int32_t *hstar)
{
    if (*hstar <= anchor)
        return true;

    /* Schema-aware split scan. The always-present NOT NULL witnesses
     * (validate_headers.hash, header_admit.hash, utxo_apply_delta.branch_hash —
     * the load-bearing coins<->header binding) are STRICT: each must be a 32-byte
     * blob AND agree with the validated header. The two nullable witnesses
     * (script_validate_log.block_hash, proof_validate_log.block_hash) were added
     * to the stage-log schema after the reducer shipped; a pre-flip datadir has
     * proof rows with NO block_hash column at all, and even post-ALTER the
     * historical rows hold NULL. Reference each nullable witness ONLY when its
     * column exists (else PREPARE fails "no such column: p.block_hash" and the
     * whole H* fold errors), and treat it as VERIFY-IF-PRESENT: a genuine SQL
     * NULL (or an absent column) means "this stage carries no independent hash
     * witness here" and is exempt — it must not falsely clamp the honestly-
     * derived prefix. A NON-NULL value is still checked in full: a malformed
     * one (wrong type / not 32 bytes) or a 32-byte blob that DISAGREES with the
     * header IS a split. A fresh node stamps block_hash on every row it authors,
     * so present-and-check == always-check there; only the legitimate historical
     * NULLs are skipped. The strict witnesses stay strict, so a NULL/missing
     * mandatory row (LEFT JOIN miss) still clamps. */
    const bool script_bh = column_exists(db, "script_validate_log", "block_hash");
    const bool proof_bh  = column_exists(db, "proof_validate_log", "block_hash");

    char sql[1200];
    int n = snprintf(sql, sizeof(sql),
            "SELECT v.height,v.hash,h.hash,%s,%s,d.branch_hash "
            "FROM validate_headers_log v "
            "LEFT JOIN header_admit_log h ON h.height=v.height "
            "LEFT JOIN script_validate_log s ON s.height=v.height "
            "LEFT JOIN proof_validate_log p ON p.height=v.height "
            "LEFT JOIN utxo_apply_delta d ON d.height=v.height "
            "WHERE v.height > ? AND v.height <= ? "
            "AND (typeof(v.hash) <> 'blob' OR length(v.hash) <> 32 "
            "OR typeof(h.hash) <> 'blob' OR length(h.hash) <> 32 "
            "OR typeof(d.branch_hash) <> 'blob' OR length(d.branch_hash) <> 32 "
            "OR v.hash <> h.hash OR v.hash <> d.branch_hash "
            "%s%s) "
            "ORDER BY v.height ASC LIMIT 1",
            script_bh ? "s.block_hash" : "NULL",
            proof_bh  ? "p.block_hash" : "NULL",
            script_bh ? "OR (s.block_hash IS NOT NULL AND "
                        "(typeof(s.block_hash) <> 'blob' "
                        "OR length(s.block_hash) <> 32 "
                        "OR s.block_hash <> v.hash)) "
                      : "",
            proof_bh  ? "OR (p.block_hash IS NOT NULL AND "
                        "(typeof(p.block_hash) <> 'blob' "
                        "OR length(p.block_hash) <> 32 "
                        "OR p.block_hash <> v.hash)) "
                      : "");
    if (n < 0 || n >= (int)sizeof(sql))
        LOG_FAIL("reducer", "hash-agreement split scan sql overflow");

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("reducer", "prepare hash-agreement split scan failed: %s",
                 sqlite3_errmsg(db));
    sqlite3_bind_int64(st, 1, (sqlite3_int64)anchor);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)*hstar);

    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) != SQLITE_INTEGER) {
            sqlite3_finalize(st);
            LOG_FAIL("reducer", "hash-agreement height has non-integer type");
        }
        int h = sqlite3_column_int(st, 0);
        uint8_t vh[4], hh[4], sh[4], ph[4], uh[4];
        hash_prefix(st, 1, vh);
        hash_prefix(st, 2, hh);
        hash_prefix(st, 3, sh);
        hash_prefix(st, 4, ph);
        hash_prefix(st, 5, uh);

        *hstar = (h - 1 < anchor) ? anchor : (h - 1);
        static struct log_throttle split_throttle = LOG_THROTTLE_INIT;
        int64_t now = platform_time_wall_unix();
        uint64_t reps = 0;
        if (log_throttle_should_emit(&split_throttle, (uint64_t)(uint32_t)h,
                                     now, 300, &reps))
            LOG_WARN("reducer",
                     "consensus-stage hash binding split at h=%d "
                     "(validate=%02x%02x%02x%02x admit=%02x%02x%02x%02x "
                     "script=%02x%02x%02x%02x proof=%02x%02x%02x%02x "
                     "utxo=%02x%02x%02x%02x) — H* clamped to %d; "
                     "re-derive all evidence from the selected block "
                     "repeated=%llu",
                     h, vh[0], vh[1], vh[2], vh[3], hh[0], hh[1], hh[2],
                     hh[3], sh[0], sh[1], sh[2], sh[3], ph[0], ph[1],
                     ph[2], ph[3], uh[0], uh[1], uh[2], uh[3], *hstar,
                     (unsigned long long)reps);
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("reducer", "step hash-agreement split scan failed: %s",
                 sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

bool reducer_frontier_log_hash_at(sqlite3 *progress_db,
                                  const char *log_table,
                                  const char *hash_col,
                                  int32_t height,
                                  uint8_t out[32], bool *found)
{
    if (!progress_db || !log_table || !hash_col || !out || !found)
        LOG_FAIL("reducer", "log_hash_at: NULL arg");
    progress_store_tx_lock();
    bool ok = log_hash_at(progress_db, log_table, hash_col, height,
                          out, found);
    progress_store_tx_unlock();
    return ok;
}

/* The evidence a *_log success row must carry to COUNT toward a frontier.
 *
 * The three profile-bound logs (script_validate, proof_validate, utxo_apply)
 * used to demand MINT_VALIDATION_EVIDENCE_VERIFIED literally. That is right for
 * every normal boot and wrong for exactly one caller: the OFFLINE FAST-MINT.
 * `-mint-anchor-fast` deliberately runs script_validate/proof_validate as a
 * crypto PASS-THROUGH and writes `checkpoint_fold` rows, so under the literal
 * rule NONE of its rows ever counted. The contiguous prefix therefore ended at
 * the scan floor, script_validate's derived frontier was pinned at 1 no matter
 * how far its raw cursor ran, proof_validate could never find a height above
 * that floor, utxo_apply could never pass proof_validate, and the mint drive
 * reported the LOWEST cursor — utxo_apply — as "the walled stage". The fold
 * died at height 1 every time, and the stall report named the wrong stage.
 *
 * mint_validation_evidence_expected(mint_skip_crypto_get()) is the SAME
 * predicate the stages themselves apply when they accept an upstream row
 * (proof_validate_stage.c, utxo_apply_stage.c), so the frontier walk now agrees
 * with the stages instead of contradicting them. mint_skip_crypto is settable
 * ONLY by the -mint-anchor driver and reads false everywhere else, so on any
 * normal boot this returns VERIFIED and the behaviour is bit-identical to the
 * literal constant it replaces. A checkpoint_fold row still never counts on a
 * normally-booted node.
 *
 * The artifact's safety does not rest on these rows in either case: the mint
 * hard-asserts the finished set's SHA3+count against the compiled checkpoint
 * and unlinks + _exit(1)s on any mismatch. */
enum mint_validation_evidence reducer_frontier_required_evidence(void)
{
    return mint_validation_evidence_expected(mint_skip_crypto_get());
}
