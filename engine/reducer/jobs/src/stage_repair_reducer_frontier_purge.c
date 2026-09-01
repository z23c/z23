/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair_reducer_frontier_purge.c — the non-canonical stage-log
 * row purge of the L1 reducer-frontier reconcile. Split from the refill
 * TU (file-size ceiling); shares the family's internal header. */

#include "stage_repair_reducer_frontier_internal.h"
#include "stage_repair_reducer_frontier_evidence.h"
#include "jobs/stage_log_rows.h"
#include "jobs/stage_repair.h"
#include "jobs/stage_repair_internal.h"
#include "jobs/utxo_apply_delta.h"
#include "tip_finalize_log_store.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* ── Non-canonical row purge ──────────────────────────────────────
 * Delete hash-bearing stage-log rows whose stored hash does not match
 * the canonical active-chain block at their height, plus the hashless
 * downstream rows (proof/body_persist/tip_finalize) at those heights.
 * Rows like this exist only after a height-relabel or reorg residue:
 * a height-relabel can process network blocks under labels below their
 * true heights, persisting false ok=0 bad-cb-height verdicts that NO
 * other repair touches (their status is outside every replay filter,
 * the refills fire only on ROWLESS holes, and the cursors moved past
 * them) — pinning H* forever. Purging converts them
 * into ordinary rowless holes the existing refill + cursor machinery
 * already heals, but ONLY when the coins frontier is known and the stale
 * height is at/above it. Below or without that frontier, deleting can make an
 * unfillable hole, so this pass reports the evidence and leaves rows intact
 * for the replay owners. Genuine consensus rejects are SAFE: their stored
 * hash IS the canonical block at that height, so they never match the
 * predicate. Heights above the active tip carry no canonical hash and
 * are left alone. This function owns the full progress-store tx lock while it
 * compares/deletes rows, and briefly takes active_chain.write_lock to copy a
 * stable canonical-hash snapshot for the scan window. */
#define RF_NONCANON_MAX_PER_PASS 8192

struct rf_canonical_hash {
    bool present;
    struct uint256 hash;
};

/* True iff `h` carries an ok=1/ok=1 validate-vs-script hash_split: both
 * validate_headers_log and script_validate_log hold a 32-byte hash at h, both
 * ok=1, and the two disagree. Such a height is owned EXCLUSIVELY by the
 * coins-rewinding stale-script replay (maybe_repair_validate_script_hash_split,
 * rewind_headers=true) — the purge must NOT delete either side below the coins
 * frontier or it blinds that replay's JOIN detector. Returns false only on a
 * real DB read error. Caller holds the progress-store tx lock. */
static bool rf_height_is_vs_hash_split(sqlite3 *db, int h, bool *out_split)
{
    *out_split = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM validate_headers_log v "
            "JOIN script_validate_log s ON s.height = v.height "
            "WHERE v.height = ? AND v.ok = 1 AND s.ok = 1 "
            "  AND length(v.hash) = 32 AND length(s.block_hash) = 32 "
            "  AND v.hash <> s.block_hash LIMIT 1",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("stage_repair", "purge_noncanonical: vs_split prepare: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int64(st, 1, h);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out_split = true;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "purge_noncanonical: vs_split step h=%d rc=%d: %s",
                 h, rc, sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_finalize(st);
    return true;
}

/* Lazily-opened purge transaction. The row deletes and the script/proof
 * cursor clamps below MUST commit atomically: a purge whose deletes commit
 * (rowless holes in script_validate_log/proof_validate_log) while both
 * cursors stay above the hole leaves the later refill scan unable to see it
 * (its body_persist_log anchor row was deleted by the same pass), so no
 * stage ever re-derives the rows.
 * Caller holds progress_store_tx_lock(). */
static bool rf_purge_tx_begin(sqlite3 *db, bool *tx_open)
{
    if (*tx_open)
        return true;
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("stage_repair", "purge_noncanonical: BEGIN failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    *tx_open = true;
    return true;
}

/* Clamp one of the script_validate / proof_validate cursors down to `target`
 * (a height whose rows this purge deleted). Dry-run records the would-be
 * clamp; apply writes it inside the purge's open transaction so the deletes
 * and the clamp commit together. Caller holds progress_store_tx_lock(). */
static bool rf_purge_clamp_cursor(sqlite3 *db, bool apply,
                                  const char *stage_name, int target,
                                  int *cursor_before, int *cursor_after,
                                  bool *clamped)
{
    int cur = -1;
    if (!stage_repair_cursor_at_unlocked(db, stage_name, &cur)) {
        LOG_WARN("stage_repair",
                 "purge_noncanonical: %s cursor read failed target=%d",
                 stage_name, target);
        return false;
    }
    *cursor_before = cur;
    *cursor_after = cur;
    if (cur <= target)
        return true;
    *clamped = true;
    *cursor_after = target;
    if (!apply)
        return true;
    if (!stage_repair_force_stage_cursor(db, stage_name, target)) {
        LOG_WARN("stage_repair",
                 "purge_noncanonical: %s cursor clamp failed target=%d "
                 "before=%d", stage_name, target, cur);
        return false;
    }
    return true;
}

bool stage_reducer_frontier_purge_noncanonical(
    sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    if (!db || !ms || !out)
        LOG_FAIL("stage_repair", "purge_noncanonical: invalid args");

    struct rf_canonical_hash *canon =
        zcl_calloc(RF_NONCANON_MAX_PER_PASS, sizeof(*canon),
                   "rf_noncanon_snapshot");
    if (!canon)
        LOG_FAIL("stage_repair",
                 "purge_noncanonical: snapshot alloc failed cap=%d",
                 RF_NONCANON_MAX_PER_PASS);

    bool ok = true;
    bool tx_open = false;
    /* Lowest height whose rows this pass judges stale, split by the FIX-2
     * coins floor: heights >= coins_applied_height are provably unapplied
     * (forward re-walk safe — the clamp target), heights below it are the
     * stale-script replay's domain (never clamped, warned below). */
    int lowest_stale_unapplied = -1;
    int lowest_stale_utxo_unapplied = -1;
    int lowest_stale_replay_domain = -1;
    progress_store_tx_lock();

    /* Re-read the coin frontier under this writer lock: a raced, lower
     * snapshot once stranded a future kernel suffix. Dry-run only observes. */
    int32_t live_coins_applied = -1;
    bool live_coins_found = false;
    if (!coins_kv_get_applied_height(db, &live_coins_applied,
                                     &live_coins_found)) {
        LOG_WARN("stage_repair",
                 "purge_noncanonical: live coins frontier read failed");
        ok = false;
        goto done_locked;
    }
    out->coins_applied_height = live_coins_applied;
    out->coins_applied_found = live_coins_found;

    int tip_h = active_chain_height(&ms->chain_active);
    int lo = out->hstar + 1;
    int hi = out->sweep_top < tip_h ? out->sweep_top : tip_h;
    if (lo < 0 || hi < lo)
        goto done_locked;
    if (hi - lo + 1 > RF_NONCANON_MAX_PER_PASS)
        hi = lo + RF_NONCANON_MAX_PER_PASS - 1;
    bool frontier_known = out->coins_applied_found &&
                          out->coins_applied_height >= 0;

    /* Keep active-chain writes out of the SQL decision window: copy exactly the
     * canonical hashes this pass will judge under the writer lock, then do all
     * DB reads/deletes against that immutable local snapshot. */
    zcl_mutex_lock(&ms->chain_active.write_lock);
    for (int h = lo; h <= hi; h++) {
        struct block_index *bi = active_chain_at(&ms->chain_active, h);
        if (!bi || !bi->phashBlock)
            continue;
        size_t i = (size_t)(h - lo);
        canon[i].present = true;
        canon[i].hash = *bi->phashBlock;
    }
    zcl_mutex_unlock(&ms->chain_active.write_lock);

    static const struct {
        const char *table;
        const char *hash_col;
    } hash_logs[] = {
        { "script_validate_log",  "block_hash" },
        { "proof_validate_log",   "block_hash" },
        { "validate_headers_log", "hash" },
        { "body_fetch_log",       "hash" },
    };
    static const char *const dep_logs[] = {
        "proof_validate_log", "body_persist_log", "tip_finalize_log",
    };

    for (int h = lo; h <= hi; h++) {
        const struct rf_canonical_hash *ch = &canon[h - lo];
        if (!ch->present)
            continue;

        /* A validate-vs-script ok=1/ok=1 hash_split BELOW the coins frontier is
         * owned by the coins-rewinding stale-script replay, which needs BOTH
         * ok=1 rows intact to detect (its JOIN) and re-derive against the
         * canonical body. Deleting either side here would blind that detector
         * and strand a rowless hole the refill REFUSES below the coins frontier
         * (refill_target_in_unapplied_domain). COUNT it so the condition stays
         * actionable (and the peer-gate bypass / sticky_escalator can arm), but
         * leave the evidence rows intact for the replay owner. */
        bool below_frontier = frontier_known &&
                              h < out->coins_applied_height;
        if (below_frontier) {
            bool vs_split = false;
            if (!rf_height_is_vs_hash_split(db, h, &vs_split)) {
                ok = false;
                goto done_locked;
            }
            if (vs_split) {
                out->noncanonical_found++;
                if (out->lowest_noncanonical < 0 ||
                    h < out->lowest_noncanonical)
                    out->lowest_noncanonical = h;
                continue; /* leave evidence rows for the stale-script replay */
            }
        }
        bool purge_allowed = frontier_known &&
                             h >= out->coins_applied_height;

        bool stale_here = false;
        for (size_t t = 0; t < sizeof(hash_logs) / sizeof(hash_logs[0]); t++) {
            char sql[160];
            snprintf(sql, sizeof(sql),
                     "SELECT %s FROM %s WHERE height = ?",
                     hash_logs[t].hash_col, hash_logs[t].table);
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
                LOG_WARN("stage_repair", "purge_noncanonical: prepare %s: %s",
                         hash_logs[t].table, sqlite3_errmsg(db));
                ok = false;
                goto done_locked;
            }
            sqlite3_bind_int64(st, 1, h);
            bool mismatch = false;
            int step_rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
            if (step_rc == SQLITE_ROW) {
                int type = sqlite3_column_type(st, 0);
                const void *blob = type == SQLITE_BLOB
                    ? sqlite3_column_blob(st, 0) : NULL;
                mismatch = type != SQLITE_BLOB || !blob ||
                    sqlite3_column_bytes(st, 0) != 32 ||
                    memcmp(blob, ch->hash.data, 32) != 0;
            } else if (step_rc != SQLITE_DONE) {
                LOG_WARN("stage_repair",
                         "purge_noncanonical: scan %s h=%d rc=%d: %s",
                         hash_logs[t].table, h, step_rc, sqlite3_errmsg(db));
                sqlite3_finalize(st);
                ok = false;
                goto done_locked;
            }
            sqlite3_finalize(st);
            if (!mismatch)
                continue;
            stale_here = true;
            out->noncanonical_found++;
            if (out->lowest_noncanonical < 0 ||
                h < out->lowest_noncanonical)
                out->lowest_noncanonical = h;
            if (!purge_allowed)
                continue;
            if (!apply)
                continue;
            if (!rf_purge_tx_begin(db, &tx_open)) {
                ok = false;
                goto done_locked;
            }
            snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE height = ?",
                     hash_logs[t].table);
            if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
                LOG_WARN("stage_repair", "purge_noncanonical: del prepare %s: %s",
                         hash_logs[t].table, sqlite3_errmsg(db));
                ok = false;
                goto done_locked;
            }
            sqlite3_bind_int64(st, 1, h);
            int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
            sqlite3_finalize(st);
            if (rc != SQLITE_DONE) {
                LOG_WARN("stage_repair", "purge_noncanonical: delete %s h=%d rc=%d",
                         hash_logs[t].table, h, rc);
                ok = false;
                goto done_locked;
            }
            out->noncanonical_purged++;
        }
        bool utxo_present = false;
        bool utxo_matches = false;
        if (!rf_utxo_branch_evidence_at(db, h, &ch->hash, &utxo_present,
                                        &utxo_matches)) {
            ok = false;
            goto done_locked;
        }
        if (utxo_present && !utxo_matches) {
            stale_here = true;
            out->noncanonical_found++;
            if (out->lowest_noncanonical < 0 ||
                h < out->lowest_noncanonical)
                out->lowest_noncanonical = h;
            if (purge_allowed) {
                if (lowest_stale_utxo_unapplied < 0)
                    lowest_stale_utxo_unapplied = h;
                if (apply) {
                    if (!rf_purge_tx_begin(db, &tx_open)) {
                        ok = false;
                        goto done_locked;
                    }
                    static const char *const tables[] = {
                        "utxo_apply_log", "utxo_apply_delta",
                    };
                    for (size_t t = 0; t < sizeof(tables) / sizeof(tables[0]);
                         t++) {
                        char sql[96];
                        snprintf(sql, sizeof(sql),
                                 "DELETE FROM %s WHERE height=?", tables[t]);
                        sqlite3_stmt *del = NULL;
                        if (sqlite3_prepare_v2(db, sql, -1, &del, NULL) !=
                            SQLITE_OK) {
                            ok = false;
                            goto done_locked;
                        }
                        sqlite3_bind_int(del, 1, h);
                        int drc = sqlite3_step(del); // raw-sql-ok:progress-kv-kernel-store
                        if (drc != SQLITE_DONE) {
                            sqlite3_finalize(del);
                            ok = false;
                            goto done_locked;
                        }
                        int purged_here = sqlite3_changes(db);
                        out->noncanonical_purged += purged_here > 0;
                        /* Keep the published row counter honest (stage_log_rows.h). */
                        stage_log_rows_note_delete(tables[t], (int64_t)purged_here);
                        sqlite3_finalize(del);
                    }
                }
            }
        }
        if (stale_here && apply && purge_allowed) {
            /* Hashless downstream rows at this height describe the same
             * wrong block — transitively stale. */
            for (size_t t = 0; t < sizeof(dep_logs) / sizeof(dep_logs[0]); t++) {
                char sql[96];
                snprintf(sql, sizeof(sql),
                         "DELETE FROM %s WHERE height = ?", dep_logs[t]);
                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
                    continue; /* table may not exist yet; holes self-heal */
                sqlite3_bind_int64(st, 1, h);
                int dep_rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
                int dep_changed = dep_rc == SQLITE_DONE ? sqlite3_changes(db) : 0;
                if (dep_rc == SQLITE_DONE && dep_changed > 0) {
                    out->noncanonical_purged++;
                    /* Keep the published row counter honest (stage_log_rows.h). */
                    stage_log_rows_note_delete(dep_logs[t], (int64_t)dep_changed);
                } else if (dep_rc != SQLITE_DONE) {
                    LOG_WARN("stage_repair",
                             "purge_noncanonical: delete %s h=%d rc=%d: %s",
                             dep_logs[t], h, dep_rc, sqlite3_errmsg(db));
                    sqlite3_finalize(st);
                    ok = false;
                    goto done_locked;
                }
                sqlite3_finalize(st);
            }
        }
        if (stale_here) {
            /* The loop ascends, so the first stale height per domain is the
             * lowest. Domain split mirrors refill_target_in_unapplied_domain
             * (stage_repair_reducer_frontier_refill.c): unknown coins
             * frontier or h below it => replay domain, never a clamp. */
            if (purge_allowed) {
                if (lowest_stale_unapplied < 0)
                    lowest_stale_unapplied = h;
            } else if (lowest_stale_replay_domain < 0) {
                lowest_stale_replay_domain = h;
            }
        }
    }

    /* The deletes above turned the stale heights into rowless holes. A
     * script_validate / proof_validate cursor left ABOVE such a height would
     * strand it forever: the forward stages only walk up, and the refill
     * scans key on upstream anchor rows (body_persist_log / script_validate_
     * log) this same pass just deleted, so they read no hole. Clamp both cursors to the lowest purged
     * height in the unapplied domain, in the SAME transaction as the deletes
     * — both log stores are INSERT OR REPLACE, the forward re-walk rewrites
     * fresh verdicts from the persisted canonical bodies and deletes nothing.
     * validate_headers / body_fetch / body_persist / tip_finalize cursors
     * stay with their existing caller-side reconciles (header_admit-keyed
     * scans survive the purge). A branch-mismatched UTXO row is the exception:
     * it is removed only at/above the durable coins frontier, then utxo_apply is
     * aligned to that exact next-unapplied height so no coin can double-apply. */
    if (lowest_stale_unapplied >= 0) {
        if (apply && !rf_purge_tx_begin(db, &tx_open)) {
            ok = false;
            goto done_locked;
        }
        if (!rf_purge_clamp_cursor(db, apply, "script_validate",
                                   lowest_stale_unapplied,
                                   &out->script_validate_cursor_before,
                                   &out->script_validate_cursor_after,
                                   &out->clamped_script_validate) ||
            !rf_purge_clamp_cursor(db, apply, "proof_validate",
                                   lowest_stale_unapplied,
                                   &out->proof_validate_cursor_before,
                                   &out->proof_validate_cursor_after,
                                   &out->clamped_proof_validate)) {
            ok = false;
            goto done_locked;
        }
        if (out->clamped_script_validate || out->clamped_proof_validate)
            LOG_WARN("stage_repair",
                     "[stage_repair] purge_noncanonical clamped "
                     "script_validate=%d->%d proof_validate=%d->%d to purged "
                     "rowless height h=%d (hstar=%d coins_applied=%d)%s",
                     out->script_validate_cursor_before,
                     out->script_validate_cursor_after,
                     out->proof_validate_cursor_before,
                     out->proof_validate_cursor_after,
                     lowest_stale_unapplied, out->hstar,
                     out->coins_applied_height, apply ? "" : "; dry-run");
    }
    if (lowest_stale_utxo_unapplied >= 0 && apply) {
        int before = -1;
        int after = -1;
        bool clamped = false;
        int target = out->coins_applied_height;
        if (!stage_repair_cursor_at_unlocked(db, "utxo_apply", &before)) {
            ok = false;
            goto done_locked;
        }
        /* Remove the whole abandoned kernel suffix. The coin frontier proves
         * it unapplied, so no inverse is needed. */
        int suffix_last = before > 0 ? before - 1 : target;
        if (hi > suffix_last)
            suffix_last = hi;
        if (!rf_purge_tx_begin(db, &tx_open) ||
            !utxo_apply_delete_rows_above(db, target, suffix_last) ||
            !rf_purge_clamp_cursor(db, true, "utxo_apply", target,
                                   &before, &after, &clamped)) {
            ok = false;
            goto done_locked;
        }
        LOG_WARN("stage_repair",
                 "[stage_repair] purge_noncanonical reconciled utxo_apply "
                 "kernel suffix=[%d,%d] cursor=%d->%d to live durable coins "
                 "frontier after mixed-fork delta at h=%d",
                 target, suffix_last, before, after,
                 lowest_stale_utxo_unapplied);
    }
    if (lowest_stale_replay_domain >= 0)
        LOG_WARN("stage_repair",
                 "[stage_repair] purge_noncanonical left noncanonical evidence "
                 "below/without the coins frontier (lowest=%d "
                 "coins_applied=%d found=%d): purge refused because no "
                 "forward refill can prove the rowless hole is safe; "
                 "stale-script replay domain%s",
                 lowest_stale_replay_domain, out->coins_applied_height,
                 out->coins_applied_found, apply ? "" : "; dry-run");

    if (out->noncanonical_found > 0)
        LOG_WARN("stage_repair",
                 "[stage_repair] non-canonical stage-log rows: found=%d "
                 "purged=%d lowest=%d window=[%d,%d] (relabel/reorg residue"
                 "%s)", out->noncanonical_found, out->noncanonical_purged,
                 out->lowest_noncanonical, lo, hi,
                 apply ? "" : "; dry-run");

done_locked:
    if (tx_open) {
        if (ok) {
            char *err = NULL;
            if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
                LOG_WARN("stage_repair",
                         "purge_noncanonical: COMMIT failed: %s",
                         err ? err : "(no message)");
                if (err) sqlite3_free(err);
                sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
                ok = false;
            }
        } else {
            /* All-or-nothing: a failed pass rolls the deletes back too, so
             * no rowless height is ever left with a cursor above it. */
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        }
        /* Belt-and-braces: if COMMIT and ROLLBACK BOTH failed (I/O-error
         * class), the shared progress.kv connection would be left inside a
         * transaction and every later BEGIN IMMEDIATE on it would fail
         * ("cannot start a transaction within a transaction"), turning one
         * purge hiccup into a whole-fold-drive JOB_FATAL. Force it closed
         * (same recovery stage_batch_end uses). */
        if (!sqlite3_get_autocommit(db)) {
            LOG_WARN("stage_repair",
                     "purge_noncanonical: transaction still open after "
                     "COMMIT/ROLLBACK failure — forcing ROLLBACK");
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        }
    }
    progress_store_tx_unlock();
    free(canon);
    return ok;
}

/* ── stale reorg-residue tip_finalize verdict replacement ────────────
 * Tri-state read of a tip_finalize_log row's ok column at `height`:
 * RF_TIPFIN_ABSENT (no row), RF_TIPFIN_OK (ok=1), RF_TIPFIN_FAIL (ok=0).
 * Only an ok=0 row is eligible for replacement (an absent row is the
 * tipfin-backfill domain; an ok=1 row needs no repair). */
enum rf_tipfin_state {
    RF_TIPFIN_ABSENT = 0,
    RF_TIPFIN_OK,
    RF_TIPFIN_FAIL,
};

static bool rf_tipfin_state_at(sqlite3 *db, int height,
                               enum rf_tipfin_state *out_state,
                               char status_out[64])
{
    *out_state = RF_TIPFIN_ABSENT;
    if (status_out)
        status_out[0] = '\0';
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT ok, status FROM tip_finalize_log WHERE height = ?",
            -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("stage_repair",
                 "reorg-residue tipfin state prepare failed h=%d: %s",
                 height, sqlite3_errmsg(db));
    sqlite3_bind_int(st, 1, height);
    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) != SQLITE_INTEGER ||
            (sqlite3_column_int(st, 0) != 0 &&
             sqlite3_column_int(st, 0) != 1)) {
            LOG_WARN("stage_repair",
                     "[stage_repair] malformed reorg-residue ok storage h=%d",
                     height);
            rc_ok = false;
        } else {
            *out_state = sqlite3_column_int(st, 0) == 1 ? RF_TIPFIN_OK
                                                         : RF_TIPFIN_FAIL;
        }
        if (status_out) {
            int status_type = sqlite3_column_type(st, 1);
            const unsigned char *s = status_type == SQLITE_TEXT
                ? sqlite3_column_text(st, 1) : NULL;
            int n = s ? sqlite3_column_bytes(st, 1) : -1;
            if (!s || n < 0 || n >= 64 || memchr(s, '\0', (size_t)n)) {
                LOG_WARN("stage_repair",
                         "[stage_repair] malformed reorg-residue status h=%d",
                         height);
                rc_ok = false;
            } else {
                memcpy(status_out, s, (size_t)n);
                status_out[n] = '\0';
            }
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] reorg-residue tipfin state step failed h=%d "
                 "rc=%d: %s", height, rc, sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

/* Read the header_admit_log hash at `height` (the canonical admitted block's
 * hash). *found is true only when a row exists with a 32-byte hash blob — a
 * row missing or with a malformed hash is success with *found=false (no
 * eligible lookahead binder, so the residue row is left alone). */
static bool rf_header_admit_hash_at(sqlite3 *db, int height,
                                    struct uint256 *out, bool *found)
{
    *found = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT hash FROM header_admit_log WHERE height = ?",
            -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("stage_repair",
                 "reorg-residue header_admit hash prepare failed h=%d: %s",
                 height, sqlite3_errmsg(db));
    sqlite3_bind_int(st, 1, height);
    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        int type = sqlite3_column_type(st, 0);
        const void *blob = type == SQLITE_BLOB
            ? sqlite3_column_blob(st, 0) : NULL;
        int blen = blob ? sqlite3_column_bytes(st, 0) : 0;
        if (blob && blen == 32) {
            memcpy(out->data, blob, 32);
            *found = true;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] reorg-residue header_admit hash step failed "
                 "h=%d rc=%d: %s", height, rc, sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

/* Caller holds progress_store_tx_lock(). A header_admit_log row is trusted by
 * this repair only when the durable header_admit cursor has advanced past that
 * row. Rows at or above the cursor are replay territory after a reorg rewind
 * and may still describe the stale branch being replaced. */
static bool rf_header_admit_cursor_locked(sqlite3 *db, uint64_t *out_cursor)
{
    *out_cursor = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name = 'header_admit'",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] reorg-residue header_admit cursor prepare "
                 "failed: %s",
                 sqlite3_errmsg(db));
        return false;
    }
    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out_cursor = (uint64_t)sqlite3_column_int64(st, 0);
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] reorg-residue header_admit cursor step "
                 "failed rc=%d: %s", rc, sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

static bool rf_tipfin_status_is_reorg_residue(const char *status)
{
    return status &&
           (strcmp(status, "reorg_detected") == 0 ||
            strcmp(status, "utxo_count_diverged") == 0);
}

/* RF_REORG_RESIDUE_MAX_PER_PASS bounds the scan window like the noncanonical
 * purge above; a contiguous reorg-residue run heals one window per tick. */
#define RF_REORG_RESIDUE_MAX_PER_PASS 8192

bool stage_reducer_frontier_purge_stale_reorg_tipfin(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out)
{
    if (!db || !out)
        LOG_FAIL("stage_repair", "purge_stale_reorg_tipfin: invalid args");

    /* Eligibility ceiling: only heights ALREADY covered by coins
     * (h <= coins_applied_height - 1) qualify — there the coins are applied
     * and replacing the verdict cannot tear a coin. Unknown coins frontier =>
     * nothing to do here (the unknown path refuses upstream). */
    if (!out->coins_applied_found || out->coins_applied_height <= 0)
        return true;

    int lo = out->hstar + 1;
    int hi = out->coins_applied_height - 1;
    if (out->sweep_top < hi)
        hi = out->sweep_top;
    if (hi - lo + 1 > RF_REORG_RESIDUE_MAX_PER_PASS)
        hi = lo + RF_REORG_RESIDUE_MAX_PER_PASS - 1;
    if (lo < 0 || hi < lo)
        return true;

    progress_store_tx_lock();
    if (!ensure_log_schema(db)) {
        progress_store_tx_unlock();
        LOG_FAIL("stage_repair",
                 "purge_stale_reorg_tipfin: schema ensure failed");
    }
    uint64_t header_admit_cursor = 0;
    if (!rf_header_admit_cursor_locked(db, &header_admit_cursor)) {
        progress_store_tx_unlock();
        return false;
    }

    struct arith_uint256 zero_work;
    arith_uint256_set_u64(&zero_work, 0);

    bool rc_ok = true;
    for (int h = lo; h <= hi; h++) {
        char status[64];
        enum rf_tipfin_state state = RF_TIPFIN_ABSENT;
        if (!rf_tipfin_state_at(db, h, &state, status)) {
            rc_ok = false;
            break;
        }
        /* Gate 1: the row must be PRESENT with ok=0 and one of the stale
         * residue statuses. Other ok=0 statuses are live consensus / upstream
         * blockers and must never be rewritten into ok=1 finalize_backfill. */
        if (state != RF_TIPFIN_FAIL)
            continue;
        if (!rf_tipfin_status_is_reorg_residue(status))
            continue;

        /* Gate 2: re-evidenced upstream — header_admit_log present at h with
         * a 32-byte hash, AND the lookahead binder hash(h+1) is available so
         * the replacement carries the row-H -> hash-H+1 finalized convention
         * (finalized_row_active_match compares row.tip_hash to
         * active_chain_at(h+1) — reorg-correct). The residue verdict pins H*
         * one below h, so the column at h+1 is precisely the rowless gap the
         * existing header_admit-keyed refill re-derives. A missing binder
         * leaves the row alone (no fabricated hash). A binder row at or above
         * the durable header_admit cursor is also ignored: after a forward-fork
         * rewind, stale H+1 rows remain in replay territory until header_admit
         * re-admits the canonical child and advances past them. */
        if ((uint64_t)(h + 1) >= header_admit_cursor)
            continue;

        struct uint256 lookahead;
        bool admit_here = false;
        bool admit_next = false;
        struct uint256 admit_dummy;
        if (!rf_header_admit_hash_at(db, h, &admit_dummy, &admit_here) ||
            !rf_header_admit_hash_at(db, h + 1, &lookahead, &admit_next)) {
            rc_ok = false;
            break;
        }
        if (!admit_here || !admit_next)
            continue;

        out->reorg_residue_tipfin_found++;
        if (out->lowest_reorg_residue_tipfin < 0 ||
            h < out->lowest_reorg_residue_tipfin)
            out->lowest_reorg_residue_tipfin = h;
        if (!apply)
            continue;

        /* Replace IN PLACE (INSERT OR REPLACE, same PRIMARY KEY h — the row
         * persists, never deleted; served_floor cannot regress). The fresh
         * verdict is ok=1 status='finalize_backfill' (NOT 'anchor', so it is
         * not an is_anchor seed) with the lookahead binder hash. */
        if (!log_insert(db, h, "finalize_backfill", true, &zero_work, -1, 0,
                        &lookahead)) {
            rc_ok = false;
            break;
        }
        out->reorg_residue_tipfin_replaced++;
        LOG_WARN("stage_repair",
                 "[stage_repair] reorg-residue tip_finalize verdict replaced "
                 "h=%d stale_status=%s -> finalize_backfill ok=1 "
                 "(hstar=%d coins_applied=%d) — false coin-tear cleared",
                 h, status, out->hstar, out->coins_applied_height);
    }

    progress_store_tx_unlock();

    if (out->reorg_residue_tipfin_found > 0 &&
        out->reorg_residue_tipfin_replaced == 0)
        LOG_WARN("stage_repair",
                 "[stage_repair] reorg-residue tip_finalize rows: found=%d "
                 "lowest=%d window=[%d,%d]%s",
                 out->reorg_residue_tipfin_found,
                 out->lowest_reorg_residue_tipfin, lo, hi,
                 apply ? "" : "; dry-run");
    return rc_ok;
}
