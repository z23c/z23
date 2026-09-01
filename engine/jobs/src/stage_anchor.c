/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "jobs/stage_anchor.h"

#include "jobs/stage_helpers.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/stage.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* The coins-DEPENDENT stages whose anchor target is capped at coins_applied.
 *
 * utxo_apply consumes proof_validate_log[h] at exactly its own cursor h, which
 * consumes script_validate_log[h], which consumes the per-height created_outputs
 * index that BODY_PERSIST builds (created_outputs_index_put_block, the prevout
 * source for transparent spends above the seed). coins_applied caps utxo_apply
 * (it must re-derive every coin above the snapshot/import seed). If the stages
 * that PRODUCE utxo_apply's per-height inputs are allowed to JUMP past
 * coins_applied on an authority/seed re-anchor — e.g. when the active-chain
 * cached tip sits far above the seed (snapshot seeded at H while the
 * on-disk/header body frontier is H+N) — they stamp their cursors to H+N
 * WITHOUT producing the [H+1 .. H+N-1] log rows / created_outputs entries. Two
 * failure shapes result, both pinning the tip at the seed (getblockcount=0):
 *   (a) proof_validate jumps -> utxo_apply (pinned at H+1) finds
 *       proof_validate_log[H+1] ABSENT, a durable upstream HOLE, idles forever
 *       ("proof_validate_log row ABSENT at height=H+1 while proof_validate
 *       cursor=H+N already past it", utxo_apply_stage.c:215); and
 *   (b) body_persist jumps -> it never builds created_outputs for [H+1..H+N-1],
 *       so script_validate (capped at H+1) cannot resolve the transparent
 *       prevouts those blocks create ("prevout_unresolved height=H+k").
 * Capping ALL of body_persist/script_validate/proof_validate/utxo_apply at
 * coins_applied keeps the whole coins-dependent sub-pipeline in lockstep with
 * the coins frontier, so it re-folds CONTIGUOUSLY from the seed and never
 * manufactures the hole / index gap — the SAME contiguous shape a small-gap
 * (live) seed gets for free. The coins-INDEPENDENT stages
 * (header_admit/validate_headers/body_fetch) are NOT capped; they legitimately
 * track the header/body frontier (body_fetch only OBSERVES on-disk bodies; it
 * builds no coins-derived index). The cap is on the re-anchor TARGET only — the
 * stages still step FORWARD past coins_applied normally as the fold advances
 * (e.g. proof_validate legitimately runs ahead of utxo_apply during IBD). */
static bool stage_is_coins_dependent(const char *stage)
{
    return stage && (strcmp(stage, "body_persist") == 0 ||
                     strcmp(stage, "script_validate") == 0 ||
                     strcmp(stage, "proof_validate") == 0 ||
                     strcmp(stage, "utxo_apply") == 0);
}

static bool anchor_target_for_stage(sqlite3 *db, const char *stage,
                                    uint64_t requested, const char *tag,
                                    const char *reason, uint64_t *out)
{
    if (!out)
        return false;
    *out = requested;
    if (!stage_is_coins_dependent(stage))
        return true;

    if (!progress_meta_table_ensure(db)) {
        LOG_WARN(tag,
                 "[%s] anchor upstream cursor failed "
                 "stage=%s reason=coins_frontier_schema reason=%s",
                 tag, stage, reason ? reason : "");
        return false;
    }

    int32_t applied = 0;
    bool found = false;
    if (!coins_kv_get_applied_height(db, &applied, &found)) {
        LOG_WARN(tag,
                 "[%s] anchor upstream cursor failed "
                 "stage=%s reason=coins_frontier_read reason=%s",
                 tag, stage, reason ? reason : "");
        return false;
    }
    if (!found)
        return true; /* Snapshot/import bootstrap may predate the frontier key. */
    if (applied < 0) {
        LOG_WARN(tag,
                 "[%s] anchor upstream cursor failed "
                 "stage=%s malformed_coins_frontier=%d reason=%s",
                 tag, stage, applied, reason ? reason : "");
        return false;
    }
    if (requested > (uint64_t)applied) {
        *out = (uint64_t)applied;
        LOG_WARN(tag,
                 "[%s] anchor upstream cursor capped "
                 "stage=%s requested=%llu coins_applied=%d reason=%s",
                 tag, stage, (unsigned long long)requested, applied,
                 reason ? reason : "");
    }
    return true;
}

/* ── FIX-3: log-frontier cap ───────────────────────────────────────────
 *
 * See stage_anchor.h for the four-prong cap rule. The helpers below keep
 * the table-existence probe separate so a missing log TABLE (a stage whose
 * schema is not created yet on a cold datadir) is fresh-seed semantics
 * (prong 3), distinguishable from a real SQLite error. */

/* *exists = true iff `log_table` exists in db. Returns false on a real
 * SQLite error (logged). */
static bool frontier_log_table_exists(sqlite3 *db, const char *log_table,
                                      bool *exists)
{
    *exists = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("stage_anchor",
                 "frontier cap: table probe prepare failed table=%s: %s",
                 log_table, sqlite3_errmsg(db));
    sqlite3_bind_text(st, 1, log_table, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    bool ok = true;
    if (rc == SQLITE_ROW) {
        *exists = true;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_anchor",
                 "frontier cap: table probe step failed table=%s: %s",
                 log_table, sqlite3_errmsg(db));
        ok = false;
    }
    sqlite3_finalize(st);
    return ok;
}

/* Single-row int64 probe over a fixed-set log table name (never caller
 * input). *found = a row came back; *value = its first column (when the
 * column is non-NULL). Returns false on a real SQLite error (logged). */
static bool frontier_probe_row(sqlite3 *db, const char *sql,
                               const char *log_table,
                               int64_t bind1, int64_t bind2, int nbinds,
                               bool *found, int64_t *value)
{
    *found = false;
    if (value)
        *value = -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("stage_anchor",
                 "frontier cap: probe prepare failed table=%s: %s",
                 log_table, sqlite3_errmsg(db));
    sqlite3_bind_int64(st, 1, (sqlite3_int64)bind1);
    if (nbinds > 1)
        sqlite3_bind_int64(st, 2, (sqlite3_int64)bind2);
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    bool ok = true;
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) != SQLITE_NULL) {
            *found = true;
            if (value)
                *value = sqlite3_column_int64(st, 0);
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_anchor",
                 "frontier cap: probe step failed table=%s: %s",
                 log_table, sqlite3_errmsg(db));
        ok = false;
    }
    sqlite3_finalize(st);
    return ok;
}

bool stage_anchor_cap_target_at_log_frontier(sqlite3 *db,
                                             const char *log_table,
                                             uint64_t cursor,
                                             uint64_t requested,
                                             bool seed_exempt,
                                             uint64_t *capped)
{
    if (!capped)
        LOG_FAIL("stage_anchor", "frontier cap: NULL capped out table=%s",
                 log_table ? log_table : "(null)");
    *capped = requested;
    if (!db || !log_table || !log_table[0])
        LOG_FAIL("stage_anchor", "frontier cap: invalid args db=%p table=%s",
                 (void *)db, log_table ? log_table : "(null)");

    /* (1) Never raise a target; at-or-behind requests pass through. */
    if (requested <= cursor)
        return true;
    /* (2) Caller-declared seed exemption (a PRE-INSERT verdict — header). */
    if (seed_exempt)
        return true;
    if (requested > (uint64_t)INT64_MAX)
        LOG_FAIL("stage_anchor",
                 "frontier cap: target out of range table=%s requested=%llu",
                 log_table, (unsigned long long)requested);

    char sql[256];
    bool ok = true;
    bool cap_hit = false;
    uint64_t cap_at = requested;
    bool found = false;
    int64_t gap = -1;

    progress_store_tx_lock();
    do {
        bool exists = false;
        if (!frontier_log_table_exists(db, log_table, &exists)) {
            ok = false;
            break;
        }
        if (!exists)
            break; /* (3) absent table == empty log == fresh seed. */

        /* (3) No row below requested -> fresh log, full jump. */
        int n = snprintf(sql, sizeof(sql),
                         "SELECT 1 FROM %s WHERE height < ? LIMIT 1",
                         log_table);
        if (n < 0 || n >= (int)sizeof(sql)) {
            LOG_WARN("stage_anchor", "frontier cap: sql overflow table=%s",
                     log_table);
            ok = false;
            break;
        }
        if (!frontier_probe_row(db, sql, log_table, (int64_t)requested, 0, 1,
                                &found, NULL)) {
            ok = false;
            break;
        }
        if (!found)
            break;

        /* (4a) Point-probe: a rowless cursor caps the jump immediately. */
        n = snprintf(sql, sizeof(sql),
                     "SELECT 1 FROM %s WHERE height = ? LIMIT 1", log_table);
        if (n < 0 || n >= (int)sizeof(sql)) {
            LOG_WARN("stage_anchor", "frontier cap: sql overflow table=%s",
                     log_table);
            ok = false;
            break;
        }
        if (!frontier_probe_row(db, sql, log_table, (int64_t)cursor, 0, 1,
                                &found, NULL)) {
            ok = false;
            break;
        }
        if (!found) {
            cap_hit = true;
            cap_at = cursor;
            break;
        }

        /* (4b) Lowest rowless height in (cursor, requested): one indexed
         * first-gap query (the PK index makes both sides O(log n)) — NOT a
         * per-height loop. With a row at `cursor` (proved by 4a), the lowest
         * rowless height necessarily follows an existing row >= cursor. */
        n = snprintf(sql, sizeof(sql),
                     "SELECT MIN(t1.height + 1) FROM %s t1 "
                     "WHERE t1.height >= ? AND t1.height + 1 < ? "
                     "AND NOT EXISTS (SELECT 1 FROM %s t2 "
                     "WHERE t2.height = t1.height + 1)",
                     log_table, log_table);
        if (n < 0 || n >= (int)sizeof(sql)) {
            LOG_WARN("stage_anchor", "frontier cap: sql overflow table=%s",
                     log_table);
            ok = false;
            break;
        }
        if (!frontier_probe_row(db, sql, log_table, (int64_t)cursor,
                                (int64_t)requested, 2, &found, &gap)) {
            ok = false;
            break;
        }
        if (found && gap >= 0 && (uint64_t)gap < requested) {
            cap_hit = true;
            cap_at = (uint64_t)gap;
        }
    } while (0);
    progress_store_tx_unlock();

    if (!ok)
        return false;  // raw-return-ok:logged-in-probe-helpers
    if (cap_hit) {
        *capped = cap_at;
        LOG_WARN("stage_anchor",
                 "[stage_anchor] anchor jump capped at log frontier "
                 "stage=%s from=%llu requested=%llu capped=%llu "
                 "reason=log_frontier",
                 log_table, (unsigned long long)cursor,
                 (unsigned long long)requested, (unsigned long long)cap_at);
    }
    return true;
}

bool stage_anchor_upstream_cursors_to(sqlite3 *db, uint64_t target,
                                      const char *owner,
                                      const char *reason,
                                      bool seed_exempt)
{
    if (!db)
        return false;
    static const struct {
        const char *stage;
        const char *log_table;
    } upstream[] = {
        { "header_admit",     "header_admit_log"     },
        { "validate_headers", "validate_headers_log" },
        { "body_fetch",       "body_fetch_log"       },
        { "body_persist",     "body_persist_log"     },
        { "script_validate",  "script_validate_log"  },
        { "proof_validate",   "proof_validate_log"   },
        { "utxo_apply",       "utxo_apply_log"       },
    };
    const char *tag = owner && owner[0] ? owner : "stage_anchor";

    for (size_t i = 0; i < sizeof(upstream) / sizeof(upstream[0]); i++) {
        uint64_t stage_target = target;
        if (!anchor_target_for_stage(db, upstream[i].stage, target, tag,
                                     reason, &stage_target))
            return false;
        uint64_t before = stage_cursor_persisted(db, upstream[i].stage, tag);
        /* FIX-3: never jump a cursor past a rowless height in the stage's
         * OWN log — that jump is what manufactures the log-hole wedge
         * class. Applied AFTER the utxo_apply coins-cap above so the
         * tighter bound wins. */
        if (!stage_anchor_cap_target_at_log_frontier(db,
                                                     upstream[i].log_table,
                                                     before, stage_target,
                                                     seed_exempt,
                                                     &stage_target)) {
            LOG_WARN(tag,
                     "[%s] anchor upstream cursor failed "
                     "stage=%s from=%llu reason=frontier_cap_error caller=%s",
                     tag, upstream[i].stage, (unsigned long long)before,
                     reason ? reason : "");
            return false;
        }
        /* Avoid entering the transaction-owning cursor setter for a proven
         * no-op. Snapshot activation pre-stamps every upstream cursor inside
         * its larger cutover transaction before asking the seed helper to add
         * log/meta witnesses; calling the setter at from==to would otherwise
         * attempt a nested BEGIN. Production seed/authority callers already
         * hold the recursive progress-store lock across this decision. */
        if (before < stage_target &&
            !stage_set_named_cursor_if_behind(db, upstream[i].stage,
                                              stage_target)) {
            LOG_WARN(tag,
                     "[%s] anchor upstream cursor failed "
                     "stage=%s from=%llu to=%llu reason=%s",
                     tag, upstream[i].stage, (unsigned long long)before,
                     (unsigned long long)stage_target, reason ? reason : "");
            return false;
        }
        if (before < stage_target) {
            LOG_INFO(tag,
                     "[%s] anchor upstream cursor stage=%s "
                     "from=%llu to=%llu reason=%s",
                     tag, upstream[i].stage, (unsigned long long)before,
                     (unsigned long long)stage_target, reason ? reason : "");
        }
    }
    return true;
}
