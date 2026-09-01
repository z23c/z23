/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_rederive_range — THE universal re-derive primitive
 * (docs/work/fail-safe-architecture.md §0c).
 *
 * Generalizes reducer_frontier_replay_stale_script_tx into one mechanism-
 * agnostic entry: given a range [from_height, to_height], rewind the
 * body-dependent stage cursors to from_height, delete the stale suffix rows,
 * and (LCC-safely) inverse-rewind coins when from_height is below the coin
 * frontier — then the normal forward fold re-runs the identical validators over
 * the same PoW-verified on-disk bodies and rewrites byte-identical verdicts.
 *
 * The mutation sequence mirrors the proven stale-script replay transaction and
 * reuses its coins-rewind + log-delete helpers (Law 2 — one write path). See
 * the header for the full contract; the load-bearing invariants:
 *   - CONSENSUS PARITY: no validity change — re-derivation reproduces the same
 *     verdict (a genuine reject re-rejects; a corrupt/stale/rowless height gets
 *     its correct verdict).
 *   - LCC: never lower a cursor below the applied coin frontier without
 *     inverse-rewinding coins in the SAME txn; refuse (never hole) if an applied
 *     height lacks its inverse delta.
 *   - tip_finalize_log ROWS are never deleted (served-floor invariant) — only
 *     its cursor is rewound.
 *   - header_admit + validate_headers are NOT rewound (header/PoW authority).
 */

#include "jobs/stage_rederive_range.h"

#include "jobs/stage_repair_internal.h"   /* cursor_at_unlocked, force_stage_cursor */
#include "jobs/utxo_apply_stage.h"
#include "reducer_frontier_replay_tx.h"   /* delete_log_range, inverse_delta_range_checked */
#include "utxo_apply_delta_internal.h"    /* delete_rows_above, unwind_write_cursor */

#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stddef.h>
#include <string.h>

/* The body-dependent stages, in fold order, that carry a per-height verdict log
 * this primitive deletes+rewinds. utxo_apply is handled separately (coins
 * inverse-rewind); tip_finalize is cursor-only (its log rows are the served
 * floor). header_admit + validate_headers are header/PoW authority and stay. */
static const struct {
    const char *stage;
    const char *log;
} k_rederive_stages[] = {
    { "body_fetch",      "body_fetch_log" },
    { "body_persist",    "body_persist_log" },
    { "script_validate", "script_validate_log" },
    { "proof_validate",  "proof_validate_log" },
};

bool stage_rederive_range(sqlite3 *db, struct main_state *ms,
                          int from_height, int to_height,
                          struct stage_rederive_range_result *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    /* ms is accepted for API symmetry; the forward fold re-creates
     * created_outputs itself, so the coins rewind never depends on it. */
    (void)ms;

    if (!db)
        LOG_FAIL("stage_rederive", "stage_rederive_range: NULL db");
    if (from_height < 0 || to_height < from_height)
        LOG_FAIL("stage_rederive",
                 "stage_rederive_range: invalid range from=%d to=%d",
                 from_height, to_height);
    if (out) {
        out->from_height = from_height;
        out->to_height = to_height;
    }

    progress_store_tx_lock();

    /* Snapshot every cursor we may lower (all reads want the lock held). */
    int utxo_cursor = -1, tip_cursor = -1;
    int scur[sizeof(k_rederive_stages) / sizeof(k_rederive_stages[0])];
    bool read_ok =
        stage_repair_cursor_at_unlocked(db, "utxo_apply", &utxo_cursor) &&
        stage_repair_cursor_at_unlocked(db, "tip_finalize", &tip_cursor);
    for (size_t i = 0; read_ok &&
         i < sizeof(k_rederive_stages) / sizeof(k_rederive_stages[0]); i++)
        read_ok = stage_repair_cursor_at_unlocked(
            db, k_rederive_stages[i].stage, &scur[i]);
    if (!read_ok) {
        progress_store_tx_unlock();
        LOG_FAIL("stage_rederive",
                 "stage_rederive_range: cursor snapshot failed from=%d",
                 from_height);
    }

    /* Below the coin frontier ⇒ the applied coins in [from_height, utxo_cursor)
     * must be inverse-rewound in the same txn (LCC). Never lower the utxo_apply
     * cursor UP: only act when it sits strictly above from_height. */
    bool rewind_coins = utxo_cursor > from_height;
    if (out)
        out->coins_frontier_before = utxo_cursor;

    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("stage_rederive",
                 "[stage_rederive] BEGIN failed from=%d: %s",
                 from_height, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        return false;  // raw-return-ok:logged-above
    }

    int cursors_rewound = 0;
    bool coins_rewound = false;

    /* (1) Coins side. The inverse-delta range check REFUSES (returns false)
     * when an applied height lacks its inverse image — that is an LCC refusal,
     * NOT a store error: roll back cleanly and report so the caller escalates
     * to a refold-from-anchor rung instead of manufacturing a coin hole. */
    if (rewind_coins) {
        if (!reducer_frontier_replay_inverse_delta_range_checked(
                db, from_height, utxo_cursor)) {
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            progress_store_tx_unlock();
            LOG_WARN("stage_rederive",
                     "[stage_rederive] LCC refusal: missing inverse delta in "
                     "[%d,%d) — escalate to refold-from-anchor",
                     from_height, utxo_cursor);
            if (out) {
                out->ok = false;
                out->refused_no_inverse = true;
            }
            return true;  /* clean refusal, not a hard error */
        }
        if (!utxo_apply_delete_rows_above(db, from_height, utxo_cursor - 1) ||
            !utxo_apply_unwind_write_cursor(db, (uint64_t)from_height) ||
            !utxo_apply_frontier_set_in_tx(db, from_height))
            goto rollback;
        coins_rewound = true;
        cursors_rewound++; /* utxo_apply */
    }

    /* (2) Upstream body-dependent verdict logs + cursors: delete the stale
     * suffix and lower the cursor. Gated per stage so a cursor already at/below
     * from_height is left untouched (idempotent; never moves a cursor up). The
     * delete helper itself no-ops when cursor <= from_height. */
    for (size_t i = 0;
         i < sizeof(k_rederive_stages) / sizeof(k_rederive_stages[0]); i++) {
        if (scur[i] <= from_height)
            continue;
        if (!reducer_frontier_replay_delete_log_range(
                db, k_rederive_stages[i].log, from_height, scur[i]) ||
            !stage_repair_force_stage_cursor(
                db, k_rederive_stages[i].stage, from_height))
            goto rollback;
        cursors_rewound++;
    }

    /* (3) tip_finalize: rewind the CURSOR only — its log rows are the durable
     * served-floor evidence and are NEVER deleted; the surviving rows
     * re-finalize forward once the upstream stages re-derive. */
    if (tip_cursor > from_height) {
        if (!stage_repair_force_stage_cursor(db, "tip_finalize", from_height))
            goto rollback;
        cursors_rewound++;
    }

    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("stage_rederive",
                 "[stage_rederive] COMMIT failed from=%d: %s",
                 from_height, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        return false;  // raw-return-ok:logged-above
    }
    progress_store_tx_unlock();

    if (out) {
        out->ok = true;
        out->rewound = cursors_rewound > 0;
        out->coins_rewound = coins_rewound;
        out->cursors_rewound = cursors_rewound;
    }
    LOG_INFO("stage_rederive",
             "[stage_rederive] rederive [%d,%d] committed: cursors_rewound=%d "
             "coins_rewound=%d (fold re-derives forward)",
             from_height, to_height, cursors_rewound, (int)coins_rewound);
    return true;

rollback:
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    LOG_FAIL("stage_rederive",
             "stage_rederive_range: rewind txn failed from=%d to=%d",
             from_height, to_height);
}
