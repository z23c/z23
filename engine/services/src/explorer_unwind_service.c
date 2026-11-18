/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Reorg unwind of the explorer projection and its on-chain overlays.
 *
 * Why this exists: the catchup cursor can be rewound below a block that a
 * reorg took off the active chain (node_db_catchup_fork_rewind), but the
 * rows the losing branch wrote stayed behind. Two kinds of damage followed:
 *
 *   1. Height-stamped rows (tx_outputs, tx_inputs, op_returns, zslp_*,
 *      zanc_anchors, view_integrity, ...) of the loser kept describing
 *      transactions that are not on the chain.
 *   2. Overlay state that is MUTATED in place (a ZNAM name's owner, target
 *      and expiry, its text and address records, ZID identity status, the
 *      ZDIR directory) cannot be undone by height: a loser REGISTER kept the
 *      name FCFS-taken so the winner's REGISTER was refused, and a re-walk of
 *      a winner RENEW or TRANSFER ran twice over state it had already
 *      changed.
 *
 * The fix is exact:
 *
 *   - everything stamped with a height above `fork_height` is deleted;
 *   - when the stale range carried any ZNAM / ZID / ZDIR operation (or a
 *     mutable row was last touched above the fork), the in-place tables are
 *     cleared and re-folded from the on-chain operations at heights at or
 *     below the fork, in block order, by the same apply code the live walk
 *     runs. The common reorg (no overlay operation in the stale range) pays
 *     only the stamped deletes;
 *   - the two cursor-owning derived catalogs (zslp_ledger, op_return_index)
 *     carry a running digest that chains every folded height. Each keeps a
 *     bounded per-height digest history (models/catalog_digest_history.h, as
 *     deep as the catchup fork scan), so a reorg within that window rewinds
 *     the catalog EXACTLY: rows above the fork go, spends above it are
 *     undone, cursor = fork and digest = the stored digest at the fork. Only
 *     a reorg deeper than the window, or a catalog that predates the history,
 *     falls back to the old drop-and-rebuild (a WARN names the reason);
 *   - the `transactions` table is pruned by block hash against the active
 *     chain when the caller can supply it, never by height alone (see
 *     unwind_transactions);
 *   - the two catalog backfills are excluded while the unwind runs (fold
 *     guards, bounded wait, lock order documented at unwind_take_guards).
 *
 * All of it runs in one transaction: a failure leaves the projection as it
 * was. node.db ONLY; never consulted by consensus.
 *
 * Knowingly NOT unwound: the append-only ZNAM event-log projection. That gap
 * predates this change and is out of its scope. */

#include "services/explorer_unwind_service.h"
#include "models/explorer_index.h"
#include "models/database.h"
#include "models/activerecord.h"
#include "models/op_return_index.h"
#include "models/zslp_ledger.h"
#include "platform/time_compat.h"
#include "util/blocker.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "overlay/overlay_projection.h"
#include "script/standard.h"
#include "util/ar_step_readonly.h"
#include "util/result.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "zdir/zdir.h"
#include "znam/znam.h"
#include "zid/zid_anchor.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Every table below carries a block height on each row; the derived row is a
 * pure function of the block at that height (and of rows below it), so a
 * delete above the fork is exact. The rows of the two cursor-owning catalogs
 * (zslp_ledger, zslp_validity, op_return_index) are NOT listed: their models
 * delete them together with the cursor/digest rewind they belong to. */
static const char *const k_stamped_deletes[] = {
    "DELETE FROM tx_outputs WHERE block_height>?",
    "DELETE FROM tx_inputs WHERE block_height>?",
    "DELETE FROM op_returns WHERE block_height>?",
    "DELETE FROM sapling_spends WHERE block_height>?",
    "DELETE FROM sapling_outputs WHERE block_height>?",
    "DELETE FROM joinsplits WHERE block_height>?",
    "DELETE FROM sprout_nullifiers WHERE block_height>?",
    "DELETE FROM view_integrity WHERE height>?",
    "DELETE FROM zslp_transfers WHERE block_height>?",
    "DELETE FROM zslp_tokens WHERE genesis_height>?",
    "DELETE FROM zanc_anchors WHERE height>?",
};

/* Tables whose rows are mutated in place by overlay operations. They are
 * rebuilt from the chain, never patched. */
static const char *const k_mutable_clears[] = {
    "DELETE FROM znam_names",
    "DELETE FROM znam_text_records",
    "DELETE FROM znam_addr_records",
    "DELETE FROM zid_identities",
    "DELETE FROM onion_directory",
};

/* Does a mutable overlay row carry a stamp above the fork? Catches state the
 * op_returns probe cannot see (a row whose op_returns row was never written). */
static const char k_mutable_stamped_probe[] =
    "SELECT 1 WHERE EXISTS (SELECT 1 FROM znam_names WHERE reg_height>?)"
    " OR EXISTS (SELECT 1 FROM zid_identities WHERE updated_height>?)"
    " OR EXISTS (SELECT 1 FROM onion_directory WHERE updated_height>?)";

static bool unwind_exec_height(struct node_db *ndb, const char *sql,
                               int64_t h)
{
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s, sql);
    AR_BIND_INT(s, 1, h);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (!ok)
        LOG_ERROR("explorer", "unwind: statement failed: %s", sql);
    return ok;
}

static bool unwind_exec_plain(struct node_db *ndb, const char *sql)
{
    if (!node_db_exec(ndb, sql)) {
        LOG_ERROR("explorer", "unwind: statement failed: %s", sql);
        return false;
    }
    return true;
}

/* The registry the replay dispatches through: only the overlays whose state
 * is mutated in place. Built from the live registry so a descriptor is never
 * duplicated here. */
static bool unwind_replay_registry(struct overlay_registry *out)
{
    static const char *const names[] = { "znam", "zid", "zdir" };
    const struct overlay_registry *all = explorer_index_overlays();
    if (!all)
        return false;
    overlay_registry_init(out);
    bool ok = true;
    for (size_t i = 0; i < all->count; i++) {
        for (size_t n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
            if (all->entries[i].name &&
                strcmp(all->entries[i].name, names[n]) == 0)
                ok = overlay_registry_add(out, &all->entries[i]) && ok;
        }
    }
    return ok && overlay_registry_count(out) == 3;
}

static bool unwind_script_replayed(const struct overlay_registry *reg,
                                   const uint8_t *script, size_t len)
{
    char tag[OVERLAY_LOKAD_LEN];
    return script && overlay_peek_lokad(script, len, tag) &&
           overlay_registry_find(reg, tag) != NULL;
}

/* True when any op_returns row above the fork is a replayed-overlay op. */
static bool unwind_stale_range_touched(struct node_db *ndb,
                                       const struct overlay_registry *reg,
                                       int fork_height, bool *touched)
{
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
        "SELECT script FROM op_returns WHERE block_height>?");
    AR_BIND_INT(s, 1, fork_height);
    *touched = false;
    enum zcl_step rc = ZCL_STEP_ROW;
    while (!*touched &&
           (rc = ar_step_checked(s, "unwind op_returns probe", NULL)) ==
               ZCL_STEP_ROW) {
        const uint8_t *script = sqlite3_column_blob(s, 0);
        if (unwind_script_replayed(reg, script, (size_t)AR_COL_BYTES(s, 0)))
            *touched = true;
    }
    AR_FINALIZE(s);
    if (rc == ZCL_STEP_ERROR)
        LOG_FAIL("explorer", "unwind: op_returns probe step failed");
    if (*touched)
        return true;

    AR_PREPARE_BOOL(ndb, s, k_mutable_stamped_probe);
    AR_BIND_INT(s, 1, fork_height);
    AR_BIND_INT(s, 2, fork_height);
    AR_BIND_INT(s, 3, fork_height);
    rc = ar_step_checked(s, "unwind stamp probe", NULL);
    AR_FINALIZE(s);
    if (rc == ZCL_STEP_ERROR)
        LOG_FAIL("explorer", "unwind: stamp probe step failed");
    *touched = rc == ZCL_STEP_ROW;
    return true;
}

/* Ascending, de-duplicated heights at or below the fork that carry a
 * replayed-overlay operation. Caller frees *out. */
static bool unwind_replay_heights(struct node_db *ndb,
                                  const struct overlay_registry *reg,
                                  int fork_height, int **out, size_t *n_out)
{
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
        "SELECT block_height,script FROM op_returns WHERE block_height<=?"
        " ORDER BY block_height ASC");
    AR_BIND_INT(s, 1, fork_height);

    int *heights = NULL;
    size_t n = 0, cap = 0;
    bool ok = true;
    enum zcl_step rc = ZCL_STEP_ROW;
    while (ok && (rc = ar_step_checked(s, "unwind replay heights", NULL)) ==
                       ZCL_STEP_ROW) {
        int h = (int)AR_COL_INT(s, 0);
        const uint8_t *script = sqlite3_column_blob(s, 1);
        if (!unwind_script_replayed(reg, script, (size_t)AR_COL_BYTES(s, 1)))
            continue;
        if (n > 0 && heights[n - 1] == h)
            continue;
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 64;
            int *grown = zcl_realloc(heights, ncap * sizeof(*heights),
                                   "unwind replay heights");
            if (!grown) {
                LOG_ERROR("explorer", "unwind: out of memory for %zu heights",
                          ncap);
                ok = false;
                break;
            }
            heights = grown;
            cap = ncap;
        }
        heights[n++] = h;
    }
    AR_FINALIZE(s);
    if (rc == ZCL_STEP_ERROR) {
        LOG_ERROR("explorer", "unwind: op_returns replay scan step failed");
        ok = false;
    }
    if (!ok) {
        free(heights);
        return false;
    }
    *out = heights;
    *n_out = n;
    return true;
}

/* The same first-OP_RETURN rule the live indexer applies. */
static const struct tx_out *unwind_first_op_return(const struct transaction *tx)
{
    for (size_t vo = 0; vo < tx->num_vout; vo++) {
        const struct tx_out *o = &tx->vout[vo];
        uint8_t a20[20];
        bool has = false;
        if (utxo_classify_script(o->script_pub_key.data,
                                 o->script_pub_key.size, a20, &has) ==
            SCRIPT_OP_RETURN)
            return o;
    }
    return NULL;
}

static bool unwind_replay_block(struct node_db *ndb,
                                const struct overlay_registry *reg,
                                const struct block *blk, int height)
{
    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        const struct tx_out *o = unwind_first_op_return(tx);
        if (!o)
            continue;
        (void)overlay_ingest(reg, ndb, tx, o->script_pub_key.data,
                             o->script_pub_key.size, height);
    }
    return true;
}

static bool unwind_replay(struct node_db *ndb,
                          const struct overlay_registry *reg, int fork_height,
                          explorer_block_reader_fn read, void *rctx)
{
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(k_mutable_clears) /
                                    sizeof(k_mutable_clears[0]); i++)
        ok = unwind_exec_plain(ndb, k_mutable_clears[i]);

    int *heights = NULL;
    size_t n = 0;
    if (ok)
        ok = unwind_replay_heights(ndb, reg, fork_height, &heights, &n);
    if (ok && n > 0 && !read) {
        LOG_ERROR("explorer", "unwind: %zu overlay block(s) to replay but no "
                  "block reader", n);
        ok = false;
    }
    for (size_t i = 0; ok && i < n; i++) {
        struct block blk;
        block_init(&blk);
        if (!read(rctx, heights[i], &blk)) {
            LOG_ERROR("explorer", "unwind: block at height %d unreadable; "
                      "overlay state cannot be rebuilt", heights[i]);
            ok = false;
            continue;
        }
        ok = unwind_replay_block(ndb, reg, &blk, heights[i]);
        block_free(&blk);
    }
    free(heights);
    return ok;
}

/* The two cursor-owning derived catalogs unwind themselves: each deletes its
 * rows above the fork and, when its cursor was above the fork, restores the
 * cursor and digest exactly from its bounded digest history, or truncates
 * for its own backfill to re-derive when the history cannot prove the fork
 * (models/catalog_digest_history.h). */
static bool unwind_derived_catalogs(struct node_db *ndb, int fork_height,
                                    struct explorer_unwind_report *report)
{
    enum catalog_rewind zl = zslp_ledger_unwind_above(ndb, fork_height);
    enum catalog_rewind oi = zl == CATALOG_REWIND_ERROR
                                 ? CATALOG_REWIND_ERROR
                                 : op_return_index_unwind_above(ndb,
                                                                fork_height);
    if (report) {
        report->zslp_ledger = zl;
        report->op_return_index = oi;
    }
    if (zl == CATALOG_REWIND_ERROR || oi == CATALOG_REWIND_ERROR) {
        LOG_ERROR("explorer", "unwind: derived catalogs could not be reset "
                  "at fork height %d", fork_height);
        return false;
    }
    return true;
}

/* The transactions table (txid -> block hash/height) is written by the same
 * catchup walk (sync_block_lean -> db_tx_save) and by the snapshot txindex
 * import. It is NOT height-stamped state a blind delete may touch: an
 * imported or lean row above the fork can be a valid row of the ACTIVE chain
 * whose block was never walked, and deleting it loses a row nothing rewrites.
 *
 * The exact rule needs the active chain: a row above the fork is stale
 * precisely when its block hash is not the active chain's hash at that
 * height. Such a row describes a transaction in a block the reorg removed;
 * a transaction of the winning branch is rewritten by the re-walk (db_tx_save
 * replaces by txid), and one only the loser carried would stay forever.
 * Rows whose hash IS the active hash are kept. Without a hash source
 * (chain->active_hash == NULL) the table is left alone. */
struct unwind_block_ref {
    int height;
    uint8_t hash[32];
};

static bool unwind_collect_blocks_above(struct node_db *ndb, int fork_height,
                                        struct unwind_block_ref **out,
                                        size_t *n_out)
{
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
        "SELECT block_height,block_hash FROM transactions"
        " WHERE block_height>? GROUP BY block_height,block_hash");
    AR_BIND_INT(s, 1, fork_height);
    struct unwind_block_ref *refs = NULL;
    size_t n = 0, cap = 0;
    bool ok = true;
    enum zcl_step rc = ZCL_STEP_ROW;
    while (ok && (rc = ar_step_checked(s, "unwind transactions scan", NULL)) ==
                       ZCL_STEP_ROW) {
        if (AR_COL_BYTES(s, 1) != 32)
            continue;
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 64;
            struct unwind_block_ref *grown = zcl_realloc(
                refs, ncap * sizeof(*refs), "unwind transactions blocks");
            if (!grown) {
                LOG_ERROR("explorer", "unwind: out of memory for %zu block "
                          "refs", ncap);
                ok = false;
                break;
            }
            refs = grown;
            cap = ncap;
        }
        refs[n].height = (int)AR_COL_INT(s, 0);
        memcpy(refs[n].hash, sqlite3_column_blob(s, 1), 32);
        n++;
    }
    AR_FINALIZE(s);
    if (rc == ZCL_STEP_ERROR) {
        LOG_ERROR("explorer", "unwind: transactions scan step failed");
        ok = false;
    }
    if (!ok) {
        free(refs);
        return false;
    }
    *out = refs;
    *n_out = n;
    return true;
}

static bool unwind_delete_block_rows(struct node_db *ndb, int fork_height,
                                     const uint8_t hash[32])
{
    sqlite3_stmt *s = NULL;
    AR_PREPARE_BOOL(ndb, s,
        "DELETE FROM transactions WHERE block_hash=? AND block_height>?");
    AR_BIND_BLOB(s, 1, hash, 32);
    AR_BIND_INT(s, 2, fork_height);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    if (!ok)
        LOG_ERROR("explorer", "unwind: transactions delete failed");
    return ok;
}

static bool unwind_transactions(struct node_db *ndb, int fork_height,
                                const struct explorer_unwind_chain *chain,
                                struct explorer_unwind_report *report)
{
    if (!chain || !chain->active_hash)
        return true;
    struct unwind_block_ref *refs = NULL;
    size_t n = 0;
    if (!unwind_collect_blocks_above(ndb, fork_height, &refs, &n))
        return false;  // raw-return-ok:the collector logged the failure
    bool ok = true;
    for (size_t i = 0; ok && i < n; i++) {
        uint8_t active[32];
        bool on_chain = chain->active_hash(chain->ctx, refs[i].height,
                                           active) &&
                        memcmp(active, refs[i].hash, 32) == 0;
        if (on_chain)
            continue;
        ok = unwind_delete_block_rows(ndb, fork_height, refs[i].hash);
        if (ok && report)
            report->stale_blocks_in_transactions++;
    }
    free(refs);
    return ok;
}

static bool unwind_stamped_deletes(struct node_db *ndb, int fork_height)
{
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(k_stamped_deletes) /
                                    sizeof(k_stamped_deletes[0]); i++)
        ok = unwind_exec_height(ndb, k_stamped_deletes[i], fork_height);
    return ok;
}

static bool unwind_body(struct node_db *ndb, int fork_height,
                        const struct explorer_unwind_chain *chain,
                        struct explorer_unwind_report *report)
{
    struct overlay_registry reg;
    if (!unwind_replay_registry(&reg)) {
        LOG_ERROR("explorer", "unwind: overlay registry is incomplete");
        return false;
    }
    bool touched = false;
    bool ok = unwind_stale_range_touched(ndb, &reg, fork_height, &touched);

    /* A replay can only rebuild what the projection holds: it needs the
     * outputs and op_returns of every height up to the fork. A datadir
     * seeded from a snapshot, or with holes below the fork, lacks them, and
     * clearing the in-place tables there would destroy state that cannot be
     * re-derived. Such a database gets the stamped deletes only. The probe
     * scans view_integrity, so it runs only when a replay is wanted. */
    bool complete = !touched || fork_height < 0 ||
                    db_view_integrity_contiguous_height(ndb) >= fork_height;

    /* The derived catalogs read the stamped tables, so they settle first. */
    if (ok)
        ok = unwind_derived_catalogs(ndb, fork_height, report);
    if (ok)
        ok = unwind_stamped_deletes(ndb, fork_height);
    if (ok)
        ok = unwind_transactions(ndb, fork_height, chain, report);
    if (ok && touched && !complete) {
        LOG_WARN("explorer", "unwind: overlay operations above height %d but "
                 "the projection is not contiguous up to it; ZNAM/ZID/ZDIR "
                 "state is left as is (reindex-explorer rebuilds it)",
                 fork_height);
    } else if (ok && touched) {
        LOG_WARN("explorer", "unwind: overlay operations above height %d; "
                 "rebuilding ZNAM/ZID/ZDIR state from the chain",
                 fork_height);
        ok = unwind_replay(ndb, &reg, fork_height,
                           chain ? chain->read : NULL,
                           chain ? chain->ctx : NULL);
    }
    return ok;
}

/* ── The fold guards ───────────────────────────────────────────────────
 *
 * zslp_ledger and op_return_index each have a backfill that, on the shared
 * node.db connection, reads its cursor, folds, and writes cursor+digest back.
 * An unwind that runs between the read and the write would have its restored
 * cursor overwritten by a stale one. The unwind therefore holds BOTH fold
 * guards around its transaction.
 *
 * Lock order: zslp_ledger guard, then op_return_index guard; release in
 * reverse. All acquisition is try-lock. The unwind never holds one guard
 * while waiting for the other (it gives the first back and retries), and the
 * backfills never wait for a guard (a held guard skips their tick), so there
 * is no hold-and-wait and no cycle.
 *
 * Bounded wait: a fold batch is at most a few seconds, so the unwind polls
 * for up to UNWIND_GUARD_WAIT_MS. If a guard stays busy it returns
 * EXPLORER_UNWIND_ERR_BUSY having changed nothing, and the caller must not
 * rewind the cursor; the next tick retries. */
#define UNWIND_GUARD_WAIT_MS 10000
#define UNWIND_GUARD_POLL_MS 20

#ifdef ZCL_TESTING
static _Atomic int g_guard_wait_ms = UNWIND_GUARD_WAIT_MS;

void explorer_unwind_test_set_guard_wait_ms(int ms)
{
    atomic_store(&g_guard_wait_ms, ms < 0 ? UNWIND_GUARD_WAIT_MS : ms);
}

static int unwind_guard_wait_ms(void)
{
    return atomic_load(&g_guard_wait_ms);
}
#else
static int unwind_guard_wait_ms(void)
{
    return UNWIND_GUARD_WAIT_MS;
}
#endif

static bool unwind_try_both_guards(void)
{
    if (!zslp_ledger_fold_try_begin())
        return false;  // raw-return-ok:a busy guard is the normal answer; the caller polls
    if (!op_return_index_fold_try_begin()) {
        zslp_ledger_fold_end();
        return false;
    }
    return true;
}

static bool unwind_take_guards(void)
{
    const int64_t deadline_us = platform_time_monotonic_us() +
                                (int64_t)unwind_guard_wait_ms() * 1000;
    for (;;) {
        if (unwind_try_both_guards())
            return true;
        if (platform_time_monotonic_us() >= deadline_us)
            return false;
        platform_sleep_ms(UNWIND_GUARD_POLL_MS);
    }
}

static void unwind_release_guards(void)
{
    op_return_index_fold_end();
    zslp_ledger_fold_end();
}

static struct zcl_result unwind_locked(struct node_db *ndb, int fork_height,
                                       const struct explorer_unwind_chain *chain,
                                       struct explorer_unwind_report *report)
{
    if (!node_db_begin_immediate(ndb))
        return ZCL_ERR(-2, "unwind above height %d: could not open a "
                       "transaction", fork_height);
    if (!unwind_body(ndb, fork_height, chain, report)) {
        if (!node_db_rollback(ndb))
            LOG_ERROR("explorer", "unwind: rollback failed");
        return ZCL_ERR(-3, "unwind above height %d failed; projection left "
                       "as it was", fork_height);
    }
    if (!node_db_commit(ndb)) {
        if (!node_db_rollback(ndb))
            LOG_ERROR("explorer", "unwind: rollback after failed commit "
                      "failed");
        return ZCL_ERR(-4, "unwind above height %d: commit failed",
                       fork_height);
    }
    return ZCL_OK;
}

/* The failure signal. A failed unwind leaves the projection as it was while
 * the caller has (or will have) moved its cursor, so the losing branch may
 * still be indexed: raise the named blocker, and clear it when a later unwind
 * succeeds. Invalid arguments and a busy guard changed nothing, so they
 * neither raise nor clear it. */
static void unwind_note_outcome(int fork_height, const struct zcl_result *res)
{
    if (res->ok) {
        blocker_clear(EXPLORER_UNWIND_BLOCKER_ID);
        return;
    }
    struct blocker_record r;
    char reason[200];
    snprintf(reason, sizeof(reason),
             "reorg unwind to height %d failed (%s): ZNAM/ZID/ZDIR and token "
             "tables may still hold the losing branch; run -reindex-explorer",
             fork_height, res->message);
    if (blocker_init(&r, EXPLORER_UNWIND_BLOCKER_ID, "explorer",
                     BLOCKER_DEPENDENCY, reason)) {
        r.escape_deadline_secs = 0; /* a person decides; a later unwind or a
                                       reindex clears it */
        (void)blocker_set(&r);
    }
}

struct zcl_result explorer_index_unwind_above_chain(
    struct node_db *ndb, int fork_height,
    const struct explorer_unwind_chain *chain,
    struct explorer_unwind_report *report)
{
    if (report)
        memset(report, 0, sizeof(*report));
    if (!ndb || !ndb->open || fork_height < -1)
        return ZCL_ERR(-1, "explorer_index_unwind_above: invalid args "
                       "(fork_height=%d)", fork_height);
    if (!unwind_take_guards())
        return ZCL_ERR(EXPLORER_UNWIND_ERR_BUSY, "unwind above height %d: a "
                       "catalog fold still holds its guard after %d ms; "
                       "nothing changed, retry on the next tick", fork_height,
                       unwind_guard_wait_ms());
    struct zcl_result res = unwind_locked(ndb, fork_height, chain, report);
    unwind_note_outcome(fork_height, &res);
    if (res.ok && chain && chain->after_commit &&
        !chain->after_commit(chain->ctx, fork_height))
        res = ZCL_ERR(EXPLORER_UNWIND_ERR_HOOK, "unwind above height %d "
                      "committed but the cursor move that follows it failed",
                      fork_height);
    unwind_release_guards();
    return res;
}

struct zcl_result explorer_index_unwind_above(struct node_db *ndb,
                                              int fork_height,
                                              explorer_block_reader_fn read,
                                              void *rctx)
{
    struct explorer_unwind_chain chain = { .read = read, .ctx = rctx };
    return explorer_index_unwind_above_chain(ndb, fork_height, &chain, NULL);
}
