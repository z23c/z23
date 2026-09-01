// one-result-type-ok:xor-mismatch-classifier — the sole remaining legacy
// export, utxo_recovery_xor_mismatch_is_corruption_candidate, is a pure
// two-integer classification (stale-vs-corruption split, see the doc
// comment above it) with no failure path — there is nothing that can fail
// when comparing two uint64_t counts, so struct zcl_result would always
// report OK. Every fallible surface in this file (utxo_recovery_commit_tip,
// utxo_recovery_wipe, utxo_recovery_execute, ...) already returns
// zcl_result.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * UTXO Recovery Service: boot-time UTXO consistency checks and destructive
 * recovery operations gated through recovery_policy.
 */

#include "services/utxo_recovery_service.h"
#include "services/recovery_policy.h"
#include "services/chain_activation_service.h"
#include "services/chain_restore_executor.h"
#include "services/chain_restore_repair.h"
#include "services/chain_state_service.h"
#include "services/chain_tip.h"
#include "net/snapshot_sync_contract.h"
#include "config/boot_internal.h"
#include "config/db_service.h"
#include "validation/main_state.h"
#include "validation/process_block.h"
#include "chain/chainparams.h"
#include "jobs/reducer_frontier.h"
#include "storage/coins_view_sqlite.h"
#include "storage/coins_db.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "coins/coins_view.h"
#include "coins/utxo_commitment.h"
#include "services/utxo_mirror_sync_service.h"
#include "chain/checkpoints.h"
#include "chain/chain.h"
#include "chain/pow.h"
#include "models/database.h"
#include "models/block.h"
#include "storage/disk_block_io.h"
#include "event/event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdatomic.h>
#include <limits.h>
#include <sqlite3.h>

#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include "utxo_recovery_internal.h"

static struct zcl_result recovery_exec_status_ok(void)
{
    return ZCL_OK;
}

/* utxo_recovery_repair_stale_cursor_from_sync_projection (the legacy
 * node_state-anchor repair) lives in utxo_recovery_stale_cursor.c. */

struct zcl_result utxo_recovery_commit_tip(struct utxo_recovery_ctx *ctx,
                              struct block_index **tip_inout,
                              const char *reason,
                              bool persist_coins_best,
                              bool frontier_exempt)
{
    struct block_index *tip = tip_inout ? *tip_inout : NULL;
    if (!ctx || !ctx->state || !tip || !tip->phashBlock)
        return ZCL_ERR(-43,
            "utxo_recovery_commit_tip: invalid args ctx=%p state=%p tip=%p "
            "phashBlock=%p reason=%s",
            (void *)ctx, ctx ? (void *)ctx->state : NULL, (void *)tip,
            tip ? (void *)tip->phashBlock : NULL, reason ? reason : "");

    /* INVARIANT A GATE — never INSTALL a tip above what can be DERIVED
     * (log + trust-rooted index). Single choke point for restore installs;
     * a clamp lowers *tip_inout, an over-clamp floor rewinds on evidence. */
    if (!frontier_exempt) {
        int32_t frontier = -1;
        bool clamped = false;
        struct block_index *gated = utxo_recovery_clamp_tip_to_header_frontier(
            ctx, tip, reason, &frontier, &clamped);
        if (!gated)
            return ZCL_ERR(-47,
                "utxo_recovery_commit_tip: candidate h=%d not derivable from "
                "the validated header frontier h=%d (reason=%s); install "
                "refused", tip->nHeight, frontier, reason ? reason : "");
        if (clamped) {
            /* Rewind bound = the COMMITTED height, not the raw frontier. */
            int floor = utxo_recovery_finalized_served_floor(NULL, NULL);
            if (floor > gated->nHeight)
                (void)utxo_recovery_rewind_finalized_floor(gated->nHeight,
                                                           floor, reason);
            tip = gated;
            *tip_inout = gated;
        }
    }

    struct chain_state_rollback_authorization rollback_auth = {
        .source = CSR_ROLLBACK_SOURCE_UTXO_REPAIR,
        .decision = POLICY_ALLOW,
        .from_height = active_chain_height(&ctx->state->chain_active),
        .to_height = tip->nHeight,
        .max_depth = INT64_MAX,
        .evidence_class = "utxo_recovery_verified",
        .reason = reason ? reason : "utxo_recovery",
    };
    struct chain_state_commit commit = {
        .new_tip = tip,
        .new_coins_best = *tip->phashBlock,
        .expected_utxo_count = 0,
        /* A UTXO repair publishes the body/coins frontier.  It must not use
         * its rollback authorization to drag an already-better header-only
         * frontier down to the repaired body tip.  Header publication below
         * uses the ordinary forward-only CSR ratchet: it fills an empty/older
         * header slot but preserves a validated header chain ahead of coins. */
        .update_header_tip = false,
        .persist_coins_best = persist_coins_best,
        .rollback_auth = &rollback_auth,
        .wallet_scan_height = -1,
        .reason = reason ? reason : "utxo_recovery",
    };

    enum csr_result rc = csr_commit_tip(csr_instance(), &commit);
    if (rc == CSR_OK) {
        bool promoted = false;
        enum csr_result hrc = csr_promote_header_tip(
            csr_instance(), &ctx->state->chain_active,
            &ctx->state->pindex_best_header, tip,
            reason ? reason : "utxo_recovery.header_floor", &promoted);
        if (hrc != CSR_OK)
            LOG_WARN("utxo_recovery",
                     "recovered body tip h=%d but header ratchet returned %s "
                     "reason=%s",
                     tip->nHeight, csr_result_name(hrc),
                     reason ? reason : "");
        return ZCL_OK;
    }

#ifdef ZCL_TESTING
    if (rc == CSR_REJECTED_NOT_INITIALIZED) {
        if (ctx->coins_tip)
            coins_view_cache_set_best_block(ctx->coins_tip,
                                            tip->phashBlock);
        /* test-only cache write — 'coins_best_block' is a projection key
         * (authority = reducer_frontier_derive_coins_best). */
        if (persist_coins_best && ctx->ndb && ctx->ndb->open)
            (void)node_db_state_set(ctx->ndb, "coins_best_block",
                                    tip->phashBlock->data, 32);
        (void)chain_set_active_tip(ctx->state, tip, TIP_FROM_UTXO_REPAIR,
                             reason ? reason : "utxo_recovery_csr_uninit");
        ctx->state->pindex_best_header = tip;
        return ZCL_OK;
    }
#endif

    LOG_WARN("utxo_recovery", "utxo_recovery: csr rejected tip promotion (%s) reason=%s h=%d", csr_result_name(rc), reason ? reason : "", tip->nHeight);
    return ZCL_ERR(-44,
        "utxo_recovery_commit_tip: csr rejected tip promotion (%s) reason=%s "
        "h=%d", csr_result_name(rc), reason ? reason : "", tip->nHeight);
}

/* scan_fallback restore epilogue (utxo_recovery_restore.c): keep the —
 * possibly Invariant-A-clamped — commit only when coins can back it. A wired
 * AND genuinely-empty canonical store (a pre-fold instant-on node whose
 * boot-1 body prefetch left block files ahead of its validated headers) makes
 * the commit a phantasm tip with NO state behind it: the bundle-install
 * fresh-genesis gate refuses (-3, served H* != 0 on a quiescent store) and a
 * doomed Sapling rebuild fires against it. "Will activate from genesis" must
 * be TRUE — roll the commit back. An unwired coins view (NULL) keeps the
 * legacy anchor commit: emptiness is unprovable before the view exists. */
bool utxo_recovery_scan_fallback_keep_commit(struct utxo_recovery_ctx *ctx,
                                             const struct block_index *committed)
{
    printf("Attempting fast chainstate rebuild from SQLite...\n");
    if (fast_rebuild_chainstate(ctx ? ctx->coins_sqlite : NULL,
                                ctx ? ctx->coins_tip : NULL,
                                ctx ? ctx->datadir : NULL)) {
        printf("Fast rebuild complete — will activate chain.\n");
        return true;
    }
    if (!ctx || !ctx->coins_sqlite || !ctx->coins_sqlite->db) {
        printf("Fast rebuild unavailable — will activate from genesis.\n");
        return true;
    }
    printf("Fast rebuild unavailable on a wired, empty coins store — "
           "rolling the tip commit back to genesis; will activate from "
           "genesis.\n");
    struct zcl_result grc = utxo_recovery_commit_genesis(
        ctx, "scan_fallback_empty_coins_rollback");
    if (!grc.ok) {
        LOG_WARN("utxo_recovery",
                 "scan_fallback empty-coins rollback to genesis failed "
                 "(tip left at h=%d): %s",
                 committed ? committed->nHeight : -1, grc.message);
        return true; /* rollback failed — no worse than the legacy behavior */
    }
    return false;
}

struct zcl_result utxo_recovery_commit_genesis(struct utxo_recovery_ctx *ctx,
                                  const char *reason)
{
    if (!ctx || !ctx->state || !ctx->params)
        return ZCL_ERR(-45,
            "utxo_recovery_commit_genesis: invalid args ctx=%p state=%p "
            "params=%p reason=%s",
            (void *)ctx, ctx ? (void *)ctx->state : NULL,
            ctx ? (void *)ctx->params : NULL, reason ? reason : "");

    struct block_index *genesis = block_map_find(
        &ctx->state->map_block_index,
        &ctx->params->consensus.hashGenesisBlock);
    if (!genesis) {
        LOG_WARN("utxo_recovery", "utxo_recovery: cannot reset coins best to genesis; " "genesis is missing from block index (reason=%s)", reason ? reason : "");
        return ZCL_ERR(-46,
            "utxo_recovery_commit_genesis: genesis is missing from block "
            "index (reason=%s)", reason ? reason : "");
    }

    /* Not frontier-exempt; genesis <= frontier always, min() never raises. */
    struct block_index *commit_blk = genesis;
    ZCL_CHECK(utxo_recovery_commit_tip(ctx, &commit_blk,
                                  reason ? reason : "utxo_recovery_genesis",
                                  true, false));
    return ZCL_OK;
}

struct utxo_count_check_result utxo_recovery_classify_count_check(
    int tip_height,
    int checkpoint_height,
    uint64_t checkpoint_count,
    uint64_t actual_count)
{
    struct utxo_count_check_result res = {0};
    res.blocks_past_checkpoint = tip_height - checkpoint_height;

    if (checkpoint_height <= 0 || checkpoint_count == 0 ||
        tip_height < checkpoint_height) {
        res.level = UTXO_COUNT_CHECK_OK;
        return res;
    }

    int64_t delta = (int64_t)actual_count - (int64_t)checkpoint_count;
    if (delta < 0)
        delta = -delta;
    res.pct_delta = (double)delta / (double)checkpoint_count * 100.0;

    if (res.blocks_past_checkpoint > UTXO_CHECKPOINT_NEAR_WINDOW) {
        res.level = UTXO_COUNT_CHECK_INFO_STALE_REFERENCE;
        return res;
    }

    if (res.pct_delta > 50.0)
        res.level = UTXO_COUNT_CHECK_CRITICAL;
    else if (res.pct_delta > 10.0)
        res.level = UTXO_COUNT_CHECK_WARNING;
    else
        res.level = UTXO_COUNT_CHECK_OK;
    return res;
}

/* See header doc. Shrink/equal-count = corruption candidate; growth =
 * stale (frozen-tracking import advanced the set). The hourly commitment
 * audit (invariant_sentinel) is its live consumer. */
bool utxo_recovery_xor_mismatch_is_corruption_candidate(
    uint64_t saved_count, uint64_t computed_count)
{
    return computed_count <= saved_count;
}

/* ── Policy-gated UTXO wipe ──────────────────────────────────────
 *
 * Every destructive UTXO wipe must go through this function.
 * It counts the rows first, asks recovery_policy for permission with
 * a grep-able reason string, and refuses loudly if the proposed wipe
 * is larger than ZCL_MAX_UTXO_WIPE_ROWS (default 1000).
 *
 * This is the gate that exists to prevent a mass UTXO wipe.
 * Do not bypass. */
struct zcl_result utxo_recovery_wipe(struct node_db *ndb, const char *reason)
{
    int64_t proposed = node_db_utxo_count(ndb);

    struct recovery_policy pol;
    policy_load_from_env(&pol);

    enum policy_decision d = policy_check_utxo_wipe(&pol, proposed, reason);
    if (d != POLICY_ALLOW) {
        LOG_INFO("utxo_recovery", "utxo_recovery: REFUSING wipe at \"%s\" — would drop %lld rows, " "policy=%s (override with ZCL_MAX_UTXO_WIPE_ROWS=%lld)", reason, (long long)proposed, policy_decision_name(d), (long long)(proposed + 1));
        return ZCL_ERR(-41,
            "utxo_recovery_wipe: policy denied wipe at \"%s\" — would drop "
            "%lld rows, policy=%s (override with ZCL_MAX_UTXO_WIPE_ROWS=%lld)",
            reason, (long long)proposed, policy_decision_name(d),
            (long long)(proposed + 1));
    }
    event_emitf(EV_RECOVERY_ACTION, 0,
        "action=utxo_wipe reason=%s rows=%lld", reason, (long long)proposed);
    if (!node_db_wipe_utxos(ndb))
        return ZCL_ERR(-42,
            "utxo_recovery_wipe: node_db_wipe_utxos failed at \"%s\" "
            "(rows=%lld)", reason, (long long)proposed);
    /* The coins are gone — the cold-import seed anchor (a height/hash/count
     * triple that asserts coins are present through H) must not survive them,
     * or a later partial reimport could read a stale key and trust-stamp a
     * finalized frontier above the real coin frontier. */
    utxo_recovery_clear_cold_import_seed(ndb);
    return ZCL_OK;
}

/* ── Auto-reimport flag ──────────────────────────────────────── */
/* The read-side needs-reimport sentinel lives in engine/modules/storage as
 * `utxo_reimport_flag_check_and_clear`. This service owns only the
 * node_db state transition needed before reimport starts. */

struct zcl_result utxo_recovery_prepare_reimport(struct node_db *ndb)
{
    printf("Forced UTXO re-import requested.\n");
    /* Only clear the migration flag — the wipe happens inside
     * utxo_recovery_import_ldb (the "boot.ldb_import_prepare" wipe in
     * utxo_recovery_restore.c).  Wiping here AND in import_ldb would be a
     * redundant double-wipe that can destroy freshly imported UTXOs. */
    if (!node_db_exec(ndb,
            "DELETE FROM node_state WHERE key='leveldb_utxo_migrated'"))
        return ZCL_ERR(-50, "prepare_reimport: failed to clear "
                       "leveldb_utxo_migrated flag");
    /* A reimport is about to replace the coins — drop the durable seed anchor
     * for the OLD import so an interrupted reimport (migrated cleared, coins
     * partially wiped) cannot leave the consumer reading a stale key. */
    utxo_recovery_clear_cold_import_seed(ndb);
    return ZCL_OK;
}

/* ── LDB→SQLite UTXO import + chain tip restoration ─────────────
 * utxo_recovery_restore.c owns the heavy boot recovery routines:
 * utxo_recovery_import_ldb and utxo_recovery_restore_chain_tip. They share the
 * CSR-gated commit primitives above via utxo_recovery_internal.h. */

/* ── Validation recovery execution ──────────────────────────── */

/* Helper: recover from stale metadata by fixing coins_best_block
 * from UTXO set heights instead of wiping. On canonical datadirs the
 * derived coins-best supersedes this guess; the coins_kv-first reads
 * below keep the abort-wipe check honest either way. */
static bool recover_stale_metadata(struct utxo_recovery_ctx *ctx)
{
    /* Count the CANONICAL store first (coins_kv); the node.db mirror
     * count is the legacy fallback. A populated coins_kv must abort the
     * wipe exactly like a populated mirror. */
    int64_t actual_utxos = coins_kv_count(progress_store_db());
    if (actual_utxos <= 0)
        actual_utxos = node_db_utxo_count(ctx->ndb);
    if (actual_utxos <= 1000)
        return false;

    LOG_WARN("chain", "ABORT WIPE: validation says 'empty' but the coin "
             "stores have %lld rows. coins_best_block may be "
             "stale, NOT the UTXOs. Refusing to destroy data.",
             (long long)actual_utxos);

    int max_h = 0;
    /* Replacement tip height = the DERIVED coins-best when
     * coins_applied_height is present; mirror MAX(height) is the legacy
     * fallback. */
    {
        int32_t d_h = -1;
        if (reducer_frontier_derive_coins_best_now(&d_h, NULL, NULL) &&
            d_h > 0)
            max_h = d_h;
    }
    if (max_h <= 0) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(ctx->ndb->db,
                "SELECT MAX(height) FROM utxos",
                -1, &st, NULL) == SQLITE_OK) {
            if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW)
                max_h = sqlite3_column_int(st, 0);
            sqlite3_finalize(st);
        }
    }
    if (max_h > 0) {
        struct db_block tip_blk;
        if (db_block_find_by_height(ctx->ndb, max_h, &tip_blk)) {
            struct uint256 tip_hash;
            memcpy(tip_hash.data, tip_blk.hash, 32);
            struct block_index *bi = block_map_find(
                &ctx->state->map_block_index, &tip_hash);
            if (bi && chain_restore_block_is_consensus_backed_on_disk(
                    bi, ctx->datadir)) {
                if (utxo_recovery_commit_tip(
                        ctx, &bi, "best_have_data", true, false).ok) {
                    printf("RECOVERY: restored chain tip from UTXO set: h=%d\n",
                           bi->nHeight);
                }
            } else if (bi) {
                LOG_INFO("chain", "RECOVERY: UTXO-derived tip h=%d is not disk-backed; " "not setting active tip", max_h);
            }
        }
    }
    return true;
}

/* L1 torn-legacy-coins boot recovery
 * (utxo_recovery_heal_torn_legacy_coins_anchor) lives in its own seam file
 * utxo_recovery_torn_anchor.c to keep this file under the size ceiling. */

/* Helper: wipe UTXOs and reset to genesis for clean re-sync */
static bool reset_to_genesis(struct utxo_recovery_ctx *ctx)
{
    struct zcl_result wipe = utxo_recovery_wipe(ctx->ndb,
                                                "boot.reset_to_genesis");
    if (!wipe.ok) {
        LOG_WARN("utxo_recovery", "%s", wipe.message);
        return false;
    }

    struct block_index *genesis = block_map_find(
        &ctx->state->map_block_index,
        &ctx->params->consensus.hashGenesisBlock);
    if (genesis) {
        struct block_index *commit_blk = genesis;
        if (!utxo_recovery_commit_tip(ctx, &commit_blk, "fresh_genesis",
                                      true, false).ok)
            return false;
    } else {
        LOG_WARN("utxo_recovery",
                 "reset_to_genesis: genesis missing from block index");
        return false;
    }

    /* Clear migration flag for LevelDB re-import on next boot */
    node_db_exec(ctx->ndb,
        "DELETE FROM node_state WHERE key='leveldb_utxo_migrated'");

    extern _Atomic bool g_utxo_commitment_skip;
    atomic_store(&g_utxo_commitment_skip, true);

    set_flush_policy(3600, 1000000, 500);
    return true;
}

/* Helper: boot-time integrity checks when BOOT_OK */
static bool integrity_checks_boot_ok(struct utxo_recovery_ctx *ctx,
                                      bool *out_skip_activate)
{
    int tip_h = active_chain_height(&ctx->state->chain_active);

    /* A: Stale UTXO wipe — chain at genesis but UTXO set non-empty.
     * SKIPPED on canonical datadirs (coins_applied_height present).
     * There, the coins live in coins_kv and a genesis tip means the TIP
     * restore is incomplete — not that the coins are stale; wiping the
     * mirror would destroy a rebuildable projection while leaving the
     * canonical set intact. Legacy datadirs keep the rung unchanged. */
    if (tip_h <= 0 && ctx->ndb->open) {
        int32_t d_h = -1;
        bool canonical = reducer_frontier_derive_coins_best_now(&d_h,
                                                                NULL, NULL);
        int64_t stale_utxos = 0;
        if (!canonical) {
            sqlite3_stmt *stale_cnt = NULL;
            if (sqlite3_prepare_v2(ctx->ndb->db,
                    "SELECT COUNT(*) FROM utxos", -1,
                    &stale_cnt, NULL) == SQLITE_OK && stale_cnt) {
                if (AR_STEP_ROW_READONLY(stale_cnt) == SQLITE_ROW)
                    stale_utxos = sqlite3_column_int64(stale_cnt, 0);
                sqlite3_finalize(stale_cnt);
            }
        }
        if (stale_utxos > 0) {
            printf("WARNING: Chain at genesis but %lld stale UTXOs "
                   "from previous snapshot — wiping for clean sync\n",
                   (long long)stale_utxos);
            struct zcl_result wipe = utxo_recovery_wipe(
                ctx->ndb, "boot.stale_utxos_at_genesis");
            if (!wipe.ok)
                LOG_WARN("utxo_recovery", "%s", wipe.message);
            (void)utxo_recovery_commit_genesis(
                ctx, "boot.stale_utxos_at_genesis");
            *out_skip_activate = true;
        }
    }

    /* B: UTXO count sanity check against SHA3 checkpoint */
    const struct sha3_utxo_checkpoint *sha3cp = get_sha3_utxo_checkpoint();
    if (sha3cp && sha3cp->height > 0 &&
        tip_h >= sha3cp->height && ctx->ndb->open) {
        sqlite3_stmt *cnt_stmt = NULL;
        sqlite3_prepare_v2(ctx->ndb->db,
            "SELECT COUNT(*) FROM utxos", -1, &cnt_stmt, NULL);
        if (cnt_stmt && AR_STEP_ROW_READONLY(cnt_stmt) == SQLITE_ROW) {
            int64_t actual = sqlite3_column_int64(cnt_stmt, 0);
            struct utxo_count_check_result count_check =
                utxo_recovery_classify_count_check(
                    tip_h, sha3cp->height, sha3cp->utxo_count,
                    (uint64_t)actual);
            if (count_check.level == UTXO_COUNT_CHECK_CRITICAL)
                LOG_WARN("chain", "UTXO count %lld vs " "checkpoint %lld (%.1f%% off) — consider " "reimport", (long long)actual, (long long)sha3cp->utxo_count, count_check.pct_delta);
            else if (count_check.level == UTXO_COUNT_CHECK_WARNING)
                printf("WARNING: UTXO count %lld vs checkpoint %lld "
                       "(%.1f%% off, chain %d blocks past checkpoint)\n",
                       (long long)actual,
                       (long long)sha3cp->utxo_count,
                       count_check.pct_delta,
                       count_check.blocks_past_checkpoint);
            else if (count_check.level ==
                     UTXO_COUNT_CHECK_INFO_STALE_REFERENCE)
                printf("INFO: skipping UTXO count checkpoint warning: "
                       "checkpoint h=%d is %d blocks behind tip h=%d "
                       "(actual=%lld checkpoint=%lld delta=%.1f%%)\n",
                       sha3cp->height,
                       count_check.blocks_past_checkpoint,
                       tip_h,
                       (long long)actual,
                       (long long)sha3cp->utxo_count,
                       count_check.pct_delta);
        }
        sqlite3_finalize(cnt_stmt);
    }

    /* C: XOR commitment verification — height-tracking aware. See
     * utxo_commitment_boot_check_and_refresh: a no-op (no O(n) `utxos` scan)
     * whenever the checkpoint's UTXO_COMMITMENT_HEIGHT_KEY stamp matches the
     * mirror's own cursor, which is the case on a cleanly-shut-down node now
     * that utxo_mirror_delta_apply maintains the stamp live at every mirror
     * commit. The O(n) recompute-and-refresh below is the fallback for a
     * genuinely-stale checkpoint (never tracked, or a torn shutdown). */
    if (ctx->ndb->open) {
        int64_t mirror_h64 = -1;
        int32_t mirror_h = (node_db_state_get_int(ctx->ndb,
                UTXO_MIRROR_SYNC_CURSOR_KEY, &mirror_h64) &&
                mirror_h64 >= 0 && mirror_h64 <= INT32_MAX)
            ? (int32_t)mirror_h64 : -1;
        struct utxo_commitment computed_uc;
        memset(&computed_uc, 0, sizeof(computed_uc));
        bool refreshed = false;
        if (utxo_commitment_boot_check_and_refresh(ctx->ndb->db, mirror_h,
                                                    &computed_uc, &refreshed)) {
            if (refreshed) {
                if (ctx->coins_tip)
                    ctx->coins_tip->commitment = computed_uc;
                printf("INFO: refreshed stale XOR commitment "
                       "checkpoint (count=%llu)\n",
                       (unsigned long long)computed_uc.count);
            }
        } else {
            LOG_WARN("chain", "failed to refresh stale XOR commitment checkpoint");
        }
    }

    return true;
}

struct recovery_exec_result utxo_recovery_execute(
    struct utxo_recovery_ctx *ctx,
    struct boot_validation_result *vr)
{
    struct recovery_exec_result res = {
        .status = recovery_exec_status_ok(),
    };

    if (!ctx || !vr || !ctx->state || !ctx->ndb ||
        !ctx->activation_ctl) {
        res.status = ZCL_ERR(-30,
            "utxo_recovery_execute: invalid ctx=%p vr=%p state=%p "
            "ndb=%p activation_ctl=%p",
            (void *)ctx, (void *)vr,
            ctx ? (void *)ctx->state : NULL,
            ctx ? (void *)ctx->ndb : NULL,
            ctx ? (void *)ctx->activation_ctl : NULL);
        LOG_WARN("utxo_recovery", "%s", res.status.message);
        return res;
    }

    /* Check activation controller — skip when ANCHOR_ACTIVE */
    struct utxo_wipe_decision wd;
    activation_should_allow_utxo_wipe(&wd,
        activation_get_state(ctx->activation_ctl),
        snapsync_get_anchor() != NULL);
    if (!wd.safe_to_wipe) {
        printf("Skipping coins/chain validation — %s\n", wd.reason);
        return res;
    }

    switch (vr->action) {
    case BOOT_RECOVER_REIMPORT:
    case BOOT_RECOVER_WIPE_WAIT:
        printf("WARNING: Chain tip at h=%d but coins DB %s!\n",
               vr->chain_height,
               vr->action == BOOT_RECOVER_REIMPORT
                   ? "empty (LevelDB available)" : "empty");

        /* SAFETY: check actual UTXO count before wiping */
        if (recover_stale_metadata(ctx)) {
            /* Refused the wipe: the coin stores are populated, only the
             * cursor was stale. A recovery ACTION was taken (the tip was
             * corrected) but NO bulk reload follows, so bulk_reload_pending
             * stays false — see struct recovery_exec_result. */
            res.recovered = true;
            break;
        }

        if (!ctx->params) {
            res.status = ZCL_ERR(-31,
                "utxo_recovery_execute: %s requires chain params",
                vr->action == BOOT_RECOVER_REIMPORT
                    ? "reimport" : "wipe_wait");
            LOG_WARN("utxo_recovery", "%s", res.status.message);
            break;
        }

        if (!reset_to_genesis(ctx)) {
            res.status = ZCL_ERR(-32,
                "utxo_recovery_execute: reset_to_genesis failed for "
                "action=%s chain_height=%d coins_height=%d",
                vr->action == BOOT_RECOVER_REIMPORT
                    ? "reimport" : "wipe_wait",
                vr->chain_height, vr->coins_height);
            LOG_WARN("utxo_recovery", "%s", res.status.message);
            break;
        }
        /* Wiped to genesis: the entire projection set is re-populated by the
         * re-sync that follows, so the caller may legitimately drop the
         * secondary indexes now and rebuild them once at the end. */
        res.recovered = true;
        res.bulk_reload_pending = true;
        break;

    case BOOT_RECOVER_RESET_CHAIN: {
        struct block_index *coins_block = block_map_find(
            &ctx->state->map_block_index, &vr->coins_hash);

        /* A genesis-phase RESET_CHAIN is a RESTORE (raise the chain to
         * the coins), never a rollback: when the CSR already holds a
         * HIGHER restored tip (the derived coins-best installed moments
         * earlier), committing the stale legacy view's lower height
         * bulldozes it — a deterministic every-boot pull-down (csr_commit
         * from a higher restored tip down to the stale legacy floor).
         * Refuse the downward commit loudly and let the higher tip stand;
         * the legacy projection reconciles forward. */
        if (coins_block) {
            struct chain_state_view csv;
            csr_snapshot(csr_instance(), &csv);
            if (csv.tip_height > coins_block->nHeight) {
                LOG_WARN("utxo_recovery",
                         "chain_coins_mismatch_reset REFUSED: csr already "
                         "holds h=%d above the legacy coins view h=%d — a "
                         "genesis-phase reset is raise-only; keeping the "
                         "restored tip",
                         csv.tip_height, coins_block->nHeight);
                event_emitf(EV_RECOVERY_ACTION, 0,
                            "action=mismatch_reset_refused csr_h=%d "
                            "legacy_h=%d", csv.tip_height,
                            coins_block->nHeight);
                res.recovered = true;
                break;
            }
        }

        if (coins_block) {
            if (chain_restore_block_is_consensus_backed_on_disk(
                    coins_block, ctx->datadir)) {
                printf("Chain tip/coins mismatch: chain=%d coins=%d\n"
                       "  Resetting chain to disk-backed coins tip — "
                       "will replay %d blocks.\n",
                       vr->chain_height, vr->coins_height,
                       vr->chain_height - vr->coins_height);
                if (!utxo_recovery_commit_tip(
                        ctx, &coins_block,
                        "chain_coins_mismatch_reset", true, false).ok) {
                    res.status = ZCL_ERR(-33,
                        "utxo_recovery_execute: failed to reset chain "
                        "to coins tip h=%d", vr->coins_height);
                    LOG_WARN("utxo_recovery", "%s", res.status.message);
                    break;
                }
            } else {
                LOG_WARN("chain", "Chain tip/coins mismatch: coins tip h=%d is not " "disk-backed; refusing active-tip reset", vr->coins_height);
                res.status = ZCL_ERR(-34,
                    "utxo_recovery_execute: coins tip h=%d is not "
                    "disk-backed", vr->coins_height);
                LOG_WARN("utxo_recovery", "%s", res.status.message);
                break;
            }
        } else {
            res.status = ZCL_ERR(-35,
                "utxo_recovery_execute: coins tip h=%d is missing from "
                "block index", vr->coins_height);
            LOG_WARN("utxo_recovery", "%s", res.status.message);
            break;
        }
        res.recovered = true;
        break;
    }
    case BOOT_RECOVER_RESET_COINS_TO_CHAIN_TIP: {
        struct block_index *chain_tip =
            active_chain_tip(&ctx->state->chain_active);
        if (chain_tip) {
            if (!utxo_recovery_commit_tip(
                    ctx, &chain_tip, "coins_cursor_to_chain_tip",
                    true, false).ok) {
                res.status = ZCL_ERR(-36,
                    "utxo_recovery_execute: failed to reset coins cursor "
                    "to active chain tip h=%d", chain_tip->nHeight);
                LOG_WARN("utxo_recovery", "%s", res.status.message);
                break;
            }
            res.recovered = true;
        } else {
            res.status = ZCL_ERR(-37,
                "utxo_recovery_execute: cannot reset coins cursor because "
                "active chain tip is missing");
            LOG_WARN("utxo_recovery", "%s", res.status.message);
        }
        break;
    }
    case BOOT_RECOVER_RESET_COINS_TO_GENESIS:
        if (!ctx->params) {
            res.status = ZCL_ERR(-38,
                "utxo_recovery_execute: reset coins to genesis requires "
                "chain params");
            LOG_WARN("utxo_recovery", "%s", res.status.message);
        } else if (utxo_recovery_commit_genesis(ctx,
                                                "coins_cursor_to_genesis").ok) {
            res.recovered = true;
        } else {
            res.status = ZCL_ERR(-39,
                "utxo_recovery_execute: failed to reset coins cursor "
                "to genesis");
            LOG_WARN("utxo_recovery", "%s", res.status.message);
        }
        break;
    case BOOT_OK:
        if (!integrity_checks_boot_ok(ctx, &res.skip_activate)) {
            res.status = ZCL_ERR(-40,
                "utxo_recovery_execute: BOOT_OK integrity checks failed");
            LOG_WARN("utxo_recovery", "%s", res.status.message);
        }
        break;
    }

    return res;
}
