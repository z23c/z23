/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reindex_epilogue — see services/reindex_epilogue.h. Composition only: every
 * step reuses an existing primitive (coins_kv reset+reseed, the SHA3 commitment
 * recompute+stamp, the trusted-seed cursor clamp via tip_finalize_stage_seed_
 * anchor, and the L0 H* self-check). No new mechanism, no new repair module —
 * a write-time epilogue at the existing reindex chokepoint that DERIVES every
 * durable post-reindex value from the just-replayed authoritative UTXO set.
 *
 * This file returns bare bool (a fail-loud derivation that wraps the seed/anchor
 * convention, like seed_integrity_gate.c) rather than struct zcl_result. */
// one-result-type-ok:fail-loud-derivation

#include "services/reindex_epilogue.h"

#include "coins/utxo_commitment.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "models/database.h"
#include "services/seed_integrity_gate.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

/* The reducer stage log schemas compute_hstar reads. reindex runs BEFORE the
 * reducer stages init (engine/composition/src/boot_services.c), so on a datadir whose
 * upstream stage logs were never created the H* self-check below would hit a
 * "no such table" and spuriously fail. Ensure them idempotently from the
 * production schema functions (single source — never a duplicated CREATE
 * TABLE). tip_finalize_log + utxo_apply_log are already created by the seed
 * anchor; these are the four remaining logs in reducer_frontier.c's k_logs[].
 * Forward-declared (the schema functions live in the jobs build's private
 * per-stage log_store headers, not on the public include path). */
bool validate_headers_log_ensure_schema(struct sqlite3 *db);
bool script_validate_log_ensure_schema(struct sqlite3 *db);
bool body_persist_log_ensure_schema(struct sqlite3 *db);
bool proof_validate_log_ensure_schema(struct sqlite3 *db);

/* PAGE: leave the reindex sentinel pending (returning false does that) AND
 * raise the loud "auto-recovery left durable state torn, a human looks" signal
 * so the never-give-up auto-reindex loop is bounded+observable, never a silent
 * infinite re-replay. Typed reason travels with the event. */
static void reindex_epi_page(int tip_h, const char *reason)
{
    event_emitf(EV_OPERATOR_NEEDED, 0,
                "check=reindex_epilogue tip_h=%d reason=%s", tip_h, reason);
}

static bool derive_authority_from_node_db_utxos(struct node_db *ndb,
                                                const char *node_db_path,
                                                int tip_h,
                                                const uint8_t tip_hash[32],
                                                const char *source)
{
    if (!ndb || !ndb->open || !ndb->db || !node_db_path ||
        !node_db_path[0] || tip_h < 0 || !tip_hash) {
        reindex_epi_page(-1, "null_or_closed_arg");
        LOG_RETURN(false, "reindex_epi",
                   "NULL/closed authority args ndb=%p path=%p h=%d hash=%p",
                   (void *)ndb, (const void *)node_db_path, tip_h,
                   (const void *)tip_hash);
    }
    if (!source || !source[0])
        source = "unknown";

    sqlite3 *pdb = progress_store_db();
    if (!pdb) {
        reindex_epi_page(tip_h, "progress_store_not_open");
        LOG_RETURN(false, "reindex_epi", "progress store not open");
    }

    /* ── (1) Reset + reseed coins_kv from the freshly-replayed node.db `utxos`
     * mirror. connect_block just wrote every coin into that mirror, so it is
     * THE authority; coins_kv (the store the derived authority reads) must be
     * a fresh copy of it. coins_kv_seed_from_node_db short-circuits when the
     * migration stamp is set, so reset_for_reseed truncates + unstamps FIRST —
     * otherwise the reseed would no-op over a pre-reindex set that may carry
     * rows the replay legitimately deleted. Snapshot import uses the same
     * derivation body after atomically copying the verified snapshot into
     * node.db.utxos. */
    if (!coins_kv_reset_for_reseed(pdb)) {
        reindex_epi_page(tip_h, "coins_kv_reset_failed");
        LOG_RETURN(false, "reindex_epi", "coins_kv reset for reseed failed");
    }
    if (!coins_kv_seed_from_node_db(pdb, node_db_path)) {
        reindex_epi_page(tip_h, "coins_kv_reseed_failed");
        LOG_RETURN(false, "reindex_epi",
                   "coins_kv reseed from node.db failed path=%s",
                   node_db_path);
    }

    /* ── (2) Recompute the SHA3 commitment over the replayed `utxos` mirror and
     * stamp it (utxo_sha3) + the coins_best_block cache. The caller already
     * cleared g_utxo_commitment_skip; we RECOMPUTE from scratch (the authority
     * the seed gate + self-heal verify), never trust the deleted-then-untouched
     * stamp. seed_integrity_stamp_utxo_sha3 wraps utxo_commitment_sha3_save and
     * ARMS the trusted-seed commitment gate that step (3) then runs — stamping
     * the very digest we recomputed makes that gate VALIDATE, never false-
     * refuse. boot_index_clear_coins_state also deleted the XOR
     * `utxo_commitment` checkpoint key; recompute + stamp it too so NO stale
     * key survives the epilogue. */
    uint8_t root[32];
    uint64_t count = 0;
    utxo_commitment_sha3_compute(ndb->db, root, &count);   /* over `utxos` */
    if (!seed_integrity_stamp_utxo_sha3(ndb, tip_h, root, count)) {
        reindex_epi_page(tip_h, "utxo_sha3_stamp_failed");
        LOG_RETURN(false, "reindex_epi", "utxo_sha3 stamp failed h=%d", tip_h);
    }
    (void)utxo_commitment_resync_from_db(ndb->db, NULL);  /* over `utxos`; logs */
    /* coins_best_block cache := the replayed tip hash (a CACHE of the
     * derivation; the authority is coins_applied_height set in step 3). */
    if (!node_db_state_set(ndb, "coins_best_block", tip_hash, 32))
        LOG_WARN("reindex_epi", "coins_best_block cache write failed (non-fatal)");

    /* ── (3) Clamp the cursors to the replayed tip via the load-bearing
     * trusted-seed convention. coins_applied_height MUST be raised to tip_h+1
     * BEFORE the seed anchor: reducer_anchor_candidate_ok(tip_h) normalizes the
     * served-tip cursor to the tip_h+1 frame and requires every upstream cursor
     * AND coins_applied >= tip_h+1 (reducer_frontier.c). Set it too LOW and the
     * trusted anchor collapses back to the compiled checkpoint, H* never climbs
     * to the replayed tip, the step-(4) self-check fails, the sentinel stays
     * pending, and the never-give-up unit re-replays forever — the exact wedge
     * this item kills, now caused by the fix. Same ordering the cold-import seed
     * proved. coins_kv_seed_from_node_db just re-stamped the migration key, so
     * the applied-height row was cleared by the reset above and is now ABSENT;
     * set it directly to tip_h+1. */
    {
        progress_store_tx_lock();
        int32_t cur = 0;
        bool found = false;
        bool ck_ok = coins_kv_get_applied_height(pdb, &cur, &found);
        bool need_raise = ck_ok && (!found || cur < tip_h + 1);
        bool set_ok = true;
        if (need_raise) {
            char *err = NULL;
            if (sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK)
                set_ok = false;
            if (set_ok && !utxo_apply_frontier_set_in_tx(pdb, tip_h + 1))
                set_ok = false;
            if (set_ok && sqlite3_exec(pdb, "COMMIT", NULL, NULL, &err) != SQLITE_OK)
                set_ok = false;
            if (!set_ok)
                sqlite3_exec(pdb, "ROLLBACK", NULL, NULL, NULL);
            if (err) sqlite3_free(err);
        }
        progress_store_tx_unlock();
        if (!ck_ok || !set_ok) {
            reindex_epi_page(tip_h, "coins_applied_clamp_failed");
            LOG_RETURN(false, "reindex_epi",
                       "coins_applied_height clamp to %d failed", tip_h + 1);
        }
    }

    /* trusted_seed=true: reindex is a from-genesis full replay through the
     * consensus connect_block path — the strongest trust root there is. The
     * seed anchor (tip_finalize_anchor.c) sets the tip_finalize cursor to the
     * served tip's OWN height tip_h (#31, NEVER tip_h+1), the 8 upstream
     * cursors to tip_h+1, the durable trusted-base declaration, and the
     * utxo_apply anchor row at tip_h — all of which step (4) then verifies. */
    if (!tip_finalize_stage_seed_anchor(tip_h, tip_hash, true)) {
        reindex_epi_page(tip_h, "seed_anchor_failed");
        LOG_RETURN(false, "reindex_epi",
                   "tip_finalize seed_anchor failed h=%d", tip_h);
    }

    /* Ensure the reducer log schemas the self-check reads exist (idempotent;
     * reindex runs before the stages init, so a never-stage-run datadir would
     * otherwise hit "no such table" and spuriously fail the check below). */
    {
        progress_store_tx_lock();
        bool sch_ok = validate_headers_log_ensure_schema(pdb)
                      && script_validate_log_ensure_schema(pdb)
                      && body_persist_log_ensure_schema(pdb)
                      && proof_validate_log_ensure_schema(pdb);
        progress_store_tx_unlock();
        if (!sch_ok) {
            reindex_epi_page(tip_h, "reducer_log_schema_ensure_failed");
            LOG_RETURN(false, "reindex_epi",
                       "reducer log schema ensure failed h=%d", tip_h);
        }
    }

    /* ── (4) Self-check: H* must have climbed to the replayed tip. If not, the
     * derivation silently did nothing coherent — fail (page + sentinel pending,
     * next boot retries) rather than serve half-derived state. The epilogue
     * stamps coins_applied_height=tip+1 and a trusted base at tip, so this is
     * exact even for a short/regtest chain below the compiled checkpoint. A
     * checkpoint is a floor only when this datadir's coin authority covers it;
     * it must never manufacture H* above the replayed state. */
    int32_t hstar = 0, served = 0;
    progress_store_tx_lock();
    bool hs_ok = reducer_frontier_compute_hstar(pdb, &hstar, &served);
    progress_store_tx_unlock();
    int32_t expect_hstar = tip_h;
    if (!hs_ok || hstar != expect_hstar) {
        reindex_epi_page(tip_h, "hstar_below_tip");
        LOG_RETURN(false, "reindex_epi",
                   "post-epilogue H*=%d != expected=%d (replayed tip=%d "
                   "anchor=%d) — incomplete",
                   hstar, expect_hstar, tip_h,
                   (int)REDUCER_FRONTIER_TRUSTED_ANCHOR);
    }

    /* Only the full reindex caller folded genesis..tip through the bounded
     * shielded replay writer. Keep snapshot-import state incomplete. For a
     * reindex, all three marker-zero writes plus replay-session retirement are
     * ONE final transaction after every other epilogue check succeeded. */
    if (strcmp(source, "reindex") == 0 &&
        !shielded_history_publish_full_replay_complete(pdb, tip_h)) {
        reindex_epi_page(tip_h, "shielded_completion_publish_failed");
        LOG_RETURN(false, "reindex_epi",
                   "shielded completion publish failed h=%d", tip_h);
    }

    LOG_INFO("reindex_epi",
             "UTXO authority epilogue derived: source=%s tip=%d "
             "coins_applied=%d utxo_count=%llu H*=%d (cursors clamped, "
             "commitment recomputed)",
             source, tip_h, tip_h + 1, (unsigned long long)count, hstar);
    event_emitf(EV_SYNC_STATE_CHANGE, 0,
                "utxo_authority_epilogue source=%s tip=%d count=%llu",
                source, tip_h, (unsigned long long)count);
    return true;
}

bool reindex_epilogue_derive(struct main_state *ms, struct node_db *ndb,
                             const char *datadir)
{
    if (!ms || !ndb || !ndb->open || !ndb->db || !datadir) {
        reindex_epi_page(-1, "null_or_closed_arg");
        LOG_RETURN(false, "reindex_epi", "NULL/closed arg ms=%p ndb=%p dd=%p",
                   (void *)ms, (void *)ndb, (const void *)datadir);
    }

    struct block_index *tip = active_chain_tip(&ms->chain_active);
    int tip_h = active_chain_height(&ms->chain_active);
    if (!tip || !tip->phashBlock || tip_h < 0) {
        reindex_epi_page(tip_h, "no_active_tip_after_replay");
        LOG_RETURN(false, "reindex_epi", "no active tip after replay (h=%d)",
                   tip_h);
    }

    char ndb_path[600];
    int n = snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", datadir);
    if (n < 0 || n >= (int)sizeof(ndb_path)) {
        reindex_epi_page(tip_h, "node_db_path_overflow");
        LOG_RETURN(false, "reindex_epi", "node.db path overflow (dd=%s)",
                   datadir);
    }

    return derive_authority_from_node_db_utxos(ndb, ndb_path, tip_h,
                                               tip->phashBlock->data,
                                               "reindex");
}

bool reindex_epilogue_derive_imported_snapshot(struct node_db *ndb,
                                               const char *node_db_path,
                                               int height,
                                               const uint8_t hash[32])
{
    return derive_authority_from_node_db_utxos(ndb, node_db_path, height, hash,
                                               "snapshot_import");
}
