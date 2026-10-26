/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_boot_refold_window_extend: regression proof for the boot loader in
 * engine/composition/src/boot_refold_staged.c
 * (boot_load_snapshot_at_own_height_reset).
 *
 * The -load-snapshot-at-own-height loader looks its seed height up in the
 * active-chain WINDOW (active_chain_at), which is pinned to coins-best. When
 * seed_h is ABOVE coins-best the lookup returns NULL. When
 * pindex_best_header->nHeight >= seed_h the loader widens the window forward
 * with active_chain_extend_window (walks pprev to fill chain[]; never
 * publishes finalized authority) and re-reads. A real pprev gap leaves the
 * slot NULL and the downstream FATAL still fires (fails closed).
 *
 * This isolates the primitive seam (active_chain_extend_window +
 * active_chain_at) with in-memory block_index fixtures, no datadir or
 * snapshot, and needs no fork:
 *
 *   (A) RECOVERY: seed_h above the coins-best window but reachable by walking
 *       pprev from pindex_best_header is INVISIBLE before the extend and
 *       VISIBLE (the correct, hash-matching block_index) after it.
 *
 *   (B) FAILS CLOSED: with a genuine pprev gap between the coins-best window
 *       and the header tip, the slot at seed_h stays NULL after the extend.
 */

#include "test/test_core.h"

#include "config/boot.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "services/block_index_loader.h"    /* block_index_loader_torn_import_detect */
#include "jobs/refold_progress.h"           /* refold_from_anchor_active/refresh */
#include "models/database.h"                /* struct node_db, node_db_open/close */
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "chain/checkpoints.h"              /* checkpoints_*_sha3_override_for_test */
#include "core/uint256.h"

#include <stdio.h>
#include <string.h>

/* Non-static exported helper, forward-declared rather than pulling its
 * src-private header (engine/jobs/src/script_validate_log_store.h) onto this
 * TU's include path. The torn detector reads the coin_backfill.refused
 * marker keyed (height, hash) from repair_marker. */
bool script_validate_log_ensure_schema(struct sqlite3 *db);

#define BRWE_CHECK(name, expr) do {                       \
    printf("  boot_refold_window_extend: %s... ", (name)); \
    if (expr) printf("OK\n");                              \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

/* Deterministic per-height block hash (distinct, non-null). The high byte is a
 * fixed tag so two different heights never collide and no hash is all-zero
 * (chainstate_insert_block_index rejects a null hash). */
static void brwe_hash_for(int h, struct uint256 *out)
{
    memset(out->data, 0, 32);
    out->data[0] = (uint8_t)(h & 0xFF);
    out->data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->data[2] = (uint8_t)((h >> 16) & 0xFF);
    out->data[31] = 0x77;  /* non-null tag */
}

/* Insert a block_index at height h into ms's block map, linked to `prev` via
 * pprev (NULL for the base). Returns the node (NULL only on insert failure).
 * pprev linkage is load-bearing: active_chain_extend_window -> fill_window
 * assembles chain[] by walking pprev down from the candidate. */
static struct block_index *brwe_insert(struct main_state *ms, int h,
                                       struct block_index *prev)
{
    struct uint256 bh;
    brwe_hash_for(h, &bh);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &bh);
    if (!bi)
        return NULL;
    bi->nHeight = h;
    bi->pprev = prev;
    bi->nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
    return bi;
}

/* Insert one terminal ok=0 script_validate_log row at height h with the given
 * status and block_hash — the exact shape the torn detector's hole scanner
 * (find_lowest_prevout_unresolved_hole_unlocked) selects. block_hash is written
 * as an X'..' hex literal so the detector reads back the same 32 bytes it uses
 * to build the coin_backfill.refused key. Returns true on success. */
static bool brwe_insert_script_hole(sqlite3 *db, int h, const char *status,
                                    const struct uint256 *bh)
{
    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", bh->data[i]);
    char sql[256];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO script_validate_log"
             "(height,status,ok,tx_count,input_count,validated_at,block_hash) "
             "VALUES(%d,'%s',0,0,0,0,X'%s')",
             h, status, hex);
    char *err = NULL;
    bool ok = sqlite3_exec(db, sql, NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    return ok;
}

/* The legacy from-genesis staged verb is refused by the app-init
 * preflight before progress.kv opens or any reset can run. */
static int brwe_case_c_check_refused_verb_preserves_markers(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_refold_contained", "main");
    BRWE_CHECK("C: containment fixture progress store opens",
               progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    BRWE_CHECK("C: assisted shielded boundary starts positive",
               db && shielded_history_reset_to_boundary(db, 7));
    BRWE_CHECK("C: normal boot passes legacy-verb preflight",
               boot_refold_staged_preflight(false));
    BRWE_CHECK("C: -refold-staged is refused before reset",
               !boot_refold_staged_preflight(true));
    int64_t sprout = -1, sapling = -1, nf = -1;
    bool sf = false, zf = false, nf_found = false;
    BRWE_CHECK("C: refused verb preserves all positive markers",
               anchor_kv_activation_cursor(
                   db, ANCHOR_POOL_SPROUT, &sprout, &sf) &&
               anchor_kv_activation_cursor(
                   db, ANCHOR_POOL_SAPLING, &sapling, &zf) &&
               nullifier_kv_activation_cursor(db, &nf, &nf_found) &&
               sf && zf && nf_found && sprout == 7 && sapling == 7 &&
               nf == 7);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Case (A) assertions once the fixture chain is built: pin the window to
 * coins-best, extend it to the header tip, and prove seed_h becomes visible
 * as the correct block_index. Returns the number of failed checks. */
static int brwe_case_a_assert_seed_recovered_by_extend(
    struct main_state *ms, bool insert_ok,
    struct block_index *at_coins_best, struct block_index *at_seed,
    struct block_index *header_tip, int coins_best, int seed_h,
    int tip_height)
{
    int failures = 0;
    if (insert_ok && at_coins_best && at_seed && header_tip) {
        /* Pin the visible window to coins-best (mirrors the boot restore:
         * utxo_recovery_restore_chain_tip -> csr_commit_tip). */
        BRWE_CHECK("A: window pinned to coins-best",
                   active_chain_install_tip_slot(&ms->chain_active,
                                                 at_coins_best) &&
                   active_chain_height(&ms->chain_active) == coins_best);
        ms->pindex_best_header = header_tip;

        /* seed_h is above the window, so it is invisible. */
        BRWE_CHECK("A: seed_h invisible before extend (the pre-fix FATAL)",
                   active_chain_at(&ms->chain_active, seed_h) == NULL);

        /* THE FIX: extend the window forward to the PoW-proven header tip. */
        BRWE_CHECK("A: extend to header tip succeeds",
                   active_chain_extend_window(&ms->chain_active, header_tip));

        /* seed_h is visible AND is the correct block_index (the anchor
         * cross-check reads bi->hashBlock, so identity matters). */
        const struct block_index *bi =
            active_chain_at(&ms->chain_active, seed_h);
        BRWE_CHECK("A: seed_h VISIBLE after extend", bi != NULL);
        BRWE_CHECK("A: seed_h slot is the RIGHT block (correct anchor hash)",
                   bi == at_seed &&
                   memcmp(bi->hashBlock.data, at_seed->hashBlock.data, 32)
                       == 0);
        /* The window now reaches the header tip; coins-best slot intact. */
        BRWE_CHECK("A: window now spans to the header tip",
                   active_chain_height(&ms->chain_active) == tip_height);
        BRWE_CHECK("A: coins-best slot still resolves after extend",
                   active_chain_at(&ms->chain_active, coins_best) ==
                       at_coins_best);
    }
    return failures;
}

/* ── Case (A): RECOVERY — contiguous pprev chain to the header tip. ─────
 * Build a fully linked header chain [0 .. HEADER_TIP], pin the active
 * window to COINS_BEST, point pindex_best_header at the tip. seed_h is then
 * invisible until the extend widens the window. */
static int brwe_case_a_window_extend_recovery(void)
{
    int failures = 0;
    /* Heights chosen far apart so coins-best, seed_h, and the header tip are
     * unambiguous. The window is pinned to COINS_BEST; the snapshot seed sits
     * above it; the PoW-proven header tip is higher still. */
    const int COINS_BEST = 100;
    const int SEED_H      = 130;   /* the snapshot height: above the window */
    const int HEADER_TIP  = 150;   /* pindex_best_header: above seed_h */

    struct main_state ms;
    main_state_init(&ms);

    struct block_index *prev = NULL;
    struct block_index *at_coins_best = NULL;
    struct block_index *at_seed = NULL;
    struct block_index *header_tip = NULL;
    bool insert_ok = true;
    for (int h = 0; h <= HEADER_TIP; h++) {
        struct block_index *bi = brwe_insert(&ms, h, prev);
        if (!bi) { insert_ok = false; break; }
        if (h == COINS_BEST) at_coins_best = bi;
        if (h == SEED_H)     at_seed = bi;
        if (h == HEADER_TIP) header_tip = bi;
        prev = bi;
    }
    BRWE_CHECK("A: header chain [0..tip] built", insert_ok &&
               at_coins_best && at_seed && header_tip);

    failures += brwe_case_a_assert_seed_recovered_by_extend(
        &ms, insert_ok, at_coins_best, at_seed, header_tip,
        COINS_BEST, SEED_H, HEADER_TIP);

    main_state_free(&ms);
    return failures;
}

/* ── Case (B): FAILS CLOSED — a genuine pprev gap at seed_h. ────────────
 * The block at SEED_H has NO pprev link to its parent, so fill_window
 * cannot reach that slot and active_chain_at(SEED_H) stays NULL after
 * the extend. */
static int brwe_case_b_pprev_gap_fails_closed(void)
{
    int failures = 0;
    /* Heights chosen far apart so coins-best, seed_h, and the header tip are
     * unambiguous. The window is pinned to COINS_BEST; the snapshot seed sits
     * above it; the PoW-proven header tip is higher still. */
    const int COINS_BEST = 100;
    const int SEED_H      = 130;   /* the snapshot height: above the window */
    const int HEADER_TIP  = 150;   /* pindex_best_header: above seed_h */

    struct main_state ms;
    main_state_init(&ms);

    struct block_index *prev = NULL;
    struct block_index *at_coins_best = NULL;
    struct block_index *header_tip = NULL;
    bool insert_ok = true;
    for (int h = 0; h <= HEADER_TIP; h++) {
        /* Break the pprev chain ABOVE seed_h: the block at SEED_H+1 has a
         * NULL pprev, so walking down from the header tip stops there and
         * never reaches SEED_H. (Below the break the chain is intact, so
         * coins-best is undisturbed.) */
        struct block_index *link = (h == SEED_H + 1) ? NULL : prev;
        struct block_index *bi = brwe_insert(&ms, h, link);
        if (!bi) { insert_ok = false; break; }
        if (h == COINS_BEST) at_coins_best = bi;
        if (h == HEADER_TIP) header_tip = bi;
        prev = bi;
    }
    BRWE_CHECK("B: header chain with a pprev gap built", insert_ok &&
               at_coins_best && header_tip);

    if (insert_ok && at_coins_best && header_tip) {
        BRWE_CHECK("B: window pinned to coins-best",
                   active_chain_install_tip_slot(&ms.chain_active,
                                                 at_coins_best) &&
                   active_chain_height(&ms.chain_active) == COINS_BEST);
        ms.pindex_best_header = header_tip;

        /* Pre-extend: invisible (same as case A). */
        BRWE_CHECK("B: seed_h invisible before extend",
                   active_chain_at(&ms.chain_active, SEED_H) == NULL);

        /* Extend toward the header tip. The primitive succeeds (no alloc
         * failure) but the pprev gap means it cannot fill the SEED_H slot. */
        BRWE_CHECK("B: extend call returns true (no alloc failure)",
                   active_chain_extend_window(&ms.chain_active, header_tip));

        /* Fail-closed: seed_h is STILL NULL after the extend, so the
         * loader never binds a coin against a missing/forged anchor. */
        BRWE_CHECK("B: seed_h STILL NULL after extend (FATAL still fires)",
                   active_chain_at(&ms.chain_active, SEED_H) == NULL);
    }

    main_state_free(&ms);
    return failures;
}

/* Coins-applied frontier at the wedge, above the anchor; a from-anchor
 * reset would clobber it back to CP_H+1. */
static int brwe_case_d_seed_coins_applied_frontier(sqlite3 *pdb, int wedge)
{
    int failures = 0;
    char *terr = NULL;
    sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, &terr);
    bool set_ok = coins_kv_set_applied_height_in_tx(pdb, wedge);
    sqlite3_exec(pdb, "COMMIT", NULL, NULL, &terr);
    if (terr) sqlite3_free(terr);
    int32_t got = -1; bool found = false;
    BRWE_CHECK("D: coins-applied seeded at the wedge",
               set_ok &&
               coins_kv_get_applied_height(pdb, &got, &found) &&
               found && got == wedge);
    return failures;
}

/* Case (D) detection checks on the seeded store: no from-anchor refold is
 * pre-armed on a fresh store, the healed post-import state declines the
 * auto-arm and keeps the coins-applied frontier at the wedge (D1), a
 * transparent hole without a refusal marker is not a tear (D3), and the
 * durable marker makes it one (D2). Returns the number of failed checks. */
static int brwe_case_d_check_tear_detection_and_auto_arm(
    struct main_state *ms, struct node_db *ndb, sqlite3 *pdb, int cp_h,
    int wedge, int hole_h)
{
    int failures = 0;

    /* Sync the durable from-anchor cache to this fresh store (absent key
     * means refold_from_anchor_active()==false). */
    (void)refold_progress_refresh(pdb);
    BRWE_CHECK("D: no from-anchor refold pre-armed on a fresh store",
               !refold_from_anchor_active());

    /* D1 — HEALED post-import state, NO transparent tear: detect() is
     * false, the ceiling cleared the anchor gate (the scan ran), the
     * auto-arm DECLINES, and the coins-applied frontier stays at the
     * wedge. */
    {
        int32_t hole = 0, ceiling = 0;
        bool tear = block_index_loader_torn_import_detect(
            ms, pdb, cp_h, &hole, &ceiling);
        BRWE_CHECK("D1: healed post-import state is NOT a tear",
                   tear == false);
        BRWE_CHECK("D1: ceiling cleared the anchor (scan actually ran)",
                   ceiling > cp_h && ceiling >= wedge);

        bool armed = boot_refold_from_anchor_arm_if_torn(ms, ndb, pdb);
        BRWE_CHECK("D1: auto-arm DECLINES (no O(chain) from-anchor re-fold)",
                   armed == false);

        int32_t got = -1; bool found = false;
        BRWE_CHECK("D1: coins-applied UNCHANGED at the wedge "
                   "(O(delta) resume, not reset to the anchor)",
                   coins_kv_get_applied_height(pdb, &got, &found) &&
                   found && got == wedge);
    }

    /* D3 — NON-VACUOUS: a transparent prevout_unresolved hole above the
     * anchor but NO coin_backfill.refused marker; detect() scans the hole
     * and is still false (condition 3 needs the marker). */
    struct uint256 hole_hash;
    brwe_hash_for(hole_h, &hole_hash);
    BRWE_CHECK("D3: insert prevout_unresolved hole above the anchor",
               brwe_insert_script_hole(pdb, hole_h, "prevout_unresolved",
                                       &hole_hash));
    {
        int32_t hole = 0, ceiling = 0;
        bool tear = block_index_loader_torn_import_detect(
            ms, pdb, cp_h, &hole, &ceiling);
        BRWE_CHECK("D3: hole WITHOUT a refusal marker is NOT a tear",
                   tear == false);
    }

    /* D2 — POSITIVE control: add the refusal marker at the hole's own
     * (height, block_hash) key; detect() is now true and reports HOLE_H
     * (no arm here). */
    {
        /* "unprovable" is one of the active refusal markers the decoder
         * treats as out_active=true (stage_repair_coin_backfill_util.h). */
        bool wrote = repair_marker_note(
            pdb, REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED, hole_h,
            hole_hash.data, "unprovable", 10);
        BRWE_CHECK("D2: durable coin_backfill.refused marker written", wrote);

        int32_t hole = 0, ceiling = 0;
        bool tear = block_index_loader_torn_import_detect(
            ms, pdb, cp_h, &hole, &ceiling);
        BRWE_CHECK("D2: hole WITH the refusal marker IS a tear (detect fires)",
                   tear == true && hole == hole_h);
    }

    return failures;
}

/* ── Case (D): POST-IMPORT O(delta) RESUME — the shielded-history import
 * (-import-complete-shielded) clears utxo_apply.{anchor,nullifier}_backfill_gap
 * and flips the activation cursors to 0. On the next boot the from-anchor
 * AUTO-ARM (boot_refold_from_anchor_arm_if_torn) MUST NOT fire on the
 * healed state: firing would reset the stage cursors and coins-applied
 * frontier to the anchor and force an O(anchor..tip) re-fold. The coin
 * cursors must stay AT the wedge (delta resume).
 *
 * The tear signal is a TRANSPARENT prevout_unresolved hole above the
 * anchor with a durable coin_backfill.refused marker
 * (block_index_loader_torn_import_detect), orthogonal to the shielded
 * cursors. Sub-steps D3/D2 keep the assertion non-vacuous: detect() is
 * false without the refusal marker and true with it. */
static int brwe_case_d_post_import_delta_resume(void)
{
    int failures = 0;
    const int CP_H   = 100;   /* compiled anchor (checkpoint override) */
    const int WEDGE   = 130;   /* post-import coins-applied frontier > anchor */
    const int TIP     = 150;   /* PoW header tip (active chain height) */
    const int HOLE_H  = 125;   /* a transparent tear height, anchor < h <= wedge */

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_refold_delta_resume", "main");
    BRWE_CHECK("D: progress store opens", progress_store_open(dir));
    sqlite3 *pdb = progress_store_db();
    BRWE_CHECK("D: coins_kv schema", pdb && coins_kv_ensure_schema(pdb));
    BRWE_CHECK("D: script_validate_log schema",
               pdb && script_validate_log_ensure_schema(pdb));

    char dbpath[320];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    struct node_db ndb;
    BRWE_CHECK("D: node_db opens", node_db_open(&ndb, dbpath));

    /* Compiled anchor at CP_H via the test override; detect() only reads
     * cp->height. */
    struct sha3_utxo_checkpoint cp_ovr;
    memset(&cp_ovr, 0, sizeof(cp_ovr));
    cp_ovr.height = CP_H;
    checkpoints_set_sha3_override_for_test(&cp_ovr);

    struct main_state ms;
    main_state_init(&ms);

    /* Active header chain [0..TIP], tip installed → active_chain_height==TIP
     * (headers synced to network tip, above the wedge — the real posture). */
    struct block_index *prev = NULL;
    struct block_index *tip = NULL;
    bool insert_ok = true;
    for (int h = 0; h <= TIP; h++) {
        struct block_index *bi = brwe_insert(&ms, h, prev);
        if (!bi) { insert_ok = false; break; }
        if (h == TIP) tip = bi;
        prev = bi;
    }
    BRWE_CHECK("D: header chain [0..tip] built", insert_ok && tip);
    if (insert_ok && tip) {
        BRWE_CHECK("D: window pinned to header tip",
                   active_chain_install_tip_slot(&ms.chain_active, tip) &&
                   active_chain_height(&ms.chain_active) == TIP);
        ms.pindex_best_header = tip;
    }

    failures += brwe_case_d_seed_coins_applied_frontier(pdb, WEDGE);
    failures += brwe_case_d_check_tear_detection_and_auto_arm(
        &ms, &ndb, pdb, CP_H, WEDGE, HOLE_H);

    main_state_free(&ms);
    checkpoints_reset_sha3_override_for_test();
    node_db_close(&ndb);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_boot_refold_window_extend(void);
int test_boot_refold_window_extend(void)
{
    test_reset_shared_globals();
    printf("\n=== boot_refold_window_extend tests ===\n");
    int failures = 0;

    failures += brwe_case_c_check_refused_verb_preserves_markers();
    failures += brwe_case_a_window_extend_recovery();
    failures += brwe_case_b_pprev_gap_fails_closed();
    failures += brwe_case_d_post_import_delta_resume();

    return failures;
}
