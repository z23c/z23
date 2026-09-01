/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sapling_anchor_frontier_condition -- the auto-terminating cure for the empty
 * Sapling anchor-frontier stall.
 *
 * Proves, hermetically (in-memory anchor store; Pedersen hashing over synthetic
 * commitments — no ~/.zcash-params, no live chain):
 *   (a) an empty sapling_anchors table with a nonzero adoption cursor classifies
 *       as the seed-curable birth defect (detect signal);
 *   (b) seeding a header-verified frontier makes anchor_kv_latest_tree FOUND and
 *       lets the reducer's anchor fold proceed on a block that previously failed
 *       closed with shielded_anchor_history_gap;
 *   (c) a root-MISMATCH seed writes NOTHING and the fold stays failed closed
 *       (fail-closed proven — consensus reject path intact);
 *   (d) the empty-table (curable) vs missing-historical-anchor / from-genesis
 *       (not seed-curable) discrimination. */

#include "test/test_core.h"

#include "conditions/sapling_anchor_frontier_unavailable.h"
#include "chain/checkpoints.h"
#include "config/consensus_state_install_runtime.h"
#include "controllers/agent_controller.h"
#include "controllers/shielded_gap_remedy_controller.h"
#include "core/arith_uint256.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_delta.h"
#include "jobs/utxo_apply_history_hold.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "json/json.h"
#include "primitives/block.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/nullifier_backfill_service.h"
#include "services/sync_monitor.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define SAFC_CHECK(name, expr) do {                                   \
    printf("sapling_anchor_frontier_condition: %s... ", (name));      \
    if ((expr)) printf("OK\n");                                       \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

static void safc_fill(struct uint256 *h, uint8_t seed, size_t idx)
{
    for (size_t i = 0; i < 32; i++)
        h->data[i] = (uint8_t)(seed ^ (idx + i));
}

/* Build a non-empty Sapling frontier of `n` synthetic commitments. */
static void safc_build_tree(size_t n, struct incremental_merkle_tree *out)
{
    sapling_tree_init(out);
    for (size_t i = 0; i < n; i++) {
        struct uint256 cm;
        safc_fill(&cm, 0x5A, i);
        incremental_tree_append(out, &cm);
    }
}

/* A block carrying one Sapling output (triggers fold_sapling). */
static bool safc_block_with_output(struct block *blk, uint8_t cm_seed)
{
    block_init(blk);
    blk->num_vtx = 1;
    blk->vtx = zcl_calloc(1, sizeof(*blk->vtx), "safc_block_tx");
    if (!blk->vtx)
        return false;
    transaction_init(&blk->vtx[0]);
    blk->vtx[0].num_shielded_output = 1;
    blk->vtx[0].v_shielded_output =
        zcl_calloc(1, sizeof(*blk->vtx[0].v_shielded_output), "safc_out");
    if (!blk->vtx[0].v_shielded_output) {
        block_free(blk);
        return false;
    }
    safc_fill(&blk->vtx[0].v_shielded_output[0].cm, cm_seed, 0);
    return true;
}

static void safc_summary_init(struct delta_summary *s)
{
    memset(s, 0, sizeof(*s));
    s->ok = true;
    s->status = "ok";
}

/* ── Engine-driven NAMED REMEDY fixture (gap-condition-healer lane) ──
 *
 * Drives detect/remedy/witness through the REAL condition engine (not just
 * the pure classify() helper above), proving the operator-facing surface for
 * the genuine (not seed-curable) historical anchor gap and the standalone
 * nullifier gap: both must surface a NAMED, contained remedy on this
 * condition's own typed detect/remedy/detail surface, refuse to auto-execute
 * anything, and clear only once BOTH the named blocker(s) are gone AND H*
 * has climbed past the stall height captured at detect.
 *
 * Uses the standalone nullifier gap (utxo_apply.nullifier_backfill_gap) as
 * the representative trigger: detect_sapling_anchor_frontier() treats it
 * identically to the anchor SAPLING_ANCHOR_GAP_HISTORICAL case (see the .c),
 * and it needs no populated anchor tree to construct. */
struct safu_engine_fixture {
    char dir[256];
    struct main_state ms;
    struct block_index *tip;
};

static bool safu_engine_setup(struct safu_engine_fixture *fx, const char *tag)
{
    memset(fx, 0, sizeof(*fx));

    condition_engine_reset_for_testing();
    sapling_anchor_frontier_test_reset();
    blocker_module_init();
    blocker_reset_for_testing();
    test_make_tmpdir(fx->dir, sizeof(fx->dir), "safu_named_remedy", tag);
    if (!progress_store_open(fx->dir))
        return false;

    main_state_init(&fx->ms);
    struct uint256 h0, h1;
    memset(&h0, 0, sizeof(h0)); h0.data[0] = 0xA1; h0.data[1] = 0x5A;
    memset(&h1, 0, sizeof(h1)); h1.data[0] = 0xA2; h1.data[1] = 0x5A;
    struct block_index *genesis =
        chainstate_insert_block_index((struct chainstate *)&fx->ms, &h0);
    struct block_index *tip =
        chainstate_insert_block_index((struct chainstate *)&fx->ms, &h1);
    if (!genesis || !tip)
        return false;
    genesis->nHeight = 0;
    genesis->pprev = NULL;
    genesis->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    genesis->nChainTx = 1;
    arith_uint256_set_u64(&genesis->nChainWork, 1);
    /* Immediately follows genesis (height 1, pprev=genesis@0) —
     * active_chain_move_window_tip()'s chain_linkage_check_advance requires
     * a strictly contiguous connect (pprev_h == h-1), so a height JUMP
     * (e.g. straight to 10) is REFUSED as a label splice. */
    tip->nHeight = 1;
    tip->pprev = genesis;
    tip->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    tip->nChainTx = 2;
    arith_uint256_set_u64(&tip->nChainWork, 2);
    if (!active_chain_move_window_tip(&fx->ms.chain_active, tip))
        return false;
    fx->tip = tip;

    sync_monitor_set_context(NULL, NULL, &fx->ms);

    /* Canonical lane over the fixture's OWN isolated temp datadir (never the
     * real ~/.zclassic-c23): a non-copy datadir still classifies refuses_live
     * (eligibility requires the -COPY- marker), so the borrowed-import
     * containment assertions hold, AND the sovereign self-heal ladder's Rung B
     * (boot_install_bundle_request / boot_autodetect_consensus_bundle) can only
     * ever touch <fx->dir>/bundles — hermetic, no live-datadir side effect. */
    rpc_agent_set_boot_context("canonical", "release", fx->dir,
                               18232, 8033, 8443, 0);

    reducer_frontier_provable_tip_reset();
    /* H* = 0 while the header tip is 1: genuinely behind (detect()'s
     * "must be genuinely behind" gate). */
    reducer_frontier_provable_tip_set(0);

    register_sapling_anchor_frontier_unavailable();
    return true;
}

static void safu_engine_teardown(struct safu_engine_fixture *fx)
{
    /* Clear the boot context so the about-to-be-deleted temp datadir never
     * leaks into a later test's agent_runtime_context_datadir(). */
    rpc_agent_set_boot_context("unknown", "unknown", "", 0, 0, 0, 0);
    sync_monitor_set_context(NULL, NULL, NULL);
    condition_engine_reset_for_testing();
    sapling_anchor_frontier_test_reset();
    reducer_frontier_provable_tip_reset();
    main_state_free(&fx->ms);
    progress_store_close();
    blocker_reset_for_testing();
    test_cleanup_tmpdir(fx->dir);
}

/* Find this condition's array entry in a condition_engine_dump_state_json()
 * "conditions" array by name. Returns NULL if not found. */
static const struct json_value *safu_find_entry(const struct json_value *dump)
{
    const struct json_value *conds = json_get(dump, "conditions");
    if (!conds)
        return NULL;
    for (size_t i = 0; i < json_size(conds); i++) {
        const struct json_value *e = json_at(conds, i);
        const char *name = json_get_str(json_get(e, "name"));
        if (name && strcmp(name, "sapling_anchor_frontier_unavailable") == 0)
            return e;
    }
    return NULL;
}

int test_sapling_anchor_frontier_condition(void);
int test_sapling_anchor_frontier_condition(void)
{
    int failures = 0;

    /* (d.1) from-genesis store (activation==0): an empty table is COMPLETE, not
     * a curable gap. */
    {
        sqlite3 *db = NULL;
        SAFC_CHECK("open from-genesis store",
                   sqlite3_open(":memory:", &db) == SQLITE_OK && db);
        SAFC_CHECK("initialize from-genesis history (activation=0)",
                   anchor_kv_initialize_history(db, 0));
        SAFC_CHECK("classify from-genesis empty table == NONE",
                   sapling_anchor_frontier_classify(db) ==
                       SAPLING_ANCHOR_GAP_NONE);
        if (db) sqlite3_close(db);
    }

    /* (a)+(d.2) empty table + activation>0 == curable EMPTY_TABLE birth defect. */
    sqlite3 *db = NULL;
    SAFC_CHECK("open snapshot-seeded store",
               sqlite3_open(":memory:", &db) == SQLITE_OK && db);
    if (!db)
        return failures + 1;
    SAFC_CHECK("initialize adopted-above-genesis history (activation=100)",
               anchor_kv_initialize_history(db, 100));
    SAFC_CHECK("classify empty table + activation>0 == EMPTY_TABLE",
               sapling_anchor_frontier_classify(db) ==
                   SAPLING_ANCHOR_GAP_EMPTY_TABLE);

    /* The stall: a shielded-output block finds the empty table -> fail closed. */
    {
        struct block blk;
        SAFC_CHECK("build shielded-output block", safc_block_with_output(&blk, 0x11));
        struct delta_summary s;
        safc_summary_init(&s);
        bool store_ok =
            utxo_apply_check_and_insert_anchors(db, &blk, 150, &s);
        SAFC_CHECK("pre-seed fold fails closed (history gap, no store error)",
                   store_ok && !s.ok &&
                   s.status &&
                   strcmp(s.status, "shielded_anchor_history_gap") == 0);
        block_free(&blk);
    }

    /* (c) root-MISMATCH seed writes NOTHING; the stall persists. */
    {
        struct incremental_merkle_tree seed_tree;
        safc_build_tree(7, &seed_tree);
        struct uint256 wrong_root;
        safc_fill(&wrong_root, 0xEE, 999);   /* deliberately != frontier root */
        SAFC_CHECK("mismatched-root seed is REFUSED",
                   !anchor_kv_seed_frontier_row(db, ANCHOR_POOL_SAPLING,
                                                &seed_tree, 100, &wrong_root));
        bool empty = false;
        SAFC_CHECK("refused seed wrote NOTHING (table still empty)",
                   anchor_kv_table_is_empty(db, ANCHOR_POOL_SAPLING, &empty) &&
                   empty);
        SAFC_CHECK("classify still EMPTY_TABLE after refused seed",
                   sapling_anchor_frontier_classify(db) ==
                       SAPLING_ANCHOR_GAP_EMPTY_TABLE);
    }

    /* (b) verified seed (root matches) -> latest_tree FOUND and the fold that
     * previously failed closed now proceeds. */
    struct incremental_merkle_tree seed_tree;
    struct uint256 seed_root;
    safc_build_tree(7, &seed_tree);
    incremental_tree_root(&seed_tree, &seed_root);
    SAFC_CHECK("verified seed (root matches) inserts the frontier",
               anchor_kv_seed_frontier_row(db, ANCHOR_POOL_SAPLING,
                                           &seed_tree, 100, &seed_root));
    {
        struct incremental_merkle_tree got;
        struct uint256 got_root;
        int64_t got_h = -1;
        SAFC_CHECK("anchor_kv_latest_tree == FOUND after verified seed",
                   anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &got, &got_root,
                                         &got_h) == ANCHOR_KV_FOUND &&
                   got_h == 100 &&
                   memcmp(got_root.data, seed_root.data, 32) == 0);
    }
    SAFC_CHECK("birth defect cured: classify no longer EMPTY_TABLE once seeded",
               sapling_anchor_frontier_classify(db) !=
                   SAPLING_ANCHOR_GAP_EMPTY_TABLE);
    {
        struct block blk;
        safc_block_with_output(&blk, 0x22);
        struct delta_summary s;
        safc_summary_init(&s);
        bool store_ok =
            utxo_apply_check_and_insert_anchors(db, &blk, 150, &s);
        SAFC_CHECK("post-seed fold PROCEEDS (ok, no gap) and threads the frontier",
                   store_ok && s.ok);
        block_free(&blk);
        /* The fold inserted the extended frontier at h=150. */
        struct incremental_merkle_tree t2;
        int64_t h2 = -1;
        SAFC_CHECK("fold advanced the stored frontier to h=150",
                   anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &t2, NULL,
                                         &h2) == ANCHOR_KV_FOUND && h2 == 150);
    }

    /* (d.3) rows present == HISTORICAL (not seed-curable via the birth-defect
     * cure). */
    SAFC_CHECK("classify non-empty table == HISTORICAL (owner-gated)",
               sapling_anchor_frontier_classify(db) ==
                   SAPLING_ANCHOR_GAP_HISTORICAL);

    sqlite3_close(db);

    /* Registration: the condition is wired into the engine registry. */
    register_sapling_anchor_frontier_unavailable();
    SAFC_CHECK("condition registered in the engine",
               condition_engine_has_registered(
                   "sapling_anchor_frontier_unavailable"));

    /* ── GAP ABSENT: no blocker -> not detected, no remedy call. ── */
    {
        struct safu_engine_fixture fx;
        bool ok = safu_engine_setup(&fx, "absent");
        SAFC_CHECK("gap-absent fixture setup", ok);
        if (ok) {
            condition_engine_tick();
            struct condition_runtime_snapshot snap;
            bool got = condition_engine_get_registered_snapshot(
                "sapling_anchor_frontier_unavailable", &snap);
            SAFC_CHECK("gap-absent: not currently_active",
                       got && !snap.currently_active);
            SAFC_CHECK("gap-absent: no remedy call",
                       sapling_anchor_frontier_test_remedy_calls() == 0);

            struct json_value dump;
            json_init(&dump);
            json_set_object(&dump);
            condition_engine_dump_state_json(&dump, NULL);
            const struct json_value *mine = safu_find_entry(&dump);
            const struct json_value *detail =
                mine ? json_get(mine, "detail") : NULL;
            SAFC_CHECK("gap-absent: detail emits no shielded_gap_remedy",
                       !detail || json_get(detail, "shielded_gap_remedy") == NULL);
            json_free(&dump);
        }
        safu_engine_teardown(&fx);
    }

    /* ── GAP PRESENT (standalone nullifier gap): NAMED REMEDY surfaced,
     * containment refuses live auto-exec, never self-resolves. ── */
    {
        struct safu_engine_fixture fx;
        bool ok = safu_engine_setup(&fx, "present");
        SAFC_CHECK("gap-present fixture setup", ok);
        if (ok) {
            struct blocker_record r;
            blocker_init(&r, UTXO_APPLY_NF_GAP_BLOCKER_ID, "utxo_apply",
                        BLOCKER_PERMANENT, "test: nullifier history gap");
            blocker_set(&r);

            condition_engine_tick();

            struct condition_runtime_snapshot snap;
            bool got = condition_engine_get_registered_snapshot(
                "sapling_anchor_frontier_unavailable", &snap);
            SAFC_CHECK("gap-present: detected + currently_active",
                       got && snap.currently_active);
            SAFC_CHECK("gap-present: remedy ran exactly once",
                       sapling_anchor_frontier_test_remedy_calls() == 1);
            SAFC_CHECK("gap-present: outcome FAILED (never self-resolves)",
                       got && snap.last_outcome == COND_REMEDY_FAILED);

            struct json_value dump;
            json_init(&dump);
            json_set_object(&dump);
            SAFC_CHECK("gap-present: engine dump ok",
                       condition_engine_dump_state_json(&dump, NULL));
            const struct json_value *mine = safu_find_entry(&dump);
            SAFC_CHECK("gap-present: found this condition's entry",
                       mine != NULL);
            const struct json_value *detail =
                mine ? json_get(mine, "detail") : NULL;
            SAFC_CHECK("gap-present: detail present", detail != NULL);
            SAFC_CHECK("gap-present: episode_kind == NAMED_REMEDY(2)",
                       detail &&
                       json_get_int(json_get(detail, "episode_kind")) == 2);
            SAFC_CHECK("gap-present: nullifier_gap_blocker_present true",
                       detail &&
                       json_get_bool(json_get(
                           detail, "nullifier_gap_blocker_present")));

            const struct json_value *sgr =
                detail ? json_get(detail, "shielded_gap_remedy") : NULL;
            SAFC_CHECK("gap-present: named-remedy sub-object present",
                       sgr != NULL);
            const struct json_value *remedy =
                sgr ? json_get(sgr, "remedy") : NULL;
            SAFC_CHECK("gap-present: remedy object present", remedy != NULL);
            const char *imp =
                remedy ? json_get_str(json_get(remedy, "import_command"))
                       : NULL;
            SAFC_CHECK("gap-present: names -import-complete-shielded",
                       imp && strstr(imp, "-import-complete-shielded=") != NULL);

            const struct json_value *cont =
                sgr ? json_get(sgr, "containment") : NULL;
            SAFC_CHECK("gap-present: containment present", cont != NULL);
            SAFC_CHECK("gap-present: auto_execute is structurally false",
                       cont && !json_get_bool(json_get(cont, "auto_execute")));
            SAFC_CHECK("gap-present: refuses live auto-exec on live datadir",
                       cont && json_get_bool(json_get(cont, "refuses_live")));
            json_free(&dump);
        }
        safu_engine_teardown(&fx);
    }

    /* ── DUAL GAP (EMPTY_TABLE anchor + nullifier blocker): the birth-defect
     * anchor half is attempted FIRST (tier1 seed), then the named-remedy
     * ladder owns the nullifier half — the 2026-08-01 seed-boot wedge
     * routing, where the ladder branch used to win on the NF-blocker
     * disjunct alone and the tier1-curable anchor side was never tried. ── */
    {
        struct safu_engine_fixture fx;
        bool ok = safu_engine_setup(&fx, "dual");
        SAFC_CHECK("dual-gap fixture setup", ok);
        if (ok) {
            /* activation>0 + empty table == the curable EMPTY_TABLE class.
             * Nullifier history is initialized too so markers_read (which
             * needs all three adoption cursors) succeeds for the hold memo. */
            SAFC_CHECK("dual-gap: anchor history adopted above genesis",
                       anchor_kv_initialize_history(progress_store_db(), 100));
            SAFC_CHECK("dual-gap: nullifier history adopted above genesis",
                       nullifier_kv_initialize_history(progress_store_db(),
                                                       100));
            /* Pin the checkpoint path to the hermetic fixture datadir (no
             * ckpt file there -> tier1 fails closed deterministically,
             * regardless of suite-order static path state). */
            set_sapling_checkpoint_datadir(fx.dir);

            struct blocker_record ra, rn;
            blocker_init(&ra, UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID, "utxo_apply",
                         BLOCKER_PERMANENT, "test: anchor history gap");
            blocker_set(&ra);
            blocker_init(&rn, UTXO_APPLY_NF_GAP_BLOCKER_ID, "utxo_apply",
                         BLOCKER_PERMANENT, "test: nullifier history gap");
            blocker_set(&rn);

            /* The 2026-08-02 wedge shape: a GATE_HOLD already recorded the
             * in-memory history-hold memo on the stall block. Only a LANDED
             * cure (tier1/tier1b seed) may clear it — a refused seed must
             * leave the park in place (the fold stays fail-closed). */
            SAFC_CHECK("dual-gap: history-hold memo recorded",
                       utxo_apply_history_hold_record(
                           progress_store_db(), 1, 2, fx.tip->phashBlock));
            SAFC_CHECK("dual-gap: hold active before remedy",
                       utxo_apply_history_hold_active());

            condition_engine_tick();

            SAFC_CHECK("dual-gap: remedy ran exactly once",
                       sapling_anchor_frontier_test_remedy_calls() == 1);
            SAFC_CHECK("dual-gap: tier1 seed attempted BEFORE the ladder",
                       sapling_anchor_frontier_test_tier1_attempts() == 1);
            struct condition_runtime_snapshot snap;
            bool got = condition_engine_get_registered_snapshot(
                "sapling_anchor_frontier_unavailable", &snap);
            SAFC_CHECK("dual-gap: episode stays active (no fake resolve)",
                       got && snap.currently_active);
            SAFC_CHECK("dual-gap: outcome is the ladder's, not tier1 OK",
                       got && snap.last_outcome == COND_REMEDY_FAILED);
            /* A refused seed wrote nothing and cleared nothing: the hold
             * memo parks the fold until a cure actually lands (the remedy's
             * utxo_apply_history_hold_clear runs only on tier1/tier1b
             * SUCCESS — covered live by the anchor replay-canary). */
            SAFC_CHECK("dual-gap: hold memo survives a refused seed",
                       utxo_apply_history_hold_active());

            struct json_value dump;
            json_init(&dump);
            json_set_object(&dump);
            SAFC_CHECK("dual-gap: engine dump ok",
                       condition_engine_dump_state_json(&dump, NULL));
            const struct json_value *mine = safu_find_entry(&dump);
            const struct json_value *detail =
                mine ? json_get(mine, "detail") : NULL;
            SAFC_CHECK("dual-gap: episode_kind == BIRTH_DEFECT(1)",
                       detail &&
                       json_get_int(json_get(detail, "episode_kind")) == 1);
            SAFC_CHECK("dual-gap: anchor gap blocker flagged",
                       detail &&
                       json_get_bool(json_get(detail, "gap_blocker_present")));
            SAFC_CHECK("dual-gap: nullifier gap blocker flagged",
                       detail &&
                       json_get_bool(json_get(
                           detail, "nullifier_gap_blocker_present")));
            json_free(&dump);

            /* The refused tier1 seed wrote nothing: still EMPTY_TABLE. */
            SAFC_CHECK("dual-gap: anchor side still EMPTY_TABLE after refused seed",
                       sapling_anchor_frontier_classify(progress_store_db()) ==
                           SAPLING_ANCHOR_GAP_EMPTY_TABLE);

            set_sapling_checkpoint_datadir(NULL);
            utxo_apply_history_hold_clear();
        }
        safu_engine_teardown(&fx);
    }

    /* ── GAP CLEARED: the operator ran the import + rebooted (activation
     * flips to 0, both refresh calls clear the blocker) and the fold resumed
     * (H* climbs past the stall). The very next tick's witness must fire. ── */
    {
        struct safu_engine_fixture fx;
        bool ok = safu_engine_setup(&fx, "cleared");
        SAFC_CHECK("gap-cleared fixture setup", ok);
        if (ok) {
            struct blocker_record r;
            blocker_init(&r, UTXO_APPLY_NF_GAP_BLOCKER_ID, "utxo_apply",
                        BLOCKER_PERMANENT, "test: nullifier history gap");
            blocker_set(&r);
            condition_engine_tick();   /* rising edge: episode active */

            struct condition_runtime_snapshot snap0;
            SAFC_CHECK("gap-cleared: episode active before the cure",
                       condition_engine_get_registered_snapshot(
                           "sapling_anchor_frontier_unavailable", &snap0) &&
                       snap0.currently_active);

            /* The cure: import flips activation -> blocker clears; H* climbs
             * past the baseline (0) captured at detect. */
            blocker_clear(UTXO_APPLY_NF_GAP_BLOCKER_ID);
            reducer_frontier_provable_tip_set(1);

            condition_engine_tick();   /* witness must fire this tick */

            struct condition_runtime_snapshot snap;
            bool got = condition_engine_get_registered_snapshot(
                "sapling_anchor_frontier_unavailable", &snap);
            SAFC_CHECK("gap-cleared: witness fired, no longer active",
                       got && !snap.currently_active);
            SAFC_CHECK("gap-cleared: cleared_count advanced",
                       got && snap.cleared_count >= 1);
        }
        safu_engine_teardown(&fx);
    }

    /* ══ Move 2a — sovereign self-heal LADDER LOGIC (pure + hermetic) ══ */

    /* (E) Pure rung selection matrix — Rung A fires when bodies present, Rung B
     * when a bundle is present, Rung C otherwise; NONE when no gap. */
    {
        SAFC_CHECK("select: nullifier gap + local bodies -> Rung A(nullifier)",
                   shielded_selfheal_select_rung(SHIELDED_GAP_NULLIFIER_ONLY,
                                                  true, false, false) ==
                       SHIELDED_SELFHEAL_RUNG_A_NULLIFIER);
        SAFC_CHECK("select: nullifier gap, no bodies, bundle -> Rung B",
                   shielded_selfheal_select_rung(SHIELDED_GAP_NULLIFIER_ONLY,
                                                  false, false, true) ==
                       SHIELDED_SELFHEAL_RUNG_B_INSTALL);
        SAFC_CHECK("select: nullifier gap, no bodies, no bundle -> Rung C",
                   shielded_selfheal_select_rung(SHIELDED_GAP_NULLIFIER_ONLY,
                                                  false, false, false) ==
                       SHIELDED_SELFHEAL_RUNG_C_NAMED_NEED);
        SAFC_CHECK("select: anchor gap + reachable refold -> Rung A(anchor)",
                   shielded_selfheal_select_rung(SHIELDED_GAP_ANCHOR_ONLY,
                                                  false, true, false) ==
                       SHIELDED_SELFHEAL_RUNG_A_ANCHOR);
        SAFC_CHECK("select: BOTH + reachable refold -> Rung A(anchor)",
                   shielded_selfheal_select_rung(SHIELDED_GAP_BOTH, false, true,
                                                 true) ==
                       SHIELDED_SELFHEAL_RUNG_A_ANCHOR);
        SAFC_CHECK("select: anchor gap, no refold, bundle -> Rung B",
                   shielded_selfheal_select_rung(SHIELDED_GAP_ANCHOR_ONLY,
                                                  false, false, true) ==
                       SHIELDED_SELFHEAL_RUNG_B_INSTALL);
        SAFC_CHECK("select: BOTH, no refold, no bundle -> Rung C",
                   shielded_selfheal_select_rung(SHIELDED_GAP_BOTH, false, false,
                                                 false) ==
                       SHIELDED_SELFHEAL_RUNG_C_NAMED_NEED);
        SAFC_CHECK("select: no gap -> Rung NONE",
                   shielded_selfheal_select_rung(SHIELDED_GAP_NONE, true, true,
                                                 true) ==
                       SHIELDED_SELFHEAL_RUNG_NONE);
    }

    /* (F) Rung C named-need composition — the exact first missing height. */
    {
        SAFC_CHECK("named_need: neither known -> -1",
                   shielded_selfheal_named_need(-1, -1) == -1);
        SAFC_CHECK("named_need: nullifier only -> that height",
                   shielded_selfheal_named_need(100, -1) == 100);
        SAFC_CHECK("named_need: body only -> that height",
                   shielded_selfheal_named_need(-1, 200) == 200);
        SAFC_CHECK("named_need: both -> the lower (exact first missing)",
                   shielded_selfheal_named_need(150, 120) == 120 &&
                   shielded_selfheal_named_need(120, 150) == 120);
    }

    /* (G) Sovereign authorization is SEPARATE from the borrowed containment:
     * refuses a throwaway -COPY- copy-prove datadir, authorizes a live one. */
    {
        char copy_dir[128];
        snprintf(copy_dir, sizeof(copy_dir),
                 "/tmp/.zclassic-c23-COPY-selfheal-test");
        rpc_agent_set_boot_context("copy", "release", copy_dir,
                                   18232, 8033, 8443, 0);
        SAFC_CHECK("sovereign auth: -COPY- datadir NOT authorized (operator)",
                   !shielded_selfheal_sovereign_authorized());
        rpc_agent_set_boot_context("canonical", "release",
                                   "/tmp/zcl-selfheal-live", 18232, 8033, 8443,
                                   0);
        SAFC_CHECK("sovereign auth: live (non-copy) datadir authorized",
                   shielded_selfheal_sovereign_authorized());
        rpc_agent_set_boot_context("unknown", "unknown", "", 0, 0, 0, 0);
    }

    /* (H) Rung B ARMS the durable install-on-next-boot request when a
     * ROM-matching bundle is present AND the checkpoint header solution is
     * durably available — hermetic against the fixture's own temp datadir (never
     * the live node). Drives the REAL remedy path: NULLIFIER_ONLY gap + no open
     * node.db (Rung A skipped) + a bundle present -> Rung B arms.
     *
     * NEW CONTRACT (solution gate): Rung B must NOT burn the bounded install
     * budget on a solutionless defer — it only arms once
     * checkpoint_header_solution_available is true. Seed a validate_headers_log
     * PASS row at the compiled checkpoint so the gated arm proceeds; the
     * un-seeded case is proven in (H-gate) below. */
    {
        struct safu_engine_fixture fx;
        bool ok = safu_engine_setup(&fx, "rungB");
        SAFC_CHECK("rungB fixture setup", ok);
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        if (ok && cp) {
            char bdir[320];
            snprintf(bdir, sizeof(bdir), "%s/bundles", fx.dir);
            mkdir(bdir, 0700);
            char bpath[400];
            snprintf(bpath, sizeof(bpath), "%s/complete-state.sqlite", bdir);
            FILE *f = fopen(bpath, "wb");
            if (f) { fputs("SQLite format 3\0stub-bundle", f); fclose(f); }

            /* Make the checkpoint header solution durably available. */
            sqlite3 *db = progress_store_db();
            sqlite3_exec(db,
                "CREATE TABLE IF NOT EXISTS validate_headers_log("
                "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER "
                "NOT NULL, fail_reason TEXT, validated_at INTEGER);",
                NULL, NULL, NULL);
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(db,
                    "INSERT OR REPLACE INTO validate_headers_log(height,hash,ok) "
                    "VALUES(?,?,1)", -1, &st, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(st, 1, cp->height);
                sqlite3_bind_blob(st, 2, cp->block_hash, 32, SQLITE_STATIC);
                sqlite3_step(st);
                sqlite3_finalize(st);
            }

            SAFC_CHECK("rungB: no install request pending before the heal",
                       !boot_install_bundle_pending(fx.dir));

            struct blocker_record r;
            blocker_init(&r, UTXO_APPLY_NF_GAP_BLOCKER_ID, "utxo_apply",
                        BLOCKER_PERMANENT, "test: nullifier history gap");
            blocker_set(&r);
            condition_engine_tick();   /* detect + remedy: Rung B arms */

            SAFC_CHECK("rungB: remedy ran exactly once",
                       sapling_anchor_frontier_test_remedy_calls() == 1);
            SAFC_CHECK("rungB: install-on-next-boot request ARMED with the "
                       "checkpoint solution present",
                       boot_install_bundle_pending(fx.dir));
        }
        safu_engine_teardown(&fx);
    }

    /* (H-gate) Rung B does NOT arm the budgeted install when the checkpoint
     * header solution is ABSENT — the solution gate that stops
     * boot_install_bundle_consume from burning BOOT_INSTALL_BUNDLE_MAX on
     * solutionless retriable defers (a live-only, copy-proof-invisible cure
     * death). Same fixture as (H) but no validate_headers_log seed. */
    {
        struct safu_engine_fixture fx;
        bool ok = safu_engine_setup(&fx, "rungB_gate");
        SAFC_CHECK("rungB-gate fixture setup", ok);
        if (ok) {
            char bdir[320];
            snprintf(bdir, sizeof(bdir), "%s/bundles", fx.dir);
            mkdir(bdir, 0700);
            char bpath[400];
            snprintf(bpath, sizeof(bpath), "%s/complete-state.sqlite", bdir);
            FILE *f = fopen(bpath, "wb");
            if (f) { fputs("SQLite format 3\0stub-bundle", f); fclose(f); }

            struct blocker_record r;
            blocker_init(&r, UTXO_APPLY_NF_GAP_BLOCKER_ID, "utxo_apply",
                        BLOCKER_PERMANENT, "test: nullifier history gap");
            blocker_set(&r);
            condition_engine_tick();   /* detect + remedy: Rung B gated off */

            SAFC_CHECK("rungB-gate: remedy ran exactly once",
                       sapling_anchor_frontier_test_remedy_calls() == 1);
            SAFC_CHECK("rungB-gate: install NOT armed without the checkpoint "
                       "solution (budget not burned)",
                       !boot_install_bundle_pending(fx.dir));
        }
        safu_engine_teardown(&fx);
    }

    /* (I) The .progressing hook resets the budget WHILE the durable heal cursor
     * advances, and returns false on a frozen cursor (so a genuinely stuck node
     * still pages in bounded time and never re-spins). Drives the real hook via
     * the nullifier backfill resume cursor. */
    {
        struct safu_engine_fixture fx;
        bool ok = safu_engine_setup(&fx, "progressing");
        SAFC_CHECK("progressing fixture setup", ok);
        if (ok) {
            sqlite3 *pdb = progress_store_db();
            progress_meta_table_ensure(pdb);
            sapling_anchor_frontier_test_force_named_episode();

            /* First observation snapshots the baseline (no advance claimed). */
            progress_meta_set(pdb, NULLIFIER_BACKFILL_RESUME_KEY, "100", 3);
            SAFC_CHECK("progressing: first observation snapshots (false)",
                       !sapling_anchor_frontier_test_progressing());
            /* Frozen cursor -> false (budget must still exhaust). */
            SAFC_CHECK("progressing: frozen resume cursor -> false",
                       !sapling_anchor_frontier_test_progressing());
            /* Durable advance -> true (engine resets the attempt budget). */
            progress_meta_set(pdb, NULLIFIER_BACKFILL_RESUME_KEY, "250", 3);
            SAFC_CHECK("progressing: advancing resume cursor -> true",
                       sapling_anchor_frontier_test_progressing());
            /* Re-snapshotted at 250 -> a repeat with no further advance is false. */
            SAFC_CHECK("progressing: re-snapshot then frozen -> false",
                       !sapling_anchor_frontier_test_progressing());
        }
        safu_engine_teardown(&fx);
    }

    return failures;
}
