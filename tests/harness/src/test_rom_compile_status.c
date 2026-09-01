/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Focused test for the ops.rom / `dumpstate rom_compile` data source
 * (engine/jobs/src/rom_compile_status.c) and its pure ASCII renderer
 * (tools/command/rom_compile_render.c). Two halves:
 *   1. The live dump function returns the documented zcl.rom_compile.v1
 *      shape (schema, 8 stages in the ha/vh/bf/bp/sv/pv/ua/tf order, the
 *      five-layer ladder) and honestly reports idle/active per the
 *      refold_progress test-only cache setter — no live progress store
 *      required (the dump function degrades gracefully with the store
 *      closed, same as reducer_frontier_dump_state_json).
 *   2. The renderer, driven with a SYNTHETIC fixture (not the live dumper —
 *      deterministic and independent of process-global stage cursors),
 *      renders the expected percent and ETA text.
 *
 * One TEST()/_test_next: pair per function (the shared ASSERT() macro
 * hardcodes `goto _test_next`, so two TEST blocks in one function would
 * collide on the label) — each case below is its own static function. */

#include "test/test_core.h"

#include "jobs/rom_compile_status.h"
#include "jobs/refold_progress.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "command/rom_compile_render.h"
#include "core/uint256.h"
#include "json/json.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"

#include <sqlite3.h>
#include <string.h>

static int test_rom_compile_dump_idle_shape(void)
{
    int failures = 0;

    TEST("rom_compile dump: idle shape is well-formed and honest") {
        refold_progress_test_set_cached(false);
        rom_compile_status_test_reset_rate_sample();

        struct json_value out;
        json_init(&out);
        bool ok = rom_compile_status_dump_state_json(&out, NULL);
        ASSERT(ok);
        ASSERT(out.type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(&out, "schema")),
                     "zcl.rom_compile.v1");

        const struct json_value *fold = json_get(&out, "fold");
        ASSERT(fold && fold->type == JSON_OBJ);
        ASSERT(!json_get_bool(json_get(fold, "active")));
        ASSERT_STR_EQ(json_get_str(json_get(fold, "mode")), "idle");
        ASSERT_EQ(json_get_int(json_get(fold, "target")), (int64_t)3056758);
        double percent = json_get_real(json_get(fold, "percent"));
        ASSERT(percent >= 0.0 && percent <= 100.0);
        ASSERT(json_get_int(json_get(fold, "remaining_blocks")) >= 0);
        /* First sample in this reset session — no prior point, so rate is
         * unknown/zero and ETA is honestly "unknown". */
        ASSERT(json_get_real(json_get(fold, "rate_blk_s")) == 0.0);
        ASSERT_EQ(json_get_int(json_get(fold, "eta_seconds")), (int64_t)-1);
        ASSERT_STR_EQ(json_get_str(json_get(fold, "eta_human")), "unknown");

        const struct json_value *stages = json_get(&out, "stages");
        ASSERT(stages && stages->type == JSON_ARR);
        ASSERT_EQ(stages->num_children, (size_t)8);
        static const char *const expect_abbrev[8] = {
            "ha", "vh", "bf", "bp", "sv", "pv", "ua", "tf" };
        for (size_t i = 0; i < 8; i++) {
            const struct json_value *s = json_at(stages, i);
            ASSERT_STR_EQ(json_get_str(json_get(s, "abbrev")),
                         expect_abbrev[i]);
            ASSERT(json_get_int(json_get(s, "step_us_ewma")) >= 0);
        }
        ASSERT(json_get_str(json_get(&out, "bottleneck_stage")) != NULL);

        const struct json_value *layers = json_get(&out, "layers");
        ASSERT(layers && layers->type == JSON_OBJ);
        static const char *const expect_layers[5] = {
            "rom_checkpoint", "sealed_history", "sealed_base_receipt",
            "delta", "tip_ring" };
        for (size_t i = 0; i < 5; i++)
            ASSERT(json_get(layers, expect_layers[i]) != NULL);
        /* The ROM checkpoint is compiled into the binary — always present,
         * regardless of live fold state. */
        ASSERT(json_get_bool(
            json_get(json_get(layers, "rom_checkpoint"), "present")));

        json_free(&out);
        PASS();
    } _test_next:;

    return failures;
}

static int test_rom_compile_dump_active_mode(void)
{
    int failures = 0;

    TEST("rom_compile dump: refold_progress_test_set_cached(true) flips "
         "fold.active") {
        refold_progress_test_set_cached(true);
        struct json_value out;
        json_init(&out);
        bool ok = rom_compile_status_dump_state_json(&out, NULL);
        ASSERT(ok);
        const struct json_value *fold = json_get(&out, "fold");
        ASSERT(json_get_bool(json_get(fold, "active")));
        ASSERT_STR_EQ(json_get_str(json_get(fold, "mode")), "from_genesis");
        json_free(&out);
        refold_progress_test_set_cached(false);
        PASS();
    } _test_next:;

    return failures;
}

static void rcs_leaf(struct uint256 *o, uint8_t seed)
{
    for (int i = 0; i < 32; i++) o->data[i] = (uint8_t)(seed + i * 7);
}

static void rcs_nf(uint8_t out[32], uint8_t tag)
{
    memset(out, 0, 32);
    out[0] = tag;
    out[1] = 0x52;
    out[31] = 0x43;
}

/* Import -> resume telemetry, end to end against a REAL progress.kv: before
 * a shielded-history import both activation cursors are positive, both gap
 * blockers are latched, and imported counts are zero; after simulating the
 * exact atomic transition shielded_history_import_from_chainstate performs
 * (write rows, flip both markers to zero in one transaction, refresh both
 * blockers) the dumper reports gap=false, the durable row counts the import
 * actually wrote, and status=complete. This is the "is it actually
 * recovering?" question the LANE exists to answer as a typed view. */
static int test_rom_compile_dump_shielded_import_transition(void)
{
    int failures = 0;

    TEST("rom_compile dump: shielded_import reflects the real import -> "
         "resume transition") {
        char dir[256];
        progress_store_close();
        test_make_tmpdir(dir, sizeof(dir), "rom_compile", "shielded_import");
        bool opened = progress_store_open(dir);
        ASSERT(opened);
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        blocker_reset_for_testing();

        /* Pre-import: a snapshot/borrowed seed activated both pools above
         * genesis — the wedge state utxo_apply.{anchor,nullifier}_backfill_gap
         * names. */
        const int64_t boundary = 50;
        ASSERT(anchor_kv_initialize_history(db, boundary));
        ASSERT(nullifier_kv_initialize_history(db, boundary));
        utxo_apply_anchor_gap_blocker_refresh(db);
        utxo_apply_nullifier_gap_blocker_refresh(db);

        struct json_value pre;
        json_init(&pre);
        ASSERT(rom_compile_status_dump_state_json(&pre, NULL));
        const struct json_value *si_pre = json_get(&pre, "shielded_import");
        ASSERT(si_pre && si_pre->type == JSON_OBJ);
        ASSERT(json_get_bool(json_get(si_pre, "progress_store_open")));
        ASSERT(json_get_bool(json_get(si_pre, "snapshot_complete")));

        const struct json_value *anchor_pre = json_get(si_pre, "anchor");
        ASSERT(json_get_bool(json_get(anchor_pre, "cursor_known")));
        ASSERT_EQ(json_get_int(json_get(anchor_pre, "sprout_activation_cursor")),
                  boundary);
        ASSERT_EQ(json_get_int(json_get(anchor_pre, "sapling_activation_cursor")),
                  boundary);
        ASSERT(json_get_bool(json_get(anchor_pre, "gap_blocker_active")));
        ASSERT(json_get_bool(json_get(anchor_pre, "gap")));
        ASSERT_EQ(json_get_int(json_get(anchor_pre, "sprout_anchors_imported")),
                  (int64_t)0);
        ASSERT_EQ(json_get_int(json_get(anchor_pre, "sapling_anchors_imported")),
                  (int64_t)0);

        const struct json_value *nf_pre = json_get(si_pre, "nullifier");
        ASSERT(json_get_bool(json_get(nf_pre, "cursor_known")));
        ASSERT_EQ(json_get_int(json_get(nf_pre, "activation_cursor")), boundary);
        ASSERT(json_get_bool(json_get(nf_pre, "gap_blocker_active")));
        ASSERT(json_get_bool(json_get(nf_pre, "gap")));

        ASSERT_STR_EQ(json_get_str(json_get(si_pre, "status")),
                     "gap_anchor_backfill_pending");
        json_free(&pre);

        /* Simulate the exact atomic cure: write the complete historical rows,
         * then flip BOTH markers to zero in one transaction — the same
         * sequence shielded_history_import_from_chainstate performs. */
        struct incremental_merkle_tree spr_tree, sap_tree;
        sprout_tree_init(&spr_tree);
        sapling_tree_init(&sap_tree);
        struct uint256 spr_leaf, sap_leaf;
        rcs_leaf(&spr_leaf, 0x11);
        rcs_leaf(&sap_leaf, 0x22);
        incremental_tree_append(&spr_tree, &spr_leaf);
        incremental_tree_append(&sap_tree, &sap_leaf);
        ASSERT(anchor_kv_add_tree(db, ANCHOR_POOL_SPROUT, &spr_tree, 10));
        ASSERT(anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &sap_tree, 20));

        uint8_t spr_nf[32], sap_nf[32];
        rcs_nf(spr_nf, 0x01);
        rcs_nf(sap_nf, 0x02);
        ASSERT(nullifier_kv_add(db, spr_nf, NULLIFIER_POOL_SPROUT, 10));
        ASSERT(nullifier_kv_add(db, sap_nf, NULLIFIER_POOL_SAPLING, 20));

        char *err = NULL;
        ASSERT(sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err)
               == SQLITE_OK);
        ASSERT(anchor_kv_publish_full_replay_complete_in_tx(db, boundary));
        ASSERT(nullifier_kv_publish_full_replay_complete_in_tx(db, boundary));
        ASSERT(sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK);
        utxo_apply_anchor_gap_blocker_refresh(db);
        utxo_apply_nullifier_gap_blocker_refresh(db);

        struct json_value post;
        json_init(&post);
        ASSERT(rom_compile_status_dump_state_json(&post, NULL));
        const struct json_value *si_post = json_get(&post, "shielded_import");
        ASSERT(si_post && si_post->type == JSON_OBJ);

        const struct json_value *anchor_post = json_get(si_post, "anchor");
        ASSERT_EQ(json_get_int(json_get(anchor_post, "sprout_activation_cursor")),
                  (int64_t)0);
        ASSERT_EQ(json_get_int(json_get(anchor_post, "sapling_activation_cursor")),
                  (int64_t)0);
        ASSERT(!json_get_bool(json_get(anchor_post, "gap_blocker_active")));
        ASSERT(!json_get_bool(json_get(anchor_post, "gap")));
        ASSERT_EQ(json_get_int(json_get(anchor_post, "sprout_anchors_imported")),
                  (int64_t)1);
        ASSERT_EQ(json_get_int(json_get(anchor_post, "sapling_anchors_imported")),
                  (int64_t)1);

        const struct json_value *nf_post = json_get(si_post, "nullifier");
        ASSERT_EQ(json_get_int(json_get(nf_post, "activation_cursor")),
                  (int64_t)0);
        ASSERT(!json_get_bool(json_get(nf_post, "gap_blocker_active")));
        ASSERT(!json_get_bool(json_get(nf_post, "gap")));
        ASSERT_EQ(json_get_int(json_get(nf_post, "sprout_nullifiers_imported")),
                  (int64_t)1);
        ASSERT_EQ(json_get_int(json_get(nf_post, "sapling_nullifiers_imported")),
                  (int64_t)1);

        ASSERT_STR_EQ(json_get_str(json_get(si_post, "status")), "complete");
        /* The resume cursor: utxo_apply hasn't run in this fixture, so it
         * simply must be a well-formed non-negative height, honestly derived
         * from the SAME live counter fold.height already reads. */
        ASSERT(json_get_int(json_get(si_post, "utxo_apply_next_height")) >= 0);

        json_free(&post);
        blocker_reset_for_testing();
        progress_store_close();
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;

    return failures;
}

/* Build a synthetic zcl.rom_compile.v1 `state` object (the shape
 * rom_compile_status_dump_state_json produces) with hand-picked
 * percent/ETA/stage values — independent of any live process-global
 * counter, so the renderer assertions are fully deterministic. */
static void build_fixture(struct json_value *out)
{
    json_init(out);
    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.rom_compile.v1");

    struct json_value fold;
    json_init(&fold);
    json_set_object(&fold);
    json_push_kv_bool(&fold, "active", true);
    json_push_kv_str(&fold, "mode", "from_genesis");
    json_push_kv_int(&fold, "height", 2200000);
    json_push_kv_int(&fold, "target", 3056758);
    json_push_kv_real(&fold, "percent", 71.99);
    json_push_kv_int(&fold, "remaining_blocks", 856758);
    json_push_kv_real(&fold, "rate_blk_s", 32.5);
    json_push_kv_int(&fold, "eta_seconds", 26362);
    json_push_kv_str(&fold, "eta_human", "7h19m22s");
    json_push_kv(out, "fold", &fold);
    json_free(&fold);

    struct json_value stages;
    json_init(&stages);
    json_set_array(&stages);
    static const struct { const char *ab; const char *name; int64_t us; }
        rows[8] = {
            { "ha", "header_admit", 5 },     { "vh", "validate_headers", 12 },
            { "bf", "body_fetch", 40 },      { "bp", "body_persist", 90 },
            { "sv", "script_validate", 210 },{ "pv", "proof_validate", 812 },
            { "ua", "utxo_apply", 150 },     { "tf", "tip_finalize", 8 },
        };
    for (size_t i = 0; i < 8; i++) {
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_str(&item, "abbrev", rows[i].ab);
        json_push_kv_str(&item, "stage", rows[i].name);
        json_push_kv_int(&item, "cursor", 2200000);
        json_push_kv_int(&item, "step_us_ewma", rows[i].us);
        json_push_kv_int(&item, "steps_per_sec",
                         rows[i].us > 0 ? 1000000 / rows[i].us : 0);
        json_push_back(&stages, &item);
        json_free(&item);
    }
    json_push_kv(out, "stages", &stages);
    json_free(&stages);
    json_push_kv_str(out, "bottleneck_stage", "pv");
    json_push_kv_int(out, "commit_us_ewma", 1400);

    struct json_value layers;
    json_init(&layers);
    json_set_object(&layers);
    {
        struct json_value l;
        json_init(&l); json_set_object(&l);
        json_push_kv_bool(&l, "present", true);
        json_push_kv_int(&l, "height", 3056758);
        json_push_kv_str(&l, "sha3_prefix", "5817f0ec");
        json_push_kv(&layers, "rom_checkpoint", &l); json_free(&l);
    }
    {
        struct json_value l;
        json_init(&l); json_set_object(&l);
        json_push_kv_bool(&l, "present", true);
        json_push_kv_int(&l, "segment_count", 12);
        json_push_kv_int(&l, "present_count", 12);
        json_push_kv_int(&l, "verified_count", 11);
        json_push_kv_int(&l, "min_height", 0);
        json_push_kv_int(&l, "max_height", 2199000);
        json_push_kv(&layers, "sealed_history", &l); json_free(&l);
    }
    {
        struct json_value l;
        json_init(&l); json_set_object(&l);
        json_push_kv_bool(&l, "present", false);
        json_push_kv_int(&l, "ratified_height", -1);
        json_push_kv(&layers, "sealed_base_receipt", &l); json_free(&l);
    }
    {
        struct json_value l;
        json_init(&l); json_set_object(&l);
        json_push_kv_bool(&l, "present", true);
        json_push_kv_int(&l, "coins_best_height", 2200000);
        json_push_kv(&layers, "delta", &l); json_free(&l);
    }
    {
        struct json_value l;
        json_init(&l); json_set_object(&l);
        json_push_kv_bool(&l, "present", true);
        json_push_kv_int(&l, "hstar", 2200000);
        json_push_kv_int(&l, "external_tip_height", 2200000);
        json_push_kv(&layers, "tip_ring", &l); json_free(&l);
    }
    {
        struct json_value l;
        json_init(&l); json_set_object(&l);
        json_push_kv_bool(&l, "present", true);
        json_push_kv_int(&l, "last_height", 2199999);
        json_push_kv_int(&l, "generations", 3);
        json_push_kv(&layers, "bundle_export", &l); json_free(&l);
    }
    json_push_kv(out, "layers", &layers);
    json_free(&layers);

    struct json_value si;
    json_init(&si);
    json_set_object(&si);
    json_push_kv_bool(&si, "progress_store_open", true);
    json_push_kv_bool(&si, "snapshot_complete", true);
    json_push_kv_str(&si, "snapshot_status", "available");
    {
        struct json_value a;
        json_init(&a); json_set_object(&a);
        json_push_kv_bool(&a, "cursor_known", true);
        json_push_kv_int(&a, "sprout_activation_cursor", 0);
        json_push_kv_int(&a, "sapling_activation_cursor", 0);
        json_push_kv_bool(&a, "gap_blocker_active", false);
        json_push_kv_bool(&a, "gap", false);
        json_push_kv_int(&a, "sprout_anchors_imported", 128);
        json_push_kv_int(&a, "sapling_anchors_imported", 256);
        json_push_kv(&si, "anchor", &a); json_free(&a);
    }
    {
        struct json_value n;
        json_init(&n); json_set_object(&n);
        json_push_kv_bool(&n, "cursor_known", true);
        json_push_kv_int(&n, "activation_cursor", 0);
        json_push_kv_bool(&n, "gap_blocker_active", false);
        json_push_kv_bool(&n, "gap", false);
        json_push_kv_int(&n, "sprout_nullifiers_imported", 64);
        json_push_kv_int(&n, "sapling_nullifiers_imported", 96);
        json_push_kv(&si, "nullifier", &n); json_free(&n);
    }
    json_push_kv_int(&si, "utxo_apply_next_height", 2200001);
    json_push_kv_str(&si, "status", "complete");
    json_push_kv(out, "shielded_import", &si);
    json_free(&si);
}

static int test_rom_compile_render_active_fixture(void)
{
    int failures = 0;

    TEST("rom_compile render: synthetic fixture shows the expected "
         "percent/ETA/bottleneck/ladder") {
        struct json_value fixture;
        build_fixture(&fixture);

        char text[4096];
        rom_compile_render_ascii(&fixture, text, sizeof(text));

        ASSERT(strstr(text, "71.99%") != NULL);
        ASSERT(strstr(text, "rate=32.5 blk/s") != NULL);
        ASSERT(strstr(text, "eta=7h19m22s") != NULL);
        /* The bottleneck stage (pv, 812us — the max of the 8 fixture rows)
         * is marked. */
        const char *pv_line = strstr(text, " pv ");
        ASSERT(pv_line != NULL);
        ASSERT(strstr(pv_line, "*") != NULL);
        /* Ladder: ROM checkpoint / sealed history / delta / tip ring
         * present ("[#]"); sealed base+receipt absent ("[ ]"). */
        ASSERT(strstr(text, "[#] ROM checkpoint") != NULL);
        ASSERT(strstr(text, "[#] Sealed history") != NULL);
        ASSERT(strstr(text, "[ ] Sealed base+receipt") != NULL);
        ASSERT(strstr(text, "[#] Delta frontier") != NULL);
        ASSERT(strstr(text, "[#] Tip ring") != NULL);

        json_free(&fixture);
        PASS();
    } _test_next:;

    return failures;
}

static int test_rom_compile_render_idle_fixture(void)
{
    int failures = 0;

    TEST("rom_compile render: idle fold (no active fold) states so, "
         "not an error") {
        struct json_value fixture;
        build_fixture(&fixture);
        struct json_value *fold =
            (struct json_value *)json_get(&fixture, "fold");
        json_set_bool((struct json_value *)json_get(fold, "active"), false);
        json_set_str((struct json_value *)json_get(fold, "mode"), "idle");
        json_set_real((struct json_value *)json_get(fold, "percent"), 100.0);

        char text[4096];
        rom_compile_render_ascii(&fixture, text, sizeof(text));
        ASSERT(strstr(text, "100.00%") != NULL);
        ASSERT(strstr(text, "no fold active") != NULL);

        json_free(&fixture);
        PASS();
    } _test_next:;

    return failures;
}

static int test_rom_compile_render_pipeline_rows(void)
{
    int failures = 0;

    TEST("rom_compile render: the ROM pipeline promotes fold/seal/manifest/"
         "bundle to first-class rows") {
        struct json_value fixture;
        build_fixture(&fixture);

        char text[8192];
        rom_compile_render_ascii(&fixture, text, sizeof(text));

        ASSERT(strstr(text,
                     "ROM pipeline (fold -> seal -> manifest -> bundle):")
               != NULL);
        /* fold present (height 2200000), seal present (12 segments),
         * manifest present (verified 11), bundle export present (last 2199999,
         * 3 generations). */
        ASSERT(strstr(text, "[#] fold") != NULL);
        ASSERT(strstr(text, "height=2200000/3056758") != NULL);
        ASSERT(strstr(text, "[#] seal") != NULL);
        ASSERT(strstr(text, "12/12 segments sealed") != NULL);
        ASSERT(strstr(text, "[#] manifest") != NULL);
        ASSERT(strstr(text, "verified=11/12") != NULL);
        ASSERT(strstr(text, "[#] bundle export") != NULL);
        ASSERT(strstr(text, "last_height=2199999 generations=3") != NULL);

        json_free(&fixture);
        PASS();
    } _test_next:;

    return failures;
}

static int test_rom_compile_render_bundle_absent(void)
{
    int failures = 0;

    TEST("rom_compile render: an absent bundle_export renders 'absent' "
         "gracefully, never a crash") {
        struct json_value fixture;
        build_fixture(&fixture);
        /* Flip the bundle_export layer to not-present (no export yet). */
        struct json_value *layers =
            (struct json_value *)json_get(&fixture, "layers");
        struct json_value *bx =
            (struct json_value *)json_get(layers, "bundle_export");
        json_set_bool((struct json_value *)json_get(bx, "present"), false);

        char text[8192];
        rom_compile_render_ascii(&fixture, text, sizeof(text));
        ASSERT(strstr(text, "[ ] bundle export") != NULL);
        ASSERT(strstr(text, "absent") != NULL);

        json_free(&fixture);
        PASS();
    } _test_next:;

    return failures;
}

static int test_rom_compile_render_null_state(void)
{
    int failures = 0;

    TEST("rom_compile render: NULL state renders a diagnostic, never "
         "crashes") {
        char text[256];
        rom_compile_render_ascii(NULL, text, sizeof(text));
        ASSERT(text[0] != '\0');
        PASS();
    } _test_next:;

    return failures;
}

static int test_rom_compile_render_shielded_import_healthy(void)
{
    int failures = 0;

    TEST("rom_compile render: healthy shielded_import (no gap) renders one "
         "compact status line, no per-pool noise") {
        struct json_value fixture;
        build_fixture(&fixture);

        char text[8192];
        rom_compile_render_ascii(&fixture, text, sizeof(text));

        ASSERT(strstr(text,
                     "shielded history: complete (utxo_apply resumes from "
                     "height=2200001)") != NULL);
        ASSERT(strstr(text, "anchor:") == NULL);
        ASSERT(strstr(text, "nullifier:") == NULL);

        json_free(&fixture);
        PASS();
    } _test_next:;

    return failures;
}

static int test_rom_compile_render_shielded_import_gap(void)
{
    int failures = 0;

    TEST("rom_compile render: a standing anchor/nullifier gap surfaces the "
         "per-pool cursor/blocker/imported-count detail") {
        struct json_value fixture;
        build_fixture(&fixture);
        struct json_value *si =
            (struct json_value *)json_get(&fixture, "shielded_import");
        json_set_str((struct json_value *)json_get(si, "status"),
                    "gap_anchor_backfill_pending");
        struct json_value *anchor =
            (struct json_value *)json_get(si, "anchor");
        json_set_bool((struct json_value *)json_get(anchor, "gap"), true);
        json_set_bool(
            (struct json_value *)json_get(anchor, "gap_blocker_active"), true);
        json_set_int(
            (struct json_value *)json_get(anchor, "sprout_activation_cursor"),
            3050000);
        json_set_int(
            (struct json_value *)json_get(anchor, "sapling_activation_cursor"),
            3050000);
        json_set_int(
            (struct json_value *)json_get(anchor, "sprout_anchors_imported"),
            0);
        json_set_int(
            (struct json_value *)json_get(anchor, "sapling_anchors_imported"),
            0);

        char text[8192];
        rom_compile_render_ascii(&fixture, text, sizeof(text));

        ASSERT(strstr(text, "shielded history: gap_anchor_backfill_pending")
               != NULL);
        ASSERT(strstr(text,
                     "anchor:    sprout_cursor=3050000 "
                     "sapling_cursor=3050000 gap_blocker=active "
                     "imported(sprout=0 sapling=0)") != NULL);
        /* The nullifier pool in this fixture is still healthy — its detail
         * line still renders because the SECTION gate is anchor_gap ||
         * nullifier_gap, not per-pool; both pools get their own line so the
         * operator can tell which one is still gated. */
        ASSERT(strstr(text, "nullifier: activation_cursor=0 "
                           "gap_blocker=clear imported(sprout=64 "
                           "sapling=96)") != NULL);

        json_free(&fixture);
        PASS();
    } _test_next:;

    return failures;
}

int test_rom_compile_status(void)
{
    int failures = 0;
    failures += test_rom_compile_dump_idle_shape();
    failures += test_rom_compile_dump_active_mode();
    failures += test_rom_compile_dump_shielded_import_transition();
    failures += test_rom_compile_render_active_fixture();
    failures += test_rom_compile_render_idle_fixture();
    failures += test_rom_compile_render_pipeline_rows();
    failures += test_rom_compile_render_bundle_absent();
    failures += test_rom_compile_render_null_state();
    failures += test_rom_compile_render_shielded_import_healthy();
    failures += test_rom_compile_render_shielded_import_gap();
    return failures;
}
