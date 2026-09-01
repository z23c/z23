/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_shielded_history_promote — the VERIFIED promote of a FINISHED producer's
 * below-checkpoint shielded history into a WEDGED COPY datadir
 * (engine/services/src/shielded_history_promote_service.c).
 *
 * Hermetic: two temp progress.kv datadirs (a finished "producer" with cursors
 * 0/0/0 and a wedged "target" with positive cursors + empty below-cursor tables)
 * and a tiny in-RAM header chain whose per-height hashFinalSaplingRoot matches
 * the producer's Sapling frontiers. The body cross-check is injected through the
 * service's test seam, so no local-body datadir is needed. Scaled-down heights
 * (Sapling activation = 2, boundary = 6) are passed as service params.
 *
 * Proves the six gates:
 *   happy path      — complete producer installs, all three cursors flip to 0,
 *                     both gap blockers clear, a below-cursor Sapling anchor
 *                     lookup returns FOUND.
 *   G2b (missing)   — a producer missing one below-boundary Sapling frontier is
 *                     refused; cursors stay positive.
 *   G5 (bound)      — a producer row above the checkpoint height is refused.
 *   G3/G4 (xcheck)  — a failing body cross-check refuses sprout+nullifier install.
 *   G1 (producer)   — a producer with positive cursors is refused.
 *   placeholder     — the default (real-symbol) cross-check returns false, so the
 *                     production default is fail-closed. */

#include "test/test_core.h"

#include "chain/chain.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/shielded_history_body_crosscheck.h"
#include "services/shielded_history_promote_service.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define P_ACTIVATION 2       /* scaled-down Sapling activation height */
#define P_BOUNDARY   6       /* the wedge boundary (positive target cursor) */
#define P_CHECKPOINT 6       /* compiled-checkpoint height for the happy path */
#define P_TOP        6       /* highest header-chain height built */

#define P_CHECK(name, expr) do {                            \
    printf("  shielded_history_promote: %s... ", (name));   \
    if ((expr)) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

/* ── fixture builders ── */

static void p_fill(struct uint256 *h, uint8_t seed, size_t idx)
{
    for (size_t i = 0; i < 32; i++)
        h->data[i] = (uint8_t)(seed ^ (idx * 7 + i));
}

/* Sapling frontier at height h = append one distinct commitment per height in
 * [activation, h]. Its root is the header-committed hashFinalSaplingRoot at h. */
static void p_sapling(int64_t h, int64_t activation,
                      struct incremental_merkle_tree *tree,
                      struct uint256 *root)
{
    sapling_tree_init(tree);
    for (int64_t k = activation; k <= h; k++) {
        struct uint256 cm;
        p_fill(&cm, 0x5A, (size_t)k);
        incremental_tree_append(tree, &cm);
    }
    incremental_tree_root(tree, root);
}

static void p_sprout(size_t n, struct incremental_merkle_tree *tree,
                     struct uint256 *root)
{
    sprout_tree_init(tree);
    for (size_t i = 0; i < n; i++) {
        struct uint256 cm;
        p_fill(&cm, 0xA5, i + 1);
        incremental_tree_append(tree, &cm);
    }
    incremental_tree_root(tree, root);
}

/* Build the in-RAM header chain bi[0..P_TOP]: pprev-linked, with the
 * header-committed final Sapling root per height (empty below activation). */
static void p_build_header_chain(struct block_index *bi, int count,
                                 int activation)
{
    for (int h = 0; h < count; h++) {
        block_index_init(&bi[h]);
        bi[h].nHeight = h;
        bi[h].pprev = (h > 0) ? &bi[h - 1] : NULL;
        p_fill(&bi[h].hashBlock, 0xB1, (size_t)h);
        bi[h].phashBlock = &bi[h].hashBlock;
        if (h >= activation) {
            struct incremental_merkle_tree tr;
            p_sapling(h, activation, &tr, &bi[h].hashFinalSaplingRoot);
        } else {
            struct incremental_merkle_tree e;
            sapling_tree_init(&e);
            incremental_tree_root(&e, &bi[h].hashFinalSaplingRoot);
        }
        block_index_build_skip(&bi[h]);
    }
}

/* Build a producer progress.kv at `dir`: cursors set to `cursor` (0 = a finished
 * from-genesis store), Sapling frontiers at heights [activation, 5] except
 * `omit_sap_h` (-1 = none omitted), plus sprout frontiers + nullifiers. */
static bool p_build_producer(const char *dir, int64_t cursor,
                             int64_t omit_sap_h)
{
    if (!progress_store_open(dir))
        return false;
    sqlite3 *db = progress_store_db();
    bool ok = db && anchor_kv_initialize_history(db, cursor) &&
              nullifier_kv_initialize_history(db, cursor);

    for (int64_t h = P_ACTIVATION; ok && h <= 5; h++) {
        if (h == omit_sap_h)
            continue;
        struct incremental_merkle_tree tr;
        struct uint256 root;
        p_sapling(h, P_ACTIVATION, &tr, &root);
        ok = anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &tr, h);
    }

    /* two sprout frontiers below the checkpoint */
    for (int i = 0; ok && i < 2; i++) {
        struct incremental_merkle_tree tr;
        struct uint256 root;
        p_sprout((size_t)(i + 2), &tr, &root);
        ok = anchor_kv_add_tree(db, ANCHOR_POOL_SPROUT, &tr, (int64_t)(1 + 2 * i));
    }

    /* two sapling + two sprout nullifiers below the checkpoint */
    for (int i = 0; ok && i < 2; i++) {
        struct uint256 nf;
        p_fill(&nf, 0x51, (size_t)i + 100);
        ok = nullifier_kv_add(db, nf.data, NULLIFIER_POOL_SAPLING,
                              (int64_t)(3 + i));
    }
    for (int i = 0; ok && i < 2; i++) {
        struct uint256 nf;
        p_fill(&nf, 0x53, (size_t)i + 200);
        ok = nullifier_kv_add(db, nf.data, NULLIFIER_POOL_SPROUT,
                              (int64_t)(2 + i));
    }

    progress_store_close();
    return ok;
}

/* Open a wedged target progress.kv at `dir`: positive cursors + raised gap
 * blockers, empty below-cursor tables. Leaves the store OPEN. */
static sqlite3 *p_open_target_wedge(const char *dir)
{
    blocker_clear(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
    blocker_clear(UTXO_APPLY_NF_GAP_BLOCKER_ID);
    if (!progress_store_open(dir))
        return NULL;
    sqlite3 *db = progress_store_db();
    if (!db || !anchor_kv_initialize_history(db, P_BOUNDARY) ||
        !nullifier_kv_initialize_history(db, P_BOUNDARY)) {
        progress_store_close();
        return NULL;
    }
    utxo_apply_anchor_gap_blocker_refresh(db);
    utxo_apply_nullifier_gap_blocker_refresh(db);
    return db;
}

static bool p_anchor_cursor_is(sqlite3 *db, int pool, int64_t want)
{
    int64_t c = -1;
    bool found = false;
    return anchor_kv_activation_cursor(db, pool, &c, &found) && found &&
           c == want;
}

static bool p_nf_cursor_is(sqlite3 *db, int64_t want)
{
    int64_t c = -1;
    bool found = false;
    return nullifier_kv_activation_cursor(db, &c, &found) && found && c == want;
}

/* ── cross-check test-seam stubs ── */

static bool cc_pass(const char *copy, const char *producer, int64_t h,
                    struct crosscheck_result *out)
{
    (void)copy; (void)producer;
    if (out) {
        out->sprout_ok = true;
        out->nullifiers_ok = true;
        out->max_height = h;
        out->nf_count = 0;
        out->sprout_frontier_count = 0;
    }
    return true;
}

static bool cc_sprout_fail(const char *copy, const char *producer, int64_t h,
                           struct crosscheck_result *out)
{
    (void)copy; (void)producer; (void)h;
    if (out) {
        out->sprout_ok = false;      /* body re-derivation disagrees */
        out->nullifiers_ok = true;
        out->max_height = -1;
        out->nf_count = 0;
        out->sprout_frontier_count = 0;
    }
    return true;   /* infrastructure OK, but the verdict fails */
}

int test_shielded_history_promote(void);
int test_shielded_history_promote(void)
{
    int failures = 0;

    struct block_index hdr[P_TOP + 1];
    p_build_header_chain(hdr, P_TOP + 1, P_ACTIVATION);
    struct block_index *header_tip = &hdr[P_TOP];

    /* a below-boundary Sapling root to prove FOUND on the happy path (h=3) */
    struct uint256 r3;
    {
        struct incremental_merkle_tree t;
        p_sapling(3, P_ACTIVATION, &t, &r3);
    }

    /* ── Scenario A: HAPPY PATH — complete producer promotes, cursors flip ── */
    {
        char prod[256], tgt[256];
        test_make_tmpdir(prod, sizeof(prod), "promote_happy", "prod");
        test_make_tmpdir(tgt, sizeof(tgt), "promote_happy", "tgt");

        P_CHECK("build finished producer (cursors 0/0/0)",
                p_build_producer(prod, 0, -1));
        sqlite3 *db = p_open_target_wedge(tgt);
        P_CHECK("wedged target opens (cursors positive, blockers raised)",
                db != NULL);
        P_CHECK("anchor gap blocker raised before promote",
                blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID));
        P_CHECK("nullifier gap blocker raised before promote",
                blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));

        shielded_history_promote_set_crosscheck_for_test(cc_pass);
        struct shielded_promote_request req = {
            .target_progress_db = db,
            .target_copy_datadir = tgt,
            .producer_datadir = prod,
            .header_tip = header_tip,
            .sapling_activation_height = P_ACTIVATION,
            .checkpoint_height = P_CHECKPOINT,
        };
        struct shielded_promote_report rep;
        bool ok = shielded_history_promote_run(&req, &rep);
        shielded_history_promote_reset_crosscheck_for_test();

        P_CHECK("promote returns success", ok);
        P_CHECK("promote committed", rep.committed);
        P_CHECK("G2b sapling completeness held", rep.sapling_header_complete);
        P_CHECK("installed exactly 4 sapling frontiers (h=2..5)",
                rep.sapling_anchors_installed == 4);
        P_CHECK("installed 2 sprout frontiers", rep.sprout_anchors_installed == 2);
        P_CHECK("installed 2 sapling nullifiers",
                rep.sapling_nullifiers_installed == 2);
        P_CHECK("installed 2 sprout nullifiers",
                rep.sprout_nullifiers_installed == 2);

        /* all three cursors flipped to zero */
        P_CHECK("Sprout anchor cursor == 0",
                p_anchor_cursor_is(db, ANCHOR_POOL_SPROUT, 0));
        P_CHECK("Sapling anchor cursor == 0",
                p_anchor_cursor_is(db, ANCHOR_POOL_SAPLING, 0));
        P_CHECK("nullifier cursor == 0", p_nf_cursor_is(db, 0));

        /* both gap blockers cleared */
        P_CHECK("anchor gap blocker cleared after promote",
                !blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID));
        P_CHECK("nullifier gap blocker cleared after promote",
                !blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));

        /* a below-cursor Sapling anchor is now FOUND */
        P_CHECK("below-cursor Sapling anchor (h=3) lookup is FOUND",
                anchor_kv_get(db, ANCHOR_POOL_SAPLING, &r3, NULL, NULL) ==
                    ANCHOR_KV_FOUND);

        progress_store_close();
        test_rm_rf_recursive(prod);
        test_rm_rf_recursive(tgt);
    }

    /* ── Scenario B: G2b — a missing below-boundary Sapling frontier refuses ── */
    {
        char prod[256], tgt[256];
        test_make_tmpdir(prod, sizeof(prod), "promote_g2b", "prod");
        test_make_tmpdir(tgt, sizeof(tgt), "promote_g2b", "tgt");

        P_CHECK("build producer with h=4 Sapling frontier OMITTED",
                p_build_producer(prod, 0, 4));
        sqlite3 *db = p_open_target_wedge(tgt);
        P_CHECK("wedged target opens (g2b)", db != NULL);

        shielded_history_promote_set_crosscheck_for_test(cc_pass);
        struct shielded_promote_request req = {
            .target_progress_db = db, .target_copy_datadir = tgt,
            .producer_datadir = prod, .header_tip = header_tip,
            .sapling_activation_height = P_ACTIVATION,
            .checkpoint_height = P_CHECKPOINT,
        };
        struct shielded_promote_report rep;
        bool ok = shielded_history_promote_run(&req, &rep);
        shielded_history_promote_reset_crosscheck_for_test();

        P_CHECK("G2b: promote REFUSES a below-boundary Sapling hole",
                !ok && !rep.committed);
        P_CHECK("G2b: Sprout anchor cursor still positive",
                p_anchor_cursor_is(db, ANCHOR_POOL_SPROUT, P_BOUNDARY));
        P_CHECK("G2b: Sapling anchor cursor still positive",
                p_anchor_cursor_is(db, ANCHOR_POOL_SAPLING, P_BOUNDARY));
        P_CHECK("G2b: nullifier cursor still positive",
                p_nf_cursor_is(db, P_BOUNDARY));
        P_CHECK("G2b: gap blockers stay raised",
                blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID) &&
                blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID));

        progress_store_close();
        test_rm_rf_recursive(prod);
        test_rm_rf_recursive(tgt);
    }

    /* ── Scenario C: G5 — a producer row above the checkpoint refuses ── */
    {
        char prod[256], tgt[256];
        test_make_tmpdir(prod, sizeof(prod), "promote_g5", "prod");
        test_make_tmpdir(tgt, sizeof(tgt), "promote_g5", "tgt");

        P_CHECK("build complete producer (g5)", p_build_producer(prod, 0, -1));
        sqlite3 *db = p_open_target_wedge(tgt);
        P_CHECK("wedged target opens (g5)", db != NULL);

        shielded_history_promote_set_crosscheck_for_test(cc_pass);
        struct shielded_promote_request req = {
            .target_progress_db = db, .target_copy_datadir = tgt,
            .producer_datadir = prod, .header_tip = header_tip,
            .sapling_activation_height = P_ACTIVATION,
            .checkpoint_height = 3,   /* producer has rows at h=4,5 > 3 */
        };
        struct shielded_promote_report rep;
        bool ok = shielded_history_promote_run(&req, &rep);
        shielded_history_promote_reset_crosscheck_for_test();

        P_CHECK("G5: promote REFUSES a producer row above the checkpoint",
                !ok && !rep.committed);
        P_CHECK("G5: cursors stay positive",
                p_anchor_cursor_is(db, ANCHOR_POOL_SAPLING, P_BOUNDARY) &&
                p_nf_cursor_is(db, P_BOUNDARY));

        progress_store_close();
        test_rm_rf_recursive(prod);
        test_rm_rf_recursive(tgt);
    }

    /* ── Scenario D: G3/G4 — a failing body cross-check refuses ── */
    {
        char prod[256], tgt[256];
        test_make_tmpdir(prod, sizeof(prod), "promote_xcheck", "prod");
        test_make_tmpdir(tgt, sizeof(tgt), "promote_xcheck", "tgt");

        P_CHECK("build complete producer (xcheck)",
                p_build_producer(prod, 0, -1));
        sqlite3 *db = p_open_target_wedge(tgt);
        P_CHECK("wedged target opens (xcheck)", db != NULL);

        shielded_history_promote_set_crosscheck_for_test(cc_sprout_fail);
        struct shielded_promote_request req = {
            .target_progress_db = db, .target_copy_datadir = tgt,
            .producer_datadir = prod, .header_tip = header_tip,
            .sapling_activation_height = P_ACTIVATION,
            .checkpoint_height = P_CHECKPOINT,
        };
        struct shielded_promote_report rep;
        bool ok = shielded_history_promote_run(&req, &rep);
        shielded_history_promote_reset_crosscheck_for_test();

        P_CHECK("G3/G4: promote REFUSES a failing body cross-check",
                !ok && !rep.committed);
        P_CHECK("G3/G4: sprout_crosscheck_ok reported false",
                !rep.sprout_crosscheck_ok);
        P_CHECK("G3/G4: cursors stay positive",
                p_anchor_cursor_is(db, ANCHOR_POOL_SAPLING, P_BOUNDARY) &&
                p_nf_cursor_is(db, P_BOUNDARY));

        progress_store_close();
        test_rm_rf_recursive(prod);
        test_rm_rf_recursive(tgt);
    }

    /* ── Scenario E: G1 — a producer with positive cursors refuses ── */
    {
        char prod[256], tgt[256];
        test_make_tmpdir(prod, sizeof(prod), "promote_g1", "prod");
        test_make_tmpdir(tgt, sizeof(tgt), "promote_g1", "tgt");

        P_CHECK("build producer with POSITIVE cursors (not finished)",
                p_build_producer(prod, 5, -1));
        sqlite3 *db = p_open_target_wedge(tgt);
        P_CHECK("wedged target opens (g1)", db != NULL);

        shielded_history_promote_set_crosscheck_for_test(cc_pass);
        struct shielded_promote_request req = {
            .target_progress_db = db, .target_copy_datadir = tgt,
            .producer_datadir = prod, .header_tip = header_tip,
            .sapling_activation_height = P_ACTIVATION,
            .checkpoint_height = P_CHECKPOINT,
        };
        struct shielded_promote_report rep;
        bool ok = shielded_history_promote_run(&req, &rep);
        shielded_history_promote_reset_crosscheck_for_test();

        P_CHECK("G1: promote REFUSES a non-finished producer", !ok &&
                !rep.committed);
        P_CHECK("G1: target cursors unchanged (still positive)",
                p_anchor_cursor_is(db, ANCHOR_POOL_SPROUT, P_BOUNDARY) &&
                p_anchor_cursor_is(db, ANCHOR_POOL_SAPLING, P_BOUNDARY) &&
                p_nf_cursor_is(db, P_BOUNDARY));

        progress_store_close();
        test_rm_rf_recursive(prod);
        test_rm_rf_recursive(tgt);
    }

    /* ── Scenario F: placeholder default (real symbol) is fail-closed ── */
    {
        char prod[256], tgt[256];
        test_make_tmpdir(prod, sizeof(prod), "promote_default", "prod");
        test_make_tmpdir(tgt, sizeof(tgt), "promote_default", "tgt");

        P_CHECK("build complete producer (default)",
                p_build_producer(prod, 0, -1));
        sqlite3 *db = p_open_target_wedge(tgt);
        P_CHECK("wedged target opens (default)", db != NULL);

        /* NO seam set — resolves to the REAL linked symbol (placeholder returns
         * false until lane B lands its verifier). */
        shielded_history_promote_reset_crosscheck_for_test();
        struct shielded_promote_request req = {
            .target_progress_db = db, .target_copy_datadir = tgt,
            .producer_datadir = prod, .header_tip = header_tip,
            .sapling_activation_height = P_ACTIVATION,
            .checkpoint_height = P_CHECKPOINT,
        };
        struct shielded_promote_report rep;
        bool ok = shielded_history_promote_run(&req, &rep);

        P_CHECK("default (real-symbol) cross-check is fail-closed",
                !ok && !rep.committed);
        P_CHECK("default: cursors stay positive",
                p_anchor_cursor_is(db, ANCHOR_POOL_SAPLING, P_BOUNDARY) &&
                p_nf_cursor_is(db, P_BOUNDARY));

        progress_store_close();
        test_rm_rf_recursive(prod);
        test_rm_rf_recursive(tgt);
    }

    /* free heap-allocated block-index solution buffers (none allocated here, but
     * keep the contract explicit for the fixture chain). */
    (void)header_tip;
    return failures;
}
