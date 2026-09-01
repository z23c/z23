/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * SYNC-STRENGTH Workflow-2 Lane-3 (shielded-verification tests).
 *
 * Proves the contract two sibling lanes are landing on separate branches:
 *
 *   W2-L1 (engine/controllers/src/sync_controller_sapling_tree.c): the
 *   sapling_tree_rebuild() replay must ADVANCE-OR-NAME-A-BLOCKER at every
 *   height, never silently `continue` past a block whose body is
 *   unreadable/missing (today's ":BLOCK_HAVE_DATA" and "nDataPos >=
 *   cached_size" continues), and must check the folded root against the
 *   header-committed root DENSELY (near the defect height), not only at a
 *   100k checkpoint or the final capped tip — the current shape turns a
 *   single bad/missing block at height H into a "root mismatch" reported
 *   tens of thousands of blocks later at the tip, which is useless for
 *   triage.
 *
 *   W2-L2 (engine/jobs/src/utxo_apply_anchors.c + engine/modules/storage/src/anchor_kv.c):
 *   a snapshot/refold seed that resets the anchor-history marker to
 *   "incomplete below N" (anchor_kv_reset_mark_empty_below_in_tx) must not
 *   leave sapling_anchors EMPTY at N — a verified frontier row belongs at
 *   the seed height so the very next Sapling-output block above N folds
 *   instead of failing closed forever (the "birth defect" this repo's
 *   anchor_kv.h/sapling_anchor_frontier_unavailable.c already document).
 *
 * Test isolation: only files under tests/harness/src are edited by this lane — the two
 * files above are owned by W2-L1/W2-L2 on separate branches. Where this
 * file's assertions describe a contract the current `main` code does not
 * implement yet (deliverables 1 and 2), that is deliberate: the test
 * documents the EXPECTED post-fix behavior and is marked PENDING below.
 * Deliverable 3's low-level anchor_kv/utxo_apply_anchors contract already
 * exists on `main` (see tests/harness/src/test_sapling_anchor_frontier_condition.c)
 * so its test is a green regression proof today, not a pending assertion.
 * Deliverable 4 proves the underlying tree math nobody in this program is
 * supposed to touch stays bit-identical.
 *
 * ASSUMED interface names (reconcile at integration if W2-L1 picks
 * different ones):
 *   - The missing/corrupted-body fail-closed path reuses the EXISTING
 *     sapling_tree_rebuild_raise_fail_blocker() plumbing (blocker id
 *     "sapling_tree_rebuild.fail_closed", reason containing "height=<H>"
 *     at the DEFECT height H, not the capped chain_tip) — this is the same
 *     mechanism every other fail_reason in sapling_tree_rebuild() already
 *     uses (see sync_controller_sapling_tree.c), so the minimal fix is
 *     replacing the two silent `continue` sites with a `fail_reason =
 *     "..."; fail_height = h; goto fail;` triple, not a new blocker id. */

#include "test/test_core.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "controllers/sync_controller.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_delta.h"
#include "models/database.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define SST_SAPLING_ACTIVATION 476969 /* matches sapling_tree_rebuild()'s
                                       * hardcoded activation height */

static void sst_init_index(struct block_index *bi, int height, uint8_t tag)
{
    block_index_init(bi);
    bi->nHeight = height;
    memset(bi->hashBlock.data, tag, 32);
    bi->phashBlock = &bi->hashBlock;
}

/* Writes a real one-Sapling-output block to <dir>'s block files and fills
 * in *pos. The commitment written is `cm` — deliberately a caller-chosen
 * parameter so a "corrupted body" scenario can write a DIFFERENT value than
 * what was folded into the header-side expectation tree. */
static bool sst_write_output_block(const char *dir, const struct uint256 *cm,
                                   struct disk_block_pos *pos_out)
{
    struct block blk;
    block_init(&blk);
    blk.vtx = zcl_calloc(1, sizeof(struct transaction), "sst_block_vtx");
    if (!blk.vtx) {
        block_free(&blk);
        return false;
    }
    blk.num_vtx = 1;
    transaction_init(&blk.vtx[0]);
    blk.vtx[0].overwintered = true;
    blk.vtx[0].version = SAPLING_TX_VERSION;
    blk.vtx[0].version_group_id = SAPLING_VERSION_GROUP_ID;
    blk.vtx[0].v_shielded_output = zcl_calloc(
        1, sizeof(struct output_description), "sst_block_out");
    if (!blk.vtx[0].v_shielded_output) {
        block_free(&blk);
        return false;
    }
    blk.vtx[0].num_shielded_output = 1;
    blk.vtx[0].v_shielded_output[0].cm = *cm;
    transaction_compute_hash(&blk.vtx[0]);

    blk.header.nVersion = 4;
    blk.header.nTime = 1700000000u;
    blk.header.nBits = 0x2000ffffu;
    struct uint256 txid = blk.vtx[0].hash;
    blk.header.hashMerkleRoot = compute_merkle_root(&txid, 1);

    static const unsigned char msg[4] = {0x24, 0xe9, 0x27, 0x64};
    disk_block_pos_init(pos_out);
    return write_block_to_disk(&blk, pos_out, dir, msg);
}

/* Scans the active blocker registry for any "sapling_tree_rebuild.*" record
 * whose reason contains `needle`. Robust to which exact blocker id the fix
 * ends up using — the load-bearing claim is "the REASON TEXT names this
 * height", not the exact id string. */
static bool sst_blocker_reason_mentions(const char *needle)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (strncmp(snaps[i].id, "sapling_tree_rebuild.", 21) != 0)
            continue;
        if (strstr(snaps[i].reason, needle))
            return true;
    }
    return false;
}

/* ── Deliverable 1: SKIP-ACCOUNTING ──────────────────────────────────────
 * A block in the middle of the replay window has NO on-disk body
 * (BLOCK_HAVE_DATA clear) even though the header chain's hashFinalSaplingRoot
 * values were computed assuming its commitment folded in. Today's
 * sapling_tree_rebuild() hit `if (!(bi->nStatus & BLOCK_HAVE_DATA))
 * continue;` and silently skipped it — the resulting root mismatch was only
 * ever detected at the capped chain_tip (10 blocks later here; ~100k+ blocks
 * later on the live replay window), not near the actual defect height.
 *
 * Post-W2-L1 the rebuild names a TYPED blocker close to the defect instead of
 * silently skipping to the tip. WHERE it names it depends on the fold endpoint:
 *   - coins-applied endpoint (the live utxo_apply wedge path): a missing body
 *     below the frontier is FATAL and fails closed AT its exact height.
 *   - header-tip endpoint (what this harness exercises — no progress store is
 *     wired, so reducer_frontier_derive_coins_best_now() is unavailable): the
 *     missing block is tolerated-and-skipped (a header-only tail block may
 *     legitimately lack a body), so its absence first surfaces one shielded
 *     block LATER, at defect_h+1, via the denser per-block root check.
 * Either way the blocker is localized NEAR the defect, never silently deferred
 * to the capped tip — so accept height=defect_h OR height=defect_h+1. */
static int test_sst_skip_accounting_names_blocker_at_defect_height(void)
{
    int failures = 0;
    const int base = SST_SAPLING_ACTIVATION;
    const int defect_h = base + 5;
    const int tip_h = base + 10;
    char dir[256], dbpath[512];

    printf("sapling_tree_rebuild: missing body mid-window names a blocker "
          "AT the defect height (not a silent skip)... ");

    test_make_tmpdir(dir, sizeof(dir), "sst_skip_acct", "case");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    blocker_module_init();
    blocker_reset_for_testing();

    struct incremental_merkle_tree true_tree;
    sapling_tree_init(&true_tree);

    struct active_chain chain;
    active_chain_init(&chain);
    struct block_index sapling_bi;
    sst_init_index(&sapling_bi, base, 0xd0);
    ok = ok && active_chain_install_tip_slot(&chain, &sapling_bi);

    struct block_index bis[10];
    for (int i = 0; i < 10 && ok; i++) {
        int h = base + 1 + i;
        struct uint256 cm;
        memset(cm.data, 0, 32);
        cm.data[0] = (uint8_t)(0xE0 + i);
        incremental_tree_append(&true_tree, &cm);

        struct uint256 root;
        incremental_tree_root(&true_tree, &root);

        sst_init_index(&bis[i], h, (uint8_t)(0x10 + i));
        bis[i].hashFinalSaplingRoot = root;

        if (h == defect_h) {
            /* THE DEFECT: header math assumes this commitment folded in
             * (root above already includes it), but the body never landed
             * on disk — nStatus stays 0 (BLOCK_HAVE_DATA clear). */
        } else {
            struct disk_block_pos pos;
            ok = ok && sst_write_output_block(dir, &cm, &pos);
            if (ok) {
                bis[i].nStatus |= BLOCK_HAVE_DATA;
                bis[i].nFile = pos.nFile;
                bis[i].nDataPos = pos.nPos;
            }
        }
        ok = ok && active_chain_install_tip_slot(&chain, &bis[i]);
    }

    int appended = ok ? sapling_tree_rebuild(&ndb, &chain, dir) : -1;

    bool failed_closed = appended < 0;

    char want_defect[32], want_defect_next[32], want_tip[32];
    snprintf(want_defect, sizeof(want_defect), "height=%d", defect_h);
    snprintf(want_defect_next, sizeof(want_defect_next), "height=%d",
             defect_h + 1);
    snprintf(want_tip, sizeof(want_tip), "height=%d", tip_h);
    /* Named AT the defect (coins-applied endpoint) OR at defect_h+1 (header-tip
     * endpoint: a skipped missing body first diverges at the next folded
     * block's denser check). Both are "near the defect", the point of W2-L1. */
    bool named_at_defect = sst_blocker_reason_mentions(want_defect) ||
                           sst_blocker_reason_mentions(want_defect_next);
    bool named_at_tip_only = sst_blocker_reason_mentions(want_tip);

    bool pass = ok && failed_closed && named_at_defect && !named_at_tip_only;

    active_chain_free(&chain);
    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (pass) {
        printf("OK\n");
    } else {
        printf("FAIL (appended=%d failed_closed=%d named_at_defect=%d "
              "named_at_tip_only=%d): missing-body block should be named near "
              "the defect (h=%d or h=%d), never silently deferred to the "
              "capped tip (h=%d)\n",
              appended, failed_closed, named_at_defect, named_at_tip_only,
              defect_h, defect_h + 1, tip_h);
        failures++;
    }
    return failures;
}

/* ── Deliverable 2: DENSER CHECK ──────────────────────────────────────────
 * Every block's body IS present and readable, but the on-disk commitment at
 * one mid-window height was corrupted (differs from what the surrounding
 * header chain's hashFinalSaplingRoot values assume folded in — simulating
 * bit rot / a localized fold defect). Today's sapling_tree_rebuild() only
 * compares the folded root against the header root at a 100k-block
 * checkpoint or the final capped tip; in a 10-block test window neither
 * ever fires mid-replay, so the mismatch is reported at the tip (h=+10),
 * not at the actual defect height (h=+6). The fix must check densely
 * enough to catch it at (or immediately after) its own height. */
static int test_sst_denser_check_catches_defect_at_own_height(void)
{
    int failures = 0;
    const int base = SST_SAPLING_ACTIVATION;
    const int defect_idx = 5; /* h = base + 1 + 5 = base + 6 */
    const int defect_h = base + 1 + defect_idx;
    const int tip_h = base + 10;
    char dir[256], dbpath[512];

    printf("sapling_tree_rebuild: corrupted mid-window commitment is caught "
          "AT its own height, not only at the capped tip... ");

    test_make_tmpdir(dir, sizeof(dir), "sst_dense_check", "case");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    blocker_module_init();
    blocker_reset_for_testing();

    struct incremental_merkle_tree true_tree;
    sapling_tree_init(&true_tree);

    struct active_chain chain;
    active_chain_init(&chain);
    struct block_index sapling_bi;
    sst_init_index(&sapling_bi, base, 0xd1);
    ok = ok && active_chain_install_tip_slot(&chain, &sapling_bi);

    struct block_index bis[10];
    for (int i = 0; i < 10 && ok; i++) {
        int h = base + 1 + i;
        struct uint256 cm_true;
        memset(cm_true.data, 0, 32);
        cm_true.data[0] = (uint8_t)(0xA0 + i);
        incremental_tree_append(&true_tree, &cm_true);

        struct uint256 root;
        incremental_tree_root(&true_tree, &root);

        sst_init_index(&bis[i], h, (uint8_t)(0x20 + i));
        bis[i].hashFinalSaplingRoot = root;

        /* On-disk commitment: correct everywhere except the defect height,
         * where the body carries a DIFFERENT value than the one the header
         * chain's root actually reflects. */
        struct uint256 cm_disk = cm_true;
        if (i == defect_idx)
            cm_disk.data[31] = 0xFF; /* corrupt: differs from cm_true */

        struct disk_block_pos pos;
        ok = ok && sst_write_output_block(dir, &cm_disk, &pos);
        if (ok) {
            bis[i].nStatus |= BLOCK_HAVE_DATA;
            bis[i].nFile = pos.nFile;
            bis[i].nDataPos = pos.nPos;
        }
        ok = ok && active_chain_install_tip_slot(&chain, &bis[i]);
    }

    int appended = ok ? sapling_tree_rebuild(&ndb, &chain, dir) : -1;

    bool failed_closed = appended < 0;

    char want_defect[32], want_tip[32];
    snprintf(want_defect, sizeof(want_defect), "height=%d", defect_h);
    snprintf(want_tip, sizeof(want_tip), "height=%d", tip_h);
    bool named_at_defect = sst_blocker_reason_mentions(want_defect);
    bool named_at_tip_only = sst_blocker_reason_mentions(want_tip);

    bool pass = ok && failed_closed && named_at_defect && !named_at_tip_only;

    active_chain_free(&chain);
    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (pass) {
        printf("OK\n");
    } else {
        printf("FAIL (appended=%d failed_closed=%d named_at_defect=%d "
              "named_at_tip_only=%d) -- PENDING W2-L1 integration if this "
              "is the only failure: today's checkpoint cadence (every "
              "100000 blocks) never fires in this window, so the mismatch "
              "surfaces only at the capped tip (h=%d), not the defect "
              "height (h=%d)\n",
              appended, failed_closed, named_at_defect, named_at_tip_only,
              tip_h, defect_h);
        failures++;
    }
    return failures;
}

/* Builds a small non-empty Sapling frontier of `n` synthetic commitments,
 * mirroring tests/harness/src/test_sapling_anchor_frontier_condition.c's
 * safc_build_tree so both files' fixtures stay recognizably related. */
static void sst_build_tree(size_t n, struct incremental_merkle_tree *out)
{
    sapling_tree_init(out);
    for (size_t i = 0; i < n; i++) {
        struct uint256 cm;
        memset(cm.data, 0, 32);
        cm.data[0] = (uint8_t)(0x77 ^ i);
        cm.data[1] = (uint8_t)i;
        incremental_tree_append(out, &cm);
    }
}

static bool sst_block_with_one_output(struct block *blk, uint8_t cm_seed)
{
    block_init(blk);
    blk->num_vtx = 1;
    blk->vtx = zcl_calloc(1, sizeof(*blk->vtx), "sst_frontier_block_tx");
    if (!blk->vtx)
        return false;
    transaction_init(&blk->vtx[0]);
    blk->vtx[0].num_shielded_output = 1;
    blk->vtx[0].v_shielded_output =
        zcl_calloc(1, sizeof(*blk->vtx[0].v_shielded_output),
                  "sst_frontier_block_out");
    if (!blk->vtx[0].v_shielded_output) {
        block_free(blk);
        return false;
    }
    memset(blk->vtx[0].v_shielded_output[0].cm.data, cm_seed, 32);
    return true;
}

static void sst_summary_init(struct delta_summary *s)
{
    memset(s, 0, sizeof(*s));
    s->ok = true;
    s->status = "ok";
}

/* ── Deliverable 3: FRONTIER SEED (positive + negative) ───────────────────
 * A snapshot/refold seed resets the Sapling anchor-history marker to
 * "incomplete below N" via anchor_kv_reset_mark_empty_below_in_tx(N) — the
 * exact primitive engine/composition/src/boot_shielded_seed.c and
 * engine/composition/src/boot_refold_staged.c call at install time. This already-shipped
 * contract (anchor_kv_seed_frontier_row + anchor_kv_latest_tree +
 * utxo_apply_check_and_insert_anchors) is proven here as a standalone,
 * from-scratch regression check so this lane's own file catches any
 * regression W2-L2 introduces in anchor_kv.c/utxo_apply_anchors.c,
 * independent of tests/harness/src/test_sapling_anchor_frontier_condition.c. */
static int test_sst_frontier_seed_positive_and_negative(void)
{
    int failures = 0;
    const int64_t seed_h = 12345;

    printf("anchor_kv frontier seed at N cures the birth defect; without "
          "it the guard still fails closed (positive+negative)... ");

    struct incremental_merkle_tree seed_tree;
    sst_build_tree(6, &seed_tree);
    struct uint256 seed_root;
    incremental_tree_root(&seed_tree, &seed_root);

    /* ── POSITIVE: seed the frontier row, prove the fold now proceeds. ── */
    sqlite3 *db_pos = NULL;
    bool ok = sqlite3_open(":memory:", &db_pos) == SQLITE_OK && db_pos;
    ok = ok && anchor_kv_reset_mark_empty_below_in_tx(db_pos, seed_h);

    /* Before the seed: latest_tree is HISTORY_INCOMPLETE (fail-closed). */
    struct incremental_merkle_tree pre;
    enum anchor_kv_lookup_result pre_lr = ok ? anchor_kv_latest_tree(
        db_pos, ANCHOR_POOL_SAPLING, &pre, NULL, NULL) : ANCHOR_KV_ERROR;
    bool pre_incomplete = pre_lr == ANCHOR_KV_HISTORY_INCOMPLETE;

    /* The first shielded-output block above N fails closed pre-seed. */
    bool pre_fold_ok = false;
    {
        struct block blk;
        bool built = ok && sst_block_with_one_output(&blk, 0x31);
        struct delta_summary s;
        sst_summary_init(&s);
        bool store_ok = built &&
            utxo_apply_check_and_insert_anchors(db_pos, &blk,
                                                (int)(seed_h + 1), &s);
        pre_fold_ok = built && store_ok && !s.ok && s.status &&
            strcmp(s.status, "shielded_anchor_history_gap") == 0;
        if (built)
            block_free(&blk);
    }

    /* The cure: a verified frontier row at N. */
    bool seeded = ok && anchor_kv_seed_frontier_row(
        db_pos, ANCHOR_POOL_SAPLING, &seed_tree, seed_h, &seed_root);

    bool row_present = false, table_empty_after = true;
    if (seeded) {
        int64_t row_count = -1;
        row_present = anchor_kv_row_count(db_pos, ANCHOR_POOL_SAPLING,
                                          &row_count) && row_count >= 1;
        anchor_kv_table_is_empty(db_pos, ANCHOR_POOL_SAPLING,
                                 &table_empty_after);
    }

    struct incremental_merkle_tree post;
    struct uint256 post_root;
    int64_t post_h = -1;
    enum anchor_kv_lookup_result post_lr = seeded ? anchor_kv_latest_tree(
        db_pos, ANCHOR_POOL_SAPLING, &post, &post_root, &post_h) :
        ANCHOR_KV_ERROR;
    bool post_found = post_lr == ANCHOR_KV_FOUND && post_h == seed_h &&
        memcmp(post_root.data, seed_root.data, 32) == 0;

    /* The first shielded-output block above N now folds successfully. */
    bool post_fold_ok = false;
    {
        struct block blk;
        bool built = seeded && sst_block_with_one_output(&blk, 0x42);
        struct delta_summary s;
        sst_summary_init(&s);
        bool store_ok = built &&
            utxo_apply_check_and_insert_anchors(db_pos, &blk,
                                                (int)(seed_h + 1), &s);
        post_fold_ok = built && store_ok && s.ok;
        if (built)
            block_free(&blk);
    }

    if (db_pos) sqlite3_close(db_pos);

    bool positive_pass = ok && pre_incomplete && pre_fold_ok && seeded &&
        row_present && !table_empty_after && post_found && post_fold_ok;

    /* ── NEGATIVE: same reset, NO seed — the guard must still fail closed
     * on the very same first shielded-output block above N. ── */
    sqlite3 *db_neg = NULL;
    bool ok2 = sqlite3_open(":memory:", &db_neg) == SQLITE_OK && db_neg;
    ok2 = ok2 && anchor_kv_reset_mark_empty_below_in_tx(db_neg, seed_h);

    struct incremental_merkle_tree neg_tree;
    enum anchor_kv_lookup_result neg_lr = ok2 ? anchor_kv_latest_tree(
        db_neg, ANCHOR_POOL_SAPLING, &neg_tree, NULL, NULL) : ANCHOR_KV_ERROR;
    bool neg_incomplete = neg_lr == ANCHOR_KV_HISTORY_INCOMPLETE;

    bool neg_fold_fails_closed = false;
    {
        struct block blk;
        bool built = ok2 && sst_block_with_one_output(&blk, 0x53);
        struct delta_summary s;
        sst_summary_init(&s);
        bool store_ok = built &&
            utxo_apply_check_and_insert_anchors(db_neg, &blk,
                                                (int)(seed_h + 1), &s);
        neg_fold_fails_closed = built && store_ok && !s.ok && s.status &&
            strcmp(s.status, "shielded_anchor_history_gap") == 0;
        if (built)
            block_free(&blk);
    }

    if (db_neg) sqlite3_close(db_neg);

    bool negative_pass = ok2 && neg_incomplete && neg_fold_fails_closed;

    bool pass = positive_pass && negative_pass;

    if (pass) {
        printf("OK\n");
    } else {
        printf("FAIL (pre_incomplete=%d pre_fold_ok=%d seeded=%d "
              "row_present=%d table_empty_after=%d post_found=%d "
              "post_fold_ok=%d | neg_incomplete=%d "
              "neg_fold_fails_closed=%d)\n",
              pre_incomplete, pre_fold_ok, seeded, row_present,
              table_empty_after, post_found, post_fold_ok, neg_incomplete,
              neg_fold_fails_closed);
        failures++;
    }
    return failures;
}

/* ── Deliverable 5: anchor_kv is the FIRST resume candidate ──────────────
 *
 * On a cure-seeded datadir the block bodies exist only ABOVE the cure anchor,
 * and both second copies of the Sapling frontier (the node_state blob and the
 * flat-file checkpoint) have lost their header binding. Replaying from Sapling
 * activation is then structurally impossible — the commitments below the
 * anchor have no bodies to fold. The CANONICAL ledger is anchor_kv's
 * sapling_anchors table, which engine/jobs/src/utxo_apply_anchors.c:fold_sapling
 * writes and root-verifies against hashFinalSaplingRoot on every applied
 * shielded block. sapling_tree_rebuild() must seed from it.
 *
 * Shared fixture builder for deliverables 5-7: an 11-block Sapling window at
 * heights [base, base+10], every block carrying exactly one commitment, with
 * the header chain's hashFinalSaplingRoot values computed from the TRUE fold.
 * Options carve the specific defect each test needs. */
struct sst_window {
    struct active_chain chain;
    struct block_index bis[11];
    struct incremental_merkle_tree true_tree;   /* after every leaf */
    struct incremental_merkle_tree anchor_tree; /* frontier at anchor_idx */
    int64_t anchor_height;
};

struct sst_window_opts {
    int missing_idx;     /* -1 none: leave this block's body off disk */
    int corrupt_idx;     /* -1 none: on-disk cm differs from the header math */
    int bodies_from_idx; /* bodies exist only at idx >= this (cure-seeded) */
    int anchor_idx;      /* -1 none: capture the frontier after this leaf */
    uint8_t tag;
};

static struct sst_window *sst_window_build(const char *dir,
                                           const struct sst_window_opts *o)
{
    const int base = SST_SAPLING_ACTIVATION;
    struct sst_window *w = zcl_calloc(1, sizeof(*w), "sst_window");
    if (!w)
        return NULL;
    w->anchor_height = -1;
    active_chain_init(&w->chain);
    sapling_tree_init(&w->true_tree);
    sapling_tree_init(&w->anchor_tree);

    bool ok = true;
    for (int i = 0; i < 11 && ok; i++) {
        int h = base + i;
        struct uint256 cm;
        memset(cm.data, 0, 32);
        cm.data[0] = (uint8_t)(o->tag + i);
        cm.data[1] = (uint8_t)i;
        incremental_tree_append(&w->true_tree, &cm);

        sst_init_index(&w->bis[i], h, (uint8_t)(o->tag + 0x10 + i));
        incremental_tree_root(&w->true_tree, &w->bis[i].hashFinalSaplingRoot);

        if (i == o->anchor_idx) {
            w->anchor_tree = w->true_tree;
            w->anchor_height = h;
        }

        if (i != o->missing_idx && i >= o->bodies_from_idx) {
            struct uint256 cm_disk = cm;
            if (i == o->corrupt_idx)
                cm_disk.data[31] = 0xFF;
            struct disk_block_pos pos;
            ok = sst_write_output_block(dir, &cm_disk, &pos);
            if (ok) {
                w->bis[i].nStatus |= BLOCK_HAVE_DATA;
                w->bis[i].nFile = pos.nFile;
                w->bis[i].nDataPos = pos.nPos;
            }
        }
        ok = ok && active_chain_install_tip_slot(&w->chain, &w->bis[i]);
    }
    if (!ok) {
        active_chain_free(&w->chain);
        free(w);
        return NULL;
    }
    return w;
}

static void sst_window_free(struct sst_window *w)
{
    if (!w)
        return;
    active_chain_free(&w->chain);
    free(w);
}

/* Class of the active sapling_tree_rebuild.* blocker whose reason contains
 * `needle`. Returns false when no such blocker is active. */
static bool sst_blocker_class_for(const char *needle, int *class_out)
{
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (strncmp(snaps[i].id, "sapling_tree_rebuild.", 21) != 0)
            continue;
        if (!strstr(snaps[i].reason, needle))
            continue;
        *class_out = snaps[i].class;
        return true;
    }
    return false;
}

/* Any active sapling_tree_rebuild.fail_closed record at all. */
static bool sst_fail_closed_active(void)
{
    struct blocker_snapshot snap;
    return blocker_find_by_id_prefix("sapling_tree_rebuild.fail_closed",
                                     &snap);
}

static int test_sst_anchor_kv_frontier_is_first_resume_candidate(void)
{
    int failures = 0;
    const int base = SST_SAPLING_ACTIVATION;
    const int anchor_idx = 4;                    /* h = base + 4 */
    char dir[256], dbpath[512];

    printf("sapling_tree_rebuild: resumes from the anchor_kv Sapling "
          "frontier when bodies exist only above the cure anchor... ");

    test_make_tmpdir(dir, sizeof(dir), "sst_anchor_seed", "case");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    blocker_module_init();
    blocker_reset_for_testing();

    struct sst_window_opts opts = {
        .missing_idx = -1,
        .corrupt_idx = -1,
        .bodies_from_idx = anchor_idx + 1, /* bodies ONLY above the anchor */
        .anchor_idx = anchor_idx,
        .tag = 0x70,
    };
    struct sst_window *w = ok ? sst_window_build(dir, &opts) : NULL;
    ok = ok && w != NULL;

    /* The canonical ledger: the reducer's per-block-verified frontier. */
    ok = ok && progress_store_open(dir);
    sqlite3 *pdb = ok ? progress_store_db() : NULL;
    ok = ok && pdb != NULL;
    ok = ok && anchor_kv_ensure_schema(pdb);
    ok = ok && anchor_kv_add_tree(pdb, ANCHOR_POOL_SAPLING, &w->anchor_tree,
                                  w->anchor_height);

    /* A DRIFTED second copy in node_state, exactly the live shape: a
     * plausible height with a tree that does not bind to the header root
     * there. If the rebuild preferred it (or fell through to a full replay)
     * the missing bodies below the anchor would fail it closed. */
    if (ok) {
        struct incremental_merkle_tree stale;
        sst_build_tree(3, &stale);
        struct byte_stream ss;
        stream_init(&ss, 1024);
        ok = incremental_tree_serialize(&stale, &ss) &&
             node_db_state_set(&ndb, "sapling_tree", ss.data, ss.size) &&
             node_db_state_set_int(&ndb, "sapling_tree_rebuild_height",
                                   base + anchor_idx);
        stream_free(&ss);
    }

    int appended = ok ? sapling_tree_rebuild(&ndb, &w->chain, dir) : -1;

    bool blocker_raised = sst_fail_closed_active();
    /* 5 leaves came in with the seed, 6 more folded from real bodies. */
    bool pass = ok && appended == 11 && !blocker_raised;

    progress_store_close();
    sst_window_free(w);
    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (pass) {
        printf("OK\n");
    } else {
        printf("FAIL (ok=%d appended=%d want=11 blocker_raised=%d): the "
              "rebuild must seed from the verified anchor_kv frontier at "
              "h=%d and fold forward from real bodies, never replay from "
              "activation over absent bodies\n",
              ok, appended, blocker_raised, base + anchor_idx);
        failures++;
    }
    return failures;
}

/* ── Deliverable 6: the anchor seed is bound fail-closed ─────────────────
 * An anchor_kv frontier whose own root does not equal the header chain's
 * hashFinalSaplingRoot at its height is REFUSED — a stored frontier is
 * trusted only when it binds to PoW-committed header data. Proof: with every
 * body present, refusing the bad seed lets the full replay from activation
 * succeed; ACCEPTING it would start the fold from a wrong tree and fail
 * closed on the very next commitment block. */
static int test_sst_anchor_kv_binding_refusal_falls_through(void)
{
    int failures = 0;
    const int anchor_idx = 4;
    char dir[256], dbpath[512];

    printf("sapling_tree_rebuild: an anchor_kv frontier that does not bind "
          "to the header root is refused and the old candidates run... ");

    test_make_tmpdir(dir, sizeof(dir), "sst_anchor_refuse", "case");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    blocker_module_init();
    blocker_reset_for_testing();

    struct sst_window_opts opts = {
        .missing_idx = -1,
        .corrupt_idx = -1,
        .bodies_from_idx = 0,   /* every body present */
        .anchor_idx = anchor_idx,
        .tag = 0x90,
    };
    struct sst_window *w = ok ? sst_window_build(dir, &opts) : NULL;
    ok = ok && w != NULL;

    ok = ok && progress_store_open(dir);
    sqlite3 *pdb = ok ? progress_store_db() : NULL;
    ok = ok && pdb != NULL;
    ok = ok && anchor_kv_ensure_schema(pdb);
    /* THE DEFECT: the 5-leaf frontier is stored at height base+3, where the
     * header commits the 4-leaf root. Root binding must reject it. */
    ok = ok && anchor_kv_add_tree(pdb, ANCHOR_POOL_SAPLING, &w->anchor_tree,
                                  w->anchor_height - 1);

    int appended = ok ? sapling_tree_rebuild(&ndb, &w->chain, dir) : -1;

    bool blocker_raised = sst_fail_closed_active();
    bool pass = ok && appended == 11 && !blocker_raised;

    progress_store_close();
    sst_window_free(w);
    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (pass) {
        printf("OK\n");
    } else {
        printf("FAIL (ok=%d appended=%d want=11 blocker_raised=%d): an "
              "unbound anchor_kv frontier must be refused, not folded from\n",
              ok, appended, blocker_raised);
        failures++;
    }
    return failures;
}

/* ── Deliverable 7: root-mismatch classification ─────────────────────────
 * A root mismatch on a walk that TOLERATED skips is not evidence of
 * corruption: the commitments of the skipped blocks are known-missing, so no
 * healthy derived state could have produced the header root either. That is a
 * body-availability DEPENDENCY. A root mismatch on a walk that folded every
 * in-range body IS a derived-state disagreement and stays PERMANENT. */
static int test_sst_root_mismatch_classification(void)
{
    int failures = 0;
    const int base = SST_SAPLING_ACTIVATION;
    char dir_dep[256], dir_perm[256], dbpath[512];

    printf("sapling_tree_rebuild: mismatch after tolerated skips is a "
          "DEPENDENCY; mismatch over a complete body set stays PERMANENT... ");

    /* ── DEPENDENCY: one body absent mid-window. ── */
    test_make_tmpdir(dir_dep, sizeof(dir_dep), "sst_class_dep", "case");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir_dep);
    struct node_db ndb_dep;
    memset(&ndb_dep, 0, sizeof(ndb_dep));
    bool ok_dep = node_db_open(&ndb_dep, dbpath);

    blocker_module_init();
    blocker_reset_for_testing();

    struct sst_window_opts dep_opts = {
        .missing_idx = 5,       /* h = base + 5 has no body on disk */
        .corrupt_idx = -1,
        .bodies_from_idx = 0,
        .anchor_idx = -1,
        .tag = 0xB0,
    };
    struct sst_window *wd = ok_dep ? sst_window_build(dir_dep, &dep_opts)
                                   : NULL;
    ok_dep = ok_dep && wd != NULL;
    int rc_dep = ok_dep ? sapling_tree_rebuild(&ndb_dep, &wd->chain, dir_dep)
                        : 0;

    char want_dep[32];
    snprintf(want_dep, sizeof(want_dep), "height=%d", base + 6);
    int class_dep = -1;
    bool found_dep = sst_blocker_class_for(want_dep, &class_dep);
    bool names_gap = sst_blocker_reason_mentions("body_gap=1") &&
                     sst_blocker_reason_mentions("classes=no_data");
    bool dep_pass = ok_dep && rc_dep < 0 && found_dep &&
                    class_dep == BLOCKER_DEPENDENCY && names_gap;

    sst_window_free(wd);
    node_db_close(&ndb_dep);
    test_rm_rf_recursive(dir_dep);

    /* ── PERMANENT: every body present, one on-disk commitment corrupted. ── */
    test_make_tmpdir(dir_perm, sizeof(dir_perm), "sst_class_perm", "case");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir_perm);
    struct node_db ndb_perm;
    memset(&ndb_perm, 0, sizeof(ndb_perm));
    bool ok_perm = node_db_open(&ndb_perm, dbpath);

    blocker_reset_for_testing();

    struct sst_window_opts perm_opts = {
        .missing_idx = -1,
        .corrupt_idx = 5,       /* h = base + 5 body disagrees with headers */
        .bodies_from_idx = 0,
        .anchor_idx = -1,
        .tag = 0xC0,
    };
    struct sst_window *wp = ok_perm ? sst_window_build(dir_perm, &perm_opts)
                                    : NULL;
    ok_perm = ok_perm && wp != NULL;
    int rc_perm = ok_perm
        ? sapling_tree_rebuild(&ndb_perm, &wp->chain, dir_perm) : 0;

    char want_perm[32];
    snprintf(want_perm, sizeof(want_perm), "height=%d", base + 5);
    int class_perm = -1;
    bool found_perm = sst_blocker_class_for(want_perm, &class_perm);
    bool no_gap = !sst_blocker_reason_mentions("body_gap=");
    bool perm_pass = ok_perm && rc_perm < 0 && found_perm &&
                     class_perm == BLOCKER_PERMANENT && no_gap;

    sst_window_free(wp);
    node_db_close(&ndb_perm);
    test_rm_rf_recursive(dir_perm);

    if (dep_pass && perm_pass) {
        printf("OK\n");
    } else {
        printf("FAIL (dep: ok=%d rc=%d found=%d class=%d names_gap=%d | "
              "perm: ok=%d rc=%d found=%d class=%d no_gap=%d) -- want "
              "class %d (DEPENDENCY) then %d (PERMANENT)\n",
              ok_dep, rc_dep, found_dep, class_dep, names_gap,
              ok_perm, rc_perm, found_perm, class_perm, no_gap,
              BLOCKER_DEPENDENCY, BLOCKER_PERMANENT);
        failures++;
    }
    return failures;
}

/* ── Deliverable 8: refuse a provably-impossible replay BEFORE walking ───
 *
 * The live shape: a snapshot-seeded datadir where no body below the seed was
 * ever downloaded. No resume candidate binds, so the replay opens onto a run of
 * body-less heights, folds nothing across it, and then reports the first
 * commitment block ABOVE the body floor as a root mismatch. On the live node
 * that latched `height=3155873 commitments=1 mismatches=1` — a one-leaf tree
 * measured against a root committing ~1.79M leaves, 30 blocks above the real
 * boundary (the seed height + 1), after 2.68M tolerated skips — and it read as
 * a PERMANENT derived-state disagreement rather than absent bodies.
 *
 * The fact is provable from headers alone: hashFinalSaplingRoot at the LAST
 * absent height commits the frontier the walk must hold when it reaches the
 * first foldable body, appends only add leaves, and the walk folds nothing over
 * the absent run — so a starting tree whose root already differs there can
 * never converge. This asserts both directions: refuse when the absent run
 * demonstrably carried commitments, and DO NOT refuse when it did not. */
static int test_sst_preflight_refuses_impossible_replay(void)
{
    int failures = 0;
    const int base = SST_SAPLING_ACTIVATION;
    const int bodies_from = 8;      /* bodies exist only at idx >= 8 */
    char dir[256], dbpath[512];

    printf("sapling_tree_rebuild: a replay that headers prove impossible is "
          "refused before reading a block, and a recoverable one is not... ");

    /* ── POSITIVE: the absent run carried commitments. Must refuse. ── */
    progress_store_close();
    test_make_tmpdir(dir, sizeof(dir), "sst_preflight_pos", "case");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    blocker_module_init();
    blocker_reset_for_testing();

    struct sst_window_opts opts = {
        .missing_idx = -1,
        .corrupt_idx = -1,
        .bodies_from_idx = bodies_from,
        .anchor_idx = -1,           /* no seed: the replay starts empty */
        .tag = 0x40,
    };
    struct sst_window *w = ok ? sst_window_build(dir, &opts) : NULL;
    ok = ok && w != NULL;

    int rc_pos = ok ? sapling_tree_rebuild(&ndb, &w->chain, dir) : 0;

    char want_boundary[32], want_span[48];
    snprintf(want_boundary, sizeof(want_boundary), "height=%d",
             base + bodies_from);
    snprintf(want_span, sizeof(want_span), "span=[%d..%d]", base,
             base + bodies_from - 1);
    int class_pos = -1;
    bool found_pos = sst_blocker_class_for(want_boundary, &class_pos);
    /* commitments=0 mismatches=0 is the un-fakeable proof that NOTHING was
     * read or folded: the pre-empted walk would have reported commitments=1
     * mismatches=1 at this same height in this small window. */
    bool nothing_folded = sst_blocker_reason_mentions("commitments=0") &&
                          sst_blocker_reason_mentions("mismatches=0");
    bool names_cause =
        sst_blocker_reason_mentions(want_span) &&
        sst_blocker_reason_mentions("classes=no_data") &&
        sst_blocker_reason_mentions(
            "replay_impossible_bodies_absent_below_first_foldable_body");
    bool pos_pass = ok && rc_pos < 0 && found_pos &&
                    class_pos == BLOCKER_DEPENDENCY && nothing_folded &&
                    names_cause;

    sst_window_free(w);
    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    /* ── NEGATIVE: same absent run, but it carried NO commitments, so the
     * header root at the last absent height IS the empty-tree root the walk
     * starts from. The walk is recoverable and must run untouched. ── */
    char dir_neg[256];
    test_make_tmpdir(dir_neg, sizeof(dir_neg), "sst_preflight_neg", "case");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir_neg);

    struct node_db ndb_neg;
    memset(&ndb_neg, 0, sizeof(ndb_neg));
    bool ok_neg = node_db_open(&ndb_neg, dbpath);

    blocker_reset_for_testing();

    struct incremental_merkle_tree neg_tree;
    sapling_tree_init(&neg_tree);
    struct uint256 empty_root;
    incremental_tree_root(&neg_tree, &empty_root);
    /* Fixture validity: an all-zero root reads as "header root unknown" and
     * would make the pre-flight skip for the wrong reason. */
    static const uint8_t zeros32[32] = {0};
    bool empty_root_is_bindable =
        memcmp(empty_root.data, zeros32, 32) != 0;

    struct active_chain neg_chain;
    active_chain_init(&neg_chain);
    struct block_index neg_bis[11];
    for (int i = 0; i < 11 && ok_neg; i++) {
        sst_init_index(&neg_bis[i], base + i, (uint8_t)(0x50 + i));
        if (i >= bodies_from) {
            struct uint256 cm;
            memset(cm.data, 0, 32);
            cm.data[0] = (uint8_t)(0x60 + i);
            incremental_tree_append(&neg_tree, &cm);
            struct disk_block_pos pos;
            ok_neg = sst_write_output_block(dir_neg, &cm, &pos);
            if (ok_neg) {
                neg_bis[i].nStatus |= BLOCK_HAVE_DATA;
                neg_bis[i].nFile = pos.nFile;
                neg_bis[i].nDataPos = pos.nPos;
            }
        }
        incremental_tree_root(&neg_tree, &neg_bis[i].hashFinalSaplingRoot);
        ok_neg = ok_neg && active_chain_install_tip_slot(&neg_chain,
                                                        &neg_bis[i]);
    }

    int rc_neg = ok_neg ? sapling_tree_rebuild(&ndb_neg, &neg_chain, dir_neg)
                        : -1;
    bool neg_blocker = sst_fail_closed_active();
    int want_neg = 11 - bodies_from;   /* only the bodies above the run fold */
    bool neg_pass = ok_neg && empty_root_is_bindable && rc_neg == want_neg &&
                    !neg_blocker;

    active_chain_free(&neg_chain);
    node_db_close(&ndb_neg);
    test_rm_rf_recursive(dir_neg);

    if (pos_pass && neg_pass) {
        printf("OK\n");
    } else {
        printf("FAIL (impossible: ok=%d rc=%d found=%d class=%d "
              "nothing_folded=%d names_cause=%d | recoverable: ok=%d "
              "bindable=%d rc=%d want=%d blocker=%d) -- want a DEPENDENCY (%d) "
              "naming h=%d with commitments=0 and span=[%d..%d], and a clean "
              "%d-commitment fold for the recoverable window\n",
              ok, rc_pos, found_pos, class_pos, nothing_folded, names_cause,
              ok_neg, empty_root_is_bindable, rc_neg, want_neg, neg_blocker,
              BLOCKER_DEPENDENCY, base + bodies_from, base,
              base + bodies_from - 1, want_neg);
        failures++;
    }
    return failures;
}

/* ── Deliverable 4: incremental-merkle-tree math is untouched ────────────
 * A tiny fixed leaf set over the PRODUCTION depth-32 Pedersen Sapling tree
 * (the exact primitive sapling_tree_rebuild()/utxo_apply_anchors.c fold
 * against, not the depth-4 testing variant) must still fold to the same
 * golden root. Neither lane in this program is supposed to touch
 * incremental_merkle_tree.c; this is the tripwire if one accidentally
 * does. The golden hex below was captured from this exact leaf sequence
 * against the current tree implementation. */
static int test_sst_merkle_tree_math_golden_root_unchanged(void)
{
    int failures = 0;

    printf("incremental_merkle_tree (Sapling/Pedersen) golden root over a "
          "known small leaf set is unchanged... ");

    struct incremental_merkle_tree t;
    sapling_tree_init(&t);
    for (int i = 0; i < 4; i++) {
        struct uint256 cm;
        memset(cm.data, 0, 32);
        cm.data[0] = (uint8_t)(i + 1);
        incremental_tree_append(&t, &cm);
    }
    struct uint256 root;
    incremental_tree_root(&t, &root);
    char hex[65];
    uint256_get_hex(&root, hex);

    static const char *want =
        "4cf4bb90a078552c04beb72e562ec09120c99cc3b04c839ee291024952ccfaf4";

    bool ok = strcmp(hex, want) == 0;

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (got=%s want=%s)\n", hex, want);
        failures++;
    }
    return failures;
}

int test_shielded_sync_strength(void)
{
    int failures = 0;

    failures += test_sst_skip_accounting_names_blocker_at_defect_height();
    failures += test_sst_denser_check_catches_defect_at_own_height();
    failures += test_sst_frontier_seed_positive_and_negative();
    failures += test_sst_anchor_kv_frontier_is_first_resume_candidate();
    failures += test_sst_anchor_kv_binding_refusal_falls_through();
    failures += test_sst_root_mismatch_classification();
    failures += test_sst_preflight_refuses_impossible_replay();
    failures += test_sst_merkle_tree_math_golden_root_unchanged();

    return failures;
}
