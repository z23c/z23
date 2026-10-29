/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "bloom/merkle.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "controllers/sync_controller.h"
#include "core/serialize.h"
#include "event/event.h"
#include "jobs/utxo_apply_stage.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/disk_block_io.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"
#include "validation/chainstate.h"
#include "validation/process_block.h"

#include <stdatomic.h>

static _Atomic int g_sapling_persist_events = 0;

static void unclean_shutdown_event_observer(enum event_type type,
                                            uint32_t peer_id,
                                            const void *payload,
                                            uint32_t payload_len,
                                            void *ctx)
{
    (void)type;
    (void)peer_id;
    (void)payload;
    (void)payload_len;
    (void)ctx;
    atomic_fetch_add(&g_sapling_persist_events, 1);
}

static void init_sapling_rebuild_index(struct block_index *bi, int height,
                                       uint8_t tag)
{
    block_index_init(bi);
    bi->nHeight = height;
    memset(bi->hashBlock.data, tag, 32);
    bi->phashBlock = &bi->hashBlock;
}

static void build_one_leaf_sapling_tree(struct incremental_merkle_tree *tree,
                                        uint8_t tag)
{
    struct uint256 cm;

    sapling_tree_init(tree);
    memset(cm.data, tag, 32);
    incremental_tree_append(tree, &cm);
}

static int test_sapling_rebuild_rejects_unverified_checkpoint(void)
{
    int failures = 0;
    const int sapling_height = 476969;
    const int checkpoint_height = sapling_height + 100000;
    char dir[256];
    char dbpath[512];

    printf("sapling rebuild rejects unverified legacy checkpoint... ");

    test_make_tmpdir(dir, sizeof(dir), "sapling_rebuild", "unverified");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    struct byte_stream ts;
    stream_init(&ts, 4096);
    ok = ok && incremental_tree_serialize(&tree, &ts);
    ok = ok && node_db_state_set(&ndb, "sapling_tree", ts.data, ts.size);
    ok = ok && node_db_state_set_int(&ndb, "sapling_tree_rebuild_height",
                                     checkpoint_height);

    struct active_chain chain;
    active_chain_init(&chain);
    struct block_index sapling;
    struct block_index checkpoint;
    init_sapling_rebuild_index(&sapling, sapling_height, 0xa5);
    init_sapling_rebuild_index(&checkpoint, checkpoint_height, 0xc5);
    /* Leave checkpoint.hashFinalSaplingRoot all-zero: the legacy resume
     * checkpoint is therefore unverified and must not be accepted. */
    ok = ok && active_chain_install_tip_slot(&chain, &sapling);
    ok = ok && active_chain_install_tip_slot(&chain, &checkpoint);

    int appended = ok ? sapling_tree_rebuild(&ndb, &chain, dir) : 0;
    ok = ok && appended < 0;

    active_chain_free(&chain);
    stream_free(&ts);
    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (appended=%d)\n", appended);
        failures++;
    }
    return failures;
}

static int test_sapling_rebuild_accepts_verified_checkpoint(void)
{
    int failures = 0;
    const int sapling_height = 476969;
    const int checkpoint_height = sapling_height + 100000;
    char dir[256];
    char dbpath[512];

    printf("sapling rebuild accepts verified legacy checkpoint... ");

    test_make_tmpdir(dir, sizeof(dir), "sapling_rebuild", "verified");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    struct incremental_merkle_tree tree;
    build_one_leaf_sapling_tree(&tree, 0x31);
    struct uint256 root;
    incremental_tree_root(&tree, &root);

    struct byte_stream ts;
    stream_init(&ts, 4096);
    ok = ok && incremental_tree_serialize(&tree, &ts);
    ok = ok && node_db_state_set(&ndb, "sapling_tree", ts.data, ts.size);
    ok = ok && node_db_state_set_int(&ndb, "sapling_tree_rebuild_height",
                                     checkpoint_height);

    struct active_chain chain;
    active_chain_init(&chain);
    struct block_index sapling;
    struct block_index checkpoint;
    init_sapling_rebuild_index(&sapling, sapling_height, 0xa6);
    init_sapling_rebuild_index(&checkpoint, checkpoint_height, 0xc6);
    checkpoint.hashFinalSaplingRoot = root;
    ok = ok && active_chain_install_tip_slot(&chain, &sapling);
    ok = ok && active_chain_install_tip_slot(&chain, &checkpoint);

    int appended = ok ? sapling_tree_rebuild(&ndb, &chain, dir) : -1;
    ok = ok && appended == (int)incremental_tree_size(&tree);

    active_chain_free(&chain);
    stream_free(&ts);
    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (appended=%d)\n", appended);
        failures++;
    }
    return failures;
}

static int test_sapling_rebuild_rejects_mismatched_checkpoint(void)
{
    int failures = 0;
    const int sapling_height = 476969;
    const int checkpoint_height = sapling_height + 100000;
    char dir[256];
    char dbpath[512];

    printf("sapling rebuild rejects mismatched legacy checkpoint... ");

    test_make_tmpdir(dir, sizeof(dir), "sapling_rebuild", "mismatch");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    struct incremental_merkle_tree tree;
    build_one_leaf_sapling_tree(&tree, 0x32);
    struct byte_stream ts;
    stream_init(&ts, 4096);
    ok = ok && incremental_tree_serialize(&tree, &ts);
    ok = ok && node_db_state_set(&ndb, "sapling_tree", ts.data, ts.size);
    ok = ok && node_db_state_set_int(&ndb, "sapling_tree_rebuild_height",
                                     checkpoint_height);

    struct active_chain chain;
    active_chain_init(&chain);
    struct block_index sapling;
    struct block_index checkpoint;
    init_sapling_rebuild_index(&sapling, sapling_height, 0xa7);
    init_sapling_rebuild_index(&checkpoint, checkpoint_height, 0xc7);
    memset(checkpoint.hashFinalSaplingRoot.data, 0x7e, 32);
    ok = ok && active_chain_install_tip_slot(&chain, &sapling);
    ok = ok && active_chain_install_tip_slot(&chain, &checkpoint);

    int appended = ok ? sapling_tree_rebuild(&ndb, &chain, dir) : 0;
    ok = ok && appended < 0;

    active_chain_free(&chain);
    stream_free(&ts);
    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (appended=%d)\n", appended);
        failures++;
    }
    return failures;
}

/* lane/sapling-tree-persist coverage below: the atomic blob+height write
 * (sapling_tree_persist_pair) and the height-aware fold-forward that
 * engine/composition/src/boot.c's loader now relies on (sapling_tree_rebuild resuming
 * from a VERIFIED saved_height instead of a full from-activation replay).
 * "corrupted tree still forces the full-rebuild fallback" is already
 * covered above by test_sapling_rebuild_rejects_unverified_checkpoint and
 * test_sapling_rebuild_rejects_mismatched_checkpoint (a node_state pair
 * whose root does not verify at its own claimed height is discarded, not
 * trusted for a partial resume). */

static int test_sapling_persist_pair_round_trip(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];

    printf("sapling_tree_persist_pair round-trips blob+height as one pair... ");

    test_make_tmpdir(dir, sizeof(dir), "sapling_persist_pair", "roundtrip");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    struct incremental_merkle_tree tree;
    build_one_leaf_sapling_tree(&tree, 0x51);
    struct uint256 want_root;
    incremental_tree_root(&tree, &want_root);

    struct byte_stream ts;
    stream_init(&ts, 4096);
    ok = ok && incremental_tree_serialize(&tree, &ts);

    const int64_t saved_h = 900123;
    ok = ok && sapling_tree_persist_pair(&ndb, ts.data, ts.size, saved_h);
    stream_free(&ts);

    uint8_t buf[8192];
    size_t len = 0;
    ok = ok && node_db_state_get(&ndb, "sapling_tree", buf, sizeof(buf), &len)
             && len > 0;
    int64_t got_h = -1;
    ok = ok && node_db_state_get_int(&ndb, "sapling_tree_rebuild_height",
                                     &got_h);

    struct incremental_merkle_tree readback;
    sapling_tree_init(&readback);
    struct byte_stream rs;
    stream_init_from_data(&rs, buf, len);
    ok = ok && incremental_tree_deserialize(&readback, &rs);
    struct uint256 got_root;
    incremental_tree_root(&readback, &got_root);

    bool height_ok = ok && got_h == saved_h;
    bool root_ok = ok && memcmp(got_root.data, want_root.data, 32) == 0;
    ok = ok && height_ok && root_ok;

    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (got_h=%lld want_h=%lld height_ok=%d root_ok=%d)\n",
               (long long)got_h, (long long)saved_h, height_ok, root_ok);
        failures++;
    }
    return failures;
}

static bool usf_caller_tx_rolled_back_absent(struct node_db *ndb,
                                             const struct byte_stream *ts,
                                             int64_t saved_h, bool refused,
                                             int64_t *got_h)
{
    bool began_rollback = refused && node_db_begin(ndb);
    bool wrote_then_rolled_back = began_rollback &&
        sapling_tree_persist_pair_in_open_tx(ndb, ts->data, ts->size,
                                              saved_h) &&
        node_db_rollback(ndb);
    return wrote_then_rolled_back &&
        !node_db_state_get_int(ndb, "sapling_tree_rebuild_height", got_h);
}

static bool usf_caller_tx_committed_visible(struct node_db *ndb,
                                            const struct byte_stream *ts,
                                            int64_t saved_h, bool absent,
                                            int64_t *got_h)
{
    bool began_commit = absent && node_db_begin(ndb);
    bool wrote_then_committed = began_commit &&
        sapling_tree_persist_pair_in_open_tx(ndb, ts->data, ts->size,
                                              saved_h) &&
        node_db_commit(ndb);
    size_t tree_len = 0;
    uint8_t tree_buf[8192];
    return wrote_then_committed &&
        node_db_state_get_int(ndb, "sapling_tree_rebuild_height", got_h) &&
        *got_h == saved_h &&
        node_db_state_get(ndb, "sapling_tree", tree_buf, sizeof(tree_buf),
                          &tree_len) && tree_len == ts->size &&
        memcmp(tree_buf, ts->data, tree_len) == 0;
}

/* The projection catchup owns a plain transaction but intentionally does not
 * set the reducer-specific sync_in_batch flag. Prove that its explicit entry
 * point writes inside that transaction without attempting a nested BEGIN,
 * that rollback removes both members of the pair, and that a committed retry
 * publishes both together. */
static int test_sapling_persist_pair_inside_caller_transaction(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];

    printf("sapling_tree_persist_pair writes atomically inside the caller's "
           "plain transaction... ");

    test_make_tmpdir(dir, sizeof(dir), "sapling_persist_pair", "caller_tx");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    struct incremental_merkle_tree tree;
    build_one_leaf_sapling_tree(&tree, 0x59);
    struct byte_stream ts;
    stream_init(&ts, 4096);
    ok = ok && incremental_tree_serialize(&tree, &ts);

    const int64_t saved_h = 900321;
    bool refused_without_tx = ok &&
        !sapling_tree_persist_pair_in_open_tx(&ndb, ts.data, ts.size,
                                              saved_h);
    int64_t got_h = -1;
    bool absent_after_rollback =
        usf_caller_tx_rolled_back_absent(&ndb, &ts, saved_h,
                                         refused_without_tx, &got_h);
    bool pair_visible =
        usf_caller_tx_committed_visible(&ndb, &ts, saved_h,
                                        absent_after_rollback, &got_h);

    ok = ok && refused_without_tx && absent_after_rollback && pair_visible;
    stream_free(&ts);
    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (refused_without_tx=%d rollback_absent=%d pair_visible=%d)\n",
               refused_without_tx, absent_after_rollback, pair_visible);
        failures++;
    }
    return failures;
}

static bool make_output_only_tx(struct transaction *tx,
                                const struct uint256 *cm)
{
    transaction_init(tx);
    tx->overwintered = true;
    tx->version = SAPLING_TX_VERSION;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    tx->v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                       "test_sapling_fold_output");
    if (!tx->v_shielded_output)
        return false;
    tx->num_shielded_output = 1;
    tx->v_shielded_output[0].cm = *cm;
    transaction_compute_hash(tx);
    return true;
}

static bool usf_build_fold_block(struct block *blk, const struct uint256 *cm3,
                                 bool ok)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "test_sapling_fold_vtx");
    ok = ok && blk->vtx != NULL;
    if (blk->vtx) {
        blk->num_vtx = 1;
        ok = ok && make_output_only_tx(&blk->vtx[0], cm3);
        blk->header.nVersion = 4;
        blk->header.nTime = 1700000000u;
        blk->header.nBits = 0x2000ffffu;
        struct uint256 txid = blk->vtx[0].hash;
        blk->header.hashMerkleRoot = compute_merkle_root(&txid, 1);
    }
    return ok;
}

static bool usf_install_fold_chain(struct active_chain *chain,
                                   struct block_index *bi_sapling,
                                   struct block_index *bi_saved,
                                   struct block_index *bi_tip)
{
    return active_chain_install_tip_slot(chain, bi_sapling) &&
           active_chain_install_tip_slot(chain, bi_saved) &&
           active_chain_install_tip_slot(chain, bi_tip);
}

static bool usf_read_fold_result(struct node_db *ndb, bool ok,
                                 struct incremental_merkle_tree *persisted,
                                 int64_t *persisted_h, bool *loaded,
                                 bool *got_h)
{
    uint8_t rbuf[8192];
    size_t rlen = 0;
    *loaded = ok && node_db_state_get(ndb, "sapling_tree", rbuf,
                                      sizeof(rbuf), &rlen) && rlen > 0;
    *got_h = *loaded && node_db_state_get_int(ndb,
                                "sapling_tree_rebuild_height", persisted_h);
    sapling_tree_init(persisted);
    struct byte_stream rs;
    stream_init_from_data(&rs, rbuf, rlen);
    return *got_h && incremental_tree_deserialize(persisted, &rs);
}

static void usf_scratch_fold_root(const struct uint256 *cm1,
                                  const struct uint256 *cm2,
                                  const struct uint256 *cm3,
                                  struct uint256 *root)
{
    struct incremental_merkle_tree scratch;
    sapling_tree_init(&scratch);
    incremental_tree_append(&scratch, cm1);
    incremental_tree_append(&scratch, cm2);
    incremental_tree_append(&scratch, cm3);
    incremental_tree_root(&scratch, root);
}

/* Reproduces the exact boot-time scenario this lane fixes: a tree persisted
 * at height A (verified against A's own hashFinalSaplingRoot) with the real
 * tip sitting at B > A. sapling_tree_rebuild() must resume from A (not
 * replay from Sapling activation) and fold forward the ONE real commitment
 * that landed in a real on-disk block at B, and the persisted result must
 * be bit-identical to an independently-built from-scratch tree over all
 * three commitments — the correctness bar the fold-forward path must meet. */
static int test_sapling_rebuild_folds_forward_from_saved_height(void)
{
    int failures = 0;
    const int sapling_height = 476969;
    const int saved_h = sapling_height + 50;
    const int tip_h = saved_h + 3;
    char dir[256];
    char dbpath[512];

    printf("sapling rebuild folds forward from saved_h=A to tip_h=B "
          "(matches from-scratch root)... ");

    test_make_tmpdir(dir, sizeof(dir), "sapling_rebuild", "fold_forward");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    /* The tree persisted at saved_h — this is what boot.c loads. */
    struct incremental_merkle_tree tree_a;
    sapling_tree_init(&tree_a);
    struct uint256 cm1, cm2, cm3;
    memset(cm1.data, 0x61, 32);
    memset(cm2.data, 0x62, 32);
    memset(cm3.data, 0x63, 32);
    incremental_tree_append(&tree_a, &cm1);
    incremental_tree_append(&tree_a, &cm2);
    struct uint256 root_a;
    incremental_tree_root(&tree_a, &root_a);

    struct byte_stream ts;
    stream_init(&ts, 4096);
    ok = ok && incremental_tree_serialize(&tree_a, &ts);
    ok = ok && sapling_tree_persist_pair(&ndb, ts.data, ts.size, saved_h);
    stream_free(&ts);

    /* The full tree after the one new commitment lands at tip_h. */
    struct incremental_merkle_tree tree_full = tree_a; /* POD copy */
    incremental_tree_append(&tree_full, &cm3);
    struct uint256 root_b;
    incremental_tree_root(&tree_full, &root_b);

    /* A REAL on-disk block at tip_h carrying that one commitment — this is
     * the "fold forward from local block data" sapling_tree_rebuild already
     * does; the test proves boot.c may now rely on it instead of deferring
     * or replaying from activation. */
    struct block blk;
    ok = usf_build_fold_block(&blk, &cm3, ok);

    static const unsigned char msg[4] = {0x24, 0xe9, 0x27, 0x64};
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    ok = ok && write_block_to_disk(&blk, &pos, dir, msg);

    struct active_chain chain;
    active_chain_init(&chain);
    struct block_index bi_sapling, bi_saved, bi_tip;
    init_sapling_rebuild_index(&bi_sapling, sapling_height, 0xa8);
    init_sapling_rebuild_index(&bi_saved, saved_h, 0xa9);
    bi_saved.hashFinalSaplingRoot = root_a;
    init_sapling_rebuild_index(&bi_tip, tip_h, 0xaa);
    bi_tip.hashFinalSaplingRoot = root_b;
    bi_tip.nStatus |= BLOCK_HAVE_DATA;
    bi_tip.nFile = pos.nFile;
    bi_tip.nDataPos = pos.nPos;

    ok = ok && usf_install_fold_chain(&chain, &bi_sapling, &bi_saved, &bi_tip);

    int appended = ok ? sapling_tree_rebuild(&ndb, &chain, dir) : -1;

    int64_t persisted_h = -1;
    bool loaded = false;
    bool got_h = false;
    struct incremental_merkle_tree persisted;
    bool deser = usf_read_fold_result(&ndb, ok, &persisted, &persisted_h,
                                      &loaded, &got_h);
    struct uint256 persisted_root;
    incremental_tree_root(&persisted, &persisted_root);

    /* Independent from-scratch build — never touches sapling_tree_rebuild. */
    struct uint256 scratch_root;
    usf_scratch_fold_root(&cm1, &cm2, &cm3, &scratch_root);

    bool matches_scratch = deser &&
        memcmp(persisted_root.data, scratch_root.data, 32) == 0;
    bool matches_tip = deser &&
        memcmp(persisted_root.data, root_b.data, 32) == 0;
    bool pass = ok && appended == 3 && loaded && got_h &&
               persisted_h == tip_h && matches_scratch && matches_tip;

    active_chain_free(&chain);
    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (pass) {
        printf("OK\n");
    } else {
        printf("FAIL (appended=%d persisted_h=%lld matches_scratch=%d "
              "matches_tip=%d)\n", appended, (long long)persisted_h,
              matches_scratch, matches_tip);
        failures++;
    }
    return failures;
}

/* lane/e3-sapling-rebuild-robust coverage below: the live incident was
 * "ERROR [sapling_tree_rebuild] ... persist_pair: BEGIN failed" spam while
 * the reducer held the store, and the deferred rebuild never completing.
 * These drive the fix via the ZCL_TESTING fault-injection seam
 * (sapling_tree_rebuild_test_force_begin_busy) instead of racing real
 * SQLite lock contention, so they stay fast and deterministic. */

static int test_sapling_persist_pair_busy_retry_succeeds(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];

    printf("sapling_tree_persist_pair retries through transient BUSY and "
          "succeeds... ");

    test_make_tmpdir(dir, sizeof(dir), "sapling_persist_pair", "busy_retry");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    struct incremental_merkle_tree tree;
    build_one_leaf_sapling_tree(&tree, 0x71);
    struct byte_stream ts;
    stream_init(&ts, 4096);
    ok = ok && incremental_tree_serialize(&tree, &ts);

    blocker_module_init();
    blocker_reset_for_testing();

    /* First two BEGIN attempts simulate SQLITE_BUSY; the third (real)
     * attempt succeeds — proves the bounded retry actually retries
     * instead of failing (and logging) on the first contention. */
    sapling_tree_rebuild_test_force_begin_busy(2);
    int64_t saved_h = 900789;
    bool persisted = ok &&
        sapling_tree_persist_pair(&ndb, ts.data, ts.size, saved_h);
    sapling_tree_rebuild_test_force_begin_busy(0);
    stream_free(&ts);

    bool no_blocker = !blocker_exists("sapling_tree_rebuild.persist_busy");

    int64_t got_h = -1;
    bool got = persisted && node_db_state_get_int(&ndb,
                                "sapling_tree_rebuild_height", &got_h);
    ok = ok && persisted && no_blocker && got && got_h == saved_h;

    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (persisted=%d no_blocker=%d got_h=%lld)\n",
               persisted, no_blocker, (long long)got_h);
        failures++;
    }
    return failures;
}

static int test_sapling_persist_pair_busy_exhausted_names_blocker(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];

    printf("sapling_tree_persist_pair names a TRANSIENT blocker once "
          "BEGIN retries are exhausted... ");

    test_make_tmpdir(dir, sizeof(dir), "sapling_persist_pair",
                     "busy_exhaust");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    struct incremental_merkle_tree tree;
    build_one_leaf_sapling_tree(&tree, 0x72);
    struct byte_stream ts;
    stream_init(&ts, 4096);
    ok = ok && incremental_tree_serialize(&tree, &ts);

    blocker_module_init();
    blocker_reset_for_testing();

    /* Every attempt simulates BUSY — retries are bounded, so persist_pair
     * must give up (one WARN line, not unbounded spam) and name a
     * TRANSIENT blocker instead of hanging. */
    sapling_tree_rebuild_test_force_begin_busy(-1);
    bool persisted = ok &&
        sapling_tree_persist_pair(&ndb, ts.data, ts.size, 900790);
    sapling_tree_rebuild_test_force_begin_busy(0);
    stream_free(&ts);

    bool blocker_named = blocker_exists("sapling_tree_rebuild.persist_busy");
    int bclass = blocker_class_for("sapling_tree_rebuild.persist_busy");

    ok = ok && !persisted && blocker_named && bclass == BLOCKER_TRANSIENT;

    blocker_clear("sapling_tree_rebuild.persist_busy");
    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (persisted=%d blocker_named=%d class=%d)\n",
               persisted, blocker_named, bclass);
        failures++;
    }
    return failures;
}

static bool usf_persist_four_while_open(struct node_db *ndb,
                                        const struct byte_stream *ts,
                                        int64_t saved_h, bool tx_opened)
{
    bool persisted_while_open = false;
    if (tx_opened) {
        for (int i = 0; i < 4; i++) {
            persisted_while_open =
                sapling_tree_persist_pair(ndb, ts->data, ts->size, saved_h);
            if (persisted_while_open)
                break;
        }
    }
    return persisted_while_open;
}

static bool usf_persist_busy_blocker_transient(void)
{
    return blocker_exists("sapling_tree_rebuild.persist_busy") &&
           blocker_class_for("sapling_tree_rebuild.persist_busy") ==
               BLOCKER_TRANSIENT;
}

static bool usf_persist_after_close(struct node_db *ndb,
                                    const struct byte_stream *ts,
                                    int64_t saved_h, bool tx_closed)
{
    return tx_closed &&
           sapling_tree_persist_pair(ndb, ts->data, ts->size, saved_h);
}

static bool usf_defer_final_ok(bool persisted_after_close,
                               bool no_extra_deferral, bool blocker_cleared,
                               bool got, bool height_matches)
{
    return persisted_after_close && no_extra_deferral && blocker_cleared &&
           got && height_matches;
}

/* The REAL production failure the adversarial verifier isolated: the rebuild
 * shares the reducer's node_db connection, so a persist attempted while that
 * connection already has an OPEN transaction issues a nested BEGIN, which
 * sqlite refuses with SQLITE_ERROR "cannot start a transaction within a
 * transaction" — NEVER SQLITE_BUSY/LOCKED, so the old bounded BUSY-retry was
 * dead code against it and re-fired forever. The fix detects the foreign open
 * tx via sqlite3_get_autocommit() and DEFERS without writing. A bounded
 * number of repeated deferrals names a height-bearing TRANSIENT blocker;
 * then the persist completes and clears it once the tx closes. This drives
 * that exact sequence on one connection, deterministically. */
static int test_sapling_persist_pair_defers_while_tx_open(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[512];

    printf("sapling_tree_persist_pair defers while the connection has an open "
          "tx, then completes when it closes... ");

    test_make_tmpdir(dir, sizeof(dir), "sapling_persist_pair", "defer_open_tx");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    struct incremental_merkle_tree tree;
    build_one_leaf_sapling_tree(&tree, 0x74);
    struct byte_stream ts;
    stream_init(&ts, 4096);
    ok = ok && incremental_tree_serialize(&tree, &ts);

    blocker_module_init();
    blocker_reset_for_testing();
    sapling_tree_rebuild_test_reset_persist_deferrals();

    const int64_t saved_h = 900791;

    /* Simulate the reducer holding an open batch tx on the SHARED connection:
     * a plain BEGIN with sync_in_batch left false (exactly the begin→flag-set
     * window, and any non-batch writer). This is the state that made the old
     * nested-BEGIN retry dead code. */
    bool tx_opened = ok && node_db_begin(&ndb);

    /* Persist must DEFER without writing. Four attempts exhaust the bounded
     * deferral budget and must name the livelock blocker with the production
     * height, proving an open reducer transaction cannot remain silent. */
    int deferrals_before = sapling_tree_rebuild_test_persist_deferrals();
    bool persisted_while_open =
        usf_persist_four_while_open(&ndb, &ts, saved_h, tx_opened);
    int deferrals_after = sapling_tree_rebuild_test_persist_deferrals();

    bool deferred = !persisted_while_open &&
                    (deferrals_after == deferrals_before + 4);
    bool blocker_named = usf_persist_busy_blocker_transient();

    /* Nothing was written while deferred: the height key must still be absent. */
    int64_t peek_h = -1;
    bool absent_while_deferred =
        !node_db_state_get_int(&ndb, "sapling_tree_rebuild_height", &peek_h);

    /* Close the reducer's tx — the connection returns to autocommit. */
    bool tx_closed = node_db_commit(&ndb);

    /* Now the SAME persist completes (own BEGIN/COMMIT, no nesting) and does
     * NOT defer again — proving the deferral is transient, not a dead end. */
    int deferrals_pre_retry = sapling_tree_rebuild_test_persist_deferrals();
    bool persisted_after_close =
        usf_persist_after_close(&ndb, &ts, saved_h, tx_closed);
    bool no_extra_deferral =
        sapling_tree_rebuild_test_persist_deferrals() == deferrals_pre_retry;
    bool blocker_cleared =
        !blocker_exists("sapling_tree_rebuild.persist_busy");

    int64_t got_h = -1;
    bool got = persisted_after_close &&
               node_db_state_get_int(&ndb, "sapling_tree_rebuild_height",
                                     &got_h);

    stream_free(&ts);
    sapling_tree_rebuild_test_reset_persist_deferrals();

    ok = ok && tx_opened && deferred && blocker_named &&
         absent_while_deferred && tx_closed;
    ok = ok && usf_defer_final_ok(persisted_after_close, no_extra_deferral,
                                  blocker_cleared, got, got_h == saved_h);

    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (tx_opened=%d deferred=%d(%d->%d) blocker_named=%d "
               "absent=%d tx_closed=%d persisted_after=%d "
               "no_extra_defer=%d blocker_cleared=%d got_h=%lld)\n",
               tx_opened, deferred, deferrals_before, deferrals_after,
               blocker_named, absent_while_deferred, tx_closed,
               persisted_after_close, no_extra_deferral, blocker_cleared,
               (long long)got_h);
        failures++;
    }
    return failures;
}

static int test_sapling_tree_rebuild_supervised_child(void)
{
    int failures = 0;
    const int sapling_height = 476969;
    const int tip_height = sapling_height + 100000;
    char dir[256];
    char dbpath[512];

    printf("sapling_tree_rebuild appears as a supervised child... ");

    test_make_tmpdir(dir, sizeof(dir), "sapling_rebuild", "supervised");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    struct incremental_merkle_tree tree;
    build_one_leaf_sapling_tree(&tree, 0x73);
    struct uint256 root;
    incremental_tree_root(&tree, &root);

    struct byte_stream ts;
    stream_init(&ts, 4096);
    ok = ok && incremental_tree_serialize(&tree, &ts);
    ok = ok && node_db_state_set(&ndb, "sapling_tree", ts.data, ts.size);
    ok = ok && node_db_state_set_int(&ndb, "sapling_tree_rebuild_height",
                                     tip_height);

    struct active_chain chain;
    active_chain_init(&chain);
    struct block_index sapling;
    struct block_index tip;
    init_sapling_rebuild_index(&sapling, sapling_height, 0xb1);
    init_sapling_rebuild_index(&tip, tip_height, 0xb2);
    tip.hashFinalSaplingRoot = root;
    ok = ok && active_chain_install_tip_slot(&chain, &sapling);
    ok = ok && active_chain_install_tip_slot(&chain, &tip);

    int appended = ok ? sapling_tree_rebuild(&ndb, &chain, dir) : -1;
    ok = ok && appended == (int)incremental_tree_size(&tree);

    struct supervisor_snapshot snaps[SUPERVISOR_CAP];
    int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
    bool found = false;
    bool completed = false;
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].name, "sync.sapling_tree_rebuild") == 0) {
            found = true;
            completed = snaps[i].completed;
            break;
        }
    }
    ok = ok && found && completed;

    active_chain_free(&chain);
    stream_free(&ts);
    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (appended=%d found=%d completed=%d)\n",
               appended, found, completed);
        failures++;
    }
    return failures;
}

/* The deferred rebuild thread runs the SAME sapling_tree_rebuild() replay
 * for hours on a live node; a replay that never polls
 * thread_registry_shutdown_requested() survives SIGTERM until the external
 * grace SIGKILLs the process (the unclean-stop class). The replay must abort
 * promptly on the registry shutdown flag: return SAPLING_TREE_REBUILD_ABORTED,
 * raise NO fail-closed blocker, and write NO final persist (the per-100k
 * checkpoint persists and the anchor_kv frontier already make the partial
 * fold resumable). Drives the REAL registry flag — reset_for_test restores
 * it so nothing leaks into later tests. */
static int test_sapling_rebuild_aborts_on_shutdown(void)
{
    int failures = 0;
    const int sapling_height = 476969;
    const int tip_height = sapling_height + 100; /* spans an h%100==0 poll */
    char dir[256];
    char dbpath[512];

    printf("sapling rebuild aborts promptly on shutdown (no blocker, no "
           "final persist)... ");

    test_make_tmpdir(dir, sizeof(dir), "sapling_rebuild", "shutdown_abort");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = node_db_open(&ndb, dbpath);

    blocker_module_init();
    blocker_reset_for_testing();

    struct active_chain chain;
    active_chain_init(&chain);
    struct block_index sapling;
    struct block_index tip;
    init_sapling_rebuild_index(&sapling, sapling_height, 0xd1);
    init_sapling_rebuild_index(&tip, tip_height, 0xd2);
    /* No tip hashFinalSaplingRoot and no block bodies: without a shutdown
     * abort this exact fixture runs to the tip and fail-closes on
     * tip_missing_sapling_root — the control run below relies on that. */
    ok = ok && active_chain_install_tip_slot(&chain, &sapling);
    ok = ok && active_chain_install_tip_slot(&chain, &tip);

    thread_registry_reset_for_test();
    thread_registry_request_shutdown();
    int abort_rc = ok ? sapling_tree_rebuild(&ndb, &chain, dir) : 0;
    thread_registry_reset_for_test();

    bool abort_named = abort_rc == SAPLING_TREE_REBUILD_ABORTED;
    bool no_fail_blocker =
        !blocker_exists("sapling_tree_rebuild.fail_closed");
    int64_t persisted_h = -1;
    bool no_final_persist =
        !node_db_state_get_int(&ndb, "sapling_tree_rebuild_height",
                               &persisted_h);

    /* Control: with the flag cleared the SAME fixture must NOT abort — it
     * reaches the tip and fail-closes, proving the abort above came from
     * the shutdown flag and not from the fixture shape. */
    int control_rc = sapling_tree_rebuild(&ndb, &chain, dir);
    bool control_not_aborted = control_rc != SAPLING_TREE_REBUILD_ABORTED;
    blocker_clear("sapling_tree_rebuild.fail_closed");

    ok = ok && abort_named && no_fail_blocker && no_final_persist &&
         control_not_aborted;

    active_chain_free(&chain);
    node_db_close(&ndb);
    test_rm_rf_recursive(dir);

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (abort_rc=%d no_fail_blocker=%d no_final_persist=%d "
               "control_rc=%d)\n", abort_rc, no_fail_blocker,
               no_final_persist, control_rc);
        failures++;
    }
    return failures;
}

int test_unclean_shutdown_advance(void)
{
    int failures = 0;

    printf("sapling persist escalates after 3 consecutive failures... ");

    event_log_init();
    atomic_store(&g_sapling_persist_events, 0);
    event_observe(EV_SAPLING_PERSIST_FAIL, unclean_shutdown_event_observer,
                  NULL);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool opened = node_db_open(&ndb, ":memory:");

    struct db_service svc;
    db_service_init(&svc);
    bool attached = db_service_attach(&svc, &ndb);
    bool started = db_service_start(&svc);

    struct app_runtime_context runtime;
    memset(&runtime, 0, sizeof(runtime));
    runtime.db_service = &svc;
    app_runtime_set_current(&runtime);

    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    {
        struct uint256 cm;
        memset(&cm, 0x42, sizeof(cm));
        incremental_tree_append(&tree, &cm);
    }
    set_sapling_tree_for_flush(&tree);

    process_block_test_fail_next_sapling_persists(3);
    atomic_store(&g_sapling_tree_rebuilding, false);

    bool apply_runs_before_rebuild =
        !utxo_apply_sapling_rebuild_paused();
    atomic_store(&g_sapling_tree_rebuilding, true);
    bool apply_pauses_during_rebuild =
        utxo_apply_sapling_rebuild_paused();
    atomic_store(&g_sapling_tree_rebuilding, false);

    bool ok = opened && attached && started && apply_runs_before_rebuild &&
              apply_pauses_during_rebuild;
    bool first = process_block_test_persist_sapling_tree(false);
    bool second = process_block_test_persist_sapling_tree(false);
    bool third = process_block_test_persist_sapling_tree(false);

    ok = ok && first;
    ok = ok && second;
    ok = ok && !third;
    ok = ok && atomic_load(&g_sapling_persist_events) == 3;
    ok = ok && atomic_load(&g_sapling_tree_rebuilding);

    set_sapling_tree_for_flush(NULL);
    process_block_test_fail_next_sapling_persists(0);
    app_runtime_set_current(NULL);
    db_service_stop(&svc);
    node_db_close(&ndb);

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (opened=%d attached=%d started=%d first=%d second=%d third=%d events=%d rebuilding=%d)\n",
               opened, attached, started, first, second, third,
               atomic_load(&g_sapling_persist_events),
               atomic_load(&g_sapling_tree_rebuilding));
        failures++;
    }

    failures += test_sapling_rebuild_rejects_unverified_checkpoint();
    failures += test_sapling_rebuild_accepts_verified_checkpoint();
    failures += test_sapling_rebuild_rejects_mismatched_checkpoint();
    failures += test_sapling_persist_pair_round_trip();
    failures += test_sapling_persist_pair_inside_caller_transaction();
    failures += test_sapling_rebuild_folds_forward_from_saved_height();
    failures += test_sapling_persist_pair_busy_retry_succeeds();
    failures += test_sapling_persist_pair_busy_exhausted_names_blocker();
    failures += test_sapling_persist_pair_defers_while_tx_open();
    failures += test_sapling_tree_rebuild_supervised_child();
    failures += test_sapling_rebuild_aborts_on_shutdown();

    return failures;
}
