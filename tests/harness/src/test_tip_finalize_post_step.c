/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for tip_finalize_run_post_finalize (engine/jobs/src/
 * tip_finalize_post_step.c) — the reducer's post-finalize side-effect
 * step. The function owns six derived effects after tip publication:
 *
 *   1. wallet transaction sync          — asserted via best_block_height
 *   2. Sapling trial-decrypt + persist  — NOT asserted here: needs a real
 *      ivk + note ciphertext + node_db; covered by the sapling crypto and
 *      wallet groups. We run with sapling_keys.num_keys == 0 so the
 *      branch is exercised as a guarded skip.
 *   3. nullifier spend marking          — asserted (note.spent flips)
 *   4. mempool removal of confirmed txs — asserted (entry removed)
 *   5. MMR append                       — asserted (num_leaves + 1)
 *   6. MMB append                       — asserted (num_leaves + 1)
 *
 * The mempool-only entry point pins the idempotent authority-race repair: it
 * removes confirmed transactions without repeating wallet/MMR/MMB effects.
 * The missing-body branch used to skip ALL six effects silently; it now logs
 * a WARN. The negative cases pin the skip behaviour: no side effect may run
 * when the body is absent (HAVE_DATA clear) or unreadable (HAVE_DATA set,
 * file missing). The final two probes pin the visible-body reconcile dedup:
 * a successful post-finalize stamps the one-shot (height, hash) pair so the
 * late-visible pass is a no-op, while the body-unreadable skip leaves no
 * stamp so a late-arriving body stays eligible for exactly one reconcile. */

#include "test/test_core.h"
#include "util/util.h"
#include "coins/undo.h"
#include "wallet/wallet.h"

#include "chain/chain.h"
#include "config/runtime.h"
#include "controllers/blockchain_controller.h"
#include "platform/private_directory.h"
#include "storage/coins_kv.h"
#include "storage/coins_ram.h"
#include "controllers/sync_controller.h"
#include "controllers/wallet_scan.h"
#include "models/wallet_key.h"
#include "config/boot_internal.h"
#include "config/db_service.h"
#include "core/serialize.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "sapling/sapling.h"
#include "sapling/note_encryption.h"
#include "support/cleanse.h"
#include "jobs/node_pace.h"
#include "services/node_db_catchup_service.h"
#include "wallet/sapling_keys.h"
#include "coins/coins_view.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/sync.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block.h" /* g_body_pull_active */

#include <errno.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* Internal to engine/jobs/src (tip_finalize_post_step.h is not on the
 * include path by design); declare the entry point directly. */
extern void tip_finalize_run_post_finalize(struct block_index *pindex_new);
extern bool tip_finalize_run_mempool_reconcile(struct block_index *pindex_new);
extern bool tip_finalize_run_wallet_reconcile(struct block_index *pindex_new);
extern bool tip_finalize_run_wallet_mempool_reconcile(
    struct block_index *pindex_new);

/* The visible-body dedup seam (engine/jobs/src/tip_finalize_visible_body.c)
 * and the served-tip observe pair it consults. A successful post-finalize
 * must stamp the same one-shot reconcile pair so the late-visible pass for
 * the same (height, hash) is a no-op; the probes below pin that contract. */
extern bool tip_finalize_reconcile_visible_cursor_body(
    struct sqlite3 *db, struct stage *stage, struct main_state *ms);
extern void tip_finalize_visible_body_reset(void);
extern void tip_finalize_observe_reset_last_height(void);
extern void tip_finalize_observe_update_last_advance(int height,
                                                     const uint8_t hash[32]);

static uint64_t tp_mmr_leaves(void)
{
    uint64_t leaves = 0;
    rpc_blockchain_mmr_snapshot(NULL, &leaves, NULL);
    return leaves;
}

static uint64_t tp_mmb_leaves(void)
{
    uint64_t leaves = 0;
    rpc_blockchain_mmb_snapshot(NULL, &leaves, NULL);
    return leaves;
}

#define TP_CHECK(name, expr) do { \
    printf("tip_finalize_post_step: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static int tp_mkdir_p(const char *p)
{
#if defined(_WIN32)
    return platform_private_directory_ensure(p) ? 0 : -1;
#else
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
#endif
}

/* Two-tx block: a minimal coinbase plus a Sapling-v4 tx that carries one
 * shielded spend whose nullifier is `nf_marker` (so the wallet's
 * spend-marking effect is observable without any sapling crypto). The
 * header is NOT consensus-valid — the post step reads the body back from
 * disk and never re-validates it, which is exactly the seam under test. */
static bool tp_build_block(struct block *blk, const uint8_t nf_marker[32])
{
    block_init(blk);
    blk->vtx = zcl_calloc(2, sizeof(struct transaction), "tp_vtx");
    if (!blk->vtx) return false;
    blk->num_vtx = 2;

    struct transaction *cb = &blk->vtx[0];
    transaction_init(cb);
    if (!transaction_alloc(cb, 1, 1)) return false;
    cb->version = 1;
    outpoint_set_null(&cb->vin[0].prevout);
    cb->vin[0].script_sig.data[0] = 0x51; /* OP_1 */
    cb->vin[0].script_sig.size = 1;
    cb->vin[0].sequence = UINT32_MAX;
    cb->vout[0].value = 50;
    cb->vout[0].script_pub_key.data[0] = 0x51;
    cb->vout[0].script_pub_key.size = 1;
    transaction_compute_hash(cb);

    struct transaction *sp = &blk->vtx[1];
    transaction_init(sp);
    if (!transaction_alloc(sp, 1, 1)) return false;
    sp->overwintered = true;
    sp->version = SAPLING_TX_VERSION;
    sp->version_group_id = SAPLING_VERSION_GROUP_ID;
    memset(sp->vin[0].prevout.hash.data, 0x77, 32);
    sp->vin[0].prevout.n = 0;
    sp->vin[0].script_sig.data[0] = 0x51;
    sp->vin[0].script_sig.size = 1;
    sp->vin[0].sequence = UINT32_MAX;
    sp->vout[0].value = 40;
    sp->vout[0].script_pub_key.data[0] = 0x51;
    sp->vout[0].script_pub_key.size = 1;
    sp->value_balance = 0;
    sp->v_shielded_spend =
        zcl_calloc(1, sizeof(struct spend_description), "tp_spend");
    if (!sp->v_shielded_spend) return false;
    sp->num_shielded_spend = 1;
    memcpy(sp->v_shielded_spend[0].nullifier.data, nf_marker, 32);
    transaction_compute_hash(sp);

    blk->header.nVersion = 4;
    memset(blk->header.hashPrevBlock.data, 0x10, 32);
    memset(blk->header.hashMerkleRoot.data, 0x20, 32);
    uint256_set_null(&blk->header.hashFinalSaplingRoot);
    blk->header.nTime = 1700000000u;
    blk->header.nBits = 0x1f07ffffu;
    return true;
}

static struct tx_mempool g_tp_pool;

static bool tp_pool_add(const struct transaction *tx)
{
    struct mempool_entry entry;
    mempool_entry_init(&entry, tx, 1000, 1700000000, 1e6, 1,
                       true, false, 0);
    bool ok = tx_mempool_add_unchecked(&g_tp_pool, &tx->hash, &entry);
    mempool_entry_free(&entry);
    return ok;
}

static job_result_t tp_vb_dummy_step(struct stage_step_ctx *c)
{
    (void)c;
    return JOB_IDLE;
}

/* Seed the durable rows the visible-body gate consults: utxo_apply_log
 * ok=1 at heights 1 and 2 (the body-visibility witness) plus the
 * stage_cursor table the probe stage persists its cursor to. */
static bool tp_vb_seed_db(sqlite3 *db)
{
    if (!db) return false;
    char *err = NULL;
    bool ok = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
        "  ok INTEGER NOT NULL, spent_count INTEGER NOT NULL,"
        "  added_count INTEGER NOT NULL);"
        "INSERT OR REPLACE INTO utxo_apply_log"
        "(height, status, ok, spent_count, added_count)"
        " VALUES(1, 'verified', 1, 1, 2);"
        "INSERT OR REPLACE INTO utxo_apply_log"
        "(height, status, ok, spent_count, added_count)"
        " VALUES(2, 'verified', 1, 1, 2);",
        NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    return ok && stage_table_ensure(db);
}

/* Dedup probe (born-red on the pre-fix tree): a successful post-finalize
 * must stamp the visible-body one-shot reconcile pair for (height, hash),
 * so the late-visible pass over the SAME block is a no-op — zero repeated
 * wallet/mempool effects, zero MMR/MMB growth. Without the stamp this
 * probe re-runs the full idempotent reconcile: it returns true and
 * consumes the re-armed state, failing every assertion below. */
static int tp_vb_dedup_probe(struct wallet *w,
                             const struct transaction *spend_tx,
                             struct block_index *bi,
                             stage_t *vb_stage, sqlite3 *vbdb,
                             struct main_state *vb_ms)
{
    int failures = 0;
    w->sapling_notes[0].spent = false;
    w->best_block_height = 0;
    TP_CHECK("dedup: probe starts with confirmed tx re-armed in pool",
             tx_mempool_exists(&g_tp_pool, &spend_tx->hash));
    uint64_t mmr0 = tp_mmr_leaves();
    uint64_t mmb0 = tp_mmb_leaves();
    tip_finalize_observe_reset_last_height();
    tip_finalize_observe_update_last_advance(bi->nHeight,
                                             bi->phashBlock->data);
    TP_CHECK("dedup: probe cursor at block height",
             stage_set_cursor(vb_stage, vbdb, (uint64_t)bi->nHeight) &&
             stage_cursor(vb_stage) == (uint64_t)bi->nHeight);
    TP_CHECK("dedup: visible-body pass is a no-op after post-finalize",
             !tip_finalize_reconcile_visible_cursor_body(vbdb, vb_stage,
                                                         vb_ms));
    TP_CHECK("dedup: re-armed pool entry untouched",
             tx_mempool_exists(&g_tp_pool, &spend_tx->hash));
    TP_CHECK("dedup: re-armed note untouched",
             w->sapling_notes[0].spent == false);
    TP_CHECK("dedup: re-armed wallet height untouched",
             w->best_block_height == 0);
    TP_CHECK("dedup: MMR unchanged by the no-op pass",
             tp_mmr_leaves() == mmr0);
    TP_CHECK("dedup: MMB unchanged by the no-op pass",
             tp_mmb_leaves() == mmb0);
    return failures;
}

/* Late-body probe: the body-unreadable skip must NOT stamp the dedup
 * pair, so when the height-2 body finally lands the visible-body pass
 * stays eligible and runs the full reconcile exactly once. */
static int tp_vb_late_body_probe(struct wallet *w,
                                 const struct transaction *spend_tx2,
                                 struct block_index *bi2,
                                 struct disk_block_pos *pos2,
                                 const char *netdir,
                                 stage_t *vb_stage, sqlite3 *vbdb,
                                 struct main_state *vb_ms)
{
    int failures = 0;
    tip_finalize_run_post_finalize(bi2); /* HAVE_DATA clear: diagnosed skip */
    TP_CHECK("late-body: height-2 body becomes readable",
             block_index_set_have_data_verified(bi2, pos2, netdir));
    bi2->nStatus |= BLOCK_VALID_SCRIPTS;
    TP_CHECK("late-body: re-arm pool with height-2 spend tx",
             tp_pool_add(spend_tx2));
    w->best_block_height = 0;
    tip_finalize_observe_update_last_advance(bi2->nHeight,
                                             bi2->phashBlock->data);
    TP_CHECK("late-body: probe cursor at block height",
             stage_set_cursor(vb_stage, vbdb, (uint64_t)bi2->nHeight) &&
             stage_cursor(vb_stage) == (uint64_t)bi2->nHeight);
    TP_CHECK("late-body: visible-body reconcile runs for the late body",
             tip_finalize_reconcile_visible_cursor_body(vbdb, vb_stage,
                                                        vb_ms));
    TP_CHECK("late-body: confirmed tx removed",
             !tx_mempool_exists(&g_tp_pool, &spend_tx2->hash));
    TP_CHECK("late-body: wallet height advanced",
             w->best_block_height == bi2->nHeight);
    return failures;
}

static void tp_vb_fixture_teardown(stage_t *vb_stage, sqlite3 *vbdb,
                                   struct main_state *vb_ms, bool vb_ms_live,
                                   struct block *blk2, bool blk2_built)
{
    tip_finalize_visible_body_reset();
    tip_finalize_observe_reset_last_height();
    if (vb_stage) stage_destroy(vb_stage);
    if (vbdb) sqlite3_close(vbdb);
    if (vb_ms_live) main_state_free(vb_ms);
    if (blk2_built) block_free(blk2);
}


/* ── Boundary coin-root recording, driven through the real post-finalize ──
 * The boundary block is finalized at height 100 with the coins applied
 * frontier at 100 (coins through block 99), 101 (exactly block 100), and 102
 * (block 101 already applied: utxo_apply runs ahead of tip_finalize). Only
 * the middle case may carry a bound record; the legacy row is written in all
 * three and differs between the last two for the same block hash, which is why
 * it cannot be compared across nodes. With the in-RAM overlay active the fold
 * misses unflushed coins, so no bound record is written either. */
struct tp_boundary_result {
    uint8_t legacy[32];
    uint8_t bound_hash[32];
    uint8_t bound_root[32];
    bool legacy_found;
    bool bound_found;
};

static bool tp_boundary_node(const char *dir, const struct block_index *bi,
                             int32_t frontier, bool inram,
                             struct tp_boundary_result *out)
{
    static const uint8_t script[1] = {0x51};
    uint8_t txid_a[32], txid_b[32];
    struct block_index at100 = *bi;
    memset(txid_a, 0xa1, 32);
    memset(txid_b, 0xb2, 32);
    at100.nHeight = 100;
    at100.pprev = NULL;

    progress_store_close();
    if (tp_mkdir_p(dir) != 0 || !progress_store_open(dir))
        return false;
    sqlite3 *db = progress_store_db();
    bool ok = db && coins_kv_ensure_schema(db) &&
              coins_kv_add(db, txid_a, 0, 5000, 99, false, script, 1);
    if (ok && frontier >= 102)
        ok = coins_kv_add(db, txid_b, 0, 7000, 101, false, script, 1);
    ok = ok && coins_kv_set_applied_height_in_tx(db, frontier);
    if (ok && inram) {
        setenv("ZCL_FOLD_INRAM", "1", 1);
        ok = coins_ram_init(db, 0, coins_kv_set_applied_height_in_tx) &&
             coins_ram_active();
    }
    if (ok)
        tip_finalize_run_post_finalize(&at100);
    memset(out, 0, sizeof(*out));
    ok = ok && coins_kv_boundary_root_get(db, 100, out->legacy,
                                          &out->legacy_found) &&
         coins_kv_boundary_record_get(db, 100, out->bound_hash,
                                      out->bound_root, &out->bound_found);
    if (inram) {
        coins_ram_shutdown();
        unsetenv("ZCL_FOLD_INRAM");
    }
    return ok;
}

static int tp_boundary_root_probe(const char *dir, const struct block_index *bi)
{
    int failures = 0;
    char d[4][640];
    struct tp_boundary_result behind, exact, ahead, overlay;
    snprintf(d[0], sizeof(d[0]), "%s/boundary_behind", dir);
    snprintf(d[1], sizeof(d[1]), "%s/boundary_exact", dir);
    snprintf(d[2], sizeof(d[2]), "%s/boundary_ahead", dir);
    snprintf(d[3], sizeof(d[3]), "%s/boundary_inram", dir);
    bool ran = tp_boundary_node(d[0], bi, 100, false, &behind) &&
               tp_boundary_node(d[1], bi, 101, false, &exact) &&
               tp_boundary_node(d[2], bi, 102, false, &ahead) &&
               tp_boundary_node(d[3], bi, 101, true, &overlay);
    progress_store_close();
    TP_CHECK("boundary: four fixture nodes finalized height 100", ran);
    if (!ran)
        return failures;
    TP_CHECK("boundary: every node wrote the legacy row",
             behind.legacy_found && exact.legacy_found &&
             ahead.legacy_found && overlay.legacy_found);
    TP_CHECK("boundary: legacy row is not a function of the height "
             "(same block, frontier 101 vs 102, different roots)",
             memcmp(exact.legacy, ahead.legacy, 32) != 0);
    TP_CHECK("boundary: frontier h (coins through h-1) records no bound root",
             !behind.bound_found);
    TP_CHECK("boundary: frontier h+1 records a root bound to the block",
             exact.bound_found &&
             memcmp(exact.bound_hash, bi->hashBlock.data, 32) == 0 &&
             memcmp(exact.bound_root, exact.legacy, 32) == 0);
    TP_CHECK("boundary: frontier h+2 (utxo_apply ahead) records no bound root",
             !ahead.bound_found);
    TP_CHECK("boundary: active in-RAM overlay records no bound root",
             !overlay.bound_found);
    return failures;
}

static bool tp_noop_write(struct node_db *ndb, void *ctx)
{
    (void)ndb;
    (void)ctx;
    return true;
}

/* The note's stored witness: at height, with the given root. */
static bool tp_witness_is(struct node_db *ndb, const uint8_t txid[32],
                          int height, const struct uint256 *root)
{
    uint8_t *blob = NULL;
    size_t len = 0;
    int wh = -1;
    struct incremental_merkle_tree proto;
    struct incremental_witness w;
    struct byte_stream s;
    struct uint256 got = {0};
    sapling_tree_init(&proto);
    if (!db_sapling_note_load_witness(ndb, txid, 0, &blob, &len, &wh) || !blob)
        return false;
    stream_init_from_data(&s, blob, len);
    bool ok = incremental_witness_deserialize(
        &w, &s, SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH, proto.combine,
        proto.uncommitted);
    free(blob);
    if (!ok)
        return false;
    incremental_witness_root(&w, &got);
    return wh == height && uint256_eq(&got, root);
}

struct tp_wit {
    struct block blk[2];
    struct block_index bi[3];
    struct uint256 cm[3], root[3];
    bool built, on_disk, have_data;
};

/* Commitments, roots and the two blocks that carry the second and third. */
static void tp_wit_blocks(struct tp_wit *t)
{
    struct incremental_merkle_tree tree;
    uint8_t marker[2][32];
    memset(marker[0], 0x5b, 32);
    memset(marker[1], 0x5c, 32);
    sapling_tree_init(&tree);
    for (int i = 0; i < 3; i++) {
        t->cm[i].data[0] = (uint8_t)(0x31 + i);
        incremental_tree_append(&tree, &t->cm[i]);
        incremental_tree_root(&tree, &t->root[i]);
    }
    t->built = tp_build_block(&t->blk[0], marker[0]) &&
               tp_build_block(&t->blk[1], marker[1]);
    for (int i = 0; t->built && i < 2; i++) {
        struct transaction *tx = &t->blk[i].vtx[1];
        tx->v_shielded_output =
            zcl_calloc(1, sizeof(struct output_description), "tp_output");
        tx->num_shielded_output = tx->v_shielded_output ? 1 : 0;
        if (tx->v_shielded_output)
            tx->v_shielded_output[0].cm = t->cm[i + 1];
        transaction_compute_hash(tx);
        t->blk[i].header.hashFinalSaplingRoot = t->root[i + 1];
    }
}

/* Block index entries for heights 1..3 and the two bodies written to disk. */
static bool tp_wit_bodies(struct tp_wit *t, const char *netdir)
{
    const struct chain_params *cp = chain_params_get();
    t->on_disk = t->built;
    t->have_data = t->on_disk;
    for (int i = 0; i < 3; i++)
        block_index_init(&t->bi[i]);
    for (int i = 0; i < 3; i++) {
        t->bi[i].nHeight = i + 1;
        t->bi[i].hashFinalSaplingRoot = t->root[i];
        t->bi[i].pprev = i ? &t->bi[i - 1] : NULL;
    }
    for (int i = 0; t->built && i < 2; i++) {
        struct block_index *bi = &t->bi[i + 1];
        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        t->on_disk = t->on_disk && t->blk[i].vtx[1].num_shielded_output == 1 &&
                     write_block_to_disk(&t->blk[i], &pos, netdir,
                                         cp->pchMessageStart);
        block_get_hash(&t->blk[i], &bi->hashBlock);
        bi->phashBlock = &bi->hashBlock;
        bi->nTime = t->blk[i].header.nTime;
        bi->nBits = t->blk[i].header.nBits;
        t->have_data = t->have_data && t->on_disk &&
                       block_index_set_have_data_verified(bi, &pos, netdir);
    }
    return t->built && t->have_data;
}

/* Heights 1..3: a reducer anchor row at 1, block 2 carrying one output and
 * block 3 another, both bodies on disk. */
static bool tp_wit_build(struct tp_wit *t, const char *netdir)
{
    tp_wit_blocks(t);
    return tp_wit_bodies(t, netdir);
}

static void tp_wit_free(struct tp_wit *t)
{
    if (t->built)
        for (int i = 0; i < 2; i++)
            block_free(&t->blk[i]);
}

/* The note's nullifier the wallet key derives for a commitment at position. */
static bool tp_wit_expected_nf(const struct sapling_key_entry *key,
                               const uint8_t rcm[32], uint64_t position,
                               uint8_t nf[32])
{
    uint8_t ak[32], nk[32];
    sapling_ask_to_ak(key->xsk.expsk.ask, ak);
    sapling_nsk_to_nk(key->xsk.expsk.nsk, nk);
    return sapling_compute_nf(key->diversifier, key->pk_d, 1000, rcm, ak, nk,
                              position, nf);
}

/* A stored note's nullifier equals nf. */
static bool tp_wit_note_nf_is(struct node_db *ndb, const uint8_t txid[32],
                              const uint8_t nf[32])
{
    struct db_sapling_note *notes = NULL;
    int n = db_sapling_note_list_unspent_alloc(ndb, &notes);
    bool ok = false;
    for (int i = 0; i < n; i++)
        if (memcmp(notes[i].txid, txid, 32) == 0)
            ok = memcmp(notes[i].nullifier, nf, 32) == 0;
    free(notes);
    return ok;
}

struct tp_wire {
    char dir[256], netdir[512];
    struct tp_wit t;
    struct node_db ndb;
    struct db_service svc;
    struct app_runtime_context rt;
    struct wallet *w;
    const struct sapling_key_entry *key;
    uint8_t txid[2][32], rcm[2][32];
    bool db_open, svc_up;
};

/* Data directory, both block bodies on disk and the reducer anchor row at 1. */
static bool tp_wire_chain(struct tp_wire *x)
{
    char blocksdir[640];
    struct incremental_merkle_tree t1;
    test_make_tmpdir(x->dir, sizeof(x->dir), "tip_post", "wit");
    SetDataDir(x->dir);
    GetDataDir(true, x->netdir, sizeof(x->netdir));
    tp_mkdir_p(x->netdir);
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", x->netdir);
    tp_mkdir_p(blocksdir);
    memset(&x->t, 0, sizeof(x->t));
    bool built = tp_wit_build(&x->t, x->netdir);
    sapling_tree_init(&t1);
    incremental_tree_append(&t1, &x->t.cm[0]);
    progress_store_close();
    return built && progress_store_open(x->dir) &&
           anchor_kv_ensure_schema(progress_store_db()) &&
           anchor_kv_initialize_history(progress_store_db(), 1) &&
           anchor_kv_add_tree(progress_store_db(), ANCHOR_POOL_SAPLING, &t1, 1);
}

/* A wallet holding a real Sapling key and one note per block, recorded in
 * node.db with a placeholder nullifier, and the db service running. */
static bool tp_wire_wallet(struct tp_wire *x)
{
    char dbpath[640];
    uint8_t seed[32], dv[11], pk[32], memo[512] = {0};
    uint8_t nf_old[2][32] = {{0x99}, {0x98}};
    uint8_t ids[2] = {0x44, 0x45}, rcms[2] = {0x51, 0x52};
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", x->dir);
    memset(seed, 0x2a, sizeof(seed));
    x->w = zcl_calloc(1, sizeof(*x->w), "tp_wit_wallet");
    x->db_open = x->w && node_db_open(&x->ndb, dbpath);
    if (!x->db_open)
        return false;
    wallet_init(x->w);
    if (!wallet_readiness_initialize(x->w, WALLET_READINESS_READY, false, 0)) return false;
    x->w->sapling_notes = zcl_calloc(2, sizeof(*x->w->sapling_notes), "tp_notes");
    if (!x->w->sapling_notes ||
        !sapling_keystore_set_seed(&x->w->sapling_keys, seed) ||
        !sapling_keystore_new_address(&x->w->sapling_keys, dv, pk))
        return false;
    x->key = &x->w->sapling_keys.keys[0];
    db_service_init(&x->svc);
    x->svc_up = db_service_attach(&x->svc, &x->ndb) &&
                db_service_start_test_worker(&x->svc);
    for (int i = 0; x->svc_up && i < 2; i++) {
        x->txid[i][0] = ids[i];
        x->rcm[i][0] = rcms[i];
        x->svc_up = node_db_sync_sapling_note(
            &x->ndb, x->txid[i], 0, 1000, x->rcm[i], memo, 512, x->key->ivk,
            x->key->diversifier, x->key->pk_d, x->t.cm[i + 1].data, nf_old[i],
            i + 2);
        x->w->sapling_notes[i].used = true;
        memcpy(x->w->sapling_notes[i].txid.data, x->txid[i], 32);
        memcpy(x->w->sapling_notes[i].nf, nf_old[i], 32);
    }
    x->w->num_sapling_notes = 2;
    x->w->sapling_notes_cap = 2;
    x->rt.db_service = &x->svc;
    x->rt.wallet = x->w;
    app_runtime_set_current(&x->rt);
    return x->svc_up;
}

static int tp_wire_check(struct tp_wire *x, bool up)
{
    int failures = 0;
    uint8_t nf[2][32];
    TP_CHECK("witness wiring: fixture up", up);
    TP_CHECK("witness wiring: reconcile runs",
             up && tip_finalize_run_wallet_reconcile(&x->t.bi[2]));
    TP_CHECK("witness wiring: queue drains",
             up && db_service_run_write(&x->svc, tp_noop_write, NULL));
    TP_CHECK("witness wiring: the note in the tip block has a witness equal "
             "to the header root",
             up && tp_witness_is(&x->ndb, x->txid[1], 3, &x->t.root[2]));
    TP_CHECK("witness wiring: the note in block 2 is replayed from disk to "
             "the same root",
             up && tp_witness_is(&x->ndb, x->txid[0], 3, &x->t.root[2]));
    TP_CHECK("witness wiring: both notes hold the nullifier of their position",
             up && tp_wit_expected_nf(x->key, x->rcm[0], 1, nf[0]) &&
             tp_wit_expected_nf(x->key, x->rcm[1], 2, nf[1]) &&
             tp_wit_note_nf_is(&x->ndb, x->txid[0], nf[0]) &&
             tp_wit_note_nf_is(&x->ndb, x->txid[1], nf[1]));
    TP_CHECK("witness wiring: the live wallet note holds it too",
             up && memcmp(x->w->sapling_notes[0].nf, nf[0], 32) == 0 &&
             memcmp(x->w->sapling_notes[1].nf, nf[1], 32) == 0);
    return failures;
}

static void tp_wire_close(struct tp_wire *x)
{
    app_runtime_set_current(NULL);
    if (x->svc_up)
        db_service_stop(&x->svc);
    if (x->db_open)
        node_db_close(&x->ndb);
    if (x->w) {
        wallet_free(x->w);
        free(x->w);
    }
    tp_wit_free(&x->t);
    progress_store_close();
    SetDataDir("");
    ClearDataDirCache();
    test_rm_rf(x->dir);
}

/* Tip finalize with a started db service, a wallet holding a real Sapling
 * key, two notes (one in block 2, one in block 3), a reducer anchor row at
 * height 1 and both bodies on disk. The wallet reconcile of block 3 must
 * queue the witness maintenance: the note in block 2 has no witness, so its
 * block is read back from disk and replayed, and both notes end with a
 * witness equal to the header root at 3 and the nullifier their key derives
 * for their position. Removing the call from the reconcile, the disk read,
 * the replay or the wallet argument leaves a note without. */
static int tp_witness_wiring(void)
{
    static struct tp_wire x;
    memset(&x, 0, sizeof(x));
    bool up = tp_wire_chain(&x) && tp_wire_wallet(&x);
    int failures = tp_wire_check(&x, up);
    tp_wire_close(&x);
    return failures;
}

#ifndef _WIN32
/* Replace the tip output with a decryptable note for the fixture wallet. */
static bool tp_gentle_tip_body(struct tp_wire *x, uint8_t rcm[32], struct uint256 *txid)
{
    struct transaction *tx = &x->t.blk[1].vtx[1];
    struct output_description *out = &tx->v_shielded_output[0];
    const struct sapling_key_entry *key = x->key;
    uint8_t pt[564] = {0}, esk[32] = {2}, shared[32], enc_key[32];
    rcm[0] = 1; pt[0] = 1; memcpy(pt + 1, key->diversifier, 11);
    pt[12] = 0xe8; pt[13] = 3; memcpy(pt + 20, rcm, 32);
    bool ok = sapling_compute_cm(key->diversifier, key->pk_d, 1000, rcm, out->cm.data) &&
        sapling_ka_derivepublic(key->diversifier, esk, out->ephemeral_key.data) &&
        sapling_ka_agree(key->pk_d, esk, shared) &&
        sapling_kdf(enc_key, shared, out->ephemeral_key.data) &&
        sapling_note_encrypt(enc_key, pt, sizeof(pt), out->enc_ciphertext);
    memcpy(tx->v_shielded_spend[0].nullifier.data, x->w->sapling_notes[0].nf, 32);
    struct incremental_merkle_tree tree; sapling_tree_init(&tree);
    incremental_tree_append(&tree, &x->t.cm[0]); incremental_tree_append(&tree, &x->t.cm[1]);
    incremental_tree_append(&tree, &out->cm); incremental_tree_root(&tree, &x->t.root[2]);
    x->t.blk[1].header.hashFinalSaplingRoot = x->t.root[2];
    transaction_compute_hash(tx); *txid = tx->hash;
    struct disk_block_pos pos; disk_block_pos_init(&pos);
    const struct chain_params *cp = chain_params_get();
    ok = ok && write_block_to_disk(&x->t.blk[1], &pos, x->netdir, cp->pchMessageStart);
    if (ok) {
        struct block_index *bi = &x->t.bi[2];
        block_get_hash(&x->t.blk[1], &bi->hashBlock); bi->phashBlock = &bi->hashBlock;
        bi->hashFinalSaplingRoot = x->t.root[2];
        ok = block_index_set_have_data_verified(bi, &pos, x->netdir);
    }
    memory_cleanse(pt, sizeof(pt)); memory_cleanse(shared, sizeof(shared));
    memory_cleanse(enc_key, sizeof(enc_key));
    return ok;
}

static bool tp_gentle_note_absent(struct tp_wire *x, const struct uint256 *txid)
{
    struct db_sapling_note *notes = NULL;
    int n = db_sapling_note_list_unspent_alloc(&x->ndb, &notes);
    bool absent = n >= 0;
    for (int i = 0; i < n; i++)
        if (memcmp(notes[i].txid, txid->data, 32) == 0) absent = false;
    free(notes);
    for (size_t i = 0; i < x->w->num_sapling_notes; i++)
        if (uint256_eq(&x->w->sapling_notes[i].txid, txid)) absent = false;
    return absent;
}

static bool tp_gentle_pending(struct tp_wire *x)
{
    struct wallet_tx pending; memset(&pending, 0, sizeof(pending));
    pending.used = true; pending.confirms = 0;
    bool ok = transaction_copy(&pending.tx, &x->t.blk[1].vtx[1]) &&
              wallet_add_to_wallet(x->w, &pending);
    transaction_free(&pending.tx); return ok;
}

static int tp_gentle_tip_verify(struct tp_wire *x, const struct uint256 *txid,
                                const uint8_t rcm[32], bool drained)
{
    int failures = 0; uint8_t nf[32];
    struct wallet_tx confirmed; memset(&confirmed, 0, sizeof(confirmed));
    bool confirms = drained && wallet_get_tx_copy(x->w, txid, &confirmed) &&
                    confirmed.confirms == 1 && uint256_eq(&confirmed.hash_block, x->t.bi[2].phashBlock);
    TP_CHECK("wallet reconcile confirms the transaction while history is deferred", confirms);
    transaction_free(&confirmed.tx);
    TP_CHECK("wallet reconcile discovers the note with current witness and nullifier",
             drained && tp_witness_is(&x->ndb, txid->data, 3, &x->t.root[2]) &&
             tp_wit_expected_nf(x->key, rcm, 2, nf) && tp_wit_note_nf_is(&x->ndb, txid->data, nf));
    TP_CHECK("wallet reconcile marks the prior nullifier spent and writer queue progresses",
             drained && x->w->sapling_notes[0].spent && x->w->best_block_height == 3);
    return failures;
}

static bool tp_gentle_chain(struct main_state *ms, struct tp_wire *x, bool body)
{
    return body && active_chain_install_tip_slot(&ms->chain_active, &x->t.bi[0]) &&
        active_chain_install_tip_slot(&ms->chain_active, &x->t.bi[1]) &&
        active_chain_install_tip_slot(&ms->chain_active, &x->t.bi[2]);
}

static int tp_gentle_wallet_tip(void)
{
    static struct tp_wire x; static struct main_state ms;
    memset(&x, 0, sizeof(x)); memset(&ms, 0, sizeof(ms));
    int failures = 0; uint8_t rcm[32] = {0}; struct uint256 txid = {0};
    bool up = tp_wire_chain(&x) && tp_wire_wallet(&x);
    bool body = up && tp_gentle_tip_body(&x, rcm, &txid) && tp_gentle_pending(&x);
    main_state_init(&ms); x.rt.main_state = &ms;
    x.t.bi[0].phashBlock = &x.t.bi[0].hashBlock;
    bool chain = tp_gentle_chain(&ms, &x, body);
    TP_CHECK("encrypted tip note absent before wallet reconcile",
             body && tp_gentle_note_absent(&x, &txid));
    node_pace_set_datadir(NULL); node_pace_set(NODE_PACE_GENTLE);
    bool deferred = false; int before = up ? node_db_sync_get_tip_height(&x.ndb) : -1;
    int walk = chain ? node_db_catchup_service_run_origin(&x.ndb, true, &deferred,
                                      &ms.chain_active, x.w, x.netdir) : -1;
    TP_CHECK("background history deferred before tip reconcile",
             chain && before < 3 && walk == 0 && deferred && node_db_sync_get_tip_height(&x.ndb) == before);
    bool tip = chain && tip_finalize_run_wallet_reconcile(&x.t.bi[2]);
    bool drained = tip && db_service_run_write(&x.svc, tp_noop_write, NULL);
    failures += tp_gentle_tip_verify(&x, &txid, rcm, drained);
    node_pace_set(NODE_PACE_NORMAL); node_pace_test_end_resume_grace();
    x.rt.main_state = NULL; main_state_free(&ms); tp_wire_close(&x); return failures;
}
#endif


/* ---- Mutation-sweep gap closers: tripwire verdicts, entry refusals, coins
 * invalidation and the golden-window walk ---- */

/* The header is not on the include path; mirror its enum and externs. */
enum tp_tripwire { TP_TW_SKIP = 0, TP_TW_MATCH = 1, TP_TW_MISMATCH = 2 };
extern enum tp_tripwire sha3_window_tripwire_report(int window_index,
                                                    bool matched);
extern enum tp_tripwire sha3_window_tripwire_eval(int window_index,
                                                  const uint8_t *concat,
                                                  size_t len);
extern const size_t g_sha3_windows_count;

static bool tp_mismatch_reason(char *out, size_t size,
                               struct blocker_snapshot *snap)
{
    memset(snap, 0, sizeof(*snap));
    if (!blocker_find_by_id_prefix("sha3_window_mismatch", snap))
        return false;
    snprintf(out, size, "%s", snap->reason);
    return true;
}

static int tp_mut_tripwire_skips(int cnt)
{
    int failures = 0;
    TP_CHECK("tripwire: negative window skips",
             sha3_window_tripwire_report(-1, false) == TP_TW_SKIP);
    TP_CHECK("tripwire: window == count skips",
             sha3_window_tripwire_report(cnt, false) == TP_TW_SKIP);
    TP_CHECK("tripwire: window past count skips",
             sha3_window_tripwire_report(cnt + 5, true) == TP_TW_SKIP);
    TP_CHECK("tripwire: skips raise no blocker",
             !blocker_exists("sha3_window_mismatch"));
    TP_CHECK("tripwire: window 0 matched is MATCH",
             sha3_window_tripwire_report(0, true) == TP_TW_MATCH);
    TP_CHECK("tripwire: last covered window matched is MATCH",
             sha3_window_tripwire_report(cnt - 1, true) == TP_TW_MATCH);
    TP_CHECK("tripwire: matches raise no blocker",
             !blocker_exists("sha3_window_mismatch"));
    TP_CHECK("tripwire eval: negative window skips",
             sha3_window_tripwire_eval(-1, (const uint8_t *)"x", 1) ==
             TP_TW_SKIP);
    TP_CHECK("tripwire eval: window == count skips",
             sha3_window_tripwire_eval(cnt, (const uint8_t *)"x", 1) ==
             TP_TW_SKIP);
    TP_CHECK("tripwire eval: skips raise no blocker",
             !blocker_exists("sha3_window_mismatch"));
    return failures;
}

static int tp_mut_tripwire_mismatch(int wi, const char *want_range)
{
    int failures = 0;
    char reason[256]; struct blocker_snapshot snap;
    blocker_clear("sha3_window_mismatch");
    TP_CHECK("tripwire: unmatched window is MISMATCH",
             sha3_window_tripwire_report(wi, false) == TP_TW_MISMATCH);
    TP_CHECK("tripwire: mismatch registers the blocker",
             tp_mismatch_reason(reason, sizeof(reason), &snap));
    TP_CHECK("tripwire: reason names window and height range",
             strstr(reason, want_range) != NULL);
    TP_CHECK("tripwire: evidence-only permanent blocker",
             snap.class == BLOCKER_PERMANENT &&
             snap.escape_action[0] == '\0' &&
             snap.escape_deadline_us == 0 &&
             strcmp(snap.owner_subsystem, "sha3_window_tripwire") == 0);
    blocker_clear("sha3_window_mismatch");
    return failures;
}

static int tp_mut_tripwire(void)
{
    int failures = 0;
    blocker_module_init();
    blocker_clear("sha3_window_mismatch");
    int cnt = (int)g_sha3_windows_count;
    TP_CHECK("tripwire: golden table covers several windows", cnt > 1);
    if (cnt <= 1) return failures;
    failures += tp_mut_tripwire_skips(cnt);
    failures += tp_mut_tripwire_mismatch(0, "wi=0 h=0..999");
    failures += tp_mut_tripwire_mismatch(1, "wi=1 h=1000..1999");
    TP_CHECK("tripwire eval: wrong bytes for window 0 mismatch",
             sha3_window_tripwire_eval(0, (const uint8_t *)"abc", 3) ==
             TP_TW_MISMATCH && blocker_exists("sha3_window_mismatch"));
    blocker_clear("sha3_window_mismatch");
    TP_CHECK("tripwire eval: wrong bytes for last window mismatch",
             sha3_window_tripwire_eval(cnt - 1, (const uint8_t *)"abc", 3) ==
             TP_TW_MISMATCH);
    blocker_clear("sha3_window_mismatch");
    return failures;
}

/* Entry points refuse NULL and an unreadable body without running effects. */
static int tp_mut_entry_refusals(const struct block *blk,
                                 struct block_index *nodata,
                                 struct block_index *unread)
{
    int failures = 0;
    TP_CHECK("entry: mempool reconcile refuses NULL",
             !tip_finalize_run_mempool_reconcile(NULL));
    TP_CHECK("entry: wallet reconcile refuses NULL",
             !tip_finalize_run_wallet_reconcile(NULL));
    TP_CHECK("entry: wallet+mempool reconcile refuses NULL",
             !tip_finalize_run_wallet_mempool_reconcile(NULL));
    TP_CHECK("entry: mempool reconcile reports no-body",
             !tip_finalize_run_mempool_reconcile(nodata));
    TP_CHECK("entry: wallet reconcile reports no-body",
             !tip_finalize_run_wallet_reconcile(nodata));
    TP_CHECK("entry: wallet+mempool reconcile reports no-body",
             !tip_finalize_run_wallet_mempool_reconcile(nodata));
    TP_CHECK("entry: mempool reconcile reports unreadable body",
             !tip_finalize_run_mempool_reconcile(unread));
    TP_CHECK("entry: wallet reconcile reports unreadable body",
             !tip_finalize_run_wallet_reconcile(unread));
    TP_CHECK("entry: wallet+mempool reconcile reports unreadable body",
             !tip_finalize_run_wallet_mempool_reconcile(unread));
    TP_CHECK("entry: refusals leave the mempool alone",
             tx_mempool_exists(&g_tp_pool, &blk->vtx[1].hash));
    return failures;
}

/* A fake backing store: every txid resolves to one live output, so a cache
 * lookup loads and keeps an entry the reconcile must then drop. */
static bool tp_fake_get_coins(void *self, const struct uint256 *txid,
                              struct coins *out)
{
    (void)self; (void)txid;
    coins_init(out);
    out->vout = zcl_calloc(1, sizeof(struct tx_out), "tp_fake_vout");
    if (!out->vout) return false;
    out->num_vout = 1;
    out->vout[0].value = 1;
    out->height = 1;
    return true;
}

static void *tp_trylock_thread(void *arg)
{
    struct main_state *m = arg;
    bool got = zcl_mutex_trylock(&m->cs_main);
    if (got) zcl_mutex_unlock(&m->cs_main);
    return got ? (void *)1 : NULL;
}

static bool tp_cs_main_free_for_other_thread(struct main_state *m)
{
    pthread_t t;
    void *got = NULL;
    if (pthread_create(&t, NULL, tp_trylock_thread, m) != 0) return false;
    pthread_join(t, &got);
    return got != NULL;
}

static bool tp_prime(struct coins_view_cache *c, const struct uint256 *h)
{
    struct coins tmp;
    coins_init(&tmp);
    bool ok = coins_view_cache_get_coins(c, h, &tmp);
    coins_free(&tmp);
    return ok;
}

/* The reconcile must drop the cached generation of every txid the block
 * created and every non-coinbase prevout it spent, and nothing else. */
static int tp_mut_coins_invalidate(struct app_runtime_context *rt,
                                   struct block *blk,
                                   struct block_index *bi)
{
    int failures = 0;
    struct coins_view_vtable vt = { .get_coins = tp_fake_get_coins };
    struct coins_view backing = { .vtable = &vt, .impl = NULL };
    struct coins_view_cache cache;
    struct main_state ms;
    struct uint256 zero;
    memset(&zero, 0, sizeof(zero));
    coins_view_cache_init(&cache, &backing);
    main_state_init(&ms);
    TP_CHECK("coins: prime coinbase txid",
             tp_prime(&cache, &blk->vtx[0].hash));
    TP_CHECK("coins: prime spend txid", tp_prime(&cache, &blk->vtx[1].hash));
    TP_CHECK("coins: prime spent prevout",
             tp_prime(&cache, &blk->vtx[1].vin[0].prevout.hash));
    TP_CHECK("coins: prime an unrelated txid", tp_prime(&cache, &zero));
    TP_CHECK("coins: four cached entries",
             coins_map_count(&cache.cache_coins) == 4);
    rt->coins_tip = &cache;
    rt->main_state = &ms;
    TP_CHECK("coins: mempool reconcile runs",
             tip_finalize_run_mempool_reconcile(bi));
    TP_CHECK("coins: only the unrelated entry remains",
             coins_map_count(&cache.cache_coins) == 1 &&
             coins_map_find(&cache.cache_coins, &zero) != NULL);
    TP_CHECK("coins: cs_main is released after the reconcile",
             tp_cs_main_free_for_other_thread(&ms));
    TP_CHECK("coins: reconcile removed the confirmed spend from the pool",
             !tx_mempool_exists(&g_tp_pool, &blk->vtx[1].hash));
    /* Restore the pool state the later probes expect. */
    TP_CHECK("coins: re-arm the pool", tp_pool_add(&blk->vtx[1]));
    rt->coins_tip = NULL;
    rt->main_state = NULL;
    main_state_free(&ms);
    coins_view_cache_free(&cache);
    return failures;
}

/* Window walk: 1000 on-disk blocks, a tip at the window's last height; the
 * digest cannot equal the golden one, so a complete walk raises evidence
 * and any gap or missing body raises none. */
#define TP_WIN 1000

static bool tp_win_write(struct block_index *bis, int i, const char *netdir)
{
    uint8_t nf[32];
    memset(nf, 0x5a, sizeof(nf));
    struct block b;
    bool built = tp_build_block(&b, nf);
    bool ok = built;
    if (ok) {
        b.header.nTime = 1700001000u + (uint32_t)i;
        if (i == TP_WIN - 1) { /* BIP34 push of 999 so no label shift fires */
            b.vtx[0].vin[0].script_sig.data[0] = 0x02;
            b.vtx[0].vin[0].script_sig.data[1] = 0xE7;
            b.vtx[0].vin[0].script_sig.data[2] = 0x03;
            b.vtx[0].vin[0].script_sig.size = 3;
            transaction_compute_hash(&b.vtx[0]);
        }
    }
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    const struct chain_params *cp = chain_params_get();
    ok = ok && write_block_to_disk(&b, &pos, netdir, cp->pchMessageStart);
    if (ok) {
        block_index_init(&bis[i]);
        block_get_hash(&b, &bis[i].hashBlock);
        bis[i].phashBlock = &bis[i].hashBlock;
        bis[i].nHeight = i;
        bis[i].nTime = b.header.nTime;
        bis[i].nBits = b.header.nBits;
        bis[i].pprev = i > 0 ? &bis[i - 1] : NULL;
        ok = block_index_set_have_data_verified(&bis[i], &pos, netdir);
    }
    if (built) block_free(&b);
    return ok;
}

static int tp_mut_window_walk(const char *netdir)
{
    int failures = 0;
    char reason[256]; struct blocker_snapshot snap;
    struct block_index *bis = zcl_calloc(TP_WIN, sizeof(*bis), "tp_win_bis");
    bool built = bis != NULL;
    for (int i = 0; built && i < TP_WIN; i++)
        built = tp_win_write(bis, i, netdir);
    TP_CHECK("window: 1000 bodies on disk", built);
    if (built) {
        blocker_clear("sha3_window_mismatch");
        tip_finalize_run_post_finalize(&bis[TP_WIN - 1]);
        TP_CHECK("window: digest mismatch raises the evidence blocker",
                 tp_mismatch_reason(reason, sizeof(reason), &snap) &&
                 strstr(reason, "wi=0 h=0..999") != NULL);
        blocker_clear("sha3_window_mismatch");
        int keep = bis[500].nFile;
        bis[500].nFile = 9999;
        tip_finalize_run_post_finalize(&bis[TP_WIN - 1]);
        TP_CHECK("window: a missing body raises no false evidence",
                 !blocker_exists("sha3_window_mismatch"));
        bis[500].nFile = keep;
        bis[200].nHeight = 7;
        tip_finalize_run_post_finalize(&bis[TP_WIN - 1]);
        TP_CHECK("window: a mislabelled link raises no false evidence",
                 !blocker_exists("sha3_window_mismatch"));
        bis[200].nHeight = 200;
        blocker_clear("sha3_window_mismatch");
    }
    free(bis);
    return failures;
}

int test_tip_finalize_post_step(void);
static int tp_birthday_verdict(struct wallet *w, bool match, bool stepped)
{
    int failures = 0;
    TP_CHECK("birthday live floor verdict", stepped &&
             (match ? (w->scan_retry.pending && w->scan_retry.from == 3 &&
                       strcmp(w->scan_retry.blocker, WALLET_BIRTHDAY_SCAN_PENDING) == 0) :
              (w->scan_retry.pending && w->initial_scan_floor == 0 &&
               wallet_scanned_through_height(w) < 0 &&
               strcmp(w->scan_retry.blocker, WALLET_BIRTHDAY_CHANGED_BLOCKER) == 0)));
    return failures;
}

static int tp_birthday_live(bool match)
{
    int failures = 0;
    static struct tp_wire x;
    static struct main_state ms;
    memset(&x, 0, sizeof(x));
    memset(&ms, 0, sizeof(ms));
    bool up = tp_wire_chain(&x) && tp_wire_wallet(&x);
    if (!up) {
        TP_CHECK("birthday live fixture", false);
        tp_wire_close(&x);
        return failures;
    }
    main_state_init(&ms);
    x.rt.main_state = &ms;
    x.t.bi[0].phashBlock = &x.t.bi[0].hashBlock;
    uint8_t expected[32];
    memcpy(expected, x.t.bi[2].phashBlock->data, sizeof(expected));
    if (!match)
        expected[0] ^= 1;
    bool ready = db_wallet_birthday_set(&x.ndb, 103, expected) &&
        active_chain_move_window_tip(&ms.chain_active, &x.t.bi[0]);
    if (match)
        x.w->sapling_keys.num_unscannable = 1;
    if (ready)
        (void)boot_wallet_boot_catch_up(x.w, &ms.chain_active, x.dir, &x.ndb);
    TP_CHECK("birthday waits unread before live floor", ready &&
             x.w->scan_retry.pending && wallet_scanned_through_height(x.w) < 0);
    bool stepped = ready && active_chain_move_window_tip(&ms.chain_active, &x.t.bi[1]) &&
        tip_finalize_run_wallet_reconcile(&x.t.bi[1]);
    TP_CHECK("birthday stays unread at the preceding tip", stepped &&
             x.w->scan_retry.pending && wallet_scanned_through_height(x.w) < 0);
    stepped = stepped && active_chain_move_window_tip(&ms.chain_active, &x.t.bi[2]) &&
        tip_finalize_run_wallet_reconcile(&x.t.bi[2]);
    failures += tp_birthday_verdict(x.w, match, stepped);
    (void)db_service_run_write(&x.svc, tp_noop_write, NULL);
    x.w->sapling_keys.num_unscannable = 0;
    x.rt.main_state = NULL;
    main_state_free(&ms);
    tp_wire_close(&x);
    return failures;
}

static bool tp_unready_wallet_reconcile(struct app_runtime_context *rt,
                                         struct block_index *index)
{
    struct wallet *pending = zcl_calloc(1, sizeof(*pending), "tp_pending_wallet");
    if (!pending) return false;
    wallet_init(pending);
    pending->sapling_notes = zcl_calloc(1, sizeof(*pending->sapling_notes), "tp_pending_note");
    if (!pending->sapling_notes) { wallet_free(pending); free(pending); return false; }
    pending->sapling_notes_cap = pending->num_sapling_notes = 1;
    pending->sapling_notes[0].used = true;
    memcpy(pending->sapling_notes[0].nf, rt->wallet->sapling_notes[0].nf, 32);
    struct wallet *original = rt->wallet;
    rt->wallet = pending;
    bool ok = true;
    for (int phase = 0; phase < 2; ++phase) {
        if (phase == 1 && !wallet_readiness_initialize(pending, WALLET_READINESS_PENDING, true, 1))
            ok = false;
        bool reconciled = tip_finalize_run_wallet_reconcile(index);
        if (reconciled || pending->best_block_height != 0 ||
            pending->num_wallet_tx != 0 || pending->sapling_notes[0].spent)
            ok = false;
    }
    rt->wallet = original;
    wallet_free(pending);
    free(pending);
    return ok;
}

int test_tip_finalize_post_step(void)
{
    int failures = 0;
    printf("\n=== tip_finalize_post_step tests ===\n");

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "tip_post", "main");
    SetDataDir(dir); /* post step resolves the body via GetDataDir() */
    char netdir[512];
    GetDataDir(true, netdir, sizeof(netdir));
    tp_mkdir_p(netdir);
    char blocksdir[640];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
    tp_mkdir_p(blocksdir);

    const struct chain_params *cp = chain_params_get();
    atomic_store(&g_body_pull_active, 0);

    uint8_t nf_marker[32];
    memset(nf_marker, 0x5a, sizeof(nf_marker));

    /* Visible-body dedup fixture state (set up below, freed at out_early). */
    struct block blk2;
    bool blk2_built = false;
    struct main_state vb_ms;
    bool vb_ms_live = false;
    sqlite3 *vbdb = NULL;
    stage_t *vb_stage = NULL;

    struct block blk;
    bool built = tp_build_block(&blk, nf_marker);
    TP_CHECK("block with coinbase + sapling spend built", built);

    /* Persist the body where stage_default_block_reader will read it. */
    struct block_index bi;
    block_index_init(&bi);
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    bool on_disk = built &&
        write_block_to_disk(&blk, &pos, netdir, cp->pchMessageStart);
    TP_CHECK("body written to disk", on_disk);
    block_get_hash(&blk, &bi.hashBlock);
    bi.phashBlock = &bi.hashBlock;
    bi.nHeight = 1;
    bi.nTime = blk.header.nTime;
    bi.nBits = blk.header.nBits;
    bool have_data = on_disk &&
        block_index_set_have_data_verified(&bi, &pos, netdir);
    TP_CHECK("HAVE_DATA verified against on-disk body", have_data);

    /* Wire the minimal app_runtime world: wallet with one unspent note
     * carrying the marker nullifier, mempool holding the block's spend
     * tx. db_service stays NULL — node_db effects (note persistence,
     * projection-deferred diagnostic) are guarded skips, documented. */
    struct wallet *w = zcl_calloc(1, sizeof(*w), "tp_wallet");
    TP_CHECK("wallet allocated", w != NULL);
    if (!w || !built || !have_data) {
        free(w); /* not wallet_init'd yet */
        goto out_early;
    }
    wallet_init(w);
    w->sapling_notes = zcl_calloc(2, sizeof(*w->sapling_notes), "tp_notes");
    TP_CHECK("notes allocated", w->sapling_notes != NULL);
    if (!w->sapling_notes) {
        wallet_free(w);
        free(w);
        goto out_early;
    }
    w->sapling_notes_cap = 2;
    w->num_sapling_notes = 1;
    w->sapling_notes[0].used = true;
    w->sapling_notes[0].spent = false;
    memcpy(w->sapling_notes[0].nf, nf_marker, 32);

    tx_mempool_init(&g_tp_pool, 0);
    TP_CHECK("spend tx in mempool", tp_pool_add(&blk.vtx[1]) &&
             tx_mempool_exists(&g_tp_pool, &blk.vtx[1].hash));

    struct app_runtime_context rt = {0};
    rt.wallet = w;
    rt.mempool = &g_tp_pool;
    app_runtime_set_current(&rt);

    /* ── Visible-body dedup fixture ──
     * A second block at height 2 (distinct nTime ⇒ distinct hash) whose
     * body is withheld until the late-body case, a three-block active-chain
     * window, the durable utxo_apply witness rows, and a probe stage whose
     * cursor drives tip_finalize_reconcile_visible_cursor_body. */
    uint8_t nf_marker2[32];
    memset(nf_marker2, 0x6b, sizeof(nf_marker2));
    blk2_built = tp_build_block(&blk2, nf_marker2);
    blk2.header.nTime = blk.header.nTime + 1; /* distinct header ⇒ hash */
    /* Distinct spend input: blk's spend tx is still pool-resident when the
     * late-body probe arms blk2's, and identical prevouts would correctly
     * reject as a mempool double-spend. */
    memset(blk2.vtx[1].vin[0].prevout.hash.data, 0x88, 32);
    transaction_compute_hash(&blk2.vtx[1]);
    TP_CHECK("dedup fixture: second block built", blk2_built);
    struct block_index bi0;
    block_index_init(&bi0);
    memset(bi0.hashBlock.data, 0xa0, 32);
    bi0.phashBlock = &bi0.hashBlock;
    bi0.nHeight = 0;
    bi0.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
    arith_uint256_set_u64(&bi0.nChainWork, 1);
    struct block_index bi2;
    block_index_init(&bi2);
    struct disk_block_pos pos2;
    disk_block_pos_init(&pos2);
    TP_CHECK("dedup fixture: second body written to disk",
             blk2_built &&
             write_block_to_disk(&blk2, &pos2, netdir, cp->pchMessageStart));
    block_get_hash(&blk2, &bi2.hashBlock);
    bi2.phashBlock = &bi2.hashBlock;
    bi2.nHeight = 2;
    bi2.nTime = blk2.header.nTime;
    bi2.nBits = blk2.header.nBits;
    arith_uint256_set_u64(&bi2.nChainWork, 3);
    bi2.pprev = &bi;
    bi.pprev = &bi0;
    bi.nStatus |= BLOCK_VALID_SCRIPTS; /* visible-body precondition */
    arith_uint256_set_u64(&bi.nChainWork, 2);
    memset(&vb_ms, 0, sizeof(vb_ms));
    main_state_init(&vb_ms);
    vb_ms_live = true;
    TP_CHECK("dedup fixture: active-chain window installed",
             active_chain_move_window_tip(&vb_ms.chain_active, &bi2));
    TP_CHECK("dedup fixture: window resolves height 1",
             active_chain_at(&vb_ms.chain_active, 1) == &bi);
    TP_CHECK("dedup fixture: window resolves height 2",
             active_chain_at(&vb_ms.chain_active, 2) == &bi2);
    char vbdb_path[600];
    snprintf(vbdb_path, sizeof(vbdb_path), "%s/vb.sqlite", netdir);
    TP_CHECK("dedup fixture: probe db open",
             sqlite3_open(vbdb_path, &vbdb) == SQLITE_OK);
    TP_CHECK("dedup fixture: probe db seeded", tp_vb_seed_db(vbdb));
    vb_stage = stage_create("tf_vb_probe", tp_vb_dummy_step, NULL);
    TP_CHECK("dedup fixture: probe stage created", vb_stage != NULL);
    tip_finalize_visible_body_reset();

    uint64_t mmr0 = tp_mmr_leaves();
    uint64_t mmb0 = tp_mmb_leaves();

    /* ── Positive: body readable → all assertable effects fire ── */
    TP_CHECK("UNKNOWN and PENDING skip wallet-only tip effects", tp_unready_wallet_reconcile(&rt, &bi));
    TP_CHECK("positive wallet is READY", wallet_readiness_initialize(w, WALLET_READINESS_READY, false, 0));
    tip_finalize_run_post_finalize(&bi);
    TP_CHECK("mempool: confirmed tx removed",
             !tx_mempool_exists(&g_tp_pool, &blk.vtx[1].hash));
    TP_CHECK("wallet: nullifier marked spent",
             w->sapling_notes[0].spent == true);
    TP_CHECK("wallet: best_block_height advanced",
             w->best_block_height == 1);
    TP_CHECK("MMR: one leaf appended", tp_mmr_leaves() == mmr0 + 1);
    TP_CHECK("MMB: one leaf appended", tp_mmb_leaves() == mmb0 + 1);

    /* Another authority path may publish this same tip before the reducer's
     * durable row. The repair must remove confirmed transactions without
     * replaying non-idempotent post-finalize effects. */
    w->sapling_notes[0].spent = false;
    w->best_block_height = 0;
    TP_CHECK("re-arm mempool for authority-race reconcile",
             tp_pool_add(&blk.vtx[1]));
    mmr0 = tp_mmr_leaves();
    mmb0 = tp_mmb_leaves();
    TP_CHECK("mempool-only: body reconcile succeeded",
             tip_finalize_run_mempool_reconcile(&bi));
    TP_CHECK("mempool-only: confirmed tx removed",
             !tx_mempool_exists(&g_tp_pool, &blk.vtx[1].hash));
    TP_CHECK("mempool-only: note remains unspent",
             w->sapling_notes[0].spent == false);
    TP_CHECK("mempool-only: wallet height unchanged",
             w->best_block_height == 0);
    TP_CHECK("mempool-only: MMR unchanged", tp_mmr_leaves() == mmr0);
    TP_CHECK("mempool-only: MMB unchanged", tp_mmb_leaves() == mmb0);

    /* A late-visible body must then publish the idempotent wallet subset
     * without repeating either append-only chain commitment. Model the exact
     * restart case: the outgoing transaction is durable in the wallet at
     * confirms=0 even though this synthetic transaction has no discoverable
     * wallet-owned parent or output. Existing membership must be enough to
     * upgrade it from mempool to confirmed. */
    struct wallet_tx pending;
    memset(&pending, 0, sizeof(pending));
    pending.used = true;
    pending.confirms = 0;
    TP_CHECK("wallet-only: seed existing unconfirmed outgoing transaction",
             transaction_copy(&pending.tx, &blk.vtx[1]) &&
             wallet_add_to_wallet(w, &pending));
    transaction_free(&pending.tx);
    TP_CHECK("wallet-only: body reconcile succeeded",
             tip_finalize_run_wallet_reconcile(&bi));
    struct wallet_tx confirmed;
    memset(&confirmed, 0, sizeof(confirmed));
    TP_CHECK("wallet-only: existing outgoing transaction confirmed",
             wallet_get_tx_copy(w, &blk.vtx[1].hash, &confirmed) &&
             confirmed.confirms == 1 &&
             uint256_eq(&confirmed.hash_block, bi.phashBlock));
    transaction_free(&confirmed.tx);
    TP_CHECK("wallet-only: nullifier marked spent",
             w->sapling_notes[0].spent == true);
    TP_CHECK("wallet-only: height advanced",
             w->best_block_height == 1);
    TP_CHECK("wallet-only: MMR unchanged", tp_mmr_leaves() == mmr0);
    TP_CHECK("wallet-only: MMB unchanged", tp_mmb_leaves() == mmb0);

    /* Ordinary late-visible catch-up needs both idempotent subsets. Pin the
     * combined one-body-view entry point so the IBD optimization cannot omit
     * either effect or accidentally replay append-only commitments. */
    w->sapling_notes[0].spent = false;
    w->best_block_height = 0;
    TP_CHECK("combined: re-arm confirmed transaction",
             tp_pool_add(&blk.vtx[1]));
    mmr0 = tp_mmr_leaves();
    mmb0 = tp_mmb_leaves();
    TP_CHECK("combined: body reconcile succeeded",
             tip_finalize_run_wallet_mempool_reconcile(&bi));
    TP_CHECK("combined: confirmed tx removed",
             !tx_mempool_exists(&g_tp_pool, &blk.vtx[1].hash));
    TP_CHECK("combined: nullifier marked spent",
             w->sapling_notes[0].spent == true);
    TP_CHECK("combined: wallet height advanced",
             w->best_block_height == 1);
    TP_CHECK("combined: MMR unchanged", tp_mmr_leaves() == mmr0);
    TP_CHECK("combined: MMB unchanged", tp_mmb_leaves() == mmb0);

    /* ── Negative: HAVE_DATA absent → diagnosed skip, zero effects ── */
    w->sapling_notes[0].spent = false;
    TP_CHECK("re-arm mempool", tp_pool_add(&blk.vtx[1]));
    mmr0 = tp_mmr_leaves();
    mmb0 = tp_mmb_leaves();
    struct block_index bi_nodata;
    block_index_init(&bi_nodata);
    memset(bi_nodata.hashBlock.data, 0x31, 32);
    bi_nodata.phashBlock = &bi_nodata.hashBlock;
    bi_nodata.nHeight = 2; /* nStatus: HAVE_DATA deliberately clear */
    tip_finalize_run_post_finalize(&bi_nodata);
    TP_CHECK("no-body skip: mempool untouched",
             tx_mempool_exists(&g_tp_pool, &blk.vtx[1].hash));
    TP_CHECK("no-body skip: note not marked spent",
             w->sapling_notes[0].spent == false);
    TP_CHECK("no-body skip: MMR unchanged", tp_mmr_leaves() == mmr0);
    TP_CHECK("no-body skip: MMB unchanged", tp_mmb_leaves() == mmb0);
    TP_CHECK("no-body skip: wallet height unchanged",
             w->best_block_height == 1);

    /* ── Negative: HAVE_DATA set but body unreadable (bogus file) ── */
    struct block_index bi_unread;
    block_index_init(&bi_unread);
    memset(bi_unread.hashBlock.data, 0x32, 32);
    bi_unread.phashBlock = &bi_unread.hashBlock;
    bi_unread.nHeight = 3;
    bi_unread.nStatus = BLOCK_HAVE_DATA;
    bi_unread.nFile = 9999; /* no such blk file */
    bi_unread.nDataPos = 0;
    tip_finalize_run_post_finalize(&bi_unread);
    TP_CHECK("unreadable skip: mempool untouched",
             tx_mempool_exists(&g_tp_pool, &blk.vtx[1].hash));
    TP_CHECK("unreadable skip: MMR unchanged", tp_mmr_leaves() == mmr0);

    /* NULL pindex is a guarded no-op. */
    tip_finalize_run_post_finalize(NULL);
    failures += tp_mut_entry_refusals(&blk, &bi_nodata, &bi_unread);
    failures += tp_mut_coins_invalidate(&rt, &blk, &bi);
    TP_CHECK("NULL pindex: no crash, MMR unchanged",
             tp_mmr_leaves() == mmr0);

    /* Visible-body dedup + late-body eligibility probes (rationale at the
     * helpers; the dedup probe is born-red on the pre-fix tree). */
    failures += tp_vb_dedup_probe(w, &blk.vtx[1], &bi,
                                  vb_stage, vbdb, &vb_ms);
    failures += tp_vb_late_body_probe(w, &blk2.vtx[1], &bi2, &pos2, netdir,
                                      vb_stage, vbdb, &vb_ms);

    failures += tp_boundary_root_probe(dir, &bi);
    failures += tp_mut_tripwire();
    failures += tp_mut_window_walk(netdir);

    app_runtime_set_current(NULL);
    tx_mempool_free(&g_tp_pool);
    wallet_free(w); /* frees sapling_notes */
    free(w);

out_early:
    tp_vb_fixture_teardown(vb_stage, vbdb, &vb_ms, vb_ms_live,
                           &blk2, blk2_built);
    block_free(&blk);
    SetDataDir("");
    ClearDataDirCache();
    test_rm_rf(dir);

    failures += tp_witness_wiring();
#ifndef _WIN32
    failures += tp_gentle_wallet_tip();
#endif
    failures += tp_birthday_live(true);
    failures += tp_birthday_live(false);
    printf("tip_finalize_post_step tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
