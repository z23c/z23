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
#include "storage/progress_store.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block.h" /* g_body_pull_active */

#include <errno.h>
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

int test_tip_finalize_post_step(void);
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
    TP_CHECK("NULL pindex: no crash, MMR unchanged",
             tp_mmr_leaves() == mmr0);

    /* Visible-body dedup + late-body eligibility probes (rationale at the
     * helpers; the dedup probe is born-red on the pre-fix tree). */
    failures += tp_vb_dedup_probe(w, &blk.vtx[1], &bi,
                                  vb_stage, vbdb, &vb_ms);
    failures += tp_vb_late_body_probe(w, &blk2.vtx[1], &bi2, &pos2, netdir,
                                      vb_stage, vbdb, &vb_ms);

    failures += tp_boundary_root_probe(dir, &bi);

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

    printf("tip_finalize_post_step tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
