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
 * file missing). */

#include "test/test_core.h"
#include "util/util.h"
#include "coins/undo.h"
#include "wallet/wallet.h"

#include "chain/chain.h"
#include "config/runtime.h"
#include "controllers/blockchain_controller.h"
#include "validation/process_block.h" /* g_body_pull_active */

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* Internal to engine/jobs/src (tip_finalize_post_step.h is not on the
 * include path by design); declare the entry point directly. */
extern void tip_finalize_run_post_finalize(struct block_index *pindex_new);
extern bool tip_finalize_run_mempool_reconcile(struct block_index *pindex_new);
extern bool tip_finalize_run_wallet_reconcile(struct block_index *pindex_new);

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
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
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

int test_tip_finalize_post_step(void);
int test_tip_finalize_post_step(void)
{
    int failures = 0;
    printf("\n=== tip_finalize_post_step tests ===\n");

    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "tip_post", "main");
    tp_mkdir_p("./test-tmp");
    tp_mkdir_p(dir);
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

    app_runtime_set_current(NULL);
    tx_mempool_free(&g_tp_pool);
    wallet_free(w); /* frees sapling_notes */
    free(w);

out_early:
    block_free(&blk);
    SetDataDir("");
    ClearDataDirCache();
    test_rm_rf(dir);

    printf("tip_finalize_post_step tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
