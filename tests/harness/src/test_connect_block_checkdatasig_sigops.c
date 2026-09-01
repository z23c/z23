/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_connect_block_checkdatasig_sigops - pins the DEFAULT-OFF
 * CHECKDATASIG_SIGOPS parity flag in core/modules/validation/src/connect_block.c.
 *
 * Background. zclassicd ConnectBlock (zclassic-cpp/src/main.cpp:2567) builds
 * its script verification flags as
 *   SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
 *   SCRIPT_VERIFY_CHECKDATASIG_SIGOPS.
 * The CHECKDATASIG_SIGOPS bit makes OP_CHECKDATASIG / OP_CHECKDATASIGVERIFY
 * count toward the per-block sigop total (script.c:117), tightening the
 * MAX_BLOCK_SIGOPS (20000) ceiling. zclassic23's connect_block omitted that
 * bit. The fix ORs it in behind the DEFAULT-OFF runtime flag
 * g_enforce_checkdatasig_sigops (-enforce-checkdatasig-sigops).
 *
 * Isolating the change. CheckBlock (domain/consensus/src/check_block.c) ALSO
 * tallies block sigops and ALWAYS counts OP_CHECKDATASIG, but only the LEGACY
 * (top-level scriptSig/scriptPubKey) count — it has no coins view, so it
 * cannot do the P2SH redeem-script count. connect_block runs CheckBlock first,
 * then adds the P2SH sigop count (connect_block.c ~:493) using the SAME flags
 * variable this fix changes. So the P2SH path is exactly where the flag has a
 * behavioral effect that CheckBlock does not already enforce.
 *
 * This test therefore builds a block that:
 *   - keeps the LEGACY top-level sigop count just UNDER 20000 (a coinbase
 *     whose outputs hold CDS_LEGACY_OPS OP_CHECKSIG bytes — counted identically
 *     by CheckBlock and connect_block, with or without the flag), so CheckBlock
 *     always passes; and
 *   - spends one P2SH input whose redeem script (pushed in the scriptSig) is
 *     CDS_REDEEM_OPS OP_CHECKDATASIG bytes. Those redeem sigops count toward
 *     the per-block ceiling ONLY when the flag adds CHECKDATASIG_SIGOPS.
 *
 * With CDS_LEGACY_OPS + CDS_REDEEM_OPS chosen to straddle 20000:
 *   1. Flag OFF (DEFAULT): total == CDS_LEGACY_OPS (P2SH CHECKDATASIG counts 0)
 *      -> under the ceiling -> connect_block does NOT reject for sigops
 *      (byte-identical to today).
 *   2. Flag ON: total == CDS_LEGACY_OPS + CDS_REDEEM_OPS -> over the ceiling
 *      -> connect_block REJECTS with "bad-blk-sigops".
 *
 * SW_HEIGHT-style setup: a checkpoint-covered, Sapling-inactive height so
 * expensive_checks=false (PoW + parallel script verification skipped) while the
 * sigop accounting still runs; the funding coin is plain + mature so neither
 * coinbase maturity nor the all-zeros Sapling-root check interferes.
 */

#include "test/test_core.h"

#include "validation/connect_block.h"
#include "validation/contextual_check_tx.h"
#include "validation/main_constants.h"  /* MAX_BLOCK_SIGOPS */
#include "coins/coins_view.h"
#include "coins/coins.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "bloom/merkle.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"
#include "script/script.h"
#include "util/safe_alloc.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define CDS_CHECK(name, expr) do {                              \
    printf("connect_block_checkdatasig_sigops: %s... ", (name)); \
    if ((expr)) printf("OK\n");                                 \
    else { printf("FAIL\n"); failures++; }                      \
} while (0)

/* Sapling-inactive height covered by a synthetic checkpoint. */
#define CDS_HEIGHT 100

/* Top-level legacy sigops (OP_CHECKSIG), split over two coinbase outputs so
 * each stays under MAX_SCRIPT_SIZE (10000). Just under the ceiling. */
#define CDS_LEGACY_OPS   19900
#define CDS_LEGACY_PER   9950   /* CDS_LEGACY_OPS / 2 outputs */
/* P2SH redeem-script OP_CHECKDATASIG bytes (<= MAX_SCRIPT_ELEMENT_SIZE 520).
 * CDS_LEGACY_OPS + CDS_REDEEM_OPS must exceed MAX_BLOCK_SIGOPS. */
#define CDS_REDEEM_OPS   500

/* The P2SH funding txid the spend consumes. */
static struct uint256 cds_funding_txid(void)
{
    struct uint256 h;
    memset(h.data, 0x5A, 32);
    return h;
}

/* Coinbase with two outputs, each CDS_LEGACY_PER OP_CHECKSIG bytes (0xac), so
 * the block's top-level legacy sigop count is CDS_LEGACY_OPS regardless of the
 * flag. The first output carries the (tiny) value. */
static struct transaction cds_make_coinbase(int height)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "cds_cb_vin");
    uint8_t sig[6] = { 4,
                       (uint8_t)(height & 0xFF),
                       (uint8_t)((height >> 8) & 0xFF),
                       (uint8_t)((height >> 16) & 0xFF),
                       (uint8_t)((height >> 24) & 0xFF),
                       0x11 };
    script_set(&tx.vin[0].script_sig, sig, 6);
    uint256_set_null(&tx.vin[0].prevout.hash);
    tx.vin[0].prevout.n = 0xFFFFFFFF;
    tx.vin[0].sequence = 0xFFFFFFFF;
    tx.num_vout = 2;
    tx.vout = zcl_calloc(2, sizeof(struct tx_out), "cds_cb_vout");
    uint8_t *pk = zcl_malloc(CDS_LEGACY_PER, "cds_cb_pk");
    memset(pk, OP_CHECKSIG, CDS_LEGACY_PER);  /* 0xac repeated */
    for (size_t i = 0; i < 2; i++) {
        tx.vout[i].value = (i == 0) ? 1000 : 0;
        script_set(&tx.vout[i].script_pub_key, pk, CDS_LEGACY_PER);
    }
    free(pk);
    transaction_compute_hash(&tx);
    return tx;
}

/* Non-coinbase tx spending the P2SH funding coin. Its scriptSig is push-only
 * (a single push of a redeem script of CDS_REDEEM_OPS OP_CHECKDATASIG bytes),
 * so the legacy count sees only a push (0 sigops) and the redeem sigops are
 * reached solely through connect_block's P2SH count. One tiny P2PKH output. */
static struct transaction cds_make_spend(void)
{
    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.num_vin = 1;
    tx.vin = zcl_calloc(1, sizeof(struct tx_in), "cds_spend_vin");
    tx.vin[0].prevout.hash = cds_funding_txid();
    tx.vin[0].prevout.n = 0;
    uint8_t *redeem = zcl_malloc(CDS_REDEEM_OPS, "cds_redeem");
    memset(redeem, OP_CHECKDATASIG, CDS_REDEEM_OPS);  /* 0xba repeated */
    script_init(&tx.vin[0].script_sig);
    (void)script_push_data(&tx.vin[0].script_sig, redeem, CDS_REDEEM_OPS);
    free(redeem);
    tx.vin[0].sequence = 0xFFFFFFFF;
    tx.num_vout = 1;
    tx.vout = zcl_calloc(1, sizeof(struct tx_out), "cds_spend_vout");
    tx.vout[0].value = 40000;
    uint8_t pk[] = {0x76, 0xa9, 0x14};
    script_set(&tx.vout[0].script_pub_key, pk, 3);
    transaction_compute_hash(&tx);
    return tx;
}

static void cds_free_tx(struct transaction *tx)
{
    free(tx->vin);
    free(tx->vout);
}

/* Seed `view` with the P2SH funding coin (OP_HASH160 <20> OP_EQUAL). The hash
 * need not match the redeem script: expensive_checks=false skips actual script
 * verification, and the P2SH sigop count keys only on the scriptPubKey SHAPE
 * (script_is_pay_to_script_hash) + the scriptSig's last push. */
static void cds_seed_p2sh_coin(struct coins_view_cache *view,
                               const struct uint256 *txid,
                               int height, int64_t value)
{
    struct coins_cache_entry *e = coins_view_cache_modify_new(view, txid);
    coins_alloc(&e->coins, 1);
    e->coins.height = height;
    e->coins.version = 1;
    e->coins.is_coinbase = false;
    e->coins.vout[0].value = value;
    uint8_t pk[23];
    pk[0] = OP_HASH160;
    pk[1] = 0x14;
    memset(pk + 2, 0xAB, 20);
    pk[22] = OP_EQUAL;
    script_set(&e->coins.vout[0].script_pub_key, pk, 23);
    e->flags = COINS_CACHE_DIRTY;
}

/* Mainnet params with a checkpoint COVERING CDS_HEIGHT so connect_block runs
 * with expensive_checks=false. */
static struct chain_params cds_params(struct checkpoint_entry *out_entry)
{
    struct chain_params p = *chain_params_get();
    memset(out_entry, 0, sizeof(*out_entry));
    out_entry->height = CDS_HEIGHT;
    memset(out_entry->hash.data, 0x01, 32);
    p.checkpointData.entries = out_entry;
    p.checkpointData.nEntries = 1;
    return p;
}

/* Run connect_block over the {coinbase, P2SH-spend} block. Returns the result
 * and copies the reject reason out. */
static bool cds_run(char reject_out[256])
{
    atomic_store(&g_deferred_proof_validation_below_height, -1);

    struct checkpoint_entry cpentry;
    struct chain_params params = cds_params(&cpentry);

    struct transaction cb = cds_make_coinbase(CDS_HEIGHT);
    struct transaction spend = cds_make_spend();

    struct block blk;
    memset(&blk, 0, sizeof(blk));
    blk.num_vtx = 2;
    blk.vtx = zcl_calloc(2, sizeof(struct transaction), "cds_blk_vtx");
    blk.vtx[0] = cb;
    blk.vtx[1] = spend;
    blk.header.nVersion = 4;

    struct uint256 txids[2] = { cb.hash, spend.hash };
    blk.header.hashMerkleRoot = compute_merkle_root(txids, 2);

    struct uint256 prev_hash;
    memset(prev_hash.data, 0x33, 32);
    blk.header.hashPrevBlock = prev_hash;

    struct uint256 block_hash;
    block_header_get_hash(&blk.header, &block_hash);

    struct block_index pprev_idx;
    block_index_init(&pprev_idx);
    pprev_idx.nHeight = CDS_HEIGHT - 1;
    pprev_idx.phashBlock = &prev_hash;
    arith_uint256_set_u64(&pprev_idx.nChainWork, (uint64_t)CDS_HEIGHT);
    pprev_idx.has_chain_sprout_value = false;
    pprev_idx.has_chain_sapling_value = false;

    struct block_index pindex;
    block_index_init(&pindex);
    pindex.nHeight = CDS_HEIGHT;
    pindex.phashBlock = &block_hash;
    pindex.pprev = &pprev_idx;

    struct coins_view_cache view;
    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    coins_view_cache_init(&view, &null_view);
    coins_view_cache_set_best_block(&view, &prev_hash);

    /* P2SH funding coin the spend consumes (plain, mature, value > output). */
    struct uint256 funding = cds_funding_txid();
    cds_seed_p2sh_coin(&view, &funding, 1 /* mature */, 50000);

    struct validation_state vs;
    validation_state_init(&vs);

    bool ok = connect_block(&blk, &vs, &pindex, &view, &params,
                            false /* just_check=false */);
    if (reject_out) {
        strncpy(reject_out, vs.reject_reason, 255);
        reject_out[255] = '\0';
    }

    coins_view_cache_free(&view);
    free(blk.vtx);
    cds_free_tx(&cb);
    cds_free_tx(&spend);
    return ok;
}

int test_connect_block_checkdatasig_sigops(void);
int test_connect_block_checkdatasig_sigops(void)
{
    printf("\n=== connect_block CHECKDATASIG_SIGOPS parity (default-off) ===\n");
    int failures = 0;

    /* The fixture must straddle the ceiling: legacy alone under it, legacy +
     * redeem over it. */
    CDS_CHECK("fixture: legacy ops below MAX_BLOCK_SIGOPS",
              (unsigned)CDS_LEGACY_OPS <= (unsigned)MAX_BLOCK_SIGOPS);
    CDS_CHECK("fixture: legacy + redeem exceeds MAX_BLOCK_SIGOPS",
              (unsigned)(CDS_LEGACY_OPS + CDS_REDEEM_OPS) >
                  (unsigned)MAX_BLOCK_SIGOPS);

    /* 1. DEFAULT (flag OFF): P2SH OP_CHECKDATASIG counts 0 -> total under the
     * ceiling -> no bad-blk-sigops (byte-identical to today). */
    {
        atomic_store(&g_enforce_checkdatasig_sigops, false);
        char reject[256] = "";
        bool ok = cds_run(reject);
        CDS_CHECK("flag OFF: no bad-blk-sigops reject (byte-identical)",
                  strstr(reject, "bad-blk-sigops") == NULL);
        CDS_CHECK("flag OFF: block ACCEPTS", ok);
    }

    /* 2. Flag ON: P2SH OP_CHECKDATASIG counts +1 each -> total over the
     * ceiling -> REJECTS with bad-blk-sigops. */
    {
        atomic_store(&g_enforce_checkdatasig_sigops, true);
        char reject[256] = "";
        bool ok = cds_run(reject);
        CDS_CHECK("flag ON: over-ceiling P2SH sigops REJECT", !ok);
        CDS_CHECK("flag ON: reject reason is bad-blk-sigops",
                  strstr(reject, "bad-blk-sigops") != NULL);
        atomic_store(&g_enforce_checkdatasig_sigops, false);
    }

    /* Leave the global in its default (off) state for any later group. */
    atomic_store(&g_enforce_checkdatasig_sigops, false);

    printf("=== connect_block CHECKDATASIG_SIGOPS parity: %d failures ===\n",
           failures);
    return failures;
}
