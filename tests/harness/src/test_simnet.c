/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pins the simnet foundation slice (engine/modules/sim/src/simnet.c): a RAM-only,
 * single-node chain harness that mints blocks through the REAL consensus
 * code (connect_block) with no disk and no real PoW.
 *
 * The keystone loop:
 *   mint coinbase  →  coin becomes spendable  →  spend the (matured)
 *   coinbase  →  input consumed + new output present, all in the in-memory
 *   coins view.
 *
 * If any of these asserts fail it means the harness assembled a block the
 * real validator rejects — the fix is ALWAYS in the harness's block
 * construction, never in a consensus predicate.
 */

#include "test/test_core.h"
#include "models/zslp.h"
#include "models/zslp_ledger.h"
#include "models/zslp_validity.h"

#include "models/explorer_index.h"
#include "models/blog_post.h"
#include "models/znam.h"
#include "sim/sim_peer.h"
#include "sim/simnet.h"
#include "primitives/block.h"
#include "validation/main_constants.h"
#include "core/uint256.h"
#include "script/standard.h"
#include "services/blog_publication_service.h"
#include "znam/znam.h"
#include "zslp/slp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SN_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static void sim_test_p2pkh_script(struct script *sp, unsigned char seed)
{
    sp->data[0] = 0x76;  /* OP_DUP */
    sp->data[1] = 0xa9;  /* OP_HASH160 */
    sp->data[2] = 0x14;  /* push 20 */
    for (int i = 0; i < 20; i++)
        sp->data[3 + i] = (unsigned char)(seed + i);
    sp->data[23] = 0x88; /* OP_EQUALVERIFY */
    sp->data[24] = 0xac; /* OP_CHECKSIG */
    sp->size = 25;
}

static bool sim_test_make_opreturn_spend_outputs(struct transaction *tx,
                                                 const struct uint256 *prev_txid,
                                                 uint32_t prev_n,
                                                 const uint8_t *opret,
                                                 size_t opret_len,
                                                 const int64_t *out_values,
                                                 const unsigned char *addr_seeds,
                                                 size_t noutputs)
{
    transaction_init(tx);
    if (!prev_txid || !opret || opret_len == 0 || !out_values ||
        !addr_seeds || noutputs == 0)
        return false;
    if (!transaction_alloc(tx, 1, noutputs + 1))
        return false;

    tx->version = 1;
    tx->vin[0].prevout.hash = *prev_txid;
    tx->vin[0].prevout.n = prev_n;
    {
        uint8_t sig[] = {0x00, 0x00};
        script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    }
    tx->vin[0].sequence = 0xFFFFFFFFu;

    tx->vout[0].value = 0;
    script_set(&tx->vout[0].script_pub_key, opret, opret_len);
    for (size_t i = 0; i < noutputs; i++) {
        tx->vout[i + 1].value = out_values[i];
        sim_test_p2pkh_script(&tx->vout[i + 1].script_pub_key, addr_seeds[i]);
    }

    transaction_compute_hash(tx);
    return true;
}

static bool sim_test_make_opreturn_spend(struct transaction *tx,
                                         const struct uint256 *prev_txid,
                                         uint32_t prev_n,
                                         const uint8_t *opret,
                                         size_t opret_len,
                                         int64_t out_value,
                                         unsigned char addr_seed)
{
    int64_t values[1] = { out_value };
    unsigned char seeds[1] = { addr_seed };
    return sim_test_make_opreturn_spend_outputs(tx, prev_txid, prev_n,
                                                opret, opret_len, values,
                                                seeds, 1);
}

static bool sim_test_make_p2pkh_spend_outputs(struct transaction *tx,
                                              const struct uint256 *prev_txid,
                                              uint32_t prev_n,
                                              const int64_t *out_values,
                                              const unsigned char *addr_seeds,
                                              size_t noutputs)
{
    transaction_init(tx);
    if (!prev_txid || !out_values || !addr_seeds || noutputs == 0)
        return false;
    if (!transaction_alloc(tx, 1, noutputs))
        return false;

    tx->version = 1;
    tx->vin[0].prevout.hash = *prev_txid;
    tx->vin[0].prevout.n = prev_n;
    {
        uint8_t sig[] = {0x00, 0x00};
        script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    }
    tx->vin[0].sequence = 0xFFFFFFFFu;

    for (size_t i = 0; i < noutputs; i++) {
        tx->vout[i].value = out_values[i];
        sim_test_p2pkh_script(&tx->vout[i].script_pub_key, addr_seeds[i]);
    }

    transaction_compute_hash(tx);
    return true;
}

static bool sim_test_make_multi_p2pkh_p2sh_spend(
    struct transaction *tx,
    const struct uint256 *prev0, uint32_t prev0_n,
    const struct uint256 *prev1, uint32_t prev1_n)
{
    transaction_init(tx);
    if (!prev0 || !prev1)
        return false;
    if (!transaction_alloc(tx, 2, 3))
        return false;

    tx->version = 1;
    tx->vin[0].prevout.hash = *prev0;
    tx->vin[0].prevout.n = prev0_n;
    tx->vin[1].prevout.hash = *prev1;
    tx->vin[1].prevout.n = prev1_n;
    for (size_t i = 0; i < tx->num_vin; i++) {
        uint8_t sig[] = {0x00, 0x00};
        script_set(&tx->vin[i].script_sig, sig, sizeof(sig));
        tx->vin[i].sequence = 0xFFFFFFFFu;
    }

    tx->vout[0].value = 400000;
    sim_test_p2pkh_script(&tx->vout[0].script_pub_key, 0x21);
    tx->vout[1].value = 300000;
    sim_test_p2pkh_script(&tx->vout[1].script_pub_key, 0x41);
    tx->vout[2].value = 200000;
    struct script_id sid;
    memset(&sid, 0x5A, sizeof(sid));
    script_for_p2sh(&tx->vout[2].script_pub_key, &sid);

    transaction_compute_hash(tx);
    return true;
}

static int sim_test_count_rows(struct node_db *ndb, const char *sql)
{
    sqlite3_stmt *s = NULL;
    int n = -1;
    if (ndb && ndb->open &&
        sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) == SQLITE_OK && s) {
        if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:test-readonly-count
            n = sqlite3_column_int(s, 0);
    }
    if (s)
        sqlite3_finalize(s);
    return n;
}

static void sim_test_slp_wire_token_id(const struct uint256 *internal,
                                       struct uint256 *wire)
{
    for (int i = 0; i < 32; i++)
        wire->data[i] = internal->data[31 - i];
}

static bool sim_test_apply_slp(struct node_db *ndb,
                               const struct transaction *tx, int height)
{
    if (!tx || tx->num_vout == 0)
        return false;
    struct slp_message msg;
    if (!slp_parse(tx->vout[0].script_pub_key.data,
                   tx->vout[0].script_pub_key.size, &msg))
        return false;
    explorer_index_apply_slp(ndb, tx, &msg, height);
    return zslp_ledger_apply_slp_live(ndb, tx, &msg, height);
}

static int64_t sim_test_transfer_amount(
    const struct db_zslp_transfer_info *xfers, int n, int tx_type, int vout)
{
    for (int i = 0; i < n; i++) {
        if (xfers[i].tx_type == tx_type && xfers[i].vout == vout)
            return xfers[i].amount;
    }
    return -1;
}

static bool sim_test_write_peer_block_file(const char *path,
                                           const struct uint256 *block_marker)
{
    if (!path || !block_marker)
        return false;

    FILE *fp = fopen(path, "wb");
    if (!fp)
        return false;
    bool ok = fwrite(block_marker->data, 1, sizeof(block_marker->data), fp) ==
              sizeof(block_marker->data);
    ok = (fclose(fp) == 0) && ok;
    return ok;
}

static bool sim_test_index_block(struct node_db *ndb,
                                 const struct transaction *txs, size_t ntx,
                                 int height, unsigned char hash_seed)
{
    if (!ndb || !ndb->open || !txs || ntx == 0)
        return false;

    struct block blk;
    block_init(&blk);
    blk.vtx = (struct transaction *)txs;
    blk.num_vtx = ntx;

    struct uint256 bhash;
    memset(bhash.data, hash_seed, sizeof(bhash.data));
    struct block_index pindex;
    block_index_init(&pindex);
    pindex.nHeight = height;
    pindex.phashBlock = &bhash;

    uint8_t prev_receipt[32] = {0};
    uint8_t out_receipt[32];
    bool ok = explorer_index_block(ndb, &blk, &pindex, prev_receipt,
                                   out_receipt, NULL, NULL);

    blk.vtx = NULL;
    blk.num_vtx = 0;
    return ok;
}

static bool ivr_make_spend(struct transaction *tx, const struct uint256 *cb,
                            uint32_t n, int64_t value, int64_t value_balance,
                            struct output_description *borrowed, uint8_t seed)
{
    unsigned char seeds[] = {seed};
    if (!sim_test_make_p2pkh_spend_outputs(tx, cb, n, &value, seeds, 1))
        return false;
    if (borrowed) {
        memset(borrowed, 0, sizeof(*borrowed));
        tx->overwintered = true;
        tx->version = SAPLING_TX_VERSION;
        tx->version_group_id = SAPLING_VERSION_GROUP_ID;
        tx->v_shielded_output = borrowed;
        tx->num_shielded_output = 1;
    }
    tx->value_balance = value_balance;
    transaction_compute_hash(tx);
    return true;
}

static bool ivr_capture_setup(struct simnet *sim, struct uint256 *cb,
                               int64_t *value)
{
    if (!simnet_init(sim))
        return false;
    simnet_activate_sapling_at(sim, simnet_tip_height(sim) + 1);
    if (!simnet_mint_coinbase(sim, cb))
        return false;
    int mature = simnet_tip_height(sim) + COINBASE_MATURITY - 1;
    if (!simnet_mint_to_height(sim, mature))
        return false;
    return simnet_coin_value(sim, cb, 0, value);
}

static bool ivr_capture_identity(const struct simnet *sim,
                                 const struct block *body, int height, int before)
{
    struct uint256 hash;
    block_get_hash(body, &hash);
    struct uint256 tip_hash;
    if (!simnet_tip_hash(sim, &tip_hash))
        return false;
    return height == before + 1 && height == simnet_tip_height(sim) &&
        uint256_eq(&hash, &tip_hash);
}

static bool ivr_capture_arrays(const struct block *body,
                               const struct uint256 *txid,
                               const struct output_description *borrowed)
{
    if (body->num_vtx != 2)
        return false;
    const struct transaction *copy = &body->vtx[1];
    return uint256_eq(&copy->hash, txid) && copy->num_shielded_output == 1 &&
        copy->v_shielded_output != borrowed &&
        memcmp(copy->v_shielded_output, borrowed, sizeof(*borrowed)) == 0;
}

/* No prover: the existing value-range fixture's zeroed Sapling description
 * exercises owning capture only; contextual proof checking stays disabled. */
static int ivr_capture_owned(void)
{
    int failures = 0;
    struct simnet sim = {0};
    struct uint256 cb;
    int64_t value = 0;
    bool ready = ivr_capture_setup(&sim, &cb, &value);
    SN_CHECK("capture: funded fixture ready", ready);
    if (!ready) {
        simnet_free(&sim);
        return failures;
    }
    struct output_description *borrowed = calloc(1, sizeof(*borrowed)); /* raw-alloc-ok:test-fixture */
    struct transaction tx;
    transaction_init(&tx);
    bool built = false;
    if (borrowed)
        built = ivr_make_spend(&tx, &cb, 0, value / 2, 1, borrowed, 0xD0);
    SN_CHECK("capture: borrowed shielded input built", built);
    if (!built) {
        free(borrowed);
        simnet_free(&sim);
        return failures;
    }
    struct uint256 expected_txid = tx.hash;
    int before = simnet_tip_height(&sim);
    struct block captured;
    block_init(&captured);
    int height = -1;
    bool minted = simnet_mint_txs_capture(&sim, &tx, 1, &captured, &height);
    SN_CHECK("capture: mint accepted", minted);
    struct uint256 block_hash;
    block_get_hash(&captured, &block_hash);
    SN_CHECK("capture: exact final hash and height",
        ivr_capture_identity(&sim, &captured, height, before));
    bool owned = ivr_capture_arrays(&captured, &expected_txid, borrowed);
    SN_CHECK("capture: payment order and independent shielded ownership", owned);
    struct output_description expected = *borrowed;
    free(borrowed); /* Original arrays remain caller-owned, not capture-owned. */
    bool later = simnet_mint_coinbase(&sim, NULL);
    SN_CHECK("capture: later mint succeeds", later);
    struct uint256 retained_hash;
    block_get_hash(&captured, &retained_hash);
    bool retained = owned && later && uint256_eq(&retained_hash, &block_hash);
    if (retained)
        retained = memcmp(captured.vtx[1].v_shielded_output, &expected,
                          sizeof(expected)) == 0;
    SN_CHECK("capture: body survives input free and later mint", retained);
    block_free(&captured);
    simnet_free(&sim);
    return failures;
}

static int ivr_capture_refusal(void)
{
    int failures = 0;
    struct simnet sim = {0};
    struct uint256 cb;
    int64_t value = 0;
    bool ready = ivr_capture_setup(&sim, &cb, &value);
    SN_CHECK("capture refusal: funded fixture ready", ready);
    if (!ready) {
        simnet_free(&sim);
        return failures;
    }
    struct transaction tx;
    bool built = ivr_make_spend(&tx, &cb, 0, value + 1, 0, NULL, 0xD1);
    SN_CHECK("capture refusal: overspend built", built);
    if (!built) {
        simnet_free(&sim);
        return failures;
    }
    struct block captured;
    block_init(&captured);
    int height = 123;
    int before = simnet_tip_height(&sim);
    struct uint256 old_hash;
    bool old_known = simnet_tip_hash(&sim, &old_hash);
    bool minted = simnet_mint_txs_capture(&sim, &tx, 1, &captured, &height);
    struct uint256 final_hash;
    bool final_known = simnet_tip_hash(&sim, &final_hash);
    SN_CHECK("capture refusal: rejection leaves empty output and unchanged tip",
        !minted && !captured.vtx && captured.num_vtx == 0 && height == -1 &&
        simnet_tip_height(&sim) == before &&
        old_known && final_known && uint256_eq(&final_hash, &old_hash));
    block_free(&captured);
    simnet_free(&sim);
    return failures;
}

static bool ivr_capture_input_preserved(const struct simnet *sim,
                                        const struct transaction *tx,
                                        const struct block *body,
                                        const struct tx_in *vin,
                                        const struct tx_out *vout,
                                        int height, int before)
{
    return body->num_vtx == 1 && !body->vtx && height == 123 &&
        tx->vin == vin && tx->vout == vout && simnet_tip_height(sim) == before;
}

static int ivr_capture_invalid_output(void)
{
    int failures = 0;
    struct simnet sim = {0};
    struct uint256 cb;
    int64_t value = 0;
    bool ready = ivr_capture_setup(&sim, &cb, &value);
    SN_CHECK("capture invalid: funded fixture ready", ready);
    if (!ready) {
        simnet_free(&sim);
        return failures;
    }
    struct transaction tx;
    bool built = ivr_make_spend(&tx, &cb, 0, value / 2, 0, NULL, 0xD2);
    SN_CHECK("capture invalid: input built", built);
    if (!built) {
        simnet_free(&sim);
        return failures;
    }
    struct block nonempty;
    block_init(&nonempty);
    nonempty.num_vtx = 1; /* Invalid output, no owned allocation. */
    struct tx_in *vin = tx.vin;
    struct tx_out *vout = tx.vout;
    int height = 123;
    int before = simnet_tip_height(&sim);
    bool minted = simnet_mint_txs_capture(&sim, &tx, 1, &nonempty, &height);
    SN_CHECK("capture invalid: nonempty output refuses without consuming input",
        !minted && ivr_capture_input_preserved(&sim, &tx, &nonempty,
                                               vin, vout, height, before));
    SN_CHECK("capture invalid: refused input still mints through old API",
        simnet_mint_txs(&sim, &tx, 1) && simnet_tip_height(&sim) == before + 1);
    simnet_free(&sim);
    return failures;
}

static int sim_test_coinbase_spend_custom(struct simnet *sim,
                                          struct uint256 *custom_txid)
{
    int failures = 0;
    SN_CHECK("simnet_init succeeds", simnet_init(sim));
    SN_CHECK("fresh tip is the synthetic base (height 99)",
             simnet_tip_height(sim) == 99);

    /* 1. Mint a coinbase block through real connect_block. */
    struct uint256 cb_txid;
    uint256_set_null(&cb_txid);
    bool minted = simnet_mint_coinbase(sim, &cb_txid);
    SN_CHECK("mint coinbase drives block through connect_block", minted);
    SN_CHECK("tip advanced to height 100", simnet_tip_height(sim) == 100);
    SN_CHECK("coinbase coin is spendable in the RAM coins view",
             simnet_coin_exists(sim, &cb_txid));

    int64_t cb_value = 0;
    SN_CHECK("coinbase output value readable from coins view",
             simnet_coin_value(sim, &cb_txid, 0, &cb_value));
    SN_CHECK("coinbase output value is the minted subsidy stub",
             cb_value == 1000000);

    /* 2. Spend the (now matured) coinbase to a chosen output. The harness
     *    mints the spending block at a height that satisfies the REAL
     *    coinbase-maturity predicate (>= 100 blocks). */
    struct uint256 spend_txid;
    uint256_set_null(&spend_txid);
    bool spent = simnet_spend(sim, &cb_txid, 0, 900000, &spend_txid);
    SN_CHECK("spend the matured coinbase through connect_block", spent);

    /* Maturity forces the spend block to height 100 + COINBASE_MATURITY. */
    SN_CHECK("spend block minted at a mature height (>= 200)",
             simnet_tip_height(sim) >= 200);

    /* 3. The coins view reflects the spend: input consumed, output present. */
    SN_CHECK("spent coinbase is consumed (no live output remains)",
             !simnet_coin_exists(sim, &cb_txid));
    SN_CHECK("new spend output is present in the coins view",
             simnet_coin_exists(sim, &spend_txid));

    int64_t spend_value = 0;
    SN_CHECK("spend output value readable from coins view",
             simnet_coin_value(sim, &spend_txid, 0, &spend_value));
    SN_CHECK("spend output carries the chosen value", spend_value == 900000);

    /* 4. A second independent coinbase still mints cleanly on top. */
    struct uint256 cb2_txid;
    uint256_set_null(&cb2_txid);
    bool minted2 = simnet_mint_coinbase(sim, &cb2_txid);
    SN_CHECK("a further coinbase mints on top of the spend block", minted2);
    SN_CHECK("second coinbase coin exists",
             simnet_coin_exists(sim, &cb2_txid));

    /* 5. Public arbitrary-tx mint: OP_RETURN is accepted by consensus and
     *    pruned as unspendable while the transparent output remains live. */
    struct transaction custom;
    uint8_t opret[] = {0x6a, 0x04, 'S', 'I', 'M', '1'};
    bool built_custom =
        sim_test_make_opreturn_spend(&custom, &spend_txid, 0, opret,
                                     sizeof(opret), 800000, 0x40);
    *custom_txid = built_custom ? custom.hash : (struct uint256){0};
    SN_CHECK("build arbitrary OP_RETURN spend tx", built_custom);
    bool minted_custom = built_custom && simnet_mint_txs(sim, &custom, 1);
    SN_CHECK("simnet_mint_txs accepts transparent+OP_RETURN block",
             minted_custom);
    SN_CHECK("arbitrary tx consumed its input",
             minted_custom && !simnet_coin_exists(sim, &spend_txid));
    int64_t custom_value = 0;
    SN_CHECK("arbitrary tx transparent output remains in coins view",
             minted_custom &&
             simnet_coin_value(sim, custom_txid, 1, &custom_value) &&
             custom_value == 800000);
    return failures;
}

static int sim_test_action_inputs(struct simnet *action_sim,
                                  struct uint256 *action_fund0,
                                  struct uint256 *action_fund1,
                                  bool *action_funded1)
{
    int failures = 0;
    /* 5b. Base transparent action matrix: multi-input/multi-output plus
     *     a standard P2SH output, all through connect_block and the
     *     explorer projection. */
    bool action_init = simnet_init(action_sim);
    SN_CHECK("action simnet initializes", action_init);
    struct uint256 action_cb0;
    struct uint256 action_cb1;
    uint256_set_null(&action_cb0);
    uint256_set_null(&action_cb1);
    bool action_cb0_minted =
        action_init && simnet_mint_coinbase(action_sim, &action_cb0);
    bool action_cb1_minted =
        action_cb0_minted && simnet_mint_coinbase(action_sim, &action_cb1);
    SN_CHECK("action simnet mints two funding coinbases",
             action_cb0_minted && action_cb1_minted);

    uint256_set_null(action_fund0);
    uint256_set_null(action_fund1);
    bool action_funded0 =
        action_cb1_minted &&
        simnet_spend(action_sim, &action_cb0, 0, 600000, action_fund0);
    *action_funded1 =
        action_funded0 &&
        simnet_spend(action_sim, &action_cb1, 0, 500000, action_fund1);
    SN_CHECK("action simnet creates two mature transparent inputs",
             action_funded0 && *action_funded1);
    return failures;
}

static int sim_test_action_multi_tx(struct simnet *action_sim,
                                    struct uint256 *action_fund0,
                                    struct uint256 *action_fund1,
                                    bool action_funded1,
                                    struct transaction *multi_action_projection,
                                    bool *minted_multi_action)
{
    int failures = 0;
    struct transaction multi_action;
    transaction_init(multi_action_projection);
    bool built_multi_action =
        action_funded1 &&
        sim_test_make_multi_p2pkh_p2sh_spend(&multi_action,
                                             action_fund0, 0,
                                             action_fund1, 0);
    bool copied_multi_action =
        built_multi_action &&
        transaction_copy(multi_action_projection, &multi_action);
    struct uint256 multi_action_txid =
        built_multi_action ? multi_action.hash : (struct uint256){0};
    SN_CHECK("build multi-input/multi-output/P2SH tx",
             built_multi_action && copied_multi_action);
    *minted_multi_action =
        built_multi_action && copied_multi_action &&
        simnet_mint_txs(action_sim, &multi_action, 1);
    SN_CHECK("mint multi-input/multi-output/P2SH tx through simnet",
             *minted_multi_action);
    int64_t p2sh_value = 0;
    SN_CHECK("multi-input tx consumes both inputs",
             *minted_multi_action &&
             !simnet_coin_exists(action_sim, action_fund0) &&
             !simnet_coin_exists(action_sim, action_fund1));
    SN_CHECK("P2SH output remains in coins view",
             *minted_multi_action &&
             simnet_coin_value(action_sim, &multi_action_txid, 2,
                               &p2sh_value) &&
             p2sh_value == 200000);
    return failures;
}

static int sim_test_action_explorer(struct simnet *action_sim,
                                    struct transaction *multi_action_projection,
                                    bool minted_multi_action)
{
    int failures = 0;
    struct node_db action_db;
    memset(&action_db, 0, sizeof(action_db));
    bool action_db_open = node_db_open(&action_db, ":memory:");
    SN_CHECK("base action explorer db opens", action_db_open);
    bool indexed_multi_action =
        action_db_open && minted_multi_action &&
        sim_test_index_block(&action_db, multi_action_projection, 1,
                             simnet_tip_height(action_sim), 0xA7);
    SN_CHECK("explorer indexes multi-input/multi-output/P2SH tx",
             indexed_multi_action);
    SN_CHECK("explorer records two transparent inputs",
             indexed_multi_action &&
             sim_test_count_rows(&action_db,
                 "SELECT COUNT(*) FROM tx_inputs") == 2);
    SN_CHECK("explorer records one P2SH output",
             indexed_multi_action &&
             sim_test_count_rows(&action_db,
                 "SELECT COUNT(*) FROM tx_outputs WHERE script_type=1") == 1);
    transaction_free(multi_action_projection);
    if (action_db_open)
        node_db_close(&action_db);
    simnet_free(action_sim);
    return failures;
}

static int sim_test_slp_genesis(struct simnet *sim,
                                struct uint256 *custom_txid,
                                struct node_db *zslp_db, bool *zslp_open,
                                struct uint256 *slp_token_id,
                                char *slp_token_hex,
                                struct transaction *slp_genesis_projection)
{
    int failures = 0;
    /* 6. ZSLP overlay slice: real SLP builders, real simnet acceptance,
     *    real chain-derived token/transfer projection. */
    memset(zslp_db, 0, sizeof(*zslp_db));
    *zslp_open = node_db_open(zslp_db, ":memory:");
    SN_CHECK("ZSLP projection db opens", *zslp_open);

    uint8_t genesis_script[512];
    size_t genesis_script_len =
        slp_build_genesis(genesis_script, sizeof(genesis_script),
                          "SIM", "Simnet Token", "", NULL, 0, 2, 1000);
    SN_CHECK("build real SLP GENESIS script", genesis_script_len > 0);

    struct transaction slp_genesis;
    transaction_init(slp_genesis_projection);
    int64_t genesis_values[2] = { 650000, 50000 };
    unsigned char genesis_seeds[2] = { 0x60, 0x61 };
    bool built_slp_genesis =
        genesis_script_len > 0 &&
        sim_test_make_opreturn_spend_outputs(
            &slp_genesis, custom_txid, 1, genesis_script,
            genesis_script_len, genesis_values, genesis_seeds, 2);
    bool copied_slp_genesis =
        built_slp_genesis &&
        transaction_copy(slp_genesis_projection, &slp_genesis);
    *slp_token_id =
        built_slp_genesis ? slp_genesis.hash : (struct uint256){0};
    SN_CHECK("build SLP GENESIS tx", built_slp_genesis && copied_slp_genesis);
    bool minted_slp_genesis =
        built_slp_genesis && copied_slp_genesis &&
        simnet_mint_txs(sim, &slp_genesis, 1);
    int slp_genesis_height = simnet_tip_height(sim);
    SN_CHECK("mint SLP GENESIS through simnet", minted_slp_genesis);
    bool applied_slp_genesis =
        *zslp_open && minted_slp_genesis &&
        sim_test_apply_slp(zslp_db, slp_genesis_projection,
                           slp_genesis_height);
    SN_CHECK("fold SLP GENESIS into token projection", applied_slp_genesis);

    /* The projection keys tokens by the DISPLAY-order genesis txid — the
     * same string app.tokens.create answers (models/zslp.h). */
    uint256_get_hex(slp_token_id, slp_token_hex);
    struct db_zslp_token_info slp_info;
    memset(&slp_info, 0, sizeof(slp_info));
    bool found_slp_token =
        *zslp_open && db_zslp_token_find(zslp_db, slp_token_hex, &slp_info);
    SN_CHECK("ZSLP projection sees token",
             found_slp_token && strcmp(slp_info.ticker, "SIM") == 0 &&
             strcmp(slp_info.name, "Simnet Token") == 0 &&
             slp_info.total_minted == 1000);
    return failures;
}

static int sim_test_slp_send(struct simnet *sim, struct node_db *zslp_db,
                             bool zslp_open, struct uint256 *slp_token_id,
                             char *slp_token_hex,
                             struct uint256 *slp_wire_token_id,
                             struct uint256 *slp_send_txid,
                             struct transaction *slp_send_projection)
{
    int failures = 0;
    sim_test_slp_wire_token_id(slp_token_id, slp_wire_token_id);
    uint64_t send_qty[2] = { 250, 750 };
    uint8_t send_script[512];
    size_t send_script_len =
        slp_build_send(send_script, sizeof(send_script), slp_wire_token_id,
                       send_qty, 2);
    SN_CHECK("build real SLP SEND script", send_script_len > 0);

    int64_t send_values[2] = { 300000, 300000 };
    unsigned char send_seeds[2] = { 0x80, 0xA0 };
    struct transaction slp_send;
    transaction_init(slp_send_projection);
    bool built_slp_send =
        send_script_len > 0 &&
        sim_test_make_opreturn_spend_outputs(&slp_send, slp_token_id, 1,
                                             send_script, send_script_len,
                                             send_values, send_seeds, 2);
    bool copied_slp_send =
        built_slp_send && transaction_copy(slp_send_projection, &slp_send);
    *slp_send_txid = built_slp_send ? slp_send.hash : (struct uint256){0};
    SN_CHECK("build SLP SEND tx", built_slp_send && copied_slp_send);
    bool minted_slp_send =
        built_slp_send && copied_slp_send &&
        simnet_mint_txs(sim, &slp_send, 1);
    int slp_send_height = simnet_tip_height(sim);
    SN_CHECK("mint SLP SEND through simnet", minted_slp_send);
    bool applied_slp_send =
        zslp_open && minted_slp_send &&
        sim_test_apply_slp(zslp_db, slp_send_projection, slp_send_height);
    SN_CHECK("fold SLP SEND into transfer projection", applied_slp_send);

    struct db_zslp_transfer_info slp_xfers[4];
    memset(slp_xfers, 0, sizeof(slp_xfers));
    int slp_xfer_count =
        zslp_open ? db_zslp_transfer_list_by_token(zslp_db, slp_token_hex,
                                                   slp_xfers, 4) : 0;
    SN_CHECK("ZSLP projection sees genesis/send transfer balances",
             slp_xfer_count == 3 &&
             sim_test_transfer_amount(slp_xfers, slp_xfer_count,
                                      SLP_TX_GENESIS, 1) == 1000 &&
             sim_test_transfer_amount(slp_xfers, slp_xfer_count,
                                      SLP_TX_SEND, 1) == 250 &&
             sim_test_transfer_amount(slp_xfers, slp_xfer_count,
                                      SLP_TX_SEND, 2) == 750);
    return failures;
}

static int sim_test_slp_mint(struct simnet *sim, struct node_db *zslp_db,
                             bool zslp_open, struct uint256 *slp_token_id,
                             char *slp_token_hex,
                             struct uint256 *slp_wire_token_id,
                             struct uint256 *slp_mint_txid,
                             struct transaction *slp_mint_projection,
                             bool *minted_slp_mint)
{
    int failures = 0;
    uint8_t mint_script[512];
    size_t mint_script_len =
        slp_build_mint(mint_script, sizeof(mint_script), slp_wire_token_id,
                       2, 125);
    SN_CHECK("build real SLP MINT script", mint_script_len > 0);

    struct transaction slp_mint;
    transaction_init(slp_mint_projection);
    int64_t mint_values[2] = { 20000, 20000 };
    unsigned char mint_seeds[2] = { 0xB0, 0xB1 };
    bool built_slp_mint =
        mint_script_len > 0 &&
        sim_test_make_opreturn_spend_outputs(
            &slp_mint, slp_token_id, 2, mint_script, mint_script_len,
            mint_values, mint_seeds, 2);
    bool copied_slp_mint =
        built_slp_mint && transaction_copy(slp_mint_projection, &slp_mint);
    *slp_mint_txid = built_slp_mint ? slp_mint.hash : (struct uint256){0};
    SN_CHECK("build SLP MINT tx", built_slp_mint && copied_slp_mint);
    *minted_slp_mint =
        built_slp_mint && copied_slp_mint &&
        simnet_mint_txs(sim, &slp_mint, 1);
    int slp_mint_height = simnet_tip_height(sim);
    SN_CHECK("mint SLP MINT through simnet", *minted_slp_mint);
    bool applied_slp_mint =
        zslp_open && *minted_slp_mint &&
        sim_test_apply_slp(zslp_db, slp_mint_projection, slp_mint_height);
    SN_CHECK("fold SLP MINT into transfer projection", applied_slp_mint);

    struct db_zslp_transfer_info slp_xfers_after_mint[5];
    memset(slp_xfers_after_mint, 0, sizeof(slp_xfers_after_mint));
    int slp_xfer_count_after_mint =
        zslp_open ? db_zslp_transfer_list_by_token(zslp_db, slp_token_hex,
                                                   slp_xfers_after_mint, 5) : 0;
    SN_CHECK("ZSLP projection sees mint transfer",
             slp_xfer_count_after_mint == 4 &&
             sim_test_transfer_amount(slp_xfers_after_mint,
                                      slp_xfer_count_after_mint,
                                      SLP_TX_MINT, 1) == 125);
    return failures;
}

static int sim_test_slp_burn(struct simnet *sim, struct node_db *zslp_db,
                             bool zslp_open,
                             struct uint256 *slp_wire_token_id,
                             struct uint256 *slp_send_txid,
                             struct uint256 *slp_burn_txid,
                             struct transaction *slp_burn_projection,
                             bool *applied_slp_burn)
{
    int failures = 0;
    uint64_t burn_change_qty[1] = { 100 };
    uint8_t burn_script[512];
    size_t burn_script_len =
        slp_build_send(burn_script, sizeof(burn_script), slp_wire_token_id,
                       burn_change_qty, 1);
    SN_CHECK("build real SLP implicit-BURN SEND script",
             burn_script_len > 0);

    struct transaction slp_burn;
    transaction_init(slp_burn_projection);
    int64_t burn_values[2] = { 20000, 250000 };
    unsigned char burn_seeds[2] = { 0xB2, 0xB3 };
    bool built_slp_burn =
        burn_script_len > 0 &&
        sim_test_make_opreturn_spend_outputs(
            &slp_burn, slp_send_txid, 1, burn_script, burn_script_len,
            burn_values, burn_seeds, 2);
    bool copied_slp_burn =
        built_slp_burn && transaction_copy(slp_burn_projection, &slp_burn);
    *slp_burn_txid = built_slp_burn ? slp_burn.hash : (struct uint256){0};
    SN_CHECK("build SLP implicit-BURN tx", built_slp_burn && copied_slp_burn);
    bool minted_slp_burn =
        built_slp_burn && copied_slp_burn &&
        simnet_mint_txs(sim, &slp_burn, 1);
    int slp_burn_height = simnet_tip_height(sim);
    SN_CHECK("mint SLP implicit-BURN through simnet", minted_slp_burn);
    *applied_slp_burn =
        zslp_open && minted_slp_burn &&
        sim_test_apply_slp(zslp_db, slp_burn_projection, slp_burn_height);
    SN_CHECK("fold SLP implicit-BURN into strict ledger", *applied_slp_burn);
    return failures;
}

static int sim_test_slp_burn_supply(struct node_db *zslp_db,
                                    struct uint256 *slp_token_id,
                                    struct uint256 *slp_burn_txid,
                                    struct uint256 *slp_mint_txid,
                                    bool applied_slp_burn)
{
    int failures = 0;
    char slp_burn_reason[96];
    struct zslp_token_validity_summary slp_supply;
    memset(&slp_supply, 0, sizeof(slp_supply));
    bool summarized_slp_burn =
        applied_slp_burn &&
        zslp_validity_get(zslp_db, slp_burn_txid->data, slp_burn_reason,
                          sizeof(slp_burn_reason)) == ZSLP_VALIDITY_VALID &&
        strcmp(slp_burn_reason, "valid_send") == 0 &&
        zslp_validity_token_summary(zslp_db, slp_token_id->data,
                                    &slp_supply);
    SN_CHECK("strict ZSLP supply records exactly 150 burned units",
             summarized_slp_burn && slp_supply.total_minted == 1125 &&
             slp_supply.total_burned == 150 &&
             slp_supply.circulating_supply == 975 &&
             slp_supply.baton_active && slp_supply.baton_vout == 2 &&
             memcmp(slp_supply.baton_txid, slp_mint_txid->data, 32) == 0);
    return failures;
}

static int sim_test_slp_malformed(struct simnet *sim,
                                  struct node_db *zslp_db, bool zslp_open,
                                  struct uint256 *slp_wire_token_id,
                                  struct uint256 *slp_mint_txid,
                                  struct transaction *slp_malformed_projection,
                                  bool minted_slp_mint, char *slp_token_hex)
{
    int failures = 0;
    uint64_t malformed_qty[1] = { 9999999 };
    uint8_t malformed_slp_script[512];
    size_t malformed_slp_len =
        slp_build_send(malformed_slp_script, sizeof(malformed_slp_script),
                       slp_wire_token_id, malformed_qty, 1);
    if (malformed_slp_len > 2)
        malformed_slp_script[2] ^= 0x11; /* corrupt lokad byte after builder */
    SN_CHECK("build malformed SLP script from real SEND builder",
             malformed_slp_len > 2);

    struct transaction slp_malformed;
    transaction_init(slp_malformed_projection);
    bool built_slp_malformed =
        malformed_slp_len > 2 && minted_slp_mint &&
        sim_test_make_opreturn_spend(&slp_malformed, slp_mint_txid, 1,
                                     malformed_slp_script, malformed_slp_len,
                                     10000, 0xB1);
    bool copied_slp_malformed =
        built_slp_malformed &&
        transaction_copy(slp_malformed_projection, &slp_malformed);
    SN_CHECK("build malformed SLP tx",
             built_slp_malformed && copied_slp_malformed);
    bool minted_slp_malformed =
        built_slp_malformed && copied_slp_malformed &&
        simnet_mint_txs(sim, &slp_malformed, 1);
    int slp_malformed_height = simnet_tip_height(sim);
    SN_CHECK("mint malformed SLP tx through simnet", minted_slp_malformed);
    bool indexed_slp_malformed =
        zslp_open && minted_slp_malformed &&
        sim_test_index_block(zslp_db, slp_malformed_projection, 1,
                             slp_malformed_height, 0xB2);
    SN_CHECK("malformed SLP OP_RETURN is indexed as non-SLP",
             indexed_slp_malformed &&
             sim_test_count_rows(zslp_db,
                 "SELECT COUNT(*) FROM op_returns WHERE is_slp=0") == 1);
    struct db_zslp_transfer_info slp_xfers_after_bad[5];
    memset(slp_xfers_after_bad, 0, sizeof(slp_xfers_after_bad));
    int slp_xfer_count_after_bad =
        zslp_open ? db_zslp_transfer_list_by_token(zslp_db, slp_token_hex,
                                                   slp_xfers_after_bad, 5) : 0;
    SN_CHECK("malformed SLP does not add token transfers",
             slp_xfer_count_after_bad == 5);
    return failures;
}

static int sim_test_znam_owner_fund(struct simnet *sim,
                                    struct uint256 *slp_burn_txid,
                                    struct node_db *znam_db, bool *znam_open,
                                    struct uint256 *znam_owner_fund_txid,
                                    struct transaction
                                        *znam_owner_fund_projection)
{
    int failures = 0;
    /* 7. ZNAM overlay slice: real ZNAM REGISTER builder, simnet acceptance,
     *    explorer owner derivation from the indexed funding output, and
     *    model-backed name resolution. */
    memset(znam_db, 0, sizeof(*znam_db));
    *znam_open = node_db_open(znam_db, ":memory:");
    SN_CHECK("ZNAM projection db opens", *znam_open);

    struct transaction znam_owner_fund;
    transaction_init(znam_owner_fund_projection);
    int64_t znam_owner_values[2] = { 120000, 120000 };
    unsigned char znam_owner_seeds[2] = { 0xC0, 0xC0 };
    bool built_znam_owner_fund =
        sim_test_make_p2pkh_spend_outputs(&znam_owner_fund, slp_burn_txid, 2,
                                          znam_owner_values, znam_owner_seeds,
                                          2);
    bool copied_znam_owner_fund =
        built_znam_owner_fund &&
        transaction_copy(znam_owner_fund_projection, &znam_owner_fund);
    *znam_owner_fund_txid =
        built_znam_owner_fund ? znam_owner_fund.hash : (struct uint256){0};
    SN_CHECK("build ZNAM owner funding tx",
             built_znam_owner_fund && copied_znam_owner_fund);
    bool minted_znam_owner_fund =
        built_znam_owner_fund && copied_znam_owner_fund &&
        simnet_mint_txs(sim, &znam_owner_fund, 1);
    int znam_owner_fund_height = simnet_tip_height(sim);
    SN_CHECK("mint ZNAM owner funding tx through simnet",
             minted_znam_owner_fund);
    bool indexed_znam_owner_fund =
        *znam_open && minted_znam_owner_fund &&
        sim_test_index_block(znam_db, znam_owner_fund_projection, 1,
                             znam_owner_fund_height, 0xD1);
    SN_CHECK("index ZNAM owner funding output", indexed_znam_owner_fund);
    return failures;
}

static int sim_test_znam_register(struct simnet *sim,
                                  struct node_db *znam_db, bool znam_open,
                                  struct uint256 *znam_owner_fund_txid,
                                  struct uint256 *znam_register_txid,
                                  struct transaction *znam_register_projection,
                                  char (*znam_owner_before_transfer)[64])
{
    int failures = 0;
    uint8_t znam_script[512];
    size_t znam_script_len =
        znam_build_register(znam_script, sizeof(znam_script),
                            "alice", ZNAM_TYPE_TADDR, "t1simtarget");
    SN_CHECK("build real ZNAM REGISTER script", znam_script_len > 0);

    struct transaction znam_register;
    transaction_init(znam_register_projection);
    bool built_znam_register =
        znam_script_len > 0 &&
        sim_test_make_opreturn_spend(&znam_register, znam_owner_fund_txid, 0,
                                     znam_script, znam_script_len,
                                     100000, 0xE0);
    bool copied_znam_register =
        built_znam_register &&
        transaction_copy(znam_register_projection, &znam_register);
    *znam_register_txid =
        built_znam_register ? znam_register.hash : (struct uint256){0};
    SN_CHECK("build ZNAM REGISTER tx",
             built_znam_register && copied_znam_register);
    bool minted_znam_register =
        built_znam_register && copied_znam_register &&
        simnet_mint_txs(sim, &znam_register, 1);
    int znam_register_height = simnet_tip_height(sim);
    SN_CHECK("mint ZNAM REGISTER through simnet", minted_znam_register);
    bool indexed_znam_register =
        znam_open && minted_znam_register &&
        sim_test_index_block(znam_db, znam_register_projection, 1,
                             znam_register_height, 0xD2);
    SN_CHECK("fold ZNAM REGISTER into name projection", indexed_znam_register);

    struct znam_entry resolved;
    memset(&resolved, 0, sizeof(resolved));
    bool resolved_znam =
        znam_open && db_znam_find(znam_db, "alice", &resolved);
    SN_CHECK("ZNAM projection resolves registered name",
             resolved_znam && strcmp(resolved.name, "alice") == 0 &&
             resolved.target_type == ZNAM_TYPE_TADDR &&
             strcmp(resolved.target_value, "t1simtarget") == 0 &&
             resolved.owner_address[0] != '\0' &&
             resolved.reg_height == znam_register_height);

    snprintf(*znam_owner_before_transfer, sizeof(*znam_owner_before_transfer),
             "%s", resolved.owner_address);
    return failures;
}

static int sim_test_znam_bad_update(struct simnet *sim,
                                    struct node_db *znam_db, bool znam_open,
                                    struct uint256 *znam_register_txid,
                                    struct transaction
                                        *znam_bad_update_projection,
                                    char (*znam_owner_before_transfer)[64])
{
    int failures = 0;
    uint8_t znam_bad_update_script[512];
    size_t znam_bad_update_script_len =
        znam_build_update(znam_bad_update_script,
                          sizeof(znam_bad_update_script),
                          "alice", ZNAM_TYPE_TADDR, "t1badtarget");
    SN_CHECK("build real ZNAM non-owner UPDATE script",
             znam_bad_update_script_len > 0);

    struct transaction znam_bad_update;
    transaction_init(znam_bad_update_projection);
    bool built_znam_bad_update =
        znam_bad_update_script_len > 0 &&
        sim_test_make_opreturn_spend(&znam_bad_update, znam_register_txid, 1,
                                     znam_bad_update_script,
                                     znam_bad_update_script_len,
                                     80000, 0xE1);
    bool copied_znam_bad_update =
        built_znam_bad_update &&
        transaction_copy(znam_bad_update_projection, &znam_bad_update);
    SN_CHECK("build ZNAM non-owner UPDATE tx",
             built_znam_bad_update && copied_znam_bad_update);
    bool minted_znam_bad_update =
        built_znam_bad_update && copied_znam_bad_update &&
        simnet_mint_txs(sim, &znam_bad_update, 1);
    int znam_bad_update_height = simnet_tip_height(sim);
    SN_CHECK("mint ZNAM non-owner UPDATE through simnet",
             minted_znam_bad_update);
    bool indexed_znam_bad_update =
        znam_open && minted_znam_bad_update &&
        sim_test_index_block(znam_db, znam_bad_update_projection, 1,
                             znam_bad_update_height, 0xD3);
    SN_CHECK("fold ZNAM non-owner UPDATE into projection",
             indexed_znam_bad_update);
    struct znam_entry after_bad_update;
    memset(&after_bad_update, 0, sizeof(after_bad_update));
    bool bad_update_ignored =
        znam_open && db_znam_find(znam_db, "alice", &after_bad_update);
    SN_CHECK("ZNAM non-owner UPDATE is ignored by projection",
             bad_update_ignored &&
             strcmp(after_bad_update.target_value, "t1simtarget") == 0 &&
             strcmp(after_bad_update.owner_address,
                    *znam_owner_before_transfer) == 0);
    return failures;
}

static int sim_test_znam_owner_update(struct simnet *sim,
                                      struct node_db *znam_db, bool znam_open,
                                      struct uint256 *znam_owner_fund_txid,
                                      struct uint256 *znam_update_txid,
                                      struct transaction
                                          *znam_update_projection,
                                      char (*znam_owner_before_transfer)[64])
{
    int failures = 0;
    uint8_t znam_update_script[512];
    size_t znam_update_script_len =
        znam_build_update(znam_update_script, sizeof(znam_update_script),
                          "alice", ZNAM_TYPE_TADDR, "t1updated");
    SN_CHECK("build real ZNAM owner UPDATE script", znam_update_script_len > 0);

    /* Output 1 continues the owner-controlled UTXO chain (unchanged from
     * before); outputs 2 and 3 are attacker-controlled decoys (seed 0xE1,
     * NOT alice's owner address) used below to fund the non-owner
     * SET_RECORD / SET_TEXT rejection tests. */
    struct transaction znam_update;
    transaction_init(znam_update_projection);
    int64_t znam_update_values[3] = { 90000, 10000, 10000 };
    unsigned char znam_update_seeds[3] = { 0xC0, 0xE1, 0xE1 };
    bool built_znam_update =
        znam_update_script_len > 0 &&
        sim_test_make_opreturn_spend_outputs(&znam_update, znam_owner_fund_txid,
                                             1, znam_update_script,
                                             znam_update_script_len,
                                             znam_update_values,
                                             znam_update_seeds, 3);
    bool copied_znam_update =
        built_znam_update && transaction_copy(znam_update_projection,
                                              &znam_update);
    *znam_update_txid =
        built_znam_update ? znam_update.hash : (struct uint256){0};
    SN_CHECK("build ZNAM owner UPDATE tx",
             built_znam_update && copied_znam_update);
    bool minted_znam_update =
        built_znam_update && copied_znam_update &&
        simnet_mint_txs(sim, &znam_update, 1);
    int znam_update_height = simnet_tip_height(sim);
    SN_CHECK("mint ZNAM owner UPDATE through simnet", minted_znam_update);
    bool indexed_znam_update =
        znam_open && minted_znam_update &&
        sim_test_index_block(znam_db, znam_update_projection, 1,
                             znam_update_height, 0xD4);
    SN_CHECK("fold ZNAM owner UPDATE into projection", indexed_znam_update);
    struct znam_entry after_update;
    memset(&after_update, 0, sizeof(after_update));
    bool update_applied =
        znam_open && db_znam_find(znam_db, "alice", &after_update);
    SN_CHECK("ZNAM owner UPDATE changes primary target",
             update_applied &&
             strcmp(after_update.target_value, "t1updated") == 0 &&
             strcmp(after_update.owner_address,
                    *znam_owner_before_transfer) == 0);
    return failures;
}

static int sim_test_znam_bad_record(struct simnet *sim,
                                    struct node_db *znam_db, bool znam_open,
                                    struct uint256 *znam_update_txid)
{
    int failures = 0;
    uint8_t znam_bad_record_script[512];
    size_t znam_bad_record_script_len =
        znam_build_set_record(znam_bad_record_script,
                              sizeof(znam_bad_record_script), "alice",
                              ZNAM_TYPE_BTC, "1AttackerBtcAddrXXXXXXXXXXXXXXXXX");
    SN_CHECK("build real ZNAM non-owner SET_RECORD script",
             znam_bad_record_script_len > 0);

    struct transaction znam_bad_record;
    struct transaction znam_bad_record_projection;
    transaction_init(&znam_bad_record_projection);
    bool built_znam_bad_record =
        znam_bad_record_script_len > 0 &&
        sim_test_make_opreturn_spend(&znam_bad_record, znam_update_txid, 2,
                                     znam_bad_record_script,
                                     znam_bad_record_script_len,
                                     8000, 0xE1);
    bool copied_znam_bad_record =
        built_znam_bad_record &&
        transaction_copy(&znam_bad_record_projection, &znam_bad_record);
    SN_CHECK("build ZNAM non-owner SET_RECORD tx",
             built_znam_bad_record && copied_znam_bad_record);
    bool minted_znam_bad_record =
        built_znam_bad_record && copied_znam_bad_record &&
        simnet_mint_txs(sim, &znam_bad_record, 1);
    int znam_bad_record_height = simnet_tip_height(sim);
    SN_CHECK("mint ZNAM non-owner SET_RECORD through simnet",
             minted_znam_bad_record);
    bool indexed_znam_bad_record =
        znam_open && minted_znam_bad_record &&
        sim_test_index_block(znam_db, &znam_bad_record_projection, 1,
                             znam_bad_record_height, 0xDA);
    SN_CHECK("fold ZNAM non-owner SET_RECORD into projection",
             indexed_znam_bad_record);
    char bad_btc_record[ZNAM_VALUE_MAX + 1];
    memset(bad_btc_record, 0, sizeof(bad_btc_record));
    bool bad_record_leaked =
        db_znam_addr_get(znam_db, "alice", ZNAM_TYPE_BTC,
                         bad_btc_record, sizeof(bad_btc_record));
    SN_CHECK("ZNAM non-owner SET_RECORD is ignored by projection",
             indexed_znam_bad_record && !bad_record_leaked);
    return failures;
}

static int sim_test_znam_record(struct simnet *sim, struct node_db *znam_db,
                                bool znam_open,
                                struct uint256 *znam_update_txid,
                                struct uint256 *znam_record_txid,
                                struct transaction *znam_record_projection)
{
    int failures = 0;
    uint8_t znam_record_script[512];
    size_t znam_record_script_len =
        znam_build_set_record(znam_record_script, sizeof(znam_record_script),
                              "alice", ZNAM_TYPE_BTC,
                              "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    SN_CHECK("build real ZNAM SET_RECORD script",
             znam_record_script_len > 0);

    struct transaction znam_record;
    transaction_init(znam_record_projection);
    bool built_znam_record =
        znam_record_script_len > 0 &&
        sim_test_make_opreturn_spend(&znam_record, znam_update_txid, 1,
                                     znam_record_script,
                                     znam_record_script_len,
                                     80000, 0xC0);
    bool copied_znam_record =
        built_znam_record && transaction_copy(znam_record_projection,
                                              &znam_record);
    *znam_record_txid =
        built_znam_record ? znam_record.hash : (struct uint256){0};
    SN_CHECK("build ZNAM SET_RECORD tx",
             built_znam_record && copied_znam_record);
    bool minted_znam_record =
        built_znam_record && copied_znam_record &&
        simnet_mint_txs(sim, &znam_record, 1);
    int znam_record_height = simnet_tip_height(sim);
    SN_CHECK("mint ZNAM SET_RECORD through simnet", minted_znam_record);
    bool indexed_znam_record =
        znam_open && minted_znam_record &&
        sim_test_index_block(znam_db, znam_record_projection, 1,
                             znam_record_height, 0xD5);
    SN_CHECK("fold ZNAM SET_RECORD into projection", indexed_znam_record);
    char btc_record[ZNAM_VALUE_MAX + 1];
    memset(btc_record, 0, sizeof(btc_record));
    SN_CHECK("ZNAM SET_RECORD writes BTC address record",
             indexed_znam_record &&
             db_znam_addr_get(znam_db, "alice", ZNAM_TYPE_BTC,
                              btc_record, sizeof(btc_record)) &&
             strcmp(btc_record, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == 0);
    return failures;
}

static int sim_test_znam_bad_text(struct simnet *sim,
                                  struct node_db *znam_db, bool znam_open,
                                  struct uint256 *znam_update_txid)
{
    int failures = 0;
    uint8_t znam_bad_text_script[512];
    size_t znam_bad_text_script_len =
        znam_build_set_text(znam_bad_text_script, sizeof(znam_bad_text_script),
                            "alice", "email", "attacker@evil.test");
    SN_CHECK("build real ZNAM non-owner SET_TEXT script",
             znam_bad_text_script_len > 0);

    struct transaction znam_bad_text;
    struct transaction znam_bad_text_projection;
    transaction_init(&znam_bad_text_projection);
    bool built_znam_bad_text =
        znam_bad_text_script_len > 0 &&
        sim_test_make_opreturn_spend(&znam_bad_text, znam_update_txid, 3,
                                     znam_bad_text_script,
                                     znam_bad_text_script_len,
                                     8000, 0xE1);
    bool copied_znam_bad_text =
        built_znam_bad_text &&
        transaction_copy(&znam_bad_text_projection, &znam_bad_text);
    SN_CHECK("build ZNAM non-owner SET_TEXT tx",
             built_znam_bad_text && copied_znam_bad_text);
    bool minted_znam_bad_text =
        built_znam_bad_text && copied_znam_bad_text &&
        simnet_mint_txs(sim, &znam_bad_text, 1);
    int znam_bad_text_height = simnet_tip_height(sim);
    SN_CHECK("mint ZNAM non-owner SET_TEXT through simnet",
             minted_znam_bad_text);
    bool indexed_znam_bad_text =
        znam_open && minted_znam_bad_text &&
        sim_test_index_block(znam_db, &znam_bad_text_projection, 1,
                             znam_bad_text_height, 0xDB);
    SN_CHECK("fold ZNAM non-owner SET_TEXT into projection",
             indexed_znam_bad_text);
    char bad_email_record[ZNAM_TEXT_VAL_MAX + 1];
    memset(bad_email_record, 0, sizeof(bad_email_record));
    bool bad_text_leaked =
        db_znam_text_get(znam_db, "alice", "email",
                         bad_email_record, sizeof(bad_email_record));
    SN_CHECK("ZNAM non-owner SET_TEXT is ignored by projection",
             indexed_znam_bad_text && !bad_text_leaked);
    return failures;
}

static int sim_test_znam_text(struct simnet *sim, struct node_db *znam_db,
                              bool znam_open,
                              struct uint256 *znam_record_txid,
                              struct uint256 *znam_text_txid,
                              struct transaction *znam_text_projection)
{
    int failures = 0;
    uint8_t znam_text_script[512];
    size_t znam_text_script_len =
        znam_build_set_text(znam_text_script, sizeof(znam_text_script),
                            "alice", "email", "alice@example.test");
    SN_CHECK("build real ZNAM SET_TEXT script", znam_text_script_len > 0);

    struct transaction znam_text;
    transaction_init(znam_text_projection);
    bool built_znam_text =
        znam_text_script_len > 0 &&
        sim_test_make_opreturn_spend(&znam_text, znam_record_txid, 1,
                                     znam_text_script, znam_text_script_len,
                                     70000, 0xC0);
    bool copied_znam_text =
        built_znam_text && transaction_copy(znam_text_projection, &znam_text);
    *znam_text_txid = built_znam_text ? znam_text.hash : (struct uint256){0};
    SN_CHECK("build ZNAM SET_TEXT tx",
             built_znam_text && copied_znam_text);
    bool minted_znam_text =
        built_znam_text && copied_znam_text &&
        simnet_mint_txs(sim, &znam_text, 1);
    int znam_text_height = simnet_tip_height(sim);
    SN_CHECK("mint ZNAM SET_TEXT through simnet", minted_znam_text);
    bool indexed_znam_text =
        znam_open && minted_znam_text &&
        sim_test_index_block(znam_db, znam_text_projection, 1,
                             znam_text_height, 0xD6);
    SN_CHECK("fold ZNAM SET_TEXT into projection", indexed_znam_text);
    char email_record[ZNAM_TEXT_VAL_MAX + 1];
    memset(email_record, 0, sizeof(email_record));
    SN_CHECK("ZNAM SET_TEXT writes text record",
             indexed_znam_text &&
             db_znam_text_get(znam_db, "alice", "email",
                              email_record, sizeof(email_record)) &&
             strcmp(email_record, "alice@example.test") == 0);
    return failures;
}

static int sim_test_znam_renew(struct simnet *sim, struct node_db *znam_db,
                               bool znam_open,
                               struct uint256 *znam_text_txid,
                               struct uint256 *znam_renew_txid,
                               struct transaction *znam_renew_projection,
                               char (*znam_owner_before_transfer)[64])
{
    int failures = 0;
    uint8_t znam_renew_script[512];
    size_t znam_renew_script_len =
        znam_build_renew(znam_renew_script, sizeof(znam_renew_script),
                         "alice");
    SN_CHECK("build real ZNAM RENEW script", znam_renew_script_len > 0);

    struct transaction znam_renew;
    transaction_init(znam_renew_projection);
    bool built_znam_renew =
        znam_renew_script_len > 0 &&
        sim_test_make_opreturn_spend(&znam_renew, znam_text_txid, 1,
                                     znam_renew_script, znam_renew_script_len,
                                     60000, 0xC0);
    bool copied_znam_renew =
        built_znam_renew && transaction_copy(znam_renew_projection,
                                             &znam_renew);
    *znam_renew_txid = built_znam_renew ? znam_renew.hash : (struct uint256){0};
    SN_CHECK("build ZNAM RENEW tx",
             built_znam_renew && copied_znam_renew);
    bool minted_znam_renew =
        built_znam_renew && copied_znam_renew &&
        simnet_mint_txs(sim, &znam_renew, 1);
    int znam_renew_height = simnet_tip_height(sim);
    SN_CHECK("mint ZNAM RENEW through simnet", minted_znam_renew);
    bool indexed_znam_renew =
        znam_open && minted_znam_renew &&
        sim_test_index_block(znam_db, znam_renew_projection, 1,
                             znam_renew_height, 0xD7);
    SN_CHECK("fold ZNAM RENEW through projection", indexed_znam_renew);
    struct znam_entry after_renew;
    memset(&after_renew, 0, sizeof(after_renew));
    bool renew_noop =
        znam_open && db_znam_find(znam_db, "alice", &after_renew);
    SN_CHECK("ZNAM RENEW is a node.db projection no-op today",
             renew_noop &&
             strcmp(after_renew.target_value, "t1updated") == 0 &&
             strcmp(after_renew.owner_address,
                    *znam_owner_before_transfer) == 0);
    return failures;
}

static int sim_test_znam_transfer(struct simnet *sim, struct node_db *znam_db,
                                  bool znam_open,
                                  struct uint256 *znam_renew_txid,
                                  struct uint256 *znam_transfer_txid,
                                  struct transaction *znam_transfer_projection)
{
    int failures = 0;
    uint8_t znam_transfer_script[512];
    size_t znam_transfer_script_len =
        znam_build_transfer(znam_transfer_script, sizeof(znam_transfer_script),
                            "alice", "t1simnewowner");
    SN_CHECK("build real ZNAM TRANSFER script",
             znam_transfer_script_len > 0);

    struct transaction znam_transfer;
    transaction_init(znam_transfer_projection);
    bool built_znam_transfer =
        znam_transfer_script_len > 0 &&
        sim_test_make_opreturn_spend(&znam_transfer, znam_renew_txid, 1,
                                     znam_transfer_script,
                                     znam_transfer_script_len,
                                     50000, 0xC0);
    bool copied_znam_transfer =
        built_znam_transfer && transaction_copy(znam_transfer_projection,
                                                &znam_transfer);
    *znam_transfer_txid =
        built_znam_transfer ? znam_transfer.hash : (struct uint256){0};
    SN_CHECK("build ZNAM TRANSFER tx",
             built_znam_transfer && copied_znam_transfer);
    bool minted_znam_transfer =
        built_znam_transfer && copied_znam_transfer &&
        simnet_mint_txs(sim, &znam_transfer, 1);
    int znam_transfer_height = simnet_tip_height(sim);
    SN_CHECK("mint ZNAM TRANSFER through simnet", minted_znam_transfer);
    bool indexed_znam_transfer =
        znam_open && minted_znam_transfer &&
        sim_test_index_block(znam_db, znam_transfer_projection, 1,
                             znam_transfer_height, 0xD8);
    SN_CHECK("fold ZNAM TRANSFER into projection", indexed_znam_transfer);
    struct znam_entry after_transfer;
    memset(&after_transfer, 0, sizeof(after_transfer));
    bool transfer_applied =
        znam_open && db_znam_find(znam_db, "alice", &after_transfer);
    SN_CHECK("ZNAM TRANSFER changes owner",
             transfer_applied &&
             strcmp(after_transfer.owner_address, "t1simnewowner") == 0 &&
             strcmp(after_transfer.target_value, "t1updated") == 0);
    return failures;
}

static int sim_test_znam_malformed(struct simnet *sim,
                                   struct node_db *znam_db, bool znam_open,
                                   struct uint256 *znam_transfer_txid,
                                   struct uint256 *znam_malformed_txid,
                                   struct transaction
                                       *znam_malformed_projection)
{
    int failures = 0;
    uint8_t malformed_znam_script[512];
    size_t malformed_znam_len =
        znam_build_update(malformed_znam_script, sizeof(malformed_znam_script),
                          "alice", ZNAM_TYPE_TADDR, "t1malformed");
    if (malformed_znam_len > 2)
        malformed_znam_script[2] ^= 0x22; /* corrupt lokad byte after builder */
    SN_CHECK("build malformed ZNAM script from real UPDATE builder",
             malformed_znam_len > 2);

    struct transaction znam_malformed;
    transaction_init(znam_malformed_projection);
    bool built_znam_malformed =
        malformed_znam_len > 2 &&
        sim_test_make_opreturn_spend(&znam_malformed, znam_transfer_txid, 1,
                                     malformed_znam_script,
                                     malformed_znam_len, 40000, 0xC0);
    bool copied_znam_malformed =
        built_znam_malformed &&
        transaction_copy(znam_malformed_projection, &znam_malformed);
    *znam_malformed_txid =
        built_znam_malformed ? znam_malformed.hash : (struct uint256){0};
    SN_CHECK("build malformed ZNAM tx",
             built_znam_malformed && copied_znam_malformed);
    bool minted_znam_malformed =
        built_znam_malformed && copied_znam_malformed &&
        simnet_mint_txs(sim, &znam_malformed, 1);
    int znam_malformed_height = simnet_tip_height(sim);
    SN_CHECK("mint malformed ZNAM tx through simnet", minted_znam_malformed);
    bool indexed_znam_malformed =
        znam_open && minted_znam_malformed &&
        sim_test_index_block(znam_db, znam_malformed_projection, 1,
                             znam_malformed_height, 0xD9);
    SN_CHECK("malformed ZNAM OP_RETURN is indexed generically",
             indexed_znam_malformed &&
             sim_test_count_rows(znam_db,
                 "SELECT COUNT(*) FROM op_returns") == 10);
    struct znam_entry after_malformed;
    memset(&after_malformed, 0, sizeof(after_malformed));
    bool malformed_ignored =
        znam_open && db_znam_find(znam_db, "alice", &after_malformed);
    SN_CHECK("malformed ZNAM lokad does not mutate name projection",
             malformed_ignored &&
             strcmp(after_malformed.owner_address, "t1simnewowner") == 0 &&
             strcmp(after_malformed.target_value, "t1updated") == 0);
    return failures;
}

static int sim_test_zblg_anchor(struct simnet *sim, struct node_db *znam_db,
                                bool znam_open,
                                struct uint256 *znam_malformed_txid,
                                struct transaction *blog_anchor_projection)
{
    int failures = 0;
    /* 8. ZBLG composite overlay: the public Blog anchor codec's exact bytes
     * enter a real block through connect_block, then the generic explorer
     * projection retains the exact OP_RETURN at its mined height. The
     * transaction/canonical-block/reorg joins plus signed-event/ZNAM-owner
     * policy are proved in test_blog; this axis proves real block acceptance
     * instead of substituting a database row. */
    uint8_t blog_event_id[32];
    memset(blog_event_id, 0x5b, sizeof(blog_event_id));
    uint8_t blog_script[BLOG_ANCHOR_SCRIPT_MAX];
    size_t blog_script_len = 0;
    struct zcl_result built_blog_script = blog_anchor_script_build(
        "alice", blog_event_id, blog_script, sizeof(blog_script),
        &blog_script_len);
    SN_CHECK("build strict ZBLG event anchor",
             built_blog_script.ok && blog_script_len > 0);

    struct transaction blog_anchor_tx;
    transaction_init(blog_anchor_projection);
    bool built_blog_anchor =
        built_blog_script.ok &&
        sim_test_make_opreturn_spend(
            &blog_anchor_tx, znam_malformed_txid, 1,
            blog_script, blog_script_len, 30000, 0xC0);
    bool copied_blog_anchor =
        built_blog_anchor &&
        transaction_copy(blog_anchor_projection, &blog_anchor_tx);
    SN_CHECK("build ZBLG funding transaction",
             built_blog_anchor && copied_blog_anchor);
    bool minted_blog_anchor =
        built_blog_anchor && copied_blog_anchor &&
        simnet_mint_txs(sim, &blog_anchor_tx, 1);
    int blog_anchor_height = simnet_tip_height(sim);
    SN_CHECK("mine ZBLG anchor through simnet", minted_blog_anchor);
    bool indexed_blog_anchor =
        znam_open && minted_blog_anchor &&
        sim_test_index_block(znam_db, blog_anchor_projection, 1,
                             blog_anchor_height, 0xDA);
    SN_CHECK("fold ZBLG anchor into explorer projection", indexed_blog_anchor);
    struct db_blog_chain_anchor projected_blog_anchor;
    memset(&projected_blog_anchor, 0, sizeof(projected_blog_anchor));
    bool found_blog_anchor =
        znam_open && db_blog_chain_anchor_find(
            znam_db, blog_script, blog_script_len, &projected_blog_anchor);
    SN_CHECK("ZBLG projection finds exact OP_RETURN",
             found_blog_anchor &&
             projected_blog_anchor.op_return_height == blog_anchor_height);
    return failures;
}

static int sim_test_multi_node_setup(struct simnet *left,
                                     struct simnet *right,
                                     struct uint256 *left_fund,
                                     bool *left_funded)
{
    int failures = 0;
    /* 9. Minimal multi-node slice: copy an accepted block marker through
     *    tools/sim/sim_peer, replay the same accepted tx into a second
     *    RAM-only simnet, and assert both nodes converge to the same tip. */
    bool left_init = simnet_init(left);
    bool right_init = simnet_init(right);
    SN_CHECK("multi-node simnets initialize", left_init && right_init);

    struct uint256 left_cb;
    struct uint256 right_cb;
    uint256_set_null(&left_cb);
    uint256_set_null(&right_cb);
    bool left_cb_minted = left_init && simnet_mint_coinbase(left, &left_cb);
    bool right_cb_minted = right_init && simnet_mint_coinbase(right, &right_cb);
    SN_CHECK("multi-node matching coinbases mint",
             left_cb_minted && right_cb_minted &&
             uint256_cmp(&left_cb, &right_cb) == 0);

    struct uint256 right_fund;
    uint256_set_null(left_fund);
    uint256_set_null(&right_fund);
    *left_funded =
        left_cb_minted && simnet_spend(left, &left_cb, 0, 850000,
                                       left_fund);
    bool right_funded =
        right_cb_minted && simnet_spend(right, &right_cb, 0, 850000,
                                        &right_fund);
    SN_CHECK("multi-node matching funding txs mint",
             *left_funded && right_funded &&
             uint256_cmp(left_fund, &right_fund) == 0);
    return failures;
}

static int sim_test_peer_block_copy(struct simnet *left,
                                    struct simnet *right,
                                    struct uint256 *left_fund,
                                    bool left_funded,
                                    struct uint256 *peer_txid,
                                    struct transaction *right_peer_tx,
                                    bool *left_accepted,
                                    bool *right_accepted,
                                    char (*peer_dir)[256])
{
    int failures = 0;
    struct transaction left_peer_tx;
    transaction_init(right_peer_tx);
    uint8_t peer_opret[] = {0x6a, 0x05, 'P', 'E', 'E', 'R', '1'};
    bool built_peer_tx =
        left_funded &&
        sim_test_make_opreturn_spend(&left_peer_tx, left_fund, 0,
                                     peer_opret, sizeof(peer_opret),
                                     800000, 0x31);
    bool copied_peer_tx =
        built_peer_tx && transaction_copy(right_peer_tx, &left_peer_tx);
    *peer_txid = built_peer_tx ? left_peer_tx.hash : (struct uint256){0};
    SN_CHECK("build peer-copied tx", built_peer_tx && copied_peer_tx);

    *left_accepted =
        built_peer_tx && simnet_mint_txs(left, &left_peer_tx, 1);
    SN_CHECK("left node accepts peer block tx", *left_accepted);

    char peer_block_path[320];
    test_make_tmpdir(*peer_dir, sizeof(*peer_dir), "simnet", "peer");
    snprintf(peer_block_path, sizeof(peer_block_path),
             "%s/accepted-block.bin", *peer_dir);
    struct uint256 left_tip_marker;
    bool wrote_peer_block =
        *left_accepted && simnet_tip_hash(left, &left_tip_marker) &&
        sim_test_write_peer_block_file(peer_block_path, &left_tip_marker);
    SN_CHECK("write accepted block marker for sim_peer", wrote_peer_block);

    struct sim_peer_set peers;
    sim_peer_set_init(&peers);
    size_t peer_bytes = 0;
    int peer_resize_rc = sim_peer_set_resize(&peers, 2);
    int peer_send_rc =
        wrote_peer_block ? sim_peer_send_block(&peers, 1, peer_block_path,
                                               &peer_bytes) : -1;
    const struct sim_peer *peer_one = sim_peer_get(&peers, 1);
    SN_CHECK("sim_peer copies accepted block marker to second node",
             peer_resize_rc == 0 && peer_send_rc == 0 && peer_one &&
             peer_one->blocks_sent == 1 && peer_bytes == 32);

    *right_accepted =
        peer_send_rc == 0 && copied_peer_tx &&
        simnet_mint_txs(right, right_peer_tx, 1);
    SN_CHECK("right node accepts copied peer block tx", *right_accepted);
    return failures;
}

static int sim_test_peer_block_converge(struct simnet *left,
                                        struct simnet *right,
                                        bool left_accepted,
                                        bool right_accepted,
                                        struct uint256 *peer_txid,
                                        struct transaction *right_peer_tx,
                                        char (*peer_dir)[256])
{
    int failures = 0;
    struct uint256 left_tip;
    struct uint256 right_tip;
    bool tips_read =
        left_accepted && right_accepted &&
        simnet_tip_hash(left, &left_tip) &&
        simnet_tip_hash(right, &right_tip);
    SN_CHECK("multi-node simnets converge to the same tip",
             tips_read &&
             simnet_tip_height(left) == simnet_tip_height(right) &&
             uint256_cmp(&left_tip, &right_tip) == 0 &&
             simnet_coin_exists(left, peer_txid) &&
             simnet_coin_exists(right, peer_txid));

    if (!right_accepted)
        transaction_free(right_peer_tx);
    test_cleanup_tmpdir(*peer_dir);
    simnet_free(left);
    simnet_free(right);
    return failures;
}

static int sim_test_negative_spend(struct simnet *sim)
{
    int failures = 0;
    /* 9. Negative path: spending an absent coin fails cleanly (no crash). */
    struct uint256 bogus;
    memset(bogus.data, 0xAB, 32);
    struct uint256 unused;
    SN_CHECK("spending an absent coin is rejected",
             !simnet_spend(sim, &bogus, 0, 1, &unused));
    return failures;
}

int test_simnet(void)
{
    printf("\n=== simnet in-memory chain harness ===\n");
    int failures = 0;
    failures += ivr_capture_owned();
    failures += ivr_capture_refusal();
    failures += ivr_capture_invalid_output();

    struct simnet sim;
    struct uint256 custom_txid;
    failures += sim_test_coinbase_spend_custom(&sim, &custom_txid);

    struct simnet action_sim;
    struct uint256 action_fund0;
    struct uint256 action_fund1;
    bool action_funded1;
    failures += sim_test_action_inputs(&action_sim, &action_fund0,
                                       &action_fund1, &action_funded1);
    struct transaction multi_action_projection;
    bool minted_multi_action;
    failures += sim_test_action_multi_tx(&action_sim, &action_fund0,
                                         &action_fund1, action_funded1,
                                         &multi_action_projection,
                                         &minted_multi_action);
    failures += sim_test_action_explorer(&action_sim,
                                         &multi_action_projection,
                                         minted_multi_action);

    struct node_db zslp_db;
    bool zslp_open;
    struct uint256 slp_token_id;
    char slp_token_hex[65];
    struct transaction slp_genesis_projection;
    struct uint256 slp_wire_token_id;
    struct uint256 slp_send_txid;
    struct transaction slp_send_projection;
    struct uint256 slp_mint_txid;
    struct transaction slp_mint_projection;
    bool minted_slp_mint;
    struct uint256 slp_burn_txid;
    struct transaction slp_burn_projection;
    bool applied_slp_burn;
    struct transaction slp_malformed_projection;
    failures += sim_test_slp_genesis(&sim, &custom_txid, &zslp_db, &zslp_open,
                                     &slp_token_id, slp_token_hex,
                                     &slp_genesis_projection);
    failures += sim_test_slp_send(&sim, &zslp_db, zslp_open, &slp_token_id,
                                  slp_token_hex, &slp_wire_token_id,
                                  &slp_send_txid, &slp_send_projection);
    failures += sim_test_slp_mint(&sim, &zslp_db, zslp_open, &slp_token_id,
                                  slp_token_hex, &slp_wire_token_id,
                                  &slp_mint_txid, &slp_mint_projection,
                                  &minted_slp_mint);
    failures += sim_test_slp_burn(&sim, &zslp_db, zslp_open,
                                  &slp_wire_token_id, &slp_send_txid,
                                  &slp_burn_txid, &slp_burn_projection,
                                  &applied_slp_burn);
    failures += sim_test_slp_burn_supply(&zslp_db, &slp_token_id,
                                         &slp_burn_txid, &slp_mint_txid,
                                         applied_slp_burn);
    failures += sim_test_slp_malformed(&sim, &zslp_db, zslp_open,
                                       &slp_wire_token_id, &slp_mint_txid,
                                       &slp_malformed_projection,
                                       minted_slp_mint, slp_token_hex);
    transaction_free(&slp_genesis_projection);
    transaction_free(&slp_send_projection);
    transaction_free(&slp_mint_projection);
    transaction_free(&slp_burn_projection);
    transaction_free(&slp_malformed_projection);
    if (zslp_open)
        node_db_close(&zslp_db);

    struct node_db znam_db;
    bool znam_open;
    struct uint256 znam_owner_fund_txid;
    struct transaction znam_owner_fund_projection;
    struct uint256 znam_register_txid;
    struct transaction znam_register_projection;
    char znam_owner_before_transfer[64];
    struct transaction znam_bad_update_projection;
    struct uint256 znam_update_txid;
    struct transaction znam_update_projection;
    struct uint256 znam_record_txid;
    struct transaction znam_record_projection;
    struct uint256 znam_text_txid;
    struct transaction znam_text_projection;
    struct uint256 znam_renew_txid;
    struct transaction znam_renew_projection;
    struct uint256 znam_transfer_txid;
    struct transaction znam_transfer_projection;
    struct uint256 znam_malformed_txid;
    struct transaction znam_malformed_projection;
    struct transaction blog_anchor_projection;
    failures += sim_test_znam_owner_fund(&sim, &slp_burn_txid, &znam_db,
                                         &znam_open, &znam_owner_fund_txid,
                                         &znam_owner_fund_projection);
    failures += sim_test_znam_register(&sim, &znam_db, znam_open,
                                       &znam_owner_fund_txid,
                                       &znam_register_txid,
                                       &znam_register_projection,
                                       &znam_owner_before_transfer);
    failures += sim_test_znam_bad_update(&sim, &znam_db, znam_open,
                                         &znam_register_txid,
                                         &znam_bad_update_projection,
                                         &znam_owner_before_transfer);
    failures += sim_test_znam_owner_update(&sim, &znam_db, znam_open,
                                           &znam_owner_fund_txid,
                                           &znam_update_txid,
                                           &znam_update_projection,
                                           &znam_owner_before_transfer);
    failures += sim_test_znam_bad_record(&sim, &znam_db, znam_open,
                                         &znam_update_txid);
    failures += sim_test_znam_record(&sim, &znam_db, znam_open,
                                     &znam_update_txid, &znam_record_txid,
                                     &znam_record_projection);
    failures += sim_test_znam_bad_text(&sim, &znam_db, znam_open,
                                       &znam_update_txid);
    failures += sim_test_znam_text(&sim, &znam_db, znam_open,
                                   &znam_record_txid, &znam_text_txid,
                                   &znam_text_projection);
    failures += sim_test_znam_renew(&sim, &znam_db, znam_open,
                                    &znam_text_txid, &znam_renew_txid,
                                    &znam_renew_projection,
                                    &znam_owner_before_transfer);
    failures += sim_test_znam_transfer(&sim, &znam_db, znam_open,
                                       &znam_renew_txid, &znam_transfer_txid,
                                       &znam_transfer_projection);
    failures += sim_test_znam_malformed(&sim, &znam_db, znam_open,
                                        &znam_transfer_txid,
                                        &znam_malformed_txid,
                                        &znam_malformed_projection);
    failures += sim_test_zblg_anchor(&sim, &znam_db, znam_open,
                                     &znam_malformed_txid,
                                     &blog_anchor_projection);
    transaction_free(&znam_owner_fund_projection);
    transaction_free(&znam_register_projection);
    transaction_free(&znam_bad_update_projection);
    transaction_free(&znam_update_projection);
    transaction_free(&znam_record_projection);
    transaction_free(&znam_text_projection);
    transaction_free(&znam_renew_projection);
    transaction_free(&znam_transfer_projection);
    transaction_free(&znam_malformed_projection);
    transaction_free(&blog_anchor_projection);
    if (znam_open)
        node_db_close(&znam_db);

    struct simnet left;
    struct simnet right;
    struct uint256 left_fund;
    bool left_funded;
    failures += sim_test_multi_node_setup(&left, &right, &left_fund,
                                          &left_funded);
    struct uint256 peer_txid;
    struct transaction right_peer_tx;
    bool left_accepted;
    bool right_accepted;
    char peer_dir[256];
    failures += sim_test_peer_block_copy(&left, &right, &left_fund,
                                         left_funded, &peer_txid,
                                         &right_peer_tx, &left_accepted,
                                         &right_accepted, &peer_dir);
    failures += sim_test_peer_block_converge(&left, &right, left_accepted,
                                             right_accepted, &peer_txid,
                                             &right_peer_tx, &peer_dir);
    failures += sim_test_negative_spend(&sim);

    simnet_free(&sim);
    return failures;
}
