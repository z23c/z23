/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Reusable isolated-chain proof fixture for production OP_RETURN builders. */

#include "test/transaction_lab_simnet.h"

#include "chain/chain.h"
#include "models/database.h"
#include "models/explorer_index.h"
#include "sim/simnet.h"
#include "validation/main_constants.h"

#include <string.h>

#define TXLAB_FUND_ZAT   900000LL
#define TXLAB_CHANGE_ZAT 800000LL

static void transaction_lab_p2pkh_script(
    struct script *script, const uint8_t owner_hash160[20])
{
    static const uint8_t prefix[] = {0x76, 0xa9, 0x14};
    static const uint8_t suffix[] = {0x88, 0xac};
    memset(script, 0, sizeof(*script));
    memcpy(script->data, prefix, sizeof(prefix));
    memcpy(script->data + sizeof(prefix), owner_hash160, 20);
    memcpy(script->data + sizeof(prefix) + 20, suffix, sizeof(suffix));
    script->size = sizeof(prefix) + 20 + sizeof(suffix);
}

static bool transaction_lab_build_op_return(
    struct transaction *tx, const struct uint256 *funding_txid,
    const uint8_t *op_return, size_t op_return_len,
    const uint8_t owner_hash160[20])
{
    transaction_init(tx);
    if (!funding_txid || !op_return || op_return_len == 0 ||
        op_return_len > MAX_SCRIPT_SIZE ||
        !transaction_alloc(tx, 1, 2))
        return false;
    tx->version = 1;
    tx->vin[0].prevout.hash = *funding_txid;
    tx->vin[0].prevout.n = 0;
    {
        static const uint8_t placeholder_sig[] = {0x00, 0x00};
        script_set(&tx->vin[0].script_sig, placeholder_sig,
                   sizeof(placeholder_sig));
    }
    tx->vin[0].sequence = UINT32_MAX;
    tx->vout[0].value = 0;
    script_set(&tx->vout[0].script_pub_key, op_return, op_return_len);
    tx->vout[1].value = TXLAB_CHANGE_ZAT;
    transaction_lab_p2pkh_script(&tx->vout[1].script_pub_key,
                                 owner_hash160);
    transaction_compute_hash(tx);
    return true;
}

bool transaction_lab_simnet_mine_op_return(
    const uint8_t *op_return, size_t op_return_len,
    struct transaction_lab_simnet_receipt *out)
{
    uint8_t owner_hash160[20];
    for (size_t i = 0; i < sizeof(owner_hash160); i++)
        owner_hash160[i] = (uint8_t)(0x40u + i);
    return transaction_lab_simnet_mine_owned_op_return_at(
        op_return, op_return_len, owner_hash160, 201, out);
}

bool transaction_lab_simnet_mine_owned_op_return_at(
    const uint8_t *op_return, size_t op_return_len,
    const uint8_t owner_hash160[20], int32_t target_height,
    struct transaction_lab_simnet_receipt *out)
{
    if (!op_return || op_return_len == 0 || !owner_hash160 || !out ||
        target_height <= COINBASE_MATURITY)
        return false;
    memset(out, 0, sizeof(*out));
    transaction_init(&out->transaction);

    struct simnet sim;
    if (!simnet_init(&sim))
        return false;
    struct uint256 funding_txid;
    uint256_set_null(&funding_txid);
    struct script funding_script;
    transaction_lab_p2pkh_script(&funding_script, owner_hash160);
    int32_t funding_target = target_height - COINBASE_MATURITY;
    bool ready = funding_target > simnet_tip_height(&sim) &&
        simnet_mint_to_height(&sim, funding_target - 1) &&
        simnet_mint_coinbase_to(
            &sim, &funding_script, TXLAB_FUND_ZAT, &funding_txid);
    int32_t funding_height = simnet_tip_height(&sim);
    ready = ready && target_height >= funding_height + COINBASE_MATURITY &&
        simnet_mint_to_height(&sim, target_height - 1);

    struct transaction tx;
    transaction_init(&tx);
    bool built = ready && transaction_lab_build_op_return(
        &tx, &funding_txid, op_return, op_return_len, owner_hash160);
    bool copied = built && transaction_copy(&out->transaction, &tx);
    if (built && !copied)
        transaction_free(&tx);
    struct uint256 txid = built ? tx.hash : (struct uint256){0};
    bool mined = copied && simnet_mint_txs(&sim, &tx, 1);
    int64_t change = 0;
    bool proved = mined && !simnet_coin_exists(&sim, &funding_txid) &&
        simnet_coin_value(&sim, &txid, 1, &change) &&
        change == TXLAB_CHANGE_ZAT;
    if (proved) {
        out->txid = txid;
        out->funding_txid = funding_txid;
        memcpy(out->owner_hash160, owner_hash160,
               sizeof(out->owner_hash160));
        out->funding_height = funding_height;
        out->mined_height = simnet_tip_height(&sim);
        out->change_zat = change;
    } else {
        transaction_free(&out->transaction);
        transaction_init(&out->transaction);
    }
    simnet_free(&sim);
    return proved;
}

bool transaction_lab_simnet_project(
    struct node_db *ndb,
    const struct transaction_lab_simnet_receipt *receipt)
{
    if (!ndb || !ndb->open || !receipt || receipt->mined_height < 0 ||
        receipt->funding_height < 0 || receipt->transaction.num_vout < 2)
        return false;
    if (!db_tx_output_save(ndb, receipt->funding_txid.data, 0,
                           TXLAB_FUND_ZAT, 0, receipt->owner_hash160,
                           receipt->funding_height))
        return false;
    struct block block;
    block_init(&block);
    block.vtx = (struct transaction *)&receipt->transaction;
    block.num_vtx = 1;
    struct uint256 block_hash = receipt->txid;
    block_hash.data[0] ^= 0xa5u;
    struct block_index index;
    block_index_init(&index);
    index.nHeight = receipt->mined_height;
    index.phashBlock = &block_hash;
    uint8_t previous_receipt[32] = {0};
    uint8_t projected_receipt[32];
    bool ok = explorer_index_block(ndb, &block, &index, previous_receipt,
                                   projected_receipt, NULL, NULL);
    block.vtx = NULL;
    block.num_vtx = 0;
    return ok;
}

void transaction_lab_simnet_receipt_free(
    struct transaction_lab_simnet_receipt *receipt)
{
    if (!receipt)
        return;
    transaction_free(&receipt->transaction);
    memset(receipt, 0, sizeof(*receipt));
}
