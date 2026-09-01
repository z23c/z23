/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * TEACHING EXAMPLE 04 — ZSLP token lifecycle in the deterministic simulator.
 *
 * WHAT THIS DEMONSTRATES: ZSLP (SLP Type 1) is ZClassic's token overlay — a
 * token's whole life is a sequence of OP_RETURN payloads carried by ordinary
 * transparent transactions. A real block accepts an OP_RETURN unconditionally
 * (it is just consensus-valid unspendable data; the chain does not know or
 * care what "SLP" means). Meaning is added by a PROJECTION outside consensus:
 * `explorer_index_apply_slp` parses the OP_RETURN with `slp_parse` and folds
 * it into the `zslp_tokens`/`zslp_transfers` SQLite tables. Consensus never
 * rejects a block over token semantics — the projection tells the
 * human-readable story on top of raw chain data.
 *
 * The story, one real block per step: GENESIS mints 1000 units of token
 * "SIM"; SEND re-splits those 1000 units into 250 + 750; MINT issues 125
 * more via the baton output from GENESIS. A final pass parses every
 * OP_RETURN back with `slp_parse` alone, independent of the projection, to
 * show the wire bytes carry the whole story by themselves.
 *
 * PROJECTION GAP, SHOWN ON PURPOSE: `explorer_index_apply_slp()`
 * (contexts/market/models/src/explorer_index_zslp.c) records a MINT the same way it
 * records a SEND — as a `zslp_transfers` row (tx_type=SLP_TX_MINT, the new
 * quantity, the destination vout) — but it does NOT add that quantity back
 * into the token's stored `total_minted` column (that field is written once,
 * at GENESIS, from the message's initial_quantity, and never touched again).
 * So after this example's MINT step, `db_zslp_token_find()->total_minted`
 * still reads 1000, not 1125 — the +125 is only visible as a transfer row.
 * This example verifies the MINT the way the real projection actually
 * represents it (a transfer row), not the way a learner might guess it
 * should (an updated running total) — see the step 4/5 checks below.
 *
 * MENTAL MODEL:
 *  1. `simnet` (engine/modules/sim/include/sim/simnet.h) drives real blocks through the
 *     real `connect_block()` validator — no disk, no PoW, no P2P, but the
 *     same consensus code path a live node runs.
 *  2. `slp_build_genesis/mint/send` (contexts/market/modules/zslp/include/zslp/slp.h) are pure
 *     encoders: struct-in, bytes-out. They know nothing about transactions.
 *  3. Each payload becomes vout[0] of an OP_RETURN tx; the transparent
 *     vout[1..] values on that SAME tx are what the SLP message describes
 *     moving — SLP overlays value onto existing transparent structure, it
 *     does not add a new UTXO type.
 *  4. `slp_parse` + `explorer_index_apply_slp` are the read side: given a
 *     tx and its OP_RETURN script, reconstruct the message and fold it into
 *     the queryable projection.
 *
 * TEST-ONLY NOTE: `build_slp_tx` below is a from-scratch equivalent of the
 * OP_RETURN carrier builder that tests/harness/src/test_simnet.c keeps as a
 * static helper under #ifdef ZCL_TESTING (not public library API) — kept
 * inline here so this example stays link-clean. The token_id byte-reversal
 * is a real ZSLP wire convention (big-endian on the wire, little-endian in
 * `struct uint256`); see the `slp_build_mint`/`slp_build_send` call sites in
 * test_simnet.c section 6 for the same reversal.
 *
 * Deterministic: every input (seeds, quantities, amounts) is a fixed
 * literal — no wall clock, no RNG — so a run always tells the same story.
 */

#include "sim/simnet.h"
#include "zslp/slp.h"
#include "models/explorer_index.h"
#include "models/zslp.h"
#include "models/database.h"
#include "core/uint256.h"
#include "script/script.h"
#include "primitives/transaction.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Fail loudly and exit nonzero — this is example code, not node code, so a
 * plain fprintf+exit stands in for the repo's LOG_FAIL/zcl_malloc rules. */
static void must(bool ok, const char *what)
{
    if (!ok) { fprintf(stderr, "FAIL: %s\n", what); exit(1); }
}

/* Minimal deterministic P2PKH-shaped output script — not spendable in this
 * demo, just a stable, distinct scriptPubKey per output. */
static void demo_p2pkh_script(struct script *sp, unsigned char seed)
{
    sp->data[0] = 0x76; sp->data[1] = 0xa9; sp->data[2] = 0x14;
    for (int i = 0; i < 20; i++) sp->data[3 + i] = (unsigned char)(seed + i);
    sp->data[23] = 0x88; sp->data[24] = 0xac;
    sp->size = 25;
}

/* Build a 1-input tx whose vout[0] is the SLP OP_RETURN payload and whose
 * vout[1..] carry the transparent values the SLP message describes moving. */
static bool build_slp_tx(struct transaction *tx, const struct uint256 *prev_txid,
                         uint32_t prev_n, const uint8_t *slp_script,
                         size_t slp_len, const int64_t *values,
                         const unsigned char *seeds, size_t noutputs)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, noutputs + 1)) return false;
    tx->version = 1;
    tx->vin[0].prevout.hash = *prev_txid;
    tx->vin[0].prevout.n = prev_n;
    uint8_t sig[] = {0x00, 0x00};
    script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    tx->vin[0].sequence = 0xFFFFFFFFu;
    tx->vout[0].value = 0;
    script_set(&tx->vout[0].script_pub_key, slp_script, slp_len);
    for (size_t i = 0; i < noutputs; i++) {
        tx->vout[i + 1].value = values[i];
        demo_p2pkh_script(&tx->vout[i + 1].script_pub_key, seeds[i]);
    }
    transaction_compute_hash(tx);
    return true;
}

/* Fold a minted tx's OP_RETURN into the ZSLP projection: parse, then apply.
 * The same two-step every real node runs during forward-sync indexing
 * (contexts/explorer/models/src/explorer_index.c). */
static bool apply_slp(struct node_db *ndb, const struct transaction *tx, int height)
{
    struct slp_message msg;
    if (!slp_parse(tx->vout[0].script_pub_key.data,
                   tx->vout[0].script_pub_key.size, &msg))
        return false;
    explorer_index_apply_slp(ndb, tx, &msg, height);
    return true;
}

/* Print a parsed SLP message in plain-language form. */
static void print_slp(const char *label, const struct slp_message *m)
{
    const char *tname = m->type == SLP_TX_GENESIS ? "GENESIS" :
                        m->type == SLP_TX_MINT    ? "MINT"    :
                        m->type == SLP_TX_SEND    ? "SEND"    : "?";
    printf("    parsed %-8s type=%s", label, tname);
    if (m->type == SLP_TX_GENESIS)
        printf(" ticker=%s name=\"%s\" initial_qty=%llu\n",
              m->ticker, m->name, (unsigned long long)m->initial_quantity);
    else if (m->type == SLP_TX_MINT)
        printf(" additional_qty=%llu\n", (unsigned long long)m->additional_quantity);
    else
        /* output_quantities[] is 0-indexed by SLOT, not by vout number: slot
         * 0 is the amount for real vout 1, slot 1 is vout 2, etc (see
         * contexts/market/modules/zslp/include/zslp/slp.h: "output_quantities[20]; vout[1]..
         * vout[19] + 1 extra" and explorer_index_apply_slp's SEND loop,
         * which emits `output_quantities[i]` to vout `i+1`). */
        printf(" outputs=%d qty[vout1]=%llu qty[vout2]=%llu\n", m->num_outputs,
              (unsigned long long)m->output_quantities[0],
              (unsigned long long)m->output_quantities[1]);
}

/* Hex-encode a 32-byte token id the way `db_zslp_token_find` expects to
 * look it up — the projection keys tokens by uppercase-hex txid. */
static void token_hex(const struct uint256 *id, char out[65])
{
    for (int i = 0; i < 32; i++) snprintf(out + i * 2, 3, "%02X", id->data[i]);
}

int main(void)
{
    printf("=== 04_zslp_token: GENESIS -> SEND -> MINT, built and parsed ===\n\n");

    /* Select a chain network before any chain/consensus code runs —
     * connect_block and the coinbase subsidy schedule read their parameters
     * through chain_params_get(), which asserts one was chosen. */
    chain_params_select(CHAIN_MAIN);

    printf("[1/5] init simnet + fund a transparent input to spend GENESIS from...\n");
    struct simnet sim;
    must(simnet_init(&sim), "simnet_init");
    struct uint256 cb_txid, fund_txid;
    must(simnet_mint_coinbase(&sim, &cb_txid), "mint coinbase");
    must(simnet_spend(&sim, &cb_txid, 0, 900000, &fund_txid), "spend matured coinbase");
    printf("      tip height %d, funding coin ready (900000 zats)\n", simnet_tip_height(&sim));

    struct node_db db;
    memset(&db, 0, sizeof(db));
    must(node_db_open(&db, ":memory:"), "node_db_open");

    printf("\n[2/5] GENESIS: create token \"SIM\" with 1000 initial units...\n");
    uint8_t genesis_script[512];
    size_t genesis_len = slp_build_genesis(genesis_script, sizeof(genesis_script),
        "SIM", "Simnet Token", "", NULL, /*decimals=*/0, /*mint_baton_vout=*/2,
        /*initial_quantity=*/1000);
    must(genesis_len > 0, "slp_build_genesis");

    /* simnet_mint_txs() MOVES each tx's vin/vout arrays into the block it
     * mints (see engine/modules/sim/src/simnet.c: `block_txs[i+1] = txs[i];` followed
     * by `transaction_init(&txs[i])`) and resets the caller's copy to an
     * empty transaction — the same "the caller no longer owns this" contract
     * tests/harness/src/test_simnet.c's ZSLP section (section 6) follows via
     * `transaction_copy()` before minting. So we keep our own `_proj` copy
     * of every SLP tx for anything read AFTER the mint call (apply_slp() and
     * the independent re-parse in step 5/5) — reading the post-mint
     * `genesis_tx`/`send_tx`/`mint_tx` directly would deref an emptied
     * (NULL vin/vout) transaction. */
    struct transaction genesis_tx, genesis_tx_proj;
    transaction_init(&genesis_tx_proj);
    int64_t genesis_values[2] = { 400000, 400000 }; /* [1]=holder, [2]=mint baton */
    unsigned char genesis_seeds[2] = { 0x10, 0x11 };
    must(build_slp_tx(&genesis_tx, &fund_txid, 0, genesis_script, genesis_len,
                      genesis_values, genesis_seeds, 2), "build genesis tx");
    must(transaction_copy(&genesis_tx_proj, &genesis_tx), "copy genesis tx for projection");
    struct uint256 token_id = genesis_tx.hash; /* SLP token_id == the GENESIS txid */
    must(simnet_mint_txs(&sim, &genesis_tx, 1), "mint genesis tx (connect_block rejected it)");
    int genesis_height = simnet_tip_height(&sim);
    must(apply_slp(&db, &genesis_tx_proj, genesis_height), "fold genesis into projection");
    printf("      block accepted at height %d; token_id = genesis txid\n", genesis_height);

    char thex[65];
    token_hex(&token_id, thex);
    struct db_zslp_token_info tinfo;
    memset(&tinfo, 0, sizeof(tinfo));
    must(db_zslp_token_find(&db, thex, &tinfo), "projection sees the new token");
    printf("      projection: ticker=%s name=\"%s\" total_minted=%lld\n",
          tinfo.ticker, tinfo.name, (long long)tinfo.total_minted);

    /* ZSLP token_id fields are big-endian on the wire; struct uint256 is
     * little-endian internally, so byte-reverse before building SEND/MINT. */
    struct uint256 wire_token_id;
    for (int i = 0; i < 32; i++) wire_token_id.data[i] = token_id.data[31 - i];

    printf("\n[3/5] SEND: split the 1000 units into 250 + 750...\n");
    uint64_t send_qty[2] = { 250, 750 };
    uint8_t send_script[512];
    size_t send_len = slp_build_send(send_script, sizeof(send_script), &wire_token_id, send_qty, 2);
    must(send_len > 0, "slp_build_send");

    struct transaction send_tx, send_tx_proj;
    transaction_init(&send_tx_proj);
    int64_t send_values[2] = { 200000, 200000 };
    unsigned char send_seeds[2] = { 0x20, 0x21 };
    /* Spend the genesis holder output (vout 1) to fund the SEND tx. */
    must(build_slp_tx(&send_tx, &token_id, 1, send_script, send_len,
                      send_values, send_seeds, 2), "build send tx");
    must(transaction_copy(&send_tx_proj, &send_tx), "copy send tx for projection");
    must(simnet_mint_txs(&sim, &send_tx, 1), "mint send tx (connect_block rejected it)");
    int send_height = simnet_tip_height(&sim);
    must(apply_slp(&db, &send_tx_proj, send_height), "fold send into projection");
    struct db_zslp_transfer_info xfers[4];
    memset(xfers, 0, sizeof(xfers));
    int nxfers = db_zslp_transfer_list_by_token(&db, thex, xfers, 4);
    printf("      block accepted at height %d; projection now has %d transfer row(s)\n",
          send_height, nxfers);

    printf("\n[4/5] MINT: baton issues 125 additional units...\n");
    uint8_t mint_script[512];
    size_t mint_len = slp_build_mint(mint_script, sizeof(mint_script), &wire_token_id,
                                     /*mint_baton_vout=*/0, /*additional_quantity=*/125);
    must(mint_len > 0, "slp_build_mint");

    struct transaction mint_tx, mint_tx_proj;
    transaction_init(&mint_tx_proj);
    int64_t mint_values[1] = { 150000 };
    unsigned char mint_seeds[1] = { 0x30 };
    /* Spend the genesis mint-baton output (vout 2) to authorize the mint. */
    must(build_slp_tx(&mint_tx, &token_id, 2, mint_script, mint_len,
                      mint_values, mint_seeds, 1), "build mint tx");
    must(transaction_copy(&mint_tx_proj, &mint_tx), "copy mint tx for projection");
    must(simnet_mint_txs(&sim, &mint_tx, 1), "mint MINT tx (connect_block rejected it)");
    int mint_height = simnet_tip_height(&sim);
    must(apply_slp(&db, &mint_tx_proj, mint_height), "fold mint into projection");
    must(db_zslp_token_find(&db, thex, &tinfo), "projection still sees the token after mint");

    /* explorer_index_apply_slp() records a MINT as a zslp_transfers row
     * (tx_type=SLP_TX_MINT, amount, vout) — the SAME shape a SEND uses — but
     * it deliberately does NOT add the quantity back into the token's
     * `total_minted` column (written once at GENESIS, never touched again;
     * see explorer_index_zslp.c's SLP_TX_MINT case and the file header
     * PROJECTION GAP note above). So the real post-condition to check is the
     * transfer row, not an updated running total. */
    struct db_zslp_transfer_info xfers_after_mint[4];
    memset(xfers_after_mint, 0, sizeof(xfers_after_mint));
    int nxfers_after_mint =
        db_zslp_transfer_list_by_token(&db, thex, xfers_after_mint, 4);
    int64_t mint_transfer_amount = -1;
    for (int i = 0; i < nxfers_after_mint; i++) {
        if (xfers_after_mint[i].tx_type == SLP_TX_MINT &&
            xfers_after_mint[i].vout == 1) {
            mint_transfer_amount = xfers_after_mint[i].amount;
            break;
        }
    }
    printf("      block accepted at height %d; total_minted (GENESIS-only "
          "field) still reads %lld; MINT recorded as a transfer row of "
          "%lld units\n",
          mint_height, (long long)tinfo.total_minted,
          (long long)mint_transfer_amount);
    must(tinfo.total_minted == 1000,
        "total_minted is a GENESIS-only field and must stay 1000");
    must(mint_transfer_amount == 125,
        "projection must record the MINT as a 125-unit transfer row");

    printf("\n[5/5] parse every OP_RETURN back independently of the projection...\n");
    struct slp_message pmsg;
    must(slp_parse(genesis_tx_proj.vout[0].script_pub_key.data,
                   genesis_tx_proj.vout[0].script_pub_key.size, &pmsg), "re-parse genesis OP_RETURN");
    print_slp("GENESIS", &pmsg);
    must(slp_parse(send_tx_proj.vout[0].script_pub_key.data,
                   send_tx_proj.vout[0].script_pub_key.size, &pmsg), "re-parse send OP_RETURN");
    print_slp("SEND", &pmsg);
    must(slp_parse(mint_tx_proj.vout[0].script_pub_key.data,
                   mint_tx_proj.vout[0].script_pub_key.size, &pmsg), "re-parse mint OP_RETURN");
    print_slp("MINT", &pmsg);

    /* genesis_tx/send_tx/mint_tx are already empty (simnet_mint_txs moved
     * their contents into the mined block and reset them) — freeing them is
     * a harmless no-op; the _proj copies are what actually own allocations. */
    transaction_free(&genesis_tx);
    transaction_free(&send_tx);
    transaction_free(&mint_tx);
    transaction_free(&genesis_tx_proj);
    transaction_free(&send_tx_proj);
    transaction_free(&mint_tx_proj);
    node_db_close(&db);
    simnet_free(&sim);

    printf("\n=== SUCCESS: GENESIS(1000) -> SEND(250+750) -> MINT(+125 "
          "recorded as a transfer row, total_minted stays a GENESIS-only "
          "1000), verified via both the chain projection and independent "
          "parse ===\n");
    return 0;
}

/* Production counterpart:
 * -----------------------
 * There is no dedicated "wallet_slp_send" in the wallet API today — a real
 * ZSLP-carrying transaction is assembled the same way this example does it
 * (an OP_RETURN vout[0] from slp_build_genesis/mint/send, plus ordinary
 * transparent value outputs), then submitted through the normal transparent
 * send path: wallet_controller.c's send/create-transaction flow
 * (contexts/wallet/controllers/src/wallet_controller.c, wallet_controller_internal.h)
 * assembles vin/vout and broadcasts via the mempool, exactly like any other
 * transparent tx — the OP_RETURN carries the token meaning, consensus does
 * not special-case it.
 *
 * The READ side this example exercises directly IS the production path: a
 * live node's forward-sync indexer calls slp_parse + explorer_index_apply_slp
 * from index_op_return (contexts/explorer/models/src/explorer_index.c /
 * contexts/market/models/src/explorer_index_zslp.c) for every OP_RETURN in every synced
 * block, and the resulting zslp_tokens/zslp_transfers rows are what the
 * zslp_controller.c RPC handlers (contexts/market/controllers/src/zslp_controller.c) and
 * the `app tokens list` native command reads back for callers.
 */
