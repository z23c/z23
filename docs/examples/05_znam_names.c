/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * TEACHING EXAMPLE 05 — ZNAM (ZCL Names) registry lifecycle in the
 * deterministic simulator.
 *
 * WHAT THIS DEMONSTRATES
 * -----------------------
 * ZNAM is ZClassic's ENS-inspired on-chain name registry: an OP_RETURN
 * payload with lokad ID "ZNAM" (contexts/naming/modules/znam/include/znam/znam.h), carried by an
 * ordinary transparent transaction. Consensus does not know what "ZNAM"
 * means — an OP_RETURN output is just unspendable data, so the block is
 * accepted unconditionally. All the meaning — ownership, first-come-first-
 * served registration, and per-command authorization — is added by a
 * projection: `explorer_index_block` -> `apply_znam`
 * (contexts/explorer/models/src/explorer_index.c) parses the OP_RETURN with `znam_parse`
 * and folds it into the `znam_names` / `znam_text_records` /
 * `znam_addr_records` SQLite tables.
 *
 * The story this file builds, one real block per step:
 *   fund     — mature a coinbase, split it into two owner-distinct P2PKH
 *              coins: one for "alice" (the eventual name owner) and one for
 *              "mallory" (an unrelated wallet that never registered anything).
 *   REGISTER — alice claims the name "alice-home" pointing at a t-address.
 *   UPDATE   — alice (the real owner) repoints the name at a new target.
 *   SET_TEXT — alice attaches an "email" text record (ENS TextResolver
 *              equivalent).
 *   NEGATIVE — mallory spends HER OWN coin (never alice's) to post a
 *              well-formed UPDATE for "alice-home". `znam_parse` decodes it
 *              fine — the wire bytes are valid ZNAM — but `apply_znam`'s
 *              owner check derives the spending tx's authorizing address
 *              from mallory's input, sees it does not match the registered
 *              owner, and silently discards the mutation. The name's target
 *              is unchanged after the block folds.
 *
 * MENTAL MODEL
 * ------------
 * 1. `simnet` (engine/modules/sim/include/sim/simnet.h) drives real blocks through the
 *    real `connect_block()` validator — no disk, no PoW, no P2P, but the
 *    same consensus code path a live node runs.
 * 2. `znam_build_register` / `znam_build_update` / `znam_build_set_text`
 *    (contexts/naming/modules/znam/include/znam/znam.h) are pure encoders: struct-in, bytes-out.
 *    They know nothing about transactions, chain state, or ownership.
 * 3. Ownership is NOT a field inside the OP_RETURN message. It is derived at
 *    fold time from *which UTXO funds the spending transaction*: `apply_znam`
 *    (via `znam_owner_address`) looks up the P2PKH address hash behind
 *    `tx->vin[0].prevout`, base58-encodes it, and compares it against the
 *    name's stored `owner_address`. This is why the negative case below
 *    needs mallory to genuinely own a DIFFERENT prior output — no signature
 *    checking is simulated, but the address-derivation-from-prevout
 *    mechanism is the real one, byte for byte.
 * 4. `db_znam_find` / `db_znam_text_get` are the READ side: the same
 *    functions behind `z23 app names resolve` and the ZNAM RPC
 *    handlers use in production.
 *
 * NOTE ON TEST-ONLY HELPERS: this file reimplements the small OP_RETURN /
 * P2PKH transaction builders that, in the test suite, live inside
 * tests/harness/src/test_simnet.c section 7 guarded by #ifdef ZCL_TESTING (they
 * are test helpers, not public library API). The equivalent minimal
 * versions here keep this example link-clean without pulling in
 * test_helpers.h.
 *
 * Deterministic: no wall clock, no RNG — every input (seeds, values,
 * names, addresses) is a fixed literal, so a run always produces the same
 * story and the same final projection rows.
 */

#include "sim/simnet.h"
#include "znam/znam.h"
#include "models/znam.h"
#include "models/explorer_index.h"
#include "models/database.h"
#include "core/uint256.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "script/script.h"
#include "primitives/transaction.h"
#include "primitives/block.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Minimal but REAL 25-byte P2PKH scriptPubKey: OP_DUP OP_HASH160 <20 bytes>
 * OP_EQUALVERIFY OP_CHECKSIG. `seed` fills the 20-byte hash so each wallet
 * ("alice" = 0xC0, "mallory" = 0xE1) gets a stable, distinct address —
 * `utxo_classify_script` must recognize this shape for `znam_owner_address`
 * to resolve an owner at all (a malformed/truncated P2PKH output makes the
 * name projection reject the op with no attributable owner). */
static void demo_p2pkh_script(struct script *sp, unsigned char seed)
{
    sp->data[0] = 0x76; sp->data[1] = 0xa9; sp->data[2] = 0x14;
    for (int i = 0; i < 20; i++) sp->data[3 + i] = (unsigned char)(seed + i);
    sp->data[23] = 0x88; sp->data[24] = 0xac;
    sp->size = 25;
}

/* One-input tx that funds two distinct P2PKH wallets (used once, to seed
 * alice's and mallory's starting coins from the same matured coinbase). */
static bool build_fund_tx(struct transaction *tx,
                          const struct uint256 *prev_txid, uint32_t prev_n,
                          int64_t alice_value, int64_t mallory_value)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 2)) return false;
    tx->version = 1;
    tx->vin[0].prevout.hash = *prev_txid;
    tx->vin[0].prevout.n = prev_n;
    uint8_t sig[] = {0x00, 0x00};
    script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    tx->vin[0].sequence = 0xFFFFFFFFu;
    tx->vout[0].value = alice_value;
    demo_p2pkh_script(&tx->vout[0].script_pub_key, 0xC0);   /* alice   */
    tx->vout[1].value = mallory_value;
    demo_p2pkh_script(&tx->vout[1].script_pub_key, 0xE1);   /* mallory */
    transaction_compute_hash(tx);
    return true;
}

/* One-input tx: vout[0] carries the ZNAM OP_RETURN payload, vout[1] is a
 * P2PKH change output back to `change_seed`'s wallet (so the same wallet can
 * keep authorizing further ZNAM ops with its own coin, chained tx-to-tx). */
static bool build_znam_tx(struct transaction *tx,
                         const struct uint256 *prev_txid, uint32_t prev_n,
                         const uint8_t *opret, size_t opret_len,
                         int64_t change_value, unsigned char change_seed)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 2)) return false;
    tx->version = 1;
    tx->vin[0].prevout.hash = *prev_txid;
    tx->vin[0].prevout.n = prev_n;
    uint8_t sig[] = {0x00, 0x00};
    script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    tx->vin[0].sequence = 0xFFFFFFFFu;
    tx->vout[0].value = 0;
    script_set(&tx->vout[0].script_pub_key, opret, opret_len);
    tx->vout[1].value = change_value;
    demo_p2pkh_script(&tx->vout[1].script_pub_key, change_seed);
    transaction_compute_hash(tx);
    return true;
}

/* Fold one minted block's single tx into the ZNAM projection — the same
 * per-block hook (`explorer_index_block`) a real node calls once per synced
 * block during forward-sync indexing. `hash_seed` only needs to make each
 * synthetic block hash distinct; it is not chained into a real header. */
static bool index_one_tx_block(struct node_db *ndb, struct transaction *tx,
                               int height, unsigned char hash_seed)
{
    struct block blk;
    block_init(&blk);
    blk.vtx = tx;
    blk.num_vtx = 1;

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

int main(void)
{
    printf("=== 05_znam_names: REGISTER -> UPDATE -> SET_TEXT, then a "
          "non-owner UPDATE that the projection discards ===\n\n");

    /* Select a chain network before any chain/consensus code runs —
     * connect_block and the coinbase subsidy schedule read their parameters
     * through chain_params_get(), which asserts one was chosen. */
    chain_params_select(CHAIN_MAIN);

    struct simnet sim;
    if (!simnet_init(&sim)) { fprintf(stderr, "simnet_init failed\n"); return 1; }

    struct node_db db;
    memset(&db, 0, sizeof(db));
    if (!node_db_open(&db, ":memory:")) {
        fprintf(stderr, "node_db_open failed\n"); return 1;
    }

    printf("[1/4] minting a coinbase and 100 blocks to reach coinbase "
          "maturity, then funding alice + mallory from it...\n");
    struct uint256 cb_txid;
    if (!simnet_mint_coinbase(&sim, &cb_txid)) {
        fprintf(stderr, "mint coinbase failed\n"); return 1;
    }
    if (!simnet_mint_to_height(&sim, 200)) {
        fprintf(stderr, "mint to maturity height failed\n"); return 1;
    }
    /* simnet_mint_txs() MOVES each tx's vin/vout arrays into the block it
     * mints (see engine/modules/sim/src/simnet.c: `block_txs[i+1] = txs[i];` followed
     * by `transaction_init(&txs[i])`) and resets the caller's copy to an
     * empty transaction — the same "the caller no longer owns this"
     * contract tests/harness/src/test_simnet.c follows via `transaction_copy()`
     * before minting. So every tx below gets a `_proj` copy, taken BEFORE
     * its mint call, for anything read AFTER minting (index_one_tx_block()
     * and the forged-tx znam_parse() re-check) — reading the post-mint tx
     * directly would deref an emptied (NULL vin/vout) transaction. */
    struct transaction fund_tx, fund_tx_proj;
    transaction_init(&fund_tx_proj);
    if (!build_fund_tx(&fund_tx, &cb_txid, 0, 400000, 400000)) {
        fprintf(stderr, "build fund tx failed\n"); return 1;
    }
    struct uint256 fund_txid = fund_tx.hash;
    if (!transaction_copy(&fund_tx_proj, &fund_tx)) {
        fprintf(stderr, "copy fund tx for projection failed\n"); return 1;
    }
    if (!simnet_mint_txs(&sim, &fund_tx, 1)) {
        fprintf(stderr, "mint fund tx rejected by connect_block\n"); return 1;
    }
    int fund_height = simnet_tip_height(&sim);
    if (!index_one_tx_block(&db, &fund_tx_proj, fund_height, 0xF1)) {
        fprintf(stderr, "index fund tx failed\n"); return 1;
    }
    printf("      block accepted at height %d; alice vout=0 (400000 zats), "
          "mallory vout=1 (400000 zats)\n", fund_height);

    printf("\n[2/4] REGISTER \"alice-home\" -> t1exampletarget, owned by "
          "whoever funds the tx (alice)...\n");
    uint8_t register_script[512];
    size_t register_len = znam_build_register(register_script,
                                              sizeof(register_script),
                                              "alice-home", ZNAM_TYPE_TADDR,
                                              "t1exampletarget");
    assert(register_len > 0 && "znam_build_register must encode a valid payload");

    struct transaction register_tx, register_tx_proj;
    transaction_init(&register_tx_proj);
    if (!build_znam_tx(&register_tx, &fund_txid, 0, register_script,
                       register_len, 350000, 0xC0)) {
        fprintf(stderr, "build register tx failed\n"); return 1;
    }
    struct uint256 register_txid = register_tx.hash;
    if (!transaction_copy(&register_tx_proj, &register_tx)) {
        fprintf(stderr, "copy register tx for projection failed\n"); return 1;
    }
    if (!simnet_mint_txs(&sim, &register_tx, 1)) {
        fprintf(stderr, "mint register tx rejected by connect_block\n"); return 1;
    }
    int register_height = simnet_tip_height(&sim);
    if (!index_one_tx_block(&db, &register_tx_proj, register_height, 0xF2)) {
        fprintf(stderr, "index register tx failed\n"); return 1;
    }

    struct znam_entry after_register;
    memset(&after_register, 0, sizeof(after_register));
    if (!db_znam_find(&db, "alice-home", &after_register)) {
        fprintf(stderr, "projection does not see \"alice-home\" after REGISTER\n");
        return 1;
    }
    printf("      block accepted at height %d; owner=%s target=%s\n",
          register_height, after_register.owner_address,
          after_register.target_value);
    assert(strcmp(after_register.target_value, "t1exampletarget") == 0);
    char alice_owner[64];
    snprintf(alice_owner, sizeof(alice_owner), "%s", after_register.owner_address);

    printf("\n[3/4] owner UPDATE (alice) repoints the name, then SET_TEXT "
          "attaches an email record...\n");
    uint8_t update_script[512];
    size_t update_len = znam_build_update(update_script, sizeof(update_script),
                                          "alice-home", ZNAM_TYPE_TADDR,
                                          "t1updatedtarget");
    assert(update_len > 0 && "znam_build_update must encode a valid payload");

    struct transaction update_tx, update_tx_proj;
    transaction_init(&update_tx_proj);
    if (!build_znam_tx(&update_tx, &register_txid, 1, update_script,
                       update_len, 300000, 0xC0)) {
        fprintf(stderr, "build update tx failed\n"); return 1;
    }
    struct uint256 update_txid = update_tx.hash;
    if (!transaction_copy(&update_tx_proj, &update_tx)) {
        fprintf(stderr, "copy update tx for projection failed\n"); return 1;
    }
    if (!simnet_mint_txs(&sim, &update_tx, 1)) {
        fprintf(stderr, "mint owner UPDATE rejected by connect_block\n"); return 1;
    }
    int update_height = simnet_tip_height(&sim);
    if (!index_one_tx_block(&db, &update_tx_proj, update_height, 0xF3)) {
        fprintf(stderr, "index owner UPDATE failed\n"); return 1;
    }
    struct znam_entry after_update;
    memset(&after_update, 0, sizeof(after_update));
    if (!db_znam_find(&db, "alice-home", &after_update)) {
        fprintf(stderr, "projection lost \"alice-home\" after UPDATE\n"); return 1;
    }
    assert(strcmp(after_update.target_value, "t1updatedtarget") == 0);
    assert(strcmp(after_update.owner_address, alice_owner) == 0);
    printf("      block accepted at height %d; target now %s (owner unchanged)\n",
          update_height, after_update.target_value);

    uint8_t text_script[512];
    size_t text_len = znam_build_set_text(text_script, sizeof(text_script),
                                          "alice-home", "email",
                                          "alice@example.test");
    assert(text_len > 0 && "znam_build_set_text must encode a valid payload");

    struct transaction text_tx, text_tx_proj;
    transaction_init(&text_tx_proj);
    if (!build_znam_tx(&text_tx, &update_txid, 1, text_script, text_len,
                       250000, 0xC0)) {
        fprintf(stderr, "build SET_TEXT tx failed\n"); return 1;
    }
    if (!transaction_copy(&text_tx_proj, &text_tx)) {
        fprintf(stderr, "copy SET_TEXT tx for projection failed\n"); return 1;
    }
    if (!simnet_mint_txs(&sim, &text_tx, 1)) {
        fprintf(stderr, "mint SET_TEXT rejected by connect_block\n"); return 1;
    }
    int text_height = simnet_tip_height(&sim);
    if (!index_one_tx_block(&db, &text_tx_proj, text_height, 0xF4)) {
        fprintf(stderr, "index SET_TEXT failed\n"); return 1;
    }
    char email_out[ZNAM_TEXT_VAL_MAX + 1];
    memset(email_out, 0, sizeof(email_out));
    if (!db_znam_text_get(&db, "alice-home", "email", email_out, sizeof(email_out))) {
        fprintf(stderr, "projection did not record the email text record\n");
        return 1;
    }
    assert(strcmp(email_out, "alice@example.test") == 0);
    printf("      block accepted at height %d; text[email]=%s\n",
          text_height, email_out);

    printf("\n[4/4] NEGATIVE: mallory (never the owner) posts a well-formed "
          "UPDATE for \"alice-home\", funded by HER OWN coin...\n");
    uint8_t forged_script[512];
    size_t forged_len = znam_build_update(forged_script, sizeof(forged_script),
                                         "alice-home", ZNAM_TYPE_TADDR,
                                         "t1stolentarget");
    assert(forged_len > 0 && "the forged message is itself well-formed ZNAM");

    struct transaction forged_tx, forged_tx_proj;
    transaction_init(&forged_tx_proj);
    /* Spends fund_txid:1 — mallory's coin from step 1, NOT alice's chain. */
    if (!build_znam_tx(&forged_tx, &fund_txid, 1, forged_script, forged_len,
                       350000, 0xE1)) {
        fprintf(stderr, "build forged UPDATE tx failed\n"); return 1;
    }
    if (!transaction_copy(&forged_tx_proj, &forged_tx)) {
        fprintf(stderr, "copy forged tx for projection failed\n"); return 1;
    }
    if (!simnet_mint_txs(&sim, &forged_tx, 1)) {
        /* Consensus does not know or care about ZNAM ownership — an ordinary
         * P2PKH-funded OP_RETURN tx is structurally valid and connect_block
         * accepts it regardless. If this ever fails, the rejection would be
         * a plain transparent-spend defect, unrelated to name ownership. */
        fprintf(stderr, "mint forged UPDATE rejected by connect_block "
                        "(unexpected: ownership is a projection concern, "
                        "not a consensus rule)\n");
        return 1;
    }
    int forged_height = simnet_tip_height(&sim);
    struct znam_message parsed_forgery;
    bool forgery_parses = znam_parse(forged_tx_proj.vout[0].script_pub_key.data,
                                     forged_tx_proj.vout[0].script_pub_key.size,
                                     &parsed_forgery);
    assert(forgery_parses && parsed_forgery.command == ZNAM_CMD_UPDATE &&
          "the wire bytes decode as a perfectly valid UPDATE message");
    printf("      block accepted at height %d; znam_parse decodes it as a "
          "valid UPDATE(\"%s\" -> %s) — the wire format has no owner field\n",
          forged_height, parsed_forgery.name, parsed_forgery.target_value);

    if (!index_one_tx_block(&db, &forged_tx_proj, forged_height, 0xF5)) {
        fprintf(stderr, "index forged UPDATE failed\n"); return 1;
    }
    struct znam_entry after_forgery;
    memset(&after_forgery, 0, sizeof(after_forgery));
    if (!db_znam_find(&db, "alice-home", &after_forgery)) {
        fprintf(stderr, "projection lost \"alice-home\" after the forged block\n");
        return 1;
    }
    /* apply_znam() derives the authorizing address from forged_tx's OWN
     * first input (mallory's coin), compares it against the stored
     * owner_address (alice's), and returns without saving on a mismatch —
     * see contexts/explorer/models/src/explorer_index.c apply_znam(), ZNAM_CMD_UPDATE
     * case, "owner auth" comment. So the target must still read the
     * legitimate value from step 3, not mallory's "t1stolentarget". */
    if (strcmp(after_forgery.target_value, "t1stolentarget") == 0) {
        fprintf(stderr,
               "SECURITY REGRESSION: non-owner UPDATE was applied! "
               "target=%s\n", after_forgery.target_value);
        return 1;
    }
    assert(strcmp(after_forgery.target_value, "t1updatedtarget") == 0);
    assert(strcmp(after_forgery.owner_address, alice_owner) == 0);
    printf("      projection after fold: target=%s owner=%s — the forged "
          "block parsed but was NOT applied (owner-address mismatch at the "
          "authorization layer)\n",
          after_forgery.target_value, after_forgery.owner_address);

    /* fund_tx/register_tx/update_tx/text_tx/forged_tx are already empty
     * (simnet_mint_txs moved their contents into the mined block and reset
     * them) — freeing them is a harmless no-op; the _proj copies are what
     * actually own allocations. */
    transaction_free(&fund_tx);
    transaction_free(&register_tx);
    transaction_free(&update_tx);
    transaction_free(&text_tx);
    transaction_free(&forged_tx);
    transaction_free(&fund_tx_proj);
    transaction_free(&register_tx_proj);
    transaction_free(&update_tx_proj);
    transaction_free(&text_tx_proj);
    transaction_free(&forged_tx_proj);
    node_db_close(&db);
    simnet_free(&sim);

    printf("\n=== SUCCESS: REGISTER -> UPDATE -> SET_TEXT applied by "
          "the true owner; a non-owner UPDATE parsed as valid ZNAM wire "
          "data but was rejected by the projection's owner-address check ===\n");
    return 0;
}

/* Production counterpart:
 * -----------------------
 * Building/broadcasting a ZNAM transaction: there is no dedicated
 * "wallet_name_register" entry point — a real ZNAM tx is assembled exactly
 * as this example does it (an OP_RETURN vout[0] built by
 * znam_build_register/update/transfer/renew/set_record/set_text, plus an
 * ordinary transparent change output), then submitted through the normal
 * transparent send path in contexts/wallet/controllers/src/wallet_controller.c, and the
 * RPC-facing entry point is `name_register` / the equivalent handlers in
 * engine/controllers/src/name_controller.c (also reachable via the
 * `app names register` native command).
 *
 * The READ side this example exercises directly IS the production path: a
 * live node's forward-sync indexer calls `explorer_index_block` ->
 * `apply_znam` (contexts/explorer/models/src/explorer_index.c) for every block, and the
 * resulting znam_names / znam_text_records / znam_addr_records rows are
 * exactly what `name_resolve` (name_controller.c) and the
 * `app names resolve` / `app names list` native commands read back for callers.
 */
