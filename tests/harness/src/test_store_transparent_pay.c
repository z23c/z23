/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A store order paid TRANSPARENTLY is credited, and only by its own payment.
 *
 * The store could only ever be paid shielded: the order address was always a
 * z-address and the merchant credited it only by decrypting the payment's
 * memo. A build with no Sapling proving backend cannot make a shielded SPEND
 * at all, so every purchase on such a build was refused. A transparent
 * payment needs no proof.
 *
 * A transparent output has nowhere to carry a memo, so the ORDER BIND is the
 * one-time address itself. That is only as tight as the memo bind while the
 * address belongs to exactly one order, so the money assertions here are the
 * ones that keep it tight — a payment must not be credited to an order it was
 * not made for, and value that is not yet confirmed, not a payment, or not
 * enough must not unlock anything.
 *
 * On the code before this group existed, the FIRST case fails: the merchant
 * reconciles a transparent order by looking for a Sapling note that does not
 * exist, finds nothing, and the order stays PENDING forever.
 *
 * Deterministic and in-process: the positive path mines an exact wallet-signed
 * transaction and derives the merchant projection from it; compact hand-made
 * rows remain only for the independent negative matrix. No network or live
 * wallet is contacted. */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "config/runtime.h"
#include "controllers/store_controller.h"
#include "controllers/wallet_controller.h"
#include "controllers/wallet_helpers.h"
#include "controllers/zslp_controller.h"
#include "models/block.h"
#include "models/store.h"
#include "models/wallet_tx.h"
#include "script/standard.h"
#include "services/store_buyer.h"
#include "sim/simnet.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "validation/main_constants.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "wallet/wallet.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "controllers/sync_controller.h"
#include "jobs/reducer_frontier.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The customer address tokens are minted to. Mainnet form, because the
 * runner selects CHAIN_MAIN and that is what the store's validator takes. */
#define TSTP_CUSTOMER "t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn"

/* Confirmation ceiling the merchant measures against is tip - 3. */
#define TSTP_TIP 100
#define TSTP_FEE_ZAT WALLET_DEFAULT_FEE_ZAT

#define TSTP_CHECK(label, expression) do {                         \
    bool tstp_check_ok = (expression);                             \
    printf("store_transparent_pay: %s... %s\n", (label),          \
           tstp_check_ok ? "OK" : "FAIL");                       \
    if (!tstp_check_ok) failures++;                                \
} while (0)

static bool tstp_open(const char *datadir, struct node_db *ndb)
{
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/node.db", datadir);
    memset(ndb, 0, sizeof(*ndb));
    return node_db_open(ndb, path);
}

/* A tip block so the payment scan has a confirmation depth to measure. */
static bool tstp_seed_tip(struct node_db *ndb, int height)
{
    struct db_block blk;
    static uint8_t solution[] = { 0x51, 0x52 };

    memset(&blk, 0, sizeof(blk));
    memset(blk.hash, 0x11, sizeof(blk.hash));
    memset(blk.prev_hash, 0x22, sizeof(blk.prev_hash));
    memset(blk.merkle_root, 0x33, sizeof(blk.merkle_root));
    memset(blk.chain_work, 0x44, sizeof(blk.chain_work));
    blk.height = height;
    blk.time = 123456789u;
    blk.bits = 0x1d00ffffu;
    blk.status = 3;
    blk.solution = solution;
    blk.solution_len = sizeof(solution);
    blk.hash[28] = (uint8_t)((uint32_t)height >> 24);
    blk.hash[29] = (uint8_t)((uint32_t)height >> 16);
    blk.hash[30] = (uint8_t)((uint32_t)height >> 8);
    blk.hash[31] = (uint8_t)height;
    return db_block_save(ndb, &blk);
}

/* Build the t-address for `hash160` AND hand back the same 20 bytes, so the
 * address the order binds to and the UTXO the wallet holds cannot drift
 * apart in the fixture the way they could if either were hand-written. */
static bool tstp_taddr_for(uint8_t tag, char *addr_out, size_t addr_max,
                           uint8_t hash160_out[20])
{
    struct tx_destination dest;

    memset(hash160_out, tag, 20);
    memset(&dest, 0, sizeof(dest));
    dest.type = DEST_KEY_ID;
    memcpy(dest.id.key.id.data, hash160_out, 20);
    return wallet_encode_destination(&dest, addr_out, addr_max);
}

static void tstp_key(struct privkey *key, uint8_t tag)
{
    memset(key->vch, tag, sizeof(key->vch));
    key->fValid = true;
    key->fCompressed = true;
}

static bool tstp_key_identity(const struct privkey *key,
                              struct key_id *key_id,
                              struct script *script,
                              char *address, size_t address_max)
{
    struct pubkey pubkey;
    struct tx_destination destination;

    if (!privkey_get_pubkey(key, &pubkey))
        return false;
    *key_id = pubkey_get_id(&pubkey);
    memset(&destination, 0, sizeof(destination));
    destination.type = DEST_KEY_ID;
    destination.id.key = *key_id;
    script_for_p2pkh(script, key_id);
    return wallet_encode_destination(&destination, address, address_max);
}

/* The faucet input only establishes an isolated, mature funding outpoint.
 * The transaction under proof is built and signed by the real wallet path. */
static bool tstp_build_funding_tx(struct transaction *tx,
                                  const struct uint256 *coinbase_txid,
                                  const struct script *payer_script,
                                  int64_t value)
{
    if (!tx || !coinbase_txid || !payer_script)
        return false;
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        return false;
    tx->version = 1;
    tx->vin[0].prevout.hash = *coinbase_txid;
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = UINT32_MAX;
    {
        static const uint8_t placeholder_sig[] = {0x00, 0x00};
        script_set(&tx->vin[0].script_sig, placeholder_sig,
                   sizeof(placeholder_sig));
    }
    tx->vout[0].value = value;
    tx->vout[0].script_pub_key = *payer_script;
    transaction_compute_hash(tx);
    return true;
}

/* The wallet spend guard fails closed without durable trust state. This
 * fixture declares the same bare/self-derived state used by the wallet import
 * E2E test; it cannot grant live authority because it lives in test-tmp. */
static bool tstp_open_trust_fixture(const char *datadir)
{
    if (!progress_store_open(datadir))
        return false;
    sqlite3 *db = progress_store_db();
    if (!db || !coins_kv_ensure_schema(db))
        return false;
    reducer_frontier_provable_tip_set(50);
    struct uint256 txid;
    uint256_set_null(&txid);
    txid.data[0] = 0x51;
    txid.data[31] = 0x77;
    static const uint8_t script[] = {0xe0, 0xe0, 0xe0, 0xe0};
    if (!coins_kv_add(db, txid.data, 0, 1234, 50, true,
                      script, sizeof(script)))
        return false;
    char *error = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &error) ==
                  SQLITE_OK &&
              coins_kv_set_applied_height_in_tx(db, 51) &&
              sqlite3_exec(db, "COMMIT", NULL, NULL, &error) == SQLITE_OK;
    if (error)
        sqlite3_free(error);
    return ok;
}

/* A confirmed, unspent, non-coinbase transparent output the wallet holds at
 * `hash160` — what a real buyer's payment looks like once it is in a block
 * and the wallet has scanned it. */
static bool tstp_seed_utxo(struct node_db *ndb, const uint8_t hash160[20],
                           int64_t value, int height, bool is_coinbase,
                           uint8_t txid_tag)
{
    struct db_wallet_utxo u;
    static uint8_t script[] = { 0x76, 0xa9, 0x14 };

    memset(&u, 0, sizeof(u));
    memset(u.txid, txid_tag, sizeof(u.txid));
    u.vout = 0;
    u.value = value;
    memcpy(u.address_hash, hash160, 20);
    u.script = script;
    u.script_len = sizeof(script);
    u.height = height;
    u.is_coinbase = is_coinbase;
    return db_wallet_utxo_save(ndb, &u);
}

/* Write a PENDING order bound to `payment_addr`. Returns its id, 0 on
 * failure. Deliberately writes the row rather than going through the HTTP
 * order route: this group is about what the merchant CREDITS, and the order
 * route's CSRF + proof-of-work admission is already proven elsewhere. */
static int64_t tstp_place_order(struct node_db *ndb, int64_t product_id,
                                const char *payment_addr, int64_t amount)
{
    struct db_store_order order;

    memset(&order, 0, sizeof(order));
    order.product_id = product_id;
    (void)snprintf(order.customer_addr, sizeof(order.customer_addr), "%s",
                   TSTP_CUSTOMER);
    (void)snprintf(order.payment_addr, sizeof(order.payment_addr), "%s",
                   payment_addr);
    order.amount_zatoshi = amount;
    order.status = STORE_ORDER_PENDING;
    if (!db_store_order_save(ndb, &order))
        return 0;
    return order.id;
}

static int tstp_order_status(const char *datadir, int64_t order_id)
{
    struct node_db ndb;
    struct db_store_order_view view;
    int status = -1;

    if (!tstp_open(datadir, &ndb))
        return -1;
    if (db_store_order_find_view(&ndb, order_id, &view))
        status = view.status;
    node_db_close(&ndb);
    return status;
}

/* Exact production path:
 *
 *   wallet_direct_sendtoaddress -> mempool validation -> connect_block
 *   -> node_db_sync_wallet_tx -> store_process_payments
 *
 * The old fixture began at the wallet_utxos projection. This one begins with
 * a spendable isolated outpoint, retains the exact transaction emitted by the
 * real transparent store sender, and derives the merchant projection from
 * those already-mined bytes. */
static int tstp_exact_chain_payment(void)
{
    int failures = 0;
    char datadir[256], trustdir[256];
    struct node_db ndb;
    bool ndb_open = false;
    struct simnet sim;
    bool sim_ready = false;
    struct wallet *payer = NULL, *merchant = NULL;
    bool payer_ready = false, merchant_ready = false;
    struct main_state main_state;
    bool main_ready = false;
    struct tx_mempool mempool;
    bool mempool_ready = false;
    struct coins_view null_view;
    struct coins_view_cache coins_tip;
    bool coins_ready = false;
    struct transaction mined_payment;
    transaction_init(&mined_payment);
    bool have_mined_payment = false;
    struct privkey payer_key = {0}, merchant_key = {0};

    printf("\n-- exact wallet-built store payment through chain + reconcile --\n");
    test_make_tmpdir(datadir, sizeof(datadir),
                     "store_transparent_pay_chain", "merchant");
    test_make_tmpdir(trustdir, sizeof(trustdir),
                     "store_transparent_pay_chain", "trust");

    struct store_buyer_offer offers[8];
    size_t offer_count = 0;
    bool catalog_ok = store_buyer_catalog(datadir, offers, 8,
                                           &offer_count).ok &&
                      offer_count > 0;
    TSTP_CHECK("chain: merchant catalog is ready", catalog_ok);
    if (!catalog_ok)
        goto cleanup;

    bool opened = tstp_open(datadir, &ndb);
    TSTP_CHECK("chain: merchant projection database opens", opened);
    if (!opened)
        goto cleanup;
    ndb_open = true;

    tstp_key(&payer_key, 0x31);
    tstp_key(&merchant_key, 0x52);
    struct key_id payer_id, merchant_id;
    struct script payer_script, merchant_script;
    char payer_address[128] = "", merchant_address[128] = "";
    bool identities_ok =
        tstp_key_identity(&payer_key, &payer_id, &payer_script,
                          payer_address, sizeof(payer_address)) &&
        tstp_key_identity(&merchant_key, &merchant_id, &merchant_script,
                          merchant_address, sizeof(merchant_address));
    TSTP_CHECK("chain: payer and one-time merchant address derive",
               identities_ok);
    if (!identities_ok)
        goto cleanup;

    int64_t price = offers[0].price_zatoshi;
    int64_t order_id = tstp_place_order(&ndb, offers[0].product_id,
                                         merchant_address, price);
    TSTP_CHECK("chain: pending order binds the one-time address",
               order_id > 0 && price > 0);
    if (order_id <= 0 || price <= 0)
        goto cleanup;

    bool sim_ok = simnet_init(&sim);
    TSTP_CHECK("chain: isolated consensus chain initializes", sim_ok);
    if (!sim_ok)
        goto cleanup;
    sim_ready = true;

    int64_t funding_value = price + TSTP_FEE_ZAT;
    struct uint256 coinbase_txid;
    int coinbase_height = simnet_tip_height(&sim) + 1;
    bool faucet_ok = simnet_mint_coinbase_to(
                         &sim, &payer_script,
                         funding_value + TSTP_FEE_ZAT, &coinbase_txid) &&
                     simnet_mint_to_height(
                         &sim, coinbase_height + COINBASE_MATURITY);
    TSTP_CHECK("chain: isolated faucet output matures", faucet_ok);
    if (!faucet_ok)
        goto cleanup;

    struct transaction funding_tx;
    transaction_init(&funding_tx);
    bool funding_built = tstp_build_funding_tx(
        &funding_tx, &coinbase_txid, &payer_script, funding_value);
    struct wallet_tx funding_wallet_tx;
    memset(&funding_wallet_tx, 0, sizeof(funding_wallet_tx));
    transaction_init(&funding_wallet_tx.tx);
    bool funding_copied = funding_built &&
        transaction_copy(&funding_wallet_tx.tx, &funding_tx);
    struct uint256 funding_txid = funding_built
        ? funding_tx.hash : (struct uint256){0};
    bool funding_mined = funding_copied &&
        simnet_mint_txs(&sim, &funding_tx, 1);
    if (funding_built && !funding_copied)
        transaction_free(&funding_tx);
    TSTP_CHECK("chain: exact payer funding outpoint enters a block",
               funding_mined &&
               simnet_coin_value(&sim, &funding_txid, 0, NULL));
    if (!funding_mined) {
        transaction_free(&funding_wallet_tx.tx);
        goto cleanup;
    }

    payer = zcl_malloc(sizeof(*payer), "store payment payer wallet");
    merchant = zcl_malloc(sizeof(*merchant), "store payment merchant wallet");
    bool wallets_allocated = payer && merchant;
    TSTP_CHECK("chain: isolated payer and merchant wallets allocate",
               wallets_allocated);
    if (!wallets_allocated) {
        transaction_free(&funding_wallet_tx.tx);
        goto cleanup;
    }
    wallet_init(payer);
    payer_ready = true;
    wallet_init(merchant);
    merchant_ready = true;
    funding_wallet_tx.confirms = 1;
    funding_wallet_tx.time_received = 1;
    bool payer_seeded = keystore_add_key(&payer->keystore, &payer_key) &&
                        wallet_add_to_wallet(payer, &funding_wallet_tx);
    transaction_free(&funding_wallet_tx.tx);
    bool merchant_seeded =
        keystore_add_key(&merchant->keystore, &merchant_key);
    payer->best_block_height = simnet_tip_height(&sim);
    TSTP_CHECK("chain: payer owns the exact confirmed funding coin",
               payer_seeded && merchant_seeded);
    if (!payer_seeded || !merchant_seeded)
        goto cleanup;

    main_state_init(&main_state);
    main_ready = true;
    tx_mempool_init(&mempool, 0);
    mempool_ready = true;
    memset(&null_view, 0, sizeof(null_view));
    coins_view_cache_init(&coins_tip, &null_view);
    coins_ready = true;
    struct coins_cache_entry *funding_entry =
        coins_view_cache_modify_new(&coins_tip, &funding_txid);
    bool coin_stamped = funding_entry != NULL;
    if (funding_entry) {
        coins_alloc(&funding_entry->coins, 1);
        funding_entry->coins.vout[0].value = funding_value;
        funding_entry->coins.vout[0].script_pub_key = payer_script;
        funding_entry->coins.height = simnet_tip_height(&sim);
        funding_entry->coins.version = 1;
        funding_entry->coins.is_coinbase = false;
    }
    TSTP_CHECK("chain: mempool sees the same isolated funding coin",
               coin_stamped);
    if (!coin_stamped)
        goto cleanup;

    bool trust_ok = tstp_open_trust_fixture(trustdir);
    TSTP_CHECK("chain: isolated self-derived spend guard opens", trust_ok);
    if (!trust_ok)
        goto cleanup;

    rpc_wallet_set_state(payer, &main_state, datadir, NULL, &mempool, NULL);
    rpc_wallet_set_node_db(NULL);
    rpc_wallet_set_coins_tip(&coins_tip);

    char payment_txid_hex[65] = "";
    char send_error[256] = "";
    bool sent = wallet_direct_sendtoaddress(
        merchant_address, price, payment_txid_hex,
        sizeof(payment_txid_hex), send_error, sizeof(send_error));
    TSTP_CHECK("chain: real store transparent sender signs and admits",
               sent && payment_txid_hex[0]);
    if (!sent)
        goto cleanup;

    struct uint256 payment_txid;
    uint256_set_hex(&payment_txid, payment_txid_hex);
    struct transaction payment_tx;
    transaction_init(&payment_tx);
    bool captured = tx_mempool_lookup(&mempool, &payment_txid, &payment_tx) &&
                    transaction_copy(&mined_payment, &payment_tx);
    have_mined_payment = captured;
    bool exact_shape = captured && payment_tx.num_vin == 1 &&
        payment_tx.num_vout == 1 &&
        uint256_eq(&payment_tx.vin[0].prevout.hash, &funding_txid) &&
        payment_tx.vin[0].prevout.n == 0 &&
        payment_tx.vout[0].value == price &&
        payment_tx.vout[0].script_pub_key.size == merchant_script.size &&
        memcmp(payment_tx.vout[0].script_pub_key.data,
               merchant_script.data, merchant_script.size) == 0;
    TSTP_CHECK("chain: captured bytes bind exact order output and fee",
               exact_shape && funding_value - price == TSTP_FEE_ZAT);

    bool mined = exact_shape && simnet_mint_txs(&sim, &payment_tx, 1);
    if (mined)
        transaction_init(&payment_tx); /* ownership moved into simnet */
    else
        transaction_free(&payment_tx);
    int payment_height = simnet_tip_height(&sim);
    int64_t paid_value = 0;
    bool chain_settled = mined &&
        !simnet_coin_value(&sim, &funding_txid, 0, NULL) &&
        simnet_coin_value(&sim, &payment_txid, 0, &paid_value) &&
        paid_value == price;
    TSTP_CHECK("chain: exact signed payment passes connect_block",
               chain_settled);
    if (!chain_settled)
        goto cleanup;

    bool block_recorded = tstp_seed_tip(&ndb, payment_height);
    bool projected = block_recorded && node_db_sync_wallet_tx(
        &ndb, &mined_payment, merchant, payment_height);
    bool tip_ready = tstp_seed_tip(&ndb, payment_height + 3);
    int64_t confirmed = projected && tip_ready
        ? store_confirmed_payment(&ndb, merchant_address, order_id,
                                  payment_height)
        : 0;
    TSTP_CHECK("chain: production wallet projection recovers exact payment",
               projected && tip_ready && confirmed == price);
    node_db_close(&ndb);
    ndb_open = false;

    if (projected && tip_ready)
        store_process_payments(datadir);
    TSTP_CHECK("chain: merchant reconciliation fulfills the bound order",
               projected && tip_ready &&
               tstp_order_status(datadir, order_id) == STORE_ORDER_SENT);

cleanup:
    rpc_wallet_set_state(NULL, NULL, NULL, NULL, NULL, NULL);
    rpc_wallet_set_node_db(NULL);
    rpc_wallet_set_coins_tip(NULL);
    reducer_frontier_provable_tip_reset();
    progress_store_close();
    if (have_mined_payment)
        transaction_free(&mined_payment);
    if (coins_ready)
        coins_view_cache_free(&coins_tip);
    if (mempool_ready)
        tx_mempool_free(&mempool);
    if (main_ready)
        main_state_free(&main_state);
    if (merchant_ready)
        wallet_free(merchant);
    if (payer_ready)
        wallet_free(payer);
    free(merchant);
    free(payer);
    if (sim_ready)
        simnet_free(&sim);
    if (ndb_open)
        node_db_close(&ndb);
    memory_cleanse(payer_key.vch, sizeof(payer_key.vch));
    memory_cleanse(merchant_key.vch, sizeof(merchant_key.vch));
    test_cleanup_tmpdir(datadir);
    test_cleanup_tmpdir(trustdir);
    return failures;
}

int test_store_transparent_pay(void)
{
    int failures = 0;
    char datadir[256];
    struct node_db ndb;
    int64_t product_id = 0;
    int64_t price = 0;

    printf("\n=== store transparent payment ===\n");

    failures += tstp_exact_chain_payment();

    test_make_tmpdir(datadir, sizeof(datadir), "store_transparent_pay",
                     "main");

    /* Warm the store so its schema exists and the demo catalog is seeded —
     * the reconcile joins orders to a product for its token id, so an order
     * against no product is never scanned. */
    {
        struct store_buyer_offer offers[8];
        size_t n = 0;
        if (!store_buyer_catalog(datadir, offers, 8, &n).ok || n == 0) {
            printf("store_transparent_pay: FAIL (no catalog to order from)\n");
            return failures + 1;
        }
        product_id = offers[0].product_id;
        price = offers[0].price_zatoshi;
    }

    if (!tstp_open(datadir, &ndb)) {
        printf("store_transparent_pay: FAIL (could not open node.db)\n");
        return failures + 1;
    }
    if (!tstp_seed_tip(&ndb, TSTP_TIP)) {
        printf("store_transparent_pay: FAIL (could not seed a tip)\n");
        node_db_close(&ndb);
        return failures + 1;
    }

    /* ── 1. A confirmed transparent payment credits its order ───────────
     *
     * THE regression this group holds. Before transparent orders existed the
     * merchant reconciled every order by hunting for a Sapling note, so this
     * order stayed PENDING no matter how much transparent value arrived. */
    printf("store_transparent_pay: a confirmed t-payment credits the order"
           "... ");
    {
        char addr[128] = "";
        uint8_t h160[20];
        int64_t order_id = 0;
        bool ok = tstp_taddr_for(0xA1, addr, sizeof(addr), h160);

        if (ok) {
            order_id = tstp_place_order(&ndb, product_id, addr, price);
            ok = order_id > 0;
        }
        /* Confirmed: height 50 is well under the tip-3 ceiling of 97. */
        ok = ok && tstp_seed_utxo(&ndb, h160, price, 50, false, 0xE1);
        node_db_close(&ndb);

        if (ok) {
            store_process_payments(datadir);
            ok = tstp_order_status(datadir, order_id) == STORE_ORDER_SENT;
        }
        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
        if (!tstp_open(datadir, &ndb)) {
            printf("store_transparent_pay: FAIL (could not reopen node.db)\n");
            return failures + 1;
        }
    }

    /* ── 2. A payment to ANOTHER order's address does not credit this one ─
     *
     * The money assertion. The one-time address IS the order bind, so an
     * order whose own address was never paid must stay unpaid even while the
     * wallet is holding a perfectly good confirmed payment for a different
     * order. */
    printf("store_transparent_pay: another order's payment does not credit"
           "... ");
    {
        char paid_addr[128] = "", unpaid_addr[128] = "";
        uint8_t paid_h160[20], unpaid_h160[20];
        int64_t unpaid_order = 0;
        bool ok = tstp_taddr_for(0xB2, paid_addr, sizeof(paid_addr),
                                 paid_h160);
        ok = ok && tstp_taddr_for(0xB3, unpaid_addr, sizeof(unpaid_addr),
                                  unpaid_h160);
        if (ok) {
            unpaid_order = tstp_place_order(&ndb, product_id, unpaid_addr,
                                            price);
            ok = unpaid_order > 0;
        }
        /* Real, confirmed, sufficient — but paid to a DIFFERENT address. */
        ok = ok && tstp_seed_utxo(&ndb, paid_h160, price * 10, 50, false,
                                  0xE2);
        node_db_close(&ndb);

        if (ok) {
            store_process_payments(datadir);
            ok = tstp_order_status(datadir, unpaid_order) ==
                 STORE_ORDER_PENDING;
        }
        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
        if (!tstp_open(datadir, &ndb)) {
            printf("store_transparent_pay: FAIL (could not reopen node.db)\n");
            return failures + 1;
        }
    }

    /* ── 3. Value too shallow to be confirmed does not credit ───────────
     *
     * The reorg control: the merchant mints tokens it cannot take back, so
     * it must not act on value that a short reorg could still remove. */
    printf("store_transparent_pay: an unconfirmed payment does not credit"
           "... ");
    {
        char addr[128] = "";
        uint8_t h160[20];
        int64_t order_id = 0;
        bool ok = tstp_taddr_for(0xC4, addr, sizeof(addr), h160);

        if (ok) {
            order_id = tstp_place_order(&ndb, product_id, addr, price);
            ok = order_id > 0;
        }
        /* Height 99 is above the tip-3 ceiling of 97 — one confirmation. */
        ok = ok && tstp_seed_utxo(&ndb, h160, price, 99, false, 0xE3);
        node_db_close(&ndb);

        if (ok) {
            store_process_payments(datadir);
            ok = tstp_order_status(datadir, order_id) == STORE_ORDER_PENDING;
        }
        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
        if (!tstp_open(datadir, &ndb)) {
            printf("store_transparent_pay: FAIL (could not reopen node.db)\n");
            return failures + 1;
        }
    }

    /* ── 4. Block subsidy at the order address is not a payment ─────────
     *
     * A coinbase output crediting the order address is the merchant paying
     * itself, not a buyer paying. Counting it would hand out the goods for
     * free to whoever asked for an order while a block was being mined. */
    printf("store_transparent_pay: coinbase at the order address is not a "
           "payment... ");
    {
        char addr[128] = "";
        uint8_t h160[20];
        int64_t order_id = 0;
        bool ok = tstp_taddr_for(0xD5, addr, sizeof(addr), h160);

        if (ok) {
            order_id = tstp_place_order(&ndb, product_id, addr, price);
            ok = order_id > 0;
        }
        ok = ok && tstp_seed_utxo(&ndb, h160, price * 5, 50, true, 0xE4);
        node_db_close(&ndb);

        if (ok) {
            store_process_payments(datadir);
            ok = tstp_order_status(datadir, order_id) == STORE_ORDER_PENDING;
        }
        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
        if (!tstp_open(datadir, &ndb)) {
            printf("store_transparent_pay: FAIL (could not reopen node.db)\n");
            return failures + 1;
        }
    }

    /* ── 5. Underpaying does not credit ─────────────────────────────── */
    printf("store_transparent_pay: an underpayment does not credit... ");
    {
        char addr[128] = "";
        uint8_t h160[20];
        int64_t order_id = 0;
        bool ok = tstp_taddr_for(0xE6, addr, sizeof(addr), h160);

        if (ok) {
            order_id = tstp_place_order(&ndb, product_id, addr, price);
            ok = order_id > 0;
        }
        ok = ok && price > 1;
        ok = ok && tstp_seed_utxo(&ndb, h160, price - 1, 50, false, 0xE5);
        node_db_close(&ndb);

        if (ok) {
            store_process_payments(datadir);
            ok = tstp_order_status(datadir, order_id) == STORE_ORDER_PENDING;
        }
        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
        if (!tstp_open(datadir, &ndb)) {
            printf("store_transparent_pay: FAIL (could not reopen node.db)\n");
            return failures + 1;
        }
    }

    /* ── 6. Crediting is idempotent across a re-run ─────────────────────
     *
     * The reconcile runs every 30 s forever. An order it already credited
     * must not be credited a second time, and a restart mid-flight must land
     * on the same answer — the durable order status is what makes a crashed
     * merchant resume rather than double-deliver. */
    printf("store_transparent_pay: re-running the reconcile does not "
           "re-credit... ");
    {
        char addr[128] = "";
        uint8_t h160[20];
        int64_t order_id = 0;
        bool ok = tstp_taddr_for(0xF7, addr, sizeof(addr), h160);

        if (ok) {
            order_id = tstp_place_order(&ndb, product_id, addr, price);
            ok = order_id > 0;
        }
        ok = ok && tstp_seed_utxo(&ndb, h160, price, 50, false, 0xE6);
        node_db_close(&ndb);

        if (ok) {
            store_process_payments(datadir);
            ok = tstp_order_status(datadir, order_id) == STORE_ORDER_SENT;
        }
        if (ok) {
            uint64_t after_first =
                zslp_balance(datadir, "", TSTP_CUSTOMER);
            /* Whatever the first pass credited, a second pass must leave
             * alone: the order is no longer PENDING, so it is not scanned. */
            store_process_payments(datadir);
            ok = tstp_order_status(datadir, order_id) == STORE_ORDER_SENT &&
                 zslp_balance(datadir, "", TSTP_CUSTOMER) == after_first;
        }
        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
        if (!tstp_open(datadir, &ndb)) {
            printf("store_transparent_pay: FAIL (could not reopen node.db)\n");
            return failures + 1;
        }
    }

    node_db_close(&ndb);
    return failures;
}
