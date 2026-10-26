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

enum {
    TSTP_PAY_EXACT = 0,
    TSTP_PAY_TIMES_10 = 1,
    TSTP_PAY_TIMES_5 = 2,
    TSTP_PAY_SHORT = 3
};

enum {
    TSTP_GATE_NONE = 0,
    TSTP_GATE_PRICE = 1,
    TSTP_GATE_BALANCE = 2
};

struct tstp_pay_scale {
    int code;
    int64_t factor;
    int64_t deduct;
};

static const struct tstp_pay_scale tstp_pay_scales[] = {
    { TSTP_PAY_EXACT, 1, 0 },
    { TSTP_PAY_TIMES_10, 10, 0 },
    { TSTP_PAY_TIMES_5, 5, 0 },
    { TSTP_PAY_SHORT, 1, 1 },
};

struct tstp_matrix_case {
    const char *lead;
    uint8_t first_tag;
    uint8_t second_tag;
    uint8_t tx_tag;
    int height;
    bool coinbase;
    int value_code;
    int expect;
    int gate;
};

static const struct tstp_matrix_case tstp_matrix_cases[] = {
    /* ── 1. A confirmed transparent payment credits its order ───────────
     *
     * THE regression this group holds. Before transparent orders existed the
     * merchant reconciled every order by hunting for a Sapling note, so this
     * order stayed PENDING no matter how much transparent value arrived. */
    /* Confirmed: height 50 is well under the tip-3 ceiling of 97. */
    {
        .lead = "store_transparent_pay: a confirmed t-payment credits the order"
                "... ",
        .first_tag = 0xA1,
        .second_tag = 0,
        .tx_tag = 0xE1,
        .height = 50,
        .coinbase = false,
        .value_code = TSTP_PAY_EXACT,
        .expect = STORE_ORDER_SENT,
        .gate = TSTP_GATE_NONE,
    },
    /* ── 2. A payment to ANOTHER order's address does not credit this one ─
     *
     * The money assertion. The one-time address IS the order bind, so an
     * order whose own address was never paid must stay unpaid even while the
     * wallet is holding a perfectly good confirmed payment for a different
     * order. */
    /* Real, confirmed, sufficient — but paid to a DIFFERENT address. */
    {
        .lead = "store_transparent_pay: another order's payment does not credit"
                "... ",
        .first_tag = 0xB2,
        .second_tag = 0xB3,
        .tx_tag = 0xE2,
        .height = 50,
        .coinbase = false,
        .value_code = TSTP_PAY_TIMES_10,
        .expect = STORE_ORDER_PENDING,
        .gate = TSTP_GATE_NONE,
    },
    /* ── 3. Value too shallow to be confirmed does not credit ───────────
     *
     * The reorg control: the merchant mints tokens it cannot take back, so
     * it must not act on value that a short reorg could still remove. */
    /* Height 99 is above the tip-3 ceiling of 97 — one confirmation. */
    {
        .lead = "store_transparent_pay: an unconfirmed payment does not credit"
                "... ",
        .first_tag = 0xC4,
        .second_tag = 0,
        .tx_tag = 0xE3,
        .height = 99,
        .coinbase = false,
        .value_code = TSTP_PAY_EXACT,
        .expect = STORE_ORDER_PENDING,
        .gate = TSTP_GATE_NONE,
    },
    /* ── 4. Block subsidy at the order address is not a payment ─────────
     *
     * A coinbase output crediting the order address is the merchant paying
     * itself, not a buyer paying. Counting it would hand out the goods for
     * free to whoever asked for an order while a block was being mined. */
    {
        .lead = "store_transparent_pay: coinbase at the order address is not a "
                "payment... ",
        .first_tag = 0xD5,
        .second_tag = 0,
        .tx_tag = 0xE4,
        .height = 50,
        .coinbase = true,
        .value_code = TSTP_PAY_TIMES_5,
        .expect = STORE_ORDER_PENDING,
        .gate = TSTP_GATE_NONE,
    },
    /* ── 5. Underpaying does not credit ─────────────────────────────── */
    {
        .lead = "store_transparent_pay: an underpayment does not credit... ",
        .first_tag = 0xE6,
        .second_tag = 0,
        .tx_tag = 0xE5,
        .height = 50,
        .coinbase = false,
        .value_code = TSTP_PAY_SHORT,
        .expect = STORE_ORDER_PENDING,
        .gate = TSTP_GATE_PRICE,
    },
    /* ── 6. Crediting is idempotent across a re-run ─────────────────────
     *
     * The reconcile runs every 30 s forever. An order it already credited
     * must not be credited a second time, and a restart mid-flight must land
     * on the same answer — the durable order status is what makes a crashed
     * merchant resume rather than double-deliver. */
    {
        .lead = "store_transparent_pay: re-running the reconcile does not "
                "re-credit... ",
        .first_tag = 0xF7,
        .second_tag = 0,
        .tx_tag = 0xE6,
        .height = 50,
        .coinbase = false,
        .value_code = TSTP_PAY_EXACT,
        .expect = STORE_ORDER_SENT,
        .gate = TSTP_GATE_BALANCE,
    },
};

static int64_t tstp_pay_amount(int code, int64_t price)
{
    for (size_t i = 0; i < sizeof(tstp_pay_scales) / sizeof(tstp_pay_scales[0]);
         i++) {
        if (tstp_pay_scales[i].code == code)
            return price * tstp_pay_scales[i].factor -
                   tstp_pay_scales[i].deduct;
    }
    return price;
}

/* Derive the order address (and, for the cross-address case, the address
 * that is actually paid), place the pending order, and seed the UTXO. The
 * projection database is closed here, before reconciliation, as each case
 * did before. */
static bool tstp_matrix_prepare(struct node_db *ndb, int64_t product_id,
                                int64_t price,
                                const struct tstp_matrix_case *k,
                                int64_t *order_id)
{
    char first_addr[128] = "";
    char second_addr[128] = "";
    uint8_t first_h160[20];
    uint8_t second_h160[20];
    bool ok = tstp_taddr_for(k->first_tag, first_addr, sizeof(first_addr),
                             first_h160);
    bool split = k->second_tag != 0;

    if (split)
        ok = ok && tstp_taddr_for(k->second_tag, second_addr,
                                  sizeof(second_addr), second_h160);
    if (ok) {
        const char *order_addr = split ? second_addr : first_addr;
        *order_id = tstp_place_order(ndb, product_id, order_addr, price);
        ok = *order_id > 0;
    }
    if (k->gate == TSTP_GATE_PRICE)
        ok = ok && price > 1;
    ok = ok && tstp_seed_utxo(ndb, first_h160,
                              tstp_pay_amount(k->value_code, price),
                              k->height, k->coinbase, k->tx_tag);
    node_db_close(ndb);
    return ok;
}

static bool tstp_matrix_credit(const char *datadir, int64_t order_id,
                               const struct tstp_matrix_case *k)
{
    store_process_payments(datadir);
    bool ok = tstp_order_status(datadir, order_id) == k->expect;
    if (ok && k->gate == TSTP_GATE_BALANCE) {
        uint64_t after_first = zslp_balance(datadir, "", TSTP_CUSTOMER);
        /* Whatever the first pass credited, a second pass must leave
         * alone: the order is no longer PENDING, so it is not scanned. */
        store_process_payments(datadir);
        ok = tstp_order_status(datadir, order_id) == STORE_ORDER_SENT &&
             zslp_balance(datadir, "", TSTP_CUSTOMER) == after_first;
    }
    return ok;
}

enum {
    TSTP_CHAIN_CATALOG = 0,
    TSTP_CHAIN_OPEN,
    TSTP_CHAIN_IDENTITIES,
    TSTP_CHAIN_ORDER,
    TSTP_CHAIN_SIM,
    TSTP_CHAIN_FAUCET,
    TSTP_CHAIN_FUNDING,
    TSTP_CHAIN_WALLETS,
    TSTP_CHAIN_SEED,
    TSTP_CHAIN_COIN,
    TSTP_CHAIN_TRUST,
    TSTP_CHAIN_SEND,
    TSTP_CHAIN_CAPTURE,
    TSTP_CHAIN_CONNECT,
    TSTP_CHAIN_PROJECT,
    TSTP_CHAIN_RECONCILE,
    TSTP_CHAIN_STEPS
};

struct tstp_chain_result {
    bool check_ok;
    bool stop;
};

struct tstp_chain {
    char datadir[256];
    char trustdir[256];
    struct node_db ndb;
    bool ndb_open;
    struct store_buyer_offer offers[8];
    size_t offer_count;
    struct privkey payer_key;
    struct privkey merchant_key;
    struct key_id payer_id;
    struct key_id merchant_id;
    struct script payer_script;
    struct script merchant_script;
    char payer_address[128];
    char merchant_address[128];
    int64_t price;
    int64_t order_id;
    struct simnet sim;
    bool sim_ready;
    int64_t funding_value;
    struct uint256 coinbase_txid;
    struct transaction funding_tx;
    struct wallet_tx funding_wallet_tx;
    struct uint256 funding_txid;
    struct wallet *payer;
    struct wallet *merchant;
    bool payer_ready;
    bool merchant_ready;
    struct main_state main_state;
    bool main_ready;
    struct tx_mempool mempool;
    bool mempool_ready;
    struct coins_view null_view;
    struct coins_view_cache coins_tip;
    bool coins_ready;
    char payment_txid_hex[65];
    char send_error[256];
    struct uint256 payment_txid;
    struct transaction payment_tx;
    struct transaction mined_payment;
    bool have_mined_payment;
    bool exact_shape;
    int payment_height;
    bool projected;
    bool tip_ready;
};

static const char *const tstp_chain_labels[TSTP_CHAIN_STEPS] = {
    "chain: merchant catalog is ready",
    "chain: merchant projection database opens",
    "chain: payer and one-time merchant address derive",
    "chain: pending order binds the one-time address",
    "chain: isolated consensus chain initializes",
    "chain: isolated faucet output matures",
    "chain: exact payer funding outpoint enters a block",
    "chain: isolated payer and merchant wallets allocate",
    "chain: payer owns the exact confirmed funding coin",
    "chain: mempool sees the same isolated funding coin",
    "chain: isolated self-derived spend guard opens",
    "chain: real store transparent sender signs and admits",
    "chain: captured bytes bind exact order output and fee",
    "chain: exact signed payment passes connect_block",
    "chain: production wallet projection recovers exact payment",
    "chain: merchant reconciliation fulfills the bound order",
};

static void tstp_chain_free_unseeded_funding(int step, struct tstp_chain *c)
{
    if (step == TSTP_CHAIN_FUNDING || step == TSTP_CHAIN_WALLETS)
        transaction_free(&c->funding_wallet_tx.tx);
}

static void tstp_chain_release(struct tstp_chain *c)
{
    rpc_wallet_set_state(NULL, NULL, NULL, NULL, NULL, NULL);
    rpc_wallet_set_node_db(NULL);
    rpc_wallet_set_coins_tip(NULL);
    reducer_frontier_provable_tip_reset();
    progress_store_close();
    if (c->have_mined_payment)
        transaction_free(&c->mined_payment);
    if (c->coins_ready)
        coins_view_cache_free(&c->coins_tip);
    if (c->mempool_ready)
        tx_mempool_free(&c->mempool);
    if (c->main_ready)
        main_state_free(&c->main_state);
    if (c->merchant_ready)
        wallet_free(c->merchant);
    if (c->payer_ready)
        wallet_free(c->payer);
    free(c->merchant);
    free(c->payer);
    if (c->sim_ready)
        simnet_free(&c->sim);
    if (c->ndb_open)
        node_db_close(&c->ndb);
    memory_cleanse(c->payer_key.vch, sizeof(c->payer_key.vch));
    memory_cleanse(c->merchant_key.vch, sizeof(c->merchant_key.vch));
    test_cleanup_tmpdir(c->datadir);
    test_cleanup_tmpdir(c->trustdir);
}

static struct tstp_chain_result tstp_chain_setup_merchant(int step,
                                                          struct tstp_chain *c)
{
    if (step == TSTP_CHAIN_CATALOG) {
        bool catalog_ok = store_buyer_catalog(c->datadir, c->offers, 8,
                                               &c->offer_count).ok &&
                          c->offer_count > 0;
        return (struct tstp_chain_result){
            .check_ok = catalog_ok,
            .stop = !catalog_ok,
        };
    }
    if (step == TSTP_CHAIN_OPEN) {
        bool opened = tstp_open(c->datadir, &c->ndb);
        return (struct tstp_chain_result){
            .check_ok = opened,
            .stop = !opened,
        };
    }
    if (step == TSTP_CHAIN_IDENTITIES) {
        c->ndb_open = true;
        tstp_key(&c->payer_key, 0x31);
        tstp_key(&c->merchant_key, 0x52);
        bool identities_ok =
            tstp_key_identity(&c->payer_key, &c->payer_id, &c->payer_script,
                              c->payer_address, sizeof(c->payer_address)) &&
            tstp_key_identity(&c->merchant_key, &c->merchant_id,
                              &c->merchant_script, c->merchant_address,
                              sizeof(c->merchant_address));
        return (struct tstp_chain_result){
            .check_ok = identities_ok,
            .stop = !identities_ok,
        };
    }
    c->price = c->offers[0].price_zatoshi;
    c->order_id = tstp_place_order(&c->ndb, c->offers[0].product_id,
                                   c->merchant_address, c->price);
    return (struct tstp_chain_result){
        .check_ok = c->order_id > 0 && c->price > 0,
        .stop = c->order_id <= 0 || c->price <= 0,
    };
}

static struct tstp_chain_result tstp_chain_setup_funding(int step,
                                                         struct tstp_chain *c)
{
    if (step == TSTP_CHAIN_SIM) {
        bool sim_ok = simnet_init(&c->sim);
        return (struct tstp_chain_result){
            .check_ok = sim_ok,
            .stop = !sim_ok,
        };
    }
    if (step == TSTP_CHAIN_FAUCET) {
        c->sim_ready = true;
        c->funding_value = c->price + TSTP_FEE_ZAT;
        int coinbase_height = simnet_tip_height(&c->sim) + 1;
        bool faucet_ok = simnet_mint_coinbase_to(
                             &c->sim, &c->payer_script,
                             c->funding_value + TSTP_FEE_ZAT,
                             &c->coinbase_txid) &&
                         simnet_mint_to_height(
                             &c->sim, coinbase_height + COINBASE_MATURITY);
        return (struct tstp_chain_result){
            .check_ok = faucet_ok,
            .stop = !faucet_ok,
        };
    }
    transaction_init(&c->funding_tx);
    bool funding_built = tstp_build_funding_tx(
        &c->funding_tx, &c->coinbase_txid, &c->payer_script, c->funding_value);
    memset(&c->funding_wallet_tx, 0, sizeof(c->funding_wallet_tx));
    transaction_init(&c->funding_wallet_tx.tx);
    bool funding_copied = funding_built &&
        transaction_copy(&c->funding_wallet_tx.tx, &c->funding_tx);
    c->funding_txid = funding_built
        ? c->funding_tx.hash : (struct uint256){0};
    bool funding_mined = funding_copied &&
        simnet_mint_txs(&c->sim, &c->funding_tx, 1);
    if (funding_built && !funding_copied)
        transaction_free(&c->funding_tx);
    return (struct tstp_chain_result){
        .check_ok = funding_mined &&
            simnet_coin_value(&c->sim, &c->funding_txid, 0, NULL),
        .stop = !funding_mined,
    };
}

static struct tstp_chain_result
tstp_chain_setup_wallets_trust(int step, struct tstp_chain *c)
{
    if (step == TSTP_CHAIN_WALLETS) {
        c->payer = zcl_malloc(sizeof(*c->payer), "store payment payer wallet");
        c->merchant = zcl_malloc(sizeof(*c->merchant),
                                 "store payment merchant wallet");
        bool wallets_allocated = c->payer && c->merchant;
        return (struct tstp_chain_result){
            .check_ok = wallets_allocated,
            .stop = !wallets_allocated,
        };
    }
    if (step == TSTP_CHAIN_SEED) {
        wallet_init(c->payer);
        c->payer_ready = true;
        wallet_init(c->merchant);
        c->merchant_ready = true;
        c->funding_wallet_tx.confirms = 1;
        c->funding_wallet_tx.time_received = 1;
        bool payer_seeded =
            keystore_add_key(&c->payer->keystore, &c->payer_key) &&
            wallet_add_to_wallet(c->payer, &c->funding_wallet_tx);
        transaction_free(&c->funding_wallet_tx.tx);
        bool merchant_seeded =
            keystore_add_key(&c->merchant->keystore, &c->merchant_key);
        c->payer->best_block_height = simnet_tip_height(&c->sim);
        return (struct tstp_chain_result){
            .check_ok = payer_seeded && merchant_seeded,
            .stop = !payer_seeded || !merchant_seeded,
        };
    }
    if (step == TSTP_CHAIN_COIN) {
        main_state_init(&c->main_state);
        c->main_ready = true;
        tx_mempool_init(&c->mempool, 0);
        c->mempool_ready = true;
        memset(&c->null_view, 0, sizeof(c->null_view));
        coins_view_cache_init(&c->coins_tip, &c->null_view);
        c->coins_ready = true;
        struct coins_cache_entry *funding_entry =
            coins_view_cache_modify_new(&c->coins_tip, &c->funding_txid);
        bool coin_stamped = funding_entry != NULL;
        if (funding_entry) {
            coins_alloc(&funding_entry->coins, 1);
            funding_entry->coins.vout[0].value = c->funding_value;
            funding_entry->coins.vout[0].script_pub_key = c->payer_script;
            funding_entry->coins.height = simnet_tip_height(&c->sim);
            funding_entry->coins.version = 1;
            funding_entry->coins.is_coinbase = false;
        }
        return (struct tstp_chain_result){
            .check_ok = coin_stamped,
            .stop = !coin_stamped,
        };
    }
    bool trust_ok = tstp_open_trust_fixture(c->trustdir);
    return (struct tstp_chain_result){
        .check_ok = trust_ok,
        .stop = !trust_ok,
    };
}

static struct tstp_chain_result tstp_chain_send(struct tstp_chain *c)
{
    rpc_wallet_set_state(c->payer, &c->main_state, c->datadir, NULL,
                         &c->mempool, NULL);
    rpc_wallet_set_node_db(NULL);
    rpc_wallet_set_coins_tip(&c->coins_tip);
    bool sent = wallet_direct_sendtoaddress(
        c->merchant_address, c->price, c->payment_txid_hex,
        sizeof(c->payment_txid_hex), c->send_error, sizeof(c->send_error));
    return (struct tstp_chain_result){
        .check_ok = sent && c->payment_txid_hex[0],
        .stop = !sent,
    };
}

static struct tstp_chain_result tstp_chain_capture(struct tstp_chain *c)
{
    uint256_set_hex(&c->payment_txid, c->payment_txid_hex);
    transaction_init(&c->payment_tx);
    bool captured = tx_mempool_lookup(&c->mempool, &c->payment_txid,
                                      &c->payment_tx) &&
                    transaction_copy(&c->mined_payment, &c->payment_tx);
    c->have_mined_payment = captured;
    bool exact_shape = captured && c->payment_tx.num_vin == 1 &&
        c->payment_tx.num_vout == 1 &&
        uint256_eq(&c->payment_tx.vin[0].prevout.hash, &c->funding_txid) &&
        c->payment_tx.vin[0].prevout.n == 0 &&
        c->payment_tx.vout[0].value == c->price &&
        c->payment_tx.vout[0].script_pub_key.size == c->merchant_script.size &&
        memcmp(c->payment_tx.vout[0].script_pub_key.data,
               c->merchant_script.data, c->merchant_script.size) == 0;
    c->exact_shape = exact_shape;
    return (struct tstp_chain_result){
        .check_ok = exact_shape && c->funding_value - c->price == TSTP_FEE_ZAT,
        .stop = false,
    };
}

static struct tstp_chain_result tstp_chain_connect(struct tstp_chain *c)
{
    bool mined = c->exact_shape && simnet_mint_txs(&c->sim, &c->payment_tx, 1);
    if (mined)
        transaction_init(&c->payment_tx); /* ownership moved into simnet */
    else
        transaction_free(&c->payment_tx);
    c->payment_height = simnet_tip_height(&c->sim);
    int64_t paid_value = 0;
    bool chain_settled = mined &&
        !simnet_coin_value(&c->sim, &c->funding_txid, 0, NULL) &&
        simnet_coin_value(&c->sim, &c->payment_txid, 0, &paid_value) &&
        paid_value == c->price;
    return (struct tstp_chain_result){
        .check_ok = chain_settled,
        .stop = !chain_settled,
    };
}

static struct tstp_chain_result tstp_chain_project(struct tstp_chain *c)
{
    bool block_recorded = tstp_seed_tip(&c->ndb, c->payment_height);
    c->projected = block_recorded && node_db_sync_wallet_tx(
        &c->ndb, &c->mined_payment, c->merchant, c->payment_height);
    c->tip_ready = tstp_seed_tip(&c->ndb, c->payment_height + 3);
    int64_t confirmed = c->projected && c->tip_ready
        ? store_confirmed_payment(&c->ndb, c->merchant_address, c->order_id,
                                  c->payment_height)
        : 0;
    return (struct tstp_chain_result){
        .check_ok = c->projected && c->tip_ready && confirmed == c->price,
        .stop = false,
    };
}

static struct tstp_chain_result tstp_chain_reconcile(struct tstp_chain *c)
{
    node_db_close(&c->ndb);
    c->ndb_open = false;
    if (c->projected && c->tip_ready)
        store_process_payments(c->datadir);
    return (struct tstp_chain_result){
        .check_ok = c->projected && c->tip_ready &&
            tstp_order_status(c->datadir, c->order_id) == STORE_ORDER_SENT,
        .stop = false,
    };
}

static struct tstp_chain_result tstp_chain_step(int step, struct tstp_chain *c)
{
    if (step <= TSTP_CHAIN_ORDER)
        return tstp_chain_setup_merchant(step, c);
    if (step <= TSTP_CHAIN_FUNDING)
        return tstp_chain_setup_funding(step, c);
    if (step <= TSTP_CHAIN_TRUST)
        return tstp_chain_setup_wallets_trust(step, c);
    if (step == TSTP_CHAIN_SEND)
        return tstp_chain_send(c);
    if (step == TSTP_CHAIN_CAPTURE)
        return tstp_chain_capture(c);
    if (step == TSTP_CHAIN_CONNECT)
        return tstp_chain_connect(c);
    if (step == TSTP_CHAIN_PROJECT)
        return tstp_chain_project(c);
    return tstp_chain_reconcile(c);
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
    struct tstp_chain chain = {0};

    transaction_init(&chain.mined_payment);
    printf("\n-- exact wallet-built store payment through chain + reconcile --\n");
    test_make_tmpdir(chain.datadir, sizeof(chain.datadir),
                     "store_transparent_pay_chain", "merchant");
    test_make_tmpdir(chain.trustdir, sizeof(chain.trustdir),
                     "store_transparent_pay_chain", "trust");
    for (int step = 0; step < TSTP_CHAIN_STEPS; step++) {
        struct tstp_chain_result result = tstp_chain_step(step, &chain);
        TSTP_CHECK(tstp_chain_labels[step], result.check_ok);
        if (result.stop) {
            tstp_chain_free_unseeded_funding(step, &chain);
            break;
        }
    }
    tstp_chain_release(&chain);
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

    for (size_t i = 0;
         i < sizeof(tstp_matrix_cases) / sizeof(tstp_matrix_cases[0]); i++) {
        const struct tstp_matrix_case *k = &tstp_matrix_cases[i];
        int64_t order_id = 0;

        printf("%s", k->lead);
        bool ok = tstp_matrix_prepare(&ndb, product_id, price, k, &order_id);
        if (ok)
            ok = tstp_matrix_credit(datadir, order_id, k);
        if (ok)
            printf("OK\n");
        else {
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
