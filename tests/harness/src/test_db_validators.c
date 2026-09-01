/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the database validator registry.  Each of the 19 registered
 * tables gets at least one positive case (a valid row passes) and one
 * negative case (a deliberately-broken row fails with a non-empty error
 * message).  We also test the registry primitives: register/unregister,
 * duplicate replacement, unknown-table pass-through, NULL handling,
 * EV_MODEL_VALIDATION_FAILED emission.
 *
 * These tests DO NOT touch SQLite — the validator registry is a pure
 * in-memory surface and can run without a live database.
 */

#include "test/test_core.h"
#include "models/database_validators.h"
#include "models/database.h"
#include "models/block.h"
#include "models/contact.h"
#include "models/file_service.h"
#include "models/mempool_entry.h"
#include "models/onion_announcement.h"
#include "models/peer.h"
#include "models/store.h"
#include "models/tx_index.h"
#include "models/utxo.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"
#include "models/zslp.h"
#include "event/event.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

/* ── Fixture helpers ────────────────────────────────────────── *
 *
 * Each `valid_<model>` helper returns a zeroed-out struct with the
 * minimum set of fields populated so that the model's `_validate()`
 * returns true.  Tests mutate one field to produce the negative case.
 */

static void fill_hash(uint8_t *h, size_t n, uint8_t seed)
{
    for (size_t i = 0; i < n; i++) h[i] = (uint8_t)(seed + i);
}

static struct db_block valid_block(void)
{
    struct db_block b = {0};
    fill_hash(b.hash, 32, 1);
    fill_hash(b.prev_hash, 32, 2);
    fill_hash(b.merkle_root, 32, 3);
    b.height = 100;
    b.time = 1700000000;
    b.bits = 0x1d00ffff;
    b.num_tx = 1;
    return b;
}

static struct db_peer valid_peer(void)
{
    struct db_peer p = {0};
    fill_hash(p.ip, 16, 1);
    p.port = 8033;
    p.last_seen = 1700000000;
    return p;
}

static struct db_file_service valid_file_service(void)
{
    struct db_file_service fs = {0};
    fill_hash(fs.ip, 16, 1);
    fs.port = 8033;
    fs.last_seen = 1700000000;
    return fs;
}

static struct db_tx_index valid_tx_index(void)
{
    struct db_tx_index t = {0};
    fill_hash(t.txid, 32, 1);
    fill_hash(t.block_hash, 32, 2);
    t.block_height = 100;
    return t;
}

static struct db_utxo valid_utxo(void)
{
    struct db_utxo u = {0};
    fill_hash(u.txid, 32, 1);
    u.value = 100000000;
    u.height = 50;
    u.script_len = 25;
    u.script_type = SCRIPT_P2PKH;
    static uint8_t script[32] = {0};
    u.script = script;
    u.has_address = true;
    return u;
}

static struct db_mempool_entry valid_mempool_entry(void)
{
    struct db_mempool_entry e = {0};
    fill_hash(e.txid, 32, 1);
    e.size = 250;
    e.fee = 1000;
    e.time_added = 1700000000;
    e.height_added = 100;
    static uint8_t raw[32] = {0};
    e.raw_tx = raw;
    e.raw_tx_len = 32;
    return e;
}

static struct db_onion_announcement valid_onion(void)
{
    struct db_onion_announcement a = {0};
    snprintf(a.onion_address, sizeof(a.onion_address),
             "abcdefghijklmnopqrstuvwxyz234567.onion");
    a.announced_at = 1700000000;
    return a;
}

static struct db_contact valid_contact(void)
{
    struct db_contact c = {0};
    snprintf(c.name, sizeof(c.name), "alice");
    snprintf(c.address, sizeof(c.address), "t1TestContactAddr");
    c.last_used = 1700000000;
    return c;
}

static struct db_store_product valid_store_product(void)
{
    struct db_store_product p = {0};
    p.id = 1;
    snprintf(p.name, sizeof(p.name), "Test Product");
    snprintf(p.description, sizeof(p.description), "A test product");
    p.price_zatoshi = 100000;
    p.tokens_per_purchase = 1;
    p.active = true;
    return p;
}

static struct db_store_order valid_store_order(void)
{
    struct db_store_order o = {0};
    o.id = 1;
    o.product_id = 1;
    snprintf(o.customer_addr, sizeof(o.customer_addr), "t1TestAddress");
    snprintf(o.payment_addr, sizeof(o.payment_addr), "t1PayAddress");
    o.amount_zatoshi = 100000;
    o.status = STORE_ORDER_PENDING;
    o.created_at = 1700000000;
    return o;
}

static struct db_wallet_key valid_wallet_key(void)
{
    struct db_wallet_key k = {0};
    fill_hash(k.pubkey_hash, 20, 1);
    fill_hash(k.pubkey, 33, 2);
    k.pubkey_len = 33;
    k.compressed = true;
    fill_hash(k.privkey, 32, 3);
    k.created_at = 1700000000;
    return k;
}

static struct db_sapling_key valid_sapling_key(void)
{
    struct db_sapling_key k = {0};
    fill_hash(k.ivk, 32, 1);
    fill_hash(k.xsk, 169, 2);
    fill_hash(k.xfvk, 169, 3);
    fill_hash(k.diversifier, 11, 4);
    fill_hash(k.pk_d, 32, 5);
    snprintf(k.address, sizeof(k.address), "zs1testaddress");
    return k;
}

static struct db_wallet_script valid_wallet_script(void)
{
    struct db_wallet_script s = {0};
    fill_hash(s.script_hash, 20, 1);
    static uint8_t script[64] = {0};
    s.redeem_script = script;
    s.script_len = 64;
    return s;
}

static struct db_wallet_tx valid_wallet_tx(void)
{
    struct db_wallet_tx t = {0};
    fill_hash(t.txid, 32, 1);
    t.time_received = 1700000000;
    return t;
}

static struct db_wallet_utxo valid_wallet_utxo(void)
{
    struct db_wallet_utxo u = {0};
    fill_hash(u.txid, 32, 1);
    u.value = 100000000;
    u.height = 50;
    static uint8_t script[25] = {0};
    u.script = script;
    u.script_len = 25;
    return u;
}

static struct db_sapling_note valid_sapling_note(void)
{
    struct db_sapling_note n = {0};
    fill_hash(n.txid, 32, 1);
    n.value = 100000000;
    fill_hash(n.ivk, 32, 2);
    fill_hash(n.nullifier, 32, 3);
    fill_hash(n.cm, 32, 4);
    fill_hash(n.pk_d, 32, 5);
    fill_hash(n.diversifier, 11, 6);
    fill_hash(n.rcm, 32, 7);
    n.memo_len = 0;
    n.block_height = 100;
    snprintf(n.source, sizeof(n.source), "%s", DB_SAPLING_NOTE_SOURCE_LOCAL);
    return n;
}

static struct db_zslp_balance valid_zslp_balance(void)
{
    struct db_zslp_balance b = {0};
    snprintf(b.token_id, sizeof(b.token_id), "TESTCOIN");
    snprintf(b.address, sizeof(b.address), "t1TestZslpAddress");
    b.balance = 10000;
    return b;
}

static struct node_db_status valid_db_status(void)
{
    struct node_db_status s = {0};
    s.open = true;
    s.sync_batch_size = 100;
    s.sync_pending_blocks = 5;
    s.last_activity_time = 1700000000;
    s.last_sqlite_rc = 0;
    return s;
}

/* ── Registry primitives ────────────────────────────────────── */

static int test_registry_empty(void)
{
    int failures = 0;
    TEST("validator registry starts empty after reset") {
        db_validator_reset();
        ASSERT(db_validator_count() == 0);
        ASSERT(!db_validator_has("peers"));
        ASSERT(db_validator_table_at(0) == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static bool stub_pass(const void *row, char *err, size_t cap)
{
    (void)row; (void)err; (void)cap;
    return true;
}

static bool stub_fail(const void *row, char *err, size_t cap)
{
    (void)row;
    if (err && cap > 0) snprintf(err, cap, "stubbed failure");
    return false;
}

static int test_registry_register(void)
{
    int failures = 0;
    TEST("db_register_validator adds entries") {
        db_validator_reset();
        db_register_validator("table_a", stub_pass);
        db_register_validator("table_b", stub_fail);
        ASSERT(db_validator_count() == 2);
        ASSERT(db_validator_has("table_a"));
        ASSERT(db_validator_has("table_b"));
        ASSERT(!db_validator_has("unknown"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_registry_duplicate_replaces(void)
{
    int failures = 0;
    TEST("registering the same table twice replaces in-place") {
        db_validator_reset();
        db_register_validator("dup", stub_pass);
        db_register_validator("dup", stub_fail);
        ASSERT(db_validator_count() == 1);
        char err[64];
        ASSERT(!db_run_validators_for("dup", "x", err, sizeof(err)));
        ASSERT(strstr(err, "stubbed failure") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_registry_unregister(void)
{
    int failures = 0;
    TEST("db_register_validator with NULL fn unregisters") {
        db_validator_reset();
        db_register_validator("one", stub_pass);
        db_register_validator("two", stub_pass);
        db_register_validator("one", NULL);
        ASSERT(db_validator_count() == 1);
        ASSERT(!db_validator_has("one"));
        ASSERT(db_validator_has("two"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_registry_unknown_pass(void)
{
    int failures = 0;
    TEST("unknown tables pass through (no validator == no constraint)") {
        db_validator_reset();
        char err[64] = "pre-existing";
        ASSERT(db_run_validators_for("nosuch", "x", err, sizeof(err)));
        ASSERT(err[0] == '\0');  /* err is cleared on call */
        PASS();
    } _test_next:;
    return failures;
}

static int test_registry_null_row(void)
{
    int failures = 0;
    TEST("null row fails with error message") {
        db_validator_reset();
        db_register_validator("t", stub_pass);
        char err[64];
        ASSERT(!db_run_validators_for("t", NULL, err, sizeof(err)));
        ASSERT(err[0] != '\0');
        PASS();
    } _test_next:;
    return failures;
}

static int test_registry_register_all(void)
{
    int failures = 0;
    TEST("db_register_all_validators wires all registered tables") {
        db_validator_reset();
        db_register_all_validators();
        ASSERT(db_validator_count() == 30);
        ASSERT(db_validator_has("blocks"));
        ASSERT(db_validator_has("peers"));
        ASSERT(db_validator_has("utxos"));
        ASSERT(db_validator_has("wallet_transactions"));
        ASSERT(db_validator_has("wallet_sapling_notes"));
        ASSERT(db_validator_has("zslp_balances"));
        ASSERT(db_validator_has("zslp_tokens"));
        ASSERT(db_validator_has("zswap_ads"));
        ASSERT(db_validator_has("shop_wants"));
        ASSERT(db_validator_has("database"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_registry_idempotent(void)
{
    int failures = 0;
    TEST("db_register_all_validators is idempotent") {
        db_validator_reset();
        db_register_all_validators();
        int first = db_validator_count();
        db_register_all_validators();
        ASSERT(db_validator_count() == first);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Per-model positive + negative tests ──────────────────── */

/* Macro to cut boilerplate: build a fixture, run positive and negative
 * validators, assert the expected outcomes. */
#define MODEL_CASE(label, table, fixture_fn, break_stmt) do { \
    TEST(label) { \
        db_validator_reset(); \
        db_register_all_validators(); \
        char err[256]; \
        typeof(fixture_fn()) _row = fixture_fn(); \
        ASSERT(db_run_validators_for((table), &_row, err, sizeof(err))); \
        ASSERT(err[0] == '\0'); \
        { typeof(_row) *r = &_row; break_stmt; } \
        ASSERT(!db_run_validators_for((table), &_row, err, sizeof(err))); \
        ASSERT(err[0] != '\0'); \
        PASS(); \
    } _test_next:; \
} while (0)

static int test_block_validator(void)
{
    int failures = 0;
    MODEL_CASE("blocks: positive + negative",
               "blocks", valid_block,
               r->bits = 0);  /* bits=0 fails validates_not_zero */
    return failures;
}

static int test_peer_validator(void)
{
    int failures = 0;
    MODEL_CASE("peers: positive + negative",
               "peers", valid_peer,
               r->port = 0);  /* port=0 fails validates_not_zero */
    return failures;
}

static int test_file_service_validator(void)
{
    int failures = 0;
    MODEL_CASE("file_services: positive + negative",
               "file_services", valid_file_service,
               r->port = 0);
    return failures;
}

static int test_tx_index_validator(void)
{
    int failures = 0;
    MODEL_CASE("tx_index: positive + negative",
               "tx_index", valid_tx_index,
               memset(r->txid, 0, 32));  /* blank txid */
    return failures;
}

static int test_utxo_validator(void)
{
    int failures = 0;
    MODEL_CASE("utxos: positive + negative",
               "utxos", valid_utxo,
               r->value = -1);  /* negative money */
    return failures;
}

static int test_mempool_validator(void)
{
    int failures = 0;
    MODEL_CASE("mempool: positive + negative",
               "mempool", valid_mempool_entry,
               r->size = 0);  /* size must be positive */
    return failures;
}

static int test_onion_validator(void)
{
    int failures = 0;
    MODEL_CASE("onion_announcements: positive + negative",
               "onion_announcements", valid_onion,
               r->onion_address[0] = '\0');  /* blank addr */
    return failures;
}

static int test_contact_validator(void)
{
    int failures = 0;
    MODEL_CASE("contacts: positive + negative",
               "contacts", valid_contact,
               r->name[0] = '\0');  /* blank name */
    return failures;
}

static int test_store_product_validator(void)
{
    int failures = 0;
    MODEL_CASE("store_products: positive + negative",
               "store_products", valid_store_product,
               r->name[0] = '\0');
    return failures;
}

static int test_store_order_validator(void)
{
    int failures = 0;
    MODEL_CASE("store_orders: positive + negative",
               "store_orders", valid_store_order,
               r->amount_zatoshi = -1);
    return failures;
}

static int test_wallet_key_validator(void)
{
    int failures = 0;
    MODEL_CASE("wallet_keys: positive + negative",
               "wallet_keys", valid_wallet_key,
               r->pubkey_len = 10);  /* wrong size */
    return failures;
}

static int test_sapling_key_validator(void)
{
    int failures = 0;
    MODEL_CASE("wallet_sapling_keys: positive + negative",
               "wallet_sapling_keys", valid_sapling_key,
               memset(r->ivk, 0, 32));  /* blank ivk */
    return failures;
}

static int test_wallet_script_validator(void)
{
    int failures = 0;
    MODEL_CASE("wallet_scripts: positive + negative",
               "wallet_scripts", valid_wallet_script,
               r->script_len = 0);  /* must be positive */
    return failures;
}

static int test_wallet_tx_validator(void)
{
    int failures = 0;
    MODEL_CASE("wallet_transactions: positive + negative",
               "wallet_transactions", valid_wallet_tx,
               memset(r->txid, 0, 32));  /* blank txid */
    return failures;
}

static int test_wallet_utxo_validator(void)
{
    int failures = 0;
    MODEL_CASE("wallet_utxos: positive + negative",
               "wallet_utxos", valid_wallet_utxo,
               r->value = -1);
    return failures;
}

static int test_sapling_note_validator(void)
{
    int failures = 0;
    {
        MODEL_CASE("wallet_sapling_notes: positive + negative",
                   "wallet_sapling_notes", valid_sapling_note,
                   memset(r->nullifier, 0, 32));
    }
    {
        printf("db_validators: wallet_sapling_notes rejects invalid source... ");
        db_validator_reset();
        db_register_all_validators();
        char err[256];
        struct db_sapling_note row = valid_sapling_note();
        snprintf(row.source, sizeof(row.source), "%s", "unknown");
        if (!db_run_validators_for("wallet_sapling_notes", &row, err,
                                   sizeof(err)) &&
            err[0] != '\0') {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
    }
    return failures;
}

static int test_zslp_balance_validator(void)
{
    int failures = 0;
    MODEL_CASE("zslp_balances: positive + negative",
               "zslp_balances", valid_zslp_balance,
               r->balance = -1);
    return failures;
}

static int test_zslp_token_validator(void)
{
    int failures = 0;
    /* zslp_tokens wraps the string-keyed validator — row is a char * */
    TEST("zslp_tokens: positive + negative") {
        db_validator_reset();
        db_register_all_validators();
        char err[128];
        /* Positive: alphanumeric key */
        ASSERT(db_run_validators_for("zslp_tokens", "TESTCOIN", err, sizeof(err)));
        ASSERT(err[0] == '\0');
        /* Negative: empty key */
        ASSERT(!db_run_validators_for("zslp_tokens", "", err, sizeof(err)));
        ASSERT(err[0] != '\0');
        PASS();
    } _test_next:;
    return failures;
}

static int test_database_validator(void)
{
    int failures = 0;
    MODEL_CASE("database (meta): positive + negative",
               "database", valid_db_status,
               r->sync_batch_size = -99);
    return failures;
}

/* ── Event emission ──────────────────────────────────────── */

static int g_emit_count = 0;
static char g_last_payload[256];

static void count_emit(enum event_type type, uint32_t peer_id,
                       const void *payload, uint32_t payload_len,
                       void *ctx)
{
    (void)peer_id; (void)ctx;
    if (type != EV_MODEL_VALIDATION_FAILED) return;
    g_emit_count++;
    size_t n = payload_len < sizeof(g_last_payload) - 1
               ? payload_len : sizeof(g_last_payload) - 1;
    if (payload && n > 0) memcpy(g_last_payload, payload, n);
    g_last_payload[n] = '\0';
}

static int test_event_emission(void)
{
    int failures = 0;
    TEST("failing validation emits EV_MODEL_VALIDATION_FAILED") {
        db_validator_reset();
        db_register_all_validators();
        g_emit_count = 0;
        g_last_payload[0] = '\0';

        /* Install observer */
        event_clear_observers(EV_MODEL_VALIDATION_FAILED);
        event_observe(EV_MODEL_VALIDATION_FAILED, count_emit, NULL);

        struct db_peer bad = valid_peer();
        bad.port = 0;
        char err[128];
        ASSERT(!db_run_validators_for("peers", &bad, err, sizeof(err)));
        ASSERT(g_emit_count >= 1);
        ASSERT(strstr(g_last_payload, "model=peers") != NULL);
        ASSERT(strstr(g_last_payload, "errors=") != NULL);

        event_clear_observers(EV_MODEL_VALIDATION_FAILED);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ────────────────────────────────────────── */

int test_db_validators(void);

int test_db_validators(void)
{
    int failures = 0;
    event_log_init();

    /* Registry primitives */
    failures += test_registry_empty();
    failures += test_registry_register();
    failures += test_registry_duplicate_replaces();
    failures += test_registry_unregister();
    failures += test_registry_unknown_pass();
    failures += test_registry_null_row();
    failures += test_registry_register_all();
    failures += test_registry_idempotent();

    /* Per-model positive + negative */
    failures += test_block_validator();
    failures += test_peer_validator();
    failures += test_file_service_validator();
    failures += test_tx_index_validator();
    failures += test_utxo_validator();
    failures += test_mempool_validator();
    failures += test_onion_validator();
    failures += test_contact_validator();
    failures += test_store_product_validator();
    failures += test_store_order_validator();
    failures += test_wallet_key_validator();
    failures += test_sapling_key_validator();
    failures += test_wallet_script_validator();
    failures += test_wallet_tx_validator();
    failures += test_wallet_utxo_validator();
    failures += test_sapling_note_validator();
    failures += test_zslp_balance_validator();
    failures += test_zslp_token_validator();
    failures += test_database_validator();

    /* Event emission */
    failures += test_event_emission();

    /* Leave registry registered so sibling suites see the validators. */
    db_validator_reset();
    db_register_all_validators();

    return failures;
}
