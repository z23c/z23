/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_wallet_summary_history: core.wallet.summary and core.wallet.history
 * over an isolated node.db fixture. Notes, coins and transaction rows are
 * written through the production models; the summary and history are read
 * back through the same fact readers the node RPCs use. No wallet, key, node
 * or network is involved. */

#include "test/test_core.h"

#include "controllers/sovereignty_controller.h"
#include "controllers/sync_controller.h"
#include "controllers/wallet_activity.h"
#include "json/json.h"
#include "models/block.h"
#include "models/database.h"
#include "models/wallet_activity.h"
#include "models/wallet_tx.h"
#include "sapling/sapling.h"
#include "wallet/sapling_keys.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZCL1 100000000LL
#define FEE 10000LL
#define TIP 300

static uint8_t IVK_A[32];
static uint8_t IVK_B[32];

struct whf {
    struct db_wallet_note_fact *notes;
    struct db_wallet_coin_fact *coins;
    struct db_wallet_tx_fact *txs;
    int nn, nc, nt;
};

static bool put_block(struct node_db *ndb, int height)
{
    struct db_block blk;
    static uint8_t sol[] = { 0x01, 0x02 };
    memset(&blk, 0, sizeof(blk));
    memset(blk.hash, 0x40 + (height & 0x3f), 32);
    memset(blk.prev_hash, 0x0b, 32);
    memset(blk.merkle_root, 0x0c, 32);
    memset(blk.chain_work, 0x0d, 32);
    blk.height = height;
    blk.time = 1700000000 + height;
    blk.bits = 0x1d00ffffU;
    blk.status = 3;
    blk.solution = sol;
    blk.solution_len = sizeof(sol);
    return db_block_save(ndb, &blk);
}

static bool put_note(struct node_db *ndb, uint8_t tx, uint32_t idx,
                     const uint8_t ivk[32], int64_t value, int height,
                     const char *memo_text)
{
    uint8_t txid[32], rcm[32], div[11], pk_d[32], cm[32], nf[32], memo[512];
    memset(txid, tx, 32);
    memset(rcm, 0x05, 32);
    memset(div, 0x07, 11);
    memset(pk_d, 0x08, 32);
    memset(cm, tx, 32);
    cm[0] = (uint8_t)idx;
    memset(nf, tx ^ 0x5a, 32);
    nf[0] = (uint8_t)idx;
    memset(memo, 0xf6, sizeof(memo));
    if (memo_text)
        memcpy(memo, memo_text, strlen(memo_text));
    return node_db_sync_sapling_note(ndb, txid, idx, value, rcm, memo, 512,
                                     ivk, div, pk_d, cm, nf, height);
}

static bool spend_note(struct node_db *ndb, uint8_t tx, uint32_t idx,
                       uint8_t spender)
{
    uint8_t nf[32], by[32];
    memset(nf, tx ^ 0x5a, 32);
    nf[0] = (uint8_t)idx;
    memset(by, spender, 32);
    return db_sapling_note_mark_spent(ndb, nf, by) == DB_MARK_SPENT_OK;
}

static bool put_coin(struct node_db *ndb, uint8_t tx, int64_t value,
                     int height, bool coinbase)
{
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    memset(u.txid, tx, 32);
    memset(u.address_hash, 0x11, 20);
    u.value = value;
    u.height = height;
    u.is_coinbase = coinbase;
    u.script = (uint8_t *)"\x76\xa9\x14\x00\x88\xac";
    u.script_len = 6;
    return db_wallet_utxo_save(ndb, &u);
}

static bool put_tx(struct node_db *ndb, uint8_t tx, int height, int64_t fee,
                   bool from_me)
{
    struct db_wallet_tx t;
    static uint8_t raw[] = { 0x01 };
    memset(&t, 0, sizeof(t));
    memset(t.txid, tx, 32);
    t.raw_tx = raw;
    t.raw_tx_len = sizeof(raw);
    t.has_block = height > 0;
    if (t.has_block) {
        memset(t.block_hash, 0x40 + (height & 0x3f), 32);
        t.block_height = height;
    }
    t.time_received = 1700000000 + (height > 0 ? height : 400);
    t.from_me = from_me;
    t.fee = fee;
    return db_wallet_tx_save(ndb, &t);
}

static bool load(struct node_db *ndb, struct whf *f)
{
    memset(f, 0, sizeof(*f));
    f->nn = db_wallet_note_facts_alloc(ndb, &f->notes);
    f->nc = db_wallet_coin_facts_alloc(ndb, &f->coins);
    f->nt = db_wallet_tx_facts_alloc(ndb, &f->txs);
    return f->nn >= 0 && f->nc >= 0 && f->nt >= 0;
}

static void unload(struct whf *f)
{
    free(f->notes);
    free(f->coins);
    free(f->txs);
}

static bool summarize(struct node_db *ndb, const uint8_t (*ivks)[32],
                      size_t nk, struct wallet_summary *out)
{
    struct whf f;
    if (!load(ndb, &f))
        return false;
    wallet_summary_accumulate(f.notes, (size_t)f.nn, f.coins, (size_t)f.nc,
                              f.txs, (size_t)f.nt, ivks, nk, TIP, out);
    unload(&f);
    return true;
}

/* Received at 1/9/10 confirmations, own change at 2/3, a spent note, a note
 * of a key that is not loaded. */
static bool build_fixture_notes(struct node_db *ndb)
{
    bool ok = put_block(ndb, TIP);
    ok = ok && put_note(ndb, 0x11, 0, IVK_A, 1 * ZCL1, 300, NULL);
    ok = ok && put_note(ndb, 0x12, 0, IVK_A, 2 * ZCL1, 292, NULL);
    ok = ok && put_note(ndb, 0x13, 0, IVK_A, 4 * ZCL1, 291, "hello memo");
    ok = ok && put_note(ndb, 0x14, 0, IVK_A, 64 * ZCL1, 250, NULL);
    ok = ok && spend_note(ndb, 0x14, 0, 0x20);
    ok = ok && put_note(ndb, 0x20, 0, IVK_A, 16 * ZCL1, 299, NULL);
    ok = ok && put_note(ndb, 0x20, 1, IVK_A, 32 * ZCL1, 298, NULL);
    ok = ok && put_tx(ndb, 0x20, 299, FEE, true);
    ok = ok && put_note(ndb, 0x15, 0, IVK_B, 100 * ZCL1, 100, NULL);
    return ok;
}

/* A pending send, an internal move with a fee, and a send of unknown fee. */
static bool build_fixture_moves(struct node_db *ndb)
{
    bool ok = put_note(ndb, 0x16, 0, IVK_A, 128 * ZCL1, 200, NULL);
    ok = ok && spend_note(ndb, 0x16, 0, 0x21);
    ok = ok && put_tx(ndb, 0x21, 0, FEE, true);
    ok = ok && put_note(ndb, 0x17, 0, IVK_A, 20 * ZCL1, 210, NULL);
    ok = ok && spend_note(ndb, 0x17, 0, 0x22);
    ok = ok && put_note(ndb, 0x22, 0, IVK_A, 20 * ZCL1 - FEE, 211, NULL);
    ok = ok && put_tx(ndb, 0x22, 211, FEE, true);
    ok = ok && put_note(ndb, 0x18, 0, IVK_A, 9 * ZCL1, 220, NULL);
    ok = ok && spend_note(ndb, 0x18, 0, 0x23);
    ok = ok && put_note(ndb, 0x23, 0, IVK_A, 4 * ZCL1, 295, NULL);
    ok = ok && put_tx(ndb, 0x23, 295, 0, true);
    return ok;
}

static bool build_fixture(struct node_db *ndb)
{
    bool ok = build_fixture_notes(ndb) && build_fixture_moves(ndb);
    ok = ok && put_coin(ndb, 0x31, 5 * ZCL1, 200, true);
    ok = ok && put_coin(ndb, 0x32, 7 * ZCL1, 201, true);
    ok = ok && put_coin(ndb, 0x33, 3 * ZCL1, 250, false);
    return ok;
}

#define SPENDABLE_EXPECT (4 * ZCL1 + 32 * ZCL1 + (20 * ZCL1 - FEE) + 4 * ZCL1)

static int test_summary_thresholds(struct node_db *ndb)
{
    int failures = 0;
    TEST_CASE("wallet_summary: 1/9/10 received, 2/3 change, spent and "
              "unloaded excluded") {
        struct wallet_summary s;
        ASSERT(summarize(ndb, (const uint8_t (*)[32])&IVK_A, 1, &s));
        ASSERT_EQ(s.spendable, SPENDABLE_EXPECT);
        ASSERT_EQ(s.pending, 1 * ZCL1 + 2 * ZCL1 + 16 * ZCL1);
        ASSERT_EQ(s.pending_count, 3);
        ASSERT_EQ(s.pending_min_confs_needed, 1);
        ASSERT_EQ(s.sending, 128 * ZCL1);
        ASSERT_EQ(s.public_confirmed, 8 * ZCL1);
        ASSERT_EQ(s.immature, 7 * ZCL1);
        ASSERT_EQ(s.public_confirmed, db_wallet_utxo_spendable_balance(ndb, NULL));
    } TEST_END
    return failures;
}

static int test_summary_double_count(struct node_db *ndb)
{
    int failures = 0;
    TEST_CASE("wallet_summary: repeated ivk and repeated row count once") {
        uint8_t twice[3][32];
        struct wallet_summary one, dup;
        memcpy(twice[0], IVK_A, 32);
        memcpy(twice[1], IVK_A, 32);
        memcpy(twice[2], IVK_A, 32);
        ASSERT(summarize(ndb, (const uint8_t (*)[32])&IVK_A, 1, &one));
        ASSERT(summarize(ndb, (const uint8_t (*)[32])twice, 3, &dup));
        ASSERT_EQ(dup.spendable, one.spendable);
        ASSERT_EQ(dup.pending, one.pending);

        struct whf f;
        ASSERT(load(ndb, &f));
        size_t n = (size_t)f.nn;
        struct db_wallet_note_fact *rows = calloc(n * 2, sizeof(*rows));
        ASSERT(rows != NULL);
        for (size_t i = 0; i < n; i++)
            rows[2 * i] = rows[2 * i + 1] = f.notes[i];
        struct wallet_summary rep;
        wallet_summary_accumulate(rows, n * 2, f.coins, (size_t)f.nc, f.txs,
                                  (size_t)f.nt,
                                  (const uint8_t (*)[32])&IVK_A, 1, TIP, &rep);
        ASSERT_EQ(rep.spendable, one.spendable);
        ASSERT_EQ(rep.pending, one.pending);
        ASSERT_EQ(rep.pending_count, one.pending_count);
        free(rows);
        unload(&f);
    } TEST_END
    return failures;
}

static int test_summary_reorg(struct node_db *ndb)
{
    int failures = 0;
    TEST_CASE("wallet_summary: a reorged-out note is gone") {
        struct wallet_summary before, after;
        ASSERT(summarize(ndb, (const uint8_t (*)[32])&IVK_A, 1, &before));
        uint8_t gone[32];
        memset(gone, 0x13, sizeof(gone));
        ASSERT(db_sapling_note_delete_for_tx(ndb, gone));
        ASSERT(summarize(ndb, (const uint8_t (*)[32])&IVK_A, 1, &after));
        ASSERT_EQ(after.spendable, before.spendable - 4 * ZCL1);
    } TEST_END
    return failures;
}

static int test_summary_json(void)
{
    int failures = 0;
    TEST_CASE("wallet_summary: chain state and send gate render both states") {
        struct wallet_summary s = { .spendable = 5999990000LL };
        struct wallet_chain_view v = { .tip_height = 300, .header_height = 305,
            .peer_best_height = 303, .scanned_through = 300, .encrypted = true,
            .locked = true, .shielded_keys = 2 };
        struct json_value j;
        json_init(&j);
        wallet_summary_to_json(&s, &v, true, "", &j);
        ASSERT_STR_EQ(json_get_str(json_get(&j, "spendable")), "59.99990000");
        ASSERT_EQ(json_get_int(json_get(&j, "blocks_behind")), 5);
        ASSERT(!json_get_bool(json_get(&j, "current")));
        ASSERT(json_get_bool(json_get(&j, "locked")));
        ASSERT(json_get_bool(json_get(&j, "send_allowed")));
        ASSERT_STR_EQ(json_get_str(json_get(&j, "send_blocked_reason")), "");
        json_free(&j);

        v.header_height = 301;
        v.peer_best_height = 0;
        json_init(&j);
        wallet_summary_to_json(&s, &v, false, "release_assisted", &j);
        ASSERT_EQ(json_get_int(json_get(&j, "blocks_behind")), 1);
        ASSERT(json_get_bool(json_get(&j, "current")));
        ASSERT(!json_get_bool(json_get(&j, "send_allowed")));
        ASSERT_STR_EQ(json_get_str(json_get(&j, "send_blocked_reason")),
                      "release_assisted");
        json_free(&j);

        v.scanned_through = 299;
        json_init(&j);
        wallet_summary_to_json(&s, &v, true, "", &j);
        ASSERT(!json_get_bool(json_get(&j, "current")));
        json_free(&j);
    } TEST_END
    return failures;
}

static int test_send_gate(void)
{
    int failures = 0;
    TEST_CASE("wallet_summary: send gate is the wallet_spend guard") {
        char via_gate[96] = {0}, direct[96] = {0};
        bool a = wallet_send_gate(via_gate, sizeof(via_gate));
        bool b = sovereignty_guard_allow("wallet_spend", direct, sizeof(direct));
        ASSERT(a == b);
        ASSERT(a || via_gate[0] != '\0');
    } TEST_END
    return failures;
}

static const struct wallet_history_entry *find(
    const struct wallet_history_entry *e, int n, uint8_t seed)
{
    uint8_t id[32];
    memset(id, seed, 32);
    for (int i = 0; i < n; i++)
        if (memcmp(e[i].txid, id, 32) == 0)
            return &e[i];
    return NULL;
}

static int build_history(struct node_db *ndb, struct wallet_history_entry **e)
{
    struct whf f;
    if (!load(ndb, &f))
        return -1;
    int n = wallet_history_build(f.notes, (size_t)f.nn, f.coins, (size_t)f.nc,
                                 f.txs, (size_t)f.nt,
                                 (const uint8_t (*)[32])&IVK_A, 1, TIP, e);
    unload(&f);
    return n;
}

static int test_history_outgoing(const struct wallet_history_entry *e, int n)
{
    int failures = 0;
    TEST_CASE("wallet_history: sent, pending, internal, unknown") {
        const struct wallet_history_entry *s = find(e, n, 0x20);
        ASSERT(s && s->direction == WALLET_DIR_SENT);
        ASSERT_EQ(s->amount, 16 * ZCL1 - FEE);
        ASSERT_EQ(s->fee, FEE);
        ASSERT_EQ(s->net, -16 * ZCL1);
        const struct wallet_history_entry *p = find(e, n, 0x21);
        ASSERT(p && p->direction == WALLET_DIR_SENT && p->height == 0);
        ASSERT_EQ(p->confirmations, 0);
        ASSERT(e[0].height == 0);
        const struct wallet_history_entry *in = find(e, n, 0x22);
        ASSERT(in && in->direction == WALLET_DIR_INTERNAL);
        ASSERT(in->fee_known && in->fee == FEE && in->amount == 0);
        const struct wallet_history_entry *u = find(e, n, 0x23);
        ASSERT(u && u->direction == WALLET_DIR_UNKNOWN);
        ASSERT(!u->amount_known && !u->fee_known);
        ASSERT_EQ(u->net, -5 * ZCL1);
    } TEST_END
    return failures;
}

static int test_history_received(const struct wallet_history_entry *e, int n)
{
    int failures = 0;
    TEST_CASE("wallet_history: received entries") {
        const struct wallet_history_entry *r = find(e, n, 0x12);
        ASSERT(r && r->direction == WALLET_DIR_RECEIVED && r->amount == 2 * ZCL1);
        ASSERT(r->height == 292 && r->confirmations == 9 && r->private_kind);
        const struct wallet_history_entry *m = find(e, n, 0x13);
        ASSERT(m && m->memo_present && !r->memo_present);
        const struct wallet_history_entry *c = find(e, n, 0x31);
        ASSERT(c && c->direction == WALLET_DIR_RECEIVED && !c->private_kind);
        ASSERT(find(e, n, 0x15) == NULL);
    } TEST_END
    return failures;
}

static int test_history_directions(struct node_db *ndb)
{
    struct wallet_history_entry *e = NULL;
    int n = build_history(ndb, &e);
    int failures = n > 0 ? 0 : 1;
    if (n > 0) {
        failures += test_history_received(e, n);
        failures += test_history_outgoing(e, n);
    }
    free(e);
    return failures;
}

static int page_all(const struct wallet_history_entry *e, int n, size_t limit,
                    uint8_t *order, int max)
{
    struct wallet_history_cursor cur = {0};
    int got = 0;
    for (;;) {
        size_t start = wallet_history_page_start(e, (size_t)n, &cur);
        if (start >= (size_t)n)
            return got;
        size_t end = start + limit < (size_t)n ? start + limit : (size_t)n;
        for (size_t i = start; i < end && got < max; i++)
            order[got++] = e[i].txid[0];
        char text[96];
        wallet_history_cursor_format(&e[end - 1], text, sizeof(text));
        if (!wallet_history_cursor_parse(text, &cur))
            return -1;
    }
}

static int test_history_paging(struct node_db *ndb)
{
    int failures = 0;
    TEST_CASE("wallet_history: paging with a cursor is stable and complete") {
        struct wallet_history_entry *e = NULL;
        int n = build_history(ndb, &e);
        ASSERT(n > 4);
        uint8_t whole[64], paged[64];
        ASSERT_EQ(page_all(e, n, (size_t)n, whole, 64), n);
        ASSERT_EQ(page_all(e, n, 3, paged, 64), n);
        ASSERT(memcmp(whole, paged, (size_t)n) == 0);
        ASSERT_EQ(page_all(e, n, 1, paged, 64), n);
        ASSERT(memcmp(whole, paged, (size_t)n) == 0);

        /* A newer transaction arriving between pages leaves the next page. */
        struct wallet_history_cursor cur = {0};
        char text[96];
        wallet_history_cursor_format(&e[2], text, sizeof(text));
        ASSERT(wallet_history_cursor_parse(text, &cur));
        uint8_t next_before = e[wallet_history_page_start(e, (size_t)n, &cur)]
                                  .txid[0];
        ASSERT(put_note(ndb, 0x77, 0, IVK_A, ZCL1, 300, NULL));
        struct wallet_history_entry *e2 = NULL;
        int n2 = build_history(ndb, &e2);
        ASSERT_EQ(n2, n + 1);
        ASSERT_EQ(e2[wallet_history_page_start(e2, (size_t)n2, &cur)].txid[0],
                  next_before);
        ASSERT(!wallet_history_cursor_parse("", &cur));
        ASSERT(!wallet_history_cursor_parse("12:zz", &cur));
        ASSERT(!wallet_history_cursor_parse("0:00", &cur));
        free(e2);
        free(e);
    } TEST_END
    return failures;
}

static int test_history_json(struct node_db *ndb)
{
    int failures = 0;
    TEST_CASE("wallet_history: list entries carry no memo text, fit budget") {
        struct wallet_history_entry *e = NULL;
        int n = build_history(ndb, &e);
        ASSERT(n > 0);
        size_t total = 0;
        for (int i = 0; i < n && i < WALLET_HISTORY_MAX_LIMIT; i++) {
            struct json_value j;
            json_init(&j);
            wallet_history_entry_to_json(&e[i], &j);
            char text[1024];
            ASSERT(json_write(&j, text, sizeof(text)) > 0);
            ASSERT(strstr(text, "hello") == NULL);
            ASSERT(strstr(text, "\"memo\"") == NULL);
            ASSERT(strstr(text, "memo_present") != NULL);
            total += strlen(text) + 1;
            json_free(&j);
        }
        ASSERT(total < 6500);
        free(e);
    } TEST_END
    return failures;
}

static int test_latest_address(struct node_db *ndb)
{
    int failures = 0;
    TEST_CASE("wallet_latest: null when empty, newest when present, creates nothing") {
        struct sapling_keystore ks;
        char got[128] = {0}, want[128] = {0};
        struct whf before, after;
        sapling_keystore_init(&ks);
        ASSERT(load(ndb, &before));
        ASSERT(!wallet_latest_shielded_address(&ks, "zs", got, sizeof(got)));
        ASSERT_EQ(ks.num_keys, 0);
        for (size_t i = 0; i < 2; i++) {
            ks.keys[i].used = true;
            memset(ks.keys[i].diversifier, 0x10 + (int)i, 11);
            memset(ks.keys[i].pk_d, 0x20 + (int)i, 32);
        }
        ks.num_keys = 2;
        ASSERT(sapling_encode_payment_address(ks.keys[1].diversifier,
                                              ks.keys[1].pk_d, "zs", want,
                                              sizeof(want)));
        ASSERT(wallet_latest_shielded_address(&ks, "zs", got, sizeof(got)));
        ASSERT_STR_EQ(got, want);
        ks.keys[1].used = false;
        ASSERT(sapling_encode_payment_address(ks.keys[0].diversifier,
                                              ks.keys[0].pk_d, "zs", want,
                                              sizeof(want)));
        ASSERT(wallet_latest_shielded_address(&ks, "zs", got, sizeof(got)));
        ASSERT_STR_EQ(got, want);
        ASSERT_EQ(ks.num_keys, 2);
        ASSERT(load(ndb, &after));
        ASSERT_EQ(after.nn, before.nn);
        ASSERT_EQ(after.nc, before.nc);
        ASSERT_EQ(after.nt, before.nt);
        unload(&before);
        unload(&after);
        sapling_keystore_free(&ks);
    } TEST_END
    return failures;
}

int test_wallet_summary_history(void);
int test_wallet_summary_history(void)
{
    int failures = 0;
    char dir[256], path[320];
    printf("\n=== wallet summary and history ===\n");
    memset(IVK_A, 0xa1, sizeof(IVK_A));
    memset(IVK_B, 0xb2, sizeof(IVK_B));
    test_make_tmpdir(dir, sizeof(dir), "wallet_summary_history", "main");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, path)) {
        printf("wallet_summary_history: node.db open FAIL\n");
        (void)test_rm_rf_recursive(dir);
        return 1;
    }
    if (!build_fixture(&ndb)) {
        printf("wallet_summary_history: fixture FAIL\n");
        node_db_close(&ndb);
        (void)test_rm_rf_recursive(dir);
        return 1;
    }
    failures += test_summary_thresholds(&ndb);
    failures += test_summary_double_count(&ndb);
    failures += test_history_directions(&ndb);
    failures += test_history_json(&ndb);
    failures += test_history_paging(&ndb);
    failures += test_summary_reorg(&ndb);
    failures += test_summary_json();
    failures += test_send_gate();
    failures += test_latest_address(&ndb);
    node_db_close(&ndb);
    (void)test_rm_rf_recursive(dir);
    return failures;
}
