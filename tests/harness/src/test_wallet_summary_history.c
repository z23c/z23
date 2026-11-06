/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_wallet_summary_history: core.wallet.summary and core.wallet.history
 * over an isolated node.db fixture. Notes, coins and transaction rows are
 * written through the production models; the summary and history are read
 * back through the same fact readers the node RPCs use. No wallet, key, node
 * or network is involved. */

#include "services/chain_evidence_authority_service.h"
#include "test/test_core.h"

#include "controllers/sovereignty_controller.h"
#include "controllers/sync_controller.h"
#include "controllers/wallet_activity.h"
#include "controllers/wallet_controller.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "models/block.h"
#include "models/database.h"
#include "models/wallet_activity.h"
#include "models/wallet_tx.h"
#include "sapling/sapling.h"
#include "test/wallet_summary_fixture.h"
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

bool wsh_put_block(struct node_db *ndb, int height)
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

bool wsh_put_note(struct node_db *ndb, uint8_t tx, uint32_t idx,
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

bool wsh_spend_note(struct node_db *ndb, uint8_t tx, uint32_t idx,
                       uint8_t spender)
{
    uint8_t nf[32], by[32];
    memset(nf, tx ^ 0x5a, 32);
    nf[0] = (uint8_t)idx;
    memset(by, spender, 32);
    return db_sapling_note_mark_spent(ndb, nf, by) == DB_MARK_SPENT_OK;
}

void wsh_note_nullifier(uint8_t tx, uint32_t idx, uint8_t out[32])
{
    memset(out, tx ^ 0x5a, 32);
    out[0] = (uint8_t)idx;
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

/* Mark every note as one send would accept: unspent on the chain with a
 * witness at the tip. Tests then spoil individual notes. */
static void mark_ready(struct db_wallet_note_fact *notes, int n)
{
    for (int i = 0; i < n; i++) {
        notes[i].chain = WALLET_NOTE_UNSPENT_ON_CHAIN;
        notes[i].witness = WALLET_WITNESS_READY;
    }
}

static struct db_wallet_note_fact *find_note(struct whf *f, uint8_t tx)
{
    for (int i = 0; i < f->nn; i++)
        if (f->notes[i].txid[0] == tx)
            return &f->notes[i];
    return NULL;
}

static bool summarize(struct node_db *ndb, const uint8_t (*ivks)[32],
                      size_t nk, struct wallet_summary *out)
{
    struct whf f;
    if (!load(ndb, &f))
        return false;
    mark_ready(f.notes, f.nn);
    bool ok = wallet_summary_accumulate(f.notes, (size_t)f.nn, f.coins,
                                        (size_t)f.nc, f.txs, (size_t)f.nt,
                                        ivks, nk, TIP, out);
    unload(&f);
    return ok;
}

/* Received at 1/9/10 confirmations, own change at 2/3, a spent note, a note
 * of a key that is not loaded. */
static bool build_fixture_notes(struct node_db *ndb)
{
    bool ok = wsh_put_block(ndb, TIP);
    ok = ok && wsh_put_note(ndb, 0x11, 0, IVK_A, 1 * ZCL1, 300, NULL);
    ok = ok && wsh_put_note(ndb, 0x12, 0, IVK_A, 2 * ZCL1, 292, NULL);
    ok = ok && wsh_put_note(ndb, 0x13, 0, IVK_A, 4 * ZCL1, 291, "hello memo");
    ok = ok && wsh_put_note(ndb, 0x14, 0, IVK_A, 64 * ZCL1, 250, NULL);
    ok = ok && wsh_spend_note(ndb, 0x14, 0, 0x20);
    ok = ok && wsh_put_note(ndb, 0x20, 0, IVK_A, 16 * ZCL1, 299, NULL);
    ok = ok && wsh_put_note(ndb, 0x20, 1, IVK_A, 32 * ZCL1, 298, NULL);
    ok = ok && put_tx(ndb, 0x20, 299, FEE, true);
    ok = ok && wsh_put_note(ndb, 0x15, 0, IVK_B, 100 * ZCL1, 100, NULL);
    return ok;
}

/* A pending send, an internal move with a fee, and a send of unknown fee. */
static bool build_fixture_moves(struct node_db *ndb)
{
    bool ok = wsh_put_note(ndb, 0x16, 0, IVK_A, 128 * ZCL1, 200, NULL);
    ok = ok && wsh_spend_note(ndb, 0x16, 0, 0x21);
    ok = ok && put_tx(ndb, 0x21, 0, FEE, true);
    ok = ok && wsh_put_note(ndb, 0x17, 0, IVK_A, 20 * ZCL1, 210, NULL);
    ok = ok && wsh_spend_note(ndb, 0x17, 0, 0x22);
    ok = ok && wsh_put_note(ndb, 0x22, 0, IVK_A, 20 * ZCL1 - FEE, 211, NULL);
    ok = ok && put_tx(ndb, 0x22, 211, FEE, true);
    ok = ok && wsh_put_note(ndb, 0x18, 0, IVK_A, 9 * ZCL1, 220, NULL);
    ok = ok && wsh_spend_note(ndb, 0x18, 0, 0x23);
    ok = ok && wsh_put_note(ndb, 0x23, 0, IVK_A, 4 * ZCL1, 295, NULL);
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
        ASSERT_EQ(s.spendable_total, SPENDABLE_EXPECT);
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
        mark_ready(f.notes, f.nn);
        size_t n = (size_t)f.nn;
        struct db_wallet_note_fact *rows = calloc(n * 2, sizeof(*rows));
        ASSERT(rows != NULL);
        for (size_t i = 0; i < n; i++)
            rows[2 * i] = rows[2 * i + 1] = f.notes[i];
        struct wallet_summary rep;
        ASSERT(wallet_summary_accumulate(rows, n * 2, f.coins, (size_t)f.nc,
                                         f.txs, (size_t)f.nt,
                                         (const uint8_t (*)[32])&IVK_A, 1,
                                         TIP, &rep));
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
            .locked = true, .shielded_keys = 2, .shielded_known = true };
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
        v.peer_best_height = 301;
        v.peer_count = 1;
        v.chain_fresh = true;
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
        ASSERT_EQ(u->fully_shielded, -1);
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
        ASSERT(r->height == 292 && r->confirmations == 9 && !r->private_kind);
        ASSERT_EQ(r->fully_shielded, -1);
        const struct wallet_history_entry *m = find(e, n, 0x13);
        ASSERT(m && m->memo_present && !r->memo_present);
        const struct wallet_history_entry *c = find(e, n, 0x31);
        ASSERT(c && c->direction == WALLET_DIR_RECEIVED && !c->private_kind);
        ASSERT_EQ(c->fully_shielded, 0);
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
    struct wallet_history_page_key cur = {0};
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
        struct wallet_history_page_key cur = {0};
        char text[96];
        wallet_history_cursor_format(&e[2], text, sizeof(text));
        ASSERT(wallet_history_cursor_parse(text, &cur));
        uint8_t next_before = e[wallet_history_page_start(e, (size_t)n, &cur)]
                                  .txid[0];
        ASSERT(wsh_put_note(ndb, 0x77, 0, IVK_A, ZCL1, 300, NULL));
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

static bool acc(struct whf *f, struct wallet_summary *out)
{
    return wallet_summary_accumulate(f->notes, (size_t)f->nn, f->coins,
                                     (size_t)f->nc, f->txs, (size_t)f->nt,
                                     (const uint8_t (*)[32])&IVK_A, 1, TIP,
                                     out);
}

static int test_summary_send_readiness(struct node_db *ndb)
{
    int failures = 0;
    TEST_CASE("wallet_summary: spendable is what send would accept") {
        struct whf f;
        struct wallet_summary base, s;
        ASSERT(load(ndb, &f));
        mark_ready(f.notes, f.nn);
        struct db_wallet_note_fact *n = find_note(&f, 0x22);
        ASSERT(n != NULL);
        ASSERT(acc(&f, &base));
        n->witness = WALLET_WITNESS_UNUSABLE;
        ASSERT(acc(&f, &s));
        ASSERT_EQ(s.spendable, base.spendable - (20 * ZCL1 - FEE));
        ASSERT_EQ(s.unready, (20 * ZCL1 - FEE));
        ASSERT_EQ(s.unready_notes, 1);
        n->witness = WALLET_WITNESS_READY;
        n->chain = WALLET_NOTE_SPENT_ON_CHAIN;
        ASSERT(acc(&f, &s));
        ASSERT_EQ(s.spendable, base.spendable - (20 * ZCL1 - FEE));
        ASSERT_EQ(s.unready, 0);
        ASSERT_EQ(s.reconciling_notes, 1);
        n->chain = WALLET_NOTE_CHAIN_UNKNOWN;
        ASSERT(acc(&f, &s));
        ASSERT_EQ(s.unready, (20 * ZCL1 - FEE));
        n->chain = WALLET_NOTE_UNCHECKED;
        n->witness = WALLET_WITNESS_UNCHECKED;
        ASSERT(acc(&f, &s));
        ASSERT_EQ(s.spendable, base.spendable - (20 * ZCL1 - FEE));
        unload(&f);
    } TEST_END
    return failures;
}

/* A 31-byte spent_txid is still a spend marker. */
static int test_malformed_spend_marker(struct node_db *ndb)
{
    int failures = 0;
    TEST_CASE("wallet_activity: a malformed spend marker still means spent") {
        struct whf f;
        struct wallet_summary before, after;
        ASSERT(summarize(ndb, (const uint8_t (*)[32])&IVK_A, 1, &before));
        ASSERT(wsh_put_note(ndb, 0x78, 0, IVK_A, 8 * ZCL1, 250, NULL));
        ASSERT(sqlite3_exec(ndb->db,
            "UPDATE wallet_sapling_notes SET spent_txid = zeroblob(31) "
            "WHERE value = 800000000", NULL, NULL, NULL) == SQLITE_OK);
        ASSERT(load(ndb, &f));
        struct db_wallet_note_fact *n = find_note(&f, 0x78);
        ASSERT(n && n->spent && !n->spent_txid_ok);
        unload(&f);
        ASSERT(summarize(ndb, (const uint8_t (*)[32])&IVK_A, 1, &after));
        ASSERT_EQ(after.spendable, before.spendable);
        ASSERT_EQ(after.pending, before.pending);
        uint8_t gone[32];
        memset(gone, 0x78, sizeof(gone));
        ASSERT(db_sapling_note_delete_for_tx(ndb, gone));
    } TEST_END
    return failures;
}

static int abort_every_query(void *unused)
{
    (void)unused;
    return 1;
}

static int test_failed_reads(struct node_db *ndb)
{
    int failures = 0;
    TEST_CASE("wallet_activity: a failed read fails, never zero or partial") {
        struct db_wallet_note_fact *notes = NULL;
        struct db_wallet_coin_fact *coins = NULL;
        struct db_wallet_tx_fact *txs = NULL;
        struct db_wallet_note_memo memos[2];
        uint8_t id[32];
        memset(id, 0x13, sizeof(id));
        sqlite3_progress_handler(ndb->db, 1, abort_every_query, NULL);
        ASSERT_EQ(db_wallet_note_facts_alloc(ndb, &notes), -1);
        ASSERT_EQ(db_wallet_coin_facts_alloc(ndb, &coins), -1);
        ASSERT_EQ(db_wallet_tx_facts_alloc(ndb, &txs), -1);
        ASSERT_EQ(db_wallet_note_memos_for_tx(ndb, id, memos, 2), -1);
        sqlite3_progress_handler(ndb->db, 0, NULL, NULL);
        ASSERT(notes == NULL && coins == NULL && txs == NULL);

        ASSERT(sqlite3_exec(ndb->db, "ALTER TABLE wallet_utxos RENAME TO wu_x",
                            NULL, NULL, NULL) == SQLITE_OK);
        ASSERT_EQ(db_wallet_coin_facts_alloc(ndb, &coins), -1);
        ASSERT(sqlite3_exec(ndb->db, "ALTER TABLE wu_x RENAME TO wallet_utxos",
                            NULL, NULL, NULL) == SQLITE_OK);

        zcl_alloc_fault_fail_next("wallet note facts");
        ASSERT_EQ(db_wallet_note_facts_alloc(ndb, &notes), -1);
        ASSERT(db_wallet_note_facts_alloc(ndb, &notes) > 0);
        free(notes);
    } TEST_END
    return failures;
}

static int test_failed_allocation(struct node_db *ndb)
{
    int failures = 0;
    TEST_CASE("wallet_activity: an allocation failure fails the aggregate") {
        struct wallet_summary s;
        struct wallet_history_entry *e = NULL;
        zcl_alloc_fault_fail_next("wallet spenders");
        ASSERT(!summarize(ndb, (const uint8_t (*)[32])&IVK_A, 1, &s));
        ASSERT_EQ(s.spendable, 0);
        zcl_alloc_fault_fail_next("wallet history acc");
        ASSERT_EQ(build_history(ndb, &e), -1);
        ASSERT(e == NULL);
        zcl_alloc_fault_fail_next("wallet history entries");
        ASSERT_EQ(build_history(ndb, &e), -1);
        ASSERT(e == NULL);
        zcl_alloc_fault_clear();
    } TEST_END
    return failures;
}

static int test_unknown_shielded_json(void)
{
    int failures = 0;
    TEST_CASE("wallet_summary: unreadable shielded amounts are null, never 0") {
        struct wallet_summary s = {0};
        struct wallet_chain_view v = { .tip_height = 300, .header_height = 300,
            .scanned_through = 300, .locked = true, .encrypted = true,
            .shielded_known = false };
        struct json_value j;
        json_init(&j);
        wallet_summary_to_json(&s, &v, true, "", &j);
        ASSERT_STR_EQ(json_get_str(json_get(&j, "shielded_state")),
                      "keys_unavailable");
        ASSERT(json_get(&j, "spendable_zat")->type == JSON_NULL);
        ASSERT(json_get(&j, "spendable")->type == JSON_NULL);
        ASSERT(json_get(&j, "spendable_total_zat")->type == JSON_NULL);
        ASSERT(json_get(&j, "pending_zat")->type == JSON_NULL);
        ASSERT(json_get(&j, "unready_zat")->type == JSON_NULL);
        ASSERT(json_get(&j, "sending_zat")->type == JSON_NULL);
        ASSERT(json_get(&j, "pending_notes")->type == JSON_NULL);
        ASSERT(json_get(&j, "public_zat")->type == JSON_INT);
        ASSERT(!json_get_bool(json_get(&j, "current")));
        json_free(&j);
    } TEST_END
    return failures;
}

static bool summary_current(const struct wallet_summary *s,
                            const struct wallet_chain_view *v)
{
    struct json_value j;
    json_init(&j);
    wallet_summary_to_json(s, v, true, "", &j);
    bool cur = json_get_bool(json_get(&j, "current"));
    json_free(&j);
    return cur;
}

static int test_current_needs_real_chain(void)
{
    int failures = 0;
    TEST_CASE("wallet_summary: current needs a real tip and real headers") {
        struct wallet_summary s = {0};
        struct wallet_chain_view v = { .tip_height = 300, .header_height = 300,
            .scanned_through = 300, .shielded_known = true,
            .chain_fresh = true };
        struct json_value j;
        /* Offline: no peer is never current, however fresh the last block. */
        ASSERT(!summary_current(&s, &v));
        /* A peer, but the newest block and header are old. */
        v.peer_count = 1;
        v.chain_fresh = false;
        ASSERT(!summary_current(&s, &v));
        /* A peer and a fresh block. */
        v.chain_fresh = true;
        ASSERT(summary_current(&s, &v));
        /* A peer reporting a height below the tip makes no difference. */
        v.peer_best_height = 250;
        ASSERT(summary_current(&s, &v));
        /* Two blocks behind the best header or the peers is not current. */
        v.header_height = 302;
        ASSERT(!summary_current(&s, &v));
        v.header_height = 300;
        v.peer_best_height = 302;
        ASSERT(!summary_current(&s, &v));
        v.peer_best_height = 0;
        v.header_height = 0;
        ASSERT(!summary_current(&s, &v));
        v.header_height = 300;
        v.tip_height = 0;
        v.scanned_through = 0;
        ASSERT(!summary_current(&s, &v));
        (void)j;
    } TEST_END
    return failures;
}

static int test_chain_fresh(void)
{
    int failures = 0;
    TEST_CASE("wallet_summary: the chain is fresh for ten minutes of local time") {
        ASSERT(!wallet_chain_fresh(-1));
        ASSERT(wallet_chain_fresh(0));
        ASSERT(wallet_chain_fresh(600 * 1000));
        ASSERT(!wallet_chain_fresh(600 * 1000 + 1));
        ASSERT(!wallet_chain_fresh(INT64_MIN));
    } TEST_END
    return failures;
}

/* A z-to-t send and a z-to-z send whose recorded fee is 0: the stored
 * transaction gives the fee and the kind. */
static bool outgoing_fixture(struct node_db *ndb)
{
    bool ok = wsh_put_note(ndb, 0x50, 0, IVK_A, 10 * ZCL1, 200, NULL);
    ok = ok && wsh_spend_note(ndb, 0x50, 0, 0x51);
    ok = ok && wsh_put_note(ndb, 0x51, 0, IVK_A, 5 * ZCL1 - FEE, 210, NULL);
    ok = ok && put_tx(ndb, 0x51, 210, 0, true);
    ok = ok && wsh_put_note(ndb, 0x52, 0, IVK_A, 10 * ZCL1, 200, NULL);
    ok = ok && wsh_spend_note(ndb, 0x52, 0, 0x53);
    ok = ok && wsh_put_note(ndb, 0x53, 0, IVK_A, 5 * ZCL1 - FEE, 211, NULL);
    ok = ok && put_tx(ndb, 0x53, 211, 0, true);
    return ok;
}

static struct db_wallet_tx_fact *find_tx(struct whf *f, uint8_t id)
{
    for (int i = 0; i < f->nt; i++)
        if (f->txs[i].txid[0] == id)
            return &f->txs[i];
    return NULL;
}

static int test_history_shielded_sends(struct node_db *ndb)
{
    int failures = 0;
    TEST_CASE("wallet_history: z-to-t is public, z-to-z recovers its amount") {
        struct whf f;
        struct wallet_history_entry *e = NULL;
        ASSERT(outgoing_fixture(ndb));
        ASSERT(load(ndb, &f));
        struct db_wallet_tx_fact *zt = find_tx(&f, 0x51);
        struct db_wallet_tx_fact *zz = find_tx(&f, 0x53);
        ASSERT(zt && zz);
        zt->raw_known = true;
        zt->vout_count = 1;
        zt->vout_total = 5 * ZCL1;
        zt->value_balance = 5 * ZCL1 + FEE;
        zz->raw_known = true;
        zz->value_balance = FEE;
        int n = wallet_history_build(f.notes, (size_t)f.nn, f.coins,
                                     (size_t)f.nc, f.txs, (size_t)f.nt,
                                     (const uint8_t (*)[32])&IVK_A, 1, TIP, &e);
        ASSERT(n > 0);
        const struct wallet_history_entry *a = find(e, n, 0x51);
        ASSERT(a && a->direction == WALLET_DIR_SENT && !a->private_kind);
        ASSERT(a->amount_known && a->amount == 5 * ZCL1 && a->fee == FEE);
        const struct wallet_history_entry *b = find(e, n, 0x53);
        ASSERT(b && b->direction == WALLET_DIR_SENT && b->private_kind);
        ASSERT(b->amount_known && b->amount == 5 * ZCL1 && b->fee == FEE);
        ASSERT_EQ(a->fully_shielded, 0);
        ASSERT_EQ(b->fully_shielded, 1);
        struct json_value ja, jb;
        json_init(&ja);
        json_init(&jb);
        wallet_history_entry_to_json(a, &ja);
        wallet_history_entry_to_json(b, &jb);
        ASSERT(json_get(&ja, "fully_shielded")->type == JSON_BOOL);
        ASSERT(!json_get_bool(json_get(&ja, "fully_shielded")));
        ASSERT(json_get_bool(json_get(&jb, "fully_shielded")));
        json_free(&ja);
        json_free(&jb);
        free(e);
        unload(&f);
    } TEST_END
    return failures;
}

/* A payment from another wallet is private only when its stored transaction
 * shows no transparent input or output. */
static int test_history_received_privacy(struct node_db *ndb)
{
    int failures = 0;
    TEST_CASE("wallet_history: a received payment is private only when shown") {
        struct whf f;
        struct wallet_history_entry *e = NULL;
        ASSERT(wsh_put_note(ndb, 0x80, 0, IVK_A, 3 * ZCL1, 250, NULL) &&
               put_tx(ndb, 0x80, 250, 0, false));
        ASSERT(wsh_put_note(ndb, 0x81, 0, IVK_A, 3 * ZCL1, 250, NULL) &&
               put_tx(ndb, 0x81, 250, 0, false));
        ASSERT(wsh_put_note(ndb, 0x82, 0, IVK_A, 3 * ZCL1, 250, NULL) &&
               put_tx(ndb, 0x82, 250, 0, false));
        ASSERT(load(ndb, &f));
        struct db_wallet_tx_fact *tz = find_tx(&f, 0x80);
        struct db_wallet_tx_fact *zz = find_tx(&f, 0x81);
        ASSERT(tz && zz);
        tz->raw_known = true;
        tz->vin_count = 1; /* a transparent sender */
        zz->raw_known = true;
        int n = wallet_history_build(f.notes, (size_t)f.nn, f.coins,
                                     (size_t)f.nc, f.txs, (size_t)f.nt,
                                     (const uint8_t (*)[32])&IVK_A, 1, TIP, &e);
        ASSERT(n > 0);
        const struct wallet_history_entry *a = find(e, n, 0x80);
        const struct wallet_history_entry *b = find(e, n, 0x81);
        const struct wallet_history_entry *c = find(e, n, 0x82);
        ASSERT(a && b && c);
        ASSERT_EQ(a->fully_shielded, 0);
        ASSERT(!a->private_kind);
        ASSERT_EQ(b->fully_shielded, 1);
        ASSERT(b->private_kind);
        ASSERT_EQ(c->fully_shielded, -1);
        ASSERT(!c->private_kind);
        struct json_value ja, jc;
        json_init(&ja);
        json_init(&jc);
        wallet_history_entry_to_json(a, &ja);
        wallet_history_entry_to_json(c, &jc);
        ASSERT_STR_EQ(json_get_str(json_get(&ja, "kind")), "public");
        ASSERT(json_get(&jc, "kind")->type == JSON_NULL);
        json_free(&ja);
        json_free(&jc);
        free(e);
        unload(&f);
    } TEST_END
    return failures;
}

static bool wsh_latest(char *out, size_t cap, bool *empty)
{
    struct json_value params = {0}, result = {0};
    json_set_array(&params);
    bool ok = rpc_walletlatestaddress(&params, false, &result);
    const struct json_value *address = json_get(&result, "address");
    const char *value = json_get_str(address);
    *empty = address && address->type == JSON_NULL;
    if (value && strlen(value) < cap) snprintf(out, cap, "%s", value);
    else if (!*empty) ok = false;
    json_free(&params);
    json_free(&result);
    return ok;
}

static int test_latest_address(struct node_db *ndb)
{
    int failures = 0;
    struct wallet *w = NULL;
    struct wallet_sqlite ws = {0};
    bool ws_open = false;
    TEST_CASE("wallet_latest: empty or selected account default, creates nothing") {
        char got[128] = {0}, want[128] = {0};
        bool empty = false;
        struct whf before, after;
        w = calloc(1, sizeof(*w));
        ASSERT(w != NULL);
        wallet_init(w);
        ASSERT(wallet_sqlite_open_r(&ws, ndb->db).ok);
        ws_open = true;
        rpc_wallet_set_state(w, NULL, NULL, &ws, NULL, NULL);
        ASSERT(load(ndb, &before));
        ASSERT(wsh_latest(got, sizeof(got), &empty) && empty);
        ASSERT_EQ(w->sapling_keys.num_keys, 0);
        for (size_t i = 0; i < 2; i++) {
            w->sapling_keys.keys[i].used = true;
            w->sapling_keys.keys[i].child_index = (uint32_t)i;
            memset(w->sapling_keys.keys[i].diversifier, 0x10 + (int)i, 11);
            memset(w->sapling_keys.keys[i].pk_d, 0x20 + (int)i, 32);
        }
        w->sapling_keys.num_keys = 2;
        ASSERT(sapling_encode_payment_address(w->sapling_keys.keys[0].diversifier,
            w->sapling_keys.keys[0].pk_d, "zs", want, sizeof(want)));
        ASSERT(wsh_latest(got, sizeof(got), &empty) && !empty);
        ASSERT_STR_EQ(got, want);
        w->sapling_keys.keys[0].used = false;
        ASSERT(sapling_encode_payment_address(w->sapling_keys.keys[1].diversifier,
            w->sapling_keys.keys[1].pk_d, "zs", want, sizeof(want)));
        ASSERT(wsh_latest(got, sizeof(got), &empty) && !empty);
        ASSERT_STR_EQ(got, want);
        ASSERT_EQ(w->sapling_keys.num_keys, 2);
        ASSERT(load(ndb, &after));
        ASSERT_EQ(after.nn, before.nn);
        ASSERT_EQ(after.nc, before.nc);
        ASSERT_EQ(after.nt, before.nt);
        unload(&before);
        unload(&after);
    } TEST_END
    rpc_wallet_set_state(NULL, NULL, NULL, NULL, NULL, NULL);
    if (ws_open) wallet_sqlite_close(&ws);
    if (w) { wallet_free(w); free(w); }
    return failures;
}

int wallet_summary_handlers_run(void);
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
    failures += test_summary_send_readiness(&ndb);
    failures += test_malformed_spend_marker(&ndb);
    failures += test_failed_reads(&ndb);
    failures += test_failed_allocation(&ndb);
    failures += test_unknown_shielded_json();
    failures += test_current_needs_real_chain();
    failures += test_chain_fresh();
    failures += test_history_shielded_sends(&ndb);
    failures += test_history_received_privacy(&ndb);
    failures += test_latest_address(&ndb);
    node_db_close(&ndb);
    failures += wallet_summary_handlers_run();
    /* Reap the one-shot evidence-maintenance thread walletsummary reads spawn. */
    chain_evidence_maintain_quiesce();
    (void)test_rm_rf_recursive(dir);
    return failures;
}
