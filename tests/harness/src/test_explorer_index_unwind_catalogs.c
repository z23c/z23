/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Reorg unwind of the two cursor-owning catalogs (zslp_ledger,
 * op_return_index), their bounded digest history, the fold guards and the
 * `transactions` rule of explorer_index_unwind_above_chain.
 *
 * A catalog carries a running digest that chains every folded height, so a
 * reorg used to drop it and rebuild it from genesis (hours on mainnet). The
 * digest history lets a reorg within CATALOG_HISTORY_DEPTH rewind it EXACTLY.
 * Every scenario here builds the stale branch and the winning branch from one
 * common prefix, folds the catalogs over the stale branch, unwinds, and
 * requires the catalog (every row, the cursor and the digest) to equal a
 * catalog built from scratch on the prefix, and after the winner is folded to
 * equal one built from scratch on prefix + winner. A control run (no unwind)
 * proves each scenario really exposes the bug. node.db in memory only. */

#include "test/test_core.h"
#include "chain/chain.h"
#include "jobs/reducer_frontier.h"
#include "models/catalog_digest_history.h"
#include "models/database.h"
#include "models/explorer_index.h"
#include "models/op_return_index.h"
#include "models/tx_index.h"
#include "models/zslp_ledger.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "services/explorer_unwind_service.h"
#include "services/zslp_ledger_backfill_service.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "zslp/slp.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CB_CHECK(label, cond) do { \
    printf("explorer_index_unwind: %s... ", (label)); \
    if (cond) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* A world needs heights 0 .. fork + CATALOG_HISTORY_DEPTH + a few. */
#define CB_MAX_H (CATALOG_HISTORY_DEPTH + 64)
#define CB_ARENA_TX 512

/* ── Blocks: one transaction per non-empty height ────────────────────── */

struct cb_arena {
    struct transaction tx[CB_ARENA_TX];
    size_t n;
};

struct cb_chain {
    const struct transaction *tx[CB_MAX_H]; /* NULL: an empty height */
    uint8_t hash[CB_MAX_H][32];
    int tip;
};

struct cb_out {
    uint8_t txid[32];
    uint32_t vout;
    uint64_t amount;
    bool baton;
    uint8_t token[32];
};

struct cb_gen {
    struct cb_out unspent[64];
    size_t n;
};

static void cb_add_out(struct cb_gen *g, const uint8_t txid[32], uint32_t vout,
                       uint64_t amount, bool baton, const uint8_t token[32])
{
    if (g->n >= sizeof(g->unspent) / sizeof(g->unspent[0]))
        return;
    struct cb_out *o = &g->unspent[g->n++];
    memcpy(o->txid, txid, 32);
    o->vout = vout;
    o->amount = amount;
    o->baton = baton;
    memcpy(o->token, token, 32);
}

static void cb_remove_out(struct cb_gen *g, size_t i)
{
    g->unspent[i] = g->unspent[--g->n];
}

static bool cb_find_out(const struct cb_gen *g, bool baton, size_t *at)
{
    for (size_t i = 0; i < g->n; i++) {
        if (g->unspent[i].baton == baton && (baton || g->unspent[i].amount >= 3)) {
            *at = i;
            return true;
        }
    }
    return false;
}

static void cb_wire_token(const uint8_t token[32], struct uint256 *wire)
{
    for (int i = 0; i < 32; i++)
        wire->data[i] = token[31 - i];
}

struct cb_spec {
    bool has_in;
    uint8_t in_txid[32];
    uint32_t in_n;
    uint8_t script[300];
    size_t slen;
    size_t npay;
    uint8_t pay_byte[2];
};

static void cb_make_tx(struct transaction *tx, const struct cb_spec *sp,
                       int h, uint8_t salt)
{
    static const uint8_t pre[3] = { 0x76, 0xa9, 0x14 };
    static const uint8_t post[2] = { 0x88, 0xac };
    transaction_init(tx);
    transaction_alloc(tx, 1, 1 + sp->npay);
    if (sp->has_in) {
        memcpy(tx->vin[0].prevout.hash.data, sp->in_txid, 32);
        tx->vin[0].prevout.n = sp->in_n;
    } else {
        memset(tx->vin[0].prevout.hash.data, 0xC0 ^ salt, 32);
        tx->vin[0].prevout.hash.data[0] = (uint8_t)h;
        tx->vin[0].prevout.hash.data[1] = (uint8_t)(h >> 8);
        tx->vin[0].prevout.n = 0;
    }
    tx->vin[0].sequence = 0xFFFFFFFFu;
    tx->vin[0].script_sig.size = 0;
    tx->vout[0].value = 0;
    memcpy(tx->vout[0].script_pub_key.data, sp->script, sp->slen);
    tx->vout[0].script_pub_key.size = sp->slen;
    for (size_t i = 0; i < sp->npay; i++) {
        uint8_t *p = tx->vout[1 + i].script_pub_key.data;
        tx->vout[1 + i].value = COIN;
        memcpy(p, pre, 3);
        memset(p + 3, sp->pay_byte[i], 20);
        memcpy(p + 23, post, 2);
        tx->vout[1 + i].script_pub_key.size = 25;
    }
    tx->lock_time = 0;
    transaction_compute_hash(tx);
}

/* kind: 'G' genesis (token + baton), 'S' send (splits a token output),
 * 'M' mint (spends a baton), 'P' plain OP_RETURN, '.' empty height. A kind
 * that has nothing to spend becomes a genesis. */
static const struct transaction *cb_gen_block(struct cb_arena *ar,
                                              struct cb_gen *g, char kind,
                                              int h, uint8_t salt)
{
    if (kind == '.' || ar->n >= CB_ARENA_TX)
        return NULL;
    struct cb_spec sp;
    memset(&sp, 0, sizeof(sp));
    size_t at = 0;
    struct uint256 wire;
    const uint64_t qty = 1000u + (uint64_t)h * 7u + salt;
    uint8_t token[32];
    uint64_t q[2] = { 0, 0 };
    bool is_genesis = false, is_send = false, is_mint = false;
    if (kind == 'S' && cb_find_out(g, false, &at)) {
        is_send = true;
        sp.has_in = true;
        memcpy(sp.in_txid, g->unspent[at].txid, 32);
        sp.in_n = g->unspent[at].vout;
        memcpy(token, g->unspent[at].token, 32);
        q[0] = g->unspent[at].amount / 3;
        q[1] = g->unspent[at].amount - q[0];
        cb_wire_token(token, &wire);
        sp.slen = slp_build_send(sp.script, sizeof(sp.script), &wire, q, 2);
        sp.npay = 2;
    } else if (kind == 'M' && cb_find_out(g, true, &at)) {
        is_mint = true;
        sp.has_in = true;
        memcpy(sp.in_txid, g->unspent[at].txid, 32);
        sp.in_n = g->unspent[at].vout;
        memcpy(token, g->unspent[at].token, 32);
        cb_wire_token(token, &wire);
        sp.slen = slp_build_mint(sp.script, sizeof(sp.script), &wire, 2, qty);
        sp.npay = 2;
    } else if (kind == 'P') {
        static const uint8_t plain[] = { 0x6a, 0x08, 'C', 'B', 'P', 'L' };
        memcpy(sp.script, plain, sizeof(plain));
        sp.script[6] = salt;
        sp.script[7] = (uint8_t)h;
        sp.script[8] = (uint8_t)(h >> 8);
        sp.script[9] = 0x01;
        sp.slen = 10;
    } else {
        is_genesis = true;
        sp.slen = slp_build_genesis(sp.script, sizeof(sp.script), "CB",
                                    "Catalog", "", NULL, 0, 2, qty);
        sp.npay = 2;
    }
    sp.pay_byte[0] = (h & 1) ? 0x11 : 0x22;
    sp.pay_byte[1] = 0x33;

    struct transaction *tx = &ar->tx[ar->n++];
    cb_make_tx(tx, &sp, h, salt);
    if (is_genesis) {
        memcpy(token, tx->hash.data, 32);
        cb_add_out(g, tx->hash.data, 1, qty, false, token);
        cb_add_out(g, tx->hash.data, 2, 0, true, token);
    } else if (is_send) {
        cb_remove_out(g, at);
        cb_add_out(g, tx->hash.data, 1, q[0], false, token);
        cb_add_out(g, tx->hash.data, 2, q[1], false, token);
    } else if (is_mint) {
        cb_remove_out(g, at);
        cb_add_out(g, tx->hash.data, 1, qty, false, token);
        cb_add_out(g, tx->hash.data, 2, 0, true, token);
    }
    return tx;
}

static void cb_set_hash(struct cb_chain *c, int h, uint8_t salt)
{
    memset(c->hash[h], 0x50 + salt, 32);
    c->hash[h][0] = (uint8_t)h;
    c->hash[h][1] = (uint8_t)(h >> 8);
    c->hash[h][2] = salt;
}

/* Append heights [from, from + strlen(kinds)) of branch `salt` to `c`. */
static void cb_extend(struct cb_chain *c, struct cb_arena *ar,
                      struct cb_gen *g, int from, const char *kinds,
                      uint8_t salt)
{
    for (size_t i = 0; kinds[i]; i++) {
        int h = from + (int)i;
        c->tx[h] = cb_gen_block(ar, g, kinds[i], h, salt);
        cb_set_hash(c, h, salt);
        c->tip = h;
    }
}

/* ── node.db helpers ─────────────────────────────────────────────────── */

static struct node_db *cb_open(void)
{
    struct node_db *ndb = zcl_calloc(1, sizeof(*ndb), "catalog test db");
    if (!ndb)
        return NULL;
    if (!node_db_open(ndb, ":memory:") || !ndb->open) {
        free(ndb);
        return NULL;
    }
    return ndb;
}

static void cb_close(struct node_db *ndb)
{
    if (!ndb)
        return;
    node_db_close(ndb);
    free(ndb);
}

static void cb_set_proj_tip(struct node_db *ndb, int64_t h)
{
    (void)node_db_state_set_int(ndb, "sync_projection_tip_height", h);
}

/* explorer_index_block for the transaction at `h`; an empty height writes
 * nothing. Does NOT move the projection tip. */
static bool cb_index_one(struct node_db *ndb, const struct cb_chain *c, int h)
{
    if (!c->tx[h])
        return true;
    struct block blk;
    block_init(&blk);
    blk.vtx = (struct transaction *)c->tx[h];
    blk.num_vtx = 1;
    blk.header.nTime = 1700000000u + (uint32_t)h;
    struct uint256 bhash;
    memcpy(bhash.data, c->hash[h], 32);
    struct block_index pindex;
    memset(&pindex, 0, sizeof(pindex));
    pindex.nHeight = h;
    pindex.phashBlock = &bhash;
    uint8_t prev[32] = {0}, out[32];
    bool ok = explorer_index_block(ndb, &blk, &pindex, prev, out, NULL, NULL);
    blk.vtx = NULL;
    blk.num_vtx = 0;
    return ok;
}

static bool cb_index(struct node_db *ndb, const struct cb_chain *c, int from,
                     int to)
{
    bool ok = true;
    for (int h = from; h <= to; h++) {
        ok = cb_index_one(ndb, c, h) && ok;
        cb_set_proj_tip(ndb, h);
    }
    return ok;
}

/* Fold zslp_ledger to `upto` through its real backfill service. */
static int32_t cb_zslp_fold_to(struct node_db *ndb, int32_t upto)
{
    g_zslp_ledger_backfill_test_ndb = ndb;
    reducer_frontier_provable_tip_set(upto);
    cb_set_proj_tip(ndb, upto);
    for (int i = 0; i < 64; i++)
        if (zslp_ledger_backfill_run_once() == 0)
            break;
    int32_t cur = -9;
    uint8_t d[32];
    (void)zslp_ledger_get_cursor(ndb, &cur, d);
    return cur;
}

/* Fold op_return_index with the same three calls the backfill service makes
 * per height (apply_block_rows, fold_block_digest, commit_fold), under its
 * fold guard. */
static bool cb_oprindex_fold_to(struct node_db *ndb, const struct cb_chain *c,
                                int32_t upto)
{
    if (!op_return_index_fold_try_begin())
        return false;
    struct op_return_index_cursor cur;
    bool ok = op_return_index_get_cursor(ndb, &cur);
    struct op_return_index_row rows[8];
    for (int32_t h = cur.height + 1; ok && h <= upto; h++) {
        struct block blk;
        block_init(&blk);
        blk.vtx = (struct transaction *)c->tx[h];
        blk.num_vtx = c->tx[h] ? 1 : 0;
        size_t n = 0;
        ok = op_return_index_apply_block_rows(ndb, &blk, h, rows, 8, &n);
        blk.vtx = NULL;
        blk.num_vtx = 0;
        struct op_return_index_cursor next = cur;
        next.height = h;
        op_return_index_fold_block_digest(cur.base_height, cur.base_digest,
                                          cur.digest, h, c->hash[h], rows, n,
                                          next.digest);
        ok = ok && op_return_index_commit_fold(ndb, &cur, &next);
        cur = next;
    }
    op_return_index_fold_end();
    return ok;
}

static bool cb_fold_all(struct node_db *ndb, const struct cb_chain *c,
                        int32_t upto)
{
    return cb_zslp_fold_to(ndb, upto) == upto &&
           cb_oprindex_fold_to(ndb, c, upto);
}

/* ── Whole-catalog comparison ────────────────────────────────────────── */

static const char *const k_cb_tables[] = {
    "zslp_ledger", "zslp_validity", "op_return_index",
};

static uint64_t cb_fnv(uint64_t h, const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) {
        h ^= b[i];
        h *= 1099511628211ull;
    }
    return h;
}

/* Order-independent of insertion order: rows are read in primary-key order,
 * then every column of every row is hashed with its type. */
static uint64_t cb_table_hash(struct node_db *ndb, const char *table,
                              int64_t *rows)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT * FROM %s ORDER BY 1,2,3,4", table);
    sqlite3_stmt *s = NULL;
    uint64_t h = 1469598103934665603ull;
    *rows = 0;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK || !s)
        return 0;
    while (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:test-readonly-dump
        (*rows)++;
        int cols = sqlite3_column_count(s);
        for (int c = 0; c < cols; c++) {
            int type = sqlite3_column_type(s, c);
            h = cb_fnv(h, &type, sizeof(type));
            if (type == SQLITE_BLOB)
                h = cb_fnv(h, sqlite3_column_blob(s, c),
                           (size_t)sqlite3_column_bytes(s, c));
            else if (type != SQLITE_NULL)
                h = cb_fnv(h, sqlite3_column_text(s, c),
                           (size_t)sqlite3_column_bytes(s, c));
        }
    }
    sqlite3_finalize(s);
    return h;
}

struct cb_state {
    int32_t zslp_h;
    uint8_t zslp_d[32];
    struct op_return_index_cursor oi;
};

static void cb_read_state(struct node_db *ndb, struct cb_state *st)
{
    memset(st, 0, sizeof(*st));
    st->zslp_h = -9;
    (void)zslp_ledger_get_cursor(ndb, &st->zslp_h, st->zslp_d);
    if (!op_return_index_get_cursor(ndb, &st->oi))
        st->oi.height = -9;
}

/* Number of differing facts between two catalogs: each table, both cursor
 * heights, both digests. Prints what differs unless `quiet`. */
static int cb_diff(struct node_db *x, struct node_db *y, bool quiet)
{
    int bad = 0;
    for (size_t i = 0; i < sizeof(k_cb_tables) / sizeof(k_cb_tables[0]); i++) {
        int64_t rx, ry;
        uint64_t hx = cb_table_hash(x, k_cb_tables[i], &rx);
        uint64_t hy = cb_table_hash(y, k_cb_tables[i], &ry);
        if (hx != hy || rx != ry) {
            bad++;
            if (!quiet)
                printf("\n    %s differs (%lld vs %lld rows)", k_cb_tables[i],
                       (long long)rx, (long long)ry);
        }
    }
    struct cb_state a, b;
    cb_read_state(x, &a);
    cb_read_state(y, &b);
    if (a.zslp_h != b.zslp_h || memcmp(a.zslp_d, b.zslp_d, 32) != 0) {
        bad++;
        if (!quiet)
            printf("\n    zslp cursor %d vs %d%s", a.zslp_h, b.zslp_h,
                   a.zslp_h == b.zslp_h ? " (digest differs)" : "");
    }
    if (a.oi.height != b.oi.height ||
        memcmp(a.oi.digest, b.oi.digest, 32) != 0 ||
        a.oi.base_height != b.oi.base_height) {
        bad++;
        if (!quiet)
            printf("\n    op_return cursor %d vs %d%s", a.oi.height,
                   b.oi.height,
                   a.oi.height == b.oi.height ? " (digest differs)" : "");
    }
    return bad;
}

static int64_t cb_count(struct node_db *ndb, const char *sql)
{
    sqlite3_stmt *s = NULL;
    int64_t n = -1;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK || !s)
        return -1;
    if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:test-readonly-count
        n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

/* ── A world: common prefix, stale branch, winning branch ────────────── */

struct cb_world {
    struct cb_arena *arena;
    struct cb_chain *common, *stale, *win;
    int fork;
};

static void cb_world_free(struct cb_world *w)
{
    if (w->arena) {
        for (size_t i = 0; i < w->arena->n; i++)
            transaction_free(&w->arena->tx[i]);
        free(w->arena);
    }
    free(w->common);
    free(w->stale);
    free(w->win);
    memset(w, 0, sizeof(*w));
}

/* `prefix` covers heights 0..fork; the tails continue from fork + 1. */
static bool cb_world_build(struct cb_world *w, const char *prefix,
                           const char *stale_kinds, const char *win_kinds)
{
    memset(w, 0, sizeof(*w));
    w->arena = zcl_calloc(1, sizeof(*w->arena), "catalog test arena");
    w->common = zcl_calloc(1, sizeof(*w->common), "catalog test chain");
    w->stale = zcl_calloc(1, sizeof(*w->stale), "catalog test chain");
    w->win = zcl_calloc(1, sizeof(*w->win), "catalog test chain");
    if (!w->arena || !w->common || !w->stale || !w->win) {
        cb_world_free(w);
        return false;
    }
    struct cb_gen g;
    memset(&g, 0, sizeof(g));
    w->fork = (int)strlen(prefix) - 1;
    cb_extend(w->common, w->arena, &g, 0, prefix, 0);
    struct cb_gen gs = g, gw = g;
    *w->stale = *w->common;
    *w->win = *w->common;
    cb_extend(w->stale, w->arena, &gs, w->fork + 1, stale_kinds, 1);
    cb_extend(w->win, w->arena, &gw, w->fork + 1, win_kinds, 2);
    return true;
}

/* A catalog database indexed and folded over `c` up to `to`. */
static struct node_db *cb_catalog_over(const struct cb_chain *c, int to)
{
    struct node_db *ndb = cb_open();
    if (!ndb)
        return NULL;
    if (!cb_index(ndb, c, 0, to) || !cb_fold_all(ndb, c, to)) {
        cb_close(ndb);
        return NULL;
    }
    return ndb;
}

/* The unwind the way catchup calls it: tip move inside the guard window. */
struct cb_hook {
    struct node_db *ndb;
    int calls;
};

static bool cb_hook_move_tip(void *ctx, int fork_height)
{
    struct cb_hook *hk = ctx;
    hk->calls++;
    cb_set_proj_tip(hk->ndb, fork_height);
    return true;
}

static struct zcl_result cb_unwind(struct node_db *ndb, int fork,
                                   struct explorer_unwind_report *rep)
{
    struct cb_hook hk = { ndb, 0 };
    struct explorer_unwind_chain src = { .after_commit = cb_hook_move_tip,
                                         .ctx = &hk };
    return explorer_index_unwind_above_chain(ndb, fork, &src, rep);
}

static bool cb_world_exposes_tokens(struct node_db *sub, int fork)
{
    char sql[160];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM zslp_ledger WHERE "
             "created_height>%d", fork);
    int64_t created = cb_count(sub, sql);
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM zslp_ledger WHERE "
             "spent_height>%d", fork);
    return created > 0 && cb_count(sub, sql) > 0;
}

/* One reorg end to end; `need_tokens` insists the stale range carries token
 * creations AND spends so the undo of both is exercised. */
static int cb_run_world(const char *name, const char *prefix,
                        const char *stale, const char *win, bool need_tokens)
{
    int failures = 0;
    char label[200];
    struct cb_world w;
    if (!cb_world_build(&w, prefix, stale, win)) {
        printf("explorer_index_unwind: %s: world... FAIL\n", name);
        return 1;
    }
    const int fork = w.fork, stale_tip = w.stale->tip, win_tip = w.win->tip;
    struct node_db *ref = cb_catalog_over(w.win, win_tip);
    struct node_db *pre = cb_catalog_over(w.common, fork);
    struct node_db *sub = cb_catalog_over(w.stale, stale_tip);
    struct node_db *ctl = cb_catalog_over(w.stale, stale_tip);
    if (!ref || !pre || !sub || !ctl) {
        printf("explorer_index_unwind: %s: could not build catalogs... FAIL\n",
               name);
        failures++;
        goto done;
    }
    if (need_tokens) {
        snprintf(label, sizeof(label), "%s: the stale range creates and "
                 "spends token outputs", name);
        CB_CHECK(label, cb_world_exposes_tokens(sub, fork));
    }

    /* Control: winner indexed over the loser's catalog, no unwind. */
    (void)cb_index(ctl, w.win, fork + 1, win_tip);
    (void)cb_fold_all(ctl, w.win, win_tip);
    snprintf(label, sizeof(label), "%s: control without unwind diverges", name);
    CB_CHECK(label, cb_diff(ctl, ref, true) > 0);

    struct explorer_unwind_report rep = { 0 };
    struct zcl_result res = cb_unwind(sub, fork, &rep);
    snprintf(label, sizeof(label), "%s: unwind succeeds, both catalogs "
             "rewound exactly (no rebuild)", name);
    CB_CHECK(label, res.ok && rep.zslp_ledger == CATALOG_REWIND_EXACT &&
                    rep.op_return_index == CATALOG_REWIND_EXACT);
    snprintf(label, sizeof(label), "%s: rewound catalogs (rows, cursor, "
             "digest) equal a catalog built from scratch on the prefix", name);
    int bad = cb_diff(sub, pre, false);
    CB_CHECK(label, bad == 0);

    (void)cb_index(sub, w.win, fork + 1, win_tip);
    snprintf(label, sizeof(label), "%s: after the winner is folded the "
             "catalogs equal one built on prefix + winner", name);
    bool folded = cb_fold_all(sub, w.win, win_tip);
    bad = cb_diff(sub, ref, false);
    CB_CHECK(label, folded && bad == 0);
done:
    cb_close(ref);
    cb_close(pre);
    cb_close(sub);
    cb_close(ctl);
    cb_world_free(&w);
    return failures;
}

static int cb_basic_reorgs(void)
{
    int failures = 0;
    const char *prefix = "PGSPGMS.SPGS";
    failures += cb_run_world("1-block reorg", prefix, "S", "M", false);
    failures += cb_run_world("10-block reorg", prefix, "SMGSSPMGSM",
                             "GSSMPSMSGP", true);
    failures += cb_run_world("reorg to a shorter chain", prefix, "SMGSSPMGSM",
                             "GSS", true);
    failures += cb_run_world("reorg to a longer chain", prefix, "SMG",
                             "GSSMPSMSGPSM", true);
    failures += cb_run_world("token genesis, mint and spend in the stale "
                             "range", prefix, "GMSSM", "S.S", true);
    return failures;
}

/* ── The history window ──────────────────────────────────────────────── */

/* A stale branch `stale_len` heights long whose only activity is at its
 * first two heights; the rest are empty heights. */
static void cb_window_kinds(char *buf, size_t len, const char *head)
{
    memset(buf, '.', len);
    memcpy(buf, head, strlen(head));
    buf[len] = '\0';
}

struct cb_window {
    struct cb_world w;
    struct node_db *ref, *pre, *sub;
    char *stale;
    size_t stale_len;
};

static void cb_window_close(struct cb_window *x)
{
    cb_close(x->ref);
    cb_close(x->pre);
    cb_close(x->sub);
    cb_world_free(&x->w);
    free(x->stale);
}

static bool cb_window_open(struct cb_window *x, size_t stale_len)
{
    memset(x, 0, sizeof(*x));
    x->stale_len = stale_len;
    x->stale = zcl_malloc(stale_len + 1, "window stale kinds");
    if (!x->stale)
        return false;
    cb_window_kinds(x->stale, stale_len, "SM");
    if (!cb_world_build(&x->w, "PGSMGSPSGS", x->stale, "S"))
        return false;
    x->ref = cb_catalog_over(x->w.win, x->w.win->tip);
    x->pre = cb_catalog_over(x->w.common, x->w.fork);
    x->sub = cb_catalog_over(x->w.stale, x->w.stale->tip);
    return x->ref && x->pre && x->sub;
}

/* The history holds exactly the window, whatever the stale length. */
static int cb_window_history(const char *name, struct cb_window *x)
{
    int failures = 0;
    char label[200];
    const int fork = x->w.fork, stale_tip = x->w.stale->tip;
    uint8_t d[32];
    int64_t zc = catalog_history_count(x->sub, CATALOG_HISTORY_ZSLP_LEDGER);
    int64_t oc = catalog_history_count(x->sub, CATALOG_HISTORY_OP_RETURN_INDEX);
    snprintf(label, sizeof(label), "%s: history holds exactly the window "
             "(%lld/%lld entries, depth %d)", name, (long long)zc,
             (long long)oc, stale_tip - fork);
    CB_CHECK(label, zc == CATALOG_HISTORY_DEPTH + 1 &&
                    oc == CATALOG_HISTORY_DEPTH + 1);
    bool fork_kept = catalog_history_lookup(x->sub, CATALOG_HISTORY_ZSLP_LEDGER,
                                            fork, d, NULL);
    snprintf(label, sizeof(label), "%s: the fork entry is %s", name,
             x->stale_len <= CATALOG_HISTORY_DEPTH ? "still held"
                                                   : "pruned away");
    CB_CHECK(label, fork_kept == (x->stale_len <= CATALOG_HISTORY_DEPTH));
    return failures;
}

/* What the unwind leaves behind: an exact rewind equals the prefix catalog; a
 * rebuild leaves both catalogs empty with a re-derive floor at the fork. */
static int cb_window_outcome(struct cb_window *x, enum catalog_rewind want)
{
    int failures = 0;
    if (want == CATALOG_REWIND_EXACT) {
        CB_CHECK("exact rewind at the window depth equals the prefix catalog",
                 cb_diff(x->sub, x->pre, false) == 0);
        return failures;
    }
    struct cb_state st;
    cb_read_state(x->sub, &st);
    CB_CHECK("a rebuild leaves the catalogs empty at cursor -1 with no "
             "history",
             st.zslp_h == -1 && st.oi.height == -1 &&
             cb_count(x->sub, "SELECT COUNT(*) FROM zslp_ledger") == 0 &&
             cb_count(x->sub, "SELECT COUNT(*) FROM op_return_index") == 0 &&
             catalog_history_count(x->sub, CATALOG_HISTORY_ZSLP_LEDGER) == 0);
    int32_t fl = -9;
    CB_CHECK("a rebuild records the re-derive floor at the fork, so the "
             "fold re-judges what the live hook wrote on the empty ledger",
             zslp_ledger_rederive_floor_get(x->sub, &fl) && fl == x->w.fork);
    return failures;
}

static int cb_window_case(const char *name, size_t stale_len,
                          enum catalog_rewind want)
{
    int failures = 0;
    char label[200];
    struct cb_window x;
    if (!cb_window_open(&x, stale_len)) {
        printf("explorer_index_unwind: %s: catalogs... FAIL\n", name);
        cb_window_close(&x);
        return 1;
    }
    const int fork = x.w.fork, win_tip = x.w.win->tip;
    failures += cb_window_history(name, &x);
    struct explorer_unwind_report rep = { 0 };
    struct zcl_result res = cb_unwind(x.sub, fork, &rep);
    snprintf(label, sizeof(label), "%s: unwind succeeds, outcome is %s", name,
             want == CATALOG_REWIND_EXACT ? "an exact rewind"
                                          : "a rebuild (deeper than window)");
    CB_CHECK(label, res.ok && rep.zslp_ledger == want &&
                    rep.op_return_index == want);
    failures += cb_window_outcome(&x, want);
    (void)cb_index(x.sub, x.w.win, fork + 1, win_tip);
    bool folded = cb_fold_all(x.sub, x.w.win, win_tip);
    snprintf(label, sizeof(label), "%s: converges to the prefix + winner "
             "catalog after the backfill", name);
    CB_CHECK(label, folded && cb_diff(x.sub, x.ref, false) == 0);
    if (want == CATALOG_REWIND_REBUILD)
        CB_CHECK("once the backfill has caught up the re-derive floor is gone",
                 !zslp_ledger_rederive_floor_get(x.sub, NULL));
    cb_window_close(&x);
    return failures;
}

/* ── Repeated reorgs, upgrade path, no-ops ───────────────────────────── */

/* Switch `sub` to the branch `to`; true when the unwind was exact and the
 * folded result equals `ref`. */
static bool cb_switch_branch(struct node_db *sub, int fork,
                             const struct cb_chain *to, struct node_db *ref,
                             bool *exact)
{
    struct explorer_unwind_report rep = { 0 };
    struct zcl_result res = cb_unwind(sub, fork, &rep);
    *exact = res.ok && rep.zslp_ledger == CATALOG_REWIND_EXACT &&
             rep.op_return_index == CATALOG_REWIND_EXACT;
    (void)cb_index(sub, to, fork + 1, to->tip);
    return cb_fold_all(sub, to, to->tip) && cb_diff(sub, ref, true) == 0;
}

static int cb_alternating(void)
{
    int failures = 0;
    struct cb_world w;
    if (!cb_world_build(&w, "PGSPGMS.SPGSSMGPSMGS", "SMGSPS", "GSSMPSMS"))
        return 1;
    struct node_db *ref_x = cb_catalog_over(w.stale, w.stale->tip);
    struct node_db *ref_y = cb_catalog_over(w.win, w.win->tip);
    struct node_db *sub = cb_catalog_over(w.stale, w.stale->tip);
    int bad_iters = 0, not_exact = 0;
    for (int i = 0; sub && ref_x && ref_y && i < 20; i++) {
        bool even = i % 2 == 0, exact = false;
        if (!cb_switch_branch(sub, w.fork, even ? w.win : w.stale,
                              even ? ref_y : ref_x, &exact))
            bad_iters++;
        if (!exact)
            not_exact++;
    }
    CB_CHECK("20 alternating reorgs: every unwind is exact", sub && !not_exact);
    CB_CHECK("20 alternating reorgs: catalogs equal a from-scratch catalog "
             "after every iteration", sub && ref_x && ref_y && bad_iters == 0);
    cb_close(ref_x);
    cb_close(ref_y);
    cb_close(sub);
    cb_world_free(&w);
    return failures;
}

static bool cb_clear_history(struct node_db *ndb)
{
    return catalog_history_clear(ndb, CATALOG_HISTORY_ZSLP_LEDGER) &&
           catalog_history_clear(ndb, CATALOG_HISTORY_OP_RETURN_INDEX);
}

static bool cb_both(const struct explorer_unwind_report *rep,
                    enum catalog_rewind want)
{
    return rep->zslp_ledger == want && rep->op_return_index == want;
}

/* A catalog that predates the history rebuilds once, then is exact again. */
static int cb_upgrade_rebuild(const struct cb_world *w)
{
    int failures = 0;
    const int fork = w->fork, win_tip = w->win->tip;
    struct node_db *ref = cb_catalog_over(w->win, win_tip);
    struct node_db *sub = cb_catalog_over(w->stale, w->stale->tip);
    if (!ref || !sub) {
        cb_close(ref);
        cb_close(sub);
        return 1;
    }
    struct explorer_unwind_report rep = { 0 };
    bool cleared = sub && cb_clear_history(sub);
    struct zcl_result res = cleared ? cb_unwind(sub, fork, &rep)
                                    : (struct zcl_result){0};
    CB_CHECK("upgrade: a catalog with no history falls back to a rebuild once",
             res.ok && cb_both(&rep, CATALOG_REWIND_REBUILD));
    (void)cb_index(sub, w->win, fork + 1, win_tip);
    bool folded = cb_fold_all(sub, w->win, win_tip);
    CB_CHECK("upgrade: the rebuilt catalog converges to prefix + winner",
             folded && ref && cb_diff(sub, ref, false) == 0);
    /* The rebuild accumulated history, so the next reorg is exact. */
    res = cb_unwind(sub, fork, &rep);
    CB_CHECK("upgrade: the next shallow reorg is exact",
             res.ok && cb_both(&rep, CATALOG_REWIND_EXACT));
    cb_close(ref);
    cb_close(sub);
    return failures;
}

/* The first fold after an upgrade remembers the cursor it started from, so a
 * reorg back to exactly that height is already exact. */
static int cb_upgrade_seed(const struct cb_world *w)
{
    int failures = 0;
    const int fork = w->fork;
    struct node_db *up = cb_catalog_over(w->stale, fork + 2);
    struct node_db *want = cb_catalog_over(w->stale, fork + 2);
    struct explorer_unwind_report rep = { 0 };
    bool more = up && cb_clear_history(up) &&
                cb_index(up, w->stale, fork + 3, fork + 3) &&
                cb_fold_all(up, w->stale, fork + 3);
    struct zcl_result res = more ? cb_unwind(up, fork + 2, &rep)
                                 : (struct zcl_result){0};
    CB_CHECK("upgrade: the first step after an upgrade seeds the cursor it "
             "started from (exact reorg back to it)",
             res.ok && cb_both(&rep, CATALOG_REWIND_EXACT) && want &&
             cb_diff(up, want, false) == 0);
    cb_close(up);
    cb_close(want);
    return failures;
}

static int cb_upgrade_path(void)
{
    struct cb_world w;
    if (!cb_world_build(&w, "PGSPGMS.SPGS", "SMGSS", "GSS"))
        return 1;
    int failures = cb_upgrade_rebuild(&w) + cb_upgrade_seed(&w);
    cb_world_free(&w);
    return failures;
}

static int cb_noops(void)
{
    int failures = 0;
    struct cb_world w;
    if (!cb_world_build(&w, "PGSPGMS.SPGS", "SMGSS", "GSS"))
        return 1;
    const int tip = w.stale->tip;
    struct node_db *sub = cb_catalog_over(w.stale, tip);
    struct node_db *twin = cb_catalog_over(w.stale, tip);
    struct explorer_unwind_report rep = { 0 };
    struct zcl_result at = sub ? cb_unwind(sub, tip, &rep)
                               : (struct zcl_result){0};
    CB_CHECK("fork exactly at the cursor: nothing changes",
             at.ok && cb_both(&rep, CATALOG_REWIND_NOOP) &&
             twin && cb_diff(sub, twin, false) == 0);
    struct zcl_result above = sub ? cb_unwind(sub, tip + 5, &rep)
                                  : (struct zcl_result){0};
    CB_CHECK("fork above the cursor: nothing changes",
             above.ok && cb_both(&rep, CATALOG_REWIND_NOOP) &&
             twin && cb_diff(sub, twin, false) == 0);
    cb_close(sub);
    cb_close(twin);
    cb_world_free(&w);
    return failures;
}

/* ── Taint: a fold that rewrites an earlier height cannot be undone ──── */

/* The stale tip spends an output of a token transaction stamped at an
 * EARLIER height. When that ancestor was refused at its own height (the
 * ancestry bound) and is settled by the descendant's walk, the fold rewrites
 * a row below the fork, which deleting rows above the fork cannot restore. */
static struct node_db *cb_tainted_catalog(const struct cb_world *w)
{
    struct node_db *sub = cb_open();
    const int fork = w->fork, tip = w->stale->tip;
    /* Refuse the ancestor at its own height, as the walk bound would. */
    bool ok = sub && cb_index(sub, w->stale, 0, fork) &&
              cb_fold_all(sub, w->stale, fork) &&
              node_db_exec(sub, "UPDATE zslp_validity SET status=0,"
                           "reason='ancestry_depth_exceeded' WHERE "
                           "block_height=1") &&
              node_db_exec(sub, "DELETE FROM zslp_ledger WHERE "
                           "created_height=1") &&
              cb_index(sub, w->stale, fork + 1, tip) &&
              cb_fold_all(sub, w->stale, tip);
    if (!ok) {
        cb_close(sub);
        return NULL;
    }
    return sub;
}

static int cb_taint_checks(const struct cb_world *w, struct node_db *sub)
{
    int failures = 0;
    const int fork = w->fork, tip = w->stale->tip;
    uint8_t d[32], cd[32], fd[32];
    char why[160] = "";
    bool t = false;
    int32_t ch = -1;
    CB_CHECK("a fold that settles an ancestor at an earlier height is "
             "recorded as tainted",
             sub && catalog_history_lookup(sub, CATALOG_HISTORY_ZSLP_LEDGER,
                                           tip, d, &t) && t);
    (void)zslp_ledger_get_cursor(sub, &ch, cd);
    CB_CHECK("an exact rewind across a tainted step is refused, naming why",
             sub && !catalog_history_can_rewind(sub,
                       CATALOG_HISTORY_ZSLP_LEDGER, fork, tip, cd, fd, why,
                       sizeof(why)) && strstr(why, "earlier height"));
    struct explorer_unwind_report rep = { 0 };
    struct zcl_result res = sub ? cb_unwind(sub, fork, &rep)
                                : (struct zcl_result){0};
    CB_CHECK("the reorg across it rebuilds the ledger; op_return_index, which "
             "has no such write, still rewinds exactly",
             res.ok && rep.zslp_ledger == CATALOG_REWIND_REBUILD &&
             rep.op_return_index == CATALOG_REWIND_EXACT);
    return failures;
}

static int cb_taint(void)
{
    int failures = 0;
    struct cb_world w;
    if (!cb_world_build(&w, "PG", "S", "G"))
        return 1;
    uint8_t d[32];
    bool t = true;
    struct node_db *clean = cb_catalog_over(w.stale, w.stale->tip);
    CB_CHECK("an ordinary fold records an untainted history entry",
             clean && catalog_history_lookup(clean,
                 CATALOG_HISTORY_ZSLP_LEDGER, w.stale->tip, d, &t) && !t);
    struct explorer_unwind_report rep = { 0 };
    struct zcl_result res = clean ? cb_unwind(clean, w.fork, &rep)
                                  : (struct zcl_result){0};
    CB_CHECK("an untainted reorg is exact",
             res.ok && rep.zslp_ledger == CATALOG_REWIND_EXACT);
    struct node_db *sub = cb_tainted_catalog(&w);
    failures += cb_taint_checks(&w, sub);
    cb_close(clean);
    cb_close(sub);
    cb_world_free(&w);
    return failures;
}

/* ── Concurrency ─────────────────────────────────────────────────────── */

/* Called while the unwind holds both fold guards, after its commit. */
struct cb_probe {
    struct node_db *ndb;
    int tip;
    int folded_during;
    bool op_guard_free_during;
    bool zslp_guard_free_during;
    int32_t zslp_cursor_during;
};

static bool cb_probe_hook(void *ctx, int fork_height)
{
    struct cb_probe *p = ctx;
    /* The projection and the frontier are far ahead of the rewound cursor, so
     * a backfill tick would fold if it were allowed to. */
    reducer_frontier_provable_tip_set(p->tip);
    cb_set_proj_tip(p->ndb, p->tip);
    p->folded_during = zslp_ledger_backfill_run_once();
    p->op_guard_free_during = op_return_index_fold_try_begin();
    if (p->op_guard_free_during)
        op_return_index_fold_end();
    p->zslp_guard_free_during = zslp_ledger_fold_try_begin();
    if (p->zslp_guard_free_during)
        zslp_ledger_fold_end();
    uint8_t d[32];
    (void)zslp_ledger_get_cursor(p->ndb, &p->zslp_cursor_during, d);
    cb_set_proj_tip(p->ndb, fork_height);
    return true;
}

struct cb_race {
    struct node_db *ndb;
    _Atomic(const struct cb_chain *) active;
    _Atomic bool stop;
    _Atomic int64_t zslp_batches;
    _Atomic int64_t oi_batches;
};

static void *cb_race_fold(void *arg)
{
    struct cb_race *r = arg;
    while (!atomic_load(&r->stop)) {
        if (zslp_ledger_backfill_run_once() > 0)
            atomic_fetch_add(&r->zslp_batches, 1);
        const struct cb_chain *c = atomic_load(&r->active);
        if (c && cb_oprindex_fold_to(r->ndb, c, c->tip))
            atomic_fetch_add(&r->oi_batches, 1);
        platform_sleep_ms(1); /* real-clock: paces a stress thread; no verdict depends on elapsed time */
    }
    return NULL;
}

static bool cb_race_hook(void *ctx, int fork_height)
{
    cb_set_proj_tip(((struct cb_race *)ctx)->ndb, fork_height);
    return true;
}

/* A held guard keeps the unwind out, and a given-up unwind changes nothing. */
static int cb_guard_busy(struct cb_world *w, struct node_db *sub,
                         struct node_db *ref_x)
{
    int failures = 0;
    const int fork = w->fork;
    explorer_unwind_test_set_guard_wait_ms(40);
    struct cb_state before, after;
    cb_read_state(sub, &before);
    bool z = zslp_ledger_fold_try_begin();
    struct zcl_result busy = cb_unwind(sub, fork, NULL);
    zslp_ledger_fold_end();
    CB_CHECK("unwind with the zslp fold guard held: busy, nothing changed",
             z && !busy.ok && busy.code == EXPLORER_UNWIND_ERR_BUSY &&
             cb_diff(sub, ref_x, false) == 0);
    bool o = op_return_index_fold_try_begin();
    busy = cb_unwind(sub, fork, NULL);
    op_return_index_fold_end();
    cb_read_state(sub, &after);
    CB_CHECK("unwind with the op_return fold guard held: busy, nothing "
             "changed, no repair blocker raised",
             o && !busy.ok && busy.code == EXPLORER_UNWIND_ERR_BUSY &&
             after.zslp_h == before.zslp_h &&
             after.oi.height == before.oi.height &&
             cb_diff(sub, ref_x, false) == 0 &&
             !blocker_exists(EXPLORER_UNWIND_BLOCKER_ID));
    bool both_free = zslp_ledger_fold_try_begin();
    bool oi_free = op_return_index_fold_try_begin();
    if (oi_free)
        op_return_index_fold_end();
    if (both_free)
        zslp_ledger_fold_end();
    CB_CHECK("an unwind that gave up released every guard it took",
             both_free && oi_free);
    return failures;
}

/* While the unwind runs, no backfill tick may fold and no guard is free. */
static int cb_guard_window(struct cb_world *w, struct node_db *sub)
{
    int failures = 0;
    explorer_unwind_test_set_guard_wait_ms(-1);
    struct cb_probe probe = { sub, w->stale->tip, -1, true, true, -9 };
    struct explorer_unwind_chain src = { .after_commit = cb_probe_hook,
                                         .ctx = &probe };
    g_zslp_ledger_backfill_test_ndb = sub;
    struct zcl_result res = explorer_index_unwind_above_chain(sub, w->fork,
                                                              &src, NULL);
    CB_CHECK("during the unwind a backfill tick folds nothing and both guards "
             "are held",
             res.ok && probe.folded_during == 0 &&
             !probe.op_guard_free_during && !probe.zslp_guard_free_during &&
             probe.zslp_cursor_during == w->fork);
    cb_set_proj_tip(sub, w->stale->tip);
    reducer_frontier_provable_tip_set(w->stale->tip);
    CB_CHECK("after the unwind the same tick folds again",
             zslp_ledger_backfill_run_once() > 0);
    return failures;
}

/* Backfills tick on another thread while reorgs flip the branch. The guards
 * are what keep a fold from writing a stale cursor and digest into an
 * unwind's transaction. Returns the active chain at the end. */
static const struct cb_chain *cb_stress(struct cb_world *w, struct node_db *sub,
                                        struct cb_race *race, int *busy_count,
                                        int *failed, bool *started)
{
    explorer_unwind_test_set_guard_wait_ms(20000);
    memset(race, 0, sizeof(*race));
    race->ndb = sub;
    atomic_store(&race->active, w->stale);
    g_zslp_ledger_backfill_test_ndb = sub;
    pthread_t th;
    *started = pthread_create(&th, NULL, cb_race_fold, race) == 0;
    for (int i = 0; *started && i < 160; i++) {
        const struct cb_chain *to = (i % 2 == 0) ? w->win : w->stale;
        atomic_store(&race->active, to);
        struct explorer_unwind_chain src = { .after_commit = cb_race_hook,
                                             .ctx = race };
        struct zcl_result res =
            explorer_index_unwind_above_chain(sub, w->fork, &src, NULL);
        if (!res.ok && res.code == EXPLORER_UNWIND_ERR_BUSY)
            (*busy_count)++;
        else if (!res.ok)
            (*failed)++;
        for (int h = w->fork + 1; h <= to->tip; h++) {
            (void)cb_index_one(sub, to, h);
            cb_set_proj_tip(sub, h);
            reducer_frontier_provable_tip_set(h);
        }
        platform_sleep_ms(1); /* real-clock: paces a stress thread; no verdict depends on elapsed time */
    }
    if (*started) {
        atomic_store(&race->stop, true);
        pthread_join(th, NULL);
    }
    return atomic_load(&race->active);
}

static int cb_concurrency(void)
{
    int failures = 0;
    struct cb_world w;
    if (!cb_world_build(&w, "PGSPGMS.SPGSSMGPSMGS", "SMGSPS", "GSSMPSMS"))
        return 1;
    struct node_db *ref_x = cb_catalog_over(w.stale, w.stale->tip);
    struct node_db *ref_y = cb_catalog_over(w.win, w.win->tip);
    struct node_db *sub = cb_catalog_over(w.stale, w.stale->tip);
    if (!ref_x || !ref_y || !sub) {
        cb_close(ref_x);
        cb_close(ref_y);
        cb_close(sub);
        cb_world_free(&w);
        return 1;
    }
    failures += cb_guard_busy(&w, sub, ref_x);
    failures += cb_guard_window(&w, sub);
    cb_close(sub);
    sub = cb_catalog_over(w.stale, w.stale->tip);

    struct cb_race race;
    memset(&race, 0, sizeof(race));
    int busy_count = 0, failed = 0;
    bool started = false;
    const struct cb_chain *last =
        sub ? cb_stress(&w, sub, &race, &busy_count, &failed, &started)
            : w.stale;
    bool settled = sub && cb_fold_all(sub, last, last->tip);
    CB_CHECK("stress: 160 reorgs against running backfills never fail or "
             "give up", started && busy_count == 0 && failed == 0);
    CB_CHECK("stress: the backfills really ran alongside the unwinds",
             atomic_load(&race.zslp_batches) > 0 &&
             atomic_load(&race.oi_batches) > 0);
    CB_CHECK("stress: after the last reorg the catalogs equal a from-scratch "
             "catalog",
             settled && cb_diff(sub, last == w.win ? ref_y : ref_x,
                                false) == 0);
    explorer_unwind_test_set_guard_wait_ms(-1);
    cb_close(ref_x);
    cb_close(ref_y);
    cb_close(sub);
    cb_world_free(&w);
    return failures;
}

/* ── `transactions` and the failure signal ───────────────────────────── */

static bool cb_active_hash(void *ctx, int height, uint8_t out[32])
{
    const struct cb_chain *c = ctx;
    if (height < 0 || height > c->tip)
        return false;
    memcpy(out, c->hash[height], 32);
    return true;
}

static bool cb_save_tx_row(struct node_db *ndb, uint8_t tag, int height,
                           const uint8_t hash[32])
{
    struct db_tx_index t;
    memset(&t, 0, sizeof(t));
    memset(t.txid, 0xD0, 32);
    t.txid[0] = tag;
    t.txid[1] = (uint8_t)height;
    t.txid[2] = (uint8_t)(height >> 8);
    memcpy(t.block_hash, hash, 32);
    t.block_height = height;
    return db_tx_save(ndb, &t);
}

static int cb_seed_tx_rows(struct node_db *ndb, const struct cb_world *w)
{
    int n = 0;
    for (int h = 1; h <= w->fork; h++)
        n += cb_save_tx_row(ndb, 1, h, w->common->hash[h]) ? 1 : 0;
    for (int h = w->fork + 1; h <= w->stale->tip; h++)
        n += cb_save_tx_row(ndb, 2, h, w->stale->hash[h]) ? 1 : 0;
    /* Rows the active chain owns above the fork: a snapshot import, or a lean
     * walk, can leave them there. */
    for (int h = w->fork + 1; h <= w->win->tip; h++)
        n += cb_save_tx_row(ndb, 3, h, w->win->hash[h]) ? 1 : 0;
    return n;
}

static int cb_transactions_rule(void)
{
    int failures = 0;
    struct cb_world w;
    if (!cb_world_build(&w, "PGSPG", "SMGS", "GS"))
        return 1;
    const int fork = w.fork;
    struct node_db *sub = cb_open();
    struct node_db *keep = cb_open();
    int seeded = sub ? cb_seed_tx_rows(sub, &w) : 0;
    (void)(keep ? cb_seed_tx_rows(keep, &w) : 0);
    int64_t total = sub ? cb_count(sub, "SELECT COUNT(*) FROM transactions") : -1;
    struct explorer_unwind_chain src = { .active_hash = cb_active_hash,
                                         .ctx = w.win };
    struct explorer_unwind_report rep = { 0 };
    struct zcl_result res = sub
        ? explorer_index_unwind_above_chain(sub, fork, &src, &rep)
        : (struct zcl_result){0};
    const int stale_n = w.stale->tip - fork;
    char sql[200];
    CB_CHECK("transactions: rows of blocks the active chain does not have are "
             "deleted, one block at a time",
             res.ok && seeded > 0 && (int)rep.stale_blocks_in_transactions ==
                 stale_n &&
             cb_count(sub, "SELECT COUNT(*) FROM transactions") ==
                 total - stale_n);
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM transactions WHERE "
             "block_height>%d AND substr(hex(txid),1,2)='03'", fork);
    CB_CHECK("transactions: rows above the fork whose block IS the active "
             "chain's (imported or lean) are kept",
             res.ok && cb_count(sub, sql) == w.win->tip - fork);
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM transactions WHERE "
             "block_height<=%d", fork);
    CB_CHECK("transactions: rows at or below the fork are kept",
             res.ok && cb_count(sub, sql) == fork);
    res = keep ? explorer_index_unwind_above(keep, fork, NULL, NULL)
               : (struct zcl_result){0};
    CB_CHECK("transactions: with no active-hash source the table is left "
             "alone", res.ok &&
             cb_count(keep, "SELECT COUNT(*) FROM transactions") == total);
    cb_close(sub);
    cb_close(keep);
    cb_world_free(&w);
    return failures;
}

static int cb_failure_signal(void)
{
    int failures = 0;
    struct cb_world w;
    if (!cb_world_build(&w, "PGSPGMS", "SMGS", "GS"))
        return 1;
    const int fork = w.fork;
    struct node_db *bad = cb_catalog_over(w.stale, w.stale->tip);
    struct node_db *twin = cb_catalog_over(w.stale, w.stale->tip);
    bool broke = bad && node_db_exec(bad, "DROP TABLE zanc_anchors");
    blocker_clear(EXPLORER_UNWIND_BLOCKER_ID);
    struct zcl_result res = broke ? cb_unwind(bad, fork, NULL)
                                  : (struct zcl_result){0};
    CB_CHECK("a failing unwind raises the explorer.unwind_failed blocker",
             broke && !res.ok && res.code != EXPLORER_UNWIND_ERR_BUSY &&
             blocker_exists(EXPLORER_UNWIND_BLOCKER_ID));
    /* The failure came after both catalogs were rewound inside the
     * transaction: the rollback must put cursors, rows and history back. */
    int64_t hz = bad ? catalog_history_count(bad, CATALOG_HISTORY_ZSLP_LEDGER)
                     : -1;
    CB_CHECK("a failing unwind rolls the catalogs and their history back",
             twin && cb_diff(bad, twin, false) == 0 &&
             hz == catalog_history_count(twin, CATALOG_HISTORY_ZSLP_LEDGER));
    struct node_db *good = cb_catalog_over(w.stale, w.stale->tip);
    res = good ? cb_unwind(good, fork, NULL) : (struct zcl_result){0};
    CB_CHECK("the next successful unwind clears the blocker",
             res.ok && !blocker_exists(EXPLORER_UNWIND_BLOCKER_ID));
    cb_close(bad);
    cb_close(twin);
    cb_close(good);
    cb_world_free(&w);
    return failures;
}

/* ── Cost at a realistic catalog size ────────────────────────────────── */

#define CB_BIG_ROWS 300000

static struct node_db *cb_big_catalog(bool with_history)
{
    struct node_db *ndb = cb_open();
    if (!ndb)
        return NULL;
    uint8_t d98[32], d99[32];
    memset(d98, 0x98, 32);
    memset(d99, 0x99, 32);
    bool ok = node_db_exec(ndb,
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE "
        "i<299999) INSERT INTO zslp_ledger(token_id,txid,vout,amount,address,"
        "created_height) SELECT zeroblob(32),randomblob(32),1,100,NULL,i/3 "
        "FROM n") &&
        node_db_exec(ndb,
        "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE "
        "i<299999) INSERT INTO op_return_index(txid,vout_n,height,tag,"
        "tag_text,payload_len,payload_sha3) SELECT randomblob(32),0,i/3,"
        "x'01','t',1,randomblob(32) FROM n");
    struct op_return_index_cursor cur, prev;
    memset(&cur, 0, sizeof(cur));
    cur.height = 99999;
    memcpy(cur.digest, d99, 32);
    prev = cur;
    prev.height = 99998;
    memcpy(prev.digest, d98, 32);
    ok = ok && zslp_ledger_set_cursor(ndb, 99999, d99) &&
         op_return_index_set_cursor(ndb, &cur);
    if (ok && with_history)
        ok = catalog_history_record_step(ndb, CATALOG_HISTORY_ZSLP_LEDGER,
                                         99998, d98, 99999, d99, false) &&
             catalog_history_record_step(ndb, CATALOG_HISTORY_OP_RETURN_INDEX,
                                         99998, d98, 99999, d99, false);
    if (!ok) {
        cb_close(ndb);
        return NULL;
    }
    return ndb;
}

static int cb_cost(void)
{
    int failures = 0;
    struct node_db *exact = cb_big_catalog(true);
    struct node_db *rebuild = cb_big_catalog(false);
    struct explorer_unwind_report rep = { 0 };
    int64_t t0 = platform_time_monotonic_us();
    struct zcl_result r1 = exact ? explorer_index_unwind_above(exact, 99998,
                                                              NULL, NULL)
                                 : (struct zcl_result){0};
    int64_t t1 = platform_time_monotonic_us();
    struct explorer_unwind_chain none = { 0 };
    struct zcl_result r2 = rebuild
        ? explorer_index_unwind_above_chain(rebuild, 99998, &none, &rep)
        : (struct zcl_result){0};
    int64_t t2 = platform_time_monotonic_us();
    printf("explorer_index_unwind: cost at %d rows per catalog: 1-block "
           "reorg exact rewind %.1f ms, drop-and-rebuild path %.1f ms\n",
           CB_BIG_ROWS, (double)(t1 - t0) / 1000.0,
           (double)(t2 - t1) / 1000.0);
    int64_t kept = exact ? cb_count(exact, "SELECT COUNT(*) FROM zslp_ledger")
                         : -1;
    CB_CHECK("cost: the exact rewind keeps every row at or below the fork",
             r1.ok && kept >= CB_BIG_ROWS - 3 &&
             cb_count(exact, "SELECT COUNT(*) FROM op_return_index") >=
                 CB_BIG_ROWS - 3);
    CB_CHECK("cost: without history the same reorg drops both catalogs",
             r2.ok && rep.zslp_ledger == CATALOG_REWIND_REBUILD &&
             cb_count(rebuild, "SELECT COUNT(*) FROM zslp_ledger") == 0);
    cb_close(exact);
    cb_close(rebuild);
    return failures;
}

int explorer_unwind_catalog_suite(void)
{
    int failures = 0;
    failures += cb_basic_reorgs();
    failures += cb_window_case("reorg exactly at the window depth",
                               CATALOG_HISTORY_DEPTH, CATALOG_REWIND_EXACT);
    failures += cb_window_case("reorg one past the window depth",
                               CATALOG_HISTORY_DEPTH + 1,
                               CATALOG_REWIND_REBUILD);
    failures += cb_alternating();
    failures += cb_upgrade_path();
    failures += cb_noops();
    failures += cb_taint();
    failures += cb_concurrency();
    failures += cb_transactions_rule();
    failures += cb_failure_signal();
    failures += cb_cost();
    g_zslp_ledger_backfill_test_ndb = NULL;
    reducer_frontier_provable_tip_reset();
    return failures;
}
