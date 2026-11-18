/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Randomised exactness check of the reorg unwind of the explorer projection
 * and its two cursor-owning catalogs (zslp_ledger, op_return_index).
 *
 * Each iteration draws, from a fixed seed, a common prefix, a losing branch
 * and a winning branch of multi-transaction blocks carrying every kind of
 * operation the zslp fold and the op_return fold handle: valid GENESIS, MINT
 * and SEND; a SEND over its input, a MINT off a non-baton output, a
 * transparent burn of a token or baton output, a truncated SLP script, a
 * plain OP_RETURN, empty heights, spends of outputs made earlier in the same
 * block, and a winner that re-mines the loser's own transactions at other
 * heights. The catalogs are folded over the loser to independent random
 * heights (behind, at or ahead of the fork), the unwind runs, and every row
 * of the projection, both catalogs and the digest history, both cursors and
 * both digests must equal a database built from scratch over the prefix with
 * the same fold heights. The winner is then folded and compared with a
 * from-scratch build of prefix + winner, and a second unwind to a random
 * height (often inside the prefix) is compared again.
 *
 * Z23_UNWIND_RANDOM_ITERS overrides the iteration count (default 120) for a
 * longer local soak. node.db in memory only. */

#include "test/test_core.h"
#include "chain/chain.h"
#include "jobs/reducer_frontier.h"
#include "models/catalog_digest_history.h"
#include "models/database.h"
#include "models/explorer_index.h"
#include "models/op_return_index.h"
#include "models/zslp_ledger.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "services/explorer_unwind_service.h"
#include "services/zslp_ledger_backfill_service.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "zslp/slp.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RZ_MAX_H 200
#define RZ_MAX_TXB 3
#define RZ_ARENA (RZ_MAX_H * RZ_MAX_TXB * 3)
#define RZ_POOL 96
#define RZ_DEFAULT_ITERS 120

#define CB_RZ_CHECK(label, cond) do { \
    printf("explorer_index_unwind: %s... ", (label)); \
    if (cond) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Deterministic randomness ────────────────────────────────────────── */

static uint64_t rz_next(uint64_t *s)
{
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

static int rz_range(uint64_t *s, int lo, int hi)
{
    return lo + (int)(rz_next(s) % (uint64_t)(hi - lo + 1));
}

/* ── Chains of multi-transaction blocks ──────────────────────────────── */

struct rz_arena {
    struct transaction tx[RZ_ARENA];
    size_t n;
    uint32_t serial;
};

struct rz_chain {
    const struct transaction *tx[RZ_MAX_H][RZ_MAX_TXB];
    int ntx[RZ_MAX_H];
    uint8_t hash[RZ_MAX_H][32];
    int tip;
};

struct rz_out {
    uint8_t txid[32];
    uint32_t vout;
    uint64_t amount;
    bool baton;
    uint8_t token[32];
};

struct rz_pool {
    struct rz_out out[RZ_POOL];
    size_t n;
};

static void rz_pool_add(struct rz_pool *p, const uint8_t txid[32],
                        uint32_t vout, uint64_t amount, bool baton,
                        const uint8_t token[32])
{
    if (p->n >= RZ_POOL)
        return;
    struct rz_out *o = &p->out[p->n++];
    memcpy(o->txid, txid, 32);
    o->vout = vout;
    o->amount = amount;
    o->baton = baton;
    memcpy(o->token, token, 32);
}

static void rz_pool_take(struct rz_pool *p, size_t i)
{
    p->out[i] = p->out[--p->n];
}

/* A random pool entry that is (or is not) a baton; false when none. */
static bool rz_pool_pick(const struct rz_pool *p, uint64_t *rng, int baton,
                         size_t *at)
{
    if (p->n == 0)
        return false;
    size_t start = (size_t)(rz_next(rng) % p->n);
    for (size_t k = 0; k < p->n; k++) {
        size_t i = (start + k) % p->n;
        if (baton < 0 || p->out[i].baton == (baton != 0)) {
            *at = i;
            return true;
        }
    }
    return false;
}

static void rz_wire(const uint8_t token[32], struct uint256 *wire)
{
    for (int i = 0; i < 32; i++)
        wire->data[i] = token[31 - i];
}

struct rz_spec {
    bool has_in;
    uint8_t in_txid[32];
    uint32_t in_n;
    uint8_t script[300];
    size_t slen;
    size_t npay;
};

static void rz_make_tx(struct rz_arena *ar, struct transaction *tx,
                       const struct rz_spec *sp)
{
    static const uint8_t pre[3] = { 0x76, 0xa9, 0x14 };
    static const uint8_t post[2] = { 0x88, 0xac };
    uint32_t serial = ++ar->serial;
    transaction_init(tx);
    transaction_alloc(tx, 1, 1 + sp->npay);
    if (sp->has_in) {
        memcpy(tx->vin[0].prevout.hash.data, sp->in_txid, 32);
        tx->vin[0].prevout.n = sp->in_n;
    } else {
        memset(tx->vin[0].prevout.hash.data, 0xC5, 32);
        memcpy(tx->vin[0].prevout.hash.data, &serial, sizeof(serial));
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
        memset(p + 3, (int)(0x10 + (serial + i) % 5), 20);
        memcpy(p + 23, post, 2);
        tx->vout[1 + i].script_pub_key.size = 25;
    }
    tx->lock_time = serial;
    transaction_compute_hash(tx);
}

/* Fill the spec of a spend of pool entry `at`. */
static void rz_spend(struct rz_spec *sp, const struct rz_pool *p, size_t at)
{
    sp->has_in = true;
    memcpy(sp->in_txid, p->out[at].txid, 32);
    sp->in_n = p->out[at].vout;
}

static void rz_plain_script(struct rz_spec *sp, uint32_t serial)
{
    static const uint8_t plain[] = { 0x6a, 0x08, 'R', 'Z', 'P', 'L' };
    memcpy(sp->script, plain, sizeof(plain));
    memcpy(sp->script + sizeof(plain), &serial, sizeof(serial));
    sp->slen = sizeof(plain) + sizeof(serial);
}

/* What the generated transaction did to the pool: outputs 1..2 as token,
 * baton or nothing. */
struct rz_effect {
    int took;              /* pool index spent, or -1 */
    uint8_t token[32];
    uint64_t amt[2];
    bool baton[2];
    int nout;              /* token-ish outputs to add */
    bool own_token;        /* GENESIS: the token is the transaction itself */
};

static void rz_kind_genesis(struct rz_spec *sp, struct rz_effect *e,
                            uint64_t qty)
{
    sp->slen = slp_build_genesis(sp->script, sizeof(sp->script), "RZ",
                                 "Random", "", NULL, 0, 2, qty);
    sp->npay = 2;
    e->own_token = true;
    e->amt[0] = qty;
    e->baton[1] = true;
    e->nout = 2;
}

/* SEND splitting one input; `over` asks for more than the input holds. */
static bool rz_kind_send(struct rz_spec *sp, struct rz_effect *e,
                         const struct rz_pool *p, uint64_t *rng, bool over)
{
    size_t at = 0;
    if (!rz_pool_pick(p, rng, 0, &at))
        return false;
    rz_spend(sp, p, at);
    struct uint256 wire;
    rz_wire(p->out[at].token, &wire);
    uint64_t q[2];
    q[0] = p->out[at].amount / 3;
    q[1] = p->out[at].amount - q[0] + (over ? 5u : 0u);
    sp->slen = slp_build_send(sp->script, sizeof(sp->script), &wire, q, 2);
    sp->npay = 2;
    e->took = (int)at;
    memcpy(e->token, p->out[at].token, 32);
    e->amt[0] = q[0];
    e->amt[1] = q[1];
    e->nout = 2;
    return true;
}

/* MINT; `bad_lineage` spends a non-baton output instead of the baton. */
static bool rz_kind_mint(struct rz_spec *sp, struct rz_effect *e,
                         const struct rz_pool *p, uint64_t *rng,
                         bool bad_lineage, uint64_t qty)
{
    size_t at = 0;
    if (!rz_pool_pick(p, rng, bad_lineage ? 0 : 1, &at))
        return false;
    rz_spend(sp, p, at);
    struct uint256 wire;
    rz_wire(p->out[at].token, &wire);
    sp->slen = slp_build_mint(sp->script, sizeof(sp->script), &wire, 2, qty);
    sp->npay = 2;
    e->took = (int)at;
    memcpy(e->token, p->out[at].token, 32);
    e->amt[0] = qty;
    e->baton[1] = true;
    e->nout = 2;
    return true;
}

/* A transparent spend of any token or baton output with a plain OP_RETURN:
 * an explicit burn. */
static bool rz_kind_burn(struct rz_spec *sp, struct rz_effect *e,
                         const struct rz_pool *p, uint64_t *rng,
                         uint32_t serial)
{
    size_t at = 0;
    if (!rz_pool_pick(p, rng, -1, &at))
        return false;
    rz_spend(sp, p, at);
    rz_plain_script(sp, serial);
    sp->npay = 1;
    e->took = (int)at;
    return true;
}

/* A SLP-tagged script cut short. The indexer stores it with is_slp=0 (only a
 * parsing script is flagged), so the zslp fold never sees it; it is an
 * op_return_index row carrying the SLP tag. */
static void rz_kind_malformed(struct rz_spec *sp)
{
    uint8_t token[32];
    memset(token, 0x77, sizeof(token));
    struct uint256 wire;
    rz_wire(token, &wire);
    uint64_t q[1] = { 9 };
    size_t n = slp_build_send(sp->script, sizeof(sp->script), &wire, q, 1);
    sp->slen = n > 12 ? n - 9 : n;
    sp->npay = 1;
}

static bool rz_fill_kind(char kind, struct rz_spec *sp, struct rz_effect *e,
                         const struct rz_pool *p, uint64_t *rng,
                         uint32_t serial)
{
    const uint64_t qty = 100u + (uint64_t)(rz_next(rng) % 5000u);
    switch (kind) {
    case 'S': return rz_kind_send(sp, e, p, rng, false);
    case 'X': return rz_kind_send(sp, e, p, rng, true);
    case 'M': return rz_kind_mint(sp, e, p, rng, false, qty);
    case 'N': return rz_kind_mint(sp, e, p, rng, true, qty);
    case 'B': return rz_kind_burn(sp, e, p, rng, serial);
    case 'Z': rz_kind_malformed(sp); return true;
    case 'P': rz_plain_script(sp, serial); return true;
    default: rz_kind_genesis(sp, e, qty); return true;
    }
}

static char rz_draw_kind(uint64_t *rng)
{
    static const char k_kinds[] = "GGGSSSSSSXXMMMNBBZPPP";
    return k_kinds[rz_next(rng) % (sizeof(k_kinds) - 1)];
}

/* One transaction of a random kind; NULL when the arena is full. */
static const struct transaction *rz_gen_tx(struct rz_arena *ar,
                                           struct rz_pool *p, uint64_t *rng)
{
    if (ar->n >= RZ_ARENA)
        return NULL;
    struct rz_spec sp;
    struct rz_effect e;
    memset(&sp, 0, sizeof(sp));
    memset(&e, 0, sizeof(e));
    e.took = -1;
    char kind = rz_draw_kind(rng);
    if (!rz_fill_kind(kind, &sp, &e, p, rng, ar->serial + 1)) {
        memset(&sp, 0, sizeof(sp));
        memset(&e, 0, sizeof(e));
        e.took = -1;
        rz_kind_genesis(&sp, &e, 777);
    }
    struct transaction *tx = &ar->tx[ar->n++];
    rz_make_tx(ar, tx, &sp);
    if (e.took >= 0)
        rz_pool_take(p, (size_t)e.took);
    if (e.own_token)
        memcpy(e.token, tx->hash.data, 32);
    for (int i = 0; i < e.nout; i++)
        rz_pool_add(p, tx->hash.data, (uint32_t)(1 + i), e.amt[i], e.baton[i],
                    e.token);
    return tx;
}

static void rz_set_hash(struct rz_chain *c, int h, uint8_t branch)
{
    memset(c->hash[h], 0x60 + branch, 32);
    c->hash[h][0] = (uint8_t)h;
    c->hash[h][1] = (uint8_t)(h >> 8);
    c->hash[h][2] = branch;
}

/* Append `len` random heights of branch `branch` starting at `from`. */
static void rz_extend(struct rz_chain *c, struct rz_arena *ar,
                      struct rz_pool *p, uint64_t *rng, int from, int len,
                      uint8_t branch)
{
    for (int i = 0; i < len && from + i < RZ_MAX_H; i++) {
        int h = from + i;
        int n = rz_range(rng, 0, 4) == 0 ? 0 : rz_range(rng, 1, RZ_MAX_TXB);
        c->ntx[h] = 0;
        for (int k = 0; k < n; k++) {
            const struct transaction *tx = rz_gen_tx(ar, p, rng);
            if (tx)
                c->tx[h][c->ntx[h]++] = tx;
        }
        rz_set_hash(c, h, branch);
        c->tip = h;
    }
}

/* The winner re-mines the loser's transactions `shift` heights later, after
 * `shift` empty heights of its own. */
static void rz_remine(struct rz_chain *win, const struct rz_chain *stale,
                      int fork, int shift)
{
    for (int i = 0; i < shift && fork + 1 + i < RZ_MAX_H; i++) {
        win->ntx[fork + 1 + i] = 0;
        rz_set_hash(win, fork + 1 + i, 2);
        win->tip = fork + 1 + i;
    }
    for (int h = fork + 1; h <= stale->tip && h + shift < RZ_MAX_H; h++) {
        int to = h + shift;
        win->ntx[to] = stale->ntx[h];
        for (int k = 0; k < stale->ntx[h]; k++)
            win->tx[to][k] = stale->tx[h][k];
        rz_set_hash(win, to, 2);
        win->tip = to;
    }
}

struct rz_world {
    struct rz_arena *arena;
    struct rz_chain *common, *stale, *win;
    int fork;
    bool remined;
};

static void rz_world_free(struct rz_world *w)
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

static bool rz_world_build(struct rz_world *w, uint64_t *rng)
{
    memset(w, 0, sizeof(*w));
    w->arena = zcl_calloc(1, sizeof(*w->arena), "rz arena");
    w->common = zcl_calloc(1, sizeof(*w->common), "rz chain");
    w->stale = zcl_calloc(1, sizeof(*w->stale), "rz chain");
    w->win = zcl_calloc(1, sizeof(*w->win), "rz chain");
    if (!w->arena || !w->common || !w->stale || !w->win) {
        rz_world_free(w);
        return false;
    }
    struct rz_pool pool;
    memset(&pool, 0, sizeof(pool));
    w->fork = rz_range(rng, 0, 50);
    rz_extend(w->common, w->arena, &pool, rng, 0, w->fork + 1, 0);
    struct rz_pool ps = pool, pw = pool;
    *w->stale = *w->common;
    *w->win = *w->common;
    rz_extend(w->stale, w->arena, &ps, rng, w->fork + 1, rz_range(rng, 1, 30),
              1);
    w->remined = rz_range(rng, 0, 3) == 0;
    if (w->remined) {
        rz_remine(w->win, w->stale, w->fork, rz_range(rng, 1, 3));
        pw = ps;
    }
    int from = w->remined ? w->win->tip + 1 : w->fork + 1;
    rz_extend(w->win, w->arena, &pw, rng, from,
              rz_range(rng, w->remined ? 0 : 1, 30), 2);
    return true;
}

/* ── Databases ───────────────────────────────────────────────────────── */

static struct node_db *rz_open(void)
{
    struct node_db *ndb = zcl_calloc(1, sizeof(*ndb), "rz db");
    if (!ndb)
        return NULL;
    if (!node_db_open(ndb, ":memory:") || !ndb->open) {
        free(ndb);
        return NULL;
    }
    return ndb;
}

static void rz_close(struct node_db *ndb)
{
    if (!ndb)
        return;
    node_db_close(ndb);
    free(ndb);
}

static void rz_set_proj_tip(struct node_db *ndb, int64_t h)
{
    (void)node_db_state_set_int(ndb, "sync_projection_tip_height", h);
}

static bool rz_index_one(struct node_db *ndb, const struct rz_chain *c, int h)
{
    if (c->ntx[h] == 0)
        return true;
    struct transaction vtx[RZ_MAX_TXB];
    for (int k = 0; k < c->ntx[h]; k++)
        vtx[k] = *c->tx[h][k];
    struct block blk;
    block_init(&blk);
    blk.vtx = vtx;
    blk.num_vtx = (size_t)c->ntx[h];
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

static bool rz_index(struct node_db *ndb, const struct rz_chain *c, int from,
                     int to)
{
    bool ok = true;
    for (int h = from; h <= to; h++) {
        ok = rz_index_one(ndb, c, h) && ok;
        rz_set_proj_tip(ndb, h);
    }
    return ok;
}

/* zslp_ledger through its real backfill service, then the projection tip
 * back where the indexer left it. */
static bool rz_zslp_fold_to(struct node_db *ndb, int32_t upto, int64_t proj)
{
    g_zslp_ledger_backfill_test_ndb = ndb;
    reducer_frontier_provable_tip_set(upto);
    rz_set_proj_tip(ndb, upto);
    for (int i = 0; i < 64; i++)
        if (zslp_ledger_backfill_run_once() == 0)
            break;
    rz_set_proj_tip(ndb, proj);
    int32_t cur = -9;
    uint8_t d[32];
    return zslp_ledger_get_cursor(ndb, &cur, d) && cur >= upto;
}

/* op_return_index with the calls its backfill makes per height. */
static bool rz_oprindex_fold_to(struct node_db *ndb, const struct rz_chain *c,
                                int32_t upto)
{
    if (!op_return_index_fold_try_begin())
        return false;
    struct op_return_index_cursor cur;
    bool ok = op_return_index_get_cursor(ndb, &cur);
    struct op_return_index_row rows[RZ_MAX_TXB * 2];
    for (int32_t h = cur.height + 1; ok && h <= upto; h++) {
        struct transaction vtx[RZ_MAX_TXB];
        for (int k = 0; k < c->ntx[h]; k++)
            vtx[k] = *c->tx[h][k];
        struct block blk;
        block_init(&blk);
        blk.vtx = c->ntx[h] ? vtx : NULL;
        blk.num_vtx = (size_t)c->ntx[h];
        size_t n = 0;
        ok = op_return_index_apply_block_rows(ndb, &blk, h, rows,
                                              RZ_MAX_TXB * 2, &n);
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

/* Index `c` to `proj` and fold the catalogs to `zc` / `oc` (-1: none). */
static struct node_db *rz_build(const struct rz_chain *c, int proj, int zc,
                                int oc)
{
    struct node_db *ndb = rz_open();
    bool ok = ndb && rz_index(ndb, c, 0, proj);
    if (ok && zc >= 0)
        ok = rz_zslp_fold_to(ndb, zc, proj);
    if (ok && oc >= 0)
        ok = rz_oprindex_fold_to(ndb, c, oc);
    if (!ok) {
        rz_close(ndb);
        return NULL;
    }
    return ndb;
}

/* ── Comparison: every row of every table the unwind touches ─────────── */

static const char *const k_rz_tables[] = {
    "zslp_ledger", "zslp_validity", "op_return_index",
    "catalog_digest_history", "tx_outputs", "tx_inputs", "op_returns",
    "zslp_transfers", "zslp_tokens", "view_integrity",
};

static uint64_t rz_fnv(uint64_t h, const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) {
        h ^= b[i];
        h *= 1099511628211ull;
    }
    return h;
}

/* A multiset hash: the sum of per-row hashes, so row order is irrelevant. */
static uint64_t rz_table_hash(struct node_db *ndb, const char *table,
                              int64_t *rows)
{
    char sql[96];
    snprintf(sql, sizeof(sql), "SELECT * FROM %s", table);
    sqlite3_stmt *s = NULL;
    uint64_t sum = 0;
    *rows = -1;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK || !s)
        return 0;
    *rows = 0;
    while (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:test-readonly-dump
        uint64_t h = 1469598103934665603ull;
        int cols = sqlite3_column_count(s);
        for (int c = 0; c < cols; c++) {
            int type = sqlite3_column_type(s, c);
            h = rz_fnv(h, &type, sizeof(type));
            if (type == SQLITE_BLOB)
                h = rz_fnv(h, sqlite3_column_blob(s, c),
                           (size_t)sqlite3_column_bytes(s, c));
            else if (type != SQLITE_NULL)
                h = rz_fnv(h, sqlite3_column_text(s, c),
                           (size_t)sqlite3_column_bytes(s, c));
        }
        sum += h;
        (*rows)++;
    }
    sqlite3_finalize(s);
    return sum;
}

static int rz_cursor_diff(struct node_db *x, struct node_db *y)
{
    int bad = 0;
    int32_t zx = -9, zy = -9;
    uint8_t dx[32] = {0}, dy[32] = {0};
    (void)zslp_ledger_get_cursor(x, &zx, dx);
    (void)zslp_ledger_get_cursor(y, &zy, dy);
    if (zx != zy || memcmp(dx, dy, 32) != 0) {
        bad++;
        printf("\n    zslp cursor %d vs %d%s", zx, zy,
               zx == zy ? " (digest differs)" : "");
    }
    struct op_return_index_cursor ox, oy;
    memset(&ox, 0, sizeof(ox));
    memset(&oy, 0, sizeof(oy));
    (void)op_return_index_get_cursor(x, &ox);
    (void)op_return_index_get_cursor(y, &oy);
    if (ox.height != oy.height || memcmp(ox.digest, oy.digest, 32) != 0 ||
        ox.base_height != oy.base_height) {
        bad++;
        printf("\n    op_return cursor %d vs %d%s", ox.height, oy.height,
               ox.height == oy.height ? " (digest differs)" : "");
    }
    if (zslp_ledger_rederive_floor_get(x, NULL)) {
        bad++;
        printf("\n    a re-derive floor is left behind");
    }
    return bad;
}

static int rz_diff(struct node_db *x, struct node_db *y)
{
    int bad = 0;
    for (size_t i = 0; i < sizeof(k_rz_tables) / sizeof(k_rz_tables[0]); i++) {
        int64_t rx, ry;
        uint64_t hx = rz_table_hash(x, k_rz_tables[i], &rx);
        uint64_t hy = rz_table_hash(y, k_rz_tables[i], &ry);
        if (hx != hy || rx != ry || rx < 0) {
            bad++;
            printf("\n    %s differs (%lld vs %lld rows)", k_rz_tables[i],
                   (long long)rx, (long long)ry);
        }
    }
    return bad + rz_cursor_diff(x, y);
}

static bool rz_hook_move_tip(void *ctx, int fork_height)
{
    rz_set_proj_tip(ctx, fork_height);
    return true;
}

static struct zcl_result rz_unwind(struct node_db *ndb, int fork,
                                   struct explorer_unwind_report *rep)
{
    struct explorer_unwind_chain src = { .after_commit = rz_hook_move_tip,
                                         .ctx = ndb };
    return explorer_index_unwind_above_chain(ndb, fork, &src, rep);
}

/* The outcome a catalog with cursor `cur` must report for `fork`. */
static bool rz_outcome_ok(enum catalog_rewind got, int cur, int fork)
{
    return cur > fork ? got == CATALOG_REWIND_EXACT
                      : got == CATALOG_REWIND_NOOP;
}

/* ── One iteration ───────────────────────────────────────────────────── */

/* The verdicts the generated operations must reach at least once over the
 * run, so a generator change cannot quietly stop exercising a fold path. */
static const char *const k_rz_reasons[] = {
    "valid_genesis", "valid_send", "valid_mint", "send_output_exceeds_input",
    "mint_baton_lineage_invalid", "send_ancestry_invalid",
};
#define RZ_N_REASONS (sizeof(k_rz_reasons) / sizeof(k_rz_reasons[0]))

struct rz_stats {
    int iters, failed, exact, noop, remined, second, rows_max;
    int64_t reason_seen[RZ_N_REASONS];
    int64_t spent_rows, burn_spends;
};

static int64_t rz_count(struct node_db *ndb, const char *sql, const char *arg)
{
    sqlite3_stmt *s = NULL;
    int64_t n = 0;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK || !s)
        return 0;
    if (arg)
        sqlite3_bind_text(s, 1, arg, -1, SQLITE_STATIC);
    if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:test-readonly-count
        n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

static void rz_note_coverage(struct node_db *ref, struct rz_stats *st)
{
    for (size_t i = 0; i < RZ_N_REASONS; i++)
        st->reason_seen[i] += rz_count(ref, "SELECT COUNT(*) FROM "
                                       "zslp_validity WHERE reason=?",
                                       k_rz_reasons[i]);
    st->spent_rows += rz_count(ref, "SELECT COUNT(*) FROM zslp_ledger WHERE "
                               "spent_by_txid IS NOT NULL", NULL);
    st->burn_spends += rz_count(ref, "SELECT COUNT(*) FROM zslp_ledger l "
                                "WHERE spent_by_txid IS NOT NULL AND NOT "
                                "EXISTS (SELECT 1 FROM zslp_validity v WHERE "
                                "v.txid=l.spent_by_txid)", NULL);
}

static bool rz_coverage_complete(const struct rz_stats *st)
{
    bool all = st->spent_rows > 0 && st->burn_spends > 0;
    for (size_t i = 0; i < RZ_N_REASONS; i++) {
        if (st->reason_seen[i] == 0) {
            printf("\n    never reached: %s", k_rz_reasons[i]);
            all = false;
        }
    }
    return all;
}

static int rz_min(int a, int b)
{
    return a < b ? a : b;
}

/* Unwind `sub` to `fork` and compare with a from-scratch build of `c` to the
 * fork with the catalogs folded to the same heights. */
static int rz_unwind_and_compare(struct node_db *sub, const struct rz_chain *c,
                                 int fork, int zc, int oc,
                                 struct rz_stats *st, const char *what)
{
    struct explorer_unwind_report rep;
    struct zcl_result res = rz_unwind(sub, fork, &rep);
    int bad = 0;
    if (!res.ok || !rz_outcome_ok(rep.zslp_ledger, zc, fork) ||
        !rz_outcome_ok(rep.op_return_index, oc, fork)) {
        printf("\n    %s: unwind to %d: ok=%d zslp=%d oprindex=%d (cursors "
               "%d/%d)", what, fork, res.ok, rep.zslp_ledger,
               rep.op_return_index, zc, oc);
        bad++;
    }
    st->exact += (rep.zslp_ledger == CATALOG_REWIND_EXACT) +
                 (rep.op_return_index == CATALOG_REWIND_EXACT);
    st->noop += (rep.zslp_ledger == CATALOG_REWIND_NOOP) +
                (rep.op_return_index == CATALOG_REWIND_NOOP);
    struct node_db *pre = rz_build(c, fork, rz_min(zc, fork),
                                   rz_min(oc, fork));
    if (!pre) {
        printf("\n    %s: prefix build failed", what);
        return bad + 1;
    }
    int d = rz_diff(sub, pre);
    if (d)
        printf("\n    %s: rewound state differs from the prefix build", what);
    rz_close(pre);
    return bad + d;
}

/* Fold the winner on `sub` and compare with a from-scratch build. */
static int rz_fold_winner(struct node_db *sub, const struct rz_chain *win,
                          int from, struct node_db *ref, const char *what)
{
    bool ok = rz_index(sub, win, from, win->tip) &&
              rz_zslp_fold_to(sub, win->tip, win->tip) &&
              rz_oprindex_fold_to(sub, win, win->tip);
    int d = ok ? rz_diff(sub, ref) : 1;
    if (d)
        printf("\n    %s: state after the winner differs from the "
               "from-scratch build", what);
    return d;
}

static int rz_second_reorg(struct node_db *sub, const struct rz_world *w,
                           struct node_db *ref, uint64_t *rng,
                           struct rz_stats *st)
{
    int tip = w->win->tip;
    int fork2 = rz_range(rng, 0, tip > 0 ? tip - 1 : 0);
    st->second++;
    int bad = rz_unwind_and_compare(sub, w->win, fork2, tip, tip, st,
                                    "second reorg");
    return bad + rz_fold_winner(sub, w->win, fork2 + 1, ref, "second reorg");
}

static int rz_iteration(uint64_t seed, struct rz_stats *st)
{
    uint64_t rng = seed;
    struct rz_world w;
    if (!rz_world_build(&w, &rng))
        return 1;
    const int fork = w.fork, stale_tip = w.stale->tip;
    int zc = rz_range(&rng, fork > 3 ? fork - 3 : 0, stale_tip);
    int oc = rz_range(&rng, fork > 3 ? fork - 3 : 0, stale_tip);
    st->remined += w.remined;
    struct node_db *sub = rz_build(w.stale, stale_tip, zc, oc);
    struct node_db *ref = rz_build(w.win, w.win->tip, w.win->tip, w.win->tip);
    int bad = (!sub || !ref) ? 1 : 0;
    if (!bad) {
        bad += rz_unwind_and_compare(sub, w.common, fork, zc, oc, st,
                                     "first reorg");
        bad += rz_fold_winner(sub, w.win, fork + 1, ref, "first reorg");
    }
    if (!bad && rz_range(&rng, 0, 1) == 0)
        bad += rz_second_reorg(sub, &w, ref, &rng, st);
    int64_t rows = 0;
    if (ref) {
        (void)rz_table_hash(ref, "zslp_ledger", &rows);
        rz_note_coverage(ref, st);
    }
    if (rows > st->rows_max)
        st->rows_max = (int)rows;
    if (bad)
        printf("\n    seed %llu: fork %d stale tip %d win tip %d zc %d oc %d "
               "remined %d\n", (unsigned long long)seed, fork, stale_tip,
               w.win->tip, zc, oc, w.remined);
    rz_close(sub);
    rz_close(ref);
    rz_world_free(&w);
    return bad;
}

/* ── History written by a different fold ─────────────────────────────── */

/* What a binary without the history did on a reorg: drop both catalogs (the
 * history table is not its to clear) and refold, cursor only. */
static bool rz_legacy_truncate(struct node_db *ndb)
{
    uint8_t zero[32] = {0};
    struct op_return_index_cursor empty;
    memset(&empty, 0, sizeof(empty));
    empty.height = -1;
    return node_db_exec(ndb, "DELETE FROM zslp_ledger") &&
           node_db_exec(ndb, "DELETE FROM zslp_validity") &&
           node_db_exec(ndb, "DELETE FROM op_return_index") &&
           zslp_ledger_set_cursor(ndb, -1, zero) &&
           op_return_index_set_cursor(ndb, &empty);
}

static bool rz_legacy_fold(struct node_db *ndb, const struct rz_chain *c,
                           int32_t upto)
{
    int32_t zh = -1;
    uint8_t zd[32], nd[32];
    bool ok = zslp_ledger_get_cursor(ndb, &zh, zd);
    for (int32_t h = zh + 1; ok && h <= upto; h++) {
        ok = zslp_ledger_apply_height(ndb, h, zd, nd) &&
             zslp_ledger_set_cursor(ndb, h, nd);
        memcpy(zd, nd, 32);
    }
    struct op_return_index_cursor cur;
    ok = ok && op_return_index_get_cursor(ndb, &cur);
    struct op_return_index_row rows[RZ_MAX_TXB * 2];
    for (int32_t h = cur.height + 1; ok && h <= upto; h++) {
        struct transaction vtx[RZ_MAX_TXB];
        for (int k = 0; k < c->ntx[h]; k++)
            vtx[k] = *c->tx[h][k];
        struct block blk;
        block_init(&blk);
        blk.vtx = c->ntx[h] ? vtx : NULL;
        blk.num_vtx = (size_t)c->ntx[h];
        size_t n = 0;
        ok = op_return_index_apply_block_rows(ndb, &blk, h, rows,
                                              RZ_MAX_TXB * 2, &n);
        blk.vtx = NULL;
        blk.num_vtx = 0;
        struct op_return_index_cursor next = cur;
        next.height = h;
        op_return_index_fold_block_digest(cur.base_height, cur.base_digest,
                                          cur.digest, h, c->hash[h], rows, n,
                                          next.digest);
        ok = ok && op_return_index_set_cursor(ndb, &next);
        cur = next;
    }
    return ok;
}

/* The node ran with the history, was downgraded to a binary without it, took
 * a reorg there (legacy truncate + refold of the winner), and was upgraded
 * again. The history still holds the LOSER's digests at heights the winner
 * now covers. The first fold after the upgrade must not keep them: a later
 * reorg to such a height would otherwise "rewind exactly" to a loser digest
 * over winner rows. */
/* A loser longer than the winner, so its history covers every winner height,
 * and a winner at least four heights past the fork. */
static void rz_downgrade_world(struct rz_world *w, uint64_t *rng)
{
    rz_extend(w->stale, w->arena, &(struct rz_pool){0}, rng,
              w->stale->tip + 1, 12, 1);
    if (w->win->tip + 6 >= w->stale->tip)
        rz_extend(w->stale, w->arena, &(struct rz_pool){0}, rng,
                  w->stale->tip + 1, w->win->tip + 7 - w->stale->tip, 1);
    rz_extend(w->win, w->arena, &(struct rz_pool){0}, rng, w->win->tip + 1,
              3, 2);
}

/* Fold the loser with the history, then take the reorg the legacy way and
 * refold the winner without it, then fold the last winner height with it. */
static bool rz_downgrade_state(struct node_db *sub, const struct rz_world *w)
{
    const int fork = w->fork, wtip = w->win->tip;
    struct explorer_unwind_report rep;
    return sub && rz_legacy_truncate(sub) &&
           rz_unwind(sub, fork, &rep).ok &&
           rz_index(sub, w->win, fork + 1, wtip - 1) &&
           rz_legacy_fold(sub, w->win, wtip - 1) &&
           rz_index(sub, w->win, wtip, wtip) &&
           rz_zslp_fold_to(sub, wtip, wtip) &&
           rz_oprindex_fold_to(sub, w->win, wtip);
}

/* Each catalog either rebuilt, or rewound exactly to the prefix's digest. */
static bool rz_rewound_honestly(struct node_db *sub, struct node_db *pre,
                                const struct explorer_unwind_report *rep)
{
    int32_t zs = -9, zp = -9;
    uint8_t ds[32] = {0}, dp[32] = {0};
    struct op_return_index_cursor os, op;
    memset(&os, 0, sizeof(os));
    memset(&op, 0, sizeof(op));
    (void)zslp_ledger_get_cursor(sub, &zs, ds);
    (void)zslp_ledger_get_cursor(pre, &zp, dp);
    (void)op_return_index_get_cursor(sub, &os);
    (void)op_return_index_get_cursor(pre, &op);
    bool zok = rep->zslp_ledger == CATALOG_REWIND_REBUILD ||
               (rep->zslp_ledger == CATALOG_REWIND_EXACT && zs == zp &&
                memcmp(ds, dp, 32) == 0);
    bool ook = rep->op_return_index == CATALOG_REWIND_REBUILD ||
               (rep->op_return_index == CATALOG_REWIND_EXACT &&
                os.height == op.height && memcmp(os.digest, op.digest, 32) == 0);
    return zok && ook;
}

static int rz_downgrade_gap(void)
{
    int failures = 0;
    uint64_t rng = 0xD0A1;
    struct rz_world w;
    if (!rz_world_build(&w, &rng))
        return 1;
    rz_downgrade_world(&w, &rng);
    const int fork = w.fork, wtip = w.win->tip;
    struct node_db *sub = rz_build(w.stale, w.stale->tip, w.stale->tip,
                                   w.stale->tip);
    bool ok = rz_downgrade_state(sub, &w);
    CB_RZ_CHECK("downgrade gap: the scenario builds", ok);
    const int f = fork + 1;
    struct explorer_unwind_report rep;
    memset(&rep, 0, sizeof(rep));
    struct zcl_result res = ok ? rz_unwind(sub, f, &rep)
                               : (struct zcl_result){0};
    struct node_db *pre = ok ? rz_build(w.win, f, f, f) : NULL;
    CB_RZ_CHECK("downgrade gap: a reorg after the upgrade never restores a "
                "loser digest kept in the history (each catalog rebuilds or "
                "rewinds to the from-scratch digest)",
                pre && res.ok && rz_rewound_honestly(sub, pre, &rep));
    struct node_db *ref = ok ? rz_build(w.win, wtip, wtip, wtip) : NULL;
    bool conv = ref && rz_fold_winner(sub, w.win, f + 1, ref,
                                      "downgrade gap") == 0;
    CB_RZ_CHECK("downgrade gap: the catalogs converge to the winner", conv);
    rz_close(pre);
    rz_close(ref);
    rz_close(sub);
    rz_world_free(&w);
    return failures;
}

/* The node.db connection is shared: an unwind that finds it inside another
 * writer's transaction changed nothing, so it must defer like a busy fold
 * guard (the caller keeps its cursor and retries), not report a failed unwind
 * and leave the losing branch behind a raised blocker. */
static int rz_foreign_transaction(void)
{
    int failures = 0;
    uint64_t rng = 0xF0E1;
    struct rz_world w;
    if (!rz_world_build(&w, &rng))
        return 1;
    const int stip = w.stale->tip;
    struct node_db *sub = rz_build(w.stale, stip, stip, stip);
    struct node_db *twin = rz_build(w.stale, stip, stip, stip);
    blocker_clear(EXPLORER_UNWIND_BLOCKER_ID);
    bool held = sub && node_db_exec(sub, "BEGIN");
    struct explorer_unwind_report rep;
    struct zcl_result res = held ? rz_unwind(sub, w.fork, &rep)
                                 : (struct zcl_result){0};
    if (held)
        (void)node_db_exec(sub, "ROLLBACK");
    CB_RZ_CHECK("foreign transaction: the unwind defers (busy), changes "
                "nothing and raises no blocker",
                held && !res.ok && res.code == EXPLORER_UNWIND_ERR_BUSY &&
                twin && rz_diff(sub, twin) == 0 &&
                !blocker_exists(EXPLORER_UNWIND_BLOCKER_ID));
    res = sub ? rz_unwind(sub, w.fork, &rep) : (struct zcl_result){0};
    CB_RZ_CHECK("foreign transaction: once it ends the retry unwinds "
                "exactly", res.ok &&
                rep.zslp_ledger == CATALOG_REWIND_EXACT &&
                rep.op_return_index == CATALOG_REWIND_EXACT);
    rz_close(sub);
    rz_close(twin);
    rz_world_free(&w);
    return failures;
}

static int rz_iterations(void)
{
    const char *env = getenv("Z23_UNWIND_RANDOM_ITERS");
    long n = env ? strtol(env, NULL, 10) : RZ_DEFAULT_ITERS;
    return n > 0 && n < 1000000 ? (int)n : RZ_DEFAULT_ITERS;
}

int explorer_unwind_random_suite(void)
{
    struct rz_stats st;
    memset(&st, 0, sizeof(st));
    const int n = rz_iterations();
    for (int i = 0; i < n; i++) {
        uint64_t seed = 0x9E3779B97F4A7C15ull * (uint64_t)(i + 1) + 0x23u;
        st.iters++;
        if (rz_iteration(seed, &st) != 0)
            st.failed++;
    }
    g_zslp_ledger_backfill_test_ndb = NULL;
    reducer_frontier_provable_tip_reset();
    printf("explorer_index_unwind: randomised reorgs (%d iterations, %d with "
           "a re-mined loser, %d second reorgs, %d exact / %d no-op catalog "
           "rewinds, up to %d ledger rows): every rewound state equals a "
           "from-scratch build... %s\n", st.iters, st.remined, st.second,
           st.exact, st.noop, st.rows_max, st.failed ? "FAIL" : "OK");
    bool covered = rz_coverage_complete(&st);
    printf("explorer_index_unwind: randomised reorgs reach every fold verdict "
           "(%lld valid sends, %lld over-input sends, %lld bad-lineage mints, "
           "%lld invalid-ancestry sends), token spends (%lld) "
           "and transparent burns (%lld)... %s\n",
           (long long)st.reason_seen[1], (long long)st.reason_seen[3],
           (long long)st.reason_seen[4], (long long)st.reason_seen[5],
           (long long)st.spent_rows,
           (long long)st.burn_spends, covered ? "OK" : "FAIL");
    int failures = (st.failed ? 1 : 0) + (covered ? 0 : 1);
    failures += rz_downgrade_gap();
    failures += rz_foreign_transaction();
    g_zslp_ledger_backfill_test_ndb = NULL;
    reducer_frontier_provable_tip_reset();
    return failures;
}
