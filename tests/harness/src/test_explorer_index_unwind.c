/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Reorg unwind of the explorer projection and its overlays
 * (explorer_index_unwind_above).
 *
 * The catchup cursor is rewound below a block a reorg removed, but the rows
 * the losing branch wrote used to stay behind: height-stamped rows described
 * transactions that are not on the chain, and the overlays that mutate rows
 * in place (ZNAM names, records and expiry; ZID; ZDIR) kept the loser's state,
 * so a loser REGISTER kept a name FCFS-taken and a loser TRANSFER stayed in
 * force.
 *
 * Every case here builds the same two-branch history, indexes branch A, unwinds
 * to the fork, indexes branch B, and requires the whole projection to be
 * EXACTLY what a database that only ever saw (common prefix + branch B)
 * holds: every row of every projection and overlay table compared, not a
 * sample. A control run (no unwind) proves each scenario really exposes the
 * bug, so the equality is not vacuous. node.db in memory only. */

#include "test/test_core.h"
#include "models/database.h"
#include "services/explorer_unwind_service.h"
#include "models/explorer_index.h"
#include "models/op_return_index.h"
#include "models/zslp_ledger.h"
#include "models/zslp_validity.h"
#include "models/znam.h"
#include "znam/znam.h"
#include "zslp/slp.h"
#include "zanc/zanc.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "chain/chain.h"

#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UW_MAX_SCRIPT 300
#define UW_CHECK(label, cond) do { \
    printf("explorer_index_unwind: %s... ", (label)); \
    if (cond) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* One transaction per block: spends (prevbyte x32, prevn), carries `script` as
 * its first (OP_RETURN) output and, when pay_to is set, pays a P2PKH to
 * vout[1] (an SLP GENESIS needs the output its message names). */
struct uw_block {
    int height;
    uint8_t prevbyte;
    uint32_t prevn;
    uint8_t script[UW_MAX_SCRIPT];
    size_t slen;
    bool pay;
    uint8_t pay_byte;
};

static const uint8_t k_owner_a = 0x11, k_owner_b = 0x22;

static void uw_seed(struct node_db *ndb)
{
    uint8_t a[20], b[20];
    memset(a, k_owner_a, sizeof(a));
    memset(b, k_owner_b, sizeof(b));
    for (uint8_t i = 1; i <= 6; i++) {
        uint8_t txid[32];
        memset(txid, 0xA0 + i, 32);
        db_tx_output_save(ndb, txid, 0, 5 * COIN, 0, a, 1);
    }
    for (uint8_t i = 1; i <= 2; i++) {
        uint8_t txid[32];
        memset(txid, 0xB0 + i, 32);
        db_tx_output_save(ndb, txid, 0, 5 * COIN, 0, b, 1);
    }
}

static void uw_make_tx(struct transaction *tx, const struct uw_block *s)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, s->pay ? 2 : 1);
    memset(tx->vin[0].prevout.hash.data, s->prevbyte, 32);
    tx->vin[0].prevout.n = s->prevn;
    tx->vin[0].sequence = 0xFFFFFFFFu;
    tx->vin[0].script_sig.size = 0;
    tx->vout[0].value = 0;
    memcpy(tx->vout[0].script_pub_key.data, s->script, s->slen);
    tx->vout[0].script_pub_key.size = s->slen;
    if (s->pay) {
        static const uint8_t pre[3] = { 0x76, 0xa9, 0x14 };
        static const uint8_t post[2] = { 0x88, 0xac };
        uint8_t *p = tx->vout[1].script_pub_key.data;
        tx->vout[1].value = COIN;
        memcpy(p, pre, 3);
        memset(p + 3, s->pay_byte, 20);
        memcpy(p + 23, post, 2);
        tx->vout[1].script_pub_key.size = 25;
    }
    tx->lock_time = 0;
    transaction_compute_hash(tx);
}

static bool uw_index(struct node_db *ndb, const struct uw_block *s, int salt)
{
    struct transaction tx;
    uw_make_tx(&tx, s);
    struct block blk;
    block_init(&blk);
    blk.vtx = &tx;
    blk.num_vtx = 1;
    blk.header.nTime = 1700000000u + (uint32_t)s->height;
    struct uint256 bhash;
    memset(bhash.data, 0x50 + salt, 32);
    bhash.data[0] = (uint8_t)s->height;
    struct block_index pindex;
    memset(&pindex, 0, sizeof(pindex));
    pindex.nHeight = s->height;
    pindex.phashBlock = &bhash;
    uint8_t prev[32] = {0}, out[32];
    bool ok = explorer_index_block(ndb, &blk, &pindex, prev, out, NULL, NULL);
    blk.vtx = NULL;
    blk.num_vtx = 0;
    transaction_free(&tx);
    return ok;
}

/* ── Whole-database comparison ─────────────────────────────────────── */

static const char *const k_tables[] = {
    "tx_outputs", "tx_inputs", "op_returns", "view_integrity",
    "znam_names", "znam_text_records", "znam_addr_records",
    "zslp_tokens", "zslp_transfers", "zslp_validity", "zslp_ledger",
    "zanc_anchors", "zid_identities", "onion_directory", "op_return_index",
};

static int uw_cmp_str(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Render every row of `table` as one line, sort the lines, join: an
 * order-independent, byte-exact image of the table. Caller frees. */
static char *uw_dump_table(struct node_db *ndb, const char *table)
{
    char sql[96];
    snprintf(sql, sizeof(sql), "SELECT * FROM %s", table);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK || !s)
        return zcl_strdup("<no such table>", "unwind test dump");
    char **lines = NULL;
    size_t n = 0, cap = 0, total = 1;
    while (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:test-readonly-dump
        size_t len = 0, lcap = 128;
        char *line = zcl_malloc(lcap, "unwind test line");
        int cols = sqlite3_column_count(s);
        for (int c = 0; c < cols; c++) {
            int type = sqlite3_column_type(s, c);
            char piece[1200];
            int w = 0;
            if (type == SQLITE_BLOB) {
                const uint8_t *b = sqlite3_column_blob(s, c);
                int nb = sqlite3_column_bytes(s, c);
                if (nb > 500) nb = 500;
                for (int i = 0; i < nb; i++)
                    w += snprintf(piece + w, sizeof(piece) - (size_t)w,
                                  "%02x", b[i]);
            } else if (type == SQLITE_NULL) {
                w = snprintf(piece, sizeof(piece), "~");
            } else {
                w = snprintf(piece, sizeof(piece), "%s",
                             (const char *)sqlite3_column_text(s, c));
            }
            if (len + (size_t)w + 2 > lcap) {
                lcap = (len + (size_t)w + 2) * 2;
                line = zcl_realloc(line, lcap, "unwind test line");
            }
            memcpy(line + len, piece, (size_t)w);
            len += (size_t)w;
            line[len++] = '|';
        }
        line[len] = '\0';
        if (n == cap) {
            cap = cap ? cap * 2 : 32;
            lines = zcl_realloc(lines, cap * sizeof(*lines), "unwind test lines");
        }
        lines[n++] = line;
        total += len + 1;
    }
    sqlite3_finalize(s);
    if (n > 1)
        qsort(lines, n, sizeof(*lines), uw_cmp_str);
    char *out = zcl_malloc(total, "unwind test dump");
    size_t at = 0;
    for (size_t i = 0; i < n; i++) {
        size_t l = strlen(lines[i]);
        memcpy(out + at, lines[i], l);
        at += l;
        out[at++] = '\n';
        free(lines[i]);
    }
    out[at] = '\0';
    free(lines);
    return out;
}

/* Compare every table; returns the number of tables that differ and prints
 * the first differing one so a failure names itself. */
static int uw_diff(struct node_db *x, struct node_db *y, bool quiet)
{
    int bad = 0;
    for (size_t i = 0; i < sizeof(k_tables) / sizeof(k_tables[0]); i++) {
        char *a = uw_dump_table(x, k_tables[i]);
        char *b = uw_dump_table(y, k_tables[i]);
        if (strcmp(a, b) != 0) {
            bad++;
            if (!quiet)
                printf("\n    table %s differs (%zu vs %zu bytes)",
                       k_tables[i], strlen(a), strlen(b));
        }
        free(a);
        free(b);
    }
    return bad;
}

/* ── Scenario scripts ──────────────────────────────────────────────── */


#define UW_SET(blk, hh, pb, pn) do { \
    memset(&(blk), 0, sizeof(blk)); (blk).height = (hh); \
    (blk).prevbyte = (pb); (blk).prevn = (pn); } while (0)

static struct uw_block uw_reg(int h, uint8_t pb, const char *name)
{
    struct uw_block b;
    UW_SET(b, h, pb, 0);
    b.slen = znam_build_register(b.script, sizeof(b.script), name,
                                 ZNAM_TYPE_TADDR, "t1target");
    return b;
}

static struct uw_block uw_update(int h, uint8_t pb, const char *name,
                                 const char *target)
{
    struct uw_block b;
    UW_SET(b, h, pb, 0);
    b.slen = znam_build_update(b.script, sizeof(b.script), name,
                               ZNAM_TYPE_TADDR, target);
    return b;
}

static struct uw_block uw_transfer(int h, uint8_t pb, const char *name,
                                   const char *to)
{
    struct uw_block b;
    UW_SET(b, h, pb, 0);
    b.slen = znam_build_transfer(b.script, sizeof(b.script), name, to);
    return b;
}

static struct uw_block uw_renew(int h, uint8_t pb, const char *name)
{
    struct uw_block b;
    UW_SET(b, h, pb, 0);
    b.slen = znam_build_renew(b.script, sizeof(b.script), name);
    return b;
}

static struct uw_block uw_text(int h, uint8_t pb, const char *name,
                               const char *key, const char *val)
{
    struct uw_block b;
    UW_SET(b, h, pb, 0);
    b.slen = znam_build_set_text(b.script, sizeof(b.script), name, key, val);
    return b;
}

static struct uw_block uw_slp_genesis(int h, uint8_t pb)
{
    struct uw_block b;
    UW_SET(b, h, pb, 0);
    b.slen = slp_build_genesis(b.script, sizeof(b.script), "UWT", "Unwind",
                               "", NULL, 0, 0, 1000);
    b.pay = true;
    b.pay_byte = k_owner_a;
    return b;
}

static struct uw_block uw_anchor(int h, uint8_t pb)
{
    struct uw_block b;
    uint8_t digest[32];
    memset(digest, 0x5C, sizeof(digest));
    UW_SET(b, h, pb, 0);
    b.slen = zanc_build_anchor(b.script, sizeof(b.script), 1, digest, "uw");
    return b;
}

static struct uw_block uw_plain(int h, uint8_t pb)
{
    struct uw_block b;
    UW_SET(b, h, pb, 0);
    static const uint8_t s[] = { 0x6a, 0x04, 'T', 'E', 'S', 'T', 0x01, 0x07 };
    memcpy(b.script, s, sizeof(s));
    b.slen = sizeof(s);
    return b;
}

#define UW_COMMON_N 4
#define UW_FORK 3

struct uw_world {
    struct uw_block common[UW_COMMON_N];
    size_t nstale;
    struct uw_block stale[8];
    size_t nwin;
    struct uw_block win[8];
};

/* Fixture 1: overlay operations in the stale range, including a REGISTER that
 * the winner re-uses a name for, a TRANSFER, a RENEW, a SET_TEXT, an SLP
 * GENESIS and an anchor. */
static void uw_world_overlay(struct uw_world *w)
{
    memset(w, 0, sizeof(*w));
    w->common[0] = uw_plain(0, 0xA1);
    w->common[1] = uw_plain(1, 0xA1);
    w->common[2] = uw_reg(2, 0xA1, "alpha");
    w->common[3] = uw_reg(3, 0xA2, "beta");
    w->stale[w->nstale++] = uw_reg(4, 0xA3, "gamma");
    w->stale[w->nstale++] = uw_transfer(5, 0xA4, "alpha", "t1LoserOwner");
    w->stale[w->nstale++] = uw_slp_genesis(6, 0xA5);
    w->stale[w->nstale++] = uw_renew(7, 0xA6, "alpha");
    w->stale[w->nstale++] = uw_anchor(8, 0xB1);
    w->win[w->nwin++] = uw_reg(4, 0xB1, "gamma");
    w->win[w->nwin++] = uw_update(5, 0xA4, "alpha", "t1winner");
    w->win[w->nwin++] = uw_renew(6, 0xA5, "beta");
}

/* Fixture 2: nothing the in-place overlays own in the stale range, so no
 * replay (and no block read) may happen. */
static void uw_world_stamped_only(struct uw_world *w)
{
    memset(w, 0, sizeof(*w));
    w->common[0] = uw_plain(0, 0xA1);
    w->common[1] = uw_plain(1, 0xA1);
    w->common[2] = uw_reg(2, 0xA1, "alpha");
    w->common[3] = uw_text(3, 0xA2, "alpha", "onion", "good.onion");
    w->stale[w->nstale++] = uw_slp_genesis(4, 0xA3);
    w->stale[w->nstale++] = uw_anchor(5, 0xA4);
    w->stale[w->nstale++] = uw_plain(6, 0xA5);
    w->win[w->nwin++] = uw_plain(4, 0xA3);
    w->win[w->nwin++] = uw_anchor(5, 0xA4);
}

/* Fixture 3: the stale range is an update to a name the common prefix owns,
 * and the winner chain is SHORTER than the loser's. */
static void uw_world_shorter_winner(struct uw_world *w)
{
    memset(w, 0, sizeof(*w));
    w->common[0] = uw_plain(0, 0xA1);
    w->common[1] = uw_plain(1, 0xA1);
    w->common[2] = uw_reg(2, 0xA1, "alpha");
    w->common[3] = uw_text(3, 0xA2, "alpha", "k", "v0");
    w->stale[w->nstale++] = uw_text(4, 0xA3, "alpha", "k", "loser");
    w->stale[w->nstale++] = uw_update(5, 0xA4, "alpha", "t1loser");
    w->stale[w->nstale++] = uw_renew(6, 0xA5, "alpha");
    w->win[w->nwin++] = uw_plain(4, 0xA3);
}

static struct node_db *uw_open(void)
{
    struct node_db *ndb = zcl_calloc(1, sizeof(*ndb), "unwind test db");
    if (!ndb)
        return NULL;
    if (!node_db_open(ndb, ":memory:") || !ndb->open) {
        free(ndb);
        return NULL;
    }
    uw_seed(ndb);
    return ndb;
}

static void uw_close(struct node_db *ndb)
{
    if (!ndb)
        return;
    node_db_close(ndb);
    free(ndb);
}

struct uw_reader {
    const struct uw_world *w;
    int calls;
};

/* Serves the COMMON-PREFIX blocks, as the active chain would. */
static bool uw_read(void *ctx, int height, struct block *out)
{
    struct uw_reader *r = ctx;
    r->calls++;
    for (size_t i = 0; i < UW_COMMON_N; i++) {
        if (r->w->common[i].height != height)
            continue;
        out->vtx = zcl_calloc(1, sizeof(struct transaction), "unwind test vtx");
        if (!out->vtx)
            return false;
        out->num_vtx = 1;
        uw_make_tx(&out->vtx[0], &r->w->common[i]);
        return true;
    }
    return false;
}

static void uw_apply(struct node_db *ndb, const struct uw_block *blocks,
                     size_t n, int salt)
{
    for (size_t i = 0; i < n; i++)
        (void)uw_index(ndb, &blocks[i], salt);
}

/* Run one world through: reference (common + winner), control (common + loser
 * + winner, NO unwind) and subject (common + loser, unwind, winner). */
static int uw_run_world(const char *name, const struct uw_world *w,
                        bool expect_replay)
{
    int failures = 0;
    char label[160];
    struct node_db *ref = uw_open();
    struct node_db *ctl = uw_open();
    struct node_db *sub = uw_open();
    if (!ref || !ctl || !sub) {
        uw_close(ref);
        uw_close(ctl);
        uw_close(sub);
        printf("explorer_index_unwind: %s: could not open node.db... FAIL\n",
               name);
        return 1;
    }

    uw_apply(ref, w->common, UW_COMMON_N, 0);
    uw_apply(ref, w->win, w->nwin, 2);

    uw_apply(ctl, w->common, UW_COMMON_N, 0);
    uw_apply(ctl, w->stale, w->nstale, 1);
    uw_apply(ctl, w->win, w->nwin, 2);

    uw_apply(sub, w->common, UW_COMMON_N, 0);
    uw_apply(sub, w->stale, w->nstale, 1);
    struct uw_reader rd = { w, 0 };
    bool unwound = explorer_index_unwind_above(sub, UW_FORK, uw_read, &rd).ok;
    uw_apply(sub, w->win, w->nwin, 2);

    snprintf(label, sizeof(label), "%s: control without unwind diverges "
             "(the scenario exposes the bug)", name);
    UW_CHECK(label, uw_diff(ctl, ref, true) > 0);
    snprintf(label, sizeof(label), "%s: unwind succeeds", name);
    UW_CHECK(label, unwound);
    snprintf(label, sizeof(label), "%s: reorged state equals a from-scratch "
             "rebuild, every table", name);
    int bad = uw_diff(sub, ref, false);
    UW_CHECK(label, bad == 0);
    snprintf(label, sizeof(label), "%s: block reads only when a replay is "
             "needed (%d)", name, rd.calls);
    UW_CHECK(label, expect_replay ? rd.calls > 0 : rd.calls == 0);

    /* Idempotent: a second unwind to the same fork over the settled state
     * (cursor already at the fork, nothing above it indexed twice) changes
     * nothing when the winner is not re-applied. */
    struct node_db *again = uw_open();
    if (again) {
        uw_apply(again, w->common, UW_COMMON_N, 0);
        bool ok1 = explorer_index_unwind_above(again, UW_FORK, uw_read, &rd).ok;
        bool ok2 = explorer_index_unwind_above(again, UW_FORK, uw_read, &rd).ok;
        struct node_db *base = uw_open();
        if (base)
            uw_apply(base, w->common, UW_COMMON_N, 0);
        snprintf(label, sizeof(label), "%s: unwind of an already-clean "
                 "database is a no-op, twice", name);
        UW_CHECK(label, ok1 && ok2 && base && uw_diff(again, base, false) == 0);
        uw_close(base);
        uw_close(again);
    }

    uw_close(ref);
    uw_close(ctl);
    uw_close(sub);
    return failures;
}

/* ── The two cursor-owning catalogs ───────────────────────────────────
 *
 * zslp_ledger and op_return_index carry a running digest that cannot be
 * rewound: with their cursor above the fork they are dropped for their own
 * services to re-derive; with it at or below the fork only the stale rows go,
 * a token spend recorded above the fork is undone, and the cursor and digest
 * stay as they were. */

static int64_t uw_count(struct node_db *ndb, const char *sql)
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

static struct node_db *uw_catalog_db(const struct uw_world *w, int32_t cursor)
{
    struct node_db *ndb = uw_open();
    if (!ndb)
        return NULL;
    uw_apply(ndb, w->common, UW_COMMON_N, 0);
    uw_apply(ndb, w->stale, w->nstale, 1);
    uint8_t tok[32], prev[32], spender[32], addr[20], digest[32];
    memset(tok, 0x7A, 32);
    memset(prev, 0x7B, 32);
    memset(spender, 0x7C, 32);
    memset(addr, k_owner_a, 20);
    memset(digest, 0x3D, 32);
    /* A common-prefix token output, spent by a stale-range transaction. */
    bool ok = zslp_ledger_record_valid_output(ndb, tok, prev, 1, 50, addr, 2,
                                              ZSLP_LEDGER_TOKEN) &&
              zslp_ledger_mark_valid_spent(ndb, prev, 1, spender, 5) &&
              zslp_ledger_set_cursor(ndb, cursor, digest);
    struct op_return_index_cursor cur;
    memset(&cur, 0, sizeof(cur));
    cur.height = cursor;
    memset(cur.digest, 0x4E, 32);
    ok = ok && op_return_index_set_cursor(ndb, &cur);
    if (!ok) {
        uw_close(ndb);
        return NULL;
    }
    return ndb;
}

static int uw_catalog_above_fork(const struct uw_world *w)
{
    int failures = 0;
    struct node_db *ndb = uw_catalog_db(w, 8);
    bool ok = ndb && explorer_index_unwind_above(ndb, UW_FORK, NULL, NULL).ok;
    int32_t lh = -2, oh = -2, ob = -2;
    uint8_t ld[32];
    ok = ok && zslp_ledger_get_cursor(ndb, &lh, ld) &&
         op_return_index_get_cursor_heights(ndb, &oh, &ob);
    UW_CHECK("catalog cursors above the fork: both catalogs are dropped "
             "for re-derivation",
             ok && lh == -1 && oh == -1 &&
             uw_count(ndb, "SELECT COUNT(*) FROM zslp_ledger") == 0 &&
             uw_count(ndb, "SELECT COUNT(*) FROM op_return_index") == 0);
    uw_close(ndb);
    return failures;
}

static int uw_catalog_at_fork(const struct uw_world *w)
{
    int failures = 0;
    int32_t lh = -2, oh = -2, ob = -2;
    uint8_t ld[32];
    struct node_db *ndb = uw_catalog_db(w, UW_FORK);
    bool ok = ndb && uw_count(ndb, "SELECT COUNT(*) FROM op_return_index"
                              " WHERE height>3") > 0 &&
         explorer_index_unwind_above(ndb, UW_FORK, NULL, NULL).ok;
    uint8_t want[32];
    memset(want, 0x3D, 32);
    ok = ok && zslp_ledger_get_cursor(ndb, &lh, ld) &&
         op_return_index_get_cursor_heights(ndb, &oh, &ob);
    UW_CHECK("catalog cursors at the fork: cursor and digest are kept",
             ok && lh == UW_FORK && memcmp(ld, want, 32) == 0 &&
             oh == UW_FORK);
    UW_CHECK("catalog cursors at the fork: stale rows go, prefix rows stay",
             ok &&
             uw_count(ndb, "SELECT COUNT(*) FROM op_return_index"
                           " WHERE height>3") == 0 &&
             uw_count(ndb, "SELECT COUNT(*) FROM op_return_index") > 0 &&
             uw_count(ndb, "SELECT COUNT(*) FROM zslp_ledger"
                           " WHERE created_height>3") == 0);
    UW_CHECK("catalog cursors at the fork: a spend above the fork is undone",
             ok &&
             uw_count(ndb, "SELECT COUNT(*) FROM zslp_ledger WHERE"
                           " created_height=2 AND spent_by_txid IS NULL"
                           " AND spent_height IS NULL") == 1);
    uw_close(ndb);
    return failures;
}

static int uw_catalog_checks(void)
{
    struct uw_world w;
    uw_world_stamped_only(&w);
    return uw_catalog_above_fork(&w) + uw_catalog_at_fork(&w);
}

int test_explorer_index_unwind(void)
{
    int failures = 0;
    struct uw_world w;

    uw_world_overlay(&w);
    failures += uw_run_world("overlay ops in the stale range", &w, true);
    uw_world_stamped_only(&w);
    failures += uw_run_world("stamped rows only", &w, false);
    uw_world_shorter_winner(&w);
    failures += uw_run_world("shorter winning chain", &w, true);
    failures += uw_catalog_checks();

    /* A projection with a hole below the fork (a snapshot-seeded datadir):
     * the in-place overlays cannot be rebuilt there, so they are left as they
     * are and only the stamped rows go. Nothing may be cleared. */
    struct node_db *holey = uw_open();
    if (holey) {
        uw_world_overlay(&w);
        uw_apply(holey, w.common + 1, UW_COMMON_N - 1, 0);   /* no height 0 */
        uw_apply(holey, w.stale, w.nstale, 1);
        struct uw_reader hrd = { &w, 0 };
        bool hok = explorer_index_unwind_above(holey, UW_FORK, uw_read, &hrd).ok;
        char *anchors = uw_dump_table(holey, "zanc_anchors");
        char *names = uw_dump_table(holey, "znam_names");
        UW_CHECK("a hole below the fork: unwind succeeds without reading blocks",
                 hok && hrd.calls == 0);
        UW_CHECK("a hole below the fork: stamped rows above the fork are gone",
                 anchors && anchors[0] == '\0');
        UW_CHECK("a hole below the fork: in-place overlay state is not cleared",
                 names && strstr(names, "alpha") && strstr(names, "gamma"));
        free(anchors);
        free(names);
        uw_close(holey);
    }

    /* Arguments and the no-reader contract. */
    struct node_db *ndb = uw_open();
    if (ndb) {
        UW_CHECK("NULL db is refused",
                 !explorer_index_unwind_above(NULL, 3, NULL, NULL).ok);
        UW_CHECK("fork below -1 is refused",
                 !explorer_index_unwind_above(ndb, -2, NULL, NULL).ok);
        uw_world_overlay(&w);
        uw_apply(ndb, w.common, UW_COMMON_N, 0);
        uw_apply(ndb, w.stale, w.nstale, 1);
        struct node_db *before = uw_open();
        uw_apply(before, w.common, UW_COMMON_N, 0);
        uw_apply(before, w.stale, w.nstale, 1);
        UW_CHECK("a replay with no block reader fails",
                 !explorer_index_unwind_above(ndb, UW_FORK, NULL, NULL).ok);
        UW_CHECK("a failed unwind leaves the projection untouched",
                 uw_diff(ndb, before, false) == 0);
        uw_close(before);
        uw_close(ndb);
    } else {
        printf("explorer_index_unwind: open node.db... FAIL\n");
        failures++;
    }
    return failures;
}
