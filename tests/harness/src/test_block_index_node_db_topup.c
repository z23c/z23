/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for block_index_node_db_topup_with() — the cold-import
 * restart-fragility fix (PART A).
 *
 * The case
 * ---------
 * After a cold import of a UTXO snapshot (seed anchor at H_seed) and a
 * forward sync past it, a flat-index reload leaves the seed anchor as a
 * DETACHED non-genesis root, while the window (H_seed, coins_best] is
 * body-backed in node.db `blocks` but not linked into the map. Restore of
 * coins-best then refuses and the tip drops to genesis.
 *
 * What this test proves
 * ---------------------
 *   1. FORWARD-EXTENT FOLD: the window [H_seed+1 .. coins_best] is read
 *      from node.db `blocks`, inserted into the map, and pprev-linked all
 *      the way down to the seed anchor — so the seed anchor stops being an
 *      orphan tip and coins_best gains a pprev chain to it.
 *   2. RAISE-ONLY: an entry already in the map keeps its richer state
 *      (HAVE_DATA / nTx) — never lowered.
 *   3. STRICT NO-OP WITHOUT A SEED ANCHOR: with the durable cold-import
 *      keys absent, the top-up inserts/links nothing (the normal /
 *      P2P-origin datadir path).
 *   4. WINDOW-BOUNDED: nothing below H_seed+1 or above coins_best is
 *      touched, and no full-chain scan occurs.
 *   5. NO-OP ON EMPTY WINDOW: coins_best <= H_seed inserts nothing.
 *
 * Scratch files live under ./test-tmp/nodedbtopup_<pid>/ per the project's
 * no-/tmp convention.
 */

#include "test/test_core.h"

#include "services/block_index_loader.h"
#include "models/database.h"
#include "models/block.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "core/uint256.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#define NDT_CHECK(name, expr) do { \
    printf("block_index_node_db_topup: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Deterministic unique hash for height h. */
static void ndt_hash_for(int h, struct uint256 *out)
{
    memset(out->data, 0, 32);
    out->data[0] = (uint8_t)(h & 0xFF);
    out->data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->data[2] = (uint8_t)((h >> 16) & 0xFF);
    out->data[31] = 0xA5;
}

/* Write a connected (status>=3) block row at height h into the node.db
 * `blocks` table, prev_hash = hash(h-1), with an explicit stored status,
 * undo column and file number. The STATUS bits are what the top-up reads as
 * "this row claims data" / "this row claims undo": a row that merely names a
 * file_num claims nothing, on either half. */
static bool ndt_write_block_full(struct node_db *ndb, int h, int status,
                                 int undo_pos, int file_num)
{
    static uint8_t dummy_solution[1] = {0};
    struct db_block b;
    memset(&b, 0, sizeof(b));
    struct uint256 hh, ph;
    ndt_hash_for(h, &hh);
    ndt_hash_for(h - 1, &ph);
    memcpy(b.hash, hh.data, 32);
    memcpy(b.prev_hash, ph.data, 32);
    b.height = h;
    b.version = 4;
    memset(b.merkle_root, 0x11, 32);
    b.time = 1700000000u + (uint32_t)h;
    b.bits = 0x2000ffffu;
    memset(b.nonce, 0x22, 32);
    b.solution = dummy_solution;
    b.solution_len = sizeof(dummy_solution);
    memset(b.chain_work, 0, 32);
    b.status = status;            /* connected — db_block_find_by_height filter */
    b.file_num = file_num;
    b.data_pos = 1000 + h;
    b.undo_pos = undo_pos;
    b.num_tx = 2;
    memset(b.sapling_root, 0, 32);
    memset(b.sprout_root, 0, 32);
    return db_block_save(ndb, &b);
}

/* The common shape: the row names block file 1. */
static bool ndt_write_block_row(struct node_db *ndb, int h, int status,
                                int undo_pos)
{
    return ndt_write_block_full(ndb, h, status, undo_pos, 1);
}

/* The plain window row the fold fixtures use: connected, body-backed, and
 * making NO undo claim (status has no BLOCK_HAVE_UNDO bit). */
static bool ndt_write_block(struct node_db *ndb, int h)
{
    return ndt_write_block_row(ndb, h, 3, 2000 + h);
}

/* Insert a header-only in-memory entry at height h (the stale-flat shape). */
static struct block_index *ndt_insert_entry(struct main_state *ms, int h)
{
    struct uint256 hh;
    ndt_hash_for(h, &hh);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &hh);
    if (!bi)
        return NULL;
    bi->nHeight = h;
    bi->nBits = 0x2000ffffu;
    bi->nTime = 1700000000u + (uint32_t)h;
    bi->nVersion = 4;
    bi->nStatus = BLOCK_VALID_TREE;
    bi->nTx = 0;
    bi->nFile = -1;
    bi->nDataPos = 0;
    return bi;
}

/* Set the coins applied frontier so coins_best == coins_applied_height - 1. */
static bool ndt_set_coins_best(sqlite3 *db, int coins_best)
{
    if (!coins_kv_ensure_schema(db) || !progress_meta_table_ensure(db))
        return false;
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    bool ok = coins_kv_set_applied_height_in_tx(db, coins_best + 1);
    const char *fin = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, fin, NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        ok = false;
    }
    return ok;
}

/* An entry in the header-only-snapshot-import shape: HAVE_DATA with a real
 * position, and `undo_pos` (0 meaning no HAVE_UNDO at all). */
static struct block_index *ndt_undo_entry(struct main_state *ms, int h,
                                          unsigned int undo_pos)
{
    struct block_index *bi = ndt_insert_entry(ms, h);
    if (!bi)
        return NULL;
    bi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    bi->nFile = 1;
    bi->nDataPos = (unsigned int)(1000 + h);
    bi->nTx = 2;
    if (undo_pos) {
        bi->nUndoPos = undo_pos;
        bi->nStatus |= BLOCK_HAVE_UNDO;
    }
    return bi;
}

/* A body-less entry carrying an undo position of its own against a different
 * block file: adopting the row's file number invalidates it, and
 * topup_apply_undo() then zeroes it. */
static struct block_index *ndt_no_data_undo_entry(struct main_state *ms,
                                                  int h)
{
    struct block_index *bi = ndt_insert_entry(ms, h);
    if (!bi)
        return NULL;
    bi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_UNDO;
    bi->nFile = 2;
    bi->nUndoPos = 777;
    bi->nTx = 2;
    return bi;
}

struct ndt_undo_fixture {
    struct node_db ndb;
    sqlite3 *progress;
    struct main_state ms;
    struct block_index *u103;
    struct block_index *u104;
    struct block_index *u105;
    struct block_index *u106;
    struct block_index *u107;
    bool opened;
    bool built;
};

/* Same seed-anchor/window shape, with 103, 104 and 105 already in the map
 * carrying HAVE_DATA (103 and 105 without an undo position, 104 with its
 * own). 103 and 104 rows carry BLOCK_HAVE_UNDO, 105 does not.
 *
 * 106 and 107 are the DATA half: body-less entries whose rows are the
 * header-only snapshot-import shape (HAVE_DATA and HAVE_UNDO stripped,
 * file_num 0, positions 0); that file_num is not an address. */
static void ndt_undo_fixture_build(struct ndt_undo_fixture *f,
                                   const char *dir)
{
    memset(f, 0, sizeof(*f));
    char ndb_path[320], prog_path[320];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node5.db", dir);
    snprintf(prog_path, sizeof(prog_path), "%s/progress5.db", dir);
    if (!node_db_open(&f->ndb, ndb_path))
        return;
    f->opened = true;
    if (sqlite3_open(prog_path, &f->progress) != SQLITE_OK)
        return;
    for (int h = 100; h <= 102; h++)
        (void)ndt_write_block(&f->ndb, h);
    /* Rows that claim undo (status bit set) vs a row that does not. */
    (void)ndt_write_block_row(&f->ndb, 103, 3 | BLOCK_HAVE_UNDO, 2103);
    (void)ndt_write_block_row(&f->ndb, 104, 3 | BLOCK_HAVE_UNDO, 2104);
    (void)ndt_write_block_row(&f->ndb, 105, 3, 2105);
    /* Header-only import rows: no HAVE_DATA, no HAVE_UNDO, file_num 0. */
    (void)ndt_write_block_full(&f->ndb, 106, 3, 0, 0);
    (void)ndt_write_block_full(&f->ndb, 107, 3, 0, 0);
    struct uint256 seed_hash;
    ndt_hash_for(102, &seed_hash);
    (void)node_db_state_set_int(&f->ndb, "cold_import_seed_anchor_height",
                                102);
    (void)node_db_state_set(&f->ndb, "cold_import_seed_anchor_hash",
                            seed_hash.data, 32);
    (void)ndt_set_coins_best(f->progress, 107);
    main_state_init(&f->ms);
    (void)ndt_insert_entry(&f->ms, 102);
    f->u103 = ndt_undo_entry(&f->ms, 103, 0);
    f->u104 = ndt_undo_entry(&f->ms, 104, 555);
    f->u105 = ndt_undo_entry(&f->ms, 105, 0);
    /* 106: pure header-only entry (nFile -1, no position bits at all). */
    f->u106 = ndt_insert_entry(&f->ms, 106);
    f->u107 = ndt_no_data_undo_entry(&f->ms, 107);
    f->built = f->u103 && f->u104 && f->u105 && f->u106 && f->u107;
}

/* Undo top-up: an entry that already carries HAVE_DATA but no HAVE_UNDO, whose
 * `blocks` row names an undo position, must gain it.
 *
 * Fail-closed half: a row whose status does not claim BLOCK_HAVE_UNDO (105) or
 * BLOCK_HAVE_DATA (106, 107) grants nothing, however plausible its columns. A
 * header-only snapshot import leaves exactly that shape, and adopting its
 * file number would count as a file change and destroy an undo position the
 * entry legitimately held (107). */
static int ndt_undo_topup_cases(const char *dir)
{
    int failures = 0;
    struct ndt_undo_fixture f;
    ndt_undo_fixture_build(&f, dir);
    NDT_CHECK("undo-topup: fixture built", f.built);
    if (f.built) {
        NDT_CHECK("undo-topup: returns ok",
                  block_index_node_db_topup_with(&f.ms, &f.ndb, f.progress,
                                                 dir));
        NDT_CHECK("undo-topup: HAVE_DATA entry gained HAVE_UNDO",
                  (f.u103->nStatus & BLOCK_HAVE_UNDO) &&
                  f.u103->nUndoPos == 2103u);
        NDT_CHECK("undo-topup: data position untouched",
                  f.u103->nFile == 1 && f.u103->nDataPos == 1103u);
        NDT_CHECK("undo-topup: existing HAVE_UNDO not overwritten",
                  (f.u104->nStatus & BLOCK_HAVE_UNDO) &&
                  f.u104->nUndoPos == 555u);
        NDT_CHECK("undo-topup: row without HAVE_UNDO grants nothing",
                  !(f.u105->nStatus & BLOCK_HAVE_UNDO) &&
                  f.u105->nUndoPos == 0u);
        NDT_CHECK("data-topup: row without HAVE_DATA grants nothing",
                  !(f.u106->nStatus & BLOCK_HAVE_DATA) &&
                  f.u106->nFile == -1 && f.u106->nDataPos == 0u);
        NDT_CHECK("data-topup: row without HAVE_DATA keeps the entry's undo",
                  (f.u107->nStatus & BLOCK_HAVE_UNDO) &&
                  f.u107->nUndoPos == 777u && f.u107->nFile == 2);
        main_state_free(&f.ms);
    }
    if (f.progress)
        sqlite3_close(f.progress);
    if (f.opened)
        node_db_close(&f.ndb);
    return failures;
}

/* ── Range scan == per-height lookup (equivalence + timing) ───────────────
 * One fixture window of >=100k heights with holes, forks (a second,
 * non-connected row at the same height with another hash, written before or
 * after the connected one), rows with/without HAVE_DATA/HAVE_UNDO, undo
 * offsets, num_tx 0/non-0, and pre-existing map entries (raise-only and
 * height-conflict shapes). The top-up runs once with the per-height oracle
 * and once with the ordered range scan on identical maps; the resulting maps
 * and the printed counter line must be identical. */
#define NDT_RANGE_SEED 1000
#define NDT_RANGE_BEST 101200

static int64_t ndt_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool ndt_range_row(struct node_db *ndb, int h, bool fork)
{
    static uint8_t sol[1] = {0};
    struct db_block b;
    memset(&b, 0, sizeof(b));
    struct uint256 hh, ph;
    ndt_hash_for(h, &hh);
    ndt_hash_for(h - 1, &ph);
    if (fork)
        hh.data[5] = 0x77;
    memcpy(b.hash, hh.data, 32);
    memcpy(b.prev_hash, ph.data, 32);
    b.height = h;
    b.version = 4;
    memset(b.merkle_root, 0x11 + (h & 7), 32);
    b.time = 1700000000u + (uint32_t)h;
    b.bits = 0x2000ffffu;
    memset(b.nonce, 0x22, 32);
    b.solution = sol;
    b.solution_len = sizeof(sol);
    b.status = fork ? 2 : (3 | ((h % 2) ? BLOCK_HAVE_DATA : 0) |
                           ((h % 3 == 0) ? BLOCK_HAVE_UNDO : 0));
    b.file_num = h % 5;
    b.data_pos = 1000 + h;
    b.undo_pos = (h % 5) ? 2000 + h : 0;
    b.num_tx = (h % 4 == 0) ? 0 : 2;
    b.sapling_value = h % 9;
    b.sprout_value = (h % 6 == 0) ? 5 : 0;
    return db_block_save(ndb, &b);
}

static bool ndt_range_build_db(struct node_db *ndb)
{
    bool ok = sqlite3_exec(ndb->db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK;
    for (int h = NDT_RANGE_SEED; ok && h <= NDT_RANGE_BEST + 5; h++) {
        bool fork = (h % 53 == 0);
        if (fork && (h % 2))
            ok &= ndt_range_row(ndb, h, true);       /* stale row first  */
        if (h % 97 != 0 || h == NDT_RANGE_SEED)       /* holes            */
            ok &= ndt_range_row(ndb, h, false);
        if (fork && !(h % 2))
            ok &= ndt_range_row(ndb, h, true);       /* stale row after  */
    }
    ok &= sqlite3_exec(ndb->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    struct uint256 sh;
    ndt_hash_for(NDT_RANGE_SEED, &sh);
    ok &= node_db_state_set_int(ndb, "cold_import_seed_anchor_height",
                                NDT_RANGE_SEED);
    ok &= node_db_state_set(ndb, "cold_import_seed_anchor_hash", sh.data, 32);
    return ok;
}

static bool ndt_range_fill_map(struct main_state *ms)
{
    bool ok = ndt_insert_entry(ms, NDT_RANGE_SEED) != NULL;
    for (int h = NDT_RANGE_SEED + 1; ok && h <= NDT_RANGE_BEST; h++) {
        if (h % 13 == 0) {
            struct block_index *bi = ndt_insert_entry(ms, h);
            ok = bi != NULL;
            if (ok && h % 2 == 0) {
                bi->nStatus |= BLOCK_HAVE_DATA;
                bi->nFile = 3;
                bi->nDataPos = 9u;
                bi->nTx = 1;
            }
            if (ok && h % 39 == 0)
                bi->nUndoPos = 7u, bi->nStatus |= BLOCK_HAVE_UNDO;
        }
        if (ok && h % 1009 == 0) {              /* height-label conflict */
            struct block_index *bi = ndt_insert_entry(ms, h);
            ok = bi != NULL;
            if (ok)
                bi->nHeight = h + 1;
        }
    }
    return ok;
}

/* Run one top-up with stdout captured; copy the counter line into `line`. */
static bool ndt_range_run(struct main_state *ms, struct node_db *ndb,
                          sqlite3 *progress, const char *dir, bool oracle,
                          char *line, size_t line_cap, int64_t *ms_out)
{
    char path[320];
    snprintf(path, sizeof(path), "%s/stdout_capture.txt", dir);
    fflush(stdout);
    int saved = dup(1);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (saved < 0 || fd < 0)
        return false;
    dup2(fd, 1);
    close(fd);
    g_node_db_topup_perheight_oracle = oracle;
    int64_t t0 = ndt_now_ms();
    bool ok = block_index_node_db_topup_with(ms, ndb, progress, dir);
    *ms_out = ndt_now_ms() - t0;
    g_node_db_topup_perheight_oracle = false;
    fflush(stdout);
    dup2(saved, 1);
    close(saved);
    line[0] = '\0';
    FILE *fp = fopen(path, "r");
    if (fp) {
        while (fgets(line, (int)line_cap, fp) &&
               !strstr(line, "node.db top-up"))
            line[0] = '\0';
        fclose(fp);
    }
    return ok;
}

static bool ndt_entries_equal(const struct block_index *a,
                              const struct block_index *b)
{
    return a->nHeight == b->nHeight && a->nStatus == b->nStatus &&
           a->nFile == b->nFile && a->nDataPos == b->nDataPos &&
           a->nUndoPos == b->nUndoPos && a->nTx == b->nTx &&
           a->nVersion == b->nVersion && a->nTime == b->nTime &&
           a->nSaplingValue == b->nSaplingValue &&
           a->nSproutValue == b->nSproutValue &&
           a->has_sprout_value == b->has_sprout_value &&
           memcmp(&a->nChainWork, &b->nChainWork, sizeof(a->nChainWork)) == 0 &&
           (a->pprev == NULL) == (b->pprev == NULL) &&
           (!a->pprev || a->pprev->nHeight == b->pprev->nHeight);
}

struct ndt_range_diff {
    size_t diffs, compared, fork_hits;
};

static struct ndt_range_diff ndt_range_compare(struct main_state *a,
                                               struct main_state *b)
{
    struct ndt_range_diff d = {0, 0, 0};
    for (int h = NDT_RANGE_SEED; h <= NDT_RANGE_BEST + 5; h++) {
        struct uint256 hh, fh;
        ndt_hash_for(h, &hh);
        fh = hh;
        fh.data[5] = 0x77;
        struct block_index *x = block_map_find(&a->map_block_index, &hh);
        struct block_index *y = block_map_find(&b->map_block_index, &hh);
        if ((x == NULL) != (y == NULL) || (x && !ndt_entries_equal(x, y)))
            d.diffs++;
        if (block_map_find(&b->map_block_index, &fh))
            d.fork_hits++;
        d.compared++;
    }
    return d;
}

static int ndt_range_equivalence_cases(const char *dir)
{
    int failures = 0;
    char ndb_path[320], prog_path[320];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node_range.db", dir);
    snprintf(prog_path, sizeof(prog_path), "%s/progress_range.db", dir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    sqlite3 *progress = NULL;
    bool ready = node_db_open(&ndb, ndb_path) &&
                 sqlite3_open(prog_path, &progress) == SQLITE_OK &&
                 ndt_range_build_db(&ndb) &&
                 ndt_set_coins_best(progress, NDT_RANGE_BEST);
    NDT_CHECK("range: fixture db built", ready);
    struct main_state old_ms, new_ms;
    main_state_init(&old_ms);
    main_state_init(&new_ms);
    if (ready)
        ready = ndt_range_fill_map(&old_ms) && ndt_range_fill_map(&new_ms);
    NDT_CHECK("range: maps seeded", ready);
    if (ready) {
        char old_line[1024], new_line[1024];
        int64_t old_ms_t = 0, new_ms_t = 0;
        bool a = ndt_range_run(&old_ms, &ndb, progress, dir, true,
                               old_line, sizeof(old_line), &old_ms_t);
        bool b = ndt_range_run(&new_ms, &ndb, progress, dir, false,
                               new_line, sizeof(new_line), &new_ms_t);
        NDT_CHECK("range: both paths return ok", a && b);
        NDT_CHECK("range: counter line present", old_line[0] != '\0');
        NDT_CHECK("range: counter lines identical",
                  strcmp(old_line, new_line) == 0);
        NDT_CHECK("range: map sizes identical",
                  old_ms.map_block_index.size == new_ms.map_block_index.size);
        struct ndt_range_diff d = ndt_range_compare(&old_ms, &new_ms);
        const size_t diffs = d.diffs, compared = d.compared,
                     fork_hits = d.fork_hits;
        NDT_CHECK("range: >=100k heights compared", compared >= 100000);
        NDT_CHECK("range: every entry identical (hash,height,status,file,"
                  "pos,undo,nTx,chainwork,pprev)", diffs == 0);
        NDT_CHECK("range: no stale fork row was ever adopted",
                  fork_hits == 0);
        struct uint256 above;
        ndt_hash_for(NDT_RANGE_BEST + 1, &above);
        NDT_CHECK("range: window above coins_best untouched",
                  block_map_find(&new_ms.map_block_index, &above) == NULL);
        printf("block_index_node_db_topup: range timing: heights=%d "
               "per_height_ms=%lld range_ms=%lld\n",
               NDT_RANGE_BEST - NDT_RANGE_SEED, (long long)old_ms_t,
               (long long)new_ms_t);
        /* Production shape: a warm boot re-folds a window already in the map
         * (inserted=0), so the cost is the row reads alone. */
        int64_t warm_old_ms = 0, warm_new_ms = 0;
        char warm_old[1024], warm_new[1024];
        bool wa = ndt_range_run(&new_ms, &ndb, progress, dir, true,
                                warm_old, sizeof(warm_old), &warm_old_ms);
        bool wb = ndt_range_run(&new_ms, &ndb, progress, dir, false,
                                warm_new, sizeof(warm_new), &warm_new_ms);
        NDT_CHECK("range: warm re-fold counter lines identical",
                  wa && wb && strcmp(warm_old, warm_new) == 0);
        printf("block_index_node_db_topup: range timing (warm, inserted=0): "
               "per_height_ms=%lld range_ms=%lld\n",
               (long long)warm_old_ms, (long long)warm_new_ms);
    }
    main_state_free(&old_ms);
    main_state_free(&new_ms);
    if (progress)
        sqlite3_close(progress);
    node_db_close(&ndb);
    return failures;
}

/* Probe scan: the same rows as the full scan with the state columns the
 * existing-entry fold reads, and none of the header blobs (the full scan
 * records the solution length, the probe leaves it zero). */
struct ndt_probe_seen {
    int n;
    bool full;
    int height[8];
    int status[8], file[8], data[8], undo[8], ntx[8];
    uint8_t hash0[8];
    size_t solution_len[8];
};

static bool ndt_probe_cb(int height, const struct db_block *row, void *ctx)
{
    struct ndt_probe_seen *p = ctx;
    if (p->n >= 8)
        return false;
    int i = p->n++;
    p->height[i] = height;
    p->status[i] = row->status;
    p->file[i] = row->file_num;
    p->data[i] = row->data_pos;
    p->undo[i] = row->undo_pos;
    p->ntx[i] = row->num_tx;
    p->hash0[i] = row->hash[0] ^ row->hash[31];
    p->solution_len[i] = row->solution_len;
    return true;
}

/* Row-for-row on the fold's columns; *narrow is true when the full scan saw a
 * solution length everywhere and the probe saw none. */
static bool ndt_probe_compare(const struct ndt_probe_seen *full,
                              const struct ndt_probe_seen *probe, bool *narrow)
{
    bool same = full->n == probe->n;
    *narrow = true;
    for (int i = 0; same && i < full->n; i++) {
        same = full->height[i] == probe->height[i] &&
               full->status[i] == probe->status[i] &&
               full->file[i] == probe->file[i] &&
               full->data[i] == probe->data[i] &&
               full->undo[i] == probe->undo[i] &&
               full->ntx[i] == probe->ntx[i] &&
               full->hash0[i] == probe->hash0[i];
        *narrow = *narrow && full->solution_len[i] > 0 &&
                  probe->solution_len[i] == 0;
    }
    return same;
}

static int ndt_probe_scan_cases(const char *dir)
{
    int failures = 0;
    char path[320];
    snprintf(path, sizeof(path), "%s/node_probe.db", dir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ready = node_db_open(&ndb, path);
    for (int h = 10; ready && h <= 14; h++)
        ready = ndt_write_block_row(&ndb, h, 3 | BLOCK_HAVE_DATA, 2000 + h);
    NDT_CHECK("probe: fixture db built", ready);
    struct ndt_probe_seen full, probe;
    memset(&full, 0, sizeof(full));
    memset(&probe, 0, sizeof(probe));
    bool a = ready && db_block_scan_height_range(&ndb, 9, 15, ndt_probe_cb,
                                                 &full);
    bool b = ready && db_block_scan_height_range_probe(&ndb, 9, 15,
                                                       ndt_probe_cb, &probe);
    NDT_CHECK("probe: both scans ok, five rows each",
              a && b && full.n == 5 && probe.n == 5);
    bool narrow = false;
    bool same = ndt_probe_compare(&full, &probe, &narrow);
    NDT_CHECK("probe: rows match the full scan on the fold's columns", same);
    NDT_CHECK("probe: no solution bytes are read", narrow);
    struct ndt_probe_seen stop;
    memset(&stop, 0, sizeof(stop));
    NDT_CHECK("probe: bad range refused",
              !db_block_scan_height_range_probe(&ndb, 5, 4, ndt_probe_cb,
                                                &stop));
    node_db_close(&ndb);
    return failures;
}

int test_block_index_node_db_topup(void)
{
    int failures = 0;
    printf("\n=== block_index node.db forward-extent top-up tests ===\n");

    char dir[256];
    snprintf(dir, sizeof(dir), "./test-tmp/nodedbtopup_%d", (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);

    char ndb_path[320];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);
    char prog_path[320];
    snprintf(prog_path, sizeof(prog_path), "%s/progress.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    NDT_CHECK("setup: node.db opens", node_db_open(&ndb, ndb_path));

    sqlite3 *progress = NULL;
    NDT_CHECK("setup: progress.db opens",
              sqlite3_open(prog_path, &progress) == SQLITE_OK);

    /* Fixture: seed anchor at H_seed=102, coins_best=105.
     * node.db `blocks` carries the connected window 103..105 (plus 100..102
     * so prev-linking is exercised through the seed anchor). */
    const int H_seed = 102;
    const int coins_best = 105;
    bool wrote = true;
    for (int h = 100; h <= coins_best; h++)
        wrote &= ndt_write_block(&ndb, h);
    NDT_CHECK("setup: window blocks written", wrote);

    /* In-memory map (the post-reload shape): contiguous chain 100..101 with
     * pprev links, then the seed anchor at 102 as a DETACHED root (pprev=NULL).
     * The forward window 103..105 is NOT in the map. */
    struct main_state ms;
    main_state_init(&ms);
    struct block_index *e100 = ndt_insert_entry(&ms, 100);
    struct block_index *e101 = ndt_insert_entry(&ms, 101);
    struct block_index *seed = ndt_insert_entry(&ms, 102);
    if (e101) e101->pprev = e100;
    /* seed->pprev deliberately left NULL — the cold-import snapshot base. */
    NDT_CHECK("setup: map has 100,101,detached-seed-102",
              e100 && e101 && seed && seed->pprev == NULL);

    /* Durable cold-import seed anchor keys (height + hash). */
    struct uint256 seed_hash;
    ndt_hash_for(H_seed, &seed_hash);
    NDT_CHECK("setup: seed anchor keys written",
              node_db_state_set_int(&ndb, "cold_import_seed_anchor_height",
                                    H_seed) &&
              node_db_state_set(&ndb, "cold_import_seed_anchor_hash",
                                seed_hash.data, 32));

    /* coins_best = 105 (applied_height = 106). */
    NDT_CHECK("setup: coins frontier set", ndt_set_coins_best(progress, coins_best));

    /* ── Run the top-up. ───────────────────────────────────────────── */
    bool ran = block_index_node_db_topup_with(&ms, &ndb, progress, dir);
    NDT_CHECK("topup returns ok", ran);

    /* 1. forward window inserted + pprev-linked down to the seed anchor. */
    struct uint256 h103, h104, h105;
    ndt_hash_for(103, &h103);
    ndt_hash_for(104, &h104);
    ndt_hash_for(105, &h105);
    struct block_index *e103 = block_map_find(&ms.map_block_index, &h103);
    struct block_index *e104 = block_map_find(&ms.map_block_index, &h104);
    struct block_index *e105 = block_map_find(&ms.map_block_index, &h105);
    NDT_CHECK("window heights inserted", e103 && e104 && e105);
    NDT_CHECK("inserted heights correct",
              e103 && e103->nHeight == 103 &&
              e104 && e104->nHeight == 104 &&
              e105 && e105->nHeight == 105);
    NDT_CHECK("inserted carry HAVE_DATA + positions",
              e103 && (e103->nStatus & BLOCK_HAVE_DATA) &&
              e103->nFile == 1 && e103->nDataPos == (unsigned)(1000 + 103));
    NDT_CHECK("inserted carry nTx from blocks row",
              e103 && e103->nTx == 2 && e105 && e105->nTx == 2);
    NDT_CHECK("pprev chain 105->104->103->seed",
              e105 && e105->pprev == e104 &&
              e104 && e104->pprev == e103 &&
              e103 && e103->pprev == seed);
    NDT_CHECK("seed anchor is no longer an orphan tip (has a child)",
              e103 && e103->pprev == seed);
    NDT_CHECK("inserted chainwork strictly increasing",
              e103 && e104 && e105 &&
              arith_uint256_compare(&e104->nChainWork,
                                    &e103->nChainWork) > 0 &&
              arith_uint256_compare(&e105->nChainWork,
                                    &e104->nChainWork) > 0);

    /* 4. window-bounded: nothing above coins_best (106) inserted. */
    struct uint256 h106;
    ndt_hash_for(106, &h106);
    NDT_CHECK("nothing above coins_best inserted",
              block_map_find(&ms.map_block_index, &h106) == NULL);

    /* 2. raise-only: pre-existing entries keep their state. */
    NDT_CHECK("e101 pprev preserved", e101 && e101->pprev == e100);

    /* 5. idempotent second run changes nothing. */
    bool ran2 = block_index_node_db_topup_with(&ms, &ndb, progress, dir);
    NDT_CHECK("second topup returns ok", ran2);
    NDT_CHECK("second topup changed nothing",
              e105 && e105->pprev == e104 && e105->nTx == 2 &&
              e103 && e103->pprev == seed);

    main_state_free(&ms);

    /* ── NO-OP without a seed anchor (normal / P2P-origin datadir). ──── */
    {
        struct node_db ndb2;
        memset(&ndb2, 0, sizeof(ndb2));
        char ndb2_path[320];
        snprintf(ndb2_path, sizeof(ndb2_path), "%s/node2.db", dir);
        bool opened = node_db_open(&ndb2, ndb2_path);
        NDT_CHECK("noseed: node.db opens", opened);
        if (opened) {
            for (int h = 100; h <= coins_best; h++)
                (void)ndt_write_block(&ndb2, h);
            /* NO cold_import_seed_anchor_* keys written. */
            struct main_state ms2;
            main_state_init(&ms2);
            struct block_index *s100 = ndt_insert_entry(&ms2, 100);
            (void)s100;
            size_t before = ms2.map_block_index.size;
            bool ok = block_index_node_db_topup_with(&ms2, &ndb2, progress, dir);
            size_t after = ms2.map_block_index.size;
            NDT_CHECK("noseed: returns ok", ok);
            NDT_CHECK("noseed: STRICT no-op (map unchanged)", after == before);
            main_state_free(&ms2);
            node_db_close(&ndb2);
        }
    }

    /* ── NO-OP on an empty window (coins_best <= H_seed). ───────────── */
    {
        struct node_db ndb3;
        memset(&ndb3, 0, sizeof(ndb3));
        char ndb3_path[320];
        snprintf(ndb3_path, sizeof(ndb3_path), "%s/node3.db", dir);
        char prog3_path[320];
        snprintf(prog3_path, sizeof(prog3_path), "%s/progress3.db", dir);
        sqlite3 *progress3 = NULL;
        bool opened = node_db_open(&ndb3, ndb3_path) &&
                      sqlite3_open(prog3_path, &progress3) == SQLITE_OK;
        NDT_CHECK("empty-window: dbs open", opened);
        if (opened) {
            for (int h = 100; h <= H_seed; h++)
                (void)ndt_write_block(&ndb3, h);
            struct uint256 sh;
            ndt_hash_for(H_seed, &sh);
            node_db_state_set_int(&ndb3, "cold_import_seed_anchor_height",
                                  H_seed);
            node_db_state_set(&ndb3, "cold_import_seed_anchor_hash",
                              sh.data, 32);
            /* coins_best == H_seed → empty forward window. */
            (void)ndt_set_coins_best(progress3, H_seed);
            struct main_state ms3;
            main_state_init(&ms3);
            struct block_index *sd = ndt_insert_entry(&ms3, H_seed);
            (void)sd;
            size_t before = ms3.map_block_index.size;
            bool ok = block_index_node_db_topup_with(&ms3, &ndb3, progress3, dir);
            size_t after = ms3.map_block_index.size;
            NDT_CHECK("empty-window: returns ok", ok);
            NDT_CHECK("empty-window: no insert", after == before);
            main_state_free(&ms3);
            if (progress3) sqlite3_close(progress3);
            node_db_close(&ndb3);
        }
    }

    /* NULL node.db / NULL progress are no-op successes. */
    {
        struct main_state ms4;
        main_state_init(&ms4);
        NDT_CHECK("NULL node.db no-op",
                  block_index_node_db_topup_with(&ms4, NULL, progress, dir));
        NDT_CHECK("NULL progress no-op",
                  block_index_node_db_topup_with(&ms4, &ndb, NULL, dir));
        main_state_free(&ms4);
    }

    if (progress) sqlite3_close(progress);
    node_db_close(&ndb);
    return failures + ndt_undo_topup_cases(dir) +
           ndt_range_equivalence_cases(dir) +
           ndt_probe_scan_cases(dir);
}
