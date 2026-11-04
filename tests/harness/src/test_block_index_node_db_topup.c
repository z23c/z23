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
#include "config/db_service.h"
#include "config/runtime.h"

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

static bool ndt_range_row_with_ntx(struct node_db *ndb, int h, bool fork,
                                   int ntx_override)
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
    b.num_tx = ntx_override >= 0 ? ntx_override : (h % 4 == 0) ? 0 : 2;
    b.sapling_value = h % 9;
    b.sprout_value = (h % 6 == 0) ? 5 : 0;
    return db_block_save(ndb, &b);
}

static bool ndt_range_row(struct node_db *ndb, int h, bool fork)
{
    return ndt_range_row_with_ntx(ndb, h, fork, -1);
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

/* Run one top-up with stdout captured; copy the counter line into `line`.
 * Clock-free: callers that assert on the counters use this directly. */
static bool ndt_range_capture(struct main_state *ms, struct node_db *ndb,
                              sqlite3 *progress, const char *dir, bool oracle,
                              char *line, size_t line_cap)
{
    char path[320];
    snprintf(path, sizeof(path), "%s/stdout_capture.txt", dir);
    line[0] = '\0';
    fflush(stdout);
    int saved = dup(1);
    if (saved < 0)
        return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        close(saved);
        return false;
    }
    if (dup2(fd, 1) < 0) {
        close(fd);
        close(saved);
        return false;
    }
    close(fd);
    g_node_db_topup_perheight_oracle = oracle;
    bool ok = block_index_node_db_topup_with(ms, ndb, progress, dir);
    g_node_db_topup_perheight_oracle = false;
    fflush(stdout);
    bool restored = dup2(saved, 1) >= 0;
    close(saved);
    if (!restored)
        return false;
    FILE *fp = fopen(path, "r");
    if (fp) {
        while (fgets(line, (int)line_cap, fp) &&
               !strstr(line, "node.db top-up"))
            line[0] = '\0';
        fclose(fp);
    }
    return ok;
}

/* Timed variant of ndt_range_capture: the timing is reported, never asserted. */
static bool ndt_range_run(struct main_state *ms, struct node_db *ndb,
                          sqlite3 *progress, const char *dir, bool oracle,
                          char *line, size_t line_cap, int64_t *ms_out)
{
    int64_t t0 = ndt_now_ms();
    bool ok = ndt_range_capture(ms, ndb, progress, dir, oracle, line, line_cap);
    *ms_out = ndt_now_ms() - t0;
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

/* The forward-extent fold's shared fixture: the node.db and progress.db
 * opened once for the whole group, the in-memory map and its entries of
 * interest. */
struct ndt_window_fixture {
    struct node_db ndb;
    sqlite3 *progress;
    struct main_state ms;
    struct block_index *e100;
    struct block_index *e101;
    struct block_index *seed;
    struct block_index *e103;
    struct block_index *e104;
    struct block_index *e105;
};

/* Open the shared dbs, write the window rows, seed the in-memory map, store
 * the durable seed-anchor keys and set the coins frontier. */
static int ndt_setup_cold_import_fixture(struct ndt_window_fixture *fx,
                                         const char *dir)
{
    int failures = 0;
    char ndb_path[320];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);
    char prog_path[320];
    snprintf(prog_path, sizeof(prog_path), "%s/progress.db", dir);

    NDT_CHECK("setup: node.db opens", node_db_open(&fx->ndb, ndb_path));

    fx->progress = NULL;
    NDT_CHECK("setup: progress.db opens",
              sqlite3_open(prog_path, &fx->progress) == SQLITE_OK);

    /* Fixture: seed anchor at H_seed=102, coins_best=105.
     * node.db `blocks` carries the connected window 103..105 (plus 100..102
     * so prev-linking is exercised through the seed anchor). */
    const int H_seed = 102;
    const int coins_best = 105;
    bool wrote = true;
    for (int h = 100; h <= coins_best; h++)
        wrote &= ndt_write_block(&fx->ndb, h);
    NDT_CHECK("setup: window blocks written", wrote);

    /* In-memory map (the post-reload shape): contiguous chain 100..101 with
     * pprev links, then the seed anchor at 102 as a DETACHED root (pprev=NULL).
     * The forward window 103..105 is NOT in the map. */
    main_state_init(&fx->ms);
    fx->e100 = ndt_insert_entry(&fx->ms, 100);
    fx->e101 = ndt_insert_entry(&fx->ms, 101);
    fx->seed = ndt_insert_entry(&fx->ms, 102);
    if (fx->e101) fx->e101->pprev = fx->e100;
    /* seed->pprev deliberately left NULL — the cold-import snapshot base. */
    NDT_CHECK("setup: map has 100,101,detached-seed-102",
              fx->e100 && fx->e101 && fx->seed && fx->seed->pprev == NULL);

    /* Durable cold-import seed anchor keys (height + hash). */
    struct uint256 seed_hash;
    ndt_hash_for(H_seed, &seed_hash);
    NDT_CHECK("setup: seed anchor keys written",
              node_db_state_set_int(&fx->ndb, "cold_import_seed_anchor_height",
                                    H_seed) &&
              node_db_state_set(&fx->ndb, "cold_import_seed_anchor_hash",
                                seed_hash.data, 32));

    /* coins_best = 105 (applied_height = 106). */
    NDT_CHECK("setup: coins frontier set", ndt_set_coins_best(fx->progress, coins_best));
    return failures;
}

/* Run the top-up once, then check the forward window heights are in the map
 * with their height labels. */
static int ndt_topup_run_check_window_inserted(struct ndt_window_fixture *fx,
                                               const char *dir)
{
    int failures = 0;

    /* ── Run the top-up. ───────────────────────────────────────────── */
    bool ran = block_index_node_db_topup_with(&fx->ms, &fx->ndb, fx->progress,
                                              dir);
    NDT_CHECK("topup returns ok", ran);

    /* 1. forward window inserted + pprev-linked down to the seed anchor. */
    struct uint256 h103, h104, h105;
    ndt_hash_for(103, &h103);
    ndt_hash_for(104, &h104);
    ndt_hash_for(105, &h105);
    fx->e103 = block_map_find(&fx->ms.map_block_index, &h103);
    fx->e104 = block_map_find(&fx->ms.map_block_index, &h104);
    fx->e105 = block_map_find(&fx->ms.map_block_index, &h105);
    NDT_CHECK("window heights inserted", fx->e103 && fx->e104 && fx->e105);
    NDT_CHECK("inserted heights correct",
              fx->e103 && fx->e103->nHeight == 103 &&
              fx->e104 && fx->e104->nHeight == 104 &&
              fx->e105 && fx->e105->nHeight == 105);
    return failures;
}

/* Check the inserted entries carry data positions and nTx from their
 * `blocks` rows. */
static int ndt_check_inserted_entry_state(const struct ndt_window_fixture *fx)
{
    int failures = 0;
    NDT_CHECK("inserted carry HAVE_DATA + positions",
              fx->e103 && (fx->e103->nStatus & BLOCK_HAVE_DATA) &&
              fx->e103->nFile == 1 && fx->e103->nDataPos == (unsigned)(1000 + 103));
    NDT_CHECK("inserted carry nTx from blocks row",
              fx->e103 && fx->e103->nTx == 2 && fx->e105 && fx->e105->nTx == 2);
    return failures;
}

/* Check the inserted window is pprev-linked down to the seed anchor and its
 * chainwork strictly increases across it. */
static int ndt_check_inserted_links_and_chainwork(const struct ndt_window_fixture *fx)
{
    int failures = 0;
    NDT_CHECK("pprev chain 105->104->103->seed",
              fx->e105 && fx->e105->pprev == fx->e104 &&
              fx->e104 && fx->e104->pprev == fx->e103 &&
              fx->e103 && fx->e103->pprev == fx->seed);
    NDT_CHECK("seed anchor is no longer an orphan tip (has a child)",
              fx->e103 && fx->e103->pprev == fx->seed);
    NDT_CHECK("inserted chainwork strictly increasing",
              fx->e103 && fx->e104 && fx->e105 &&
              arith_uint256_compare(&fx->e104->nChainWork,
                                    &fx->e103->nChainWork) > 0 &&
              arith_uint256_compare(&fx->e105->nChainWork,
                                    &fx->e104->nChainWork) > 0);
    return failures;
}

/* Check nothing above coins_best was inserted, pre-existing links survive,
 * and a second run changes nothing. */
static int ndt_check_window_bounds_and_idempotence(struct ndt_window_fixture *fx,
                                                   const char *dir)
{
    int failures = 0;

    /* 4. window-bounded: nothing above coins_best (106) inserted. */
    struct uint256 h106;
    ndt_hash_for(106, &h106);
    NDT_CHECK("nothing above coins_best inserted",
              block_map_find(&fx->ms.map_block_index, &h106) == NULL);

    /* 2. raise-only: pre-existing entries keep their state. */
    NDT_CHECK("e101 pprev preserved", fx->e101 && fx->e101->pprev == fx->e100);

    /* 5. idempotent second run changes nothing. */
    bool ran2 = block_index_node_db_topup_with(&fx->ms, &fx->ndb, fx->progress,
                                               dir);
    NDT_CHECK("second topup returns ok", ran2);
    NDT_CHECK("second topup changed nothing",
              fx->e105 && fx->e105->pprev == fx->e104 && fx->e105->nTx == 2 &&
              fx->e103 && fx->e103->pprev == fx->seed);
    return failures;
}

/* ── NO-OP without a seed anchor (normal / P2P-origin datadir). ──── */
static int ndt_noseed_noop_checks(const char *dir, sqlite3 *progress)
{
    int failures = 0;
    const int coins_best = 105;
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
    return failures;
}

/* ── NO-OP on an empty window (coins_best <= H_seed). ───────────── */
static int ndt_empty_window_noop_checks(const char *dir)
{
    int failures = 0;
    const int H_seed = 102;
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
    return failures;
}

/* NULL node.db / NULL progress are no-op successes. */
static int ndt_null_db_noop_checks(const char *dir, struct node_db *ndb,
                                   sqlite3 *progress)
{
    int failures = 0;
    struct main_state ms4;
    main_state_init(&ms4);
    NDT_CHECK("NULL node.db no-op",
              block_index_node_db_topup_with(&ms4, NULL, progress, dir));
    NDT_CHECK("NULL progress no-op",
              block_index_node_db_topup_with(&ms4, ndb, NULL, dir));
    main_state_free(&ms4);
    return failures;
}

static int ndt_clean_prefix_cases(const char *dir);
static int ndt_holes_cases(const char *dir);
static int ndt_tail_advance_cases(const char *dir, bool prefix_change);
static int ndt_transaction_ownership(const char *dir);
static int ndt_service_dispatch(const char *dir);

int test_block_index_node_db_topup(void)
{
    printf("\n=== block_index node.db forward-extent top-up tests ===\n");

    char dir[256];
    snprintf(dir, sizeof(dir), "./test-tmp/nodedbtopup_%d", (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);

    struct ndt_window_fixture fx;
    memset(&fx, 0, sizeof(fx));
    int failures = ndt_setup_cold_import_fixture(&fx, dir);
    failures += ndt_topup_run_check_window_inserted(&fx, dir);
    failures += ndt_check_inserted_entry_state(&fx);
    failures += ndt_check_inserted_links_and_chainwork(&fx);
    failures += ndt_check_window_bounds_and_idempotence(&fx, dir);
    main_state_free(&fx.ms);
    failures += ndt_noseed_noop_checks(dir, fx.progress);
    failures += ndt_empty_window_noop_checks(dir);
    failures += ndt_null_db_noop_checks(dir, &fx.ndb, fx.progress);

    if (fx.progress) sqlite3_close(fx.progress);
    node_db_close(&fx.ndb);
    return failures + ndt_undo_topup_cases(dir) +
           ndt_range_equivalence_cases(dir) +
           ndt_probe_scan_cases(dir) +
           ndt_clean_prefix_cases(dir) +
           ndt_holes_cases(dir) + ndt_tail_advance_cases(dir, false) +
           ndt_tail_advance_cases(dir, true) + ndt_transaction_ownership(dir) +
           ndt_service_dispatch(dir);
}

/* ── Proven-clean prefix: a warm re-fold reads only the tip region ─────────
 * A window whose fold changes nothing is recorded as clean up to
 * coins_best - margin. The next top-up over an identical map must read only
 * the rows above that prefix and leave the map exactly as a full fold does;
 * a map the mark was not proven against, or a node.db whose row count moved,
 * must fall back to the whole window. */
#define NDT_CLEAN_SEED 5000
#define NDT_CLEAN_BEST 8500
#define NDT_CLEAN_MARGIN 1024

static bool ndt_clean_build(struct node_db *ndb)
{
    bool ok = sqlite3_exec(ndb->db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK;
    for (int h = NDT_CLEAN_SEED; ok && h <= NDT_CLEAN_BEST; h++)
        ok &= ndt_range_row(ndb, h, false);
    ok &= sqlite3_exec(ndb->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    struct uint256 sh;
    ndt_hash_for(NDT_CLEAN_SEED, &sh);
    ok &= node_db_state_set_int(ndb, "cold_import_seed_anchor_height",
                                NDT_CLEAN_SEED);
    ok &= node_db_state_set(ndb, "cold_import_seed_anchor_hash", sh.data, 32);
    return ok;
}

static int ndt_transaction_ownership(const char *dir)
{
    int failures = 0;
    char ndb_path[320], prog_path[320];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node_tx.db", dir);
    snprintf(prog_path, sizeof(prog_path), "%s/progress_tx.db", dir);
    struct node_db ndb = {0};
    sqlite3 *progress = NULL;
    struct main_state ms;
    main_state_init(&ms);
    bool ready = node_db_open(&ndb, ndb_path) &&
                 sqlite3_open(prog_path, &progress) == SQLITE_OK &&
                 ndt_clean_build(&ndb) &&
                 ndt_set_coins_best(progress, NDT_CLEAN_BEST) &&
                 ndt_insert_entry(&ms, NDT_CLEAN_SEED);
    NDT_CHECK("transaction: fixture opened", ready);
    if (ready) {
        bool begun = node_db_begin(&ndb);
        NDT_CHECK("transaction: caller began", begun);
        bool wrote = begun && node_db_state_set_int(&ndb, "topup_tx_probe", 7);
        NDT_CHECK("transaction: caller write succeeds", wrote);
        NDT_CHECK("transaction: topup runs inside caller transaction",
                  wrote && block_index_node_db_topup_with(&ms, &ndb, progress, dir) &&
                  g_node_db_topup_last_rows_seen == NDT_CLEAN_BEST - NDT_CLEAN_SEED);
        int64_t value = 0;
        NDT_CHECK("transaction: caller transaction remains open and intact",
                  sqlite3_get_autocommit(ndb.db) == 0 &&
                  node_db_state_get_int(&ndb, "topup_tx_probe", &value) && value == 7);
        NDT_CHECK("transaction: caller rollback succeeds", begun && node_db_rollback(&ndb));
        NDT_CHECK("transaction: caller write rolled back",
                  !node_db_state_get_int(&ndb, "topup_tx_probe", &value));
    }
    main_state_free(&ms);
    if (progress) sqlite3_close(progress);
    node_db_close(&ndb);
    return failures;
}

struct ndt_service_call {
    struct db_service *svc;
    struct main_state *ms;
    const char *dir;
};

static bool ndt_service_reentrant(struct node_db *ndb, void *arg)
{
    struct ndt_service_call *call = arg;
    return db_service_is_worker_thread(call->svc) &&
           block_index_node_db_topup(call->ms, ndb, call->dir);
}

static int ndt_service_dispatch(const char *dir)
{
    int failures = 0;
    char ndb_path[320], other_path[320];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node_service.db", dir);
    snprintf(other_path, sizeof(other_path), "%s/node_service_other.db", dir);
    struct node_db ndb = {0};
    struct node_db other = {0};
    struct main_state ms, other_ms;
    struct db_service svc;
    struct app_runtime_context runtime = {0};
    main_state_init(&ms);
    main_state_init(&other_ms);
    db_service_init(&svc);
    bool ready = node_db_open(&ndb, ndb_path) &&
                 node_db_open(&other, other_path) && progress_store_open(dir) &&
                 ndt_clean_build(&ndb) &&
                 ndt_clean_build(&other) &&
                 ndt_set_coins_best(progress_store_db(), NDT_CLEAN_BEST) &&
                 ndt_insert_entry(&ms, NDT_CLEAN_SEED) &&
                 ndt_insert_entry(&other_ms, NDT_CLEAN_SEED) &&
                 db_service_attach(&svc, &ndb) && db_service_start_test_worker(&svc);
    NDT_CHECK("service: fixture and writer started", ready);
    if (ready) {
        runtime.db_service = &svc;
        app_runtime_set_current(&runtime);
        NDT_CHECK("service: topup dispatched to matching writer",
                  block_index_node_db_topup(&ms, &ndb, dir) &&
                  g_node_db_topup_last_rows_seen == NDT_CLEAN_BEST - NDT_CLEAN_SEED);
        struct ndt_service_call call = { &svc, &ms, dir };
        NDT_CHECK("service: worker reentrant topup succeeds",
                  db_service_run_write(&svc, ndt_service_reentrant, &call));
        NDT_CHECK("service: unrelated database uses direct path",
                  block_index_node_db_topup(&other_ms, &other, dir) &&
                  g_node_db_topup_last_rows_seen == NDT_CLEAN_BEST - NDT_CLEAN_SEED);
        zcl_mutex_lock(&ms.cs_main);
        bool locked_ok = block_index_node_db_topup_with(
            &ms, &ndb, progress_store_db(), dir);
        zcl_mutex_unlock(&ms.cs_main);
        NDT_CHECK("service: locked caller uses direct with path", locked_ok);
        app_runtime_set_current(NULL);
    }
    db_service_stop(&svc);
    main_state_free(&ms);
    main_state_free(&other_ms);
    progress_store_close();
    node_db_close(&other);
    node_db_close(&ndb);
    return failures;
}

static bool ndt_clean_topup(struct main_state *ms, struct node_db *ndb,
                            sqlite3 *progress, const char *dir, bool oracle,
                            size_t *rows_seen)
{
    char line[1024];
    bool ok = ndt_range_capture(ms, ndb, progress, dir, oracle, line,
                                sizeof(line));
    *rows_seen = g_node_db_topup_last_rows_seen;
    return ok;
}

static int ndt_clean_prefix_cases(const char *dir)
{
    int failures = 0;
    char ndb_path[320], prog_path[320];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node_clean.db", dir);
    snprintf(prog_path, sizeof(prog_path), "%s/progress_clean.db", dir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    sqlite3 *progress = NULL;
    bool ready = node_db_open(&ndb, ndb_path) &&
                 sqlite3_open(prog_path, &progress) == SQLITE_OK &&
                 ndt_clean_build(&ndb) &&
                 ndt_set_coins_best(progress, NDT_CLEAN_BEST);
    NDT_CHECK("clean: fixture db built", ready);
    struct main_state a, b, c;
    main_state_init(&a);
    main_state_init(&b);
    main_state_init(&c);
    ready = ready && ndt_insert_entry(&a, NDT_CLEAN_SEED) &&
            ndt_insert_entry(&b, NDT_CLEAN_SEED) &&
            ndt_insert_entry(&c, NDT_CLEAN_SEED);
    const size_t window = NDT_CLEAN_BEST - NDT_CLEAN_SEED;
    size_t r1 = 0, r2 = 0, r3 = 0, r4 = 0, r5 = 0, r6 = 0, ro = 0;
    if (ready) {
        /* Cold: inserts the window (not a no-op, so no mark yet). */
        NDT_CHECK("clean: cold fold ok",
                  ndt_clean_topup(&a, &ndb, progress, dir, false, &r1));
        NDT_CHECK("clean: cold fold read the whole window", r1 == window);
        /* Second fold changes nothing and records the prefix. */
        NDT_CHECK("clean: no-op fold ok",
                  ndt_clean_topup(&a, &ndb, progress, dir, false, &r2));
        NDT_CHECK("clean: no-op fold read the whole window", r2 == window);
        /* Third: the prefix re-verifies; only the tip region is read. */
        NDT_CHECK("clean: warm fold ok",
                  ndt_clean_topup(&a, &ndb, progress, dir, false, &r3));
        printf("block_index_node_db_topup: clean prefix rows read: "
               "cold=%zu noop=%zu warm=%zu\n", r1, r2, r3);
        NDT_CHECK("clean: warm fold read only the tip region",
                  r3 > 0 && r3 <= NDT_CLEAN_MARGIN);
        /* The map the resumed fold leaves is the full fold's map. */
        NDT_CHECK("clean: oracle full fold ok",
                  ndt_clean_topup(&b, &ndb, progress, dir, true, &ro));
        NDT_CHECK("clean: resumed map size == full-fold map size",
                  a.map_block_index.size == b.map_block_index.size);
        int diffs = 0;
        for (int h = NDT_CLEAN_SEED; h <= NDT_CLEAN_BEST + 5; h++) {
            struct uint256 hh;
            ndt_hash_for(h, &hh);
            struct block_index *x = block_map_find(&a.map_block_index, &hh);
            struct block_index *y = block_map_find(&b.map_block_index, &hh);
            if ((x == NULL) != (y == NULL) || (x && !ndt_entries_equal(x, y)))
                diffs++;
        }
        NDT_CHECK("clean: every entry identical to the full fold", diffs == 0);
        /* A map the mark was not proven against must fold the whole window. */
        NDT_CHECK("clean: foreign map fold ok",
                  ndt_clean_topup(&c, &ndb, progress, dir, false, &r4));
        NDT_CHECK("clean: foreign map read the whole window", r4 == window);
        /* A node.db row the mark never saw forces the whole window too. */
        NDT_CHECK("clean: refold records the mark again",
                  ndt_clean_topup(&c, &ndb, progress, dir, false, &r4));
        NDT_CHECK("clean: row 6000 de-connected",
                  sqlite3_exec(ndb.db,
                               "UPDATE blocks SET status=2 WHERE height=6000",
                               NULL, NULL, NULL) == SQLITE_OK);
        NDT_CHECK("clean: changed row count fold ok",
                  ndt_clean_topup(&c, &ndb, progress, dir, false, &r5));
        NDT_CHECK("clean: changed row count read the whole window",
                  r5 == window - 1);
        /* Row 6000 is now a fixed hole (no status>=3 row). The fold above
         * saw every connected row and changed nothing, so it records a mark
         * pinning the hole; the next fold resumes past it. */
        NDT_CHECK("clean: fold after a fixed hole ok",
                  ndt_clean_topup(&c, &ndb, progress, dir, false, &r6));
        NDT_CHECK("clean: fold after a fixed hole resumed",
                  r6 > 0 && r6 <= NDT_CLEAN_MARGIN);
    }
    main_state_free(&a);
    main_state_free(&b);
    main_state_free(&c);
    if (progress)
        sqlite3_close(progress);
    node_db_close(&ndb);
    return failures;
}

/* ── Known holes: a window with fixed interior holes still earns a mark ────
 * The holes are heights with no status>=3 row. A no-op fold over them
 * records the mark; the next top-up resumes past it. Filling a hole, changing
 * an entry the mark covers, or a mark of an older format forces the whole
 * window again. */
#define NDT_HOLE_A 6001
#define NDT_HOLE_B 7002
#define NDT_HOLE_PROBE 6200
#define NDT_MARK_VERSION_OFFSET 44

static bool ndt_holes_build(struct node_db *ndb)
{
    bool ok = sqlite3_exec(ndb->db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK;
    for (int h = NDT_CLEAN_SEED; ok && h <= NDT_CLEAN_BEST; h++)
        if (h != NDT_HOLE_A && h != NDT_HOLE_B)
            ok &= ndt_range_row(ndb, h, false);
    ok &= sqlite3_exec(ndb->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    struct uint256 sh;
    ndt_hash_for(NDT_CLEAN_SEED, &sh);
    ok &= node_db_state_set_int(ndb, "cold_import_seed_anchor_height",
                                NDT_CLEAN_SEED);
    ok &= node_db_state_set(ndb, "cold_import_seed_anchor_hash", sh.data, 32);
    return ok;
}

/* Fold twice so a mark is recorded over the unchanged window. */
static bool ndt_holes_mark(struct main_state *ms, struct node_db *ndb,
                           sqlite3 *progress, const char *dir)
{
    size_t r = 0;
    return ndt_clean_topup(ms, ndb, progress, dir, false, &r) &&
           ndt_clean_topup(ms, ndb, progress, dir, false, &r);
}

static bool ndt_holes_old_mark(struct node_db *ndb)
{
    uint8_t blob[256];
    size_t n = 0;
    if (!node_db_state_get(ndb, "nodedb_topup_clean", blob, sizeof(blob), &n) ||
        n <= NDT_MARK_VERSION_OFFSET + 4)
        return false;
    memset(blob + NDT_MARK_VERSION_OFFSET, 0, 4);
    return node_db_state_set(ndb, "nodedb_topup_clean", blob, n);
}

static bool ndt_tail_entry_equal(const struct block_index *a,
                                 const struct block_index *b)
{
    if (!a || !b) return a == b;
    if (!ndt_entries_equal(a, b) || a->nBits != b->nBits ||
        a->nChainTx != b->nChainTx || (a->pskip == NULL) != (b->pskip == NULL))
        return false;
    if (a->pskip && memcmp(&a->pskip->hashBlock, &b->pskip->hashBlock,
                           sizeof(a->hashBlock)))
        return false;
    return !a->pprev || !memcmp(&a->pprev->hashBlock, &b->pprev->hashBlock,
                                sizeof(a->hashBlock));
}

static int ndt_deny_blocks_read(void *ctx, int action, const char *table,
                                const char *column, const char *db,
                                const char *source)
{
    (void)ctx; (void)column; (void)db; (void)source;
    return action == SQLITE_READ && table && strcmp(table, "blocks") == 0
               ? SQLITE_DENY : SQLITE_OK;
}

static int ndt_tail_read_control(struct main_state *ms, struct node_db *ndb,
                                 sqlite3 *progress, const char *dir)
{
    int failures = 0;
    size_t rows = 0;
    NDT_CHECK("tail safety: block reads denied in fixture",
              sqlite3_set_authorizer(ndb->db, ndt_deny_blocks_read, NULL) == SQLITE_OK);
    NDT_CHECK("tail safety: failed prefix read refuses topup",
              !ndt_clean_topup(ms, ndb, progress, dir, false, &rows));
    NDT_CHECK("tail safety: block reads restored",
              sqlite3_set_authorizer(ndb->db, NULL, NULL) == SQLITE_OK);
    NDT_CHECK("tail safety: revalidated prefix resumes after read recovery",
              ndt_clean_topup(ms, ndb, progress, dir, false, &rows) &&
              rows > 0 && rows <= NDT_CLEAN_MARGIN);
    return failures;
}

static int ndt_tail_map_diffs(struct main_state *actual, struct main_state *oracle)
{
    int diffs = actual->map_block_index.size != oracle->map_block_index.size;
    for (int h = NDT_CLEAN_SEED; h <= NDT_CLEAN_BEST + 68; h++) {
        struct uint256 hash;
        ndt_hash_for(h, &hash);
        struct block_index *a = block_map_find(&actual->map_block_index, &hash);
        struct block_index *b = block_map_find(&oracle->map_block_index, &hash);
        if (!ndt_tail_entry_equal(a, b)) diffs++;
    }
    return diffs;
}

static int ndt_tail_change_prefix(struct node_db *ndb)
{
    int failures = 0;
    struct db_block row;
    bool found = db_block_find_by_height(ndb, NDT_HOLE_PROBE, &row);
    NDT_CHECK("tail safety: connected prefix row initially has zero nTx",
              found && row.num_tx == 0);
    NDT_CHECK("tail safety: same-count prefix change saved",
              found && ndt_range_row_with_ntx(ndb, NDT_HOLE_PROBE, false, 7));
    return failures;
}

static int ndt_tail_verify_prefix(struct main_state *actual, size_t rows)
{
    int failures = 0;
    struct uint256 hash;
    ndt_hash_for(NDT_HOLE_PROBE, &hash);
    struct block_index *entry = block_map_find(&actual->map_block_index, &hash);
    NDT_CHECK("tail safety: full fold observes same-count prefix change",
              rows == NDT_CLEAN_BEST + 68 - NDT_CLEAN_SEED - 2 &&
              entry && entry->nTx == 7);
    return failures;
}

static bool ndt_tail_fixture_ready(struct node_db *ndb, sqlite3 **progress,
                                   const char *ndb_path, const char *prog_path,
                                   struct main_state *actual, struct main_state *oracle)
{
    return node_db_open(ndb, ndb_path) &&
           sqlite3_open(prog_path, progress) == SQLITE_OK &&
           ndt_holes_build(ndb) && ndt_set_coins_best(*progress, NDT_CLEAN_BEST) &&
           ndt_insert_entry(actual, NDT_CLEAN_SEED) &&
           ndt_insert_entry(oracle, NDT_CLEAN_SEED);
}

/* A changed tip must not discard the previously verified sparse prefix. */
static int ndt_tail_advance_cases(const char *dir, bool prefix_change)
{
    int failures = 0;
    char ndb_path[320], prog_path[320];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node_tail_%d.db", dir, prefix_change);
    snprintf(prog_path, sizeof(prog_path), "%s/progress_tail_%d.db", dir, prefix_change);
    struct node_db ndb = {0};
    sqlite3 *progress = NULL;
    struct main_state actual, oracle;
    main_state_init(&actual);
    main_state_init(&oracle);
    bool ready = ndt_tail_fixture_ready(&ndb, &progress, ndb_path, prog_path,
                                        &actual, &oracle);
    NDT_CHECK("tail advance: fixture built", ready);
    size_t rows = 0;
    if (ready) {
        NDT_CHECK("tail advance: sparse mark established",
                  ndt_holes_mark(&actual, &ndb, progress, dir));
        NDT_CHECK("tail advance: prefix initially resumed",
                  ndt_clean_topup(&actual, &ndb, progress, dir, false, &rows) &&
                  rows > 0 && rows <= NDT_CLEAN_MARGIN);
        if (prefix_change)
            failures += ndt_tail_read_control(&actual, &ndb, progress, dir);
        bool wrote = true;
        for (int h = NDT_CLEAN_BEST + 1; h <= NDT_CLEAN_BEST + 68; h++)
            wrote = ndt_range_row(&ndb, h, false) && wrote;
        NDT_CHECK("tail advance: new rows and frontier recorded",
                  wrote && ndt_set_coins_best(progress, NDT_CLEAN_BEST + 68));
        NDT_CHECK("tail advance: changed tail fold succeeds",
                  ndt_clean_topup(&actual, &ndb, progress, dir, false, &rows));
        struct uint256 last_hash;
        ndt_hash_for(NDT_CLEAN_BEST + 68, &last_hash);
        NDT_CHECK("tail advance: new tail was inserted",
                  block_map_find(&actual.map_block_index, &last_hash) != NULL);
        if (prefix_change) failures += ndt_tail_change_prefix(&ndb);
        NDT_CHECK("tail advance: next fold succeeds",
                  ndt_clean_topup(&actual, &ndb, progress, dir, false, &rows));
        printf("block_index_node_db_topup: tail advance next rows=%zu\n", rows);
        if (prefix_change)
            failures += ndt_tail_verify_prefix(&actual, rows);
        else {
            NDT_CHECK("tail advance: verified prefix remains bounded",
                      rows > 0 && rows <= NDT_CLEAN_MARGIN + 68);
        }
        size_t oracle_rows = 0;
        NDT_CHECK("tail advance: full oracle succeeds",
                  ndt_clean_topup(&oracle, &ndb, progress, dir, true, &oracle_rows));
        int diffs = ndt_tail_map_diffs(&actual, &oracle);
        if (prefix_change)
            NDT_CHECK("tail safety: map equals full oracle", diffs == 0);
        else
            NDT_CHECK("tail advance: map equals full oracle", diffs == 0);
    }
    main_state_free(&actual);
    main_state_free(&oracle);
    if (progress) sqlite3_close(progress);
    node_db_close(&ndb);
    return failures;
}

static int ndt_holes_cases(const char *dir)
{
    int failures = 0;
    char ndb_path[320], prog_path[320];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node_holes.db", dir);
    snprintf(prog_path, sizeof(prog_path), "%s/progress_holes.db", dir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    sqlite3 *progress = NULL;
    bool ready = node_db_open(&ndb, ndb_path) &&
                 sqlite3_open(prog_path, &progress) == SQLITE_OK &&
                 ndt_holes_build(&ndb) &&
                 ndt_set_coins_best(progress, NDT_CLEAN_BEST);
    NDT_CHECK("holes: fixture db built", ready);
    struct main_state a;
    main_state_init(&a);
    ready = ready && ndt_insert_entry(&a, NDT_CLEAN_SEED);
    const size_t window = NDT_CLEAN_BEST - NDT_CLEAN_SEED;
    size_t r = 0;
    if (ready) {
        NDT_CHECK("holes: cold fold ok",
                  ndt_clean_topup(&a, &ndb, progress, dir, false, &r));
        NDT_CHECK("holes: cold fold read every connected row", r == window - 2);
        /* (1)+(2) a no-op fold over the holes records a mark; the next
         * top-up resumes with the same holes. */
        NDT_CHECK("holes: no-op fold ok",
                  ndt_clean_topup(&a, &ndb, progress, dir, false, &r));
        NDT_CHECK("holes: no-op fold read the whole window", r == window - 2);
        NDT_CHECK("holes: warm fold ok",
                  ndt_clean_topup(&a, &ndb, progress, dir, false, &r));
        NDT_CHECK("holes: warm fold resumed past the prefix",
                  r > 0 && r <= NDT_CLEAN_MARGIN);
        /* (3) filling a hole forces the whole window. */
        NDT_CHECK("holes: hole filled",
                  ndt_range_row(&ndb, NDT_HOLE_A, false));
        NDT_CHECK("holes: fill fold ok",
                  ndt_clean_topup(&a, &ndb, progress, dir, false, &r));
        NDT_CHECK("holes: fill fold read the whole window", r == window - 1);
        /* (4) changing an entry the mark covers forces the whole window. */
        NDT_CHECK("holes: mark re-recorded", ndt_holes_mark(&a, &ndb, progress, dir));
        struct uint256 hh;
        ndt_hash_for(NDT_HOLE_PROBE, &hh);
        struct block_index *bi = block_map_find(&a.map_block_index, &hh);
        NDT_CHECK("holes: probe entry present", bi != NULL);
        if (bi)
            bi->nTx += 1;
        NDT_CHECK("holes: changed entry fold ok",
                  ndt_clean_topup(&a, &ndb, progress, dir, false, &r));
        NDT_CHECK("holes: changed entry read the whole window",
                  r == window - 1);
        /* (5) a mark of an older format is ignored. */
        NDT_CHECK("holes: mark re-recorded again",
                  ndt_holes_mark(&a, &ndb, progress, dir));
        NDT_CHECK("holes: mark downgraded to the old format",
                  ndt_holes_old_mark(&ndb));
        NDT_CHECK("holes: old-format mark fold ok",
                  ndt_clean_topup(&a, &ndb, progress, dir, false, &r));
        NDT_CHECK("holes: old-format mark ignored, whole window read",
                  r == window - 1);
    }
    main_state_free(&a);
    if (progress)
        sqlite3_close(progress);
    node_db_close(&ndb);
    return failures;
}
