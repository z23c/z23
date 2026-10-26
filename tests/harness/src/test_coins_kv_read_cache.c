/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_coins_kv_read_cache: differential byte-equivalence proof for the
 * cached point-read variants (coins_kv_get_prevout_sqlite_cached /
 * coins_kv_get_sqlite_cached / coins_kv_exists_sqlite_cached) against the
 * fresh-prepare _sqlite variants they mirror.
 *
 * The cached variants reuse one prepared statement (reset+rebind+step) to
 * skip per-call sqlite3_prepare_v2. Query text, binds and column extraction
 * are identical, so (found, value, script bytes, height, is_coinbase) must be
 * bit-for-bit the same and the terminal coins_kv / snapshot SHA3 unchanged.
 *
 * Over a populated coins_kv, for every present and a set of absent keys, the
 * cached read equals the fresh read: repeated through one cache, across a
 * finalize + re-prepare cycle, and with interleaved writes (the post-read
 * reset releases the row lock).
 *
 * make t ONLY=coins_kv_read_cache */

#include "test/test_core.h"

#include "script/script.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CKR_CHECK(name, expr) do {                                      \
    if (expr) { printf("  coins_kv_read_cache: %s... OK\n", (name)); }  \
    else { printf("  coins_kv_read_cache: %s... FAIL\n", (name)); failures++; } \
} while (0)

#define CKR_N 2000  /* populated coins */

static void ckr_txid(uint8_t out[32], uint64_t i)
{
    uint64_t h = 1469598103934665603ull;
    for (int k = 0; k < 8; k++) { h ^= (i >> (8 * k)) & 0xff; h *= 1099511628211ull; }
    for (int k = 0; k < 32; k++) {
        h ^= (uint64_t)(k + 1) * 2654435761ull; h *= 1099511628211ull;
        out[k] = (uint8_t)(h >> ((k % 8) * 8));
    }
}

/* Deterministic per-coin script: varied length incl. 0 (empty) and one large
 * near-MAX_SCRIPT_SIZE case, so the byte-compare exercises the blob path. */
static size_t ckr_script(uint64_t i, uint8_t *buf)
{
    size_t len;
    if (i % 37 == 0) len = 0;                       /* empty script */
    else if (i % 101 == 0) len = MAX_SCRIPT_SIZE;   /* max-size script */
    else len = 25 + (i % 40);                       /* typical */
    for (size_t k = 0; k < len; k++)
        buf[k] = (uint8_t)((i * 131 + k * 17) & 0xff);
    return len;
}

/* One durable read result, captured for byte-comparison. */
struct ckr_res {
    bool     found;
    int64_t  value;
    int32_t  height;
    bool     is_coinbase;
    size_t   slen;
    uint8_t  script[MAX_SCRIPT_SIZE];
};

static bool ckr_res_eq(const struct ckr_res *a, const struct ckr_res *b)
{
    if (a->found != b->found) return false;
    if (!a->found) return true;  /* absent: other fields undefined by contract */
    return a->value == b->value && a->height == b->height &&
           a->is_coinbase == b->is_coinbase && a->slen == b->slen &&
           memcmp(a->script, b->script, a->slen) == 0;
}

/* Fill the batched-writer rows from the deterministic txid/script generators. */
static void ckr_fill_rows(uint8_t txids[CKR_N][32],
                          uint8_t scripts[CKR_N][MAX_SCRIPT_SIZE],
                          struct coins_kv_add_row *rows)
{
    for (int i = 0; i < CKR_N; i++) {
        ckr_txid(txids[i], (uint64_t)i);
        size_t slen = ckr_script((uint64_t)i, scripts[i]);
        rows[i].txid        = txids[i];
        rows[i].vout        = (uint32_t)(i % 4);
        rows[i].value       = 50000 + i * 7;
        rows[i].height      = i % 3000000;
        rows[i].is_coinbase = (i % 5 == 0);
        rows[i].script      = slen ? scripts[i] : NULL;
        rows[i].script_len  = slen;
    }
}

/* Write every row through the raw batched writer in one transaction. */
static int ckr_populate_coins_kv(sqlite3 *db, struct coins_kv_add_row *rows)
{
    int failures = 0;
    sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
    bool wrote = coins_kv_add_many_sqlite(db, rows, CKR_N);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    CKR_CHECK("populated coins_kv", wrote);
    return failures;
}

/* Stage the lifetime probe: write one coin whose script buffer the caller
 * frees mid-transaction, then allocator-churn and COMMIT. */
static void ckr_stage_lifetime_write(sqlite3 *db, uint8_t lifetime_txid[32],
                                     uint8_t *lifetime_expect,
                                     size_t lifetime_expect_len,
                                     bool *lifetime_wrote,
                                     bool *lifetime_finished,
                                     int64_t *lifetime_delta)
{
    ckr_txid(lifetime_txid, CKR_N + 99);
    for (size_t i = 0; i < lifetime_expect_len; i++)
        lifetime_expect[i] = (uint8_t)(0x40 + i);
    uint8_t *lifetime_src = malloc(lifetime_expect_len);
    if (lifetime_src) memcpy(lifetime_src, lifetime_expect,
                             lifetime_expect_len);
    struct coins_kv_add_row lifetime_row = {
        .txid = lifetime_txid, .vout = 7, .value = 777, .height = 77,
        .is_coinbase = false, .script = lifetime_src,
        .script_len = lifetime_expect_len };
    coins_kv_delta_begin();
    sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
    *lifetime_wrote = lifetime_src &&
        coins_kv_add_many_sqlite(db, &lifetime_row, 1);
    free(lifetime_src);
    uint8_t *churn = malloc(lifetime_expect_len);
    if (churn) memset(churn, 0xEE, lifetime_expect_len);
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    *lifetime_delta = 0;
    *lifetime_finished = coins_kv_delta_finish(lifetime_delta);
    free(churn);
}

/* Cached write statements must not retain caller-owned script bytes
 * through COMMIT/finalize: free and allocator-churn the source, then
 * demand a byte-exact durable read. */
static int ckr_check_script_lifetime(sqlite3 *db)
{
    int failures = 0;
    uint8_t lifetime_txid[32];
    uint8_t lifetime_expect[25];
    bool lifetime_wrote = false;
    bool lifetime_finished = false;
    int64_t lifetime_delta = 0;
    ckr_stage_lifetime_write(db, lifetime_txid, lifetime_expect,
                             sizeof(lifetime_expect), &lifetime_wrote,
                             &lifetime_finished, &lifetime_delta);
    uint8_t lifetime_got[32] = {0};
    size_t lifetime_len = 0;
    CKR_CHECK("cached writer owns script through caller free + COMMIT",
              lifetime_wrote && lifetime_finished && lifetime_delta == 1 &&
              coins_kv_get_sqlite(db, lifetime_txid, 7, NULL, lifetime_got,
                                  sizeof(lifetime_got), &lifetime_len) &&
              lifetime_len == sizeof(lifetime_expect) &&
              memcmp(lifetime_got, lifetime_expect,
                     sizeof(lifetime_expect)) == 0);
    return failures;
}

/* One fresh-vs-cached prevout read pair over one key; true when equal. */
static bool ckr_prevout_reads_match(sqlite3 *db, sqlite3_stmt **c_prevout,
                                    uint8_t *txid, uint32_t vout)
{
    struct ckr_res f = {0}, c = {0};
    f.found = coins_kv_get_prevout_sqlite(db, txid, vout, &f.value,
                                          f.script, sizeof f.script, &f.slen,
                                          &f.height, &f.is_coinbase);
    c.found = coins_kv_get_prevout_sqlite_cached(db, c_prevout, txid,
                                                 vout, &c.value, c.script,
                                                 sizeof c.script, &c.slen,
                                                 &c.height, &c.is_coinbase);
    return ckr_res_eq(&f, &c);
}

/* Compare all three cached variants against fresh for one present key. */
static void ckr_compare_present_row(sqlite3 *db, sqlite3_stmt **c_prevout,
                                    sqlite3_stmt **c_get,
                                    sqlite3_stmt **c_exists, uint8_t *txid,
                                    uint32_t vout, int *prevout_mismatch,
                                    int *get_mismatch, int *exists_mismatch)
{
    if (!ckr_prevout_reads_match(db, c_prevout, txid, vout))
        (*prevout_mismatch)++;

    struct ckr_res fg = {0}, cg = {0};
    fg.found = coins_kv_get_sqlite(db, txid, vout, &fg.value, fg.script,
                                   sizeof fg.script, &fg.slen);
    cg.found = coins_kv_get_sqlite_cached(db, c_get, txid, vout,
                                          &cg.value, cg.script,
                                          sizeof cg.script, &cg.slen);
    /* get() does not fill height/is_coinbase; compare only value+script. */
    if (fg.found != cg.found ||
        (fg.found && (fg.value != cg.value || fg.slen != cg.slen ||
                      memcmp(fg.script, cg.script, fg.slen) != 0)))
        (*get_mismatch)++;

    bool fe = coins_kv_exists_sqlite(db, txid, vout);
    bool ce = coins_kv_exists_sqlite_cached(db, c_exists, txid, vout);
    if (fe != ce || !ce) (*exists_mismatch)++;
}

/* Every populated key: prevout/get/exists cached == fresh, byte-for-byte. */
static int ckr_check_present_reads(sqlite3 *db, uint8_t txids[CKR_N][32],
                                   sqlite3_stmt **c_prevout,
                                   sqlite3_stmt **c_get,
                                   sqlite3_stmt **c_exists)
{
    int failures = 0;
    int prevout_mismatch = 0, get_mismatch = 0, exists_mismatch = 0;
    for (int i = 0; i < CKR_N; i++)
        ckr_compare_present_row(db, c_prevout, c_get, c_exists, txids[i],
                                (uint32_t)(i % 4), &prevout_mismatch,
                                &get_mismatch, &exists_mismatch);
    CKR_CHECK("present: get_prevout cached == fresh (all rows)",
              prevout_mismatch == 0);
    CKR_CHECK("present: get cached == fresh (all rows)", get_mismatch == 0);
    CKR_CHECK("present: exists cached == fresh == true (all rows)",
              exists_mismatch == 0);
    return failures;
}

/* Never-inserted keys: cached == fresh == not-found. */
static int ckr_check_absent_reads(sqlite3 *db, sqlite3_stmt **c_prevout,
                                  sqlite3_stmt **c_exists)
{
    int failures = 0;
    int absent_mismatch = 0;
    for (int i = 0; i < CKR_N; i++) {
        uint8_t miss[32];
        ckr_txid(miss, (uint64_t)(CKR_N + i));  /* never inserted */
        struct ckr_res f = {0}, c = {0};
        f.found = coins_kv_get_prevout_sqlite(db, miss, 0, &f.value, f.script,
                                              sizeof f.script, &f.slen,
                                              &f.height, &f.is_coinbase);
        c.found = coins_kv_get_prevout_sqlite_cached(db, c_prevout, miss, 0,
                                                     &c.value, c.script,
                                                     sizeof c.script, &c.slen,
                                                     &c.height, &c.is_coinbase);
        bool fe = coins_kv_exists_sqlite(db, miss, 0);
        bool ce = coins_kv_exists_sqlite_cached(db, c_exists, miss, 0);
        if (f.found || c.found || fe || ce) absent_mismatch++;
    }
    CKR_CHECK("absent: cached == fresh == not-found (all misses)",
              absent_mismatch == 0);
    return failures;
}

/* (3) reuse determinism: the SAME cached stmt, many repeats. */
static int ckr_check_reuse_reads(sqlite3 *db, uint8_t txids[CKR_N][32],
                                 sqlite3_stmt **c_prevout)
{
    int failures = 0;
    int repeat_mismatch = 0;
    for (int rep = 0; rep < 500; rep++) {
        int i = (rep * 131) % CKR_N;
        uint32_t vout = (uint32_t)(i % 4);
        if (!ckr_prevout_reads_match(db, c_prevout, txids[i], vout))
            repeat_mismatch++;
    }
    CKR_CHECK("reuse: repeated cached reads stay byte-identical to fresh",
              repeat_mismatch == 0);
    return failures;
}

/* (5) after the finalize, a fresh cache pointer re-prepares and returns the
 * same bytes. */
static int ckr_check_reprepare_reads(sqlite3 *db, uint8_t txids[CKR_N][32],
                                     sqlite3_stmt **c_prevout)
{
    int failures = 0;
    int reprep_mismatch = 0;
    for (int i = 0; i < 200; i++) {
        int idx = (i * 271) % CKR_N;
        uint32_t vout = (uint32_t)(idx % 4);
        if (!ckr_prevout_reads_match(db, c_prevout, txids[idx], vout))
            reprep_mismatch++;
    }
    CKR_CHECK("re-prepare after finalize returns identical bytes",
              reprep_mismatch == 0);
    return failures;
}

/* Cached read, then spend + re-add on the same connection, then read back. */
static int ckr_check_interleaved_write(sqlite3 *db, uint8_t txids[CKR_N][32],
                                       struct coins_kv_add_row *rows,
                                       sqlite3_stmt **c_prevout)
{
    int failures = 0;
    bool write_after_read_ok = true;
    {
        struct ckr_res c = {0};
        (void)coins_kv_get_prevout_sqlite_cached(db, c_prevout, txids[0], 0,
                                                 &c.value, c.script,
                                                 sizeof c.script, &c.slen,
                                                 &c.height, &c.is_coinbase);
        /* spend then re-add a coin on the same connection while the cache is
         * live (reset, not finalized). */
        struct coins_kv_spend_row sp = { .txid = txids[1],
                                         .vout = (uint32_t)(1 % 4) };
        sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
        write_after_read_ok = coins_kv_spend_many_sqlite(db, &sp, 1) &&
                              coins_kv_add_many_sqlite(db, &rows[1], 1);
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
        /* the coin is back — cached read still resolves it correctly. */
        struct ckr_res f = {0}, c2 = {0};
        f.found = coins_kv_get_prevout_sqlite(db, txids[1], (uint32_t)(1 % 4),
                                              &f.value, f.script, sizeof f.script,
                                              &f.slen, &f.height, &f.is_coinbase);
        c2.found = coins_kv_get_prevout_sqlite_cached(db, c_prevout, txids[1],
                                                      (uint32_t)(1 % 4), &c2.value,
                                                      c2.script, sizeof c2.script,
                                                      &c2.slen, &c2.height,
                                                      &c2.is_coinbase);
        write_after_read_ok = write_after_read_ok && ckr_res_eq(&f, &c2);
    }
    CKR_CHECK("interleaved write after cached read is not wedged",
              write_after_read_ok);
    return failures;
}

int test_coins_kv_read_cache(void);
int test_coins_kv_read_cache(void)
{
    int failures = 0;
    printf("\n=== test_coins_kv_read_cache: cached vs fresh point-read "
           "byte-equivalence ===\n");

    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "coins_kv_read_cache", "db");
    test_rm_rf_recursive(dir);
    if ((mkdir("./test-tmp", 0700) != 0 && errno != EEXIST) ||
        (mkdir(dir, 0700) != 0 && errno != EEXIST)) {
        printf("  coins_kv_read_cache: mkdir datadir FAIL\n");
        return 1;
    }
    if (!progress_store_open(dir)) {
        printf("  coins_kv_read_cache: progress_store_open FAIL\n");
        return 1;
    }
    sqlite3 *db = progress_store_db();
    if (!db || !coins_kv_ensure_schema(db)) {
        printf("  coins_kv_read_cache: ensure_schema FAIL\n");
        progress_store_close();
        test_rm_rf_recursive(dir);
        return 1;
    }

    /* Populate coins_kv directly (durable SQLite) via the raw batched writer. */
    static uint8_t txids[CKR_N][32];
    static uint8_t scripts[CKR_N][MAX_SCRIPT_SIZE];
    struct coins_kv_add_row *rows =
        calloc(CKR_N, sizeof(*rows));
    if (!rows) { progress_store_close(); test_rm_rf_recursive(dir); return 1; }
    ckr_fill_rows(txids, scripts, rows);
    failures += ckr_populate_coins_kv(db, rows);

    failures += ckr_check_script_lifetime(db);

    /* Owned cached statements (single-owner, as coins_ram owns them). */
    sqlite3_stmt *c_prevout = NULL, *c_get = NULL, *c_exists = NULL;

    /* ── (1) present keys: cached == fresh, byte-for-byte ── */
    failures += ckr_check_present_reads(db, txids, &c_prevout, &c_get,
                                        &c_exists);

    /* ── (2) absent keys: cached == fresh == not-found ── */
    failures += ckr_check_absent_reads(db, &c_prevout, &c_exists);

    /* ── (3) reuse determinism: the SAME cached stmt, many repeats ── */
    failures += ckr_check_reuse_reads(db, txids, &c_prevout);

    /* ── (4) interleaved WRITE: a cached read then a same-connection write
     *        must not wedge (the post-read reset released the row lock) ── */
    failures += ckr_check_interleaved_write(db, txids, rows, &c_prevout);

    /* ── (5) finalize + re-prepare cycle: a fresh cache pointer re-prepares
     *        and returns the same bytes ── */
    sqlite3_finalize(c_prevout); c_prevout = NULL;
    sqlite3_finalize(c_get);     c_get = NULL;
    sqlite3_finalize(c_exists);  c_exists = NULL;
    failures += ckr_check_reprepare_reads(db, txids, &c_prevout);

    /* NULL-arg guards return false, never crash. */
    CKR_CHECK("cached get_prevout NULL cache returns false",
              !coins_kv_get_prevout_sqlite_cached(db, NULL, txids[0], 0, NULL,
                                                  NULL, 0, NULL, NULL, NULL));

    sqlite3_finalize(c_prevout);
    free(rows);
    progress_store_close();
    test_rm_rf_recursive(dir);

    printf("=== test_coins_kv_read_cache complete: %d failure(s) ===\n",
           failures);
    return failures;
}
