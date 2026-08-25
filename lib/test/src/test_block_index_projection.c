/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the Phase 4c block_index_projection
 * (lib/storage/src/block_index_projection.c).
 *
 * Coverage matrix (per docs/work/wt-phase4c-block-index-projection.md):
 *   1. open_close_clean       — open empty, close, reopen, offset=0
 *   2. single_header_consumed — emit 1 header event; catch_up; get() returns it
 *   3. get_by_height          — insert 3 entries at heights 100/200/300
 *   4. iterate_canonical      — iterate returns entries in (height, hash) order
 *   5. replay_idempotent      — second catch_up is a no-op
 *   6. reorg_replace          — INSERT then INSERT (same hash, different
 *                                nStatus); final state reflects second write
 *   7. commitment_canonical   — 3 entries in scrambled insertion order;
 *                                commitment matches a 4th projection that
 *                                inserted in different order
 *   8. resume_from_partial    — emit 1000 events; rewind last_consumed_offset
 *                                to mid-stream; reopen; catch_up consumes only
 *                                the suffix
 *
 * Scratch files live under ./test-tmp/bip_<pid>_<tag>/ in line with the
 * project's no-/tmp convention. */

#include "test/test_core.h"

#include "platform/time_compat.h"
#include "storage/block_index_projection.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BIP_CHECK(name, expr) do { \
    printf("block_index_projection: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Tmpdir helpers ────────────────────────────────────────────────── */

static int bip_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static void bip_ensure_root(void)
{
    bip_mkdir_p("./test-tmp");
}

static void bip_cleanup_dir(const char *dir)
{
    test_cleanup_tmpdir(dir);
}

static off_t bip_file_size(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? st.st_size : (off_t)-1;
}

/* Build a synthetic ev_block_header. `seed` differentiates every field
 * so collisions are obvious. */
static void make_header(struct ev_block_header *h, uint8_t *solution,
                        size_t solution_size, uint32_t seed,
                        int32_t height, uint32_t nStatus)
{
    memset(h, 0, sizeof(*h));
    /* hash: seed in first 4 bytes, repeat for visual debug */
    for (int i = 0; i < 32; i++)
        h->hash[i] = (uint8_t)((seed >> ((i % 4) * 8)) & 0xFF);
    for (int i = 0; i < 32; i++)
        h->hashPrev[i] = (uint8_t)((seed + 1) >> ((i % 4) * 8) & 0xFF);
    h->height        = height;
    h->nStatus       = nStatus;
    h->nFile         = (int32_t)(seed % 16);
    h->nDataPos      = seed * 4 + 100;
    h->nUndoPos      = seed * 4 + 200;
    h->nTime         = 1700000000u + seed;
    h->nBits         = 0x1d00ffffu;
    for (int i = 0; i < 32; i++) h->nNonce[i] = (uint8_t)(seed + i);
    for (int i = 0; i < 32; i++) h->hashMerkleRoot[i] = (uint8_t)(seed * 2 + i);
    for (int i = 0; i < 32; i++) h->hashFinalSaplingRoot[i] = 0;
    h->nVersion      = 4;
    h->nTx           = 1;
    h->nSolutionSize = (uint16_t)solution_size;
    for (size_t i = 0; i < solution_size; i++)
        solution[i] = (uint8_t)((seed + i) & 0xFF);
}

static bool emit_header(event_log_t *log, const struct ev_block_header *h,
                        const uint8_t *solution)
{
    size_t bufcap = ev_block_header_wire_size(h->nSolutionSize);
    uint8_t buf[256 + 1344];
    if (bufcap > sizeof(buf)) return false;
    size_t written = 0;
    if (!ev_block_header_serialize(h, solution, buf, bufcap, &written))
        return false;
    return event_log_append(log, EV_BLOCK_HEADER, buf, written) != UINT64_MAX;
}

/* ── Test 1: open_close_clean ──────────────────────────────────────── */

static int run_open_close_clean(int *failures)
{
    int start_failures = *failures;

    char dir[256]; test_make_tmpdir(dir, sizeof(dir), "bip", "open_close");
    char el_path[320]; snprintf(el_path, sizeof(el_path), "%s/log.bin", dir);
    char db_path[320]; snprintf(db_path, sizeof(db_path), "%s/p.db", dir);

    event_log_t *log = event_log_open(el_path);
    BIP_CHECK("open_close: event log opens", log != NULL);
    if (!log) goto done;

    block_index_projection_t *p = block_index_projection_open(db_path, log);
    BIP_CHECK("open_close: projection opens cleanly", p != NULL);
    if (!p) { event_log_close(log); goto done; }

    BIP_CHECK("open_close: count=0 on fresh",
              block_index_projection_count(p) == 0);

    uint64_t off = block_index_projection_catch_up(p);
    BIP_CHECK("open_close: catch_up returns 0 (empty log)", off == 0);

    block_index_projection_close(p);

    /* Reopen — cursor should still be 0. */
    p = block_index_projection_open(db_path, log);
    BIP_CHECK("open_close: reopen succeeds", p != NULL);
    if (p) {
        BIP_CHECK("open_close: reopen count=0",
                  block_index_projection_count(p) == 0);
        block_index_projection_close(p);
    }
    event_log_close(log);
    bip_cleanup_dir(dir);
done:
    return *failures - start_failures;
}

/* ── Test 2: single_header_consumed ────────────────────────────────── */

static int run_single_header_consumed(int *failures)
{
    int start_failures = *failures;

    char dir[256]; test_make_tmpdir(dir, sizeof(dir), "bip", "single");
    char el_path[320]; snprintf(el_path, sizeof(el_path), "%s/log.bin", dir);
    char db_path[320]; snprintf(db_path, sizeof(db_path), "%s/p.db", dir);

    event_log_t *log = event_log_open(el_path);
    if (!log) { *failures += 1; printf("single: event_log_open FAIL\n"); goto done; }

    struct ev_block_header h;
    uint8_t sol[16];
    make_header(&h, sol, sizeof(sol), 0xABCD, 42, 0x01);

    BIP_CHECK("single: emit OK", emit_header(log, &h, sol));

    block_index_projection_t *p = block_index_projection_open(db_path, log);
    if (!p) { event_log_close(log); *failures += 1; goto done; }

    uint64_t off = block_index_projection_catch_up(p);
    BIP_CHECK("single: catch_up returns non-zero", off > 0);
    BIP_CHECK("single: count=1", block_index_projection_count(p) == 1);
    char wal_path[336]; snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);
    BIP_CHECK("single: catch_up truncates committed WAL",
              bip_file_size(wal_path) == 0);

    struct disk_block_index got;
    disk_block_index_init(&got);
    BIP_CHECK("single: get(hash) succeeds",
              block_index_projection_get(p, h.hash, &got));
    BIP_CHECK("single: height matches", got.nHeight == 42);
    BIP_CHECK("single: nStatus matches", got.nStatus == 0x01);
    BIP_CHECK("single: nDataPos matches",
              got.nDataPos == h.nDataPos);

    block_index_projection_close(p);
    event_log_close(log);
    bip_cleanup_dir(dir);
done:
    return *failures - start_failures;
}

/* ── Test 3: get_by_height ─────────────────────────────────────────── */

static int run_get_by_height(int *failures)
{
    int start_failures = *failures;

    char dir[256]; test_make_tmpdir(dir, sizeof(dir), "bip", "by_height");
    char el_path[320]; snprintf(el_path, sizeof(el_path), "%s/log.bin", dir);
    char db_path[320]; snprintf(db_path, sizeof(db_path), "%s/p.db", dir);

    event_log_t *log = event_log_open(el_path);
    if (!log) { *failures += 1; goto done; }

    int heights[3] = {100, 200, 300};
    struct ev_block_header h[3];
    uint8_t sol[3][8];
    for (int i = 0; i < 3; i++) {
        make_header(&h[i], sol[i], sizeof(sol[i]),
                    (uint32_t)(0x1000 + i), heights[i], 0x40);
        emit_header(log, &h[i], sol[i]);
    }

    block_index_projection_t *p = block_index_projection_open(db_path, log);
    if (!p) { event_log_close(log); *failures += 1; goto done; }
    (void)block_index_projection_catch_up(p);
    BIP_CHECK("by_height: count=3", block_index_projection_count(p) == 3);

    struct disk_block_index got;
    for (int i = 0; i < 3; i++) {
        disk_block_index_init(&got);
        BIP_CHECK("by_height: get_by_height succeeds",
                  block_index_projection_get_by_height(p, heights[i], &got));
        BIP_CHECK("by_height: returned height matches request",
                  got.nHeight == heights[i]);
        BIP_CHECK("by_height: returned nDataPos matches insertion",
                  got.nDataPos == h[i].nDataPos);
    }

    /* Lookup of a height that wasn't inserted. */
    disk_block_index_init(&got);
    BIP_CHECK("by_height: missing height returns false",
              !block_index_projection_get_by_height(p, 999, &got));

    block_index_projection_close(p);
    event_log_close(log);
    bip_cleanup_dir(dir);
done:
    return *failures - start_failures;
}

/* ── Test 4: iterate_canonical ─────────────────────────────────────── */

struct iter_ctx {
    int n;
    int heights[8];
    uint8_t hashes[8][32];
};

static bool iter_cb(const uint8_t hash[32],
                    const struct disk_block_index *idx, void *user)
{
    struct iter_ctx *c = (struct iter_ctx *)user;
    if (c->n >= 8) return false;
    c->heights[c->n] = idx->nHeight;
    memcpy(c->hashes[c->n], hash, 32);
    c->n++;
    return true;
}

static int run_iterate_canonical(int *failures)
{
    int start_failures = *failures;

    char dir[256]; test_make_tmpdir(dir, sizeof(dir), "bip", "iterate");
    char el_path[320]; snprintf(el_path, sizeof(el_path), "%s/log.bin", dir);
    char db_path[320]; snprintf(db_path, sizeof(db_path), "%s/p.db", dir);

    event_log_t *log = event_log_open(el_path);
    if (!log) { *failures += 1; goto done; }

    /* Insert in scrambled order: heights 50, 10, 30. */
    int order[3] = {50, 10, 30};
    struct ev_block_header h[3];
    uint8_t sol[3][8];
    for (int i = 0; i < 3; i++) {
        make_header(&h[i], sol[i], sizeof(sol[i]),
                    (uint32_t)(0x2000 + order[i]), order[i], 0);
        emit_header(log, &h[i], sol[i]);
    }

    block_index_projection_t *p = block_index_projection_open(db_path, log);
    if (!p) { event_log_close(log); *failures += 1; goto done; }
    (void)block_index_projection_catch_up(p);

    struct iter_ctx c = {0};
    BIP_CHECK("iterate: returns 0",
              block_index_projection_iterate(p, iter_cb, &c) == 0);
    BIP_CHECK("iterate: visited all 3", c.n == 3);
    BIP_CHECK("iterate: heights ascending h[0]<h[1]",
              c.n >= 2 && c.heights[0] < c.heights[1]);
    BIP_CHECK("iterate: heights ascending h[1]<h[2]",
              c.n >= 3 && c.heights[1] < c.heights[2]);
    BIP_CHECK("iterate: first height is 10",
              c.n >= 1 && c.heights[0] == 10);
    BIP_CHECK("iterate: last height is 50",
              c.n >= 3 && c.heights[2] == 50);

    struct iter_ctx storage = {0};
    BIP_CHECK("storage-order iterate: returns 0",
              block_index_projection_iterate_storage_order(
                  p, iter_cb, &storage) == 0);
    BIP_CHECK("storage-order iterate: visited all 3", storage.n == 3);

    block_index_projection_close(p);
    event_log_close(log);
    bip_cleanup_dir(dir);
done:
    return *failures - start_failures;
}

/* ── Test 5: replay_idempotent ─────────────────────────────────────── */

static int run_replay_idempotent(int *failures)
{
    int start_failures = *failures;

    char dir[256]; test_make_tmpdir(dir, sizeof(dir), "bip", "replay");
    char el_path[320]; snprintf(el_path, sizeof(el_path), "%s/log.bin", dir);
    char db_path[320]; snprintf(db_path, sizeof(db_path), "%s/p.db", dir);

    event_log_t *log = event_log_open(el_path);
    if (!log) { *failures += 1; goto done; }

    for (int i = 0; i < 10; i++) {
        struct ev_block_header h;
        uint8_t sol[8];
        make_header(&h, sol, sizeof(sol),
                    (uint32_t)(0x3000 + i), i, 0);
        emit_header(log, &h, sol);
    }

    block_index_projection_t *p = block_index_projection_open(db_path, log);
    if (!p) { event_log_close(log); *failures += 1; goto done; }

    uint64_t off1 = block_index_projection_catch_up(p);
    uint64_t cnt1 = block_index_projection_count(p);
    BIP_CHECK("replay: first catch_up has entries", cnt1 == 10);

    /* Second catch_up — log unchanged, projection should not change. */
    uint64_t off2 = block_index_projection_catch_up(p);
    uint64_t cnt2 = block_index_projection_count(p);
    BIP_CHECK("replay: offset stable across no-op catch_up", off1 == off2);
    BIP_CHECK("replay: count stable across no-op catch_up", cnt1 == cnt2);

    block_index_projection_close(p);
    event_log_close(log);
    bip_cleanup_dir(dir);
done:
    return *failures - start_failures;
}

/* ── Test 6: reorg_replace ─────────────────────────────────────────── */

static int run_reorg_replace(int *failures)
{
    int start_failures = *failures;

    char dir[256]; test_make_tmpdir(dir, sizeof(dir), "bip", "reorg");
    char el_path[320]; snprintf(el_path, sizeof(el_path), "%s/log.bin", dir);
    char db_path[320]; snprintf(db_path, sizeof(db_path), "%s/p.db", dir);

    event_log_t *log = event_log_open(el_path);
    if (!log) { *failures += 1; goto done; }

    /* Emit same hash twice, different nStatus. */
    struct ev_block_header h1, h2;
    uint8_t sol[8] = {0};
    make_header(&h1, sol, sizeof(sol), 0x4000, 500, 0x04);
    make_header(&h2, sol, sizeof(sol), 0x4000, 500, 0x80);  /* same seed → same hash */
    BIP_CHECK("reorg: hashes are equal",
              memcmp(h1.hash, h2.hash, 32) == 0);
    emit_header(log, &h1, sol);
    emit_header(log, &h2, sol);

    block_index_projection_t *p = block_index_projection_open(db_path, log);
    if (!p) { event_log_close(log); *failures += 1; goto done; }
    (void)block_index_projection_catch_up(p);

    BIP_CHECK("reorg: count=1 after replace",
              block_index_projection_count(p) == 1);

    struct disk_block_index got;
    disk_block_index_init(&got);
    BIP_CHECK("reorg: get succeeds",
              block_index_projection_get(p, h1.hash, &got));
    BIP_CHECK("reorg: nStatus is the SECOND write",
              got.nStatus == 0x80);

    block_index_projection_close(p);
    event_log_close(log);
    bip_cleanup_dir(dir);
done:
    return *failures - start_failures;
}

/* ── Test 7: commitment_canonical ──────────────────────────────────── */

static int run_commitment_canonical(int *failures)
{
    int start_failures = *failures;

    char dir[256]; test_make_tmpdir(dir, sizeof(dir), "bip", "commitment");
    char el_path1[320]; snprintf(el_path1, sizeof(el_path1), "%s/log1.bin", dir);
    char el_path2[320]; snprintf(el_path2, sizeof(el_path2), "%s/log2.bin", dir);
    char db_path1[320]; snprintf(db_path1, sizeof(db_path1), "%s/p1.db", dir);
    char db_path2[320]; snprintf(db_path2, sizeof(db_path2), "%s/p2.db", dir);

    /* Build the same 3 entries; insert in different orders into two
     * separate projections; commitment must be identical. */
    int orders1[3] = {7, 3, 5};   /* heights, scrambled */
    int orders2[3] = {5, 7, 3};   /* same heights, different order */

    event_log_t *log1 = event_log_open(el_path1);
    event_log_t *log2 = event_log_open(el_path2);
    if (!log1 || !log2) { *failures += 1; goto done; }

    for (int i = 0; i < 3; i++) {
        struct ev_block_header h;
        uint8_t sol[8] = {0};
        make_header(&h, sol, sizeof(sol),
                    (uint32_t)(0x5000 + orders1[i]),
                    orders1[i], 0x40);
        emit_header(log1, &h, sol);
    }
    for (int i = 0; i < 3; i++) {
        struct ev_block_header h;
        uint8_t sol[8] = {0};
        make_header(&h, sol, sizeof(sol),
                    (uint32_t)(0x5000 + orders2[i]),
                    orders2[i], 0x40);
        emit_header(log2, &h, sol);
    }

    block_index_projection_t *p1 = block_index_projection_open(db_path1, log1);
    block_index_projection_t *p2 = block_index_projection_open(db_path2, log2);
    if (!p1 || !p2) {
        if (p1) block_index_projection_close(p1);
        if (p2) block_index_projection_close(p2);
        event_log_close(log1); event_log_close(log2);
        *failures += 1;
        goto done;
    }
    (void)block_index_projection_catch_up(p1);
    (void)block_index_projection_catch_up(p2);

    uint8_t c1[32], c2[32];
    BIP_CHECK("commitment: p1 commitment succeeds",
              block_index_projection_commitment(p1, c1) == 0);
    BIP_CHECK("commitment: p2 commitment succeeds",
              block_index_projection_commitment(p2, c2) == 0);
    BIP_CHECK("commitment: identical across insertion order",
              memcmp(c1, c2, 32) == 0);

    block_index_projection_close(p1);
    block_index_projection_close(p2);
    event_log_close(log1);
    event_log_close(log2);
    bip_cleanup_dir(dir);
done:
    return *failures - start_failures;
}

/* ── Test 8: resume_from_partial ──────────────────────────────────── */

static int run_resume_from_partial(int *failures)
{
    int start_failures = *failures;

    char dir[256]; test_make_tmpdir(dir, sizeof(dir), "bip", "resume");
    char el_path[320]; snprintf(el_path, sizeof(el_path), "%s/log.bin", dir);
    char db_path[320]; snprintf(db_path, sizeof(db_path), "%s/p.db", dir);

    event_log_t *log = event_log_open(el_path);
    if (!log) { *failures += 1; goto done; }

    /* Emit 200 events (faster than 1000 in test; same property). Track
     * the offset of event index 100 so we can rewind to that point. */
    uint64_t midpoint_offset = 0;
    for (int i = 0; i < 200; i++) {
        struct ev_block_header h;
        uint8_t sol[8] = {0};
        make_header(&h, sol, sizeof(sol),
                    (uint32_t)(0x6000 + i), 1000 + i, 0x20);
        /* event_log_append returns the offset of THIS event. The next
         * event starts at offset + 16 + payload_len + 16. We want the
         * offset AFTER event 99 (which is the start of event 100). */
        size_t bufcap = ev_block_header_wire_size(h.nSolutionSize);
        uint8_t buf[256 + 1344];
        size_t written = 0;
        ev_block_header_serialize(&h, sol, buf, bufcap, &written);
        uint64_t off = event_log_append(log, EV_BLOCK_HEADER, buf, written);
        if (i == 100) midpoint_offset = off;
    }
    BIP_CHECK("resume: midpoint offset captured", midpoint_offset > 0);

    /* First projection: consume everything. */
    block_index_projection_t *p = block_index_projection_open(db_path, log);
    if (!p) { event_log_close(log); *failures += 1; goto done; }
    (void)block_index_projection_catch_up(p);
    BIP_CHECK("resume: first catch_up has 200 entries",
              block_index_projection_count(p) == 200);
    block_index_projection_close(p);

    /* Manually rewind last_consumed_offset to midpoint by editing
     * projection_meta. We open a raw sqlite3 handle for this. */
    sqlite3 *raw = NULL;
    int rc = sqlite3_open_v2(db_path, &raw,
                             SQLITE_OPEN_READWRITE, NULL);
    if (rc != SQLITE_OK) {
        printf("resume: sqlite open for rewind FAIL: %s\n",
               raw ? sqlite3_errmsg(raw) : sqlite3_errstr(rc));
        if (raw) sqlite3_close(raw);
        event_log_close(log);
        *failures += 1;
        goto done;
    }
    /* Also clear the block_index so we can prove catch_up only re-
     * consumes the suffix (entries 100..199). */
    sqlite3_exec(raw, "DELETE FROM block_index", NULL, NULL, NULL);
    sqlite3_stmt *stmt = NULL;
    char val[32];
    snprintf(val, sizeof(val), "%" PRIu64, midpoint_offset);
    sqlite3_prepare_v2(raw,
        "INSERT OR REPLACE INTO projection_meta(k, v) "
        "VALUES('last_consumed_offset', ?)", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, val, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(raw);

    /* Reopen, catch_up — should consume only entries 100..199 (100 of them). */
    p = block_index_projection_open(db_path, log);
    if (!p) { event_log_close(log); *failures += 1; goto done; }
    BIP_CHECK("resume: reopen entry_count starts at 0 (we cleared)",
              block_index_projection_count(p) == 0);
    uint64_t off = block_index_projection_catch_up(p);
    BIP_CHECK("resume: catch_up after rewind returns valid offset",
              off != (uint64_t)-1 && off > midpoint_offset);
    BIP_CHECK("resume: only suffix entries consumed (100 entries)",
              block_index_projection_count(p) == 100);

    block_index_projection_close(p);
    event_log_close(log);
    bip_cleanup_dir(dir);
done:
    return *failures - start_failures;
}

/* ── Test 9: collision_accounting_cached_stmt ──────────────────────── */

/* Regression test for the exists-check statement being hoisted out of the
 * per-event hot path (block_index_projection_catch_up() now prepares the
 * "SELECT 1 FROM block_index WHERE hash = ?" exists-check once, alongside
 * ins_stmt, instead of once per EV_BLOCK_HEADER event). This exercises the
 * cached statement across multiple catch_up() calls (each call re-prepares
 * and finalizes its own cached statement) and confirms the
 * replace_collisions_total / was_present accounting is unchanged: a fresh
 * hash must not be counted as a collision, and a re-inserted (same) hash
 * must be. */
static uint64_t read_meta_u64(const char *db_path, const char *key)
{
    sqlite3 *raw = NULL;
    if (sqlite3_open_v2(db_path, &raw, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (raw) sqlite3_close(raw);
        return (uint64_t)-1;
    }
    sqlite3_stmt *stmt = NULL;
    uint64_t result = (uint64_t)-1;
    if (sqlite3_prepare_v2(raw,
            "SELECT v FROM projection_meta WHERE k = ?", -1, &stmt, NULL)
            == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *txt = sqlite3_column_text(stmt, 0);
            if (txt) result = (uint64_t)strtoull((const char *)txt, NULL, 10);
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(raw);
    return result;
}

static int run_collision_accounting_cached_stmt(int *failures)
{
    int start_failures = *failures;

    char dir[256]; test_make_tmpdir(dir, sizeof(dir), "bip", "collision");
    char el_path[320]; snprintf(el_path, sizeof(el_path), "%s/log.bin", dir);
    char db_path[320]; snprintf(db_path, sizeof(db_path), "%s/p.db", dir);

    event_log_t *log = event_log_open(el_path);
    if (!log) { *failures += 1; goto done; }

    block_index_projection_t *p = block_index_projection_open(db_path, log);
    if (!p) { event_log_close(log); *failures += 1; goto done; }

    /* Round 1: one brand-new hash. Must NOT be counted as a collision. */
    struct ev_block_header hA1;
    uint8_t solA[8] = {0};
    make_header(&hA1, solA, sizeof(solA), 0x7000, 700, 0x01);
    BIP_CHECK("collision: emit A(v1) OK", emit_header(log, &hA1, solA));
    (void)block_index_projection_catch_up(p);

    BIP_CHECK("collision: count=1 after fresh insert",
              block_index_projection_count(p) == 1);
    BIP_CHECK("collision: collisions=0 after fresh insert",
              read_meta_u64(db_path, "replace_collisions_total") == 0);
    BIP_CHECK("collision: events_consumed_total=1 after fresh insert",
              read_meta_u64(db_path, "events_consumed_total") == 1);

    /* Round 2: same hash again (same seed => same hash), different
     * nStatus — a genuine INSERT OR REPLACE collision. Must be counted. */
    struct ev_block_header hA2;
    uint8_t solA2[8] = {0};
    make_header(&hA2, solA2, sizeof(solA2), 0x7000, 700, 0x80);
    BIP_CHECK("collision: hashes match across rounds",
              memcmp(hA1.hash, hA2.hash, 32) == 0);
    BIP_CHECK("collision: emit A(v2) OK", emit_header(log, &hA2, solA2));
    (void)block_index_projection_catch_up(p);

    BIP_CHECK("collision: count stays 1 (same hash replaced)",
              block_index_projection_count(p) == 1);
    BIP_CHECK("collision: collisions=1 after re-inserting same hash",
              read_meta_u64(db_path, "replace_collisions_total") == 1);

    struct disk_block_index got;
    disk_block_index_init(&got);
    BIP_CHECK("collision: get reflects second write",
              block_index_projection_get(p, hA1.hash, &got) &&
              got.nStatus == 0x80);

    /* Round 3: a fresh, distinct hash. Must NOT bump the collision
     * counter (proves was_present isn't stuck true/false from a stale
     * cached statement). */
    struct ev_block_header hB;
    uint8_t solB[8] = {0};
    make_header(&hB, solB, sizeof(solB), 0x7001, 701, 0x01);
    BIP_CHECK("collision: emit B OK", emit_header(log, &hB, solB));
    (void)block_index_projection_catch_up(p);

    BIP_CHECK("collision: count=2 after second fresh insert",
              block_index_projection_count(p) == 2);
    BIP_CHECK("collision: collisions stays 1 after fresh insert of B",
              read_meta_u64(db_path, "replace_collisions_total") == 1);
    BIP_CHECK("collision: events_consumed_total=3 across 3 catch_up calls",
              read_meta_u64(db_path, "events_consumed_total") == 3);

    block_index_projection_close(p);
    event_log_close(log);
    bip_cleanup_dir(dir);
done:
    return *failures - start_failures;
}

/* ── EV_BLOCK_HEADER round-trip (covers Task 1) ────────────────────── */

static int run_payload_roundtrip(int *failures)
{
    int start_failures = *failures;

    struct ev_block_header h;
    uint8_t sol[64];
    make_header(&h, sol, sizeof(sol), 0xDEAD, 12345, 0x05);

    size_t cap = ev_block_header_wire_size(h.nSolutionSize);
    uint8_t buf[256 + 1344];
    size_t written = 0;
    BIP_CHECK("payload: serialize OK",
              ev_block_header_serialize(&h, sol, buf, cap, &written));
    BIP_CHECK("payload: written == wire_size", written == cap);

    struct ev_block_header h2;
    const uint8_t *sol2 = NULL;
    BIP_CHECK("payload: parse OK",
              ev_block_header_parse(buf, written, &h2, &sol2));
    BIP_CHECK("payload: hash roundtrips",
              memcmp(h.hash, h2.hash, 32) == 0);
    BIP_CHECK("payload: height roundtrips", h.height == h2.height);
    BIP_CHECK("payload: nStatus roundtrips", h.nStatus == h2.nStatus);
    BIP_CHECK("payload: nFile roundtrips", h.nFile == h2.nFile);
    BIP_CHECK("payload: nDataPos roundtrips", h.nDataPos == h2.nDataPos);
    BIP_CHECK("payload: nUndoPos roundtrips", h.nUndoPos == h2.nUndoPos);
    BIP_CHECK("payload: nTime roundtrips", h.nTime == h2.nTime);
    BIP_CHECK("payload: nBits roundtrips", h.nBits == h2.nBits);
    BIP_CHECK("payload: nVersion roundtrips", h.nVersion == h2.nVersion);
    BIP_CHECK("payload: nSolutionSize roundtrips",
              h.nSolutionSize == h2.nSolutionSize);
    BIP_CHECK("payload: solution roundtrips",
              sol2 != NULL && memcmp(sol, sol2, h.nSolutionSize) == 0);

    return *failures - start_failures;
}

int test_block_index_projection(void)
{
    printf("\n=== block_index_projection tests ===\n");
    int failures = 0;
    bip_ensure_root();

    run_payload_roundtrip(&failures);
    run_open_close_clean(&failures);
    run_single_header_consumed(&failures);
    run_get_by_height(&failures);
    run_iterate_canonical(&failures);
    run_replay_idempotent(&failures);
    run_reorg_replace(&failures);
    run_commitment_canonical(&failures);
    run_resume_from_partial(&failures);
    run_collision_accounting_cached_stmt(&failures);

    printf("block_index_projection: %d failures\n", failures);
    return failures;
}
