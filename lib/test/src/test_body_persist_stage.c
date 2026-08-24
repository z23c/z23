/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Unit tests for Wave S S-5 body_persist stage. */

#include "test/test_core.h"
#include "test/block_fixtures.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "jobs/body_persist_stage.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/reducer_stage_profile.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BP_CHECK(name, expr) do { \
    printf("body_persist: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

struct synth_chain_bp {
    struct block_index *blocks;
    struct uint256     *hashes;
    struct block       *bodies;
    int                 n;
    int                 fail_read_height;
    int                 header_mismatch_height;
    int                 merkle_mismatch_height;
};

static int mkdir_p_bp(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static bool make_body(struct block *b, int h)
{
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700000000u + (uint32_t)h);
    b->header.nBits = 0x1f07ffff;
    b->num_vtx = 1;
    b->vtx = zcl_calloc(1, sizeof(struct transaction), "bp_tx");
    if (!b->vtx) return false;
    transaction_init(&b->vtx[0]);
    b->vtx[0].hash.data[0] = (uint8_t)h;
    b->vtx[0].hash.data[1] = 0x5b;
    b->vtx[0].hash.data[2] = 0x50;
    b->header.hashMerkleRoot = compute_merkle_root(&b->vtx[0].hash, 1);
    return true;
}

static bool synth_chain_bp_build(struct synth_chain_bp *sc, int n)
{
    memset(sc, 0, sizeof(*sc));
    sc->fail_read_height = -1;
    sc->header_mismatch_height = -1;
    sc->merkle_mismatch_height = -1;
    sc->blocks = zcl_calloc((size_t)n, sizeof(struct block_index),
                            "bp_blocks");
    sc->hashes = zcl_calloc((size_t)n, sizeof(struct uint256),
                            "bp_hashes");
    sc->bodies = zcl_calloc((size_t)n, sizeof(struct block),
                            "bp_bodies");
    if (!sc->blocks || !sc->hashes || !sc->bodies) return false;
    for (int i = 0; i < n; i++) {
        if (!make_body(&sc->bodies[i], i)) return false;
        block_header_get_hash(&sc->bodies[i].header, &sc->hashes[i]);
        block_index_init(&sc->blocks[i]);
        sc->blocks[i].phashBlock = &sc->hashes[i];
        sc->blocks[i].hashMerkleRoot = sc->bodies[i].header.hashMerkleRoot;
        sc->blocks[i].nHeight = i;
        sc->blocks[i].nVersion = sc->bodies[i].header.nVersion;
        sc->blocks[i].nTime = sc->bodies[i].header.nTime;
        sc->blocks[i].nBits = sc->bodies[i].header.nBits;
        sc->blocks[i].nStatus = BLOCK_HAVE_DATA;
        if (i > 0) sc->blocks[i].pprev = &sc->blocks[i - 1];
    }
    sc->n = n;
    return true;
}

static void synth_chain_bp_free(struct synth_chain_bp *sc)
{
    if (sc->bodies) {
        for (int i = 0; i < sc->n; i++)
            block_free(&sc->bodies[i]);
    }
    free(sc->blocks);
    free(sc->hashes);
    free(sc->bodies);
    memset(sc, 0, sizeof(*sc));
}

static bool fake_reader(struct block *out, const struct block_index *bi,
                        const char *datadir, void *user)
{
    (void)datadir;
    struct synth_chain_bp *sc = user;
    if (!out || !bi || !sc || bi->nHeight < 0 || bi->nHeight >= sc->n)
        return false;
    if (bi->nHeight == sc->fail_read_height)
        return false;
    if (!test_block_copy(out, &sc->bodies[bi->nHeight], "bp_tx_copy"))
        return false;
    if (bi->nHeight == sc->header_mismatch_height)
        out->header.nTime++;
    if (bi->nHeight == sc->merkle_mismatch_height)
        out->vtx[0].hash.data[31] ^= 0x5a;
    return true;
}

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool seed_body_fetch(sqlite3 *db, int n, int upstream_fail_height,
                            int missing_row_height)
{
    if (!exec_sql(db,
        "CREATE TABLE IF NOT EXISTS body_fetch_log ("
        "  height      INTEGER PRIMARY KEY,"
        "  hash        BLOB    NOT NULL,"
        "  source      TEXT    NOT NULL,"
        "  bytes       INTEGER NOT NULL DEFAULT 0,"
        "  fetched_at  INTEGER NOT NULL,"
        "  ok          INTEGER NOT NULL,"
        "  fail_reason TEXT"
        ")"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO body_fetch_log "
        "(height, hash, source, bytes, fetched_at, ok, fail_reason) "
        "VALUES (?, zeroblob(32), ?, 0, 1, ?, NULL)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h < n; h++) {
        if (h == missing_row_height) continue;
        int ok = (h == upstream_fail_height) ? 0 : 1;
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_text(st, 2, ok ? "disk" : "skipped_invalid",
                          -1, SQLITE_STATIC);
        sqlite3_bind_int(st, 3, ok);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return false;
        }
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
    }
    sqlite3_finalize(st);

    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
        "VALUES('body_fetch', ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, n);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static int log_row_count(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM body_persist_log", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int n = -1;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static bool log_row_at(sqlite3 *db, int height,
                       int *out_ok, char *out_source, size_t source_size)
{
    *out_ok = -1;
    if (out_source && source_size) out_source[0] = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, source FROM body_persist_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *out_ok = sqlite3_column_int(st, 0);
        const unsigned char *txt = sqlite3_column_text(st, 1);
        if (txt && out_source && source_size)
            snprintf(out_source, source_size, "%s", (const char *)txt);
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

static int64_t profile_cumulative_field(const char *name)
{
    struct json_value root;
    json_init(&root);
    if (!reducer_stage_profile_dump_state_json(&root, NULL)) {
        json_free(&root);
        return -1;
    }
    const struct json_value *body = json_get(&root, "body_persist");
    const struct json_value *cumulative = body
        ? json_get(body, "cumulative") : NULL;
    const struct json_value *field = cumulative
        ? json_get(cumulative, name) : NULL;
    int64_t value = field ? json_get_int(field) : -1;
    json_free(&root);
    return value;
}

static int bp_setup(const char *tag, int n, int upstream_fail_height,
                    int missing_row_height, char *dir_out,
                    size_t dir_out_size, struct main_state *ms,
                    struct synth_chain_bp *sc)
{
    test_fmt_tmpdir(dir_out, dir_out_size, "body_persist", tag);
    mkdir_p_bp("./test-tmp");
    mkdir_p_bp(dir_out);
    if (!progress_store_open(dir_out)) return 1;

    memset(ms, 0, sizeof(*ms));
    active_chain_init(&ms->chain_active);
    if (!synth_chain_bp_build(sc, n)) return 2;
    active_chain_move_window_tip(&ms->chain_active, &sc->blocks[n - 1]);

    if (!seed_body_fetch(progress_store_db(), n, upstream_fail_height,
                         missing_row_height))
        return 3;
    if (!body_persist_stage_init(ms)) return 4;
    body_persist_stage_set_reader(fake_reader, sc);
    return 0;
}

static void bp_teardown(const char *dir, struct main_state *ms,
                        struct synth_chain_bp *sc)
{
    body_persist_stage_shutdown();
    active_chain_free(&ms->chain_active);
    synth_chain_bp_free(sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

int test_body_persist_stage(void);
int test_body_persist_stage(void)
{
    printf("\n=== body_persist_stage tests ===\n");
    int failures = 0;

    blocker_module_init();

    {
        char dir[256]; struct main_state ms; struct synth_chain_bp sc;
        BP_CHECK("happy: setup",
                 bp_setup("happy", 5, -1, -1, dir, sizeof(dir), &ms, &sc) == 0);
        reducer_stage_profile_reset();
        BP_CHECK("happy: drains 5", body_persist_stage_drain(100) == 5);
        BP_CHECK("happy: cursor at 5", body_persist_stage_cursor() == 5);
        BP_CHECK("happy: verified_total == 5",
                 body_persist_stage_verified_total() == 5);
        BP_CHECK("happy: log rows == 5",
                 log_row_count(progress_store_db()) == 5);
        BP_CHECK("happy: one reusable merkle scratch allocation",
                 profile_cumulative_field(
                     "merkle_temporary_allocations") == 1);
        BP_CHECK("happy: merkle scratch allocates one hash",
                 profile_cumulative_field("merkle_temporary_bytes") == 32);
        for (int h = 0; h < 5; h++) {
            int ok = -1; char src[32];
            log_row_at(progress_store_db(), h, &ok, src, sizeof(src));
            BP_CHECK("happy: row ok=1", ok == 1);
            BP_CHECK("happy: row source verified",
                     strcmp(src, "verified") == 0);
        }
        BP_CHECK("happy: next step IDLE",
                 body_persist_stage_step_once() == JOB_IDLE);
        bp_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_bp sc;
        BP_CHECK("merkle_oom: setup",
                 bp_setup("merkle_oom", 2, -1, -1, dir, sizeof(dir), &ms,
                          &sc) == 0);
        zcl_alloc_fault_fail_next("body_persist_merkle_txids");
        job_result_t result = body_persist_stage_step_once();
        zcl_alloc_fault_clear();
        BP_CHECK("merkle_oom: allocation failure is fatal",
                 result == JOB_FATAL);
        BP_CHECK("merkle_oom: cursor stays at zero",
                 body_persist_stage_cursor() == 0);
        BP_CHECK("merkle_oom: HAVE_DATA is retained",
                 (sc.blocks[0].nStatus & BLOCK_HAVE_DATA) != 0);
        BP_CHECK("merkle_oom: no verdict row is written",
                 log_row_count(progress_store_db()) == 0);
        bp_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_bp sc;
        BP_CHECK("upstream_failed: setup",
                 bp_setup("upstream", 5, 3, -1, dir, sizeof(dir), &ms, &sc) == 0);
        BP_CHECK("upstream_failed: drains 5",
                 body_persist_stage_drain(100) == 5);
        BP_CHECK("upstream_failed: counter == 1",
                 body_persist_stage_upstream_failed_total() == 1);
        int ok = -1; char src[32];
        log_row_at(progress_store_db(), 3, &ok, src, sizeof(src));
        BP_CHECK("upstream_failed: h=3 ok=0", ok == 0);
        BP_CHECK("upstream_failed: h=3 source",
                 strcmp(src, "upstream_failed") == 0);
        bp_teardown(dir, &ms, &sc);
    }

    /* READ-class failures must requeue for re-fetch (clear HAVE_DATA, hold
     * the cursor, no permanent ok=0 row) and heal once the body is back. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_bp sc;
        BP_CHECK("header_mismatch: setup",
                 bp_setup("header", 3, -1, -1, dir, sizeof(dir), &ms, &sc) == 0);
        sc.header_mismatch_height = 2;
        BP_CHECK("header_mismatch: drains 2",
                 body_persist_stage_drain(100) == 2);
        BP_CHECK("header_mismatch: counter == 1",
                 body_persist_stage_header_mismatch_total() == 1);
        BP_CHECK("header_mismatch: cursor holds at 2",
                 body_persist_stage_cursor() == 2);
        BP_CHECK("header_mismatch: HAVE_DATA cleared",
                 (sc.blocks[2].nStatus & BLOCK_HAVE_DATA) == 0);
        int ok = -1; char src[32];
        BP_CHECK("header_mismatch: no permanent row",
                 !log_row_at(progress_store_db(), 2, &ok, src, sizeof(src)));
        /* Idle while cleared: no re-read, counter does not climb per step. */
        BP_CHECK("header_mismatch: idles while cleared",
                 body_persist_stage_step_once() == JOB_IDLE);
        BP_CHECK("header_mismatch: counter stays 1",
                 body_persist_stage_header_mismatch_total() == 1);
        /* Re-fetch lands a good body + HAVE_DATA: the stage heals. */
        sc.header_mismatch_height = -1;
        sc.blocks[2].nStatus |= BLOCK_HAVE_DATA;
        BP_CHECK("header_mismatch: heals after re-fetch",
                 body_persist_stage_drain(100) == 1);
        BP_CHECK("header_mismatch: h=2 verified",
                 log_row_at(progress_store_db(), 2, &ok, src, sizeof(src)) &&
                 ok == 1 && strcmp(src, "verified") == 0);
        bp_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_bp sc;
        BP_CHECK("merkle_mismatch: setup",
                 bp_setup("merkle", 3, -1, -1, dir, sizeof(dir), &ms, &sc) == 0);
        sc.merkle_mismatch_height = 1;
        BP_CHECK("merkle_mismatch: drains 1",
                 body_persist_stage_drain(100) == 1);
        BP_CHECK("merkle_mismatch: counter == 1",
                 body_persist_stage_merkle_mismatch_total() == 1);
        BP_CHECK("merkle_mismatch: cursor holds at 1",
                 body_persist_stage_cursor() == 1);
        BP_CHECK("merkle_mismatch: HAVE_DATA cleared",
                 (sc.blocks[1].nStatus & BLOCK_HAVE_DATA) == 0);
        int ok = -1; char src[32];
        BP_CHECK("merkle_mismatch: no permanent row",
                 !log_row_at(progress_store_db(), 1, &ok, src, sizeof(src)));
        sc.merkle_mismatch_height = -1;
        sc.blocks[1].nStatus |= BLOCK_HAVE_DATA;
        BP_CHECK("merkle_mismatch: heals after re-fetch",
                 body_persist_stage_drain(100) == 2);
        BP_CHECK("merkle_mismatch: h=1 verified",
                 log_row_at(progress_store_db(), 1, &ok, src, sizeof(src)) &&
                 ok == 1 && strcmp(src, "verified") == 0);
        bp_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_bp sc;
        BP_CHECK("read_failed: setup",
                 bp_setup("read", 3, -1, -1, dir, sizeof(dir), &ms, &sc) == 0);
        sc.fail_read_height = 1;
        BP_CHECK("read_failed: drains 1",
                 body_persist_stage_drain(100) == 1);
        BP_CHECK("read_failed: counter == 1",
                 body_persist_stage_read_failed_total() == 1);
        BP_CHECK("read_failed: cursor holds at 1",
                 body_persist_stage_cursor() == 1);
        BP_CHECK("read_failed: HAVE_DATA cleared",
                 (sc.blocks[1].nStatus & BLOCK_HAVE_DATA) == 0);
        int ok = -1; char src[32];
        BP_CHECK("read_failed: no permanent row",
                 !log_row_at(progress_store_db(), 1, &ok, src, sizeof(src)));
        BP_CHECK("read_failed: idles while cleared",
                 body_persist_stage_step_once() == JOB_IDLE);
        BP_CHECK("read_failed: counter stays 1",
                 body_persist_stage_read_failed_total() == 1);
        /* SILENT-HOLD GUARD. The requeue fires ONCE and the HAVE_DATA gate then
         * idles without re-reading, so a repeat COUNT never grows: before the
         * named blocker this hold was invisible (JOB_IDLE, blocked_count 0,
         * nothing in `dumpstate blocker`) — exactly how the from-genesis wedge
         * at height 0 stayed unnamed for 617 s on the 2026-07-27 bare cold
         * start. Drive the hold clock to 0 so the naming asserts without a
         * sleep. */
        BP_CHECK("read_failed: hold not yet named (inside the 60s window)",
                 !blocker_exists("body_persist.body_unfetchable"));
        body_persist_stage_set_unfetchable_hold_secs_for_testing(0);
        BP_CHECK("read_failed: still idle after the hold ages out",
                 body_persist_stage_step_once() == JOB_IDLE);
        BP_CHECK("read_failed: the hold is NAMED, not silent",
                 blocker_exists("body_persist.body_unfetchable"));
        sc.fail_read_height = -1;
        sc.blocks[1].nStatus |= BLOCK_HAVE_DATA;
        BP_CHECK("read_failed: heals after re-fetch",
                 body_persist_stage_drain(100) == 2);
        BP_CHECK("read_failed: h=1 verified",
                 log_row_at(progress_store_db(), 1, &ok, src, sizeof(src)) &&
                 ok == 1 && strcmp(src, "verified") == 0);
        BP_CHECK("read_failed: the named hold self-clears on advance",
                 !blocker_exists("body_persist.body_unfetchable"));
        body_persist_stage_set_unfetchable_hold_secs_for_testing(-1);
        bp_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_bp sc;
        BP_CHECK("idle_missing_data: setup",
                 bp_setup("idle", 5, -1, -1, dir, sizeof(dir), &ms, &sc) == 0);
        sc.blocks[3].nStatus &= ~BLOCK_HAVE_DATA;
        BP_CHECK("idle_missing_data: advances to h=3",
                 body_persist_stage_drain(100) == 3);
        BP_CHECK("idle_missing_data: next step IDLE",
                 body_persist_stage_step_once() == JOB_IDLE);
        BP_CHECK("idle_missing_data: cursor stays 3",
                 body_persist_stage_cursor() == 3);
        bp_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_bp sc;
        BP_CHECK("idle_missing_fetch_row: setup",
                 bp_setup("missingrow", 5, -1, 2, dir, sizeof(dir), &ms, &sc) == 0);
        BP_CHECK("idle_missing_fetch_row: advances 2",
                 body_persist_stage_drain(100) == 2);
        BP_CHECK("idle_missing_fetch_row: next step IDLE",
                 body_persist_stage_step_once() == JOB_IDLE);
        BP_CHECK("idle_missing_fetch_row: cursor stays 2",
                 body_persist_stage_cursor() == 2);
        bp_teardown(dir, &ms, &sc);
    }

    {
        BP_CHECK("guard: step_once with no init returns IDLE",
                 body_persist_stage_step_once() == JOB_IDLE);
        BP_CHECK("guard: init(NULL) rejected",
                 !body_persist_stage_init(NULL));
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_bp sc;
        BP_CHECK("dump: setup",
                 bp_setup("dump", 2, -1, -1, dir, sizeof(dir), &ms, &sc) == 0);
        body_persist_stage_drain(100);
        struct json_value v;
        json_init(&v);
        BP_CHECK("dump: returns true",
                 body_persist_dump_state_json(&v, NULL));
        char buf[1024];
        size_t n = json_write(&v, buf, sizeof(buf));
        BP_CHECK("dump: serializes", n > 0 && n < sizeof(buf));
        BP_CHECK("dump: stage_name",
                 strstr(buf, "\"stage_name\":\"body_persist\"") != NULL);
        BP_CHECK("dump: cursor=2",
                 strstr(buf, "\"cursor\":2") != NULL);
        BP_CHECK("dump: verified_total=2",
                 strstr(buf, "\"verified_total\":2") != NULL);
        BP_CHECK("dump: log_rows=2",
                 strstr(buf, "\"log_rows\":2") != NULL);
        json_free(&v);
        bp_teardown(dir, &ms, &sc);
    }

    printf("body_persist_stage tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
