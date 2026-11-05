/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Unit tests for the body_persist stage. */

#include "test/block_index_ext_fixture.h"
#include "test/test_core.h"
#include "test/block_fixtures.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "jobs/body_persist_stage.h"
#include "storage/event_log.h"
#include "storage/event_log_singleton.h"
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
        tbi_ext(&sc->blocks[i])->hashMerkleRoot = sc->bodies[i].header.hashMerkleRoot;
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

/* Nine subtests each open/close a real progress_store (sqlite WAL) over this
 * fixture directory. Prefer tmpfs (/dev/shm) where writable so WAL checkpoints
 * do not queue behind other processes' commits; otherwise fall back to
 * ./test-tmp (test_fmt_tmpdir), e.g. on macOS. */
static void bp_fmt_tmpdir(char *dir_out, size_t dir_out_size,
                          const char *tag)
{
    if (access("/dev/shm", W_OK) == 0) {
        int wrote = snprintf(dir_out, dir_out_size,
                             "/dev/shm/body_persist_%d_%s",
                             (int)getpid(), tag);
        if (wrote > 0 && (size_t)wrote < dir_out_size)
            return;
    }
    test_fmt_tmpdir(dir_out, dir_out_size, "body_persist", tag);
}

static int bp_setup(const char *tag, int n, int upstream_fail_height,
                    int missing_row_height, char *dir_out,
                    size_t dir_out_size, struct main_state *ms,
                    struct synth_chain_bp *sc)
{
    /* First, so bp_teardown can main_state_free after any early return. */
    main_state_init(ms);
    bp_fmt_tmpdir(dir_out, dir_out_size, tag);
    mkdir_p_bp("./test-tmp");
    mkdir_p_bp(dir_out);
    if (!progress_store_open(dir_out)) return 1;

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
    main_state_free(ms);
    synth_chain_bp_free(sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

/* ---- Mutation-sweep gap closers (dump, reset, hold, fatal, drain, init) ---- */

static bool bp_dump_text(char *buf, size_t size)
{
    struct json_value v;
    json_init(&v);
    bool ok = body_persist_dump_state_json(&v, NULL);
    size_t n = ok ? json_write(&v, buf, size) : 0;
    json_free(&v);
    return ok && n > 0 && n < size;
}

static bool bp_dump_has(const char *needle)
{
    char buf[4096];
    return bp_dump_text(buf, sizeof(buf)) && strstr(buf, needle) != NULL;
}

static bool bp_unfetchable_reason(char *out, size_t size)
{
    struct blocker_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    if (!blocker_find_by_id_prefix("body_persist.body_unfetchable", &snap))
        return false;
    snprintf(out, size, "%s", snap.reason);
    return true;
}

static void bp_restore_have_data(struct synth_chain_bp *sc, int h)
{
    sc->blocks[h].nStatus |= BLOCK_HAVE_DATA;
}

/* Counters, the status-event emits, nTx and the last_* gauges across a run
 * that exercises every verdict; then the shutdown reset of all of them. */
static int bp_mut_counters_run(struct synth_chain_bp *sc)
{
    int failures = 0;
    sc->fail_read_height = 3;
    BP_CHECK("counters: read failure holds after 3 advances",
             body_persist_stage_drain(100) == 3);
    BP_CHECK("counters: read_failed_total == 1",
             body_persist_stage_read_failed_total() == 1);
    BP_CHECK("counters: requeue stamps last_blocked_unix",
             !bp_dump_has("\"last_blocked_unix\":0"));
    sc->fail_read_height = -1;
    sc->header_mismatch_height = 3;
    bp_restore_have_data(sc, 3);
    BP_CHECK("counters: header mismatch holds", body_persist_stage_drain(100) == 0);
    sc->header_mismatch_height = -1;
    sc->merkle_mismatch_height = 3;
    bp_restore_have_data(sc, 3);
    BP_CHECK("counters: merkle mismatch holds", body_persist_stage_drain(100) == 0);
    sc->merkle_mismatch_height = -1;
    bp_restore_have_data(sc, 3);
    BP_CHECK("counters: heals 3..7", body_persist_stage_drain(100) == 5);
    return failures;
}

static int bp_mut_counters_check(struct synth_chain_bp *sc)
{
    int failures = 0;
    BP_CHECK("counters: verified 7", body_persist_stage_verified_total() == 7);
    BP_CHECK("counters: upstream_failed 1",
             body_persist_stage_upstream_failed_total() == 1);
    BP_CHECK("counters: read_failed 1",
             body_persist_stage_read_failed_total() == 1);
    BP_CHECK("counters: header_mismatch 1",
             body_persist_stage_header_mismatch_total() == 1);
    BP_CHECK("counters: merkle_mismatch 1",
             body_persist_stage_merkle_mismatch_total() == 1);
    BP_CHECK("counters: cursor 8", body_persist_stage_cursor() == 8);
    BP_CHECK("counters: step ewma is measured",
             body_persist_stage_step_us_ewma() > 0);
    BP_CHECK("counters: preset nTx is kept", sc->blocks[2].nTx == 7);
    BP_CHECK("counters: zero nTx takes num_vtx",
             sc->blocks[0].nTx == 1 && sc->blocks[4].nTx == 1);
    BP_CHECK("counters: upstream-failed height keeps nTx 0",
             sc->blocks[7].nTx == 0);
    BP_CHECK("dump: verified_total", bp_dump_has("\"verified_total\":7"));
    BP_CHECK("dump: upstream_failed_total",
             bp_dump_has("\"upstream_failed_total\":1"));
    BP_CHECK("dump: read_failed_total", bp_dump_has("\"read_failed_total\":1"));
    BP_CHECK("dump: header_mismatch_total",
             bp_dump_has("\"header_mismatch_total\":1"));
    BP_CHECK("dump: merkle_mismatch_total",
             bp_dump_has("\"merkle_mismatch_total\":1"));
    BP_CHECK("dump: header_event_emit_total counts 7 verified + 3 requeues",
             bp_dump_has("\"header_event_emit_total\":10"));
    BP_CHECK("dump: header_event_emit_fail_total",
             bp_dump_has("\"header_event_emit_fail_total\":0"));
    BP_CHECK("dump: last_advance_height is the upstream-failed height",
             bp_dump_has("\"last_advance_height\":7"));
    BP_CHECK("dump: last_step_unix stamped",
             !bp_dump_has("\"last_step_unix\":0"));
    BP_CHECK("dump: last_step_age computed",
             !bp_dump_has("\"last_step_age_seconds\":-1"));
    BP_CHECK("dump: last_blocked_unix stamped",
             !bp_dump_has("\"last_blocked_unix\":0"));
    BP_CHECK("dump: no blocked or error results",
             bp_dump_has("\"blocked_count\":0") &&
             bp_dump_has("\"error_count\":0"));
    return failures;
}

static int bp_mut_shutdown_reset(void)
{
    int failures = 0;
    body_persist_stage_shutdown();
    BP_CHECK("shutdown: verified reset", body_persist_stage_verified_total() == 0);
    BP_CHECK("shutdown: upstream reset",
             body_persist_stage_upstream_failed_total() == 0);
    BP_CHECK("shutdown: read reset", body_persist_stage_read_failed_total() == 0);
    BP_CHECK("shutdown: header reset",
             body_persist_stage_header_mismatch_total() == 0);
    BP_CHECK("shutdown: merkle reset",
             body_persist_stage_merkle_mismatch_total() == 0);
    BP_CHECK("shutdown: no stage -> cursor 0", body_persist_stage_cursor() == 0);
    BP_CHECK("shutdown: no stage -> ewma 0",
             body_persist_stage_step_us_ewma() == 0);
    BP_CHECK("shutdown dump: emit total reset",
             bp_dump_has("\"header_event_emit_total\":0"));
    BP_CHECK("shutdown dump: emit fail reset",
             bp_dump_has("\"header_event_emit_fail_total\":0"));
    BP_CHECK("shutdown dump: last_advance_height back to -1",
             bp_dump_has("\"last_advance_height\":-1"));
    BP_CHECK("shutdown dump: last_step_unix reset",
             bp_dump_has("\"last_step_unix\":0"));
    BP_CHECK("shutdown dump: last_step_age is -1 when never stepped",
             bp_dump_has("\"last_step_age_seconds\":-1"));
    BP_CHECK("shutdown dump: last_blocked_unix reset",
             bp_dump_has("\"last_blocked_unix\":0"));
    BP_CHECK("shutdown dump: uninitialised", bp_dump_has("\"initialised\":false"));
    return failures;
}

static int bp_mut_counters(void)
{
    int failures = 0;
    char dir[256] = {0}, logp[320] = {0};
    struct main_state ms; struct synth_chain_bp sc;
    memset(&sc, 0, sizeof(sc));
    event_log_t *log = NULL;
    int rc = bp_setup("mut_ctr", 8, 7, -1, dir, sizeof(dir), &ms, &sc);
    BP_CHECK("counters: setup", rc == 0);
    if (rc == 0) {
        snprintf(logp, sizeof(logp), "%s/mut_ev.log", dir);
        log = event_log_open(logp);
        BP_CHECK("counters: event log opens", log != NULL);
    }
    if (rc != 0 || !log) {
        bp_teardown(dir, &ms, &sc);
        return failures + 1;
    }
    event_log_set_singleton(log);
    sc.blocks[2].nTx = 7;
    failures += bp_mut_counters_run(&sc);
    failures += bp_mut_counters_check(&sc);
    failures += bp_mut_shutdown_reset();
    event_log_set_singleton(NULL);
    event_log_close(log);
    bp_teardown(dir, &ms, &sc);
    return failures;
}

/* Frontier gate (== is idle), drain bounds, and the idle-gate stamp. */
static int bp_mut_drain_gate(void)
{
    int failures = 0;
    char dir[256] = {0}; struct main_state ms; struct synth_chain_bp sc;
    memset(&sc, 0, sizeof(sc));
    int rc = bp_setup("mut_gate", 6, -1, -1, dir, sizeof(dir), &ms, &sc);
    BP_CHECK("gate: setup", rc == 0);
    if (rc != 0) { bp_teardown(dir, &ms, &sc); return failures; }
    BP_CHECK("gate: drain(0) is 0", body_persist_stage_drain(0) == 0);
    BP_CHECK("gate: drain(-1) is 0", body_persist_stage_drain(-1) == 0);
    BP_CHECK("gate: drain(1) advances exactly 1",
             body_persist_stage_drain(1) == 1);
    BP_CHECK("gate: drain(2) advances exactly 2",
             body_persist_stage_drain(2) == 2);
    BP_CHECK("gate: cursor 3", body_persist_stage_cursor() == 3);
    BP_CHECK("gate: lower the upstream frontier to 4",
             exec_sql(progress_store_db(),
                      "UPDATE stage_cursor SET cursor = 4 "
                      "WHERE name = 'body_fetch'"));
    BP_CHECK("gate: drain stops at the frontier",
             body_persist_stage_drain(100) == 1);
    BP_CHECK("gate: cursor at frontier 4", body_persist_stage_cursor() == 4);
    BP_CHECK("gate: nothing past the frontier is persisted",
             log_row_count(progress_store_db()) == 4);
    BP_CHECK("gate: idle at the frontier",
             body_persist_stage_step_once() == JOB_IDLE);
    BP_CHECK("gate: frontier idle stamps last_blocked_unix",
             !bp_dump_has("\"last_blocked_unix\":0"));
    bp_teardown(dir, &ms, &sc);
    return failures;
}

static int bp_mut_idle_stamp(void)
{
    int failures = 0;
    char dir[256] = {0}; struct main_state ms; struct synth_chain_bp sc;
    memset(&sc, 0, sizeof(sc));
    int rc = bp_setup("mut_idle", 5, -1, -1, dir, sizeof(dir), &ms, &sc);
    BP_CHECK("idle stamp: setup", rc == 0);
    if (rc != 0) { bp_teardown(dir, &ms, &sc); return failures; }
    sc.blocks[3].nStatus &= ~BLOCK_HAVE_DATA;
    BP_CHECK("idle stamp: drains 3", body_persist_stage_drain(100) == 3);
    BP_CHECK("idle stamp: HAVE_DATA gate stamps last_blocked_unix",
             !bp_dump_has("\"last_blocked_unix\":0"));
    BP_CHECK("idle stamp: gate idle is counted idle, not blocked",
             bp_dump_has("\"blocked_count\":0"));
    bp_teardown(dir, &ms, &sc);
    return failures;
}

/* A failed write must surface as FATAL and hold the cursor. */
static int bp_mut_fatal_one(const char *tag, int upstream_fail,
                            const char *sql, unsigned want_ntx)
{
    int failures = 0;
    char dir[256] = {0}; struct main_state ms; struct synth_chain_bp sc;
    memset(&sc, 0, sizeof(sc));
    int rc = bp_setup(tag, 3, upstream_fail, -1, dir, sizeof(dir), &ms, &sc);
    BP_CHECK(tag, rc == 0);
    if (rc != 0) { bp_teardown(dir, &ms, &sc); return failures; }
    BP_CHECK("fatal: break the table", exec_sql(progress_store_db(), sql));
    job_result_t r = body_persist_stage_step_once();
    BP_CHECK("fatal: step reports FATAL", r == JOB_FATAL);
    BP_CHECK("fatal: cursor does not move", body_persist_stage_cursor() == 0);
    BP_CHECK("fatal: nTx as the failing phase leaves it",
             sc.blocks[0].nTx == want_ntx);
    BP_CHECK("fatal: no verified counter bump",
             body_persist_stage_verified_total() == 0);
    BP_CHECK("fatal: no upstream_failed counter bump",
             body_persist_stage_upstream_failed_total() == 0);
    bp_teardown(dir, &ms, &sc);
    return failures;
}

static int bp_mut_fatal(void)
{
    int failures = 0;
    failures += bp_mut_fatal_one("fatal: verified-row insert fails", -1,
        "ALTER TABLE body_persist_log RENAME TO bpl_gone", 1);
    failures += bp_mut_fatal_one("fatal: upstream_failed-row insert fails", 0,
        "ALTER TABLE body_persist_log RENAME TO bpl_gone", 0);
    failures += bp_mut_fatal_one("fatal: created_outputs write fails", -1,
        "ALTER TABLE created_outputs RENAME TO co_gone", 0);
    failures += bp_mut_fatal_one("fatal: body_fetch_log read fails", -1,
        "ALTER TABLE body_fetch_log RENAME TO bfl_gone", 0);
    return failures;
}

/* With the progress store closed the drain must not open a batch. */
static int bp_mut_closed_store(void)
{
    int failures = 0;
    char dir[256] = {0}; struct main_state ms; struct synth_chain_bp sc;
    memset(&sc, 0, sizeof(sc));
    int rc = bp_setup("mut_closed", 3, -1, -1, dir, sizeof(dir), &ms, &sc);
    BP_CHECK("closed: setup", rc == 0);
    if (rc != 0) { bp_teardown(dir, &ms, &sc); return failures; }
    progress_store_close();
    BP_CHECK("closed: drain advances nothing", body_persist_stage_drain(10) == 0);
    BP_CHECK("closed: step idles", body_persist_stage_step_once() == JOB_IDLE);
    body_persist_stage_shutdown();
    main_state_free(&ms);
    synth_chain_bp_free(&sc);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* Unfetchable-body hold: the genesis wording, disarm at height 0, the
 * above-genesis wording with the tip, and the upstream-failed disarm. */
static int bp_mut_hold_genesis(void)
{
    int failures = 0;
    char dir[256] = {0}, why[512] = {0};
    struct main_state ms; struct synth_chain_bp sc;
    memset(&sc, 0, sizeof(sc));
    int rc = bp_setup("mut_hold0", 2, -1, -1, dir, sizeof(dir), &ms, &sc);
    BP_CHECK("hold0: setup", rc == 0);
    if (rc != 0) { bp_teardown(dir, &ms, &sc); return failures; }
    body_persist_stage_set_unfetchable_hold_secs_for_testing(0);
    sc.fail_read_height = 0;
    BP_CHECK("hold0: read failure at genesis idles",
             body_persist_stage_step_once() == JOB_IDLE);
    BP_CHECK("hold0: requeue stamps last_blocked_unix",
             !bp_dump_has("\"last_blocked_unix\":0"));
    BP_CHECK("hold0: idle names the hold",
             body_persist_stage_step_once() == JOB_IDLE &&
             bp_unfetchable_reason(why, sizeof(why)));
    BP_CHECK("hold0: genesis wording",
             strstr(why, "height=0 genesis body absent") != NULL);
    sc.fail_read_height = -1;
    bp_restore_have_data(&sc, 0);
    BP_CHECK("hold0: heals", body_persist_stage_drain(100) == 2);
    BP_CHECK("hold0: advance at height 0 disarms and clears the blocker",
             !blocker_exists("body_persist.body_unfetchable"));
    body_persist_stage_set_unfetchable_hold_secs_for_testing(-1);
    bp_teardown(dir, &ms, &sc);
    return failures;
}

static int bp_mut_hold_above_genesis(void)
{
    int failures = 0;
    char dir[256] = {0}, why[512] = {0};
    struct main_state ms; struct synth_chain_bp sc;
    memset(&sc, 0, sizeof(sc));
    int rc = bp_setup("mut_hold1", 3, -1, -1, dir, sizeof(dir), &ms, &sc);
    BP_CHECK("hold1: setup", rc == 0);
    if (rc != 0) { bp_teardown(dir, &ms, &sc); return failures; }
    body_persist_stage_set_unfetchable_hold_secs_for_testing(0);
    sc.fail_read_height = 1;
    BP_CHECK("hold1: holds at 1", body_persist_stage_drain(100) == 1);
    BP_CHECK("hold1: idle names the hold",
             body_persist_stage_step_once() == JOB_IDLE &&
             bp_unfetchable_reason(why, sizeof(why)));
    BP_CHECK("hold1: above-genesis wording carries height and tip",
             strstr(why, "height=1 body refetch pending") != NULL &&
             strstr(why, "tip=2") != NULL &&
             strstr(why, "genesis") == NULL);
    BP_CHECK("hold1: upstream verdict flips to failed",
             exec_sql(progress_store_db(),
                      "UPDATE body_fetch_log SET ok = 0 WHERE height = 1"));
    BP_CHECK("hold1: upstream-failed advance passes 1 and 2",
             body_persist_stage_drain(100) == 2);
    BP_CHECK("hold1: upstream-failed advance disarms the hold",
             !blocker_exists("body_persist.body_unfetchable"));
    body_persist_stage_set_unfetchable_hold_secs_for_testing(-1);
    bp_teardown(dir, &ms, &sc);
    return failures;
}

/* Upstream-log hole: named on a missing row, cleared when it is found, and
 * cleared by shutdown. */
static int bp_mut_hole(void)
{
    int failures = 0;
    char dir[256] = {0}; struct main_state ms; struct synth_chain_bp sc;
    memset(&sc, 0, sizeof(sc));
    int rc = bp_setup("mut_hole", 5, -1, 2, dir, sizeof(dir), &ms, &sc);
    BP_CHECK("hole: setup", rc == 0);
    if (rc != 0) { bp_teardown(dir, &ms, &sc); return failures; }
    BP_CHECK("hole: drain stops at the hole", body_persist_stage_drain(100) == 2);
    BP_CHECK("hole: the hole is named",
             blocker_exists("body_persist.upstream_log_hole"));
    BP_CHECK("hole: hole stamps last_blocked_unix",
             !bp_dump_has("\"last_blocked_unix\":0"));
    BP_CHECK("hole: refill the row",
             exec_sql(progress_store_db(),
                      "INSERT INTO body_fetch_log (height, hash, source, "
                      "bytes, fetched_at, ok, fail_reason) VALUES "
                      "(2, zeroblob(32), 'disk', 0, 1, 1, NULL)"));
    BP_CHECK("hole: drain resumes", body_persist_stage_drain(100) == 3);
    BP_CHECK("hole: found row clears the hole",
             !blocker_exists("body_persist.upstream_log_hole"));
    bp_teardown(dir, &ms, &sc);

    memset(&sc, 0, sizeof(sc));
    rc = bp_setup("mut_hole2", 3, -1, 0, dir, sizeof(dir), &ms, &sc);
    BP_CHECK("hole2: setup", rc == 0);
    if (rc != 0) { bp_teardown(dir, &ms, &sc); return failures; }
    BP_CHECK("hole2: idle on the hole",
             body_persist_stage_step_once() == JOB_IDLE &&
             blocker_exists("body_persist.upstream_log_hole"));
    body_persist_stage_shutdown();
    BP_CHECK("hole2: shutdown clears the hole",
             !blocker_exists("body_persist.upstream_log_hole"));
    bp_teardown(dir, &ms, &sc);
    return failures;
}

/* init: idempotent for the same main_state, refuses another, releases its
 * lock on every refusal, and fails closed when the schema cannot be made. */
static int bp_mut_init_rebind(void)
{
    int failures = 0;
    char dir[256] = {0}; struct main_state ms; struct synth_chain_bp sc;
    struct main_state other;
    memset(&sc, 0, sizeof(sc));
    main_state_init(&other);
    int rc = bp_setup("mut_init", 2, -1, -1, dir, sizeof(dir), &ms, &sc);
    BP_CHECK("init: setup", rc == 0);
    if (rc == 0) {
        BP_CHECK("init: same main_state is accepted again",
                 body_persist_stage_init(&ms));
        BP_CHECK("init: a different main_state is refused",
                 !body_persist_stage_init(&other));
        BP_CHECK("init: the lock was released (same again)",
                 body_persist_stage_init(&ms));
        BP_CHECK("init: stage still runs", body_persist_stage_drain(100) == 2);
    }
    bp_teardown(dir, &ms, &sc);
    main_state_free(&other);
    return failures;
}

static int bp_mut_init_schema(void)
{
    int failures = 0;
    char dir[256] = {0};
    struct main_state ms;
    main_state_init(&ms);
    bp_fmt_tmpdir(dir, sizeof(dir), "mut_schema");
    mkdir_p_bp("./test-tmp");
    mkdir_p_bp(dir);
    bool opened = progress_store_open(dir);
    BP_CHECK("schema: store opens", opened);
    if (opened) {
        sqlite3 *db = progress_store_db();
        BP_CHECK("schema: read-only on", exec_sql(db, "PRAGMA query_only = 1"));
        BP_CHECK("schema: log table cannot be made -> init false",
                 !body_persist_stage_init(&ms));
        BP_CHECK("schema: read-only off", exec_sql(db, "PRAGMA query_only = 0"));
        BP_CHECK("schema: init succeeds once writable (lock was released)",
                 body_persist_stage_init(&ms));
        body_persist_stage_shutdown();
    }
    main_state_free(&ms);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

static int bp_mut_dump_null(void)
{
    int failures = 0;
    BP_CHECK("dump: NULL out is refused",
             !body_persist_dump_state_json(NULL, NULL));
    return failures;
}

static int bp_mutation_gap_tests(void)
{
    int failures = 0;
    failures += bp_mut_counters();
    failures += bp_mut_drain_gate();
    failures += bp_mut_idle_stamp();
    failures += bp_mut_fatal();
    failures += bp_mut_closed_store();
    failures += bp_mut_hold_genesis();
    failures += bp_mut_hold_above_genesis();
    failures += bp_mut_hole();
    failures += bp_mut_init_rebind();
    failures += bp_mut_init_schema();
    failures += bp_mut_dump_null();
    return failures;
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
        /* SILENT-HOLD GUARD. The requeue fires once and the HAVE_DATA gate then
         * idles without re-reading, so a repeat COUNT never grows; the hold
         * must be a named blocker in `dumpstate blocker`. Drive the hold clock
         * to 0 so the naming asserts without a sleep. */
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

    failures += bp_mutation_gap_tests();

    printf("body_persist_stage tests: %s\n",
           failures ? "FAILED" : "PASSED");
#if !defined(_WIN32)
    /* Every subtest has ended (pass or fail); drop this run's RAM trees. */
    test_shm_reap_own("body_persist_");
#endif
    return failures;
}
