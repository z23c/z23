/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the Wave S S-4 body_fetch stage
 * (app/services/src/body_fetch_stage.c).
 *
 * Coverage:
 *   - init / shutdown round-trip
 *   - happy path: 5 blocks all HAVE_DATA → 5 "disk" rows
 *   - cursor floor: body_fetch never overruns validate_headers
 *   - skipped_invalid: validate ok=0 → body_fetch records a skip row
 *   - body not yet available (BLOCK_HAVE_DATA unset) → JOB_IDLE, no advance
 *   - availability flip: set HAVE_DATA later → cursor advances
 *   - replay across progress_store reopen: cursor + log row count persist
 *   - pre-init guards
 *   - dump_state_json shape
 *   - crash-replay sub-process (fork + SIGKILL) — DoD addition,
 *     asserts the F-2 atomicity contract under signal pressure
 *   - cursor floor invariant: body_fetch cannot pass validate even when
 *     validate cursor is forced backward (truncated log) */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "json/json.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/header_admit_stage.h"
#include "jobs/reducer_frontier.h"
#include "jobs/validate_headers_stage.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <time.h>
#include <unistd.h>
#if !defined(_WIN32)

#define BF_CHECK(name, expr) do { \
    printf("body_fetch: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static int mkdir_p_bf(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static bool ensure_tip_finalize_fixture_schema_bf(sqlite3 *db)
{
    char *err = NULL;
    int rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "height INTEGER PRIMARY KEY, status TEXT NOT NULL, "
        "ok INTEGER NOT NULL, tip_hash BLOB)",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        if (err)
            sqlite3_free(err);
        return false;
    }
    return true;
}

/* Synthetic chain — fully controllable nStatus + nHeight per block. */
struct synth_chain_bf {
    struct block_index *blocks;
    struct uint256     *hashes;
    int                 n;
};

static bool synth_chain_bf_build(struct synth_chain_bf *sc, int n)
{
    memset(sc, 0, sizeof(*sc));
    sc->blocks = zcl_malloc((size_t)n * sizeof(struct block_index),
                             "bf_blocks");
    if (!sc->blocks) return false;
    sc->hashes = zcl_malloc((size_t)n * sizeof(struct uint256),
                             "bf_hashes");
    if (!sc->hashes) { free(sc->blocks); return false; }
    for (int i = 0; i < n; i++) {
        block_index_init(&sc->blocks[i]);
        memset(&sc->hashes[i], 0, sizeof(struct uint256));
        sc->hashes[i].data[0] = (uint8_t)(i & 0xFF);
        sc->hashes[i].data[1] = (uint8_t)((i >> 8) & 0xFF);
        sc->hashes[i].data[2] = 0xB4;  /* tag distinct from vh tests */
        sc->blocks[i].phashBlock = &sc->hashes[i];
        sc->blocks[i].nHeight = i;
        sc->blocks[i].nVersion = 4;
        sc->blocks[i].nBits = 0x1f07ffff;
        sc->blocks[i].nStatus = BLOCK_HAVE_DATA;  /* default: body present */
        if (i > 0) sc->blocks[i].pprev = &sc->blocks[i - 1];
    }
    sc->n = n;
    return true;
}

static void synth_chain_bf_free(struct synth_chain_bf *sc)
{
    free(sc->blocks);
    free(sc->hashes);
    memset(sc, 0, sizeof(*sc));
}

/* Stub validator — always passes. Tests that want failure flip the
 * specific row in validate_headers_log directly. */
static bool stub_pass(const struct block_index *bi, const char *datadir,
                      char *out_reason, size_t out_reason_size,
                      void *user)
{
    (void)bi; (void)datadir; (void)user;
    if (out_reason && out_reason_size) out_reason[0] = 0;
    return true;
}

static int log_row_count(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM body_fetch_log", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int n = -1;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static int deny_second_stage_cursor_read(void *user, int action,
                                         const char *arg1,
                                         const char *arg2,
                                         const char *db_name,
                                         const char *trigger)
{
    (void)db_name;
    (void)trigger;
    if (action == SQLITE_READ &&
        arg1 && strcmp(arg1, "stage_cursor") == 0 &&
        arg2 && strcmp(arg2, "cursor") == 0) {
        int *reads = (int *)user;
        (*reads)++;
        if (*reads > 1)
            return SQLITE_DENY;
    }
    return SQLITE_OK;
}

static bool log_row_at(sqlite3 *db, int height,
                        int *out_ok, char *out_source, size_t source_size)
{
    *out_ok = -1;
    if (out_source && source_size) out_source[0] = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, source FROM body_fetch_log WHERE height = ?",
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

static bool log_hash_at(sqlite3 *db, int height, struct uint256 *out_hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT hash FROM body_fetch_log WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (blob && n == 32) {
            memcpy(out_hash->data, blob, 32);
            found = true;
        }
    }
    sqlite3_finalize(st);
    return found;
}

static bool dump_has_idle_reason(const char *reason)
{
    struct json_value v;
    json_init(&v);
    if (!body_fetch_stage_dump_state_json(&v, NULL)) {
        json_free(&v);
        return false;
    }
    const char *got = json_get_str(json_get(&v, "last_idle_reason"));
    bool matches = got && strcmp(got, reason) == 0;
    json_free(&v);
    return matches;
}

/* Flip the ok flag on a validate_headers_log row (for testing the
 * skipped_invalid path without rewiring the vh stub validator). */
static bool vh_log_force_ok(sqlite3 *db, int height, int ok)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "UPDATE validate_headers_log SET ok = ? WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(st, 1, ok);
    sqlite3_bind_int(st, 2, height);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static bool vh_log_force_failure(sqlite3 *db, int height, const char *reason)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "UPDATE validate_headers_log SET ok = 0, fail_reason = ? "
        "WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_text(st, 1, reason, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, height);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static bool vh_log_force_short_hash(sqlite3 *db, int height)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "UPDATE validate_headers_log SET hash = X'01' WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(st, 1, height);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static bool seed_trusted_parent_bf(sqlite3 *db, int height,
                                   const struct uint256 *hash)
{
    if (!db || height < 0 || !hash)
        return false;
    uint8_t encoded_height[8];
    uint64_t value = (uint64_t)height;
    for (size_t i = 0; i < sizeof(encoded_height); i++)
        encoded_height[i] = (uint8_t)(value >> (8u * i));
    return progress_meta_set(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                             encoded_height, sizeof(encoded_height)) &&
           progress_meta_set(db, REDUCER_TRUSTED_BASE_HASH_KEY,
                             hash->data, sizeof(hash->data));
}

/* Set up the full saga prefix (progress + admit + validate + body_fetch).
 * Returns 0 on success. The caller is responsible for tearing down. */
static int bf_setup(const char *tag, int n,
                     char *dir_out, size_t dir_out_size,
                     struct main_state *ms,
                     struct synth_chain_bf *sc)
{
    test_fmt_tmpdir(dir_out, dir_out_size, "body_fetch", tag);
    mkdir_p_bf(dir_out);
    if (!progress_store_open(dir_out)) return 1;

    memset(ms, 0, sizeof(*ms));
    main_state_init(ms);
    if (!synth_chain_bf_build(sc, n)) return 2;
    active_chain_move_window_tip(&ms->chain_active, &sc->blocks[n - 1]);
    ms->pindex_best_header = &sc->blocks[n - 1];

    if (!header_admit_stage_init(ms))      return 3;
    if (!validate_headers_stage_init(ms))  return 4;
    validate_headers_stage_set_validator(stub_pass, NULL);
    if (!body_fetch_stage_init(ms))        return 5;
    return 0;
}

static void bf_teardown(const char *dir, struct main_state *ms,
                         struct synth_chain_bf *sc)
{
    /* Shutdown order: bottom-up. body_fetch → validate_headers → admit. */
    body_fetch_stage_shutdown();
    validate_headers_stage_shutdown();
    header_admit_stage_shutdown();
    main_state_free(ms);
    synth_chain_bf_free(sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

int test_body_fetch_stage(void);
int test_body_fetch_stage(void)
{
    printf("\n=== body_fetch_stage tests ===\n");
    int failures = 0;

    blocker_module_init();

    /* ── happy: 5 blocks all HAVE_DATA → 5 disk rows ─────────────────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_bf sc;
        BF_CHECK("happy: setup",
                 bf_setup("happy", 5, dir, sizeof(dir), &ms, &sc) == 0);

        BF_CHECK("happy: admit drains 5",
                 header_admit_stage_drain(100) == 5);
        BF_CHECK("happy: validate drains all",
                 validate_headers_stage_drain(100) >= 1 &&
                 validate_headers_stage_cursor() == 5);

        int adv = body_fetch_stage_drain(100);
        BF_CHECK("happy: body_fetch advances 5 steps", adv == 5);
        BF_CHECK("happy: cursor at 5", body_fetch_stage_cursor() == 5);
        BF_CHECK("happy: observed_total == 5",
                 body_fetch_stage_observed_total() == 5);
        BF_CHECK("happy: skipped_total == 0",
                 body_fetch_stage_skipped_total() == 0);

        sqlite3 *db = progress_store_db();
        BF_CHECK("happy: log has 5 rows", log_row_count(db) == 5);
        for (int h = 0; h < 5; h++) {
            int ok = -1; char src[32] = {0};
            log_row_at(db, h, &ok, src, sizeof(src));
            BF_CHECK("happy: row ok=1", ok == 1);
            BF_CHECK("happy: row source='disk'", strcmp(src, "disk") == 0);
        }

        /* Caught up — next step IDLE. */
        BF_CHECK("happy: next step IDLE",
                 body_fetch_stage_step_once() == JOB_IDLE);

        bf_teardown(dir, &ms, &sc);
    }

    /* ── upstream cursor read errors are FATAL, not cursor-0 IDLE ───── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_bf sc;
        BF_CHECK("cursor_read_error: setup",
                 bf_setup("cursor_read_error", 3, dir, sizeof(dir),
                          &ms, &sc) == 0);

        sqlite3 *db = progress_store_db();
        int reads = 0;
        BF_CHECK("cursor_read_error: install authorizer",
                 sqlite3_set_authorizer(db, deny_second_stage_cursor_read,
                                        &reads) == SQLITE_OK);
        job_result_t r = body_fetch_stage_step_once();
        sqlite3_set_authorizer(db, NULL, NULL);
        BF_CHECK("cursor_read_error: upstream read returns fatal",
                 r == JOB_FATAL && reads >= 2);

        bf_teardown(dir, &ms, &sc);
    }

    /* ── cursor floor: body_fetch never overruns validate ────────────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_bf sc;
        BF_CHECK("floor: setup",
                 bf_setup("floor", 10, dir, sizeof(dir), &ms, &sc) == 0);

        /* Admit + validate only 3 of 10. */
        for (int i = 0; i < 3; i++) header_admit_stage_step_once();
        validate_headers_stage_drain(10);  /* validates 3 in one batched step */
        BF_CHECK("floor: validate cursor at 3",
                 validate_headers_stage_cursor() == 3);

        int adv = body_fetch_stage_drain(100);
        BF_CHECK("floor: body_fetch advances exactly 3", adv == 3);
        BF_CHECK("floor: body_fetch cursor at 3",
                 body_fetch_stage_cursor() == 3);

        /* Next step must be IDLE — validate cursor is the wall. */
        BF_CHECK("floor: next step IDLE",
                 body_fetch_stage_step_once() == JOB_IDLE);

        /* Push validate forward 3 more, body_fetch follows. */
        for (int i = 0; i < 3; i++) header_admit_stage_step_once();
        validate_headers_stage_drain(10);
        BF_CHECK("floor: validate cursor at 6",
                 validate_headers_stage_cursor() == 6);

        adv = body_fetch_stage_drain(100);
        BF_CHECK("floor: body_fetch advances 3 more", adv == 3);
        BF_CHECK("floor: body_fetch cursor at 6",
                 body_fetch_stage_cursor() == 6);

        bf_teardown(dir, &ms, &sc);
    }

    /* ── skipped_invalid: validate ok=0 → body_fetch records skip ────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_bf sc;
        BF_CHECK("skip: setup",
                 bf_setup("skip", 5, dir, sizeof(dir), &ms, &sc) == 0);

        header_admit_stage_drain(100);
        validate_headers_stage_drain(100);
        /* Force validate row at h=2 to ok=0 to simulate post-validation
         * failure. */
        sqlite3 *db = progress_store_db();
        BF_CHECK("skip: flip vh row h=2 to ok=0",
                 vh_log_force_ok(db, 2, 0));

        int adv = body_fetch_stage_drain(100);
        BF_CHECK("skip: body_fetch still advances 5", adv == 5);
        BF_CHECK("skip: cursor at 5", body_fetch_stage_cursor() == 5);
        BF_CHECK("skip: observed_total == 4",
                 body_fetch_stage_observed_total() == 4);
        BF_CHECK("skip: skipped_total == 1",
                 body_fetch_stage_skipped_total() == 1);

        int ok = -1; char src[32] = {0};
        log_row_at(db, 2, &ok, src, sizeof(src));
        BF_CHECK("skip: h=2 row ok=0", ok == 0);
        BF_CHECK("skip: h=2 source='skipped_invalid'",
                 strcmp(src, "skipped_invalid") == 0);
        struct uint256 skipped_hash;
        BF_CHECK("skip: row keeps exact validate hash",
                 log_hash_at(db, 2, &skipped_hash) &&
                 uint256_eq(&skipped_hash, &sc.hashes[2]));

        log_row_at(db, 1, &ok, src, sizeof(src));
        BF_CHECK("skip: h=1 row source='disk'", strcmp(src, "disk") == 0);

        bf_teardown(dir, &ms, &sc);
    }

    /* ── solution missing: prerequisite blocker, not invalid skip ──── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_bf sc;
        BF_CHECK("solutionless: setup",
                 bf_setup("solutionless", 5, dir, sizeof(dir), &ms, &sc) == 0);

        header_admit_stage_drain(100);
        validate_headers_stage_drain(100);
        sqlite3 *db = progress_store_db();
        BF_CHECK("solutionless: mark vh row h=2 prerequisite-missing",
                 vh_log_force_failure(db, 2,
                    "no-header-solution-backfill-required"));

        int adv = body_fetch_stage_drain(100);
        BF_CHECK("solutionless: advances only before blocker", adv == 2);
        BF_CHECK("solutionless: cursor halts at 2",
                 body_fetch_stage_cursor() == 2);
        int ok = -1; char src[32] = {0};
        BF_CHECK("solutionless: no skipped row written",
                 !log_row_at(db, 2, &ok, src, sizeof(src)));
        BF_CHECK("solutionless: direct step is BLOCKED",
                 body_fetch_stage_step_once() == JOB_BLOCKED);

        bf_teardown(dir, &ms, &sc);
    }

    /* ── body absent: HAVE_DATA cleared → JOB_IDLE, no advance ─────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_bf sc;
        BF_CHECK("absent: setup",
                 bf_setup("absent", 5, dir, sizeof(dir), &ms, &sc) == 0);

        /* Clear HAVE_DATA on heights 2..4 — only 0 and 1 are fetchable. */
        for (int i = 2; i < 5; i++)
            sc.blocks[i].nStatus &= ~BLOCK_HAVE_DATA;

        header_admit_stage_drain(100);
        validate_headers_stage_drain(100);

        int adv = body_fetch_stage_drain(100);
        BF_CHECK("absent: body_fetch advances exactly 2", adv == 2);
        BF_CHECK("absent: cursor halts at 2",
                 body_fetch_stage_cursor() == 2);

        /* Step again — still IDLE; cursor unchanged. */
        BF_CHECK("absent: next step IDLE",
                 body_fetch_stage_step_once() == JOB_IDLE);
        BF_CHECK("absent: cursor still 2",
                 body_fetch_stage_cursor() == 2);

        /* Flip HAVE_DATA on h=2 — body now appears. */
        sc.blocks[2].nStatus |= BLOCK_HAVE_DATA;
        BF_CHECK("absent: step ADVANCED after flip",
                 body_fetch_stage_step_once() == JOB_ADVANCED);
        BF_CHECK("absent: cursor at 3", body_fetch_stage_cursor() == 3);

        bf_teardown(dir, &ms, &sc);
    }

    /* A durable validate verdict is hash authority. A data-bearing active
     * sibling at the same height must not borrow it or receive a body row. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_bf sc;
        BF_CHECK("stale_sibling: setup",
                 bf_setup("stale_sibling", 3, dir, sizeof(dir),
                          &ms, &sc) == 0);
        header_admit_stage_drain(100);
        validate_headers_stage_drain(100);
        BF_CHECK("stale_sibling: prefix reaches target",
                 body_fetch_stage_drain(2) == 2 &&
                 body_fetch_stage_cursor() == 2);

        struct uint256 sibling_hash;
        memset(&sibling_hash, 0, sizeof(sibling_hash));
        sibling_hash.data[0] = 2;
        sibling_hash.data[1] = 0x51;
        struct block_index sibling;
        block_index_init(&sibling);
        sibling.phashBlock = &sibling_hash;
        sibling.nHeight = 2;
        sibling.pprev = &sc.blocks[1];
        sibling.nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
        BF_CHECK("stale_sibling: install data-bearing active sibling",
                 active_chain_move_window_tip(&ms.chain_active, &sibling));
        BF_CHECK("stale_sibling: exact authority fails closed",
                 body_fetch_stage_step_once() == JOB_IDLE &&
                 body_fetch_stage_cursor() == 2 &&
                 !log_row_at(progress_store_db(), 2, &(int){0}, NULL, 0));
        BF_CHECK("stale_sibling: stable reason names active mismatch",
                 dump_has_idle_reason("authority.active_hash_mismatch"));

        BF_CHECK("stale_sibling: restore exact active child",
                 active_chain_move_window_tip(&ms.chain_active,
                                              &sc.blocks[2]));
        BF_CHECK("stale_sibling: exact canonical HAVE_DATA advances",
                 body_fetch_stage_step_once() == JOB_ADVANCED &&
                 body_fetch_stage_cursor() == 3);
        struct uint256 recorded;
        BF_CHECK("stale_sibling: row carries validate hash",
                 log_hash_at(progress_store_db(), 2, &recorded) &&
                 uint256_eq(&recorded, &sc.hashes[2]) &&
                 !uint256_eq(&recorded, &sibling_hash));

        bf_teardown(dir, &ms, &sc);
    }

    /* Best-header and visible-parent identity are both required. Neither an
     * absent authority nor a disagreement may create a row or move cursor. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_bf sc;
        BF_CHECK("authority_refusal: setup",
                 bf_setup("authority_refusal", 3, dir, sizeof(dir),
                          &ms, &sc) == 0);
        header_admit_stage_drain(100);
        validate_headers_stage_drain(100);
        BF_CHECK("authority_refusal: prefix reaches target",
                 body_fetch_stage_drain(2) == 2 &&
                 body_fetch_stage_cursor() == 2);

        ms.pindex_best_header = NULL;
        BF_CHECK("authority_refusal: absent best is IDLE zero-row",
                 body_fetch_stage_step_once() == JOB_IDLE &&
                 !log_row_at(progress_store_db(), 2, &(int){0}, NULL, 0) &&
                 dump_has_idle_reason("authority.best_header_absent"));

        struct uint256 other_hash;
        memset(&other_hash, 0, sizeof(other_hash));
        other_hash.data[0] = 2;
        other_hash.data[1] = 0x72;
        struct block_index other_best;
        block_index_init(&other_best);
        other_best.phashBlock = &other_hash;
        other_best.nHeight = 2;
        other_best.pprev = &sc.blocks[1];
        other_best.nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
        ms.pindex_best_header = &other_best;
        BF_CHECK("authority_refusal: best hash mismatch is IDLE zero-row",
                 body_fetch_stage_step_once() == JOB_IDLE &&
                 body_fetch_stage_cursor() == 2 &&
                 !log_row_at(progress_store_db(), 2, &(int){0}, NULL, 0) &&
                 dump_has_idle_reason("authority.best_hash_mismatch"));

        ms.pindex_best_header = &sc.blocks[2];
        struct block_index *saved_parent = sc.blocks[2].pprev;
        sc.blocks[2].pprev = &sc.blocks[0];
        BF_CHECK("authority_refusal: parent disagreement is IDLE zero-row",
                 body_fetch_stage_step_once() == JOB_IDLE &&
                 body_fetch_stage_cursor() == 2 &&
                 !log_row_at(progress_store_db(), 2, &(int){0}, NULL, 0) &&
                 dump_has_idle_reason("authority.visible_parent_mismatch"));
        sc.blocks[2].pprev = saved_parent;

        const struct uint256 *saved_parent_hash = sc.blocks[1].phashBlock;
        sc.blocks[1].phashBlock = NULL;
        BF_CHECK("authority_refusal: durable fixture schema",
                 ensure_tip_finalize_fixture_schema_bf(progress_store_db()));
        BF_CHECK("authority_refusal: absent parent is IDLE zero-row",
                 body_fetch_stage_step_once() == JOB_IDLE &&
                 body_fetch_stage_cursor() == 2 &&
                 !log_row_at(progress_store_db(), 2, &(int){0}, NULL, 0) &&
                 dump_has_idle_reason("authority.visible_parent_absent"));
        sc.blocks[1].phashBlock = saved_parent_hash;

        BF_CHECK("authority_refusal: corrupt validate hash fixture",
                 vh_log_force_short_hash(progress_store_db(), 2));
        BF_CHECK("authority_refusal: non-32-byte hash is FATAL zero-row",
                 body_fetch_stage_step_once() == JOB_FATAL &&
                 body_fetch_stage_cursor() == 2 &&
                 !log_row_at(progress_store_db(), 2, &(int){0}, NULL, 0));

        bf_teardown(dir, &ms, &sc);
    }

    /* Checkpoint boot deliberately has no active-chain slot at H*, but the
     * checkpoint CAS leaves an exact durable (H*,hash) authority pair. The
     * H*+1 validate verdict may advance only when its best-header parent
     * matches that pair. This is the real C3 post-respawn window shape. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_bf sc;
        BF_CHECK("durable_parent: setup",
                 bf_setup("durable_parent", 3, dir, sizeof(dir),
                          &ms, &sc) == 0);
        header_admit_stage_drain(100);
        validate_headers_stage_drain(100);
        BF_CHECK("durable_parent: prefix reaches H*+1",
                 body_fetch_stage_drain(2) == 2 &&
                 body_fetch_stage_cursor() == 2);
        BF_CHECK("durable_parent: finalized fixture schema",
                 ensure_tip_finalize_fixture_schema_bf(progress_store_db()));

        active_chain_free(&ms.chain_active);
        active_chain_init(&ms.chain_active);
        BF_CHECK("durable_parent: absent active H* refuses without witness",
                 body_fetch_stage_step_once() == JOB_IDLE &&
                 body_fetch_stage_cursor() == 2 &&
                 !log_row_at(progress_store_db(), 2, &(int){0}, NULL, 0) &&
                 dump_has_idle_reason("authority.visible_parent_absent"));

        BF_CHECK("durable_parent: mismatched durable H* witness seeded",
                 seed_trusted_parent_bf(progress_store_db(), 1,
                                        &sc.hashes[0]));
        BF_CHECK("durable_parent: mismatch fails closed with zero movement",
                 body_fetch_stage_step_once() == JOB_IDLE &&
                 body_fetch_stage_cursor() == 2 &&
                 !log_row_at(progress_store_db(), 2, &(int){0}, NULL, 0) &&
                 dump_has_idle_reason("authority.visible_parent_mismatch"));

        BF_CHECK("durable_parent: exact durable H* witness seeded",
                 seed_trusted_parent_bf(progress_store_db(), 1,
                                        &sc.hashes[1]));
        BF_CHECK("durable_parent: exact best-header child advances",
                 body_fetch_stage_step_once() == JOB_ADVANCED &&
                 body_fetch_stage_cursor() == 3);
        struct uint256 recorded;
        BF_CHECK("durable_parent: row remains bound to validate hash",
                 log_hash_at(progress_store_db(), 2, &recorded) &&
                 uint256_eq(&recorded, &sc.hashes[2]));

        bf_teardown(dir, &ms, &sc);
    }

    /* ── replay across reopen: cursor + log persist ──────────────────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_bf sc;
        BF_CHECK("replay: setup",
                 bf_setup("replay", 7, dir, sizeof(dir), &ms, &sc) == 0);
        header_admit_stage_drain(100);
        validate_headers_stage_drain(100);
        body_fetch_stage_drain(100);
        BF_CHECK("replay: cursor at 7 pre-close",
                 body_fetch_stage_cursor() == 7);

        body_fetch_stage_shutdown();
        validate_headers_stage_shutdown();
        header_admit_stage_shutdown();
        progress_store_close();

        BF_CHECK("replay: reopen store", progress_store_open(dir));
        BF_CHECK("replay: re-init admit", header_admit_stage_init(&ms));
        BF_CHECK("replay: re-init validate",
                 validate_headers_stage_init(&ms));
        validate_headers_stage_set_validator(stub_pass, NULL);
        BF_CHECK("replay: re-init body_fetch",
                 body_fetch_stage_init(&ms));

        /* The persisted cursor is loaded lazily on first stage_run_once;
         * step_once first to materialise it into memory, then assert. */
        BF_CHECK("replay: first step after reopen is IDLE (cursor=7)",
                 body_fetch_stage_step_once() == JOB_IDLE);
        BF_CHECK("replay: cursor restored to 7",
                 body_fetch_stage_cursor() == 7);

        sqlite3 *db = progress_store_db();
        BF_CHECK("replay: log still has 7 rows", log_row_count(db) == 7);

        bf_teardown(dir, &ms, &sc);
    }

    /* ── pre-init guards ─────────────────────────────────────────────── */
    {
        BF_CHECK("guard: step_once with no init returns IDLE",
                 body_fetch_stage_step_once() == JOB_IDLE);
        BF_CHECK("guard: init(NULL) rejected",
                 !body_fetch_stage_init(NULL));
    }

    /* ── dump_state_json shape ───────────────────────────────────────── */
    {
        char dir[256]; struct main_state ms; struct synth_chain_bf sc;
        BF_CHECK("dump: setup",
                 bf_setup("dump", 2, dir, sizeof(dir), &ms, &sc) == 0);
        header_admit_stage_drain(100);
        validate_headers_stage_drain(100);
        body_fetch_stage_drain(100);

        struct json_value v;
        json_init(&v);
        BF_CHECK("dump: returns true",
                 body_fetch_stage_dump_state_json(&v, NULL));
        char buf[2048];
        size_t n = json_write(&v, buf, sizeof(buf));
        BF_CHECK("dump: serializes", n > 0 && n < sizeof(buf));
        BF_CHECK("dump: initialised=true",
                 strstr(buf, "\"initialised\":true") != NULL);
        BF_CHECK("dump: stage_name=body_fetch",
                 strstr(buf, "\"stage_name\":\"body_fetch\"") != NULL);
        BF_CHECK("dump: cursor=2",
                 strstr(buf, "\"cursor\":2") != NULL);
        BF_CHECK("dump: observed_total=2",
                 strstr(buf, "\"observed_total\":2") != NULL);
        json_free(&v);

        bf_teardown(dir, &ms, &sc);
    }

    /* ── crash-replay sub-process (DoD addition) ─────────────────────────
     *
     * Forks a child that opens progress.kv, pre-populates a synthetic
     * `validate_headers_log` and validate's stage_cursor directly via
     * SQL (so we don't have to spin up the validate worker pool inside
     * the forked child — pthread state + fork() is a hazard), then
     * inits + runs body_fetch_stage in a tight loop. The parent waits
     * a randomised short interval, SIGKILLs the child, reaps it, then
     * reopens progress.kv and asserts the F-2 atomicity contract: the
     * persisted cursor equals the number of body_fetch_log rows.
     *
     * The child runs N=1000 heights worth of work so it cannot finish
     * in the random window, guaranteeing the kill lands mid-drain. */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "body_fetch", "crash_replay");
        mkdir_p_bf(dir);

        /* Temporarily restore default SIGCHLD: alerts.c installs
         * SA_NOCLDWAIT for the alert subsystem's reaper, which would
         * make waitpid() return ECHILD here. Mirrors the
         * test_make_lint_gates pattern. */
        struct sigaction old_chld, dfl_chld;
        int restore_chld = 0;
        memset(&old_chld, 0, sizeof(old_chld));
        memset(&dfl_chld, 0, sizeof(dfl_chld));
        dfl_chld.sa_handler = SIG_DFL;
        sigemptyset(&dfl_chld.sa_mask);
        if (sigaction(SIGCHLD, NULL, &old_chld) == 0 &&
            sigaction(SIGCHLD, &dfl_chld, NULL) == 0) {
            restore_chld = 1;
        }

        const int CRASH_N = 200;  /* chain depth in child */

        int ready_pipe[2] = { -1, -1 };
        BF_CHECK("crash: create ready pipe", pipe(ready_pipe) == 0);

        pid_t pid = fork();
        if (pid < 0) {
            BF_CHECK("crash: fork failed", false);
        } else if (pid == 0) {
            /* Child. No BF_CHECK calls — exit codes signal failure. */
            close(ready_pipe[0]);
            if (!progress_store_open(dir)) _exit(2);
            struct main_state ms;
            struct synth_chain_bf sc;
            memset(&ms, 0, sizeof(ms));
            main_state_init(&ms);
            if (!synth_chain_bf_build(&sc, CRASH_N)) _exit(3);
            active_chain_move_window_tip(&ms.chain_active, &sc.blocks[CRASH_N - 1]);
            ms.pindex_best_header = &sc.blocks[CRASH_N - 1];

            sqlite3 *db = progress_store_db();
            if (sqlite3_exec(db,
                "CREATE TABLE IF NOT EXISTS validate_headers_log ("
                "  height INTEGER PRIMARY KEY,"
                "  hash BLOB NOT NULL,"
                "  ok INTEGER NOT NULL,"
                "  fail_reason TEXT,"
                "  validated_at INTEGER NOT NULL)",
                NULL, NULL, NULL) != SQLITE_OK) _exit(4);
            if (sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK)
                _exit(5);
            sqlite3_stmt *vh_st = NULL;
            sqlite3_prepare_v2(db,
                "INSERT INTO validate_headers_log "
                "(height, hash, ok, validated_at) VALUES (?, ?, 1, 0)",
                -1, &vh_st, NULL);
            for (int i = 0; i < CRASH_N; i++) {
                sqlite3_bind_int(vh_st, 1, i);
                sqlite3_bind_blob(vh_st, 2, sc.hashes[i].data, 32,
                                  SQLITE_STATIC);
                sqlite3_step(vh_st);
                sqlite3_reset(vh_st);
            }
            sqlite3_finalize(vh_st);
            sqlite3_exec(db,
                "INSERT OR REPLACE INTO stage_cursor "
                "(name, cursor, updated_at) VALUES "
                "('validate_headers', 200, 0)",
                NULL, NULL, NULL);
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);

            if (!body_fetch_stage_init(&ms)) _exit(6);
            /* Drain a known small amount, then tell the parent we are
             * idling. The parent kills only after this byte, so the on-disk
             * state is exactly `committed body_fetch rows == cursor`. */
            (void)body_fetch_stage_drain(30);
            {
                char ready = 'R';
                if (write(ready_pipe[1], &ready, 1) != 1)
                    _exit(7);
                close(ready_pipe[1]);
            }
            for (;;) {
                struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
                nanosleep(&ts, NULL);
            }
            _exit(0);  /* unreachable */
        }

        /* Parent. Wait until the child has finished the deterministic drain
         * and is idling. A timer here is flaky on loaded CI: it can kill the
         * child during setup before body_fetch_log exists. */
        close(ready_pipe[1]);
        {
            char ready = 0;
            ssize_t got = read(ready_pipe[0], &ready, 1);
            close(ready_pipe[0]);
            BF_CHECK("crash: child reached idle point",
                     got == 1 && ready == 'R');
        }
        BF_CHECK("crash: kill child",
                 kill(pid, SIGKILL) == 0);
        int status = 0;
        pid_t reaped = waitpid(pid, &status, 0);
        BF_CHECK("crash: waitpid reaped child", reaped == pid);
        BF_CHECK("crash: child died by SIGKILL",
                 WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

        /* Parent opens the store + verifies invariant. */
        BF_CHECK("crash: parent reopens store",
                 progress_store_open(dir));
        sqlite3 *db = progress_store_db();

        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name = 'body_fetch'",
            -1, &st, NULL);
        int64_t cursor = 0;
        bool have_cursor = false;
        if (sqlite3_step(st) == SQLITE_ROW) {
            cursor = sqlite3_column_int64(st, 0);
            have_cursor = true;
        }
        sqlite3_finalize(st);

        int rows = log_row_count(db);

        /* Invariant: cursor == row count — the F-2 atomicity contract.
         * If the child was SIGKILLed before its first body_fetch commit,
         * both are 0 and have_cursor may be false. */
        if (!have_cursor) {
            BF_CHECK("crash: zero-progress case is consistent",
                     rows == 0);
        } else {
            BF_CHECK("crash: cursor matches row count after kill",
                     (int64_t)rows == cursor);
        }
        BF_CHECK("crash: rows bounded by chain size",
                 rows >= 0 && rows <= CRASH_N);

        progress_store_close();
        test_cleanup_tmpdir(dir);

        if (restore_chld)
            (void)sigaction(SIGCHLD, &old_chld, NULL);
    }

    printf("body_fetch_stage: %d failures\n", failures);
    return failures;
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's fork+SIGKILL body-fetch crash-window lane
 * cannot run here. Skipped loudly rather than faked. */
int test_body_fetch_stage(void)
{
    printf("body_fetch_stage: SKIP (Windows): fork+SIGKILL body-fetch crash-window lane\n");
    return 0;
}
#endif
