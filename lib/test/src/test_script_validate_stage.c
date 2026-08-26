/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Unit tests for Wave S S-6 script_validate stage. */

#include "test/test_core.h"
#include "test/block_fixtures.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "jobs/created_outputs_index.h"
#include "jobs/reducer_frontier.h"
#include "jobs/script_validate_stage.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
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

/* src-private util helpers (app/jobs/src/stage_repair_coin_backfill_util.h):
 * the STEP-2A pending-prevout HOLD signal getter + the shared hole finder that
 * coin_backfill (G2) and the boot torn-import gate consult. Forward-declared
 * here — same pattern as test_stage_repair_coin_backfill.c — to drive the REAL
 * stage and assert the HOLD arms the repair WITHOUT a hand-seeded ok=0 row. */
bool coin_backfill_pending_prevout_get(struct sqlite3 *db, int *out_height,
                                       struct uint256 *out_block_hash,
                                       struct uint256 *out_txid, int *out_vin,
                                       bool *out_found);
bool find_lowest_prevout_unresolved_hole_unlocked(
    struct sqlite3 *db, int cursor, const char *wanted_status, int *out_height,
    char status_out[32], struct uint256 *hash_out, bool *hash_found);

/* Root-cause chaining exemplar (app/jobs/src/script_validate_stage.c,
 * non-static for this reason): the body-availability-blocker discovery a
 * prevout_unresolved HOLD uses to wire caused_by. Driven directly here
 * because the real HOLD-to-PERMANENT-blocker transition is gated by a
 * real-wall-clock 10-minute budget (SV_UNRESOLVED_BUDGET_SECONDS) that a
 * fast test must not wait out. */
const char *sv_find_body_availability_cause(struct blocker_snapshot *snap_out);

#define SV_CHECK(name, expr) do { \
    printf("script_validate: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

struct synth_chain_sv {
    struct block_index *blocks;
    struct uint256     *hashes;
    struct block       *bodies;
    struct uint256     *prev_hashes;
    struct tx_out      *prevouts;
    int                 n;
    int                 invalid_height;
    int                 missing_prevout_height;
    int                 no_data_height;
    int                 read_fail_height;  /* fake_reader() fails here */
};

static int mkdir_p_sv(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static void make_prevout(struct tx_out *out, bool valid)
{
    tx_out_set_null(out);
    out->value = 100000000;
    script_init(&out->script_pub_key);
    script_push_op(&out->script_pub_key, valid ? OP_TRUE : OP_FALSE);
}

static bool make_body(struct synth_chain_sv *sc, int h)
{
    struct block *b = &sc->bodies[h];
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700000000u + (uint32_t)h);
    b->header.nBits = 0x1f07ffff;
    b->num_vtx = 2;
    b->vtx = zcl_calloc(2, sizeof(struct transaction), "sv_tx");
    if (!b->vtx) return false;

    transaction_init(&b->vtx[0]);
    if (!transaction_alloc(&b->vtx[0], 1, 1)) return false;
    outpoint_set_null(&b->vtx[0].vin[0].prevout);
    script_push_data(&b->vtx[0].vin[0].script_sig, (const unsigned char *)&h,
                     sizeof(h));
    b->vtx[0].vout[0] = sc->prevouts[h];
    transaction_compute_hash(&b->vtx[0]);
    sc->prev_hashes[h] = b->vtx[0].hash;

    transaction_init(&b->vtx[1]);
    if (!transaction_alloc(&b->vtx[1], 1, 1)) return false;
    b->vtx[1].vin[0].prevout.hash = sc->prev_hashes[h];
    b->vtx[1].vin[0].prevout.n = 0;
    script_init(&b->vtx[1].vin[0].script_sig);
    b->vtx[1].vout[0].value = 99900000;
    script_init(&b->vtx[1].vout[0].script_pub_key);
    script_push_op(&b->vtx[1].vout[0].script_pub_key, OP_TRUE);
    transaction_compute_hash(&b->vtx[1]);

    struct uint256 txids[2] = { b->vtx[0].hash, b->vtx[1].hash };
    b->header.hashMerkleRoot = compute_merkle_root(txids, 2);
    return true;
}

static bool synth_chain_sv_build(struct synth_chain_sv *sc, int n)
{
    memset(sc, 0, sizeof(*sc));
    sc->invalid_height = -1;
    sc->missing_prevout_height = -1;
    sc->no_data_height = -1;
    sc->read_fail_height = -1;
    sc->blocks = zcl_calloc((size_t)n, sizeof(struct block_index),
                            "sv_blocks");
    sc->hashes = zcl_calloc((size_t)n, sizeof(struct uint256),
                            "sv_hashes");
    sc->bodies = zcl_calloc((size_t)n, sizeof(struct block),
                            "sv_bodies");
    sc->prev_hashes = zcl_calloc((size_t)n, sizeof(struct uint256),
                                 "sv_prev_hashes");
    sc->prevouts = zcl_calloc((size_t)n, sizeof(struct tx_out),
                              "sv_prevouts");
    if (!sc->blocks || !sc->hashes || !sc->bodies ||
        !sc->prev_hashes || !sc->prevouts)
        return false;
    for (int i = 0; i < n; i++) {
        make_prevout(&sc->prevouts[i], true);
        if (!make_body(sc, i)) return false;
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

static void synth_chain_sv_free(struct synth_chain_sv *sc)
{
    if (sc->bodies) {
        for (int i = 0; i < sc->n; i++)
            block_free(&sc->bodies[i]);
    }
    free(sc->blocks);
    free(sc->hashes);
    free(sc->bodies);
    free(sc->prev_hashes);
    free(sc->prevouts);
    memset(sc, 0, sizeof(*sc));
}

static bool fake_reader(struct block *out, const struct block_index *bi,
                        const char *datadir, void *user)
{
    (void)datadir;
    struct synth_chain_sv *sc = user;
    if (!out || !bi || !sc || bi->nHeight < 0 || bi->nHeight >= sc->n)
        return false;
    if (bi->nHeight == sc->read_fail_height)
        return false;  /* simulate on-disk bytes vanished/corrupted */
    return test_block_copy(out, &sc->bodies[bi->nHeight], "sv_tx_copy");
}

static bool fake_prevout(const struct outpoint *prevout, struct tx_out *out,
                         void *user)
{
    struct synth_chain_sv *sc = user;
    if (!prevout || !out || !sc) return false;
    for (int h = 0; h < sc->n; h++) {
        if (h == sc->missing_prevout_height)
            continue;
        if (uint256_eq(&prevout->hash, &sc->prev_hashes[h]) &&
            prevout->n == 0) {
            *out = sc->prevouts[h];
            if (h == sc->invalid_height) {
                script_init(&out->script_pub_key);
                script_push_op(&out->script_pub_key, OP_FALSE);
            }
            return true;
        }
    }
    return false;
}

static bool retarget_spend(struct synth_chain_sv *sc, int spend_h,
                           int created_h)
{
    if (!sc || spend_h < 0 || spend_h >= sc->n ||
        created_h < 0 || created_h >= sc->n)
        return false;
    struct block *b = &sc->bodies[spend_h];
    b->vtx[1].vin[0].prevout.hash = sc->prev_hashes[created_h];
    b->vtx[1].vin[0].prevout.n = 0;
    transaction_compute_hash(&b->vtx[1]);
    struct uint256 txids[2] = { b->vtx[0].hash, b->vtx[1].hash };
    b->header.hashMerkleRoot = compute_merkle_root(txids, 2);
    block_header_get_hash(&b->header, &sc->hashes[spend_h]);
    sc->blocks[spend_h].hashMerkleRoot = b->header.hashMerkleRoot;
    return true;
}

static bool seed_coins_frontier(sqlite3 *db, int32_t frontier)
{
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    bool ok = coins_kv_set_applied_height_in_tx(db, frontier);
    if (ok)
        ok = sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (!ok)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    if (err) sqlite3_free(err);
    return ok;
}

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool seed_body_persist(sqlite3 *db, int n, int upstream_fail_height)
{
    if (!exec_sql(db,
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height       INTEGER PRIMARY KEY,"
        "  source       TEXT    NOT NULL,"
        "  ok           INTEGER NOT NULL,"
        "  persisted_at INTEGER NOT NULL"
        ")"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO body_persist_log "
        "(height, source, ok, persisted_at) VALUES (?, ?, ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h < n; h++) {
        int ok = (h == upstream_fail_height) ? 0 : 1;
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_text(st, 2, ok ? "verified" : "upstream_failed",
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
        "VALUES('body_persist', ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, n);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool log_row_at(sqlite3 *db, int height, int *out_ok,
                       char *out_status, size_t status_size,
                       int *out_vin)
{
    *out_ok = -1;
    *out_vin = -2;
    if (out_status && status_size) out_status[0] = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT ok, status, first_failure_vin FROM script_validate_log "
        "WHERE height = ?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(st, 1, height);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *out_ok = sqlite3_column_int(st, 0);
        const unsigned char *txt = sqlite3_column_text(st, 1);
        if (txt && out_status && status_size)
            snprintf(out_status, status_size, "%s", (const char *)txt);
        *out_vin = sqlite3_column_type(st, 2) == SQLITE_NULL
            ? -1 : sqlite3_column_int(st, 2);
        found = true;
    }
    sqlite3_finalize(st);
    return found;
}

static int sv_setup(const char *tag, int n, int upstream_fail_height,
                    char *dir_out, size_t dir_out_size,
                    struct main_state *ms, struct synth_chain_sv *sc)
{
    test_fmt_tmpdir(dir_out, dir_out_size, "script_validate", tag);
    mkdir_p_sv("./test-tmp");
    mkdir_p_sv(dir_out);
    if (!progress_store_open(dir_out)) return 1;

    memset(ms, 0, sizeof(*ms));
    active_chain_init(&ms->chain_active);
    if (!synth_chain_sv_build(sc, n)) return 2;
    active_chain_move_window_tip(&ms->chain_active, &sc->blocks[n - 1]);

    if (!seed_body_persist(progress_store_db(), n, upstream_fail_height))
        return 3;
    if (!script_validate_stage_init(ms)) return 4;
    script_validate_stage_set_reader(fake_reader, sc);
    script_validate_stage_set_prevout_resolver(fake_prevout, sc);
    return 0;
}

static void sv_teardown(const char *dir, struct main_state *ms,
                        struct synth_chain_sv *sc)
{
    script_validate_stage_shutdown();
    active_chain_free(&ms->chain_active);
    synth_chain_sv_free(sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

int test_script_validate_stage(void);
int test_script_validate_stage(void)
{
    printf("\n=== script_validate_stage tests ===\n");
    int failures = 0;

    blocker_module_init();

    {
        char dir[256]; struct main_state ms; struct synth_chain_sv sc;
        SV_CHECK("happy: setup",
                 sv_setup("happy", 3, -1, dir, sizeof(dir), &ms, &sc) == 0);
        SV_CHECK("happy: drains 3", script_validate_stage_drain(100) == 3);
        SV_CHECK("happy: cursor at 3", script_validate_stage_cursor() == 3);
        SV_CHECK("happy: verified_total == 3",
                 script_validate_stage_verified_total() == 3);
        SV_CHECK("happy: inputs_verified_total == 3",
                 script_validate_stage_inputs_verified_total() == 3);
        for (int h = 0; h < 3; h++) {
            int ok = -1, vin = -2; char status[32];
            log_row_at(progress_store_db(), h, &ok, status, sizeof(status),
                       &vin);
            SV_CHECK("happy: row ok=1", ok == 1);
            SV_CHECK("happy: row status verified",
                     strcmp(status, "verified") == 0);
            SV_CHECK("happy: failure vin null", vin == -1);
        }
        SV_CHECK("happy: next step IDLE",
                 script_validate_stage_step_once() == JOB_IDLE);
        sv_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_sv sc;
        SV_CHECK("script_invalid: setup",
                 sv_setup("invalid", 3, -1, dir, sizeof(dir), &ms, &sc) == 0);
        sc.invalid_height = 1;
        SV_CHECK("script_invalid: drains 3",
                 script_validate_stage_drain(100) == 3);
        SV_CHECK("script_invalid: counter == 1",
                 script_validate_stage_script_invalid_total() == 1);
        int ok = -1, vin = -2; char status[32];
        log_row_at(progress_store_db(), 1, &ok, status, sizeof(status),
                   &vin);
        SV_CHECK("script_invalid: h=1 ok=0", ok == 0);
        SV_CHECK("script_invalid: h=1 status",
                 strcmp(status, "script_invalid") == 0);
        SV_CHECK("script_invalid: first vin 0", vin == 0);
        sv_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_sv sc;
        SV_CHECK("upstream_failed: setup",
                 sv_setup("upstream", 3, 2, dir, sizeof(dir), &ms, &sc) == 0);
        SV_CHECK("upstream_failed: drains 3",
                 script_validate_stage_drain(100) == 3);
        SV_CHECK("upstream_failed: counter == 1",
                 script_validate_stage_upstream_failed_total() == 1);
        int ok = -1, vin = -2; char status[32];
        log_row_at(progress_store_db(), 2, &ok, status, sizeof(status),
                   &vin);
        SV_CHECK("upstream_failed: h=2 ok=0", ok == 0);
        SV_CHECK("upstream_failed: h=2 status",
                 strcmp(status, "upstream_failed") == 0);
        sv_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_sv sc;
        SV_CHECK("upstream_storage: setup",
                 sv_setup("upstream_storage", 2, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        SV_CHECK("upstream_storage: BLOB ok fixture",
                 exec_sql(progress_store_db(),
                          "UPDATE body_persist_log SET ok=X'01' "
                          "WHERE height=0"));
        SV_CHECK("upstream_storage: BLOB ok cannot advance",
                 script_validate_stage_step_once() != JOB_ADVANCED &&
                 script_validate_stage_cursor() == 0);
        SV_CHECK("upstream_storage: restore ok and inject NUL source",
                 exec_sql(progress_store_db(),
                          "UPDATE body_persist_log SET ok=1,"
                          "source=CAST(X'76657269666965640078' AS TEXT) "
                          "WHERE height=0"));
        SV_CHECK("upstream_storage: embedded-NUL source cannot advance",
                 script_validate_stage_step_once() != JOB_ADVANCED &&
                 script_validate_stage_cursor() == 0);
        int ok = -1, vin = -2; char status[32];
        SV_CHECK("upstream_storage: no verdict was authored",
                 !log_row_at(progress_store_db(), 0, &ok, status,
                             sizeof(status), &vin));
        sv_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_sv sc;
        SV_CHECK("internal_error: setup",
                 sv_setup("internal", 3, -1, dir, sizeof(dir), &ms, &sc) == 0);
        sc.missing_prevout_height = 1;
        /* STEP 2A: prevout_unresolved is a TRANSIENT "cannot determine yet",
         * NOT a permanent reject. The stage HOLDS the cursor at the hole — no
         * terminal ok=0 row, no advance — and re-derives next tick. So the drain
         * stops at the hole (only h=0 advances) and NO row is written at h=1. */
        SV_CHECK("internal_error: drains only up to the hole",
                 script_validate_stage_drain(100) == 1);
        SV_CHECK("internal_error: cursor held at the hole (1)",
                 script_validate_stage_cursor() == 1);
        SV_CHECK("internal_error: counter == 1 (one held height)",
                 script_validate_stage_internal_error_total() == 1);
        int ok = -1, vin = -2; char status[32];
        bool row = log_row_at(progress_store_db(), 1, &ok, status,
                              sizeof(status), &vin);
        SV_CHECK("internal_error: no terminal row written at the hole",
                 !row && ok == -1);
        sv_teardown(dir, &ms, &sc);
    }

    {
        /* STEP-2A torn-coin remedy (never-stuck-invariant-0): the real stage
         * HOLDS on a torn pre-anchor coin (no terminal ok=0 row), but it MUST
         * still publish the NON-TERMINAL pending-prevout signal — the TRIGGER
         * that arms coin_backfill's G2 hole finder and the boot torn gate. For
         * a genuinely torn coin re-derivation alone never resolves, so without
         * this signal the torn-coins class would lose its auto-terminating
         * remedy owner. This drives the REAL stage (NOT a hand-seeded ok=0 row),
         * asserts the signal is published AND found by the shared hole finder,
         * then resolves the coin (as coin_backfill re-inserts it) and asserts
         * H* advances and the signal clears — auto-termination, no operator, no
         * terminal reject. */
        char dir[256]; struct main_state ms; struct synth_chain_sv sc;
        SV_CHECK("torn_hold_signal: setup",
                 sv_setup("torn_hold", 3, -1, dir, sizeof(dir), &ms, &sc) == 0);
        sc.missing_prevout_height = 1;        /* coin for h=1's spend is torn */
        SV_CHECK("torn_hold_signal: drains only up to the hole",
                 script_validate_stage_drain(100) == 1);
        SV_CHECK("torn_hold_signal: cursor HELD at the hole (1)",
                 script_validate_stage_cursor() == 1);
        int ok0 = -1, vin0 = -2; char st0[32];
        SV_CHECK("torn_hold_signal: no terminal ok=0 row at the hole",
                 !log_row_at(progress_store_db(), 1, &ok0, st0, sizeof(st0),
                             &vin0));

        /* (1) the non-terminal pending signal is published with the hole's
         *     coordinates (height, block_hash, first-failure txid+vin). */
        int ph = -1, pvin = -1; struct uint256 phash, ptxid; bool pf = false;
        SV_CHECK("torn_hold_signal: pending signal read",
                 coin_backfill_pending_prevout_get(progress_store_db(), &ph,
                                                   &phash, &ptxid, &pvin, &pf));
        SV_CHECK("torn_hold_signal: pending signal present", pf);
        SV_CHECK("torn_hold_signal: pending height == hole (1)", ph == 1);
        SV_CHECK("torn_hold_signal: pending block_hash == hole block",
                 uint256_eq(&phash, &sc.hashes[1]));
        SV_CHECK("torn_hold_signal: pending txid == spender",
                 uint256_eq(&ptxid, &sc.bodies[1].vtx[1].hash));
        SV_CHECK("torn_hold_signal: pending vin == 0", pvin == 0);

        /* (2) coin_backfill's hole finder + the boot torn gate are ARMED by the
         *     pending signal alone (no ok=0 row exists). Use cursor == hole —
         *     the exact frozen-cursor call backfill_run makes (script_validate
         *     is HELD at the hole, so its cursor equals hole_h). */
        int hh = -1; char hst[32]; struct uint256 hhash; bool hf = false;
        progress_store_tx_lock();
        bool found_hole = find_lowest_prevout_unresolved_hole_unlocked(
            progress_store_db(), 1, "prevout_unresolved", &hh, hst, &hhash,
            &hf);
        progress_store_tx_unlock();
        SV_CHECK("torn_hold_signal: hole finder returns ok", found_hole);
        SV_CHECK("torn_hold_signal: hole finder found the hole (1)", hh == 1);
        SV_CHECK("torn_hold_signal: hole finder hash-bound",
                 hf && uint256_eq(&hhash, &sc.hashes[1]));
        SV_CHECK("torn_hold_signal: hole status prevout_unresolved",
                 strcmp(hst, "prevout_unresolved") == 0);

        /* (3) coin_backfill re-inserts the missing coin; the next HOLD
         *     re-derivation now resolves ok=1, H* advances, the signal clears —
         *     the torn-coins class terminates on its own, no operator. */
        sc.missing_prevout_height = -1;       /* coin now resolvable */
        SV_CHECK("torn_hold_signal: H* climbs once the coin is restored",
                 script_validate_stage_drain(100) == 2);
        SV_CHECK("torn_hold_signal: cursor advanced to tip (3)",
                 script_validate_stage_cursor() == 3);
        bool pf2 = true; int ph2 = -1;
        SV_CHECK("torn_hold_signal: pending signal read after resolve",
                 coin_backfill_pending_prevout_get(progress_store_db(), &ph2,
                                                   NULL, NULL, NULL, &pf2));
        SV_CHECK("torn_hold_signal: pending signal CLEARED on resolve", !pf2);
        sv_teardown(dir, &ms, &sc);
    }

    {
        /* Regression for wedge-retry: a transient internal_error dry-run
         * (missing prevout / sapling-ctx race) must report
         * dry.internal_error == true so the stale-script repair treats it
         * as retriable rather than a permanent "genuinely invalid" verdict.
         * If this flag were false, the repair would refuse to rewind and H*
         * would terminate on the first transient ok=0 row forever. */
        char dir[256]; struct main_state ms; struct synth_chain_sv sc;
        SV_CHECK("internal_error_dry_run: setup",
                 sv_setup("internal_dry", 3, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        sc.missing_prevout_height = 1;
        struct script_validate_dry_run_report dry;
        SV_CHECK("internal_error_dry_run: dry-run flags internal_error",
                 script_validate_stage_dry_run_block(&sc.bodies[1], 1,
                                                     &dry) &&
                 !dry.ok && dry.internal_error);
        sv_teardown(dir, &ms, &sc);
    }

    /* FIX A regression pin (wedge-retry, stage_repair_reducer_frontier_coin.c
     * maybe_repair_stale_script): the repair discriminates a TRANSIENT
     * internal_error (ok=0 + internal_error=true → one-shot rewind, retriable)
     * from a GENUINE consensus failure (ok=0 + internal_error=false →
     * stale_script_repair_genuinely_invalid refusal) on exactly this dry-run
     * contract. The block above pins the transient→rewind side; this block
     * pins the complementary genuine-invalid side: a block whose prevout
     * resolves to a failing script (OP_FALSE) must report internal_error=FALSE
     * so the repair takes the genuinely_invalid refusal branch, NOT the rewind.
     * If a regression ever set internal_error on a real script failure, the
     * repair would wrongly rewind a permanently-invalid block forever,
     * re-introducing the silent wedge class this fix deleted. An end-to-end
     * on-disk rewind fixture is not constructible in this unit-test infra
     * (stage_repair_read_active_block_checked preads real block files), so the
     * load-bearing dry-run contract that DRIVES the branch is pinned instead. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_sv sc;
        SV_CHECK("script_invalid_dry_run: setup",
                 sv_setup("invalid_dry", 3, -1, dir, sizeof(dir),
                          &ms, &sc) == 0);
        sc.invalid_height = 1;   /* prevout resolves to OP_FALSE */
        struct script_validate_dry_run_report dry;
        SV_CHECK("script_invalid_dry_run: dry-run is NOT ok",
                 script_validate_stage_dry_run_block(&sc.bodies[1], 1,
                                                     &dry) &&
                 !dry.ok);
        SV_CHECK("script_invalid_dry_run: internal_error FALSE (genuine)",
                 !dry.internal_error);
        sv_teardown(dir, &ms, &sc);
    }

    {
        char dir[256]; struct synth_chain_sv sc;
        test_fmt_tmpdir(dir, sizeof(dir), "script_validate",
                        "bounded_created");
        mkdir_p_sv("./test-tmp");
        mkdir_p_sv(dir);
        SV_CHECK("bounded_created: progress opens",
                 progress_store_open(dir));
        SV_CHECK("bounded_created: chain builds",
                 synth_chain_sv_build(&sc, 3));
        SV_CHECK("bounded_created: block2 spends block1 output",
                 retarget_spend(&sc, 2, 1));
        SV_CHECK("bounded_created: index schema",
                 created_outputs_index_ensure_schema(progress_store_db()));
        SV_CHECK("bounded_created: index block1",
                 created_outputs_index_put_block(progress_store_db(),
                                                 &sc.bodies[1], 1));
        SV_CHECK("bounded_created: seed frontier",
                 seed_coins_frontier(progress_store_db(), 1));
        struct script_validate_dry_run_report dry;
        SV_CHECK("bounded_created: dry-run resolves above-frontier coin",
                 script_validate_stage_dry_run_block(&sc.bodies[2], 2,
                                                     &dry) &&
                 dry.ok && strcmp(dry.status, "verified") == 0);
        synth_chain_sv_free(&sc);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    {
        char dir[256]; struct synth_chain_sv sc;
        test_fmt_tmpdir(dir, sizeof(dir), "script_validate",
                        "bounded_future_coin");
        mkdir_p_sv("./test-tmp");
        mkdir_p_sv(dir);
        SV_CHECK("bounded_future_coin: progress opens",
                 progress_store_open(dir));
        SV_CHECK("bounded_future_coin: chain builds",
                 synth_chain_sv_build(&sc, 3));
        struct uint256 future_txid;
        uint256_set_null(&future_txid);
        future_txid.data[0] = 0x77;
        future_txid.data[31] = 0x88;
        sc.bodies[2].vtx[1].vin[0].prevout.hash = future_txid;
        sc.bodies[2].vtx[1].vin[0].prevout.n = 0;
        transaction_compute_hash(&sc.bodies[2].vtx[1]);
        struct uint256 txids[2] = {
            sc.bodies[2].vtx[0].hash,
            sc.bodies[2].vtx[1].hash,
        };
        sc.bodies[2].header.hashMerkleRoot = compute_merkle_root(txids, 2);
        SV_CHECK("bounded_future_coin: index schema",
                 created_outputs_index_ensure_schema(progress_store_db()));
        SV_CHECK("bounded_future_coin: coin schema",
                 coins_kv_ensure_schema(progress_store_db()));
        unsigned char sc_true[1] = { OP_TRUE };
        SV_CHECK("bounded_future_coin: seed live future coin",
                 coins_kv_add(progress_store_db(), future_txid.data, 0,
                              100000000, 3, false, sc_true,
                              sizeof(sc_true)));
        SV_CHECK("bounded_future_coin: seed frontier ahead of block",
                 seed_coins_frontier(progress_store_db(), 4));
        struct script_validate_dry_run_report dry;
        SV_CHECK("bounded_future_coin: dry-run rejects future coin",
                 script_validate_stage_dry_run_block(&sc.bodies[2], 2,
                                                     &dry) &&
                 !dry.ok &&
                 strcmp(dry.status, "prevout_unresolved") == 0);
        synth_chain_sv_free(&sc);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_sv sc;
        SV_CHECK("idle: setup",
                 sv_setup("idle", 3, -1, dir, sizeof(dir), &ms, &sc) == 0);
        sqlite3_exec(progress_store_db(),
            "UPDATE stage_cursor SET cursor=1 WHERE name='body_persist'",
            NULL, NULL, NULL);
        SV_CHECK("idle: advances one",
                 script_validate_stage_drain(100) == 1);
        SV_CHECK("idle: next step IDLE",
                 script_validate_stage_step_once() == JOB_IDLE);
        SV_CHECK("idle: cursor stays 1",
                 script_validate_stage_cursor() == 1);
        sv_teardown(dir, &ms, &sc);
    }

    {
        SV_CHECK("guard: step_once with no init returns IDLE",
                 script_validate_stage_step_once() == JOB_IDLE);
        SV_CHECK("guard: init(NULL) rejected",
                 !script_validate_stage_init(NULL));
    }

    {
        char dir[256]; struct main_state ms; struct synth_chain_sv sc;
        SV_CHECK("dump: setup",
                 sv_setup("dump", 2, -1, dir, sizeof(dir), &ms, &sc) == 0);
        script_validate_stage_drain(100);
        struct json_value v;
        json_init(&v);
        SV_CHECK("dump: returns true",
                 script_validate_dump_state_json(&v, NULL));
        char buf[1024];
        size_t n = json_write(&v, buf, sizeof(buf));
        SV_CHECK("dump: serializes", n > 0 && n < sizeof(buf));
        SV_CHECK("dump: stage_name",
                 strstr(buf, "\"stage_name\":\"script_validate\"") != NULL);
        SV_CHECK("dump: cursor=2",
                 strstr(buf, "\"cursor\":2") != NULL);
        SV_CHECK("dump: verified_total=2",
                 strstr(buf, "\"verified_total\":2") != NULL);
        json_free(&v);
        sv_teardown(dir, &ms, &sc);
    }

    /* stall-taxonomy audit: stage_upstream_log_hole_note. A durable
     * hole (row deleted below the already-advanced upstream cursor — the
     * residue of a noncanonical-row purge in script_validate_log +
     * proof_validate_log, see docs/AGENT_TRAPS.md / reducer_frontier_
     * reconcile_light.c) must name a typed DEPENDENCY blocker immediately,
     * not rely solely on the 60-minute stage-freeze backstop. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_sv sc;
        SV_CHECK("upstream_log_hole: setup",
                 sv_setup("upstream_hole", 3, -1, dir, sizeof(dir), &ms,
                          &sc) == 0);
        /* body_persist's cursor is already at 3 (sv_setup's seed); delete
         * its row at height=1 to simulate the torn-invariant residue. */
        SV_CHECK("upstream_log_hole: delete row at height=1 below the floor",
                 exec_sql(progress_store_db(),
                          "DELETE FROM body_persist_log WHERE height=1"));
        SV_CHECK("upstream_log_hole: h=0 advances, holds at the hole",
                 script_validate_stage_drain(100) == 1);
        SV_CHECK("upstream_log_hole: cursor held at the hole (1)",
                 script_validate_stage_cursor() == 1);
        SV_CHECK("upstream_log_hole: stays JOB_IDLE, never JOB_BLOCKED",
                 script_validate_stage_step_once() == JOB_IDLE);

        struct blocker_snapshot uh_snaps[16];
        int uh_n = blocker_snapshot_all(uh_snaps, 16);
        bool uh_found = false, uh_fields_ok = false;
        for (int k = 0; k < uh_n; k++) {
            if (strcmp(uh_snaps[k].id,
                      "script_validate.upstream_log_hole") == 0) {
                uh_found = true;
                uh_fields_ok =
                    strstr(uh_snaps[k].reason, "body_persist_log") &&
                    strstr(uh_snaps[k].reason, "height=1") &&
                    uh_snaps[k].class == BLOCKER_DEPENDENCY;
                break;
            }
        }
        SV_CHECK("upstream_log_hole: typed blocker raised", uh_found);
        SV_CHECK("upstream_log_hole: blocker names the row + height + class "
                 "DEPENDENCY", uh_fields_ok);

        int ok = -1, vin = -2; char status[32];
        SV_CHECK("upstream_log_hole: no terminal row written at the hole",
                 !log_row_at(progress_store_db(), 1, &ok, status,
                             sizeof(status), &vin));

        /* The healer (reducer_frontier_reconcile_light, out of scope for
         * this unit test) refills the row on its own cadence; simulate
         * that directly and prove the stage resumes and the blocker
         * clears — auto-termination, no operator. */
        SV_CHECK("upstream_log_hole: refill the row (healer simulation)",
                 exec_sql(progress_store_db(),
                          "INSERT OR REPLACE INTO body_persist_log "
                          "(height, source, ok, persisted_at) "
                          "VALUES (1, 'verified', 1, 1)"));
        SV_CHECK("upstream_log_hole: resumes once the row is refilled",
                 script_validate_stage_drain(100) == 2);
        SV_CHECK("upstream_log_hole: cursor advanced to tip (3)",
                 script_validate_stage_cursor() == 3);
        SV_CHECK("upstream_log_hole: blocker cleared on resolve",
                 !blocker_exists("script_validate.upstream_log_hole"));
        sv_teardown(dir, &ms, &sc);
    }

    /* lane/stall-taxonomy audit: stage_body_read_hold. body_persist already
     * verified this body's hash+merkle root before advancing (BLOCK_HAVE_
     * DATA set), so a later stage_read_block() failure here is on-disk
     * damage, not a normal wait — it must name a typed TRANSIENT blocker
     * immediately instead of holding on a bare timestamp. */
    {
        char dir[256]; struct main_state ms; struct synth_chain_sv sc;
        SV_CHECK("body_read_failed: setup",
                 sv_setup("body_read_failed", 3, -1, dir, sizeof(dir), &ms,
                          &sc) == 0);
        sc.read_fail_height = 1;
        SV_CHECK("body_read_failed: drains only up to the hole",
                 script_validate_stage_drain(100) == 1);
        SV_CHECK("body_read_failed: cursor held at the hole (1)",
                 script_validate_stage_cursor() == 1);
        SV_CHECK("body_read_failed: next step stays JOB_IDLE",
                 script_validate_stage_step_once() == JOB_IDLE);

        struct blocker_snapshot rf_snaps[16];
        int rf_n = blocker_snapshot_all(rf_snaps, 16);
        bool rf_found = false, rf_fields_ok = false;
        for (int k = 0; k < rf_n; k++) {
            if (strcmp(rf_snaps[k].id,
                      "script_validate.body_read_failed") == 0) {
                rf_found = true;
                rf_fields_ok = strstr(rf_snaps[k].reason, "height=1") &&
                               rf_snaps[k].class == BLOCKER_TRANSIENT;
                break;
            }
        }
        SV_CHECK("body_read_failed: typed blocker raised", rf_found);
        SV_CHECK("body_read_failed: blocker names height + class TRANSIENT",
                 rf_fields_ok);

        int ok2 = -1, vin2 = -2; char status2[32];
        SV_CHECK("body_read_failed: no terminal row written at the hole",
                 !log_row_at(progress_store_db(), 1, &ok2, status2,
                             sizeof(status2), &vin2));

        sc.read_fail_height = -1;
        SV_CHECK("body_read_failed: resumes once the read succeeds again",
                 script_validate_stage_drain(100) == 2);
        SV_CHECK("body_read_failed: cursor advanced to tip (3)",
                 script_validate_stage_cursor() == 3);
        SV_CHECK("body_read_failed: blocker cleared on resolve",
                 !blocker_exists("script_validate.body_read_failed"));
        sv_teardown(dir, &ms, &sc);
    }

    {
        /* Lane E3, part 3 — downstream cause naming. A torn ANCESTOR body
         * (recorded by stage_repair_read_active_block_checked via the
         * reducer_frontier body-read note) is the ROOT CAUSE of a descendant's
         * prevout_unresolved HOLD: the coin the ancestor block creates cannot be
         * applied until the torn body is refetched + revalidated. The
         * descendant's named prevout_unresolved blocker must NAME that torn
         * ancestor height as its cause both in the free-text reason AND (lane
         * E4) via the typed caused_by/cause_detail fields. Proves the chain:
         * torn body => dependent script_validate defers with a blocker naming
         * the missing-body height; restore the body + coin => H* climbs and
         * the blocker clears via the normal revalidation flow. */
        char dir[256]; struct main_state ms; struct synth_chain_sv sc;
        SV_CHECK("torn_cause: setup",
                 sv_setup("torn_cause", 3, -1, dir, sizeof(dir), &ms, &sc) == 0);
        sc.missing_prevout_height = 1;         /* h=1's spend is unresolved */

        blocker_reset_for_testing();
        reducer_frontier_body_read_note_reset_for_testing();
        /* A torn ancestor body at h=0 (below the held height) — armed exactly
         * as read_active_block_checked would on a failed disk read. */
        reducer_frontier_body_read_note_record(
            0, 12, 34, REDUCER_FRONTIER_BODY_READ_DISK, &sc.hashes[0]);
        /* Reach the named-blocker path on the first held tick (no 10-min wait). */
        script_validate_stage_unresolved_budget_set_for_test(0);

        /* h=0 advances; h=1 HOLDS on prevout_unresolved → JOB_BLOCKED (budget
         * 0) → the stage framework publishes the typed blocker. */
        script_validate_stage_drain(100);
        SV_CHECK("torn_cause: cursor held at the hole (1)",
                 script_validate_stage_cursor() == 1);

        struct blocker_snapshot snaps[16];
        int n = blocker_snapshot_all(snaps, 16);
        bool named = false, caused_by_ok = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id, "script_validate.prevout_unresolved") != 0)
                continue;
            named = strstr(snaps[i].reason, "torn body height=0") != NULL;
            caused_by_ok =
                strcmp(snaps[i].caused_by, "reducer_frontier.body_read_torn") == 0 &&
                strstr(snaps[i].cause_detail, "height=0") != NULL;
        }
        SV_CHECK("torn_cause: prevout_unresolved blocker names the torn "
                 "ancestor body height", named);
        SV_CHECK("torn_cause: typed caused_by/cause_detail name the torn "
                 "ancestor blocker (lane E4 field)", caused_by_ok);

        /* Restore: the torn body is refetched + revalidated (clear the note)
         * and the missing coin resolves — H* climbs and the blocker clears via
         * the normal advance path (sv_unresolved_clear). */
        struct reducer_frontier_body_read_note completed_note;
        if (reducer_frontier_body_read_note_snapshot(&completed_note))
            (void)reducer_frontier_body_read_note_clear_if(&completed_note);
        sc.missing_prevout_height = -1;
        SV_CHECK("torn_cause: cursor advances once the body revalidates",
                 script_validate_stage_drain(100) == 2 &&
                 script_validate_stage_cursor() == 3);
        SV_CHECK("torn_cause: prevout_unresolved blocker cleared on resolve",
                 !blocker_exists("script_validate.prevout_unresolved"));

        script_validate_stage_unresolved_budget_set_for_test(-1); /* restore */
        reducer_frontier_body_read_note_reset_for_testing();
        blocker_reset_for_testing();
        sv_teardown(dir, &ms, &sc);
    }

    /* Root-cause chaining exemplar: script_validate's prevout_unresolved
     * defer path wires caused_by to an active body-availability blocker
     * (see util/blocker.h "Root-cause chaining" + sv_find_body_availability_
     * cause in script_validate_stage.c). Driven directly — the real HOLD
     * transition into the named PERMANENT blocker is gated by a real
     * 10-minute wall-clock budget (SV_UNRESOLVED_BUDGET_SECONDS) a fast
     * test must not wait out; this proves the discovery half of the wire
     * fires correctly, including which candidate wins when both are active. */
    {
        blocker_clear("utxo_apply.body_read_failed");
        blocker_clear("body_persist.body_read_failed");

        struct blocker_snapshot snap;
        SV_CHECK("root_cause: no candidate active -> NULL",
                 sv_find_body_availability_cause(&snap) == NULL);

        struct blocker_record r;
        blocker_init(&r, "body_persist.body_read_failed", "body_persist",
                    BLOCKER_TRANSIENT, "height=7: body vanished");
        blocker_set(&r);
        const char *found = sv_find_body_availability_cause(&snap);
        SV_CHECK("root_cause: body_persist candidate found",
                 found && strcmp(found, "body_persist.body_read_failed") == 0);

        /* utxo_apply is the stage that must itself read the block bytes to
         * fold the coin — its own read failure is the more direct cause and
         * is checked first; it must win when both candidates are active. */
        blocker_init(&r, "utxo_apply.body_read_failed", "utxo_apply",
                    BLOCKER_TRANSIENT, "height=7: body vanished");
        blocker_set(&r);
        found = sv_find_body_availability_cause(&snap);
        SV_CHECK("root_cause: utxo_apply candidate preferred",
                 found && strcmp(found, "utxo_apply.body_read_failed") == 0);

        blocker_clear("utxo_apply.body_read_failed");
        blocker_clear("body_persist.body_read_failed");
    }

    printf("script_validate_stage tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
