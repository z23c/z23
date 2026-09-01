/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * T6 (WP-E / FIX-4): utxo_apply's silent hole-idle becomes observable.
 *
 * Control flow in step_apply guarantees that a missing proof_validate_log
 * row BELOW the proof_validate cursor is a durable upstream hole (the
 * cursor guard returns first otherwise). This test proves the FIX-4
 * surfacing contract:
 *   - the stage stays JOB_IDLE (deliberately NOT JOB_BLOCKED — JOB_BLOCKED
 *     feeds the supervisor restart ladder, and a watchdog self-restart is
 *     what manufactured this hole class),
 *   - upstream_hole_total counts HOLES (1 across repeated ticks, not ticks),
 *   - the hole height + first-seen unix + consecutive-tick count appear in
 *     utxo_apply_dump_state_json,
 *   - the WARN is transition-logged: exactly once across repeated ticks at
 *     the same height (300 s keep-alive not reached in-test),
 *   - the hole registers the DEPENDENCY blocker
 *     reducer_frontier.upstream_log_hole (escape_action names the healer,
 *     reducer_frontier_reconcile_light) so `zclassic23 blockers` is non-zero
 *     for the stall's whole duration — the 3166989 hole ran 3 h with zero
 *     reported blockers
 *     because only the WARN/dump path existed,
 *   - healing the hole resumes the stage, zeroes consec, and clears the
 *     blocker.
 *
 * Fixture is a trimmed copy of test_utxo_apply_stage.c's synthetic chain
 * (happy path only — no fail kinds needed). */

#include "test/test_core.h"
#include "test/block_fixtures.h"

#include "bloom/merkle.h"
#include "core/uint256.h"
#include "json/json.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "jobs/utxo_apply_stage.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Mirrors engine/jobs/src/utxo_apply_stage_internal.h (a src-private header) —
 * the test_utxo_apply_stage.c delta-internal pattern. warn_total counts
 * actually-emitted (un-throttled) WARN lines. */
extern _Atomic uint64_t g_ua_upstream_hole_warn_total;

#define UH_CHECK(name, expr) do { \
    printf("utxo_apply_upstream_hole: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

struct uh_ext_utxo {
    struct uint256 txid;
    uint32_t vout;
    int64_t value;
};

struct uh_chain {
    struct block_index *blocks;
    struct uint256     *hashes;
    struct block       *bodies;
    struct uh_ext_utxo *ext;
    int                 n;
};

static int uh_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static void uh_synthetic_txid(struct uint256 *out, int h, int salt)
{
    uint256_set_null(out);
    out->data[0] = (uint8_t)(0x80 + h);
    out->data[1] = (uint8_t)salt;
}

static bool uh_make_tx(struct transaction *tx, int h, bool coinbase,
                       const struct uint256 *prev, int64_t out_value)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1)) return false;
    if (coinbase) {
        outpoint_set_null(&tx->vin[0].prevout);
    } else {
        tx->vin[0].prevout.hash = *prev;
        tx->vin[0].prevout.n = 0;
    }
    tx->vout[0].value = out_value;
    tx->vout[0].script_pub_key.size = 0;
    uh_synthetic_txid(&tx->hash, h, coinbase ? 1 : 2);
    return true;
}

static bool uh_make_body(struct uh_chain *sc, int h)
{
    struct block *b = &sc->bodies[h];
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700002000u + (uint32_t)h);
    b->header.nBits = 0x1f07ffff;
    b->num_vtx = 2;
    b->vtx = zcl_calloc(2, sizeof(struct transaction), "uh_tx");
    if (!b->vtx) return false;

    struct uint256 prev;
    uh_synthetic_txid(&prev, h, 9);
    sc->ext[h].txid = prev;
    sc->ext[h].vout = 0;
    sc->ext[h].value = 1000 + h;

    if (!uh_make_tx(&b->vtx[0], h, true, NULL, 50 + h)) return false;
    if (!uh_make_tx(&b->vtx[1], h, false, &prev, 900 + h)) return false;
    struct uint256 txids[2] = { b->vtx[0].hash, b->vtx[1].hash };
    b->header.hashMerkleRoot = compute_merkle_root(txids, 2);
    return true;
}

static bool uh_chain_build(struct uh_chain *sc, int n)
{
    sc->blocks = zcl_calloc((size_t)n, sizeof(struct block_index),
                            "uh_blocks");
    sc->hashes = zcl_calloc((size_t)n, sizeof(struct uint256), "uh_hashes");
    sc->bodies = zcl_calloc((size_t)n, sizeof(struct block), "uh_bodies");
    sc->ext = zcl_calloc((size_t)n, sizeof(struct uh_ext_utxo), "uh_ext");
    if (!sc->blocks || !sc->hashes || !sc->bodies || !sc->ext)
        return false;
    for (int i = 0; i < n; i++) {
        if (!uh_make_body(sc, i)) return false;
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

static void uh_chain_free(struct uh_chain *sc)
{
    if (sc->bodies) {
        for (int i = 0; i < sc->n; i++)
            block_free(&sc->bodies[i]);
    }
    free(sc->blocks);
    free(sc->hashes);
    free(sc->bodies);
    free(sc->ext);
    memset(sc, 0, sizeof(*sc));
}

static bool uh_reader(struct block *out, const struct block_index *bi,
                      const char *datadir, void *user)
{
    (void)datadir;
    struct uh_chain *sc = user;
    if (!out || !bi || !sc || bi->nHeight < 0 || bi->nHeight >= sc->n)
        return false;
    return test_block_copy(out, &sc->bodies[bi->nHeight], "uh_tx_copy");
}

static bool uh_lookup(const struct uint256 *txid, uint32_t vout,
                      struct utxo_apply_lookup *out, void *user)
{
    struct uh_chain *sc = user;
    memset(out, 0, sizeof(*out));
    if (!sc) return true;
    for (int i = 0; i < sc->n; i++) {
        if (sc->ext[i].vout == vout && uint256_eq(&sc->ext[i].txid, txid)) {
            out->found = true;
            out->value = sc->ext[i].value;
            return true;
        }
    }
    return true;
}

static bool uh_exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool uh_seed_proof_validate(sqlite3 *db, const struct uh_chain *sc,
                                   int n)
{
    if (!db || !sc || n <= 0 || n > sc->n)
        return false;
    if (!uh_exec_sql(db,
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height                  INTEGER PRIMARY KEY,"
        "  status                  TEXT    NOT NULL,"
        "  ok                      INTEGER NOT NULL,"
        "  sapling_spends_total    INTEGER NOT NULL,"
        "  sapling_outputs_total   INTEGER NOT NULL,"
        "  sprout_joinsplits_total INTEGER NOT NULL,"
        "  block_hash              BLOB,"
        "  first_failure_txid      BLOB,"
        "  first_failure_proof_type TEXT,"
        "  validated_at            INTEGER NOT NULL"
        ")") ||
        !uh_exec_sql(db,
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  tx_count INTEGER NOT NULL, input_count INTEGER NOT NULL,"
        "  first_failure_txid BLOB, first_failure_vin INTEGER,"
        "  first_failure_serror INTEGER, validated_at INTEGER NOT NULL,"
        "  block_hash BLOB)"))
        return false;
    sqlite3_stmt *st = NULL, *script_st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO proof_validate_log "
        "(height, status, ok, sapling_spends_total, sapling_outputs_total, "
        " sprout_joinsplits_total, block_hash, validated_at) "
        "VALUES (?, 'verified', 1, 0, 0, 0, ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO script_validate_log "
        "(height, status, ok, tx_count, input_count, validated_at, block_hash) "
        "VALUES (?, 'verified', 1, 0,0,1,?)",
        -1, &script_st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return false;
    }
    for (int h = 0; h < n; h++) {
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_blob(st, 2, sc->hashes[h].data, 32, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            sqlite3_finalize(script_st);
            return false;
        }
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_int(script_st, 1, h);
        sqlite3_bind_blob(script_st, 2, sc->hashes[h].data, 32,
                          SQLITE_STATIC);
        if (sqlite3_step(script_st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            sqlite3_finalize(script_st);
            return false;
        }
        sqlite3_reset(script_st);
        sqlite3_clear_bindings(script_st);
    }
    sqlite3_finalize(st);
    sqlite3_finalize(script_st);

    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
        "VALUES('proof_validate', ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, n);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool uh_delete_pv_row(sqlite3 *db, int height)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "DELETE FROM proof_validate_log WHERE height = ?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool uh_restore_pv_row(sqlite3 *db, const struct uh_chain *sc,
                              int height)
{
    if (!db || !sc || height < 0 || height >= sc->n)
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO proof_validate_log "
        "(height, status, ok, sapling_spends_total, sapling_outputs_total, "
        " sprout_joinsplits_total, block_hash, validated_at) "
        "VALUES (?, 'verified', 1, 0, 0, 0, ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, sc->hashes[height].data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* Read one integer field out of the dump JSON; INT64_MIN on a missing key
 * so a silently-absent field can never satisfy an equality check. */
static int64_t uh_dump_int(const char *key)
{
    struct json_value v;
    json_init(&v);
    int64_t out = INT64_MIN;
    if (utxo_apply_dump_state_json(&v, NULL)) {
        const struct json_value *f = json_get(&v, key);
        if (f)
            out = json_get_int(f);
    }
    json_free(&v);
    return out;
}

int test_utxo_apply_upstream_hole(void);
int test_utxo_apply_upstream_hole(void)
{
    printf("\n=== utxo_apply upstream-hole observability tests ===\n");
    int failures = 0;

    blocker_module_init();

    char dir[256];
    struct main_state ms;
    struct uh_chain sc;
    memset(&sc, 0, sizeof(sc));
    memset(&ms, 0, sizeof(ms));

    test_fmt_tmpdir(dir, sizeof(dir), "utxo_apply_upstream_hole", "t6");
    uh_mkdir_p("./test-tmp");
    uh_mkdir_p(dir);
    UH_CHECK("setup: progress store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();

    active_chain_init(&ms.chain_active);
    UH_CHECK("setup: synthetic chain builds", uh_chain_build(&sc, 3));
    active_chain_move_window_tip(&ms.chain_active, &sc.blocks[2]);

    UH_CHECK("setup: proof_validate rows 0..2 + cursor 3 seeded",
             uh_seed_proof_validate(db, &sc, 3));
    /* The hole: row 0 absent while the proof_validate cursor (3) is already
     * past it — the durable stale-replay artifact class. */
    UH_CHECK("setup: pv row at h=0 deleted (durable hole)",
             uh_delete_pv_row(db, 0));
    UH_CHECK("setup: upstream_log_hole blocker absent before first tick",
             !blocker_exists("reducer_frontier.upstream_log_hole"));
    UH_CHECK("setup: stage init", utxo_apply_stage_init(&ms));
    utxo_apply_stage_set_reader(uh_reader, &sc);
    utxo_apply_stage_set_lookup(uh_lookup, &sc);

    /* First tick: JOB_IDLE (NOT JOB_BLOCKED), hole counted + dumped, WARN
     * emitted exactly once (transition). */
    UH_CHECK("hole tick 1: stays JOB_IDLE (not JOB_BLOCKED)",
             utxo_apply_stage_step_once() == JOB_IDLE);
    UH_CHECK("hole tick 1: upstream_hole_total == 1 in dump",
             uh_dump_int("upstream_hole_total") == 1);
    UH_CHECK("hole tick 1: hole height == 0 in dump",
             uh_dump_int("upstream_hole_height") == 0);
    UH_CHECK("hole tick 1: first-seen unix recorded",
             uh_dump_int("upstream_hole_first_unix") > 0);
    UH_CHECK("hole tick 1: consec == 1 in dump",
             uh_dump_int("upstream_hole_consec") == 1);
    UH_CHECK("hole tick 1: WARN emitted once",
             atomic_load(&g_ua_upstream_hole_warn_total) == 1);
    UH_CHECK("hole tick 1: cursor held at 0",
             utxo_apply_stage_cursor() == 0);
    UH_CHECK("hole tick 1: upstream_log_hole blocker registered",
             blocker_exists("reducer_frontier.upstream_log_hole"));
    UH_CHECK("hole tick 1: blocker class DEPENDENCY (waits on the "
             "reconcile-light condition, never the restart ladder)",
             blocker_class_for("reducer_frontier.upstream_log_hole")
                 == BLOCKER_DEPENDENCY);
    {
        struct blocker_snapshot snaps[BLOCKER_CAP];
        int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
        bool escape_named = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id,
                       "reducer_frontier.upstream_log_hole") == 0 &&
                strcmp(snaps[i].escape_action,
                       "reducer_frontier_reconcile_light") == 0)
                escape_named = true;
        }
        UH_CHECK("hole tick 1: escape_action names "
                 "reducer_frontier_reconcile_light", escape_named);
    }

    /* Repeated ticks: total counts HOLES not ticks; consec counts ticks;
     * the WARN stays at 1 (same height, 300 s keep-alive not reached). */
    for (int i = 0; i < 5; i++) {
        if (utxo_apply_stage_step_once() != JOB_IDLE)
            failures++;
    }
    UH_CHECK("hole ticks 2-6: total still 1 (counts holes, not ticks)",
             uh_dump_int("upstream_hole_total") == 1);
    UH_CHECK("hole ticks 2-6: consec == 6",
             uh_dump_int("upstream_hole_consec") == 6);
    UH_CHECK("hole ticks 2-6: WARN still exactly once",
             atomic_load(&g_ua_upstream_hole_warn_total) == 1);
    UH_CHECK("hole ticks 2-6: no JOB_BLOCKED restart-ladder blocker "
             "(the hole stays out of supervisor escalation)",
             !blocker_exists("utxo_apply.apply_failed"));
    UH_CHECK("hole ticks 2-6: upstream_log_hole blocker persists",
             blocker_exists("reducer_frontier.upstream_log_hole"));

    /* Heal: restore the row; the stage resumes forward and consec zeroes
     * (the dump's "currently observing" signal); the hole evidence
     * (total/height/first_unix) stays. */
    UH_CHECK("heal: pv row restored", uh_restore_pv_row(db, &sc, 0));
    UH_CHECK("heal: next tick advances",
             utxo_apply_stage_step_once() == JOB_ADVANCED);
    UH_CHECK("heal: consec reset to 0",
             uh_dump_int("upstream_hole_consec") == 0);
    UH_CHECK("heal: upstream_log_hole blocker cleared",
             !blocker_exists("reducer_frontier.upstream_log_hole"));
    UH_CHECK("heal: total stays 1 (last-hole evidence preserved)",
             uh_dump_int("upstream_hole_total") == 1);
    UH_CHECK("heal: remaining heights drain",
             utxo_apply_stage_drain(100) == 2);
    UH_CHECK("heal: cursor at 3", utxo_apply_stage_cursor() == 3);

    utxo_apply_stage_shutdown();
    active_chain_free(&ms.chain_active);
    uh_chain_free(&sc);
    progress_store_close();
    test_cleanup_tmpdir(dir);

    printf("utxo_apply_upstream_hole: %d failures\n", failures);
    return failures;
}
