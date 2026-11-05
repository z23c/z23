/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the orphan_utxo_above_tip Condition — the continuous
 * self-healer that detects UTXO rows sitting ABOVE the active chain tip
 * (reorg/rewind orphans) and heals them through the bounded
 * utxo_recovery_clean_above_tip helper.
 *
 * The Condition's detect/remedy/witness function pointers are static in
 * engine/conditions/src/orphan_utxo_above_tip.c. The only public surface is
 * register_orphan_utxo_above_tip() plus the ZCL_TESTING seams
 * (orphan_utxo_above_tip_test_set_node_db / _test_reset /
 * _test_remedy_calls). We therefore drive the Condition the canonical
 * way — through condition_engine_tick() — and assert via the engine's
 * observable state (active count, last_outcome, cleared_count,
 * remedy-call count) together with direct UTXO-row queries against the
 * fixture node_db.
 *
 * Fixture pattern reused from test_utxo_recovery_service.c: a temp
 * SQLite node_db with a `utxos` table, plus a minimal in-RAM main_state
 * chain whose tip height the Condition compares against. The db is wired
 * in via orphan_utxo_above_tip_test_set_node_db(); the tip is wired in
 * via condition_engine_set_main_state().
 */

#include "test/test_core.h"

#include "conditions/orphan_utxo_above_tip.h"
#include "core/arith_uint256.h"
#include "framework/condition.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "models/database.h"
#include "storage/progress_store.h"
#include "services/utxo_recovery_service.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OUT_CHECK(name, expr) do {                  \
    printf("orphan_utxo_above_tip: %s... ", (name)); \
    if (expr) printf("OK\n");                         \
    else { printf("FAIL\n"); failures++; }           \
} while (0)

/* Build a minimal linked chain in main_state with tip at height n-1. */
static void out_build_chain(struct main_state *ms, int n)
{
    struct uint256 hashes[256];
    int limit = n < 256 ? n : 256;

    for (int h = 0; h < limit; h++) {
        memset(&hashes[h], 0, sizeof(hashes[h]));
        hashes[h].data[0] = (uint8_t)(h & 0xFF);
        hashes[h].data[1] = (uint8_t)((h >> 8) & 0xFF);
        hashes[h].data[3] = 0xAB; /* distinct salt from other tests */

        struct block_index *pi = chainstate_insert_block_index(
            (struct chainstate *)ms, &hashes[h]);
        if (!pi) continue;

        pi->nHeight = h;
        pi->nBits = 0x1f07ffff;
        pi->nTime = 1000000 + (uint32_t)h * 150;
        pi->nVersion = 4;
        pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        pi->nTx = 1;
        pi->nChainTx = (uint32_t)(h + 1);
        arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));

        if (h > 0)
            pi->pprev = block_map_find(&ms->map_block_index, &hashes[h - 1]);
    }
    if (limit > 0) {
        struct block_index *tip = block_map_find(
            &ms->map_block_index, &hashes[limit - 1]);
        if (tip) active_chain_move_window_tip(&ms->chain_active, tip);
    }
}

/* Insert `count` UTXO rows all at a single height. */
static void out_insert_utxos_at(struct node_db *ndb, int base_id,
                                int height, int count)
{
    node_db_begin(ndb);
    for (int i = 0; i < count; i++) {
        char sql[256];
        snprintf(sql, sizeof(sql),
            "INSERT INTO utxos(txid, vout, height, value, script, "
            "is_coinbase) VALUES(X'%032d', %d, %d, 100000, X'51', 0)",
            base_id + i, base_id + i, height);
        node_db_exec(ndb, sql);
    }
    node_db_commit(ndb);
}

/* Open a fresh temp node_db. Returns true on success. */
static bool out_open_db(struct node_db *ndb, const char *tag, char *path_out,
                        size_t path_cap)
{
    snprintf(path_out, path_cap, "./test-tmp/%d_orphan_%s.db",
             getpid(), tag);
    mkdir("./test-tmp", 0755);
    memset(ndb, 0, sizeof(*ndb));
    return node_db_open(ndb, path_out);
}

/* ── 1. No orphans: utxos all at/below tip → detect false ── */
static int out_case_no_orphans_quiet(void)
{
    int failures = 0;

    condition_engine_reset_for_testing();
    orphan_utxo_above_tip_test_reset();

    struct main_state ms;
    main_state_init(&ms);
    out_build_chain(&ms, 50); /* tip at h=49 */
    condition_engine_set_main_state(&ms);

    char db_path[256];
    struct node_db ndb;
    bool ok = out_open_db(&ndb, "noorphan", db_path, sizeof(db_path));
    if (ok) {
        /* 10 rows, all at or below tip (h=1..10). */
        out_insert_utxos_at(&ndb, 0, 5, 10);
        orphan_utxo_above_tip_test_set_node_db(&ndb);
        register_orphan_utxo_above_tip();

        condition_engine_tick();

        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && orphan_utxo_above_tip_test_remedy_calls() == 0;
        /* witness() is true (no orphans), so the engine never
         * marks the condition active. */
        OUT_CHECK("no orphans -> detect false, no remedy", ok);

        node_db_close(&ndb);
    } else {
        OUT_CHECK("no orphans (db open failed)", false);
    }
    unlink(db_path);

    condition_engine_set_main_state(NULL);
    condition_engine_reset_for_testing();
    orphan_utxo_above_tip_test_reset();
    main_state_free(&ms);

    return failures;
}

/* ── 2. Small overshoot heals: <=32 rows above tip ── */
static int out_case_small_overshoot_heals(void)
{
    int failures = 0;

    condition_engine_reset_for_testing();
    orphan_utxo_above_tip_test_reset();

    struct main_state ms;
    main_state_init(&ms);
    out_build_chain(&ms, 50); /* tip at h=49 */
    condition_engine_set_main_state(&ms);

    char db_path[256];
    struct node_db ndb;
    bool ok = out_open_db(&ndb, "small", db_path, sizeof(db_path));
    if (ok) {
        /* 8 rows at tip+1 (h=50) — single-block overshoot, <=32. */
        out_insert_utxos_at(&ndb, 0, 50, 8);
        orphan_utxo_above_tip_test_set_node_db(&ndb);
        register_orphan_utxo_above_tip();

        /* cleared_count is a cumulative lifetime counter on the
         * (static) condition struct; capture a baseline and assert it
         * advances by exactly one when the heal is witnessed. */
        struct condition_runtime_snapshot pre;
        int cleared_before = 0;
        if (condition_engine_get_registered_snapshot(
                "orphan_utxo_above_tip", &pre))
            cleared_before = pre.cleared_count;

        int64_t above_before = node_db_utxo_count(&ndb);
        condition_engine_tick();
        int64_t above_after = node_db_utxo_count(&ndb);

        /* remedy ran exactly once, returned OK, witness confirmed the
         * heal, so the engine cleared the condition. */
        ok = ok && above_before == 8;
        ok = ok && orphan_utxo_above_tip_test_remedy_calls() == 1;
        ok = ok && above_after == 0;
        ok = ok && condition_engine_get_active_count() == 0;

        struct condition_runtime_snapshot snap;
        ok = ok && condition_engine_get_registered_snapshot(
                       "orphan_utxo_above_tip", &snap);
        ok = ok && snap.cleared_count == cleared_before + 1;
        OUT_CHECK("small overshoot -> remedy OK, rows pruned, "
                  "witness true", ok);

        node_db_close(&ndb);
    } else {
        OUT_CHECK("small overshoot heals (db open failed)", false);
    }
    unlink(db_path);

    condition_engine_set_main_state(NULL);
    condition_engine_reset_for_testing();
    orphan_utxo_above_tip_test_reset();
    main_state_free(&ms);

    return failures;
}

/* ── 3. Oversized overshoot refuses + pages ── */
static int out_case_oversized_overshoot_refuses(void)
{
    int failures = 0;

    condition_engine_reset_for_testing();
    orphan_utxo_above_tip_test_reset();

    struct main_state ms;
    main_state_init(&ms);
    out_build_chain(&ms, 50); /* tip at h=49 */
    condition_engine_set_main_state(&ms);

    char db_path[256];
    struct node_db ndb;
    bool ok = out_open_db(&ndb, "big", db_path, sizeof(db_path));
    if (ok) {
        /* 40 rows at tip+1 (h=50) — exceeds the 32-row guard. */
        out_insert_utxos_at(&ndb, 0, 50, 40);
        orphan_utxo_above_tip_test_set_node_db(&ndb);
        register_orphan_utxo_above_tip();

        /* cleared_count is a cumulative lifetime counter on the
         * (static) condition struct that survives re-registration, so
         * capture a baseline and assert it does NOT advance (the
         * symptom must not clear). */
        struct condition_runtime_snapshot pre;
        int cleared_before = 0;
        if (condition_engine_get_registered_snapshot(
                "orphan_utxo_above_tip", &pre))
            cleared_before = pre.cleared_count;

        condition_engine_tick();
        int64_t above_after = node_db_utxo_count(&ndb);

        /* remedy ran (guard refused) -> FAILED; rows remain; the
         * symptom is NOT cleared so the condition stays active. */
        ok = ok && orphan_utxo_above_tip_test_remedy_calls() == 1;
        ok = ok && above_after == 40;
        ok = ok && condition_engine_get_active_count() == 1;

        struct condition_runtime_snapshot snap;
        ok = ok && condition_engine_get_registered_snapshot(
                       "orphan_utxo_above_tip", &snap);
        ok = ok && snap.last_outcome == COND_REMEDY_FAILED;
        ok = ok && snap.cleared_count == cleared_before;
        OUT_CHECK("oversized overshoot -> remedy FAILED, witness "
                  "false (symptom persists)", ok);

        node_db_close(&ndb);
    } else {
        OUT_CHECK("oversized overshoot refuses (db open failed)", false);
    }
    unlink(db_path);

    condition_engine_set_main_state(NULL);
    condition_engine_reset_for_testing();
    orphan_utxo_above_tip_test_reset();
    main_state_free(&ms);

    return failures;
}

/* ── 4. Tip not established (tip_h == 0) → no false positive ── */
static int out_case_tip_not_established_quiet(void)
{
    int failures = 0;

    condition_engine_reset_for_testing();
    orphan_utxo_above_tip_test_reset();

    struct main_state ms;
    main_state_init(&ms); /* no chain built — tip is NULL/height 0 */
    condition_engine_set_main_state(&ms);

    char db_path[256];
    struct node_db ndb;
    bool ok = out_open_db(&ndb, "notip", db_path, sizeof(db_path));
    if (ok) {
        /* Rows present at high heights, but with no established tip
         * the Condition must stay quiet (boot not finalized). */
        out_insert_utxos_at(&ndb, 0, 100, 5);
        orphan_utxo_above_tip_test_set_node_db(&ndb);
        register_orphan_utxo_above_tip();

        condition_engine_tick();

        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && orphan_utxo_above_tip_test_remedy_calls() == 0;
        /* rows untouched — no heal attempted against an
         * unestablished tip. */
        ok = ok && node_db_utxo_count(&ndb) == 5;
        OUT_CHECK("tip not established -> detect false, witness true",
                  ok);

        node_db_close(&ndb);
    } else {
        OUT_CHECK("tip not established (db open failed)", false);
    }
    unlink(db_path);

    condition_engine_set_main_state(NULL);
    condition_engine_reset_for_testing();
    orphan_utxo_above_tip_test_reset();
    main_state_free(&ms);

    return failures;
}

/* ── Mutation-gap cases ──────────────────────────────────────────────────
 * condition_engine_tick() runs detect(), and when detect() is true it then
 * asks witness(). A wrongly-true detect() with a true witness() therefore
 * leaves no active episode and no remedy call: the only trace is that the
 * engine marks the (phantom) episode cleared, so cleared_count must stay put
 * in every quiet case below. */
struct out_fx {
    struct main_state ms;
    struct node_db ndb;
    char path[256];
    bool ok;
    int cleared_before;
};

static int out_cleared_count(void)
{
    struct condition_runtime_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    if (!condition_engine_get_registered_snapshot("orphan_utxo_above_tip",
                                                  &snap))
        return -1;
    return snap.cleared_count;
}

static void out_fx_begin(struct out_fx *fx, const char *tag, int chain_n)
{
    condition_engine_reset_for_testing();
    orphan_utxo_above_tip_test_reset();
    main_state_init(&fx->ms);
    out_build_chain(&fx->ms, chain_n);
    condition_engine_set_main_state(&fx->ms);
    fx->ok = out_open_db(&fx->ndb, tag, fx->path, sizeof(fx->path));
    if (fx->ok) {
        orphan_utxo_above_tip_test_set_node_db(&fx->ndb);
        register_orphan_utxo_above_tip();
        fx->cleared_before = out_cleared_count();
    }
}

static void out_fx_end(struct out_fx *fx)
{
    if (fx->ok)
        node_db_close(&fx->ndb);
    unlink(fx->path);
    condition_engine_set_main_state(NULL);
    condition_engine_reset_for_testing();
    orphan_utxo_above_tip_test_reset();
    main_state_free(&fx->ms);
}

enum out_quirk { OUT_Q_NONE, OUT_Q_CLOSED, OUT_Q_NO_TABLE, OUT_Q_NO_MAIN_STATE };

static void out_apply_quirk(struct out_fx *fx, enum out_quirk q)
{
    if (q == OUT_Q_CLOSED)
        fx->ndb.open = false;
    else if (q == OUT_Q_NO_TABLE)
        node_db_exec(&fx->ndb, "DROP TABLE utxos");
    else if (q == OUT_Q_NO_MAIN_STATE)
        condition_engine_set_main_state(NULL);
}

/* Rows sit at `rows_h`; the chain has `chain_n` blocks. detect() must stay
 * false: no heal, no episode, no phantom clear, rows untouched. */
static int out_quiet_case(const char *name, const char *tag, int chain_n,
                          int rows_h, enum out_quirk q)
{
    int failures = 0;
    struct out_fx fx;
    out_fx_begin(&fx, tag, chain_n);
    bool ok = fx.ok;
    if (ok) {
        out_insert_utxos_at(&fx.ndb, 0, rows_h, 5);
        out_apply_quirk(&fx, q);
        condition_engine_tick();
        fx.ndb.open = true;
        ok = condition_engine_get_active_count() == 0 &&
             orphan_utxo_above_tip_test_remedy_calls() == 0 &&
             out_cleared_count() == fx.cleared_before &&
             (q == OUT_Q_NO_TABLE || node_db_utxo_count(&fx.ndb) == 5);
    }
    OUT_CHECK(name, ok);
    out_fx_end(&fx);
    return failures;
}

static int out_case_quiet_variants(void)
{
    int failures = 0;
    failures += out_quiet_case("no orphans -> no phantom episode",
                               "q_none", 50, 5, OUT_Q_NONE);
    failures += out_quiet_case("closed node_db -> quiet", "q_closed", 50, 50,
                               OUT_Q_CLOSED);
    failures += out_quiet_case("missing utxos table -> quiet", "q_notable", 50,
                               50, OUT_Q_NO_TABLE);
    failures += out_quiet_case("tip at genesis (height 0) -> quiet",
                               "q_genesis", 1, 5, OUT_Q_NONE);
    failures += out_quiet_case("no main_state -> quiet", "q_nomain", 50, 50,
                               OUT_Q_NO_MAIN_STATE);
    return failures;
}

/* Tip height 1 is a real tip: rows above it heal, and the heal is reported as
 * a successful remedy that the witness confirmed. */
static int out_case_tip_one_heals(void)
{
    int failures = 0;
    struct out_fx fx;
    out_fx_begin(&fx, "tipone", 2);
    bool ok = fx.ok;
    if (ok) {
        out_insert_utxos_at(&fx.ndb, 0, 2, 3);
        condition_engine_tick();
        struct condition_runtime_snapshot snap;
        memset(&snap, 0, sizeof(snap));
        ok = orphan_utxo_above_tip_test_remedy_calls() == 1 &&
             node_db_utxo_count(&fx.ndb) == 0 &&
             condition_engine_get_active_count() == 0 &&
             condition_engine_get_registered_snapshot(
                 "orphan_utxo_above_tip", &snap) &&
             snap.cleared_count == fx.cleared_before + 1 &&
             snap.last_outcome == COND_REMEDY_OK;
    }
    OUT_CHECK("tip height 1 -> rows above heal, remedy OK, witnessed", ok);
    out_fx_end(&fx);
    return failures;
}

/* An active episode ends through the witness: once the tip is gone there is
 * nothing to clean and the episode clears, without another remedy attempt. */
static int out_case_tip_lost_clears_episode(void)
{
    int failures = 0;
    struct out_fx fx;
    out_fx_begin(&fx, "tiplost", 50);
    bool ok = fx.ok;
    if (ok) {
        out_insert_utxos_at(&fx.ndb, 0, 50, 40); /* guard refuses: stays active */
        condition_engine_tick();
        ok = condition_engine_get_active_count() == 1 &&
             orphan_utxo_above_tip_test_remedy_calls() == 1;
        active_chain_move_window_tip(&fx.ms.chain_active, NULL);
        condition_engine_tick();
        ok = ok && condition_engine_get_active_count() == 0 &&
             orphan_utxo_above_tip_test_remedy_calls() == 1 &&
             out_cleared_count() == fx.cleared_before + 1 &&
             node_db_utxo_count(&fx.ndb) == 40;
    }
    OUT_CHECK("tip lost mid-episode -> witness clears, no second heal", ok);
    out_fx_end(&fx);
    return failures;
}

/* The registration parameters are the condition's operating contract. */
static int out_case_registration_contract(void)
{
    int failures = 0;
    struct out_fx fx;
    out_fx_begin(&fx, "regparams", 50);
    struct condition_runtime_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    bool ok = fx.ok && condition_engine_get_registered_snapshot(
                           "orphan_utxo_above_tip", &snap);
    ok = ok && snap.severity == COND_WARN && snap.poll_secs == 60 &&
         snap.backoff_secs == 300 && snap.max_attempts == 3 &&
         snap.witness_window_secs == 60;
    OUT_CHECK("registration: WARN, poll 60s, backoff 300s, 3 attempts, "
              "witness window 60s", ok);
    out_fx_end(&fx);
    return failures;
}

/* A datadir where coins_kv is the proven authority keeps "rows above tip" as
 * harmless mirror lag: the condition must NOT heal (delete) there. */
static bool out_seed_canonical_store(sqlite3 *db, int applied)
{
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "CREATE TABLE IF NOT EXISTS progress_meta(key TEXT PRIMARY KEY, "
        "value BLOB);"
        "CREATE TABLE IF NOT EXISTS coins(k BLOB PRIMARY KEY, v BLOB);"
        "INSERT OR IGNORE INTO coins(k,v) VALUES(x'00', x'00');"
        "CREATE TABLE IF NOT EXISTS validate_headers_log(height INTEGER "
        "PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL, "
        "fail_reason TEXT, validated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log(height INTEGER PRIMARY "
        "KEY, status TEXT, ok INTEGER, tip_hash BLOB);"
        "INSERT OR REPLACE INTO progress_meta(key,value) VALUES("
        "'coins_applied_height', x'%02x00000000000000');"
        "INSERT OR REPLACE INTO progress_meta(key,value) VALUES("
        "'coins_kv_migration_complete', x'01');", applied);
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static int out_case_canonical_datadir_quiet(void)
{
    int failures = 0;
    struct out_fx fx;
    out_fx_begin(&fx, "canonical", 50);
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "orphan_utxo", "canonical");
    bool ok = fx.ok && progress_store_open(dir) &&
              out_seed_canonical_store(progress_store_db(), 51);
    if (ok) {
        out_insert_utxos_at(&fx.ndb, 0, 50, 5);
        condition_engine_tick();
        ok = condition_engine_get_active_count() == 0 &&
             orphan_utxo_above_tip_test_remedy_calls() == 0 &&
             out_cleared_count() == fx.cleared_before &&
             node_db_utxo_count(&fx.ndb) == 5;
    }
    OUT_CHECK("canonical datadir -> mirror rows above tip are never healed",
              ok);
    progress_store_close();
    test_cleanup_tmpdir(dir);
    out_fx_end(&fx);
    return failures;
}

/* With no test node_db injected the condition reaches node.db through the
 * app runtime, exactly as production does. */
static int out_case_runtime_node_db(void)
{
    int failures = 0;
    struct out_fx fx;
    out_fx_begin(&fx, "rtdb", 50);
    bool ok = fx.ok;
    struct db_service svc;
    struct app_runtime_context rt;
    memset(&rt, 0, sizeof(rt));
    db_service_init(&svc);
    ok = ok && db_service_attach(&svc, &fx.ndb) &&
         db_service_start_test_worker(&svc);
    if (ok) {
        orphan_utxo_above_tip_test_set_node_db(NULL);
        rt.db_service = &svc;
        app_runtime_set_current(&rt);
        out_insert_utxos_at(&fx.ndb, 0, 50, 8);
        condition_engine_tick();
        ok = orphan_utxo_above_tip_test_remedy_calls() == 1 &&
             node_db_utxo_count(&fx.ndb) == 0 &&
             out_cleared_count() == fx.cleared_before + 1;
        app_runtime_set_current(NULL);
    }
    db_service_stop(&svc);
    OUT_CHECK("runtime node_db (no test seam) -> rows above tip heal", ok);
    out_fx_end(&fx);
    return failures;
}

static int out_mutation_gap_cases(void)
{
    int failures = 0;
    failures += out_case_quiet_variants();
    failures += out_case_tip_one_heals();
    failures += out_case_tip_lost_clears_episode();
    failures += out_case_registration_contract();
    failures += out_case_canonical_datadir_quiet();
    failures += out_case_runtime_node_db();
    return failures;
}


int test_orphan_utxo_above_tip(void)
{
    printf("\n=== orphan_utxo_above_tip condition tests ===\n");
    int failures = 0;

    failures += out_case_no_orphans_quiet();
    failures += out_case_small_overshoot_heals();
    failures += out_case_oversized_overshoot_refuses();
    failures += out_case_tip_not_established_quiet();
    failures += out_mutation_gap_cases();

    return failures;
}
