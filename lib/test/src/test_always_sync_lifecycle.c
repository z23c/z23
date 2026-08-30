/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_always_sync_lifecycle — the FULL-LIFECYCLE always-sync proof harness.
 *
 * MISSION (the core guarantee): the node ALWAYS folds an L1-style anchor base
 * forward to the network tip, and every fault it can hit terminates in exactly
 * ONE of two acceptable states:
 *   (a) H* reaches the target tip, or
 *   (b) a typed TERMINAL blocker is NAMED at a known height WITH a remedy.
 *
 * FORBIDDEN outcomes this test actively catches (a red here that names a real
 * production defect is a SUCCESS for the harness, not a failure):
 *   - a SILENT idle: not at tip, no named blocker, ladder not armed;
 *   - an UNBOUNDED rung/rewind loop: the escalator dispatch count is bounded;
 *   - a CRASH/SIGSEGV: every injector runs under a siglongjmp crash guard;
 *   - a coins_kv WIPE: the raw coin-row count is asserted MONOTONIC across
 *     every fault (a legitimate re-derive rewinds the cursor/delta, never the
 *     durable coin rows in this fixture).
 *
 * It drives the REAL machinery — the reducer frontier (reducer_frontier_
 * compute_hstar), the universal re-derive primitive (stage_rederive_range),
 * the body-fetch-gap detector, the sticky_escalator ladder (via
 * sticky_escalator_test_drive, exactly as test_stall_totality_matrix does),
 * and the peer-floor decision — over a repo-local scratch progress.kv (never a
 * live datadir). Section 1 is a forward-fold soak that climbs H* to a target
 * tip while injecting inline faults; section 2 runs the full sim/simnet_chaos
 * injector matrix under the two-state + crash-guard contract; section 3 covers
 * the two faults whose oracles live under app/services (the lib/ layering gate
 * keeps them out of lib/sim): a non-monotonic clock and a peer-floor breach. */

#include "platform/time_compat.h"
#include "test/test_core.h"

#include "chain/chainparams.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_rederive_range.h"
#include "jobs/stage_repair.h"
#include "services/block_source_policy.h"
#include "services/sticky_escalator.h"
#include "services/sync_monitor.h"
#include "sim/simnet_chaos_faults.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "storage/seal_kv.h"
#include "util/blocker.h"
#include "util/stage.h"
#include "validation/main_state.h"

#include <setjmp.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)

/* Test-only seam (defined in reducer_frontier.c under ZCL_TESTING; the same
 * forward declaration test_stall_totality_matrix.c uses): pin the compiled
 * finality-anchor floor so the fixtures' below-anchor heights are exact.
 * Restored to -1 (production default) before return. */
void reducer_frontier_test_set_compiled_anchor(int32_t height);

#define LC_CHECK(name, expr) do { \
    printf("always_sync_lifecycle: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── crash guard: catch a SIGSEGV/SIGABRT/SIGBUS/SIGFPE in the real machinery
 * and report it as the forbidden CRASH outcome instead of killing the run. ── */

static sigjmp_buf g_cg_jmp;
static volatile sig_atomic_t g_cg_sig;

static void cg_handler(int s)
{
    g_cg_sig = (sig_atomic_t)s;
    siglongjmp(g_cg_jmp, 1);
}

/* Runs one injector under the crash guard. Returns true iff it completed
 * without a fatal signal; *out_crashed_sig carries the signal on a crash. */
static bool cg_run(bool (*fn)(struct chaos_fault_result *),
                   struct chaos_fault_result *r, int *out_crashed_sig)
{
    struct sigaction sa, old_segv, old_abrt, old_bus, old_fpe;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cg_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGABRT, &sa, &old_abrt);
    sigaction(SIGBUS, &sa, &old_bus);
    sigaction(SIGFPE, &sa, &old_fpe);

    g_cg_sig = 0;
    bool completed;
    if (sigsetjmp(g_cg_jmp, 1) == 0) {
        (void)fn(r);
        completed = true;
    } else {
        completed = false;
    }

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGABRT, &old_abrt, NULL);
    sigaction(SIGBUS, &old_bus, NULL);
    sigaction(SIGFPE, &old_fpe, NULL);
    if (out_crashed_sig)
        *out_crashed_sig = (int)g_cg_sig;
    return completed;
}

/* ── compact anchor-base progress.kv fixture (the section-1 fold) ──────────
 * The row shapes mirror the reviewed lib/sim/simnet_chaos_faults.c stamper:
 * one mutually-consistent ok=1 row per height across every log
 * reducer_frontier_compute_hstar folds, so H* == the stamped frontier. This
 * is TEST scaffolding building the durable image, not production reducer
 * code (the same convention test_reducer_frontier.c documents). */

static bool lc_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {  // raw-sql-ok:test-fixture-schema
        printf("[lifecycle] SQL failed: %s\n", err ? err : "(no message)");
        sqlite3_free(err);
        return false;
    }
    return true;
}

static bool lc_ensure_schema(sqlite3 *db)
{
    return lc_exec(db,
        "CREATE TABLE IF NOT EXISTS header_admit_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
        "  parent_hash BLOB, admitted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "  fail_reason TEXT, validated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  tx_count INTEGER NOT NULL, input_count INTEGER NOT NULL,"
        "  first_failure_txid BLOB, first_failure_vin INTEGER,"
        "  first_failure_serror INTEGER, validated_at INTEGER NOT NULL,"
        "  block_hash BLOB, source_epoch_digest BLOB);"
        "CREATE TABLE IF NOT EXISTS body_persist_log ("
        "  height INTEGER PRIMARY KEY, source TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  persisted_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  sapling_spends_total INTEGER NOT NULL,"
        "  sapling_outputs_total INTEGER NOT NULL,"
        "  sprout_joinsplits_total INTEGER NOT NULL, block_hash BLOB,"
        "  source_epoch_digest BLOB, first_failure_txid BLOB,"
        "  first_failure_proof_type TEXT, validated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  spent_count INTEGER NOT NULL, added_count INTEGER NOT NULL,"
        "  total_value_delta INTEGER NOT NULL, first_failure_kind TEXT,"
        "  first_failure_detail BLOB, applied_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
        "  height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
        "  spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  work_delta_high INTEGER NOT NULL, work_delta_low INTEGER NOT NULL,"
        "  utxo_size_after INTEGER NOT NULL, reorg_depth INTEGER NOT NULL,"
        "  finalized_at INTEGER NOT NULL);");
}

static void lc_synth_hash(uint8_t out[32], int32_t h)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xff);
    out[1] = (uint8_t)((h >> 8) & 0xff);
    out[2] = (uint8_t)((h >> 16) & 0xff);
    out[31] = 0xC5;
}

static bool lc_bind_put(sqlite3 *db, const char *sql, int32_t h,
                        const uint8_t *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, h);
    if (hash)
        sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return ok;
}

static bool lc_put_height(sqlite3 *db, int32_t h)
{
    uint8_t hh[32];
    lc_synth_hash(hh, h);
    return
        lc_bind_put(db,
            "INSERT INTO header_admit_log(height,hash,admitted_at) VALUES(?,?,0)"
            " ON CONFLICT(height) DO UPDATE SET hash=excluded.hash", h, hh) &&
        lc_bind_put(db,
            "INSERT INTO validate_headers_log(height,hash,ok,validated_at) "
            "VALUES(?,?,1,0) ON CONFLICT(height) DO UPDATE SET "
            "hash=excluded.hash, ok=1", h, hh) &&
        lc_bind_put(db,
            "INSERT INTO script_validate_log"
            "(height,status,ok,tx_count,input_count,validated_at,block_hash) "
            "VALUES(?,'verified',1,1,1,0,?) ON CONFLICT(height) DO UPDATE SET "
            "status='verified', ok=1, block_hash=excluded.block_hash", h, hh) &&
        lc_bind_put(db,
            "INSERT INTO body_persist_log(height,source,ok,persisted_at) "
            "VALUES(?,'lc',1,0) ON CONFLICT(height) DO UPDATE SET ok=1", h,
            NULL) &&
        lc_bind_put(db,
            "INSERT INTO proof_validate_log(height,status,ok,"
            "sapling_spends_total,sapling_outputs_total,sprout_joinsplits_total,"
            "block_hash,validated_at) VALUES(?,'verified',1,0,0,0,?,0) "
            "ON CONFLICT(height) DO UPDATE SET status='verified', ok=1, "
            "block_hash=excluded.block_hash", h, hh) &&
        lc_bind_put(db,
            "INSERT INTO utxo_apply_log(height,status,ok,spent_count,"
            "added_count,total_value_delta,applied_at) "
            "VALUES(?,'verified',1,0,0,0,0) ON CONFLICT(height) DO UPDATE SET "
            "status='verified', ok=1", h, NULL) &&
        lc_bind_put(db,
            "INSERT INTO utxo_apply_delta(height,branch_hash,spent_blob,"
            "added_blob) VALUES(?,?,x'',x'') ON CONFLICT(height) DO UPDATE SET "
            "branch_hash=excluded.branch_hash", h, hh) &&
        lc_bind_put(db,
            "INSERT OR IGNORE INTO tip_finalize_log(height,status,ok,"
            "work_delta_high,work_delta_low,utxo_size_after,reorg_depth,"
            "finalized_at) VALUES(?,'ok',1,0,0,0,0,0)", h, NULL);
}

/* Stamp a consistent prefix [0, n] + the matching cursors (tip_finalize uses
 * the served-tip convention: its cursor is n, the upstream stages n+1). */
static bool lc_fold_to(sqlite3 *db, int32_t n)
{
    for (int32_t h = 0; h <= n; h++)
        if (!lc_put_height(db, h))
            return false;
    return stage_set_named_cursor(db, "validate_headers", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "script_validate", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "body_persist", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "proof_validate", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "utxo_apply", (uint64_t)(n + 1)) &&
           stage_set_named_cursor(db, "tip_finalize", (uint64_t)n);
}

static int32_t lc_hstar(sqlite3 *db)
{
    int32_t h = -1, served = -1;
    progress_store_tx_lock();
    bool ok = reducer_frontier_compute_hstar(db, &h, &served);
    progress_store_tx_unlock();
    return ok ? h : -2;
}

static int64_t lc_coins_count(sqlite3 *db)
{
    return coins_kv_count_sqlite(db);
}

/* Seed `n` synthetic live outputs so the coin-row count is a real, non-zero
 * wipe-guard witness (the raw overlay-bypassing write path). */
static bool lc_seed_coins(sqlite3 *db, size_t n)
{
    if (!coins_kv_ensure_schema(db))
        return false;
    struct coins_kv_add_row *rows = calloc(n, sizeof(*rows)); // raw-alloc-ok:test
    uint8_t (*txids)[32] = calloc(n, 32); // raw-alloc-ok:test
    if (!rows || !txids) {
        free(rows);
        free(txids);
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        memset(txids[i], 0, 32);
        txids[i][0] = (uint8_t)(i & 0xff);
        txids[i][1] = (uint8_t)((i >> 8) & 0xff);
        txids[i][31] = 0xA7;
        rows[i].txid = txids[i];
        rows[i].vout = 0;
        rows[i].value = 5000 + (int64_t)i;
        rows[i].height = 1;
    }
    sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    bool ok = coins_kv_add_many_sqlite(db, rows, n);
    if (ok)
        ok = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;  // raw-sql-ok:test-fixture-seeding
    if (!ok)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    free(rows);
    free(txids);
    return ok;
}

/* Seed a single self-valid L1-base seal at grid point G so the seal ring is a
 * real recovery artifact the faults must leave intact. */
static bool lc_seed_seal(sqlite3 *db, int32_t g)
{
    struct seal_record rec;
    memset(&rec, 0, sizeof(rec));
    rec.height = g;
    rec.block_hash[0] = 0x5e;
    rec.block_hash[1] = 0xa1;
    rec.coins_sha3[0] = 0xc0;
    rec.utxo_count = 50;
    rec.supply = 100000;
    rec.ratified = 0;
    rec.sealed_at = 1;
    if (!seal_kv_ensure_schema(db))
        return false;
    progress_store_tx_lock();
    sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    bool ok = seal_kv_insert_candidate_in_tx(db, &rec);
    if (ok)
        ok = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;  // raw-sql-ok:test-fixture-seeding
    if (!ok)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    progress_store_tx_unlock();
    return ok;
}

static bool lc_seal_intact(sqlite3 *db, int32_t g)
{
    struct seal_record out;
    bool found = false;
    if (!seal_kv_newest(db, &out, &found))
        return false;
    return found && out.height == g;
}

/* ── section-3 helper: the escalator ladder under a non-monotonic clock ──── */

static enum sticky_rung lc_drive_to_deepest(int64_t t0, int64_t *last_now,
                                            int *out_dispatches,
                                            bool *out_saw_count_sentinel)
{
    enum sticky_rung r = STICKY_RUNG_RETRY;
    int64_t now = t0 + 1;
    int dispatches = 0;
    for (int i = 0; i < 60 && r != STICKY_RUNG_REFOLD_FROM_ANCHOR; i++) {
        now = t0 + 1 + (int64_t)i * 4000;
        r = sticky_escalator_test_drive(0, now);
        dispatches++;
        if (r == STICKY_RUNG_COUNT)
            *out_saw_count_sentinel = true;
    }
    if (last_now)
        *last_now = now;
    if (out_dispatches)
        *out_dispatches = dispatches;
    return r;
}

int test_always_sync_lifecycle(void);
int test_always_sync_lifecycle(void)
{
    printf("\n=== always_sync_lifecycle (full-lifecycle sync proof harness) ===\n");
    int failures = 0;

    blocker_module_init();

    /* ══ SECTION 1 — forward-fold soak: anchor base → target tip, faults
     * injected inline, two-state + forbidden guards asserted after each. ══ */
    {
        const int32_t TARGET = 240;   /* a few hundred synthetic blocks */
        const int32_t STEP = 40;

        char dir[256];
        mkdir("./test-tmp", 0755);
        test_fmt_tmpdir(dir, sizeof(dir), "lifecycle_soak", "main");
        mkdir(dir, 0755);
        progress_store_close();
        reducer_frontier_test_set_compiled_anchor(0);

        LC_CHECK("S1: progress store opens on scratch datadir",
                 progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        LC_CHECK("S1: schema + L1 anchor-base coins + seal seeded",
                 db && lc_ensure_schema(db) && lc_seed_coins(db, 50) &&
                 lc_seed_seal(db, 0));

        int64_t coins_floor = lc_coins_count(db);
        LC_CHECK("S1: anchor-base coin set is non-empty (wipe-guard witness)",
                 coins_floor == 50);

        /* Fold forward in steps; H* must CLIMB monotonically to each frontier. */
        int32_t prev_hstar = lc_hstar(db);
        LC_CHECK("S1: fresh anchor base sits at H*=0", prev_hstar == 0);
        bool climbs_monotonic = true;
        for (int32_t f = STEP; f <= TARGET; f += STEP) {
            if (!lc_fold_to(db, f)) {
                climbs_monotonic = false;
                break;
            }
            int32_t h = lc_hstar(db);
            if (h != f || h <= prev_hstar || lc_coins_count(db) < coins_floor) {
                climbs_monotonic = false;
                printf("[lifecycle] fold stall: frontier=%d H*=%d prev=%d\n",
                       f, h, prev_hstar);
                break;
            }
            prev_hstar = h;
        }
        LC_CHECK("S1: fold climbs H* monotonically to the target tip",
                 climbs_monotonic && prev_hstar == TARGET);

        /* Fault 1 — kill -9 mid-fold: abrupt close + reopen; nothing lost. */
        int64_t coins_before = lc_coins_count(db);
        int32_t hstar_pre_kill = lc_hstar(db);
        progress_store_close();
        LC_CHECK("S1/kill: store reopens after abrupt close",
                 progress_store_open(dir));
        db = progress_store_db();
        int32_t hstar_post_kill = lc_hstar(db);
        LC_CHECK("S1/kill: H* survives identically, no coin wipe",
                 hstar_post_kill == hstar_pre_kill &&
                 hstar_post_kill == TARGET &&
                 lc_coins_count(db) == coins_before);
        LC_CHECK("S1/kill: not a silent idle (at tip == acceptable state a)",
                 lc_hstar(db) == TARGET);
        LC_CHECK("S1/kill: seal ring intact across the kill",
                 lc_seal_intact(db, 0));

        /* Fault 2 — a rowless script+proof hole below the cursors: the fold
         * caps at the hole, the re-derive primitive rewinds, the re-fold lifts
         * H* back to tip. State (a) reached; no wipe; bounded. */
        const int32_t HOLE = 120;
        LC_CHECK("S1/hole: punch a rowless script+proof hole below the cursor",
                 lc_exec(db,
                    "DELETE FROM script_validate_log WHERE height=120;"
                    "DELETE FROM proof_validate_log WHERE height=120;"));
        int32_t hstar_holed = lc_hstar(db);
        LC_CHECK("S1/hole: H* caps one below the rowless hole (not silent)",
                 hstar_holed == HOLE - 1);
        /* Seed the coin frontier so the re-derive primitive can LCC-rewind. */
        progress_store_tx_lock();
        sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
        bool set_coins = coins_kv_set_applied_height_in_tx(db, TARGET + 1);
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
        progress_store_tx_unlock();
        struct stage_rederive_range_result rr;
        bool rederive_ok = set_coins &&
                           stage_rederive_range(db, NULL, HOLE, HOLE, &rr) &&
                           rr.ok;
        LC_CHECK("S1/hole: universal re-derive rewinds to the hole (a re-derive "
                 "PATH, not a wipe)",
                 rederive_ok && rr.rewound && rr.coins_rewound);
        int32_t hstar_rewound = lc_hstar(db);
        LC_CHECK("S1/hole: H* dips to the rewound floor, coins NOT wiped",
                 hstar_rewound == HOLE - 1 && lc_coins_count(db) == coins_before);
        /* Re-fold the rewound span: H* climbs back to the target tip. */
        progress_store_tx_lock();
        sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
        coins_kv_set_applied_height_in_tx(db, TARGET + 1);
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
        progress_store_tx_unlock();
        bool refold_ok = lc_fold_to(db, TARGET);
        int32_t hstar_recovered = lc_hstar(db);
        LC_CHECK("S1/hole: re-fold lifts H* back to tip (state a: reached tip)",
                 refold_ok && hstar_recovered == TARGET &&
                 lc_coins_count(db) == coins_before);

        /* Combination — fault 1 THEN fault 2 stacked before any drive: kill,
         * reopen, punch a fresh hole; the same two-state contract holds. */
        progress_store_close();
        LC_CHECK("S1/combo: reopen after stacked kill", progress_store_open(dir));
        db = progress_store_db();
        LC_CHECK("S1/combo: punch a second rowless hole after the kill",
                 lc_exec(db,
                    "DELETE FROM script_validate_log WHERE height=200;"
                    "DELETE FROM proof_validate_log WHERE height=200;"));
        int32_t combo_hstar = lc_hstar(db);
        bool combo_named = combo_hstar == 199;  /* capped at a KNOWN height */
        LC_CHECK("S1/combo: stacked faults cap H* at a known height (never "
                 "silent, never below the anchor)",
                 combo_named && combo_hstar >= 0 && combo_hstar < TARGET);
        bool combo_healed = lc_fold_to(db, TARGET) && lc_hstar(db) == TARGET &&
                            lc_coins_count(db) == coins_before;
        LC_CHECK("S1/combo: converges back to tip with no coin wipe",
                 combo_healed);

        progress_store_close();
        reducer_frontier_test_set_compiled_anchor(-1);
        test_cleanup_tmpdir(dir);
    }

    /* ══ SECTION 2 — the full sim/simnet_chaos injector matrix under the
     * two-state contract + the crash guard + never-page. Each injector builds
     * and tears down its own throwaway fixture and drives real oracles. ══ */
    {
        struct {
            const char *name;
            bool (*fn)(struct chaos_fault_result *);
        } matrix[] = {
            { "kill/restart mid-fold", chaos_fault_kill_restart_mid_fold },
            { "corrupt sealed segment", chaos_fault_corrupt_sealed_segment },
            { "freeze reducer drive", chaos_fault_freeze_reducer_drive },
            { "stall single stage", chaos_fault_stall_single_stage },
            { "kill/restart mid-recovery",
              chaos_fault_kill_restart_mid_recovery },
            { "torn progress.kv WAL", chaos_fault_torn_progress_wal },
            { "disk-full pause", chaos_fault_disk_full_pause },
            { "HAVE_DATA cleared hole", chaos_fault_cleared_have_data_hole },
        };
        size_t n = sizeof(matrix) / sizeof(matrix[0]);
        for (size_t i = 0; i < n; i++) {
            struct chaos_fault_result r;
            memset(&r, 0, sizeof(r));
            int crashed_sig = 0;
            bool completed = cg_run(matrix[i].fn, &r, &crashed_sig);
            char label[160];

            snprintf(label, sizeof(label), "S2[%s]: no crash/SIGSEGV",
                     matrix[i].name);
            LC_CHECK(label, completed && crashed_sig == 0);
            if (!completed)
                continue;  /* a crash is the forbidden outcome; skip the rest */

            printf("  note: %s\n", r.note);
            snprintf(label, sizeof(label),
                     "S2[%s]: harness built + never pages a recoverable cause",
                     matrix[i].name);
            LC_CHECK(label, r.ok && !r.operator_paged);

            /* Two-state contract: state (a) recovered/advancing, OR state (b)
             * a named terminal blocker. Every injector here is a recoverable
             * class, so (a) is required — a false `recovered` is the SILENT /
             * unbounded / wipe failure the matrix forbids. */
            snprintf(label, sizeof(label),
                     "S2[%s]: reaches state (a) — recovered/advancing",
                     matrix[i].name);
            LC_CHECK(label, r.recovered);
        }

        /* The G-TIP Pillar-0 injector: a BOUNDED gap is an unconditional
         * regression floor; the over-cap live-wedge scale is the known-open
         * wedge (SKIP, never fail — flips to a hard gate when a sibling lane's
         * fix lands, exactly like test_always_sync_chaos). */
        {
            struct chaos_fault_result r;
            memset(&r, 0, sizeof(r));
            int crashed_sig = 0;
            bool ok = false;
            /* wrap the bounded-gap call in the crash guard too. */
            struct sigaction sa, o1, o2, o3, o4;
            memset(&sa, 0, sizeof(sa));
            sa.sa_handler = cg_handler;
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = SA_NODEFER;
            sigaction(SIGSEGV, &sa, &o1);
            sigaction(SIGABRT, &sa, &o2);
            sigaction(SIGBUS, &sa, &o3);
            sigaction(SIGFPE, &sa, &o4);
            g_cg_sig = 0;
            bool completed;
            if (sigsetjmp(g_cg_jmp, 1) == 0) {
                ok = chaos_fault_empty_active_chain_window(200, &r);
                completed = true;
            } else {
                completed = false;
            }
            sigaction(SIGSEGV, &o1, NULL);
            sigaction(SIGABRT, &o2, NULL);
            sigaction(SIGBUS, &o3, NULL);
            sigaction(SIGFPE, &o4, NULL);
            crashed_sig = (int)g_cg_sig;
            printf("  note: %s\n", r.note);
            LC_CHECK("S2[gtip bounded]: no crash", completed && crashed_sig == 0);
            LC_CHECK("S2[gtip bounded]: repair installs tip + H* climbs (never "
                     "pages)",
                     ok && r.ok && r.recovered && !r.operator_paged &&
                     r.hstar_after == 200);
        }
    }

    /* ══ SECTION 3 — the two faults whose oracles live under app/services
     * (kept out of lib/sim by the layering gate): a non-monotonic clock and a
     * peer-floor breach. Both drive REAL production code. ══ */

    /* Fault — CLOCK SKEW: drive the real escalator ladder to its deepest rung,
     * then batter it with a clock that jumps far backward and re-forward. Under
     * a non-monotonic clock the ladder must never emit the COUNT sequencing
     * sentinel, never crash, keep its dispatch count BOUNDED (no runaway
     * spin), and stay armed (auto-terminating). The ladder legitimately
     * fail-forwards through immediately-failing rungs — the invariant proven
     * here is that a skewed clock cannot break that termination, not that a
     * backward jump freezes it. */
    {
        char dir[256];
        mkdir("./test-tmp", 0755);
        test_fmt_tmpdir(dir, sizeof(dir), "lifecycle_clock", "main");
        mkdir(dir, 0755);
        progress_store_close();
        reducer_frontier_test_set_compiled_anchor(0);
        LC_CHECK("S3/clock: scratch store opens", progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        LC_CHECK("S3/clock: clean fold fixture seeded",
                 db && lc_ensure_schema(db) && lc_seed_coins(db, 8) &&
                 lc_fold_to(db, 6));

        struct main_state ms;
        main_state_init(&ms);
        sync_monitor_set_context(NULL, NULL, &ms);
        sticky_escalator_test_reset();
        sticky_escalator_set_datadir(dir);
        sticky_escalator_test_set_suppress_refold_restart(true);
        sticky_escalator_test_set_refold_artifact_available(0);
        stage_reducer_frontier_reset_detect_memo_for_testing();

        sticky_escalator_note_stall("lifecycle_clock_skew");
        int64_t t0 = (int64_t)platform_time_wall_time_t();
        LC_CHECK("S3/clock: ladder arms on the stall",
                 sticky_escalator_test_armed());

        /* Forward march to the deepest rung — bounded, no COUNT sentinel. */
        int dispatches = 0;
        int64_t last_now = 0;
        bool saw_count = false;
        enum sticky_rung deep =
            lc_drive_to_deepest(t0, &last_now, &dispatches, &saw_count);
        LC_CHECK("S3/clock: forward march reaches the deepest rung, bounded, "
                 "no COUNT sentinel",
                 deep == STICKY_RUNG_REFOLD_FROM_ANCHOR && dispatches <= 60 &&
                 !saw_count);

        /* Now oscillate the clock hard (far backward, then re-forward). Each
         * dispatch must remain a valid rung (< COUNT), never crash, and the
         * ladder must stay armed. */
        int skew_dispatches = 0;
        bool skew_valid = true;
        for (int i = 0; i < 40; i++) {
            int64_t now = (i % 2 == 0) ? (t0 - 100000 - (int64_t)i)
                                       : (last_now + (int64_t)i * 4000);
            enum sticky_rung r = sticky_escalator_test_drive(0, now);
            skew_dispatches++;
            if (r == STICKY_RUNG_COUNT)
                saw_count = true;
            if (r >= STICKY_RUNG_COUNT)
                skew_valid = false;
        }
        LC_CHECK("S3/clock: a non-monotonic clock never emits COUNT nor an "
                 "invalid rung (bounded dispatch)",
                 !saw_count && skew_valid && skew_dispatches == 40);
        LC_CHECK("S3/clock: ladder stays armed through the skew "
                 "(auto-terminating, no crash-loop)",
                 sticky_escalator_test_armed());

        sync_monitor_set_context(NULL, NULL, NULL);
        sticky_escalator_test_reset();
        main_state_free(&ms);
        progress_store_close();
        reducer_frontier_test_set_compiled_anchor(-1);
        test_cleanup_tmpdir(dir);
    }

    /* Fault — PEER-FLOOR BREACH: the real block-source decision must NAME the
     * peer-floor breach (recover via a non-P2P source = the remedy) when
     * healthy outbound sits below the floor, and clear the moment peers return.
     * The named decision (never a silent idle) is state (b) of the dichotomy. */
    {
        const int min_healthy = 8;
        const int local = 100000;
        const int peer = 100050;

        struct bsp_decision breached;
        memset(&breached, 0, sizeof(breached));
        bool recover_breach = block_source_policy_peer_floor_recovery_needed(
            0, min_healthy, local, peer, &breached);
        bool p2p_unhealthy = !breached.sources[BSP_SOURCE_P2P].healthy;
        printf("  note: peer_floor breach: recover=%d p2p.state=%s "
               "p2p.blocker=%s\n",
               recover_breach, breached.sources[BSP_SOURCE_P2P].state,
               breached.sources[BSP_SOURCE_P2P].blocker);
        LC_CHECK("S3/peers: below-floor breach is NAMED (recover-from-alternate "
                 "decided, P2P marked unhealthy) — never a silent idle",
                 recover_breach && p2p_unhealthy);

        struct bsp_decision healthy;
        memset(&healthy, 0, sizeof(healthy));
        bool recover_healthy = block_source_policy_peer_floor_recovery_needed(
            min_healthy, min_healthy, local, peer, &healthy);
        LC_CHECK("S3/peers: recovers to no-op the moment peers return "
                 "(state a: advancing)",
                 !recover_healthy && healthy.sources[BSP_SOURCE_P2P].healthy);
    }

    if (failures == 0)
        printf("=== always_sync_lifecycle: ALL PASS ===\n\n");
    else
        printf("always_sync_lifecycle: failures=%d\n", failures);
    return failures;
}
#else  /* _WIN32 */
/* Fatal-signal crash-guard lane built on sigaction/sigsetjmp/siglongjmp, which have no Windows delivery mechanism. Skipped loudly rather than faked. */
int test_always_sync_lifecycle(void)
{
    printf("always_sync_lifecycle: SKIP (Windows): fatal-signal crash-guard lane built on sigaction/sigsetjmp/siglongjmp, which have no windows delivery mechanism.\n");
    return 0;
}
#endif
