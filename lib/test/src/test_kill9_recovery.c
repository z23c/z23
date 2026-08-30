/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * MVP criterion #7 CI gate: recover from `kill -9` in <2 min.
 *
 * Exercises the SIGKILL-mid-block-apply recovery surface that 
 * (`ac782fef5`) protects.  For each of 10 cycles:
 *   1. Parent `fork()`s a child.
 *   2. Child opens the shared datadir, walks a connect-block-style write
 *      sequence inside a BEGIN/COMMIT transaction (insert a batch of
 *      UTXOs at height h+1, update the coins_best_block tip pointer,
 *      insert the block-index row), with a small per-step delay to
 *      widen the kill window.
 *   3. Parent sleeps a randomised short duration (0.5ms–40ms), then
 *      `kill(pid, SIGKILL)` — covers different points across the
 *      transaction (pre-begin, mid-insert, pre-commit, post-commit).
 *   4. Parent `waitpid()`s, then reopens the datadir through
 *      `coins_view_sqlite_open()` — the same entry point the live node
 *      takes on boot.
 *   5. Parent asserts: the reopen succeeds (the boot-time atomicity
 *      check + auto-rewind already covered by
 *      `test_coins_view_atomicity` kicks in if the child died in the
 *      "UTXOs ahead of tip" window), and the post-recovery state has
 *      no UTXO row above the tip height — the exact invariant
 *      `test_coins_view_atomicity` asserts, but now exercised under a
 *      real SIGKILL instead of a hand-crafted mismatch.
 *
 * Total elapsed time across all 10 cycles must stay under the
 * 2-minute MVP budget.
 *
 * What this test proves
 * ---------------------
 *   - SQLite's BEGIN/COMMIT atomicity survives `SIGKILL` — the journal
 *     rollback path is never half-applied.
 *   - `coins_view_sqlite_open`'s boot-time invariant (`utxos.height
 *     must never exceed tip.height`) auto-heals the crash-mid-flush
 *     shape (single-block overshoot ≤32 rows — see
 *     `test_coins_view_atomicity:t_utxos_one_ahead_auto_rewound`).
 *   - A `SIGKILL` anywhere during a realistic write loop does not
 *     leave the datadir in a shape the operator would have to fix
 *     by hand.
 *
 * What this test does NOT prove
 * -----------------------------
 *   - Full-binary cold restart recovery (that's MVP criterion #6's
 *     soak test — `deploy/zclassic23.service` under systemd).
 *   - Protocol-level resync after restart (covered by MVP criterion
 * #3, `test_cold_start_sync`).
 *   - Block validation correctness (covered by
 *     `test_chain_stall_repro`, `test_chain_rollback`,
 *     `test_consensus_reject_events`).
 *
 * It proves the narrower but load-bearing claim: "on-disk state is
 * atomically recoverable after `SIGKILL`", which is the hard part of
 * MVP criterion #7.
 *
 * Two further crash windows (plan lane 2.4, robustness matrix
 * extension), each its own fork+SIGKILL cycle set reusing the SAME
 * pattern above:
 *
 *   - MID-MINT-FOLD (p11_7mf_*): drives the REAL durable-marker API the
 *     offline `-mint-anchor` producer uses (`mint_anchor_producer_lane_bind`
 *     / `mint_anchor_progress_mark` / `_can_resume`, config/src/
 *     mint_anchor_progress.c) plus the REAL coins_kv per-block apply shape
 *     (`coins_kv_add_many` + `coins_kv_set_applied_height_in_tx` inside one
 *     BEGIN IMMEDIATE, storage/coins_kv.h) — the same atomic unit
 *     `utxo_apply_stage.c`'s forward-apply step commits. On every reopen it
 *     asserts the qed-harvested invariant by name: the durable
 *     coins_applied_height cursor's implied row count
 *     (`(applied_through+1) * rows_per_step`) must equal `coins_kv_count()`
 *     EXACTLY — the cursor can never be ahead of (or behind) the content it
 *     claims, which is exactly what the drain pre-commit veto guarantees in
 *     production. `mint_anchor_progress_can_resume()` must authorize one of
 *     exactly two clean outcomes at every reopen: a non-legacy RESUME when
 *     fold progress exists, or — since cf71eb314 — the sanctioned GENESIS
 *     RESET when the marker matches but nothing was ever applied (an empty
 *     resume would skip the reset that truncates coins_kv and wedge the
 *     producer against its node.db mirror). Any other refusal is the silent
 *     wedge this test exists to catch; a final
 *     uninterrupted drain to the last step plus `mint_anchor_progress_clear`
 *     proves the OTHER named terminal (verified completion) is always
 *     reachable regardless of interruption history.
 *
 *   - MID-IMPORTBLOCKINDEX (p11_7ib_*): forks real calls to
 *     `snapshot_import_block_index()` (app/controllers/src/
 *     snapshot_controller_import.c) — the function `--importblockindex`
 *     dispatches to, the MANDATORY FIRST STEP of the two-step cold-sync
 *     recipe (CLAUDE.md "Tenacity & recovery"). Self-calibrates the SIGKILL
 *     delay window from one timed uninterrupted run (portable across dev
 *     boxes without a hardcoded duration guess) then asserts the `blocks`
 *     table is EMPTY or FULLY populated on every reopen — never partial —
 *     and that the fast-boot cursors (pprev_repaired_height /
 *     shielded_backfill_height) are never stamped unless the row count is
 *     also full (the same cursor-ahead-of-content shape, on a different
 *     write path). A final uninterrupted re-run proves the fully-imported
 *     terminal is always reachable.
 *
 * Gating
 * ------
 * Skipped unless `ZCL_STRESS_TESTS=1`.  The test spawns child processes and
 * does real SQLite/LevelDB I/O against a tempdir — measured at low tens of
 * seconds on the dev box across all three phases.  Keeping it out of
 * `make test` default protects the default suite's sub-minute budget.
 *
 * Invocation
 * ----------
 *   ZCL_STRESS_TESTS=1 build/bin/test_zcl
 *   ZCL_STRESS_TESTS=1 ZCL_TEST_ONLY=kill9 build/bin/test_zcl (focused)
 *
 * MVP linkage
 * -----------
 * Flips `MVP.md` criterion #7 from ☐ to ✅.  Forward-looking CI
 * gate, not RED-first.
 */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "storage/coins_view_sqlite.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <time.h>
#include <unistd.h>

/* ── MID-MINT-FOLD phase deps ── */
#include "chain/checkpoints.h"
#include "chain/chainparams.h"
#include "config/mint_anchor_progress.h"
#include "core/arith_uint256.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

/* ── MID-IMPORTBLOCKINDEX phase deps ── */
#include "chain/chain.h"           /* BLOCK_VALID_TRANSACTIONS/HAVE_DATA/HAVE_UNDO */
#include "controllers/snapshot_controller.h"
#include "core/serialize.h"
#include "models/block.h"
#include "models/database.h"
#include "storage/block_index_db.h"
#include "storage/dbwrapper.h"
#include "util/safe_alloc.h"

int test_kill9_recovery(void);

/* ── Datadir helpers ────────────────────────────────────────
 *
 * Mirror the minimal SQLite schema builder from
 * `test_coins_view_atomicity.c` so this test is self-contained and
 * doesn't drag in node_db's full migration cost.  The helpers there
 * are file-static; duplicating (not extracting) keeps both tests
 * independent. */

static int p11_7_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

static void p11_7_dir_path(char *buf, size_t n)
{
    snprintf(buf, n, "./test-tmp/kill9_%d", (int)getpid());
}

static bool p11_7_build_schema(sqlite3 *db)
{
    char *err = NULL;
    int rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS utxos("
        " txid BLOB, vout INTEGER, value INTEGER,"
        " script BLOB, script_type INTEGER, address_hash BLOB,"
        " height INTEGER, is_coinbase INTEGER,"
        " PRIMARY KEY(txid,vout));"
        "CREATE TABLE IF NOT EXISTS node_state("
        " key TEXT PRIMARY KEY, value BLOB);"
        "CREATE TABLE IF NOT EXISTS blocks("
        " hash BLOB PRIMARY KEY, height INTEGER, status INTEGER);",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "p11_7 build_schema: %s\n", err ? err : "?");
        sqlite3_free(err);
        return false;
    }
    return true;
}

/* ── Query the current tip height via node_state + blocks join ── */

static int p11_7_query_tip_height(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    int height = -1;
    int rc = sqlite3_prepare_v2(db,
        "SELECT b.height FROM blocks b, node_state n "
        "WHERE n.key = 'coins_best_block' AND b.hash = n.value",
        -1, &s, NULL);
    if (rc == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW)
        height = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return height;
}

/* ── Count UTXO rows strictly above the tip — the regression invariant ── */

static int p11_7_count_utxos_above_tip(sqlite3 *db)
{
    int tip = p11_7_query_tip_height(db);
    if (tip < 0) return -1;
    sqlite3_stmt *s = NULL;
    int n = 0;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM utxos WHERE height > ?", -1, &s, NULL) == SQLITE_OK) {
        sqlite3_bind_int(s, 1, tip);
        if (sqlite3_step(s) == SQLITE_ROW)
            n = sqlite3_column_int(s, 0);
    }
    sqlite3_finalize(s);
    return n;
}

/* ── Child worker: realistic write loop, designed to be killed ──
 *
 * Each "block" application is wrapped in its own BEGIN/COMMIT —
 * matches the per-block atomicity guarantee the live node relies on.
 * A small nanosleep between steps widens the kill window so the
 * randomised parent delay has a real chance of landing mid-cycle.
 *
 * On success (not killed), the child exits 0 after applying the full
 * block batch.  On SIGKILL, the process dies leaving whichever
 * BEGIN/COMMIT rounds had already landed and possibly one
 * partially-staged transaction the SQLite journal will roll back on
 * the parent's next open. */

static void p11_7_child_worker(const char *dbpath, int start_height)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(dbpath, &db) != SQLITE_OK)
        _exit(1);

    /* WAL mode matches production (see boot_services.c); gives the
     * fastest recovery path on reopen. */
    sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);

    const int n_blocks = 30;
    for (int i = 0; i < n_blocks; i++) {
        int h = start_height + 1 + i;

        if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
            _exit(2);

        /* Insert the block-index row first — matches the live write
         * order in connect_block. */
        uint8_t hash[32];
        memset(hash, (uint8_t)(0xA0 ^ (h & 0xFF)), 32);
        /* Mix the iteration into the hash so each block has a unique
         * primary key. */
        hash[0] ^= (uint8_t)(h >> 8);

        sqlite3_stmt *s = NULL;
        sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO blocks(hash,height,status) VALUES(?,?,3)",
            -1, &s, NULL);
        sqlite3_bind_blob(s, 1, hash, 32, SQLITE_TRANSIENT);
        sqlite3_bind_int(s, 2, h);
        sqlite3_step(s);
        sqlite3_finalize(s);

        /* Insert a handful of UTXOs at this block's height. */
        for (int k = 0; k < 4; k++) {
            uint8_t txid[32];
            memset(txid, 0, 32);
            txid[0] = (uint8_t)(h & 0xFF);
            txid[1] = (uint8_t)((h >> 8) & 0xFF);
            txid[2] = (uint8_t)k;
            sqlite3_prepare_v2(db,
                "INSERT OR REPLACE INTO utxos(txid,vout,value,script,"
                " script_type,address_hash,height,is_coinbase) "
                "VALUES(?,0,0,NULL,0,NULL,?,0)", -1, &s, NULL);
            sqlite3_bind_blob(s, 1, txid, 32, SQLITE_TRANSIENT);
            sqlite3_bind_int(s, 2, h);
            sqlite3_step(s);
            sqlite3_finalize(s);
        }

        /* Update the tip pointer LAST — the ordering that makes the
         * "UTXOs ahead of tip" pathology observable if we get killed
         * between the UTXO inserts and the tip update. */
        sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO node_state(key,value) "
            "VALUES('coins_best_block',?)", -1, &s, NULL);
        sqlite3_bind_blob(s, 1, hash, 32, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);

        if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
            _exit(3);

        /* Widen the kill window: ~1ms per block.  30 blocks * 1ms ≈
         * 30ms total — covers the full 0.5-40ms randomised parent
         * kill range. */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000L };
        nanosleep(&ts, NULL);
    }

    sqlite3_close(db);
    _exit(0);
}

/* ── One kill-and-recover cycle ───────────────────────────── */

static int p11_7_one_cycle(const char *dbpath, int cycle_idx,
                            unsigned int *rng_state)
{
    int start_height;
    {
        sqlite3 *db = NULL;
        if (sqlite3_open(dbpath, &db) != SQLITE_OK) {
            printf("FAIL (cycle %d: pre-fork open failed)\n", cycle_idx);
            return 1;
        }
        start_height = p11_7_query_tip_height(db);
        sqlite3_close(db);
    }
    if (start_height < 0) {
        printf("FAIL (cycle %d: no tip before fork)\n", cycle_idx);
        return 1;
    }

#if defined(_WIN32)
    /* Re-exec the crash victim; TerminateProcess is the SIGKILL analogue. */
    void *hp = NULL;
    {
        char k9_log[560];
        char k9_start[32];
        snprintf(k9_log, sizeof(k9_log), "%s.k9child.log", dbpath);
        snprintf(k9_start, sizeof(k9_start), "%d", start_height);
        if (_putenv_s("ZCL_K9_DB", dbpath) != 0 ||
            _putenv_s("ZCL_K9_START", k9_start) != 0) {
            printf("FAIL (cycle %d: child env setup failed)\n", cycle_idx);
            return 1;
        }
        hp = test_spawn_self_with_role("test_kill9_recovery", "p11_7",
                                       k9_log);
        _putenv_s("ZCL_K9_DB", "");
        _putenv_s("ZCL_K9_START", "");
    }
    if (!hp) {
        printf("FAIL (cycle %d: child spawn failed)\n", cycle_idx);
        return 1;
    }

    /* Randomised kill delay: 0.5ms to ~40ms.  Covers cases where the
     * child is (a) still opening the DB, (b) mid-transaction, (c)
     * between COMMIT rounds, (d) already finished (delay > 30ms). */
    long delay_us = 500 + (long)(rand_r(rng_state) % 40000);
    struct timespec delay_ts = {
        .tv_sec = 0,
        .tv_nsec = delay_us * 1000,
    };
    nanosleep(&delay_ts, NULL);

    /* Like kill(pid, SIGKILL): if the child already finished, the terminate
     * is a no-op and the reaped exit code is its own. */
    test_self_child_kill(hp);
    int wcode = test_self_child_wait(hp);
    bool killed = (wcode == 137); /* test_self_child_kill's exit code */
    bool exited = (wcode == 0);
    if (!killed && !exited) {
        printf("FAIL (cycle %d: child ended abnormally; exit=%d)\n",
               cycle_idx, wcode);
        return 1;
    }
#else
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        p11_7_child_worker(dbpath, start_height);
        /* unreachable — child always _exit()s */
        _exit(99);
    }

    /* Randomised kill delay: 0.5ms to ~40ms.  Covers cases where the
     * child is (a) still opening the DB, (b) mid-transaction, (c)
     * between COMMIT rounds, (d) already finished (delay > 30ms). */
    long delay_us = 500 + (long)(rand_r(rng_state) % 40000);
    struct timespec delay_ts = {
        .tv_sec = 0,
        .tv_nsec = delay_us * 1000,
    };
    nanosleep(&delay_ts, NULL);

    if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
        /* ESRCH = child already finished; that's fine. */
        perror("kill");
        waitpid(pid, NULL, 0);
        return 1;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) != pid) {
        perror("waitpid");
        return 1;
    }
    bool killed = WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
    bool exited = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!killed && !exited) {
        printf("FAIL (cycle %d: child ended abnormally; "
               "WIFSIGNALED=%d WIFEXITED=%d status=%d)\n",
               cycle_idx, WIFSIGNALED(status), WIFEXITED(status), status);
        return 1;
    }
#endif

    /* Parent reopens through the live node's entry point.  This is
     * where the "UTXOs ahead of tip → auto-rewind-or-refuse" invariant
     * fires (see test_coins_view_atomicity). */
    sqlite3 *rdb = NULL;
    if (sqlite3_open(dbpath, &rdb) != SQLITE_OK) {
        printf("FAIL (cycle %d: reopen failed after %s)\n",
               cycle_idx, killed ? "SIGKILL" : "clean exit");
        return 1;
    }
    sqlite3_exec(rdb, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);

    struct coins_view_sqlite cvs;
    bool opened = coins_view_sqlite_open(&cvs, rdb);
    if (!opened) {
        /* The boot-time integrity check refused.  That's an acceptable
         * outcome if the overshoot exceeds the auto-rewind threshold
         * (32 rows per test_coins_view_atomicity:t_utxos_one_ahead_too_many_rejected).
         * But for our workload (4 UTXOs per block, 30 blocks max), the
         * overshoot should always be ≤ a few rows — auto-heal should
         * succeed every time.  A refusal here is a regression. */
        printf("FAIL (cycle %d: coins_view_sqlite_open refused after %s)\n",
               cycle_idx, killed ? "SIGKILL" : "clean exit");
        sqlite3_close(rdb);
        return 1;
    }
    coins_view_sqlite_close(&cvs);

    /* Post-recovery invariant: no UTXO row above the tip height. */
    int overshoot = p11_7_count_utxos_above_tip(rdb);
    if (overshoot != 0) {
        printf("FAIL (cycle %d: %d UTXO row(s) above tip after recovery "
               "— auto-rewind did not restore the invariant)\n",
               cycle_idx, overshoot);
        sqlite3_close(rdb);
        return 1;
    }

    sqlite3_close(rdb);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 * MID-MINT-FOLD kill9 phase
 *
 * Drives the REAL durable-marker API the offline `-mint-anchor` producer
 * uses (config/src/mint_anchor_progress.c) and the REAL per-block coins_kv
 * apply shape (storage/coins_kv.h: coins_kv_add_many +
 * coins_kv_set_applied_height_in_tx inside ONE BEGIN IMMEDIATE — the same
 * atomic unit utxo_apply_stage.c's forward-apply step commits) against a
 * fresh progress.kv, killing the child mid-fold and reopening through the
 * SAME `mint_anchor_progress_can_resume()` gate a real restart of the
 * producer calls before resuming.
 * ════════════════════════════════════════════════════════════════════════ */

#define MF_ROWS_PER_STEP 3
#define MF_N_STEPS       48
#define MF_BATCH         8

/* Deterministic per-step coin rows: step h contributes MF_ROWS_PER_STEP
 * outputs, each with a txid derived from h so a later coins_kv_exists probe
 * can name exactly which step's content is being checked. `txids` must
 * outlive the coins_kv_add_many call (it binds SQLITE_TRANSIENT copies, but
 * the caller still owns the array through the call). */
static void mf_step_rows(int32_t step, struct coins_kv_add_row rows[MF_ROWS_PER_STEP],
                         uint8_t txids[MF_ROWS_PER_STEP][32])
{
    for (int k = 0; k < MF_ROWS_PER_STEP; k++) {
        memset(txids[k], 0, 32);
        txids[k][0] = (uint8_t)(step & 0xFF);
        txids[k][1] = (uint8_t)((step >> 8) & 0xFF);
        txids[k][2] = (uint8_t)k;
        txids[k][31] = 0xC9;
        rows[k].txid = txids[k];
        rows[k].vout = 0;
        rows[k].value = 1000 + step;
        rows[k].height = step;
        rows[k].is_coinbase = (k == 0);
        rows[k].script = NULL;
        rows[k].script_len = 0;
    }
}

/* Child worker: fold steps [start_step, end_step) — each step is ONE
 * BEGIN IMMEDIATE / coins_kv_add_many + coins_kv_set_applied_height_in_tx /
 * COMMIT, mirroring the real forward-apply step's atomic unit. A small
 * nanosleep between steps widens the SIGKILL window, same convention as
 * p11_7_child_worker above. */
static void mf_child_worker(const char *dir, int32_t start_step, int32_t end_step)
{
    if (!progress_store_open(dir))
        _exit(1);
    sqlite3 *db = progress_store_db();
    if (!db)
        _exit(2);

    for (int32_t step = start_step; step < end_step; step++) {
        progress_store_tx_lock();
        bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;

        uint8_t txids[MF_ROWS_PER_STEP][32];
        struct coins_kv_add_row rows[MF_ROWS_PER_STEP];
        mf_step_rows(step, rows, txids);

        ok = ok && coins_kv_add_many(db, rows, MF_ROWS_PER_STEP);
        ok = ok && coins_kv_set_applied_height_in_tx(db, step + 1);
        ok = ok && sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
        progress_store_tx_unlock();

        if (!ok)
            _exit(3);

        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000L };
        nanosleep(&ts, NULL);
    }

    progress_store_close();
    _exit(0);
}

/* Read the durable applied frontier (coins_kv's "next height to apply").
 * *out_start_step receives that frontier, or 0 when absent (nothing folded
 * yet). Returns false only on a hard read error. */
static bool mf_read_start_step(const char *dir, int32_t *out_start_step)
{
    *out_start_step = 0;
    if (!progress_store_open(dir))
        return false;
    sqlite3 *db = progress_store_db();
    int32_t frontier = 0;
    bool found = false;
    bool ok = db && coins_kv_get_applied_height(db, &frontier, &found);
    progress_store_close();
    if (!ok)
        return false;
    *out_start_step = found ? frontier : 0;
    return true;
}

static int p11_7mf_run_phase(void)
{
    int failures = 0;
    printf("\n=== kill -9 mid-mint-fold recovery ===\n");

    char dir[300];
    snprintf(dir, sizeof(dir), "./test-tmp/kill9mf_%d", (int)getpid());
    p11_7_mkdir_p("./test-tmp");
    test_cleanup_tmpdir(dir);
    p11_7_mkdir_p(dir);

    /* Fixture checkpoint: only its OWN internal consistency matters here
     * (mark/can_resume compare against the SAME struct every call) — it does
     * not need to match a compiled checkpoint. */
    struct sha3_utxo_checkpoint cp;
    memset(&cp, 0, sizeof(cp));
    cp.height = MF_N_STEPS - 1;
    cp.utxo_count = (uint64_t)MF_N_STEPS * MF_ROWS_PER_STEP;
    cp.total_supply = 0;
    memset(cp.block_hash, 0xEE, sizeof(cp.block_hash));
    memset(cp.sha3_hash, 0xAB, sizeof(cp.sha3_hash));

    /* Setup: bind the producer lane + write the durable in-progress marker —
     * exactly the durable state the real -mint-anchor producer leaves before
     * folding a single block. This is the marker mint_anchor_progress_can_
     * resume() below authenticates on every reopen. */
    {
        if (!progress_store_open(dir)) {
            printf("FAIL (mint-fold: progress_store_open setup failed)\n");
            return 1;
        }
        sqlite3 *db = progress_store_db();
        bool setup_ok = db && coins_kv_ensure_schema(db) &&
                        mint_anchor_producer_lane_bind(db, /*checkpoint_fold=*/true) &&
                        mint_anchor_progress_mark(db, &cp);
        progress_store_close();
        if (!setup_ok) {
            printf("FAIL (mint-fold: producer lane / marker setup failed)\n");
            test_cleanup_tmpdir(dir);
            return 1;
        }
    }

    const int n_cycles = 10;
    const int budget_sec = 60;
    unsigned int rng = (unsigned int)(platform_time_wall_time_t() ^ getpid() ^ 0x4d46u);
    time_t t0 = platform_time_wall_time_t();

    for (int i = 0; i < n_cycles && !failures; i++) {
        int32_t start_step = 0;
        if (!mf_read_start_step(dir, &start_step)) {
            printf("FAIL (mint-fold cycle %d: pre-fork frontier read failed)\n", i);
            failures++;
            break;
        }
        if (start_step >= MF_N_STEPS)
            break; /* already complete from an earlier cycle's clean finish */

        int32_t end_step = start_step + MF_BATCH;
        if (end_step > MF_N_STEPS) end_step = MF_N_STEPS;

#if defined(_WIN32)
        void *hp = NULL;
        {
            char k9_log[340];
            char k9_ss[24], k9_se[24];
            snprintf(k9_log, sizeof(k9_log), "%s/k9mf_child.log", dir);
            snprintf(k9_ss, sizeof(k9_ss), "%d", (int)start_step);
            snprintf(k9_se, sizeof(k9_se), "%d", (int)end_step);
            if (_putenv_s("ZCL_K9_DIR", dir) != 0 ||
                _putenv_s("ZCL_K9_START", k9_ss) != 0 ||
                _putenv_s("ZCL_K9_END", k9_se) != 0) {
                printf("FAIL (mint-fold cycle %d: child env setup failed)\n",
                       i);
                failures++;
                break;
            }
            hp = test_spawn_self_with_role("test_kill9_recovery", "mf",
                                           k9_log);
            _putenv_s("ZCL_K9_DIR", "");
            _putenv_s("ZCL_K9_START", "");
            _putenv_s("ZCL_K9_END", "");
        }
        if (!hp) {
            printf("FAIL (mint-fold cycle %d: child spawn failed)\n", i);
            failures++;
            break;
        }

        long delay_us = 300 + (long)(rand_r(&rng) % 9000);
        struct timespec delay_ts = { .tv_sec = 0, .tv_nsec = delay_us * 1000 };
        nanosleep(&delay_ts, NULL);

        test_self_child_kill(hp);
        int wcode = test_self_child_wait(hp);
        bool killed = (wcode == 137);
        bool exited_ok = (wcode == 0);
        if (!killed && !exited_ok) {
            printf("FAIL (mint-fold cycle %d: child ended abnormally; "
                   "exit=%d)\n", i, wcode);
            failures++;
            break;
        }
#else
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); failures++; break; }
        if (pid == 0) {
            mf_child_worker(dir, start_step, end_step);
            _exit(99); /* unreachable */
        }

        long delay_us = 300 + (long)(rand_r(&rng) % 9000);
        struct timespec delay_ts = { .tv_sec = 0, .tv_nsec = delay_us * 1000 };
        nanosleep(&delay_ts, NULL);

        if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
            perror("kill");
            waitpid(pid, NULL, 0);
            failures++;
            break;
        }
        int status = 0;
        if (waitpid(pid, &status, 0) != pid) {
            perror("waitpid");
            failures++;
            break;
        }
        bool killed = WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
        bool exited_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (!killed && !exited_ok) {
            printf("FAIL (mint-fold cycle %d: child ended abnormally; "
                   "WIFSIGNALED=%d WIFEXITED=%d status=%d)\n",
                   i, WIFSIGNALED(status), WIFEXITED(status), status);
            failures++;
            break;
        }
#endif

        /* Reopen — the same durable-marker inspection a real restart of the
         * offline -mint-anchor producer performs before resuming a fold. */
        if (!progress_store_open(dir)) {
            printf("FAIL (mint-fold cycle %d: reopen failed after %s)\n",
                   i, killed ? "SIGKILL" : "clean exit");
            failures++;
            break;
        }
        sqlite3 *db = progress_store_db();

        int32_t applied_through = -2;
        bool legacy_adopted = true; /* poison — must come back false */
        bool can_resume = mint_anchor_progress_can_resume(db, &cp, &applied_through,
                                                           &legacy_adopted);
        if (!can_resume) {
            /* cf71eb314 contract: an intact matched marker with NOTHING
             * durably applied authorizes a genesis reset (can_resume=false)
             * rather than an empty resume — resuming would skip the reset
             * that truncates coins_kv. That refusal is clean ONLY when it is
             * provably the empty case: no durable frontier and nothing
             * adopted. Any other false here is the silent wedge this test
             * exists to catch (a kill after real progress must resume). */
            int32_t empty_frontier = 0;
            bool have_frontier = true; /* poison — must come back false */
            if (legacy_adopted ||
                !coins_kv_get_applied_height(db, &empty_frontier,
                                             &have_frontier) ||
                have_frontier) {
                printf("FAIL (mint-fold cycle %d: unexpected resume refusal: "
                       "legacy_adopted=%d have_frontier=%d — a SIGKILL after "
                       "the marker was written must end in exactly one clean "
                       "state: non-legacy resume when progress exists, or the "
                       "sanctioned genesis reset only while nothing was ever "
                       "applied — never a silent wedge)\n",
                       i, legacy_adopted, have_frontier);
                failures++;
                progress_store_close();
                break;
            }
            /* Mirror boot_refold_staged.c's false branch: re-bind the lane,
             * re-mark, and fold again from step 0. */
            bool rearmed = mint_anchor_producer_lane_bind(
                               db, /*checkpoint_fold=*/true) &&
                           mint_anchor_progress_mark(db, &cp);
            progress_store_close();
            if (!rearmed) {
                printf("FAIL (mint-fold cycle %d: could not re-arm the "
                       "producer lane/marker after a sanctioned genesis "
                       "reset)\n", i);
                failures++;
                break;
            }
            printf("[kill9mf] cycle %d: SIGKILL landed pre-first-commit — "
                   "sanctioned genesis reset taken, producer re-armed\n", i);
            continue;
        }
        if (legacy_adopted) {
            printf("FAIL (mint-fold cycle %d: legacy_adopted=1 on a resumed "
                   "fold — this fixture never arms the refold signal, so "
                   "legacy adoption must be impossible)\n", i);
            failures++;
            progress_store_close();
            break;
        }

        /* THE qed-harvested assertion: the durable applied-through cursor
         * must never be AHEAD of the coin content it implies. Exactly
         * (applied_through+1) * MF_ROWS_PER_STEP rows must exist — no more,
         * no less — regardless of where inside the per-step BEGIN/COMMIT the
         * SIGKILL landed. This is the drain pre-commit veto's invariant,
         * proven here under a real SIGKILL instead of by construction. */
        int64_t expect_count = applied_through < 0
                                    ? 0
                                    : (int64_t)(applied_through + 1) * MF_ROWS_PER_STEP;
        int64_t actual_count = coins_kv_count(db);
        if (actual_count != expect_count) {
            printf("FAIL (mint-fold cycle %d: cursor/content mismatch — "
                   "applied_through=%d implies %lld coin row(s) but coins_kv "
                   "holds %lld — the applied cursor raced ahead of (or fell "
                   "behind) its own content)\n",
                   i, applied_through, (long long)expect_count,
                   (long long)actual_count);
            failures++;
            progress_store_close();
            break;
        }

        /* Point check at the exact boundary: the last-applied step's own
         * coin is present; the next (not-yet-applied) step's coin is absent. */
        bool boundary_ok = true;
        if (applied_through >= 0) {
            uint8_t txids[MF_ROWS_PER_STEP][32];
            struct coins_kv_add_row rows[MF_ROWS_PER_STEP];
            mf_step_rows(applied_through, rows, txids);
            boundary_ok = coins_kv_exists(db, txids[0], 0);
        }
        if (boundary_ok && applied_through + 1 < MF_N_STEPS) {
            uint8_t txids[MF_ROWS_PER_STEP][32];
            struct coins_kv_add_row rows[MF_ROWS_PER_STEP];
            mf_step_rows(applied_through + 1, rows, txids);
            boundary_ok = !coins_kv_exists(db, txids[0], 0);
        }
        if (!boundary_ok) {
            printf("FAIL (mint-fold cycle %d: boundary coin check failed at "
                   "applied_through=%d)\n", i, applied_through);
            failures++;
            progress_store_close();
            break;
        }

        progress_store_close();
    }

    /* Terminal: drain any remaining steps UNINTERRUPTED, then clear the
     * durable marker — models the real producer's "snapshot written +
     * hard-verified" completion step. Proves the OTHER named terminal
     * (verified completion) is always reachable regardless of how many
     * SIGKILLs preceded it. */
    if (!failures) {
        int32_t start_step = 0;
        if (!mf_read_start_step(dir, &start_step)) {
            printf("FAIL (mint-fold: final frontier read failed)\n");
            failures++;
        } else if (!progress_store_open(dir)) {
            printf("FAIL (mint-fold: final reopen failed)\n");
            failures++;
        } else {
            sqlite3 *db = progress_store_db();
            bool ok = true;
            for (int32_t step = start_step; step < MF_N_STEPS && ok; step++) {
                progress_store_tx_lock();
                ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
                uint8_t txids[MF_ROWS_PER_STEP][32];
                struct coins_kv_add_row rows[MF_ROWS_PER_STEP];
                mf_step_rows(step, rows, txids);
                ok = ok && coins_kv_add_many(db, rows, MF_ROWS_PER_STEP);
                ok = ok && coins_kv_set_applied_height_in_tx(db, step + 1);
                ok = ok && sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
                progress_store_tx_unlock();
            }

            int64_t final_count = coins_kv_count(db);
            int32_t final_frontier = 0;
            bool final_found = false;
            bool frontier_ok = coins_kv_get_applied_height(db, &final_frontier,
                                                            &final_found);
            bool complete = ok && final_count == (int64_t)MF_N_STEPS * MF_ROWS_PER_STEP &&
                            frontier_ok && final_found && final_frontier == MF_N_STEPS;
            if (!complete) {
                printf("FAIL (mint-fold: uninterrupted drain to completion "
                       "failed — ok=%d count=%lld frontier=%d found=%d)\n",
                       ok, (long long)final_count, final_frontier, final_found);
                failures++;
            } else {
                bool cleared = mint_anchor_progress_clear(db);
                /* MINT_ANCHOR_MARKER_LEN (48) is private to
                 * mint_anchor_progress.c — size generously rather than
                 * duplicate the private constant. */
                uint8_t marker_after[64] = {0};
                size_t marker_after_n = 0;
                bool marker_after_found = true; /* poison — must come back false */
                bool read_ok = cleared &&
                    progress_meta_get_blob_exact(db, MINT_ANCHOR_IN_PROGRESS_KEY,
                                                 marker_after, sizeof(marker_after),
                                                 &marker_after_n, &marker_after_found);
                if (!cleared || !read_ok || marker_after_found) {
                    printf("FAIL (mint-fold: marker clear terminal failed — "
                           "cleared=%d read_ok=%d still_present=%d)\n",
                           cleared, read_ok, marker_after_found);
                    failures++;
                } else {
                    printf(" mint_fold kill9 OK (%d cycles; cursor never raced "
                           "ahead of content at any reopen; drained to h=%d, "
                           "%lld coins; marker cleared — verified-completion "
                           "terminal reached)\n",
                           n_cycles, MF_N_STEPS - 1, (long long)final_count);
                }
            }
            progress_store_close();
        }
    }

    int elapsed = (int)(platform_time_wall_time_t() - t0);
    if (!failures && elapsed > budget_sec) {
        printf("FAIL (mint-fold: %d cycles took %ds, exceeds %ds budget)\n",
               n_cycles, elapsed, budget_sec);
        failures++;
    }

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ════════════════════════════════════════════════════════════════════════
 * MID-IMPORTBLOCKINDEX kill9 phase
 *
 * Forks real calls to snapshot_import_block_index() (app/controllers/src/
 * snapshot_controller_import.c) — the function `--importblockindex`
 * dispatches to, the mandatory first step of the two-step cold-sync recipe.
 * Its internal shape is an autocommit `DELETE FROM blocks` (+ tip reset)
 * followed by ONE BEGIN..COMMIT bulk-insert transaction (our fixture stays
 * well under its 100000-row batch-commit boundary, so it is a single
 * all-or-nothing unit): a SIGKILL anywhere in that sequence must leave
 * `blocks` EMPTY (pre-insert / rolled back) or FULLY populated (post-commit)
 * on reopen — never partial.
 * ════════════════════════════════════════════════════════════════════════ */

#define IB9_N_BLOCKS 2000

static uint32_t ib9_pow_limit_bits(void)
{
    const struct chain_params *cp = chain_params_get();
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    return arith_uint256_get_compact(&pow_limit, false);
}

/* Import admission now hash-binds every LevelDB key to its serialized header
 * and checks the resulting hash against the network powLimit.  Manufacture a
 * valid test header by varying nTime; Equihash is deliberately outside this
 * crash-atomicity fixture because all rows are below the import stride. */
static bool ib9_mine_pow(struct disk_block_index *dbi, uint32_t bits,
                         struct uint256 *out_hash)
{
    bool neg = false, overflow = false;
    struct arith_uint256 target;
    arith_uint256_set_compact(&target, bits, &neg, &overflow);
    if (neg || overflow || arith_uint256_is_zero(&target))
        return false;

    dbi->nBits = bits;
    for (uint32_t tries = 0; tries < 2000000u; tries++) {
        dbi->nTime = 1231006505u + tries;
        disk_block_index_get_hash(dbi, out_hash);
        struct arith_uint256 hash_arith;
        uint256_to_arith(&hash_arith, out_hash);
        if (arith_uint256_compare(&hash_arith, &target) <= 0)
            return true;
    }
    return false;
}

static bool ib9_build_fixture(const char *src_dir, int n)
{
    char idx_dir[512];
    snprintf(idx_dir, sizeof(idx_dir), "%s/blocks/index", src_dir);

    struct db_wrapper dbw;
    if (!db_wrapper_open(&dbw, idx_dir, 64 << 20, false, true))
        return false;

    uint8_t prev[32];
    memset(prev, 0, sizeof(prev));
    uint32_t pow_bits = ib9_pow_limit_bits();
    bool ok = true;

    for (int h = 0; h < n && ok; h++) {
        struct disk_block_index dbi;
        disk_block_index_init(&dbi);
        dbi.nHeight = h;
        memcpy(dbi.hashPrev.data, prev, 32);
        dbi.nStatus = (unsigned int)(BLOCK_VALID_TRANSACTIONS |
                                     BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
        dbi.nTx = 1;
        dbi.nFile = 0;
        dbi.nDataPos = 2000u + (uint32_t)h * 100u;
        dbi.nUndoPos = dbi.nDataPos + 500u;
        dbi.nVersion = 4;
        dbi.hashMerkleRoot.data[0] = 0xBB;
        dbi.hashMerkleRoot.data[1] = (uint8_t)(h & 0xff);
        dbi.hashMerkleRoot.data[2] = (uint8_t)((h >> 8) & 0xff);
        dbi.nSolutionSize = 0;
        dbi.has_sprout_value = false;
        dbi.nSaplingValue = 0;

        struct uint256 mined_hash;
        if (!ib9_mine_pow(&dbi, pow_bits, &mined_hash)) {
            ok = false;
            break;
        }

        struct byte_stream s;
        stream_init(&s, 256);
        if (!disk_block_index_serialize(&dbi, &s) || s.error) {
            ok = false;
        } else {
            char key[33];
            key[0] = 'b';
            memcpy(key + 1, mined_hash.data, 32);
            if (!db_write(&dbw, key, sizeof(key), (const char *)s.data,
                          s.size, false))
                ok = false;
        }
        stream_free(&s);
        memcpy(prev, mined_hash.data, 32);
    }

    db_wrapper_close(&dbw);
    return ok;
}

static int p11_7ib_run_phase(void)
{
    int failures = 0;
    printf("\n=== kill -9 mid-importblockindex recovery ===\n");

    char base[300];
    snprintf(base, sizeof(base), "./test-tmp/kill9ib_%d", (int)getpid());
    p11_7_mkdir_p("./test-tmp");
    test_rm_rf_recursive(base);
    p11_7_mkdir_p(base);

    char src_dir[340];
    snprintf(src_dir, sizeof(src_dir), "%s/legacy-src", base);
    p11_7_mkdir_p(src_dir);

    if (!ib9_build_fixture(src_dir, IB9_N_BLOCKS)) {
        printf("FAIL (importblockindex: fixture build failed)\n");
        test_rm_rf_recursive(base);
        return 1;
    }

    char db_path[380];
    snprintf(db_path, sizeof(db_path), "%s/node.db", base);

    /* Calibration run: time ONE full uninterrupted import to size the kill
     * delay window to THIS box's actual disk/CPU speed instead of a guessed
     * constant — portable across dev boxes. */
    int64_t t_cal0 = platform_time_monotonic_us();
    int cal_count = -1;
    bool cal_ok = snapshot_import_block_index(src_dir, db_path, /*header_only=*/true,
                                              &cal_count);
    int64_t t_cal_us = platform_time_monotonic_us() - t_cal0;
    if (!cal_ok || cal_count != IB9_N_BLOCKS) {
        printf("FAIL (importblockindex: calibration run failed ok=%d count=%d)\n",
               cal_ok, cal_count);
        test_rm_rf_recursive(base);
        return 1;
    }
    long delay_ceiling_us = t_cal_us + t_cal_us / 2; /* 1.5x calibrated duration */
    if (delay_ceiling_us < 5000) delay_ceiling_us = 5000;
    if (delay_ceiling_us > 5000000) delay_ceiling_us = 5000000; /* 5s safety cap */

    const int n_cycles = 6;
    const int budget_sec = 90;
    unsigned int rng = (unsigned int)(platform_time_wall_time_t() ^ getpid() ^ 0x1B2Cu);
    time_t t0 = platform_time_wall_time_t();

    for (int i = 0; i < n_cycles; i++) {
#if defined(_WIN32)
        void *hp = NULL;
        {
            char k9_log[420];
            snprintf(k9_log, sizeof(k9_log), "%s/k9ib_child.log", base);
            if (_putenv_s("ZCL_K9_SRC", src_dir) != 0 ||
                _putenv_s("ZCL_K9_DB", db_path) != 0) {
                printf("FAIL (importblockindex cycle %d: child env setup "
                       "failed)\n", i);
                failures++;
                break;
            }
            hp = test_spawn_self_with_role("test_kill9_recovery", "ib",
                                           k9_log);
            _putenv_s("ZCL_K9_SRC", "");
            _putenv_s("ZCL_K9_DB", "");
        }
        if (!hp) {
            printf("FAIL (importblockindex cycle %d: child spawn failed)\n",
                   i);
            failures++;
            break;
        }
#else
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); failures++; break; }
        if (pid == 0) {
            int child_count = -1;
            bool ok = snapshot_import_block_index(src_dir, db_path,
                                                  /*header_only=*/true, &child_count);
            _exit(ok ? 0 : 1);
        }
#endif

        long delay_us = 300 + (long)(rand_r(&rng) % (unsigned long)delay_ceiling_us);
        struct timespec delay_ts = {
            .tv_sec = delay_us / 1000000,
            .tv_nsec = (delay_us % 1000000) * 1000,
        };
        nanosleep(&delay_ts, NULL);

#if defined(_WIN32)
        test_self_child_kill(hp);
        int wcode = test_self_child_wait(hp);
        bool killed = (wcode == 137);
        bool exited_ok = (wcode == 0);
        if (!killed && !exited_ok) {
            printf("FAIL (importblockindex cycle %d: child ended abnormally; "
                   "exit=%d)\n", i, wcode);
            failures++;
            break;
        }
#else
        if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
            perror("kill");
            waitpid(pid, NULL, 0);
            failures++;
            break;
        }
        int status = 0;
        if (waitpid(pid, &status, 0) != pid) {
            perror("waitpid");
            failures++;
            break;
        }
        bool killed = WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
        bool exited_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (!killed && !exited_ok) {
            printf("FAIL (importblockindex cycle %d: child ended abnormally; "
                   "WIFSIGNALED=%d WIFEXITED=%d status=%d)\n",
                   i, WIFSIGNALED(status), WIFEXITED(status), status);
            failures++;
            break;
        }
#endif

        struct node_db ndb;
        if (!node_db_open(&ndb, db_path)) {
            printf("FAIL (importblockindex cycle %d: reopen failed after %s)\n",
                   i, killed ? "SIGKILL" : "clean exit");
            failures++;
            break;
        }
        int count = db_block_count(&ndb);
        bool empty_or_full = (count == 0) || (count == IB9_N_BLOCKS);
        if (!empty_or_full) {
            printf("FAIL (importblockindex cycle %d: blocks row count=%d — "
                   "neither the rolled-back (0) nor committed (%d) shape; a "
                   "partial DELETE+bulk-insert survived the SIGKILL)\n",
                   i, count, IB9_N_BLOCKS);
            node_db_close(&ndb);
            failures++;
            break;
        }

        /* Cursor-ahead-of-content check on THIS write path: the fast-boot
         * cursors are stamped ONLY after the full commit + index rebuild, so
         * they must be absent whenever count==0 and, when present, must
         * equal exactly count-1 — never a stale/garbled value. */
        int64_t pprev_h = -2, shielded_h = -2;
        bool pprev_found = node_db_state_get_int(&ndb, "pprev_repaired_height", &pprev_h);
        bool shielded_found = node_db_state_get_int(&ndb, "shielded_backfill_height",
                                                     &shielded_h);
        bool cursors_absent = !pprev_found && !shielded_found;
        bool cursors_at_tip = pprev_found && shielded_found &&
            pprev_h == IB9_N_BLOCKS - 1 &&
            shielded_h == IB9_N_BLOCKS - 1;
        /* Full rows with absent cursors is the safe crash window after the
         * row commit but before the atomic cursor stamp: boot recomputes them.
         * Empty rows may never retain cursors, and a mixed pair is never safe. */
        bool cursors_consistent = count == 0 ? cursors_absent :
                                                (cursors_absent || cursors_at_tip);
        if (!cursors_consistent) {
            printf("FAIL (importblockindex cycle %d: fast-boot cursors "
                   "inconsistent with row count=%d — pprev_found=%d(%lld) "
                   "shielded_found=%d(%lld))\n",
                   i, count, pprev_found, (long long)pprev_h,
                   shielded_found, (long long)shielded_h);
            node_db_close(&ndb);
            failures++;
            break;
        }

        node_db_close(&ndb);
    }

    /* Terminal: one uninterrupted re-run proves the fully-imported state is
     * ALWAYS reachable regardless of how the prior cycles left the table —
     * the function's own DELETE+rebuild is itself a valid, named resume
     * strategy (proven idempotent by test_importblockindex_roundtrip). */
    if (!failures) {
        int final_count = -1;
        bool final_ok = snapshot_import_block_index(src_dir, db_path,
                                                     /*header_only=*/true,
                                                     &final_count);
        struct node_db ndb;
        bool reopened = final_ok && node_db_open(&ndb, db_path);
        int row_count = reopened ? db_block_count(&ndb) : -1;
        if (reopened) node_db_close(&ndb);
        if (!final_ok || final_count != IB9_N_BLOCKS || row_count != IB9_N_BLOCKS) {
            printf("FAIL (importblockindex: final uninterrupted re-run did not "
                   "reach the fully-imported terminal — ok=%d count=%d rows=%d)\n",
                   final_ok, final_count, row_count);
            failures++;
        } else {
            printf(" importblockindex kill9 OK (%d cycles, calibrated kill "
                   "window ceiling %ldus from a %lldus reference run; every "
                   "reopen was empty-or-full, never partial; final re-run "
                   "reached the full %d-row terminal)\n",
                   n_cycles, delay_ceiling_us, (long long)t_cal_us, IB9_N_BLOCKS);
        }
    }

    int elapsed = (int)(platform_time_wall_time_t() - t0);
    if (!failures && elapsed > budget_sec) {
        printf("FAIL (importblockindex: %d cycles took %ds, exceeds %ds budget)\n",
               n_cycles, elapsed, budget_sec);
        failures++;
    }

    test_rm_rf_recursive(base);
    return failures;
}

/* ── Test entrypoint ───────────────────────────────────────── */

int test_kill9_recovery(void)
{
    int failures = 0;
#if defined(_WIN32)
    /* Windows has no fork(): the crash-victim child is this same binary
     * re-exec'd with ZCL_TEST_FORK_ROLE set (see test_spawn_self_with_role).
     * Run the worker body — which always _exit()s — with its parameters
     * passed through the environment. TerminateProcess from the parent is
     * the uncatchable SIGKILL analogue, so the crash-window semantics are
     * identical. */
    const char *fork_role = getenv("ZCL_TEST_FORK_ROLE");
    if (fork_role && fork_role[0]) {
        if (strcmp(fork_role, "p11_7") == 0) {
            const char *db = getenv("ZCL_K9_DB");
            const char *st = getenv("ZCL_K9_START");
            if (!db || !st) _exit(98);
            p11_7_child_worker(db, atoi(st));
            _exit(99); /* unreachable */
        }
        if (strcmp(fork_role, "mf") == 0) {
            const char *dir = getenv("ZCL_K9_DIR");
            const char *ss = getenv("ZCL_K9_START");
            const char *se = getenv("ZCL_K9_END");
            if (!dir || !ss || !se) _exit(98);
            mf_child_worker(dir, (int32_t)atoi(ss), (int32_t)atoi(se));
            _exit(99); /* unreachable */
        }
        if (strcmp(fork_role, "ib") == 0) {
            const char *src = getenv("ZCL_K9_SRC");
            const char *db = getenv("ZCL_K9_DB");
            if (!src || !db) _exit(98);
            int child_count = -1;
            bool ok = snapshot_import_block_index(src, db,
                                                  /*header_only=*/true,
                                                  &child_count);
            _exit(ok ? 0 : 1);
        }
        _exit(97); /* unknown role */
    }
#endif
    printf("\n=== kill -9 recovery (MVP #7, <2 min) — three crash-window "
           "phases: UTXO-apply, mint-fold, importblockindex ===\n");
    printf("kill9_recovery SIGKILL-mid-apply × 10 cycles... ");

    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("SKIP (set ZCL_STRESS_TESTS=1 to run — spawns child procs "
               "across three phases)\n");
        return 0;
    }
    printf("\n");

    char dir[256];
    p11_7_dir_path(dir, sizeof(dir));
    p11_7_mkdir_p("./test-tmp");
    p11_7_mkdir_p(dir);

    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    /* Remove any stale DB from an earlier aborted run — fresh start. */
    unlink(dbpath);
    {
        char wal[520];
        snprintf(wal, sizeof(wal), "%s-wal", dbpath); unlink(wal);
        snprintf(wal, sizeof(wal), "%s-shm", dbpath); unlink(wal);
    }

    /* Seed: build schema + genesis block at height 0 + one UTXO. */
    {
        sqlite3 *db = NULL;
        if (sqlite3_open(dbpath, &db) != SQLITE_OK) {
            printf("FAIL (seed open failed)\n");
            return 1;
        }
        if (!p11_7_build_schema(db)) {
            sqlite3_close(db);
            printf("FAIL (seed schema failed)\n");
            return 1;
        }

        uint8_t genesis[32];
        memset(genesis, 0xA0, 32);

        sqlite3_stmt *s = NULL;
        sqlite3_prepare_v2(db,
            "INSERT INTO blocks(hash,height,status) VALUES(?,0,3)",
            -1, &s, NULL);
        sqlite3_bind_blob(s, 1, genesis, 32, SQLITE_TRANSIENT);
        sqlite3_step(s); sqlite3_finalize(s);

        uint8_t gen_txid[32];
        memset(gen_txid, 0, 32); gen_txid[0] = 0xFF;
        sqlite3_prepare_v2(db,
            "INSERT INTO utxos(txid,vout,value,script,script_type,"
            " address_hash,height,is_coinbase) "
            "VALUES(?,0,0,NULL,0,NULL,0,1)", -1, &s, NULL);
        sqlite3_bind_blob(s, 1, gen_txid, 32, SQLITE_TRANSIENT);
        sqlite3_step(s); sqlite3_finalize(s);

        sqlite3_prepare_v2(db,
            "INSERT INTO node_state(key,value) "
            "VALUES('coins_best_block',?)", -1, &s, NULL);
        sqlite3_bind_blob(s, 1, genesis, 32, SQLITE_TRANSIENT);
        sqlite3_step(s); sqlite3_finalize(s);

        sqlite3_close(db);
    }

    const int n_cycles = 10;
    const int budget_sec = 120;

    unsigned int rng = (unsigned int)(platform_time_wall_time_t() ^ getpid());
    time_t t0 = platform_time_wall_time_t();

    int n_killed = 0, n_clean = 0;
    for (int i = 0; i < n_cycles; i++) {
        int before_tip;
        {
            sqlite3 *db = NULL;
            sqlite3_open(dbpath, &db);
            before_tip = p11_7_query_tip_height(db);
            sqlite3_close(db);
        }

        if (p11_7_one_cycle(dbpath, i, &rng) != 0) {
            failures++;
            break;
        }

        int after_tip;
        {
            sqlite3 *db = NULL;
            sqlite3_open(dbpath, &db);
            after_tip = p11_7_query_tip_height(db);
            sqlite3_close(db);
        }
        if (after_tip > before_tip) n_clean++;
        else n_killed++;
    }

    int elapsed = (int)(platform_time_wall_time_t() - t0);

    if (!failures && elapsed > budget_sec) {
        printf("FAIL (10 cycles took %ds, exceeds %ds MVP budget)\n",
               elapsed, budget_sec);
        failures++;
    }
    if (!failures) {
        printf(" kill9_recovery OK "
               "(10 cycles in %ds; %d advanced tip, %d killed mid-apply "
               "— all recovered cleanly, no UTXO overshoot)\n",
               elapsed, n_clean, n_killed);
    }

    /* Cleanup */
    test_cleanup_tmpdir(dir);

    /* Extended crash-window matrix (plan lane 2.4): mid-mint-fold and
     * mid-importblockindex, each an independent fork+SIGKILL cycle set with
     * its own cleanup. Both run regardless of the UTXO-apply phase's result
     * so a single-phase regression doesn't hide failures in the others. */
    failures += p11_7mf_run_phase();
    failures += p11_7ib_run_phase();

    return failures;
}
