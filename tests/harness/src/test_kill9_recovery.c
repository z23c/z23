/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * MVP criterion #7 CI gate: recover from `kill -9` in <2 min.
 *
 * Exercises SIGKILL mid-block-apply recovery. For each of 10 cycles the parent
 * forks a child that walks a connect-block-style write sequence inside
 * BEGIN/COMMIT (UTXO batch at h+1, coins_best_block tip, block-index row),
 * kills it after a random 0.5-40 ms, then reopens the datadir through
 * `coins_view_sqlite_open()`. The reopen must succeed (boot-time atomicity
 * check and auto-rewind, see `test_coins_view_atomicity`) and leave no UTXO row
 * above the tip height. All 10 cycles must finish under the 2-minute budget.
 *
 * Proves: SQLite BEGIN/COMMIT atomicity survives SIGKILL, the boot-time
 * invariant (`utxos.height` never exceeds tip.height) auto-heals a
 * single-block overshoot (<=32 rows), and the datadir never needs manual repair.
 * Does not prove full-binary cold restart, protocol resync, or block validation.
 *
 * Two further crash windows, each its own fork+SIGKILL cycle set:
 *
 *   - MID-MINT-FOLD (p11_7mf_*): drives the real durable-marker API of the
 *     offline `-mint-anchor` producer (`mint_anchor_producer_lane_bind` /
 *     `mint_anchor_progress_mark` / `_can_resume`,
 *     engine/composition/src/mint_anchor_progress.c) and the real coins_kv
 *     per-block apply (`coins_kv_add_many` + `coins_kv_set_applied_height_in_tx`
 *     inside one BEGIN IMMEDIATE). On every reopen the cursor's implied row
 *     count `(applied_through+1) * rows_per_step` must equal `coins_kv_count()`
 *     exactly, and `_can_resume()` must authorize a non-legacy RESUME when fold
 *     progress exists or the sanctioned GENESIS RESET when the marker matches but
 *     nothing was applied. Any other refusal is a wedge. A final uninterrupted
 *     drain plus `mint_anchor_progress_clear` proves verified completion is
 *     always reachable.
 *
 *   - MID-IMPORTBLOCKINDEX (p11_7ib_*): forks real calls to
 *     `snapshot_import_block_index()` (engine/controllers/src/
 *     snapshot_controller_import.c), the first step of the two-step cold-sync
 *     recipe. The kill delay is calibrated from one timed uninterrupted run. The
 *     `blocks` table must be empty or fully populated on every reopen, and the
 *     fast-boot cursors (pprev_repaired_height / shielded_backfill_height) must
 *     never be stamped unless the row count is full. A final uninterrupted
 *     re-run proves the fully-imported terminal is reachable.
 *
 * Gating: skipped unless `ZCL_STRESS_TESTS=1` (child processes, real SQLite and
 * LevelDB I/O; keeps `make test` under a minute).
 *   ZCL_STRESS_TESTS=1 build/bin/test_zcl
 *   ZCL_STRESS_TESTS=1 ZCL_TEST_ONLY=kill9 build/bin/test_zcl (focused)
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
#include <poll.h>
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
 * Minimal SQLite schema builder, duplicated from `test_coins_view_atomicity.c`
 * (file-static there) so the tests stay independent. */

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
 * Each "block" is its own BEGIN/COMMIT, matching the live node's per-block
 * atomicity. A small nanosleep between steps widens the kill window. On
 * success the child exits 0; on SIGKILL the SQLite journal rolls back any
 * partial transaction on the next open. */

#if !defined(_WIN32)
static int p11_7_mid_apply_fd = -1;

static void p11_7_hold_mid_apply(sqlite3 *db)
{
    if (p11_7_mid_apply_fd < 0) return;
    if (sqlite3_get_autocommit(db) || p11_7_count_utxos_above_tip(db) != 4)
        _exit(4);
    const char ready = 'R';
    if (write(p11_7_mid_apply_fd, &ready, 1) != 1) _exit(5);
    for (;;) pause(); /* Parent owns the bounded wait and SIGKILL. */
}

static bool p11_7_wait_mid_apply(int fd)
{
    struct pollfd event = { .fd = fd, .events = POLLIN };
    char ready = 0;
    return poll(&event, 1, 5000) == 1 && (event.revents & POLLIN) &&
        read(fd, &ready, 1) == 1 && ready == 'R';
}
#endif

static void p11_7_child_worker(const char *dbpath, int start_height)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(dbpath, &db) != SQLITE_OK)
        _exit(1);

    /* WAL mode matches production (boot_services.c). */
    sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);

    const int n_blocks = 30;
    for (int i = 0; i < n_blocks; i++) {
        int h = start_height + 1 + i;

        if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
            _exit(2);

        /* Block-index row first, matching connect_block's write order. */
        uint8_t hash[32];
        memset(hash, (uint8_t)(0xA0 ^ (h & 0xFF)), 32);
        /* Mix the iteration into the hash for a unique primary key. */
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

#if !defined(_WIN32)
        p11_7_hold_mid_apply(db);
#endif
        /* Tip pointer LAST, so a kill between UTXO inserts and the tip update leaves UTXOs ahead of tip. */
        sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO node_state(key,value) "
            "VALUES('coins_best_block',?)", -1, &s, NULL);
        sqlite3_bind_blob(s, 1, hash, 32, SQLITE_TRANSIENT);
        sqlite3_step(s);
        sqlite3_finalize(s);

        if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
            _exit(3);

        /* ~1ms per block; 30 blocks cover the 0.5-40ms kill range. */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000L };
        nanosleep(&ts, NULL);
    }

    sqlite3_close(db);
    _exit(0);
}

#if !defined(_WIN32)
static pid_t p11_7_spawn_cycle(const char *dbpath, int start_height,
    int cycle_idx, bool *mid_apply_observed)
{
    int ready_pipe[2] = {-1, -1};
    if (cycle_idx == 0 && pipe(ready_pipe) != 0) {
        perror("mid-apply pipe");
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        if (ready_pipe[0] >= 0) { close(ready_pipe[0]); close(ready_pipe[1]); }
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        if (ready_pipe[0] >= 0) close(ready_pipe[0]);
        p11_7_mid_apply_fd = ready_pipe[1];
        p11_7_child_worker(dbpath, start_height);
        /* unreachable — child always _exit()s */
        _exit(99);
    }

    *mid_apply_observed = true;
    if (ready_pipe[0] >= 0) {
        close(ready_pipe[1]);
        *mid_apply_observed = p11_7_wait_mid_apply(ready_pipe[0]);
        close(ready_pipe[0]);
    }
    return pid;
}

static bool p11_7_mid_apply_verified(int cycle_idx, bool observed, bool killed)
{
    if (!observed || (cycle_idx == 0 && !killed)) {
        printf("FAIL (cycle %d: deterministic mid-apply SIGKILL was not observed)\n", cycle_idx);
        return false;
    }
    if (cycle_idx == 0)
        printf("kill9_recovery: observed SIGKILL with four uncommitted UTXOs before tip update\n");
    return true;
}
#endif

/* Abnormal child endings for the three phases. kind 0 is the UTXO cycle,
 * 1 is mint-fold, 2 is importblockindex. Both platform wordings live here
 * so the mapping is one body. */
static void p11_7_printf_child_abnormal(int kind, int idx, int status, int wcode)
{
#if !defined(_WIN32)
    (void)wcode;
    int signaled = WIFSIGNALED(status);
    int exited = WIFEXITED(status);
    if (kind == 0)
        printf("FAIL (cycle %d: child ended abnormally; "
               "WIFSIGNALED=%d WIFEXITED=%d status=%d)\n",
               idx, signaled, exited, status);
    else if (kind == 1)
        printf("FAIL (mint-fold cycle %d: child ended abnormally; "
               "WIFSIGNALED=%d WIFEXITED=%d status=%d)\n",
               idx, signaled, exited, status);
    else
        printf("FAIL (importblockindex cycle %d: child ended abnormally; "
               "WIFSIGNALED=%d WIFEXITED=%d status=%d)\n",
               idx, signaled, exited, status);
#else
    (void)status;
    if (kind == 0)
        printf("FAIL (cycle %d: child ended abnormally; exit=%d)\n",
               idx, wcode);
    else if (kind == 1)
        printf("FAIL (mint-fold cycle %d: child ended abnormally; "
               "exit=%d)\n", idx, wcode);
    else
        printf("FAIL (importblockindex cycle %d: child ended abnormally; "
               "exit=%d)\n", idx, wcode);
#endif
}

#if defined(_WIN32)
/* 0 = SIGKILL analogue (137), 1 = clean exit, 4 = anything else. */
static int p11_7_win_child_class(void *hp, int *wcode_out)
{
    test_self_child_kill(hp);
    int wcode = test_self_child_wait(hp);
    *wcode_out = wcode;
    if (wcode == 137) return 0; /* test_self_child_kill's exit code */
    if (wcode == 0) return 1;
    return 4;
}

static int p11_7_report_win_reap(void *hp, int idx, int kind, bool *killed_out)
{
    int wcode = 0;
    int cls = p11_7_win_child_class(hp, &wcode);
    *killed_out = (cls == 0);
    if (cls == 4) {
        p11_7_printf_child_abnormal(kind, idx, 0, wcode);
        return 1;
    }
    return 0;
}
#else
/* 0 = SIGKILL, 1 = clean exit 0, 2 = kill error (errno preserved, not reaped),
 * 3 = waitpid error (errno preserved), 4 = any other exit. */
static int p11_7_sigkill_reap(pid_t pid, int *status_out)
{
    if (kill(pid, SIGKILL) != 0 && errno != ESRCH)
        return 2;
    int status = 0;
    if (waitpid(pid, &status, 0) != pid)
        return 3;
    *status_out = status;
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
        return 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return 1;
    return 4;
}

static int p11_7_report_posix_reap(pid_t pid, int idx, int kind, bool *killed_out)
{
    int status = 0;
    int reap = p11_7_sigkill_reap(pid, &status);
    if (reap == 2) {
        /* ESRCH = child already finished; that's fine. */
        perror("kill");
        waitpid(pid, NULL, 0);
        return 1;
    }
    if (reap == 3) {
        perror("waitpid");
        return 1;
    }
    if (reap == 4) {
        p11_7_printf_child_abnormal(kind, idx, status, 0);
        return 1;
    }
    *killed_out = (reap == 0);
    return 0;
}
#endif

/* ── One kill-and-recover cycle ───────────────────────────── */

static int p11_7_cycle_tip_before_fork(const char *dbpath, int cycle_idx,
                                       int *start_height)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(dbpath, &db) != SQLITE_OK) {
        printf("FAIL (cycle %d: pre-fork open failed)\n", cycle_idx);
        return 1;
    }
    *start_height = p11_7_query_tip_height(db);
    sqlite3_close(db);
    if (*start_height < 0) {
        printf("FAIL (cycle %d: no tip before fork)\n", cycle_idx);
        return 1;
    }
    return 0;
}

#if defined(_WIN32)
static int p11_7_cycle_crash_win(const char *dbpath, int cycle_idx,
                                 int start_height, unsigned int *rng_state,
                                 bool *killed_out)
{
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

    /* Randomised kill delay 0.5-40ms: opening, mid-transaction, between commits, or already finished. */
    long delay_us = 500 + (long)(rand_r(rng_state) % 40000);
    struct timespec delay_ts = {
        .tv_sec = 0,
        .tv_nsec = delay_us * 1000,
    };
    nanosleep(&delay_ts, NULL);

    /* Like kill(pid, SIGKILL): if the child already finished, the terminate
     * is a no-op and the reaped exit code is its own. */
    return p11_7_report_win_reap(hp, cycle_idx, 0, killed_out);
}
#else
static int p11_7_cycle_crash_posix(const char *dbpath, int cycle_idx,
                                   int start_height, unsigned int *rng_state,
                                   bool *killed_out)
{
    bool mid_apply_observed = false;
    pid_t pid = p11_7_spawn_cycle(dbpath, start_height, cycle_idx, &mid_apply_observed);
    if (pid < 0) return 1;
    /* Randomised kill delay 0.5-40ms: opening, mid-transaction, between commits, or already finished. */
    long delay_us = 500 + (long)(rand_r(rng_state) % 40000);
    struct timespec delay_ts = {
        .tv_sec = 0,
        .tv_nsec = delay_us * 1000,
    };
    nanosleep(&delay_ts, NULL);

    bool killed = false;
    int reap_rc = p11_7_report_posix_reap(pid, cycle_idx, 0, &killed);
    if (reap_rc != 0)
        return reap_rc;
    if (!p11_7_mid_apply_verified(cycle_idx, mid_apply_observed, killed)) return 1;
    *killed_out = killed;
    return 0;
}
#endif

static int p11_7_cycle_crash(const char *dbpath, int cycle_idx, int start_height,
                             unsigned int *rng_state, bool *killed_out)
{
#if defined(_WIN32)
    return p11_7_cycle_crash_win(dbpath, cycle_idx, start_height, rng_state,
                                 killed_out);
#else
    return p11_7_cycle_crash_posix(dbpath, cycle_idx, start_height, rng_state,
                                   killed_out);
#endif
}

static int p11_7_cycle_reopen_check(const char *dbpath, int cycle_idx, bool killed)
{
    /* Reopen through the live node's entry point, where the "UTXOs ahead of tip" auto-rewind fires. */
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
        /* A refusal is acceptable only past the auto-rewind threshold (32 rows,
         * test_coins_view_atomicity:t_utxos_one_ahead_too_many_rejected); this
         * workload overshoots by a few rows, so a refusal is a regression. */
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

static int p11_7_one_cycle(const char *dbpath, int cycle_idx,
                            unsigned int *rng_state)
{
    int start_height = 0;
    if (p11_7_cycle_tip_before_fork(dbpath, cycle_idx, &start_height) != 0)
        return 1;
    bool killed = false;
    int crash = p11_7_cycle_crash(dbpath, cycle_idx, start_height, rng_state,
                                  &killed);
    if (crash != 0)
        return crash;
    return p11_7_cycle_reopen_check(dbpath, cycle_idx, killed);
}

/* ════════════════════════════════════════════════════════════════════════
 * MID-MINT-FOLD kill9 phase
 *
 * Drives the real durable-marker API of the offline `-mint-anchor` producer and
 * the real per-block coins_kv apply (one BEGIN IMMEDIATE, the same unit as
 * utxo_apply_stage.c's forward-apply) against a fresh progress.kv, killing the
 * child mid-fold and reopening through `mint_anchor_progress_can_resume()`.
 * ════════════════════════════════════════════════════════════════════════ */

#define MF_ROWS_PER_STEP 3
#define MF_N_STEPS       48
#define MF_BATCH         8

/* Deterministic per-step coin rows: step h contributes MF_ROWS_PER_STEP
 * outputs with txids derived from h. `txids` must outlive the
 * coins_kv_add_many call. */
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

/* Child worker: fold steps [start_step, end_step), each one BEGIN IMMEDIATE /
 * coins_kv_add_many + coins_kv_set_applied_height_in_tx / COMMIT. A small
 * nanosleep widens the SIGKILL window. */
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

/* Cycle-loop outcomes for the mint-fold phase. INSPECT means the progress
 * store is still open and the cursor check should run. STOP breaks the
 * loop. NEXT advances to the following cycle with the store already closed. */
enum {
    P11_7MF_INSPECT = 0,
    P11_7MF_STOP = 1,
    P11_7MF_NEXT = 2
};

static int p11_7mf_setup_lane(const char *dir, const struct sha3_utxo_checkpoint *cp)
{
    /* Setup: bind the producer lane and write the in-progress marker the real producer leaves before folding. */
    if (!progress_store_open(dir)) {
        printf("FAIL (mint-fold: progress_store_open setup failed)\n");
        return 1;
    }
    sqlite3 *db = progress_store_db();
    bool setup_ok = db && coins_kv_ensure_schema(db) &&
                    mint_anchor_producer_lane_bind(db, /*checkpoint_fold=*/true) &&
                    mint_anchor_progress_mark(db, cp);
    progress_store_close();
    if (!setup_ok) {
        printf("FAIL (mint-fold: producer lane / marker setup failed)\n");
        test_cleanup_tmpdir(dir);
        return 1;
    }
    return 0;
}

static int p11_7mf_cycle_bounds(const char *dir, int i, int32_t *start_step,
                                int32_t *end_step, int *failures)
{
    *start_step = 0;
    if (!mf_read_start_step(dir, start_step)) {
        printf("FAIL (mint-fold cycle %d: pre-fork frontier read failed)\n", i);
        (*failures)++;
        return P11_7MF_STOP;
    }
    if (*start_step >= MF_N_STEPS)
        return P11_7MF_STOP; /* already complete from an earlier cycle's clean finish */
    *end_step = *start_step + MF_BATCH;
    if (*end_step > MF_N_STEPS) *end_step = MF_N_STEPS;
    return 0;
}

#if defined(_WIN32)
static int p11_7mf_crash_win(const char *dir, int i, int32_t start_step,
                             int32_t end_step, unsigned int *rng, bool *killed_out)
{
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
            return 1;
        }
        hp = test_spawn_self_with_role("test_kill9_recovery", "mf",
                                       k9_log);
        _putenv_s("ZCL_K9_DIR", "");
        _putenv_s("ZCL_K9_START", "");
        _putenv_s("ZCL_K9_END", "");
    }
    if (!hp) {
        printf("FAIL (mint-fold cycle %d: child spawn failed)\n", i);
        return 1;
    }

    long delay_us = 300 + (long)(rand_r(rng) % 9000);
    struct timespec delay_ts = { .tv_sec = 0, .tv_nsec = delay_us * 1000 };
    nanosleep(&delay_ts, NULL);

    return p11_7_report_win_reap(hp, i, 1, killed_out);
}
#else
static int p11_7mf_crash_posix(const char *dir, int i, int32_t start_step,
                               int32_t end_step, unsigned int *rng, bool *killed_out)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        mf_child_worker(dir, start_step, end_step);
        _exit(99); /* unreachable */
    }

    long delay_us = 300 + (long)(rand_r(rng) % 9000);
    struct timespec delay_ts = { .tv_sec = 0, .tv_nsec = delay_us * 1000 };
    nanosleep(&delay_ts, NULL);

    return p11_7_report_posix_reap(pid, i, 1, killed_out);
}
#endif

static int p11_7mf_crash_child(const char *dir, int i, int32_t start_step,
                               int32_t end_step, unsigned int *rng, bool *killed_out)
{
#if defined(_WIN32)
    return p11_7mf_crash_win(dir, i, start_step, end_step, rng, killed_out);
#else
    return p11_7mf_crash_posix(dir, i, start_step, end_step, rng, killed_out);
#endif
}

static int p11_7mf_genesis_reset(sqlite3 *db, const struct sha3_utxo_checkpoint *cp,
                                 int i, bool legacy_adopted, int *failures)
{
    /* An intact matched marker with nothing durably applied authorizes a
     * genesis reset (can_resume=false), clean only when there is no durable
     * frontier and nothing adopted. Any other false is a wedge. */
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
        (*failures)++;
        progress_store_close();
        return P11_7MF_STOP;
    }
    /* Mirror boot_refold_staged.c's false branch: re-bind, re-mark, fold from step 0. */
    bool rearmed = mint_anchor_producer_lane_bind(
                       db, /*checkpoint_fold=*/true) &&
                   mint_anchor_progress_mark(db, cp);
    progress_store_close();
    if (!rearmed) {
        printf("FAIL (mint-fold cycle %d: could not re-arm the "
               "producer lane/marker after a sanctioned genesis "
               "reset)\n", i);
        (*failures)++;
        return P11_7MF_STOP;
    }
    printf("[kill9mf] cycle %d: SIGKILL landed pre-first-commit — "
           "sanctioned genesis reset taken, producer re-armed\n", i);
    return P11_7MF_NEXT;
}

static int p11_7mf_resume_gate(const char *dir, const struct sha3_utxo_checkpoint *cp,
                               int i, bool killed, sqlite3 **db_out,
                               int32_t *applied_through_out, int *failures)
{
    /* Reopen: the durable-marker inspection a restart performs before resuming. */
    if (!progress_store_open(dir)) {
        printf("FAIL (mint-fold cycle %d: reopen failed after %s)\n",
               i, killed ? "SIGKILL" : "clean exit");
        (*failures)++;
        return P11_7MF_STOP;
    }
    sqlite3 *db = progress_store_db();

    int32_t applied_through = -2;
    bool legacy_adopted = true; /* poison — must come back false */
    bool can_resume = mint_anchor_progress_can_resume(db, cp, &applied_through,
                                                       &legacy_adopted);
    if (!can_resume)
        return p11_7mf_genesis_reset(db, cp, i, legacy_adopted, failures);
    if (legacy_adopted) {
        printf("FAIL (mint-fold cycle %d: legacy_adopted=1 on a resumed "
               "fold — this fixture never arms the refold signal, so "
               "legacy adoption must be impossible)\n", i);
        (*failures)++;
        progress_store_close();
        return P11_7MF_STOP;
    }
    *db_out = db;
    *applied_through_out = applied_through;
    return P11_7MF_INSPECT;
}

static int p11_7mf_check_content(sqlite3 *db, int i, int32_t applied_through,
                                 int *failures)
{
    /* The applied-through cursor never runs ahead of its content: exactly
     * (applied_through+1) * MF_ROWS_PER_STEP rows exist wherever the SIGKILL landed. */
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
        (*failures)++;
        progress_store_close();
        return P11_7MF_STOP;
    }

    /* The last-applied step's coin is present; the next step's is absent. */
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
        (*failures)++;
        progress_store_close();
        return P11_7MF_STOP;
    }

    progress_store_close();
    return 0;
}

static int p11_7mf_inspect_resume(const char *dir, const struct sha3_utxo_checkpoint *cp,
                                  int i, bool killed, int *failures)
{
    sqlite3 *db = NULL;
    int32_t applied_through = -2;
    int gate = p11_7mf_resume_gate(dir, cp, i, killed, &db, &applied_through,
                                   failures);
    if (gate == P11_7MF_NEXT)
        return 0;
    if (gate != P11_7MF_INSPECT)
        return gate;
    return p11_7mf_check_content(db, i, applied_through, failures);
}

static int p11_7mf_one_kill(const char *dir, const struct sha3_utxo_checkpoint *cp,
                            unsigned int *rng, int i, int *failures)
{
    int32_t start_step = 0;
    int32_t end_step = 0;
    int bounds = p11_7mf_cycle_bounds(dir, i, &start_step, &end_step, failures);
    if (bounds != 0)
        return bounds;
    bool killed = false;
    int child = p11_7mf_crash_child(dir, i, start_step, end_step, rng, &killed);
    if (child != 0) {
        (*failures)++;
        return P11_7MF_STOP;
    }
    return p11_7mf_inspect_resume(dir, cp, i, killed, failures);
}

static void p11_7mf_run_cycles(const char *dir, const struct sha3_utxo_checkpoint *cp,
                               unsigned int *rng, int n_cycles, int *failures)
{
    for (int i = 0; i < n_cycles && !*failures; i++) {
        if (p11_7mf_one_kill(dir, cp, rng, i, failures) != 0)
            break;
    }
}

static bool p11_7mf_drain_steps(sqlite3 *db, int32_t start_step)
{
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
    return ok;
}

static int p11_7mf_clear_marker(sqlite3 *db, int n_cycles, int64_t final_count)
{
    bool cleared = mint_anchor_progress_clear(db);
    /* MINT_ANCHOR_MARKER_LEN is private to mint_anchor_progress.c; size generously. */
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
        return 1;
    }
    printf(" mint_fold kill9 OK (%d cycles; cursor never raced "
           "ahead of content at any reopen; drained to h=%d, "
           "%lld coins; marker cleared — verified-completion "
           "terminal reached)\n",
           n_cycles, MF_N_STEPS - 1, (long long)final_count);
    return 0;
}

static int p11_7mf_drain_verify(sqlite3 *db, bool ok, int n_cycles)
{
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
        return 1;
    }
    return p11_7mf_clear_marker(db, n_cycles, final_count);
}

static void p11_7mf_final_drain(const char *dir, int n_cycles, int *failures)
{
    /* Terminal: drain remaining steps uninterrupted, then clear the marker (verified completion). */
    int32_t start_step = 0;
    if (!mf_read_start_step(dir, &start_step)) {
        printf("FAIL (mint-fold: final frontier read failed)\n");
        (*failures)++;
        return;
    }
    if (!progress_store_open(dir)) {
        printf("FAIL (mint-fold: final reopen failed)\n");
        (*failures)++;
        return;
    }
    sqlite3 *db = progress_store_db();
    bool ok = p11_7mf_drain_steps(db, start_step);
    if (p11_7mf_drain_verify(db, ok, n_cycles) != 0)
        (*failures)++;
    progress_store_close();
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

    /* Fixture checkpoint: only its own consistency matters (mark/can_resume compare the same struct). */
    struct sha3_utxo_checkpoint cp;
    memset(&cp, 0, sizeof(cp));
    cp.height = MF_N_STEPS - 1;
    cp.utxo_count = (uint64_t)MF_N_STEPS * MF_ROWS_PER_STEP;
    cp.total_supply = 0;
    memset(cp.block_hash, 0xEE, sizeof(cp.block_hash));
    memset(cp.sha3_hash, 0xAB, sizeof(cp.sha3_hash));

    if (p11_7mf_setup_lane(dir, &cp) != 0)
        return 1;

    const int n_cycles = 10;
    const int budget_sec = 60;
    unsigned int rng = (unsigned int)(platform_time_wall_time_t() ^ getpid() ^ 0x4d46u);
    time_t t0 = platform_time_wall_time_t();

    p11_7mf_run_cycles(dir, &cp, &rng, n_cycles, &failures);

    /* Terminal: drain remaining steps uninterrupted, then clear the marker (verified completion). */
    if (!failures)
        p11_7mf_final_drain(dir, n_cycles, &failures);

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
 * Forks real calls to snapshot_import_block_index() (engine/controllers/src/
 * snapshot_controller_import.c), the first step of the cold-sync recipe: an
 * autocommit `DELETE FROM blocks` then one BEGIN..COMMIT bulk insert. A
 * SIGKILL anywhere must leave `blocks` empty or fully populated, never partial.
 * ════════════════════════════════════════════════════════════════════════ */

#define IB9_N_BLOCKS 2000

static uint32_t ib9_pow_limit_bits(void)
{
    const struct chain_params *cp = chain_params_get();
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    return arith_uint256_get_compact(&pow_limit, false);
}

/* Import admission hash-binds each LevelDB key to its header and checks the
 * hash against powLimit; test headers vary nTime. Equihash is outside this
 * fixture because all rows are below the import stride. */
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

static int p11_7ib_build_fixture_checked(const char *src_dir, const char *base)
{
    if (!ib9_build_fixture(src_dir, IB9_N_BLOCKS)) {
        printf("FAIL (importblockindex: fixture build failed)\n");
        test_rm_rf_recursive(base);
        return 1;
    }
    return 0;
}

/* Calibration: time one uninterrupted import to size the kill window to this box. */
static int p11_7ib_calibrate(const char *src_dir, const char *db_path,
                             const char *base, long *delay_ceiling_us,
                             int64_t *t_cal_us_out)
{
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
    long ceiling = t_cal_us + t_cal_us / 2; /* 1.5x calibrated duration */
    if (ceiling < 5000) ceiling = 5000;
    if (ceiling > 5000000) ceiling = 5000000; /* 5s safety cap */
    *delay_ceiling_us = ceiling;
    *t_cal_us_out = t_cal_us;
    return 0;
}

#if defined(_WIN32)
static int p11_7ib_spawn_win(const char *base, const char *src_dir,
                             const char *db_path, int i, void **hp_out)
{
    char k9_log[420];
    snprintf(k9_log, sizeof(k9_log), "%s/k9ib_child.log", base);
    if (_putenv_s("ZCL_K9_SRC", src_dir) != 0 ||
        _putenv_s("ZCL_K9_DB", db_path) != 0) {
        printf("FAIL (importblockindex cycle %d: child env setup "
               "failed)\n", i);
        return 1;
    }
    void *hp = test_spawn_self_with_role("test_kill9_recovery", "ib",
                                       k9_log);
    _putenv_s("ZCL_K9_SRC", "");
    _putenv_s("ZCL_K9_DB", "");
    if (!hp) {
        printf("FAIL (importblockindex cycle %d: child spawn failed)\n",
               i);
        return 1;
    }
    *hp_out = hp;
    return 0;
}
#else
static int p11_7ib_spawn_posix(const char *src_dir, const char *db_path,
                               pid_t *pid_out)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        int child_count = -1;
        bool ok = snapshot_import_block_index(src_dir, db_path,
                                              /*header_only=*/true, &child_count);
        _exit(ok ? 0 : 1);
    }
    *pid_out = pid;
    return 0;
}
#endif

static int p11_7ib_reopen_rows(const char *db_path, int i, bool killed,
                               struct node_db *ndb, int *count_out)
{
    if (!node_db_open(ndb, db_path)) {
        printf("FAIL (importblockindex cycle %d: reopen failed after %s)\n",
               i, killed ? "SIGKILL" : "clean exit");
        return 1;
    }
    int count = db_block_count(ndb);
    bool empty_or_full = (count == 0) || (count == IB9_N_BLOCKS);
    if (!empty_or_full) {
        printf("FAIL (importblockindex cycle %d: blocks row count=%d — "
               "neither the rolled-back (0) nor committed (%d) shape; a "
               "partial DELETE+bulk-insert survived the SIGKILL)\n",
               i, count, IB9_N_BLOCKS);
        node_db_close(ndb);
        return 1;
    }
    *count_out = count;
    return 0;
}

static int p11_7ib_check_cursors(struct node_db *ndb, int i, int count)
{
    /* Fast-boot cursors are stamped only after commit + index rebuild: absent when count==0, else exactly count-1. */
    int64_t pprev_h = -2, shielded_h = -2;
    bool pprev_found = node_db_state_get_int(ndb, "pprev_repaired_height", &pprev_h);
    bool shielded_found = node_db_state_get_int(ndb, "shielded_backfill_height",
                                                 &shielded_h);
    bool cursors_absent = !pprev_found && !shielded_found;
    bool cursors_at_tip = pprev_found && shielded_found &&
        pprev_h == IB9_N_BLOCKS - 1 &&
        shielded_h == IB9_N_BLOCKS - 1;
    /* Full rows with absent cursors is the safe window before the cursor stamp; boot recomputes them.
     * Empty rows may never retain cursors, and a mixed pair is never safe. */
    bool cursors_consistent = count == 0 ? cursors_absent :
                                            (cursors_absent || cursors_at_tip);
    if (!cursors_consistent) {
        printf("FAIL (importblockindex cycle %d: fast-boot cursors "
               "inconsistent with row count=%d — pprev_found=%d(%lld) "
               "shielded_found=%d(%lld))\n",
               i, count, pprev_found, (long long)pprev_h,
               shielded_found, (long long)shielded_h);
        return 1;
    }
    return 0;
}

static int p11_7ib_one_cycle(const char *base, const char *src_dir,
                             const char *db_path, int i, unsigned int *rng,
                             long delay_ceiling_us)
{
    int spawn_rc;
    int reap_rc;
    bool killed = false;
#if defined(_WIN32)
    void *hp = NULL;
    spawn_rc = p11_7ib_spawn_win(base, src_dir, db_path, i, &hp);
#else
    pid_t pid = -1;
    (void)base;
    spawn_rc = p11_7ib_spawn_posix(src_dir, db_path, &pid);
#endif
    if (spawn_rc != 0)
        return spawn_rc;

    long delay_us = 300 + (long)(rand_r(rng) % (unsigned long)delay_ceiling_us);
    struct timespec delay_ts = {
        .tv_sec = delay_us / 1000000,
        .tv_nsec = (delay_us % 1000000) * 1000,
    };
    nanosleep(&delay_ts, NULL);

#if defined(_WIN32)
    reap_rc = p11_7_report_win_reap(hp, i, 2, &killed);
#else
    reap_rc = p11_7_report_posix_reap(pid, i, 2, &killed);
#endif
    if (reap_rc != 0)
        return reap_rc;

    struct node_db ndb;
    int count = 0;
    if (p11_7ib_reopen_rows(db_path, i, killed, &ndb, &count) != 0)
        return 1;
    int cursors = p11_7ib_check_cursors(&ndb, i, count);
    node_db_close(&ndb);
    return cursors;
}

static void p11_7ib_run_cycles(const char *base, const char *src_dir,
                               const char *db_path, unsigned int *rng,
                               int n_cycles, long delay_ceiling_us,
                               int *failures)
{
    for (int i = 0; i < n_cycles; i++) {
        if (p11_7ib_one_cycle(base, src_dir, db_path, i, rng,
                              delay_ceiling_us) != 0) {
            (*failures)++;
            break;
        }
    }
}

static void p11_7ib_final_rerun(const char *src_dir, const char *db_path,
                                int n_cycles, long delay_ceiling_us,
                                int64_t t_cal_us, int *failures)
{
    /* Terminal: one uninterrupted re-run proves the imported state is always reachable (DELETE+rebuild is idempotent, see test_importblockindex_roundtrip). */
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
        (*failures)++;
    } else {
        printf(" importblockindex kill9 OK (%d cycles, calibrated kill "
               "window ceiling %ldus from a %lldus reference run; every "
               "reopen was empty-or-full, never partial; final re-run "
               "reached the full %d-row terminal)\n",
               n_cycles, delay_ceiling_us, (long long)t_cal_us, IB9_N_BLOCKS);
    }
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

    if (p11_7ib_build_fixture_checked(src_dir, base) != 0)
        return 1;

    char db_path[380];
    snprintf(db_path, sizeof(db_path), "%s/node.db", base);

    long delay_ceiling_us = 0;
    int64_t t_cal_us = 0;
    if (p11_7ib_calibrate(src_dir, db_path, base, &delay_ceiling_us,
                          &t_cal_us) != 0)
        return 1;

    const int n_cycles = 6;
    const int budget_sec = 90;
    unsigned int rng = (unsigned int)(platform_time_wall_time_t() ^ getpid() ^ 0x1B2Cu);
    time_t t0 = platform_time_wall_time_t();

    p11_7ib_run_cycles(base, src_dir, db_path, &rng, n_cycles,
                       delay_ceiling_us, &failures);

    if (!failures)
        p11_7ib_final_rerun(src_dir, db_path, n_cycles, delay_ceiling_us,
                            t_cal_us, &failures);

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

#if defined(_WIN32)
static void p11_7_fork_role_mint_or_import(const char *fork_role)
{
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
}

static void p11_7_fork_role_dispatch(void)
{
    const char *fork_role = getenv("ZCL_TEST_FORK_ROLE");
    if (fork_role && fork_role[0]) {
        if (strcmp(fork_role, "p11_7") == 0) {
            const char *db = getenv("ZCL_K9_DB");
            const char *st = getenv("ZCL_K9_START");
            if (!db || !st) _exit(98);
            p11_7_child_worker(db, atoi(st));
            _exit(99); /* unreachable */
        }
        p11_7_fork_role_mint_or_import(fork_role);
        _exit(97); /* unknown role */
    }
}
#endif

int test_kill9_recovery(void)
{
    int failures = 0;
#if defined(_WIN32)
    /* Windows has no fork(): the victim is this binary re-exec'd with
     * ZCL_TEST_FORK_ROLE, parameters via the environment; TerminateProcess is
     * the SIGKILL analogue. */
    p11_7_fork_role_dispatch();
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
               "(10 cycles in %ds; %d advanced tip, %d retained tip "
               "— all recovered cleanly, no UTXO overshoot)\n",
               elapsed, n_clean, n_killed);
    }

    /* Cleanup */
    test_cleanup_tmpdir(dir);

    /* Extended crash-window matrix: mid-mint-fold and mid-importblockindex, each with its own
     * cleanup and run regardless of the UTXO-apply result. */
    failures += p11_7mf_run_phase();
    failures += p11_7ib_run_phase();

    return failures;
}
