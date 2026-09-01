/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply crash-replay: SIGKILL the consensus co-commit, replay, verify.
 *
 * The utxo_apply step commits FIVE effects of one block as ONE
 * stage_run_once BEGIN IMMEDIATE txn against progress.kv: the coins_kv
 * mutation, the inverse delta, the utxo_apply_log row, the
 * coins_applied_height frontier, and the stage cursor
 * (docs/work/tip-durability-collapse.md). Splitting that transaction is
 * the exact tear class behind the live tip-wedge; until this test, no
 * suite SIGKILLed the real stage mid-commit, so a future edit that splits
 * the txn would ship green. test_kill9_recovery covers the legacy
 * coins_view path under SIGKILL; this is its reducer-path counterpart.
 *
 * Shape (clone of test_kill9_recovery's fork+SIGKILL scaffolding):
 *   - parent seeds a shared progress.kv: UCR_BLOCKS ok=1 proof_validate
 *     rows + the proof_validate cursor, then closes the store pre-fork;
 *   - each cycle forks a child that reopens the SAME store, rebuilds the
 *     deterministic synthetic chain, and drains utxo_apply_stage_step_once
 *     (the production entry point). The fake reader nanosleeps INSIDE the
 *     open stage txn so the parent's randomized SIGKILL (0.5-40 ms, FIXED
 *     rand_r seed — reproducible offsets) lands mid-co-commit;
 *   - after every kill the parent reopens the file raw (WAL recovery, the
 *     same thing the next boot does) and asserts the invariants below;
 *     the next cycle resumes from the durable cursor (the replay);
 *   - a final unkilled cycle must drain to UCR_BLOCKS exactly.
 *
 * Invariants asserted after EVERY kill:
 *   1. utxo_apply_log is EXACTLY the contiguous ok=1 prefix [0, cursor)
 *   2. coins_applied_height == cursor (absent only while cursor == 0)
 *   3. coins content == the recomputed expectation for the prefix: both
 *      outputs of every applied height live with exact values, ZERO coins
 *      at/above the cursor, live count == 2*cursor
 *   4. utxo_apply_delta holds EXACTLY one inverse delta per applied height
 *   5. tip_finalize cursor <= utxo_apply cursor
 *   6. the cursor never rewinds across replay cycles
 *
 * UN-gated (no ZCL_STRESS_TESTS): ~10 kill cycles + one full drain of
 * UCR_BLOCKS synthetic blocks measures low single-digit seconds. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "test/block_fixtures.h"

#include "bloom/merkle.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "jobs/utxo_apply_stage.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <signal.h>
#include <sqlite3.h>
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

#define UCR_BLOCKS      240
#define UCR_KILL_CYCLES 10
#define UCR_RNG_SEED    0x5EEDu  /* fixed: kill offsets reproduce exactly */
#define UCR_BUDGET_SECS 60

static int test_utxo_apply_crash_replay_platform_arm(void);

#define UCR_CHECK(name, expr) do { \
    printf("utxo_apply_crash_replay: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Deterministic synthetic chain ──────────────────────────────────
 * Happy-path clone of test_utxo_apply_stage.c's builder: block h carries a
 * coinbase paying 50+h and one tx spending an "external" prevout (resolved
 * by the fake lookup, value 1000+h) into a 900+h output. Every field is a
 * constant function of h, so each crash-replay cycle rebuilds bit-identical
 * blocks — the determinism the content check below relies on. */

struct ucr_ext_utxo {
    struct uint256 txid;
    uint32_t vout;
    int64_t value;
};

struct ucr_chain {
    struct block_index  *blocks;
    struct uint256      *hashes;
    struct block        *bodies;
    struct ucr_ext_utxo *ext;
    int                  n;
};

static void ucr_txid(struct uint256 *out, int h, int salt)
{
    uint256_set_null(out);
    out->data[0] = (uint8_t)(0x80 + h);
    out->data[1] = (uint8_t)salt;
    out->data[2] = (uint8_t)(h >> 8);  /* keep txids distinct past h=127 */
}

static bool ucr_make_tx(struct transaction *tx, int h, bool coinbase,
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
    ucr_txid(&tx->hash, h, coinbase ? 1 : 2);
    return true;
}

static bool ucr_make_body(struct ucr_chain *cc, int h)
{
    struct block *b = &cc->bodies[h];
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700002000u + (uint32_t)h);
    b->header.nBits = 0x1f07ffff;
    b->num_vtx = 2;
    b->vtx = zcl_calloc(2, sizeof(struct transaction), "ucr_tx");
    if (!b->vtx) return false;

    struct uint256 prev;
    ucr_txid(&prev, h, 9);
    cc->ext[h].txid = prev;
    cc->ext[h].vout = 0;
    cc->ext[h].value = 1000 + h;

    if (!ucr_make_tx(&b->vtx[0], h, true, NULL, 50 + h)) return false;
    if (!ucr_make_tx(&b->vtx[1], h, false, &prev, 900 + h)) return false;
    struct uint256 txids[2] = { b->vtx[0].hash, b->vtx[1].hash };
    b->header.hashMerkleRoot = compute_merkle_root(txids, 2);
    return true;
}

static bool ucr_chain_build(struct ucr_chain *cc, int n)
{
    memset(cc, 0, sizeof(*cc));
    cc->blocks = zcl_calloc((size_t)n, sizeof(struct block_index),
                            "ucr_blocks");
    cc->hashes = zcl_calloc((size_t)n, sizeof(struct uint256), "ucr_hashes");
    cc->bodies = zcl_calloc((size_t)n, sizeof(struct block), "ucr_bodies");
    cc->ext    = zcl_calloc((size_t)n, sizeof(struct ucr_ext_utxo),
                            "ucr_ext");
    if (!cc->blocks || !cc->hashes || !cc->bodies || !cc->ext)
        return false;
    for (int i = 0; i < n; i++) {
        if (!ucr_make_body(cc, i)) return false;
        block_header_get_hash(&cc->bodies[i].header, &cc->hashes[i]);
        block_index_init(&cc->blocks[i]);
        cc->blocks[i].phashBlock = &cc->hashes[i];
        cc->blocks[i].hashMerkleRoot = cc->bodies[i].header.hashMerkleRoot;
        cc->blocks[i].nHeight = i;
        cc->blocks[i].nVersion = cc->bodies[i].header.nVersion;
        cc->blocks[i].nTime = cc->bodies[i].header.nTime;
        cc->blocks[i].nBits = cc->bodies[i].header.nBits;
        cc->blocks[i].nStatus = BLOCK_HAVE_DATA;
        if (i > 0) cc->blocks[i].pprev = &cc->blocks[i - 1];
    }
    cc->n = n;
    return true;
}

static void ucr_chain_free(struct ucr_chain *cc)
{
    if (cc->bodies) {
        for (int i = 0; i < cc->n; i++)
            block_free(&cc->bodies[i]);
    }
    free(cc->blocks);
    free(cc->hashes);
    free(cc->bodies);
    free(cc->ext);
    memset(cc, 0, sizeof(*cc));
}

/* Runs INSIDE stage_run_once's BEGIN IMMEDIATE: the sleep stretches the
 * open-txn window so the parent's randomized SIGKILL lands mid-co-commit
 * (not just between transactions). */
static bool ucr_crash_reader(struct block *out, const struct block_index *bi,
                             const char *datadir, void *user)
{
    (void)datadir;
    struct ucr_chain *cc = user;
    if (!out || !bi || !cc || bi->nHeight < 0 || bi->nHeight >= cc->n)
        return false;
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 400000L };
    nanosleep(&ts, NULL);
    return test_block_copy(out, &cc->bodies[bi->nHeight], "ucr_tx_copy");
}

static bool ucr_lookup(const struct uint256 *txid, uint32_t vout,
                       struct utxo_apply_lookup *out, void *user)
{
    struct ucr_chain *cc = user;
    memset(out, 0, sizeof(*out));
    if (!cc) return true;
    for (int i = 0; i < cc->n; i++) {
        if (cc->ext[i].vout == vout && uint256_eq(&cc->ext[i].txid, txid)) {
            out->found = true;
            out->value = cc->ext[i].value;
            return true;
        }
    }
    return true;
}

/* ── Child worker: the process the parent SIGKILLs ─────────────────
 * Opens the shared store and drains the REAL utxo_apply stage through its
 * production entry point. Exit 0 == drained to the proof_validate cursor;
 * any other exit code is a child-side failure the parent reports. */
static void ucr_child_worker(const char *dir)
{
    blocker_module_init();
    /* The sequential runner shares one process across groups: drop any
     * stage binding inherited over fork() before binding our main_state
     * (shutdown with no live stage is a safe no-op). */
    utxo_apply_stage_shutdown();
    if (!progress_store_open(dir)) _exit(10);

    struct ucr_chain cc;
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    active_chain_init(&ms.chain_active);
    if (!ucr_chain_build(&cc, UCR_BLOCKS)) _exit(11);
    active_chain_move_window_tip(&ms.chain_active,
                                 &cc.blocks[UCR_BLOCKS - 1]);

    if (!utxo_apply_stage_init(&ms)) _exit(12);
    utxo_apply_stage_set_reader(ucr_crash_reader, &cc);
    utxo_apply_stage_set_lookup(ucr_lookup, &cc);

    for (;;) {
        job_result_t r = utxo_apply_stage_step_once();
        if (r == JOB_IDLE) break;          /* drained to the pv cursor */
        if (r != JOB_ADVANCED) _exit(13);  /* BLOCKED/FATAL = real bug */
    }
    _exit(0);
}

/* ── Parent-side seed + verification (raw handle, like the next boot) ── */

static bool ucr_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool ucr_seed_proof_validate(sqlite3 *db, int n)
{
    if (!db || n <= 0)
        return false;
    struct ucr_chain cc;
    if (!ucr_chain_build(&cc, n)) {
        ucr_chain_free(&cc);
        return false;
    }
    bool result = false;
    sqlite3_stmt *st = NULL, *script_st = NULL;
    if (!ucr_exec(db,
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
        !ucr_exec(db,
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL, ok INTEGER NOT NULL,"
        "  tx_count INTEGER NOT NULL, input_count INTEGER NOT NULL,"
        "  first_failure_txid BLOB, first_failure_vin INTEGER,"
        "  first_failure_serror INTEGER, validated_at INTEGER NOT NULL,"
        "  block_hash BLOB)"))
        goto done;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO proof_validate_log "
        "(height, status, ok, sapling_spends_total, sapling_outputs_total, "
        " sprout_joinsplits_total, block_hash, validated_at) "
        "VALUES (?, 'verified', 1, 0, 0, 0, ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        goto done;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO script_validate_log "
        "(height, status, ok, tx_count, input_count, validated_at, block_hash) "
        "VALUES (?, 'verified', 1, 0,0,1,?)",
        -1, &script_st, NULL) != SQLITE_OK)
        goto done;
    for (int h = 0; h < n; h++) {
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_blob(st, 2, cc.hashes[h].data, 32, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) {
            goto done;
        }
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_int(script_st, 1, h);
        sqlite3_bind_blob(script_st, 2, cc.hashes[h].data, 32,
                          SQLITE_STATIC);
        if (sqlite3_step(script_st) != SQLITE_DONE)
            goto done;
        sqlite3_reset(script_st);
        sqlite3_clear_bindings(script_st);
    }
    sqlite3_finalize(st);
    st = NULL;
    sqlite3_finalize(script_st);
    script_st = NULL;

    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
        "VALUES('proof_validate', ?, 1)", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int(st, 1, n);
    result = sqlite3_step(st) == SQLITE_DONE;
done:
    sqlite3_finalize(st);
    sqlite3_finalize(script_st);
    ucr_chain_free(&cc);
    return result;
}

static bool ucr_table_exists(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    bool yes = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return yes;
}

/* -1 on error, 0 when no row (a never-advanced stage). */
static int64_t ucr_stage_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int64_t c = 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        c = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return c;
}

/* `table` (height PRIMARY KEY) must hold EXACTLY rows 0..c-1; with the
 * unique key, COUNT==c plus MIN==0/MAX==c-1 proves contiguity. min_ok_col
 * additionally requires every row's `ok` to be 1 (pass NULL to skip). */
static bool ucr_height_table_is_prefix(sqlite3 *db, const char *table,
                                       const char *min_ok_col, int64_t c)
{
    if (!ucr_table_exists(db, table))
        return c == 0;  /* killed before the stage's init ensured it */
    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*), COALESCE(MIN(height),0),"
             " COALESCE(MAX(height),-1), COALESCE(MIN(%s),1) FROM %s",
             min_ok_col ? min_ok_col : "1", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        int64_t count = sqlite3_column_int64(st, 0);
        int64_t min_h = sqlite3_column_int64(st, 1);
        int64_t max_h = sqlite3_column_int64(st, 2);
        int64_t min_v = sqlite3_column_int64(st, 3);
        ok = count == c && min_v == 1 &&
             (c == 0 || (min_h == 0 && max_h == c - 1));
    }
    sqlite3_finalize(st);
    return ok;
}

/* Recompute the expected coins set for the applied prefix [0, c) from the
 * chain DEFINITION (no replay needed — every block is a constant function
 * of h) and compare against the durable coins table, both directions:
 * every expected output live with its exact value, nothing above the
 * cursor, and the total live count exact. */
static bool ucr_coins_match(sqlite3 *db, int64_t c, char *why, size_t why_sz)
{
    if (!ucr_table_exists(db, "coins")) {
        if (c != 0) snprintf(why, why_sz, "coins table missing at c=%lld",
                             (long long)c);
        return c == 0;
    }
    int64_t live = coins_kv_count(db);
    if (live != 2 * c) {
        snprintf(why, why_sz, "live=%lld expected=%lld",
                 (long long)live, (long long)(2 * c));
        return false;
    }
    for (int h = 0; h < UCR_BLOCKS; h++) {
        bool want = (int64_t)h < c;
        struct uint256 id;
        int64_t v;
        ucr_txid(&id, h, 1);
        v = -1;
        if (coins_kv_get(db, id.data, 0, &v, NULL, 0, NULL) != want ||
            (want && v != 50 + h)) {
            snprintf(why, why_sz, "coinbase h=%d want=%d v=%lld",
                     h, (int)want, (long long)v);
            return false;
        }
        ucr_txid(&id, h, 2);
        v = -1;
        if (coins_kv_get(db, id.data, 0, &v, NULL, 0, NULL) != want ||
            (want && v != 900 + h)) {
            snprintf(why, why_sz, "tx out h=%d want=%d v=%lld",
                     h, (int)want, (long long)v);
            return false;
        }
    }
    return true;
}

/* One reopen-and-assert pass; the same recovery surface the next boot
 * walks. Returns the verified cursor via *out_cursor; -1 on any failure
 * (reason printed). */
static int ucr_verify(const char *dbpath, int cycle, int64_t prev_cursor,
                      int64_t *out_cursor)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(dbpath, &db) != SQLITE_OK) {
        printf("FAIL (cycle %d: reopen failed)\n", cycle);
        sqlite3_close(db);
        return -1;
    }

    int rc = -1;
    char why[128] = "";
    int64_t c = ucr_stage_cursor(db, "utxo_apply");
    int64_t tf = ucr_stage_cursor(db, "tip_finalize");
    int32_t frontier = -1;
    bool frontier_found = false;

    if (c < 0 || tf < 0) {
        printf("FAIL (cycle %d: cursor read error)\n", cycle);
    } else if (c < prev_cursor) {
        printf("FAIL (cycle %d: cursor REWOUND %lld -> %lld)\n",
               cycle, (long long)prev_cursor, (long long)c);
    } else if (!ucr_height_table_is_prefix(db, "utxo_apply_log", "ok", c)) {
        printf("FAIL (cycle %d: utxo_apply_log != contiguous ok=1 prefix "
               "[0,%lld))\n", cycle, (long long)c);
    } else if (!ucr_height_table_is_prefix(db, "utxo_apply_delta", NULL, c)) {
        printf("FAIL (cycle %d: inverse deltas != one per applied height "
               "[0,%lld))\n", cycle, (long long)c);
    } else if (!coins_kv_get_applied_height(db, &frontier, &frontier_found)) {
        printf("FAIL (cycle %d: coins_applied_height read error)\n", cycle);
    } else if (frontier_found ? (int64_t)frontier != c : c != 0) {
        printf("FAIL (cycle %d: coins_applied_height %s%d != cursor %lld)\n",
               cycle, frontier_found ? "" : "ABSENT ", (int)frontier,
               (long long)c);
    } else if (!ucr_coins_match(db, c, why, sizeof(why))) {
        printf("FAIL (cycle %d: coins diverged from recompute: %s)\n",
               cycle, why);
    } else if (tf > c) {
        printf("FAIL (cycle %d: tip_finalize cursor %lld > utxo_apply "
               "%lld)\n", cycle, (long long)tf, (long long)c);
    } else {
        *out_cursor = c;
        rc = 0;
    }
    sqlite3_close(db);
    return rc;
}

/* Fork the worker; SIGKILL it after delay_us (skip the kill when
 * delay_us < 0 — the final full-drain cycle). Returns -1 on harness
 * failure, else 1 if the child died to SIGKILL, 0 if it exited clean. */
static int ucr_one_cycle(const char *dir, int cycle, long delay_us)
{
    pid_t pid = fork();
    if (pid < 0) {
        printf("FAIL (cycle %d: fork: %s)\n", cycle, strerror(errno));
        return -1;
    }
    if (pid == 0) {
        ucr_child_worker(dir);
        _exit(99);  /* unreachable — the worker always _exit()s */
    }

    if (delay_us >= 0) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = delay_us * 1000L };
        nanosleep(&ts, NULL);
        if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
            printf("FAIL (cycle %d: kill: %s)\n", cycle, strerror(errno));
            waitpid(pid, NULL, 0);
            return -1;
        }
    }

    int status = 0;
    if (waitpid(pid, &status, 0) != pid) {
        printf("FAIL (cycle %d: waitpid: %s)\n", cycle, strerror(errno));
        return -1;
    }
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
        return 1;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return 0;
    printf("FAIL (cycle %d: child ended abnormally; signaled=%d exited=%d "
           "code=%d)\n", cycle, WIFSIGNALED(status), WIFEXITED(status),
           WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return -1;
}

static int test_utxo_apply_crash_replay_platform_arm(void)
{
    int failures = 0;
    printf("\n=== utxo_apply crash-replay (SIGKILL the co-commit) ===\n");

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "utxo_apply", "crash_replay");
    char dbpath[512];
    /* After the A3 flip the kernel co-commit store is consensus.db, not
     * progress.kv — the direct cursor read below must open that file. */
    snprintf(dbpath, sizeof(dbpath), "%s/consensus.db", dir);

    /* Seed through the singleton, then CLOSE before any fork so no child
     * inherits an open handle. */
    bool seeded = progress_store_open(dir) &&
                  ucr_seed_proof_validate(progress_store_db(), UCR_BLOCKS);
    progress_store_close();
    UCR_CHECK("seed proof_validate prefix", seeded);
    if (failures) return failures;

    time_t t0 = platform_time_wall_time_t();
    unsigned int rng = UCR_RNG_SEED;
    int64_t cursor = 0;
    int n_killed = 0, n_clean = 0;

    /* monolith isolation: a prior group's alerts_init() installs SA_NOCLDWAIT
     * on SIGCHLD (auto-reap), so the waitpid() in ucr_one_cycle returns ECHILD
     * and no child is ever observed killed (n_killed stays 0). Restore default
     * SIGCHLD for the fork+kill cycles. Mirrors test_body_fetch_stage.c. */
    struct sigaction ucr_old_chld, ucr_dfl_chld;
    int ucr_restore_chld = 0;
    memset(&ucr_old_chld, 0, sizeof(ucr_old_chld));
    memset(&ucr_dfl_chld, 0, sizeof(ucr_dfl_chld));
    ucr_dfl_chld.sa_handler = SIG_DFL;
    sigemptyset(&ucr_dfl_chld.sa_mask);
    if (sigaction(SIGCHLD, NULL, &ucr_old_chld) == 0 &&
        sigaction(SIGCHLD, &ucr_dfl_chld, NULL) == 0)
        ucr_restore_chld = 1;

    for (int i = 0; i < UCR_KILL_CYCLES && !failures; i++) {
        long delay_us = 500 + (long)(rand_r(&rng) % 40000);
        int kr = ucr_one_cycle(dir, i, delay_us);
        if (kr < 0 || ucr_verify(dbpath, i, cursor, &cursor) != 0) {
            failures++;
            break;
        }
        if (kr == 1) n_killed++;
        else n_clean++;
    }
    /* The first cycle starts at cursor 0 and a full drain takes far longer
     * than the 40 ms kill ceiling, so a run where NO child died to SIGKILL
     * means the harness lost its teeth — fail loudly, don't pass vacuously. */
    UCR_CHECK("at least one child SIGKILLed mid-apply", n_killed >= 1);

    if (!failures) {
        int kr = ucr_one_cycle(dir, UCR_KILL_CYCLES, -1);
        UCR_CHECK("final unkilled cycle drains clean", kr == 0);
        UCR_CHECK("final replay verifies",
                  !failures &&
                  ucr_verify(dbpath, UCR_KILL_CYCLES, cursor, &cursor) == 0);
        UCR_CHECK("final cursor == all blocks applied",
                  cursor == UCR_BLOCKS);
    }

    if (ucr_restore_chld) (void)sigaction(SIGCHLD, &ucr_old_chld, NULL);

    int elapsed = (int)(platform_time_wall_time_t() - t0);
    UCR_CHECK("runtime within budget", elapsed <= UCR_BUDGET_SECS);

    if (!failures)
        printf("utxo_apply_crash_replay OK (%d killed, %d clean, final "
               "cursor %lld, %ds)\n", n_killed, n_clean,
               (long long)cursor, elapsed);

    test_cleanup_tmpdir(dir);
    printf("utxo_apply crash-replay tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's fork+SIGKILL UTXO-apply crash-replay lane
 * cannot run here. Skipped loudly rather than faked. */
static int test_utxo_apply_crash_replay_platform_arm(void)
{
    printf("utxo_apply_crash_replay: SKIP (Windows): fork+SIGKILL UTXO-apply crash-replay lane\n");
    return 0;
}
#endif

int test_utxo_apply_crash_replay(void)
{
    return test_utxo_apply_crash_replay_platform_arm();
}
