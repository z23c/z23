/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_block_status_event_restart_proof — kill -9 restart-proof for the
 * lightweight EV_BLOCK_STATUS status-bump emitter.
 *
 * body_persist_stage and script_validate_stage bump BLOCK_HAVE_DATA /
 * BLOCK_VALID_SCRIPTS by appending a fixed 52-byte EV_BLOCK_STATUS event
 * (block_index_emit_status_event). The projection's catch_up
 * (catch_up_apply_status) reconstructs the full row by patching the mutable
 * fields of the blob the earlier EV_BLOCK_HEADER wrote.
 *
 * Proves the projection reconstructs byte-identical state after a hard kill -9
 * mid-fold, using the real emit helpers and the real projection catch_up path.
 *
 * Method:
 *   (a) FOLD: a forked child processes RP_N_BLOCKS blocks, each through the
 *       real three-event sequence (EV_BLOCK_HEADER, HAVE_DATA status bump,
 *       VALID_SCRIPTS status bump) plus a durable "done" marker via the real
 *       stage_cursor primitive (util/stage.h).
 *   (b) HARD-STOP: the parent SIGKILLs the child at a randomised point.
 *   (c) REBOOT: the parent reopens the event log (torn-tail recovery), the
 *       projection (catch_up from the persisted offset) and the stage_cursor
 *       table, then asserts every height below the durable cursor
 *       reconstructs exactly: found, both status bits set, mutable fields
 *       (nFile/nDataPos/nTx) correct, immutable header fields (merkle root,
 *       sapling root, solution bytes) byte-identical. The boundary height may
 *       legitimately be ahead of the cursor (two independently durable
 *       stores) but must never show corrupted data. A fresh projection
 *       replayed from offset 0 matches the live one exactly.
 *   (d) RESUME: one more height is folded through the same reopened handles.
 *
 * Repeated across RP_N_CYCLES fork+SIGKILL rounds against the same datadir
 * until the fixture completes, then one uninterrupted drain proves the
 * fully-folded terminal is reachable.
 *
 * script_validate's ECDSA/script verification is covered by
 * test_script_validate_stage.c; stage-cursor/coins_kv resumption for the full
 * pipeline by test_stage_crash_sweep.c.
 *
 * make t-fast ONLY=block_status_event_restart_proof */

#include "test/block_index_ext_fixture.h"
#include "test/test_core.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "jobs/block_header_emit.h"
#include "jobs/stage_helpers.h"
#include "storage/block_index_db.h"
#include "storage/block_index_projection.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/event_log_singleton.h"
#include "storage/progress_store.h"
#include "util/stage.h"

#include <errno.h>
#include <inttypes.h>
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

static int test_block_status_event_restart_proof_platform_arm(void);

#define RP_N_BLOCKS     48
#define RP_SOLUTION_LEN 96
#define RP_N_CYCLES     8
#define RP_BUDGET_SEC   60
#define RP_CURSOR_NAME  "rp_status_event_restart"

static void rp_event_log_close(event_log_t *log)
{
    if (!log)
        return;
    if (event_log_singleton() == log)
        event_log_set_singleton(NULL);
    event_log_close(log);
}

#define RP_CHECK(name, expr) do {                                     \
    printf("  block_status_event_restart_proof: %s... ", (name));     \
    if ((expr)) printf("OK\n");                                       \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

/* ── Deterministic fixture: pure function of height, no I/O ─────────── */

struct rp_block {
    struct uint256 hash;
    struct uint256 merkle_root;
    struct uint256 sapling_root;
    struct uint256 nonce;
    uint8_t solution[RP_SOLUTION_LEN];
};

struct rp_chain {
    struct rp_block blocks[RP_N_BLOCKS];
};

static void rp_fill_u256(struct uint256 *u, uint32_t seed)
{
    for (int i = 0; i < 32; i++)
        u->data[i] = (uint8_t)((seed * 2654435761u + (uint32_t)i * 97u) & 0xFFu);
}

static void rp_build_chain(struct rp_chain *c)
{
    memset(c, 0, sizeof(*c));
    for (int h = 0; h < RP_N_BLOCKS; h++) {
        struct rp_block *b = &c->blocks[h];
        rp_fill_u256(&b->hash, 0x1000u + (uint32_t)h);
        rp_fill_u256(&b->merkle_root, 0x2000u + (uint32_t)h);
        rp_fill_u256(&b->sapling_root, 0x3000u + (uint32_t)h);
        rp_fill_u256(&b->nonce, 0x4000u + (uint32_t)h);
        for (int i = 0; i < RP_SOLUTION_LEN; i++)
            b->solution[i] = (uint8_t)((h * 31 + i) & 0xFF);
    }
}

static int rp_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* Rebuild the in-memory block_index entry for height h — a pure function of
 * the fixture, independent per process. Does NOT emit anything. */
static void rp_make_block_index(struct block_index *bi, struct block_index *prev,
                                struct rp_chain *c, int h)
{
    block_index_init(bi);
    bi->hashBlock = c->blocks[h].hash;
    bi->phashBlock = &bi->hashBlock;
    bi->pprev = prev;
    bi->nHeight = h;
    bi->nVersion = 4;
    bi->nTime = 1700200000u + (uint32_t)h;
    bi->nBits = 0x1f07ffffu;
    tbi_ext(bi)->hashMerkleRoot = c->blocks[h].merkle_root;
    bi->hashFinalSaplingRoot = c->blocks[h].sapling_root;
    tbi_ext(bi)->nNonce = c->blocks[h].nonce;
    tbi_ext(bi)->nSolution = c->blocks[h].solution;
    tbi_ext(bi)->nSolutionSize = RP_SOLUTION_LEN;
    bi->nStatus = BLOCK_VALID_HEADER;
}

/* Rebuild blocks[0..upto) purely in-memory (no emits) so pprev links are
 * correct before the parent drives a resume step. */
static void rp_rebuild_prefix(struct rp_chain *c, struct block_index *blocks,
                              int upto)
{
    for (int h = 0; h < upto && h < RP_N_BLOCKS; h++)
        rp_make_block_index(&blocks[h], h > 0 ? &blocks[h - 1] : NULL, c, h);
}

/* One durable "unit of fold" for height h:
 *   1. header_admit: full EV_BLOCK_HEADER (first admit).
 *   2. body_persist: BLOCK_HAVE_DATA + nFile/nDataPos/nTx status bump.
 *   3. script_validate: BLOCK_VALID_SCRIPTS status bump.
 *   4. A durable "done" marker via the real stage_cursor primitive,
 *      independent of the event log. */
static bool rp_process_one(sqlite3 *db, struct rp_chain *c,
                           struct block_index *blocks, int h)
{
    struct block_index *bi = &blocks[h];
    rp_make_block_index(bi, h > 0 ? &blocks[h - 1] : NULL, c, h);

    block_index_emit_header_event(bi, "header_admit", NULL, NULL);

    block_index_status_fetch_or(bi, BLOCK_HAVE_DATA);
    bi->nFile = 0;
    bi->nDataPos = 1000u + (unsigned)h * 100u;
    bi->nTx = 1;
    block_index_emit_status_event(bi, "body_persist", NULL, NULL);

    block_index_status_set_valid_level(bi, BLOCK_VALID_SCRIPTS);
    block_index_emit_status_event(bi, "script_validate", NULL, NULL);

    return stage_set_named_cursor(db, RP_CURSOR_NAME, (uint64_t)(h + 1));
}

/* ── Child worker: resumable — starts wherever the durable cursor says ── */

static void rp_child_worker(const char *log_path, const char *bip_path,
                            const char *dir, struct rp_chain *c)
{
    event_log_t *log = event_log_open(log_path);
    if (!log) _exit(1);
    event_log_set_singleton(log);

    block_index_projection_t *bip = block_index_projection_open(bip_path, log);
    if (!bip) _exit(2);

    if (!progress_store_open(dir)) _exit(3);
    sqlite3 *db = progress_store_db();
    if (!db || !stage_table_ensure(db)) _exit(4);

    uint64_t cursor = 0;
    (void)stage_cursor_read_or_zero(db, RP_CURSOR_NAME, "rp", &cursor);

    static struct block_index blocks[RP_N_BLOCKS];
    rp_rebuild_prefix(c, blocks, (int)cursor);

    for (int h = (int)cursor; h < RP_N_BLOCKS; h++) {
        if (!rp_process_one(db, c, blocks, h))
            _exit(5);
        if (block_index_projection_catch_up(bip) == UINT64_MAX)
            _exit(6);
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 300000L }; /* 0.3ms */
        nanosleep(&ts, NULL);
    }

    progress_store_close();
    block_index_projection_close(bip);
    rp_event_log_close(log);
    _exit(0);
}

/* ── One fork + randomised SIGKILL + reboot + verify cycle ───────────── */

static int rp_one_cycle(const char *log_path, const char *bip_path,
                        const char *dir, struct rp_chain *c,
                        int cycle_idx, unsigned int *rng_state,
                        bool *out_all_done)
{
    int failures = 0;
    *out_all_done = false;

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        rp_child_worker(log_path, bip_path, dir, c);
        _exit(99); /* unreachable */
    }

    long delay_us = 100 + (long)(rand_r(rng_state) % 15000); /* 0.1-15.1ms */
    struct timespec delay_ts = { .tv_sec = 0, .tv_nsec = delay_us * 1000 };
    nanosleep(&delay_ts, NULL);

    if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
        perror("kill");
        waitpid(pid, NULL, 0);
        return 1;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) { perror("waitpid"); return 1; }
    bool killed = WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
    bool exited_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!killed && !exited_ok) {
        printf("FAIL (cycle %d: child ended abnormally; WIFSIGNALED=%d "
               "WIFEXITED=%d status=%d)\n",
               cycle_idx, WIFSIGNALED(status), WIFEXITED(status), status);
        return 1;
    }

    /* ── REBOOT: reopen exactly as a real restart would ── */
    event_log_t *log = event_log_open(log_path);
    if (!log) {
        printf("FAIL (cycle %d: event_log reopen failed)\n", cycle_idx);
        return 1;
    }
    event_log_set_singleton(log);

    block_index_projection_t *bip = block_index_projection_open(bip_path, log);
    if (!bip) {
        printf("FAIL (cycle %d: projection reopen failed)\n", cycle_idx);
        rp_event_log_close(log);
        return 1;
    }
    if (block_index_projection_catch_up(bip) == UINT64_MAX) {
        printf("FAIL (cycle %d: projection catch_up failed)\n", cycle_idx);
        failures++;
    }

    if (!progress_store_open(dir)) {
        printf("FAIL (cycle %d: progress_store reopen failed)\n", cycle_idx);
        failures++;
        block_index_projection_close(bip);
        rp_event_log_close(log);
        return failures;
    }

    sqlite3 *db = progress_store_db();
    uint64_t cursor = 0;
    bool cursor_ok = db != NULL &&
                    stage_cursor_read_or_zero(db, RP_CURSOR_NAME, "rp", &cursor);
    RP_CHECK("stage cursor reads back durably (survives the SIGKILL)",
             cursor_ok);

    /* (c) Every height BELOW the durable cursor completed its FULL
     * three-event sequence before the crash (or an earlier cycle) — the
     * heights a real fold considers done and never revisits. Assert the
     * projection reconstructs each one EXACTLY. */
    bool all_heights_ok = true;
    for (uint64_t h = 0; h < cursor; h++) {
        struct disk_block_index dbi;
        disk_block_index_init(&dbi);
        bool found = block_index_projection_get(bip, c->blocks[h].hash.data,
                                                &dbi);
        if (!found) {
            all_heights_ok = false;
            printf("    height %" PRIu64 " MISSING from the projection "
                   "after restart (missing-header error)\n", h);
            continue;
        }
        bool status_ok = (dbi.nStatus & BLOCK_HAVE_DATA) != 0 &&
                         (dbi.nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS;
        bool mutable_ok = dbi.nFile == 0 &&
                          dbi.nDataPos == 1000u + (unsigned)h * 100u &&
                          dbi.nTx == 1;
        bool immutable_ok =
            uint256_cmp(&dbi.hashMerkleRoot, &c->blocks[h].merkle_root) == 0 &&
            uint256_cmp(&dbi.hashFinalSaplingRoot,
                       &c->blocks[h].sapling_root) == 0 &&
            uint256_cmp(&dbi.nNonce, &c->blocks[h].nonce) == 0 &&
            dbi.nSolutionSize == RP_SOLUTION_LEN &&
            memcmp(dbi.nSolution, c->blocks[h].solution, RP_SOLUTION_LEN) == 0;
        if (!status_ok || !mutable_ok || !immutable_ok) {
            all_heights_ok = false;
            printf("    height %" PRIu64 " WRONG after restart: status_ok=%d "
                   "mutable_ok=%d immutable_ok=%d\n",
                   h, status_ok, mutable_ok, immutable_ok);
        }
    }
    RP_CHECK("every completed height reconstructs identical state "
             "(status + mutable fields + immutable header bytes)",
             all_heights_ok);

    /* Boundary height (at the cursor): the event log and the stage cursor are
     * two independently durable stores written with separate barriers, so a
     * SIGKILL between them can leave the projection legitimately ahead of the
     * cursor for this one height. That is not corruption: every field is a
     * deterministic function of h and the fold resumes at the cursor. What
     * must never happen is the boundary showing wrong data. */
    bool boundary_ok = true;
    if (cursor < (uint64_t)RP_N_BLOCKS) {
        struct disk_block_index bdbi;
        disk_block_index_init(&bdbi);
        bool bfound = block_index_projection_get(
            bip, c->blocks[cursor].hash.data, &bdbi);
        if (bfound) {
            boundary_ok =
                uint256_cmp(&bdbi.hashMerkleRoot,
                           &c->blocks[cursor].merkle_root) == 0 &&
                uint256_cmp(&bdbi.hashFinalSaplingRoot,
                           &c->blocks[cursor].sapling_root) == 0 &&
                uint256_cmp(&bdbi.nNonce, &c->blocks[cursor].nonce) == 0 &&
                bdbi.nSolutionSize == RP_SOLUTION_LEN &&
                memcmp(bdbi.nSolution, c->blocks[cursor].solution,
                      RP_SOLUTION_LEN) == 0;
        }
    }
    RP_CHECK("boundary height (at the cursor), if present in the "
             "projection at all, is never corrupted — correct header "
             "bytes whether or not the fold has durably marked it done",
             boundary_ok);

    /* Prime-Directive check: a FRESH projection replayed from offset 0 over
     * the SAME (possibly torn-tail-truncated) log must match the live
     * continued projection exactly — no path dependence from the crash. */
    char fresh_path[600];
    snprintf(fresh_path, sizeof(fresh_path), "%s.fresh_%d", bip_path,
            cycle_idx);
    block_index_projection_t *fresh = block_index_projection_open(fresh_path,
                                                                  log);
    bool fresh_ok = fresh != NULL;
    if (fresh) {
        fresh_ok = block_index_projection_catch_up(fresh) != UINT64_MAX;
        uint8_t clive[32], cfresh[32];
        fresh_ok = fresh_ok &&
            block_index_projection_commitment(bip, clive) == 0 &&
            block_index_projection_commitment(fresh, cfresh) == 0 &&
            memcmp(clive, cfresh, 32) == 0 &&
            block_index_projection_count(bip) == block_index_projection_count(fresh);
        block_index_projection_close(fresh);
    }
    RP_CHECK("fresh replay-from-scratch == live continued projection "
             "(Prime Directive)", fresh_ok);

    /* (d) RESUME: fold one more height through the SAME reopened handles —
     * no consumer error, the fold resumes cleanly. */
    static struct block_index blocks[RP_N_BLOCKS];
    rp_rebuild_prefix(c, blocks, (int)cursor);
    if (cursor < (uint64_t)RP_N_BLOCKS) {
        bool resumed = rp_process_one(db, c, blocks, (int)cursor);
        RP_CHECK("fold resumes past the crash with no error", resumed);
        if (resumed) {
            bool caught_up =
                block_index_projection_catch_up(bip) != UINT64_MAX;
            struct disk_block_index dbi;
            disk_block_index_init(&dbi);
            bool found = caught_up &&
                block_index_projection_get(bip, c->blocks[cursor].hash.data,
                                           &dbi);
            RP_CHECK("resumed height is found + fully bumped",
                     found && (dbi.nStatus & BLOCK_HAVE_DATA) != 0 &&
                     (dbi.nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS);
        }
        *out_all_done = (cursor + 1 >= (uint64_t)RP_N_BLOCKS);
    } else {
        *out_all_done = true;
    }

    progress_store_close();
    block_index_projection_close(bip);
    rp_event_log_close(log);
    return failures;
}

static int test_block_status_event_restart_proof_platform_arm(void)
{
    int failures = 0;
    printf("\n=== test_block_status_event_restart_proof "
           "(kill -9 mid-fold, EV_BLOCK_STATUS reconstruction) ===\n");

    rp_mkdir_p("./test-tmp");
    char dir[300];
    snprintf(dir, sizeof(dir), "./test-tmp/rp_status_%d", (int)getpid());
    test_rm_rf_recursive(dir);
    rp_mkdir_p(dir);

    char log_path[400], bip_path[400];
    snprintf(log_path, sizeof(log_path), "%s/events.log", dir);
    snprintf(bip_path, sizeof(bip_path), "%s/block_index_projection.db", dir);

    struct rp_chain *c = malloc(sizeof(*c));
    if (!c) {
        printf("FAIL (fixture alloc failed)\n");
        test_rm_rf_recursive(dir);
        return 1;
    }
    rp_build_chain(c);

    unsigned int rng = (unsigned int)(platform_time_wall_time_t() ^
                                      (uint64_t)getpid() ^ 0x53544154ull);
    time_t t0 = platform_time_wall_time_t();

    bool all_done = false;
    int cycles_run = 0;
    for (int i = 0; i < RP_N_CYCLES && !all_done; i++) {
        cycles_run++;
        int cyc_failures = rp_one_cycle(log_path, bip_path, dir, c, i, &rng,
                                        &all_done);
        failures += cyc_failures;
        if (cyc_failures)
            break;
    }

    /* Terminal: drain any remaining heights uninterrupted, proving the
     * fully-folded terminal is reachable however many SIGKILLs preceded it. */
    if (!failures) {
        event_log_t *log = event_log_open(log_path);
        block_index_projection_t *bip =
            log ? block_index_projection_open(bip_path, log) : NULL;
        bool ok = log && bip;
        if (ok) {
            event_log_set_singleton(log);
            ok = progress_store_open(dir);
        }
        if (ok) {
            sqlite3 *db = progress_store_db();
            uint64_t cursor = 0;
            ok = db != NULL &&
                stage_cursor_read_or_zero(db, RP_CURSOR_NAME, "rp", &cursor);
            static struct block_index blocks[RP_N_BLOCKS];
            rp_rebuild_prefix(c, blocks, (int)cursor);
            for (uint64_t h = cursor; ok && h < (uint64_t)RP_N_BLOCKS; h++)
                ok = rp_process_one(db, c, blocks, (int)h);
            ok = ok && block_index_projection_catch_up(bip) != UINT64_MAX;

            bool complete = ok;
            for (int h = 0; complete && h < RP_N_BLOCKS; h++) {
                struct disk_block_index dbi;
                disk_block_index_init(&dbi);
                complete = block_index_projection_get(
                               bip, c->blocks[h].hash.data, &dbi) &&
                           (dbi.nStatus & BLOCK_HAVE_DATA) != 0 &&
                           (dbi.nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS;
            }
            RP_CHECK("uninterrupted terminal drain completes the whole "
                     "fixture (every height bumped)", complete);
            all_done = complete;
            progress_store_close();
        } else {
            RP_CHECK("terminal drain: reopen succeeded", false);
        }
        if (bip) block_index_projection_close(bip);
        rp_event_log_close(log);
    }

    RP_CHECK("fixture fully folded (kill cycles + terminal drain)", all_done);

    int elapsed = (int)(platform_time_wall_time_t() - t0);
    if (elapsed > RP_BUDGET_SEC) {
        printf("FAIL (%d cycles took %ds, exceeds %ds budget)\n",
               cycles_run, elapsed, RP_BUDGET_SEC);
        failures++;
    }

    if (!failures)
        printf("test_block_status_event_restart_proof: OK (%d cycle(s) in "
               "%ds; every completed height survived a real SIGKILL with "
               "identical status + header state; fold always resumed)\n",
               cycles_run, elapsed);
    else
        printf("test_block_status_event_restart_proof: %d FAILURE(S)\n",
               failures);

    free(c);
    test_rm_rf_recursive(dir);
    return failures;
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's fork+SIGKILL restart-proof child lane
 * cannot run here. Skipped loudly rather than faked. */
static int test_block_status_event_restart_proof_platform_arm(void)
{
    printf("block_status_event_restart_proof: SKIP (Windows): fork+SIGKILL restart-proof child lane\n");
    return 0;
}
#endif

int test_block_status_event_restart_proof(void)
{
    return test_block_status_event_restart_proof_platform_arm();
}
