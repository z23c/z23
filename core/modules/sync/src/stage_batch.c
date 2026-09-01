/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Outer transaction lifecycle for batched stage drains. */

#include "stage_batch_internal.h"

#include "core/utiltime.h"
#include "sync/stage.h"
#include "sync/stage_lcc.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static _Atomic bool g_open;
static _Atomic bool g_dirty;
static _Atomic uint64_t g_generation;
static _Atomic int64_t g_commit_last_us;
static _Atomic int64_t g_commit_us_ewma;
static stage_batch_precommit_fn g_precommit;

/* ── Transaction accounting ───────────────────────────────────────────────
 * The EWMA above says how long a COMMIT takes but not how many are paid, and
 * nothing at all said how many batches are opened only to be rolled back with
 * no work in them. STAGE_DRAIN_IMPL (engine/jobs/include/jobs/job.h) opens one
 * batch per stage per drain round — eight write-lock transactions per round,
 * whether or not any stage had work — so a drain that runs an advancing round
 * plus a converged round pays sixteen, of which the converged eight are empty.
 * That shape was folklore ("~16 per block, half empty"); these counters make
 * it a measured number:
 *   opened      — BEGIN IMMEDIATE succeeded
 *   committed   — COMMIT succeeded
 *   rolled_back — ROLLBACK issued (empty batch, LCC/precommit veto, or a
 *                 failed COMMIT); opened == committed + rolled_back once the
 *                 in-flight batch closes
 *   empty       — the caller asked to end WITHOUT committing, i.e. no step
 *                 advanced and no durable non-advancing work was enrolled
 *                 (stage_batch_mark_dirty); a subset of rolled_back and the
 *                 pure overhead term
 *   commit_us_total / commit_count — running totals beside the EWMA, so mean
 *                 microseconds per commit is exact rather than smoothed
 * Same threading contract as the EWMA: every mutation happens under the
 * recursive progress_store_tx_lock that serializes batches, so the adds are
 * single-writer; readers are other threads, hence atomics. */
static _Atomic uint64_t g_batches_opened;
static _Atomic uint64_t g_batches_committed;
static _Atomic uint64_t g_batches_rolled_back;
static _Atomic uint64_t g_batches_empty;
static _Atomic uint64_t g_commit_count;
static _Atomic uint64_t g_commit_us_total;

void stage_batch_stats_snapshot(struct stage_batch_stats *out)
{
    if (!out)
        return;
    out->opened          = atomic_load(&g_batches_opened);
    out->committed       = atomic_load(&g_batches_committed);
    out->rolled_back     = atomic_load(&g_batches_rolled_back);
    out->empty           = atomic_load(&g_batches_empty);
    out->commit_count    = atomic_load(&g_commit_count);
    out->commit_us_total = atomic_load(&g_commit_us_total);
    out->commit_last_us  = atomic_load(&g_commit_last_us);
    out->commit_us_ewma  = atomic_load(&g_commit_us_ewma);
}

/* The outer transaction makes intermediate cursor values unobservable, so one
 * exact initial..final LCC proof at COMMIT is equivalent to every prefix. */
static bool g_lcc_seen;
static char g_lcc_name[STAGE_NAME_MAX];
static uint64_t g_lcc_initial;
static uint64_t g_lcc_final;

void stage_batch_set_precommit_hook(stage_batch_precommit_fn fn)
{
    g_precommit = fn;
}

static void record_commit_timing(int64_t elapsed_us)
{
    if (elapsed_us <= 0) elapsed_us = 1;
    atomic_store(&g_commit_last_us, elapsed_us);
    int64_t prev = atomic_load(&g_commit_us_ewma);
    atomic_store(&g_commit_us_ewma,
                 prev ? prev + (elapsed_us - prev) / 16 : elapsed_us);
    atomic_fetch_add(&g_commit_count, 1u);
    atomic_fetch_add(&g_commit_us_total, (uint64_t)elapsed_us);
}

int64_t stage_batch_commit_us_ewma(void)
{
    return atomic_load(&g_commit_us_ewma);
}

bool stage_batch_active(void) { return atomic_load(&g_open); }
uint64_t stage_batch_generation(void) { return atomic_load(&g_generation); }
void stage_batch_mark_dirty(void) { atomic_store(&g_dirty, true); }
bool stage_batch_dirty(void) { return atomic_load(&g_dirty); }

bool stage_batch_defer_lcc(const char *name, uint64_t old_cursor,
                           uint64_t new_cursor)
{
    if (!atomic_load(&g_open) || !name || !name[0]) return false;
    if (!g_lcc_seen) {
        snprintf(g_lcc_name, sizeof(g_lcc_name), "%s", name);
        g_lcc_initial = old_cursor;
        g_lcc_seen = true;
    } else if (strcmp(g_lcc_name, name) != 0) {
        return false;
    }
    g_lcc_final = new_cursor;
    return true;
}

bool stage_batch_begin(sqlite3 *db)
{
    if (!db) return false;
    if (atomic_load(&g_open)) {
        fprintf(stderr, "[stage] batch_begin: a batch is already open\n");  // obs-ok:stage-begin-failure
        return false;
    }
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[stage] batch BEGIN: %s\n",  // obs-ok:stage-begin-failure
                err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    atomic_store(&g_open, true);
    atomic_fetch_add(&g_batches_opened, 1u);
    atomic_store(&g_dirty, false);
    g_lcc_seen = false;
    g_lcc_name[0] = '\0';
    g_lcc_initial = g_lcc_final = 0;
    atomic_fetch_add(&g_generation, 1u);
    return true;
}

static bool lcc_allows_commit(sqlite3 *db)
{
    if (!g_lcc_seen) return true;
    char err[192];
    if (stage_lcc_check_raise(db, g_lcc_name, g_lcc_initial, g_lcc_final,
                              err, sizeof(err)))
        return true;
    bool enforce = stage_lcc_enforcement_enabled(db);
    fprintf(stderr,  // obs-ok:stage-lcc-refuse
            "[stage] LCC %s batched raise %s %llu->%llu: %s\n",
            enforce ? "REFUSE" : "warn(allow)", g_lcc_name,
            (unsigned long long)g_lcc_initial,
            (unsigned long long)g_lcc_final, err);
    return !enforce;
}

bool stage_batch_end(sqlite3 *db, bool commit)
{
    if (!db) return false;
    if (!atomic_load(&g_open)) return true;
    /* An end WITHOUT commit is the empty case the accounting exists to size:
     * the drain opened a write transaction, no step advanced, nothing enrolled
     * durable work, and the whole transaction is pure overhead. */
    if (!commit)
        atomic_fetch_add(&g_batches_empty, 1u);
    if (commit && (!lcc_allows_commit(db) || (g_precommit && !g_precommit()))) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        atomic_store(&g_open, false);
        atomic_fetch_add(&g_batches_rolled_back, 1u);
        return false;
    }
    char *err = NULL;
    const char *finish = commit ? "COMMIT" : "ROLLBACK";
    int64_t started = commit ? GetTimeMicros() : 0;
    int rc = sqlite3_exec(db, finish, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[stage] batch %s: %s\n",  // obs-ok:stage-commit-failure
                finish, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        atomic_store(&g_open, false);
        atomic_fetch_add(&g_batches_rolled_back, 1u);
        return false;
    }
    if (err) sqlite3_free(err);
    if (commit) {
        record_commit_timing(GetTimeMicros() - started);
        atomic_fetch_add(&g_batches_committed, 1u);
    } else {
        atomic_fetch_add(&g_batches_rolled_back, 1u);
    }
    atomic_store(&g_open, false);
    return true;
}
