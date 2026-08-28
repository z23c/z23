// one-result-type-ok:fail-loud-predicates
/* E2 override: the gate's surface is one pass/refuse predicate. The
 * refusal reason travels via the seed.linkage_gate blocker +
 * EV_OPERATOR_NEEDED + LOG_WARN (fail-loud pack convention); callers
 * only need the boolean (publish vs refuse the seed). */

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * seed_integrity_gate — see services/seed_integrity_gate.h. */

#include "services/seed_integrity_gate.h"

#include "config/runtime.h"
#include "event/event.h"
#include "models/database.h"
#include "services/invariant_sentinel.h"
#include "coins/utxo_commitment.h"
#include "util/ar_step_readonly.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define SEED_GATE_MAX_WALK 10000

#ifdef ZCL_TESTING
static struct node_db *g_test_ndb;
#endif

/* Memo: the at-tip ingest re-seed calls the gate every tick; only the
 * first evaluation of a (height, hash) pair pays the walk. */
static pthread_mutex_t g_memo_lock = PTHREAD_MUTEX_INITIALIZER;
static int     g_memo_height = -1;
static uint8_t g_memo_hash[32];
static bool    g_memo_pass = false;
static bool    g_memo_valid = false;

static struct node_db *gate_ndb(void)
{
#ifdef ZCL_TESTING
    if (g_test_ndb)
        return g_test_ndb;
#endif
    return app_runtime_node_db();
}

static void gate_refuse(int height, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void gate_refuse(int height, const char *fmt, ...)
{
    char reason[BLOCKER_REASON_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);

    LOG_WARN("validation_pack",
             "[validation_pack] SEED REFUSED at h=%d: %s", height, reason);
    struct blocker_record rec;
    if (blocker_init(&rec, "seed.linkage_gate", "validation_pack",
                     BLOCKER_PERMANENT, reason) &&
        blocker_set(&rec) == 0)
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "check=seed.linkage_gate seed_h=%d %s", height, reason);
}

/* Fetch (height, prev_hash) for `hash`. 1=found, 0=absent, -1=error. */
static int gate_row_by_hash(sqlite3 *db, const uint8_t hash[32],
                            int64_t *out_h, uint8_t out_prev[32])
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT height, prev_hash FROM blocks WHERE hash = ?",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("validation_pack",
                 "[validation_pack] seed gate prepare failed: %s",
                 sqlite3_errmsg(db));
        return -1; // raw-return-ok:warned-on-previous-line
    }
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    int rc = AR_STEP_ROW_READONLY(st);
    int found = 0;
    if (rc == SQLITE_ROW) {
        *out_h = sqlite3_column_int64(st, 0);
        const void *prev = sqlite3_column_blob(st, 1);
        int n = sqlite3_column_bytes(st, 1);
        memset(out_prev, 0, 32);
        if (prev && n == 32)
            memcpy(out_prev, prev, 32);
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

static void hash8_hex(const uint8_t h[32], char out[17])
{
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i * 2]     = hexd[h[i] >> 4];
        out[i * 2 + 1] = hexd[h[i] & 0xf];
    }
    out[16] = '\0';
}

/* Check 7 core: follow prev_hash from the seed tip through PRESENT rows;
 * every resolved parent must be labeled child-1. Returns true = clean (or
 * suffix ended / walk budget exhausted); false = refused (named). */
static bool gate_linkage_walk(sqlite3 *db, int height,
                              const uint8_t tip_hash[32])
{
    int64_t row_h = -1;
    uint8_t prev[32];
    int found = gate_row_by_hash(db, tip_hash, &row_h, prev);
    if (found < 0)
        return true; /* read error: fail open, the sweep backstops */
    if (found == 0) {
        /* Absent tip row: projection backfill ordering — WARN, not a
         * refusal (the sweep + per-connect checks backstop). */
        LOG_WARN("validation_pack",
                 "[validation_pack] seed gate: no blocks row for seed tip "
                 "h=%d (projection lag?) — linkage walk skipped", height);
        return true;
    }

    /* step 0 — authority pair at the seed tip itself. */
    if (row_h != (int64_t)height) {
        char hh[17];
        hash8_hex(tip_hash, hh);
        gate_refuse(height,
                    "seed pair mismatch: blocks row for hash=%s has "
                    "height=%lld, seed says %d",
                    hh, (long long)row_h, height);
        return false;
    }

    int64_t child_h = row_h;
    uint8_t child_prev[32];
    memcpy(child_prev, prev, 32);

    for (int steps = 0; steps < SEED_GATE_MAX_WALK; steps++) {
        if (child_h <= 0)
            return true; /* reached genesis */
        bool all_zero = true;
        for (int i = 0; i < 32; i++)
            if (child_prev[i]) { all_zero = false; break; }
        if (all_zero)
            return true; /* genesis-style prev: suffix ends cleanly */

        int64_t parent_h = -1;
        uint8_t parent_prev[32];
        int pf = gate_row_by_hash(db, child_prev, &parent_h, parent_prev);
        if (pf < 0)
            return true; /* read error: fail open */
        if (pf == 0)
            return true; /* suffix ended (snapshot seeds lack deep rows) */

        if (parent_h != child_h - 1) {
            char ch[17];
            hash8_hex(child_prev, ch);
            gate_refuse(height,
                        "linkage break at h=%lld: parent %s is labeled "
                        "h=%lld (expected %lld) — label splice at birth",
                        (long long)child_h, ch, (long long)parent_h,
                        (long long)(child_h - 1));
            return false;
        }
        child_h = parent_h;
        memcpy(child_prev, parent_prev, 32);
    }
    return true; /* walk budget exhausted over a clean span */
}

/* Check 5, post-import half: when a stored 'utxo_sha3' commitment exists
 * AT the seed height, the utxos table must recompute to it exactly. */
static bool gate_commitment_check(sqlite3 *db, int height)
{
    uint8_t want[32];
    int32_t commit_h = -1;
    uint64_t want_count = 0;
    if (!utxo_commitment_sha3_load(db, want, &commit_h, &want_count))
        return true; /* no stored stamp: nothing to gate against */
    if (commit_h != height) {
        LOG_INFO("validation_pack",
                 "[validation_pack] seed gate: utxo_sha3 stamp at h=%d != "
                 "seed h=%d — commitment gate skipped", commit_h, height);
        return true;
    }

    uint8_t got[32];
    uint64_t got_count = 0;
    utxo_commitment_sha3_compute(db, got, &got_count);
    if (got_count == want_count && memcmp(got, want, 32) == 0) {
        LOG_INFO("validation_pack",
                 "[validation_pack] seed gate: utxo_sha3 verified at h=%d "
                 "(count=%llu)", height, (unsigned long long)want_count);
        return true;
    }

    gate_refuse(height,
                "utxo commitment mismatch at seed h=%d: count_expected=%llu "
                "count_got=%llu (silent truncation/corruption at birth)",
                height, (unsigned long long)want_count,
                (unsigned long long)got_count);
    return false;
}

bool seed_integrity_stamp_utxo_sha3(struct node_db *ndb, int height,
                                    const uint8_t root[32], uint64_t count)
{
    if (!ndb || !ndb->open || !ndb->db || height < 0 || !root) {
        LOG_WARN("validation_pack",
                 "[validation_pack] utxo_sha3 stamp skipped: bad args "
                 "(ndb=%p h=%d root=%p)", (void *)ndb, height,
                 (const void *)root);
        return false;
    }
    if (!utxo_commitment_sha3_save(ndb->db, root, height, count)) {
        LOG_WARN("validation_pack",
                 "[validation_pack] utxo_sha3 stamp save FAILED at h=%d — "
                 "seed-gate commitment check stays unarmed", height);
        return false;
    }
    LOG_INFO("validation_pack",
             "[validation_pack] utxo_sha3 stamp saved at h=%d (count=%llu)"
             " — seed-gate commitment check armed",
             height, (unsigned long long)count);
    return true;
}

bool seed_integrity_gate_check(int height, const uint8_t hash[32],
                               bool trusted_seed)
{
    if (height < 0 || !hash)
        return true; /* caller validates args; not a gate concern */

    struct node_db *ndb = gate_ndb();
    if (!ndb || !ndb->open || !ndb->db) {
        LOG_WARN("validation_pack",
                 "[validation_pack] seed gate: node_db not wired at seed "
                 "h=%d — gate skipped (early boot/unit test)", height);
        return true;
    }

    pthread_mutex_lock(&g_memo_lock);
    if (g_memo_valid && g_memo_height == height &&
        memcmp(g_memo_hash, hash, 32) == 0) {
        bool pass = g_memo_pass;
        pthread_mutex_unlock(&g_memo_lock);
        return pass;
    }
    pthread_mutex_unlock(&g_memo_lock);

    bool pass = gate_linkage_walk(ndb->db, height, hash);
    /* Commitment gate only for trusted (cold-import / snapshot) seeds:
     * the at-tip ingest re-seed must stay O(1)-ish. */
    if (pass && trusted_seed)
        pass = gate_commitment_check(ndb->db, height);

    invariant_sentinel_note_seed_gate(!pass);

    pthread_mutex_lock(&g_memo_lock);
    g_memo_height = height;
    memcpy(g_memo_hash, hash, 32);
    g_memo_pass = pass;
    g_memo_valid = true;
    pthread_mutex_unlock(&g_memo_lock);
    return pass;
}

#ifdef ZCL_TESTING
void seed_integrity_gate_reset_for_testing(void)
{
    g_test_ndb = NULL;
    pthread_mutex_lock(&g_memo_lock);
    g_memo_valid = false;
    g_memo_height = -1;
    pthread_mutex_unlock(&g_memo_lock);
}

void seed_integrity_gate_set_node_db_for_testing(struct node_db *ndb)
{
    g_test_ndb = ndb;
}
#endif
