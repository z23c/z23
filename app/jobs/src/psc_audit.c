/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * psc_audit — opt-in Parallel State Compiler audit + `dumpstate psc`.
 * See jobs/psc_audit.h.
 */
#include "jobs/psc_audit.h"

#include "base/hex.h"
#include "jobs/psc_block_source.h"
#include "jobs/psc_range_fold.h"

#include "json/json.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* Last audit result — a process-global snapshot for dumpstate psc. Written by
 * psc_audit_run, read by psc_dump_state_json; a brief mutex gives a consistent
 * snapshot (the struct is copied out under the lock). */
static pthread_mutex_t g_psc_audit_mu = PTHREAD_MUTEX_INITIALIZER;
static bool                    g_psc_audit_has_run = false;
static struct psc_audit_result g_psc_audit_last;

static void psc_audit_store(const struct psc_audit_result *r)
{
    pthread_mutex_lock(&g_psc_audit_mu);
    g_psc_audit_last = *r;
    g_psc_audit_has_run = true;
    pthread_mutex_unlock(&g_psc_audit_mu);
}

bool psc_audit_run(struct main_state *ms, const char *datadir,
                   uint32_t lo, uint32_t hi, int k_workers, int s_shards,
                   struct psc_audit_result *out)
{
    struct psc_audit_result r;
    memset(&r, 0, sizeof(r));
    r.lo = lo;
    r.hi = hi;
    r.durable_count = -1;
    r.reject_height = -1;

    if (!ms) {
        snprintf(r.reject_kind, sizeof(r.reject_kind), "no_ms");
        LOG_WARN("psc", "[psc] audit: NULL main_state");
        psc_audit_store(&r);
        if (out) *out = r;
        return false;
    }

    if (k_workers <= 0) k_workers = psc_audit_default_workers();
    if (s_shards <= 0)  s_shards  = k_workers * 2;

    /* Parallel compile over the production block source. */
    struct psc_prod_source src = { .ms = ms, .datadir = datadir };
    struct psc_range_result rr;
    bool compiled = psc_compile_range(lo, hi, k_workers, s_shards,
                                      psc_prod_block_provider, &src, &rr);
    r.k_workers   = rr.k_workers;
    r.s_shards    = rr.s_shards;
    r.compile_us  = rr.total_us;
    uint64_t nblk = (hi >= lo) ? (uint64_t)(hi - lo + 1) : 0;
    r.us_per_block = nblk ? rr.total_us / (double)nblk : 0.0;

    if (!compiled || !rr.ok) {
        snprintf(r.reject_kind, sizeof(r.reject_kind), "%s",
                 rr.reject_kind[0] ? rr.reject_kind : "compile_failed");
        r.reject_height = rr.reject_height;
        LOG_WARN("psc", "[psc] audit [%u,%u]: parallel compile did not accept "
                 "(%s, height=%d)", lo, hi, r.reject_kind, r.reject_height);
        psc_audit_store(&r);
        if (out) *out = r;
        return false;
    }

    r.ran = true;
    memcpy(r.parallel_sha3, rr.terminal_sha3, 32);
    r.parallel_count  = rr.terminal_count;
    r.parallel_supply = rr.terminal_supply;

    /* Durable coins_kv commitment (the SAME encoder the parallel digest uses). */
    sqlite3 *db = progress_store_db();
    if (!db) {
        snprintf(r.reject_kind, sizeof(r.reject_kind), "no_db");
        LOG_WARN("psc", "[psc] audit [%u,%u]: no progress store db", lo, hi);
        psc_audit_store(&r);
        if (out) *out = r;
        return false;
    }
    if (coins_kv_commitment(db, r.durable_sha3) != 0) {
        snprintf(r.reject_kind, sizeof(r.reject_kind), "durable_commitment_failed");
        LOG_WARN("psc", "[psc] audit [%u,%u]: coins_kv_commitment failed", lo, hi);
        psc_audit_store(&r);
        if (out) *out = r;
        return false;
    }
    r.durable_count = coins_kv_count(db);

    r.match = memcmp(r.parallel_sha3, r.durable_sha3, 32) == 0 &&
              (int64_t)r.parallel_count == r.durable_count;

    if (!r.match)
        LOG_WARN("psc", "[psc] audit [%u,%u]: MISMATCH parallel_count=%llu "
                 "durable_count=%lld", lo, hi,
                 (unsigned long long)r.parallel_count, (long long)r.durable_count);

    psc_audit_store(&r);
    if (out) *out = r;
    return r.match;
}

bool psc_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        LOG_FAIL("psc", "dump_state_json: NULL out");
    json_set_object(out);

    pthread_mutex_lock(&g_psc_audit_mu);
    bool has_run = g_psc_audit_has_run;
    struct psc_audit_result r = g_psc_audit_last;
    pthread_mutex_unlock(&g_psc_audit_mu);

    json_push_kv_bool(out, "has_run", has_run);
    if (!has_run)
        return true;

    char phex[65], dhex[65];
    zcl_hex_encode(r.parallel_sha3, 32, phex);
    zcl_hex_encode(r.durable_sha3, 32, dhex);

    json_push_kv_bool(out, "ran", r.ran);
    json_push_kv_bool(out, "match", r.match);
    json_push_kv_int(out, "lo", (int64_t)r.lo);
    json_push_kv_int(out, "hi", (int64_t)r.hi);
    json_push_kv_str(out, "parallel_sha3", phex);
    json_push_kv_str(out, "durable_sha3", dhex);
    json_push_kv_int(out, "parallel_count", (int64_t)r.parallel_count);
    json_push_kv_int(out, "durable_count", r.durable_count);
    json_push_kv_int(out, "parallel_supply", r.parallel_supply);
    json_push_kv_int(out, "k_workers", (int64_t)r.k_workers);
    json_push_kv_int(out, "s_shards", (int64_t)r.s_shards);
    json_push_kv_real(out, "compile_us", r.compile_us);
    json_push_kv_real(out, "us_per_block", r.us_per_block);
    json_push_kv_str(out, "reject_kind", r.reject_kind[0] ? r.reject_kind : "");
    return true;
}
