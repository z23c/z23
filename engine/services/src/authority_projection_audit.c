// one-result-type-ok:fail-loud-audit
/* E2 override: this module's public surface is a fail-loud pass/refuse audit
 * (pure predicate + best-effort background pass + JSON dump). A divergence is
 * not an error to propagate — the reason travels via the typed PERMANENT
 * blocker + EV_OPERATOR_NEEDED + LOG_WARN, the same fail-loud channel the sibling
 * invariant_sentinel uses. A zcl_result would duplicate that channel with a
 * code/message callers must not branch on. */

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * authority_projection_audit — see services/authority_projection_audit.h.
 *
 * Crash-only: a firing check raises a blocker + pages; the process and every
 * other stage keep running. Redundant/observational ONLY — it never changes a
 * validity predicate or the primary derivation. */

#include "services/authority_projection_audit.h"

#include "services/utxo_mirror_sync_service.h" /* UTXO_MIRROR_SYNC_CURSOR_KEY */
#include "config/runtime.h"
#include "coins/utxo_commitment.h"
#include "encoding/utilstrencodings.h"
#include "event/event.h"
#include "json/json.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "supervisors/domains.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/supervisor.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* Hourly: the recompute is O(utxo-set) (two ~1.3M-row scans, a few seconds),
 * so it is cadenced off the hot path — NEVER per-block. Same cadence + O(n)
 * shape as the sibling invariant_sentinel commitment audit. */
#define AP_AUDIT_PERIOD_SECS         ((int64_t)3600)
/* Confirm a divergence across this many consecutive samples before raising —
 * swallows any residual torn-scan window the marker guard misses. */
#define AP_DIVERGENCE_STREAK_RAISE   2

/* ── counters (atomic; dumped via JSON) ─────────────────────────────── */
static _Atomic uint64_t g_ap_runs_total          = 0; /* passes attempted */
static _Atomic uint64_t g_ap_checks_total        = 0; /* full comparisons done */
static _Atomic uint64_t g_ap_passes_total        = 0; /* clean comparisons */
static _Atomic uint64_t g_ap_divergences_total   = 0; /* blocker raises */
static _Atomic uint64_t g_ap_skipped_unsynced    = 0; /* markers absent/unequal */
static _Atomic uint64_t g_ap_skipped_tip_moved   = 0; /* markers moved mid-scan */
static _Atomic uint64_t g_ap_skipped_read_error  = 0; /* commitment/count read err */
static _Atomic int      g_ap_divergence_streak   = 0;
static _Atomic bool     g_ap_blocker_active      = false;
static _Atomic int64_t  g_ap_last_unix           = 0;
static _Atomic int32_t  g_ap_last_height         = -1;
static _Atomic uint64_t g_ap_last_auth_count     = 0;
static _Atomic uint64_t g_ap_last_proj_count     = 0;

static pthread_mutex_t g_ap_detail_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_ap_last_auth_hex[65];
static char g_ap_last_proj_hex[65];

#ifdef ZCL_TESTING
struct node_db *g_ap_test_ndb;
#endif

static struct node_db *ap_audit_ndb(void)
{
#ifdef ZCL_TESTING
    if (g_ap_test_ndb)
        return g_ap_test_ndb;
#endif
    return app_runtime_node_db();
}

/* ── Pure evaluator ─────────────────────────────────────────────────── */

void ap_audit_evaluate(const struct ap_audit_inputs *in,
                       struct ap_audit_verdict *out)
{
    memset(out, 0, sizeof(*out));
    if (!in || !in->comparable)
        return; /* only compared at a proven-equal applied height */

    bool root_diff  = memcmp(in->auth_root, in->proj_root, 32) != 0;
    bool count_diff = in->auth_count != in->proj_count;
    if (!root_diff && !count_diff)
        return; /* byte-identical — the expected steady state */

    out->violated       = true;
    out->root_mismatch  = root_diff;
    out->count_mismatch = count_diff;
    snprintf(out->detail, sizeof(out->detail),
             "authority(coins) vs projection(utxos) diverge at applied h=%d: "
             "%s%s%scount auth=%llu proj=%llu",
             in->height,
             root_diff ? "SHA3 root mismatch " : "",
             (root_diff && count_diff) ? "+ " : "",
             count_diff ? "count mismatch " : "",
             (unsigned long long)in->auth_count,
             (unsigned long long)in->proj_count);
}

/* ── Verdict bookkeeping + blocker ──────────────────────────────────── */

bool ap_audit_apply_verdict(const struct ap_audit_verdict *v,
                            int32_t height,
                            uint64_t auth_count, uint64_t proj_count,
                            const uint8_t auth_root[32],
                            const uint8_t proj_root[32])
{
    if (!v || !v->violated) {
        atomic_store(&g_ap_divergence_streak, 0);
        atomic_fetch_add(&g_ap_passes_total, 1);
        if (atomic_exchange(&g_ap_blocker_active, false)) {
            /* Self-clearing: a clean pass releases the latch — a repair job may
             * legitimately rebuild the projection from the authority. Crash-only
             * and recovery-friendly, same as invariant_sentinel's sweeps. */
            blocker_clear("authority_projection_divergence");
            LOG_INFO("validation_pack",
                     "[ap-audit] authority_projection_divergence cleared by a "
                     "clean pass");
        }
        return false;
    }

    char auth_hex[65] = {0};
    char proj_hex[65] = {0};
    HexStr(auth_root, 32, false, auth_hex, sizeof(auth_hex));
    HexStr(proj_root, 32, false, proj_hex, sizeof(proj_hex));

    pthread_mutex_lock(&g_ap_detail_lock);
    snprintf(g_ap_last_auth_hex, sizeof(g_ap_last_auth_hex), "%s", auth_hex);
    snprintf(g_ap_last_proj_hex, sizeof(g_ap_last_proj_hex), "%s", proj_hex);
    pthread_mutex_unlock(&g_ap_detail_lock);
    atomic_store(&g_ap_last_height, height);
    atomic_store(&g_ap_last_auth_count, auth_count);
    atomic_store(&g_ap_last_proj_count, proj_count);

    int streak = atomic_fetch_add(&g_ap_divergence_streak, 1) + 1;
    if (streak < AP_DIVERGENCE_STREAK_RAISE) {
        LOG_WARN("validation_pack",
                 "[ap-audit] %s auth_root=%s proj_root=%s — awaiting "
                 "confirmation on the next sample (streak=%d)",
                 v->detail, auth_hex, proj_hex, streak);
        return false;
    }

    atomic_fetch_add(&g_ap_divergences_total, 1);
    atomic_store(&g_ap_blocker_active, true);

    /* Compact reason so BOTH full 64-char roots always fit under
     * BLOCKER_REASON_MAX (256). The verbose detail goes to the log line. */
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "authority/projection diverge h=%d auth_count=%llu proj_count=%llu "
             "auth_root=%s proj_root=%s",
             height, (unsigned long long)auth_count,
             (unsigned long long)proj_count, auth_hex, proj_hex);

    struct blocker_record rec;
    if (blocker_init(&rec, "authority_projection_divergence", "validation_pack",
                     BLOCKER_PERMANENT, reason)) {
        if (blocker_set(&rec) == 0)
            event_emitf(EV_OPERATOR_NEEDED, 0,
                        "check=authority_projection_divergence %s", reason);
    }
    LOG_WARN("validation_pack",
             "[ap-audit] PERMANENT authority_projection_divergence: %s "
             "(%s)", reason, v->detail);
    return true;
}

/* ── Background pass ─────────────────────────────────────────────────── */

/* Read the two applied-height markers: coins_kv authority frontier
 * (progress.kv, under the brief observational trylock) and the utxos mirror
 * cursor (node.db). *ok is true only when BOTH are present and non-negative. */
static void ap_read_markers(struct node_db *ndb, sqlite3 *pdb,
                            int32_t *auth_h, int64_t *proj_h, bool *ok)
{
    *auth_h = -1;
    *proj_h = -1;
    *ok = false;

    bool afound = false;
    progress_store_tx_lock();
    (void)coins_kv_get_applied_height(pdb, auth_h, &afound);
    progress_store_tx_unlock();

    int64_t pv = -1;
    bool pfound = node_db_state_get_int(ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, &pv);
    *proj_h = pv;

    *ok = afound && pfound && *auth_h >= 0 && *proj_h >= 0;
}

bool ap_audit_run_once(void)
{
    struct node_db *ndb = ap_audit_ndb();
    sqlite3 *pdb = progress_store_db();
    if (!ndb || !ndb->open || !ndb->db || !pdb)
        return false; /* not wired (early boot / unit tests) — benign */

    atomic_fetch_add(&g_ap_runs_total, 1);
    atomic_store(&g_ap_last_unix, platform_time_wall_unix());

    /* Bulk-import freeze: while g_utxo_commitment_skip is set the incremental
     * tracking is frozen and a full recompute would compare two moving sets —
     * skip the pass entirely. */
    if (atomic_load_explicit(&g_utxo_commitment_skip, memory_order_relaxed))
        return true;

    int32_t auth_h0 = -1;
    int64_t proj_h0 = -1;
    bool ok0 = false;
    ap_read_markers(ndb, pdb, &auth_h0, &proj_h0, &ok0);
    if (!ok0 || (int64_t)auth_h0 != proj_h0) {
        /* Projection legitimately lags/leads the authority during catch-up —
         * NOT a divergence. Only an equal-height pair is byte-comparable. */
        atomic_fetch_add(&g_ap_skipped_unsynced, 1);
        return true;
    }

    /* Recompute BOTH roots independently, OFF the drive lock. coins_kv_commitment
     * honours the RAM read-flip (coins_ram) internally; the projection scan hits
     * node.db `utxos`. Both use the SAME must-never-fork record encoder. */
    uint8_t auth_root[32];
    if (coins_kv_commitment(pdb, auth_root) != 0) {
        atomic_fetch_add(&g_ap_skipped_read_error, 1);
        return true;
    }
    int64_t auth_count = coins_kv_count(pdb);
    if (auth_count < 0) {
        atomic_fetch_add(&g_ap_skipped_read_error, 1);
        return true;
    }
    uint8_t proj_root[32];
    uint64_t proj_count = 0;
    utxo_commitment_sha3_compute(ndb->db, proj_root, &proj_count);

    /* Torn-scan guard: re-read the markers. If either moved, the two scans did
     * not observe one atomic height — discard (no verdict), same discipline as
     * the commitment audit's tip-before/after check. */
    int32_t auth_h1 = -1;
    int64_t proj_h1 = -1;
    bool ok1 = false;
    ap_read_markers(ndb, pdb, &auth_h1, &proj_h1, &ok1);
    if (!ok1 || auth_h1 != auth_h0 || proj_h1 != proj_h0) {
        atomic_fetch_add(&g_ap_skipped_tip_moved, 1);
        return true;
    }

    atomic_fetch_add(&g_ap_checks_total, 1);

    struct ap_audit_inputs in;
    memset(&in, 0, sizeof(in));
    in.comparable = true;
    in.height     = auth_h0;
    memcpy(in.auth_root, auth_root, 32);
    in.auth_count = (uint64_t)auth_count;
    memcpy(in.proj_root, proj_root, 32);
    in.proj_count = proj_count;

    struct ap_audit_verdict v;
    ap_audit_evaluate(&in, &v);
    (void)ap_audit_apply_verdict(&v, in.height, in.auth_count, in.proj_count,
                                 in.auth_root, in.proj_root);
    return true;
}

/* ── supervisor child (hourly, chain domain) ────────────────────────── */

static struct liveness_contract g_ap_contract;
static _Atomic supervisor_child_id g_ap_id = SUPERVISOR_INVALID_ID;
static _Atomic int64_t g_ap_ticks = 0;

static void ap_tick(struct liveness_contract *c)
{
    (void)c;
    (void)ap_audit_run_once();
    int64_t marker = atomic_fetch_add(&g_ap_ticks, 1) + 1;
    supervisor_progress(atomic_load(&g_ap_id), marker);
    supervisor_tick(atomic_load(&g_ap_id));
}

void ap_audit_register(void)
{
    supervisor_domains_init();
    if (atomic_load(&g_ap_id) != SUPERVISOR_INVALID_ID)
        return;
    liveness_contract_init(&g_ap_contract, "chain.authority_projection_audit");
    atomic_store(&g_ap_contract.period_secs, AP_AUDIT_PERIOD_SECS);
    atomic_store(&g_ap_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_ap_contract.progress_max_quiet_us, (int64_t)0);
    g_ap_contract.on_tick = ap_tick;
    g_ap_contract.on_stall = NULL;
    supervisor_child_id id =
        supervisor_register_in_domain(g_chain_sup, &g_ap_contract);
    atomic_store(&g_ap_id, id);
    if (id == SUPERVISOR_INVALID_ID)
        LOG_WARN("validation_pack",
                 "[ap-audit] supervisor register failed");
}

void ap_audit_reset_for_test(void)
{
    atomic_store(&g_ap_runs_total, 0);
    atomic_store(&g_ap_checks_total, 0);
    atomic_store(&g_ap_passes_total, 0);
    atomic_store(&g_ap_divergences_total, 0);
    atomic_store(&g_ap_skipped_unsynced, 0);
    atomic_store(&g_ap_skipped_tip_moved, 0);
    atomic_store(&g_ap_skipped_read_error, 0);
    atomic_store(&g_ap_divergence_streak, 0);
    atomic_store(&g_ap_last_height, -1);
    atomic_store(&g_ap_last_auth_count, 0);
    atomic_store(&g_ap_last_proj_count, 0);
    if (atomic_exchange(&g_ap_blocker_active, false))
        blocker_clear("authority_projection_divergence");
    pthread_mutex_lock(&g_ap_detail_lock);
    g_ap_last_auth_hex[0] = '\0';
    g_ap_last_proj_hex[0] = '\0';
    pthread_mutex_unlock(&g_ap_detail_lock);
}

/* ── Native dump-state view ─────────────────────────────────────────── */

bool ap_audit_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);
    json_push_kv_int(out, "runs_total",
                     (int64_t)atomic_load(&g_ap_runs_total));
    json_push_kv_int(out, "checks_total",
                     (int64_t)atomic_load(&g_ap_checks_total));
    json_push_kv_int(out, "passes_total",
                     (int64_t)atomic_load(&g_ap_passes_total));
    json_push_kv_int(out, "divergences_total",
                     (int64_t)atomic_load(&g_ap_divergences_total));
    json_push_kv_int(out, "skipped_unsynced",
                     (int64_t)atomic_load(&g_ap_skipped_unsynced));
    json_push_kv_int(out, "skipped_tip_moved",
                     (int64_t)atomic_load(&g_ap_skipped_tip_moved));
    json_push_kv_int(out, "skipped_read_error",
                     (int64_t)atomic_load(&g_ap_skipped_read_error));
    json_push_kv_int(out, "divergence_streak",
                     (int64_t)atomic_load(&g_ap_divergence_streak));
    json_push_kv_bool(out, "blocker_active",
                      atomic_load(&g_ap_blocker_active));
    json_push_kv_int(out, "last_unix", atomic_load(&g_ap_last_unix));
    json_push_kv_int(out, "last_height",
                     (int64_t)atomic_load(&g_ap_last_height));
    json_push_kv_int(out, "last_auth_count",
                     (int64_t)atomic_load(&g_ap_last_auth_count));
    json_push_kv_int(out, "last_proj_count",
                     (int64_t)atomic_load(&g_ap_last_proj_count));
    pthread_mutex_lock(&g_ap_detail_lock);
    json_push_kv_str(out, "last_auth_root", g_ap_last_auth_hex);
    json_push_kv_str(out, "last_proj_root", g_ap_last_proj_hex);
    pthread_mutex_unlock(&g_ap_detail_lock);
    return true;
}
