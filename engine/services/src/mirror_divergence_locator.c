// one-result-type-ok:fail-loud-locator
/* E2 override: the locator returns the located height or -1 (skipped/
 * aborted). Every actionable outcome travels via the
 * mirror.divergence_located blocker + EV_OPERATOR_NEEDED payload
 * (first_div_h, ours, theirs) per the fail-loud pack convention;
 * aborts are by-design silent (rate limit / RPC errors already covered
 * by mirror.rpc-unreachable). */

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mirror_divergence_locator — see services/mirror_divergence_locator.h. */

#include "services/mirror_divergence_locator.h"

#include "base/hex.h"
#include "config/runtime.h"
#include "event/event.h"
#include "json/json.h"
#include "legacy_mirror_sync_internal.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "services/invariant_sentinel.h"
#include "services/oracle_policy.h"
#include "util/ar_step_readonly.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "validation/chain_linkage_check.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#define MDL_RELOCATE_MIN_SECS 600
#define MDL_MAX_PROBES        64 /* ~2*22 with verify overhead; hard stop */

static _Atomic int64_t g_last_locate_unix = 0;
static _Atomic int     g_last_first_div = -1;
static _Atomic int     g_probes_last_run = 0;
static _Atomic bool    g_divergence_latched = false;

/* Pending (located-but-unconfirmed) tip-window divergence: a first_div
 * inside the MDL_CONFIRM_DEPTH window of the disagreeing tip. Single
 * mirror-tick thread writes it; note_agreement (same thread in
 * production) clears it. Lock kept for the dump/agreement composition. */
static pthread_mutex_t g_pending_lock = PTHREAD_MUTEX_INITIALIZER;
static int     g_pending_first_div = -1;
static int64_t g_pending_first_seen_unix = 0;

/* ── production probes ──────────────────────────────────────────── */

/* Local: the in-RAM active chain first (fast, covers the recent window),
 * then the blocks projection for deeper heights — the projection IS what
 * we serve, which is exactly the thing to locate divergence in. The
 * status>=3 partial unique index makes height->hash unambiguous for
 * main-chain rows. */
static bool mdl_local_hash(int height, char out_hex[65])
{
    if (lms_local_hash_at(height, out_hex).ok)
        return true;

    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !ndb->open || !ndb->db)
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT hash FROM blocks WHERE height = ? AND status >= 3",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("validation_pack",
                 "[mirror_divergence] local probe prepare failed: %s",
                 sqlite3_errmsg(ndb->db));
        return false;
    }
    sqlite3_bind_int(st, 1, height);
    bool ok = false;
    if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (blob && n == 32) {
            /* Block hashes display reversed (big-endian), matching
             * getblockhash and uint256_get_hex. */
            const uint8_t *b = blob;
            uint8_t rev[32];
            for (int i = 0; i < 32; i++)
                rev[i] = b[31 - i];
            zcl_hex_encode(rev, 32, out_hex);
            ok = true;
        }
    }
    sqlite3_finalize(st);
    return ok;
}

static bool mdl_remote_hash(int height, char out_hex[65])
{
    return lms_remote_hash_at(height, out_hex).ok;
}

#ifdef ZCL_TESTING
static mdl_probe_fn g_test_local;
static mdl_probe_fn g_test_remote;
#endif

static bool probe_local(int height, char out_hex[65])
{
#ifdef ZCL_TESTING
    if (g_test_local)
        return g_test_local(height, out_hex);
#endif
    return mdl_local_hash(height, out_hex);
}

static bool probe_remote(int height, char out_hex[65])
{
#ifdef ZCL_TESTING
    if (g_test_remote)
        return g_test_remote(height, out_hex);
#endif
    return mdl_remote_hash(height, out_hex);
}

/* One comparison probe. Returns 1 = agree, 0 = disagree, -1 = abort
 * (either probe failed; the caller stops the bisect silently). */
static int probe_compare(int height, int *probes,
                         char local_out[65], char remote_out[65])
{
    if (*probes >= MDL_MAX_PROBES)
        return -1; // raw-return-ok:probe-budget-abort-is-the-contract
    char local[65], remote[65];
    if (!probe_local(height, local))
        return -1; // raw-return-ok:probe-failure-abort-is-the-contract
    if (!probe_remote(height, remote))
        return -1; // raw-return-ok:rpc-unreachable-blocker-covers-this
    *probes += 2;
    if (local_out)
        memcpy(local_out, local, sizeof(local));
    if (remote_out)
        memcpy(remote_out, remote, sizeof(remote));
    return strcasecmp(local, remote) == 0 ? 1 : 0;
}

int mirror_divergence_locate(int disagree_height)
{
    if (disagree_height < 0)
        return -1; // raw-return-ok:nothing-to-locate

    int64_t now = platform_time_wall_unix();
    int64_t last = atomic_load(&g_last_locate_unix);
    if (last != 0 && now - last < MDL_RELOCATE_MIN_SECS)
        return -1; // raw-return-ok:rate-limited-relocate-by-design
    atomic_store(&g_last_locate_unix, now);

    int probes = 0;
    char ours[65] = {0}, theirs[65] = {0};

    /* Re-verify the disagreement first: a transient remote-ahead race
     * must not start a 22-probe walk (one extra probe). */
    int hi_cmp = probe_compare(disagree_height, &probes, ours, theirs);
    if (hi_cmp != 0) {
        atomic_store(&g_probes_last_run, probes);
        return -1; // raw-return-ok:transient-flap-or-probe-failure-abort
    }

    /* Genesis must agree (same network). If even h=0 disagrees, that IS
     * the first diverging height. */
    int lo = 0, hi = disagree_height;
    if (hi > 0) {
        int lo_cmp = probe_compare(0, &probes, NULL, NULL);
        if (lo_cmp < 0) {
            atomic_store(&g_probes_last_run, probes);
            return -1; // raw-return-ok:probe-failure-abort-is-the-contract
        }
        if (lo_cmp == 0)
            hi = 0; /* diverged from genesis */
    }

    while (hi - lo > 1) {
        int mid = lo + (hi - lo) / 2;
        char l[65], r[65];
        int cmp = probe_compare(mid, &probes, l, r);
        if (cmp < 0) {
            atomic_store(&g_probes_last_run, probes);
            LOG_WARN("validation_pack",
                     "[mirror_divergence] bisect aborted at h=%d after %d "
                     "probes (probe failure)", mid, probes);
            return -1; // raw-return-ok:warned-on-previous-line
        }
        if (cmp == 1) {
            lo = mid;
        } else {
            hi = mid;
            memcpy(ours, l, sizeof(ours));
            memcpy(theirs, r, sizeof(theirs));
        }
    }

    int first_div = hi;
    atomic_store(&g_probes_last_run, probes);
    invariant_sentinel_note_locator(first_div);

    /* FALSE-POSITIVE GATE (see header): a first_div inside the tip
     * confirmation window is indistinguishable from a healthy transient
     * fork (natural 1-block fork / one-tick reorg lag). Latching a HOLD
     * here would refuse the resolving reorg itself — the outage class
     * this gate exists to kill. Escalate only when the divergence is at
     * confirmed depth, OR when the SAME first_div persisted across
     * repeated locates for >= MDL_CONFIRM_PERSIST_SECS (the wedged-at-tip
     * shape, where our tip never advances so depth never confirms). */
    if (first_div > disagree_height - MDL_CONFIRM_DEPTH) {
        bool persisted = false;
        int64_t pending_age = 0;
        pthread_mutex_lock(&g_pending_lock);
        if (g_pending_first_div == first_div) {
            pending_age = now - g_pending_first_seen_unix;
            persisted = pending_age >= MDL_CONFIRM_PERSIST_SECS;
        } else {
            g_pending_first_div = first_div;
            g_pending_first_seen_unix = now;
        }
        pthread_mutex_unlock(&g_pending_lock);
        if (!persisted) {
            LOG_WARN("validation_pack",
                     "[mirror_divergence] tip-window divergence at h=%d "
                     "(tip=%d, depth<%d) — NOT escalated (healthy-fork "
                     "window; pending_age=%llds, escalates at %ds if it "
                     "persists or confirms at depth)",
                     first_div, disagree_height, MDL_CONFIRM_DEPTH,
                     (long long)pending_age, MDL_CONFIRM_PERSIST_SECS);
            return first_div;
        }
        LOG_WARN("validation_pack",
                 "[mirror_divergence] tip-window divergence at h=%d "
                 "PERSISTED %llds at an unmoving first_div — escalating",
                 first_div, (long long)pending_age);
    }

    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "first diverging height=%d ours=%.16s theirs=%.16s "
             "(located in %d probes)",
             first_div, ours, theirs, probes);

    int prev_first_div = atomic_exchange(&g_last_first_div, first_div);
    atomic_store(&g_divergence_latched, true);

    struct blocker_record rec;
    int rc = -1;
    if (blocker_init(&rec, "mirror.divergence_located", "validation_pack",
                     BLOCKER_PERMANENT, reason))
        rc = blocker_set(&rec);

    /* ONE loud page per located height: emit on a fresh blocker write or
     * when the located height CHANGED (deeper/different divergence). */
    if (rc == 0 || first_div != prev_first_div)
        event_emitf(EV_OPERATOR_NEEDED, 0,
                    "check=mirror_divergence first_div_h=%d ours=%.16s "
                    "theirs=%.16s probes=%d",
                    first_div, ours, theirs, probes);
    LOG_WARN("validation_pack",
             "[mirror_divergence] LOCATED first_div_h=%d ours=%.16s "
             "theirs=%.16s probes=%d", first_div, ours, theirs, probes);

    /* HOLD: refuse extending a chain that diverges from the mirror at
     * first_div; rewinds below it (the repair direction) stay possible.
     * EXCEPTION first_div == 0: a genesis-level disagreement means the
     * REFERENCE is on a different network/chain — our genesis is compiled
     * in and cannot be poisoned — so a misconfigured zclassicd must page
     * (blocker + event above) but never freeze this node. */
    if (first_div > 0)
        chain_linkage_hold_set("mirror_divergence", first_div, reason);

    /* Escalated: the pending record served its purpose. */
    pthread_mutex_lock(&g_pending_lock);
    g_pending_first_div = -1;
    g_pending_first_seen_unix = 0;
    pthread_mutex_unlock(&g_pending_lock);

    /* Feed the existing oracle disagreement state machine with the
     * LOCATED height (it previously only ever saw the tip-level one). */
    oracle_policy_record_disagreement(first_div, ours, theirs);
    return first_div;
}

void mirror_divergence_note_agreement(int height)
{
    if (height < 0)
        return;

    /* Agreement at h on hash-linked chains implies an identical chain
     * below h: any pending or latched divergence located AT OR BELOW h
     * is stale. Self-clear — the same discipline the window sweep uses
     * (crash-only, recovery-friendly: the next real divergence
     * re-locates and re-latches). */
    bool had_pending = false;
    pthread_mutex_lock(&g_pending_lock);
    if (g_pending_first_div >= 0 && g_pending_first_div <= height) {
        had_pending = true;
        g_pending_first_div = -1;
        g_pending_first_seen_unix = 0;
    }
    pthread_mutex_unlock(&g_pending_lock);

    int located = atomic_load(&g_last_first_div);
    if (atomic_load(&g_divergence_latched) &&
        located >= 0 && located <= height &&
        atomic_exchange(&g_divergence_latched, false)) {
        atomic_store(&g_last_first_div, -1);
        blocker_clear("mirror.divergence_located");
        chain_linkage_hold_clear("mirror_divergence");
        /* Allow an immediate re-locate on the next disagreement: the
         * fork landscape changed, the 10-min rate window is stale. */
        atomic_store(&g_last_locate_unix, (int64_t)0);
        LOG_INFO("validation_pack",
                 "[mirror_divergence] divergence (first_div=%d) RESOLVED "
                 "by mirror agreement at h=%d — blocker + HOLD cleared",
                 located, height);
    } else if (had_pending) {
        LOG_INFO("validation_pack",
                 "[mirror_divergence] pending tip-window divergence "
                 "resolved by mirror agreement at h=%d (healthy fork)",
                 height);
    }
}

/* See CLAUDE.md "Adding state introspection". Reentrant-safe: g_last_locate_unix
 * / g_last_first_div / g_probes_last_run / g_divergence_latched are atomics;
 * the pending (unconfirmed tip-window) record is guarded by g_pending_lock,
 * the same lock mirror_divergence_locate/note_agreement already take. */
bool mirror_divergence_dump_state_json(struct json_value *out,
                                       const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    json_push_kv_int(out, "last_locate_unix",
                     atomic_load(&g_last_locate_unix));
    json_push_kv_int(out, "last_first_div",
                     (int64_t)atomic_load(&g_last_first_div));
    json_push_kv_int(out, "probes_last_run",
                     (int64_t)atomic_load(&g_probes_last_run));
    json_push_kv_bool(out, "divergence_latched",
                      atomic_load(&g_divergence_latched));

    pthread_mutex_lock(&g_pending_lock);
    int pending_first_div = g_pending_first_div;
    int64_t pending_first_seen_unix = g_pending_first_seen_unix;
    pthread_mutex_unlock(&g_pending_lock);
    json_push_kv_bool(out, "pending_present", pending_first_div >= 0);
    json_push_kv_int(out, "pending_first_div", (int64_t)pending_first_div);
    json_push_kv_int(out, "pending_first_seen_unix",
                     pending_first_seen_unix);
    return true;
}

#ifdef ZCL_TESTING
void mirror_divergence_set_probes_for_testing(mdl_probe_fn local,
                                              mdl_probe_fn remote)
{
    g_test_local = local;
    g_test_remote = remote;
}

void mirror_divergence_reset_for_testing(void)
{
    /* Does NOT clear injected probes — that is set_probes_for_testing
     * (NULL, NULL)'s job, so a test can reset rate-limit/blocker state
     * between cases without losing its probe injection. */
    atomic_store(&g_last_locate_unix, (int64_t)0);
    atomic_store(&g_last_first_div, -1);
    atomic_store(&g_probes_last_run, 0);
    atomic_store(&g_divergence_latched, false);
    pthread_mutex_lock(&g_pending_lock);
    g_pending_first_div = -1;
    g_pending_first_seen_unix = 0;
    pthread_mutex_unlock(&g_pending_lock);
    blocker_clear("mirror.divergence_located");
    chain_linkage_hold_clear("mirror_divergence");
}

void mirror_divergence_backdate_pending_for_testing(int64_t secs)
{
    /* Simulates `secs` of wall time passing: ages the pending record AND
     * the relocate rate-limit stamp together. */
    pthread_mutex_lock(&g_pending_lock);
    if (g_pending_first_div >= 0)
        g_pending_first_seen_unix -= secs;
    pthread_mutex_unlock(&g_pending_lock);
    int64_t last = atomic_load(&g_last_locate_unix);
    if (last != 0)
        atomic_store(&g_last_locate_unix, last - secs);
}

int mirror_divergence_probes_last_run_for_testing(void)
{
    return atomic_load(&g_probes_last_run);
}
#endif
