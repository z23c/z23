/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "conditions/utxo_drift_detected.h"
#include "util/log_macros.h"
#include "util/blocker.h"
#include "framework/condition.h"

#include "config/runtime.h"
#include "event/event.h"
#include "models/database.h"

#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static _Atomic int64_t g_height_at_detect = -1;

#ifdef ZCL_TESTING
static struct node_db *g_test_ndb;
static _Atomic int g_test_remedy_calls;
#endif

static struct node_db *runtime_ndb(void)
{
#ifdef ZCL_TESTING
    if (g_test_ndb)
        return g_test_ndb;
#endif
    return app_runtime_node_db();
}

/* Two independent drift detectors share this pager but own SEPARATE keys:
 *   - utxo_drift_detected: the UTXO SHA3 path; its own confirmations clear it.
 *   - parity_bh_drift_detected: the coarse block-hash parity LATCH; nothing
 *     automatic clears it (operator-only) — a later SHA3 confirmation must
 *     never un-page a block-hash contradiction (wave-3 review finding).
 * Either key pages; the condition deactivates only when BOTH are clear. */
static bool read_drift_flags(struct node_db *ndb, int64_t *utxo_out,
                             int64_t *bh_out)
{
    int64_t utxo = 0;
    int64_t bh = 0;
    if (utxo_out)
        *utxo_out = 0;
    if (bh_out)
        *bh_out = 0;
    if (!ndb || !ndb->open)
        return false;
    (void)node_db_state_get_int(ndb, "utxo_drift_detected", &utxo);
    (void)node_db_state_get_int(ndb, "parity_bh_drift_detected", &bh);
    if (utxo_out)
        *utxo_out = utxo;
    if (bh_out)
        *bh_out = bh;
    return utxo != 0 || bh != 0;
}

static bool detect_utxo_drift_detected(void)
{
    struct node_db *ndb = runtime_ndb();
    int64_t utxo = 0;
    int64_t bh = 0;
    if (!read_drift_flags(ndb, &utxo, &bh))
        return false; // raw-return-ok:no-drift-is-the-healthy-steady-state

    int64_t height = -1;
    if (utxo != 0)
        (void)node_db_state_get_int(ndb, "utxo_audit_last_height", &height);
    else
        (void)node_db_state_get_int(ndb, "parity_bh_drift_height", &height);
    atomic_store(&g_height_at_detect, height);
    return true;
}

static void read_state_text(struct node_db *ndb, const char *key,
                            char *out, size_t out_len)
{
    size_t len = 0;
    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!ndb || !key ||
        !node_db_state_get(ndb, key, out, out_len - 1, &len))
        return;
    if (len >= out_len)
        len = out_len - 1;
    out[len] = '\0';
}

static enum condition_remedy_result remedy_utxo_drift_detected(void)
{
    struct node_db *ndb = runtime_ndb();
    char local[65];
    char remote[65];
    read_state_text(ndb, "utxo_audit_last_local_sha3",
                    local, sizeof(local));
    read_state_text(ndb, "utxo_audit_last_remote_sha3",
                    remote, sizeof(remote));

#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif

    LOG_WARN("condition", "[condition:utxo_drift_detected] height=%" PRId64 " " "local_sha3=%s remote_sha3=%s action=operator_escalation", atomic_load(&g_height_at_detect), local[0] ? local : "-", remote[0] ? remote : "-");

    /* When the block-hash parity latch is what paged, name its evidence too
     * (the SHA3 keys above may be empty or stale for a BH-only drift). */
    int64_t bh = 0;
    (void)node_db_state_get_int(ndb, "parity_bh_drift_detected", &bh);
    if (bh != 0) {
        int64_t bh_height = -1;
        char bh_local[65];
        char bh_ref[65];
        (void)node_db_state_get_int(ndb, "parity_bh_drift_height", &bh_height);
        read_state_text(ndb, "parity_bh_drift_local_hash",
                        bh_local, sizeof(bh_local));
        read_state_text(ndb, "parity_bh_drift_ref_hash",
                        bh_ref, sizeof(bh_ref));
        LOG_WARN("condition", "[condition:utxo_drift_detected] block-hash parity latch: height=%" PRId64 " local=%s ref=%s (operator-cleared only)", bh_height, bh_local[0] ? bh_local : "-", bh_ref[0] ? bh_ref : "-");
    }
    event_emitf(EV_UTXO_DRIFT_DETECTED, 0,
                "condition=utxo_drift_detected height=%lld local_sha3=%s "
                "remote_sha3=%s",
                (long long)atomic_load(&g_height_at_detect),
                local[0] ? local : "-",
                remote[0] ? remote : "-");

    /* UTXO drift is consensus-critical. Until the repair job lands, keep the
     * condition unresolved so the engine pages instead of pretending a
     * destructive wipe/reimport was safe to run automatically. This remedy
     * is a DELIBERATE no-op — never auto-run a destructive wipe/reimport —
     * but a no-op remedy that never touches the blocker registry is
     * invisible to blocker_stall_meta_detector and the rest of the
     * safety net. Name a typed, retry-forever DEPENDENCY blocker so the
     * unresolved drift surfaces in `dumpstate blocker` / the supervisor
     * tree even though nothing here attempts a repair. */
    char blocker_reason[BLOCKER_REASON_MAX];
    snprintf(blocker_reason, sizeof(blocker_reason),
             "utxo_drift_detected: height=%" PRId64 " local_sha3=%s "
             "remote_sha3=%s — no automatic repair (destructive "
             "wipe/reimport requires operator action)",
             atomic_load(&g_height_at_detect),
             local[0] ? local : "-", remote[0] ? remote : "-");
    blocker_name_dependency("utxo.parity_bh_drift", "utxo_drift_detected",
                            blocker_reason);

    return COND_REMEDY_FAILED;
}

static bool witness_utxo_drift_detected(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: remedy_utxo_drift_detected returns COND_REMEDY_FAILED
    // and NEVER clears the drift flags — only an external repair (or operator)
    // can. So this poison-absence read cannot be self-certified by the remedy
    // (the Law-7 trap). It exists solely for the engine's !detected
    // deactivation path: once drift genuinely resolves externally the
    // condition must clear, which needs a truthful flag read, never a constant.
    return !read_drift_flags(runtime_ndb(), NULL, NULL);
}

static struct condition c_utxo_drift_detected = {
    .name = "utxo_drift_detected",
    .severity = COND_CRITICAL,
    .poll_secs = 60,
    .backoff_secs = 300,
    .max_attempts = 1,
    .detect = detect_utxo_drift_detected,
    .remedy = remedy_utxo_drift_detected,
    .witness = witness_utxo_drift_detected,
    .witness_window_secs = 60,
};

void register_utxo_drift_detected(void)
{
    (void)condition_register(&c_utxo_drift_detected);
}

#ifdef ZCL_TESTING
void utxo_drift_detected_test_reset(void)
{
    g_test_ndb = NULL;
    atomic_store(&g_height_at_detect, -1);
    atomic_store(&g_test_remedy_calls, 0);
}

void utxo_drift_detected_test_set_node_db(struct node_db *ndb)
{
    g_test_ndb = ndb;
}

int utxo_drift_detected_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}
#endif
