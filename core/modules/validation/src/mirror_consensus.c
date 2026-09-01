/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "validation/mirror_consensus.h"

#include "event/event.h"
#include "util/blocker.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static struct {
    pthread_mutex_t lock;
    _Atomic int enabled;
    _Atomic int64_t overrides_total;
    _Atomic int64_t unsafe_overrides_total;
    _Atomic int64_t blockers_total;
    _Atomic int last_override_height;
    _Atomic int last_override_safe;
    char last_override_reason[128];
    char last_override_scope[32];
    enum blocker_class activation_blocker_class;
    char activation_blocker_reason[128];
} g_mirror_consensus = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

void mirror_consensus_set_enabled(bool enabled)
{
    atomic_store(&g_mirror_consensus.enabled, enabled ? 1 : 0);
}

void mirror_consensus_record_override(int height, const char *reason)
{
    const char *r = (reason && reason[0]) ? reason : "local_consensus_overridden";
    /* All overrides are classified "unsafe": there is no scope/auth machinery
     * to tag an override as authorized. The override observability stays
     * intact; the stats do not split safe vs unsafe. */
    bool safe = false;
    int64_t overrides =
        atomic_fetch_add(&g_mirror_consensus.overrides_total, 1) + 1;
    atomic_fetch_add(&g_mirror_consensus.unsafe_overrides_total, 1);
    atomic_store(&g_mirror_consensus.last_override_height, height);
    atomic_store(&g_mirror_consensus.last_override_safe, 0);
    pthread_mutex_lock(&g_mirror_consensus.lock);
    snprintf(g_mirror_consensus.last_override_reason,
             sizeof(g_mirror_consensus.last_override_reason), "%s", r);
    snprintf(g_mirror_consensus.last_override_scope,
             sizeof(g_mirror_consensus.last_override_scope), "%s",
             "unsafe_no_authorized_scope");
    g_mirror_consensus.activation_blocker_class = BLOCKER_TRANSIENT;
    g_mirror_consensus.activation_blocker_reason[0] = '\0';
    pthread_mutex_unlock(&g_mirror_consensus.lock);
    event_emitf(EV_BLOCK_CHECK_PASSED, 0,
                "mirror_consensus_override h=%d reason=%s", height, r);
    event_emitf(EV_MIRROR_CONSENSUS_DECISION, 0,
                "op=override authority=local_consensus_validation "
                "trust=bounded_advisory_fallback allowed=true safe=%s h=%d "
                "reason=%s overrides=%lld unsafe=%lld blockers=%lld blk=-",
                safe ? "true" : "false",
                height, r,
                (long long)overrides,
                (long long)atomic_load(
                    &g_mirror_consensus.unsafe_overrides_total),
                (long long)atomic_load(&g_mirror_consensus.blockers_total));
    fprintf(stderr,  // obs-ok:operational-log-override-paired-above
            "[mirror_consensus] override h=%d safe=%s reason=%s\n",
            height, safe ? "true" : "false", r);
}

/* Mirror reasons → typed blocker class. Most are TRANSIENT — they go
 * away when the network advances or local validation retries. A few
 * are PERMANENT (cryptographic mismatches that won't change without
 * operator action). */
enum blocker_class mirror_consensus_classify_blocker_reason(const char *r)
{
    if (!r || !r[0]) return BLOCKER_TRANSIENT;
    /* Cryptographic mismatches — bad data, never auto-retry. */
    if (strcmp(r, "body-hash-mismatch") == 0)              return BLOCKER_PERMANENT;
    if (strcmp(r, "header-hash-mismatch") == 0)            return BLOCKER_PERMANENT;
    if (strcmp(r, "merkle-root-mismatch") == 0)            return BLOCKER_PERMANENT;
    if (strcmp(r, "consensus-reject") == 0)                return BLOCKER_PERMANENT;
    /* Everything else: TRANSIENT (chain may advance next try). */
    return BLOCKER_TRANSIENT;
}

void mirror_consensus_record_blocker(const char *reason)
{
    const char *r = reason ? reason : "";
    /* Typed primitive: rate-limits + classifies. If it tells us this is
     * a rate-limited dup, suppress event emission (spam guard). */
    struct blocker_record rec;
    char bid[BLOCKER_ID_MAX];
    /* blocker-id: mirror.* */
    snprintf(bid, sizeof(bid), "mirror.%s", r[0] ? r : "unknown");
    enum blocker_class cls = mirror_consensus_classify_blocker_reason(r);
    blocker_init(&rec, bid, "mirror_consensus",
                 cls, r);
    pthread_mutex_lock(&g_mirror_consensus.lock);
    /* Serialize the typed record with the legacy latch so an exact resolver
     * cannot leave one active while clearing the other. */
    int rc = blocker_set(&rec);
    g_mirror_consensus.activation_blocker_class = cls;
    snprintf(g_mirror_consensus.activation_blocker_reason,
             sizeof(g_mirror_consensus.activation_blocker_reason), "%s",
             r);
    pthread_mutex_unlock(&g_mirror_consensus.lock);
    /* Always increment the unsuppressed total (legacy semantics). */
    int64_t blockers =
        atomic_fetch_add(&g_mirror_consensus.blockers_total, 1) + 1;
    /* Only emit the event on a fresh write (rc == 0) — rate-limited
     * dups (rc == 1) are suppressed at the source. */
    if (rc == 0) {
        event_emitf(EV_MIRROR_CONSENSUS_DECISION, 0,
                    "op=blocker authority=local_consensus_validation "
                    "trust=bounded_advisory_fallback allowed=false "
                    "reason=%s blockers=%lld blk=%s",
                    r, (long long)blockers, r[0] ? r : "-");
    }
}

static bool mirror_consensus_resolve_exact(const char *reason)
{
    bool matched = false;
    char blocker_id[BLOCKER_ID_MAX];
    snprintf(blocker_id, sizeof(blocker_id), "mirror.%s", reason);

    /* Record and resolve share this lock order, so the legacy latch and typed
     * registry change as one ordered mirror-control-plane transition. */
    pthread_mutex_lock(&g_mirror_consensus.lock);
    matched = blocker_exists(blocker_id);
    if (strcmp(g_mirror_consensus.activation_blocker_reason, reason) == 0) {
        g_mirror_consensus.activation_blocker_class = BLOCKER_TRANSIENT;
        g_mirror_consensus.activation_blocker_reason[0] = '\0';
        matched = true;
    }
    blocker_clear(blocker_id);
    pthread_mutex_unlock(&g_mirror_consensus.lock);
    return matched;
}

bool mirror_consensus_resolve_hash_disagreement(void)
{
    return mirror_consensus_resolve_exact("hash-disagreement");
}

bool mirror_consensus_resolve_observation_blocker(const char *reason)
{
    if (!reason ||
        (strcmp(reason, "hash-comparison-unavailable") != 0 &&
         strcmp(reason, "rpc-unreachable") != 0))
        return false;
    return mirror_consensus_resolve_exact(reason);
}

void mirror_consensus_stats_snapshot(struct mirror_consensus_stats *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->enabled = atomic_load(&g_mirror_consensus.enabled) != 0;
    /* scope/auth machinery removed in F-1e — override_active is
     * permanently false. Field kept for stats wire-compat. */
    out->override_active = false;
    out->last_override_safe =
        atomic_load(&g_mirror_consensus.last_override_safe) != 0;
    out->overrides_total = atomic_load(&g_mirror_consensus.overrides_total);
    out->unsafe_overrides_total =
        atomic_load(&g_mirror_consensus.unsafe_overrides_total);
    out->blockers_total = atomic_load(&g_mirror_consensus.blockers_total);
    out->last_override_height =
        atomic_load(&g_mirror_consensus.last_override_height);
    pthread_mutex_lock(&g_mirror_consensus.lock);
    out->activation_blocker_class =
        g_mirror_consensus.activation_blocker_reason[0]
            ? g_mirror_consensus.activation_blocker_class
            : BLOCKER_TRANSIENT;
    snprintf(out->last_override_reason, sizeof(out->last_override_reason),
             "%s", g_mirror_consensus.last_override_reason);
    snprintf(out->last_override_scope, sizeof(out->last_override_scope),
             "%s", g_mirror_consensus.last_override_scope);
    snprintf(out->activation_blocker_reason,
             sizeof(out->activation_blocker_reason),
             "%s", g_mirror_consensus.activation_blocker_reason);
    pthread_mutex_unlock(&g_mirror_consensus.lock);
}

void mirror_consensus_reset_for_test(void)
{
    pthread_mutex_lock(&g_mirror_consensus.lock);
    g_mirror_consensus.last_override_reason[0] = '\0';
    g_mirror_consensus.last_override_scope[0] = '\0';
    g_mirror_consensus.activation_blocker_class = BLOCKER_TRANSIENT;
    g_mirror_consensus.activation_blocker_reason[0] = '\0';
    pthread_mutex_unlock(&g_mirror_consensus.lock);
    atomic_store(&g_mirror_consensus.enabled, 0);
    atomic_store(&g_mirror_consensus.overrides_total, 0);
    atomic_store(&g_mirror_consensus.unsafe_overrides_total, 0);
    atomic_store(&g_mirror_consensus.blockers_total, 0);
    atomic_store(&g_mirror_consensus.last_override_height, 0);
    atomic_store(&g_mirror_consensus.last_override_safe, 0);
}
