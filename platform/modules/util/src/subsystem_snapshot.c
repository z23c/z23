/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * subsystem_snapshot — see util/subsystem_snapshot.h. The memory-ordering
 * discipline is copied field-for-field from the proven seqlock in
 * cognition/controllers/src/event_agent_peers.c: the writer marks itself busy with a
 * release-ordered odd seq, publishes payload with relaxed stores, then a
 * release-ordered even seq; the reader takes an acquire-ordered seq before the
 * payload, then an acquire fence before the final seq validation, and accepts
 * the sample only when both seq values are the same even value. */

#include "util/subsystem_snapshot.h"

#include "json/json.h"
#include "platform/time_compat.h"

void zcl_snapshot_publish_begin(struct zcl_snapshot_env *env)
{
    if (!env)
        return;
    /* Claim the even -> odd transition with a CAS loop, exactly as
     * event_agent_peers.c's writer does: a concurrent publisher (a caller that
     * does not hold the subsystem lock) either wins the CAS or spins until the
     * other writer's even seq is visible. The acq_rel success ordering keeps
     * the payload stores that follow from being hoisted above the claim. */
    uint64_t seq;
    for (;;) {
        seq = atomic_load_explicit(&env->seq, memory_order_acquire);
        if ((seq & 1U) != 0)
            continue;
        if (atomic_compare_exchange_weak_explicit(
                &env->seq, &seq, seq + 1,
                memory_order_acq_rel, memory_order_acquire))
            break;
    }
}

void zcl_snapshot_publish_end(struct zcl_snapshot_env *env, int64_t last_height)
{
    if (!env)
        return;
    atomic_store_explicit(&env->published_us,
                          platform_time_monotonic_us(), memory_order_relaxed);
    atomic_store_explicit(&env->last_height, last_height, memory_order_relaxed);
    atomic_fetch_add_explicit(&env->generation, 1, memory_order_relaxed);
    /* Close the window: the seq is odd (old_even + 1) because we hold the
     * claim; add one more to land on old_even + 2 (even again). The release
     * store publishes every payload/metadata store above to any reader that
     * acquires this seq. */
    uint64_t seq = atomic_load_explicit(&env->seq, memory_order_relaxed);
    atomic_store_explicit(&env->seq, seq + 1, memory_order_release);
}

bool zcl_snapshot_read_try(const struct zcl_snapshot_env *env,
                           uint64_t *seq_out)
{
    if (!env || !seq_out)
        return false;
    uint64_t seq = atomic_load_explicit(&env->seq, memory_order_acquire);
    *seq_out = seq;
    return (seq & 1U) == 0;
}

bool zcl_snapshot_read_ok(const struct zcl_snapshot_env *env,
                          uint64_t seq_before)
{
    if (!env)
        return false;
    /* This is the trailing half of the seqlock bracket.  The acquire load in
     * read_try keeps payload loads after the opening seq observation; this
     * acquire fence keeps those loads before the closing seq observation.
     * A second acquire load by itself is not that trailing load-load barrier
     * on weakly ordered CPUs such as ARM64: payload loads may otherwise be
     * observed after seq validation and a torn generation can be accepted. */
    atomic_thread_fence(memory_order_acquire);
    uint64_t seq = atomic_load_explicit(&env->seq, memory_order_acquire);
    return (seq_before & 1U) == 0 && seq == seq_before;
}

void zcl_snapshot_note_torn(struct zcl_snapshot_env *env)
{
    if (!env)
        return;
    atomic_fetch_add_explicit(&env->torn_reads_total, 1, memory_order_relaxed);
}

void zcl_snapshot_emit_label(struct json_value *out,
                             const struct zcl_snapshot_env *env,
                             bool torn, int64_t now_us)
{
    if (!out || !env)
        return;

    uint64_t generation =
        atomic_load_explicit(&env->generation, memory_order_relaxed);
    int64_t published_us =
        atomic_load_explicit(&env->published_us, memory_order_relaxed);
    int64_t last_height =
        atomic_load_explicit(&env->last_height, memory_order_relaxed);
    uint64_t torn_total =
        atomic_load_explicit(&env->torn_reads_total, memory_order_relaxed);

    bool never = generation == 0;
    bool stale = never || torn;
    const char *reason = never ? "never_published"
                       : torn  ? "snapshot_torn_read"
                               : "ok";
    int64_t age_us = (never || published_us <= 0 || now_us < published_us)
                         ? -1
                         : now_us - published_us;

    json_push_kv_bool(out, "stale", stale);
    json_push_kv_int (out, "age_us", age_us);
    json_push_kv_int (out, "last_publish_height", last_height);
    json_push_kv_int (out, "generation", (int64_t)generation);
    json_push_kv_int (out, "torn_reads_total", (int64_t)torn_total);
    json_push_kv_str (out, "warning_reason", reason);
}
