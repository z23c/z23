/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Full-lifecycle SHADOW observer for the pure sync kernel — see
 * net/sync_shadow.h. The reference FSM stays authoritative; this only observes.
 */

#include "net/sync_shadow.h"
#include "net/sync_reduce_adapter.h"

#include "json/json.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

/* ── Diagnostics counters (observability only; NOT the sync authority) ── */

#define SYNC_SHADOW_RING 8

struct shadow_ring_entry {
    bool            valid;
    enum sync_shadow_point point;
    uint64_t        session_id;
    enum sync_phase kernel_after;
    enum sync_phase ref_after;
};

static _Atomic uint64_t g_observed[SYNC_SHADOW_POINT_COUNT];
static _Atomic uint64_t g_agree[SYNC_SHADOW_POINT_COUNT];
static _Atomic uint64_t g_allowlisted[SYNC_SHADOW_POINT_COUNT];
static _Atomic uint64_t g_mismatch[SYNC_SHADOW_POINT_COUNT];
static _Atomic uint64_t g_total_mismatch;

static pthread_mutex_t g_ring_lock = PTHREAD_MUTEX_INITIALIZER;
static struct shadow_ring_entry g_ring[SYNC_SHADOW_RING];
static unsigned g_ring_head;   /* next write slot */

const char *sync_shadow_point_name(enum sync_shadow_point p)
{
    switch (p) {
    case SYNC_SHADOW_OFFER:            return "offer";
    case SYNC_SHADOW_RECEIVE_BEGIN:    return "receive_begin";
    case SYNC_SHADOW_CHUNK_ACCEPTED:   return "chunk_accepted";
    case SYNC_SHADOW_CHUNK_REJECTED:   return "chunk_rejected";
    case SYNC_SHADOW_RECEIVE_COMPLETE: return "receive_complete";
    case SYNC_SHADOW_PROOF_SUCCESS:    return "proof_success";
    case SYNC_SHADOW_PROOF_FAILURE:    return "proof_failure";
    case SYNC_SHADOW_PEER_LOSS:        return "peer_loss";
    case SYNC_SHADOW_TIMEOUT:          return "timeout";
    case SYNC_SHADOW_STOP_RESET:       return "stop_reset";
    case SYNC_SHADOW_CONTAINMENT:      return "containment";
    case SYNC_SHADOW_POINT_COUNT:      break;
    }
    return "?";
}

/* ── Pure comparator + allowlist ────────────────────────────────────── */

/* Known structural gaps between the coarse kernel and the reference FSM that
 * are EXPECTED, not defects. Returns a static reason string, or NULL if the
 * disagreement is genuine (and should be LOUD). */
static const char *expected_gap(enum sync_event_kind kernel_event,
                                enum sync_phase kernel_after,
                                enum sync_phase ref_after)
{
    /* Activation containment: on a passing proof the kernel reaches STAGED,
     * while the reference deliberately re-marks FAILED (activation is contained
     * until a unified installer exists). Same safety outcome, different label. */
    if (kernel_after == SYNC_PHASE_STAGED && ref_after == SYNC_PHASE_FAILED)
        return "activation_contained_gap";

    /* A bad chunk: the kernel penalizes the peer and HOLDS at RECEIVING; the
     * reference may hard-fail the write path to FAILED. Both reject the chunk. */
    if (kernel_event == SYNC_EVENT_CHUNK_REJECTED &&
        kernel_after == SYNC_PHASE_RECEIVING && ref_after == SYNC_PHASE_FAILED)
        return "ref_hardfail_on_chunk_writepath";

    return NULL;
}

struct sync_shadow_obs sync_shadow_compare(
    enum sync_shadow_point point, uint64_t session_id,
    enum snapshot_sync_state ref_before, enum snapshot_sync_state ref_after,
    enum sync_event_kind kernel_event, bool proof_ok)
{
    struct sync_kernel_state state;
    memset(&state, 0, sizeof(state));
    state.session_id.value = session_id;
    state.phase = sync_reduce_adapter_map_phase(ref_before);

    struct sync_event event;
    memset(&event, 0, sizeof(event));
    event.session_id.value = session_id;
    event.kind = kernel_event;
    event.proof_ok = proof_ok;

    struct sync_transition t = sync_reduce(state, event);

    struct sync_shadow_obs obs;
    memset(&obs, 0, sizeof(obs));
    obs.point = point;
    obs.session_id = session_id;
    obs.kernel_before = state.phase;
    obs.kernel_after = t.next_state.phase;
    obs.ref_before = sync_reduce_adapter_map_phase(ref_before);
    obs.ref_after = sync_reduce_adapter_map_phase(ref_after);
    obs.agrees = (obs.kernel_after == obs.ref_after);
    obs.expected_disagreement =
        obs.agrees ? NULL
                   : expected_gap(kernel_event, obs.kernel_after, obs.ref_after);
    return obs;
}

/* ── Record ─────────────────────────────────────────────────────────── */

void sync_shadow_record(const struct sync_shadow_obs *obs)
{
    if (!obs || obs->point < 0 || obs->point >= SYNC_SHADOW_POINT_COUNT)
        return;

    atomic_fetch_add_explicit(&g_observed[obs->point], 1, memory_order_relaxed);

    if (obs->agrees) {
        atomic_fetch_add_explicit(&g_agree[obs->point], 1, memory_order_relaxed);
        return;
    }
    if (obs->expected_disagreement) {
        atomic_fetch_add_explicit(&g_allowlisted[obs->point], 1,
                                  memory_order_relaxed);
        return;
    }

    /* Genuine mismatch — LOUD, counted, and ringed. */
    atomic_fetch_add_explicit(&g_mismatch[obs->point], 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_total_mismatch, 1, memory_order_relaxed);

    LOG_ERROR("sync_shadow",
        "shadow kernel disagrees with reference at %s: session=%llu "
        "ref %s->%s but kernel %s->%s (no allowlisted gap)",
        sync_shadow_point_name(obs->point),
        (unsigned long long)obs->session_id,
        sync_phase_name(obs->ref_before), sync_phase_name(obs->ref_after),
        sync_phase_name(obs->kernel_before), sync_phase_name(obs->kernel_after));

    pthread_mutex_lock(&g_ring_lock);
    g_ring[g_ring_head].valid = true;
    g_ring[g_ring_head].point = obs->point;
    g_ring[g_ring_head].session_id = obs->session_id;
    g_ring[g_ring_head].kernel_after = obs->kernel_after;
    g_ring[g_ring_head].ref_after = obs->ref_after;
    g_ring_head = (g_ring_head + 1) % SYNC_SHADOW_RING;
    pthread_mutex_unlock(&g_ring_lock);
}

void sync_shadow_observe(
    enum sync_shadow_point point, uint64_t session_id,
    enum snapshot_sync_state ref_before, enum snapshot_sync_state ref_after,
    enum sync_event_kind kernel_event, bool proof_ok)
{
    struct sync_shadow_obs obs = sync_shadow_compare(
        point, session_id, ref_before, ref_after, kernel_event, proof_ok);
    sync_shadow_record(&obs);
}

uint64_t sync_shadow_total_mismatches(void)
{
    return atomic_load_explicit(&g_total_mismatch, memory_order_relaxed);
}

void sync_shadow_reset(void)
{
    for (int i = 0; i < SYNC_SHADOW_POINT_COUNT; i++) {
        atomic_store_explicit(&g_observed[i], 0, memory_order_relaxed);
        atomic_store_explicit(&g_agree[i], 0, memory_order_relaxed);
        atomic_store_explicit(&g_allowlisted[i], 0, memory_order_relaxed);
        atomic_store_explicit(&g_mismatch[i], 0, memory_order_relaxed);
    }
    atomic_store_explicit(&g_total_mismatch, 0, memory_order_relaxed);
    pthread_mutex_lock(&g_ring_lock);
    memset(g_ring, 0, sizeof(g_ring));
    g_ring_head = 0;
    pthread_mutex_unlock(&g_ring_lock);
}

/* ── dumpstate ──────────────────────────────────────────────────────── */

bool sync_shadow_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    (void)json_push_kv_bool(out, "authoritative", false);
    (void)json_push_kv_int(out, "total_mismatches",
                           (int64_t)sync_shadow_total_mismatches());

    struct json_value points;
    json_init(&points);
    json_set_object(&points);
    for (int i = 0; i < SYNC_SHADOW_POINT_COUNT; i++) {
        uint64_t obs = atomic_load_explicit(&g_observed[i], memory_order_relaxed);
        if (obs == 0)
            continue; /* keep the object bounded to points actually exercised */
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_int(&row, "observed", (int64_t)obs);
        (void)json_push_kv_int(&row, "agree",
            (int64_t)atomic_load_explicit(&g_agree[i], memory_order_relaxed));
        (void)json_push_kv_int(&row, "allowlisted",
            (int64_t)atomic_load_explicit(&g_allowlisted[i], memory_order_relaxed));
        (void)json_push_kv_int(&row, "mismatch",
            (int64_t)atomic_load_explicit(&g_mismatch[i], memory_order_relaxed));
        (void)json_push_kv(&points, sync_shadow_point_name((enum sync_shadow_point)i),
                           &row);
        json_free(&row);
    }
    (void)json_push_kv(out, "points", &points);
    json_free(&points);

    struct json_value ring;
    json_init(&ring);
    json_set_array(&ring);
    pthread_mutex_lock(&g_ring_lock);
    for (int i = 0; i < SYNC_SHADOW_RING; i++) {
        if (!g_ring[i].valid)
            continue;
        struct json_value e;
        json_init(&e);
        json_set_object(&e);
        (void)json_push_kv_str(&e, "point",
                               sync_shadow_point_name(g_ring[i].point));
        (void)json_push_kv_int(&e, "session_id",
                               (int64_t)g_ring[i].session_id);
        (void)json_push_kv_str(&e, "kernel_after",
                               sync_phase_name(g_ring[i].kernel_after));
        (void)json_push_kv_str(&e, "ref_after",
                               sync_phase_name(g_ring[i].ref_after));
        (void)json_push_back(&ring, &e);
        json_free(&e);
    }
    pthread_mutex_unlock(&g_ring_lock);
    (void)json_push_kv(out, "recent_mismatches", &ring);
    json_free(&ring);
    return true;
}
