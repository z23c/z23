/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: fixed-size process and per-target stage telemetry for raw onion
 * dials.  Kept separate from the byte bridge so observability cannot turn the
 * transport implementation into another oversized component. */

#include "net/onion_stream_telemetry.h"
#include "net/peer_lifecycle.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

struct onion_stream_dial_record {
    bool used;                    /* protected by g_records_mu */
    char target[NET_SERVICE_STR_MAX + 1];
    uint64_t generation;          /* protected by g_records_mu */
    int64_t started_ms;           /* immutable while used */
    _Atomic int64_t ended_ms;
    _Atomic bool active;
    _Atomic bool poisoned;        /* terminal callback contract broke */
    _Atomic uint64_t stages[ONION_DIAL_STAGE_COUNT];
    struct peer_lifecycle_summary p2p_baseline; /* immutable while used */
};

static _Atomic uint64_t g_stage_totals[ONION_DIAL_STAGE_COUNT + 1];
static pthread_mutex_t g_records_mu = PTHREAD_MUTEX_INITIALIZER;
static struct onion_stream_dial_record
    g_records[ONION_STREAM_RECENT_DIALS_MAX];
static uint64_t g_generation;

static void stage_bump(_Atomic uint64_t *counter, uint64_t by)
{
    atomic_fetch_add_explicit(counter, by, memory_order_relaxed);
}

static void peer_baseline(const char *target,
                          struct peer_lifecycle_summary *out)
{
    memset(out, 0, sizeof(*out));
    struct json_value life = {0};
    if (!peer_lifecycle_addr_json(target, &life))
        return;
#define COPY_COUNT(name) out->name = json_get_int(json_get(&life, #name))
    COPY_COUNT(connected);
    COPY_COUNT(version_sent);
    COPY_COUNT(version_received);
    COPY_COUNT(verack_received);
    COPY_COUNT(handshake_complete);
    COPY_COUNT(pre_handshake_disconnects);
#undef COPY_COUNT
    json_free(&life);
}

struct onion_stream_dial_record *onion_stream_dial_begin(
    const struct net_service *svc)
{
    stage_bump(&g_stage_totals[0], 1); /* dial_started */
    char target[NET_SERVICE_STR_MAX + 1];
    if (!svc || net_service_to_string(svc, target, sizeof(target)) < 0)
        return NULL;
    struct peer_lifecycle_summary baseline;
    peer_baseline(target, &baseline);

    pthread_mutex_lock(&g_records_mu);
    struct onion_stream_dial_record *pick = NULL;
    for (size_t i = 0; i < ONION_STREAM_RECENT_DIALS_MAX; i++) {
        struct onion_stream_dial_record *record = &g_records[i];
        if (!record->used) {
            pick = record;
            break;
        }
        if (!atomic_load_explicit(&record->active, memory_order_acquire) &&
            (!pick || record->generation < pick->generation))
            pick = record;
    }
    if (pick) {
        memset(pick, 0, sizeof(*pick));
        pick->used = true;
        snprintf(pick->target, sizeof(pick->target), "%s", target);
        pick->generation = ++g_generation;
        pick->started_ms = platform_time_monotonic_ms();
        pick->p2p_baseline = baseline;
        atomic_store_explicit(&pick->active, true, memory_order_release);
    }
    pthread_mutex_unlock(&g_records_mu);
    if (!pick)
        LOG_WARN("onion", "onion per-dial ledger full target=%s capacity=%d",
                 target, ONION_STREAM_RECENT_DIALS_MAX);
    return pick;
}

void onion_stream_dial_bump(struct onion_stream_dial_record *record,
                            enum onion_stream_dial_stage stage, uint64_t by)
{
    if (stage < ONION_DIAL_STREAM_QUEUED ||
        stage >= ONION_DIAL_STAGE_COUNT)
        return;
    size_t index = (size_t)stage;
    stage_bump(&g_stage_totals[index + 1], by);
    if (record)
        stage_bump(&record->stages[index], by);
}

void onion_stream_dial_poison(struct onion_stream_dial_record *record)
{
    if (record)
        atomic_store_explicit(&record->poisoned, true, memory_order_release);
}

void onion_stream_dial_end(struct onion_stream_dial_record *record)
{
    if (!record ||
        atomic_load_explicit(&record->poisoned, memory_order_acquire))
        return;
    atomic_store_explicit(&record->ended_ms, platform_time_monotonic_ms(),
                          memory_order_relaxed);
    atomic_store_explicit(&record->active, false, memory_order_release);
}

void onion_stream_get_stages(struct onion_stream_stages *out)
{
    if (!out)
        return;
#define LOAD_TOTAL(name, index) \
    out->name = atomic_load_explicit(&g_stage_totals[index], \
                                     memory_order_relaxed)
    LOAD_TOTAL(dial_started, 0);
    LOAD_TOTAL(stream_queued, 1);
    LOAD_TOTAL(circuit_ready, 2);
    LOAD_TOTAL(bridge_up, 3);
    LOAD_TOTAL(open_refused, 4);
    LOAD_TOTAL(circuit_timeout, 5);
    LOAD_TOTAL(circuit_torn_down, 6);
    LOAD_TOTAL(bridge_closed, 7);
    LOAD_TOTAL(bytes_to_peer, 8);
    LOAD_TOTAL(bytes_from_peer, 9);
    LOAD_TOTAL(peers_answered, 10);
#undef LOAD_TOTAL
}

static void record_snapshot(const struct onion_stream_dial_record *record,
                            struct onion_stream_dial_snapshot *out)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->target, sizeof(out->target), "%s", record->target);
    out->generation = record->generation;
    out->active = atomic_load_explicit(&record->active, memory_order_acquire);
    out->started_ms = record->started_ms;
    out->ended_ms = atomic_load_explicit(&record->ended_ms,
                                         memory_order_relaxed);
    out->stages.dial_started = 1;
#define LOAD_DIAL(name, index) \
    out->stages.name = atomic_load_explicit(&record->stages[index], \
                                            memory_order_relaxed)
    LOAD_DIAL(stream_queued, 0);
    LOAD_DIAL(circuit_ready, 1);
    LOAD_DIAL(bridge_up, 2);
    LOAD_DIAL(open_refused, 3);
    LOAD_DIAL(circuit_timeout, 4);
    LOAD_DIAL(circuit_torn_down, 5);
    LOAD_DIAL(bridge_closed, 6);
    LOAD_DIAL(bytes_to_peer, 7);
    LOAD_DIAL(bytes_from_peer, 8);
    LOAD_DIAL(peers_answered, 9);
#undef LOAD_DIAL
    out->p2p_baseline.connected = record->p2p_baseline.connected;
    out->p2p_baseline.version_sent = record->p2p_baseline.version_sent;
    out->p2p_baseline.version_received = record->p2p_baseline.version_received;
    out->p2p_baseline.verack_received = record->p2p_baseline.verack_received;
    out->p2p_baseline.handshake_complete =
        record->p2p_baseline.handshake_complete;
    out->p2p_baseline.pre_handshake_disconnects =
        record->p2p_baseline.pre_handshake_disconnects;
}

size_t onion_stream_get_recent_dials(struct onion_stream_dial_snapshot *out,
                                     size_t cap)
{
    if (!out || cap == 0)
        return 0;
    if (cap > ONION_STREAM_RECENT_DIALS_MAX)
        cap = ONION_STREAM_RECENT_DIALS_MAX;
    pthread_mutex_lock(&g_records_mu);
    size_t count = 0;
    for (size_t n = 0; n < cap; n++) {
        const struct onion_stream_dial_record *newest = NULL;
        for (size_t i = 0; i < ONION_STREAM_RECENT_DIALS_MAX; i++) {
            const struct onion_stream_dial_record *record = &g_records[i];
            if (!record->used)
                continue;
            bool copied = false;
            for (size_t j = 0; j < count; j++) {
                if (out[j].generation == record->generation) {
                    copied = true;
                    break;
                }
            }
            if (!copied &&
                (!newest || record->generation > newest->generation))
                newest = record;
        }
        if (!newest)
            break;
        record_snapshot(newest, &out[count++]);
    }
    pthread_mutex_unlock(&g_records_mu);
    return count;
}

#ifdef ZCL_TESTING
void onion_stream_reset_stages_for_test(void)
{
    for (size_t i = 0; i < ONION_DIAL_STAGE_COUNT + 1; i++)
        atomic_store(&g_stage_totals[i], 0);
    pthread_mutex_lock(&g_records_mu);
    memset(g_records, 0, sizeof(g_records));
    g_generation = 0;
    pthread_mutex_unlock(&g_records_mu);
}
#endif
