/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Lease table behind boot_zcode_swarm_discovery_tick(): one DHT record
 * discovery per stalled package root, retried with capped exponential
 * backoff, its completed route applied back into the swarm engine as
 * verified provider evidence. See the header for the contract. */

#include "config/boot_zcode_swarm_dht.h"

#include "config/boot_zcode_dht.h"
#include "platform/time_compat.h"
#include "vcs/package_swarm_node.h"
#include "vcs/zcode_dht_msgs.h"
#include "vcs/zcode_dht_service.h"

#include <stddef.h>
#include <string.h>

/* Half of the DHT service's own operation slots: normal record traffic
 * keeps room even while every swarm download is stalled at once. */
#define SWARM_DISCOVERY_MAX_LEASES 4u
#define SWARM_DISCOVERY_MAX_ROOTS 16u

/* Backoff ladder for terminal-but-unhelpful outcomes (no usable route,
 * discovery rejected). Short start: providers often enroll within one
 * membership-sync period. */
#define SWARM_DISCOVERY_RETRY_MIN_S 15u
#define SWARM_DISCOVERY_RETRY_CAP_S 1800u
/* After offers land, re-check this rarely: the root leaves the work list
 * on its own once an advertisement (ours included) goes live. */
#define SWARM_DISCOVERY_APPLIED_RECHECK_S 600u
/* A lease whose root vanished from the work list is dropped after one
 * full retry period, so flapping roots keep their backoff memory. */
#define SWARM_DISCOVERY_STALE_S 1800u
/* Providers known to the record store but not yet enrolled as swarm
 * peers: retry inside one membership-sync horizon, without counting a
 * failed attempt. */
#define SWARM_DISCOVERY_ENROLL_WAIT_S 15u
/* Poll gate once a discovery is in flight. */
#define SWARM_DISCOVERY_POLL_PERIOD_S 1u

enum swarm_discovery_state {
    LEASE_IDLE = 0,
    LEASE_DISCOVERING,
    LEASE_RETRY, /* parked until next_mono; begin() again after */
};

struct swarm_discovery_lease {
    bool used;
    uint8_t root[32];
    enum swarm_discovery_state state;
    uint64_t operation_id;
    uint64_t generation;
    uint64_t attempts;
    uint64_t next_mono; /* poll gate when DISCOVERING, retry gate else */
};

static struct swarm_discovery_lease s_leases[SWARM_DISCOVERY_MAX_LEASES];

static const struct boot_zcode_swarm_dht_ops *s_ops;

/* Same pair, and same intent, as dht_now() in boot_zcode_dht.c — that
 * file sits at the size ceiling, so this derivation lives here instead
 * of being exported. The values only gate lease bookkeeping; the DHT
 * adapters re-read time internally where it matters. */
static uint64_t swarm_dht_now_mono(void)
{
    return (uint64_t)(platform_time_monotonic_ms() / 1000);
}

static void swarm_dht_now(struct vcs_zcode_dht_time *out)
{
    out->wall_unix = (uint64_t)platform_time_wall_time_t();
    out->monotonic_s = swarm_dht_now_mono();
}

/* ── production adapters ──────────────────────────────────────────── */

static bool prod_begin(void *ctx, const uint8_t root[32], uint64_t now_mono,
                       uint64_t *operation_id, uint64_t *generation)
{
    (void)ctx;
    struct vcs_zcode_dht_time now;
    swarm_dht_now(&now);
    now.monotonic_s = now_mono; /* tests drive the lane clock */
    struct vcs_zcode_dht_record_selector selector = {
        .kind = VCS_ZCODE_DHT_RECORD_PROVIDER};
    memcpy(selector.root, root, 32);
    return boot_zcode_dht_record_discovery_begin(&selector, now,
                                                 operation_id, generation);
}

static int prod_poll(void *ctx, uint64_t operation_id, uint64_t generation,
                     uint64_t now_mono)
{
    (void)ctx;
    struct vcs_zcode_dht_time now;
    swarm_dht_now(&now);
    now.monotonic_s = now_mono;
    struct vcs_zcode_dht_record_discovery_result out;
    memset(&out, 0, sizeof(out));
    if (!boot_zcode_dht_record_discovery_poll(operation_id, generation, now,
                                              &out))
        return VCS_ZCODE_DHT_RECORD_OPERATION_REJECTED;
    return (int)out.state;
}

static bool prod_route(void *ctx, const uint8_t root[32], uint64_t now_mono,
                       uint64_t *known_peer_ids, uint64_t *expires_at,
                       size_t max, size_t *count_out)
{
    (void)ctx;
    (void)now_mono;
    struct vcs_zcode_dht_record_selector selector = {
        .kind = VCS_ZCODE_DHT_RECORD_PROVIDER};
    memcpy(selector.root, root, 32);
    struct vcs_zcode_dht_provider_route route;
    memset(&route, 0, sizeof(route));
    uint64_t wall_now = (uint64_t)platform_time_wall_time_t();
    if (!boot_zcode_dht_provider_route(wall_now, &selector, &route))
        return false;
    size_t n = 0;
    for (size_t i = 0; i < VCS_ZCODE_DHT_K && n < max; i++) {
        uint64_t id = route.peer_ids[i];
        if (id == 0)
            continue;
        bool dup = false;
        for (size_t j = 0; j < n; j++)
            if (known_peer_ids[j] == id) {
                dup = true;
                break;
            }
        if (!dup) {
          known_peer_ids[n++] = id;
          expires_at[n - 1] = route.expires_at[i];
        }
    }
    *count_out = n;
    return true;
}

static const struct boot_zcode_swarm_dht_ops g_prod_ops = {
    .ctx = NULL,
    .begin = prod_begin,
    .poll = prod_poll,
    .route = prod_route,
};

void boot_zcode_swarm_dht_test_install(
    const struct boot_zcode_swarm_dht_ops *ops)
{
    s_ops = ops;
    memset(s_leases, 0, sizeof(s_leases));
}

/* ── lane ─────────────────────────────────────────────────────────── */

static uint64_t retry_delay(uint64_t attempts)
{
    uint64_t delay =
        SWARM_DISCOVERY_RETRY_MIN_S << (attempts > 7u ? 7u : attempts);
    return delay > SWARM_DISCOVERY_RETRY_CAP_S ? SWARM_DISCOVERY_RETRY_CAP_S
                                               : delay;
}

static bool root_known(const uint8_t roots[][32], size_t n,
                       const uint8_t root[32])
{
    for (size_t i = 0; i < n; i++)
        if (memcmp(roots[i], root, 32) == 0)
            return true;
    return false;
}

static struct swarm_discovery_lease *lease_for(const uint8_t root[32])
{
    for (size_t i = 0; i < SWARM_DISCOVERY_MAX_LEASES; i++)
        if (s_leases[i].used && memcmp(s_leases[i].root, root, 32) == 0)
            return &s_leases[i];
    return NULL;
}

/* Apply a completed route to the global engine. Only enrolled peers get
 * an offer here: enrollment rides the ordinary membership sync, and an
 * ENROLL_WAIT re-poll re-runs the route once those sessions show up.
 * Offers are idempotent by design. */
static size_t apply_route(const uint8_t root[32], const uint64_t *ids,
                          const uint64_t *expires_at, size_t count)
{
    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    if (!engine)
        return 0;
    uint64_t now = (uint64_t)platform_time_wall_time_t();
    size_t offered = 0;
    for (size_t i = 0; i < count; i++)
        if (vcs_swarm_engine_peer_known(engine, ids[i]) &&
            vcs_swarm_engine_peer_offer(engine, ids[i], root,
                                        expires_at[i], now))
            offered++;
    if (offered > 0)
        vcs_swarm_engine_schedule_ready(engine, 0, 0);
    return offered;
}

void boot_zcode_swarm_discovery_tick(uint64_t now_mono)
{
    if (!s_ops)
        s_ops = &g_prod_ops;
    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    if (!engine)
        return;

    uint8_t roots[SWARM_DISCOVERY_MAX_ROOTS][32];
    size_t stalled =
        vcs_swarm_engine_unadvertised_roots(engine, roots,
                                            SWARM_DISCOVERY_MAX_ROOTS);

    /* Reap leases whose root left the work list (completed, failed, or
     * newly advertised by anyone) once their stale grace lapses. */
    for (size_t i = 0; i < SWARM_DISCOVERY_MAX_LEASES; i++) {
        struct swarm_discovery_lease *lease = &s_leases[i];
        if (!lease->used ||
            root_known(roots, stalled, lease->root))
            continue;
        if (now_mono >= lease->next_mono + SWARM_DISCOVERY_STALE_S) {
            /* Free the DHT operation slot with the lease so a reaped
             * in-flight discovery cannot strand capacity. */
            boot_zcode_dht_record_discovery_cancel(lease->operation_id,
                                                   lease->generation);
            lease->used = false;
        }
    }

    size_t active = 0;
    for (size_t i = 0; i < SWARM_DISCOVERY_MAX_LEASES; i++)
        active +=
            s_leases[i].used && s_leases[i].state == LEASE_DISCOVERING;

    for (size_t r = 0; r < stalled; r++) {
        struct swarm_discovery_lease *lease = lease_for(roots[r]);
        if (!lease) {
            if (active >= SWARM_DISCOVERY_MAX_LEASES)
                continue; /* honest cap: existing work advances first */
            struct swarm_discovery_lease *fresh = NULL;
            for (size_t i = 0; i < SWARM_DISCOVERY_MAX_LEASES && !fresh;
                 i++)
                if (!s_leases[i].used)
                    fresh = &s_leases[i];
            if (!fresh)
                continue;
            fresh->used = true;
            memcpy(fresh->root, roots[r], 32);
            fresh->attempts = 0;
            fresh->state = LEASE_DISCOVERING;
            fresh->next_mono = now_mono;
            if (!s_ops->begin(s_ops->ctx, fresh->root, now_mono,
                              &fresh->operation_id, &fresh->generation)) {
                fresh->state = LEASE_RETRY;
                fresh->next_mono =
                    now_mono + retry_delay(fresh->attempts++);
            } else {
                active++;
            }
            continue;
        }

        switch (lease->state) {
        case LEASE_DISCOVERING:
            if (now_mono < lease->next_mono)
                break;
            lease->next_mono = now_mono + SWARM_DISCOVERY_POLL_PERIOD_S;
            int state = s_ops->poll(s_ops->ctx, lease->operation_id,
                                    lease->generation, now_mono);
            if (state == VCS_ZCODE_DHT_RECORD_OPERATION_PENDING)
                break;
            active--;
            if (state != VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE) {
                lease->state = LEASE_RETRY;
                lease->next_mono =
                    now_mono + retry_delay(lease->attempts++);
                break;
            }
            uint64_t ids[VCS_ZCODE_DHT_K];
            uint64_t expires_at[VCS_ZCODE_DHT_K];
            size_t count = 0;
            if (s_ops->route(s_ops->ctx, lease->root, now_mono, ids, expires_at,
                             VCS_ZCODE_DHT_K, &count) &&
                apply_route(lease->root, ids, expires_at, count) > 0) {
                /* Parked on RECHECK; stall-reap drops it when the root
                 * gets advertised (by us or anyone). */
                lease->next_mono =
                    now_mono + SWARM_DISCOVERY_APPLIED_RECHECK_S;
            } else {
                lease->next_mono = now_mono + SWARM_DISCOVERY_ENROLL_WAIT_S;
            }
            break;
        case LEASE_RETRY:
            if (now_mono < lease->next_mono || active >=
                                                   SWARM_DISCOVERY_MAX_LEASES)
                break;
            lease->state = LEASE_DISCOVERING;
            lease->next_mono = now_mono;
            if (!s_ops->begin(s_ops->ctx, lease->root, now_mono,
                              &lease->operation_id, &lease->generation)) {
                lease->next_mono =
                    now_mono + retry_delay(lease->attempts++);
            } else {
                active++;
            }
            break;
        case LEASE_IDLE:
            lease->used = false;
            break;
        }
    }
}
