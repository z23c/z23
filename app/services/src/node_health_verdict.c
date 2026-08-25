/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_health_verdict.c — the published health verdict atomics.
 *
 * Split out of node_health_service.c (E1 file-size ceiling: that unit sits
 * at the 800-line ceiling; this contract is self-contained). Two halves:
 *
 *   - node_health_verdict_publish(): called once at the end of every
 *     node_health_collect() — health ring, RPC handlers, soak service;
 *     last writer wins.
 *   - node_health_last_verdict(): exposes the latest publication timestamp to
 *     cheap non-blocking observers. It is diagnostic evidence only: a collect
 *     can block for minutes on reducer-held locks during bulk ingest, so its
 *     freshness must not decide process liveness.
 *
 * The verdict itself stays authoritative for serving, conditions, remedies,
 * and operator action. Neither verdict content nor publication cadence is a
 * process-hang signal. */

// one-result-type-ok:verdict-atomics-no-fallible-surface — E2 (one way
// out): this unit owns no fallible service surface. node_health_last_verdict's
// bool is a PRESENCE flag ("has any verdict been published yet") — there is
// no failure reason to carry because an absent verdict is data, not an error.
// node_health_verdict_publish returns void and cannot fail (atomic stores
// only). Nothing here can produce a zcl_result a caller could act on.

#include "platform/time_compat.h"
#include "services/node_health_service.h"
#include <stdatomic.h>

static _Atomic int64_t g_last_verdict_us      = 0; /* 0 = never published */

bool node_health_last_verdict(int64_t *publish_us_out)
{
    int64_t pub = atomic_load(&g_last_verdict_us);
    if (pub == 0)
        return false;
    if (publish_us_out)
        *publish_us_out = pub;
    return true;
}

void node_health_verdict_publish(const struct node_health_snapshot *snapshot)
{
    if (!snapshot)
        return;
    atomic_store(&g_last_verdict_us, platform_time_monotonic_us());
}
