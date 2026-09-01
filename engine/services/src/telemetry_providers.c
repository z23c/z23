// one-result-type-ok:telemetry-fill-provider — see the block comment below.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The telemetry provider registry. Contract and rationale:
 * services/telemetry_providers.h.
 *
 * The adapters here have the
 * frozen collector signature (bool over a typed snapshot) because that is what
 * the registry's function-pointer type is, and the registry exists precisely
 * so that eight collectors can be called through ONE type. A struct zcl_result
 * cannot travel through it, and there is nothing for one to carry: a value a
 * collector could not read is recorded IN the snapshot as TELEMETRY_UNAVAILABLE
 * with a static reason token, which says more than a single per-call message
 * could. The bool means only "this domain could not be read at all".
 */

#include "services/telemetry_providers.h"

#include "services/agents_telemetry.h"
#include "services/metaverse_telemetry.h"
#include "services/network_telemetry.h"
#include "services/runtime_telemetry.h"
#include "services/storage_telemetry.h"
#include "services/sync_telemetry.h"
#include "services/wallet_telemetry.h"
#include "services/zcode_telemetry.h"

#include "util/log_macros.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"

#include <string.h>

/* Forward-declare one adapter per domain, from the domains table. A domain
 * added to telemetry_domains.def and forgotten here is a link error against an
 * adapter that was declared and never defined — which is the whole point. */
#define TL_DOMAIN(d_) static bool tp_fill_##d_(void *snapshot);
#include "util/telemetry_domains.def"
#undef TL_DOMAIN

/* Six domains already have the contract signature. */
#define TP_ADAPTER_PLAIN(d_)                                                  \
    static bool tp_fill_##d_(void *snapshot)                                  \
    {                                                                         \
        return d_##_dump_state_fill((struct d_##_snapshot *)snapshot);        \
    }

TP_ADAPTER_PLAIN(sync)
TP_ADAPTER_PLAIN(network)
TP_ADAPTER_PLAIN(storage)
TP_ADAPTER_PLAIN(wallet)
TP_ADAPTER_PLAIN(zcode)
TP_ADAPTER_PLAIN(metaverse)

/* runtime reads its subsystems over dumpstate and reports which one was
 * missing through a `why` out-parameter. The reason is logged here rather than
 * discarded: the registry's uniform type has nowhere to put it, and a rollup
 * that sees `false` reports the domain as unknown, so the specific subsystem
 * name would otherwise be lost. */
static bool tp_fill_runtime(void *snapshot)
{
    const char *why = NULL;
    if (runtime_dump_state_fill((struct runtime_snapshot *)snapshot, &why))
        return true;
    LOG_FAIL("telemetry_providers", "runtime collector could not fill: %s",
             why ? why : "no reason given");
}

/* agents reads only in-process state with no fallible surface, so its
 * collector returns void. */
static bool tp_fill_agents(void *snapshot)
{
    agents_dump_state_fill((struct agents_snapshot *)snapshot);
    return true;
}

#define TL_DOMAIN(d_)                                                         \
    {                                                                         \
        .domain = #d_,                                                        \
        .fill = tp_fill_##d_,                                                 \
        .snapshot_size = sizeof(struct d_##_snapshot),                        \
        .schema = &g_##d_##_schema,                                           \
    },
static const struct telemetry_provider g_providers[] = {
#include "util/telemetry_domains.def"
};
#undef TL_DOMAIN

#define TP_PROVIDER_COUNT (sizeof(g_providers) / sizeof(g_providers[0]))

/* The registry and the schema registry are pasted from the same table, so a
 * mismatch means one of them was hand-edited. Caught at compile time. */
static_assert(TP_PROVIDER_COUNT >= 8,
              "every telemetry domain must have a provider adapter");

size_t telemetry_provider_count(void) { return TP_PROVIDER_COUNT; }

const struct telemetry_provider *telemetry_provider_at(size_t idx)
{
    if (idx >= TP_PROVIDER_COUNT)
        return NULL;
    return &g_providers[idx];
}

const struct telemetry_provider *telemetry_provider_find(const char *domain)
{
    if (!domain)
        return NULL;
    for (size_t i = 0; i < TP_PROVIDER_COUNT; i++)
        if (strcmp(g_providers[i].domain, domain) == 0)
            return &g_providers[i];
    return NULL;
}

size_t telemetry_snapshot_max_size(void)
{
    size_t max = 0;
    for (size_t i = 0; i < TP_PROVIDER_COUNT; i++)
        if (g_providers[i].snapshot_size > max)
            max = g_providers[i].snapshot_size;
    return max;
}

bool telemetry_provider_collect(const struct telemetry_provider *p, void *buf,
                                size_t buf_sz)
{
    if (!p || !buf)
        LOG_FAIL("telemetry_providers",
                 "collect needs both a provider and a buffer");
    if (buf_sz < p->snapshot_size)
        LOG_FAIL("telemetry_providers",
                 "buffer too small for domain %s: have %zu bytes, need %zu",
                 p->domain, buf_sz, p->snapshot_size);
    memset(buf, 0, p->snapshot_size);
    return p->fill(buf);
}
