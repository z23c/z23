/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "net/net_fault.h"

#include <stdatomic.h>

static _Atomic int64_t g_net_partition_until_unix = 0;

void net_partition_until_unix(int64_t until_unix)
{
    atomic_store(&g_net_partition_until_unix,
                 until_unix > 0 ? until_unix : 0);
}

void net_partition_clear(void)
{
    atomic_store(&g_net_partition_until_unix, 0);
}

int64_t net_partition_armed_until_unix(void)
{
    return atomic_load(&g_net_partition_until_unix);
}

bool net_partition_active_at(int64_t now_unix)
{
    int64_t until = atomic_load(&g_net_partition_until_unix);
    return until > 0 && now_unix < until;
}
