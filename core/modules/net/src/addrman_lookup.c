/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Exact, lock-safe addrman lookup. Kept separate so the oversized core table
 * does not grow and callers never receive an internal pointer. */

#include "addrman_internal.h"

bool addrman_find_info(struct addr_man *am, const struct net_service *addr,
                       struct addr_info *out)
{
    if (!am || !addr || !out)
        return false;
    zcl_mutex_lock(&am->cs);
    int id;
    struct addr_info *info =
        addrman_find_addr_locked(am, &addr->addr, &id);
    bool found = info && info->used && net_service_eq(&info->addr.svc, addr);
    if (found)
        *out = *info;
    zcl_mutex_unlock(&am->cs);
    return found;
}
