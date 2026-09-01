/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded DHT endpoint-hint queue feeding the normal P2P dialer. */

#include "net/connman.h"

#include "net/addrman.h"
#include "util/log_macros.h"

#include <string.h>

bool connman_queue_dht_hint(struct connman *cm,
                            const struct net_address *addr)
{
    if (!cm || !addr || !net_addr_is_valid(&addr->svc.addr) ||
        addr->svc.port == 0)
        return false;
    struct net_addr source;
    net_addr_init(&source);
    (void)addrman_add(&cm->manager.addrman, addr, &source, 0);
    zcl_mutex_lock(&cm->dht_hint_lock);
    for (size_t i = 0; i < cm->dht_hint_count; i++) {
        if (net_service_eq(&cm->dht_hints[i].svc, &addr->svc)) {
            zcl_mutex_unlock(&cm->dht_hint_lock);
            return true;
        }
    }
    if (cm->dht_hint_count == CONNMAN_DHT_HINT_MAX) {
        zcl_mutex_unlock(&cm->dht_hint_lock);
        LOG_FAIL("connman", "DHT hint queue full (%d)",
                 CONNMAN_DHT_HINT_MAX);
    }
    cm->dht_hints[cm->dht_hint_count++] = *addr;
    zcl_mutex_unlock(&cm->dht_hint_lock);
    return true;
}

bool connman_take_dht_hint(struct connman *cm, struct net_address *out)
{
    if (!cm || !out)
        return false;
    zcl_mutex_lock(&cm->dht_hint_lock);
    if (cm->dht_hint_count == 0) {
        zcl_mutex_unlock(&cm->dht_hint_lock);
        return false;
    }
    *out = cm->dht_hints[0];
    cm->dht_hint_count--;
    if (cm->dht_hint_count)
        memmove(&cm->dht_hints[0], &cm->dht_hints[1],
                cm->dht_hint_count * sizeof(cm->dht_hints[0]));
    memset(&cm->dht_hints[cm->dht_hint_count], 0,
           sizeof(cm->dht_hints[0]));
    zcl_mutex_unlock(&cm->dht_hint_lock);
    return true;
}

bool connman_dht_hint_pending(struct connman *cm)
{
    if (!cm)
        return false;
    zcl_mutex_lock(&cm->dht_hint_lock);
    bool pending = cm->dht_hint_count > 0;
    zcl_mutex_unlock(&cm->dht_hint_lock);
    return pending;
}
