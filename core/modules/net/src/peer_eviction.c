/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * See net/peer_eviction.h. */

#include "net/peer_eviction.h"
#include <stdlib.h>

struct sort_entry {
    size_t idx;
    int64_t connected_time;
};

static int cmp_sort_entry(const void *a, const void *b)
{
    const struct sort_entry *ea = a;
    const struct sort_entry *eb = b;
    if (ea->connected_time != eb->connected_time)
        return ea->connected_time < eb->connected_time ? -1 : 1;
    if (ea->idx != eb->idx)
        return ea->idx < eb->idx ? -1 : 1;
    return 0;
}

int peer_eviction_select(const struct peer_eviction_candidate *candidates,
                          size_t n, int64_t now)
{
    if (!candidates || n == 0)
        return -1;
    if (n > PEER_EVICTION_MAX_CANDIDATES)
        n = PEER_EVICTION_MAX_CANDIDATES;

    struct sort_entry entries[PEER_EVICTION_MAX_CANDIDATES];
    size_t inbound_count = 0;
    for (size_t i = 0; i < n; i++) {
        if (candidates[i].is_outbound || candidates[i].whitelisted)
            continue;
        entries[inbound_count].idx = i;
        entries[inbound_count].connected_time = candidates[i].connected_time;
        inbound_count++;
    }
    if (inbound_count == 0)
        return -1;

    qsort(entries, inbound_count, sizeof(entries[0]), cmp_sort_entry);

    /* Protect the longest-connected quartile — the oldest entries after
     * the connected_time sort above. */
    bool is_protected[PEER_EVICTION_MAX_CANDIDATES] = {0};
    size_t quartile = inbound_count / 4;
    for (size_t i = 0; i < quartile; i++)
        is_protected[entries[i].idx] = true;

    /* Protect recent novel block/tx relayers regardless of connection age. */
    for (size_t i = 0; i < inbound_count; i++) {
        size_t idx = entries[i].idx;
        const struct peer_eviction_candidate *c = &candidates[idx];
        if ((c->last_block_time > 0 &&
             now - c->last_block_time < PEER_EVICTION_RECENT_RELAY_SECS) ||
            (c->last_tx_time > 0 &&
             now - c->last_tx_time < PEER_EVICTION_RECENT_RELAY_SECS))
            is_protected[idx] = true;
    }

    /* Evict the newest (largest connected_time) unprotected candidate;
     * entries[] is sorted ascending so the last unprotected entry wins. */
    int evict_idx = -1;
    int64_t evict_connected_time = 0;
    for (size_t i = 0; i < inbound_count; i++) {
        size_t idx = entries[i].idx;
        if (is_protected[idx])
            continue;
        if (evict_idx == -1 || entries[i].connected_time >= evict_connected_time) {
            evict_idx = (int)idx;
            evict_connected_time = entries[i].connected_time;
        }
    }
    return evict_idx;
}
