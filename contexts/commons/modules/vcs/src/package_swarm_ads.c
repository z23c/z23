/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Union of roots peers have ANNOUNCEd this session. Read-only inventory
 * for dumpstate and operator catalog leaves. */

#include "package_swarm_priv.h"

#include <stdint.h>
#include <string.h>

static int root_cmp(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32);
}

size_t vcs_swarm_engine_advertised(struct vcs_swarm_engine *engine,
                                   struct vcs_swarm_advertised *out,
                                   size_t max)
{
    if (!engine || !out || max == 0)
        return 0;
    pthread_mutex_lock(&engine->lock);
    size_t n = 0;
    for (size_t p = 0; p < VCS_SWARM_MAX_PEERS; p++) {
        const struct swarm_peer *peer = &engine->peers[p];
        if (!peer->used)
            continue;
        for (size_t a = 0; a < peer->ad_count; a++) {
            const uint8_t *root = peer->ads[a];
            size_t lo = 0;
            size_t hi = n;
            while (lo < hi) {
                size_t mid = lo + (hi - lo) / 2u;
                int c = root_cmp(out[mid].root, root);
                if (c < 0)
                    lo = mid + 1u;
                else
                    hi = mid;
            }
            if (lo < n && root_cmp(out[lo].root, root) == 0) {
                if (out[lo].advertisers < UINT32_MAX)
                    out[lo].advertisers++;
                continue;
            }
            if (n >= max)
                continue;
            for (size_t i = n; i > lo; i--)
                out[i] = out[i - 1u];
            memcpy(out[lo].root, root, 32);
            out[lo].advertisers = 1;
            n++;
        }
    }
    pthread_mutex_unlock(&engine->lock);
    return n;
}
