/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Roots of in-flight downloads nobody advertises. This is the discovery
 * fallback's work list: a download can only stall here — every other
 * scheduler state has a named exit — so these are exactly the roots a
 * DHT provider lookup could still rescue. Mirrors package_swarm_ads.c:
 * sorted, deduplicated snapshot under the engine lock. */

#include "package_swarm_priv.h"

#include <stdint.h>
#include <string.h>

static int root_cmp(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32);
}

size_t vcs_swarm_engine_unadvertised_roots(struct vcs_swarm_engine *engine,
                                           uint8_t out[][32], size_t max)
{
    if (!engine || !out || max == 0)
        return 0;
    pthread_mutex_lock(&engine->lock);
    size_t n = 0;
    for (size_t i = 0; i < VCS_SWARM_MAX_DOWNLOADS; i++) {
        const struct swarm_download *dl = &engine->dls[i];
        if (!dl->used || dl->provider_restricted ||
            (dl->state != VCS_SWARM_DL_WANT_MANIFEST &&
             dl->state != VCS_SWARM_DL_CHUNKS))
            continue;
        /* Zero live advertisements is the stall condition itself;
         * anything else still has scheduler moves available. */
        if (advertisers_of(engine, dl) > 0)
            continue;
        const uint8_t *root = dl->root;
        size_t lo = 0;
        size_t hi = n;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2u;
            int c = root_cmp(out[mid], root);
            if (c < 0)
                lo = mid + 1u;
            else
                hi = mid;
        }
        if (lo < n && root_cmp(out[lo], root) == 0)
            continue; /* two downloads can race the same root */
        if (n >= max)
            continue; /* caller bound: report the sorted prefix only */
        for (size_t j = n; j > lo; j--)
            memcpy(out[j], out[j - 1u], 32);
        memcpy(out[lo], root, 32);
        n++;
    }
    pthread_mutex_unlock(&engine->lock);
    return n;
}
