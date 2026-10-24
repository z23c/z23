/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A one-shot writer on this datadir (plugin fetch, zcode use, blob put) may
 * have advanced the store generation since this resident handle last synced.
 * Rebuild the derived catalog only then, outside engine->lock: the store lock
 * is a leaf, so no store path re-enters the engine. A refused refresh (for
 * example a previously observed manifest was removed) is retried once per
 * SWARM_REFRESH_RETRY_S, or as soon as the disk generation moves again, so a
 * persistent refusal does not rebuild and warn on every tick. */

#include "package_swarm_priv.h"

#include "vcs/package_store.h"

#include "util/log_macros.h"

#include <stdint.h>

#define SWARM_LOG "vcs.swarm"
#define SWARM_REFRESH_RETRY_S 60u

void vcs_swarm_refresh_moved_store(struct vcs_swarm_engine *engine,
                                   uint64_t now)
{
    struct vcs_package_store *store = engine->store;
    uint64_t disk = 0;
    if (!store || !vcs_package_store_generation_moved(store, &disk))
        return;
    if (engine->refresh_refused && engine->refresh_refused_generation == disk &&
        now - engine->refresh_refused_at < SWARM_REFRESH_RETRY_S)
        return;
    engine->refresh_refused = !vcs_package_store_refresh(store);
    engine->refresh_refused_generation = disk;
    engine->refresh_refused_at = now;
    if (engine->refresh_refused)
        LOG_WARN(SWARM_LOG,
                 "store refresh after foreign writer refused at generation "
                 "%llu; retrying in %us or when the store moves again",
                 (unsigned long long)disk, SWARM_REFRESH_RETRY_S);
}
