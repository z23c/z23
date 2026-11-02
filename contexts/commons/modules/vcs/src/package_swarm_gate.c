/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_swarm_gate — the public-hosting admission gate and the
 * rate-limited reasons for every silent serve-side drop.
 *
 * A node that stays quiet gives its operator nothing to read when a fetch
 * stalls against it. Each drop below names its reason in the log, once per
 * reason per window, with a count of how many repeats were folded in. */

#include "package_swarm_priv.h"

#include "platform/time_compat.h"
#include "support/log_throttle.h"

#include <stdint.h>
#include <string.h>

#define SWARM_DROP_LOG_WINDOW_SECS 300

/* Zero-initialised: last_key 0 differs from the key used below, so the
 * first drop of each reason always logs. */
static struct log_throttle g_drop_log[VCS_SWARM_DROP_COUNT];

bool vcs_swarm_drop_due(enum vcs_swarm_drop why, uint64_t *suppressed)
{
    *suppressed = 0;
    if ((unsigned)why >= VCS_SWARM_DROP_COUNT)
        return true;
    return log_throttle_should_emit(&g_drop_log[why], 1, (int64_t)platform_time_wall_time_t(),
                                    SWARM_DROP_LOG_WINDOW_SECS, suppressed);
}

/* Public-hosting admission for one root.
 *
 * Every byte this node offers a stranger passes through here: the ANNOUNCE
 * that advertises a root and the WANT that asks for its manifest or its
 * chunks. Completeness is not enough. The root must match one of the
 * closed shapes in vcs/package_public_shape.h, and the shapes that carry
 * source for other people to build must re-derive their whole signed,
 * permissively licensed closure — dependency graph included — out of the
 * bytes we hold. Anything else is refused by name.
 *
 * Caching. A self-contained verdict is only invalidated by this package
 * changing, so it keys on the package's own generation. A verdict that
 * rested on the dependency graph can be falsified by a SIBLING package
 * being evicted or mutated, which that generation cannot see, so it keys
 * on the store-wide epoch as well. Getting this wrong would keep serving a
 * package whose dependencies this node can no longer hand over.
 *
 * Called with engine->lock held; takes the store lock beneath it, which is
 * the order the serve path already uses. */
bool vcs_swarm_public_serveable(struct vcs_swarm_engine *engine,
                                const uint8_t root[32], const char **rule_out)
{
    struct vcs_package_possession_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    if (!vcs_package_store_possession_snapshot(engine->store, root,
                                               &receipt)) {
        if (rule_out) *rule_out = "not-tracked";
        return false;
    }
    uint64_t epoch = vcs_package_store_mutation_epoch(engine->store);
    struct swarm_public_entry *slot =
        &engine->public_cache[root[0] % VCS_SWARM_PUBLIC_CACHE_SLOTS];
    bool stale = !slot->used || memcmp(slot->root, root, 32) != 0 ||
                 slot->generation != receipt.mutation_generation ||
                 (slot->dep_scoped && slot->epoch != epoch);
    if (stale) {
        struct vcs_package_public_verdict verdict;
        vcs_package_public_shape_classify(engine->store, root, &verdict);
        memcpy(slot->root, root, 32);
        slot->generation = receipt.mutation_generation;
        slot->epoch = epoch;
        slot->shape = verdict.shape;
        slot->rule = verdict.rule;
        slot->dep_scoped = verdict.dep_scoped;
        slot->used = true;
    }
    if (rule_out)
        *rule_out = slot->rule;
    return slot->shape != VCS_PACKAGE_PUBLIC_REFUSED;
}
