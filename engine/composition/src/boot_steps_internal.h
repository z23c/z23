/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_steps_internal.h — the private seam between boot.c's boot sequence
 * and the heavy leaves of that sequence in boot_steps.c.
 *
 * app_init is a list of named phases, each a list of named steps. Three of
 * those steps are large enough that keeping them inline would push boot.c
 * past its size budget: the legacy zclassicd block-index
 * import, the legacy post-scan anchor ladder, and the Sapling
 * commitment-tree load. They live in boot_steps.c and take the state they
 * work on as parameters — boot.c still owns the storage, so no boot-owned
 * global's linkage is widened by the split. */
#ifndef ZCLASSIC_BOOT_STEPS_INTERNAL_H
#define ZCLASSIC_BOOT_STEPS_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct app_context;
struct chain_params;
struct coins_view_sqlite;
struct main_state;
struct node_db;

/* DERIVED coins-best (wave 2): one cheap point-read of progress.kv's own
 * co-committed state via reducer_frontier_derive_coins_best. Recomputed at
 * every decision point (derive, don't cache). Returns true iff
 * coins_applied_height is present — the canonical-datadir signal that the
 * legacy node_state/mirror anchors are mere caches and every legacy
 * anchor-repair rung must be skipped. */
struct boot_derived_coins_best {
    int32_t height;      /* coins_applied_height - 1 */
    uint8_t hash[32];    /* valid iff hash_found */
    bool hash_found;
};
bool boot_derive_coins_best(struct boot_derived_coins_best *out);

/* Pull ancestry, the chain tip and block files from a legacy zclassicd
 * LevelDB index when our own index is far short of the chain. */
void boot_blkidx_pull_legacy_zclassicd(struct app_context *ctx,
                                       struct main_state *st,
                                       struct node_db *ndb);

/* Legacy post-scan anchor ladder: resolve coins_best_block against the
 * freshly scanned block files. Skipped on canonical (derived) datadirs. */
void boot_post_scan_anchor_ladder(struct main_state *st, struct node_db *ndb,
                                  struct coins_view_sqlite *cs,
                                  const char *datadir,
                                  const struct chain_params *params);

/* Load the Sapling commitment tree (flat checkpoint, then node_state) and
 * verify its root against the coins-applied endpoint, rebuilding or folding
 * forward when they disagree. */
void boot_sapling_tree_boot_load(struct app_context *ctx, struct main_state *st,
                                 struct node_db *ndb, const char *datadir);

#endif /* ZCLASSIC_BOOT_STEPS_INTERNAL_H */
