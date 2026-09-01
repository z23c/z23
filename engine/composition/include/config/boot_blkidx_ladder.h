/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Table-driven block-index load ladder for boot (engine/composition/src/boot.c
 * app_init). The ordered rungs that select where the in-memory block index
 * comes from — projection rebuild, flat file, sqlite cache, kill-9 projection
 * rebuild, flat-union taint check, blocks-table hydrate, LevelDB — live here as
 * a const rung table iterated in order, replacing the prior hand-written
 * if/else chain and keeping boot.c under the E1 file-size ceiling. The
 * flat_union_tainted guard (the LevelDB rung's mid-boot flat-save gate, the
 * reason a prior lane deferred this fold) is a first-class field of the shared
 * context. Per-rung fire counters are surfaced via the boot_block_index_rungs
 * dump_state entry (see CLAUDE.md "Adding state introspection"). */
#ifndef CONFIG_BOOT_BLKIDX_LADDER_H
#define CONFIG_BOOT_BLKIDX_LADDER_H

#include <stdbool.h>

struct app_context;
struct main_state;
struct node_db;
struct chain_params;
struct block_tree_db;
struct json_value;

/* Shared mutable context threaded through every rung. The pointers are the
 * boot globals (static in boot.c, passed in by the caller); the three bool
 * fields carry the exact cross-rung state the original inline if/else ladder
 * kept in function locals:
 *   rebuilt_from_log   — the projection-as-authority path won; every later
 *                        rung is suppressed and the caller reads this back.
 *   loaded             — a rung populated the map; gates fall-through.
 *   flat_union_tainted — the loaded flat file is a corrupt union; the LevelDB
 *                        rung's mid-boot flat re-save is suppressed so the
 *                        poison record is not laundered into the next flat
 *                        generation (the shutdown save persists the healed
 *                        map instead). */
struct boot_blkidx_load_ctx {
    struct app_context        *ctx;
    struct main_state         *st;
    struct node_db            *ndb;
    const struct chain_params *params;
    struct block_tree_db      *block_tree;
    bool                       block_tree_open;

    bool rebuilt_from_log;
    bool loaded;
    bool flat_union_tainted;
};

/* Run the block-index load ladder: iterate the const rung table in order,
 * firing each applicable rung's load (+ optional post) exactly as the prior
 * inline if/else chain did, and bumping that rung's fire counter. All context
 * mutation happens through `c`; the caller reads back c->rebuilt_from_log. */
void boot_blkidx_run_ladder(struct boot_blkidx_load_ctx *c);

/* dump_state entry: per-rung fire counters + last-run outcome flags. */
bool boot_blkidx_rungs_dump_state_json(struct json_value *out, const char *key);

#endif /* CONFIG_BOOT_BLKIDX_LADDER_H */
