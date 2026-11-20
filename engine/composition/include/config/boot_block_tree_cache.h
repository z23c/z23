/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Block-tree cache boot adapter — declares the RAM-class default for the
 * process-lifetime block tree's LevelDB LRU cap (ZCL_BLOCK_TREE_CACHE_BYTES)
 * and the ONE helper both open sites — boot.c boot_step_open_block_tree and
 * boot_wallet_cutover_startup.c boot_pending_runtime_stores_open — use to
 * convert that env (or the class default) into the cache_size
 * block_tree_db_open passes to dbwrapper.
 * See engine/composition/src/boot_block_tree_cache.c for the decision table. */

#ifndef ZCL_BOOT_BLOCK_TREE_CACHE_H
#define ZCL_BOOT_BLOCK_TREE_CACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util/hw_profile.h"

/* Block-tree LRU cap per RAM class. LOW 64 MiB; MEDIUM 128 MiB; HIGH
 * refuses (the 256 MiB engine default stands, byte-identical behavior). */
struct boot_block_tree_cache_limits {
    int64_t cache_bytes;
};

/* Pure per-class decision — no env reads, no hardware probing. Returns
 * true and fills *out for LOW and MEDIUM; returns false for HIGH (and
 * refuses a NULL out), leaving *out untouched. */
bool boot_block_tree_cache_limits_for_class(enum hw_profile_ram_class cls,
                                            struct boot_block_tree_cache_limits
                                                *out);

/* Sets ZCL_BLOCK_TREE_CACHE_BYTES ONLY when it is absent, so an explicit
 * operator env always wins, then prints the effective-limits style line
 * with the APPLIED value by env readback. HIGH sets nothing and reports
 * defaults=engine; a failed setenv logs and returns false while the open
 * step continues with the engine default standing. Call BEFORE the first
 * block_tree_db_open: the main open step runs before app_init_services,
 * so a service-kernel adapter would bind the default too late. */
bool boot_block_tree_cache_limits_apply_class(enum hw_profile_ram_class cls);

/* The shared open-site converter: the cache_size both block_tree_db_open
 * call sites pass to dbwrapper. An explicit, parsable env value always
 * wins; an absent or empty one falls back to the class table (warned when
 * a non-empty value fails to parse), so the cap is right even on a path
 * that never ran the apply — the wallet-cutover pending open can run
 * first. HIGH resolves to the unchanged 256 MiB engine default. */
size_t boot_block_tree_cache_size_for_class(enum hw_profile_ram_class cls);
size_t boot_block_tree_cache_size(void);

#endif /* ZCL_BOOT_BLOCK_TREE_CACHE_H */
