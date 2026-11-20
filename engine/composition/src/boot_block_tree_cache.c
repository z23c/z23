/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block-tree cache boot adapter — boot_net_budgets.c / boot_parse_cache.c
 * pattern for the process-lifetime block tree's LevelDB LRU cap.
 *
 * Both open sites (boot.c boot_step_open_block_tree and
 * boot_wallet_cutover_startup.c boot_pending_runtime_stores_open) passed
 * the same 256<<20 literal; they now read ONE helper so the two cannot
 * drift. The cap is a lazily-allocated ceiling — an LRU holds
 * min(bytes-ever-read, cap), never a promised allocation — so the spread
 * between the HIGH and LOW defaults bounds what the cache MAY hold, not
 * what it will.
 *
 * Ordering: unlike parse_cache (whose consumer reads the env lazily, after
 * the service kernel's start_all), the block tree opens inside
 * boot_seq_open_coins_state — long BEFORE app_init_services registers any
 * service — so the class default is applied at the open step itself, not
 * from a service-kernel adapter. The helper still resolves the class
 * default when the env is absent, so the wallet-cutover pending open
 * (which can run on a path that never applied) is sized correctly. */

#include "config/boot_block_tree_cache.h"
#include "platform/environment_compat.h"

#include <stdio.h>
#include <stdlib.h>

#define BOOT_BLOCK_TREE_CACHE_ENGINE_BYTES (256LL * 1024 * 1024) /* 256 MiB */
#define BOOT_BLOCK_TREE_CACHE_LOW_BYTES    (64LL * 1024 * 1024)  /* 64 MiB */
#define BOOT_BLOCK_TREE_CACHE_MEDIUM_BYTES (128LL * 1024 * 1024) /* 128 MiB */

bool boot_block_tree_cache_limits_for_class(enum hw_profile_ram_class cls,
                                            struct boot_block_tree_cache_limits
                                                *out)
{
    if (!out)
        return false;
    switch (cls) {
    case HW_PROFILE_RAM_LOW:
        out->cache_bytes = BOOT_BLOCK_TREE_CACHE_LOW_BYTES;
        return true;
    case HW_PROFILE_RAM_MEDIUM:
        out->cache_bytes = BOOT_BLOCK_TREE_CACHE_MEDIUM_BYTES;
        return true;
    case HW_PROFILE_RAM_HIGH:
        return false;
    }
    return false;
}

bool boot_block_tree_cache_limits_apply_class(enum hw_profile_ram_class cls)
{
    const char *cls_name = cls == HW_PROFILE_RAM_LOW     ? "low"
                           : cls == HW_PROFILE_RAM_MEDIUM ? "medium"
                                                          : "high";
    struct boot_block_tree_cache_limits limits;
    if (!boot_block_tree_cache_limits_for_class(cls, &limits)) {
        /* HIGH: the 256 MiB engine default stands; report it as such. */
        printf("Block tree cache budget set (ram=%s defaults=engine)\n",
               cls_name);
        return true;
    }
    if (getenv("ZCL_BLOCK_TREE_CACHE_BYTES") == NULL) {
        char value[32];
        snprintf(value, sizeof(value), "%lld", (long long)limits.cache_bytes);
        if (platform_environment_set("ZCL_BLOCK_TREE_CACHE_BYTES", value, 0)
            != 0) {
            /* Not a boot refusal: the open step continues with the class
             * default resolved by the helper below (or the engine default
             * on HIGH), so the message must not claim one. */
            fprintf(stderr,
                    "[boot] block_tree_cache: setenv "
                    "ZCL_BLOCK_TREE_CACHE_BYTES=%s failed; continuing with "
                    "the default\n",
                    value);
            return false;
        }
    }
    /* Report the APPLIED cap (env readback in MiB), not the decided one:
     * an operator override must be visible as such on this line. */
    const char *env = getenv("ZCL_BLOCK_TREE_CACHE_BYTES");
    long long mib = env ? strtoll(env, NULL, 10) >> 20
                        : (long long)(limits.cache_bytes >> 20);
    printf("Block tree cache budget set (ram=%s block_tree_cache=%lldMiB%s)\n",
           cls_name, mib, env ? " (override)" : "");
    return true;
}

size_t boot_block_tree_cache_size_for_class(enum hw_profile_ram_class cls)
{
    const char *env = getenv("ZCL_BLOCK_TREE_CACHE_BYTES");
    if (env != NULL && env[0] != '\0') {
        char *end = NULL;
        long long bytes = strtoll(env, &end, 10);
        if (end != env && *end == '\0' && bytes >= 0)
            return (size_t)bytes; /* explicit operator env always wins */
        fprintf(stderr,
                "Warning: block tree cache: unparsable "
                "ZCL_BLOCK_TREE_CACHE_BYTES=%s; using the class default\n",
                env);
    }
    struct boot_block_tree_cache_limits limits;
    if (boot_block_tree_cache_limits_for_class(cls, &limits))
        return (size_t)limits.cache_bytes;
    return (size_t)BOOT_BLOCK_TREE_CACHE_ENGINE_BYTES;
}

size_t boot_block_tree_cache_size(void)
{
    return boot_block_tree_cache_size_for_class(
        hw_profile_ram_class_of(hw_profile_ram_bytes()));
}
