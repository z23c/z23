/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot_block_tree_cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BBTC_BOOT_CHECK(name, expr) do {                                 \
    printf("boot_block_tree_cache: %s... ", (name));                     \
    if (expr) printf("OK\n");                                            \
    else { printf("FAIL\n"); failures++; }                               \
} while (0)

static const char k_cap_env[] = "ZCL_BLOCK_TREE_CACHE_BYTES";

/* Env holds exactly `want` (non-NULL, byte-equal). */
static bool bbtc_boot_env_is(const char *name, const char *want)
{
    const char *value = getenv(name);
    return value != NULL && strcmp(value, want) == 0;
}

static bool bbtc_boot_env_absent(const char *name)
{
    return getenv(name) == NULL;
}

int test_boot_block_tree_cache(void)
{
    int failures = 0;
    struct boot_block_tree_cache_limits limits;

    /* ── 1. pure per-class decision ─────────────────────────── */
    BBTC_BOOT_CHECK("low decision is a 64 MiB cap",
                   boot_block_tree_cache_limits_for_class(HW_PROFILE_RAM_LOW,
                                                          &limits) &&
                   limits.cache_bytes == (int64_t)(64LL << 20));
    BBTC_BOOT_CHECK("medium decision is a 128 MiB cap",
                   boot_block_tree_cache_limits_for_class(
                       HW_PROFILE_RAM_MEDIUM, &limits) &&
                   limits.cache_bytes == (int64_t)(128LL << 20));
    BBTC_BOOT_CHECK("high decision refuses (engine default stands)",
                   !boot_block_tree_cache_limits_for_class(
                       HW_PROFILE_RAM_HIGH, &limits));
    BBTC_BOOT_CHECK("null out refuses",
                   !boot_block_tree_cache_limits_for_class(HW_PROFILE_RAM_LOW,
                                                           NULL));

    /* ── 2. apply sets the default only when the env is absent ── */
    unsetenv(k_cap_env);
    BBTC_BOOT_CHECK("apply low sets the absent env default",
                   boot_block_tree_cache_limits_apply_class(
                       HW_PROFILE_RAM_LOW) &&
                   bbtc_boot_env_is(k_cap_env, "67108864"));
    unsetenv(k_cap_env);
    BBTC_BOOT_CHECK("apply medium fills the absent default (128 MiB)",
                   boot_block_tree_cache_limits_apply_class(
                       HW_PROFILE_RAM_MEDIUM) &&
                   bbtc_boot_env_is(k_cap_env, "134217728"));
    unsetenv(k_cap_env);

    /* ── 3. an existing env var is never overridden ─────────── */
    setenv(k_cap_env, "999", 1);
    BBTC_BOOT_CHECK("apply medium never overrides an operator cap",
                   boot_block_tree_cache_limits_apply_class(
                       HW_PROFILE_RAM_MEDIUM) &&
                   bbtc_boot_env_is(k_cap_env, "999"));
    unsetenv(k_cap_env);

    /* ── 4. HIGH applies nothing ────────────────────────────── */
    BBTC_BOOT_CHECK("apply high leaves env untouched",
                   boot_block_tree_cache_limits_apply_class(
                       HW_PROFILE_RAM_HIGH) &&
                   bbtc_boot_env_absent(k_cap_env));

    /* ── 5. helper class defaults; HIGH keeps the old literal ── */
    BBTC_BOOT_CHECK("helper low default is 64 MiB",
                   boot_block_tree_cache_size_for_class(HW_PROFILE_RAM_LOW) ==
                       (size_t)(64LL << 20));
    BBTC_BOOT_CHECK("helper medium default is 128 MiB",
                   boot_block_tree_cache_size_for_class(
                       HW_PROFILE_RAM_MEDIUM) == (size_t)(128LL << 20));
    BBTC_BOOT_CHECK("helper high default is the unchanged 256<<20 literal",
                   boot_block_tree_cache_size_for_class(HW_PROFILE_RAM_HIGH) ==
                       (size_t)(256 << 20));
    BBTC_BOOT_CHECK("empty env falls back to the class default",
                   setenv(k_cap_env, "", 1) == 0 &&
                   boot_block_tree_cache_size_for_class(HW_PROFILE_RAM_LOW) ==
                       (size_t)(64LL << 20));
    BBTC_BOOT_CHECK("unparsable env falls back to the class default",
                   setenv(k_cap_env, "not-a-number", 1) == 0 &&
                   boot_block_tree_cache_size_for_class(HW_PROFILE_RAM_LOW) ==
                       (size_t)(64LL << 20));
    unsetenv(k_cap_env);

    /* ── 6. an explicit env always wins, for every class ────── */
    BBTC_BOOT_CHECK("explicit operator env wins over the low default",
                   setenv(k_cap_env, "104857600", 1) == 0 &&
                   boot_block_tree_cache_size_for_class(HW_PROFILE_RAM_LOW) ==
                       (size_t)104857600);
    BBTC_BOOT_CHECK("explicit operator env wins over the medium default",
                   boot_block_tree_cache_size_for_class(
                       HW_PROFILE_RAM_MEDIUM) == (size_t)104857600);
    BBTC_BOOT_CHECK("explicit operator env wins over the high default",
                   boot_block_tree_cache_size_for_class(HW_PROFILE_RAM_HIGH) ==
                       (size_t)104857600);

    /* ── 7. both open sites share ONE helper ──────────────────
     * boot.c and boot_wallet_cutover_startup.c call
     * boot_block_tree_cache_size(); two reads through it (one per open
     * order) must agree with each other and with the class-explicit
     * resolver under the same env, so the two sites cannot drift. */
    size_t site_a = boot_block_tree_cache_size();
    size_t site_b = boot_block_tree_cache_size();
    BBTC_BOOT_CHECK("both open-site reads agree",
                   site_a == site_b);
    BBTC_BOOT_CHECK("open-site read matches the class-explicit resolver",
                   site_a == boot_block_tree_cache_size_for_class(
                                 hw_profile_ram_class_of(
                                     hw_profile_ram_bytes())));
    unsetenv(k_cap_env);

    return failures;
}
