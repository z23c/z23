/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot_parse_cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BPC_BOOT_CHECK(name, expr) do {                                 \
    printf("boot_parse_cache: %s... ", (name));                         \
    if (expr) printf("OK\n");                                           \
    else { printf("FAIL\n"); failures++; }                              \
} while (0)

static const char k_ceiling_env[] = "ZCL_PARSE_CACHE_MAX_BYTES";

/* Env holds exactly `want` (non-NULL, byte-equal). */
static bool bpc_boot_env_is(const char *name, const char *want)
{
    const char *value = getenv(name);
    return value != NULL && strcmp(value, want) == 0;
}

static bool bpc_boot_env_absent(const char *name)
{
    return getenv(name) == NULL;
}

int test_boot_parse_cache(void)
{
    int failures = 0;
    struct boot_parse_cache_limits limits;

    /* ── 1. pure per-class decision ─────────────────────────── */
    BPC_BOOT_CHECK("low decision is a 64 MiB parse ceiling",
                   boot_parse_cache_limits_for_class(HW_PROFILE_RAM_LOW,
                                                     &limits) &&
                   limits.max_bytes == (int64_t)(64LL << 20));
    BPC_BOOT_CHECK("medium decision is a 128 MiB parse ceiling",
                   boot_parse_cache_limits_for_class(HW_PROFILE_RAM_MEDIUM,
                                                     &limits) &&
                   limits.max_bytes == (int64_t)(128LL << 20));
    BPC_BOOT_CHECK("high decision refuses (sets nothing)",
                   !boot_parse_cache_limits_for_class(HW_PROFILE_RAM_HIGH,
                                                      &limits));
    BPC_BOOT_CHECK("null out refuses",
                   !boot_parse_cache_limits_for_class(HW_PROFILE_RAM_LOW,
                                                      NULL));

    /* ── 2. apply sets the default only when the env var is absent ── */
    unsetenv(k_ceiling_env);
    BPC_BOOT_CHECK("apply low sets the absent env default",
                   boot_parse_cache_limits_apply_class(HW_PROFILE_RAM_LOW) &&
                   bpc_boot_env_is(k_ceiling_env, "67108864"));
    unsetenv(k_ceiling_env);

    /* ── 3. an existing env var is never overridden ─────────── */
    setenv(k_ceiling_env, "999", 1);
    BPC_BOOT_CHECK("apply medium never overrides an operator ceiling",
                   boot_parse_cache_limits_apply_class(
                       HW_PROFILE_RAM_MEDIUM) &&
                   bpc_boot_env_is(k_ceiling_env, "999"));
    unsetenv(k_ceiling_env);
    BPC_BOOT_CHECK("apply medium fills the absent default (128 MiB)",
                   boot_parse_cache_limits_apply_class(
                       HW_PROFILE_RAM_MEDIUM) &&
                   bpc_boot_env_is(k_ceiling_env, "134217728"));
    unsetenv(k_ceiling_env);

    /* ── 4. HIGH applies nothing ────────────────────────────── */
    BPC_BOOT_CHECK("apply high leaves env untouched",
                   boot_parse_cache_limits_apply_class(HW_PROFILE_RAM_HIGH) &&
                   bpc_boot_env_absent(k_ceiling_env));

    return failures;
}
