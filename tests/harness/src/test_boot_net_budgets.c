/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot_net_budgets.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BNB_CHECK(name, expr) do {                                      \
    printf("boot_net_budgets: %s... ", (name));                         \
    if (expr) printf("OK\n");                                           \
    else { printf("FAIL\n"); failures++; }                              \
} while (0)

static const char k_send_env[] = "ZCL_MAX_SENDBUFFER_TOTAL_BYTES";
static const char k_recv_env[] = "ZCL_MAX_RECVBUFFER_TOTAL_BYTES";

/* Env holds exactly `want` (non-NULL, byte-equal). */
static bool bnb_env_is(const char *name, const char *want)
{
    const char *value = getenv(name);
    return value != NULL && strcmp(value, want) == 0;
}

static bool bnb_env_absent(const char *name)
{
    return getenv(name) == NULL;
}

static void bnb_env_clear(void)
{
    unsetenv(k_send_env);
    unsetenv(k_recv_env);
}

int test_boot_net_budgets(void)
{
    int failures = 0;
    struct boot_net_budgets budgets;

    /* ── 1. pure per-class decision ─────────────────────────── */
    BNB_CHECK("low decision is 128 MiB send / 64 MiB recv",
              boot_net_budgets_for_class(HW_PROFILE_RAM_LOW, &budgets) &&
              budgets.send_total_bytes == (int64_t)(128LL << 20) &&
              budgets.recv_total_bytes == (int64_t)(64LL << 20));
    BNB_CHECK("medium decision is 256 MiB send / 128 MiB recv",
              boot_net_budgets_for_class(HW_PROFILE_RAM_MEDIUM, &budgets) &&
              budgets.send_total_bytes == (int64_t)(256LL << 20) &&
              budgets.recv_total_bytes == (int64_t)(128LL << 20));
    BNB_CHECK("high decision refuses (sets nothing)",
              !boot_net_budgets_for_class(HW_PROFILE_RAM_HIGH, &budgets));
    BNB_CHECK("null out refuses",
              !boot_net_budgets_for_class(HW_PROFILE_RAM_LOW, NULL));

    /* ── 2. apply sets defaults only when the env var is absent ── */
    bnb_env_clear();
    BNB_CHECK("apply low sets both absent env defaults",
              boot_net_budgets_apply_class(HW_PROFILE_RAM_LOW) &&
              bnb_env_is(k_send_env, "134217728") &&
              bnb_env_is(k_recv_env, "67108864"));
    bnb_env_clear();

    /* ── 3. an existing env var is never overridden ─────────── */
    setenv(k_send_env, "999", 1);
    setenv(k_recv_env, "555", 1);
    BNB_CHECK("apply medium never overrides existing env",
              boot_net_budgets_apply_class(HW_PROFILE_RAM_MEDIUM) &&
              bnb_env_is(k_send_env, "999") &&
              bnb_env_is(k_recv_env, "555"));
    unsetenv(k_recv_env);
    BNB_CHECK("apply medium fills only the absent side",
              boot_net_budgets_apply_class(HW_PROFILE_RAM_MEDIUM) &&
              bnb_env_is(k_send_env, "999") &&
              bnb_env_is(k_recv_env, "134217728"));
    bnb_env_clear();

    /* ── 4. HIGH applies nothing ────────────────────────────── */
    bnb_env_clear();
    BNB_CHECK("apply high leaves env untouched",
              boot_net_budgets_apply_class(HW_PROFILE_RAM_HIGH) &&
              bnb_env_absent(k_send_env) &&
              bnb_env_absent(k_recv_env));
    bnb_env_clear();

    return failures;
}
