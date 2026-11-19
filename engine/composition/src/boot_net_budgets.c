/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Network-budget boot adapter — lifted out of boot_services.c to keep that
 * composition-root file under the E1 line ceiling (same pattern as
 * boot_mempool_limits.c).
 *
 * core/modules/net/src/net.c re-reads ZCL_MAX_SENDBUFFER_TOTAL_BYTES /
 * ZCL_MAX_RECVBUFFER_TOTAL_BYTES from the environment on every budget
 * check, so a boot-time setenv binds the peer path's worst case without any
 * core init hook — and core/ stays untouched. The kernel/core flat defaults
 * (512 MiB send + 256 MiB recv = 768 MiB worst case) exceed what a
 * small-RAM node can hold, so LOW and MEDIUM get tightened defaults here;
 * HIGH sets nothing and keeps byte-identical behavior.
 *
 * Ordering: this file's adapter registers BEFORE boot_start_mempool_limits_
 * service() runs its zcl_service_kernel_start_all, so the kernel starts
 * net_budgets first and the defaults are in the environment before
 * admission workers or any network service registration runs. */

#include "config/boot_net_budgets.h"
#include "config/boot_internal.h"
#include "platform/environment_compat.h"
#include "util/boot_phase.h"

#include <stdio.h>
#include <stdlib.h>

#define BOOT_NET_SEND_LOW_BYTES (128LL * 1024 * 1024)    /* 128 MiB */
#define BOOT_NET_RECV_LOW_BYTES (64LL * 1024 * 1024)     /* 64 MiB */
#define BOOT_NET_SEND_MEDIUM_BYTES (256LL * 1024 * 1024) /* 256 MiB */
#define BOOT_NET_RECV_MEDIUM_BYTES (128LL * 1024 * 1024) /* 128 MiB */

bool boot_net_budgets_for_class(enum hw_profile_ram_class cls,
                                struct boot_net_budgets *out)
{
    if (!out)
        return false;
    switch (cls) {
    case HW_PROFILE_RAM_LOW:
        out->send_total_bytes = BOOT_NET_SEND_LOW_BYTES;
        out->recv_total_bytes = BOOT_NET_RECV_LOW_BYTES;
        return true;
    case HW_PROFILE_RAM_MEDIUM:
        out->send_total_bytes = BOOT_NET_SEND_MEDIUM_BYTES;
        out->recv_total_bytes = BOOT_NET_RECV_MEDIUM_BYTES;
        return true;
    case HW_PROFILE_RAM_HIGH:
        return false;
    }
    return false;
}

static const char *boot_net_budgets_class_name(enum hw_profile_ram_class cls)
{
    switch (cls) {
    case HW_PROFILE_RAM_LOW: return "low";
    case HW_PROFILE_RAM_MEDIUM: return "medium";
    case HW_PROFILE_RAM_HIGH: return "high";
    }
    return "unknown";
}

/* One env row: the net.c budget variable and which budget fills it. */
struct boot_net_budget_row {
    const char *name;
    int64_t bytes;
};

static bool boot_net_budgets_set_default(const struct boot_net_budget_row *row)
{
    if (getenv(row->name) != NULL)
        return true; /* explicit operator env always wins */
    char value[32];
    snprintf(value, sizeof(value), "%lld", (long long)row->bytes);
    if (platform_environment_set(row->name, value, 0) != 0) {
        fprintf(stderr,
                "[boot] net_budgets: setenv %s=%s failed; refusing to boot "
                "with an unbudgeted peer path\n",
                row->name, value);
        return false;
    }
    return true;
}

bool boot_net_budgets_apply_class(enum hw_profile_ram_class cls)
{
    struct boot_net_budgets budgets;
    if (!boot_net_budgets_for_class(cls, &budgets))
        return true; /* HIGH: kernel/core defaults stand */

    const struct boot_net_budget_row rows[] = {
        { "ZCL_MAX_SENDBUFFER_TOTAL_BYTES", budgets.send_total_bytes },
        { "ZCL_MAX_RECVBUFFER_TOTAL_BYTES", budgets.recv_total_bytes },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
        if (!boot_net_budgets_set_default(&rows[i]))
            return false;
    return true;
}

static bool boot_net_budgets_start(void *ctx)
{
    (void)ctx;
    const enum hw_profile_ram_class cls =
        hw_profile_ram_class_of(hw_profile_ram_bytes());
    if (!boot_net_budgets_apply_class(cls))
        return false;
    struct boot_net_budgets budgets;
    if (boot_net_budgets_for_class(cls, &budgets))
        printf("Net budgets started (ram=%s send_total=%lldMiB "
               "recv_total=%lldMiB)\n",
               boot_net_budgets_class_name(cls),
               (long long)(budgets.send_total_bytes >> 20),
               (long long)(budgets.recv_total_bytes >> 20));
    else
        printf("Net budgets started (ram=%s defaults=kernel)\n",
               boot_net_budgets_class_name(cls));
    return true;
}

static void boot_net_budgets_stop(void *ctx)
{
    (void)ctx;
}

bool boot_start_net_budgets_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return boot_step_fail("net_budgets_service");
    const struct zcl_service_spec net_budgets_spec = {
        .name = "net_budgets",
        .start = boot_net_budgets_start,
        .stop = boot_net_budgets_stop,
        .ctx = svc,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    if (!zcl_service_kernel_register(&svc->service_kernel, &net_budgets_spec)) {
        fprintf(stderr,
                "[boot] net_budgets: zcl_service_kernel_register failed\n");
        return boot_step_fail("net_budgets_service");
    }
    return true;
}
