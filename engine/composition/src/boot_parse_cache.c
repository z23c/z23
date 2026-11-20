/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Parse-cache budget boot adapter — same shape as boot_net_budgets.c
 * (lifted out of boot_services.c to keep the composition root under its
 * line ceiling).
 *
 * engine/modules/storage/src/block_parse_cache.c reads
 * ZCL_PARSE_CACHE_MAX_BYTES ONCE, lazily, on the first cache use (the same
 * pthread_once as its mem-pressure sink registration), so a boot-time
 * setenv sizes the ring for the whole run without any storage init hook —
 * and the storage module stays untouched. The flat engine default
 * (128 MiB) is the right catch-up ceiling on a HIGH-RAM box but
 * overshoots a small node's steady state, so LOW and MEDIUM get explicit
 * defaults here; HIGH sets nothing and keeps byte-identical behavior.
 *
 * Ordering: this adapter registers right after net_budgets and BEFORE
 * boot_start_mempool_limits_service() runs its zcl_service_kernel_start_
 * all, so the kernel starts it there and the default is in the
 * environment long before a staged-sync stage can touch the cache. */

#include "config/boot_parse_cache.h"
#include "config/boot_internal.h"
#include "platform/environment_compat.h"
#include "util/boot_phase.h"

#include <stdio.h>
#include <stdlib.h>

#define BOOT_PARSE_CACHE_LOW_BYTES    (64LL * 1024 * 1024)   /* 64 MiB */
#define BOOT_PARSE_CACHE_MEDIUM_BYTES (128LL * 1024 * 1024) /* 128 MiB */

bool boot_parse_cache_limits_for_class(enum hw_profile_ram_class cls,
                                       struct boot_parse_cache_limits *out)
{
    if (!out)
        return false;
    switch (cls) {
    case HW_PROFILE_RAM_LOW:
        out->max_bytes = BOOT_PARSE_CACHE_LOW_BYTES;
        return true;
    case HW_PROFILE_RAM_MEDIUM:
        out->max_bytes = BOOT_PARSE_CACHE_MEDIUM_BYTES;
        return true;
    case HW_PROFILE_RAM_HIGH:
        return false;
    }
    return false;
}

static bool boot_parse_cache_set_default(const char *name, int64_t bytes)
{
    if (getenv(name) != NULL)
        return true; /* explicit operator env always wins */
    char value[32];
    snprintf(value, sizeof(value), "%lld", (long long)bytes);
    if (platform_environment_set(name, value, 0) != 0) {
        /* This service registers OPTIONAL: a setenv failure continues boot
         * with the engine default standing, so the message must not claim
         * a boot refusal that the service kernel will not perform. */
        fprintf(stderr,
                "[boot] parse_cache: setenv %s=%s failed; continuing with "
                "engine default\n",
                name, value);
        return false;
    }
    return true;
}

bool boot_parse_cache_limits_apply_class(enum hw_profile_ram_class cls)
{
    struct boot_parse_cache_limits limits;
    if (!boot_parse_cache_limits_for_class(cls, &limits))
        return true; /* HIGH: engine default stands */
    return boot_parse_cache_set_default("ZCL_PARSE_CACHE_MAX_BYTES",
                                        limits.max_bytes);
}

static bool boot_parse_cache_start(void *ctx)
{
    (void)ctx;
    const enum hw_profile_ram_class cls =
        hw_profile_ram_class_of(hw_profile_ram_bytes());
    if (!boot_parse_cache_limits_apply_class(cls))
        return false;
    /* Report the APPLIED ceiling (env readback in MiB), not the decided
     * one: an operator override must be visible as such on this line. */
    const char *cls_name = cls == HW_PROFILE_RAM_LOW     ? "low"
                           : cls == HW_PROFILE_RAM_MEDIUM ? "medium"
                                                          : "high";
    struct boot_parse_cache_limits limits;
    if (boot_parse_cache_limits_for_class(cls, &limits)) {
        const char *env = getenv("ZCL_PARSE_CACHE_MAX_BYTES");
        long long mib = env ? strtoll(env, NULL, 10) >> 20
                            : (long long)(limits.max_bytes >> 20);
        printf("Parse cache budget started (ram=%s parse_cache_max=%lldMiB"
               "%s)\n",
               cls_name, mib, env ? " (override)" : "");
    } else
        printf("Parse cache budget started (ram=%s defaults=engine)\n",
               cls_name);
    return true;
}

static void boot_parse_cache_stop(void *ctx)
{
    (void)ctx;
}

bool boot_start_parse_cache_service(struct boot_svc_ctx *svc)
{
    const struct zcl_service_spec parse_cache_spec = {
        .name = "parse_cache",
        .start = boot_parse_cache_start,
        .stop = boot_parse_cache_stop,
        .ctx = svc,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    /* One failure path covers both a NULL svc and a refused registration:
     * the spec fields are inert until the kernel reads them. */
    if (!svc || !zcl_service_kernel_register(&svc->service_kernel,
                                             &parse_cache_spec)) {
        fprintf(stderr,
                "[boot] parse_cache: service registration failed\n");
        return boot_step_fail("parse_cache_service");
    }
    return true;
}
