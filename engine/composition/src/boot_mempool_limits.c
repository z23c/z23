/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Mempool-limits boot adapter — lifted out of boot_services.c to keep that
 * composition-root file under the E1 line ceiling. The backend lock guard is
 * installed before the limits service starts or admission workers run.
 *
 * svc->service_kernel has exactly one registrant across the whole boot
 * path: mempool_limits. It is registered and started as the very first
 * step of app_init_services, immediately after the four
 * zcl_service_kernel_init() calls and before boot_register_process_block_hooks
 * / projection storage / network / runtime / frontend service registration —
 * i.e. it sits between BOOT_STAGE_DB_OPEN (already advanced before
 * app_init_services runs, see engine/composition/src/boot.c) and BOOT_STAGE_READY
 * (advanced after app_init_services returns true). Relocating the whole
 * register+start_all block into boot_start_mempool_limits_service() and
 * calling it from the same point in app_init_services preserves that
 * ordering exactly — the call site moves from an inline `if (svc->db_service)
 * { ... }` block to a single function call at the identical line position. */

#include "config/boot_mempool_limits.h"
#include "services/mempool_limits.h"
#include "storage/progress_store.h"
#include "util/boot_phase.h"
#include "validation/accept_to_mempool.h"
#include <stdatomic.h>
#include <stdio.h>

#ifdef ZCL_TESTING
static _Atomic(void (*)(void)) g_mempool_guard_attempt;
void boot_test_set_mempool_guard_attempt(void (*hook)(void))
{
    atomic_store(&g_mempool_guard_attempt, hook);
}
#endif

static void boot_mempool_guard_acquire(void)
{
#ifdef ZCL_TESTING
    void (*attempt)(void) = atomic_load(&g_mempool_guard_attempt);
    if (attempt) attempt();
#endif
    progress_store_tx_lock();
}

bool boot_install_mempool_backend_guard(void)
{
    static const struct mempool_backend_guard guard = {
        .acquire = boot_mempool_guard_acquire,
        .release = progress_store_tx_unlock,
    };
    return mempool_install_backend_guard(&guard);
}

static bool boot_mempool_limits_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->mempool)
        return false;

    struct mempool_limits_config ml_cfg;
    mempool_limits_config_defaults(&ml_cfg);
    struct zcl_result mr = mempool_limits_start(svc->mempool, &ml_cfg);
    if (!mr.ok) {
        fprintf(stderr, "[boot] %s:%d mempool_limits_start failed: code=%d %s\n",
                mr.source_file, mr.source_line, mr.code, mr.message);
        return false;
    }

    printf("Mempool limits started (max=%lldMB max_tx=%lld)\n",
           (long long)(ml_cfg.max_bytes >> 20),
           (long long)ml_cfg.max_tx_count);
    return true;
}

static void boot_mempool_limits_stop(void *ctx)
{
    (void)ctx;
    mempool_limits_stop();
}

bool boot_start_mempool_limits_service(struct boot_svc_ctx *svc)
{
    if (!boot_install_mempool_backend_guard())
        return boot_step_fail("mempool_backend_guard");
    if (svc->db_service) {
        const struct zcl_service_spec mempool_limits_spec = {
            .name = "mempool_limits",
            .start = boot_mempool_limits_start,
            .stop = boot_mempool_limits_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        };
        if (!zcl_service_kernel_register(&svc->service_kernel,
                                         &mempool_limits_spec)) {
            fprintf(stderr, "FATAL: failed to register boot services\n");
            return boot_step_fail("mempool_limits_service");
        }
        if (!zcl_service_kernel_start_all(&svc->service_kernel)) {
            fprintf(stderr, "FATAL: failed to start required boot services\n");
            return boot_step_fail("mempool_limits_service");
        }
    }
    return true;
}
