/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Resident diagnostics dispatch trampoline + controller-level state.
 *
 * Two resident concerns that must NOT live in the swap-eligible
 * diagnostics_registry.c (a generation .so recompiles that TU and would get its
 * own zero-initialized copies):
 *
 *   1. The boot-populated controller state (main_state + datadir). The registry's
 *      dumpers read it through diag_datadir() / diag_main_state(); keeping the
 *      storage resident means a hot-swapped dumper still sees the LIVE boot state.
 *
 *   2. The `dumpstate` hot-swap trampoline: the atomic provider slot, the public
 *      diag_rpc_dumpstate entry the RPC surface registers, and the dev-only
 *      replace API. A generation .so re-points the provider (via
 *      diag_dumpstate_replace, an undefined symbol in the .so that binds to this
 *      resident copy under RTLD_LOCAL) at its recompiled diag_rpc_dumpstate_builtin.
 *
 * The atomic slot uses release-store / acquire-load publication. See
 * docs/work/HOTSWAP.md. */

#include "controllers/diagnostics_controller.h"
#include "controllers/diagnostics_internal.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>

/* ── Controller-level state (resident; boot-populated) ─────────────── */

static struct {
    struct main_state *main_state;
    char datadir[1024];
} g_diag = {0};

void diagnostics_controller_set_state(struct main_state *ms,
                                      const char *datadir)
{
    g_diag.main_state = ms;
    if (datadir) {
        snprintf(g_diag.datadir, sizeof(g_diag.datadir), "%s", datadir);
    }
    /* Arm the supervisor-stall debug-bundle auto-capture.  The observer
     * rate-limits and hands the write to one persistent worker which is
     * explicitly joined during diagnostics_controller_shutdown(). */
    debug_bundle_register_stall_observer();
}

bool diagnostics_controller_shutdown(void)
{
    if (!debug_bundle_shutdown()) {
        LOG_ERROR("diagnostics",
                  "capture ownership remains live; controller state retained");
        return false;
    }
    g_diag.main_state = NULL;
    return true;
}

const char *diag_datadir(void)
{
    return g_diag.datadir;
}

struct main_state *diag_main_state(void)
{
    return g_diag.main_state;
}

/* ── `dumpstate` hot-swap trampoline (resident) ────────────────────── */

/* NULL provider = use the resident built-in (diagnostics_registry.c). A dev
 * generation .so release-stores its recompiled diag_rpc_dumpstate_builtin here. */
static diag_dumpstate_fn _Atomic g_diag_dumpstate_provider = NULL;

bool diag_rpc_dumpstate(const struct json_value *params, bool help,
                        struct json_value *result)
{
    /* Acquire-load is unconditional (all builds): a single relaxed-cost atomic
     * pointer read. When no generation is loaded the slot is NULL and we fall
     * through to the resident built-in dumpstate. */
    diag_dumpstate_fn provider =
        atomic_load_explicit(&g_diag_dumpstate_provider, memory_order_acquire);
    if (provider)
        return provider(params, help, result);
    return diag_rpc_dumpstate_builtin(params, help, result);
}

#ifdef ZCL_DEV_BUILD
bool diag_dumpstate_replace(diag_dumpstate_fn fn)
{
    if (!fn)
        return false; /* raw-return-ok:predicate-null-input */
    atomic_store_explicit(&g_diag_dumpstate_provider, fn, memory_order_release);
    return true;
}
#endif
