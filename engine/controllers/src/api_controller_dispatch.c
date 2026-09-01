/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Resident hot-swap trampoline for REST dynamic dispatch.
 *
 * The REST route tables + built-in dispatch live in the swap-eligible
 * api_controller_routes.c. This TU is deliberately NOT swap-eligible: it owns
 * the atomic provider pointer, the dev-only replace API, and the public
 * dispatch entry the HTTPS/onion frontends call. Keeping them resident is what
 * makes a hot-swap actually take effect — a generation .so re-points THIS
 * provider (via api_resource_dispatch_replace, an undefined symbol in the .so
 * that binds to this resident copy under RTLD_LOCAL) at the .so's own
 * recompiled builtin, and the read path below picks it up on its next call.
 *
 * The atomic slot uses release-store / acquire-load publication: a worker
 * thread observes either the old or new provider, never a torn pointer, with
 * no lock on the hot path. See docs/work/HOTSWAP.md. */

#include "api_controller_internal.h"

#include <stdatomic.h>

/* NULL provider = use the resident built-in table. A dev generation .so
 * release-stores its recompiled api_resource_route_dispatch_builtin here. */
static api_resource_dispatch_fn _Atomic g_api_resource_dispatch_provider = NULL;

size_t api_resource_route_dispatch_dynamic(const char *method,
                                           const char *path,
                                           uint8_t *response,
                                           size_t response_max,
                                           bool *handled)
{
    /* Acquire-load is unconditional (all builds): a single relaxed-cost atomic
     * pointer read on the request path. When no generation is loaded the slot
     * is NULL and we fall through to the resident built-in. */
    api_resource_dispatch_fn provider =
        atomic_load_explicit(&g_api_resource_dispatch_provider,
                             memory_order_acquire);
    if (provider)
        return provider(method, path, response, response_max, handled);
    return api_resource_route_dispatch_builtin(method, path, response,
                                               response_max, handled);
}

#ifdef ZCL_DEV_BUILD
bool api_resource_dispatch_replace(api_resource_dispatch_fn fn)
{
    if (!fn)
        return false; /* raw-return-ok:predicate-null-input */
    atomic_store_explicit(&g_api_resource_dispatch_provider, fn,
                          memory_order_release);
    return true;
}
#endif
