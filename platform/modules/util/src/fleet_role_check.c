/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The role-check seam. See util/fleet_role_check.h for the contract.
 *
 * There is exactly one static here that a decision reads, and it starts
 * empty: a fresh process refuses every foreign-signed byte until the layer
 * that can see the signed grant store installs the thing that answers.
 * The refusal is announced once rather than per row, because a node whose
 * checker never got installed would otherwise drown its own log in the one
 * fact it needs the operator to read.
 */

#include "util/fleet_role_check.h"

#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define ROLE_DOMAIN "fleet.roles"

static struct zcl_fleet_role_checker g_checker;
/* Published with release ordering AFTER g_checker is written, and read with
 * acquire ordering before it, so a reader that sees `true` sees the whole
 * struct. Installs happen at boot, before the lanes that read this exist. */
static _Atomic bool g_ready;
static _Atomic bool g_warned;

void zcl_fleet_role_checker_install(const struct zcl_fleet_role_checker *c)
{
    if (!c || !c->allow) {
        atomic_store_explicit(&g_ready, false, memory_order_release);
        memset(&g_checker, 0, sizeof g_checker);
        return;
    }
    g_checker = *c;
    atomic_store_explicit(&g_ready, true, memory_order_release);
}

bool zcl_fleet_role_checker_installed(void)
{
    return atomic_load_explicit(&g_ready, memory_order_acquire);
}

bool zcl_fleet_role_allows(const uint8_t key[32], const char *leaf,
                           const char *kind, char *why, size_t why_cap)
{
    if (why && why_cap)
        why[0] = '\0';
    if (!key || !leaf) {
        if (why && why_cap)
            (void)snprintf(why, why_cap,
                           "REFUSED role: a role check needs a key and a leaf");
        return false;
    }
    if (!atomic_load_explicit(&g_ready, memory_order_acquire)) {
        if (!atomic_exchange_explicit(&g_warned, true, memory_order_relaxed))
            LOG_WARN(ROLE_DOMAIN,
                     "no role checker installed; refusing %s and every other "
                     "leaf that carries another machine's signature", leaf);
        if (why && why_cap)
            (void)snprintf(why, why_cap,
                           "REFUSED role: no role checker installed; refusing "
                           "%s", leaf);
        return false;
    }
    return g_checker.allow(key, leaf, kind, why, why_cap, g_checker.ctx);
}

bool zcl_fleet_role_grandfather(const uint8_t key[32], const char *origin)
{
    if (!key || !origin)
        return false;
    if (!atomic_load_explicit(&g_ready, memory_order_acquire))
        return false;
    if (!g_checker.grandfather)
        return false;
    return g_checker.grandfather(key, origin, g_checker.ctx);
}

#ifdef ZCL_TESTING
static bool role_permissive(const uint8_t key[32], const char *leaf,
                            const char *kind, char *why, size_t why_cap,
                            void *ctx)
{
    (void)key;
    (void)leaf;
    (void)kind;
    (void)why;
    (void)why_cap;
    (void)ctx;
    return true;
}

void zcl_fleet_role_checker_install_permissive_for_testing(void)
{
    struct zcl_fleet_role_checker c = { .allow = role_permissive,
                                        .ctx = NULL,
                                        .name = "test-permissive" };
    zcl_fleet_role_checker_install(&c);
}
#endif
