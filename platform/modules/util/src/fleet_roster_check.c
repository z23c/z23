/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The roster seam. See util/fleet_roster_check.h for the contract. One
 * static a decision reads, empty at start: a process nobody installed a
 * provider into has no fleet root and the roster gate stays unarmed. */

#include "util/fleet_roster_check.h"

#include <stdatomic.h>
#include <string.h>

#define ROSTER_WHY_NO_PROVIDER "fleetboard.roster_signature_invalid"

static struct zcl_fleet_roster_provider g_provider;
/* Published with release ordering after g_provider is written. Installs
 * happen at boot, before the lanes that read this exist. */
static _Atomic bool g_ready;

void zcl_fleet_roster_provider_install(
    const struct zcl_fleet_roster_provider *p)
{
    if (!p || !p->root) {
        atomic_store_explicit(&g_ready, false, memory_order_release);
        memset(&g_provider, 0, sizeof g_provider);
        return;
    }
    g_provider = *p;
    atomic_store_explicit(&g_ready, true, memory_order_release);
}

bool zcl_fleet_roster_provider_installed(void)
{
    return atomic_load_explicit(&g_ready, memory_order_acquire);
}

bool zcl_fleet_roster_root(uint8_t root[32], bool *present, bool *manager)
{
    if (present)
        *present = false;
    if (manager)
        *manager = false;
    if (!root || !present)
        return false;
    memset(root, 0, 32);
    if (!atomic_load_explicit(&g_ready, memory_order_acquire))
        return true; /* no provider: no root, which is a state */
    bool is_manager = false;
    if (!g_provider.root(root, present, &is_manager, g_provider.ctx)) {
        *present = false;
        memset(root, 0, 32);
        return false;
    }
    if (manager)
        *manager = *present && is_manager;
    return true;
}

bool zcl_fleet_roster_verify(const char *line, const uint8_t root[32],
                             enum zcl_fleet_root_state state, bool require,
                             uint8_t signer[32], uint8_t box[32], bool *sealed,
                             const char **why)
{
    uint8_t scratch[32];
    if (sealed)
        *sealed = false;
    if (why)
        *why = ROSTER_WHY_NO_PROVIDER;
    if (signer)
        memset(signer, 0, 32);
    if (box)
        memset(box, 0, 32);
    if (!line || !root || !signer ||
        !atomic_load_explicit(&g_ready, memory_order_acquire) ||
        !g_provider.verify)
        return false;
    return g_provider.verify(line, root, state, require, signer,
                             box ? box : scratch, sealed, why,
                             g_provider.ctx);
}

void zcl_fleet_roster_head(const uint8_t root[32], struct zcl_fleet_head *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof *out);
    if (!root || !atomic_load_explicit(&g_ready, memory_order_acquire) ||
        !g_provider.head)
        return; /* no provider, or none that revokes: nothing is revoked */
    g_provider.head(root, out, g_provider.ctx);
}

bool zcl_fleet_roster_each_line(void (*visit)(const char *line, void *user),
                                void *user)
{
    if (!visit || !atomic_load_explicit(&g_ready, memory_order_acquire) ||
        !g_provider.each_line)
        return true; /* nothing to visit is not a failure */
    return g_provider.each_line(visit, user, g_provider.ctx);
}

bool zcl_fleet_roster_endpoint(const char *line, const uint8_t root[32],
                               char *onion, size_t cap, bool *self)
{
    if (onion && cap)
        onion[0] = '\0';
    if (self)
        *self = false;
    if (!line || !root || !onion || !cap || !self ||
        !atomic_load_explicit(&g_ready, memory_order_acquire) ||
        !g_provider.endpoint)
        return false;
    return g_provider.endpoint(line, root, onion, cap, self, g_provider.ctx);
}
