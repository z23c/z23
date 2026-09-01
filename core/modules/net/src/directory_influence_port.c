/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directory_influence_port — registration + accessors for the seam declared
 * in net/directory_influence_port.h. One atomic pointer, no locks: the port
 * is installed once by the composition root before any P2P thread starts and
 * is read from every dial path afterwards. */

#include "net/directory_influence_port.h"

#include <stdatomic.h>
#include <stddef.h>

static const struct directory_influence_port *_Atomic g_port;

void directory_influence_port_set(const struct directory_influence_port *port)
{
    atomic_store_explicit(&g_port, port, memory_order_release);
}

enum directory_influence_verdict directory_influence_port_verdict(void)
{
    const struct directory_influence_port *p =
        atomic_load_explicit(&g_port, memory_order_acquire);
    if (!p || !p->verdict)
        return DIRECTORY_INFLUENCE_UNGOVERNED;
    enum directory_influence_verdict v = p->verdict();
    /* Total: an out-of-range answer from a mis-wired implementation is read
     * as UNGOVERNED rather than silently meaning something. */
    if (v != DIRECTORY_INFLUENCE_GRANTED && v != DIRECTORY_INFLUENCE_WITHHELD)
        return DIRECTORY_INFLUENCE_UNGOVERNED;
    return v;
}

bool directory_influence_port_admits(void)
{
    return directory_influence_port_verdict() != DIRECTORY_INFLUENCE_WITHHELD;
}

bool directory_influence_port_admits_entry(int32_t entry_final_height,
                                           bool entry_is_root)
{
    const struct directory_influence_port *p =
        atomic_load_explicit(&g_port, memory_order_acquire);
    if (!p || !p->admit_entry)
        return directory_influence_port_admits();
    return p->admit_entry(entry_final_height, entry_is_root);
}
