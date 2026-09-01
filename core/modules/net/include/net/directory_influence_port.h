/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * directory_influence_port — the seam through which core/modules/net asks whether the
 * peer/name DIRECTORY is currently allowed to influence anything.
 *
 * The policy itself lives upstairs
 * (engine/services/include/services/directory_influence_policy.h) because it
 * reads the netsplit detector and the sync capability table, both of which
 * sit above lib/. core/modules/net declares what it needs; the composition root
 * registers the implementation at process start. Same one-way shape as
 * net/net_runtime_port.h — nothing in core/modules/net names an app/ symbol.
 *
 * Default when NOTHING is registered: UNGOVERNED, which every accessor here
 * treats as "influence permitted". That is a DELIBERATE departure from
 * net_runtime_port.h's blanket fail-closed rule, and the reason is that the
 * two ports guard different kinds of thing. net_runtime_port guards SERVING
 * STATE, where the wrong answer hands out unverified data. This port guards a
 * bounded, additive dial/resolution preference that can only ever RAISE a
 * candidate's standing and never exclude one. Defaulting it to "withheld"
 * would silently switch off directory preference in every binary that links
 * core/modules/net without the composition root — fuzz targets, standalone tools,
 * unit tests — with no signal at all, which is precisely the silent
 * behaviour change this codebase treats as the defect. So: unregistered
 * means UNGOVERNED and behaves exactly as the tree did before this port
 * existed; the live node always registers, and a registered policy that says
 * WITHHELD is obeyed.
 */

#ifndef ZCL_NET_DIRECTORY_INFLUENCE_PORT_H
#define ZCL_NET_DIRECTORY_INFLUENCE_PORT_H

#include <stdbool.h>
#include <stdint.h>

enum directory_influence_verdict {
    DIRECTORY_INFLUENCE_UNGOVERNED = 0, /* no policy registered */
    DIRECTORY_INFLUENCE_GRANTED    = 1,
    DIRECTORY_INFLUENCE_WITHHELD   = 2, /* degraded mode: SUSPECTED_NETSPLIT */
};

/* Implementations supplied by the composition root. Every member may be
 * NULL; each accessor degrades to the UNGOVERNED answer. */
struct directory_influence_port {
    /* The standing verdict. Must be side-effect free and callable from any
     * thread, including a P2P thread holding a lock. */
    enum directory_influence_verdict (*verdict)(void);
    /* Per-entry admission. `entry_final_height` is the height the directory
     * entry became final, negative when it never did; `entry_is_root` marks
     * the always-present roots (compiled seeds, addr gossip), which are
     * never gated. */
    bool (*admit_entry)(int32_t entry_final_height, bool entry_is_root);
};

/* Install the port. `port` is borrowed and must have static storage
 * duration; pass NULL to unregister (back to UNGOVERNED). */
void directory_influence_port_set(const struct directory_influence_port *port);

/* The standing verdict, or UNGOVERNED when nothing is registered. */
enum directory_influence_verdict directory_influence_port_verdict(void);

/* True unless a registered policy says WITHHELD. The one-line question a
 * dial/preference path asks. */
bool directory_influence_port_admits(void);

/* Per-entry admission; true unless a registered policy withholds this entry.
 * With no port registered, or no admit_entry implementation, falls back to
 * directory_influence_port_admits(). */
bool directory_influence_port_admits_entry(int32_t entry_final_height,
                                           bool entry_is_root);

#endif /* ZCL_NET_DIRECTORY_INFLUENCE_PORT_H */
