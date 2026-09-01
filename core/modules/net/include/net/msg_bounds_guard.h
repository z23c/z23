/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* msg_bounds_guard.h — shared P2P message-count bound check.
 *
 * Several wire-message handlers and deserializers begin by reading a
 * compact-size element count and rejecting the message if the count
 * exceeds a protocol cap (inv/headers/addr/notfound, compact-block tx
 * and index counts). The "if (count > max) { log; reject }" boilerplate
 * was copy-pasted across ~8 sites. This consolidates the bound check and
 * its rejection log into one place.
 *
 * The helper deliberately does NOT perform the reject itself — each call
 * site keeps full control of its own side effects (peer disconnect +
 * misbehave event + scoring for the network handlers; buffer free for
 * the deserializers) and then returns its own failure value. The helper
 * only answers "is this count over the cap?" and logs a uniform
 * diagnostic when it is. */

#ifndef ZCL_NET_MSG_BOUNDS_GUARD_H
#define ZCL_NET_MSG_BOUNDS_GUARD_H

#include <stdbool.h>
#include <stdint.h>

/* Returns true (after logging "<what> count N exceeds cap M[ from <peer>]"
 * to stderr under the given log domain) when count > max_count; returns
 * false otherwise, having logged nothing. `peer` is the peer addr_name for
 * the network handlers, or NULL for the node-less deserializers (compact
 * blocks), in which case the "from <peer>" suffix is omitted. */
bool msg_count_exceeds(const char *domain, const char *what,
                       uint64_t count, uint64_t max_count,
                       const char *peer);

#endif /* ZCL_NET_MSG_BOUNDS_GUARD_H */
