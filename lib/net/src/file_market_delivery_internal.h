/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared internals for the paid-file delivery gate, which is split by
 * WHICH SIDE OF THE WIRE the code stands on:
 *
 *   file_market_delivery.c       — the serving side. Wire codec, the
 *                                  injected authorize/load/moderation
 *                                  ports, and the prepare/serve gate that
 *                                  decides whether this node hands over
 *                                  bytes at all.
 *   file_market_delivery_fetch.c — the buying side. Asks another node for
 *                                  a chunk over an fs_session or a fresh
 *                                  endpoint connection. It holds no
 *                                  handlers and makes no hosting policy
 *                                  decision, because a buyer has none to
 *                                  make.
 *
 * Only the leaf predicates both sides need live here. Nothing stateful
 * does: the handler table stays private to the serving side so a fetch
 * path can never read, still less answer, this node's hosting policy. */

#ifndef ZCL_NET_FILE_MARKET_DELIVERY_INTERNAL_H
#define ZCL_NET_FILE_MARKET_DELIVERY_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* True when the buffer exists and is not all zero. Both sides treat an
 * all-zero id, key, or digest as absent rather than as a value, so a
 * zero-filled struct can never authenticate or address anything. */
static inline bool delivery_bytes_nonzero(const uint8_t *bytes, size_t len)
{
    uint8_t any = 0;
    if (!bytes)
        return false;
    for (size_t i = 0; i < len; i++)
        any |= bytes[i];
    return any != 0;
}

#endif /* ZCL_NET_FILE_MARKET_DELIVERY_INTERNAL_H */
