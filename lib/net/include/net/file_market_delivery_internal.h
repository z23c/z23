/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal helpers shared between the zfileget.v3 delivery split files.
 * NOT part of the public API — only included by file_market_delivery*.c. */

#ifndef ZCL_NET_FILE_MARKET_DELIVERY_INTERNAL_H
#define ZCL_NET_FILE_MARKET_DELIVERY_INTERNAL_H

#include "net/file_market_delivery.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Zero-length or all-zero byte ranges mean "field absent" throughout the
 * delivery protocol. */
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
