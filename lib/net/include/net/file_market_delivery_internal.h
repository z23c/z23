/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal helpers shared between the zfileget.v3 delivery split files.
 * NOT part of the public API — only included by file_market_delivery*.c. */

#ifndef ZCL_NET_FILE_MARKET_DELIVERY_INTERNAL_H
#define ZCL_NET_FILE_MARKET_DELIVERY_INTERNAL_H

#include "base/bytes.h"
#include "net/file_market_delivery.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Zero-length or all-zero byte ranges mean "field absent" throughout the
 * delivery protocol: zcl_bytes_any_set is the test for "field present". */

#endif /* ZCL_NET_FILE_MARKET_DELIVERY_INTERNAL_H */
