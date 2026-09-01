/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Generation-bound chain authorization cache for the ZCODE DHT. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_DHT_CHAIN_H
#define ZCL_CONFIG_BOOT_ZCODE_DHT_CHAIN_H

#include "vcs/zcode_dht_delegation.h"

#include <stdbool.h>
#include <stddef.h>

struct boot_svc_ctx;
struct json_value;

/* Slow path. Database lookup and ancestry work happen on the caller's thread,
 * which must hold no DHT mutex. A successful verdict is cached only if both
 * external generations still match after the work. */
bool boot_zcode_dht_chain_authorize(
    struct boot_svc_ctx *svc,
    const struct vcs_zcode_dht_delegation *delegation);

/* Fixed-memory callback installed into the live service. Safe under the DHT
 * mutex: it performs atomic generation reads plus a sorted cache lookup only. */
bool boot_zcode_dht_chain_cached(void *ctx,
    const struct vcs_zcode_dht_delegation *delegation);
bool boot_zcode_dht_chain_epoch_current(void);

void boot_zcode_dht_chain_dump_json(struct json_value *out);
void boot_zcode_dht_chain_reset(void);

#endif /* ZCL_CONFIG_BOOT_ZCODE_DHT_CHAIN_H */
