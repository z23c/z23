/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Composition adapter for bounded DHT ACK possession proofs. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_DHT_POSSESSION_H
#define ZCL_CONFIG_BOOT_ZCODE_DHT_POSSESSION_H

#include "vcs/zcode_dht_service.h"

struct json_value;
struct vcs_package_store;

typedef void (*boot_zcode_dht_possession_apply_fn)(
    void *context, const uint8_t root[32], uint64_t proof_epoch, bool valid);
size_t boot_zcode_dht_possession_cycle(
    struct vcs_package_store *store,
    const struct vcs_zcode_dht_storage_ack_proof_request *requests,
    size_t request_count, uint64_t now_mono,
    boot_zcode_dht_possession_apply_fn apply, void *apply_context);
bool boot_zcode_dht_possession_current(
    struct vcs_package_store *store, const uint8_t root[32]);
void boot_zcode_dht_possession_dump_json(struct json_value *out,
                                         uint64_t now_mono);
void boot_zcode_dht_possession_append_json(struct json_value *out,
                                           uint64_t now_mono);
void boot_zcode_dht_possession_reset(void);

#endif /* ZCL_CONFIG_BOOT_ZCODE_DHT_POSSESSION_H */
