/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Owner-bound distributed replication-status lifecycle. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_DHT_REPLICATION_H
#define ZCL_CONFIG_BOOT_ZCODE_DHT_REPLICATION_H

#include <stdint.h>

struct rpc_table;

void boot_zcode_dht_replication_public_tick(uint64_t monotonic_s);
void boot_zcode_dht_replication_public_reset(void);
void boot_zcode_dht_replication_register_rpc(struct rpc_table *table);

#ifdef ZCL_TESTING
#include "vcs/zcode_dht_service.h"

/* Hermetic composition-root seam. Production builds call the boot-owned DHT
 * adapters directly; tests replace only child lifecycle and monotonic time. */
struct boot_zcode_dht_replication_test_backend {
    void *ctx;
    struct vcs_zcode_dht_time (*now)(void *ctx);
    bool (*begin)(void *ctx,
                  const struct vcs_zcode_dht_record_selector *selector,
                  struct vcs_zcode_dht_time now, uint64_t *operation_id,
                  uint64_t *generation);
    bool (*poll)(void *ctx, uint64_t operation_id, uint64_t generation,
                 struct vcs_zcode_dht_time now,
                 struct vcs_zcode_dht_record_discovery_result *out);
    bool (*cancel)(void *ctx, uint64_t operation_id, uint64_t generation);
};

void boot_zcode_dht_replication_test_set_backend(
    const struct boot_zcode_dht_replication_test_backend *backend);
#endif

#endif /* ZCL_CONFIG_BOOT_ZCODE_DHT_REPLICATION_H */
