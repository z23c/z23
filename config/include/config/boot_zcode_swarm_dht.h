/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Automatic DHT provider discovery for stalled package-swarm downloads.
 * A download that no connected peer advertises has no scheduler move
 * left; this lane recovers provider evidence from the DHT record store
 * and hands it back to the swarm engine through peer_offer().
 *
 * Driven from boot_zcode_dht_periodic()'s trailing tick block. Never
 * holds the swarm lock or the DHT lock across an adapter call; every
 * operation goes through the short critical-section adapters in
 * config/boot_zcode_dht.h or the internally-locked swarm engine API.
 */

#ifndef ZCL_CONFIG_BOOT_ZCODE_SWARM_DHT_H
#define ZCL_CONFIG_BOOT_ZCODE_SWARM_DHT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Advance the discovery lane at monotonic second `now_mono`. Safe to
 * call before hosting is up: with no swarm engine registered it is a
 * quiet no-op. */
void boot_zcode_swarm_discovery_tick(uint64_t now_mono);

/* ── test-only controls ────────────────────────────────────────────
 * The adapters below normally resolve to boot_zcode_dht_* wrappers;
 * tests install stubs to script begin/poll/route outcomes and reset to
 * restore production wiring and clear lease state. */
struct boot_zcode_swarm_dht_ops {
  void *ctx;
  bool (*begin)(void *ctx, const uint8_t root[32], uint64_t now_mono,
                uint64_t *operation_id, uint64_t *generation);
  /* Returns the operation state; PENDING keeps the lease open. */
  int (*poll)(void *ctx, uint64_t operation_id, uint64_t generation,
              uint64_t now_mono);
  bool (*route)(void *ctx, const uint8_t root[32], uint64_t now_mono,
                uint64_t *known_peer_ids, size_t max, size_t *count_out);
};

/* Install stub ops (NULL restores production adapters and clears all
 * lease state). Test binaries only. */
void boot_zcode_swarm_dht_test_install(
    const struct boot_zcode_swarm_dht_ops *ops);

#endif /* ZCL_CONFIG_BOOT_ZCODE_SWARM_DHT_H */
