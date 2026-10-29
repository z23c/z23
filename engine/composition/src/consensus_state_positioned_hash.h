/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Streaming SHA3-256 of a positioned file, shared by the replay receipt and
 * the snapshot export proof so both bind the same running-binary digest. */

#ifndef ZCL_CONSENSUS_STATE_POSITIONED_HASH_H
#define ZCL_CONSENSUS_STATE_POSITIONED_HASH_H

#include <stdbool.h>
#include <stdint.h>

struct platform_positioned_file;
struct sha3_256_ctx;

/* Stream exactly `size` bytes of `file` into `ctx`; false on any short read. */
bool consensus_state_hash_positioned_file(struct platform_positioned_file *file,
                                          uint64_t size,
                                          struct sha3_256_ctx *ctx);

#endif /* ZCL_CONSENSUS_STATE_POSITIONED_HASH_H */
