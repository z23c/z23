/* purpose: Validate bounded experimental profile artifacts for offline and startup callers. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_EXPERIMENTAL_PROFILE_H
#define ZCL_SERVICES_EXPERIMENTAL_PROFILE_H
#include "services/miner_signal_catalog_pin.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define EXPERIMENTAL_PROFILE_MAX (24u + 32u + 32u + 36u * 256u)
#define EXPERIMENTAL_GENESIS_SIZE 272u
struct experimental_profile {
    uint8_t digest[32], magic[32];
    uint32_t timestamp, bits;
    struct miner_signal_catalog_pin catalog;
    struct uint256 genesis_hash;
    uint8_t genesis_wire[EXPERIMENTAL_GENESIS_SIZE];
    size_t genesis_size;
};
enum experimental_profile_status {
    EXPERIMENTAL_PROFILE_OK,
    EXPERIMENTAL_PROFILE_INVALID,
    EXPERIMENTAL_PROFILE_CATALOG_INVALID,
    EXPERIMENTAL_PROFILE_PIN_MISMATCH
};
void experimental_profile_digest(const void *data, size_t size, uint8_t out[32]);
struct zcl_result experimental_profile_read_file(const char *path, uint8_t *buf, size_t cap, size_t *len);
struct zcl_result experimental_profile_parse(const uint8_t *buf, size_t len, struct experimental_profile *out);
struct zcl_result experimental_profile_genesis(const uint8_t *bytes, size_t len, const struct experimental_profile *p, struct uint256 *hash);
enum experimental_profile_status experimental_profile_inspect(const uint8_t *manifest, size_t mlen,
    const uint8_t *genesis, size_t glen, struct experimental_profile *out);
/* Requires an independently supplied 32-byte pin. On any failure *out is unchanged.
 * The successful value owns its catalog entries and exact validated genesis bytes;
 * copying the structure retains ownership without pointer fixups. */
enum experimental_profile_status experimental_profile_load(const uint8_t *manifest, size_t mlen,
    const uint8_t *genesis, size_t glen, const uint8_t expected[32], struct experimental_profile *out);
struct zcl_result experimental_profile_select(const struct experimental_profile *p, size_t slot,
    struct miner_signal_schedule *out);
#endif
