/* purpose: Shared experimental profile validation for offline tools. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_PROFILE_INSPECTOR_COMMON_H
#define Z23_PROFILE_INSPECTOR_COMMON_H
#include "services/miner_signal_catalog.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define PROFILE_MAX (24u + 32u + 32u + 36u * 256u)
#define GENESIS_SIZE 272u
struct profile {
    uint8_t digest[32], magic[32];
    uint32_t timestamp, bits;
    struct miner_signal_catalog catalog;
    struct miner_signal_catalog_entry entries[256];
};
void profile_digest(const void *data, size_t size, uint8_t out[32]);
bool profile_read_file(const char *path, uint8_t *buf, size_t cap, size_t *len);
bool profile_parse(const uint8_t *buf, size_t len, struct profile *out);
bool profile_inspect_genesis(const uint8_t *bytes, size_t len, struct profile *p,
                             struct uint256 *hash);
void profile_print_hex(const uint8_t *bytes, size_t n);
#endif
