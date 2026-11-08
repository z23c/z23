/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Retain one immutable history generation for file service readers. */
#ifndef ZCL_FILE_SERVICE_GENERATION_H
#define ZCL_FILE_SERVICE_GENERATION_H
#include "net/file_manifest.h"
#include "platform/directory_transaction.h"
#include <stdbool.h>
#include <stdint.h>

struct fs_history_generation {
    struct platform_directory_transaction root, blocks;
    struct file_manifest manifest;
    uint8_t snapshot_digest[32], endpoint_hash[32];
    int32_t endpoint_height;
    bool ready;
};
void fs_history_generation_init(struct fs_history_generation *g);
/* On success consumes root and resets it to its canonical empty state.
 * On failure root remains owned by caller. Caller supplies a validated exporter manifest with chain_height set to the
 * admitted endpoint (the exporter builder leaves it zero), admits endpoint and promises
 * exclusive immutability of all files until generation close after all readers
 * join. This does not independently prove inventory or ancestry, and confers no authority or advertised offer. */
bool fs_history_generation_take(struct fs_history_generation *g,
    struct platform_directory_transaction *root, const struct file_manifest *m,
    const uint8_t snapshot_digest[32], int32_t height, const uint8_t hash[32]);
/* Concurrent reads allowed; each may allocate up to FILE_CHUNK_SIZE (50 MiB);
 * existing server worker limits apply. Caller frees *out. Close only after readers join. */
bool fs_history_generation_read(const struct fs_history_generation *g,
    uint32_t index, uint8_t **out, uint32_t *size);
void fs_history_generation_close(struct fs_history_generation *g);
/* Accepted new start consumes and resets generation; refusal leaves it owned
 * by caller. An asynchronous bind failure retains it until server stop. */
bool fs_server_start_with_history(struct fs_history_generation *generation,
                                  const char *snapshot_datadir,
                                  uint16_t port, const char *bind_address);
bool fs_server_history_matches(const uint8_t digest[32], int32_t height,
                               const uint8_t hash[32]);
#endif
