/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Helpers for fetching raw block headers from a legacy zclassicd JSON-RPC
 * endpoint. These functions only fetch and deserialize headers; callers still
 * own consensus validation and insertion.
 */

#ifndef ZCL_RPC_LEGACY_HEADER_CLIENT_H
#define ZCL_RPC_LEGACY_HEADER_CLIENT_H

#include <stdbool.h>
#include <stddef.h>

struct block_header;

#define LEGACY_HEADER_RPC_BATCH_MAX 128

bool legacy_header_rpc_fetch_remote_tip(const char *host, int port,
                                        const char *user, const char *pass,
                                        int *out_height,
                                        char *err, size_t err_sz);

bool legacy_header_rpc_fetch_one(const char *host, int port,
                                 const char *user, const char *pass,
                                 int height,
                                 struct block_header *out_hdr,
                                 char *err, size_t err_sz);

bool legacy_header_rpc_fetch_batch(const char *host, int port,
                                   const char *user, const char *pass,
                                   int from_h, int n,
                                   struct block_header *out,
                                   int *out_count,
                                   char *err, size_t err_sz);

#endif /* ZCL_RPC_LEGACY_HEADER_CLIENT_H */
