/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_WALLET_HISTORY_EXPORT_H
#define ZCL_WALLET_HISTORY_EXPORT_H
#include "net/file_manifest.h"
#include "util/result.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct wallet_history_export_request {
    const char *source_datadir;
    const char *private_parent;
    const char *staging_leaf;
    const char *destination_leaf;
    int32_t endpoint_height;
    uint8_t endpoint_hash[32];
    size_t max_rows;
    uint64_t max_bytes;
    uint64_t min_free_bytes;
    /* Cancellation is polled during copy and between validation phases;
     * archive verification and manifest hashing can delay observation. */
    bool (*cancelled)(void *context);
    void *cancel_context;
};

/* Caller independently admits the endpoint and ensures exclusive ownership of
 * the private staging namespace until publication completes. The source may
 * append, but its indexed prefix must remain readable during copying. This operation does not
 * grant chain authority or advertise files. UNKNOWN requires reconciliation of
 * both names before any cleanup. The caller retains failed staging evidence. */
enum wallet_history_export_outcome {
    WALLET_HISTORY_EXPORT_FAILED,
    WALLET_HISTORY_EXPORT_PUBLISHED,
    WALLET_HISTORY_EXPORT_UNKNOWN
};
struct wallet_history_export_result {
    enum wallet_history_export_outcome outcome;
    struct file_manifest manifest;
};
struct zcl_result wallet_history_export_run(
    const struct wallet_history_export_request *request,
    struct wallet_history_export_result *result);
#endif
