/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Declare the private wallet history export contract. */
#ifndef ZCL_WALLET_HISTORY_EXPORT_H
#define ZCL_WALLET_HISTORY_EXPORT_H
#include "net/file_manifest.h"
#include "util/result.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct platform_directory_transaction;

/* Check visible ancestry using the retained parent. Caller keeps the source
 * pathname identity and trusted mount namespace stable through check and use.
 * Bind-mounted aliases of source descendants are not detected. */
struct zcl_result wallet_history_export_parent_outside_source(
    const char *source, const struct platform_directory_transaction *parent);

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
/* Caller independently admits the endpoint and keeps the archive namespace
 * and bytes immutable through validation and use. The path does not retain
 * identity. Checks selected ancestry and authenticated bodies, not the full
 * manifest; grants no chain or proof-of-work authority. */
struct zcl_result wallet_history_export_validate_archive(
    const struct wallet_history_export_request *request, const char *path);
struct zcl_result wallet_history_export_run(
    const struct wallet_history_export_request *request,
    struct wallet_history_export_result *result);
#endif
