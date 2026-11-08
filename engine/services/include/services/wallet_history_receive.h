/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Declare verified resumable history receiving and lease ownership. */
#ifndef ZCL_WALLET_HISTORY_RECEIVE_H
#define ZCL_WALLET_HISTORY_RECEIVE_H

#include "net/file_manifest.h"
#include "platform/directory_transaction.h"
#include "util/result.h"
#include <stdint.h>

struct wallet_history_receiver;

enum wallet_history_receive_outcome {
    WALLET_HISTORY_RECEIVE_ERROR,
    WALLET_HISTORY_RECEIVE_COMPLETE,
    WALLET_HISTORY_RECEIVE_STOPPED,
    WALLET_HISTORY_RECEIVE_UNKNOWN
};

struct wallet_history_receive_request {
    const char *peer;
    uint16_t port;
    const char *private_parent;
    uint8_t snapshot_digest[32];
    uint8_t history_root[32];
    uint64_t max_bytes;
    uint64_t min_free_bytes;
    uint64_t reserved_install_bytes;
};

struct wallet_history_receive_result {
    enum wallet_history_receive_outcome outcome;
    struct platform_directory_transaction parent, root;
    struct platform_directory_lock lease;
    char root_leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    char lock_leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    unsigned block_files;
    uint8_t snapshot_digest[32];
    uint8_t history_root[32];
    struct file_manifest manifest;
};

/* The caller keeps the private parent, its ancestors and stage namespace
 * stable and exclusively controlled throughout the operation and returned
 * lease lifetime. This interface does not prevent same-owner namespace ABA.
 * Incomplete stages are credited only for an independently hashed contiguous
 * prefix; the transport rechecks that prefix before writing chunks.
 * Request strings and bindings are copied. One run is allowed per receiver. */
struct zcl_result wallet_history_receiver_create(
    const struct wallet_history_receive_request *request,
    struct wallet_history_receiver **out);
/* COMPLETE transfers the retained parent, root and exclusive lease to out. All
 * other outcomes preserve any stage or destination; UNKNOWN does not assert
 * publication. COMPLETE establishes byte and storage binding, not chain authority.
 * A result must be initialized before run and closed after use. */
struct zcl_result wallet_history_receiver_run(struct wallet_history_receiver *receiver,
                                               struct wallet_history_receive_result *out);
/* Cancellation is sticky and may run concurrently with run. It requests
 * socket shutdown; interrupted I/O may still report ERROR. The caller joins
 * all run and cancel users before destroying the receiver. */
void wallet_history_receiver_cancel(struct wallet_history_receiver *receiver);
void wallet_history_receiver_destroy(struct wallet_history_receiver **receiver);
void wallet_history_receive_result_init(struct wallet_history_receive_result *result);
void wallet_history_receive_result_close(struct wallet_history_receive_result *result);
#endif
