/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Declare immutable history manifest construction. */
#ifndef ZCL_WALLET_HISTORY_MANIFEST_H
#define ZCL_WALLET_HISTORY_MANIFEST_H
#include "net/file_manifest.h"
#include "util/result.h"
/* Caller holds the complete source tree immutable until this call returns. */
struct zcl_result wallet_history_manifest_build(struct file_manifest *out, const char *datadir,
                                   unsigned block_files);
/* Output is unchanged on failure. Cancellation is observed only at explicit
 * boundaries; a detected I/O or close failure takes precedence. */
enum { WALLET_HISTORY_MANIFEST_CANCELLED = -2 };
struct zcl_result wallet_history_manifest_build_cancelable(struct file_manifest *out, const char *datadir,
    unsigned block_files, bool (*cancelled)(void *), void *context);
#endif
