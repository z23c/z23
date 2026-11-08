/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_WALLET_HISTORY_MANIFEST_H
#define ZCL_WALLET_HISTORY_MANIFEST_H
#include "net/file_manifest.h"
#include "util/result.h"
/* Caller holds the complete source tree immutable until this call returns. */
struct zcl_result wallet_history_manifest_build(struct file_manifest *out, const char *datadir,
                                   unsigned block_files);
#endif
