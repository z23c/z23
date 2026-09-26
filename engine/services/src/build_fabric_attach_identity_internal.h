/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Private host identity capture for fixed compile attachment. */
#ifndef ZCL_BUILD_FABRIC_ATTACH_IDENTITY_INTERNAL_H
#define ZCL_BUILD_FABRIC_ATTACH_IDENTITY_INTERNAL_H

#include "base/result.h"
#include "platform/toolchain.h"
#include <stdint.h>

struct zcl_result bfat_runtime_roots(
    const char *workspace, const struct platform_toolchain_descriptor *desc,
    uint8_t runtime_root[32], uint8_t verifier_root[32]);
struct zcl_result bfat_cached_tool_hashes(
    const struct platform_toolchain_descriptor *desc,
    uint8_t driver_sha3[32], uint8_t backend_sha3[32],
    uint8_t assembler_sha3[32]);

#endif
