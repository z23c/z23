/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Strict parsers for fixed build test and fuzz evidence wires. */

#include "services/build_fabric_service.h"

#include "base/serialize_le.h"
#include "vcs/zcode_dev.h"

#include <string.h>

#define BF_TEST_EVIDENCE_BYTES 84u
#define BF_FUZZ_EVIDENCE_BYTES 96u

struct zcl_result build_fabric_test_evidence_parse(
    const uint8_t *bytes, size_t len, uint8_t *status, int *exit_status)
{
    if (!bytes || len != BF_TEST_EVIDENCE_BYTES ||
        memcmp(bytes, "ZCTEST\r\n", 8) != 0 || bytes[8] != 1 ||
        bytes[9] != 0 || (bytes[10] != 1 && bytes[10] != 2) ||
        (bytes[11] & ~UINT8_C(7)) != 0 || !status || !exit_status)
        return ZCL_ERR(-1, "test-evidence-wire-invalid");
    uint32_t code = zcl_read_u32_le(bytes + 12);
    uint32_t signal = zcl_read_u32_le(bytes + 16);
    if (bytes[10] == 1 &&
        (code != 0 || signal != 0 || (bytes[11] & UINT8_C(1)) != 0))
        return ZCL_ERR(-1, "passing-test-evidence-reports-failure");
    *status = bytes[10] == 1 ? VCS_ZCODE_WORK_PASS : VCS_ZCODE_WORK_FAIL;
    *exit_status = *status == VCS_ZCODE_WORK_PASS ? 0
        : code > 0 && code <= 255 ? (int)code : 255;
    return ZCL_OK;
}

struct zcl_result build_fabric_fuzz_evidence_parse(
    const uint8_t *bytes, size_t len, uint32_t expected_seeds,
    uint8_t *status, int *exit_status)
{
    if (!bytes || len != BF_FUZZ_EVIDENCE_BYTES ||
        memcmp(bytes, "ZCFUZZ\r\n", 8) != 0 || bytes[8] != 1 ||
        bytes[9] != 0 || (bytes[10] != 1 && bytes[10] != 2) ||
        (bytes[11] & ~UINT8_C(7)) != 0 || !status || !exit_status)
        return ZCL_ERR(-1, "fuzz-evidence-wire-invalid");
    uint32_t seeds = zcl_read_u32_le(bytes + 12);
    uint32_t completed = zcl_read_u32_le(bytes + 16);
    uint32_t failing_seed = zcl_read_u32_le(bytes + 20);
    uint32_t code = zcl_read_u32_le(bytes + 24);
    uint32_t signal = zcl_read_u32_le(bytes + 28);
    if (seeds == 0 || seeds != expected_seeds || completed == 0 ||
        completed > seeds)
        return ZCL_ERR(-1, "fuzz-evidence-seed-range-invalid");
    if (bytes[10] == 1) {
        if (completed != seeds || failing_seed != UINT32_MAX || code != 0 ||
            signal != 0 || (bytes[11] & UINT8_C(1)) != 0)
            return ZCL_ERR(-1, "passing-fuzz-evidence-is-inconsistent");
        *status = VCS_ZCODE_WORK_PASS;
        *exit_status = 0;
    } else {
        if (failing_seed >= seeds || completed != failing_seed + 1u)
            return ZCL_ERR(-1, "failing-fuzz-evidence-seed-invalid");
        *status = VCS_ZCODE_WORK_FAIL;
        *exit_status = code > 0 && code <= 255 ? (int)code : 255;
    }
    return ZCL_OK;
}
