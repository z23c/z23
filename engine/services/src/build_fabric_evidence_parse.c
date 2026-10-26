/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Strict parsers for fixed build test and fuzz evidence wires. */

#include "services/build_fabric_service.h"

#include "base/serialize_le.h"
#include "vcs/zcode_dev.h"

#include <string.h>

#define BF_TEST_EVIDENCE_BYTES 84u
#define BF_FUZZ_EVIDENCE_BYTES 96u

static bool evidence_wire_header_is_valid(const uint8_t *bytes, size_t len,
    size_t wire_bytes, const char *magic)
{
    return bytes && len == wire_bytes && memcmp(bytes, magic, 8) == 0 &&
        bytes[8] == 1 && bytes[9] == 0 && (bytes[10] == 1 || bytes[10] == 2) &&
        (bytes[11] & ~UINT8_C(7)) == 0;
}

static int evidence_exit_status_from_code(uint32_t code)
{
    return code > 0 && code <= 255 ? (int)code : 255;
}

struct zcl_result build_fabric_test_evidence_parse(
    const uint8_t *bytes, size_t len, uint8_t *status, int *exit_status)
{
    if (!evidence_wire_header_is_valid(bytes, len, BF_TEST_EVIDENCE_BYTES,
        "ZCTEST\r\n") || !status || !exit_status)
        return ZCL_ERR(-1, "test-evidence-wire-invalid");
    uint32_t code = zcl_read_u32_le(bytes + 12);
    uint32_t signal = zcl_read_u32_le(bytes + 16);
    if (bytes[10] == 1 &&
        (code != 0 || signal != 0 || (bytes[11] & UINT8_C(1)) != 0))
        return ZCL_ERR(-1, "passing-test-evidence-reports-failure");
    *status = bytes[10] == 1 ? VCS_ZCODE_WORK_PASS : VCS_ZCODE_WORK_FAIL;
    *exit_status = *status == VCS_ZCODE_WORK_PASS ? 0
        : evidence_exit_status_from_code(code);
    return ZCL_OK;
}

static bool fuzz_evidence_seed_range_is_valid(uint32_t seeds,
    uint32_t expected_seeds, uint32_t completed)
{
    return seeds != 0 && seeds == expected_seeds && completed != 0 &&
        completed <= seeds;
}

static bool fuzz_evidence_pass_state_is_consistent(const uint8_t *bytes,
    uint32_t seeds, uint32_t completed, uint32_t failing_seed, uint32_t code,
    uint32_t signal)
{
    return completed == seeds && failing_seed == UINT32_MAX && code == 0 &&
        signal == 0 && (bytes[11] & UINT8_C(1)) == 0;
}

static bool fuzz_evidence_failing_seed_is_valid(uint32_t seeds,
    uint32_t completed, uint32_t failing_seed)
{
    return failing_seed < seeds && completed == failing_seed + 1u;
}

struct zcl_result build_fabric_fuzz_evidence_parse(
    const uint8_t *bytes, size_t len, uint32_t expected_seeds,
    uint8_t *status, int *exit_status)
{
    if (!evidence_wire_header_is_valid(bytes, len, BF_FUZZ_EVIDENCE_BYTES,
        "ZCFUZZ\r\n") || !status || !exit_status)
        return ZCL_ERR(-1, "fuzz-evidence-wire-invalid");
    uint32_t seeds = zcl_read_u32_le(bytes + 12);
    uint32_t completed = zcl_read_u32_le(bytes + 16);
    uint32_t failing_seed = zcl_read_u32_le(bytes + 20);
    uint32_t code = zcl_read_u32_le(bytes + 24);
    uint32_t signal = zcl_read_u32_le(bytes + 28);
    if (!fuzz_evidence_seed_range_is_valid(seeds, expected_seeds, completed))
        return ZCL_ERR(-1, "fuzz-evidence-seed-range-invalid");
    if (bytes[10] == 1) {
        if (!fuzz_evidence_pass_state_is_consistent(bytes, seeds, completed,
            failing_seed, code, signal))
            return ZCL_ERR(-1, "passing-fuzz-evidence-is-inconsistent");
        *status = VCS_ZCODE_WORK_PASS;
        *exit_status = 0;
    } else {
        if (!fuzz_evidence_failing_seed_is_valid(seeds, completed,
            failing_seed))
            return ZCL_ERR(-1, "failing-fuzz-evidence-seed-invalid");
        *status = VCS_ZCODE_WORK_FAIL;
        *exit_status = evidence_exit_status_from_code(code);
    }
    return ZCL_OK;
}
