/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: bind native proof receipt admission to a caller's pinned request. */
#include "dev_proof_remote.h"
#include "base/bytes.h"

#include <stdio.h>
#include <string.h>

static bool remote_refuse(char *why, size_t size, const char *reason)
{
    if (why && size) (void)snprintf(why, size, "%s", reason);
    return false;
}

static bool remote_expectation_valid(
    const struct zcl_dev_proof_remote_expectation *expected)
{
    uint8_t oid[ZCL_DEV_PROOF_OID_MAX], length;
    return expected &&
        zcl_dev_proof_oid_decode(expected->local_commit, oid, &length) &&
        zcl_dev_proof_oid_decode(expected->remote_base, oid, &length) &&
        zcl_bytes_any_set(expected->signer_pubkey, 32) &&
        zcl_bytes_any_set(expected->source_root, 32) &&
        zcl_bytes_any_set(expected->source_cas_root, 32) &&
        zcl_bytes_any_set(expected->changed_set_root, 32) &&
        zcl_bytes_any_set(expected->impact_policy_root, 32);
}

static bool remote_bindings_match(
    const struct zcl_dev_acceptance_receipt_v1 *receipt,
    const struct zcl_dev_proof_remote_expectation *expected,
    char *why, size_t size)
{
    const struct { const uint8_t *actual, *pinned; const char *reason; } fields[] = {
        {receipt->signer_pubkey, expected->signer_pubkey, "remote_signer_mismatch"},
        {receipt->source_root, expected->source_root, "remote_source_root_mismatch"},
        {receipt->source_cas_root, expected->source_cas_root, "remote_source_cas_root_mismatch"},
        {receipt->changed_set_root, expected->changed_set_root, "remote_changed_set_root_mismatch"},
        {receipt->impact_policy_root, expected->impact_policy_root, "remote_impact_policy_root_mismatch"},
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        if (memcmp(fields[i].actual, fields[i].pinned, 32) != 0)
            return remote_refuse(why, size, fields[i].reason);
    return true;
}

bool zcl_dev_proof_remote_verify(
    const uint8_t *wire, size_t wire_len,
    const struct zcl_dev_proof_remote_expectation *expected,
    zcl_dev_proof_host_toolchain_fn capture, void *capture_ctx,
    struct zcl_dev_acceptance_receipt_v1 *out,
    char *why, size_t why_len)
{
    if (!wire || !out || !capture || !remote_expectation_valid(expected))
        return remote_refuse(why, why_len, "remote_arguments_invalid");
    struct zcl_dev_acceptance_receipt_v1 receipt;
    if (!zcl_dev_proof_receipt_parse(wire, wire_len, &receipt))
        return remote_refuse(why, why_len, "remote_receipt_parse_failed");
    if (!zcl_dev_proof_receipt_admit(&receipt, expected->local_commit,
            expected->remote_base, capture, capture_ctx, why, why_len) ||
        !remote_bindings_match(&receipt, expected, why, why_len))
        return false;
    *out = receipt;
    if (why && why_len) why[0] = '\0';
    return true;
}
