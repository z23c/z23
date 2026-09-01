/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure block-header acceptance structural checks. Mirrors the PURE
 * branches of the two legacy entry points:
 *
 *   core/modules/validation/check_block::check_block_header_impl
 *     - version-too-low gate
 *     - time-too-new gate (parameterised by now_upper_bound)
 *
 *   core/modules/validation/check_block::contextual_check_block_header
 *     - bad-equihash-solution-size gate
 *     - bad-diffbits gate (parameterised by expected_bits)
 *     - time-too-old gate (parameterised by prev_mtp)
 *     - bad-version gate
 *
 * Purity: no clock, no RNG, no I/O, no global state, no allocation.
 */

#include "domain/consensus/header_accept.h"

#include "reject_out.h"

#include "primitives/block.h"

#include <stddef.h>
#include <string.h>

struct zcl_result domain_consensus_check_header_version_too_low(
        const struct block_header *header,
        int32_t min_version,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos)
{
    if (!header)
        return ZCL_ERR(DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_NULL_ARG,
                       "check_header_version_too_low: null header");

    if (header->nVersion < min_version) {
        set_reject(out_reject_reason, out_reject_reason_size,
                   "version-too-low");
        set_dos(out_dos, 100);
        return ZCL_ERR(
                DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_VERSION_TOO_LOW,
                "check_header_version_too_low: version-too-low "
                "(nVersion=%d min=%d)",
                (int)header->nVersion, (int)min_version);
    }

    set_reject(out_reject_reason, out_reject_reason_size, "");
    set_dos(out_dos, 0);
    return ZCL_OK;
}

struct zcl_result domain_consensus_check_header_version_obsolete(
        const struct block_header *header,
        int32_t obsolete_below,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos)
{
    if (!header)
        return ZCL_ERR(DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_NULL_ARG,
                       "check_header_version_obsolete: null header");

    if (header->nVersion < obsolete_below) {
        set_reject(out_reject_reason, out_reject_reason_size,
                   "bad-version");
        /* REJECT_OBSOLETE_IF: peer isn't necessarily misbehaving;
         * DoS = 0. */
        set_dos(out_dos, 0);
        return ZCL_ERR(
                DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_BAD_VERSION,
                "check_header_version_obsolete: bad-version "
                "(nVersion=%d obsolete_below=%d)",
                (int)header->nVersion, (int)obsolete_below);
    }

    set_reject(out_reject_reason, out_reject_reason_size, "");
    set_dos(out_dos, 0);
    return ZCL_OK;
}

struct zcl_result domain_consensus_check_header_timestamp_too_new(
        const struct block_header *header,
        int64_t now_upper_bound,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos)
{
    if (!header)
        return ZCL_ERR(DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_NULL_ARG,
                       "check_header_timestamp_too_new: null header");

    int64_t header_time = block_header_get_time(header);
    if (header_time > now_upper_bound) {
        set_reject(out_reject_reason, out_reject_reason_size,
                   "time-too-new");
        /* REJECT_INVALID_IF: no DoS. */
        set_dos(out_dos, 0);
        return ZCL_ERR(
                DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_TIME_TOO_NEW,
                "check_header_timestamp_too_new: time-too-new "
                "(header_time=%lld upper=%lld)",
                (long long)header_time, (long long)now_upper_bound);
    }

    set_reject(out_reject_reason, out_reject_reason_size, "");
    set_dos(out_dos, 0);
    return ZCL_OK;
}

struct zcl_result domain_consensus_check_header_timestamp_too_old(
        const struct block_header *header,
        int64_t prev_mtp,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos)
{
    if (!header)
        return ZCL_ERR(DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_NULL_ARG,
                       "check_header_timestamp_too_old: null header");

    int64_t header_time = block_header_get_time(header);
    if (header_time <= prev_mtp) {
        set_reject(out_reject_reason, out_reject_reason_size,
                   "time-too-old");
        /* REJECT_INVALID_IF: no DoS. */
        set_dos(out_dos, 0);
        return ZCL_ERR(
                DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_TIME_TOO_OLD,
                "check_header_timestamp_too_old: time-too-old "
                "(header_time=%lld prev_mtp=%lld)",
                (long long)header_time, (long long)prev_mtp);
    }

    set_reject(out_reject_reason, out_reject_reason_size, "");
    set_dos(out_dos, 0);
    return ZCL_OK;
}

struct zcl_result domain_consensus_check_header_equihash_solution_size(
        const struct block_header *header,
        size_t expected_solution_size,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos)
{
    if (!header)
        return ZCL_ERR(DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_NULL_ARG,
                       "check_header_equihash_solution_size: null header");

    /* Legacy: only reject when sol_size > 0. A zero-size header
     * (fast-sync placeholder, not-yet-resolved) silently passes — the
     * full solution is verified once the block body arrives. */
    size_t sol_size = header->nSolutionSize;
    if (sol_size > 0 && sol_size != expected_solution_size) {
        set_reject(out_reject_reason, out_reject_reason_size,
                   "bad-equihash-solution-size");
        set_dos(out_dos, 100);
        return ZCL_ERR(
                DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_BAD_EQUIHASH_SOL_SIZE,
                "check_header_equihash_solution_size: "
                "bad-equihash-solution-size (got=%zu expected=%zu)",
                sol_size, expected_solution_size);
    }

    set_reject(out_reject_reason, out_reject_reason_size, "");
    set_dos(out_dos, 0);
    return ZCL_OK;
}

struct zcl_result domain_consensus_check_header_bits_match(
        const struct block_header *header,
        uint32_t expected_bits,
        char  *out_reject_reason,
        size_t out_reject_reason_size,
        int   *out_dos)
{
    if (!header)
        return ZCL_ERR(DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_NULL_ARG,
                       "check_header_bits_match: null header");

    if (header->nBits != expected_bits) {
        set_reject(out_reject_reason, out_reject_reason_size,
                   "bad-diffbits");
        set_dos(out_dos, 100);
        return ZCL_ERR(
                DOMAIN_CONSENSUS_HEADER_ACCEPT_ERR_BAD_DIFFBITS,
                "check_header_bits_match: bad-diffbits "
                "(got=0x%08x expected=0x%08x)",
                (unsigned)header->nBits, (unsigned)expected_bits);
    }

    set_reject(out_reject_reason, out_reject_reason_size, "");
    set_dos(out_dos, 0);
    return ZCL_OK;
}
